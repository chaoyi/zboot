//! Exact snapshot deletion for reviewed manual loss and namespaced retention.
//! Plans bind local incarnations and admitted dataset scopes. Only individual
//! `zfs destroy NAME` commands are issued: no recursion, deferred deletion,
//! automatic hold release, retries, or compensation.
use crate::engine::{
    Error, Snapshot, SnapshotRef, native,
    operation::SnapshotScope,
    state::{self, NativeState},
};
use crate::{DeleteOutcome, DeletePointOutcome, DeletePointStatus, DeleteStatus};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Target {
    point: SnapshotRef,
    userrefs: u64,
    holds: Vec<String>,
    clones: Vec<String>,
    defer_destroy: bool,
}
impl Target {
    fn observe(snapshot: &Snapshot) -> Self {
        Self {
            point: snapshot.point(),
            userrefs: snapshot.userrefs,
            holds: snapshot.holds.clone(),
            clones: snapshot.clones.clone(),
            defer_destroy: snapshot.defer_destroy,
        }
    }
}

/// An immutable review artifact. Serialization is for review/audit; deserializing
/// a file cannot create authority to delete. Plans must be freshly native-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotDeletePlan {
    schema_version: u32,
    scope: SnapshotScope,
    targets: Vec<Target>,
    loss_token: String,
}
impl SnapshotDeletePlan {
    pub fn points(&self) -> Vec<SnapshotRef> {
        self.targets.iter().map(|t| t.point.clone()).collect()
    }
    pub fn loss_token(&self) -> &str {
        &self.loss_token
    }
}

/// Native observation/effect seam for isolated tests. A backend never receives a
/// caller-provided command; its only effect is destroying one exact named point.
pub trait DeleteBackend {
    fn observe(&mut self) -> Result<NativeState, Error>;
    fn observe_point(&mut self, point: &SnapshotRef) -> Result<Snapshot, Error>;
    fn destroy(&mut self, name: &str) -> Result<(), Error>;
}

pub struct NativeDelete;
impl DeleteBackend for NativeDelete {
    fn observe(&mut self) -> Result<NativeState, Error> {
        state::observe()
    }
    fn observe_point(&mut self, point: &SnapshotRef) -> Result<Snapshot, Error> {
        // The resolver refuses unavailable pools, so a failed import/query does
        // not masquerade as post-destroy absence. Rename is refused by the
        // executor's name equality check, never silently followed for deletion.
        native::resolve_with(point, &mut native::run)
    }
    fn destroy(&mut self, name: &str) -> Result<(), Error> {
        crate::engine::validate_snapshot_name(name)?;
        native::run_mutating("zfs", &destroy_args(name)).map(|_| ())
    }
}
fn destroy_args(name: &str) -> Vec<String> {
    vec!["destroy".into(), name.into()]
}

fn refuse(detail: impl Into<String>) -> Error {
    Error::Inconsistent(detail.into())
}

pub fn plan_snapshots_with(
    points: &[SnapshotRef],
    backend: &mut impl DeleteBackend,
) -> Result<SnapshotDeletePlan, Error> {
    let state = backend.observe()?;
    plan_from_state(points, &state)
}

fn plan_from_state(
    points: &[SnapshotRef],
    state: &NativeState,
) -> Result<SnapshotDeletePlan, Error> {
    if points.is_empty() {
        return Err(Error::InvalidScope("empty snapshot deletion scope".into()));
    }
    let mut names = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut targets = Vec::new();
    for point in points {
        crate::engine::validate_snapshot_name(&point.name)?;
        if !names.insert(&point.name) {
            return Err(Error::InvalidScope(
                "duplicate snapshot deletion target".into(),
            ));
        }
        roots.insert(point.name.split_once('@').unwrap().0.to_string());
        let snapshot = exact_snapshot(state, point)?;
        refuse_protected(snapshot)?;
        targets.push(Target::observe(snapshot));
    }
    let scope = SnapshotScope::plan_exact(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
        &roots.into_iter().collect::<Vec<_>>(),
    )?;
    targets.sort_by(|a, b| a.point.name.cmp(&b.point.name));
    let encoded = serde_json::to_vec(&(1_u32, &scope, &targets))
        .map_err(|error| refuse(error.to_string()))?;
    let loss_token = format!("sha256:{:x}", Sha256::digest(encoded));
    Ok(SnapshotDeletePlan {
        schema_version: 1,
        scope,
        targets,
        loss_token,
    })
}

fn exact_snapshot<'a>(state: &'a NativeState, point: &SnapshotRef) -> Result<&'a Snapshot, Error> {
    let snapshots = state
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| refuse("snapshot deletion requires observed complete history"))?;
    let mut found = snapshots.iter().filter(|s| s.name == point.name);
    let snapshot = found
        .next()
        .ok_or_else(|| Error::NotFound(point.name.clone()))?;
    if found.next().is_some() || snapshot.point() != *point {
        return Err(refuse(format!(
            "snapshot name has changed incarnation: {}",
            point.name
        )));
    }
    if !point.is_complete() {
        return Err(refuse("incomplete snapshot deletion identity"));
    }
    Ok(snapshot)
}

fn refuse_protected(snapshot: &Snapshot) -> Result<(), Error> {
    if snapshot.userrefs != 0 || !snapshot.holds.is_empty() {
        return Err(refuse(format!(
            "snapshot has managed or foreign holds: {}",
            snapshot.name
        )));
    }
    if snapshot.defer_destroy {
        return Err(refuse(format!(
            "snapshot is already marked for deferred destruction: {}",
            snapshot.name
        )));
    }
    if !snapshot.clones.is_empty() {
        return Err(refuse(format!(
            "snapshot has clone dependents: {}",
            snapshot.name
        )));
    }
    Ok(())
}

fn revalidate(
    plan: &SnapshotDeletePlan,
    state: &NativeState,
    targets: &[Target],
) -> Result<(), Error> {
    plan.scope.revalidate(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
    )?;
    for target in targets {
        let snapshot = exact_snapshot(state, &target.point)?;
        refuse_protected(snapshot)?;
        if Target::observe(snapshot) != *target {
            return Err(refuse(
                "snapshot protection/dependency state changed since review",
            ));
        }
    }
    Ok(())
}

pub fn execute_snapshot_delete_with(
    plan: &SnapshotDeletePlan,
    loss_token: &str,
    backend: &mut impl DeleteBackend,
) -> Result<DeleteOutcome, Error> {
    if loss_token != plan.loss_token {
        return Err(refuse(
            "exact snapshot loss token does not match reviewed plan",
        ));
    }

    revalidate(plan, &backend.observe()?, &plan.targets)?;
    let mut outcome = DeleteOutcome {
        status: DeleteStatus::Complete,
        points: Vec::new(),
    };
    for (index, target) in plan.targets.iter().enumerate() {
        let ready = (|| {
            revalidate(plan, &backend.observe()?, &plan.targets[index..])?;
            let current = backend.observe_point(&target.point)?;
            if Target::observe(&current) != *target {
                return Err(refuse(
                    "snapshot incarnation, name or protection changed before destroy",
                ));
            }
            refuse_protected(&current)?;
            Ok(())
        })();
        if let Err(error) = ready {
            if outcome.points.is_empty() {
                return Err(error);
            }
            outcome.status = DeleteStatus::Partial;
            for skipped in &plan.targets[index..] {
                outcome.points.push(DeletePointOutcome {
                    point: skipped.point.clone(),
                    status: DeletePointStatus::NotAttempted,
                    command_error: None,
                    detail: Some(error.to_string()),
                });
            }
            return Ok(outcome);
        }
        let command_error = backend
            .destroy(&target.point.name)
            .err()
            .map(|error| error.to_string());
        let (status, detail) = match backend.observe_point(&target.point) {
            Err(Error::NotFound(_)) => (DeletePointStatus::AbsentAfterCommand, None),
            Ok(after) if after.point() == target.point => (
                DeletePointStatus::StillPresent,
                Some("snapshot still present after destroy command".into()),
            ),
            Ok(_) | Err(Error::Inconsistent(_)) => (
                DeletePointStatus::Changed,
                Some("snapshot identity or imported pool changed; absence is unproven".into()),
            ),
            Err(error) => (DeletePointStatus::Uncertain, Some(error.to_string())),
        };
        outcome.points.push(DeletePointOutcome {
            point: target.point.clone(),
            status,
            command_error,
            detail,
        });
        if status != DeletePointStatus::AbsentAfterCommand {
            outcome.status = if matches!(
                status,
                DeletePointStatus::Changed | DeletePointStatus::Uncertain
            ) {
                DeleteStatus::Uncertain
            } else {
                DeleteStatus::Partial
            };
            for skipped in &plan.targets[index + 1..] {
                outcome.points.push(DeletePointOutcome {
                    point: skipped.point.clone(),
                    status: DeletePointStatus::NotAttempted,
                    command_error: None,
                    detail: Some("stopped after an incomplete or uncertain deletion".into()),
                });
            }
            return Ok(outcome);
        }
    }
    Ok(outcome)
}

/// Caller-owned retention policy evidence, constructed in code after Zsnap's
/// policy selection. This shared crate validates namespace/scope and binds the
/// exact candidates; it does not implement or trust serialized policy programs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg(feature = "internal")]
pub struct RetentionSelection {
    dataset: String,
    policy_evidence: String,
    evaluated_at_epoch_seconds: i64,
    points: Vec<SnapshotRef>,
}
#[cfg(feature = "internal")]
impl RetentionSelection {
    pub fn new(
        dataset: String,
        policy_evidence: String,
        evaluated_at_epoch_seconds: i64,
        points: Vec<SnapshotRef>,
    ) -> Result<Self, Error> {
        crate::engine::validate_dataset_name(&dataset)?;
        if policy_evidence.is_empty()
            || policy_evidence.len() > 65536
            || evaluated_at_epoch_seconds < 0
        {
            return Err(Error::InvalidScope(
                "retention needs bounded nonempty policy evidence and a valid evaluation time"
                    .into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for point in &points {
            crate::engine::validate_snapshot_name(&point.name)?;
            if !seen.insert(&point.name) {
                return Err(Error::InvalidScope("duplicate retention candidate".into()));
            }
            let (parent, suffix) = point.name.split_once('@').unwrap();
            if parent != dataset || !suffix.starts_with("zsnap_") || suffix.len() <= "zsnap_".len()
            {
                return Err(Error::InvalidScope(
                    "retention candidate outside exact dataset/zsnap namespace".into(),
                ));
            }
        }
        Ok(Self {
            dataset,
            policy_evidence,
            evaluated_at_epoch_seconds,
            points,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg(feature = "internal")]
pub struct DeleteSkip {
    pub point: SnapshotRef,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg(feature = "internal")]
pub struct RetentionDeletePlan {
    selection: RetentionSelection,
    plan: Option<SnapshotDeletePlan>,
    skipped: Vec<DeleteSkip>,
}
#[cfg(feature = "internal")]
impl RetentionDeletePlan {
    pub fn plan(&self) -> Option<&SnapshotDeletePlan> {
        self.plan.as_ref()
    }
    pub fn skipped(&self) -> &[DeleteSkip] {
        &self.skipped
    }
}

#[cfg(feature = "internal")]
pub fn plan_retention_with(
    selection: &RetentionSelection,
    backend: &mut impl DeleteBackend,
) -> Result<RetentionDeletePlan, Error> {
    let state = backend.observe()?;
    plan_retention_from_state(selection, &state)
}

#[cfg(feature = "internal")]
pub fn plan_retention_from_state(
    selection: &RetentionSelection,
    state: &NativeState,
) -> Result<RetentionDeletePlan, Error> {
    // Admission only: a writable working copy, never a fenced pair copy.
    SnapshotScope::plan_exact(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
        std::slice::from_ref(&selection.dataset),
    )?;
    let mut accepted = Vec::new();
    let mut skipped = Vec::new();
    for point in &selection.points {
        let snapshot = exact_snapshot(state, point)?;
        match refuse_protected(snapshot) {
            Ok(()) => accepted.push(point.clone()),
            Err(error) => skipped.push(DeleteSkip {
                point: point.clone(),
                reason: error.to_string(),
            }),
        }
    }
    let plan = if accepted.is_empty() {
        None
    } else {
        Some(plan_from_state(&accepted, state)?)
    };
    Ok(RetentionDeletePlan {
        selection: selection.clone(),
        plan,
        skipped,
    })
}

#[cfg(feature = "internal")]
pub fn execute_retention_with(
    plan: &RetentionDeletePlan,
    backend: &mut impl DeleteBackend,
) -> Result<DeleteOutcome, Error> {
    match &plan.plan {
        Some(plan) => execute_snapshot_delete_with(plan, plan.loss_token(), backend),
        None => Ok(DeleteOutcome {
            status: DeleteStatus::Complete,
            points: vec![],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        InspectRequest,
        native::{NativeProperty, PropertyInventory},
    };
    use std::collections::BTreeMap;

    fn property(value: impl ToString) -> NativeProperty {
        NativeProperty {
            value: value.to_string(),
            source: "-".into(),
        }
    }
    fn fixture() -> NativeState {
        let output = [
            "tank\t1\t1000\t100\t900\tONLINE\t-\n",
            "tank\tfilesystem\t1\t100\t900\t80\t/tank\t-\t11\t21\tno\toff\ton\t-\toff\t-\t-\t-\t-\ntank/data\tfilesystem\t2\t100\t900\t80\t/tank/data\t-\t12\t22\tno\toff\ton\t-\toff\t-\t-\t-\t-\n",
            "tank/data@s0\t30\t1700000000\t0\t20\t4\t50\t0\toff\t-\ntank/data@s1\t31\t1700000001\t0\t20\t5\t51\t0\toff\t-\n",
        ];
        let mut output = output.into_iter();
        let inspection =
            native::inspect_with(&InspectRequest::new(vec![], true).unwrap(), |_, _| {
                Ok(output.next().unwrap().into())
            })
            .unwrap();
        let dataset_properties = inspection
            .datasets
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    BTreeMap::from([
                        ("guid".into(), property(d.identity.guid)),
                        ("createtxg".into(), property(d.identity.createtxg)),
                        ("objsetid".into(), property(d.identity.objsetid)),
                    ]),
                )
            })
            .collect();
        NativeState {
            inspection,
            dataset_properties,
            pool_properties: PropertyInventory::from([(
                "tank".into(),
                BTreeMap::from([("guid".into(), property(1))]),
            )]),
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Normal,
        LostReply,
        NoEffect,
        PostQueryFailure,
        ReplaceAfterEffect,
        LateHold,
        LateScope,
        HoldSecondAfterFirst,
    }
    struct Fake {
        state: NativeState,
        destroys: Vec<String>,
        observations: usize,
        mode: Mode,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                state: fixture(),
                destroys: vec![],
                observations: 0,
                mode: Mode::Normal,
            }
        }
        fn points(&self) -> Vec<SnapshotRef> {
            self.state
                .inspection
                .snapshots
                .as_ref()
                .unwrap()
                .iter()
                .map(Snapshot::point)
                .collect()
        }
        fn snapshots(&mut self) -> &mut Vec<Snapshot> {
            self.state.inspection.snapshots.as_mut().unwrap()
        }
    }
    impl DeleteBackend for Fake {
        fn observe(&mut self) -> Result<NativeState, Error> {
            self.observations += 1;
            if self.mode == Mode::LateScope && self.observations >= 2 {
                self.state.inspection.datasets[1].identity.objsetid =
                    crate::engine::ObjsetId::new(999);
            }
            Ok(self.state.clone())
        }
        fn observe_point(&mut self, point: &SnapshotRef) -> Result<Snapshot, Error> {
            if self.mode == Mode::PostQueryFailure && !self.destroys.is_empty() {
                return Err(refuse("post-effect pool observation unavailable"));
            }
            if self.mode == Mode::LateHold && self.destroys.is_empty() {
                self.snapshots()[0].holds = vec!["foreign:reader".into()];
                self.snapshots()[0].userrefs = 1;
            }
            self.snapshots()
                .iter()
                .find(|s| s.name == point.name)
                .cloned()
                .ok_or_else(|| Error::NotFound(point.name.clone()))
        }
        fn destroy(&mut self, name: &str) -> Result<(), Error> {
            self.destroys.push(name.into());
            let index = self
                .snapshots()
                .iter()
                .position(|s| s.name == name)
                .unwrap();
            assert!(
                self.snapshots()[index].holds.is_empty(),
                "executor attempted held snapshot"
            );
            assert!(
                self.snapshots()[index].clones.is_empty(),
                "executor attempted clone origin"
            );
            if self.mode == Mode::NoEffect {
                return Err(refuse("native destroy denied"));
            }
            if self.mode == Mode::ReplaceAfterEffect {
                self.snapshots()[index].identity.objsetid = crate::engine::ObjsetId::new(999);
            } else {
                self.snapshots().remove(index);
            }
            if self.mode == Mode::HoldSecondAfterFirst && self.destroys.len() == 1 {
                self.snapshots()[0].holds = vec!["foreign:reader".into()];
                self.snapshots()[0].userrefs = 1;
            }
            if self.mode == Mode::LostReply {
                Err(refuse("destroy reply lost"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn deterministic_review_token_binds_all_local_identity_fields_and_exact_names() {
        let mut fake = Fake::new();
        let points = fake.points();
        let plan = plan_snapshots_with(&points, &mut fake).unwrap();
        let reversed: Vec<_> = points.iter().cloned().rev().collect();
        assert_eq!(plan, plan_snapshots_with(&reversed, &mut fake).unwrap());
        assert!(plan.loss_token().starts_with("sha256:"));
        assert_eq!(plan.loss_token().len(), 71);
        let before_queries = fake.observations;
        assert!(execute_snapshot_delete_with(&plan, "wrong-token", &mut fake).is_err());
        assert_eq!(fake.observations, before_queries);
        assert!(fake.destroys.is_empty());
        fake.snapshots()[0].identity.objsetid = crate::engine::ObjsetId::new(999);
        let replacement = plan_snapshots_with(&fake.points(), &mut fake).unwrap();
        assert_ne!(plan.loss_token(), replacement.loss_token());
        assert!(execute_snapshot_delete_with(&plan, plan.loss_token(), &mut fake).is_err());
        assert!(fake.destroys.is_empty());
    }

    #[test]
    fn native_destroy_is_one_exact_snapshot_without_force_or_recursive_flags() {
        assert_eq!(destroy_args("tank/data@s"), vec!["destroy", "tank/data@s"]);

        let mut fake = Fake::new();
        let points = fake.points();
        let plan = plan_snapshots_with(&points[..1], &mut fake).unwrap();
        let report = execute_snapshot_delete_with(&plan, plan.loss_token(), &mut fake).unwrap();
        assert_eq!(report.status, DeleteStatus::Complete);
        assert_eq!(fake.destroys, vec![points[0].name.clone()]);
        assert_eq!(fake.points(), points[1..]);
    }

    #[test]
    fn holds_dependencies_deferred_and_unknown_management_refuse_before_effects() {
        for change in 0..6 {
            let mut fake = Fake::new();
            let points = fake.points();
            match change {
                0 => {
                    fake.snapshots()[0].holds = vec!["zboot:anchor".into()];
                    fake.snapshots()[0].userrefs = 1;
                }
                1 => {
                    fake.snapshots()[0].holds = vec!["foreign:reader".into()];
                    fake.snapshots()[0].userrefs = 1;
                }
                2 => fake.snapshots()[0].clones = vec!["tank/external-clone".into()],
                3 => fake.snapshots()[0].defer_destroy = true,
                4 => fake.state.inspection.datasets[1].readonly = true,
                _ => {
                    fake.state
                        .dataset_properties
                        .get_mut("tank/data")
                        .unwrap()
                        .insert("zboot:future".into(), property("-"));
                }
            }
            assert!(
                plan_snapshots_with(&points, &mut fake).is_err(),
                "change {change}"
            );
            assert!(fake.destroys.is_empty());
        }
    }

    #[test]
    fn late_scope_hold_missing_and_replaced_identity_refuse_before_first_effect() {
        for mode in [Mode::LateHold, Mode::LateScope] {
            let mut fake = Fake::new();
            let points = fake.points();
            let plan = plan_snapshots_with(&points, &mut fake).unwrap();
            fake.mode = mode;
            assert!(execute_snapshot_delete_with(&plan, plan.loss_token(), &mut fake).is_err());
            assert!(fake.destroys.is_empty());
        }
        let mut fake = Fake::new();
        let points = fake.points();
        let plan = plan_snapshots_with(&points, &mut fake).unwrap();
        fake.snapshots().remove(0);
        assert!(execute_snapshot_delete_with(&plan, plan.loss_token(), &mut fake).is_err());
        assert!(fake.destroys.is_empty());
    }

    #[test]
    fn lost_reply_is_reported_with_verified_absence_and_no_retry() {
        let mut fake = Fake::new();
        let plan = plan_snapshots_with(&fake.points(), &mut fake).unwrap();
        fake.mode = Mode::LostReply;
        let report = execute_snapshot_delete_with(&plan, plan.loss_token(), &mut fake).unwrap();
        assert_eq!(report.status, DeleteStatus::Complete);
        assert_eq!(fake.destroys.len(), 2);
        assert!(report.points.iter().all(
            |p| p.status == DeletePointStatus::AbsentAfterCommand && p.command_error.is_some()
        ));
    }

    #[test]
    fn partial_and_uncertain_effects_stop_and_keep_exact_not_attempted_points() {
        for mode in [
            Mode::NoEffect,
            Mode::PostQueryFailure,
            Mode::ReplaceAfterEffect,
            Mode::HoldSecondAfterFirst,
        ] {
            let mut fake = Fake::new();
            let plan = plan_snapshots_with(&fake.points(), &mut fake).unwrap();
            fake.mode = mode;
            let report = execute_snapshot_delete_with(&plan, plan.loss_token(), &mut fake).unwrap();
            assert_ne!(report.status, DeleteStatus::Complete);
            assert_eq!(fake.destroys.len(), 1);
            assert_eq!(report.points.len(), 2);
            assert_eq!(report.points[1].status, DeletePointStatus::NotAttempted);
            if matches!(mode, Mode::PostQueryFailure | Mode::ReplaceAfterEffect) {
                assert_eq!(report.status, DeleteStatus::Uncertain);
            }
            if mode == Mode::HoldSecondAfterFirst {
                assert_eq!(
                    report.points[0].status,
                    DeletePointStatus::AbsentAfterCommand
                );
            }
        }
    }

    #[cfg(feature = "internal")]
    #[test]
    fn retention_binds_policy_and_namespace_and_reports_protected_skips() {
        let mut fake = Fake::new();
        for (i, snapshot) in fake.snapshots().iter_mut().enumerate() {
            snapshot.name = format!("tank/data@zsnap_2026-09-0{}-120000", i + 1);
        }
        fake.snapshots()[0].holds = vec!["foreign:reader".into()];
        fake.snapshots()[0].userrefs = 1;
        let selection = RetentionSelection::new(
            "tank/data".into(),
            "policy=daily;keep=last=1".into(),
            1800000000,
            fake.points(),
        )
        .unwrap();
        let plan = plan_retention_with(&selection, &mut fake).unwrap();
        assert_eq!(plan.skipped().len(), 1);
        assert_eq!(plan.plan().unwrap().points().len(), 1);
        let report = execute_retention_with(&plan, &mut fake).unwrap();
        assert_eq!(report.status, DeleteStatus::Complete);
        assert_eq!(fake.snapshots().len(), 1);
        assert_eq!(fake.snapshots()[0].holds, vec!["foreign:reader"]);
        let mut foreign = fake.points();
        foreign[0].name = "tank/data@manual".into();
        assert!(RetentionSelection::new("tank/data".into(), "policy".into(), 1, foreign).is_err());
        assert!(
            RetentionSelection::new("tank/other".into(), "policy".into(), 1, fake.points())
                .is_err()
        );
        assert!(
            RetentionSelection::new("tank/data".into(), String::new(), 1, fake.points()).is_err()
        );
    }
    #[cfg(feature = "internal")]
    #[test]
    fn a_paired_working_copy_prunes_and_a_fenced_copy_refuses() {
        use crate::engine::management::{Endpoint, PAIR_PROPERTY, PairRecord, Role};

        let mut fake = Fake::new();
        let mut peer = fake.state.inspection.datasets[1].clone();
        peer.name = "tank/backup".into();
        peer.guid = crate::engine::Guid::new(3);
        peer.identity.guid = peer.guid;
        peer.identity.createtxg = crate::engine::Txg::new(13);
        peer.identity.objsetid = crate::engine::ObjsetId::new(23);
        peer.readonly = true;
        peer.canmount = Some(crate::engine::CanMount::Off);
        let primary = &fake.state.inspection.datasets[1];
        let record = PairRecord {
            schema_version: 1,
            pair_id: "12345678-1234-4234-9234-1234567890ab".into(),
            endpoint: Endpoint {
                name: primary.name.clone(),
                identity: primary.identity.clone(),
            },
            peer: Endpoint {
                name: peer.name.clone(),
                identity: peer.identity.clone(),
            },
            role: Role::Primary,
        };
        fake.state
            .dataset_properties
            .get_mut("tank/data")
            .unwrap()
            .insert(
                PAIR_PROPERTY.into(),
                NativeProperty {
                    value: record.encode().unwrap(),
                    source: "local".into(),
                },
            );
        fake.state.dataset_properties.insert(
            peer.name.clone(),
            BTreeMap::from([
                ("guid".into(), property(peer.identity.guid)),
                ("createtxg".into(), property(peer.identity.createtxg)),
                ("objsetid".into(), property(peer.identity.objsetid)),
                (
                    PAIR_PROPERTY.into(),
                    NativeProperty {
                        value: record.counterpart().encode().unwrap(),
                        source: "local".into(),
                    },
                ),
            ]),
        );
        fake.state.inspection.datasets.push(peer);
        SnapshotScope::plan_exact(
            &fake.state.inspection,
            &fake.state.dataset_properties,
            &fake.state.pool_properties,
            &["tank/data".into()],
        )
        .unwrap();
        plan_snapshots_with(&fake.points(), &mut fake).unwrap();
        // The same dataset as the fenced side of the pair refuses.
        let data = &mut fake.state.inspection.datasets[1];
        data.readonly = true;
        data.canmount = Some(crate::engine::CanMount::NoAuto);
        data.mounted = Some(false);
        let backup = fake.state.inspection.datasets.last_mut().unwrap();
        backup.readonly = false;
        backup.canmount = Some(crate::engine::CanMount::On);
        let fenced = PairRecord {
            role: Role::Secondary,
            ..record
        };
        fake.state
            .dataset_properties
            .get_mut("tank/data")
            .unwrap()
            .insert(
                PAIR_PROPERTY.into(),
                NativeProperty {
                    value: fenced.encode().unwrap(),
                    source: "local".into(),
                },
            );
        fake.state
            .dataset_properties
            .get_mut("tank/backup")
            .unwrap()
            .insert(
                PAIR_PROPERTY.into(),
                NativeProperty {
                    value: fenced.counterpart().encode().unwrap(),
                    source: "local".into(),
                },
            );
        let error = plan_snapshots_with(&fake.points(), &mut fake).unwrap_err();
        assert!(error.to_string().contains("fenced pair copy"), "{error}");
        assert!(fake.destroys.is_empty());
    }
}
