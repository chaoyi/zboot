//! Shared recursive capture. Exact members are frozen before the command, so a
//! newly created descendant cannot silently enter an approved scope. Native
//! snapshot creation is atomic per pool; cross-pool outcomes may be partial.
use crate::engine::{
    Error, SnapshotRef, native,
    operation::SnapshotScope,
    state::{self, NativeState},
};
use crate::{CaptureOutcome, CaptureStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    pub roots: Vec<String>,
    pub name: String,
    pub recursive: bool,
}

/// Native boundary, injectable for failure tests. Evidence must come from native
/// observations; deserializing a caller-supplied inventory is not this contract.
pub trait CaptureBackend {
    fn observe(&mut self) -> Result<NativeState, Error>;
    fn snapshot(&mut self, names: &[String], operation_id: &str) -> Result<(), Error>;
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error>;
}

pub struct NativeCapture;
impl CaptureBackend for NativeCapture {
    fn observe(&mut self) -> Result<NativeState, Error> {
        state::observe()
    }
    fn snapshot(&mut self, names: &[String], operation_id: &str) -> Result<(), Error> {
        let mut args = vec![
            "snapshot".into(),
            "-o".into(),
            format!("zboot:capture={operation_id}"),
        ];
        args.extend_from_slice(names);
        native::run_mutating("zfs", &args).map(|_| ())
    }
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error> {
        // Resolve before and after the property query: neither names nor tags
        // alone establish that the marker belongs to this local incarnation.
        native::resolve_with(point, &mut native::run)?;
        let output = native::run(
            "zfs",
            &[
                "get".into(),
                "-H".into(),
                "-p".into(),
                "-o".into(),
                "name,property,value,source".into(),
                "zboot:capture".into(),
                point.name.clone(),
            ],
        )?;
        let row: Vec<_> = output.trim_end_matches('\n').split('\t').collect();
        if row.len() != 4
            || row[0] != point.name
            || row[1] != "zboot:capture"
            || row[3] != "local"
            || row[2].contains(['\n', '\r'])
        {
            return Err(Error::Inconsistent(
                "capture marker is missing, inherited or malformed".into(),
            ));
        }
        let marker = row[2].to_owned();
        native::resolve_with(point, &mut native::run)?;
        Ok(marker)
    }
}

pub fn capture_with(
    request: &CaptureRequest,
    backend: &mut impl CaptureBackend,
) -> Result<CaptureOutcome, Error> {
    crate::engine::validate_snapshot_name(&format!("validation/point@{}", request.name))?;

    let before = backend.observe()?;
    let planner = if request.recursive {
        SnapshotScope::plan
    } else {
        SnapshotScope::plan_exact
    };
    let plan = planner(
        &before.inspection,
        &before.dataset_properties,
        &before.pool_properties,
        &request.roots,
    )?;
    let names: Vec<_> = plan
        .datasets()
        .iter()
        .map(|dataset| format!("{}@{}", dataset.name, request.name))
        .collect();
    refuse_collisions(&before, &names)?;
    let operation_id = uuid::Uuid::new_v4().to_string();
    capture_prepared_with(&plan, &request.name, &operation_id, backend)
}

pub fn capture_prepared(
    plan: &SnapshotScope,
    name: &str,
    operation_id: &str,
) -> Result<CaptureOutcome, Error> {
    capture_prepared_with(plan, name, operation_id, &mut NativeCapture)
}

/// Capture an already admitted in-memory scope under its caller's durable ID.
/// The scope is revalidated against native observations before dispatch.
pub fn capture_prepared_with(
    plan: &SnapshotScope,
    name: &str,
    operation_id: &str,
    backend: &mut impl CaptureBackend,
) -> Result<CaptureOutcome, Error> {
    crate::engine::validate_snapshot_name(&format!("validation/point@{name}"))?;
    if !crate::engine::is_canonical_uuid_v4(operation_id) {
        return Err(Error::InvalidScope(
            "capture operation ID must be canonical UUIDv4".into(),
        ));
    }
    let operation_id = operation_id.to_owned();
    let names: Vec<_> = plan
        .datasets()
        .iter()
        .map(|dataset| format!("{}@{name}", dataset.name))
        .collect();
    let current = backend.observe()?;
    plan.revalidate(
        &current.inspection,
        &current.dataset_properties,
        &current.pool_properties,
    )?;
    refuse_collisions(&current, &names)?;

    // `zfs snapshot` is atomic only within one pool and refuses names from
    // several pools outright, so each pool gets its own command. A failure
    // in one pool does not stop the others; the observation below decides
    // the outcome either way.
    let mut pools: Vec<(&str, Vec<String>)> = Vec::new();
    for name in &names {
        let pool = name.split(['/', '@']).next().unwrap_or(name);
        match pools.iter_mut().find(|(p, _)| *p == pool) {
            Some((_, group)) => group.push(name.clone()),
            None => pools.push((pool, vec![name.clone()])),
        }
    }
    let errors: Vec<String> = pools
        .iter()
        .filter_map(|(_, group)| backend.snapshot(group, &operation_id).err())
        .map(|e| e.to_string())
        .collect();
    let command_error = (!errors.is_empty()).then(|| errors.join("; "));
    let after = match backend.observe() {
        Ok(state) => state,
        Err(error) => {
            return Ok(CaptureOutcome {
                operation_id,
                status: CaptureStatus::Uncertain,
                points: vec![],
                missing: names,
                detail: Some(format!(
                    "capture issued; outcome observation failed: {error}"
                )),
            });
        }
    };
    let mut outcome = CaptureOutcome {
        operation_id,
        status: CaptureStatus::Complete,
        points: vec![],
        missing: vec![],
        detail: command_error,
    };
    if let Err(error) = plan.revalidate(
        &after.inspection,
        &after.dataset_properties,
        &after.pool_properties,
    ) {
        outcome.status = CaptureStatus::Uncertain;
        outcome.detail = Some(format!("capture issued; dataset scope changed: {error}"));
    }
    let snapshots = after
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| Error::Inconsistent("capture observation omitted snapshots".into()))?;
    for name in names {
        let Some(snapshot) = snapshots.iter().find(|s| s.name == name) else {
            outcome.missing.push(name);
            continue;
        };
        let point = snapshot.point();
        let dataset = plan
            .datasets()
            .iter()
            .find(|d| {
                name.split_once('@')
                    .is_some_and(|(parent, _)| parent == d.name)
            })
            .unwrap();
        if point.dataset_guid != dataset.identity.guid
            || point.identity.pool_guid != dataset.identity.pool_guid
        {
            outcome.status = CaptureStatus::Uncertain;
            outcome.missing.push(name);
            continue;
        }
        match backend.capture_marker(&point) {
            Ok(marker) if marker == outcome.operation_id => outcome.points.push(point),
            other => {
                outcome.status = CaptureStatus::Uncertain;
                outcome.detail = Some(match other {
                    Err(e) => e.to_string(),
                    _ => "snapshot exists without this invocation's exact capture marker".into(),
                });
                outcome.missing.push(name);
            }
        }
    }
    if !outcome.missing.is_empty() && outcome.status == CaptureStatus::Complete {
        outcome.status = CaptureStatus::Partial;
    }
    Ok(outcome)
}

fn refuse_collisions(state: &NativeState, names: &[String]) -> Result<(), Error> {
    let snapshots = state
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| Error::Inconsistent("capture planning omitted snapshots".into()))?;
    if let Some(snapshot) = snapshots.iter().find(|s| names.contains(&s.name)) {
        return Err(Error::Inconsistent(format!(
            "capture name already exists: {}",
            snapshot.name
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        CanMount, Dataset, DatasetIdentity, DatasetKind, Encryption, Guid, Inspection, KeyStatus,
        ObjsetId, Pool, Snapshot, SnapshotIdentity, Txg,
        native::{NativeProperty, PropertyInventory},
    };
    use std::collections::BTreeMap;

    fn dataset(name: &str, id: u64) -> Dataset {
        Dataset {
            name: name.into(),
            kind: DatasetKind::Filesystem,
            guid: Guid::new(id),
            identity: DatasetIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(id),
                createtxg: Txg::new(id + 10),
                objsetid: ObjsetId::new(id + 20),
            },
            used_bytes: 0,
            available_bytes: 1000,
            referenced_bytes: 0,
            mountpoint: Some(format!("/{name}")),
            volume_size_bytes: None,
            mounted: Some(false),
            readonly: false,
            canmount: Some(CanMount::On),
            origin: None,
            encryption: Encryption::Off,
            keystatus: KeyStatus::Unencrypted,
            encryptionroot: None,
            staging: None,
            pending: None,
        }
    }
    fn prop(value: impl ToString) -> NativeProperty {
        NativeProperty {
            value: value.to_string(),
            source: "-".into(),
        }
    }
    fn fixture() -> NativeState {
        let datasets = vec![
            dataset("tank", 1),
            dataset("tank/data", 2),
            dataset("tank/data/child", 3),
            dataset("tank/other", 4),
        ];
        let dataset_properties = datasets
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    BTreeMap::from([
                        ("guid".into(), prop(d.identity.guid)),
                        ("createtxg".into(), prop(d.identity.createtxg)),
                        ("objsetid".into(), prop(d.identity.objsetid)),
                    ]),
                )
            })
            .collect();
        NativeState {
            inspection: Inspection {
                schema_version: 3,
                imported_only: true,
                non_atomic: true,
                recursive: true,
                requested_datasets: vec![],
                pools: vec![Pool {
                    name: "tank".into(),
                    guid: Guid::new(1),
                    size_bytes: 1000,
                    allocated_bytes: 0,
                    free_bytes: 1000,
                    health: "ONLINE".into(),
                    bootfs: None,
                }],
                datasets,
                snapshots: Some(vec![]),
            },
            dataset_properties,
            pool_properties: PropertyInventory::from([(
                "tank".into(),
                BTreeMap::from([("guid".into(), prop(1))]),
            )]),
        }
    }
    fn snapshot(name: &str, dataset_guid: Guid) -> Snapshot {
        Snapshot {
            name: name.into(),
            guid: Guid::new(dataset_guid.get() + 100),
            dataset_guid,
            identity: SnapshotIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(dataset_guid.get() + 100),
                createtxg: Txg::new(99),
                objsetid: ObjsetId::new(dataset_guid.get() + 200),
            },
            userrefs: 0,
            defer_destroy: false,
            clones: vec![],
            holds: vec![],
            creation_epoch_seconds: 1,
            used_bytes: 0,
            referenced_bytes: 0,
        }
    }
    struct Fake {
        state: NativeState,
        calls: Vec<Vec<String>>,
        marker: String,
        fail_reply: bool,
        partial: bool,
        foreign_marker: bool,
        late_pending: bool,
        observations: usize,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                state: fixture(),
                calls: vec![],
                marker: String::new(),
                fail_reply: false,
                partial: false,
                foreign_marker: false,
                late_pending: false,
                observations: 0,
            }
        }
    }
    impl CaptureBackend for Fake {
        fn observe(&mut self) -> Result<NativeState, Error> {
            self.observations += 1;
            if self.late_pending && self.observations == 2 {
                self.state.inspection.datasets[1].pending = Some("other".into());
            }
            Ok(self.state.clone())
        }
        fn snapshot(&mut self, names: &[String], operation_id: &str) -> Result<(), Error> {
            self.calls.push(names.to_vec());
            self.marker = operation_id.into();
            // As OpenZFS: one command never spans pools, and refuses whole.
            let pool = |n: &String| n.split(['/', '@']).next().unwrap().to_owned();
            if names.iter().any(|n| pool(n) != pool(&names[0])) {
                return Err(Error::Inconsistent("no snapshots were created".into()));
            }
            for (i, name) in names.iter().enumerate() {
                if self.partial && i > 0 {
                    continue;
                }
                let ds = self
                    .state
                    .inspection
                    .datasets
                    .iter()
                    .find(|d| name.starts_with(&format!("{}@", d.name)))
                    .unwrap();
                let mut point = snapshot(name, ds.guid);
                point.identity.pool_guid = ds.identity.pool_guid;
                self.state
                    .inspection
                    .snapshots
                    .as_mut()
                    .unwrap()
                    .push(point);
            }
            if self.fail_reply {
                Err(Error::Inconsistent("lost command reply".into()))
            } else {
                Ok(())
            }
        }
        fn capture_marker(&mut self, _: &SnapshotRef) -> Result<String, Error> {
            Ok(if self.foreign_marker {
                "foreign".into()
            } else {
                self.marker.clone()
            })
        }
    }
    fn request(recursive: bool) -> CaptureRequest {
        CaptureRequest {
            roots: vec!["tank/data".into()],
            name: "point".into(),
            recursive,
        }
    }

    #[test]
    fn prepared_capture_keeps_its_reserved_id_and_revalidates_the_frozen_scope() {
        let mut fake = Fake::default();
        let scope = SnapshotScope::plan(
            &fake.state.inspection,
            &fake.state.dataset_properties,
            &fake.state.pool_properties,
            &request(true).roots,
        )
        .unwrap();
        let id = "00112233-4455-4677-8899-aabbccddeeff";
        let result = capture_prepared_with(&scope, "point", id, &mut fake).unwrap();
        assert_eq!(result.operation_id, id);
        assert_eq!(fake.marker, id);
        assert_eq!(result.status, CaptureStatus::Complete);
        let mut unrelated = Fake::default();
        unrelated
            .state
            .inspection
            .datasets
            .retain(|dataset| dataset.name != "tank/other");
        assert_eq!(
            capture_prepared_with(&scope, "point", id, &mut unrelated)
                .unwrap()
                .status,
            CaptureStatus::Complete
        );
        let mut changed = Fake::default();
        changed
            .state
            .inspection
            .datasets
            .retain(|dataset| dataset.name != "tank/data/child");
        assert!(capture_prepared_with(&scope, "point", id, &mut changed).is_err());
        assert!(changed.calls.is_empty());
        let mut invalid = Fake::default();
        assert!(capture_prepared_with(&scope, "", id, &mut invalid).is_err());
        assert!(capture_prepared_with(&scope, "point", "foreign", &mut invalid).is_err());
        assert!(invalid.calls.is_empty());
    }

    #[test]
    fn recursive_capture_uses_frozen_explicit_members_and_verifies_marker() {
        let mut fake = Fake::default();
        let result = capture_with(&request(true), &mut fake).unwrap();
        assert_eq!(
            fake.calls,
            vec![vec!["tank/data@point", "tank/data/child@point"]]
        );
        assert_eq!(result.status, CaptureStatus::Complete);
        assert_eq!(result.points.len(), 2);
        assert!(result.missing.is_empty());
    }
    #[test]
    fn conventional_exact_capture_does_not_expand_descendants() {
        let mut fake = Fake::default();
        let result = capture_with(&request(false), &mut fake).unwrap();
        assert_eq!(fake.calls, vec![vec!["tank/data@point"]]);
        assert_eq!(result.points.len(), 1);
    }
    #[test]
    fn collisions_passive_scope_and_late_pending_issue_no_snapshot() {
        for case in 0..3 {
            let mut fake = Fake::default();
            match case {
                0 => fake
                    .state
                    .inspection
                    .snapshots
                    .as_mut()
                    .unwrap()
                    .push(snapshot("tank/data@point", Guid::new(2))),
                1 => fake.state.inspection.datasets[1].readonly = true,
                _ => fake.late_pending = true,
            }
            assert!(capture_with(&request(true), &mut fake).is_err());
            assert!(fake.calls.is_empty());
        }
    }
    #[test]
    fn lost_reply_is_reconciled_by_exact_identity_and_invocation_marker() {
        let mut fake = Fake {
            fail_reply: true,
            ..Fake::default()
        };
        let result = capture_with(&request(true), &mut fake).unwrap();
        assert_eq!(result.status, CaptureStatus::Complete);
        assert!(result.detail.unwrap().contains("lost command reply"));
        let mut fake = Fake {
            foreign_marker: true,
            ..Fake::default()
        };
        let result = capture_with(&request(true), &mut fake).unwrap();
        assert_eq!(result.status, CaptureStatus::Uncertain);
        assert!(result.points.is_empty());
    }
    #[test]
    fn exact_capture_across_pools_issues_one_command_per_pool() {
        let mut fake = Fake::default();
        let mut vault = dataset("vault", 5);
        let mut vault_data = dataset("vault/data", 6);
        for d in [&mut vault, &mut vault_data] {
            d.identity.pool_guid = Guid::new(2);
        }
        for d in [&vault, &vault_data] {
            fake.state.dataset_properties.insert(
                d.name.clone(),
                BTreeMap::from([
                    ("guid".into(), prop(d.identity.guid)),
                    ("createtxg".into(), prop(d.identity.createtxg)),
                    ("objsetid".into(), prop(d.identity.objsetid)),
                ]),
            );
        }
        fake.state.inspection.datasets.extend([vault, vault_data]);
        fake.state.inspection.pools.push(Pool {
            name: "vault".into(),
            guid: Guid::new(2),
            size_bytes: 1000,
            allocated_bytes: 0,
            free_bytes: 1000,
            health: "ONLINE".into(),
            bootfs: None,
        });
        fake.state
            .pool_properties
            .insert("vault".into(), BTreeMap::from([("guid".into(), prop(2))]));
        let request = CaptureRequest {
            roots: vec!["tank/other".into(), "vault/data".into()],
            name: "point".into(),
            recursive: false,
        };
        let result = capture_with(&request, &mut fake).unwrap();
        assert_eq!(
            result.status,
            CaptureStatus::Complete,
            "{:?}",
            result.detail
        );
        assert_eq!(result.points.len(), 2);
        assert_eq!(
            fake.calls,
            vec![
                vec!["tank/other@point".to_owned()],
                vec!["vault/data@point".to_owned()]
            ]
        );
    }
    #[test]
    fn partial_capture_preserves_verified_points_and_reports_missing_members() {
        let mut fake = Fake {
            fail_reply: true,
            partial: true,
            ..Fake::default()
        };
        let result = capture_with(&request(true), &mut fake).unwrap();
        assert_eq!(result.status, CaptureStatus::Partial);
        assert_eq!(result.points.len(), 1);
        assert_eq!(result.missing, vec!["tank/data/child@point"]);
        assert_eq!(fake.calls.len(), 1); // no blind compensating destroy or retry
    }
}
