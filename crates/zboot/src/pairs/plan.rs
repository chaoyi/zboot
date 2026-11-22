//! Pair plans, and pair publication behind receiver fencing and common
//! anchors for a bootstrap's nested pair, whose caller records the phases it
//! reaches. Every replay reobserves native state. Phases are progress, not
//! permission to repeat an unverified mutation or to bypass changed identities.
use crate::{
    history::{self, Side},
    observation::{self, HistoryBackend, NativeHistory},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zfs_tools::engine::{
    Error, SnapshotRef,
    attachment::{AttachmentBackend, NativeAttachment},
    management::{self, Endpoint, PairRecord, Placement, Role},
    mutation::{NativeMutation, PropertyKey, PropertyValue},
    pool_of,
    state::{self, NativeState},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequest {
    pub left: String,
    pub right: String,
    pub primary: Option<Side>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub endpoint: Endpoint,
    pub placement: Placement,
    pub mountpoint: Option<String>,
    pub snapshots: Vec<SnapshotRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundTree {
    pub endpoint: Endpoint,
    pub members: Vec<Member>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairPlan {
    pub schema_version: u32,
    pub left: BoundTree,
    pub right: BoundTree,
    pub primary: Side,
    pub anchors: Vec<(SnapshotRef, SnapshotRef)>,
    pub existing_pair: Option<String>,
}
/// The phases a nested pair records, in order, each once the effects before
/// it were verified. `Prepared` commits its plan: it is never planned again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Fenced,
    Anchored,
    Published,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairOutcome {
    pub operation_id: String,
    pub left: Endpoint,
    pub right: Endpoint,
    pub primary: Side,
    pub already_paired: bool,
}

impl PairPlan {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 {
            return Err(refuse("unsupported pair plan schema"));
        }
        for tree in [&self.left, &self.right] {
            zfs_tools::engine::validate_dataset_name(&tree.endpoint.name)?;
            // A pair joins two leaves: each side binds exactly its root.
            let [member] = tree.members.as_slice() else {
                return Err(refuse("pair plan must bind exactly one leaf on each side"));
            };
            if member.endpoint != tree.endpoint {
                return Err(refuse("pair plan must bind exactly one leaf on each side"));
            }
            let identity = &member.endpoint.identity;
            if [
                identity.pool_guid.get(),
                identity.guid.get(),
                identity.createtxg.get(),
                identity.objsetid.get(),
            ]
            .contains(&0)
                || member.placement.identity != *identity
            {
                return Err(refuse("pair plan member scope or incarnation is invalid"));
            }
            Placement::parse(&member.placement.encode()?)?;
            let mut snapshot_names = BTreeSet::new();
            let mut snapshot_guids = BTreeSet::new();
            let mut previous_txg = None;
            for point in &member.snapshots {
                zfs_tools::engine::validate_snapshot_name(&point.name)?;
                if point.name.split_once('@').map(|(name, _)| name)
                    != Some(member.endpoint.name.as_str())
                    || point.dataset_guid != identity.guid
                    || point.identity.pool_guid != identity.pool_guid
                    || [
                        point.identity.guid.get(),
                        point.identity.createtxg.get(),
                        point.identity.objsetid.get(),
                    ]
                    .contains(&0)
                    || !snapshot_names.insert(&point.name)
                    || !snapshot_guids.insert(point.identity.guid)
                    || previous_txg.is_some_and(|txg| txg >= point.identity.createtxg)
                {
                    return Err(refuse("pair snapshot scope or ancestry is invalid"));
                }
                previous_txg = Some(point.identity.createtxg);
            }
        }
        if history::contains_dataset(&self.left.endpoint.name, &self.right.endpoint.name)
            || history::contains_dataset(&self.right.endpoint.name, &self.left.endpoint.name)
        {
            return Err(refuse("pair plan scopes overlap"));
        }
        let (a, b) = (&self.left.members[0], &self.right.members[0]);
        let on_right: BTreeSet<_> = b.snapshots.iter().map(|p| p.identity.guid).collect();
        let on_left: BTreeSet<_> = a.snapshots.iter().map(|p| p.identity.guid).collect();
        let common_left: Vec<_> = a
            .snapshots
            .iter()
            .filter(|p| on_right.contains(&p.identity.guid))
            .collect();
        let common_right: Vec<_> = b
            .snapshots
            .iter()
            .filter(|p| on_left.contains(&p.identity.guid))
            .collect();
        if common_left.is_empty()
            || common_left
                .iter()
                .map(|p| p.identity.guid)
                .ne(common_right.iter().map(|p| p.identity.guid))
        {
            return Err(refuse("pair plan lacks consistent common ancestry"));
        }
        let anchor = (
            (*common_left.last().unwrap()).clone(),
            (*common_right.last().unwrap()).clone(),
        );
        let newer = |member: &Member, anchor: &SnapshotRef| {
            member
                .snapshots
                .iter()
                .position(|p| p == anchor)
                .is_some_and(|at| at + 1 < member.snapshots.len())
        };
        let ahead = match (newer(a, &anchor.0), newer(b, &anchor.1)) {
            (true, true) => return Err(refuse("pair plan histories have diverged")),
            (true, false) => Some(Side::Left),
            (false, true) => Some(Side::Right),
            (false, false) => None,
        };
        let expected = vec![anchor];
        if self.anchors != expected {
            return Err(refuse(
                "pair plan anchors must cover each mapped member's latest common snapshot",
            ));
        }
        if let Some(id) = &self.existing_pair {
            self.records(id).0.encode()?;
        } else if ahead.is_some_and(|side| side != self.primary) {
            return Err(refuse(
                "initial pair primary must contain the complete history",
            ));
        }
        Ok(())
    }
    /// The request that plans this pair again.
    pub(super) fn request(&self) -> PairRequest {
        PairRequest {
            left: self.left.endpoint.name.clone(),
            right: self.right.endpoint.name.clone(),
            primary: Some(self.primary),
        }
    }
    pub(super) fn receiver(&self) -> &BoundTree {
        match self.primary {
            Side::Left => &self.right,
            Side::Right => &self.left,
        }
    }
    pub(super) fn records(&self, id: &str) -> (PairRecord, PairRecord) {
        let left = PairRecord {
            schema_version: 1,
            pair_id: id.into(),
            endpoint: self.left.endpoint.clone(),
            peer: self.right.endpoint.clone(),
            role: if self.primary == Side::Left {
                Role::Primary
            } else {
                Role::Secondary
            },
        };
        let right = left.counterpart();
        (left, right)
    }
}

pub fn plan(request: &PairRequest) -> Result<PairPlan, Error> {
    let state = state::observe()?;
    one_host(&state, request, &mut crate::hostid::native_recorded)?;
    plan_with(&state, request, &mut NativeHistory)
}
/// The two trees' pools must record one hostid: pools of two hosts are never
/// paired. Checked before anything reopens them writable, which would stamp
/// the importer's hostid over what their labels recorded.
pub fn one_host(
    state: &NativeState,
    request: &PairRequest,
    recorded: &mut impl FnMut(&str, zfs_tools::engine::Guid) -> Result<u32, Error>,
) -> Result<(), Error> {
    let pool = |root: &str| -> Result<(String, zfs_tools::engine::Guid), Error> {
        let name = pool_of(root);
        state
            .inspection
            .pools
            .iter()
            .find(|pool| pool.name == name)
            .map(|pool| (name.to_owned(), pool.guid))
            .ok_or_else(|| Error::MissingScope(name.into()))
    };
    let (left, left_guid) = pool(&request.left)?;
    let (right, right_guid) = pool(&request.right)?;
    if left_guid == right_guid {
        return Ok(());
    }
    let left_hostid = recorded(&left, left_guid)?;
    let right_hostid = recorded(&right, right_guid)?;
    crate::hostid::require_one_host((&left, left_hostid), (&right, right_hostid))
        .map_err(|error| refuse(error.to_string()))
}
/// A pair joins two leaf datasets: a child under either side refuses, because
/// switching roles would mount a `canmount=on` child of the dormant side over
/// the live copy's path.
pub fn refuse_children(left: &str, right: &str, children: &[String]) -> Result<(), Error> {
    if children.is_empty() {
        return Ok(());
    }
    Err(refuse(format!(
        "a pair joins leaf datasets, but {left} or {right} has child datasets ({}); move them out or pair each leaf on its own",
        children.join(", ")
    )))
}
/// zboot writes only to a pool imported writable and without an altroot
/// (decision 8): a pool imported with `-R` shows every mountpoint under
/// another root, and zboot itself never imports one that way.
pub fn writable_pool_of(state: &NativeState, dataset: &str) -> Result<(), Error> {
    let pool = zfs_tools::engine::pool_of(dataset);
    let props = state
        .pool_properties
        .get(pool)
        .ok_or_else(|| refuse(format!("pool {pool} is not imported")))?;
    if props.get("readonly").is_none_or(|p| p.value != "off") {
        return Err(refuse(format!(
            "pool {pool} is imported read-only; import it writable first"
        )));
    }
    if props
        .get("altroot")
        .is_some_and(|p| !matches!(p.value.as_str(), "-" | ""))
    {
        return Err(refuse(format!(
            "pool {pool} is imported with an altroot (zpool import -R); zboot writes \
             nothing there: export it and import it again without -R"
        )));
    }
    Ok(())
}

pub fn plan_with(
    state: &NativeState,
    request: &PairRequest,
    backend: &mut impl HistoryBackend,
) -> Result<PairPlan, Error> {
    let left = observation::tree(state, &request.left, backend)?;
    let right = observation::tree(state, &request.right, backend)?;
    let admission = history::admit_pair(&left, &right).map_err(|e| refuse(e.to_string()))?;
    refuse_children(&request.left, &request.right, &admission.children)?;
    let root_record = management::bound_properties(state, &request.left)?
        .get(management::PAIR_PROPERTY)
        .map(|p| PairRecord::parse(&p.value))
        .transpose()?;
    let (primary, existing_pair) = if let Some(record) = root_record {
        management::ownership(state, &request.left)?;
        management::ownership(state, &request.right)?;
        let primary = if record.role == Role::Primary {
            Side::Left
        } else {
            Side::Right
        };
        if request.primary.is_some_and(|chosen| chosen != primary) {
            return Err(refuse(
                "pair does not switch existing ownership; use primary",
            ));
        }
        (primary, Some(record.pair_id))
    } else {
        if let (Some(ahead), Some(chosen)) = (admission.ahead, request.primary)
            && ahead != chosen
        {
            return Err(refuse(
                "initial pair primary must be the containing/ahead copy. Pair takes PRIMARY SECONDARY. Swap the arguments",
            ));
        }
        (
            admission.ahead.or(request.primary).unwrap_or(Side::Left),
            None,
        )
    };
    // The fenced copy receives every later sync, so it may not hold clones;
    // the working copy may (a fork of a boot environment).
    let (secondary, secondary_name) = match primary {
        Side::Left => (Side::Right, &request.right),
        Side::Right => (Side::Left, &request.left),
    };
    admission
        .refuse_receiver_clones(secondary, secondary_name)
        .map_err(|e| refuse(e.to_string()))?;
    crate::mounting::require_outside_boot_environment(
        state,
        if primary == Side::Left {
            &request.right
        } else {
            &request.left
        },
    )?;
    let bind = |root: &str| -> Result<BoundTree, Error> {
        let dataset = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == root)
            .ok_or_else(|| Error::MissingScope(root.into()))?;
        let endpoint = Endpoint {
            name: root.into(),
            identity: dataset.identity.clone(),
        };
        let properties = management::bound_properties(state, root)?;
        let placement = match properties
            .get(management::PLACEMENT_PROPERTY)
            .filter(|p| p.source == "local")
        {
            Some(p) => Placement::parse(&p.value)?,
            None => Placement::observed(dataset, properties),
        };
        let mut snapshots: Vec<_> = state
            .inspection
            .snapshots
            .as_ref()
            .unwrap()
            .iter()
            .filter(|s| s.name.split_once('@').is_some_and(|(name, _)| name == root))
            .map(|s| s.point())
            .collect();
        snapshots.sort_by_key(|p| p.identity.createtxg);
        let member = Member {
            endpoint: endpoint.clone(),
            placement,
            mountpoint: dataset.mountpoint.clone(),
            snapshots,
        };
        Ok(BoundTree {
            endpoint,
            members: vec![member],
        })
    };
    let left = bind(&request.left)?;
    let right = bind(&request.right)?;
    let point = |tree: &BoundTree| -> Result<SnapshotRef, Error> {
        tree.members[0]
            .snapshots
            .iter()
            .find(|s| s.identity.guid == admission.anchor)
            .cloned()
            .ok_or_else(|| refuse("admitted anchor disappeared from frozen inventory"))
    };
    let anchors = vec![(point(&left)?, point(&right)?)];
    let plan = PairPlan {
        schema_version: 1,
        left,
        right,
        primary,
        anchors,
        existing_pair,
    };
    plan.validate()?;
    validate_placement(state, &plan)?;
    Ok(plan)
}

fn validate_placement(state: &NativeState, plan: &PairPlan) -> Result<(), Error> {
    let primary = if plan.primary == Side::Left {
        &plan.left
    } else {
        &plan.right
    };
    for member in &primary.members {
        let Some(path) = &member.mountpoint else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        if state.inspection.datasets.iter().any(|d| {
            d.mounted == Some(true)
                && d.mountpoint.as_ref() == Some(path)
                && !history::contains_dataset(&plan.left.endpoint.name, &d.name)
                && !history::contains_dataset(&plan.right.endpoint.name, &d.name)
        }) {
            return Err(refuse(format!(
                "primary placement conflicts with another mounted dataset: {path}"
            )));
        }
    }
    Ok(())
}

/// Injectable operation boundary. Tests may interrupt typed effects while the
/// native adapter retains exact endpoint checks; callers own exclusive workflow use.
pub trait PairBackend: HistoryBackend {
    fn observe(&mut self) -> Result<NativeState, Error>;
    /// Complete identity-bound native properties, preserving sources.
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<std::collections::BTreeMap<String, zfs_tools::engine::native::NativeProperty>, Error>;
    /// `zpool sync` of the endpoint's pool, the endpoint bound before and after.
    fn sync(&mut self, endpoint: &Endpoint) -> Result<(), Error>;
    fn set_property(&mut self, endpoint: &Endpoint, value: &PropertyValue) -> Result<(), Error>;
    fn inherit_property(
        &mut self,
        endpoint: &Endpoint,
        key: PropertyKey,
        expected: &str,
    ) -> Result<Option<zfs_tools::engine::native::NativeProperty>, Error>;
    fn observe_point(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Snapshot, Error>;
    fn unmount(&mut self, endpoint: &Endpoint) -> Result<(), Error>;
    fn add_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error>;
    fn running_root(&mut self) -> Result<Option<String>, Error>;
}

#[derive(Default)]
pub struct NativePair {}
impl NativePair {
    pub fn new() -> Self {
        Self {}
    }
}
impl HistoryBackend for NativePair {
    fn written(
        &mut self,
        dataset: &zfs_tools::engine::Dataset,
        base: &SnapshotRef,
    ) -> Result<u64, Error> {
        NativeHistory.written(dataset, base)
    }
    fn ivset(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Guid, Error> {
        NativeHistory.ivset(point)
    }
}
impl PairBackend for NativePair {
    fn observe(&mut self) -> Result<NativeState, Error> {
        state::observe_with(&mut |program, args| zfs_tools::engine::native::run(program, args))
    }
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<std::collections::BTreeMap<String, zfs_tools::engine::native::NativeProperty>, Error>
    {
        NativeAttachment.properties(endpoint)
    }
    fn sync(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.properties(endpoint)?;
        zfs_tools::engine::native::run("zpool", &["sync".into(), pool_of(&endpoint.name).into()])?;
        self.properties(endpoint).map(drop)
    }
    fn set_property(&mut self, endpoint: &Endpoint, value: &PropertyValue) -> Result<(), Error> {
        NativeMutation::new().set(endpoint, value)
    }
    fn inherit_property(
        &mut self,
        endpoint: &Endpoint,
        key: PropertyKey,
        expected: &str,
    ) -> Result<Option<zfs_tools::engine::native::NativeProperty>, Error> {
        NativeMutation::new().inherit_exact(endpoint, key, expected)
    }
    fn observe_point(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Snapshot, Error> {
        let snapshot = zfs_tools::engine::observe_snapshot(&point.name)?;
        if snapshot.point() != *point {
            return Err(refuse("snapshot incarnation changed"));
        }
        Ok(snapshot)
    }
    fn unmount(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.properties(endpoint)?;
        zfs_tools::engine::native::run_mutating("zfs", &["unmount".into(), endpoint.name.clone()])
            .map(|_| ())
    }
    fn add_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
        self.observe_point(point)?;
        zfs_tools::engine::native::run_mutating(
            "zfs",
            &["hold".into(), tag.into(), point.name.clone()],
        )
        .map(|_| ())
    }
    fn running_root(&mut self) -> Result<Option<String>, Error> {
        crate::status::running_root().map_err(|error| refuse(error.to_string()))
    }
}

struct Runtime<'a, B: PairBackend> {
    backend: &'a mut B,
}
impl<B: PairBackend> Runtime<'_, B> {
    fn observe(&mut self) -> Result<NativeState, Error> {
        self.backend.observe()
    }
    fn backend(&mut self) -> &mut B {
        self.backend
    }
    fn set(&mut self, endpoint: &Endpoint, key: &str, value: &str) -> Result<(), Error> {
        let property = match key {
            management::PAIR_PROPERTY => PropertyValue::Pair(PairRecord::parse(value)?),
            management::PENDING_PROPERTY => PropertyValue::Pending(value.into()),
            _ => return Err(refuse("unsupported pair property mutation")),
        };
        self.backend.set_property(endpoint, &property)
    }
    fn clear_pending(&mut self, endpoint: &Endpoint, id: &str) -> Result<(), Error> {
        if self
            .backend
            .inherit_property(endpoint, PropertyKey::Pending, id)?
            .is_some()
        {
            return Err(refuse(
                "pending cleanup revealed inherited or new operation",
            ));
        }
        Ok(())
    }
    fn fence(&mut self, member: &Member) -> Result<(), Error> {
        crate::pairs::fence(
            &mut *self.backend,
            &member.endpoint,
            Some(&member.placement),
            crate::placement::Posture::AtRest,
        )
    }
    fn hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
        let before = self.backend.observe_point(point)?;
        if before.point() != *point || before.defer_destroy {
            return Err(refuse(
                "anchor incarnation changed or is deferred for deletion",
            ));
        }
        if before.holds.iter().any(|held| held == tag) {
            return Ok(());
        }
        let result = self.backend.add_hold(point, tag);
        let after = self.backend.observe_point(point)?;
        if after.point() == *point && after.holds.iter().any(|held| held == tag) {
            Ok(())
        } else {
            Err(result
                .err()
                .unwrap_or_else(|| refuse("common anchor protection was not verified")))
        }
    }
    fn refuse_running_receiver(&mut self, plan: &PairPlan) -> Result<(), Error> {
        refuse_running_receiver(self.backend.running_root()?.as_deref(), plan)
    }
}

/// Publish PLAN's pair under ID, which its caller reserved, recording each
/// phase it reaches with REACHED in the caller's own record. RECORDED is the
/// last phase recorded. With none, PLAN is planned again from native state
/// and `Prepared` commits it; from then on every effect is replayed and
/// reobserved, and PLAN is never planned again.
pub fn apply_with_id<B: PairBackend>(
    plan: &PairPlan,
    id: &str,
    recorded: Option<Phase>,
    backend: &mut B,
    reached: &mut impl FnMut(&mut B, Phase) -> Result<(), Error>,
) -> Result<PairOutcome, Error> {
    let parsed = uuid::Uuid::parse_str(id).map_err(|_| refuse("invalid pair operation ID"))?;
    if parsed.to_string() != id
        || parsed.get_version_num() != 4
        || parsed.get_variant() != uuid::Variant::RFC4122
    {
        return Err(refuse("pair operation ID must be canonical UUIDv4"));
    }
    let mut runtime = Runtime { backend };
    plan.validate()?;
    if recorded.is_none() {
        let state = runtime.observe()?;
        let fresh = plan_with(&state, &plan.request(), runtime.backend())?;
        if &fresh != plan {
            return Err(refuse("pair plan changed before execution"));
        }
        runtime.refuse_running_receiver(plan)?;
    }
    (|| {
        if recorded.is_none() {
            reached(runtime.backend(), Phase::Prepared)?;
        }
        execute(&mut runtime, plan, id, true, reached)
    })()
    .map_err(|error| {
        zfs_tools::engine::effect::operation_hint(id);
        refuse(format!(
            "pair operation {id} needs reconciliation on {} and {}: {error}",
            plan.left.endpoint.name, plan.right.endpoint.name
        ))
    })
}

/// Publish PLAN's pair under ID for the `pair` verb, whose own record
/// committed the plan: REACHED records each later phase there. The endpoints
/// carry no pending mark meanwhile, so an interrupted `pair` leaves its
/// working copy usable.
pub(super) fn publish<B: PairBackend>(
    plan: &PairPlan,
    id: &str,
    backend: &mut B,
    reached: &mut impl FnMut(&mut B, Phase) -> Result<(), Error>,
) -> Result<PairOutcome, Error> {
    execute(&mut Runtime { backend }, plan, id, false, reached)
}

/// The one way a pair is published: fence the receiver, hold the common
/// anchors on both sides, write both records, each step verified from native
/// state and the plan made again in between. With MARKS both endpoints carry
/// `zboot:pending=ID` until the records are verified, which a bootstrapping
/// `sync` needs once it has cleared its own marks.
fn execute<B: PairBackend>(
    runtime: &mut Runtime<'_, B>,
    plan: &PairPlan,
    id: &str,
    marks: bool,
    reached: &mut impl FnMut(&mut B, Phase) -> Result<(), Error>,
) -> Result<PairOutcome, Error> {
    plan.validate()?;
    runtime.refuse_running_receiver(plan)?;
    crate::mounting::require_outside_boot_environment(
        &runtime.observe()?,
        &plan.receiver().endpoint.name,
    )?;
    let (left_record, right_record) = plan.records(id);
    left_record.validate()?;
    right_record.validate()?;
    // Each phase is recorded only once the effects before it are verified;
    // a replay repeats every effect, each of them idempotent.
    if marks {
        for endpoint in [&plan.left.endpoint, &plan.right.endpoint] {
            let properties = runtime.backend().properties(endpoint)?;
            if let Some(p) = properties.get(management::PENDING_PROPERTY)
                && (p.source != "local" || p.value != id)
            {
                return Err(refuse("another pending operation occupies the endpoint"));
            }
            runtime.set(endpoint, management::PENDING_PROPERTY, id)?;
        }
    }
    revalidate(runtime, plan, id)?;
    // Children first avoids a parent unmount hiding still-mounted descendants.
    for member in plan.receiver().members.iter().rev() {
        runtime.fence(member)?;
    }
    runtime.backend().sync(&plan.receiver().endpoint)?;
    verify_fence(&runtime.observe()?, plan)?;
    revalidate(runtime, plan, id)?;
    reached(runtime.backend(), Phase::Fenced)?;
    let tag = format!("zboot:anchor:{id}");
    for (a, b) in &plan.anchors {
        runtime.hold(a, &tag)?;
        runtime.hold(b, &tag)?;
    }
    verify_anchors(&runtime.observe()?, plan, &tag)?;
    reached(runtime.backend(), Phase::Anchored)?;
    revalidate(runtime, plan, id)?;
    runtime.set(
        &plan.left.endpoint,
        management::PAIR_PROPERTY,
        &left_record.encode()?,
    )?;
    runtime.set(
        &plan.right.endpoint,
        management::PAIR_PROPERTY,
        &right_record.encode()?,
    )?;
    verify_publication(&runtime.observe()?, plan, id)?;
    reached(runtime.backend(), Phase::Published)?;
    if marks {
        for endpoint in [&plan.left.endpoint, &plan.right.endpoint] {
            runtime.clear_pending(endpoint, id)?;
        }
    }
    verify_published(&runtime.observe()?, plan, id)?;
    Ok(outcome(plan, id, false))
}

/// STATE without this pair's own pending markers and expected publication.
fn clean_state(state: &NativeState, plan: &PairPlan, id: &str) -> Result<NativeState, Error> {
    let mut clean = state.clone();
    let records = plan.records(id);
    for (tree, expected) in [(&plan.left, &records.0), (&plan.right, &records.1)] {
        for member in &tree.members {
            let props = clean
                .dataset_properties
                .get_mut(&member.endpoint.name)
                .ok_or_else(|| refuse("pair member properties disappeared"))?;
            let source = if member.endpoint == tree.endpoint {
                "local".into()
            } else {
                format!("inherited from {}", tree.endpoint.name)
            };
            let keys: Vec<_> = props.keys().cloned().collect();
            for key in keys {
                let property = &props[&key];
                if key == management::PENDING_PROPERTY {
                    if property.value != id || property.source != source {
                        return Err(refuse("foreign pending operation or source"));
                    }
                    props.remove(&key);
                } else if key == management::PAIR_PROPERTY {
                    if property.source != source || PairRecord::parse(&property.value)? != *expected
                    {
                        return Err(refuse("pair publication drifted"));
                    }
                    props.remove(&key);
                }
            }
        }
    }
    Ok(clean)
}
fn revalidate(
    runtime: &mut Runtime<'_, impl PairBackend>,
    plan: &PairPlan,
    id: &str,
) -> Result<(), Error> {
    let current = runtime.observe()?;
    let clean = clean_state(&current, plan, id)?;
    let fresh = plan_with(&clean, &plan.request(), runtime.backend())?;
    if fresh != *plan {
        return Err(refuse(
            "pair scope, history or placement changed after durable planning",
        ));
    }
    Ok(())
}
/// The receiver is fenced: every planned member is still that dataset and at
/// rest, and so is everything else now in its tree, outside any boot
/// environment.
fn verify_fence(state: &NativeState, plan: &PairPlan) -> Result<(), Error> {
    crate::pairs::verify_fenced(state, &plan.receiver().endpoint.name)?;
    for member in &plan.receiver().members {
        let d = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == member.endpoint.name)
            .ok_or_else(|| refuse("fenced receiver disappeared"))?;
        if d.identity != member.endpoint.identity || !crate::pairs::at_rest(state, d) {
            return Err(refuse("receiver is not fully fenced"));
        }
    }
    Ok(())
}
/// A pair fences its receiving tree, which therefore cannot hold the running
/// root.
pub(super) fn refuse_running_receiver(running: Option<&str>, plan: &PairPlan) -> Result<(), Error> {
    if running.is_some_and(|root| history::contains_dataset(&plan.receiver().endpoint.name, root)) {
        return Err(refuse(
            "the receiving tree contains the running root; pair from the Menu or choose the running side as primary",
        ));
    }
    Ok(())
}
pub(super) fn verify_anchors(state: &NativeState, plan: &PairPlan, tag: &str) -> Result<(), Error> {
    for point in plan.anchors.iter().flat_map(|(a, b)| [a, b]) {
        let held = state
            .inspection
            .snapshots
            .as_ref()
            .and_then(|s| s.iter().find(|s| s.point() == *point))
            .is_some_and(|s| s.holds.iter().any(|h| h == tag));
        if !held {
            return Err(refuse(format!("common anchor {} is not held", point.name)));
        }
    }
    Ok(())
}
/// Pair ID is on disk as PLAN has it: the receiver fenced, the anchors held
/// and both records local and exact.
fn verify_publication(state: &NativeState, plan: &PairPlan, id: &str) -> Result<(), Error> {
    verify_fence(state, plan)?;
    verify_anchors(state, plan, &format!("zboot:anchor:{id}"))?;
    let (left, right) = plan.records(id);
    for expected in [left, right] {
        let properties = management::bound_properties(state, &expected.endpoint.name)?;
        let published = properties.get(management::PAIR_PROPERTY).is_some_and(|p| {
            p.source == "local" && PairRecord::parse(&p.value).ok().as_ref() == Some(&expected)
        });
        if !published {
            return Err(refuse(format!(
                "{}'s pair record is not the published one",
                expected.endpoint.name
            )));
        }
    }
    Ok(())
}
/// [`verify_publication`], and both endpoints are a valid mutual pair with
/// nothing else pending on them.
pub(super) fn verify_published(
    state: &NativeState,
    plan: &PairPlan,
    id: &str,
) -> Result<(), Error> {
    verify_publication(state, plan, id)?;
    management::ownership(state, &plan.left.endpoint.name)?;
    management::ownership(state, &plan.right.endpoint.name)?;
    Ok(())
}
pub(super) fn outcome(plan: &PairPlan, id: &str, already_paired: bool) -> PairOutcome {
    PairOutcome {
        operation_id: id.into(),
        left: plan.left.endpoint.clone(),
        right: plan.right.endpoint.clone(),
        primary: plan.primary,
        already_paired,
    }
}
fn refuse(detail: impl Into<String>) -> Error {
    Error::Refused(detail.into())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use zfs_tools::engine::{DatasetIdentity, Guid, ObjsetId, SnapshotIdentity, Txg};

    const ID: &str = "11111111-1111-4111-8111-111111111111";
    pub(crate) fn member(name: &str, pool: u64, guid: u64, history: &[u64]) -> Member {
        let identity = DatasetIdentity {
            pool_guid: Guid::new(pool),
            guid: Guid::new(guid),
            createtxg: Txg::new(1),
            objsetid: ObjsetId::new(guid),
        };
        Member {
            endpoint: Endpoint {
                name: name.into(),
                identity: identity.clone(),
            },
            placement: Placement {
                schema_version: 1,
                identity,
                readonly: false,
                canmount: Some(management::MountMode::On),
                volmode: None,
            },
            mountpoint: Some(format!("/{name}")),
            snapshots: history
                .iter()
                .enumerate()
                .map(|(i, &snapshot)| SnapshotRef {
                    name: format!("{name}@s{i}"),
                    dataset_guid: Guid::new(guid),
                    identity: SnapshotIdentity {
                        pool_guid: Guid::new(pool),
                        guid: Guid::new(snapshot),
                        createtxg: Txg::new(10 + i as u64),
                        objsetid: ObjsetId::new(1000 + i as u64),
                    },
                })
                .collect(),
        }
    }
    fn fixture() -> PairPlan {
        let a = member("a/data", 1, 10, &[100, 101]);
        let b = member("b/data", 2, 20, &[100, 101]);
        PairPlan {
            schema_version: 1,
            anchors: vec![(a.snapshots[1].clone(), b.snapshots[1].clone())],
            left: BoundTree {
                endpoint: a.endpoint.clone(),
                members: vec![a],
            },
            right: BoundTree {
                endpoint: b.endpoint.clone(),
                members: vec![b],
            },
            primary: Side::Left,
            existing_pair: None,
        }
    }
    #[test]
    fn frozen_plan_requires_the_exact_newest_common_anchor() {
        let good = fixture();
        good.validate().unwrap();
        for case in 0..8 {
            let mut bad = good.clone();
            match case {
                0 => {
                    bad.anchors.pop();
                }
                1 => {
                    bad.anchors.push(bad.anchors[0].clone());
                }
                2 => {
                    bad.anchors[0] = (
                        bad.left.members[0].snapshots[0].clone(),
                        bad.right.members[0].snapshots[0].clone(),
                    )
                }
                3 => bad.anchors[0] = (bad.anchors[0].1.clone(), bad.anchors[0].0.clone()),
                4 => bad.anchors[0].1 = bad.right.members[0].snapshots[0].clone(),
                5 => bad.left.members[0].snapshots[1].identity.guid = Guid::new(999),
                6 => bad.left.members[0].snapshots[0].identity.guid = Guid::new(101),
                _ => bad.left.members[0].snapshots.clear(),
            }
            assert!(bad.validate().is_err(), "case {case}");
        }
    }
    #[test]
    fn frozen_plan_binds_one_leaf_per_side_and_exact_incarnations() {
        let good = fixture();
        for case in 0..8 {
            let mut bad = good.clone();
            match case {
                0 => bad.left.members.push(member("a/data/child", 1, 11, &[200])),
                1 => bad.left.members.clear(),
                2 => bad.left.members[0].endpoint.name = "a/other".into(),
                3 => {
                    bad.left.members[0].snapshots[1].name =
                        bad.left.members[0].snapshots[0].name.clone()
                }
                4 => {
                    bad.left.members[0].snapshots[1].identity.createtxg =
                        bad.left.members[0].snapshots[0].identity.createtxg
                }
                5 => bad.left.members[0].snapshots[1].identity.objsetid = ObjsetId::new(0),
                6 => bad.left.members[0].placement.identity.guid = Guid::new(0),
                _ => bad.existing_pair = Some("not-an-id".into()),
            }
            assert!(bad.validate().is_err(), "case {case}");
        }
    }
    #[test]
    fn pruned_older_history_pairs_and_the_primary_holds_the_newest_snapshots() {
        let mut plan = fixture();
        plan.right.members[0].snapshots.pop();
        plan.anchors[0] = (
            plan.left.members[0].snapshots[0].clone(),
            plan.right.members[0].snapshots[0].clone(),
        );
        plan.validate().unwrap();
        plan.primary = Side::Right;
        assert!(plan.validate().is_err());
        plan.existing_pair = Some(ID.into());
        plan.validate().unwrap();
        // The left side pruned s0; both still share s1, the newest common snapshot.
        let mut pruned = fixture();
        pruned.left.members[0].snapshots.remove(0);
        pruned.validate().unwrap();
        // Diverged: each side has a snapshot the other lacks after the anchor.
        let mut diverged = fixture();
        diverged.left.members[0].snapshots[1].identity.guid = Guid::new(301);
        diverged.right.members[0].snapshots[1].identity.guid = Guid::new(302);
        diverged.anchors[0] = (
            diverged.left.members[0].snapshots[0].clone(),
            diverged.right.members[0].snapshots[0].clone(),
        );
        assert!(diverged.validate().is_err());
    }
    #[derive(Clone)]
    pub(crate) struct Fake {
        pub(crate) members: Vec<Member>,
        pub(crate) properties: zfs_tools::engine::native::PropertyInventory,
        pub(crate) mounted: BTreeSet<String>,
        pub(crate) holds: std::collections::BTreeMap<String, BTreeSet<String>>,
        pub(crate) effects: usize,
        pub(crate) cut: Option<(usize, bool)>,
        pub(crate) crashed: bool,
        pub(crate) running: Option<String>,
        pub(crate) written: std::collections::BTreeMap<String, u64>,
        pub(crate) ivsets: std::collections::BTreeMap<String, Guid>,
        pub(crate) encrypted: bool,
        /// Encryption roots of datasets that inherit their key; every other
        /// encrypted dataset is its own root.
        pub(crate) roots: std::collections::BTreeMap<String, String>,
        pub(crate) deferred: BTreeSet<String>,
        pub(crate) clones: std::collections::BTreeMap<String, String>,
        /// The last pair phase recorded, as a caller's record would keep it.
        pub(crate) recorded: Option<Phase>,
    }
    impl Fake {
        pub(crate) fn new() -> Self {
            let plan = fixture();
            let members: Vec<_> = [member("a", 1, 3, &[]), member("b", 2, 4, &[])]
                .into_iter()
                .chain(plan.left.members)
                .chain(plan.right.members)
                .collect();
            Self {
                mounted: members.iter().map(|m| m.endpoint.name.clone()).collect(),
                members,
                properties: Default::default(),
                holds: Default::default(),
                effects: 0,
                cut: None,
                crashed: false,
                running: None,
                written: Default::default(),
                ivsets: Default::default(),
                encrypted: false,
                roots: Default::default(),
                deferred: Default::default(),
                clones: Default::default(),
                recorded: None,
            }
        }
        pub(crate) fn alive(&self) -> Result<(), Error> {
            if self.crashed {
                Err(refuse("simulated process loss"))
            } else {
                Ok(())
            }
        }
        pub(crate) fn before(&mut self) -> Result<(), Error> {
            self.alive()?;
            self.effects += 1;
            if self.cut == Some((self.effects, false)) {
                self.crashed = true;
            }
            self.alive()
        }
        pub(crate) fn after(&mut self) -> Result<(), Error> {
            if self.cut == Some((self.effects, true)) {
                self.crashed = true;
            }
            self.alive()
        }
        pub(crate) fn effective(
            &self,
            name: &str,
        ) -> std::collections::BTreeMap<String, zfs_tools::engine::native::NativeProperty> {
            let mut result = std::collections::BTreeMap::from([
                (
                    "readonly".into(),
                    zfs_tools::engine::native::NativeProperty {
                        value: "off".into(),
                        source: "default".into(),
                    },
                ),
                (
                    "canmount".into(),
                    zfs_tools::engine::native::NativeProperty {
                        value: "on".into(),
                        source: "default".into(),
                    },
                ),
                (
                    "volmode".into(),
                    zfs_tools::engine::native::NativeProperty {
                        value: "default".into(),
                        source: "default".into(),
                    },
                ),
            ]);
            if let Some(member) = self.members.iter().find(|m| m.endpoint.name == name) {
                result.insert(
                    "mountpoint".into(),
                    zfs_tools::engine::native::NativeProperty {
                        value: member.mountpoint.clone().unwrap_or_else(|| "none".into()),
                        source: "default".into(),
                    },
                );
            }
            for member in &self.members {
                if !history::contains_dataset(&member.endpoint.name, name) {
                    continue;
                }
                if let Some(props) = self.properties.get(&member.endpoint.name) {
                    for (key, value) in props {
                        let mut value = value.clone();
                        if member.endpoint.name != name {
                            if key == "canmount" {
                                continue;
                            }
                            if key == "mountpoint" && value.value.starts_with('/') {
                                // As ZFS: a child of `/` mounts at `/child`.
                                value.value = format!(
                                    "{}{}",
                                    value.value.trim_end_matches('/'),
                                    &name[member.endpoint.name.len()..]
                                );
                            }
                            value.source = format!("inherited from {}", member.endpoint.name);
                        }
                        result.insert(key.clone(), value);
                    }
                }
            }
            result
        }
        pub(crate) fn state(&self) -> Result<NativeState, Error> {
            self.alive()?;
            let mut data = String::new();
            let mut snapshots = String::new();
            let mut hold_rows = String::new();
            let mut properties = zfs_tools::engine::native::PropertyInventory::new();
            for member in &self.members {
                let ep = &member.endpoint;
                let mut props = self.effective(&ep.name);
                let readonly = props
                    .get("readonly")
                    .map(|p| p.value.as_str())
                    .unwrap_or("off");
                let canmount = props
                    .get("canmount")
                    .map(|p| p.value.as_str())
                    .unwrap_or("on");
                let volume = member.placement.canmount.is_none();
                let mountpoint = props
                    .get("mountpoint")
                    .map(|property| property.value.clone())
                    .unwrap_or_else(|| member.mountpoint.clone().unwrap_or_else(|| "-".into()));
                data.push_str(&format!(
                    "{}\t{}\t{}\t100\t900\t80\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\toff\t-\t-\t-\t-\n",
                    ep.name,
                    if volume { "volume" } else { "filesystem" },
                    ep.identity.guid,
                    if volume { "-" } else { &mountpoint },
                    if volume { "1048576" } else { "-" },
                    ep.identity.createtxg,
                    ep.identity.objsetid,
                    if volume {
                        "-"
                    } else if self.mounted.contains(&ep.name) {
                        "yes"
                    } else {
                        "no"
                    },
                    readonly,
                    if volume { "-" } else { canmount },
                    "-"
                ));
                for (key, value) in [
                    ("guid", ep.identity.guid.get()),
                    ("createtxg", ep.identity.createtxg.get()),
                    ("objsetid", ep.identity.objsetid.get()),
                ] {
                    props.insert(
                        key.into(),
                        zfs_tools::engine::native::NativeProperty {
                            value: value.to_string(),
                            source: "-".into(),
                        },
                    );
                }
                properties.insert(ep.name.clone(), props);
                for point in &member.snapshots {
                    let holds = self.holds.get(&point.name).cloned().unwrap_or_default();
                    snapshots.push_str(&format!(
                        "{}\t{}\t1700000000\t0\t20\t{}\t{}\t{}\toff\t-\n",
                        point.name,
                        point.identity.guid,
                        point.identity.createtxg,
                        point.identity.objsetid,
                        holds.len()
                    ));
                    for tag in holds {
                        hold_rows.push_str(&format!("{}\t{tag}\t1700000000\n", point.name));
                    }
                }
            }
            if self.encrypted {
                data = data
                    .lines()
                    .map(|line| {
                        let mut fields: Vec<_> = line.split('\t').map(str::to_owned).collect();
                        if self
                            .effective(&fields[0])
                            .get("encryption")
                            .is_some_and(|property| property.value == "off")
                        {
                            fields[14] = "off".into();
                            fields[15] = "-".into();
                            fields[16] = "-".into();
                        } else {
                            fields[14] = "aes-256-gcm".into();
                            fields[15] = "available".into();
                            fields[16] = self
                                .roots
                                .get(&fields[0])
                                .cloned()
                                .unwrap_or(fields[0].clone());
                        }
                        fields.join("\t") + "\n"
                    })
                    .collect();
            }
            snapshots = snapshots
                .lines()
                .map(|line| {
                    let mut fields: Vec<_> = line.split('\t').map(str::to_owned).collect();
                    if self.deferred.contains(&fields[0]) {
                        fields[8] = "on".into();
                    }
                    if let Some(clone) = self.clones.get(&fields[0]) {
                        fields[9] = clone.clone();
                    }
                    fields.join("\t") + "\n"
                })
                .collect();
            let inspection = zfs_tools::engine::native::inspect_with(
                &zfs_tools::engine::InspectRequest::new(vec![], true)?,
                |program, args| match (program, args[0].as_str()) {
                    ("zpool", "list") => Ok(self
                        .members
                        .iter()
                        .filter(|m| !m.endpoint.name.contains('/'))
                        .map(|m| {
                            format!(
                                "{}\t{}\t1000\t100\t900\tONLINE\t-\n",
                                m.endpoint.name, m.endpoint.identity.pool_guid
                            )
                        })
                        .collect()),
                    ("zfs", "list") if args.iter().any(|a| a == "filesystem,volume") => {
                        Ok(data.clone())
                    }
                    ("zfs", "list") => Ok(snapshots.clone()),
                    ("zfs", "holds") => Ok(hold_rows.clone()),
                    _ => panic!("unexpected query {program} {args:?}"),
                },
            )?;
            let pool_properties = [("a", "1"), ("b", "2")]
                .into_iter()
                .filter(|(name, _)| self.members.iter().any(|m| m.endpoint.name == *name))
                .map(|(name, guid)| {
                    (
                        name.into(),
                        [(
                            "guid".into(),
                            zfs_tools::engine::native::NativeProperty {
                                value: guid.into(),
                                source: "-".into(),
                            },
                        )]
                        .into_iter()
                        .collect(),
                    )
                })
                .collect();
            Ok(NativeState {
                inspection,
                dataset_properties: properties,
                pool_properties,
            })
        }
    }
    impl Fake {
        pub(crate) fn set(
            &mut self,
            endpoint: &Endpoint,
            values: &[(String, String)],
        ) -> Result<(), Error> {
            self.before()?;
            for (key, value) in values {
                self.properties
                    .entry(endpoint.name.clone())
                    .or_default()
                    .insert(
                        key.clone(),
                        zfs_tools::engine::native::NativeProperty {
                            value: value.clone(),
                            source: "local".into(),
                        },
                    );
            }
            self.after()
        }
        pub(crate) fn inherit(&mut self, endpoint: &Endpoint, key: &str) -> Result<(), Error> {
            self.before()?;
            self.properties
                .entry(endpoint.name.clone())
                .or_default()
                .remove(key);
            self.after()
        }
    }
    /// A record write of PHASE, cut like any other effect.
    fn record(fake: &mut Fake, phase: Phase) -> Result<(), Error> {
        fake.before()?;
        fake.recorded = fake.recorded.max(Some(phase));
        fake.after()
    }
    impl HistoryBackend for Fake {
        fn written(
            &mut self,
            dataset: &zfs_tools::engine::Dataset,
            _: &SnapshotRef,
        ) -> Result<u64, Error> {
            self.alive()?;
            Ok(*self.written.get(&dataset.name).unwrap_or(&0))
        }
        fn ivset(&mut self, point: &SnapshotRef) -> Result<Guid, Error> {
            self.alive()?;
            Ok(*self.ivsets.get(&point.name).unwrap_or(&Guid::new(999)))
        }
    }
    impl PairBackend for Fake {
        fn observe(&mut self) -> Result<NativeState, Error> {
            self.state()
        }
        fn properties(
            &mut self,
            endpoint: &Endpoint,
        ) -> Result<
            std::collections::BTreeMap<String, zfs_tools::engine::native::NativeProperty>,
            Error,
        > {
            self.alive()?;
            assert!(self.members.iter().any(|m| m.endpoint == *endpoint));
            Ok(self.effective(&endpoint.name))
        }
        fn sync(&mut self, _: &Endpoint) -> Result<(), Error> {
            self.before()?;
            self.after()
        }
        fn set_property(
            &mut self,
            endpoint: &Endpoint,
            value: &PropertyValue,
        ) -> Result<(), Error> {
            if matches!(value, PropertyValue::Pair(_)) {
                let state = self.state()?;
                let plan = fixture();
                verify_fence(&state, &plan)?;
                verify_anchors(&state, &plan, &format!("zboot:anchor:{ID}"))?;
            }
            self.set(
                endpoint,
                &[(value.key().native().into(), value.encode(endpoint)?)],
            )
        }
        fn inherit_property(
            &mut self,
            endpoint: &Endpoint,
            key: PropertyKey,
            expected: &str,
        ) -> Result<Option<zfs_tools::engine::native::NativeProperty>, Error> {
            if let Some(p) = self.effective(&endpoint.name).get(key.native()) {
                assert_eq!(p.value, expected);
                assert_eq!(p.source, "local");
            }
            self.inherit(endpoint, key.native())?;
            Ok(self.effective(&endpoint.name).get(key.native()).cloned())
        }
        fn observe_point(
            &mut self,
            point: &SnapshotRef,
        ) -> Result<zfs_tools::engine::Snapshot, Error> {
            self.state()?
                .inspection
                .snapshots
                .as_ref()
                .unwrap()
                .iter()
                .find(|s| s.point() == *point)
                .cloned()
                .ok_or_else(|| refuse("point absent"))
        }
        fn unmount(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
            assert!(endpoint.name.starts_with("b/data"));
            self.before()?;
            self.mounted.remove(&endpoint.name);
            self.after()
        }
        fn add_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
            self.before()?;
            assert!(
                self.holds
                    .entry(point.name.clone())
                    .or_default()
                    .insert(tag.into())
            );
            self.after()
        }
        fn running_root(&mut self) -> Result<Option<String>, Error> {
            self.alive()?;
            Ok(self.running.clone())
        }
    }
    #[test]
    fn native_observation_and_pair_execution_publish_only_after_fence_and_holds() {
        let mut fake = Fake::new();
        let plan = plan_with(
            &fake.state().unwrap(),
            &PairRequest {
                left: "a/data".into(),
                right: "b/data".into(),
                primary: None,
            },
            &mut fake,
        )
        .unwrap();
        assert_eq!(plan, fixture());
        let mut phases = Vec::new();
        apply_with_id(&plan, ID, None, &mut fake, &mut |fake: &mut Fake, phase| {
            phases.push((phase, fake.effects));
            Ok(())
        })
        .unwrap();
        // Each phase is recorded in order, once its effects are verified.
        let order: Vec<_> = phases.iter().map(|(phase, _)| *phase).collect();
        assert_eq!(
            order,
            [
                Phase::Prepared,
                Phase::Fenced,
                Phase::Anchored,
                Phase::Published
            ]
        );
        assert_eq!(phases[0].1, 0, "Prepared commits before any effect");
        verify_publication(&fake.state().unwrap(), &plan, ID).unwrap();
        assert!(
            fake.properties
                .values()
                .all(|p| !p.contains_key(management::PENDING_PROPERTY))
        );
        // A replay from the last phase changes nothing it does not repeat.
        let members = fake.members.clone();
        apply_with_id(
            &plan,
            ID,
            Some(Phase::Published),
            &mut fake,
            &mut |_: &mut Fake, _| Ok(()),
        )
        .unwrap();
        assert_eq!(fake.members, members);
    }

    #[test]
    fn every_pair_effect_interruption_recovers_from_its_recorded_phase() {
        let plan = fixture();
        let mut reference = Fake::new();
        apply_with_id(&plan, ID, None, &mut reference, &mut record).unwrap();
        assert_eq!(reference.recorded, Some(Phase::Published));
        let effects = reference.effects;
        let mut recovered = 0;
        for cut in 1..=effects {
            for after in [false, true] {
                let mut fake = Fake::new();
                fake.cut = Some((cut, after));
                let error = apply_with_id(&plan, ID, None, &mut fake, &mut record).unwrap_err();
                assert!(error.to_string().contains(ID), "cut {cut} {after}: {error}");
                fake.crashed = false;
                fake.cut = None;
                if fake.recorded.is_none() {
                    // Nothing was committed, and nothing done.
                    assert!(fake.holds.is_empty());
                    assert!(fake.properties.values().all(|p| p.is_empty()));
                }
                apply_with_id(&plan, ID, fake.recorded, &mut fake, &mut record)
                    .unwrap_or_else(|error| panic!("cut {cut} after={after}: {error}"));
                verify_publication(&fake.state().unwrap(), &plan, ID).unwrap();
                assert_eq!(fake.members, reference.members);
                assert_eq!(fake.holds, reference.holds);
                assert_eq!(fake.properties, reference.properties, "cut {cut} {after}");
                assert_eq!(fake.recorded, Some(Phase::Published));
                recovered += 1;
            }
        }
        assert_eq!(recovered, 2 * effects);
        assert!(effects > 10, "{effects}");
    }
    #[test]
    fn running_receiver_and_invalid_id_refuse_before_effects_and_on_resume() {
        let plan = fixture();
        let mut fake = Fake::new();
        fake.running = Some("b/data/child".into());
        assert!(apply_with_id(&plan, ID, None, &mut fake, &mut record).is_err());
        assert_eq!(fake.effects, 0);
        fake.running = None;
        assert!(apply_with_id(&plan, "invalid", None, &mut fake, &mut record).is_err());
        assert_eq!(fake.effects, 0);
        fake.running = Some("b/data".into());
        let prepared = Some(Phase::Prepared);
        assert!(apply_with_id(&plan, ID, prepared, &mut fake, &mut record).is_err());
        assert_eq!(fake.effects, 0);
        assert_eq!(fake.recorded, None);
    }

    #[test]
    fn native_history_bridge_refuses_dirty_receivers_dependencies_and_metadata_drift() {
        let request = PairRequest {
            left: "a/data".into(),
            right: "b/data".into(),
            primary: Some(Side::Left),
        };
        let mut fake = Fake::new();
        fake.written.insert("a/data".into(), 4096);
        plan_with(&fake.state().unwrap(), &request, &mut fake).unwrap();
        fake.written.insert("b/data".into(), 1);
        assert!(plan_with(&fake.state().unwrap(), &request, &mut fake).is_err());
        fake.written.clear();
        // The primary may carry clones (a fork); the secondary, which
        // receives, may not.
        fake.clones.insert("a/data@s0".into(), "a/external".into());
        plan_with(&fake.state().unwrap(), &request, &mut fake).unwrap();
        fake.clones.clear();
        fake.clones.insert("b/data@s0".into(), "b/external".into());
        let error = plan_with(&fake.state().unwrap(), &request, &mut fake)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("b/data has clones of its snapshots (b/external)"),
            "{error}"
        );
        fake.clones.clear();
        fake.deferred.insert("b/data@s0".into());
        assert!(plan_with(&fake.state().unwrap(), &request, &mut fake).is_err());
        fake.deferred.clear();
        let mut state = fake.state().unwrap();
        state.pool_properties.get_mut("a").unwrap().insert(
            "zboot:unknown".into(),
            zfs_tools::engine::native::NativeProperty {
                value: "1".into(),
                source: "local".into(),
            },
        );
        assert!(plan_with(&state, &request, &mut fake).is_err());
        let mut state = fake.state().unwrap();
        state
            .dataset_properties
            .get_mut("a/data")
            .unwrap()
            .get_mut("objsetid")
            .unwrap()
            .value = "999".into();
        assert!(plan_with(&state, &request, &mut fake).is_err());
        fake.encrypted = true;
        plan_with(&fake.state().unwrap(), &request, &mut fake).unwrap();
        fake.ivsets.insert("b/data@s0".into(), Guid::new(888));
        assert!(plan_with(&fake.state().unwrap(), &request, &mut fake).is_err());
    }
}
