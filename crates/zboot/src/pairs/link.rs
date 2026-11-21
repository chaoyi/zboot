//! `pair`, `unpair` and `unpair --release-anchors`.
use super::{
    Backend, Journal, Recorded, dataset, digest, endpoint, local_record, new_id, peer_status,
    pool_of, refuse, remove_record,
};
use crate::{
    history::Side,
    pairs::plan::{self, PairBackend, PairPlan, PairRequest},
    transfer::NativeTransfer,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zfs_tools::engine::{
    Error, SnapshotRef, hold, intent,
    management::{self, Endpoint, Ownership, PairRecord},
    state::NativeState,
};

// ---- pair ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairState {
    left: Endpoint,
    right: Endpoint,
    primary: Side,
    /// Digest of the frozen pair plan; a resumed plan must match it.
    plan: String,
}
impl Recorded for PairState {
    fn pool(&self) -> String {
        let root = match self.primary {
            Side::Left => &self.left.name,
            Side::Right => &self.right.name,
        };
        pool_of(root).into()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PairResult {
    #[serde(flatten)]
    pub outcome: plan::PairOutcome,
}

/// Fence the receiver, hold the common anchors on both sides and publish both
/// records; the pair ID is the operation ID. An existing pair is verified and
/// reported, never changed.
#[cfg(test)]
pub fn pair_with(
    request: &PairRequest,
    id: &str,
    b: &mut impl Backend,
) -> Result<PairResult, Error> {
    super::valid_id(id)?;
    let state = PairBackend::observe(b)?;
    plan::one_host(&state, request, &mut |pool, guid| {
        b.recorded_hostid(pool, guid)
    })?;
    let plan = plan::plan_with(&state, request, b)?;
    apply_pair_plan(&plan, id, b)
}

pub fn pair_prepared(plan: &PairPlan) -> Result<PairResult, Error> {
    pair_prepared_with(plan, &new_id(), &mut NativeTransfer::new())
}
pub fn pair_prepared_with(
    plan: &PairPlan,
    id: &str,
    b: &mut impl Backend,
) -> Result<PairResult, Error> {
    super::valid_id(id)?;
    let request = plan.request();
    let state = PairBackend::observe(b)?;
    plan::one_host(&state, &request, &mut |pool, guid| {
        b.recorded_hostid(pool, guid)
    })?;
    if plan::plan_with(&state, &request, b)? != *plan {
        return Err(refuse("the pair plan changed; preview it again"));
    }
    apply_pair_plan(plan, id, b)
}

fn apply_pair_plan(plan: &PairPlan, id: &str, b: &mut impl Backend) -> Result<PairResult, Error> {
    let state = PairBackend::observe(b)?;
    if let Some(existing) = &plan.existing_pair {
        plan::verify_published(&state, plan, existing)?;
        return Ok(PairResult {
            outcome: plan::outcome(plan, existing, true),
        });
    }
    plan::refuse_running_receiver(b.running_root()?.as_deref(), plan)?;
    for e in [&plan.left.endpoint, &plan.right.endpoint] {
        plan::writable_pool_of(&state, &e.name)?;
    }
    // A write not yet on disk does not show in "unchanged since the anchor".
    // Sync the receiver's pool and plan once more before the record, so a
    // receiver that did change is refused here with nothing done, not after
    // its fence, where the executor plans again.
    PairBackend::sync(b, &plan.receiver().endpoint)?;
    if plan::plan_with(&PairBackend::observe(b)?, &plan.request(), b)? != *plan {
        return Err(refuse("the pair plan changed; preview it again"));
    }
    let journal = Journal::begin(
        b,
        id,
        "pair",
        PairState {
            left: plan.left.endpoint.clone(),
            right: plan.right.endpoint.clone(),
            primary: plan.primary,
            plan: digest(plan)?,
        },
    )?;
    run_pair(b, plan, journal)?;
    Ok(PairResult {
        outcome: plan::outcome(plan, id, false),
    })
}
/// Publish PLAN under JOURNAL's id with the one pair executor, recording in
/// the journal the steps it reaches: 1 receiver fenced, 2 anchors held.
/// Publishing both records finishes the operation.
fn run_pair(
    b: &mut impl Backend,
    plan: &PairPlan,
    mut journal: Journal<PairState>,
) -> Result<(), Error> {
    let id = journal.id().to_string();
    plan::publish(plan, &id, b, &mut |b, phase| match phase {
        plan::Phase::Prepared | plan::Phase::Published => Ok(()),
        plan::Phase::Fenced => journal.reach(b, 1),
        plan::Phase::Anchored => journal.reach(b, 2),
    })?;
    journal.finish(b)
}
/// The state without this operation's own (possibly partial) records, so the
/// plan can be made again exactly as it was before the first effect.
fn without_records(state: &NativeState, roots: [&Endpoint; 2], id: &str) -> NativeState {
    let mut clean = state.clone();
    for root in roots {
        let inherited = format!("inherited from {}", root.name);
        for (name, props) in clean.dataset_properties.iter_mut() {
            if !crate::history::contains_dataset(&root.name, name) {
                continue;
            }
            let ours = props.get(management::PAIR_PROPERTY).is_some_and(|p| {
                (p.source == "local" && name == &root.name || p.source == inherited)
                    && PairRecord::parse(&p.value).is_ok_and(|r| r.pair_id == id)
            });
            if ours {
                props.remove(management::PAIR_PROPERTY);
            }
        }
    }
    clean
}
pub(crate) fn resume_pair(
    journal: Journal<PairState>,
    abandon: bool,
    dialogue: &mut dyn std::io::Write,
    b: &mut impl Backend,
) -> Result<PairResult, Error> {
    let id = journal.id().to_string();
    let s = journal.intent.state.clone();
    // A pair records steps 0 to 2; a later step is an older record.
    if journal.step() > 2 {
        return Err(refuse(intent::earlier("pair", &id)));
    }
    let state = PairBackend::observe(b)?;
    let present = |e: &Endpoint| endpoint(&state, &e.name).is_ok_and(|now| now == *e);
    if abandon {
        // Only this operation's own records are removed, from the endpoints
        // still here as they were; fences and anchor holds stay, so nothing
        // becomes writable or deletable. An absent endpoint does not keep
        // the record.
        for (root, peer) in [(&s.left, &s.right), (&s.right, &s.left)] {
            if !present(root) {
                writeln!(
                    dialogue,
                    "{} is not here as it was; its pair record is left",
                    root.name
                )
                .map_err(|e| refuse(e.to_string()))?;
                continue;
            }
            let props = b.properties(root)?;
            if let Some(p) = props
                .get(management::PAIR_PROPERTY)
                .filter(|p| p.source == "local")
            {
                let record = PairRecord::parse(&p.value)?;
                if record.pair_id == id && record.peer == *peer {
                    remove_record(b, root, &record)?;
                }
            }
        }
        let note = format!(
            "abandoned pair {id}: {} and {} keep their read-only fences and any zboot:anchor:{id} holds; \
             `zboot unpair DATASET --release-anchors` releases the holds",
            s.left.name, s.right.name
        );
        writeln!(dialogue, "{note}").map_err(|e| refuse(e.to_string()))?;
        let primary = s.primary;
        let (left, right) = (s.left.clone(), s.right.clone());
        journal.finish(b)?;
        return Ok(PairResult {
            outcome: plan::PairOutcome {
                operation_id: id,
                left,
                right,
                primary,
                already_paired: false,
            },
        });
    }
    for e in [&s.left, &s.right] {
        if !present(e) {
            return Err(refuse(format!(
                "{} was replaced since pairing began",
                e.name
            )));
        }
    }
    // Continuing writes both pools; say so before anything else fails on it.
    for e in [&s.left, &s.right] {
        plan::writable_pool_of(&state, &e.name)?;
    }
    let clean = without_records(&state, [&s.left, &s.right], &id);
    let plan = plan::plan_with(
        &clean,
        &PairRequest {
            left: s.left.name.clone(),
            right: s.right.name.clone(),
            primary: Some(s.primary),
        },
        b,
    )
    .map_err(|error| {
        refuse(format!(
            "pair {id} cannot continue as it began: {error}. Abandon it with `zboot abandon {id}`"
        ))
    })?;
    if digest(&plan)? != s.plan {
        return Err(refuse(format!(
            "the pair's history, members or placement changed since operation {id} began; \
             abandon it with `zboot abandon {id}`"
        )));
    }
    plan::refuse_running_receiver(b.running_root()?.as_deref(), &plan)?;
    run_pair(b, &plan, journal)?;
    Ok(PairResult {
        outcome: plan::outcome(&plan, &id, false),
    })
}

// ---- unpair ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerStatus {
    Mutual,
    /// The peer's pool is not imported.
    PoolNotImported,
    /// The pool is imported but the peer dataset is not there.
    Absent,
    /// A different dataset now has the peer's name.
    Replaced,
    /// The peer does not hold the matching record (a half-pair).
    NotReciprocating,
}
impl PeerStatus {
    fn describe(self) -> &'static str {
        match self {
            Self::Mutual => "mutual",
            Self::PoolNotImported => "its pool is not imported",
            Self::Absent => "it is not in its imported pool",
            Self::Replaced => "another dataset now has its name",
            Self::NotReciprocating => "it does not hold the matching pair record",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorPoint {
    pub point: SnapshotRef,
    pub tag: String,
    /// Every hold on the snapshot now, ours included.
    pub holds: Vec<String>,
    pub clones: Vec<String>,
    /// Marked for deferred destroy: releasing its last hold destroys it.
    pub deferred_destroy: bool,
}

/// What `unpair` changes. Typed confirmation is needed when it is one-sided
/// (the peer is stated gone) or releases anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnpairPlan {
    pub schema_version: u32,
    pub dataset: Endpoint,
    /// DATASET's pair record; `None` after an earlier unpair.
    pub record: Option<PairRecord>,
    pub peer: Option<PeerStatus>,
    /// Only DATASET's record is removed; the operator states the peer is gone.
    pub one_sided: bool,
    pub statement: Option<String>,
    /// Anchor holds released with `--release-anchors`, on both sides.
    pub release: Option<Vec<AnchorPoint>>,
}
impl UnpairPlan {
    pub fn confirms(&self) -> bool {
        self.one_sided || self.release.is_some()
    }
    fn tags(&self) -> Vec<String> {
        let mut tags: Vec<_> = self
            .release
            .iter()
            .flatten()
            .map(|p| p.tag.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        tags.sort();
        tags
    }
    fn effects(&self) -> usize {
        let records = match (&self.record, self.one_sided) {
            (None, _) => 0,
            (Some(_), true) => 1,
            (Some(_), false) => 2,
        };
        records + self.release.as_ref().map_or(0, Vec::len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Released {
    #[serde(rename = "released")]
    HoldRemoved,
    NotHeld,
    /// The snapshot was destroyed with its last hold (deferred destroy).
    Destroyed,
}
#[derive(Debug, Clone, Serialize)]
pub struct UnpairResult {
    pub operation_id: Option<String>,
    pub dataset: Endpoint,
    pub peer: Option<Endpoint>,
    pub one_sided: bool,
    /// The anchor tag left in place by a plain unpair.
    pub retained_anchor_tag: Option<String>,
    pub released: Vec<ReleasedPoint>,
}
#[derive(Debug, Clone, Serialize)]
pub struct ReleasedPoint {
    pub snapshot: String,
    pub tag: String,
    pub state: Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnpairState {
    dataset: Endpoint,
    record: Option<PairRecord>,
    one_sided: bool,
    /// Anchor tags released; empty for a plain unpair.
    tags: Vec<String>,
    /// The other pair roots whose snapshots may carry those tags.
    roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    root_bindings: Vec<Endpoint>,
    /// Digest of the confirmed plan.
    plan: String,
    /// Digest of the exact remaining approved holds, including defer_destroy.
    anchors: Option<String>,
    /// One in-flight release, never a list of snapshot members. Both digests
    /// are recorded before releasing so a lost reply can be judged exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    anchor_pending: Option<PendingAnchor>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingAnchor {
    anchor: (SnapshotRef, String, bool),
    remaining: String,
}
impl Recorded for UnpairState {
    fn pool(&self) -> String {
        pool_of(&self.dataset.name).into()
    }
}

pub fn unpair_plan(dataset: &str, release_anchors: bool) -> Result<UnpairPlan, Error> {
    let mut b = NativeTransfer::new();
    unpair_plan_with(&PairBackend::observe(&mut b)?, dataset, release_anchors)
}
pub fn unpair_plan_with(
    state: &NativeState,
    dataset: &str,
    release_anchors: bool,
) -> Result<UnpairPlan, Error> {
    zfs_tools::engine::validate_dataset_name(dataset)?;
    let target = endpoint(state, dataset)?;
    let record = local_record(state, dataset)?;
    if record.is_none() {
        if let Ownership::Primary { record } | Ownership::Secondary { record } =
            management::ownership(state, dataset)?
        {
            return Err(refuse(format!(
                "{dataset} is inside the pair rooted at {}; name the pair root",
                record.endpoint.name
            )));
        }
        if !release_anchors {
            return Err(refuse(format!(
                "{dataset} is not paired; nothing to unpair"
            )));
        }
    }
    let peer = record.as_ref().map(|r| peer_status(state, r));
    if peer == Some(PeerStatus::Mutual) {
        // Full validation, including the secondary's fence.
        management::ownership(state, dataset)?;
    }
    let one_sided = peer.is_some_and(|p| p != PeerStatus::Mutual);
    let statement = match (&record, peer) {
        (Some(r), Some(status)) if one_sided => Some(format!(
            "You are stating that {} is gone or offline ({}). Only {dataset}'s pair record is \
             removed; its snapshots stay{}. If {} returns, it still claims this pair: unpair it \
             there too.",
            r.peer.name,
            status.describe(),
            if release_anchors {
                ", and only the anchor holds listed are released"
            } else {
                " and so do its anchor holds"
            },
            r.peer.name
        )),
        _ => None,
    };
    // A one-sided unpair does not speak for the peer: its anchors are
    // released only where it is unpaired, like any other dataset's.
    let release = if release_anchors {
        Some(anchor_points(
            state,
            dataset,
            record.as_ref().filter(|_| !one_sided),
            record.as_ref().map(|r| r.pair_id.as_str()),
        )?)
    } else {
        None
    };
    if release.as_ref().is_some_and(Vec::is_empty) && record.is_none() {
        return Err(refuse(format!(
            "{dataset} holds no zboot anchor; nothing to release"
        )));
    }
    Ok(UnpairPlan {
        schema_version: 1,
        dataset: target,
        record,
        peer,
        one_sided,
        statement,
        release,
    })
}
fn anchor_tag(tag: &str) -> bool {
    tag.strip_prefix("zboot:anchor:")
        .and_then(|id| uuid::Uuid::parse_str(id).ok().map(|u| u.to_string() == id))
        .unwrap_or(false)
}
/// Every snapshot holding one of the anchor tags found on `dataset`'s tree,
/// on both sides. A tag also held inside another, still paired tree refuses.
fn anchor_points(
    state: &NativeState,
    dataset: &str,
    record: Option<&PairRecord>,
    pair_id: Option<&str>,
) -> Result<Vec<AnchorPoint>, Error> {
    let snapshots = state
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| refuse("snapshot inventory missing"))?;
    let mut tags: BTreeSet<String> = snapshots
        .iter()
        .filter(|s| {
            s.name
                .split_once('@')
                .is_some_and(|(name, _)| crate::history::contains_dataset(dataset, name))
        })
        .flat_map(|s| s.holds.iter().filter(|t| anchor_tag(t)).cloned())
        .collect();
    if let Some(id) = pair_id {
        tags.insert(format!("zboot:anchor:{id}"));
    }
    let mut points = Vec::new();
    for s in snapshots {
        for tag in s.holds.iter().filter(|t| tags.contains(*t)) {
            let name = s.name.split_once('@').unwrap().0;
            let ours = crate::history::contains_dataset(dataset, name)
                || record.is_some_and(|r| crate::history::contains_dataset(&r.peer.name, name));
            if !ours && management::ownership(state, name)? != Ownership::Unpaired {
                return Err(refuse(format!(
                    "{tag} is also held on {}, inside a paired tree; unpair it first",
                    s.name
                )));
            }
            points.push(AnchorPoint {
                point: s.point(),
                tag: tag.clone(),
                holds: s.holds.clone(),
                clones: s.clones.clone(),
                deferred_destroy: s.defer_destroy,
            });
        }
    }
    points.sort_by(|a, b| (&a.point.name, &a.tag).cmp(&(&b.point.name, &b.tag)));
    Ok(points)
}

pub fn unpair(plan: &UnpairPlan) -> Result<UnpairResult, Error> {
    unpair_with(plan, &new_id(), &mut NativeTransfer::new())
}
/// Apply a plan made (and, when it confirms, confirmed) moments ago; it is
/// made again here and must be unchanged.
pub fn unpair_with(
    plan: &UnpairPlan,
    id: &str,
    b: &mut impl Backend,
) -> Result<UnpairResult, Error> {
    super::valid_id(id)?;
    let state = PairBackend::observe(b)?;
    let fresh = unpair_plan_with(&state, &plan.dataset.name, plan.release.is_some())?;
    if fresh != *plan {
        return Err(refuse(
            "the unpair plan changed; nothing changed, run it again",
        ));
    }
    let mut roots = plan
        .record
        .iter()
        .filter(|_| !plan.one_sided)
        .map(|r| r.peer.name.clone())
        .collect::<Vec<_>>();
    roots.extend(
        plan.release
            .iter()
            .flatten()
            .map(|p| p.point.name.split_once('@').unwrap().0.to_owned()),
    );
    roots.sort();
    roots.dedup();
    let mut scopes = vec![plan.dataset.name.clone()];
    for root in roots {
        if !scopes
            .iter()
            .any(|scope| crate::history::contains_dataset(scope, &root))
        {
            scopes.push(root);
        }
    }
    let roots = scopes
        .into_iter()
        .filter(|root| root != &plan.dataset.name)
        .collect::<Vec<_>>();
    let unpair_state = UnpairState {
        dataset: plan.dataset.clone(),
        record: plan.record.clone(),
        one_sided: plan.one_sided,
        tags: plan.tags(),
        roots,
        root_bindings: Vec::new(),
        plan: digest(plan)?,
        anchors: plan
            .release
            .as_ref()
            .map(|points| {
                digest(
                    &points
                        .iter()
                        .map(|p| (&p.point, &p.tag, p.deferred_destroy))
                        .collect::<Vec<_>>(),
                )
            })
            .transpose()?,
        anchor_pending: None,
    };
    let mut unpair_state = unpair_state;
    unpair_state.root_bindings = unpair_state
        .roots
        .iter()
        .map(|root| endpoint(&state, root))
        .collect::<Result<_, _>>()?;
    let kind = if plan.release.is_some() {
        "release-anchors"
    } else {
        "unpair"
    };
    if plan.effects() <= 1 {
        // One effect needs no record: it either happened or did not.
        return run_unpair(b, &unpair_state, None);
    }
    // Every later checkpoint must fit before the first durable effect.
    for point in plan.release.iter().flatten() {
        let mut largest = unpair_state.clone();
        largest.anchor_pending = Some(PendingAnchor {
            anchor: (
                point.point.clone(),
                point.tag.clone(),
                point.deferred_destroy,
            ),
            remaining: digest(&Vec::<(SnapshotRef, String, bool)>::new())?,
        });
        zfs_tools::engine::intent::encode(&zfs_tools::engine::intent::Intent::new(
            id, kind, largest,
        ))?;
    }
    let mut journal = Journal::begin(b, id, kind, unpair_state.clone())?;
    let result = run_unpair(b, &unpair_state, Some(&mut journal))?;
    journal.finish(b)?;
    Ok(UnpairResult {
        operation_id: Some(id.into()),
        ..result
    })
}
/// Steps: 1 records removed, 2 anchors released.
fn run_unpair(
    b: &mut impl Backend,
    s: &UnpairState,
    mut journal: Option<&mut Journal<UnpairState>>,
) -> Result<UnpairResult, Error> {
    let step = journal.as_ref().map_or(0, |j| j.step());
    let peer = s.record.as_ref().map(|r| r.peer.clone());
    if step < 1 && !s.tags.is_empty() {
        approved_anchors(&PairBackend::observe(b)?, s)?;
    }
    if step < 1 {
        if let Some(record) = &s.record {
            remove_record(b, &s.dataset, record)?;
            if !s.one_sided {
                let state = PairBackend::observe(b)?;
                if dataset(&state, &record.peer.name)?.identity != record.peer.identity {
                    return Err(refuse(format!("{} was replaced", record.peer.name)));
                }
                remove_record(b, &record.peer, &record.counterpart())?;
            }
        }
        if let Some(j) = journal.as_deref_mut() {
            j.reach(b, 1)?;
        }
    }
    let mut released = Vec::new();
    if !s.tags.is_empty() {
        let mut current = journal
            .as_ref()
            .map_or_else(|| s.clone(), |j| j.intent.state.clone());
        loop {
            let state = PairBackend::observe(b)?;
            let points = scoped_anchors(&state, &current)?;
            if let Some(pending) = current.anchor_pending.clone() {
                let observed = digest(&points)?;
                if Some(&observed) != current.anchors.as_ref() && observed != pending.remaining {
                    return Err(anchor_drift());
                }
                let (point, tag, _) = pending.anchor;
                if management::ownership(&state, point.name.split_once('@').unwrap().0)?
                    != Ownership::Unpaired
                {
                    return Err(refuse(
                        "a pending anchor now belongs to a paired tree; nothing more released",
                    ));
                }
                if observed == pending.remaining
                    && hold::Backend::resolve(b, &point)?
                        .is_some_and(|seen| seen.holds.contains(&tag))
                {
                    return Err(anchor_drift());
                }
                let outcome = match hold::release(b, &point, &tag)? {
                    hold::Released::HoldRemoved => Released::HoldRemoved,
                    hold::Released::NotHeld => Released::NotHeld,
                    hold::Released::Destroyed => Released::Destroyed,
                };
                if digest(&scoped_anchors(&PairBackend::observe(b)?, &current)?)?
                    != pending.remaining
                {
                    return Err(anchor_drift());
                }
                released.push(ReleasedPoint {
                    snapshot: point.name,
                    tag,
                    state: outcome,
                });
                current.anchors = Some(pending.remaining);
                current.anchor_pending = None;
                if let Some(j) = journal.as_deref_mut() {
                    j.replace_state(b, current.clone())?;
                }
                continue;
            }
            if current.anchors.as_ref() != Some(&digest(&points)?) {
                return Err(anchor_drift());
            }
            let Some((point, tag, deferred)) = points.first() else {
                break;
            };
            let name = point.name.split_once('@').unwrap().0.to_string();
            if management::ownership(&state, &name)? != Ownership::Unpaired {
                return Err(refuse(format!(
                    "{tag} is held on {}, inside a paired tree; nothing more released",
                    point.name
                )));
            }
            current.anchor_pending = Some(PendingAnchor {
                anchor: (point.clone(), tag.clone(), *deferred),
                remaining: digest(&points[1..].to_vec())?,
            });
            if let Some(j) = journal.as_deref_mut() {
                j.replace_state(b, current.clone())?;
            }
        }
        if let Some(j) = journal {
            j.reach(b, 2)?;
        }
    }
    Ok(UnpairResult {
        operation_id: None,
        dataset: s.dataset.clone(),
        peer,
        one_sided: s.one_sided,
        retained_anchor_tag: if s.tags.is_empty() {
            s.record
                .as_ref()
                .map(|r| format!("zboot:anchor:{}", r.pair_id))
        } else {
            None
        },
        released,
    })
}
fn anchor_drift() -> Error {
    refuse(
        "the approved anchor holds or defer_destroy changed; nothing more released; abandon and plan again",
    )
}
fn scoped_anchors(
    state: &NativeState,
    s: &UnpairState,
) -> Result<Vec<(SnapshotRef, String, bool)>, Error> {
    if endpoint(state, &s.dataset.name)? != s.dataset
        || s.root_bindings
            .iter()
            .any(|root| !endpoint(state, &root.name).is_ok_and(|actual| actual == *root))
    {
        return Err(anchor_drift());
    }
    let mut roots = vec![s.dataset.name.as_str()];
    roots.extend(s.roots.iter().map(String::as_str));
    tagged(state, &s.tags.iter().collect(), &roots)
}
fn approved_anchors(state: &NativeState, s: &UnpairState) -> Result<(), Error> {
    if s.anchors.as_ref() != Some(&digest(&scoped_anchors(state, s)?)?) {
        return Err(anchor_drift());
    }
    Ok(())
}
/// Every snapshot holding one of `tags`, with the tag and whether it is
/// marked for deferred destroy, ordered as [`anchor_points`] orders them.
fn tagged(
    state: &NativeState,
    tags: &BTreeSet<&String>,
    roots: &[&str],
) -> Result<Vec<(SnapshotRef, String, bool)>, Error> {
    let mut points: Vec<_> = state
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| refuse("snapshot inventory missing"))?
        .iter()
        .filter(|snap| {
            snap.name.split_once('@').is_some_and(|(name, _)| {
                roots
                    .iter()
                    .any(|root| crate::history::contains_dataset(root, name))
            })
        })
        .flat_map(|snap| {
            snap.holds
                .iter()
                .filter(|t| tags.contains(t))
                .map(|t| (snap.point(), t.clone(), snap.defer_destroy))
                .collect::<Vec<_>>()
        })
        .collect();
    points.sort_by(|a, b| (&a.0.name, &a.1).cmp(&(&b.0.name, &b.1)));
    Ok(points)
}
pub(crate) fn resume_unpair(
    mut journal: Journal<UnpairState>,
    abandon: bool,
    dialogue: &mut dyn std::io::Write,
    b: &mut impl Backend,
) -> Result<UnpairResult, Error> {
    let s = journal.intent.state.clone();
    let id = journal.id().to_string();
    // An unpair records steps 0 to 2, binds every other root it names and,
    // when it releases anchors, their digest; anything else is an older record.
    let kind = &journal.intent.kind;
    if journal.step() > 2
        || s.root_bindings.len() != s.roots.len()
        || s.anchors.is_some() != (kind == "release-anchors")
    {
        return Err(refuse(intent::earlier(kind, &id)));
    }
    let state = PairBackend::observe(b)?;
    if endpoint(&state, &s.dataset.name)? != s.dataset {
        return Err(refuse(format!("{} was replaced", s.dataset.name)));
    }
    if abandon {
        writeln!(
            dialogue,
            "abandoned unpair {id}: pair records and anchor holds stay as they are now; \
             `zboot status {}` shows them",
            s.dataset.name
        )
        .map_err(|e| refuse(e.to_string()))?;
        journal.finish(b)?;
        return Ok(UnpairResult {
            operation_id: Some(id),
            dataset: s.dataset.clone(),
            peer: s.record.as_ref().map(|r| r.peer.clone()),
            one_sided: s.one_sided,
            retained_anchor_tag: None,
            released: vec![],
        });
    }
    let result = run_unpair(b, &s, Some(&mut journal))?;
    journal.finish(b)?;
    Ok(UnpairResult {
        operation_id: Some(id),
        ..result
    })
}

/// Every dataset holding a local pair record, by name.
pub fn pair_roots(state: &NativeState) -> Vec<String> {
    state
        .inspection
        .datasets
        .iter()
        .filter(|d| {
            state
                .dataset_properties
                .get(&d.name)
                .and_then(|p| p.get(management::PAIR_PROPERTY))
                .is_some_and(|p| p.source == "local")
        })
        .map(|d| d.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
