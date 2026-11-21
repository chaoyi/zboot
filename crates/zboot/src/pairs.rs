//! The pair verbs on the shared primitives: `pair`, `unpair` (and
//! `--release-anchors`), `sync` and `primary`.
//!
//! An operation with more than one durable effect keeps one
//! [`zfs_tools::engine::intent`] record on the root of the pool that survives it, written
//! before its first effect, advanced per step and cleared on completion. Every
//! effect is idempotent and judged from native state, so [`resume`] continues
//! from the record alone; records name roots, boundaries and digests, never
//! member lists. Snapshot protection goes through [`zfs_tools::engine::hold`]. The nested
//! transfer of `sync` and `primary` runs on the `transfer` engine, which keeps its progress
//! in the verb's record ([`crate::transfer::Record`]).
//! Callers hold the writer lock; nothing here takes it.
use crate::{
    boot_support::{self, DefaultHandoff, DefaultHandoffOutcome},
    history,
    pairs::plan::PairBackend,
    placement::Posture,
    transfer::{self, NativeTransfer, TransferBackend, TransferProgress},
};
use serde::{Serialize, de::DeserializeOwned};
use zfs_tools::engine::{
    Error, SnapshotRef, hold, intent,
    management::{self, Endpoint, MountMode, PairRecord, Placement},
    mutation::{PropertyKey, PropertyValue},
    native::NativeProperty,
    pool_of,
    state::NativeState,
};

pub mod describe;
mod link;
pub mod plan;
pub mod prune;
mod switch;
mod sync;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use link::unpair_plan_with;
pub use link::{
    PairResult, PeerStatus, Released, UnpairPlan, UnpairResult, pair_prepared, pair_roots, unpair,
    unpair_plan,
};
#[cfg(test)]
use link::{pair_prepared_with, unpair_with};
pub use switch::{Mode as PrimaryMode, PrimaryPlan, PrimaryResult, primary, primary_plan};
#[cfg(test)]
use switch::{primary_plan_with, primary_with};
pub use sync::{SyncAll, SyncEntry, SyncPlan, SyncTarget, sync_plan, sync_prepared};
#[cfg(test)]
use sync::{sync_plan_with, sync_prepared_with, sync_with};

/// The bytes a pair verb's record stays within at its widest, which its size
/// tests assert: the intent limit before restore's records needed more
/// (`intent::LIMIT` is 6000), so every pair record keeps that room below it.
#[cfg(test)]
const RECORD_BUDGET: usize = 4096;

/// The record kinds this module owns, as `zboot resume` dispatches them.
pub const KINDS: [&str; 5] = ["pair", "unpair", "release-anchors", "sync", "primary"];

/// Native effects beyond the transfer engine's. Tests substitute a model that
/// can be cut before or after any effect or record write.
pub trait Backend: TransferBackend + hold::Backend {
    /// `zfs rollback -r` to `point`, destroying the dataset's later snapshots.
    fn rollback(&mut self, point: &SnapshotRef) -> Result<(), Error>;
    fn hand_off_default(&mut self, handoff: &DefaultHandoff) -> DefaultHandoffOutcome;
    /// The hostid the labels of an imported pool record (0: none).
    fn recorded_hostid(&mut self, pool: &str, guid: zfs_tools::engine::Guid) -> Result<u32, Error>;
}

impl intent::Backend for NativeTransfer {
    fn pools(&mut self) -> Result<Vec<String>, Error> {
        intent::Native.pools()
    }
    fn read(&mut self, pool: &str) -> Result<Option<String>, Error> {
        intent::Native.read(pool)
    }
    fn write(&mut self, pool: &str, value: &str) -> Result<(), Error> {
        intent::Native.write(pool, value)
    }
    fn remove(&mut self, pool: &str) -> Result<(), Error> {
        intent::Native.remove(pool)
    }
}
impl hold::Backend for NativeTransfer {
    fn resolve(&mut self, point: &SnapshotRef) -> Result<Option<hold::Seen>, Error> {
        hold::Native.resolve(point)
    }
    fn hold(&mut self, name: &str, tag: &str) -> Result<(), Error> {
        hold::Native.hold(name, tag)
    }
    fn release(&mut self, name: &str, tag: &str) -> Result<(), Error> {
        hold::Native.release(name, tag)
    }
}
impl Backend for NativeTransfer {
    fn rollback(&mut self, point: &SnapshotRef) -> Result<(), Error> {
        self.observe_point(point)?;
        zfs_tools::engine::native::run_mutating(
            "zfs",
            &["rollback".into(), "-r".into(), point.name.clone()],
        )
        .map(drop)
    }
    fn hand_off_default(&mut self, handoff: &DefaultHandoff) -> DefaultHandoffOutcome {
        boot_support::hand_off_default(handoff)
    }
    fn recorded_hostid(&mut self, pool: &str, guid: zfs_tools::engine::Guid) -> Result<u32, Error> {
        crate::hostid::native_recorded(pool, guid)
    }
}

/// Continue or abandon an interrupted pair operation from its record.
///
/// Continuing needs no new confirmation: the record stays within the consent
/// it was written under, and every step is rechecked against native state.
/// Abandoning clears the record and reports what the operation leaves behind;
/// it never destroys data. The result is the verb's own `result` payload.
#[cfg(test)]
pub fn resume_with(
    record: intent::Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn std::io::Write,
    b: &mut impl Backend,
) -> Result<serde_json::Value, Error> {
    resume_outcome_with(record, abandon, dialogue, b).map(|outcome| outcome.result)
}

/// A typed completion status, kept separate from the verb's serialized payload.
#[derive(Debug, Clone, Serialize)]
pub struct ResumeOutcome {
    pub complete: bool,
    pub result: serde_json::Value,
}
impl ResumeOutcome {
    pub(crate) fn new(complete: bool, value: impl Serialize) -> Result<Self, Error> {
        Ok(Self {
            complete,
            result: json(value)?,
        })
    }
}
pub fn resume_outcome(
    record: intent::Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn std::io::Write,
) -> Result<ResumeOutcome, Error> {
    resume_outcome_with(record, abandon, dialogue, &mut NativeTransfer::new())
}
pub fn resume_outcome_with(
    record: intent::Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn std::io::Write,
    b: &mut impl Backend,
) -> Result<ResumeOutcome, Error> {
    match record.kind.as_str() {
        "pair" => ResumeOutcome::new(
            true,
            link::resume_pair(Journal::decode(record)?, abandon, dialogue, b)?,
        ),
        "unpair" | "release-anchors" => ResumeOutcome::new(
            true,
            link::resume_unpair(Journal::decode(record)?, abandon, dialogue, b)?,
        ),
        "sync" => {
            let journal: Journal<sync::SyncState> = Journal::decode(record)?;
            // A sync records only step 0; a later step is an older record.
            if journal.step() > 0 {
                return Err(refuse(intent::earlier("sync", journal.id())));
            }
            ResumeOutcome::new(true, sync::resume_sync(journal, abandon, dialogue, b)?)
        }
        "primary" => {
            let value = switch::resume_primary(Journal::decode(record)?, abandon, dialogue, b)?;
            ResumeOutcome::new(abandon || value.complete(), value)
        }
        other => Err(refuse(format!("operation kind {other} is not a pair verb"))),
    }
}

fn json(value: impl Serialize) -> Result<serde_json::Value, Error> {
    serde_json::to_value(value).map_err(|e| refuse(e.to_string()))
}

/// The verb's one intent record and the pool root it lives on.
pub(crate) struct Journal<S> {
    pub(crate) pool: String,
    pub(crate) intent: intent::Intent<S>,
}
/// A record's state names the pool root that holds it.
pub(crate) trait Recorded {
    fn pool(&self) -> String;
}
impl<S: Serialize + DeserializeOwned + Clone + Recorded> Journal<S> {
    /// Record the operation before its first effect.
    pub(crate) fn begin(
        b: &mut impl intent::Backend,
        id: &str,
        kind: &str,
        state: S,
    ) -> Result<Self, Error> {
        let pool = state.pool();
        let intent = intent::Intent::new(id, kind, state);
        intent::begin(b, &pool, &intent)?;
        Ok(Self { pool, intent })
    }
    /// A state this build does not write was written by an earlier zboot.
    pub(crate) fn decode(record: intent::Intent<serde_json::Value>) -> Result<Self, Error> {
        let state: S = serde_json::from_value(record.state.clone()).map_err(|e| {
            refuse(format!(
                "{} ({e})",
                intent::earlier(&record.kind, &record.id)
            ))
        })?;
        valid_id(&record.id)?;
        let intent = intent::Intent {
            schema_version: record.schema_version,
            id: record.id,
            kind: record.kind,
            step: record.step,
            state,
        };
        Ok(Self {
            pool: intent.state.pool(),
            intent,
        })
    }
    pub(crate) fn id(&self) -> &str {
        &self.intent.id
    }
    pub(crate) fn step(&self) -> u32 {
        self.intent.step
    }
    pub(crate) fn replace_state(
        &mut self,
        b: &mut impl intent::Backend,
        state: S,
    ) -> Result<(), Error> {
        let mut next = self.intent.clone();
        next.state = state;
        intent::advance(b, &self.pool, &self.intent, &next)?;
        self.intent = next;
        Ok(())
    }
    /// Record that `step` is complete together with its result, in one write.
    pub(crate) fn reach_with(
        &mut self,
        b: &mut impl intent::Backend,
        step: u32,
        state: S,
    ) -> Result<(), Error> {
        let mut next = self.intent.clone();
        next.step = step;
        next.state = state;
        intent::advance(b, &self.pool, &self.intent, &next)?;
        self.intent = next;
        Ok(())
    }
    /// Record that `step` is complete; a lower or equal step is already known.
    pub(crate) fn reach(&mut self, b: &mut impl intent::Backend, step: u32) -> Result<(), Error> {
        if self.intent.step >= step {
            return Ok(());
        }
        let mut next = self.intent.clone();
        next.step = step;
        intent::advance(b, &self.pool, &self.intent, &next)?;
        self.intent = next;
        Ok(())
    }
    pub(crate) fn finish(self, b: &mut impl intent::Backend) -> Result<(), Error> {
        intent::finish(b, &self.pool, &self.intent)
    }
}

/// A verb's state that can carry one nested transfer: its progress and the
/// leaf on the record's pool that holds its attachments.
pub(crate) trait Transferring {
    fn holder(&self) -> &Endpoint;
    fn transfer(&self) -> Option<&TransferProgress>;
    fn set_transfer(&mut self, transfer: Option<TransferProgress>);
}
impl<S: Serialize + DeserializeOwned + Clone + Recorded + Transferring> transfer::Record
    for Journal<S>
{
    fn id(&self) -> &str {
        &self.intent.id
    }
    fn pool(&self) -> &str {
        &self.pool
    }
    fn holder(&self) -> &Endpoint {
        self.intent.state.holder()
    }
    fn transfer(&self) -> Option<&TransferProgress> {
        self.intent.state.transfer()
    }
    fn advance(
        &mut self,
        b: &mut impl intent::Backend,
        transfer: TransferProgress,
    ) -> Result<(), Error> {
        let mut state = self.intent.state.clone();
        state.set_transfer(Some(transfer));
        self.replace_state(b, state)
    }
}

pub(crate) fn refuse(detail: impl Into<String>) -> Error {
    Error::Refused(detail.into())
}
pub(crate) fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub(crate) fn valid_id(id: &str) -> Result<(), Error> {
    if !zfs_tools::engine::is_canonical_uuid_v4(id) {
        return Err(refuse("operation ID must be a canonical UUID v4"));
    }
    Ok(())
}
pub(crate) fn digest(value: &impl Serialize) -> Result<String, Error> {
    crate::consent::token(value).map_err(|e| refuse(e.to_string()))
}
pub(crate) fn dataset<'a>(
    state: &'a NativeState,
    name: &str,
) -> Result<&'a zfs_tools::engine::Dataset, Error> {
    state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == name)
        .ok_or_else(|| Error::MissingScope(name.into()))
}
pub(crate) fn endpoint(state: &NativeState, name: &str) -> Result<Endpoint, Error> {
    Ok(Endpoint {
        name: name.into(),
        identity: dataset(state, name)?.identity.clone(),
    })
}
/// `root` and its descendants, parents first.
pub(crate) fn tree<'a>(state: &'a NativeState, root: &str) -> Vec<&'a zfs_tools::engine::Dataset> {
    let mut members: Vec<_> = state
        .inspection
        .datasets
        .iter()
        .filter(|d| history::contains_dataset(root, &d.name))
        .collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));
    members
}
/// Digest of a tree's member names and incarnations.
pub(crate) fn membership(state: &NativeState, root: &str) -> Result<String, Error> {
    let members: Vec<_> = tree(state, root)
        .into_iter()
        .map(|d| (d.name.clone(), d.identity.clone()))
        .collect();
    digest(&members)
}
pub(crate) fn pool_imported(state: &NativeState, pool: &str) -> bool {
    state.inspection.pools.iter().any(|p| p.name == pool)
}
/// The pool must be imported writable with its recorded identity and no
/// pool-level management properties.
pub(crate) fn writable_pool(state: &NativeState, e: &Endpoint) -> Result<(), Error> {
    bound_pool(state, e)?;
    crate::pairs::plan::writable_pool_of(state, &e.name)
}
/// The pool is imported (possibly read-only, for a preview) with its
/// recorded identity and no pool-level management properties.
pub(crate) fn bound_pool(state: &NativeState, e: &Endpoint) -> Result<(), Error> {
    let pool = pool_of(&e.name);
    let props = state
        .pool_properties
        .get(pool)
        .ok_or_else(|| refuse(format!("pool {pool} is not imported")))?;
    if props.get("guid").map(|p| p.value.as_str())
        != Some(e.identity.pool_guid.to_string().as_str())
        || props.keys().any(|key| management::managed_key(key))
    {
        return Err(refuse(format!(
            "pool {pool} identity or management properties changed"
        )));
    }
    Ok(())
}
/// The local pair record on `name`, which must be the pair root itself.
pub(crate) fn local_record(state: &NativeState, name: &str) -> Result<Option<PairRecord>, Error> {
    let props = management::bound_properties(state, name)?;
    management::validate_supported_properties(props, name)?;
    let Some(p) = props.get(management::PAIR_PROPERTY) else {
        return Ok(None);
    };
    if p.source != "local" {
        let root = p
            .source
            .strip_prefix("inherited from ")
            .unwrap_or(p.source.as_str());
        return Err(refuse(format!(
            "{name} is inside the pair rooted at {root}; name the pair root"
        )));
    }
    let record = PairRecord::parse(&p.value)?;
    if record.endpoint != endpoint(state, name)? {
        return Err(refuse(format!(
            "{name}'s pair record names another incarnation of it"
        )));
    }
    let mut parent = name.rsplit_once('/').map(|(p, _)| p);
    while let Some(ancestor) = parent {
        let props = management::bound_properties(state, ancestor)?;
        management::validate_supported_properties(props, ancestor)?;
        if props.contains_key(management::PAIR_PROPERTY) {
            return Err(refuse(format!(
                "{name} overlaps the management scope of {ancestor}"
            )));
        }
        parent = ancestor.rsplit_once('/').map(|(p, _)| p);
    }
    Ok(Some(record))
}
/// Whether `record`'s peer still answers as its mutual peer.
pub(crate) fn peer_status(state: &NativeState, record: &PairRecord) -> link::PeerStatus {
    use link::PeerStatus;
    let peer = &record.peer;
    if !pool_imported(state, pool_of(&peer.name)) {
        return PeerStatus::PoolNotImported;
    }
    let Some(d) = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == peer.name)
    else {
        return PeerStatus::Absent;
    };
    if d.identity != peer.identity {
        return PeerStatus::Replaced;
    }
    let reciprocates = management::bound_properties(state, &peer.name)
        .ok()
        .and_then(|props| props.get(management::PAIR_PROPERTY).cloned())
        .is_some_and(|p| {
            p.source == "local"
                && PairRecord::parse(&p.value).is_ok_and(|r| r == record.counterpart())
        });
    if reciprocates {
        PeerStatus::Mutual
    } else {
        PeerStatus::NotReciprocating
    }
}

fn local(
    properties: &std::collections::BTreeMap<String, NativeProperty>,
    key: &str,
) -> Option<String> {
    properties
        .get(key)
        .filter(|p| p.source == "local")
        .map(|p| p.value.clone())
}
/// Set one management property, skipping it when already set and judging the
/// outcome by reading it back.
pub(crate) fn set(
    b: &mut impl PairBackend,
    e: &Endpoint,
    value: PropertyValue,
) -> Result<(), Error> {
    let expected = value.encode(e)?;
    let key = value.key().native();
    if local(&b.properties(e)?, key).as_deref() == Some(expected.as_str()) {
        return Ok(());
    }
    let result = b.set_property(e, &value);
    if local(&b.properties(e)?, key).as_deref() != Some(expected.as_str()) {
        return Err(result
            .err()
            .unwrap_or_else(|| refuse(format!("{key} on {} was not verified", e.name))));
    }
    Ok(())
}
/// Remove `e`'s local pair record if it is `expected`; absent is done.
pub(crate) fn remove_record(
    b: &mut impl Backend,
    e: &Endpoint,
    expected: &PairRecord,
) -> Result<(), Error> {
    let Some(value) = local(&b.properties(e)?, management::PAIR_PROPERTY) else {
        return Ok(());
    };
    if PairRecord::parse(&value)? != *expected {
        return Err(refuse(format!(
            "{}'s pair record changed; nothing removed",
            e.name
        )));
    }
    let result = b.inherit_property(e, PropertyKey::Pair, &value);
    let after = b.properties(e)?;
    if after.contains_key(management::PAIR_PROPERTY) {
        return Err(match result {
            Err(error) => error,
            Ok(_) => refuse(format!("{} still has a pair record after removal", e.name)),
        });
    }
    Ok(())
}
/// Hold E in POSTURE: save PLACEMENT first when given, set each value of the
/// posture locally and read it back, and unmount E. An inert posture unmounts
/// first, as `canmount=off` and `mountpoint=none` would unmount it as a side
/// effect; at rest E is read-only before it is unmounted. A value already set
/// is skipped, so fencing a fenced member changes nothing.
pub(crate) fn fence(
    b: &mut impl PairBackend,
    e: &Endpoint,
    placement: Option<&Placement>,
    posture: Posture,
) -> Result<(), Error> {
    let (volume, _) = observed(b, e)?;
    if let Some(placement) = placement {
        set(b, e, PropertyValue::Placement(placement.clone()))?;
    }
    if posture != Posture::AtRest {
        unmount(b, e)?;
    }
    for (key, value) in posture.properties(volume) {
        let value = match (*key, *value) {
            ("readonly", "on") => PropertyValue::Readonly(true),
            ("volmode", "none") => PropertyValue::Volmode("none".into()),
            ("mountpoint", "none") => PropertyValue::Mountpoint("none".into()),
            ("canmount", "off") => PropertyValue::Canmount(MountMode::Off),
            ("canmount", "noauto") => PropertyValue::Canmount(MountMode::NoAuto),
            _ => return Err(refuse(format!("no fence sets {key}={value}"))),
        };
        set(b, e, value)?;
    }
    unmount(b, e)?;
    verify_posture(b, e, posture)
}
/// E holds POSTURE by its own local values.
pub(crate) fn verify_posture(
    b: &mut impl PairBackend,
    e: &Endpoint,
    posture: Posture,
) -> Result<(), Error> {
    let (volume, mounted) = observed(b, e)?;
    let props = b.properties(e)?;
    let local = |key: &str| {
        props
            .get(key)
            .filter(|p| p.source == "local")
            .map(|p| (p.value.as_str(), true))
    };
    if !posture.holds(volume, mounted, local) {
        return Err(refuse(format!(
            "{} is not verifiably {}",
            e.name,
            if posture == Posture::AtRest {
                "fenced"
            } else {
                "inert"
            }
        )));
    }
    Ok(())
}
/// Whether E, still this incarnation, is a volume and is mounted.
fn observed(b: &mut impl PairBackend, e: &Endpoint) -> Result<(bool, bool), Error> {
    let state = PairBackend::observe(b)?;
    let d = dataset(&state, &e.name)?;
    if d.identity != e.identity {
        return Err(refuse(format!("{} was replaced while fencing", e.name)));
    }
    Ok((
        d.kind == zfs_tools::engine::DatasetKind::Volume,
        d.mounted == Some(true),
    ))
}
fn unmount(b: &mut impl PairBackend, e: &Endpoint) -> Result<(), Error> {
    if !observed(b, e)?.1 {
        return Ok(());
    }
    let result = b.unmount(e);
    match (observed(b, e), result) {
        (Ok((_, false)), _) => Ok(()),
        (_, Err(error)) | (Err(error), Ok(())) => Err(error),
        (Ok(_), Ok(())) => Err(refuse(format!("{} did not unmount", e.name))),
    }
}
/// D holds the at-rest posture by its effective values.
pub(crate) fn at_rest(state: &NativeState, d: &zfs_tools::engine::Dataset) -> bool {
    let props = state.dataset_properties.get(&d.name);
    Posture::AtRest.holds(
        d.kind == zfs_tools::engine::DatasetKind::Volume,
        d.mounted == Some(true),
        |key| {
            props?
                .get(key)
                .map(|p| (p.value.as_str(), p.source == "local"))
        },
    )
}
/// Every member of `root` holds the at-rest posture.
pub(crate) fn verify_fenced(state: &NativeState, root: &str) -> Result<(), Error> {
    crate::mounting::require_outside_boot_environment(state, root)?;
    for d in tree(state, root) {
        if !at_rest(state, d) {
            return Err(refuse(format!("{} is not fenced", d.name)));
        }
    }
    Ok(())
}

/// One member's activation: the placement it is restored to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Activation {
    pub dataset: Endpoint,
    /// Its `volmode`, when set, is the local value the volume gets back.
    pub placement: Placement,
    /// Whether the member differs from its placement now.
    pub changes: bool,
    /// Whether it is mounted after activation.
    pub mounts: bool,
    /// Whether the placement is saved on the member (absent for a member
    /// that was never fenced, which is left as it is).
    pub stored: bool,
    /// The member's own saved placement as observed, which activation
    /// replaces when it differs: a switch takes the departing working copy's
    /// `volmode`, and a value set by hand since stays.
    #[serde(skip)]
    saved: Option<String>,
}
/// The placement every member of `root` is activated to: its own saved
/// placement, else (for descendants new since the last transfer) the saved
/// placement of the matching member of `peer`. A fenced member with neither
/// cannot be activated safely.
pub(crate) fn activation(
    state: &NativeState,
    root: &str,
    peer: Option<&str>,
) -> Result<Vec<Activation>, Error> {
    activation_with(state, root, peer, None, false)
}
/// [`activation`] as `primary` applies it, `departing` naming the fenced old
/// working copy of a switch: a dormant volume takes the `volmode` that side
/// had set by hand, saved when it was fenced, rather than its own.
pub(crate) fn switch_activation(
    state: &NativeState,
    root: &str,
    peer: Option<&str>,
    departing: Option<&str>,
) -> Result<Vec<Activation>, Error> {
    activation_with(state, root, peer, departing, false)
}
/// Preview an ownership switch before its old primary is fenced. Only that
/// bound peer's members may still occupy the destination's mountpoints. The
/// executor calls ordinary `switch_activation` after fencing, so no overlap
/// is tolerated when the new primary actually becomes mountable.
pub(crate) fn activation_before_fencing(
    state: &NativeState,
    root: &str,
    placement_peer: Option<&str>,
    departing: &Endpoint,
) -> Result<Vec<Activation>, Error> {
    if endpoint(state, &departing.name)? != *departing {
        return Err(refuse("the primary to fence was replaced"));
    }
    activation_with(state, root, placement_peer, Some(&departing.name), true)
}
fn activation_with(
    state: &NativeState,
    root: &str,
    peer: Option<&str>,
    departing: Option<&str>,
    fencing: bool,
) -> Result<Vec<Activation>, Error> {
    let mut out = Vec::new();
    // A verified working copy may intentionally keep a readonly member after
    // its activation receipt has been retired. Its native role is then the
    // authority; an unpaired readonly tree still needs saved placement.
    let active_primary = matches!(
        management::ownership(state, root),
        Ok(management::Ownership::Primary { .. })
    );
    for d in tree(state, root) {
        let props = management::bound_properties(state, &d.name)?;
        let relative = &d.name[root.len()..];
        let saved = |props: &std::collections::BTreeMap<String, NativeProperty>| {
            local(props, management::PLACEMENT_PROPERTY)
                .map(|v| Placement::parse(&v))
                .transpose()
        };
        let own = saved(props)?;
        let mut stored = true;
        let mut placement = match own.clone() {
            Some(p) => p,
            None => {
                let mapped = peer.and_then(|peer| {
                    let name = format!("{peer}{relative}");
                    management::bound_properties(state, &name).ok().cloned()
                });
                match mapped.map(|props| saved(&props)).transpose()?.flatten() {
                    Some(mut p) => {
                        p.identity = d.identity.clone();
                        p
                    }
                    None if !d.readonly || active_primary => {
                        stored = false;
                        Placement::observed(d, props)
                    }
                    None => {
                        return Err(refuse(format!(
                            "{} is read-only with no saved placement; set readonly and canmount by hand",
                            d.name
                        )));
                    }
                }
            }
        };
        if placement.identity != d.identity {
            return Err(refuse(format!(
                "{}'s saved placement names another incarnation",
                d.name
            )));
        }
        let current = Placement::observed(d, props);
        placement.volmode = if stored && dormant(props) {
            // A switch gives the new working copy the departing one's value,
            // the operator's latest; otherwise the saved one comes back.
            match departing
                .and_then(|departing| dataset(state, &format!("{departing}{relative}")).ok())
            {
                Some(old) => departing_placement(state, old)?.volmode,
                None => placement.volmode,
            }
        } else {
            // Not fenced by zboot: a local value stays as it is.
            current.volmode.clone()
        };
        let mountpoint = d.mountpoint.clone();
        if placement.canmount == Some(MountMode::On) && mountpoint.as_deref() == Some("/") {
            return Err(refuse(format!(
                "boot environment {} must keep canmount=noauto",
                d.name
            )));
        }
        let mounts = placement.canmount == Some(MountMode::On)
            && mountpoint
                .as_deref()
                .is_some_and(|p| p.starts_with('/') && p != "/");
        if mounts && d.mounted != Some(true) {
            let path = mountpoint.as_deref().unwrap();
            if let Some(other) = state.inspection.datasets.iter().find(|o| {
                o.name != d.name
                    && o.mounted == Some(true)
                    && o.mountpoint.as_deref() == Some(path)
                    && !(fencing
                        && departing.is_some_and(|peer| history::contains_dataset(peer, &o.name)))
            }) {
                return Err(refuse(format!(
                    "{}'s mountpoint {path} is occupied by {}",
                    d.name, other.name
                )));
            }
        }
        out.push(Activation {
            dataset: Endpoint {
                name: d.name.clone(),
                identity: d.identity.clone(),
            },
            changes: current != placement
                || (stored && own.as_ref() != Some(&placement))
                || (stored && dormant(props))
                || (mounts && d.mounted != Some(true)),
            placement,
            mounts,
            stored,
            saved: local(props, management::PLACEMENT_PROPERTY),
        });
    }
    Ok(out)
}
/// The placement a switch saves for a member `d` of the departing working
/// copy before fencing it: the saved one while it is already fenced from an
/// earlier attempt, else its live state, with a volume's hand-set `volmode`.
pub(crate) fn departing_placement(
    state: &NativeState,
    d: &zfs_tools::engine::Dataset,
) -> Result<Placement, Error> {
    let props = management::bound_properties(state, &d.name)?;
    if d.readonly
        && let Some(p) = props
            .get(management::PLACEMENT_PROPERTY)
            .filter(|p| p.source == "local")
    {
        let saved = Placement::parse(&p.value)?;
        if saved.identity == d.identity {
            return Ok(saved);
        }
    }
    Ok(Placement::observed(d, props))
}
/// Restore each member's placement (parents first) and mount the members
/// that mount automatically.
pub(crate) fn activate(b: &mut impl Backend, members: &[Activation]) -> Result<(), Error> {
    for m in members.iter().filter(|m| m.stored) {
        let props = b.properties(&m.dataset)?;
        let expected = m.placement.encode()?;
        if props.get(management::PLACEMENT_PROPERTY).is_some_and(|p| {
            p.source != "local" || (p.value != expected && m.saved.as_ref() != Some(&p.value))
        }) {
            return Err(refuse(
                "saved placement authority changed before activation",
            ));
        }
    }
    for m in members.iter().filter(|m| m.changes) {
        let e = &m.dataset;
        if m.stored {
            set(b, e, PropertyValue::Placement(m.placement.clone()))?;
        }
        if let Some(mode) = m.placement.canmount {
            set(b, e, PropertyValue::Canmount(mode))?;
        }
        set(b, e, PropertyValue::Readonly(m.placement.readonly))?;
        match &m.placement.volmode {
            Some(mode) => set(b, e, PropertyValue::Volmode(mode.clone()))?,
            None if m.stored && dormant(&b.properties(e)?) => {
                b.inherit_property(e, PropertyKey::Volmode, "none")?;
            }
            None => {}
        }
    }
    for m in members.iter().filter(|m| m.mounts) {
        let state = PairBackend::observe(b)?;
        let d = dataset(&state, &m.dataset.name)?;
        if d.identity != m.dataset.identity {
            return Err(refuse(format!("{} was replaced", m.dataset.name)));
        }
        if d.mounted == Some(true) {
            continue;
        }
        let result = b.mount(&m.dataset);
        let after = PairBackend::observe(b)?;
        let d = dataset(&after, &m.dataset.name)?;
        if d.identity != m.dataset.identity || d.mounted != Some(true) {
            return Err(result
                .err()
                .unwrap_or_else(|| refuse(format!("{} did not mount", m.dataset.name))));
        }
    }
    let state = PairBackend::observe(b)?;
    for m in members {
        let d = dataset(&state, &m.dataset.name)?;
        let props = management::bound_properties(&state, &m.dataset.name)?;
        if Placement::observed(d, props) != m.placement
            || (m.mounts && d.mounted != Some(true))
            || (m.stored && dormant(props))
        {
            return Err(refuse("activation roles or mounts were not verified"));
        }
    }
    Ok(())
}
/// A volume of a fenced copy keeps a local `volmode=none` at rest. Activation
/// of a member zboot fenced (its placement is saved) sets the saved `volmode`
/// back, or inherits it when none was saved. A volume hidden by hand, or a
/// local value other than `none`, stays.
fn dormant(props: &std::collections::BTreeMap<String, NativeProperty>) -> bool {
    props
        .get("volmode")
        .is_some_and(|p| p.source == "local" && p.value == "none")
}

/// Retire only exact local receipts after the caller durably approved and
/// verified the complete active tree. Missing receipts are lost-reply progress;
/// inherited, received or changed authority is never cleared.
pub(crate) fn retire_activation_placements(b: &mut impl Backend, root: &str) -> Result<(), Error> {
    let state = PairBackend::observe(b)?;
    let mut saved = Vec::new();
    for d in tree(&state, root) {
        let props = management::bound_properties(&state, &d.name)?;
        let Some(property) = props.get(management::PLACEMENT_PROPERTY) else {
            continue;
        };
        if outside(property, root) {
            continue;
        }
        if let Some(ancestor) = property.source.strip_prefix("inherited from ") {
            // A cut while saving placements can leave only a parent's local
            // receipt. It is not authority for this child: removing the exact
            // owner below will also retire its inherited view here.
            if ancestor != d.name
                && history::contains_dataset(root, ancestor)
                && history::contains_dataset(ancestor, &d.name)
            {
                let owner = dataset(&state, ancestor)?;
                let owner_props = management::bound_properties(&state, ancestor)?;
                if let Some(local) = owner_props.get(management::PLACEMENT_PROPERTY)
                    && local.source == "local"
                    && local.value == property.value
                {
                    let placement = Placement::parse(&local.value)?;
                    if placement == Placement::observed(owner, owner_props)
                        && placement.encode()? == local.value
                    {
                        continue;
                    }
                }
            }
            return Err(refuse(
                "inherited placement has no verified local owner in this activation",
            ));
        }
        let placement = Placement::parse(&property.value)?;
        if property.source != "local"
            || placement != Placement::observed(d, props)
            || placement.encode()? != property.value
        {
            return Err(refuse("activated placement receipt or native role changed"));
        }
        saved.push((endpoint(&state, &d.name)?, placement));
    }
    // Parents first: removing a child's local receipt must not reveal its
    // still-owned parent's receipt as foreign inherited authority.
    for (e, placement) in saved {
        let state = PairBackend::observe(b)?;
        let props = management::bound_properties(&state, &e.name)?;
        if Placement::observed(dataset(&state, &e.name)?, props) != placement {
            return Err(refuse(
                "activated member changed before placement retirement",
            ));
        }
        let expected = PropertyValue::Placement(placement).encode(&e)?;
        let before = b.properties(&e)?;
        let Some(property) = before.get(management::PLACEMENT_PROPERTY) else {
            continue;
        };
        if property.source != "local" || property.value != expected {
            return Err(refuse("placement authority changed before retirement"));
        }
        let result = b.inherit_property(&e, PropertyKey::Placement, &expected);
        if b.properties(&e)?
            .get(management::PLACEMENT_PROPERTY)
            .is_some_and(|property| !outside(property, root))
        {
            return Err(result
                .err()
                .unwrap_or_else(|| refuse("placement authority remains after retirement")));
        }
    }
    // Retiring a parent's local value can reveal a child's previously hidden
    // received value, even when that child had no local receipt of its own.
    let after = PairBackend::observe(b)?;
    for d in tree(&after, root) {
        if management::bound_properties(&after, &d.name)?
            .get(management::PLACEMENT_PROPERTY)
            .is_some_and(|property| !outside(property, root))
        {
            return Err(refuse("placement authority remains in the activated tree"));
        }
    }
    Ok(())
}
/// A placement record inherited from above the activated leaf belongs to
/// another dataset: `unpair` leaves the fenced side's saved placement on it,
/// and a leaf created below it and paired later inherits that record.
fn outside(property: &NativeProperty, root: &str) -> bool {
    property
        .source
        .strip_prefix("inherited from ")
        .is_some_and(|owner| !history::contains_dataset(root, owner))
}
