//! Recursive dataset verbs on the one intent record: `rollback`,
//! `drop`, `rename` and `fork`.
//!
//! Each verb plans from one complete native observation. An operation with
//! more than one durable effect writes its [`zfs_tools::engine::intent`] record on the root
//! of the pool that survives it before the first effect, advances it as steps
//! complete and clears it at the end. Records name roots, boundaries and a
//! member digest, never member lists; members an operation must find again are
//! marked natively instead. Every native effect re-binds the identity it acts
//! on, and an uncertain step is judged from native state when resumed. Library
//! code never takes the writer lock: the CLI entry and the Menu action do.
pub mod discard;
#[cfg(test)]
pub(crate) mod fake;
pub mod fork;
pub mod rename;
pub mod rollback;

use crate::history::contains_dataset as contains;
use serde::{Serialize, de::DeserializeOwned};
use std::{collections::BTreeSet, io::Write};
use zfs_tools::engine::{
    Dataset, Error, Snapshot, SnapshotRef, hold,
    intent::{self, Intent},
    management::{self, Endpoint, MountMode, Ownership, Placement},
    native::{self, NativeProperty},
    pool_of,
    state::{self, NativeState},
};

/// The record kinds [`resume_outcome`] continues: these verbs'.
pub const KINDS: [&str; 4] = [rollback::KIND, discard::KIND, rename::KIND, fork::KIND];

#[cfg(test)]
pub fn resume(
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<serde_json::Value, Error> {
    resume_outcome(record, abandon, dialogue).map(|outcome| outcome.result)
}

/// Continue or abandon an interrupted operation of one of [`KINDS`], returning
/// a typed completion status for CLI and Menu consumers.
pub fn resume_outcome(
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<crate::pairs::ResumeOutcome, Error> {
    fn outcome<O: Serialize>(
        value: Resumed<O>,
        complete: impl FnOnce(&O) -> bool,
    ) -> Result<crate::pairs::ResumeOutcome, Error> {
        let done = match &value {
            Resumed::Complete(value) => complete(value),
            Resumed::Abandoned(_) => true,
        };
        crate::pairs::ResumeOutcome::new(done, value)
    }
    match record.kind.as_str() {
        rollback::KIND => outcome(rollback::resume(record, abandon, dialogue)?, |v| v.complete),
        discard::KIND => outcome(discard::resume(record, abandon, dialogue)?, |v| v.complete),
        rename::KIND => outcome(rename::resume(record, abandon, dialogue)?, |v| v.complete),
        fork::KIND => outcome(fork::resume(record, abandon, dialogue)?, |v| v.complete),
        kind => Err(refuse(format!("{kind} is not a dataset tree operation"))),
    }
}

fn safe_inherit(key: &str) -> bool {
    key == "readonly" || key.starts_with("zboot:")
}

#[cfg(test)]
mod native_property_tests {
    #[test]
    fn inherit_cannot_enter_a_native_mount_changelist() {
        for key in [
            "mountpoint",
            "canmount",
            "sharenfs",
            "sharesmb",
            "zoned",
            "compression",
        ] {
            assert!(!super::safe_inherit(key), "{key}");
        }
        for key in [
            "readonly",
            "zboot:placement",
            "zboot:pending",
            "zboot:staging",
        ] {
            assert!(super::safe_inherit(key), "{key}");
        }
    }
}

pub(crate) fn refuse(detail: impl Into<String>) -> Error {
    Error::Refused(detail.into())
}

/// One native effect. The native backend re-binds the named identity first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Set {
        at: Endpoint,
        key: String,
        value: String,
    },
    Inherit {
        at: Endpoint,
        key: String,
    },
    /// One atomic `zfs snapshot` of every name, marked `zboot:capture=id`.
    Snapshot {
        names: Vec<String>,
        id: String,
    },
    DestroySnapshot(SnapshotRef),
    /// One dataset with no snapshots or children left.
    DestroyDataset(Endpoint),
    /// Plain `zfs rollback` to the latest snapshot; newer ones are destroyed
    /// first, each by its exact identity.
    Rollback(SnapshotRef),
    Rename {
        from: Endpoint,
        to: String,
    },
    /// Empty preparation only. A data-bearing clone requires a separately
    /// read-verified inert parent, bound again by Clone before its ioctl.
    CreateInert {
        parent: Endpoint,
        to: String,
        id: String,
    },
    RenameInert {
        from: Endpoint,
        parent: Endpoint,
        to: String,
    },
    QuiesceInert {
        at: Endpoint,
        id: String,
    },
    Clone {
        origin: SnapshotRef,
        parent: Endpoint,
        to: String,
        properties: Vec<(String, String)>,
    },
    /// `zpool set bootfs=`; `None` clears it.
    Bootfs {
        pool: String,
        dataset: Option<String>,
    },
}

/// Native state, effects, the intent record and holds. Tests use a model.
pub trait Backend: intent::Backend + hold::Backend {
    /// Complete native state, including snapshots and holds.
    fn observe(&mut self) -> Result<NativeState, Error>;
    fn running_root(&mut self) -> Result<Option<String>, Error>;
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error>;
    fn apply(&mut self, effect: &Effect) -> Result<(), Error>;
}

/// The host's pools.
pub struct Native;
impl intent::Backend for Native {
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
impl hold::Backend for Native {
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
fn bind(endpoint: &Endpoint) -> Result<(), Error> {
    use zfs_tools::engine::attachment::AttachmentBackend;
    zfs_tools::engine::attachment::NativeAttachment
        .properties(endpoint)
        .map(drop)
}
fn bind_point(point: &SnapshotRef) -> Result<(), Error> {
    let current = native::resolve_with(point, &mut native::run)?;
    if current.name != point.name {
        return Err(refuse(format!(
            "snapshot {} is now named {}; nothing changed",
            point.name, current.name
        )));
    }
    Ok(())
}
/// `zfs mount` overlays a non-empty directory on Linux, so refuse a
/// mountpoint that anything, ZFS or not (a RAM `/var`), already mounts.
fn zfs(args: &[&str]) -> Result<(), Error> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    native::run_mutating("zfs", &args).map(drop)
}
impl Backend for Native {
    fn observe(&mut self) -> Result<NativeState, Error> {
        state::observe()
    }
    fn running_root(&mut self) -> Result<Option<String>, Error> {
        crate::status::running_root().map_err(|e| refuse(format!("mountinfo: {e}")))
    }
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error> {
        use zfs_tools::engine::capture::CaptureBackend;
        zfs_tools::engine::capture::NativeCapture.capture_marker(point)
    }
    fn apply(&mut self, effect: &Effect) -> Result<(), Error> {
        match effect {
            Effect::Set { at, key, value } => {
                bind(at)?;
                zfs(&["set", "-u", &format!("{key}={value}"), &at.name])
            }
            Effect::Inherit { at, key } => {
                // OpenZFS has no `inherit -u`. User properties bypass its
                // mount changelist; readonly has an empty changelist and
                // only updates flags on already mounted filesystems. Never
                // permit a mountpoint/canmount inherit through this effect.
                if !safe_inherit(key) {
                    return Err(refuse(format!(
                        "unsafe native inherit of {key}; use an explicit set -u"
                    )));
                }
                bind(at)?;
                zfs(&["inherit", key, &at.name])
            }
            Effect::Snapshot { names, id } => {
                use zfs_tools::engine::capture::CaptureBackend;
                zfs_tools::engine::capture::NativeCapture.snapshot(names, id)
            }
            Effect::DestroySnapshot(point) => {
                bind_point(point)?;
                zfs(&["destroy", &point.name])
            }
            Effect::DestroyDataset(at) => {
                bind(at)?;
                zfs(&["destroy", &at.name])
            }
            Effect::Rollback(point) => {
                bind_point(point)?;
                zfs(&["rollback", &point.name])
            }
            Effect::Rename { from, to } => {
                zfs_tools::engine::validate_dataset_name(to)?;
                bind(from)?;
                zfs(&["rename", &from.name, to])
            }
            Effect::CreateInert { parent, to, id } => {
                bind(parent)?;
                zfs_tools::engine::validate_dataset_name(to)?;
                if to.rsplit_once('/').map(|p| p.0) != Some(parent.name.as_str()) {
                    return Err(refuse("inert preparation parent differs"));
                }
                let mut args = vec![
                    "create".into(),
                    "-u".into(),
                    "-o".into(),
                    "encryption=off".into(),
                ];
                for (key, value) in crate::placement::inert_properties(false)
                    .into_iter()
                    .chain([
                        (management::STAGING_PROPERTY.into(), id.clone()),
                        (management::PENDING_PROPERTY.into(), id.clone()),
                    ])
                {
                    args.extend(["-o".into(), format!("{key}={value}")]);
                }
                args.push(to.clone());
                native::run_mutating("zfs", &args).map(drop)
            }
            Effect::RenameInert { from, parent, to } => {
                zfs_tools::engine::validate_dataset_name(to)?;
                bind(from)?;
                bind(parent)?;
                if to.rsplit_once('/').map(|p| p.0) != Some(parent.name.as_str()) {
                    return Err(refuse("inert rename parent differs"));
                }
                require_inert_native(from)?;
                bind(parent)?;
                zfs(&["rename", "-u", &from.name, to])
            }
            Effect::QuiesceInert { at, id } => zfs_tools::engine::stream::quiesce_inert(at, id),
            Effect::Clone {
                origin,
                parent,
                to,
                properties,
            } => {
                zfs_tools::engine::validate_dataset_name(to)?;
                bind_point(origin)?;
                bind(parent)?;
                if to.rsplit_once('/').map(|p| p.0) != Some(parent.name.as_str()) {
                    return Err(refuse("clone parent differs"));
                }
                require_inert_native(parent)?;
                bind_point(origin)?;
                let mut args = vec!["clone".to_string()];
                for (key, value) in properties {
                    args.extend(["-o".into(), format!("{key}={value}")]);
                }
                args.extend([origin.name.clone(), to.clone()]);
                native::run_mutating("zfs", &args).map(drop)
            }
            Effect::Bootfs { pool, dataset } => {
                zfs_tools::engine::validate_dataset_name(pool)?;
                if pool.contains('/') {
                    return Err(Error::InvalidScope(pool.clone()));
                }
                native::run_mutating(
                    "zpool",
                    &[
                        "set".into(),
                        format!("bootfs={}", dataset.as_deref().unwrap_or("")),
                        pool.clone(),
                    ],
                )
                .map(drop)
            }
        }
    }
}

fn require_inert_native(at: &Endpoint) -> Result<(), Error> {
    bind(at)?;
    let state = state::observe()?;
    let root = dataset(&state, &at.name)?;
    for key in ["readonly", "volmode", "mountpoint"] {
        if key == "mountpoint" && root.kind == zfs_tools::engine::DatasetKind::Volume {
            continue;
        }
        if property(&state, &at.name, key).is_none_or(|p| p.source != "local") {
            return Err(refuse(format!(
                "{} lacks local inert {key} authority",
                at.name
            )));
        }
    }
    for member in members(&state, &at.name) {
        let volume = member.kind == zfs_tools::engine::DatasetKind::Volume;
        let inert = crate::placement::Posture::Inert { parent: false };
        if !inert.holds(volume, member.mounted == Some(true), |key| {
            property(&state, &member.name, key).map(|p| (p.value.as_str(), false))
        }) {
            return Err(refuse(format!("{} is not inert", member.name)));
        }
    }
    bind(at)
}

/// A finished operation's result, or what abandoning it left behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resumed<O> {
    Complete(O),
    Abandoned(Abandoned),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Abandoned {
    pub operation_id: String,
    pub kind: String,
    /// What the operation leaves behind, one line each.
    pub left: Vec<String>,
}

pub(crate) fn split_snapshot(text: &str) -> Result<(&str, &str), Error> {
    zfs_tools::engine::validate_snapshot_name(text)?;
    Ok(text.split_once('@').unwrap())
}
pub(crate) fn snapshots(state: &NativeState) -> Result<&[Snapshot], Error> {
    state
        .inspection
        .snapshots
        .as_deref()
        .ok_or_else(|| refuse("native inventory lacks snapshots"))
}
pub(crate) fn find<'a>(state: &'a NativeState, name: &str) -> Option<&'a Dataset> {
    state.inspection.datasets.iter().find(|d| d.name == name)
}
pub(crate) fn dataset<'a>(state: &'a NativeState, name: &str) -> Result<&'a Dataset, Error> {
    find(state, name).ok_or_else(|| Error::NotFound(name.to_string()))
}
pub(crate) fn endpoint(dataset: &Dataset) -> Endpoint {
    Endpoint {
        name: dataset.name.clone(),
        identity: dataset.identity.clone(),
    }
}
/// `root` and its descendants, parents before children.
pub(crate) fn members<'a>(state: &'a NativeState, root: &str) -> Vec<&'a Dataset> {
    let mut members: Vec<_> = state
        .inspection
        .datasets
        .iter()
        .filter(|d| contains(root, &d.name))
        .collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));
    members
}
/// Snapshots of exactly `dataset`, oldest first.
pub(crate) fn history<'a>(snapshots: &'a [Snapshot], dataset: &str) -> Vec<&'a Snapshot> {
    let mut found: Vec<_> = snapshots
        .iter()
        .filter(|s| s.name.split_once('@').map(|p| p.0) == Some(dataset))
        .collect();
    found.sort_by_key(|s| s.identity.createtxg);
    found
}
pub(crate) fn snapshot<'a>(snapshots: &'a [Snapshot], name: &str) -> Option<&'a Snapshot> {
    snapshots.iter().find(|s| s.name == name)
}
/// `name` below `root`: `""` for the root, else `/child...`.
pub(crate) fn relative<'a>(root: &str, name: &'a str) -> &'a str {
    &name[root.len()..]
}
pub(crate) fn property<'a>(
    state: &'a NativeState,
    name: &str,
    key: &str,
) -> Option<&'a NativeProperty> {
    state.dataset_properties.get(name)?.get(key)
}
pub(crate) fn local<'a>(state: &'a NativeState, name: &str, key: &str) -> Option<&'a str> {
    property(state, name, key)
        .filter(|p| p.source == "local")
        .map(|p| p.value.as_str())
}
/// A 32-hex-digit digest, as consent tokens are.
pub(crate) fn digest(value: &impl Serialize) -> Result<String, Error> {
    crate::consent::token(value).map_err(|e| refuse(e.to_string()))
}
/// The members digest: names below the root with their native identities.
pub(crate) fn member_digest(root: &str, members: &[&Dataset]) -> Result<String, Error> {
    let rows: Vec<_> = members
        .iter()
        .map(|d| (relative(root, &d.name), &d.identity))
        .collect();
    digest(&rows)
}
pub(crate) fn unpaired(state: &NativeState, name: &str) -> Result<(), Error> {
    match management::ownership(state, name)? {
        Ownership::Unpaired => Ok(()),
        _ => Err(refuse(format!(
            "{} belongs to a pair; unpair it first",
            zfs_tools::engine::escape_display(name)
        ))),
    }
}
/// Why a snapshot cannot be destroyed now, if it cannot.
pub(crate) fn protection(snapshot: &Snapshot) -> Option<String> {
    let name = zfs_tools::engine::escape_display(&snapshot.name);
    if snapshot.userrefs != 0 || !snapshot.holds.is_empty() {
        Some(format!("{name} is held ({})", snapshot.holds.join(", ")))
    } else if snapshot.defer_destroy {
        Some(format!("{name} is already marked for deferred destruction"))
    } else {
        None
    }
}
pub(crate) fn refuse_running(
    backend: &mut impl Backend,
    roots: &[&str],
    verb: &str,
) -> Result<(), Error> {
    if let Some(running) = backend.running_root()?
        && roots.iter().any(|root| contains(root, &running))
    {
        return Err(refuse(format!(
            "{verb} cannot change the running root {}; boot another BE or the Menu",
            zfs_tools::engine::escape_display(&running)
        )));
    }
    Ok(())
}
/// The bootfs of any pool inside `root`.
pub(crate) fn bootfs_inside<'a>(state: &'a NativeState, root: &str) -> Option<&'a String> {
    state
        .inspection
        .pools
        .iter()
        .filter_map(|p| p.bootfs.as_ref())
        .find(|bootfs| contains(root, bootfs))
}
pub(crate) fn pool_bootfs<'a>(state: &'a NativeState, name: &str) -> Option<&'a String> {
    state
        .inspection
        .pools
        .iter()
        .find(|p| p.name == name)
        .and_then(|p| p.bootfs.as_ref())
}
/// Ids of every active operation: those its intent records carry.
pub(crate) fn active(backend: &mut impl Backend) -> Result<BTreeSet<String>, Error> {
    let mut ids = BTreeSet::new();
    for (_, found) in intent::find(backend)? {
        if let intent::Found::Record(record) = found {
            ids.insert(record.id);
        }
    }
    Ok(ids)
}
pub(crate) fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
/// `PREFIX-YYYYMMDDTHHMMSSZ` in UTC, the default snapshot name format.
pub fn snapshot_name(prefix: &str, now: std::time::SystemTime) -> String {
    let seconds = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{prefix}-{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// Write `record` on `pool` and say its id, so an interrupted run names it.
pub(crate) fn begin<S: Serialize>(
    backend: &mut impl Backend,
    pool: &str,
    record: &Intent<S>,
    dialogue: &mut dyn Write,
) -> Result<(), Error> {
    intent::begin(backend, pool, record)?;
    let _ = writeln!(
        dialogue,
        "operation {} ({}); if interrupted, continue with `zboot resume {}`",
        record.id, record.kind, record.id
    );
    Ok(())
}
pub(crate) fn advance<S: Serialize + Clone>(
    backend: &mut impl Backend,
    pool: &str,
    record: &mut Intent<S>,
    step: u32,
) -> Result<(), Error> {
    let next = Intent {
        step,
        ..record.clone()
    };
    intent::advance(backend, pool, record, &next)?;
    *record = next;
    Ok(())
}
/// The record as `kind`'s state; anything else is refused before any effect.
pub(crate) fn decode<S: DeserializeOwned>(
    record: Intent<serde_json::Value>,
    kind: &str,
) -> Result<Intent<S>, Error> {
    if record.kind != kind {
        return Err(refuse(format!(
            "operation {} is a {} operation, not {kind}",
            record.id, record.kind
        )));
    }
    // A state this build does not write was written by an earlier zboot.
    let state = serde_json::from_value(record.state)
        .map_err(|e| refuse(format!("{} ({e})", intent::earlier(kind, &record.id))))?;
    Ok(Intent {
        schema_version: record.schema_version,
        id: record.id,
        kind: record.kind,
        step: record.step,
        state,
    })
}
/// The record on `pool` must still be exactly `record` before resuming it.
pub(crate) fn current<S: Serialize>(
    backend: &mut impl Backend,
    pool: &str,
    record: &Intent<S>,
) -> Result<(), Error> {
    let expected = intent::encode(record)?;
    if backend.read(pool)?.as_deref() != Some(expected.as_str()) {
        return Err(refuse(format!(
            "pool {pool} no longer records operation {} as given; list operations with `zboot status`",
            record.id
        )));
    }
    Ok(())
}
pub(crate) fn stopped(id: &str, error: Error) -> Error {
    zfs_tools::engine::effect::operation_hint(id);
    refuse(format!("operation {id} stopped: {error}"))
}

/// The placement a fence recorded on `dataset`, if it recorded one.
pub(crate) fn recorded_placement(
    state: &NativeState,
    dataset: &Dataset,
) -> Result<Option<Placement>, Error> {
    local(state, &dataset.name, management::PLACEMENT_PROPERTY)
        .map(Placement::parse)
        .transpose()?
        .map(|placement| {
            if placement.identity == dataset.identity {
                Ok(placement)
            } else {
                Err(refuse(format!(
                    "{} carries a placement record for another incarnation",
                    zfs_tools::engine::escape_display(&dataset.name)
                )))
            }
        })
        .transpose()
}
/// Whether `name`'s `readonly` is its own value rather than inherited.
fn readonly_is_own(state: &NativeState, name: &str) -> bool {
    property(state, name, "readonly").is_none_or(|p| p.source == "local" || p.source == "received")
}
/// The `readonly` value `name`'s children inherit once `finals` (values this
/// pass gives members, parents first) are applied.
fn parent_readonly(
    state: &NativeState,
    name: &str,
    finals: &std::collections::BTreeMap<String, bool>,
) -> bool {
    let Some((parent, _)) = name.rsplit_once('/') else {
        return false;
    };
    finals
        .get(parent)
        .copied()
        .unwrap_or_else(|| find(state, parent).is_some_and(|d| d.readonly))
}
/// Effects that fence `members` (parents first) read-only. Every placement
/// is recorded before any member changes, so a resumed fence never records
/// a placement it already changed. `readonly=on` is set only where it would
/// not be inherited.
pub(crate) fn fence(state: &NativeState, members: &[&Dataset]) -> Result<Vec<Effect>, Error> {
    let (mut placements, mut sets) = (Vec::new(), Vec::new());
    let mut finals = std::collections::BTreeMap::new();
    for dataset in members {
        let at = endpoint(dataset);
        if recorded_placement(state, dataset)?.is_none() {
            placements.push(Effect::Set {
                at: at.clone(),
                key: management::PLACEMENT_PROPERTY.into(),
                value: Placement::from_dataset(dataset).encode()?,
            });
        }
        let after = if readonly_is_own(state, &dataset.name) {
            dataset.readonly
        } else {
            parent_readonly(state, &dataset.name, &finals)
        };
        if !after {
            sets.push(Effect::Set {
                at: at.clone(),
                key: "readonly".into(),
                value: "on".into(),
            });
        }
        finals.insert(dataset.name.clone(), true);
    }
    placements.extend(sets);
    Ok(placements)
}
/// Effects that restore every recorded placement in `members`.
pub(crate) fn unfence_recorded(
    state: &NativeState,
    members: &[&Dataset],
) -> Result<Vec<Effect>, Error> {
    let mut targets = Vec::new();
    for dataset in members {
        if let Some(placement) = recorded_placement(state, dataset)? {
            targets.push((*dataset, placement));
        }
    }
    Ok(unfence(state, &targets, true))
}
/// Effects that restore each placement recorded by [`fence`] onto its
/// dataset (parents first; the same dataset, or a copy when the placement
/// came from the source). A `readonly` the parent will give anyway is
/// inherited rather than set; `recorded` also removes the record.
pub(crate) fn unfence(
    state: &NativeState,
    targets: &[(&Dataset, Placement)],
    recorded: bool,
) -> Vec<Effect> {
    let mut effects = Vec::new();
    let mut finals = std::collections::BTreeMap::new();
    for (dataset, placement) in targets {
        let at = endpoint(dataset);
        let inherited = parent_readonly(state, &dataset.name, &finals);
        if readonly_is_own(state, &dataset.name) {
            let local = local(state, &dataset.name, "readonly").is_some();
            if inherited == placement.readonly && local {
                effects.push(Effect::Inherit {
                    at: at.clone(),
                    key: "readonly".into(),
                });
            } else if dataset.readonly != placement.readonly {
                effects.push(Effect::Set {
                    at: at.clone(),
                    key: "readonly".into(),
                    value: if placement.readonly { "on" } else { "off" }.into(),
                });
            }
        } else if inherited != placement.readonly {
            effects.push(Effect::Set {
                at: at.clone(),
                key: "readonly".into(),
                value: if placement.readonly { "on" } else { "off" }.into(),
            });
        }
        finals.insert(dataset.name.clone(), placement.readonly);
        if let Some(mode) = placement.canmount {
            let current = dataset.canmount.map(|m| match m {
                zfs_tools::engine::CanMount::On => MountMode::On,
                zfs_tools::engine::CanMount::Off => MountMode::Off,
                zfs_tools::engine::CanMount::NoAuto => MountMode::NoAuto,
            });
            if mode == MountMode::On && local(state, &dataset.name, "canmount").is_some() {
                // canmount is non-inheritable. Restore its default value
                // explicitly with set -u rather than an invalid inherit.
                effects.push(Effect::Set {
                    at: at.clone(),
                    key: "canmount".into(),
                    value: "on".into(),
                });
            } else if current != Some(mode) {
                effects.push(Effect::Set {
                    at: at.clone(),
                    key: "canmount".into(),
                    value: mode.native().into(),
                });
            }
        }
        if recorded {
            effects.push(Effect::Inherit {
                at,
                key: management::PLACEMENT_PROPERTY.into(),
            });
        }
    }
    effects
}
pub(crate) fn apply_all(backend: &mut impl Backend, effects: &[Effect]) -> Result<(), Error> {
    effects.iter().try_for_each(|effect| backend.apply(effect))
}

/// The id a staging mark (`zboot:staging`/`zboot:pending`) names, if any.
pub(crate) fn staging_id(state: &NativeState, name: &str) -> Option<String> {
    [management::STAGING_PROPERTY, management::PENDING_PROPERTY]
        .iter()
        .find_map(|key| property(state, name, key).map(|p| p.value.clone()))
}

/// The staging mark a dataset at `name` inherits from its parent chain once it
/// has none of its own, as `KEY=ID on OWNER`: set on the parent or inherited
/// by it. Such a dataset looks like that operation's staging.
pub(crate) fn inherited_marker(state: &NativeState, name: &str) -> Option<String> {
    let (parent, _) = name.rsplit_once('/')?;
    [management::STAGING_PROPERTY, management::PENDING_PROPERTY]
        .iter()
        .find_map(|key| {
            let p = property(state, parent, key)?;
            let owner = p.source.strip_prefix("inherited from ").unwrap_or(parent);
            Some(format!(
                "{key}={} on {}",
                zfs_tools::engine::escape_display(&p.value),
                zfs_tools::engine::escape_display(owner)
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_kinds_are_disjoint_from_the_other_engines_and_others_are_refused() {
        for kind in KINDS {
            assert!(!crate::pairs::KINDS.contains(&kind), "{kind}");
            assert_ne!(kind, crate::restore::KIND);
        }
        let record = Intent::new(
            "11111111-1111-4111-8111-111111111111",
            "sync",
            serde_json::Value::Null,
        );
        assert!(resume(record, true, &mut std::io::sink()).is_err());
    }

    /// The Menu plans on read-only pools and reopens them writable after the
    /// typed answer; every engine plans again there and must find the same
    /// plan and token, so the confirmed operation runs.
    #[test]
    fn plans_and_tokens_survive_a_read_only_to_writable_reopen() {
        use fake::Fake;
        let fixture = || {
            let mut f = Fake::new();
            f.create("a/old");
            f.create("a/old/home");
            f.snap("a/old@one");
            f.snap("a/old/home@one");
            f.write("a/old");
            f.readonly_pools = ["a", "b"].map(String::from).into();
            f
        };
        // Planning wrote nothing, and saw every dataset read-only.
        let reopen = |f: &mut Fake| {
            assert_eq!(f.writes, 0);
            let state = f.state().unwrap();
            assert!(state.inspection.datasets.iter().all(|d| d.readonly));
            f.readonly_pools.clear();
        };
        let sink = &mut std::io::sink();

        let mut f = fixture();
        let plan = discard::plan_with(&mut f, &["a/old".into()]).unwrap();
        let token = discard::consent(&plan).unwrap();
        reopen(&mut f);
        assert_eq!(
            discard::consent(&discard::plan_with(&mut f, &["a/old".into()]).unwrap()).unwrap(),
            token
        );
        assert!(
            discard::execute_with(&mut f, &plan, &token, sink)
                .unwrap()
                .complete
        );

        let mut f = fixture();
        let plan = rollback::plan_with(&mut f, "a/old@one").unwrap();
        let token = rollback::consent(&plan).unwrap();
        reopen(&mut f);
        assert!(
            rollback::execute_with(&mut f, &plan, &token, sink)
                .unwrap()
                .complete
        );

        let mut f = fixture();
        assert!(rename::plan_with(&mut f, "a/old", "b/old").is_err());
        assert_eq!(f.writes, 0);

        let mut f = fixture();
        let plan = rename::plan_with(&mut f, "a/old", "a/new").unwrap();
        reopen(&mut f);
        assert!(rename::execute_with(&mut f, &plan, sink).unwrap().complete);

        // fork takes only a boot environment, one dataset with no children.
        let mut f = fixture();
        f.create("a/be");
        f.set("a/be", "mountpoint", "/");
        f.set("a/be", "canmount", "noauto");
        f.snap("a/be@one");
        assert!(fork::plan_with(&mut f, "a/old@one", "a/fork").is_err());
        let plan = fork::plan_with(&mut f, "a/be@one", "a/fork").unwrap();
        reopen(&mut f);
        assert!(fork::execute_with(&mut f, &plan, sink).unwrap().complete);
    }
}
