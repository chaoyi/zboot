//! `fork BE@SNAP DEST`: clone a snapshot of a boot environment as a new boot
//! environment in the same pool. Nothing is lost, so it runs directly.
//!
//! zboot forks only a boot environment, and a boot environment is one dataset
//! with no children; anything else is refused before any effect (a data tree
//! is `zfs clone`'s job). The record (on the pool's root) names the source,
//! its boundary snapshot, the destination and the reviewed placement. Steps:
//! hold the boundary snapshot, clone it below a verified inert empty
//! container, verify the clone's role and native identity, one rename, then
//! publication of placement and boot metadata. The hold and the empty
//! container are retired only after publication.
//!
//! A snapshot on the clone or the container, even another tool's recursive
//! one, changes no identity the fork binds, so it never stops the fork; the
//! container is destroyed only when it is empty, and otherwise left as this
//! operation's staging for `drop`. The clone's own markers are retired only
//! while its parent chain carries no staging mark it would inherit.
//!
//! A fork is refused while any boot environment has a `canmount=on`
//! descendant: the new boot environment would boot with it mounted over its
//! own ([`crate::mounting::refusal`]).
use super::{
    Abandoned, Backend, Effect, Resumed, advance, begin, current, dataset, decode, endpoint, find,
    history, inherited_marker, local, members, new_id, pool_of, refuse, snapshot, snapshots,
    split_snapshot, stopped, unpaired,
};
use crate::history::contains_dataset as contains;
use serde::{Deserialize, Serialize};
use std::io::Write;
use zfs_tools::engine::{
    CanMount, Dataset, DatasetIdentity, DatasetKind, Error, Guid, ObjsetId, SnapshotIdentity,
    SnapshotRef, Txg,
    capture::{self, CaptureBackend},
    escape_display as escape, hold,
    intent::{self, Intent},
    management::{self, Endpoint},
    operation::{DatasetRef, SnapshotScope},
    state::NativeState,
};

pub const KIND: &str = "fork";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForkPlan {
    pub source: Endpoint,
    pub parent: Endpoint,
    pub boundary: ForkBoundary,
    pub destination: String,
    pub cmdline: Option<String>,
    /// The role the fork publishes: `noauto`, or `off` kept from its source.
    pub canmount: String,
    /// The source's `volmode`, given back to the fork after inert staging.
    pub volmode: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkBoundary {
    Snapshot {
        snapshot: String,
        origin: SnapshotRef,
    },
    /// Snapshot the running boot environment when the fork runs.
    Capture,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForkOutcome {
    pub operation_id: String,
    pub source_snapshot: String,
    pub destination: Option<Endpoint>,
    pub complete: bool,
    /// What the fork leaves for review: a staging container that holds
    /// something zboot did not make.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub left: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    pool: String,
    source: Endpoint,
    /// The boundary label; generated when the fork captures.
    snapshot: String,
    /// Whether the fork makes its boundary snapshot itself.
    capture: bool,
    /// The boundary snapshot; unset only until a capture is verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    point: Option<SnapshotRef>,
    destination: String,
    canmount: String,
    volmode: String,
    cmdline: Option<String>,
    workspace: Workspace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workspace {
    parent: Endpoint,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<Endpoint>,
    /// The clone's native identity, once its inertness and role are verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clone: Option<DatasetIdentity>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    retired: bool,
}

const HELD: u32 = 1;
const CLONED: u32 = 2;
const PUBLISHED: u32 = 3;

fn tag(id: &str) -> String {
    format!("zboot:fork:{id}")
}

pub fn plan(snapshot: &str, destination: &str) -> Result<ForkPlan, Error> {
    plan_with(&mut super::Native, snapshot, destination)
}
pub fn plan_with(
    backend: &mut impl Backend,
    snapshot_name: &str,
    destination: &str,
) -> Result<ForkPlan, Error> {
    let (root, label) = split_snapshot(snapshot_name)?;
    plan_fork(backend, root, Some(label), destination)
}

pub fn plan_running(source: &str, destination: &str) -> Result<ForkPlan, Error> {
    plan_running_with(&mut super::Native, source, destination)
}

pub fn plan_running_with(
    backend: &mut impl Backend,
    source: &str,
    destination: &str,
) -> Result<ForkPlan, Error> {
    if backend.running_root()?.as_deref() != Some(source) {
        return Err(refuse(
            "a fork without a snapshot must capture the running boot environment",
        ));
    }
    plan_fork(backend, source, None, destination)
}

fn plan_fork(
    backend: &mut impl Backend,
    root: &str,
    label: Option<&str>,
    destination: &str,
) -> Result<ForkPlan, Error> {
    zfs_tools::engine::validate_dataset_name(root)?;
    zfs_tools::engine::validate_dataset_name(destination)?;
    if destination.len() >= 256 {
        return Err(refuse(
            "fork destination exceeds the native dataset name limit",
        ));
    }
    let Some((parent, _)) = destination.rsplit_once('/') else {
        return Err(refuse("a fork needs an existing parent dataset"));
    };
    if pool_of(root) != pool_of(destination) {
        return Err(refuse(
            "a fork is a clone in the same pool; use `zboot sync SRC DEST` for a paired copy across pools",
        ));
    }
    // OpenZFS2.4.4 dsl_dataset_clone_check rejects names >=256 bytes.
    if format!("{}/zboot-fork-{}/copy", pool_of(root), "f".repeat(36)).len() >= 256 {
        return Err(refuse(
            "the inert fork workspace would exceed the native dataset name limit",
        ));
    }
    if contains(root, destination) || contains(destination, root) {
        return Err(Error::InvalidScope(format!(
            "{root} and {destination} overlap"
        )));
    }
    let state = backend.observe()?;
    if let Some(reason) = crate::mounting::refusal(&state, None) {
        return Err(refuse(reason));
    }
    let parent_dataset = dataset(&state, parent)?;
    if parent_dataset.kind != DatasetKind::Filesystem {
        return Err(refuse("a fork's parent must be a filesystem"));
    }
    unmarked_parent(&state, destination)?;
    unpaired(&state, parent)?;
    destination_outside_boot_environment(&state, destination)?;
    if state
        .inspection
        .datasets
        .iter()
        .any(|d| contains(destination, &d.name))
    {
        return Err(refuse(format!("{} exists", escape(destination))));
    }
    let source = dataset(&state, root)?;
    require_boot_environment(&state, source)?;
    forkable(&state, root)?;
    crate::boot_environment::admit(&state, root).map_err(|error| match error {
        crate::menu::RecoveryError::Native(error) => error,
        error => refuse(error.to_string()),
    })?;
    rename_crypto(source, parent_dataset)?;
    let boundary = match label {
        Some(label) => {
            let name = format!("{root}@{label}");
            let point = snapshot(snapshots(&state)?, &name)
                .ok_or_else(|| refuse(format!("{} is missing", escape(&name))))?;
            if point.defer_destroy {
                return Err(refuse(format!(
                    "{} is marked for deferred destruction",
                    escape(&name)
                )));
            }
            ForkBoundary::Snapshot {
                snapshot: label.into(),
                origin: point.point(),
            }
        }
        None => {
            capture_scope(&state, &endpoint(source))?;
            ForkBoundary::Capture
        }
    };
    Ok(ForkPlan {
        source: endpoint(source),
        parent: endpoint(parent_dataset),
        boundary,
        destination: destination.into(),
        cmdline: super::property(&state, root, "zboot:cmdline").map(|p| p.value.clone()),
        canmount: if source.canmount == Some(CanMount::Off) {
            "off"
        } else {
            "noauto"
        }
        .into(),
        volmode: super::property(&state, root, "volmode")
            .ok_or_else(|| refuse("source volmode is unknown"))?
            .value
            .clone(),
    })
}

/// zboot forks only a boot environment, and a boot environment is one
/// dataset with no children. A data tree is `zfs clone`'s job.
fn require_boot_environment(state: &NativeState, source: &Dataset) -> Result<(), Error> {
    let name = escape(&source.name);
    if !crate::boot_environment::is_root(state, source) {
        return Err(refuse(format!(
            "{name} is not a boot environment (a filesystem with mountpoint=/); zboot forks only boot environments; use `zfs clone` for a data tree"
        )));
    }
    let children: Vec<_> = members(state, &source.name)
        .into_iter()
        .skip(1)
        .map(|d| escape(&d.name))
        .collect();
    if !children.is_empty() {
        let mut shown = children
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if children.len() > 3 {
            shown.push_str(&format!(" and {} more", children.len() - 3));
        }
        return Err(refuse(format!(
            "boot environment {name} has child datasets ({shown}); a boot environment is one dataset with no children, so zboot does not fork it; move them out of the boot environment first"
        )));
    }
    Ok(())
}

fn destination_outside_boot_environment(
    state: &NativeState,
    destination: &str,
) -> Result<(), Error> {
    // OpenZFS initramfs scripts/zfs1025-1030 walks ALL BE descendants;
    // mount_fs364-394 mounts noauto too, and none may fall back to the
    // org.zol:mountpoint property. Publication beneath another boot root
    // therefore cannot rely on noauto or an inert preparation mountpoint.
    // Share mounting's native shape/default ancestor definition. The
    // new root itself must not make its own publication fail.
    if let Some(ancestor) = crate::mounting::ancestor_boot_environment(state, destination) {
        return Err(refuse(format!(
            "fork destination {} is inside boot environment {}; its initramfs mounts descendants even with canmount=noauto; choose a destination outside that boot environment",
            escape(destination),
            escape(ancestor)
        )));
    }
    Ok(())
}

/// The fork's own staging marks are retired at publication, and then it
/// inherits whatever mark its parent chain carries: it would look like that
/// operation's staging, so the menu would fence it and `drop` could take it.
fn unmarked_parent(state: &NativeState, destination: &str) -> Result<(), Error> {
    match inherited_marker(state, destination) {
        Some(marker) => Err(refuse(format!(
            "fork destination {} would inherit {marker} and look like that operation's staging; finish or abandon that operation, or drop its staging, first",
            escape(destination)
        ))),
        None => Ok(()),
    }
}

fn rename_crypto(source: &Dataset, parent: &Dataset) -> Result<(), Error> {
    // Pinned2.4.4 dsl_crypt.c1913: clones share the origin's key object;
    // dsl_dir_rename_crypt_check1656 requires its root match the new parent.
    // Explicit encryption=off prep needs no key (create check1825-1833), so
    // locked parents with a compatible root are deliberately still supported.
    if source.encryption != zfs_tools::engine::Encryption::Off
        && source.encryptionroot != parent.encryptionroot
    {
        return Err(refuse(
            "inert fork publication cannot rename this encrypted clone outside its origin's encryption root; destination parent must share that root",
        ));
    }
    Ok(())
}
fn canonical_mountpoint(state: &NativeState, name: &str, value: &str) -> Result<String, Error> {
    let altroot = state
        .pool_properties
        .get(pool_of(name))
        .and_then(|p| p.get("altroot"))
        .map(|p| p.value.as_str());
    crate::placement::mountpoint_without_altroot(value, altroot)
}

pub fn describe(plan: &ForkPlan) -> String {
    let source = match &plan.boundary {
        ForkBoundary::Snapshot { snapshot, .. } => format!("{}@{snapshot}", plan.source.name),
        ForkBoundary::Capture => format!("{} (capture now)", plan.source.name),
    };
    format!(
        "Fork boot environment {} as {}; nothing is lost.\n  the fork is a boot environment candidate; boot selection checks its kernels\n  {} guid={} -> {}  mountpoint=/ canmount={} volmode={}\n",
        escape(&source),
        escape(&plan.destination),
        escape(&plan.source.name),
        plan.source.identity.guid,
        escape(&plan.destination),
        escape(&plan.canmount),
        escape(&plan.volmode),
    )
}

/// The boundary snapshot, which must still be the bound snapshot of the
/// planned source.
fn origin(state: &NativeState, s: &State) -> Result<SnapshotRef, Error> {
    let name = format!("{}@{}", s.source.name, s.snapshot);
    let source = find(state, &s.source.name).is_some_and(|d| endpoint(d) == s.source);
    match (source, snapshot(snapshots(state)?, &name), &s.point) {
        (true, Some(found), Some(point)) if found.point() == *point => Ok(found.point()),
        _ => Err(refuse(format!(
            "{} is not the snapshot the fork was planned for",
            escape(&name)
        ))),
    }
}

/// Refuse, before any effect, a record that could outgrow one intent
/// property once every identity it will learn is filled in.
fn fits(record: &Intent<State>) -> Result<(), Error> {
    let max = DatasetIdentity {
        pool_guid: Guid::new(u64::MAX),
        guid: Guid::new(u64::MAX),
        createtxg: Txg::new(u64::MAX),
        objsetid: ObjsetId::new(u64::MAX),
    };
    let mut largest = record.clone();
    let s = &mut largest.state;
    s.point = Some(SnapshotRef {
        name: format!("{}@{}", s.source.name, s.snapshot),
        dataset_guid: max.guid,
        identity: SnapshotIdentity {
            pool_guid: max.pool_guid,
            guid: max.guid,
            createtxg: max.createtxg,
            objsetid: max.objsetid,
        },
    });
    s.workspace.owner = Some(Endpoint {
        name: s.workspace.name.clone(),
        identity: max.clone(),
    });
    s.workspace.clone = Some(max);
    s.workspace.retired = true;
    largest.step = PUBLISHED;
    intent::encode(&largest).map(drop)
}

pub fn execute(plan: &ForkPlan, dialogue: &mut dyn Write) -> Result<ForkOutcome, Error> {
    execute_with(&mut super::Native, plan, dialogue)
}
pub fn execute_with(
    backend: &mut impl Backend,
    plan: &ForkPlan,
    dialogue: &mut dyn Write,
) -> Result<ForkOutcome, Error> {
    execute_at_with(backend, plan, std::time::SystemTime::now(), dialogue)
}

fn execute_at_with(
    backend: &mut impl Backend,
    plan: &ForkPlan,
    now: std::time::SystemTime,
    dialogue: &mut dyn Write,
) -> Result<ForkOutcome, Error> {
    let fresh = match &plan.boundary {
        ForkBoundary::Snapshot { snapshot, .. } => plan_with(
            backend,
            &format!("{}@{snapshot}", plan.source.name),
            &plan.destination,
        )?,
        ForkBoundary::Capture => plan_running_with(backend, &plan.source.name, &plan.destination)?,
    };
    if fresh != *plan {
        return Err(refuse("the fork plan changed; nothing changed"));
    }
    let id = new_id();
    let (label, point) = match &plan.boundary {
        ForkBoundary::Snapshot { snapshot, origin } => (snapshot.clone(), Some(origin.clone())),
        ForkBoundary::Capture => (super::snapshot_name("zboot", now), None),
    };
    let mut record = Intent::new(
        id.clone(),
        KIND,
        State {
            pool: pool_of(&plan.source.name).into(),
            source: plan.source.clone(),
            snapshot: label,
            capture: point.is_none(),
            point,
            destination: plan.destination.clone(),
            canmount: plan.canmount.clone(),
            volmode: plan.volmode.clone(),
            cmdline: plan.cmdline.clone(),
            workspace: Workspace {
                name: format!("{}/zboot-fork-{id}", pool_of(&plan.parent.name)),
                parent: plan.parent.clone(),
                owner: None,
                clone: None,
                retired: false,
            },
        },
    );
    fits(&record)?;
    let state = backend.observe()?;
    if record.state.capture {
        capture_scope(&state, &record.state.source)?;
        let name = format!("{}@{}", record.state.source.name, record.state.snapshot);
        zfs_tools::engine::validate_snapshot_name(&name)?;
        if snapshot(snapshots(&state)?, &name).is_some() {
            return Err(refuse(format!("capture name already exists: {name}")));
        }
    } else if origin(&state, &record.state).is_err() {
        return Err(refuse("the fork boundary changed before its intent"));
    }
    begin(backend, &record.state.pool.clone(), &record, dialogue)?;
    run(backend, &mut record)
        .map(|outcome| say(dialogue, outcome))
        .map_err(|e| stopped(&id, e))
}

/// Say what a finished fork leaves for review; the outcome carries it too.
fn say(dialogue: &mut dyn Write, outcome: ForkOutcome) -> ForkOutcome {
    for line in &outcome.left {
        let _ = writeln!(dialogue, "{line}");
    }
    outcome
}

fn checkpoint(
    backend: &mut impl Backend,
    record: &mut Intent<State>,
    step: u32,
    change: impl FnOnce(&mut State),
) -> Result<(), Error> {
    let mut next = record.clone();
    next.step = step;
    change(&mut next.state);
    intent::advance(backend, &record.state.pool, record, &next)?;
    *record = next;
    Ok(())
}

/// The capture scope: exactly the planned source, which has no children.
fn capture_scope(state: &NativeState, source: &Endpoint) -> Result<SnapshotScope, Error> {
    let scope = SnapshotScope::plan(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
        std::slice::from_ref(&source.name),
    )?;
    let planned = DatasetRef {
        name: source.name.clone(),
        identity: source.identity.clone(),
    };
    if scope.datasets() != std::slice::from_ref(&planned) {
        return Err(refuse(format!(
            "{} is no longer the planned boot environment with no children",
            escape(&source.name)
        )));
    }
    Ok(scope)
}

struct CaptureAdapter<'a, B>(&'a mut B);
impl<B: Backend> CaptureBackend for CaptureAdapter<'_, B> {
    fn observe(&mut self) -> Result<NativeState, Error> {
        self.0.observe()
    }
    fn snapshot(&mut self, names: &[String], id: &str) -> Result<(), Error> {
        self.0.apply(&Effect::Snapshot {
            names: names.to_vec(),
            id: id.into(),
        })
    }
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error> {
        self.0.capture_marker(point)
    }
}

fn ensure_capture(backend: &mut impl Backend, record: &mut Intent<State>) -> Result<(), Error> {
    if !record.state.capture || record.state.point.is_some() {
        return Ok(());
    }
    if record.step != 0 || record.state.workspace.owner.is_some() {
        return Err(refuse("fork capture checkpoint is inconsistent"));
    }
    let source = record.state.source.clone();
    let name = format!("{}@{}", source.name, record.state.snapshot);
    let state = backend.observe()?;
    let scope = capture_scope(&state, &source)?;
    if snapshot(snapshots(&state)?, &name).is_none() {
        // A resumed capture snapshots the source as it is now, so it must
        // still be an unpaired boot environment.
        require_boot_environment(&state, dataset(&state, &source.name)?)?;
        forkable(&state, &source.name)?;
        let outcome = capture::capture_prepared_with(
            &scope,
            &record.state.snapshot,
            &record.id,
            &mut CaptureAdapter(backend),
        )?;
        if outcome.status() != zfs_tools::CaptureStatus::Complete || !outcome.missing().is_empty() {
            return Err(refuse(format!(
                "fork capture is incomplete or uncertain: {:?}",
                outcome.detail()
            )));
        }
    }
    let state = backend.observe()?;
    let point = snapshot(snapshots(&state)?, &name)
        .ok_or_else(|| refuse("fork capture is missing"))?
        .point();
    if point.dataset_guid != source.identity.guid
        || point.identity.pool_guid != source.identity.pool_guid
        || backend.capture_marker(&point)? != record.id
    {
        return Err(refuse(
            "fork capture has foreign ownership or native identities",
        ));
    }
    let state = backend.observe()?;
    scope.revalidate(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
    )?;
    if snapshot(snapshots(&state)?, &name).is_none_or(|s| s.point() != point) {
        return Err(refuse("fork captured snapshot changed during verification"));
    }
    checkpoint(backend, record, 0, |s| s.point = Some(point))
}

fn set_local(
    backend: &mut impl Backend,
    at: &Endpoint,
    key: &str,
    value: &str,
) -> Result<(), Error> {
    let state = backend.observe()?;
    if endpoint(dataset(&state, &at.name)?) != *at {
        return Err(refuse("fork clone incarnation changed"));
    }
    let matches = |state: &NativeState| -> Result<bool, Error> {
        match local(state, &at.name, key) {
            Some(actual) => Ok(if key == "mountpoint" {
                canonical_mountpoint(state, &at.name, actual)? == value
            } else {
                actual == value
            }),
            None => Ok(false),
        }
    };
    if matches(&state)? {
        return Ok(());
    }
    let result = backend.apply(&Effect::Set {
        at: at.clone(),
        key: key.into(),
        value: value.into(),
    });
    let after = backend.observe()?;
    if find(&after, &at.name).is_some_and(|d| endpoint(d) == *at) && matches(&after)? {
        Ok(())
    } else {
        Err(result
            .err()
            .unwrap_or_else(|| refuse(format!("{} {key} was not verified", at.name))))
    }
}
/// `root` and everything below it are unmounted filesystems that cannot
/// mount or expose devices; with `locals`, by values set on each of them.
fn inert(state: &NativeState, root: &str, locals: bool) -> Result<(), Error> {
    for d in members(state, root) {
        let inert = crate::placement::Posture::Inert { parent: false };
        if !inert.holds(false, d.mounted == Some(true), |key| {
            super::property(state, &d.name, key).map(|p| (p.value.as_str(), false))
        }) {
            return Err(refuse(format!("{} is not an inert fork workspace", d.name)));
        }
        if locals {
            for (key, value) in crate::placement::inert_properties(false) {
                if key != "canmount" && local(state, &d.name, &key) != Some(value.as_str()) {
                    return Err(refuse(format!("{} lacks local {key} authority", d.name)));
                }
            }
        }
    }
    Ok(())
}
fn prepare(backend: &mut impl Backend, record: &mut Intent<State>) -> Result<Endpoint, Error> {
    let w = record.state.workspace.clone();
    let state = backend.observe()?;
    if endpoint(dataset(&state, &w.parent.name)?) != w.parent {
        return Err(refuse("fork destination parent changed"));
    }
    if let Some(owner) = w.owner {
        if endpoint(dataset(&state, &owner.name)?) != owner {
            return Err(refuse("fork container incarnation changed"));
        }
        for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
            if local(&state, &owner.name, key) != Some(record.id.as_str()) {
                return Err(refuse("fork container ownership changed"));
            }
        }
        return Ok(owner);
    }
    if find(&state, &w.name).is_none() {
        let creation_parent = endpoint(dataset(&state, pool_of(&w.name))?);
        if creation_parent.identity.pool_guid != record.state.source.identity.pool_guid {
            return Err(refuse("fork preparation pool incarnation changed"));
        }
        backend.apply(&Effect::CreateInert {
            parent: creation_parent,
            to: w.name.clone(),
            id: record.id.clone(),
        })?;
    }
    // A snapshot of the container (another tool's recursive one) changes
    // neither its identity nor its emptiness; it only keeps the container
    // from being destroyed at the end.
    let state = backend.observe()?;
    let d = dataset(&state, &w.name)?;
    if d.kind != DatasetKind::Filesystem
        || d.origin.is_some()
        || members(&state, &w.name).len() != 1
        || local(&state, &w.name, management::STAGING_PROPERTY) != Some(record.id.as_str())
    {
        return Err(refuse(format!(
            "{} is an unbound preparation survivor; it is left untouched; abandon this fork before creating another",
            w.name
        )));
    }
    inert(&state, &w.name, true)?;
    let owner = endpoint(d);
    let step = record.step;
    checkpoint(backend, record, step, |s| {
        s.workspace.owner = Some(owner.clone())
    })?;
    Ok(owner)
}

/// The fork's clone at `name`, if anything is there: a filesystem cloned from
/// the bound snapshot after the container was made, with no children, and the
/// verified identity once it is recorded. Its snapshots, even another tool's,
/// change none of these and are left alone.
fn clone_at(state: &NativeState, s: &State, name: &str) -> Result<Option<Endpoint>, Error> {
    let Some(d) = find(state, name) else {
        return Ok(None);
    };
    let point = s
        .point
        .as_ref()
        .ok_or_else(|| refuse("fork boundary is not bound"))?;
    let origin = snapshots(state)?
        .iter()
        .find(|p| p.identity == point.identity && p.dataset_guid == point.dataset_guid)
        .ok_or_else(|| refuse("fork's bound origin snapshot is no longer observable"))?;
    if d.origin.as_deref() != Some(origin.name.as_str())
        || d.kind != DatasetKind::Filesystem
        || d.identity.pool_guid != s.source.identity.pool_guid
        || s.workspace
            .owner
            .as_ref()
            .is_some_and(|owner| d.identity.createtxg < owner.identity.createtxg)
        || s.workspace
            .clone
            .as_ref()
            .is_some_and(|clone| d.identity != *clone)
    {
        return Err(refuse(format!(
            "{} is not the fork's clone of the bound snapshot",
            escape(name)
        )));
    }
    if let Some(child) = members(state, name).get(1) {
        return Err(refuse(format!(
            "{} has child dataset {}; a fork is one dataset with no children",
            escape(name),
            escape(&child.name)
        )));
    }
    Ok(Some(endpoint(d)))
}
fn require_clone(state: &NativeState, s: &State, name: &str) -> Result<Endpoint, Error> {
    clone_at(state, s, name)?
        .ok_or_else(|| refuse(format!("fork clone {} is missing", escape(name))))
}
fn role(state: &NativeState, s: &State, name: &str) -> Result<(), Error> {
    if local(state, name, "canmount") != Some(s.canmount.as_str()) {
        return Err(refuse(format!(
            "{name} final canmount role was not verified"
        )));
    }
    Ok(())
}
fn admit_host(state: &NativeState) -> Result<(), Error> {
    match crate::mounting::refusal(state, None) {
        Some(reason) => Err(refuse(reason)),
        None => Ok(()),
    }
}
fn finish(backend: &mut impl Backend, record: &mut Intent<State>) -> Result<ForkOutcome, Error> {
    let s = record.state.clone();
    let owner = s
        .workspace
        .owner
        .as_ref()
        .ok_or_else(|| refuse("fork container is not bound"))?;
    if !s.workspace.retired {
        let state = backend.observe()?;
        if find(&state, &owner.name).is_some_and(|d| endpoint(d) != *owner) {
            return Err(refuse("fork cleanup container was replaced"));
        }
        let at = require_clone(&state, &s, &s.destination)?;
        for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
            let state = backend.observe()?;
            retirable(backend, &state, &at, &record.id)?;
            if let Some(value) = local(&state, &at.name, key) {
                if value != record.id {
                    return Err(refuse("fork management authority changed"));
                }
                backend.apply(&Effect::Inherit {
                    at: at.clone(),
                    key: key.into(),
                })?;
            }
        }
        // A mark that reached the parent during the retirement would now be
        // the fork's; retirement is recorded only without one.
        let state = backend.observe()?;
        retirable(backend, &state, &at, &record.id)?;
        let point = s
            .point
            .as_ref()
            .ok_or_else(|| refuse("fork boundary is not bound"))?;
        hold::release(backend, point, &tag(&record.id))?;
        checkpoint(backend, record, PUBLISHED, |s| s.workspace.retired = true)?;
    }
    let left = retire_container(backend, owner, &record.id)?;
    intent::finish(backend, &s.pool, record)?;
    let state = backend.observe()?;
    Ok(ForkOutcome {
        operation_id: record.id.clone(),
        source_snapshot: format!("{}@{}", s.source.name, s.snapshot),
        destination: find(&state, &s.destination).map(endpoint),
        complete: true,
        left,
    })
}

/// Whether the published fork may lose its own staging marks: not while its
/// parent chain carries one. Then it keeps its own, set again where they were
/// already retired, so until retirement is recorded it is this operation's
/// staging and never looks like another's.
fn retirable(
    backend: &mut impl Backend,
    state: &NativeState,
    at: &Endpoint,
    id: &str,
) -> Result<(), Error> {
    match unmarked_parent(state, &at.name) {
        Ok(()) => Ok(()),
        Err(error) => {
            keep_marks(backend, at, id)?;
            Err(error)
        }
    }
}
fn keep_marks(backend: &mut impl Backend, at: &Endpoint, id: &str) -> Result<(), Error> {
    for key in [management::STAGING_PROPERTY, management::PENDING_PROPERTY] {
        set_local(backend, at, key, id)?;
    }
    Ok(())
}

/// Destroy the fork's empty container. One that holds a snapshot or dataset
/// zboot did not make (another tool's `zfs snapshot -r POOL@x`, say) stays,
/// still marked as this operation's staging, for `drop` to list for review:
/// a native destroy without `-r` cannot remove them, and zboot never destroys
/// them. Returns what is left, one line each.
fn retire_container(
    backend: &mut impl Backend,
    owner: &Endpoint,
    id: &str,
) -> Result<Vec<String>, Error> {
    // None once the container is gone, else what it holds.
    let contents = |state: &NativeState| -> Result<Option<Vec<String>>, Error> {
        let Some(container) = find(state, &owner.name) else {
            return Ok(None);
        };
        if endpoint(container) != *owner
            || local(state, &owner.name, management::STAGING_PROPERTY) != Some(id)
        {
            return Err(refuse("fork container cleanup marker changed"));
        }
        let mut held: Vec<String> = members(state, &owner.name)
            .into_iter()
            .skip(1)
            .map(|d| d.name.clone())
            .collect();
        held.extend(
            history(snapshots(state)?, &owner.name)
                .into_iter()
                .map(|p| p.name.clone()),
        );
        Ok(Some(held))
    };
    let kept = |held: Vec<String>| {
        let mut shown = held.iter().take(3).map(|n| escape(n)).collect::<Vec<_>>();
        if held.len() > 3 {
            shown.push(format!("{} more", held.len() - 3));
        }
        vec![format!(
            "staging container {} is left in place, still marked as this fork's staging: it holds {}, which zboot did not make; inspect it, then `zboot drop {}`",
            escape(&owner.name),
            shown.join(", "),
            escape(&owner.name)
        )]
    };
    match contents(&backend.observe()?)? {
        None => return Ok(Vec::new()),
        Some(held) if !held.is_empty() => return Ok(kept(held)),
        Some(_) => {}
    }
    // Something can appear between that observation and the destroy, which
    // then fails; the container's state afterwards decides.
    let destroyed = backend.apply(&Effect::DestroyDataset(owner.clone()));
    match (destroyed, contents(&backend.observe()?)?) {
        (_, None) => Ok(Vec::new()),
        (_, Some(held)) if !held.is_empty() => Ok(kept(held)),
        (Err(error), Some(_)) => Err(error),
        (Ok(()), Some(_)) => Err(refuse("fork container was not destroyed")),
    }
}
fn run(backend: &mut impl Backend, record: &mut Intent<State>) -> Result<ForkOutcome, Error> {
    if record.step >= PUBLISHED {
        return finish(backend, record);
    }
    let state = backend.observe()?;
    destination_outside_boot_environment(&state, &record.state.destination)?;
    unmarked_parent(&state, &record.state.destination)?;
    admit_host(&state)?;
    if record.step < CLONED && find(&state, &record.state.destination).is_some() {
        return Err(refuse("fork final name is occupied; no clone created"));
    }
    ensure_capture(backend, record)?;
    let point = origin(&backend.observe()?, &record.state)?;
    if record.step < HELD {
        hold::hold(backend, &point, &tag(&record.id))?;
        advance(backend, &record.state.pool.clone(), record, HELD)?;
    }
    let owner = prepare(backend, record)?;
    let staged = format!("{}/copy", owner.name);
    if record.step < CLONED {
        let s = record.state.clone();
        let state = backend.observe()?;
        for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
            if let Some(value) = local(&state, &staged, key)
                && value != record.id
            {
                return Err(refuse(format!(
                    "{staged} carries another operation's {key}"
                )));
            }
        }
        admit_host(&state)?;
        if clone_at(&state, &s, &staged)?.is_none() {
            let parent = endpoint(dataset(&state, &owner.name)?);
            inert(&state, &parent.name, true)?;
            let mut properties = crate::placement::inert_properties(false);
            properties.retain(|(key, _)| key != "canmount");
            properties.extend([
                (management::STAGING_PROPERTY.into(), record.id.clone()),
                (management::PENDING_PROPERTY.into(), record.id.clone()),
                ("canmount".into(), s.canmount.clone()),
            ]);
            backend.apply(&Effect::Clone {
                origin: point,
                parent,
                to: staged.clone(),
                properties,
            })?;
        }
        let state = backend.observe()?;
        inert(&state, &staged, false)?;
        let at = require_clone(&state, &s, &staged)?;
        for (key, value) in crate::placement::inert_properties(false) {
            if key != "canmount" {
                set_local(backend, &at, &key, &value)?;
            }
        }
        set_local(backend, &at, "canmount", &s.canmount)?;
        for key in [management::STAGING_PROPERTY, management::PENDING_PROPERTY] {
            set_local(backend, &at, key, &record.id)?;
        }
        let state = backend.observe()?;
        inert(&state, &staged, true)?;
        role(&state, &s, &staged)?;
        backend.apply(&Effect::QuiesceInert {
            at: at.clone(),
            id: record.id.clone(),
        })?;
        let clone = require_clone(&backend.observe()?, &s, &staged)?;
        checkpoint(backend, record, CLONED, |s| {
            s.workspace.clone = Some(clone.identity)
        })?;
    }
    let s = record.state.clone();
    let state = backend.observe()?;
    destination_outside_boot_environment(&state, &s.destination)?;
    if find(&state, &staged).is_some() {
        if find(&state, &s.destination).is_some() {
            return Err(refuse("fork final name is occupied; no rename attempted"));
        }
        let at = require_clone(&state, &s, &staged)?;
        inert(&state, &staged, true)?;
        role(&state, &s, &staged)?;
        admit_host(&state)?;
        unmarked_parent(&state, &s.destination)?;
        let parent = &s.workspace.parent;
        rename_crypto(dataset(&state, &staged)?, dataset(&state, &parent.name)?)?;
        backend.apply(&Effect::RenameInert {
            from: at,
            parent: parent.clone(),
            to: s.destination.clone(),
        })?;
    }
    let state = backend.observe()?;
    let at = require_clone(&state, &s, &s.destination)?;
    role(&state, &s, &s.destination)?;
    admit_host(&state)?;
    set_local(backend, &at, "mountpoint", "/")?;
    set_local(backend, &at, "readonly", "off")?;
    set_local(backend, &at, "volmode", &s.volmode)?;
    role(&backend.observe()?, &s, &s.destination)?;
    if let Some(cmdline) = &s.cmdline {
        set_local(backend, &at, "zboot:cmdline", cmdline)?;
    }
    advance(backend, &s.pool, record, PUBLISHED)?;
    finish(backend, record)
}

/// Fence an unpublished clone again so it stays staging for `drop`: inert
/// in the container, or at the destination when the rename already ran.
fn abandon_workspace(backend: &mut impl Backend, record: &Intent<State>) -> Result<(), Error> {
    let s = &record.state;
    let Some(owner) = &s.workspace.owner else {
        return Ok(());
    };
    let state = backend.observe()?;
    // The container holds no record of its own; a missing one leaves only a
    // renamed clone to fence, but a replaced one is never acted on.
    if find(&state, &owner.name).is_some_and(|d| {
        endpoint(d) != *owner
            || local(&state, &owner.name, management::STAGING_PROPERTY) != Some(record.id.as_str())
    }) {
        return Err(refuse("fork abandonment lost its container authority"));
    }
    let staged = format!("{}/copy", owner.name);
    let at = if find(&state, &staged).is_some() {
        clone_at(&state, s, &staged)?
    } else if local(&state, &s.destination, management::STAGING_PROPERTY)
        == Some(record.id.as_str())
    {
        clone_at(&state, s, &s.destination)?
    } else {
        None
    };
    if let Some(at) = at {
        if dataset(&state, &at.name)?.mounted == Some(true) {
            return Err(refuse(
                "an unpublished fork was mounted; unmount it before abandonment",
            ));
        }
        for (key, value) in crate::placement::inert_properties(false) {
            set_local(backend, &at, &key, &value)?;
        }
    }
    Ok(())
}

/// The record as this build writes it. A fork record from another build is
/// not resumed or abandoned here.
fn decode_current(record: Intent<serde_json::Value>) -> Result<Intent<State>, Error> {
    let (id, ours) = (record.id.clone(), record.kind == KIND);
    decode(record, KIND).map_err(|error| {
        if ours {
            refuse(format!(
                "fork operation {id} was written by another zboot build, which this one does not resume or abandon; finish it with the build that started it"
            ))
        } else {
            error
        }
    })
}

/// Continue or abandon an interrupted fork. Abandoning releases the hold and
/// destroys nothing; an unpublished clone stays as staging for `drop`.
pub fn resume(
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<Resumed<ForkOutcome>, Error> {
    resume_with(&mut super::Native, record, abandon, dialogue)
}
pub fn resume_with(
    backend: &mut impl Backend,
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<Resumed<ForkOutcome>, Error> {
    let mut record = decode_current(record)?;
    let pool = record.state.pool.clone();
    current(backend, &pool, &record)?;
    let id = record.id.clone();
    // A fork records steps 0 to PUBLISHED; a later step is another build's.
    if record.step > PUBLISHED {
        return Err(refuse(zfs_tools::engine::intent::earlier("fork", &id)));
    }
    let s = &record.state;
    if s.point.is_none() && (!s.capture || record.step != 0 || s.workspace.owner.is_some()) {
        return Err(refuse("fork capture checkpoint is inconsistent"));
    }
    if !abandon {
        let _ = writeln!(dialogue, "resuming fork {id}");
        return run(backend, &mut record)
            .map(|outcome| Resumed::Complete(say(dialogue, outcome)))
            .map_err(|e| stopped(&id, e));
    }
    let left = abandon_fork(backend, &mut record)?;
    for line in &left {
        let _ = writeln!(dialogue, "abandoned fork {id}: {line}");
    }
    Ok(Resumed::Abandoned(Abandoned {
        operation_id: id,
        kind: KIND.into(),
        left,
    }))
}

/// End the fork without finishing it, and say what it leaves. A published
/// fork finishes its retirement, unless its parent chain now carries a
/// staging mark: then it stays this operation's staging, as an unpublished
/// clone does.
fn abandon_fork(
    backend: &mut impl Backend,
    record: &mut Intent<State>,
) -> Result<Vec<String>, Error> {
    let id = record.id.clone();
    let pool = record.state.pool.clone();
    let state = backend.observe()?;
    let marker = inherited_marker(&state, &record.state.destination);
    // A published clone that is no longer at its name, destroyed or renamed
    // by hand, has nothing left to retire: abandoning ends the record
    // instead of asking for the clone forever.
    let gone = find(&state, &record.state.destination).is_none();
    if record.step >= PUBLISHED && (record.state.workspace.retired || (marker.is_none() && !gone)) {
        let mut left = vec![format!(
            "the fork {} is published",
            escape(&record.state.destination)
        )];
        left.extend(finish(backend, record)?.left);
        return Ok(left);
    }
    let mut left = Vec::new();
    if record.step >= PUBLISHED {
        if let Some(at) = clone_at(&state, &record.state, &record.state.destination)? {
            keep_marks(backend, &at, &id)?;
        } else {
            left.push(format!(
                "the fork's clone is no longer at {}; nothing is published there",
                escape(&record.state.destination)
            ));
        }
        // From here the clone is fenced again, so it is no longer published.
        // Record that first: a resume after a cut then publishes it again,
        // where the published step would finish over a fenced clone.
        advance(backend, &pool, record, CLONED)?;
    }
    let s = &record.state;
    let state = backend.observe()?;
    let all = snapshots(&state)?;
    let tag = tag(&id);
    if let Some(marker) = &marker
        && find(&state, &s.destination).is_some()
    {
        left.push(format!(
            "the fork {} is not published, because it would inherit {marker}",
            escape(&s.destination)
        ));
    }
    if find(&state, &s.workspace.name).is_some() {
        left.push(format!(
            "preparation {} is left untouched; an unpublished clone in it remains staging; inspect it before `zboot drop {}`",
            s.workspace.name, s.workspace.name
        ));
    }
    for point in all.iter().filter(|point| {
        point.identity.pool_guid == s.source.identity.pool_guid && point.holds.contains(&tag)
    }) {
        // Other holds, including a recursive sender's temporary holds, and
        // clones can disappear before the release.
        if point.defer_destroy {
            left.push(format!(
                "{} is marked for deferred destruction. Hold {tag} stays because releasing it can destroy the snapshot",
                escape(&point.name)
            ));
            continue;
        }
        hold::release(backend, &point.point(), &tag)?;
    }
    let captured = format!("{}@{}", s.source.name, s.snapshot);
    if s.capture && snapshot(all, &captured).is_some() {
        left.push(format!("snapshot {} is left untouched", escape(&captured)));
    }
    // Release only this operation's identity-bound tagged snapshot before
    // fencing the clone again. The native tag scan follows renames and never
    // guesses a replacement from an old source path.
    abandon_workspace(backend, record)?;
    if find(&state, &s.destination).is_some()
        && local(&state, &s.destination, management::STAGING_PROPERTY) == Some(id.as_str())
    {
        left.push(format!(
            "the unpublished clone {} is staging; `zboot drop {}` removes it",
            s.destination, s.destination
        ));
    }
    intent::finish(backend, &pool, record)?;
    Ok(left)
}

/// A fork's source is unpaired or a pair's working copy. The clone stays
/// with the working copy, which only sends; a fenced copy receives every
/// sync, and a clone of its snapshots would block or be lost with them.
fn forkable(state: &NativeState, name: &str) -> Result<(), Error> {
    match zfs_tools::engine::management::ownership(state, name)? {
        zfs_tools::engine::management::Ownership::Unpaired => Ok(()),
        // A working copy that carries zboot's fence is being switched by
        // `primary`, which binds clones only when it plans.
        zfs_tools::engine::management::Ownership::Primary { .. }
            if super::local(state, name, "readonly") == Some("on") =>
        {
            Err(refuse(format!(
                "{} is fenced while its pair switches; fork it once `zboot primary` has finished",
                escape(name)
            )))
        }
        zfs_tools::engine::management::Ownership::Primary { .. } => Ok(()),
        zfs_tools::engine::management::Ownership::Secondary { record } => Err(refuse(format!(
            "{} is the fenced copy of {}; fork the working copy, or make this one the working copy with `zboot primary`",
            escape(name),
            escape(&record.peer.name)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake::{Fake, every_cut, record, storage};
    use super::*;

    fn fixture() -> Fake {
        let mut f = Fake::new();
        f.create("a/BE");
        f.create("a/BE/root");
        f.set("a/BE/root", "mountpoint", "/");
        f.set("a/BE/root", "canmount", "noauto");
        f.set("a/BE/root", "zboot:cmdline", "quiet");
        f.snap("a/BE/root@base");
        f.write("a/BE/root");
        f
    }
    fn forked(f: &mut Fake) -> Result<(), Error> {
        let plan = plan_with(f, "a/BE/root@base", "a/BE/next")?;
        execute_with(f, &plan, &mut std::io::sink()).map(drop)
    }

    fn running_fixture() -> Fake {
        let mut fake = fixture();
        fake.running = Some("a/BE/root".into());
        fake
    }
    fn capture_time() -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
    }
    fn fork_running(fake: &mut Fake) -> Result<ForkOutcome, Error> {
        let plan = plan_running_with(fake, "a/BE/root", "a/BE/next")?;
        execute_at_with(fake, &plan, capture_time(), &mut std::io::sink())
    }
    fn setup(running: bool) -> Fake {
        if running {
            running_fixture()
        } else {
            fixture()
        }
    }
    fn fork(fake: &mut Fake, running: bool) -> Result<(), Error> {
        if running {
            fork_running(fake).map(drop)
        } else {
            forked(fake)
        }
    }
    /// The write a clean run makes first whose log line matches.
    fn write_of(running: bool, effect: impl Fn(&str) -> bool) -> usize {
        let mut clean = setup(running);
        fork(&mut clean, running).unwrap();
        clean.log.iter().position(|line| effect(line)).unwrap() + 1
    }
    /// A fork stopped just before that write, as a fresh process finds it.
    fn cut_before(running: bool, effect: impl Fn(&str) -> bool) -> Fake {
        let at = write_of(running, effect);
        let mut fake = setup(running);
        fake.cut = Some((at, false));
        assert!(fork(&mut fake, running).is_err());
        fake.revive();
        fake
    }

    #[test]
    fn fork_refuses_a_source_that_is_not_a_boot_environment() {
        let cases: [(&str, super::super::fake::Setup); 4] = [
            ("a/data", |f| {
                f.create("a/data");
                f.snap("a/data@base");
            }),
            ("a/data", |f| {
                f.create("a/data");
                f.create("a/data/child");
                f.snap("a/data@base");
                f.snap("a/data/child@base");
            }),
            ("a/BE", |f| f.snap("a/BE@base")),
            ("a/vol", |f| {
                f.create("a/vol");
                f.datasets.get_mut("a/vol").unwrap().volume = true;
                f.snap("a/vol@base");
            }),
        ];
        for (source, change) in cases {
            for running in [false, true] {
                let mut f = fixture();
                change(&mut f);
                f.running = Some(source.into());
                let before = storage(&f);
                let error = if running {
                    plan_running_with(&mut f, source, "a/copy")
                } else {
                    plan_with(&mut f, &format!("{source}@base"), "a/copy")
                }
                .unwrap_err()
                .to_string();
                assert!(
                    error.contains(&format!("{source} is not a boot environment"))
                        && error.contains("use `zfs clone` for a data tree"),
                    "{source} {running}: {error}"
                );
                assert_eq!(f.writes, 0);
                assert_eq!(storage(&f), before);
                assert!(record(&mut f).is_none());
            }
        }
    }

    #[test]
    fn fork_refuses_a_boot_environment_with_children() {
        for running in [false, true] {
            let mut f = setup(running);
            for child in [
                "a/BE/root/var",
                "a/BE/root/var/log",
                "a/BE/root/home",
                "a/BE/root/srv",
            ] {
                f.create(child);
                f.set(child, "canmount", "noauto");
                f.snap(&format!("{child}@base"));
            }
            let before = storage(&f);
            let error = if running {
                plan_running_with(&mut f, "a/BE/root", "a/BE/next")
            } else {
                plan_with(&mut f, "a/BE/root@base", "a/BE/next")
            }
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(
                    "boot environment a/BE/root has child datasets (a/BE/root/home, a/BE/root/srv, a/BE/root/var and 1 more)"
                ) && error.contains("a boot environment is one dataset with no children"),
                "{running}: {error}"
            );
            assert_eq!(f.writes, 0);
            assert_eq!(storage(&f), before);
            assert!(record(&mut f).is_none());
        }
    }

    #[test]
    fn an_old_fork_record_is_refused_for_the_build_that_started_it() {
        let mut f = fixture();
        let source = serde_json::to_value(endpoint(
            dataset(&f.observe().unwrap(), "a/BE/root").unwrap(),
        ))
        .unwrap();
        let parent =
            serde_json::to_value(endpoint(dataset(&f.observe().unwrap(), "a/BE").unwrap()))
                .unwrap();
        let id = "33333333-3333-4333-8333-333333333333";
        // The multi-member form with its chunked placement receipt.
        let mut old = Intent::new(
            id,
            KIND,
            serde_json::json!({
                "pool": "a",
                "source": source,
                "snapshot": "base",
                "destination": "a/BE/next",
                "members": "f".repeat(32),
                "boot_eligible": true,
                "cmdline": null,
                "workspace": {"parent": parent, "name": format!("a/zboot-fork-{id}")},
                "placement": "e".repeat(32),
            }),
        );
        old.step = HELD;
        f.set("a", intent::PROPERTY, &intent::encode(&old).unwrap());
        let before = storage(&f);
        let writes = f.writes;
        for abandon in [false, true] {
            let found = record(&mut f).unwrap();
            let error = resume_with(&mut f, found.clone(), abandon, &mut std::io::sink())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!(
                    "fork operation {id} was written by another zboot build"
                )) && error.contains("finish it with the build that started it"),
                "{abandon}: {error}"
            );
            assert_eq!(f.writes, writes);
            assert_eq!(storage(&f), before);
            assert_eq!(record(&mut f).unwrap(), found);
        }
    }

    #[test]
    fn a_maximal_fork_record_fits_one_intent_property() {
        let identity = DatasetIdentity {
            pool_guid: Guid::new(u64::MAX),
            guid: Guid::new(u64::MAX),
            createtxg: Txg::new(u64::MAX),
            objsetid: ObjsetId::new(u64::MAX),
        };
        // Pool names leave room for the workspace's `/copy`; dataset names
        // and the whole boundary snapshot name stay below 256 bytes.
        let pool = "p".repeat(255 - "/zboot-fork-/copy".len() - 36);
        let at = |length: usize| Endpoint {
            name: format!("{pool}/{}", "n".repeat(length - pool.len() - 1)),
            identity: identity.clone(),
        };
        let source = at(230);
        let record = Intent::new(
            new_id(),
            KIND,
            State {
                pool: pool.clone(),
                snapshot: "l".repeat(255 - source.name.len() - 1),
                source,
                capture: true,
                point: None,
                destination: at(255).name,
                canmount: "noauto".into(),
                volmode: "default".into(),
                cmdline: Some("x".repeat(512)),
                workspace: Workspace {
                    parent: at(254),
                    name: format!("{pool}/zboot-fork-{}", new_id()),
                    owner: None,
                    clone: None,
                    retired: false,
                },
            },
        );
        fits(&record).unwrap();
    }

    #[test]
    fn fork_without_a_source_captures_the_running_be() {
        let mut fake = running_fixture();
        let content = fake.datasets["a/BE/root"].content;
        assert_ne!(content, fake.snapshots["a/BE/root@base"].content);
        let outcome = fork_running(&mut fake).unwrap();
        assert!(outcome.complete);
        assert!(record(&mut fake).is_none());
        let label = super::super::snapshot_name("zboot", capture_time());
        assert_eq!(outcome.source_snapshot, format!("a/BE/root@{label}"));
        let point = fake.point(&outcome.source_snapshot);
        assert_eq!(fake.capture_marker(&point).unwrap(), outcome.operation_id);
        assert_eq!(
            fake.datasets["a/BE/next"].origin.as_deref(),
            Some(outcome.source_snapshot.as_str())
        );
        assert!(fake.snapshots[&outcome.source_snapshot].holds.is_empty());
        assert_eq!(fake.snapshots[&outcome.source_snapshot].content, content);
        assert_eq!(fake.datasets["a/BE/next"].content, content);
    }

    #[test]
    fn fork_preview_creates_neither_a_snapshot_nor_a_record() {
        let mut fake = running_fixture();
        let before = storage(&fake);
        let writes = fake.writes;
        let plan = plan_running_with(&mut fake, "a/BE/root", "a/BE/next").unwrap();
        assert_eq!(plan.boundary, ForkBoundary::Capture);
        assert!(describe(&plan).contains("capture now"));
        assert_eq!(fake.writes, writes);
        assert_eq!(storage(&fake), before);
        assert!(record(&mut fake).is_none());
        assert!(fake.capture_markers.is_empty());
        assert!(plan_running_with(&mut fake, "a/BE", "a/BE/next").is_err());
    }

    #[test]
    fn fork_capture_and_clone_resume_through_every_cut() {
        every_cut(
            running_fixture,
            |fake| {
                let result = fork_running(fake).map(drop);
                safe_copies(fake);
                result
            },
            |fake, found| {
                safe_copies(fake);
                let result = resume_with(fake, found, false, &mut std::io::sink()).map(drop);
                safe_copies(fake);
                result
            },
        );
    }

    #[test]
    fn fork_never_adopts_a_foreign_or_partial_capture() {
        let mut clean = running_fixture();
        let outcome = fork_running(&mut clean).unwrap();
        let at = clean
            .log
            .iter()
            .position(|line| line.starts_with("Snapshot {"))
            .unwrap()
            + 1;
        let mut stopped = running_fixture();
        stopped.cut = Some((at, true));
        assert!(fork_running(&mut stopped).is_err());
        stopped.revive();
        let found = record(&mut stopped).unwrap();
        let saved: State = serde_json::from_value(found.state.clone()).unwrap();
        let root = format!("a/BE/root@{}", saved.snapshot);
        for scenario in [
            "missing marker",
            "foreign marker",
            "received marker",
            "inherited marker",
            "replaced point",
            "new child",
            "replaced source",
        ] {
            let mut fake = stopped.clone();
            match scenario {
                "missing marker" => {
                    fake.capture_markers.remove(&root);
                }
                "foreign marker" => {
                    fake.capture_markers.get_mut(&root).unwrap().1.value = new_id();
                }
                "received marker" => {
                    fake.capture_markers.get_mut(&root).unwrap().1.source = "received".into();
                }
                "inherited marker" => {
                    fake.capture_markers.get_mut(&root).unwrap().1.source =
                        "inherited from a".into();
                }
                "replaced point" => {
                    fake.snap(&root);
                }
                "new child" => {
                    fake.create("a/BE/root/new");
                    fake.set("a/BE/root/new", "canmount", "noauto");
                }
                "replaced source" => {
                    fake.create("a/BE/root");
                    fake.set("a/BE/root", "mountpoint", "/");
                    fake.set("a/BE/root", "canmount", "noauto");
                }
                _ => unreachable!(),
            }
            let before = storage(&fake);
            let writes = fake.writes;
            assert!(
                resume_with(&mut fake, found.clone(), false, &mut std::io::sink()).is_err(),
                "{scenario}"
            );
            assert_eq!(fake.writes, writes, "{scenario}");
            assert_eq!(storage(&fake), before, "{scenario}");
            assert!(record(&mut fake).is_some());
            assert!(!fake.datasets.contains_key("a/BE/next"));
        }
        // A completed capture binds the snapshot identity independently of
        // its mutable marker, before the hold or clone.
        let mut fake = cut_before(true, |line| line.starts_with("hold "));
        let found = record(&mut fake).unwrap();
        fake.snap(&outcome.source_snapshot);
        let guid = fake.snapshots[&outcome.source_snapshot].guid;
        let marker = fake
            .capture_markers
            .get_mut(&outcome.source_snapshot)
            .unwrap();
        marker.0 = guid;
        marker.1.value = found.id.clone();
        let writes = fake.writes;
        assert!(resume_with(&mut fake, found, false, &mut std::io::sink()).is_err());
        assert_eq!(fake.writes, writes);
    }

    #[test]
    fn fork_generated_values_do_not_change_the_token() {
        let mut first = running_fixture();
        let plan = plan_running_with(&mut first, "a/BE/root", "a/BE/next").unwrap();
        let token = crate::consent::token(&plan).unwrap();
        let first =
            execute_at_with(&mut first, &plan, capture_time(), &mut std::io::sink()).unwrap();
        let mut second = running_fixture();
        let fresh = plan_running_with(&mut second, "a/BE/root", "a/BE/next").unwrap();
        assert_eq!(crate::consent::token(&fresh).unwrap(), token);
        let second = execute_at_with(
            &mut second,
            &fresh,
            capture_time() + std::time::Duration::from_secs(1),
            &mut std::io::sink(),
        )
        .unwrap();
        assert_ne!(first.source_snapshot, second.source_snapshot);
        assert_ne!(first.operation_id, second.operation_id);
        assert_eq!(crate::consent::token(&plan).unwrap(), token);
    }

    #[test]
    fn both_fork_tokens_bind_the_published_placement_and_stale_plans_write_nothing() {
        for running in [false, true] {
            for (key, value) in [("canmount", "off"), ("volmode", "none")] {
                let mut fake = setup(running);
                let plan = if running {
                    plan_running_with(&mut fake, "a/BE/root", "a/BE/next")
                } else {
                    plan_with(&mut fake, "a/BE/root@base", "a/BE/next")
                }
                .unwrap();
                let token = crate::consent::token(&plan).unwrap();
                fake.set("a/BE/root", key, value);
                let changed = if running {
                    plan_running_with(&mut fake, "a/BE/root", "a/BE/next")
                } else {
                    plan_with(&mut fake, "a/BE/root@base", "a/BE/next")
                }
                .unwrap();
                assert_eq!(plan.boundary, changed.boundary, "{running} {key}");
                assert_ne!(
                    token,
                    crate::consent::token(&changed).unwrap(),
                    "{running} {key}"
                );
                let error = execute_at_with(&mut fake, &plan, capture_time(), &mut std::io::sink())
                    .unwrap_err();
                assert!(error.to_string().contains("plan changed"), "{error}");
                assert_eq!(fake.writes, 0, "{running} {key}");
                assert!(record(&mut fake).is_none());
            }
        }
    }

    #[test]
    fn the_reviewed_placement_in_the_record_is_published_after_source_drift() {
        for running in [false, true] {
            let mut clean = setup(running);
            fork(&mut clean, running).unwrap();
            let mut exercised = 0;
            for at in 1..=clean.writes {
                let mut fake = setup(running);
                fake.cut = Some((at, true));
                if fork(&mut fake, running).is_ok() {
                    continue;
                }
                fake.revive();
                let Some(found) = record(&mut fake) else {
                    continue;
                };
                if found.step >= PUBLISHED {
                    continue;
                }
                exercised += 1;
                fake.set("a/BE/root", "canmount", "off");
                fake.set("a/BE/root", "volmode", "none");
                resume_with(&mut fake, found, false, &mut std::io::sink()).unwrap();
                assert!(record(&mut fake).is_none());
                assert_eq!(
                    fake.effective("a/BE/next", "canmount").unwrap().0,
                    "noauto",
                    "{running} {at}"
                );
                assert_eq!(
                    fake.effective("a/BE/next", "volmode").unwrap().0,
                    "default",
                    "{running} {at}"
                );
                assert_eq!(fake.effective("a/BE/next", "mountpoint").unwrap().0, "/");
            }
            assert!(exercised > 5, "{running} {exercised}");
        }
    }

    #[test]
    fn abandoning_fork_keeps_its_generated_snapshot_and_destroys_nothing() {
        let mut clean = running_fixture();
        fork_running(&mut clean).unwrap();
        for at in 1..=clean.writes {
            for after in [false, true] {
                let mut fake = running_fixture();
                fake.cut = Some((at, after));
                let _ = fork_running(&mut fake);
                fake.revive();
                let captured: Vec<_> = fake
                    .snapshots
                    .iter()
                    .filter(|(name, _)| name.contains("@zboot-"))
                    .map(|(name, point)| (name.clone(), point.guid))
                    .collect();
                let datasets: Vec<_> = fake
                    .datasets
                    .iter()
                    .map(|(name, d)| (name.clone(), d.guid))
                    .collect();
                let snapshots: Vec<_> = fake
                    .snapshots
                    .iter()
                    .map(|(name, s)| (name.clone(), s.guid))
                    .collect();
                if let Some(found) = record(&mut fake) {
                    let typed: Intent<State> = decode(found.clone(), KIND).unwrap();
                    resume_with(&mut fake, found, true, &mut std::io::sink()).unwrap();
                    // Only a published fork's own empty container goes.
                    for (name, guid) in datasets {
                        if typed.step < PUBLISHED || name != typed.state.workspace.name {
                            assert_eq!(
                                fake.datasets.get(&name).map(|d| d.guid),
                                Some(guid),
                                "{name} {at} {after}"
                            );
                        }
                    }
                    for (name, guid) in snapshots {
                        assert_eq!(
                            fake.snapshots.get(&name).map(|s| s.guid),
                            Some(guid),
                            "{name} {at} {after}"
                        );
                    }
                }
                for (name, guid) in captured {
                    assert_eq!(fake.snapshots[&name].guid, guid, "{at} {after}");
                }
                assert!(record(&mut fake).is_none(), "{at} {after}");
                safe_copies(&fake);
            }
        }
        let mut stopped = cut_before(true, |line| line.starts_with("CreateInert {"));
        let found = record(&mut stopped).unwrap();
        assert_eq!(found.step, HELD);
        let saved: State = serde_json::from_value(found.state.clone()).unwrap();
        let name = format!("a/BE/root@{}", saved.snapshot);
        let guid = stopped.snapshots[&name].guid;
        stopped.snapshots.get_mut(&name).unwrap().defer = true;
        stopped
            .snapshots
            .get_mut(&name)
            .unwrap()
            .holds
            .insert(".send-1-1".into());
        let mut baseline = stopped.clone();
        let Resumed::Abandoned(left) =
            resume_with(&mut baseline, found.clone(), true, &mut std::io::sink()).unwrap()
        else {
            panic!()
        };
        assert!(
            left.left
                .iter()
                .any(|line| line.contains(&name) && line.contains(&tag(&found.id)))
        );
        assert_eq!(baseline.snapshots[&name].guid, guid);
        assert!(baseline.snapshots[&name].holds.contains(&tag(&found.id)));
        for at in stopped.writes + 1..=baseline.writes {
            for after in [false, true] {
                let mut fake = stopped.clone();
                fake.cut = Some((at, after));
                let _ = resume_with(&mut fake, found.clone(), true, &mut std::io::sink());
                fake.revive();
                if let Some(found) = record(&mut fake) {
                    resume_with(&mut fake, found, true, &mut std::io::sink()).unwrap();
                }
                assert_eq!(storage(&fake), storage(&baseline), "{at} {after}");
            }
            let mut fake = stopped.clone();
            fake.lose = Some(at);
            let _ = resume_with(&mut fake, found.clone(), true, &mut std::io::sink());
            fake.revive();
            if let Some(found) = record(&mut fake) {
                resume_with(&mut fake, found, true, &mut std::io::sink()).unwrap();
            }
            assert_eq!(storage(&fake), storage(&baseline), "lost {at}");
        }
        hold::Backend::release(&mut baseline, &name, ".send-1-1").unwrap();
        assert_eq!(baseline.snapshots[&name].guid, guid);
        assert_eq!(
            baseline.snapshots[&name].holds,
            std::collections::BTreeSet::from([tag(&found.id)])
        );
    }

    #[test]
    fn a_resumed_capture_refuses_a_source_that_is_no_longer_an_unpaired_boot_environment() {
        for (key, value) in [("mountpoint", "/srv"), (management::PAIR_PROPERTY, "{}")] {
            let mut fake = cut_before(true, |line| line.starts_with("Snapshot {"));
            let found = record(&mut fake).unwrap();
            fake.set("a/BE/root", key, value);
            let before = storage(&fake);
            let writes = fake.writes;
            assert!(
                resume_with(&mut fake, found, false, &mut std::io::sink()).is_err(),
                "{key}"
            );
            assert_eq!(fake.writes, writes, "{key}");
            assert_eq!(storage(&fake), before, "{key}");
            assert!(!fake.snapshots.keys().any(|name| name.contains("@zboot-")));
        }
    }

    #[test]
    fn abandon_without_the_empty_container_still_fences_and_releases() {
        for published in [false, true] {
            let at = if published {
                // Renamed, and partly published: mountpoint=/ and readonly=off.
                write_of(false, |line| {
                    line.contains("name: \"a/BE/next\"") && line.contains("key: \"readonly\"")
                })
            } else {
                write_of(false, |line| line.starts_with("bare Clone"))
            };
            let mut f = fixture();
            // Cut after the readonly write, or before the clone.
            f.cut = Some((at, published));
            assert!(forked(&mut f).is_err());
            f.revive();
            let found = record(&mut f).unwrap();
            let typed: Intent<State> = decode(found.clone(), KIND).unwrap();
            // Someone removed the (now empty) container by hand.
            assert!(f.datasets.remove(&typed.state.workspace.name).is_some());
            resume_with(&mut f, found, true, &mut std::io::sink()).unwrap();
            assert!(record(&mut f).is_none(), "{published}");
            assert!(
                f.snapshots.values().all(|s| s.holds.is_empty()),
                "{published}"
            );
            if published {
                for (key, value) in [
                    ("mountpoint", "none"),
                    ("readonly", "on"),
                    ("volmode", "none"),
                ] {
                    assert_eq!(f.effective("a/BE/next", key).unwrap().0, value, "{key}");
                }
            } else {
                assert!(!f.datasets.contains_key("a/BE/next"));
            }
        }
    }

    /// A clone that is not inert is exposed only after its identity and role
    /// were checkpointed, and its role is already set.
    fn safe_copies(f: &Fake) {
        let record = f.datasets["a"]
            .props
            .get(intent::PROPERTY)
            .and_then(|raw| serde_json::from_str::<Intent<State>>(raw).ok());
        for (name, _) in f.datasets.iter().filter(|(_, d)| {
            d.origin
                .as_ref()
                .is_some_and(|o| o.starts_with("a/BE/root@"))
        }) {
            let inert = f.effective(name, "readonly").map(|p| p.0).as_deref() == Some("on")
                && f.effective(name, "volmode").map(|p| p.0).as_deref() == Some("none")
                && f.effective(name, "mountpoint").map(|p| p.0).as_deref() == Some("none");
            if !inert {
                assert!(
                    record
                        .as_ref()
                        .is_none_or(|r| r.state.workspace.clone.is_some()),
                    "{name} exposed before its clone identity and role checkpoint"
                );
                assert!(
                    matches!(
                        f.effective(name, "canmount").map(|p| p.0).as_deref(),
                        Some("noauto" | "off")
                    ),
                    "{name} role not set before exposure"
                );
            }
        }
    }

    #[test]
    fn a_fork_clones_the_boundary_as_a_published_boot_environment() {
        let mut f = fixture();
        forked(&mut f).unwrap();
        let root = &f.datasets["a/BE/next"];
        assert_eq!(root.origin.as_deref(), Some("a/BE/root@base"));
        assert_eq!(root.content, f.snapshots["a/BE/root@base"].content);
        assert_eq!(
            root.props.get("zboot:cmdline").map(String::as_str),
            Some("quiet")
        );
        assert_eq!(f.effective("a/BE/next", "mountpoint").unwrap().0, "/");
        assert_eq!(f.effective("a/BE/next", "readonly").unwrap().0, "off");
        assert_eq!(f.effective("a/BE/next", "canmount").unwrap().0, "noauto");
        assert_eq!(f.effective("a/BE/next", "volmode").unwrap().0, "default");
        assert_eq!(f.effective("a/BE/next", "zboot:staging"), None);
        assert!(f.snapshots.values().all(|s| s.holds.is_empty()));
        assert!(!f.datasets.keys().any(|name| name.contains("zboot-fork-")));
        let state = f.observe().unwrap();
        assert!(crate::boot_environment::is_root(
            &state,
            dataset(&state, "a/BE/next").unwrap()
        ));
    }

    #[test]
    fn every_cut_and_lost_reply_resumes_to_the_same_fork() {
        every_cut(
            fixture,
            |f| {
                let result = forked(f);
                safe_copies(f);
                result
            },
            |f, found| {
                safe_copies(f);
                let result = resume_with(f, found, false, &mut std::io::sink()).map(drop);
                safe_copies(f);
                result
            },
        );
    }

    #[test]
    fn a_failed_clone_role_setter_leaves_native_split_survivors_inert() {
        let at = write_of(false, |line| {
            line.starts_with("clone property") && line.contains("key: \"canmount\"")
        });
        let mut f = fixture();
        f.fail = Some(at);
        assert!(forked(&mut f).is_err());
        let copies: Vec<_> = f
            .datasets
            .iter()
            .filter(|(_, d)| d.origin.is_some())
            .map(|(n, _)| n.clone())
            .collect();
        assert_eq!(copies.len(), 1);
        for name in copies {
            assert_eq!(f.effective(&name, "mountpoint").unwrap().0, "none");
            assert_eq!(f.effective(&name, "readonly").unwrap().0, "on");
            assert_eq!(f.effective(&name, "volmode").unwrap().0, "none");
        }
        safe_copies(&f);
        f.revive();
        let found = record(&mut f).unwrap();
        resume_with(&mut f, found, false, &mut std::io::sink()).unwrap();
    }

    #[test]
    fn encrypted_rename_constraints_are_checked_before_effects_without_requiring_keys() {
        let mut f = fixture();
        f.create("a/crypt");
        f.set("a/crypt", "encryption", "aes-256-gcm");
        f.set("a/crypt", "encryptionroot", "a/crypt");
        f.set("a/crypt", "keystatus", "unavailable");
        f.set("a/BE/root", "encryption", "aes-256-gcm");
        f.set("a/BE/root", "encryptionroot", "a/crypt");
        f.set("a/BE/root", "keystatus", "unavailable");
        let error = plan_with(&mut f, "a/BE/root@base", "a/BE/next").unwrap_err();
        assert!(error.to_string().contains("encryption root"));
        assert_eq!(f.writes, 0);
        let plan = plan_with(&mut f, "a/BE/root@base", "a/crypt/next").unwrap();
        execute_with(&mut f, &plan, &mut std::io::sink()).unwrap();
        assert_eq!(
            f.datasets["a/crypt/next"].props["encryptionroot"],
            "a/crypt"
        );
        assert_eq!(f.datasets["a/crypt/next"].props["keystatus"], "unavailable");
    }

    #[test]
    fn a_replaced_final_parent_refuses_before_any_preparation_or_hold() {
        let mut f = fixture();
        let plan = plan_with(&mut f, "a/BE/root@base", "a/BE/next").unwrap();
        f.datasets.get_mut("a/BE").unwrap().guid += 10000;
        let error = execute_with(&mut f, &plan, &mut std::io::sink()).unwrap_err();
        assert!(error.to_string().contains("plan changed"));
        assert_eq!(f.writes, 0);
    }

    #[test]
    fn mountpoint_readbacks_remove_only_the_current_pool_altroot() {
        let mut f = fixture();
        let mut state = f.observe().unwrap();
        state.pool_properties.get_mut("a").unwrap().insert(
            "altroot".into(),
            zfs_tools::engine::native::NativeProperty {
                value: "/ram/import".into(),
                source: "local".into(),
            },
        );
        for (seen, original) in [
            ("/ram/import", "/"),
            ("/ram/import/var", "/var"),
            ("/ram/import/ram/import/data", "/ram/import/data"),
            ("legacy", "legacy"),
            ("none", "none"),
        ] {
            assert_eq!(
                canonical_mountpoint(&state, "a/BE/root", seen).unwrap(),
                original
            );
        }
        assert!(canonical_mountpoint(&state, "a/BE/root", "/ram/imported/data").is_err());
    }

    #[test]
    fn unbound_preparation_is_reported_and_left_without_poisoning_another_fork() {
        let at = write_of(false, |line| line.contains("CreateInert"));
        let mut f = fixture();
        f.cut = Some((at, true));
        assert!(forked(&mut f).is_err());
        f.revive();
        let found = record(&mut f).unwrap();
        let typed: Intent<State> = decode(found.clone(), KIND).unwrap();
        let name = typed.state.workspace.name;
        // Native create can commit its empty DSL dataset before ANY
        // fallible property setter. It contains no cloned source data.
        f.datasets.get_mut(&name).unwrap().props.clear();
        let survivor = f.datasets[&name].clone();
        let error = resume_with(&mut f, found, false, &mut std::io::sink()).unwrap_err();
        assert!(error.to_string().contains(&name));
        let found = record(&mut f).unwrap();
        let Resumed::Abandoned(left) =
            resume_with(&mut f, found, true, &mut std::io::sink()).unwrap()
        else {
            panic!()
        };
        assert!(left.left.iter().any(|line| line.contains(&name)));
        assert_eq!(f.datasets[&name], survivor);
        let plan = plan_with(&mut f, "a/BE/root@base", "a/BE/healthy").unwrap();
        execute_with(&mut f, &plan, &mut std::io::sink()).unwrap();
        assert_eq!(f.datasets[&name], survivor);
    }

    #[test]
    fn preparation_is_a_pool_root_sibling_of_the_final_parent() {
        let mut f = fixture();
        f.create("a/other");
        let plan = plan_with(&mut f, "a/BE/root@base", "a/other/next").unwrap();
        let mut clean = f.clone();
        execute_with(&mut clean, &plan, &mut std::io::sink()).unwrap();
        let at = clean
            .log
            .iter()
            .position(|line| line.starts_with("bare Clone"))
            .unwrap()
            + 1;
        f.cut = Some((at, true));
        assert!(execute_with(&mut f, &plan, &mut std::io::sink()).is_err());
        f.revive();
        let found = record(&mut f).unwrap();
        let typed: Intent<State> = decode(found.clone(), KIND).unwrap();
        let workspace = typed.state.workspace;
        assert!(workspace.name.starts_with("a/zboot-fork-"));
        assert!(!contains("a/other", &workspace.name));
        safe_copies(&f);
        resume_with(&mut f, found, false, &mut std::io::sink()).unwrap();
        assert!(f.datasets.contains_key("a/other/next"));
    }

    #[test]
    fn nested_destinations_refuse_before_effects_for_shape_and_default_boot_roots() {
        for (ancestor, default) in [("a/other", false), ("a/other", true), ("a", false)] {
            let mut f = fixture();
            f.create("a/other");
            f.set("a/other", "canmount", "noauto");
            if default {
                f.pools.get_mut("a").unwrap().bootfs = Some(ancestor.into());
            } else {
                f.set(ancestor, "mountpoint", "/");
            }
            // Keep this test about initramfs's explicit noauto mounts,
            // independently of the ordinary canmount=on admission check.
            for d in f.datasets.values_mut() {
                d.props.insert("canmount".into(), "noauto".into());
            }
            let before = storage(&f);
            let error = plan_with(&mut f, "a/BE/root@base", "a/other/next").unwrap_err();
            assert!(
                error.to_string().contains("initramfs mounts descendants"),
                "{error}"
            );
            assert_eq!(f.writes, 0);
            assert_eq!(storage(&f), before);
        }
        let mut f = fixture();
        f.create("a/other");
        let state = f.observe().unwrap();
        destination_outside_boot_environment(&state, "a/other/next").unwrap();
        // A shaped root itself is permitted after publication.
        destination_outside_boot_environment(&state, "a/BE/root").unwrap();
    }

    #[test]
    fn a_new_boot_ancestor_on_resume_refuses_before_more_effects() {
        let mut f = cut_before(false, |line| line.starts_with("bare Clone"));
        f.set("a/BE", "mountpoint", "/");
        f.set("a/BE", "canmount", "noauto");
        let found = record(&mut f).unwrap();
        let before = storage(&f);
        let writes = f.writes;
        let error = resume_with(&mut f, found, false, &mut std::io::sink()).unwrap_err();
        assert!(
            error.to_string().contains("initramfs mounts descendants"),
            "{error}"
        );
        assert_eq!(f.writes, writes);
        assert_eq!(storage(&f), before);
    }

    #[test]
    fn abandoning_a_published_fork_finishes_its_retirement() {
        let mut clean = fixture();
        forked(&mut clean).unwrap();
        // Inspect each durable boundary: at least one must be the first
        // PUBLISHED checkpoint, before marker retirement has completed.
        let mut exercised = false;
        for at in 1..=clean.writes {
            let mut f = fixture();
            f.cut = Some((at, true));
            if forked(&mut f).is_ok() {
                continue;
            }
            f.revive();
            let Some(found) = record(&mut f) else {
                continue;
            };
            if found.step != PUBLISHED {
                continue;
            }
            let typed: Intent<State> = decode(found.clone(), KIND).unwrap();
            if typed.state.workspace.retired {
                continue;
            }
            exercised = true;
            resume_with(&mut f, found, true, &mut std::io::sink()).unwrap();
            assert!(record(&mut f).is_none());
            for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
                assert_eq!(f.effective("a/BE/next", key), None);
            }
            assert!(f.snapshots.values().all(|s| s.holds.is_empty()));
            assert!(
                !f.datasets
                    .keys()
                    .any(|name| name.starts_with("a/zboot-fork-"))
            );
        }
        assert!(exercised);
    }

    #[test]
    fn a_replaced_container_or_copy_is_never_adopted_and_foreign_children_are_never_deleted() {
        for attack in 0..3 {
            let mut f = cut_before(false, |line| line.contains("RenameInert"));
            let found = record(&mut f).unwrap();
            let typed: Intent<State> = decode(found.clone(), KIND).unwrap();
            let name = typed.state.workspace.name;
            let foreign = match attack {
                0 => {
                    f.datasets.get_mut(&name).unwrap().guid += 10000;
                    name.clone()
                }
                1 => {
                    let n = format!("{name}/copy");
                    f.datasets.get_mut(&n).unwrap().guid += 10000;
                    n
                }
                _ => {
                    let n = format!("{name}/foreign");
                    f.create(&n);
                    n
                }
            };
            let saved = f.datasets[&foreign].clone();
            let resumed = resume_with(&mut f, found, false, &mut std::io::sink());
            assert_eq!(f.datasets[&foreign], saved, "{attack}");
            if attack < 2 {
                assert!(resumed.is_err(), "{attack}");
                continue;
            }
            // A dataset someone made in the container after the clone keeps
            // the container, still this fork's staging, for `drop`.
            let Ok(Resumed::Complete(outcome)) = resumed else {
                panic!("{resumed:?}")
            };
            assert!(record(&mut f).is_none());
            assert!(f.datasets.contains_key("a/BE/next"));
            assert_eq!(
                f.datasets[&name].props[management::STAGING_PROPERTY],
                typed.id
            );
            assert!(
                outcome
                    .left
                    .iter()
                    .any(|line| line.contains(&foreign) && line.contains("zboot drop")),
                "{:?}",
                outcome.left
            );
        }
    }

    #[test]
    fn fork_takes_a_pairs_working_copy_and_refuses_its_fenced_copy() {
        for role in [management::Role::Primary, management::Role::Secondary] {
            let mut f = fixture();
            f.create("b/copy");
            let endpoint = |f: &super::super::fake::Fake, name: &str| management::Endpoint {
                name: name.into(),
                identity: f.identity(name),
            };
            let record = management::PairRecord {
                schema_version: 1,
                pair_id: "11111111-1111-4111-8111-111111111111".into(),
                endpoint: endpoint(&f, "a/BE/root"),
                peer: endpoint(&f, "b/copy"),
                role,
            };
            f.set(
                "a/BE/root",
                management::PAIR_PROPERTY,
                &record.encode().unwrap(),
            );
            f.set(
                "b/copy",
                management::PAIR_PROPERTY,
                &record.counterpart().encode().unwrap(),
            );
            // The fenced side is read-only and never mounts by itself.
            let fenced = if role == management::Role::Primary {
                "b/copy"
            } else {
                "a/BE/root"
            };
            f.set(fenced, "readonly", "on");
            f.set(fenced, "canmount", "noauto");
            if role == management::Role::Primary {
                // While `primary` has fenced it, the working copy is refused.
                let mut fenced = f.clone();
                fenced.set("a/BE/root", "readonly", "on");
                let error = plan_with(&mut fenced, "a/BE/root@base", "a/BE/next")
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("fenced while its pair switches"), "{error}");
            }
            let before = storage(&f);
            let result = plan_with(&mut f, "a/BE/root@base", "a/BE/next")
                .and_then(|plan| execute_with(&mut f, &plan, &mut std::io::sink()));
            if role == management::Role::Primary {
                result.unwrap();
                assert!(f.datasets.contains_key("a/BE/next"));
                // The working copy keeps its pair record.
                assert!(
                    f.effective("a/BE/root", management::PAIR_PROPERTY)
                        .is_some()
                );
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("fenced copy"), "{error}");
                assert_eq!(storage(&f), before);
            }
        }
    }

    #[test]
    fn refusals_happen_before_any_effect() {
        let cases: [(&str, &str, super::super::fake::Setup); 8] = [
            ("missing", "a/BE/next", |f| {
                f.snapshots.remove("a/BE/root@base");
            }),
            ("exists", "a/BE/next", |f| f.create("a/BE/next")),
            ("cross pool", "b/next", |_| {}),
            ("overlap", "a/BE/root/x", |_| {}),
            ("paired", "a/BE/next", |f| {
                f.set("a/BE/root", management::PAIR_PROPERTY, "{}")
            }),
            ("deferred", "a/BE/next", |f| {
                f.snapshots.get_mut("a/BE/root@base").unwrap().defer = true;
            }),
            ("not a boot environment", "a/BE/next", |f| {
                f.set("a/BE/root", "mountpoint", "/srv")
            }),
            ("child", "a/BE/next", |f| {
                f.create("a/BE/root/var");
                f.set("a/BE/root/var", "canmount", "noauto");
            }),
        ];
        for (label, to, change) in cases {
            let mut f = fixture();
            change(&mut f);
            let before = storage(&f);
            let result = plan_with(&mut f, "a/BE/root@base", to)
                .and_then(|plan| execute_with(&mut f, &plan, &mut std::io::sink()));
            assert!(result.is_err(), "{label}");
            assert_eq!(f.writes, 0, "{label}");
            assert_eq!(storage(&f), before, "{label}");
        }
    }

    #[test]
    fn an_intruder_at_the_destination_is_refused_and_abandon_releases_the_hold() {
        let mut f = cut_before(false, |line| line.starts_with("CreateInert"));
        f.create("a/BE/next");
        let found = record(&mut f).unwrap();
        assert_eq!(found.step, HELD);
        assert!(resume_with(&mut f, found, false, &mut std::io::sink()).is_err());
        assert!(f.datasets["a/BE/next"].origin.is_none());
        let found = record(&mut f).unwrap();
        let Resumed::Abandoned(abandoned) =
            resume_with(&mut f, found, true, &mut std::io::sink()).unwrap()
        else {
            panic!()
        };
        assert!(abandoned.left.is_empty(), "{:?}", abandoned.left);
        assert!(f.snapshots.values().all(|s| s.holds.is_empty()));
        assert!(record(&mut f).is_none());
    }

    #[test]
    fn abandon_never_destroys_a_boundary_marked_for_deferred_destruction_since_the_cut() {
        for protection in ["none", "sender", "clone"] {
            let mut stopped = cut_before(false, |line| line.starts_with("CreateInert"));
            let name = "a/BE/root@base";
            let guid = stopped.snapshots[name].guid;
            stopped.snapshots.get_mut(name).unwrap().defer = true;
            match protection {
                "sender" => {
                    stopped
                        .snapshots
                        .get_mut(name)
                        .unwrap()
                        .holds
                        .insert(".send-1-1".into());
                }
                "clone" => {
                    stopped.create("a/other-clone");
                    stopped.datasets.get_mut("a/other-clone").unwrap().origin = Some(name.into());
                }
                _ => {}
            }
            let found = record(&mut stopped).unwrap();
            let mut baseline = stopped.clone();
            let Resumed::Abandoned(abandoned) =
                resume_with(&mut baseline, found.clone(), true, &mut std::io::sink()).unwrap()
            else {
                panic!()
            };
            assert!(
                abandoned.left.iter().any(|line| {
                    line.contains(name)
                        && line.contains(&tag(&found.id))
                        && line.contains("can destroy")
                }),
                "{:?}",
                abandoned.left
            );
            assert_eq!(baseline.snapshots[name].guid, guid);
            assert!(baseline.snapshots[name].holds.contains(&tag(&found.id)));
            assert!(record(&mut baseline).is_none());
            for at in stopped.writes + 1..=baseline.writes {
                for after in [false, true] {
                    let mut fake = stopped.clone();
                    fake.cut = Some((at, after));
                    let _ = resume_with(&mut fake, found.clone(), true, &mut std::io::sink());
                    fake.revive();
                    if let Some(found) = record(&mut fake) {
                        resume_with(&mut fake, found, true, &mut std::io::sink()).unwrap();
                    }
                    assert_eq!(
                        storage(&fake),
                        storage(&baseline),
                        "{protection} {at} {after}"
                    );
                }
                let mut fake = stopped.clone();
                fake.lose = Some(at);
                let _ = resume_with(&mut fake, found.clone(), true, &mut std::io::sink());
                fake.revive();
                if let Some(found) = record(&mut fake) {
                    resume_with(&mut fake, found, true, &mut std::io::sink()).unwrap();
                }
                assert_eq!(storage(&fake), storage(&baseline), "{protection} lost {at}");
            }
            if protection == "sender" {
                hold::Backend::release(&mut baseline, name, ".send-1-1").unwrap();
                assert_eq!(baseline.snapshots[name].guid, guid);
                assert!(baseline.snapshots[name].holds.contains(&tag(&found.id)));
            }
        }
    }

    #[test]
    fn roles_are_set_on_every_member_at_creation_and_never_swept() {
        let mut f = fixture();
        // A second boot environment its owner keeps from mounting for good.
        f.create("a/BE/kept");
        f.set("a/BE/kept", "mountpoint", "/");
        f.set("a/BE/kept", "canmount", "off");
        f.snap("a/BE/kept@base");
        forked(&mut f).unwrap();
        let plan = plan_with(&mut f, "a/BE/kept@base", "a/BE/kept-copy").unwrap();
        execute_with(&mut f, &plan, &mut std::io::sink()).unwrap();
        // A fork is `noauto` whatever its source was, so nothing mounts it
        // by itself; a source kept `off` stays `off`.
        for (name, role) in [
            ("a/BE/next", "noauto"),
            ("a/BE/kept-copy", "off"),
            ("a/BE/root", "noauto"),
            ("a/BE/kept", "off"),
        ] {
            assert_eq!(f.effective(name, "canmount").unwrap().0, role, "{name}");
        }
        // Nothing outside the clones was touched.
        assert!(
            f.log.iter().all(|effect| !effect.contains("canmount")
                || effect.contains("a/BE/next")
                || effect.contains("a/BE/kept-copy")
                || effect.contains("zboot-fork-")),
            "{:?}",
            f.log
        );
    }

    #[test]
    fn a_resumed_fork_rechecks_host_wide_automount_hazards_before_cloning_and_publication() {
        for (cut, step) in [("CreateInert", HELD), ("RenameInert", CLONED)] {
            let mut f = cut_before(false, |line| line.starts_with(cut));
            let found = record(&mut f).unwrap();
            assert_eq!(found.step, step);
            f.create("a/BE/other");
            f.set("a/BE/other", "mountpoint", "/");
            f.set("a/BE/other", "canmount", "noauto");
            f.create("a/BE/other/var");
            let before = storage(&f);
            let writes = f.writes;
            let error = resume_with(&mut f, found, false, &mut std::io::sink()).unwrap_err();
            assert!(error.to_string().contains("a/BE/other/var"), "{error}");
            assert_eq!(f.writes, writes);
            assert_eq!(storage(&f), before);
            f.set("a/BE/other/var", "canmount", "noauto");
            let found = record(&mut f).unwrap();
            assert!(matches!(
                resume_with(&mut f, found, false, &mut std::io::sink()).unwrap(),
                Resumed::Complete(_)
            ));
            assert!(record(&mut f).is_none());
        }
    }

    #[test]
    fn a_resumed_fork_refuses_a_child_or_a_changed_role_on_its_unpublished_clone() {
        for change in ["child", "role"] {
            let mut f = cut_before(false, |line| line.contains("RenameInert"));
            let found = record(&mut f).unwrap();
            let decoded: Intent<State> = decode(found.clone(), KIND).unwrap();
            let staged = format!("{}/copy", decoded.state.workspace.name);
            let child = format!("{staged}/var");
            match change {
                "child" => {
                    f.create(&child);
                    f.set(&child, "canmount", "noauto");
                }
                _ => f.set(&staged, "canmount", "on"),
            }
            let before = storage(&f);
            let writes = f.writes;
            let error = resume_with(&mut f, found, false, &mut std::io::sink())
                .unwrap_err()
                .to_string();
            assert!(error.contains(&staged), "{change}: {error}");
            assert_eq!(f.writes, writes);
            assert_eq!(storage(&f), before);
            match change {
                "child" => {
                    f.datasets.remove(&child);
                }
                _ => f.set(&staged, "canmount", "noauto"),
            }
            let found = record(&mut f).unwrap();
            resume_with(&mut f, found, false, &mut std::io::sink()).unwrap();
            assert!(record(&mut f).is_none());
        }
    }

    #[test]
    fn fork_and_default_refuse_while_any_be_has_a_canmount_on_dataset() {
        use crate::boot_support::default;
        let mut f = fixture();
        // Another boot environment, with a child someone set `on` by hand.
        f.create("a/BE/old");
        f.set("a/BE/old", "mountpoint", "/");
        f.set("a/BE/old", "canmount", "noauto");
        f.create("a/BE/old/var");
        f.set("a/BE/old/var", "canmount", "on");
        let before = storage(&f);
        let error = plan_with(&mut f, "a/BE/root@base", "a/BE/next").unwrap_err();
        assert!(error.to_string().contains("a/BE/old/var"), "{error}");
        let error = default::start_with("a/BE/root", &mut f).unwrap_err();
        assert!(error.to_string().contains("a/BE/old/var"), "{error}");
        // The refusal names it whichever boot environment is the subject.
        let error = default::start_with("a/BE/old", &mut f).unwrap_err();
        assert!(error.to_string().contains("a/BE/old/var"), "{error}");
        assert_eq!(f.writes, 0);
        assert_eq!(storage(&f), before);
        // Once it is `noauto`, both run.
        f.set("a/BE/old/var", "canmount", "noauto");
        forked(&mut f).unwrap();
        let change = default::start_with("a/BE/next", &mut f).unwrap();
        assert!(change.complete, "{change:?}");
        assert_eq!(f.pools["a"].bootfs.as_deref(), Some("a/BE/next"));
    }

    /// Every clone of the fork's source.
    fn clones(f: &Fake) -> Vec<String> {
        f.datasets
            .iter()
            .filter(|(_, d)| {
                d.origin
                    .as_ref()
                    .is_some_and(|o| o.starts_with("a/BE/root@"))
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
    fn local_mark(f: &Fake, name: &str, key: &str) -> Option<String> {
        f.datasets[name].props.get(key).cloned()
    }
    /// The mark `name` shows, its own or its container's.
    fn mark(f: &Fake, name: &str, key: &str) -> Option<String> {
        f.effective(name, key).map(|(value, _)| value)
    }

    #[test]
    fn a_foreign_snapshot_on_the_clone_never_stops_resume_or_abandon_at_any_cut() {
        let sink = &mut std::io::sink();
        for running in [false, true] {
            let mut clean = setup(running);
            fork(&mut clean, running).unwrap();
            let expected = storage(&clean);
            let mut exercised = 0;
            for at in 1..=clean.writes {
                for (cut, lose) in [
                    (Some((at, false)), None),
                    (Some((at, true)), None),
                    (None, Some(at)),
                ] {
                    let label = format!("{running} {at} {cut:?} {lose:?}");
                    let mut stopped = setup(running);
                    stopped.cut = cut;
                    stopped.lose = lose;
                    let _ = fork(&mut stopped, running);
                    stopped.revive();
                    let Some(found) = record(&mut stopped) else {
                        continue;
                    };
                    let found_clones = clones(&stopped);
                    let [clone] = found_clones.as_slice() else {
                        assert!(found_clones.is_empty(), "{label}: {found_clones:?}");
                        continue;
                    };
                    let clone = clone.clone();
                    exercised += 1;
                    let typed: Intent<State> = decode(found.clone(), KIND).unwrap();
                    // Another tool's snapshot of the clone, wherever it is.
                    let foreign = format!("{clone}@foreign");
                    let guid = stopped.foreign_snap(&foreign);

                    // Resume makes the uninterrupted run's fork, and the
                    // snapshot moves with the clone.
                    let mut f = stopped.clone();
                    resume_with(&mut f, found.clone(), false, sink)
                        .unwrap_or_else(|e| panic!("{label}: {e}"));
                    assert!(record(&mut f).is_none(), "{label}");
                    let moved = f.snapshots.remove("a/BE/next@foreign");
                    assert_eq!(moved.map(|s| s.guid), Some(guid), "{label}");
                    assert_eq!(storage(&f), expected, "{label}");

                    // Abandon completes and leaves the snapshot on the clone.
                    let mut f = stopped.clone();
                    resume_with(&mut f, found, true, sink)
                        .unwrap_or_else(|e| panic!("{label}: {e}"));
                    assert!(record(&mut f).is_none(), "{label}");
                    assert_eq!(f.snapshots[&foreign].guid, guid, "{label}");
                    if typed.step < PUBLISHED {
                        // It stays staging, and `drop` lists the snapshot.
                        assert_eq!(
                            mark(&f, &clone, management::STAGING_PROPERTY),
                            Some(typed.id.clone()),
                            "{label}"
                        );
                        let plan =
                            super::super::discard::plan_with(&mut f, std::slice::from_ref(&clone))
                                .unwrap_or_else(|e| panic!("{label}: {e}"));
                        assert!(
                            plan.trees[0]
                                .snapshots
                                .iter()
                                .any(|p| p.name == foreign && p.identity.guid.get() == guid),
                            "{label}"
                        );
                    } else {
                        assert_eq!(f.effective(&clone, management::STAGING_PROPERTY), None);
                    }
                }
            }
            assert!(exercised > 20, "{running} {exercised}");
        }
    }

    #[test]
    fn another_tools_recursive_snapshot_before_any_write_never_stops_a_fork() {
        for running in [false, true] {
            let mut clean = setup(running);
            fork(&mut clean, running).unwrap();
            let expected = storage(&clean);
            let mut kept = 0;
            for at in 1..=clean.writes {
                let label = format!("{running} {at}");
                let mut f = setup(running);
                f.foreign_snapshot = Some((at, "a@foreign".into()));
                let mut said = Vec::new();
                let outcome = if running {
                    let plan = plan_running_with(&mut f, "a/BE/root", "a/BE/next").unwrap();
                    execute_at_with(&mut f, &plan, capture_time(), &mut said)
                } else {
                    let plan = plan_with(&mut f, "a/BE/root@base", "a/BE/next").unwrap();
                    execute_with(&mut f, &plan, &mut said)
                }
                .unwrap_or_else(|e| panic!("{label}: {e}"));
                assert!(outcome.complete && record(&mut f).is_none(), "{label}");
                let container = format!("a/zboot-fork-{}", outcome.operation_id);
                let taken: Vec<_> = f
                    .snapshots
                    .keys()
                    .filter(|name| name.ends_with("@foreign"))
                    .cloned()
                    .collect();
                assert!(taken.contains(&"a/BE/root@foreign".to_string()), "{label}");
                if f.datasets.contains_key(&container) {
                    // The snapshot landed on the container: it stays, still
                    // this fork's staging, and the fork says so.
                    kept += 1;
                    assert!(taken.contains(&format!("{container}@foreign")), "{label}");
                    assert_eq!(
                        local_mark(&f, &container, management::STAGING_PROPERTY),
                        Some(outcome.operation_id.clone()),
                        "{label}"
                    );
                    assert!(
                        outcome.left.iter().any(|line| line.contains(&container)
                            && line.contains(&format!("{container}@foreign"))
                            && line.contains("zboot drop")),
                        "{label}: {:?}",
                        outcome.left
                    );
                    let said = String::from_utf8(said).unwrap();
                    assert!(
                        said.contains(&format!("`zboot drop {container}`")),
                        "{said}"
                    );
                    f.datasets.remove(&container);
                } else {
                    assert!(outcome.left.is_empty(), "{label}: {:?}", outcome.left);
                }
                for name in taken {
                    f.snapshots.remove(&name);
                }
                assert_eq!(storage(&f), expected, "{label}");
            }
            assert!(kept > 3, "{running} {kept}");
        }
    }

    #[test]
    fn a_snapshot_on_the_container_leaves_it_for_drop_and_frees_the_pool() {
        use super::super::discard;
        let sink = &mut std::io::sink();
        let mut clean = fixture();
        forked(&mut clean).unwrap();
        let expected = storage(&clean);
        let mut exercised = 0;
        for at in 1..=clean.writes {
            for after in [false, true] {
                let label = format!("{at} {after}");
                let mut stopped = fixture();
                stopped.cut = Some((at, after));
                assert!(forked(&mut stopped).is_err());
                stopped.revive();
                let Some(found) = record(&mut stopped) else {
                    continue;
                };
                let typed: Intent<State> = decode(found.clone(), KIND).unwrap();
                let container = typed.state.workspace.name.clone();
                if !stopped.datasets.contains_key(&container) {
                    continue;
                }
                exercised += 1;
                let foreign = format!("{container}@foreign");
                let guid = stopped.foreign_snap(&foreign);

                // Resume publishes the fork, finishes the record and names
                // the container it leaves.
                let mut f = stopped.clone();
                let mut said = Vec::new();
                let Resumed::Complete(outcome) =
                    resume_with(&mut f, found.clone(), false, &mut said)
                        .unwrap_or_else(|e| panic!("{label}: {e}"))
                else {
                    panic!("{label}")
                };
                assert!(record(&mut f).is_none(), "{label}");
                for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
                    assert_eq!(f.effective("a/BE/next", key), None, "{label}");
                    assert_eq!(local_mark(&f, &container, key), Some(typed.id.clone()));
                }
                assert!(
                    outcome.left.iter().any(|line| line.contains(&foreign)),
                    "{label}: {:?}",
                    outcome.left
                );
                let said = String::from_utf8(said).unwrap();
                assert!(
                    said.contains(&format!("`zboot drop {container}`")),
                    "{said}"
                );
                // Harmless leftover staging: no boot environment, no hazard,
                // and `drop` takes it with the snapshot listed.
                let state = f.observe().unwrap();
                assert!(!crate::boot_environment::is_root(
                    &state,
                    dataset(&state, &container).unwrap()
                ));
                assert_eq!(crate::mounting::refusal(&state, None), None);
                let plan = discard::plan_with(&mut f, std::slice::from_ref(&container))
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(
                    plan.trees[0]
                        .snapshots
                        .iter()
                        .map(|p| (p.name.as_str(), p.identity.guid.get()))
                        .collect::<Vec<_>>(),
                    [(foreign.as_str(), guid)],
                    "{label}"
                );
                let token = discard::consent(&plan).unwrap();
                discard::execute_with(&mut f, &plan, &token, sink).unwrap();
                assert_eq!(storage(&f), expected, "{label}");

                // Abandon completes too, and leaves the container as it is.
                let mut f = stopped.clone();
                resume_with(&mut f, found, true, sink).unwrap_or_else(|e| panic!("{label}: {e}"));
                assert!(record(&mut f).is_none(), "{label}");
                assert_eq!(f.snapshots[&foreign].guid, guid, "{label}");
                assert_eq!(
                    local_mark(&f, &container, management::STAGING_PROPERTY),
                    Some(typed.id.clone()),
                    "{label}"
                );
            }
        }
        assert!(exercised > 10, "{exercised}");
    }

    const OTHER: &str = "22222222-2222-4222-8222-222222222222";
    const MARKED: &str = "a/other/ROOT/next";
    /// The fork destination `a/other/ROOT/next` sits below two plain datasets.
    fn marked_fixture() -> Fake {
        let mut f = running_fixture();
        f.create("a/other");
        f.create("a/other/ROOT");
        f
    }

    #[test]
    fn a_destination_below_a_staging_mark_is_refused_before_any_effect() {
        for key in [management::STAGING_PROPERTY, management::PENDING_PROPERTY] {
            // Set on the parent, or inherited by it from an ancestor.
            for owner in ["a/other/ROOT", "a/other"] {
                for running in [false, true] {
                    let label = format!("{key} {owner} {running}");
                    let plan = |f: &mut Fake| {
                        if running {
                            plan_running_with(f, "a/BE/root", MARKED)
                        } else {
                            plan_with(f, "a/BE/root@base", MARKED)
                        }
                    };
                    let mut f = marked_fixture();
                    let reviewed = plan(&mut f).unwrap();
                    f.set(owner, key, OTHER);
                    let before = storage(&f);
                    let error = plan(&mut f).unwrap_err().to_string();
                    assert!(
                        error.contains(&format!(
                            "fork destination {MARKED} would inherit {key}={OTHER} on {owner}"
                        )),
                        "{label}: {error}"
                    );
                    // A plan reviewed before the mark appeared is refused too.
                    let error =
                        execute_at_with(&mut f, &reviewed, capture_time(), &mut std::io::sink())
                            .unwrap_err()
                            .to_string();
                    assert!(error.contains("would inherit"), "{label}: {error}");
                    assert_eq!(f.writes, 0, "{label}");
                    assert_eq!(storage(&f), before, "{label}");
                    assert!(record(&mut f).is_none(), "{label}");
                }
            }
        }
    }

    /// The clone at the fork's destination is usable as published, or it is
    /// still this fork's staging: never fenced and unmarked.
    fn published_or_staging(f: &Fake, id: &str, label: &str) {
        for clone in clones(f) {
            let staging = mark(f, &clone, management::STAGING_PROPERTY).as_deref() == Some(id);
            let usable = f.effective(&clone, "mountpoint").map(|(value, _)| value)
                == Some("/".into())
                && f.effective(&clone, "readonly").map(|(value, _)| value) == Some("off".into());
            assert!(
                staging != usable,
                "{label} {clone}: staging {staging}, usable {usable}: {:?}",
                f.datasets[&clone].props
            );
        }
    }

    #[test]
    fn an_abandon_cut_under_a_parent_mark_is_never_finished_over_a_fenced_clone() {
        let sink = &mut std::io::sink();
        let fork_marked = |f: &mut Fake| {
            plan_with(f, "a/BE/root@base", MARKED)
                .and_then(|plan| execute_with(f, &plan, &mut std::io::sink()))
        };
        let mut clean = marked_fixture();
        fork_marked(&mut clean).unwrap();
        let rename = 1 + clean
            .log
            .iter()
            .position(|line| line.starts_with("RenameInert"))
            .unwrap();
        let inherit = rename
            + 1
            + clean.log[rename..]
                .iter()
                .position(|line| line.starts_with("Inherit"))
                .unwrap();
        // Published and not yet retired, then another operation's mark
        // reaches the parent.
        let stopped = || {
            let mut f = marked_fixture();
            f.cut = Some((inherit, false));
            assert!(fork_marked(&mut f).is_err());
            f.revive();
            f.set("a/other", management::STAGING_PROPERTY, OTHER);
            f
        };
        let mut whole = stopped();
        let found = record(&mut whole).unwrap();
        assert_eq!(found.step, PUBLISHED);
        let id = found.id.clone();
        let before = whole.writes;
        resume_with(&mut whole, found, true, sink).unwrap();
        let total = whole.writes - before;
        assert!(total > 3, "{total}");
        published_or_staging(&whole, &id, "whole abandon");
        for n in 1..=total {
            for after in [false, true] {
                let mut cut = stopped();
                let found = record(&mut cut).unwrap();
                let id = found.id.clone();
                cut.cut = Some((cut.writes + n, after));
                let _ = resume_with(&mut cut, found, true, sink);
                cut.revive();
                // The other operation ends, and its mark goes with it.
                cut.datasets
                    .get_mut("a/other")
                    .unwrap()
                    .props
                    .remove(management::STAGING_PROPERTY);
                for abandon in [false, true] {
                    let label = format!("cut {n} {after}, then abandon {abandon}");
                    let mut f = cut.clone();
                    if let Some(found) = record(&mut f) {
                        // A resume may refuse a half-fenced clone; it must
                        // not call it published.
                        let _ = resume_with(&mut f, found, abandon, sink);
                    }
                    if let Some(found) = record(&mut f) {
                        resume_with(&mut f, found, true, sink)
                            .unwrap_or_else(|e| panic!("{label}: {e}"));
                    }
                    assert!(record(&mut f).is_none(), "{label}");
                    published_or_staging(&f, &id, &label);
                }
            }
        }
    }

    #[test]
    fn an_abandon_ends_a_published_fork_whose_clone_was_removed_by_hand() {
        let sink = &mut std::io::sink();
        let fork_marked = |f: &mut Fake| {
            plan_with(f, "a/BE/root@base", MARKED)
                .and_then(|plan| execute_with(f, &plan, &mut std::io::sink()))
        };
        let mut clean = marked_fixture();
        fork_marked(&mut clean).unwrap();
        let rename = 1 + clean
            .log
            .iter()
            .position(|line| line.starts_with("RenameInert"))
            .unwrap();
        let inherit = rename
            + 1
            + clean.log[rename..]
                .iter()
                .position(|line| line.starts_with("Inherit"))
                .unwrap();
        let mut f = marked_fixture();
        f.cut = Some((inherit, false));
        assert!(fork_marked(&mut f).is_err());
        f.revive();
        f.datasets.remove(MARKED);
        let found = record(&mut f).unwrap();
        assert_eq!(found.step, PUBLISHED);
        let error = resume_with(&mut f, found.clone(), false, sink)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is missing"), "{error}");
        let Resumed::Abandoned(abandoned) = resume_with(&mut f, found, true, sink).unwrap() else {
            panic!("not abandoned");
        };
        assert!(
            abandoned
                .left
                .iter()
                .any(|note| note.contains("is no longer at")),
            "{:?}",
            abandoned.left
        );
        assert!(record(&mut f).is_none());
    }

    #[test]
    fn a_staging_mark_reaching_the_parent_mid_fork_stops_it_with_its_own_marks() {
        let sink = &mut std::io::sink();
        let fork_marked = |f: &mut Fake| {
            plan_with(f, "a/BE/root@base", MARKED)
                .and_then(|plan| execute_with(f, &plan, &mut std::io::sink()))
        };
        let mut clean = marked_fixture();
        fork_marked(&mut clean).unwrap();
        let write = |prefix: &str, from: usize| {
            from + clean.log[from..]
                .iter()
                .position(|line| line.starts_with(prefix))
                .unwrap()
                + 1
        };
        let rename = write("RenameInert", 0);
        // The fork's last own mark goes with this write; then it is checked
        // once more, and the record write after the hold's release records
        // the retirement.
        let last = write("Inherit", rename) + 1;
        assert!(clean.log[last - 1].contains(management::STAGING_PROPERTY));
        let retired = write("record ", write("release ", last));
        let mut stopped = 0;
        for key in [management::STAGING_PROPERTY, management::PENDING_PROPERTY] {
            for owner in ["a/other/ROOT", "a/other"] {
                // The mark lands just before an observation, or just before
                // a write, after the observation that checked for it.
                for (racing, n) in (1..=clean.observations)
                    .map(|n| (false, n))
                    .chain((1..=clean.writes).map(|n| (true, n)))
                {
                    let label = format!("{key} {owner} {racing} {n}");
                    let mut f = marked_fixture();
                    let change = (owner.into(), key.into(), OTHER.into());
                    if racing {
                        f.write_changes.insert(n, change);
                    } else {
                        f.observe_changes.insert(n, change);
                    }
                    let result = fork_marked(&mut f);
                    let landed = f.changed_at.expect("the mark landed");
                    // After the last check (only a race with the effects
                    // between it and the record write can land there), or
                    // once retirement is recorded, the fork is published and
                    // the mark is someone else's doing.
                    if (racing && n > last) || landed >= retired {
                        assert!(result.is_ok(), "{label}: {result:?}");
                        continue;
                    }
                    let error = result.unwrap_err().to_string();
                    assert!(error.contains("would inherit"), "{label}: {error}");
                    if !racing && landed < rename {
                        // Seen before the rename, it stops the rename.
                        assert!(!f.datasets.contains_key(MARKED), "{label}");
                    }
                    let Some(found) = record(&mut f) else {
                        assert_eq!(f.writes, 0, "{label}");
                        continue;
                    };
                    stopped += 1;
                    // Whatever exists of the fork is this operation's staging.
                    for clone in clones(&f) {
                        assert_eq!(
                            mark(&f, &clone, management::STAGING_PROPERTY),
                            Some(found.id.clone()),
                            "{label} {clone}"
                        );
                    }
                    // Resume refuses again, before any write.
                    let (writes, before) = (f.writes, storage(&f));
                    let error = resume_with(&mut f, found.clone(), false, sink)
                        .unwrap_err()
                        .to_string();
                    assert!(error.contains("would inherit"), "{label}: {error}");
                    assert_eq!(f.writes, writes, "{label}");
                    assert_eq!(storage(&f), before, "{label}");
                    // Abandon frees the pool; the fork stays fenced staging,
                    // which `drop` takes.
                    resume_with(&mut f, found.clone(), true, sink)
                        .unwrap_or_else(|e| panic!("{label}: {e}"));
                    assert!(record(&mut f).is_none(), "{label}");
                    for clone in clones(&f) {
                        assert_eq!(
                            mark(&f, &clone, management::STAGING_PROPERTY),
                            Some(found.id.clone()),
                            "{label} {clone}"
                        );
                        for (key, value) in [("mountpoint", "none"), ("readonly", "on")] {
                            assert_eq!(f.effective(&clone, key).unwrap().0, value, "{label}");
                        }
                        super::super::discard::plan_with(&mut f, std::slice::from_ref(&clone))
                            .unwrap_or_else(|e| panic!("{label} {clone}: {e}"));
                    }
                }
            }
        }
        assert!(stopped > 40, "{stopped}");
        // Set while the fork is stopped, the mark stops its resume before
        // any effect, whichever step is next; a fork part way through its
        // retirement first gets back the mark it already gave up.
        for at in [
            write("CreateInert", 0),
            write("bare Clone", 0),
            rename,
            last - 1,
            last,
        ] {
            let mut f = marked_fixture();
            f.cut = Some((at, false));
            assert!(fork_marked(&mut f).is_err());
            f.revive();
            f.set("a/other", management::STAGING_PROPERTY, OTHER);
            let found = record(&mut f).unwrap();
            for attempt in 0..2 {
                let (writes, before) = (f.writes, storage(&f));
                let error = resume_with(&mut f, found.clone(), false, sink)
                    .unwrap_err()
                    .to_string();
                assert!(
                    error.contains(&format!(
                        "{MARKED} would inherit {}={OTHER} on a/other",
                        management::STAGING_PROPERTY
                    )),
                    "{at}: {error}"
                );
                if at == last && attempt == 0 {
                    assert_eq!(f.writes, writes + 1, "{at}");
                    for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
                        assert_eq!(local_mark(&f, MARKED, key), Some(found.id.clone()));
                    }
                } else {
                    assert_eq!(f.writes, writes, "{at} {attempt}");
                    assert_eq!(storage(&f), before, "{at} {attempt}");
                }
            }
        }
    }
}
