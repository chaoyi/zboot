//! `drop TARGET...` †: destroy exact snapshots and whole unpaired trees,
//! including staging an interrupted operation left behind.
//!
//! The plan lists every dataset and snapshot destroyed; the token binds them.
//! Execution records intent on the pool root, marks every tree member with a
//! local `zboot:pending=ID`, then destroys exact snapshot targets and each
//! tree leaf-first. The record names the tree roots, the snapshot targets
//! (name and GUID), a member digest and the newest approved creation txg: on
//! resume, an unmarked dataset or a newer snapshot inside a tree is refused,
//! never destroyed.
//!
//! A snapshot held only by an ended restore (`zboot:restore:ID`, its record
//! gone from the pool all of its holds and its record are on) is listed with
//! those holds; the confirmed drop releases them, then destroys it.
use super::{
    Abandoned, Backend, Effect, Resumed, active, advance, apply_all, begin, bootfs_inside, current,
    decode, digest, endpoint, find, history, local, members, new_id, pool_of, protection, refuse,
    refuse_running, relative, snapshot, snapshots, split_snapshot, staging_id, stopped,
};
use crate::history::contains_dataset as contains;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::Write};
use zfs_tools::engine::{
    Error, Guid, Snapshot, SnapshotRef, hold,
    intent::{self, Intent},
    management::{self, Endpoint},
    state::NativeState,
};

pub const KIND: &str = "drop";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DropTree {
    pub root: Endpoint,
    /// Every dataset destroyed, parents first.
    pub datasets: Vec<Endpoint>,
    /// Every snapshot of those datasets.
    pub snapshots: Vec<SnapshotRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DropPlan {
    pub pool: String,
    pub snapshots: Vec<SnapshotRef>,
    pub trees: Vec<DropTree>,
    /// What the operator types to confirm several targets.
    pub summary: String,
    /// The targets as given, for a single-target typed confirmation.
    #[serde(skip)]
    pub targets: Vec<String>,
    /// Holds of ended restores released before their snapshots are destroyed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub releases: Vec<Release>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub snapshot: SnapshotRef,
    pub tag: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DropOutcome {
    pub operation_id: String,
    /// Datasets and snapshots this run destroyed.
    pub destroyed: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    pool: String,
    trees: Vec<Endpoint>,
    snapshots: Vec<(String, Guid)>,
    members: String,
    newest: u64,
    token: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    releases: Vec<Release>,
}
const MARKED: u32 = 1;
const RESTORE_TAG: &str = "zboot:restore:";

/// The holds on `s` when every one is an ended restore's: no record with its
/// id is active. A restore records on the pool that has its holds, so with
/// that pool imported a missing record is proof the restore ended.
fn ended_restore_holds(s: &Snapshot, active: &BTreeSet<String>) -> Option<Vec<String>> {
    let ended = !s.holds.is_empty()
        && s.userrefs == s.holds.len() as u64
        && s.holds.iter().all(|t| {
            t.strip_prefix(RESTORE_TAG)
                .is_some_and(|id| !id.is_empty() && !active.contains(id))
        });
    ended.then(|| s.holds.clone())
}
/// Why `s` cannot be destroyed, given the holds `releases` lets go first.
fn protection_after(s: &Snapshot, releases: &[Release]) -> Option<String> {
    let released = |t: &String| {
        releases
            .iter()
            .any(|r| r.snapshot.identity == s.identity && r.tag == *t)
    };
    if !s.holds.is_empty()
        && s.userrefs == s.holds.len() as u64
        && s.holds.iter().all(released)
        && !s.defer_destroy
    {
        None
    } else {
        protection(s)
    }
}

fn count(n: usize, one: &str, many: &str) -> Option<String> {
    match n {
        0 => None,
        1 => Some(format!("1 {one}")),
        n => Some(format!("{n} {many}")),
    }
}

pub fn plan(targets: &[String]) -> Result<DropPlan, Error> {
    plan_with(&mut super::Native, targets)
}
pub fn plan_with(backend: &mut impl Backend, targets: &[String]) -> Result<DropPlan, Error> {
    if targets.is_empty() {
        return Err(Error::InvalidScope("drop needs a target".into()));
    }
    let mut seen = BTreeSet::new();
    for target in targets {
        if !seen.insert(target) {
            return Err(Error::InvalidScope(format!("{target} is named twice")));
        }
    }
    let pools: BTreeSet<_> = targets
        .iter()
        .map(|t| pool_of(t.split('@').next().unwrap()))
        .collect();
    if pools.len() != 1 {
        return Err(refuse("drop targets in one pool at a time"));
    }
    let pool_name = pools.into_iter().next().unwrap().to_string();
    let state = backend.observe()?;
    let all = snapshots(&state)?;
    let active = active(backend)?;
    let (snapshot_targets, tree_targets): (Vec<_>, Vec<_>) =
        targets.iter().partition(|t| t.contains('@'));
    for (i, a) in tree_targets.iter().enumerate() {
        zfs_tools::engine::validate_dataset_name(a)?;
        if !a.contains('/') {
            return Err(refuse("a pool's root dataset cannot be dropped"));
        }
        if let Some(b) = tree_targets[i + 1..]
            .iter()
            .find(|b| contains(a, b) || contains(b, a))
        {
            return Err(Error::InvalidScope(format!("{a} and {b} overlap")));
        }
    }
    let roots: Vec<&str> = tree_targets.iter().map(|t| t.as_str()).collect();
    refuse_running(backend, &roots, "drop")?;
    let mut trees = Vec::new();
    let mut releases = Vec::new();
    for root in &roots {
        let tree = members(&state, root);
        if tree.is_empty() {
            return Err(Error::NotFound(root.to_string()));
        }
        if let Some(bootfs) = bootfs_inside(&state, root) {
            return Err(refuse(format!(
                "{} is its pool's boot default; make another BE the default first",
                zfs_tools::engine::escape_display(bootfs)
            )));
        }
        let mut points = Vec::new();
        for d in &tree {
            admit(&state, &d.name, &active)?;
            if let Some(origin) = zfs_tools::engine::deferred_origin(d, root, all) {
                return Err(refuse(format!(
                    "dropping {} would also destroy its deferred origin {}",
                    zfs_tools::engine::escape_display(&d.name),
                    zfs_tools::engine::escape_display(origin)
                )));
            }
            for s in history(all, &d.name) {
                if let Some(tags) = ended_restore_holds(s, &active)
                    && !s.defer_destroy
                {
                    releases.extend(tags.into_iter().map(|tag| Release {
                        snapshot: s.point(),
                        tag,
                    }));
                } else if let Some(reason) = protection(s) {
                    return Err(refuse(reason));
                }
                if let Some(clone) = s.clones.iter().find(|c| !contains(root, c)) {
                    return Err(refuse(format!(
                        "{} outside the tree is a clone of {}; drop or promote it first",
                        zfs_tools::engine::escape_display(clone),
                        zfs_tools::engine::escape_display(&s.name)
                    )));
                }
                points.push(s.point());
            }
        }
        trees.push(DropTree {
            root: endpoint(tree[0]),
            datasets: tree.iter().map(|d| endpoint(d)).collect(),
            snapshots: points,
        });
    }
    let mut points = Vec::new();
    for target in &snapshot_targets {
        let (parent, _) = split_snapshot(target)?;
        if let Some(root) = roots.iter().find(|root| contains(root, parent)) {
            return Err(Error::InvalidScope(format!(
                "{target} is inside {root}, which is dropped whole"
            )));
        }
        let s = snapshot(all, target).ok_or_else(|| Error::NotFound(target.to_string()))?;
        admit_snapshot(&state, parent, &active)?;
        if let Some(tags) = ended_restore_holds(s, &active)
            && !s.defer_destroy
        {
            releases.extend(tags.into_iter().map(|tag| Release {
                snapshot: s.point(),
                tag,
            }));
        } else if let Some(reason) = protection(s) {
            return Err(refuse(reason));
        }
        if let Some(clone) = s.clones.first() {
            return Err(refuse(format!(
                "{} is a clone of {}; drop or promote it first",
                zfs_tools::engine::escape_display(clone),
                zfs_tools::engine::escape_display(target)
            )));
        }
        points.push(s.point());
    }
    let summary = [
        count(points.len(), "snapshot", "snapshots"),
        count(trees.len(), "tree", "trees"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" and ")
        + &format!(" in {pool_name}");
    if !releases.is_empty()
        && intent::find(backend)?
            .iter()
            .any(|(_, found)| matches!(found, intent::Found::Unreadable(_)))
    {
        return Err(refuse(
            "an unreadable operation record may be the restore that holds these snapshots; \
             nothing is released",
        ));
    }
    Ok(DropPlan {
        pool: pool_name,
        snapshots: points,
        trees,
        summary,
        targets: targets.to_vec(),
        releases,
    })
}
/// Unpaired, or leftover staging of an operation that is no longer active.
///
/// No visible record is proof of abandonment only where the record would be
/// visible: every operation records on the pool its marks are in, except a
/// cross-pool move, whose fenced source (marked, with its placement saved)
/// is recorded on the destination pool, which may not be imported.
fn admit(state: &NativeState, name: &str, active: &BTreeSet<String>) -> Result<(), Error> {
    admit_with(state, name, active, super::unpaired)
}
/// A snapshot is dropped on a working copy, paired or not, never on a fenced
/// pair copy: that copy's snapshots follow its working copy through `sync`.
fn admit_snapshot(state: &NativeState, name: &str, active: &BTreeSet<String>) -> Result<(), Error> {
    admit_with(
        state,
        name,
        active,
        |state, name| match management::ownership(state, name)? {
            management::Ownership::Secondary { record } => Err(refuse(format!(
                "{} is a fenced pair copy: its snapshots follow {}; drop them there, and \
                 `zboot sync {}` then offers this copy's for review (one that only this copy \
                 has after their last common snapshot stops that sync: `zfs destroy` it)",
                zfs_tools::engine::escape_display(name),
                zfs_tools::engine::escape_display(&record.peer.name),
                zfs_tools::engine::escape_display(name)
            ))),
            _ => Ok(()),
        },
    )
}
fn admit_with(
    state: &NativeState,
    name: &str,
    active: &BTreeSet<String>,
    owner: fn(&NativeState, &str) -> Result<(), Error>,
) -> Result<(), Error> {
    let Some(id) = staging_id(state, name) else {
        return owner(state, name);
    };
    if active.contains(&id) {
        return Err(refuse(format!(
            "{} is staging of operation {id}, which is still recorded; resume or abandon it first",
            zfs_tools::engine::escape_display(name)
        )));
    }
    if local(state, name, management::PENDING_PROPERTY) == Some(id.as_str())
        && local(state, name, management::PLACEMENT_PROPERTY).is_some()
    {
        return Err(refuse(format!(
            "{} is fenced and marked by operation {id}, which may be recorded on a pool that is \
             not imported (a move's destination); import that pool and resume or abandon it, or, \
             if that pool is gone, clear the mark with `zfs inherit {} {}` first",
            zfs_tools::engine::escape_display(name),
            management::PENDING_PROPERTY,
            zfs_tools::engine::escape_display(name)
        )));
    }
    let mut view = state.clone();
    for properties in view.dataset_properties.values_mut() {
        properties.remove(management::PENDING_PROPERTY);
        properties.remove(management::STAGING_PROPERTY);
    }
    owner(&view, name)
}
pub fn consent(plan: &DropPlan) -> std::io::Result<String> {
    crate::consent::token(&(KIND, plan))
}
pub fn typed(plan: &DropPlan) -> crate::consent::Typed {
    match plan.targets.as_slice() {
        [one] => crate::consent::Typed {
            what: "the target",
            text: one.clone(),
        },
        _ => crate::consent::Typed {
            what: "the summary",
            text: plan.summary.clone(),
        },
    }
}
pub fn describe(plan: &DropPlan, token: &str) -> String {
    let mut text = format!("Drop {}:\n", plan.summary);
    for point in &plan.snapshots {
        text.push_str(&format!(
            "  snapshot {}\n",
            zfs_tools::engine::escape_display(&point.name)
        ));
    }
    for tree in &plan.trees {
        text.push_str(&format!(
            "  tree {}: {} dataset(s) and {} snapshot(s), with all their data\n",
            zfs_tools::engine::escape_display(&tree.root.name),
            tree.datasets.len(),
            tree.snapshots.len()
        ));
        for d in &tree.datasets {
            text.push_str(&format!(
                "    {}\n",
                zfs_tools::engine::escape_display(&d.name)
            ));
        }
    }
    for release in &plan.releases {
        text.push_str(&format!(
            "  releases {} on {} (left by an ended restore; this may be its only copy)\n",
            zfs_tools::engine::escape_display(&release.tag),
            zfs_tools::engine::escape_display(&release.snapshot.name)
        ));
    }
    text.push_str(&format!("Token: {token}\n"));
    text
}

fn tree_digest(state: &NativeState, roots: &[Endpoint]) -> Result<String, Error> {
    let all = snapshots(state)?;
    let mut rows = Vec::new();
    for root in roots {
        for d in members(state, &root.name) {
            let points: Vec<_> = history(all, &d.name)
                .into_iter()
                .map(|s| s.identity.clone())
                .collect();
            rows.push((
                root.name.clone(),
                relative(&root.name, &d.name).to_string(),
                d.identity.clone(),
                points,
            ));
        }
    }
    digest(&rows)
}

pub fn execute(
    plan: &DropPlan,
    token: &str,
    dialogue: &mut dyn Write,
) -> Result<DropOutcome, Error> {
    execute_with(&mut super::Native, plan, token, dialogue)
}
pub fn execute_with(
    backend: &mut impl Backend,
    plan: &DropPlan,
    token: &str,
    dialogue: &mut dyn Write,
) -> Result<DropOutcome, Error> {
    let fresh = plan_with(backend, &plan.targets)?;
    if fresh != *plan || consent(&fresh).map_err(|e| refuse(e.to_string()))? != token {
        return Err(refuse(
            "the drop plan changed since it was confirmed; nothing changed",
        ));
    }
    let roots: Vec<_> = plan.trees.iter().map(|t| t.root.clone()).collect();
    let newest = plan
        .trees
        .iter()
        .flat_map(|t| {
            t.datasets
                .iter()
                .map(|d| d.identity.createtxg.get())
                .chain(t.snapshots.iter().map(|s| s.identity.createtxg.get()))
        })
        .max()
        .unwrap_or(0);
    let state = State {
        pool: plan.pool.clone(),
        members: tree_digest(&backend.observe()?, &roots)?,
        trees: roots,
        snapshots: plan
            .snapshots
            .iter()
            .map(|s| (s.name.clone(), s.identity.guid))
            .collect(),
        newest,
        token: token.into(),
        releases: plan.releases.clone(),
    };
    let mut record = Intent::new(new_id(), KIND, state);
    begin(backend, &plan.pool, &record, dialogue)?;
    let id = record.id.clone();
    run(backend, &mut record).map_err(|e| stopped(&id, e))
}

pub(super) fn mark(id: &str) -> (String, String) {
    (management::PENDING_PROPERTY.to_string(), id.to_string())
}

/// The destruction order for what is left of `root`: each leaf's snapshots,
/// newest first, then the leaf, a clone before its origin.
fn teardown_releasing(
    state: &NativeState,
    root: &Endpoint,
    id: &str,
    newest: u64,
    releases: &[Release],
) -> Result<Vec<Effect>, Error> {
    let all = snapshots(state)?;
    let mut left: Vec<_> = members(state, &root.name);
    if let Some(d) = left.first()
        && d.name == root.name
        && d.identity != root.identity
    {
        return Err(refuse(format!("{} is another dataset now", root.name)));
    }
    for d in &left {
        if local(state, &d.name, management::PENDING_PROPERTY) != Some(id) {
            return Err(refuse(format!(
                "{} appeared in {} after the drop was confirmed; it is not destroyed",
                zfs_tools::engine::escape_display(&d.name),
                zfs_tools::engine::escape_display(&root.name)
            )));
        }
        // Rechecked here, not only at planning: the origin may have been
        // marked for deferred destruction since, and destroying its last
        // clone would destroy it too.
        if let Some(origin) = zfs_tools::engine::deferred_origin(d, &root.name, all) {
            return Err(refuse(format!(
                "destroying {} would also destroy its deferred origin {}; it is not destroyed",
                zfs_tools::engine::escape_display(&d.name),
                zfs_tools::engine::escape_display(origin)
            )));
        }
        for s in history(all, &d.name) {
            if s.identity.createtxg.get() > newest {
                return Err(refuse(format!(
                    "{} was taken after the drop was confirmed; it is not destroyed",
                    zfs_tools::engine::escape_display(&s.name)
                )));
            }
            if let Some(reason) = protection_after(s, releases) {
                return Err(refuse(reason));
            }
        }
    }
    let mut gone = BTreeSet::new();
    let mut effects = Vec::new();
    while !left.is_empty() {
        let position = left
            .iter()
            .rposition(|d| {
                let leaf = !left
                    .iter()
                    .any(|o| o.name != d.name && contains(&d.name, &o.name));
                let free = history(all, &d.name)
                    .iter()
                    .all(|s| s.clones.iter().all(|c| gone.contains(c)));
                leaf && free
            })
            .ok_or_else(|| refuse(format!("{} has a dependency outside the tree", root.name)))?;
        let d = left.remove(position);
        for s in history(all, &d.name).into_iter().rev() {
            if s.clones.iter().any(|c| !contains(&root.name, c)) {
                return Err(refuse(format!("{} gained an outside clone", s.name)));
            }
            effects.push(Effect::DestroySnapshot(s.point()));
        }
        effects.push(Effect::DestroyDataset(endpoint(d)));
        gone.insert(d.name.clone());
    }
    Ok(effects)
}

fn run(backend: &mut impl Backend, record: &mut Intent<State>) -> Result<DropOutcome, Error> {
    let pool = record.state.pool.clone();
    let id = record.id.clone();
    if record.step < MARKED {
        let state = backend.observe()?;
        for root in &record.state.trees {
            if find(&state, &root.name).is_none_or(|d| d.identity != root.identity) {
                return Err(refuse(format!("{} changed since the plan", root.name)));
            }
        }
        let marked_digest = {
            // Marks are this operation's own; they do not change identities.
            tree_digest(&state, &record.state.trees)?
        };
        if marked_digest != record.state.members {
            return Err(refuse(
                "the trees to drop changed since the plan; nothing more changed",
            ));
        }
        let (key, value) = mark(&id);
        for root in &record.state.trees {
            for d in members(&state, &root.name) {
                if local(&state, &d.name, &key) != Some(value.as_str()) {
                    backend.apply(&Effect::Set {
                        at: endpoint(d),
                        key: key.clone(),
                        value: value.clone(),
                    })?;
                }
            }
        }
        advance(backend, &pool, record, MARKED)?;
    }
    let state = backend.observe()?;
    let all = snapshots(&state)?;
    let mut effects = Vec::new();
    for (name, guid) in &record.state.snapshots {
        match snapshot(all, name) {
            None => {}
            Some(s) if s.identity.guid == *guid => {
                if let Some(reason) = protection_after(s, &record.state.releases) {
                    return Err(refuse(reason));
                }
                effects.push(Effect::DestroySnapshot(s.point()));
            }
            Some(_) => {
                return Err(refuse(format!(
                    "{} is another snapshot now; it is not destroyed",
                    zfs_tools::engine::escape_display(name)
                )));
            }
        }
    }
    for root in &record.state.trees {
        effects.extend(teardown_releasing(
            &state,
            root,
            &id,
            record.state.newest,
            &record.state.releases,
        )?);
    }
    // Only once every destruction is admitted: the confirmed holds go.
    for release in &record.state.releases {
        hold::release(backend, &release.snapshot, &release.tag)?;
    }
    let destroyed = effects
        .iter()
        .map(|e| match e {
            Effect::DestroySnapshot(p) => p.name.clone(),
            Effect::DestroyDataset(d) => d.name.clone(),
            _ => unreachable!(),
        })
        .collect();
    apply_all(backend, &effects)?;
    // Everything is destroyed: the drop is done.
    intent::finish(backend, &pool, record)?;
    Ok(DropOutcome {
        operation_id: id,
        destroyed,
        complete: true,
    })
}

/// Continue or abandon an interrupted drop. Abandoning destroys nothing more;
/// before any destruction it removes this operation's marks.
pub fn resume(
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<Resumed<DropOutcome>, Error> {
    resume_with(&mut super::Native, record, abandon, dialogue)
}
pub fn resume_with(
    backend: &mut impl Backend,
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<Resumed<DropOutcome>, Error> {
    let mut record: Intent<State> = decode(record, KIND)?;
    let pool = record.state.pool.clone();
    current(backend, &pool, &record)?;
    let id = record.id.clone();
    // A drop records steps 0 and MARKED; a later step is an older record.
    if record.step > MARKED {
        return Err(refuse(zfs_tools::engine::intent::earlier("drop", &id)));
    }
    if !abandon {
        let _ = writeln!(dialogue, "resuming drop {id}");
        return run(backend, &mut record)
            .map(Resumed::Complete)
            .map_err(|e| stopped(&id, e));
    }
    let state = backend.observe()?;
    let mut left = Vec::new();
    for root in &record.state.trees {
        let tree = members(&state, &root.name);
        let marked: Vec<_> = tree
            .iter()
            .filter(|d| local(&state, &d.name, management::PENDING_PROPERTY) == Some(id.as_str()))
            .collect();
        if record.step < MARKED {
            for d in marked {
                backend.apply(&Effect::Inherit {
                    at: endpoint(d),
                    key: management::PENDING_PROPERTY.into(),
                })?;
            }
        } else if !tree.is_empty() {
            left.push(format!(
                "{} is partly destroyed; its remaining datasets carry zboot:pending={id}, and `zboot drop {}` destroys the rest",
                root.name, root.name
            ));
        }
    }
    if record.step >= MARKED {
        let all = snapshots(&state)?;
        for (name, _) in &record.state.snapshots {
            if snapshot(all, name).is_some() {
                left.push(format!("{name} was not destroyed"));
            }
        }
    }
    intent::finish(backend, &pool, &record)?;
    Ok(Resumed::Abandoned(Abandoned {
        operation_id: id,
        kind: KIND.into(),
        left,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::fake::{Fake, every_cut, record, storage};
    use super::*;

    /// A live record of operation ID, on the other pool.
    fn live(f: &mut Fake, id: &str) {
        let record = Intent::new(id, "restore", serde_json::json!({}));
        f.set("b", intent::PROPERTY, &intent::encode(&record).unwrap());
    }
    fn fixture() -> Fake {
        let mut f = Fake::new();
        f.create("a/old");
        f.create("a/old/home");
        f.create("a/keep");
        f.snap("a/old@one");
        f.snap("a/old/home@one");
        f.snap("a/old@two");
        f.snap("a/keep@one");
        f.snap("a/keep@two");
        // A clone inside the tree of a snapshot inside the tree.
        f.datasets
            .insert("a/old/fork".into(), f.datasets["a/keep"].clone());
        f.datasets.get_mut("a/old/fork").unwrap().guid = 900;
        f.datasets.get_mut("a/old/fork").unwrap().origin = Some("a/old/home@one".into());
        f
    }
    fn targets() -> Vec<String> {
        vec!["a/old".into(), "a/keep@one".into()]
    }

    fn drop(f: &mut Fake) -> Result<(), Error> {
        let plan = plan_with(f, &targets())?;
        let token = consent(&plan).unwrap();
        execute_with(f, &plan, &token, &mut std::io::sink()).map(|_| ())
    }

    #[test]
    fn drop_destroys_exactly_the_planned_tree_and_snapshots() {
        let mut f = fixture();
        let plan = plan_with(&mut f, &targets()).unwrap();
        assert_eq!(plan.summary, "1 snapshot and 1 tree in a");
        assert_eq!(typed(&plan).text, plan.summary);
        assert_eq!(
            typed(&plan_with(&mut f, &["a/keep@one".into()]).unwrap()).text,
            "a/keep@one"
        );
        drop(&mut f).unwrap();
        assert!(f.datasets.keys().all(|d| !d.starts_with("a/old")));
        assert!(f.snapshots.keys().all(|s| !s.starts_with("a/old")));
        assert!(!f.snapshots.contains_key("a/keep@one"));
        assert!(f.snapshots.contains_key("a/keep@two"));
        assert!(f.datasets.contains_key("a/keep"));
    }

    #[test]
    fn every_cut_and_lost_reply_resumes_to_the_same_result() {
        every_cut(fixture, drop, |f, found| {
            resume_with(f, found, false, &mut std::io::sink()).map(|_| ())
        });
    }

    #[test]
    fn refusals_happen_before_any_effect() {
        let cases: [(&str, Vec<&str>, super::super::fake::Setup); 9] = [
            ("held", vec!["a/old"], |f| {
                f.snapshots
                    .get_mut("a/old@one")
                    .unwrap()
                    .holds
                    .insert("keep".into());
            }),
            ("outside clone", vec!["a/keep@two"], |f| {
                f.datasets
                    .insert("a/c".into(), f.datasets["a/keep"].clone());
                f.datasets.get_mut("a/c").unwrap().guid = 901;
                f.datasets.get_mut("a/c").unwrap().origin = Some("a/keep@two".into());
            }),
            ("bootfs", vec!["a/old"], |f| {
                f.pools.get_mut("a").unwrap().bootfs = Some("a/old/home".into());
            }),
            ("running", vec!["a/old"], |f| {
                f.running = Some("a/old".into())
            }),
            ("paired", vec!["a/old"], |f| {
                f.set("a/old/home", management::PAIR_PROPERTY, "{}")
            }),
            ("pool root", vec!["a"], |_| {}),
            ("overlap", vec!["a/old", "a/old/home"], |_| {}),
            ("two pools", vec!["a/old", "b"], |_| {}),
            ("active staging", vec!["a/old"], |f| {
                f.set("a/old", management::STAGING_PROPERTY, "op");
                live(f, "op");
            }),
        ];
        for (label, targets, change) in cases {
            let mut f = fixture();
            change(&mut f);
            let before = storage(&f);
            let targets: Vec<String> = targets.into_iter().map(String::from).collect();
            let result = plan_with(&mut f, &targets).and_then(|plan| {
                let token = consent(&plan).unwrap();
                execute_with(&mut f, &plan, &token, &mut std::io::sink())
            });
            assert!(result.is_err(), "{label}");
            assert_eq!(f.writes, 0, "{label}");
            assert_eq!(storage(&f), before, "{label}");
        }
    }

    #[test]
    fn leftover_staging_of_an_ended_operation_can_be_dropped() {
        let mut f = fixture();
        f.set("a/old", management::STAGING_PROPERTY, "gone");
        f.set("a/old", management::PENDING_PROPERTY, "gone");
        drop(&mut f).unwrap();
        assert!(!f.datasets.contains_key("a/old"));
    }

    #[test]
    fn a_dataset_or_snapshot_added_after_an_interruption_is_not_destroyed() {
        for add in [
            (|f: &mut Fake| f.create("a/old/late")) as fn(&mut Fake),
            |f: &mut Fake| f.snap("a/old/home@late"),
        ] {
            let mut f = fixture();
            // Cut after the record, every mark and the step are written.
            f.cut = Some((5, true));
            assert!(drop(&mut f).is_err());
            f.revive();
            add(&mut f);
            let found = record(&mut f).unwrap();
            assert_eq!(found.step, MARKED);
            let before = storage(&f);
            assert!(resume_with(&mut f, found.clone(), false, &mut std::io::sink()).is_err());
            assert_eq!(storage(&f), before);
            let Resumed::Abandoned(abandoned) =
                resume_with(&mut f, found, true, &mut std::io::sink()).unwrap()
            else {
                panic!()
            };
            assert!(!abandoned.left.is_empty());
            assert_eq!(storage(&f), before);
            assert!(record(&mut f).is_none());
        }
    }

    #[test]
    fn abandoning_before_any_destruction_removes_the_marks() {
        let mut f = fixture();
        let before = storage(&f);
        f.cut = Some((3, true));
        assert!(drop(&mut f).is_err());
        f.revive();
        let found = record(&mut f).unwrap();
        resume_with(&mut f, found, true, &mut std::io::sink()).unwrap();
        assert_eq!(storage(&f), before);
    }

    #[test]
    fn a_resumed_drop_never_destroys_an_outside_origin_deferred_since_the_cut() {
        let setup = || {
            let mut f = Fake::new();
            f.create("a/base");
            f.snap("a/base@one");
            f.create("a/old");
            f.create("a/old/clone");
            f.datasets.get_mut("a/old/clone").unwrap().origin = Some("a/base@one".into());
            f
        };
        let run = |f: &mut Fake| {
            let plan = plan_with(f, &["a/old".to_string()])?;
            let token = consent(&plan).unwrap();
            execute_with(f, &plan, &token, &mut std::io::sink()).map(|_| ())
        };
        let mut f = setup();
        f.cut = Some((4, true)); // record, two marks, advance
        assert!(run(&mut f).is_err());
        f.revive();
        assert_eq!(record(&mut f).unwrap().step, MARKED);
        f.snapshots.get_mut("a/base@one").unwrap().defer = true;
        let found = record(&mut f).unwrap();
        let error = resume_with(&mut f, found, false, &mut std::io::sink()).unwrap_err();
        assert!(error.to_string().contains("deferred origin"), "{error}");
        assert!(f.snapshots.contains_key("a/base@one"));
        assert!(f.datasets.contains_key("a/old/clone"));
    }

    const RESTORE: &str = "22222222-2222-4222-8222-222222222222";
    /// What an abandoned restore leaves when staging is the only copy.
    fn abandoned_restore() -> Fake {
        let mut f = Fake::new();
        let staging = format!("a/zboot-restore-{RESTORE}");
        f.create(&staging);
        f.set(&staging, management::STAGING_PROPERTY, RESTORE);
        f.create(&format!("{staging}/home"));
        for name in ["one", "two"] {
            f.snap(&format!("{staging}/home@{name}"));
        }
        let tag = format!("zboot:restore:{RESTORE}");
        for s in f.snapshots.values_mut() {
            s.holds.insert(tag.clone());
        }
        f
    }
    fn drop_staging(f: &mut Fake) -> Result<(), Error> {
        let plan = plan_with(f, &[format!("a/zboot-restore-{RESTORE}")])?;
        let token = consent(&plan).unwrap();
        execute_with(f, &plan, &token, &mut std::io::sink()).map(|_| ())
    }

    #[test]
    fn a_confirmed_drop_releases_an_ended_restores_holds_and_destroys_its_staging() {
        let mut f = abandoned_restore();
        let plan = plan_with(&mut f, &[format!("a/zboot-restore-{RESTORE}")]).unwrap();
        assert_eq!(plan.releases.len(), 2);
        let token = consent(&plan).unwrap();
        assert!(describe(&plan, &token).contains(&format!("releases zboot:restore:{RESTORE}")));
        drop_staging(&mut f).unwrap();
        assert!(f.datasets.keys().all(|d| !d.contains("zboot-restore")));
        assert!(f.snapshots.is_empty());
        every_cut(abandoned_restore, drop_staging, |f, found| {
            resume_with(f, found, false, &mut std::io::sink()).map(|_| ())
        });
    }

    #[test]
    fn restore_holds_are_kept_while_their_record_lives_or_another_hold_remains() {
        let cases: [(&str, super::super::fake::Setup); 3] = [
            ("live record", |f| live(f, RESTORE)),
            ("another hold", |f| {
                f.snapshots
                    .values_mut()
                    .next()
                    .unwrap()
                    .holds
                    .insert("keep".into());
            }),
            ("deferred", |f| {
                f.snapshots.values_mut().next().unwrap().defer = true;
            }),
        ];
        for (label, change) in cases {
            let mut f = abandoned_restore();
            change(&mut f);
            let before = storage(&f);
            assert!(drop_staging(&mut f).is_err(), "{label}");
            assert_eq!(f.writes, 0, "{label}");
            assert_eq!(storage(&f), before, "{label}");
        }
        // A hold added after the plan was confirmed is not released.
        let mut f = abandoned_restore();
        f.cut = Some((1, true));
        assert!(drop_staging(&mut f).is_err());
        f.revive();
        let first = f.snapshots.keys().next().unwrap().clone();
        f.snapshots
            .get_mut(&first)
            .unwrap()
            .holds
            .insert("keep".into());
        let found = record(&mut f).unwrap();
        assert!(resume_with(&mut f, found, false, &mut std::io::sink()).is_err());
        assert!(f.snapshots.values().all(|s| !s.holds.is_empty()));
    }
}
