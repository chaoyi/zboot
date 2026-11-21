//! `rename SRC DEST`: a native rename within one pool, run directly.
//! Cross-pool relocation uses sync, primary, unpair and drop as separate
//! reviewable commands; this module never receives or retires a copied tree.
//!
//! In-pool: properties the tree inherits from outside it (and default
//! mountpoints) are set locally so the moved tree keeps its placement, the
//! tree is renamed natively (identities, snapshots, mounts and clone origins
//! follow), and a boot default inside it is kept on the new name.
//!
use super::{
    Abandoned, Backend, Effect, Resumed, advance, begin, current, dataset, decode, endpoint, find,
    local, member_digest, members, new_id, pool_bootfs, pool_of, refuse, refuse_running, relative,
    stopped, unpaired,
};
use crate::history::contains_dataset as contains;
use serde::{Deserialize, Serialize};
use std::io::Write;
use zfs_tools::engine::{
    Dataset, DatasetKind, Error,
    intent::{self, Intent},
    management::{self, Endpoint},
    state::NativeState,
};

pub const KIND: &str = "rename";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Preserved {
    pub dataset: String,
    pub property: String,
    pub value: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenamePlan {
    pub source: Endpoint,
    pub destination: String,
    pub members: Vec<Endpoint>,
    /// Inherited values set locally so they survive the new parent.
    pub preserved: Vec<Preserved>,
    /// The pool's boot default inside the tree, which follows it.
    pub bootfs: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MovePlan {
    /// Same pool: a native rename; nothing is lost.
    Rename(RenamePlan),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MoveOutcome {
    pub operation_id: String,
    /// `None` once a completed move's destination was moved or dropped.
    pub destination: Option<Endpoint>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameState {
    pool: String,
    source: Endpoint,
    destination: String,
    members: String,
    /// The bootfs below the source root (`""` for the root), if any.
    bootfs: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum State {
    Rename(RenameState),
}
impl State {
    fn pool(&self) -> String {
        let Self::Rename(s) = self;
        s.pool.clone()
    }
}
const PRESERVED: u32 = 1;
const RENAMED: u32 = 2;
/// Four independently reviewable pair commands replace the retired receive
/// engine. Refuse during planning, including dry runs, before any effect.
fn cross_pool_recipe(source: &str, destination: &str) -> Error {
    let source = zfs_tools::engine::escape_display(source);
    let destination = zfs_tools::engine::escape_display(destination);
    refuse(format!(
        "rename stays within one pool; to move {source} to another pool, run these in order, reviewing each confirmation: `zboot sync {source} {destination}`, `zboot primary {destination}`, `zboot unpair {destination} --release-anchors`, `zboot drop {source}`"
    ))
}

pub fn plan(source: &str, destination: &str) -> Result<MovePlan, Error> {
    plan_with(&mut super::Native, source, destination)
}
pub fn plan_with(
    backend: &mut impl Backend,
    source: &str,
    destination: &str,
) -> Result<MovePlan, Error> {
    zfs_tools::engine::validate_dataset_name(source)?;
    zfs_tools::engine::validate_dataset_name(destination)?;
    if !source.contains('/') || !destination.contains('/') {
        return Err(refuse("a pool's root dataset cannot be moved or replaced"));
    }
    if contains(source, destination) || contains(destination, source) {
        return Err(Error::InvalidScope(format!(
            "{source} and {destination} overlap"
        )));
    }
    if pool_of(source) != pool_of(destination) {
        return Err(cross_pool_recipe(source, destination));
    }
    let state = backend.observe()?;
    let tree = members(&state, source);
    if tree.is_empty() {
        return Err(Error::NotFound(source.into()));
    }
    if state
        .inspection
        .datasets
        .iter()
        .any(|d| contains(destination, &d.name))
    {
        return Err(refuse(format!(
            "{} exists",
            zfs_tools::engine::escape_display(destination)
        )));
    }
    let parent_name = destination.rsplit_once('/').unwrap().0;
    find(&state, parent_name).ok_or_else(|| {
        refuse(format!(
            "{} does not exist; create the parent first",
            zfs_tools::engine::escape_display(parent_name)
        ))
    })?;
    unpaired(&state, parent_name)?;
    for d in &tree {
        unpaired(&state, &d.name)?;
        if local(&state, &d.name, management::PLACEMENT_PROPERTY).is_some() {
            return Err(refuse(format!(
                "{} carries a placement record left by an interrupted operation; resume or abandon it first",
                zfs_tools::engine::escape_display(&d.name)
            )));
        }
    }
    refuse_running(backend, &[source], "rename")?;
    for d in &tree {
        if let Some(root) = &d.encryptionroot
            && !contains(source, root)
            && !contains(root, destination)
        {
            return Err(refuse(format!(
                "{} uses the key of {}, outside the destination",
                zfs_tools::engine::escape_display(&d.name),
                zfs_tools::engine::escape_display(root)
            )));
        }
    }
    Ok(MovePlan::Rename(RenamePlan {
        source: endpoint(tree[0]),
        destination: destination.into(),
        members: tree.iter().map(|d| endpoint(d)).collect(),
        preserved: preserved(&state, source, &tree),
        bootfs: pool_bootfs(&state, pool_of(source))
            .filter(|b| contains(source, b))
            .cloned(),
    }))
}

/// Properties a move carries over: user properties outside zboot's and
/// zctl's namespaces, and the native tuning and behaviour a reparent changes.
fn preservable(key: &str) -> bool {
    key == "mountpoint"
        || ((key.contains(':') && !management::managed_key(key))
            || matches!(
                key,
                "compression"
                    | "checksum"
                    | "recordsize"
                    | "acltype"
                    | "aclinherit"
                    | "aclmode"
                    | "xattr"
                    | "dnodesize"
                    | "dedup"
                    | "copies"
                    | "atime"
                    | "relatime"
                    | "devices"
                    | "exec"
                    | "setuid"
                    | "snapdir"
                    | "sync"
                    | "logbias"
                    | "special_small_blocks"
                    | "redundant_metadata"
            ))
}
/// Properties `tree` inherits from outside `root`, and a default
/// mountpoint, that a new parent would change. Only the root can inherit from
/// outside: its descendants inherit through it, so setting these on the root
/// keeps every member's value, and a resumed pass finds nothing left to set.
fn preserved(state: &NativeState, root: &str, tree: &[&Dataset]) -> Vec<Preserved> {
    let mut found = Vec::new();
    for d in tree.iter().take(1) {
        let Some(properties) = state.dataset_properties.get(&d.name) else {
            continue;
        };
        for (key, p) in properties {
            if !preservable(key) || (key == "mountpoint" && d.kind != DatasetKind::Filesystem) {
                continue;
            }
            let outside = p
                .source
                .strip_prefix("inherited from ")
                .is_some_and(|owner| !contains(root, owner));
            if outside || (key == "mountpoint" && p.source == "default") {
                found.push(Preserved {
                    dataset: d.name.clone(),
                    property: key.clone(),
                    value: p.value.clone(),
                });
            }
        }
    }
    found
}
pub fn consent(plan: &MovePlan) -> std::io::Result<String> {
    crate::consent::token(&(KIND, plan))
}
pub fn describe(plan: &MovePlan, _token: &str) -> String {
    match plan {
        MovePlan::Rename(p) => {
            let mut text = format!(
                "Rename {} to {} ({} dataset(s)); nothing is lost.\n",
                zfs_tools::engine::escape_display(&p.source.name),
                zfs_tools::engine::escape_display(&p.destination),
                p.members.len()
            );
            for kept in &p.preserved {
                text.push_str(&format!(
                    "  keeps {}={} on {}\n",
                    zfs_tools::engine::escape_display(&kept.property),
                    zfs_tools::engine::escape_display(&kept.value),
                    zfs_tools::engine::escape_display(&kept.dataset)
                ));
            }
            if let Some(bootfs) = &p.bootfs {
                text.push_str(&format!(
                    "  the boot default {} follows the move\n",
                    zfs_tools::engine::escape_display(bootfs)
                ));
            }
            text
        }
    }
}

fn tree_digest(state: &NativeState, root: &str) -> Result<String, Error> {
    member_digest(root, &members(state, root))
}

/// Run an in-pool rename. Like fork it loses nothing, so the command's review
/// binds any confirmation; this re-plans and refuses a changed plan.
pub fn execute(plan: &MovePlan, dialogue: &mut dyn Write) -> Result<MoveOutcome, Error> {
    execute_with(&mut super::Native, plan, dialogue)
}
pub fn execute_with(
    backend: &mut impl Backend,
    plan: &MovePlan,
    dialogue: &mut dyn Write,
) -> Result<MoveOutcome, Error> {
    let MovePlan::Rename(p) = plan;
    let fresh = plan_with(backend, &p.source.name, &p.destination)?;
    if fresh != *plan {
        return Err(refuse("the rename plan changed; nothing changed"));
    }
    let observed = backend.observe()?;
    let state = State::Rename(RenameState {
        pool: pool_of(&p.source.name).into(),
        source: p.source.clone(),
        destination: p.destination.clone(),
        members: tree_digest(&observed, &p.source.name)?,
        bootfs: p
            .bootfs
            .as_ref()
            .map(|b| relative(&p.source.name, b).to_string()),
    });
    let mut record = Intent::new(new_id(), KIND, state);
    begin(backend, &record.state.pool(), &record, dialogue)?;
    let id = record.id.clone();
    run(backend, &mut record).map_err(|e| stopped(&id, e))
}

fn run(backend: &mut impl Backend, record: &mut Intent<State>) -> Result<MoveOutcome, Error> {
    let State::Rename(s) = record.state.clone();
    rename(backend, record, &s)
}

fn rename(
    backend: &mut impl Backend,
    record: &mut Intent<State>,
    s: &RenameState,
) -> Result<MoveOutcome, Error> {
    let pool = s.pool.clone();
    let bound = |state: &NativeState, renamed: bool| -> Result<(), Error> {
        let root = if renamed {
            &s.destination
        } else {
            &s.source.name
        };
        if find(state, root).is_none_or(|d| d.identity != s.source.identity)
            || tree_digest(state, root)? != s.members
        {
            return Err(refuse(format!(
                "{root} is not the tree the move was planned for"
            )));
        }
        Ok(())
    };
    let moved = |state: &NativeState| {
        find(state, &s.destination).is_some_and(|d| d.identity == s.source.identity)
    };
    if record.step < PRESERVED {
        let state = backend.observe()?;
        bound(&state, false)?;
        let tree = members(&state, &s.source.name);
        for kept in preserved(&state, &s.source.name, &tree) {
            backend.apply(&Effect::Set {
                at: endpoint(dataset(&state, &kept.dataset)?),
                key: kept.property,
                value: kept.value,
            })?;
        }
        advance(backend, &pool, record, PRESERVED)?;
    }
    if record.step < RENAMED {
        let state = backend.observe()?;
        if !moved(&state) {
            bound(&state, false)?;
            backend.apply(&Effect::Rename {
                from: s.source.clone(),
                to: s.destination.clone(),
            })?;
        }
        advance(backend, &pool, record, RENAMED)?;
    }
    let state = backend.observe()?;
    bound(&state, true)?;
    if let Some(rel) = &s.bootfs {
        let expected = format!("{}{rel}", s.destination);
        if pool_bootfs(&state, &pool) != Some(&expected) {
            backend.apply(&Effect::Bootfs {
                pool: pool.clone(),
                dataset: Some(expected),
            })?;
        }
    }
    // The boot default follows the rename: the move is done.
    intent::finish(backend, &pool, record)?;
    Ok(MoveOutcome {
        operation_id: record.id.clone(),
        destination: Some(Endpoint {
            name: s.destination.clone(),
            identity: s.source.identity.clone(),
        }),
        complete: true,
    })
}

/// Continue or abandon an interrupted rename.
pub fn resume(
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<Resumed<MoveOutcome>, Error> {
    resume_with(&mut super::Native, record, abandon, dialogue)
}
pub fn resume_with(
    backend: &mut impl Backend,
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<Resumed<MoveOutcome>, Error> {
    if record.kind != KIND {
        return Err(refuse("this is not a rename operation"));
    }
    let mut record: Intent<State> = decode(record, KIND)?;
    let pool = record.state.pool();
    current(backend, &pool, &record)?;
    let id = record.id.clone();
    // A rename records steps 0 to RENAMED; a later step is an older record.
    if record.step > RENAMED {
        return Err(refuse(zfs_tools::engine::intent::earlier("rename", &id)));
    }
    if !abandon {
        let _ = writeln!(dialogue, "resuming rename {id}");
        return run(backend, &mut record)
            .map(Resumed::Complete)
            .map_err(|e| stopped(&id, e));
    }
    let state = backend.observe()?;
    let State::Rename(s) = &record.state;
    let at = if find(&state, &s.destination).is_some() {
        &s.destination
    } else {
        &s.source.name
    };
    let left = vec![format!(
        "the tree is at {at}; inherited properties may now be set locally"
    )];
    intent::finish(backend, &pool, &record)?;
    Ok(Resumed::Abandoned(Abandoned {
        operation_id: id,
        kind: record.kind.clone(),
        left,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::fake::{Fake, every_cut, storage};
    use super::*;

    fn fixture() -> Fake {
        let mut f = Fake::new();
        f.create("a/data");
        f.set("a/data", "compression", "lz4");
        f.set("a/data", "mountpoint", "/srv");
        f.create("a/src");
        f.create("a/src/child");
        f.snap("a/src@one");
        f.snap("a/src/child@one");
        f.create("a/box");
        f.set("a/box", "compression", "zstd");
        f.create("b/dst");
        f.pools.get_mut("a").unwrap().bootfs = Some("a/src".into());
        f
    }
    fn moved(f: &mut Fake, to: &str) -> Result<(), Error> {
        let plan = plan_with(f, "a/src", to)?;
        execute_with(f, &plan, &mut std::io::sink()).map(drop)
    }

    #[test]
    fn an_in_pool_move_renames_keeping_identity_placement_and_the_boot_default() {
        let mut f = fixture();
        f.set("a/src", "compression", "gzip");
        let identity = f.identity("a/src");
        plan_with(&mut f, "a/src", "a/box/src").unwrap();
        moved(&mut f, "a/box/src").unwrap();
        assert_eq!(f.identity("a/box/src"), identity);
        assert_eq!(f.effective("a/box/src", "mountpoint").unwrap().0, "/a/src");
        assert_eq!(
            f.effective("a/box/src/child", "mountpoint").unwrap().0,
            "/a/src/child"
        );
        assert_eq!(
            f.effective("a/box/src/child", "compression").unwrap().0,
            "gzip"
        );
        assert_eq!(f.pools["a"].bootfs.as_deref(), Some("a/box/src"));
        assert!(f.snapshots.contains_key("a/box/src/child@one"));
    }

    #[test]
    fn every_in_pool_cut_and_lost_reply_resumes_to_the_same_result() {
        every_cut(
            fixture,
            |f| moved(f, "a/box/src"),
            |f, found| resume_with(f, found, false, &mut std::io::sink()).map(drop),
        );
    }

    #[test]
    fn refusals_happen_before_any_effect() {
        let cases: [(&str, &str, super::super::fake::Setup); 5] = [
            ("exists", "a/box", |_| {}),
            ("overlap", "a/src/child/x", |_| {}),
            ("no parent", "a/none/src", |_| {}),
            ("running", "a/box/src", |f| {
                f.running = Some("a/src/child".into())
            }),
            ("paired", "a/box/src", |f| {
                f.set("a/src", management::PAIR_PROPERTY, "{}")
            }),
        ];
        for (label, to, change) in cases {
            let mut f = fixture();
            change(&mut f);
            let before = storage(&f);
            assert!(moved(&mut f, to).is_err(), "{label}");
            assert_eq!(f.writes, 0, "{label}");
            assert_eq!(storage(&f), before, "{label}");
        }
    }

    #[test]
    fn cross_pool_move_refuses_with_four_commands_before_any_effect() {
        let mut f = fixture();
        let before = storage(&f);
        let error = moved(&mut f, "b/dst/src").unwrap_err().to_string();
        for command in [
            "zboot sync a/src b/dst/src",
            "zboot primary b/dst/src",
            "zboot unpair b/dst/src --release-anchors",
            "zboot drop a/src",
        ] {
            assert!(error.contains(command), "{error}");
        }
        assert_eq!(f.writes, 0);
        assert_eq!(storage(&f), before);
    }

    #[test]
    fn inactive_same_pool_moves_keep_roles_and_never_mount() {
        for mode in ["noauto", "off"] {
            let mut f = fixture();
            for name in ["a/src", "a/src/child"] {
                f.set(name, "canmount", mode);
                f.datasets.get_mut(name).unwrap().mounted = false;
            }
            moved(&mut f, "a/box/src").unwrap();
            for name in ["a/box/src", "a/box/src/child"] {
                assert!(!f.datasets[name].mounted);
                assert_eq!(f.effective(name, "canmount").unwrap().0, mode);
            }
            assert!(f.log.iter().all(|entry| !entry.starts_with("Mount(")));
        }
    }
}
