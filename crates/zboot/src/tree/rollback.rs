//! `rollback DATASET@SNAP` †: rewind DATASET and every descendant to `@SNAP`.
//!
//! The plan names every newer snapshot it destroys; changes written since
//! `@SNAP` are lost. The token binds the members, their `@SNAP` identities and
//! the destroyed snapshots. Execution records intent on the pool root, fences
//! the tree read-only, destroys exactly the approved newer snapshots (newest
//! first), rolls each member back natively and restores its placement. The
//! record holds the root, the label, a member digest and the newest approved
//! creation txg: a snapshot taken after the plan is newer than that and is
//! refused, never destroyed.
use super::{
    Abandoned, Backend, Effect, Resumed, advance, apply_all, begin, current, dataset, decode,
    digest, endpoint, fence, history, local, members, new_id, pool_of, protection, refuse,
    refuse_running, relative, snapshot, snapshots, split_snapshot, stopped, unfence_recorded,
    unpaired,
};
use serde::{Deserialize, Serialize};
use std::io::Write;
use zfs_tools::engine::{
    Dataset, Error, SnapshotRef,
    intent::{self, Intent},
    management::{self, Endpoint},
    state::NativeState,
};

pub const KIND: &str = "rollback";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RollbackMember {
    pub dataset: Endpoint,
    pub target: SnapshotRef,
    /// Newer snapshots of this member that the rollback destroys.
    pub destroyed: Vec<SnapshotRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RollbackPlan {
    pub root: Endpoint,
    pub snapshot: String,
    pub members: Vec<RollbackMember>,
    /// Always true: changes written since `@SNAP` on every member are lost.
    pub unsnapshotted_changes_lost: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RollbackOutcome {
    pub operation_id: String,
    pub root: Endpoint,
    pub snapshot: String,
    /// Snapshots this run destroyed.
    pub destroyed: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    pool: String,
    root: Endpoint,
    snapshot: String,
    /// Members with their `@SNAP` identities.
    members: String,
    /// The newest creation txg the plan approved destroying.
    newest: u64,
    token: String,
}
const FENCED: u32 = 1;
const REWOUND: u32 = 2;

pub fn plan(target: &str) -> Result<RollbackPlan, Error> {
    plan_with(&mut super::Native, target)
}
pub fn plan_with(backend: &mut impl Backend, target: &str) -> Result<RollbackPlan, Error> {
    let state = backend.observe()?;
    let (root, label) = split_snapshot(target)?;
    if !root.contains('/') {
        return Err(refuse(
            "rollback of a pool's root dataset is not supported; select a dataset below it",
        ));
    }
    let all = snapshots(&state)?;
    let tree = members(&state, root);
    if tree.is_empty() {
        return Err(Error::NotFound(root.into()));
    }
    refuse_running(backend, &[root], "rollback")?;
    let mut planned = Vec::new();
    for d in &tree {
        unpaired(&state, &d.name)?;
        if local(&state, &d.name, management::PLACEMENT_PROPERTY).is_some() {
            return Err(refuse(format!(
                "{} carries a placement record left by an interrupted operation; resume or abandon it first",
                zfs_tools::engine::escape_display(&d.name)
            )));
        }
        let name = format!("{}@{label}", d.name);
        let target = snapshot(all, &name).ok_or_else(|| {
            refuse(format!(
                "{} has no @{label}; rollback needs it on every member",
                zfs_tools::engine::escape_display(&d.name)
            ))
        })?;
        let mut destroyed = Vec::new();
        for newer in history(all, &d.name)
            .into_iter()
            .filter(|s| s.identity.createtxg > target.identity.createtxg)
        {
            if let Some(reason) = protection(newer) {
                return Err(refuse(format!(
                    "{reason}; release it or roll back to a newer snapshot"
                )));
            }
            if let Some(clone) = newer.clones.first() {
                return Err(refuse(format!(
                    "{} is the origin of {}; drop or promote it first",
                    zfs_tools::engine::escape_display(&newer.name),
                    zfs_tools::engine::escape_display(clone)
                )));
            }
            destroyed.push(newer.point());
        }
        destroyed.reverse();
        planned.push(RollbackMember {
            dataset: endpoint(d),
            target: target.point(),
            destroyed,
        });
    }
    Ok(RollbackPlan {
        root: endpoint(tree[0]),
        snapshot: label.into(),
        members: planned,
        unsnapshotted_changes_lost: true,
    })
}
pub fn consent(plan: &RollbackPlan) -> std::io::Result<String> {
    crate::consent::token(&(KIND, plan))
}
pub fn typed(plan: &RollbackPlan) -> crate::consent::Typed {
    crate::consent::Typed {
        what: "the snapshot",
        text: format!("{}@{}", plan.root.name, plan.snapshot),
    }
}
pub fn describe(plan: &RollbackPlan, token: &str) -> String {
    let root = zfs_tools::engine::escape_display(&plan.root.name);
    let mut text = format!(
        "Roll back {root} and {} descendant(s) to @{}.\n",
        plan.members.len() - 1,
        zfs_tools::engine::escape_display(&plan.snapshot)
    );
    let destroyed: Vec<_> = plan.members.iter().flat_map(|m| &m.destroyed).collect();
    if destroyed.is_empty() {
        text.push_str("No newer snapshots are destroyed.\n");
    } else {
        text.push_str("Destroys these newer snapshots:\n");
        for point in destroyed {
            text.push_str(&format!(
                "  {}\n",
                zfs_tools::engine::escape_display(&point.name)
            ));
        }
    }
    text.push_str(&format!(
        "Changes written since @{} on every member are lost.\nToken: {token}\n",
        zfs_tools::engine::escape_display(&plan.snapshot)
    ));
    text
}

fn rows(state: &NativeState, root: &str, label: &str) -> Result<String, Error> {
    let all = snapshots(state)?;
    let mut rows = Vec::new();
    for d in members(state, root) {
        let target = snapshot(all, &format!("{}@{label}", d.name))
            .ok_or_else(|| refuse(format!("{}@{label} is gone", d.name)))?;
        rows.push((
            relative(root, &d.name).to_string(),
            d.identity.clone(),
            target.identity.clone(),
        ));
    }
    digest(&rows)
}

pub fn execute(
    plan: &RollbackPlan,
    token: &str,
    dialogue: &mut dyn Write,
) -> Result<RollbackOutcome, Error> {
    execute_with(&mut super::Native, plan, token, dialogue)
}
pub fn execute_with(
    backend: &mut impl Backend,
    plan: &RollbackPlan,
    token: &str,
    dialogue: &mut dyn Write,
) -> Result<RollbackOutcome, Error> {
    let target = format!("{}@{}", plan.root.name, plan.snapshot);
    let fresh = plan_with(backend, &target)?;
    let digest_token = consent(&fresh).map_err(|e| refuse(e.to_string()))?;
    if fresh != *plan || digest_token != token {
        return Err(refuse(
            "the rollback plan changed since it was confirmed; nothing changed",
        ));
    }
    let newest = plan
        .members
        .iter()
        .flat_map(|m| m.destroyed.iter().chain([&m.target]))
        .map(|p| p.identity.createtxg.get())
        .max()
        .unwrap_or(0);
    let state = State {
        pool: pool_of(&plan.root.name).into(),
        root: plan.root.clone(),
        snapshot: plan.snapshot.clone(),
        members: rows(&backend.observe()?, &plan.root.name, &plan.snapshot)?,
        newest,
        token: token.into(),
    };
    let mut record = Intent::new(new_id(), KIND, state);
    begin(backend, &record.state.pool.clone(), &record, dialogue)?;
    let id = record.id.clone();
    run(backend, &mut record).map_err(|e| stopped(&id, e))
}

/// The tree as recorded, else a refusal naming what changed.
fn bound<'a>(state: &'a NativeState, record: &State) -> Result<Vec<&'a Dataset>, Error> {
    let root = dataset(state, &record.root.name)?;
    if root.identity != record.root.identity {
        return Err(refuse(format!(
            "{} is another dataset now",
            record.root.name
        )));
    }
    if rows(state, &record.root.name, &record.snapshot)? != record.members {
        return Err(refuse(format!(
            "the members of {} or their @{} changed since the plan",
            record.root.name, record.snapshot
        )));
    }
    Ok(members(state, &record.root.name))
}

fn run(backend: &mut impl Backend, record: &mut Intent<State>) -> Result<RollbackOutcome, Error> {
    let pool = record.state.pool.clone();
    let mut destroyed = Vec::new();
    if record.step < FENCED {
        let state = backend.observe()?;
        let tree = bound(&state, &record.state)?;
        apply_all(backend, &fence(&state, &tree)?)?;
        advance(backend, &pool, record, FENCED)?;
    }
    if record.step < REWOUND {
        let state = backend.observe()?;
        let tree = bound(&state, &record.state)?;
        let all = snapshots(&state)?;
        for d in &tree {
            let target = snapshot(all, &format!("{}@{}", d.name, record.state.snapshot))
                .ok_or_else(|| refuse("rollback target disappeared"))?;
            let mut newer: Vec<_> = history(all, &d.name)
                .into_iter()
                .filter(|s| s.identity.createtxg > target.identity.createtxg)
                .collect();
            newer.reverse();
            for s in &newer {
                if s.identity.createtxg.get() > record.state.newest {
                    return Err(refuse(format!(
                        "{} was taken after the rollback was confirmed; it is not destroyed",
                        zfs_tools::engine::escape_display(&s.name)
                    )));
                }
                if let Some(reason) = protection(s) {
                    return Err(refuse(reason));
                }
                if !s.clones.is_empty() {
                    return Err(refuse(format!("{} gained a clone", s.name)));
                }
            }
            for s in newer {
                backend.apply(&Effect::DestroySnapshot(s.point()))?;
                destroyed.push(s.name.clone());
            }
            backend.apply(&Effect::Rollback(target.point()))?;
        }
        advance(backend, &pool, record, REWOUND)?;
    }
    let state = backend.observe()?;
    let tree = bound(&state, &record.state)?;
    apply_all(backend, &unfence_recorded(&state, &tree)?)?;
    intent::finish(backend, &pool, record)?;
    Ok(RollbackOutcome {
        operation_id: record.id.clone(),
        root: record.state.root.clone(),
        snapshot: record.state.snapshot.clone(),
        destroyed,
        complete: true,
    })
}

/// Continue or abandon an interrupted rollback. Abandoning restores the
/// recorded placement and destroys nothing.
pub fn resume(
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<Resumed<RollbackOutcome>, Error> {
    resume_with(&mut super::Native, record, abandon, dialogue)
}
pub fn resume_with(
    backend: &mut impl Backend,
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> Result<Resumed<RollbackOutcome>, Error> {
    let mut record: Intent<State> = decode(record, KIND)?;
    let pool = record.state.pool.clone();
    current(backend, &pool, &record)?;
    // A rollback records steps 0 to REWOUND; a later step is an older record.
    if record.step > REWOUND {
        return Err(refuse(zfs_tools::engine::intent::earlier(
            "rollback", &record.id,
        )));
    }
    if !abandon {
        let _ = writeln!(dialogue, "resuming rollback {}", record.id);
        let id = record.id.clone();
        return run(backend, &mut record)
            .map(Resumed::Complete)
            .map_err(|e| stopped(&id, e));
    }
    let state = backend.observe()?;
    let tree = members(&state, &record.state.root.name);
    let bound_root = tree
        .first()
        .is_some_and(|d| d.identity == record.state.root.identity);
    let mut left = Vec::new();
    if bound_root {
        apply_all(backend, &unfence_recorded(&state, &tree)?)?;
    } else {
        left.push(format!(
            "{} is gone or replaced; any placement records on it were left",
            record.state.root.name
        ));
    }
    if record.step >= FENCED {
        left.push(format!(
            "{} may be partly rolled back to @{}: some newer snapshots may already be destroyed",
            record.state.root.name, record.state.snapshot
        ));
    }
    intent::finish(backend, &pool, &record)?;
    Ok(Resumed::Abandoned(Abandoned {
        operation_id: record.id,
        kind: KIND.into(),
        left,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::fake::{Fake, every_cut, record, storage};
    use super::*;

    fn fixture() -> Fake {
        let mut f = Fake::new();
        f.create("a/be");
        f.create("a/be/home");
        f.create("a/other");
        f.snap("a/be@base");
        f.snap("a/be/home@base");
        f.snap("a/other@base");
        f.write("a/be");
        f.snap("a/be@later");
        f.snap("a/be/home@later");
        f.snap("a/other@later");
        f.write("a/be");
        f.write("a/be/home");
        f
    }
    fn rollback(f: &mut Fake) -> Result<(), Error> {
        let plan = plan_with(f, "a/be@base")?;
        let token = consent(&plan).unwrap();
        execute_with(f, &plan, &token, &mut std::io::sink()).map(drop)
    }

    #[test]
    fn rollback_destroys_exactly_the_planned_newer_snapshots_and_restores_placement() {
        let mut f = fixture();
        let before = f.clone();
        let plan = plan_with(&mut f, "a/be@base").unwrap();
        let destroyed: Vec<_> = plan
            .members
            .iter()
            .flat_map(|m| &m.destroyed)
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(destroyed, ["a/be@later", "a/be/home@later"]);
        assert!(describe(&plan, "t").contains("Changes written since @base"));
        assert_eq!(typed(&plan).text, "a/be@base");
        rollback(&mut f).unwrap();
        assert!(!f.snapshots.contains_key("a/be@later"));
        assert!(f.snapshots.contains_key("a/other@later"));
        assert_eq!(
            f.datasets["a/be"].content,
            before.snapshots["a/be@base"].content
        );
        assert_eq!(
            f.datasets["a/be/home"].content,
            before.snapshots["a/be/home@base"].content
        );
        assert_eq!(f.datasets["a/other"], before.datasets["a/other"]);
        for name in ["a/be", "a/be/home"] {
            assert!(
                !f.datasets[name]
                    .props
                    .contains_key(management::PLACEMENT_PROPERTY)
            );
            assert_eq!(f.effective(name, "readonly").unwrap().0, "off");
        }
        assert!(record(&mut f).is_none());
    }

    #[test]
    fn every_cut_and_lost_reply_resumes_to_the_same_result() {
        every_cut(fixture, rollback, |f, found| {
            resume_with(f, found, false, &mut std::io::sink()).map(drop)
        });
    }

    #[test]
    fn refusals_happen_before_any_effect() {
        let cases: [(&str, super::super::fake::Setup); 6] = [
            ("missing", |f| {
                f.snapshots.remove("a/be/home@base");
            }),
            ("held", |f| {
                f.snapshots
                    .get_mut("a/be@later")
                    .unwrap()
                    .holds
                    .insert("keep".into());
            }),
            ("clone", |f| {
                f.datasets
                    .insert("a/c".into(), f.datasets["a/other"].clone());
                f.datasets.get_mut("a/c").unwrap().origin = Some("a/be/home@later".into());
            }),
            ("paired", |f| {
                f.set("a/be", management::PAIR_PROPERTY, "{}");
            }),
            ("running", |f| f.running = Some("a/be/home".into())),
            ("staging", |f| {
                f.set("a/be/home", management::STAGING_PROPERTY, "x")
            }),
        ];
        for (label, change) in cases {
            let mut f = fixture();
            change(&mut f);
            let before = storage(&f);
            assert!(rollback(&mut f).is_err(), "{label}");
            assert_eq!(f.writes, 0, "{label}");
            assert_eq!(storage(&f), before, "{label}");
        }
        let mut f = fixture();
        assert!(plan_with(&mut f, "a@base").is_err());
    }

    #[test]
    fn a_changed_plan_or_wrong_token_changes_nothing() {
        let mut f = fixture();
        let plan = plan_with(&mut f, "a/be@base").unwrap();
        assert!(execute_with(&mut f, &plan, "0", &mut std::io::sink()).is_err());
        f.snap("a/be/home@newest");
        let token = consent(&plan).unwrap();
        assert!(execute_with(&mut f, &plan, &token, &mut std::io::sink()).is_err());
        assert_eq!(f.writes, 0);
    }

    #[test]
    fn a_snapshot_taken_after_an_interruption_is_refused_not_destroyed() {
        let mut f = fixture();
        f.cut = Some((3, true));
        assert!(rollback(&mut f).is_err());
        f.revive();
        f.snap("a/be/home@intruder");
        let found = record(&mut f).unwrap();
        assert!(resume_with(&mut f, found, false, &mut std::io::sink()).is_err());
        assert!(f.snapshots.contains_key("a/be/home@intruder"));
        // The refused resume advanced the record; abandon what is recorded now.
        let found = record(&mut f).unwrap();
        let abandoned = resume_with(&mut f, found, true, &mut std::io::sink()).unwrap();
        assert!(matches!(abandoned, Resumed::Abandoned(_)));
        assert!(record(&mut f).is_none());
        assert!(f.snapshots.contains_key("a/be/home@intruder"));
        for name in ["a/be", "a/be/home"] {
            assert!(
                !f.datasets[name]
                    .props
                    .contains_key(management::PLACEMENT_PROPERTY)
            );
            assert_eq!(f.effective(name, "readonly").unwrap().0, "off");
        }
    }

    #[test]
    fn a_changed_tree_is_refused_on_resume() {
        let mut f = fixture();
        f.cut = Some((2, true));
        assert!(rollback(&mut f).is_err());
        f.revive();
        f.create("a/be/new");
        f.snap("a/be/new@base");
        let found = record(&mut f).unwrap();
        let before = storage(&f);
        assert!(resume_with(&mut f, found, false, &mut std::io::sink()).is_err());
        assert_eq!(storage(&f), before);
    }
}
