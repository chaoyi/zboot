//! Fault injection for the pair verbs: every effect and every record write is
//! cut before and after it lands, the process restarts, and `resume` (or, with
//! no record left, the verb again) must reach the same safe end state.
use super::*;
use crate::{
    history::Side,
    observation::HistoryBackend,
    pairs::plan::PairRequest,
    transfer::{TransferBackend, TransferRequest, tests::Fake as Transfer},
};
use std::collections::BTreeMap;
use zfs_tools::engine::{
    Guid, ObjsetId, SnapshotIdentity, Txg,
    attachment::{self, AttachmentBackend},
    capture::CaptureBackend,
    management::{Ownership, Role},
    mutation::PropertyKey,
    native::NativeProperty,
    stream::{LeafStream, StreamOutcome},
};

const ID: &str = "11111111-1111-4111-8111-111111111111";
const OP: &str = "33333333-3333-4333-8333-333333333333";
const RERUN: &str = "55555555-5555-4555-8555-555555555555";
const SECOND: &str = "66666666-6666-4666-8666-666666666666";

#[derive(Clone)]
struct World {
    t: Transfer,
    bootfs: BTreeMap<String, String>,
    /// Pools observed as imported read-only.
    readonly: Vec<String>,
    fail_default: bool,
    /// The operation ID `primary_now` uses; a rerun after an abandon takes
    /// a new one, as every run does.
    op: &'static str,
    /// The hostid each pool's labels record; absent pools record 7.
    hostids: BTreeMap<String, u32>,
    lose_placement_reply: bool,
    /// A write to this dataset that only the next `zpool sync` puts on disk.
    unsynced: Option<String>,
}
impl World {
    fn new(bootstrap: bool) -> Self {
        let mut t = Transfer::unpaired(bootstrap);
        t.primary_mode = true;
        Self {
            t,
            bootfs: BTreeMap::new(),
            readonly: vec![],
            fail_default: false,
            op: OP,
            hostids: BTreeMap::new(),
            lose_placement_reply: false,
            unsynced: None,
        }
    }
    fn n(&mut self) -> &mut crate::pairs::plan::tests::Fake {
        &mut self.t.native
    }
    fn state(&mut self) -> NativeState {
        PairBackend::observe(self).unwrap()
    }
    fn effects(&self) -> usize {
        self.t.native.effects
    }
    fn restart(&mut self) {
        self.t.native.crashed = false;
        self.t.native.cut = None;
    }
    fn export(&mut self, pool: &str) {
        let n = self.n();
        n.members
            .retain(|m| !history::contains_dataset(pool, &m.endpoint.name));
        n.mounted.retain(|m| !history::contains_dataset(pool, m));
    }
    fn record(&mut self, name: &str) -> Option<PairRecord> {
        self.t
            .native
            .properties
            .get(name)
            .and_then(|p| p.get(management::PAIR_PROPERTY))
            .filter(|p| p.source == "local")
            .map(|p| PairRecord::parse(&p.value).unwrap())
    }
    fn readonly(&mut self, name: &str) -> bool {
        let state = self.state();
        dataset(&state, name).unwrap().readonly
    }
    fn mounted(&self, name: &str) -> bool {
        self.t.native.mounted.contains(name)
    }
    fn guids(&self, name: &str) -> Vec<u64> {
        self.t
            .native
            .members
            .iter()
            .find(|m| m.endpoint.name == name)
            .map(|m| m.snapshots.iter().map(|s| s.identity.guid.get()).collect())
            .unwrap_or_default()
    }
    /// Existing snapshots holding `tag`.
    fn holds(&self, tag: &str) -> Vec<String> {
        let n = &self.t.native;
        n.holds
            .iter()
            .filter(|(name, tags)| {
                tags.contains(tag)
                    && n.members
                        .iter()
                        .flat_map(|m| &m.snapshots)
                        .any(|s| &s.name == *name)
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
    fn records(&mut self) -> Vec<intent::Intent<serde_json::Value>> {
        intent::find(self)
            .unwrap()
            .into_iter()
            .map(|(_, found)| match found {
                intent::Found::Record(r) => r,
                intent::Found::Unreadable(e) => panic!("unreadable record {e}"),
            })
            .collect()
    }
    /// A snapshot only on `name`, as if taken there after the last sync.
    fn diverge(&mut self, name: &str, guid: u64) {
        let member = self
            .n()
            .members
            .iter_mut()
            .find(|m| m.endpoint.name == name)
            .unwrap();
        let last = member.snapshots.last().unwrap().clone();
        member.snapshots.push(SnapshotRef {
            name: format!("{name}@x{guid}"),
            dataset_guid: last.dataset_guid,
            identity: SnapshotIdentity {
                pool_guid: last.identity.pool_guid,
                guid: Guid::new(guid),
                createtxg: Txg::new(last.identity.createtxg.get() + 50),
                objsetid: ObjsetId::new(7000 + guid),
            },
        });
    }
    /// A child dataset made under `parent` by hand, as `zfs create` would:
    /// no snapshots yet, mounted when its parent is. A pair joins leaves, so
    /// no pair verb copies or compares it. Returns its name.
    fn add_child(&mut self, parent: &str) -> String {
        let name = format!("{parent}/new");
        let pool = if history::contains_dataset("a", parent) {
            1
        } else {
            2
        };
        let mounted = self.mounted(parent);
        let n = self.n();
        n.members.push(crate::pairs::plan::tests::member(
            &name,
            pool,
            10 * pool + 2,
            &[],
        ));
        n.members
            .sort_by(|a, b| a.endpoint.name.cmp(&b.endpoint.name));
        if mounted {
            n.mounted.insert(name.clone());
        }
        name
    }
    /// Fence `child` as the fenced copy's own members are: `canmount=noauto`
    /// and unmounted; it inherits `readonly` from its parent.
    fn fence_child(&mut self, child: &str) {
        self.n().properties.entry(child.into()).or_default().insert(
            "canmount".into(),
            NativeProperty {
                value: "noauto".into(),
                source: "local".into(),
            },
        );
        self.n().mounted.remove(child);
    }
    /// The datasets that exist under `root`, `root` included.
    fn names(&self, root: &str) -> Vec<String> {
        self.t
            .native
            .members
            .iter()
            .filter(|m| history::contains_dataset(root, &m.endpoint.name))
            .map(|m| m.endpoint.name.clone())
            .collect()
    }
}

impl HistoryBackend for World {
    fn written(&mut self, d: &zfs_tools::engine::Dataset, p: &SnapshotRef) -> Result<u64, Error> {
        self.t.written(d, p)
    }
    fn ivset(&mut self, p: &SnapshotRef) -> Result<Guid, Error> {
        self.t.ivset(p)
    }
}
impl PairBackend for World {
    fn observe(&mut self) -> Result<NativeState, Error> {
        let mut state = PairBackend::observe(&mut self.t)?;
        for pool in &self.readonly {
            if let Some(props) = state.pool_properties.get_mut(pool) {
                props.insert(
                    "readonly".into(),
                    NativeProperty {
                        value: "on".into(),
                        source: "-".into(),
                    },
                );
            }
        }
        for (pool, be) in &self.bootfs {
            // Native zpool list and zpool get report the same bootfs.
            if let Some(observed) = state.inspection.pools.iter_mut().find(|p| &p.name == pool) {
                observed.bootfs = Some(be.clone());
            }
            if let Some(props) = state.pool_properties.get_mut(pool) {
                props.insert(
                    "bootfs".into(),
                    NativeProperty {
                        value: be.clone(),
                        source: "local".into(),
                    },
                );
            }
        }
        Ok(state)
    }
    fn properties(&mut self, e: &Endpoint) -> Result<BTreeMap<String, NativeProperty>, Error> {
        self.t.properties(e)
    }
    fn sync(&mut self, e: &Endpoint) -> Result<(), Error> {
        PairBackend::sync(&mut self.t, e)?;
        if let Some(dataset) = self.unsynced.take() {
            self.n().written.insert(dataset, 4096);
        }
        Ok(())
    }
    fn set_property(&mut self, e: &Endpoint, v: &PropertyValue) -> Result<(), Error> {
        self.t.set_property(e, v)
    }
    fn inherit_property(
        &mut self,
        e: &Endpoint,
        key: PropertyKey,
        expected: &str,
    ) -> Result<Option<NativeProperty>, Error> {
        let after = self.t.inherit_property(e, key, expected)?;
        if key == PropertyKey::Placement && self.lose_placement_reply {
            self.lose_placement_reply = false;
            return Err(refuse("simulated lost placement retirement reply"));
        }
        Ok(after)
    }
    fn observe_point(&mut self, p: &SnapshotRef) -> Result<zfs_tools::engine::Snapshot, Error> {
        self.t.observe_point(p)
    }
    fn unmount(&mut self, e: &Endpoint) -> Result<(), Error> {
        self.t.unmount(e)
    }
    fn add_hold(&mut self, p: &SnapshotRef, tag: &str) -> Result<(), Error> {
        self.t.add_hold(p, tag)
    }
    fn running_root(&mut self) -> Result<Option<String>, Error> {
        self.t.running_root()
    }
}
// These regressions use the real tree planners against the pair model's
// resulting native state. A plan is forbidden to issue any tree effect.
impl crate::tree::Backend for World {
    fn observe(&mut self) -> Result<NativeState, Error> {
        PairBackend::observe(self)
    }
    fn running_root(&mut self) -> Result<Option<String>, Error> {
        PairBackend::running_root(self)
    }
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error> {
        CaptureBackend::capture_marker(self, point)
    }
    fn apply(&mut self, effect: &crate::tree::Effect) -> Result<(), Error> {
        panic!("tree planning issued an effect: {effect:?}")
    }
}
impl CaptureBackend for World {
    fn observe(&mut self) -> Result<NativeState, Error> {
        CaptureBackend::observe(&mut self.t)
    }
    fn snapshot(&mut self, names: &[String], id: &str) -> Result<(), Error> {
        self.t.snapshot(names, id)
    }
    fn capture_marker(&mut self, p: &SnapshotRef) -> Result<String, Error> {
        self.t.capture_marker(p)
    }
}
impl TransferBackend for World {
    fn attachments(&mut self) -> impl AttachmentBackend {
        self.t.attachments()
    }
    fn create_inert_container(&mut self, p: &Endpoint, n: &str, id: &str) -> Result<(), Error> {
        self.t.create_inert_container(p, n, id)
    }
    fn rename_received(&mut self, s: &Endpoint, p: &Endpoint, n: &str) -> Result<(), Error> {
        self.t.rename_received(s, p, n)
    }
    fn publish_mountpoint(
        &mut self,
        e: &Endpoint,
        p: &crate::placement::SavedProperty,
    ) -> Result<(), Error> {
        self.t.publish_mountpoint(e, p)
    }
    fn quiesce_receive_scope(&mut self, e: &Endpoint, id: &str) -> Result<(), Error> {
        self.t.quiesce_receive_scope(e, id)
    }
    fn volume_unavailable(&mut self, e: &Endpoint) -> Result<bool, Error> {
        self.t.volume_unavailable(e)
    }
    fn destroy_empty_container(&mut self, e: &Endpoint, id: &str) -> Result<(), Error> {
        self.t.destroy_empty_container(e, id)
    }
    fn copy_property(
        &mut self,
        target: &Endpoint,
        key: &str,
        value: Option<&str>,
        id: &str,
    ) -> Result<(), Error> {
        self.t.copy_property(target, key, value, id)
    }
    fn stream(&mut self, r: &LeafStream) -> Result<StreamOutcome, Error> {
        self.t.stream(r)
    }
    fn wrapping(&mut self, root: &Endpoint) -> Result<crate::transfer::Wrapping, Error> {
        self.t.wrapping(root)
    }
    fn key_opens(&mut self, root: &Endpoint, location: &str) -> Result<bool, Error> {
        self.t.key_opens(root, location)
    }
    fn set_keylocation(&mut self, e: &Endpoint, location: &str, id: &str) -> Result<(), Error> {
        self.t.set_keylocation(e, location, id)
    }
    fn release_hold(&mut self, p: &SnapshotRef, tag: &str) -> Result<(), Error> {
        self.t.release_hold(p, tag)
    }
    fn mount(&mut self, e: &Endpoint) -> Result<(), Error> {
        self.t.mount(e)
    }
    fn rename_snapshot(&mut self, p: &SnapshotRef, name: &str) -> Result<(), Error> {
        self.t.rename_snapshot(p, name)
    }
    fn destroy_snapshot(&mut self, p: &SnapshotRef) -> Result<(), Error> {
        self.t.destroy_snapshot(p)
    }
}
impl intent::Backend for World {
    fn pools(&mut self) -> Result<Vec<String>, Error> {
        self.t.native.alive()?;
        Ok(self
            .t
            .native
            .members
            .iter()
            .filter(|m| !m.endpoint.name.contains('/'))
            .map(|m| m.endpoint.name.clone())
            .collect())
    }
    fn read(&mut self, pool: &str) -> Result<Option<String>, Error> {
        self.t.native.alive()?;
        Ok(self
            .t
            .native
            .properties
            .get(pool)
            .and_then(|p| p.get(intent::PROPERTY))
            .filter(|p| p.source == "local")
            .map(|p| p.value.clone()))
    }
    fn write(&mut self, pool: &str, value: &str) -> Result<(), Error> {
        self.n().before()?;
        self.n().properties.entry(pool.into()).or_default().insert(
            intent::PROPERTY.into(),
            NativeProperty {
                value: value.into(),
                source: "local".into(),
            },
        );
        self.n().after()
    }
    fn remove(&mut self, pool: &str) -> Result<(), Error> {
        self.n().before()?;
        if let Some(p) = self.n().properties.get_mut(pool) {
            p.remove(intent::PROPERTY);
        }
        self.n().after()
    }
}
impl hold::Backend for World {
    fn resolve(&mut self, point: &SnapshotRef) -> Result<Option<hold::Seen>, Error> {
        self.t.native.alive()?;
        let n = &self.t.native;
        Ok(n.members
            .iter()
            .filter(|m| m.endpoint.identity.guid == point.dataset_guid)
            .flat_map(|m| &m.snapshots)
            .find(|s| s.identity == point.identity)
            .map(|s| hold::Seen {
                name: s.name.clone(),
                holds: n
                    .holds
                    .get(&s.name)
                    .map(|h| h.iter().cloned().collect())
                    .unwrap_or_default(),
            }))
    }
    fn hold(&mut self, name: &str, tag: &str) -> Result<(), Error> {
        self.n().before()?;
        self.n()
            .holds
            .entry(name.into())
            .or_default()
            .insert(tag.into());
        self.n().after()
    }
    fn release(&mut self, name: &str, tag: &str) -> Result<(), Error> {
        self.n().before()?;
        let n = self.n();
        let empty = n.holds.get_mut(name).is_some_and(|h| {
            h.remove(tag);
            h.is_empty()
        });
        if empty && n.deferred.contains(name) {
            for m in &mut n.members {
                m.snapshots.retain(|s| s.name != name);
            }
        }
        self.n().after()
    }
}
impl Backend for World {
    fn rollback(&mut self, point: &SnapshotRef) -> Result<(), Error> {
        let dataset = point.name.split_once('@').unwrap().0.to_string();
        let n = &self.t.native;
        let member = n
            .members
            .iter()
            .find(|m| m.endpoint.name == dataset)
            .unwrap();
        let at = member
            .snapshots
            .iter()
            .position(|s| s.identity == point.identity)
            .ok_or_else(|| refuse("rollback target absent"))?;
        if member.snapshots[at + 1..]
            .iter()
            .any(|s| n.holds.get(&s.name).is_some_and(|h| !h.is_empty()))
        {
            return Err(refuse("a later snapshot is held"));
        }
        self.n().before()?;
        let n = self.n();
        let member = n
            .members
            .iter_mut()
            .find(|m| m.endpoint.name == dataset)
            .unwrap();
        member.snapshots.truncate(at + 1);
        n.written.remove(&dataset);
        self.n().after()
    }
    fn recorded_hostid(&mut self, pool: &str, _: zfs_tools::engine::Guid) -> Result<u32, Error> {
        Ok(self.hostids.get(pool).copied().unwrap_or(7))
    }
    fn hand_off_default(&mut self, h: &DefaultHandoff) -> DefaultHandoffOutcome {
        if self.fail_default {
            return DefaultHandoffOutcome {
                selected: None,
                cleared: None,
                complete: false,
                detail: Some("default refused".into()),
            };
        }
        self.bootfs.insert(h.pool.clone(), h.dataset.clone());
        if let Some(stale) = &h.clears {
            self.bootfs.remove(&stale.pool);
        }
        DefaultHandoffOutcome {
            selected: None,
            cleared: None,
            complete: true,
            detail: None,
        }
    }
}

fn paired() -> World {
    let mut w = World::new(false);
    let request = PairRequest {
        left: "a/data".into(),
        right: "b/data".into(),
        primary: Some(Side::Left),
    };
    link::pair_with(&request, ID, &mut w).unwrap();
    w.t.native.effects = 0;
    w
}

/// Records that claim a pair are safe: a secondary is read-only and
/// unmounted throughout its tree, and two roots never both claim primary.
fn no_split_brain(w: &mut World) {
    let state = w.state();
    let mut primaries = 0;
    for root in ["a/data", "b/data"] {
        let Some(record) = w.record(root) else {
            continue;
        };
        match record.role {
            Role::Primary => primaries += 1,
            Role::Secondary => {
                for d in tree(&state, root) {
                    assert!(d.readonly, "{} is a writable secondary", d.name);
                    assert_ne!(d.mounted, Some(true), "{} is mounted", d.name);
                }
            }
        }
    }
    assert!(primaries < 2, "both roots claim primary");
}

/// No attachment chunk or journal property on any dataset: an operation
/// removes its attachments before its record, and nothing writes a journal.
fn no_chunks(w: &World) {
    for (name, props) in &w.t.native.properties {
        for key in props.keys() {
            assert!(
                !key.starts_with(attachment::PREFIX) && !key.starts_with("zboot:journal:"),
                "{name} keeps {key}"
            );
        }
    }
}

/// Cut every effect of `run` before and after it lands. After the restart,
/// `resume` continues any record; with none left, `done` decides whether the
/// verb is run again. `check` then judges the end state, which never keeps
/// an attachment or a journal.
fn every_cut(
    setup: impl Fn() -> World,
    run: impl Fn(&mut World) -> Result<(), Error>,
    done: impl Fn(&mut World) -> bool,
    check: impl Fn(&mut World),
) -> usize {
    let mut reference = setup();
    let base = reference.effects();
    run(&mut reference).unwrap();
    assert!(reference.records().is_empty());
    no_chunks(&reference);
    check(&mut reference);
    let total = reference.effects() - base;
    for n in 1..=total {
        for after in [false, true] {
            let mut w = setup();
            w.t.native.cut = Some((base + n, after));
            assert!(run(&mut w).is_err(), "cut {n}/{after} was not observed");
            w.restart();
            no_split_brain(&mut w);
            let records = w.records();
            assert!(records.len() <= 1);
            for record in records {
                let mut dialogue = Vec::new();
                if let Err(e) = resume_with(record.clone(), false, &mut dialogue, &mut w) {
                    // A catch-up finished without its receipt: the operator
                    // abandons and runs the verb again.
                    assert!(
                        e.to_string().contains("receipt was not recorded"),
                        "resume after cut {n}/{after}: {e}"
                    );
                    resume_with(record, true, &mut dialogue, &mut w)
                        .unwrap_or_else(|e| panic!("abandon after cut {n}/{after}: {e}"));
                    w.op = RERUN;
                }
            }
            if !done(&mut w) {
                run(&mut w).unwrap_or_else(|e| panic!("rerun after cut {n}/{after}: {e}"));
            }
            assert!(w.records().is_empty());
            no_chunks(&w);
            no_split_brain(&mut w);
            check(&mut w);
        }
    }
    total
}

// ---- pair ------------------------------------------------------------------

fn pair_request() -> PairRequest {
    PairRequest {
        left: "a/data".into(),
        right: "b/data".into(),
        primary: Some(Side::Left),
    }
}
fn is_paired(w: &mut World) -> bool {
    w.record("a/data").is_some() && w.record("b/data").is_some()
}
fn check_paired(w: &mut World) {
    check_pair(w);
    let mut held = w.holds(&format!("zboot:anchor:{ID}"));
    held.sort();
    assert_eq!(held, ["a/data@s1", "b/data@s1"]);
}
fn check_pair(w: &mut World) {
    let a = w.record("a/data").unwrap();
    assert_eq!(a.role, Role::Primary);
    assert_eq!(a.pair_id, ID);
    assert_eq!(w.record("b/data").unwrap(), a.counterpart());
    assert!(w.readonly("b/data"));
    assert!(!w.mounted("b/data"));
    assert!(!w.readonly("a/data"));
    assert_eq!(w.holds(&format!("zboot:anchor:{ID}")).len(), 2);
    let state = w.state();
    assert!(matches!(
        management::ownership(&state, "a/data").unwrap(),
        Ownership::Primary { .. }
    ));
}

#[test]
fn pair_survives_every_cut_and_publishes_only_after_fence_and_holds() {
    let total = every_cut(
        || World::new(false),
        |w| link::pair_with(&pair_request(), ID, w).map(drop),
        is_paired,
        check_paired,
    );
    assert!(total > 8);
}

/// "Unchanged since the anchor" is read from disk. A receiver write that
/// only a sync shows must stop the pair before its record, not after its
/// fence, where the executor plans again and would leave it half done.
#[test]
fn a_receiver_write_that_only_a_sync_shows_refuses_the_pair_before_its_record() {
    let mut w = World::new(false);
    let plan = crate::pairs::plan::plan_with(&w.state(), &pair_request(), &mut w).unwrap();
    w.unsynced = Some("b/data".into());
    assert!(pair_prepared_with(&plan, ID, &mut w).is_err());
    assert!(w.records().is_empty());
    assert!(!w.readonly("b/data"));
    assert!(w.record("a/data").is_none() && w.record("b/data").is_none());
    assert!(w.holds(&format!("zboot:anchor:{ID}")).is_empty());
}

#[test]
fn pools_of_two_hosts_are_never_paired() {
    let request = pair_request();
    let mut w = World::new(false);
    let left = request.left.split('/').next().unwrap().to_string();
    w.hostids.insert(left, 8);
    let error = link::pair_with(&request, ID, &mut w).unwrap_err();
    assert!(
        error.to_string().contains("record different hosts"),
        "{error}"
    );
    assert_eq!(w.effects(), 0);
    assert!(w.records().is_empty());
}

#[test]
fn pair_again_reports_the_existing_pair_without_effects() {
    let mut w = paired();
    let result = link::pair_with(&pair_request(), OP, &mut w).unwrap();
    assert!(result.outcome.already_paired);
    assert_eq!(result.outcome.operation_id, ID);
    assert_eq!(w.effects(), 0);
}

#[test]
fn pair_refuses_a_running_receiver_before_any_effect() {
    let mut w = World::new(false);
    w.t.native.running = Some("b/data".into());
    let error = link::pair_with(&pair_request(), ID, &mut w).unwrap_err();
    assert!(error.to_string().contains("running root"), "{error}");
    assert_eq!(w.effects(), 0);
    assert!(w.records().is_empty());
}

#[test]
fn abandoned_pair_leaves_fences_and_holds_but_no_half_record() {
    let mut reference = World::new(false);
    link::pair_with(&pair_request(), ID, &mut reference).unwrap();
    let total = reference.effects();
    for n in 1..=total {
        for after in [false, true] {
            let mut w = World::new(false);
            w.t.native.cut = Some((n, after));
            assert!(link::pair_with(&pair_request(), ID, &mut w).is_err());
            w.restart();
            for record in w.records() {
                let step = record.step;
                let mut dialogue = Vec::new();
                resume_with(record, true, &mut dialogue, &mut w).unwrap();
                assert!(
                    String::from_utf8(dialogue)
                        .unwrap()
                        .contains("abandoned pair")
                );
                if step < 3 {
                    assert!(w.record("a/data").is_none() && w.record("b/data").is_none());
                }
            }
            assert!(w.records().is_empty());
            no_split_brain(&mut w);
            // Pairing again from scratch is always possible.
            let a = w.record("a/data");
            if a.is_none() {
                let mut fresh = w.clone();
                link::pair_with(&pair_request(), OP, &mut fresh)
                    .unwrap_or_else(|e| panic!("pair after abandon {n}/{after}: {e}"));
            }
        }
    }
}

#[test]
fn an_unpublished_pair_abandons_after_its_secondary_pool_leaves() {
    let worlds = cut_worlds(
        || World::new(false),
        |w| link::pair_with(&pair_request(), ID, w).map(drop),
        |s| s < 3,
    );
    assert!(!worlds.is_empty());
    for (mut w, record) in worlds {
        w.export("b");
        let mut dialogue = Vec::new();
        assert!(resume_with(record.clone(), false, &mut dialogue, &mut w).is_err());
        resume_with(record, true, &mut dialogue, &mut w).unwrap();
        assert!(w.records().is_empty());
        assert!(w.record("a/data").is_none());
    }
}

// ---- unpair ----------------------------------------------------------------

fn unpair_now(w: &mut World, release: bool) -> Result<UnpairResult, Error> {
    let state = w.state();
    let plan = unpair_plan_with(&state, "a/data", release)?;
    unpair_with(&plan, OP, w)
}

#[test]
fn unpair_removes_both_records_and_keeps_every_anchor_hold() {
    let total = every_cut(
        paired,
        |w| unpair_now(w, false).map(drop),
        |w| w.record("a/data").is_none() && w.record("b/data").is_none(),
        |w| {
            assert!(w.record("a/data").is_none() && w.record("b/data").is_none());
            assert_eq!(w.holds(&format!("zboot:anchor:{ID}")).len(), 2);
            assert!(w.readonly("b/data"));
        },
    );
    assert!(total >= 4);
    let mut w = paired();
    let plan = unpair_plan_with(&w.state(), "a/data", false).unwrap();
    assert!(!plan.confirms());
    let result = unpair_with(&plan, OP, &mut w).unwrap();
    assert_eq!(
        result.retained_anchor_tag.as_deref(),
        Some(format!("zboot:anchor:{ID}").as_str())
    );
}

#[test]
fn release_anchors_after_a_plain_unpair_releases_both_sides() {
    let setup = || {
        let mut w = paired();
        unpair_now(&mut w, false).unwrap();
        w.t.native.effects = 0;
        w
    };
    let mut w = setup();
    let plan = unpair_plan_with(&w.state(), "a/data", true).unwrap();
    assert!(plan.confirms());
    assert!(plan.record.is_none());
    assert_eq!(plan.release.as_ref().unwrap().len(), 2);
    assert!(
        crate::consent::token(&plan).unwrap() == crate::consent::token(&plan).unwrap(),
        "plan tokens are stable"
    );
    every_cut(
        setup,
        |w| unpair_now(w, true).map(drop),
        |w| w.holds(&format!("zboot:anchor:{ID}")).is_empty(),
        |w| assert!(w.holds(&format!("zboot:anchor:{ID}")).is_empty()),
    );
    // Nothing left to release refuses.
    let mut done = setup();
    unpair_now(&mut done, true).unwrap();
    assert!(unpair_now(&mut done, true).is_err());
}

#[test]
fn unpair_with_release_does_both_in_one_operation() {
    every_cut(
        paired,
        |w| unpair_now(w, true).map(drop),
        |w| w.record("a/data").is_none() && w.holds(&format!("zboot:anchor:{ID}")).is_empty(),
        |w| {
            assert!(w.record("a/data").is_none() && w.record("b/data").is_none());
            assert!(w.holds(&format!("zboot:anchor:{ID}")).is_empty());
        },
    );
}

#[test]
fn unpair_of_a_dead_peer_is_one_sided_typed_and_keeps_holds() {
    let mut w = paired();
    w.export("b");
    let plan = unpair_plan_with(&w.state(), "a/data", false).unwrap();
    assert!(plan.one_sided && plan.confirms());
    assert_eq!(plan.peer, Some(PeerStatus::PoolNotImported));
    assert!(
        plan.statement
            .as_ref()
            .unwrap()
            .contains("b/data is gone or offline")
    );
    let result = unpair_with(&plan, OP, &mut w).unwrap();
    // A single effect needs no record.
    assert!(result.operation_id.is_none());
    assert!(w.record("a/data").is_none());
    assert_eq!(w.holds(&format!("zboot:anchor:{ID}")), ["a/data@s1"]);
}

#[test]
fn a_half_pair_unpairs_one_sided() {
    let mut w = paired();
    w.n()
        .properties
        .get_mut("b/data")
        .unwrap()
        .remove(management::PAIR_PROPERTY);
    let plan = unpair_plan_with(&w.state(), "a/data", false).unwrap();
    assert_eq!(plan.peer, Some(PeerStatus::NotReciprocating));
    assert!(plan.one_sided && plan.confirms());
    unpair_with(&plan, OP, &mut w).unwrap();
    assert!(w.record("a/data").is_none());
}

#[test]
fn unpair_refuses_a_child_of_a_pair_leaf_and_an_unpaired_dataset_before_any_effect() {
    // A child made under a paired leaf is not part of the pair, but it
    // inherits the leaf's record: unpair names the leaf instead.
    let mut w = paired();
    let child = w.add_child("a/data");
    let state = w.state();
    assert!(
        unpair_plan_with(&state, &child, false)
            .unwrap_err()
            .to_string()
            .contains("name the pair root")
    );
    let mut lone = World::new(false);
    let state = lone.state();
    assert!(unpair_plan_with(&state, "a/data", false).is_err());
    assert!(unpair_plan_with(&state, "a/data", true).is_err());
    assert_eq!(w.effects() + lone.effects(), 0);
}

#[test]
fn a_changed_unpair_plan_is_refused_before_any_effect() {
    let mut w = paired();
    let plan = unpair_plan_with(&w.state(), "a/data", true).unwrap();
    w.n()
        .holds
        .entry("a/data@s0".into())
        .or_default()
        .insert(format!("zboot:anchor:{ID}"));
    assert!(unpair_with(&plan, OP, &mut w).is_err());
    assert_eq!(w.effects(), 0);
}

#[test]
fn a_pair_preview_is_stable_and_rechecks_both_trees_before_intent() {
    let request = PairRequest {
        left: "a/data".into(),
        right: "b/data".into(),
        primary: Some(Side::Left),
    };
    for attack in 0..4 {
        let mut w = World::new(false);
        let plan = crate::pairs::plan::plan_with(&w.state(), &request, &mut w).unwrap();
        assert_eq!(
            plan,
            crate::pairs::plan::plan_with(&w.state(), &request, &mut w).unwrap()
        );
        assert_eq!(w.effects(), 0);
        assert!(w.records().is_empty());
        let member = w
            .n()
            .members
            .iter_mut()
            .find(|member| {
                member.endpoint.name == if attack % 2 == 0 { "a/data" } else { "b/data" }
            })
            .unwrap();
        if attack < 2 {
            member.endpoint.identity.guid = Guid::new(999);
        } else {
            member.mountpoint = Some("/changed-after-preview".into());
        }
        assert!(
            pair_prepared_with(&plan, OP, &mut w).is_err(),
            "attack {attack}"
        );
        assert_eq!(w.effects(), 0, "attack {attack}");
        assert!(w.records().is_empty(), "attack {attack}");
        assert!(w.holds(&format!("zboot:anchor:{OP}")).is_empty());
    }
    let mut w = World::new(false);
    let plan = crate::pairs::plan::plan_with(&w.state(), &request, &mut w).unwrap();
    pair_prepared_with(&plan, ID, &mut w).unwrap();
    check_pair(&mut w);
}

// ---- sync ------------------------------------------------------------------

fn sync_request() -> TransferRequest {
    TransferRequest {
        source: "a/data".into(),
        destination: "b/data".into(),
    }
}
fn changed() -> World {
    let mut w = paired();
    w.n().written.insert("a/data".into(), 4096);
    w
}
fn synced(w: &mut World) -> bool {
    let a = w.guids("a/data");
    a.len() > 2 && w.guids("b/data").ends_with(&a[a.len() - 1..])
}
/// No attachment chunk or journal property is left on any dataset, nor a
/// marker of the operation or of a bootstrap's nested pair.
fn no_transfer_records(w: &World, id: &str) {
    no_chunks(w);
    let ids = [id.to_owned(), crate::transfer::bootstrap_pair_id(id)];
    for (name, props) in &w.t.native.properties {
        for (key, p) in props {
            let marker = matches!(
                key.as_str(),
                management::PENDING_PROPERTY | management::STAGING_PROPERTY
            ) && ids.contains(&p.value);
            assert!(!marker, "{name} keeps {key}");
        }
    }
}

#[test]
fn sync_survives_every_cut_and_never_unfences_the_receiver() {
    every_cut(
        changed,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        synced,
        |w| {
            assert!(synced(w));
            check_pair(w);
            no_transfer_records(w, OP);
        },
    );
}

#[test]
fn sync_of_a_pair_root_follows_the_working_copy() {
    let mut w = changed();
    let state = w.state();
    assert_eq!(sync::direction(&state, "b/data").unwrap(), sync_request());
    assert_eq!(sync::direction(&state, "a/data").unwrap(), sync_request());
    assert_eq!(sync::all_pairs(&state), vec![sync_request()]);
    let entries = sync_with(&SyncTarget::Pair("b/data".into()), &mut w).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].result.as_ref().unwrap().bootstrapped.is_none());
    assert!(synced(&mut w));
}

#[test]
fn sync_refuses_divergent_receiver_history_before_any_effect() {
    let mut w = changed();
    w.diverge("b/data", 901);
    let error = sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap_err();
    let text = error.to_string();
    assert!(text.contains("never overwrites"), "{error}");
    // Both ways out are named; `rollback` refuses a pair member, so it is not one.
    assert!(
        text.contains("`zboot primary b/data` keeps b/data's side")
            && text.contains("to keep a/data's")
            && !text.contains("zboot rollback"),
        "{error}"
    );
    assert_eq!(w.effects(), 0);
    assert!(w.records().is_empty());
    // --all reports the pair as failed instead of refusing.
    let entries = sync_with(&SyncTarget::All, &mut w).unwrap();
    assert!(entries[0].error.is_some() && entries[0].result.is_none());
    assert_eq!(w.effects(), 0);
}

#[test]
fn a_sync_preview_freezes_endpoint_identity_properties_and_bootstrap_parent() {
    for bootstrap in [false, true] {
        for attack in 0..3 {
            let mut w = if bootstrap {
                World::new(true)
            } else {
                changed()
            };
            let target = SyncTarget::Between {
                source: "a/data".into(),
                destination: "b/data".into(),
            };
            let plan = sync_plan_with(&target, &mut w).unwrap();
            assert_eq!(plan, sync_plan_with(&target, &mut w).unwrap());
            assert_eq!(w.effects(), 0);
            assert!(w.records().is_empty());
            match attack {
                0 | 1 => {
                    let name = if attack == 0 {
                        "a/data"
                    } else if bootstrap {
                        "b"
                    } else {
                        "b/data"
                    };
                    w.n()
                        .members
                        .iter_mut()
                        .find(|member| member.endpoint.name == name)
                        .unwrap()
                        .endpoint
                        .identity
                        .guid = Guid::new(999);
                }
                2 => {
                    w.n().properties.entry("a/data".into()).or_default().insert(
                        "compression".into(),
                        NativeProperty {
                            value: "lz4".into(),
                            source: "local".into(),
                        },
                    );
                }
                _ => unreachable!(),
            }
            assert!(
                sync_prepared_with(&plan, false, &mut w).is_err(),
                "bootstrap {bootstrap} attack {attack}"
            );
            assert_eq!(w.effects(), 0, "bootstrap {bootstrap} attack {attack}");
            assert!(w.records().is_empty());
        }
    }
}

#[test]
fn a_sync_all_preview_retains_failed_members_without_starting_an_operation() {
    let mut w = changed();
    w.diverge("b/data", 901);
    let plan = sync_plan_with(&SyncTarget::All, &mut w).unwrap();
    assert_eq!(plan, sync_plan_with(&SyncTarget::All, &mut w).unwrap());
    assert_eq!(plan.entries.len(), 1);
    assert!(plan.entries[0].admitted.is_none());
    assert!(plan.entries[0].error.is_some());
    assert_eq!(w.effects(), 0);
    let entries = sync_prepared_with(&plan, false, &mut w).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].source, "a/data");
    assert_eq!(entries[0].destination, "b/data");
    assert!(entries[0].error.is_some());
    assert!(entries[0].result.is_none());
    assert_eq!(w.effects(), 0);
    assert!(w.records().is_empty());
}

#[test]
fn sync_to_an_absent_destination_bootstraps_and_pairs_it() {
    let setup = || World::new(true);
    every_cut(
        setup,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        is_paired,
        |w| {
            let a = w.record("a/data").unwrap();
            assert_eq!(a.role, Role::Primary);
            assert_eq!(w.record("b/data").unwrap(), a.counterpart());
            assert!(w.readonly("b/data"));
            no_transfer_records(w, OP);
        },
    );
    let mut w = setup();
    let result = sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap();
    assert_eq!(result.bootstrapped, result.transfer.pair_id);
    assert!(result.bootstrapped.is_some());
}

/// Staged, a new copy has `volmode=none` like every member of its inert
/// container. Published, only a volume keeps it: a filesystem copy takes its
/// parent's value again, whatever cut the bootstrap survived.
#[test]
fn a_bootstrapped_filesystem_copy_has_no_local_volmode_through_every_cut() {
    for volume in [false, true] {
        let setup = move || {
            let mut w = World::new(true);
            if volume {
                w.t = Transfer::volumes(true);
                w.t.primary_mode = true;
            }
            w
        };
        every_cut(
            setup,
            |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
            is_paired,
            |w| {
                assert!(is_paired(w));
                no_transfer_records(w, OP);
                let volmode = w.t.native.effective("b/data")["volmode"].clone();
                if volume {
                    assert_eq!(
                        (volmode.value.as_str(), volmode.source.as_str()),
                        ("none", "local")
                    );
                } else {
                    assert_ne!(volmode.source, "local", "{volmode:?}");
                }
            },
        );
    }
}

#[test]
fn a_sync_preview_into_an_absent_destination_says_it_creates_and_pairs_it() {
    let target = SyncTarget::Between {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    let mut w = World::new(true);
    let plan = sync_plan_with(&target, &mut w).unwrap();
    assert_eq!(
        describe::sync_plan(&plan, "T"),
        "Sync a/data -> b/data: creates b/data and pairs the two, with a/data as the working \
         copy\nToken T\n"
    );
    let mut w = changed();
    let plan = sync_plan_with(&target, &mut w).unwrap();
    assert!(describe::sync_plan(&plan, "T").starts_with("Sync a/data -> b/data\n"));
}

// ---- children under a pair's leaves ---------------------------------------

#[test]
fn pair_refuses_a_child_on_either_side_before_any_effect() {
    for parent in ["a/data", "b/data"] {
        let mut w = World::new(false);
        w.add_child(parent);
        let before = format!("{:?}", w.state());
        let error = crate::pairs::plan::plan_with(&w.state(), &pair_request(), &mut w)
            .unwrap_err()
            .to_string();
        assert!(error.contains("a pair joins leaf datasets"), "{error}");
        let error = link::pair_with(&pair_request(), ID, &mut w)
            .unwrap_err()
            .to_string();
        assert!(error.contains("a pair joins leaf datasets"), "{error}");
        assert_eq!(w.effects(), 0);
        assert!(w.records().is_empty());
        assert!(w.holds(&format!("zboot:anchor:{ID}")).is_empty());
        assert_eq!(format!("{:?}", w.state()), before);
    }
}

#[test]
fn a_bootstrap_sync_refuses_a_child_of_its_source_before_any_effect() {
    let mut w = World::new(true);
    w.add_child("a/data");
    let before = format!("{:?}", w.state());
    let target = SyncTarget::Between {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    let error = sync_plan_with(&target, &mut w).unwrap_err().to_string();
    assert!(error.contains("a pair joins leaf datasets"), "{error}");
    let error = sync::sync_one(&sync_request(), OP, &[], &mut w)
        .unwrap_err()
        .to_string();
    assert!(error.contains("a pair joins leaf datasets"), "{error}");
    assert_eq!((w.effects(), w.t.streams), (0, 0));
    assert!(w.records().is_empty());
    assert_eq!(format!("{:?}", w.state()), before);
}

#[test]
fn a_sync_into_an_existing_unpaired_dataset_is_refused_before_any_effect() {
    let mut w = World::new(false);
    let before = format!("{:?}", w.state());
    let error = sync::sync_one(&sync_request(), OP, &[], &mut w)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("b/data already exists and is not paired with a/data; pair them first"),
        "{error}"
    );
    assert_eq!((w.effects(), w.t.streams), (0, 0));
    assert!(w.records().is_empty());
    assert_eq!(format!("{:?}", w.state()), before);
}

/// A child made under the working copy does not stop its leaf's backup: the
/// leaf completes, the child is reported and never copied, fenced or swept.
#[test]
fn a_paired_sync_completes_the_leaf_and_reports_a_new_child_through_every_cut() {
    let setup = || {
        let mut w = changed();
        w.add_child("a/data");
        w
    };
    let role = |w: &mut World| {
        let state = w.state();
        let child = dataset(&state, "a/data/new").unwrap();
        (child.canmount, child.readonly, child.mounted)
    };
    let mut w = setup();
    let unchanged = role(&mut w);
    assert_eq!(unchanged.2, Some(true));
    let result = sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap();
    assert_eq!(result.transfer.unmirrored, ["a/data/new"]);
    assert!(synced(&mut w));
    assert_eq!(w.names("b/data"), ["b/data"]);
    assert_eq!(role(&mut w), unchanged);
    // `sync --all` reports it too; the CLI counts the pair unfinished.
    let mut w = setup();
    let entries = sync_with(&SyncTarget::All, &mut w).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].result.as_ref().unwrap().transfer.unmirrored,
        ["a/data/new"]
    );
    every_cut(
        setup,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        synced,
        |w| {
            assert!(synced(w));
            check_pair(w);
            assert_eq!(w.names("b/data"), ["b/data"]);
            assert_eq!(role(w), unchanged);
            no_transfer_records(w, OP);
        },
    );
    // Through every cut the child only inherits the source's attachment
    // chunks, never holding one of its own, and the copy never gets any.
    for (w, _) in cut_worlds(
        setup,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        |_| true,
    ) {
        for (name, props) in &w.t.native.properties {
            assert!(
                name == "a/data" || !props.keys().any(|k| k.starts_with(attachment::PREFIX)),
                "{name} holds an attachment chunk"
            );
        }
        let child = w.t.native.effective("a/data/new");
        let copy = w.t.native.effective("b/data");
        for (key, property) in child
            .iter()
            .filter(|(k, _)| k.starts_with(attachment::PREFIX))
        {
            assert_eq!(property.source, "inherited from a/data", "{key}");
        }
        assert!(!copy.keys().any(|k| k.starts_with(attachment::PREFIX)));
    }
    // A child of the fenced copy, fenced and snapshotted like it, is reported
    // the same way and left as it is.
    let mut w = changed();
    let child = w.add_child("b/data");
    let snapshotted = crate::pairs::plan::tests::member(&child, 2, 22, &[500]);
    *w.n()
        .members
        .iter_mut()
        .find(|m| m.endpoint.name == child)
        .unwrap() = snapshotted.clone();
    w.fence_child(&child);
    let result = sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap();
    assert_eq!(result.transfer.unmirrored, [child]);
    assert!(synced(&mut w));
    check_pair(&mut w);
    assert!(w.n().members.contains(&snapshotted));
}

#[test]
fn a_child_under_the_fenced_copy_never_blocks_the_leafs_sync() {
    // Unfenced and unsnapshotted, as `zfs create` leaves it: outside the
    // pair, reported, and the leaf still syncs.
    let mut w = changed();
    let child = w.add_child("b/data");
    let result = sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap();
    assert_eq!(result.transfer.unmirrored, [child]);
    assert!(synced(&mut w));
}

// ---- around the transfer: pending deletions, renames, boundary snapshots ---

/// Put a snapshot NAME with GUID on DATASET at creation txg TXG, in creation
/// order. Below the fixture's s0 (txg 10) it is older than every common one.
fn put(w: &mut World, dataset: &str, name: &str, guid: u64, txg: u64) -> SnapshotRef {
    let member = w
        .n()
        .members
        .iter_mut()
        .find(|m| m.endpoint.name == dataset)
        .unwrap();
    let first = member.snapshots[0].clone();
    let point = SnapshotRef {
        name: format!("{dataset}@{name}"),
        dataset_guid: first.dataset_guid,
        identity: SnapshotIdentity {
            pool_guid: first.identity.pool_guid,
            guid: Guid::new(guid),
            createtxg: Txg::new(txg),
            objsetid: ObjsetId::new(8000 + guid),
        },
    };
    member.snapshots.push(point.clone());
    member.snapshots.sort_by_key(|p| p.identity.createtxg);
    point
}
/// Rename DATASET@FROM to TO, as `zfs rename` does: holds go with it.
fn rename(w: &mut World, dataset: &str, from: &str, to: &str) {
    let point = w
        .n()
        .members
        .iter()
        .flat_map(|m| &m.snapshots)
        .find(|s| s.name == format!("{dataset}@{from}"))
        .unwrap()
        .clone();
    w.t.rename_snapshot(&point, to).unwrap();
    w.t.renamed.clear();
    w.t.native.effects = 0;
}
/// DATASET's snapshot names, oldest first.
fn snapshot_names(w: &World, dataset: &str) -> Vec<String> {
    w.t.native
        .members
        .iter()
        .find(|m| m.endpoint.name == dataset)
        .map(|m| {
            m.snapshots
                .iter()
                .map(|s| s.name.split_once('@').unwrap().1.to_owned())
                .collect()
        })
        .unwrap_or_default()
}
/// A pair whose working copy pruned two old snapshots the copy still keeps,
/// with a change to send.
fn pruned() -> World {
    let mut w = changed();
    put(&mut w, "b/data", "old1", 90, 5);
    put(&mut w, "b/data", "old2", 91, 6);
    w
}
/// The copy keeps an old `x` the working copy deleted, and the working copy
/// has since made a newer snapshot named `x` again.
fn colliding() -> World {
    let mut w = changed();
    put(&mut w, "b/data", "x", 90, 5);
    put(&mut w, "a/data", "x", 900, 50);
    w
}
/// A second pair beside the fixture's: a/more (working copy) and b/more.
fn with_second_pair(mut w: World) -> World {
    let n = w.n();
    n.members.push(crate::pairs::plan::tests::member(
        "a/more",
        1,
        13,
        &[200, 201],
    ));
    n.members.push(crate::pairs::plan::tests::member(
        "b/more",
        2,
        23,
        &[200, 201],
    ));
    n.members
        .sort_by(|a, b| a.endpoint.name.cmp(&b.endpoint.name));
    n.mounted.insert("a/more".into());
    let request = PairRequest {
        left: "a/more".into(),
        right: "b/more".into(),
        primary: Some(Side::Left),
    };
    link::pair_with(&request, SECOND, &mut w).unwrap();
    w.n().written.insert("a/more".into(), 4096);
    w.t.native.effects = 0;
    w
}
fn pair_target() -> SyncTarget {
    SyncTarget::Pair("a/data".into())
}
fn pending_names(pending: Option<&prune::Pending>) -> Vec<String> {
    pending
        .into_iter()
        .flat_map(|p| &p.snapshots)
        .map(|s| s.snapshot.name.clone())
        .collect()
}
/// The pending deletions the operator reviews in a plan of SETUP.
fn reviewed_points(setup: impl Fn() -> World) -> Vec<SnapshotRef> {
    let mut w = setup();
    sync_plan_with(&pair_target(), &mut w).unwrap().entries[0]
        .pending
        .as_ref()
        .unwrap()
        .points()
}

#[test]
fn a_sync_plan_lists_pending_deletions_and_its_token_binds_them_exactly() {
    let mut w = pruned();
    let plan = sync_plan_with(&pair_target(), &mut w).unwrap();
    let pending = plan.entries[0].pending.clone().unwrap();
    assert_eq!(pending.copy, endpoint(&w.state(), "b/data").unwrap());
    assert_eq!(
        pending_names(Some(&pending)),
        ["b/data@old1", "b/data@old2"]
    );
    assert_eq!(pending.snapshots[0].snapshot.identity.guid, Guid::new(90));
    assert_eq!(
        pending.snapshots[0].snapshot.identity.createtxg,
        Txg::new(5)
    );
    assert!(pending.snapshots.iter().all(|s| !s.collides));
    assert_eq!(plan.summary().as_deref(), Some("2 snapshots on b/data"));
    let token = plan.token().unwrap();
    assert_eq!(
        sync_plan_with(&pair_target(), &mut w)
            .unwrap()
            .token()
            .unwrap(),
        token
    );
    // The space shown is not part of the consent.
    let mut space = plan.clone();
    space.entries[0].pending.as_mut().unwrap().snapshots[0].used_bytes = 1 << 20;
    assert_eq!(space.token().unwrap(), token);
    assert_eq!(w.effects(), 0);
    // Any change to the set refuses the token and the plan before any effect.
    for change in 0..5 {
        let mut w = pruned();
        let b = w
            .n()
            .members
            .iter_mut()
            .find(|m| m.endpoint.name == "b/data")
            .unwrap();
        let old2 = b
            .snapshots
            .iter()
            .position(|s| s.name == "b/data@old2")
            .unwrap();
        match change {
            0 => {
                put(&mut w, "b/data", "old3", 92, 7);
            }
            1 => {
                b.snapshots.remove(old2);
            }
            2 => b.snapshots[old2].identity.guid = Guid::new(93),
            3 => b.snapshots[old2].identity.createtxg = Txg::new(4),
            _ => b.snapshots[old2].name = "b/data@other".into(),
        }
        let fresh = sync_plan_with(&pair_target(), &mut w).unwrap();
        assert_ne!(fresh.token().unwrap(), token, "change {change}");
        let error = sync_prepared_with(&plan, true, &mut w).unwrap_err();
        assert!(
            error.to_string().contains("plan changed"),
            "change {change}: {error}"
        );
        assert_eq!((w.effects(), w.t.streams), (0, 0), "change {change}");
        assert!(w.records().is_empty() && w.t.destroyed.is_empty());
    }
    let mut w = changed();
    let plan = sync_plan_with(&pair_target(), &mut w).unwrap();
    assert!(plan.summary().is_none() && plan.entries[0].pending.is_none());
}

#[test]
fn an_unattended_sync_transfers_and_deletes_nothing() {
    let mut w = pruned();
    let plan = sync_plan_with(&SyncTarget::All, &mut w).unwrap();
    let entries = sync_prepared_with(&plan, false, &mut w).unwrap();
    let result = entries[0].result.as_ref().unwrap();
    assert!(synced(&mut w));
    check_pair(&mut w);
    assert!(w.t.destroyed.is_empty());
    assert!(result.deleted.is_empty() && result.kept.is_empty());
    assert_eq!(
        pending_names(result.pending.as_ref()),
        ["b/data@old1", "b/data@old2"]
    );
    assert_eq!(&w.guids("b/data")[..2], [90, 91]);
    let text = describe::synced(&entries);
    assert!(
        text.contains("2 snapshots only on b/data await review for deletion")
            && text.contains("Review with `zboot sync b/data` on a terminal"),
        "{text}"
    );
}

#[test]
fn a_confirmed_sync_deletes_exactly_the_reviewed_snapshots_first() {
    let mut w = pruned();
    let plan = sync_plan_with(&pair_target(), &mut w).unwrap();
    let entries = sync_prepared_with(&plan, true, &mut w).unwrap();
    let result = entries[0].result.as_ref().unwrap();
    assert_eq!(w.t.destroyed, ["b/data@old1", "b/data@old2"]);
    let deleted: Vec<_> = result.deleted.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(deleted, ["b/data@old1", "b/data@old2"]);
    assert!(result.pending.is_none() && result.kept.is_empty());
    assert!(synced(&mut w));
    check_pair(&mut w);
    assert!(!w.guids("b/data").iter().any(|g| [90, 91].contains(g)));
    // Only what was reviewed goes.
    let mut w = pruned();
    let first = reviewed_points(pruned)[..1].to_vec();
    let result = sync::sync_one(&sync_request(), OP, &first, &mut w).unwrap();
    assert_eq!(w.t.destroyed, ["b/data@old1"]);
    assert_eq!(pending_names(result.pending.as_ref()), ["b/data@old2"]);
    // A reviewed snapshot that is no longer exactly that one stays.
    let mut w = pruned();
    let mut stale = reviewed_points(pruned);
    stale[0].identity.guid = Guid::new(77);
    sync::sync_one(&sync_request(), OP, &stale, &mut w).unwrap();
    assert_eq!(w.t.destroyed, ["b/data@old2"]);
    assert!(w.guids("b/data").contains(&90));
}

#[test]
fn a_confirmed_sync_survives_every_cut_and_a_cut_shows_the_rest_again() {
    let reviewed = reviewed_points(pruned);
    every_cut(
        pruned,
        |w| sync::sync_one(&sync_request(), OP, &reviewed, w).map(drop),
        synced,
        |w| {
            assert!(synced(w));
            check_pair(w);
            assert!(!w.guids("b/data").iter().any(|g| [90, 91].contains(g)));
        },
    );
    // Native state is the record: a cut after the first deletion leaves no
    // operation, and the next plan shows only what remains.
    let mut w = pruned();
    let base = w.effects();
    w.t.native.cut = Some((base + 1, true));
    assert!(sync::sync_one(&sync_request(), OP, &reviewed, &mut w).is_err());
    w.restart();
    assert!(w.records().is_empty());
    assert_eq!(w.t.destroyed, ["b/data@old1"]);
    let plan = sync_plan_with(&pair_target(), &mut w).unwrap();
    assert_eq!(
        pending_names(plan.entries[0].pending.as_ref()),
        ["b/data@old2"]
    );
}

#[test]
fn held_reviewed_deletions_and_an_unheld_anchor_keep_snapshots_and_the_sync_goes_on() {
    let reviewed = reviewed_points(pruned);
    let mut w = pruned();
    w.n()
        .holds
        .entry("b/data@old1".into())
        .or_default()
        .insert("zboot:reader:job".into());
    let result = sync::sync_one(&sync_request(), OP, &reviewed, &mut w).unwrap();
    assert_eq!(w.t.destroyed, ["b/data@old2"]);
    assert_eq!(result.kept.len(), 1);
    assert_eq!(result.kept[0].snapshot, "b/data@old1");
    assert!(
        result.kept[0].reason.contains("held (zboot:reader:job)"),
        "{:?}",
        result.kept
    );
    assert_eq!(pending_names(result.pending.as_ref()), ["b/data@old1"]);
    assert!(synced(&mut w));
    // Without the anchor's hold on both sides nothing is deleted.
    let mut w = pruned();
    w.n().holds.get_mut("b/data@s1").unwrap().clear();
    let result = sync::sync_one(&sync_request(), OP, &reviewed, &mut w).unwrap();
    assert!(w.t.destroyed.is_empty());
    assert_eq!(result.kept.len(), 2);
    assert!(
        result
            .kept
            .iter()
            .all(|k| k.reason.contains(&format!("zboot:anchor:{ID}"))),
        "{:?}",
        result.kept
    );
    assert!(synced(&mut w));
}

#[test]
fn a_name_collision_stops_its_pair_before_any_effect_unless_reviewed() {
    let mut w = colliding();
    let plan = sync_plan_with(&pair_target(), &mut w).unwrap();
    assert!(plan.entries[0].pending.as_ref().unwrap().snapshots[0].collides);
    let before = format!("{:?}", w.state());
    let unattended = sync_prepared_with(&plan, false, &mut w).map(drop);
    let direct = sync::sync_one(&sync_request(), OP, &[], &mut w).map(drop);
    for error in [unattended, direct] {
        let error = error.unwrap_err().to_string();
        assert!(error.contains("b/data@x (not reviewed)"), "{error}");
        assert!(
            error.contains("review it with `zboot sync b/data` on a terminal"),
            "{error}"
        );
    }
    assert_eq!((w.effects(), w.t.streams), (0, 0));
    assert!(w.records().is_empty());
    assert_eq!(format!("{:?}", w.state()), before);
    // Reviewed but held, it still stops the pair before any effect.
    let mut held = colliding();
    held.n()
        .holds
        .entry("b/data@x".into())
        .or_default()
        .insert("keep".into());
    let error = sync::sync_one(&sync_request(), OP, &reviewed_points(colliding), &mut held)
        .unwrap_err()
        .to_string();
    assert!(error.contains("reviewed, but it is held (keep)"), "{error}");
    assert_eq!((held.effects(), held.t.streams), (0, 0));
    // Reviewed, it is deleted before the stream, which would otherwise fail
    // on the existing name, and the pair syncs.
    let entries = sync_prepared_with(&plan, true, &mut w).unwrap();
    assert!(entries[0].error.is_none());
    assert_eq!(w.t.destroyed, ["b/data@x"]);
    assert!(synced(&mut w));
    assert!(w.guids("b/data").contains(&900) && !w.guids("b/data").contains(&90));
}

#[test]
fn a_name_collision_stops_only_its_pair_and_sync_all_asks_once() {
    let mut w = with_second_pair(colliding());
    let plan = sync_plan_with(&SyncTarget::All, &mut w).unwrap();
    assert_eq!(plan.entries.len(), 2);
    assert_eq!(plan.summary().as_deref(), Some("1 snapshot on b/data"));
    let entries = sync_prepared_with(&plan, false, &mut w).unwrap();
    let blocked = entries.iter().find(|e| e.source == "a/data").unwrap();
    assert!(
        blocked
            .error
            .as_deref()
            .is_some_and(|e| e.contains("b/data@x (not reviewed)")),
        "{blocked:?}"
    );
    let other = entries.iter().find(|e| e.source == "a/more").unwrap();
    assert!(other.result.is_some(), "{other:?}");
    let more = w.guids("a/more");
    assert!(w.guids("b/more").ends_with(&more[more.len() - 1..]));
    assert!(w.guids("b/data").contains(&90) && !w.guids("b/data").contains(&900));
    // One answer for all pairs: both sync, the collision deleted first.
    w.n().written.insert("a/more".into(), 4096);
    let plan = sync_plan_with(&SyncTarget::All, &mut w).unwrap();
    let entries = sync_prepared_with(&plan, true, &mut w).unwrap();
    assert!(entries.iter().all(|e| e.result.is_some()), "{entries:?}");
    assert!(synced(&mut w));
    assert!(!w.guids("b/data").contains(&90));
}

/// The working copy swapped the names of its two snapshots.
fn swapped() -> World {
    let mut w = changed();
    rename(&mut w, "a/data", "s0", "tmp");
    rename(&mut w, "a/data", "s1", "s0");
    rename(&mut w, "a/data", "tmp", "s1");
    w
}

#[test]
fn common_snapshots_take_the_working_copys_names_through_a_swap_and_every_cut() {
    let mut w = swapped();
    assert_eq!(snapshot_names(&w, "b/data"), ["s0", "s1"]);
    let result = sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap();
    assert!(synced(&mut w));
    check_pair(&mut w);
    assert_eq!(snapshot_names(&w, "b/data"), snapshot_names(&w, "a/data"));
    assert_eq!(&snapshot_names(&w, "b/data")[..2], ["s1", "s0"]);
    assert_eq!(result.renamed.len(), 2);
    assert!(
        w.t.renamed
            .iter()
            .any(|(_, to)| to.starts_with("b/data@zboot_rename_")),
        "{:?}",
        w.t.renamed
    );
    every_cut(
        swapped,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        synced,
        |w| {
            assert!(synced(w));
            check_pair(w);
            assert_eq!(snapshot_names(w, "b/data"), snapshot_names(w, "a/data"));
        },
    );
    // Idempotent: the next sync has nothing to rename.
    w.n().written.insert("a/data".into(), 4096);
    let result = sync::sync_one(&sync_request(), RERUN, &[], &mut w).unwrap();
    assert!(result.renamed.is_empty());
}

#[test]
fn a_snapshot_renamed_and_taken_again_on_the_working_copy_still_syncs() {
    // The probe's case: a/data@s1 became s1-old and a new s1 was taken; a
    // receive into b/data, which still calls it s1, fails until it follows.
    let mut w = changed();
    rename(&mut w, "a/data", "s1", "s1-old");
    put(&mut w, "a/data", "s1", 950, 50);
    let result = sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap();
    assert_eq!(
        result.renamed,
        [prune::Renamed {
            from: "b/data@s1".into(),
            to: "b/data@s1-old".into(),
        }]
    );
    assert!(synced(&mut w));
    assert_eq!(snapshot_names(&w, "b/data"), snapshot_names(&w, "a/data"));
}

#[test]
fn a_primary_catch_up_renames_first_and_a_collision_refuses_its_plan() {
    let mut w = paired();
    rename(&mut w, "a/data", "s1", "s1-old");
    put(&mut w, "a/data", "s1", 950, 50);
    primary_now(&mut w, "b/data").unwrap();
    check_b_primary(&mut w);
    assert_eq!(snapshot_names(&w, "b/data"), snapshot_names(&w, "a/data"));
    // A snapshot only on the target under a name the catch-up needs would
    // fail its receive after the peer is fenced: the plan refuses.
    let mut w = paired();
    put(&mut w, "b/data", "x", 90, 5);
    put(&mut w, "a/data", "x", 900, 50);
    let error = primary_plan_with(&w.state(), "b/data", &mut w)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("b/data@x exists only on b/data")
            && error.contains("`zboot sync b/data` on a terminal"),
        "{error}"
    );
    assert_eq!(w.effects(), 0);
}

fn boundaries(w: &World, dataset: &str) -> Vec<String> {
    snapshot_names(w, dataset)
        .into_iter()
        .filter(|n| n.starts_with("zboot_transfer_"))
        .collect()
}
/// After one sync, with a new change: its boundary snapshot is the anchor
/// and the next sync makes it older than the anchor.
fn synced_once() -> World {
    let mut w = changed();
    sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap();
    w.n().written.insert("a/data".into(), 4096);
    w.t.destroyed.clear();
    w.t.native.effects = 0;
    w
}

#[test]
fn boundary_cleanup_deletes_only_zboots_own_older_snapshots_copy_first() {
    let mut w = synced_once();
    let first = boundaries(&w, "a/data");
    assert_eq!(first.len(), 1);
    // Boundary-named by hand: no capture marker on the working copy.
    let hand = "zboot_transfer_0123456789abcdef0123456789abcdef";
    put(&mut w, "a/data", hand, 970, 12);
    put(&mut w, "b/data", hand, 970, 12);
    let result = sync::sync_one(&sync_request(), RERUN, &[], &mut w).unwrap();
    let (copy, working) = (
        format!("b/data@{}", first[0]),
        format!("a/data@{}", first[0]),
    );
    assert_eq!(w.t.destroyed, [copy.clone(), working.clone()]);
    assert_eq!(result.boundaries.deleted, [copy, working]);
    let left = boundaries(&w, "a/data");
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(left.contains(&hand.to_string()));
    assert_eq!(boundaries(&w, "b/data"), left);
    assert!(synced(&mut w));
    check_pair(&mut w);
    // A held one stays on both sides and is reported.
    let mut w = synced_once();
    let held = format!("a/data@{}", boundaries(&w, "a/data")[0]);
    w.n()
        .holds
        .entry(held)
        .or_default()
        .insert("zboot:reader:job".into());
    let result = sync::sync_one(&sync_request(), RERUN, &[], &mut w).unwrap();
    assert!(w.t.destroyed.is_empty());
    assert_eq!(result.boundaries.kept.len(), 1);
    assert!(
        result.boundaries.kept[0]
            .reason
            .contains("zboot:reader:job")
    );
    assert_eq!(boundaries(&w, "a/data").len(), 2);
    assert_eq!(boundaries(&w, "b/data").len(), 2);
}

/// A fork of the working copy (a clone of one of its snapshots) does not stop
/// the pair: the sync runs, and the clone's origin is kept, not destroyed. A
/// clone on the copy, which receives, stops the sync before anything changes.
#[test]
fn a_clone_of_the_working_copy_syncs_and_one_of_the_copy_refuses() {
    let mut w = synced_once();
    let origin = format!("a/data@{}", boundaries(&w, "a/data")[0]);
    w.n().clones.insert(origin.clone(), "a/fork".into());
    let result = sync::sync_one(&sync_request(), RERUN, &[], &mut w).unwrap();
    assert!(!w.t.destroyed.contains(&origin), "{:?}", w.t.destroyed);
    assert!(
        result
            .boundaries
            .kept
            .iter()
            .any(|k| k.snapshot == origin && k.reason.contains("clone (a/fork)")),
        "{:?}",
        result.boundaries.kept
    );
    assert!(synced(&mut w));
    check_pair(&mut w);

    let mut w = synced_once();
    let copy = format!("b/data@{}", boundaries(&w, "b/data")[0]);
    w.n().clones.insert(copy, "b/fork".into());
    let effects = w.effects();
    let error = sync::sync_one(&sync_request(), RERUN, &[], &mut w)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("b/data has clones of its snapshots (b/fork)"),
        "{error}"
    );
    assert_eq!(w.effects(), effects);
}

/// After `primary`, zboot's older boundary snapshots carry their capture
/// marker on the side that is now the copy; they are still zboot's own.
#[test]
fn boundary_cleanup_after_a_switch_recognizes_the_marker_on_the_copy() {
    let mut w = synced_once();
    let first = boundaries(&w, "a/data");
    assert_eq!(first.len(), 1);
    w.op = SECOND;
    primary_now(&mut w, "b/data").unwrap();
    w.n().written.insert("b/data".into(), 4096);
    let back = TransferRequest {
        source: "b/data".into(),
        destination: "a/data".into(),
    };
    let result = sync::sync_one(&back, RERUN, &[], &mut w).unwrap();
    let gone = [
        format!("b/data@{}", first[0]),
        format!("a/data@{}", first[0]),
    ];
    for name in &gone {
        assert!(result.boundaries.deleted.contains(name), "{result:?}");
    }
    // The unmarked side (the new working copy) goes first.
    assert_eq!(result.boundaries.deleted[..2], gone);
}

#[test]
fn boundary_cleanup_survives_every_cut() {
    let first = synced_once().guids("b/data").last().copied().unwrap();
    let done = move |w: &mut World| synced(w) && w.guids("b/data").last() != Some(&first);
    every_cut(
        synced_once,
        |w| sync::sync_one(&sync_request(), RERUN, &[], w).map(drop),
        done,
        move |w| {
            assert!(synced(w) && w.guids("b/data").last() != Some(&first));
            check_pair(w);
            // The unmarked copy's is deleted first; a cut between the two
            // leaves the working copy's marked one, which the resume deletes.
            assert!(!w.guids("b/data").contains(&first));
            assert!(!w.guids("a/data").contains(&first));
            assert_eq!(boundaries(w, "b/data").len(), 1);
            assert_eq!(boundaries(w, "a/data").len(), 1);
        },
    );
}

#[test]
fn status_lists_the_copys_pending_deletions_on_both_sides() {
    let mut w = pruned();
    let state = w.state();
    let relations = crate::status::relationships_with(&state, &mut w);
    for side in ["a/data", "b/data"] {
        assert!(relations[side].blockers.is_empty(), "{side}");
        assert_eq!(
            relations[side].pending_deletions,
            ["b/data@old1", "b/data@old2"],
            "{side}"
        );
    }
    let mut w = changed();
    let state = w.state();
    assert!(
        crate::status::relationships_with(&state, &mut w)
            .values()
            .all(|r| r.pending_deletions.is_empty())
    );
}

#[test]
fn sync_texts_show_the_review_the_consequence_and_the_review_command() {
    let mut w = colliding();
    put(&mut w, "b/data", "old1", 91, 6);
    let plan = sync_plan_with(&pair_target(), &mut w).unwrap();
    let token = plan.token().unwrap();
    let text = describe::sync_plan(&plan, &token);
    println!("--- one pair\n{text}");
    for expected in [
        "Sync a/data -> b/data\n",
        "  2 snapshots only on b/data; a/data no longer has them:\n",
        "    b/data@x  created 20231114T221320Z  frees 0B  (its name arrives from a/data",
        "    b/data@old1  created 20231114T221320Z  frees 0B\n",
        "After deletion these snapshots exist nowhere. Type the summary (2 snapshots on b/data)",
        &format!("Token {token}\n"),
    ] {
        assert!(text.contains(expected), "{expected:?}\n{text}");
    }
    let mut w = with_second_pair(pruned());
    put(&mut w, "b/more", "gone", 190, 5);
    let plan = sync_plan_with(&SyncTarget::All, &mut w).unwrap();
    assert_eq!(plan.summary().as_deref(), Some("3 snapshots on 2 copies"));
    let text = describe::sync_plan(&plan, &plan.token().unwrap());
    println!("--- all pairs\n{text}");
    assert!(text.contains("  1 snapshot only on b/more; a/more no longer has it:\n"));
    let entries = sync_prepared_with(&plan, false, &mut w).unwrap();
    let text = describe::synced(&entries);
    println!("--- unattended\n{text}");
    assert!(
        text.contains(
            "2 snapshots only on b/data await review for deletion; a/data no longer has them. \
             Review with `zboot sync b/data` on a terminal, or `zboot sync b/data --dry-run` then \
             `--confirm TOKEN`.\n"
        ),
        "{text}"
    );
    w.n().written.insert("a/data".into(), 4096);
    w.n().written.insert("a/more".into(), 4096);
    let plan = sync_plan_with(&SyncTarget::All, &mut w).unwrap();
    let entries = sync_prepared_with(&plan, true, &mut w).unwrap();
    let text = describe::synced(&entries);
    println!("--- confirmed\n{text}");
    assert!(text.contains("Deleted b/data@old1: it existed only on b/data.\n"));
    assert!(text.contains("Deleted 2 of zboot's older boundary snapshots on a/data and b/data.\n"));
}

#[test]
fn primary_refuses_a_child_on_either_side_before_any_effect() {
    // A child on either side, fenced or not, is refused by the leaf rule.
    let cases = [("a/data", false), ("b/data", false), ("b/data", true)];
    for takeover in [false, true] {
        for (parent, fence) in cases {
            let expected = "a pair joins leaf datasets";
            let setup = || {
                if takeover {
                    let mut w = paired();
                    w.diverge("a/data", 900);
                    w.diverge("b/data", 901);
                    w
                } else {
                    changed()
                }
            };
            let add = |w: &mut World| {
                let child = w.add_child(parent);
                if fence {
                    w.fence_child(&child);
                }
            };
            let mut w = setup();
            assert_eq!(
                primary_plan_with(&w.state(), "b/data", &mut w)
                    .unwrap()
                    .mode,
                if takeover {
                    PrimaryMode::Takeover
                } else {
                    PrimaryMode::CatchUp
                }
            );
            // A child already there refuses the preview.
            add(&mut w);
            let error = primary_plan_with(&w.state(), "b/data", &mut w)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert_eq!(w.effects(), 0);
            // A child made after the preview refuses its execution.
            let mut w = setup();
            let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
            add(&mut w);
            let before = format!("{:?}", w.state());
            let error = primary_with(&plan, OP, &mut w).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert_eq!(w.effects(), 0);
            assert!(w.records().is_empty());
            assert_eq!(format!("{:?}", w.state()), before);
        }
    }
}

// ---- primary ---------------------------------------------------------------

fn primary_now(w: &mut World, target: &str) -> Result<PrimaryResult, Error> {
    let state = w.state();
    let plan = primary_plan_with(&state, target, w)?;
    primary_with(&plan, w.op, w)
}
fn b_is_primary(w: &mut World) -> bool {
    w.record("b/data").is_some_and(|r| r.role == Role::Primary) && !w.readonly("b/data")
}
fn check_b_primary(w: &mut World) {
    assert!(b_is_primary(w));
    assert_eq!(w.record("a/data").unwrap().role, Role::Secondary);
    assert!(!w.readonly("b/data"));
    assert!(w.mounted("b/data"), "b/data is not mounted");
    assert!(w.readonly("a/data"));
    assert!(!w.mounted("a/data"));
    let state = w.state();
    assert!(matches!(
        management::ownership(&state, "b/data").unwrap(),
        Ownership::Primary { .. }
    ));
}

#[test]
fn primary_catches_up_a_clean_secondary_without_loss_through_every_cut() {
    let mut w = changed();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::CatchUp);
    assert!(!plan.confirms());
    every_cut(
        changed,
        |w| primary_now(w, "b/data").map(drop),
        b_is_primary,
        |w| {
            check_b_primary(w);
            // The final capture of the old primary reached the new one.
            let a = w.guids("a/data");
            assert!(w.guids("b/data").ends_with(&a[a.len() - 1..]));
        },
    );
}

fn set_quota(w: &mut World, name: &str, value: &str) {
    w.n().properties.entry(name.into()).or_default().insert(
        "quota".into(),
        NativeProperty {
            value: value.into(),
            source: "local".into(),
        },
    );
}

/// The plan lists the space limits the pair's fenced side does not hold, by
/// the rule `status` uses, for review. They lose nothing: the token, the
/// switch's fresh plan and its record do not bind them.
#[test]
fn primary_reviews_space_differences_without_binding_them() {
    let differences = |w: &mut World, working: &str, copy: &str| {
        crate::transfer::props::space_differences(&w.state(), working, copy).unwrap()
    };
    let mut w = changed();
    let before = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert!(before.space_differences.is_empty());
    set_quota(&mut w, "a/data", "107374182400");
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::CatchUp);
    assert!(!plan.confirms());
    assert_eq!(
        plan.space_differences,
        differences(&mut w, "a/data", "b/data")
    );
    assert_eq!(plan.space_differences.len(), 1);
    assert_ne!(plan, before);
    assert_eq!(plan.token().unwrap(), before.token().unwrap());
    let text = describe::primary(&plan);
    assert!(
        text.contains(
            "Space limits differ. The catch-up applies a/data's where b/data can take them"
        ) && text.contains("\n  quota 100G on a/data, none on b/data\n"),
        "{text}"
    );
    let json = serde_json::to_value(&plan).unwrap();
    assert_eq!(json["space_differences"][0]["working_copy"], "a/data");
    assert!(
        serde_json::to_value(&before)
            .unwrap()
            .get("space_differences")
            .is_none()
    );
    // The switch runs from the plan made before the limit was set, and its
    // catch-up gives b/data the limit, so nothing differs afterwards.
    primary_with(&before, w.op, &mut w).unwrap();
    check_b_primary(&mut w);
    assert!(differences(&mut w, "b/data", "a/data").is_empty());

    // Already the working copy: the same comparison, toward the fenced side.
    let mut w = paired();
    set_quota(&mut w, "b/data", "1024");
    let plan = primary_plan_with(&w.state(), "a/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::AlreadyPrimary);
    assert_eq!(
        plan.space_differences,
        differences(&mut w, "a/data", "b/data")
    );
    assert!(describe::primary(&plan).contains(
        "A sync applies a/data's when b/data can take them, and removes from b/data a limit \
         a/data does not set:\n  quota none on a/data, 1K on b/data\n"
    ));

    // A takeover: the activated side keeps its own limits.
    let mut w = paired();
    w.diverge("a/data", 900);
    w.diverge("b/data", 901);
    let before = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    set_quota(&mut w, "b/data", "1024");
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Takeover);
    assert!(plan.confirms());
    assert_eq!(plan.space_differences.len(), 1);
    assert_eq!(plan.token().unwrap(), before.token().unwrap());
    assert!(describe::primary(&plan).contains(
        "Space limits differ. b/data keeps its own, and the next sync gives them to a/data:"
    ));
}

fn shared_mountpoints(takeover: bool) -> World {
    let mut w = paired();
    let paths: Vec<_> = w
        .n()
        .members
        .iter()
        .filter(|m| history::contains_dataset("a/data", &m.endpoint.name))
        .map(|m| {
            (
                m.endpoint.name["a/data".len()..].to_string(),
                m.mountpoint.clone(),
            )
        })
        .collect();
    for (relative, mountpoint) in paths {
        w.n()
            .members
            .iter_mut()
            .find(|m| m.endpoint.name == format!("b/data{relative}"))
            .unwrap()
            .mountpoint = mountpoint;
    }
    if takeover {
        w.diverge("a/data", 900);
        w.diverge("b/data", 901);
    }
    w
}

#[test]
fn primary_fences_the_bound_peer_before_reusing_its_mountpoints_through_every_cut() {
    for takeover in [false, true] {
        every_cut(
            || shared_mountpoints(takeover),
            |w| primary_now(w, "b/data").map(drop),
            b_is_primary,
            check_b_primary,
        );
    }
}

#[test]
fn a_primary_preview_never_allows_an_unrelated_mountpoint_occupant() {
    for takeover in [false, true] {
        let mut w = shared_mountpoints(takeover);
        // An unrelated dataset mounted at the path b/data takes over, which
        // the departing a/data also occupies until it is fenced.
        let mut unrelated = crate::pairs::plan::tests::member("a/unrelated", 1, 99, &[]);
        unrelated.mountpoint = w
            .n()
            .members
            .iter()
            .find(|m| m.endpoint.name == "b/data")
            .unwrap()
            .mountpoint
            .clone();
        w.n().members.push(unrelated);
        w.n().mounted.insert("a/unrelated".into());
        let before = w.state();
        let effects = w.effects();
        let error = primary_plan_with(&before, "b/data", &mut w).unwrap_err();
        assert!(
            error.to_string().contains("occupied by a/unrelated"),
            "{error}"
        );
        assert_eq!(w.effects(), effects);
        assert_eq!(format!("{:?}", w.state()), format!("{before:?}"));
    }
}

#[test]
fn abandoning_a_primary_switch_leaves_one_side_recoverable_by_primary() {
    let mut reference = changed();
    primary_now(&mut reference, "b/data").unwrap();
    let total = reference.effects();
    for n in 1..=total {
        for after in [false, true] {
            let mut w = changed();
            w.t.native.cut = Some((n, after));
            assert!(primary_now(&mut w, "b/data").is_err());
            w.restart();
            for record in w.records() {
                let mut dialogue = Vec::new();
                if resume_with(record.clone(), true, &mut dialogue, &mut w).is_err() {
                    // Mid-transfer: abandoning is refused; it is resumed.
                    resume_with(record, false, &mut dialogue, &mut w).unwrap();
                }
            }
            assert!(w.records().is_empty());
            no_chunks(&w);
            no_split_brain(&mut w);
            let owner = if w.record("b/data").is_some_and(|r| r.role == Role::Primary) {
                "b/data"
            } else {
                "a/data"
            };
            primary_now(&mut w, owner)
                .unwrap_or_else(|e| panic!("primary {owner} after abandon {n}/{after}: {e}"));
            assert!(!w.readonly(owner), "{owner} after abandon {n}/{after}");
            no_split_brain(&mut w);
        }
    }
}

#[test]
fn primary_takeover_is_typed_on_the_peer_and_rolls_it_back_through_every_cut() {
    let setup = || {
        let mut w = paired();
        w.diverge("a/data", 900);
        w.diverge("b/data", 901);
        w
    };
    let mut w = setup();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Takeover);
    assert!(plan.confirms());
    assert_eq!(plan.typed_target(), "a/data");
    let loss = plan.loss.as_ref().unwrap();
    assert_eq!(loss.snapshots.len(), 1);
    assert_eq!(loss.snapshots[0].name, "a/data@x900");
    assert_eq!(loss.rollback[0].name, "a/data@s1");
    every_cut(
        setup,
        |w| primary_now(w, "b/data").map(drop),
        b_is_primary,
        |w| {
            check_b_primary(w);
            assert!(!w.guids("a/data").contains(&900));
            assert!(w.guids("b/data").contains(&901));
        },
    );
}

#[test]
fn a_takeover_never_destroys_a_snapshot_made_after_the_plan() {
    let mut w = paired();
    w.diverge("a/data", 900);
    w.diverge("b/data", 901);
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    w.diverge("a/data", 902);
    assert!(primary_with(&plan, OP, &mut w).is_err());
    assert_eq!(w.effects(), 0);
    assert!(w.guids("a/data").contains(&902));
}

#[test]
fn a_takeover_refuses_held_peer_snapshots_and_a_changed_target() {
    let mut w = paired();
    w.diverge("a/data", 900);
    w.diverge("b/data", 901);
    w.n()
        .holds
        .entry("a/data@x900".into())
        .or_default()
        .insert("zboot:keep".into());
    assert!(primary_plan_with(&w.state(), "b/data", &mut w).is_err());
    let mut w = changed();
    w.n().written.insert("b/data".into(), 1);
    assert!(primary_plan_with(&w.state(), "b/data", &mut w).is_err());
    assert_eq!(w.effects(), 0);
}

#[test]
fn primary_with_a_dead_peer_is_typed_on_the_survivor_and_activates_it() {
    let setup = || {
        let mut w = paired();
        w.export("a");
        w
    };
    let mut w = setup();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::DeadPeer);
    assert!(plan.confirms());
    assert_eq!(plan.typed_target(), "b/data");
    assert!(
        plan.statement
            .as_ref()
            .unwrap()
            .contains("a/data is offline")
    );
    every_cut(
        setup,
        |w| primary_now(w, "b/data").map(drop),
        |w| w.record("b/data").is_none() && !w.readonly("b/data"),
        |w| {
            assert!(w.record("b/data").is_none());
            assert!(!w.readonly("b/data"));
            assert!(w.mounted("b/data"));
            assert_eq!(w.holds(&format!("zboot:anchor:{ID}")), ["b/data@s1"]);
        },
    );
}

#[test]
fn primary_of_a_fenced_unpaired_dataset_restores_its_placement() {
    let setup = || {
        let mut w = paired();
        unpair_now(&mut w, false).unwrap();
        w.t.native.effects = 0;
        w
    };
    let mut w = setup();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Standalone);
    assert!(!plan.confirms());
    every_cut(
        setup,
        |w| primary_now(w, "b/data").map(drop),
        |w| !w.readonly("b/data") && w.mounted("b/data"),
        |w| {
            assert!(!w.readonly("b/data"));
            assert!(w.mounted("b/data"));
        },
    );
}

#[test]
fn primary_of_the_primary_changes_nothing_and_records_nothing() {
    let mut w = paired();
    let result = primary_now(&mut w, "a/data").unwrap();
    assert!(result.already_primary);
    assert_eq!(result.mode, PrimaryMode::AlreadyPrimary);
    assert!(result.operation_id.is_none());
    assert_eq!(w.effects(), 0);
}

#[test]
fn primary_refuses_a_running_root_before_any_effect() {
    let mut w = changed();
    w.t.native.running = Some("a/data".into());
    assert!(primary_plan_with(&w.state(), "b/data", &mut w).is_err());
    assert_eq!(w.effects(), 0);
}

fn local_placements(w: &mut World, root: &str) -> Vec<String> {
    let state = w.state();
    tree(&state, root)
        .into_iter()
        .filter(|d| {
            management::bound_properties(&state, &d.name)
                .unwrap()
                .get(management::PLACEMENT_PROPERTY)
                .is_some_and(|p| p.source == "local")
        })
        .map(|d| d.name.clone())
        .collect()
}

#[test]
fn activation_retires_only_the_promoted_working_copys_local_placement() {
    let mut w = paired();
    primary_now(&mut w, "b/data").unwrap();
    assert!(local_placements(&mut w, "b/data").is_empty());
    assert_eq!(local_placements(&mut w, "a/data"), ["a/data"]);
    check_b_primary(&mut w);
    let before = w.effects();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(w.effects(), before, "a preview writes nothing");
    assert!(plan.activation.iter().all(|m| !m.changes && !m.stored));
    assert!(
        primary_with(&plan, SECOND, &mut w)
            .unwrap()
            .operation_id
            .is_none()
    );
    assert_eq!(w.effects(), before);

    // A later operator readonly policy is live primary state, not the old
    // readonly=false receipt that promotion used and has now retired.
    w.n().properties.get_mut("b/data").unwrap().insert(
        "readonly".into(),
        NativeProperty {
            value: "on".into(),
            source: "local".into(),
        },
    );
    let before = w.effects();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(w.effects(), before);
    assert!(plan.activation.iter().all(|m| !m.changes && !m.stored));
    assert!(
        plan.activation
            .iter()
            .find(|m| m.dataset.name == "b/data")
            .unwrap()
            .placement
            .readonly
    );
    assert!(
        primary_with(&plan, SECOND, &mut w)
            .unwrap()
            .operation_id
            .is_none()
    );
    assert_eq!(w.effects(), before);
    assert!(w.readonly("b/data"));
}

#[test]
fn intentionally_readonly_promoted_member_has_an_idempotent_primary_preview() {
    let mut w = World::new(false);
    w.n().properties.entry("b/data".into()).or_default().insert(
        "readonly".into(),
        NativeProperty {
            value: "on".into(),
            source: "local".into(),
        },
    );
    link::pair_with(&pair_request(), ID, &mut w).unwrap();
    primary_now(&mut w, "b/data").unwrap();
    assert!(w.readonly("b/data"));
    assert!(local_placements(&mut w, "b/data").is_empty());
    let before = w.effects();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(w.effects(), before);
    assert!(plan.activation.iter().all(|m| !m.changes && !m.stored));
    assert!(
        plan.activation
            .iter()
            .find(|m| m.dataset.name == "b/data")
            .unwrap()
            .placement
            .readonly
    );
    assert!(
        primary_with(&plan, SECOND, &mut w)
            .unwrap()
            .operation_id
            .is_none()
    );
    assert_eq!(w.effects(), before);
    // No corresponding authority exception is introduced for an unpaired
    // readonly member whose saved placement has been removed.
    let unpair = unpair_plan_with(&w.state(), "b/data", false).unwrap();
    unpair_with(&unpair, SECOND, &mut w).unwrap();
    assert!(primary_plan_with(&w.state(), "b/data", &mut w).is_err());
}

#[test]
fn promoted_then_unpaired_working_copy_can_plan_rename_and_rollback() {
    let mut w = World::new(true);
    sync::sync_one(&sync_request(), ID, &[], &mut w).unwrap();
    primary_now(&mut w, "b/data").unwrap();
    let plan = unpair_plan_with(&w.state(), "b/data", true).unwrap();
    unpair_with(&plan, SECOND, &mut w).unwrap();
    assert!(local_placements(&mut w, "b/data").is_empty());
    assert!(w.record("a/data").is_none() && w.record("b/data").is_none());
    let before = w.effects();
    crate::tree::discard::plan_with(&mut w, &["a/data".into()]).unwrap();
    crate::tree::rename::plan_with(&mut w, "b/data", "b/archive").unwrap();
    let latest = w
        .n()
        .members
        .iter()
        .find(|m| m.endpoint.name == "b/data")
        .unwrap()
        .snapshots
        .last()
        .unwrap()
        .name
        .clone();
    crate::tree::rollback::plan_with(&mut w, &latest).unwrap();
    assert_eq!(
        w.effects(),
        before,
        "all three follow-up plans are read-only"
    );
}

#[test]
fn unpaired_fenced_secondary_keeps_placement_until_standalone_activation() {
    let mut w = paired();
    let original: Vec<_> = tree(&w.state(), "b/data")
        .into_iter()
        .map(|d| {
            (
                d.name.clone(),
                w.t.native.effective(&d.name)[management::PLACEMENT_PROPERTY].clone(),
            )
        })
        .collect();
    unpair_now(&mut w, false).unwrap();
    for (name, saved) in &original {
        assert_eq!(
            &w.t.native.effective(name)[management::PLACEMENT_PROPERTY],
            saved
        );
        assert!(w.readonly(name));
    }
    primary_now(&mut w, "b/data").unwrap();
    assert!(local_placements(&mut w, "b/data").is_empty());
    assert!(original.iter().all(|(name, _)| !w.readonly(name)));
}

fn readonly_standalone_activation() -> World {
    let mut w = paired();
    unpair_now(&mut w, false).unwrap();
    let state = w.state();
    let placement = Placement::from_dataset(dataset(&state, "b/data").unwrap());
    w.n().properties.get_mut("b/data").unwrap().insert(
        management::PLACEMENT_PROPERTY.into(),
        NativeProperty {
            value: placement.encode().unwrap(),
            source: "local".into(),
        },
    );
    w.t.native.effects = 0;
    w
}

#[test]
fn readonly_activation_receipt_retirement_resumes_through_every_cut() {
    every_cut(
        readonly_standalone_activation,
        |w| primary_now(w, "b/data").map(drop),
        |w| local_placements(w, "b/data").is_empty(),
        |w| {
            assert!(local_placements(w, "b/data").is_empty());
            assert!(w.readonly("b/data"));
        },
    );
}

#[test]
fn a_lost_placement_retirement_reply_is_reconciled_without_recreating_it() {
    let mut w = paired();
    w.lose_placement_reply = true;
    primary_now(&mut w, "b/data").unwrap();
    assert!(!w.lose_placement_reply);
    assert!(w.records().is_empty());
    assert!(local_placements(&mut w, "b/data").is_empty());
    let before = w.effects();
    primary_now(&mut w, "b/data").unwrap();
    assert_eq!(w.effects(), before);
}

#[test]
fn primary_retires_a_leftover_placement_receipt_of_the_working_copy() {
    let mut w = paired();
    let state = w.state();
    let e = endpoint(&state, "a/data").unwrap();
    let placement = Placement::from_dataset(dataset(&state, &e.name).unwrap());
    // A switch cut after it saved the working copy's placement, then
    // abandoned, leaves this receipt on a still active working copy.
    set(&mut w, &e, PropertyValue::Placement(placement)).unwrap();
    assert_eq!(local_placements(&mut w, "a/data"), ["a/data"]);
    primary_now(&mut w, "a/data").unwrap();
    assert!(local_placements(&mut w, "a/data").is_empty());
    assert!(!w.readonly("a/data") && w.mounted("a/data"));
    assert!(w.records().is_empty());
}

#[test]
fn step_six_cleanup_refuses_changed_roles_foreign_placement_and_replaced_members() {
    let worlds = cut_worlds(
        readonly_standalone_activation,
        |w| primary_now(w, "b/data").map(drop),
        |step| step == 6,
    );
    assert!(!worlds.is_empty());
    for (world, record) in worlds {
        for drift in ["role", "authority", "source", "identity"] {
            let mut w = world.clone();
            match drift {
                "role" => {
                    w.n().properties.get_mut("b/data").unwrap().insert(
                        "canmount".into(),
                        NativeProperty {
                            value: "off".into(),
                            source: "local".into(),
                        },
                    );
                }
                "identity" => {
                    w.n()
                        .members
                        .iter_mut()
                        .find(|m| m.endpoint.name == "b/data")
                        .unwrap()
                        .endpoint
                        .identity
                        .guid = Guid::new(999999);
                }
                other => {
                    let state = w.state();
                    let mut placement = Placement::from_dataset(dataset(&state, "b/data").unwrap());
                    if other == "authority" {
                        placement.readonly = false;
                    }
                    w.n().properties.get_mut("b/data").unwrap().insert(
                        management::PLACEMENT_PROPERTY.into(),
                        NativeProperty {
                            value: placement.encode().unwrap(),
                            source: if other == "source" {
                                "received"
                            } else {
                                "local"
                            }
                            .into(),
                        },
                    );
                }
            }
            let before = w.effects();
            assert!(
                resume_with(record.clone(), false, &mut Vec::new(), &mut w).is_err(),
                "{drift}"
            );
            assert_eq!(
                w.effects(),
                before,
                "{drift} changed authority is preserved"
            );
            assert!(!w.records().is_empty());
        }
    }
}

/// A record of each pair verb as only an earlier zboot wrote it: resume and
/// abandon both refuse before any effect and leave the record in place.
#[test]
fn pair_records_from_an_earlier_zboot_are_neither_resumed_nor_abandoned() {
    type Worlds = Vec<(World, intent::Intent<serde_json::Value>)>;
    fn at(worlds: &Worlds, step: u32) -> (World, intent::Intent<serde_json::Value>) {
        worlds
            .iter()
            .find(|(_, record)| record.step == step)
            .cloned()
            .unwrap_or_else(|| panic!("no record at step {step}"))
    }
    let all = |_: u32| true;
    let pair = cut_worlds(
        || World::new(false),
        |w| link::pair_with(&pair_request(), ID, w).map(drop),
        all,
    );
    let release = cut_worlds(paired, |w| unpair_now(w, true).map(drop), all);
    let sync = cut_worlds(
        changed,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        all,
    );
    let primary = cut_worlds(paired, |w| primary_now(w, "b/data").map(drop), all);
    // A later step, or a field this build always writes, taken away.
    let cases = [
        (at(&pair, 0), Some(3), None),
        (at(&release, 0), None, Some("root_bindings")),
        (at(&release, 0), None, Some("anchors")),
        (at(&sync, 0), None, Some("origin")),
        (at(&sync, 0), None, Some("destination_pool")),
        (at(&sync, 0), Some(1), None),
        (at(&primary, 6), None, Some("target_activation")),
        (at(&primary, 4), None, Some("received")),
        (at(&primary, 6), Some(7), None),
    ];
    for ((mut w, mut record), step, without) in cases {
        let old = format!("{} {step:?} {without:?}", record.kind);
        if let Some(step) = step {
            record.step = step;
        }
        if let Some(key) = without {
            assert!(
                record.state.as_object_mut().unwrap().remove(key).is_some(),
                "{old}"
            );
        }
        let pool = ["a", "b"]
            .into_iter()
            .find(|pool| intent::Backend::read(&mut w, pool).unwrap().is_some())
            .unwrap();
        intent::Backend::write(&mut w, pool, &intent::encode(&record).unwrap()).unwrap();
        let effects = w.effects();
        let expected = intent::earlier(&record.kind, &record.id);
        for abandon in [false, true] {
            let error = resume_with(record.clone(), abandon, &mut Vec::new(), &mut w)
                .unwrap_err()
                .to_string();
            assert!(error.contains(&expected), "{old}: {error}");
        }
        assert_eq!(w.effects(), effects, "{old}");
        assert_eq!(w.records(), [record], "{old}");
    }
}

/// Only its source holds a sync's transfer attachments. Renamed, or replaced at
/// its name, resume and abandon refuse before any effect, saying what to do.
/// Gone, resume refuses; abandon ends the sync while no dataset carries a
/// marker of it, and otherwise names that marker.
#[test]
fn a_sync_whose_source_is_not_as_recorded_ends_only_once_nothing_carries_it() {
    fn refused(w: &mut World, record: &intent::Intent<serde_json::Value>, abandon: bool) -> String {
        let effects = w.effects();
        let error = resume_with(record.clone(), abandon, &mut Vec::new(), w)
            .unwrap_err()
            .to_string();
        assert_eq!(w.effects(), effects);
        assert_eq!(w.records(), std::slice::from_ref(record));
        error
    }
    let setups: [fn() -> World; 2] = [changed, || World::new(true)];
    let (mut ended, mut marked, mut nested_marked) = (0, 0, 0);
    for setup in setups {
        let worlds = cut_worlds(
            setup,
            |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
            |_| true,
        );
        assert!(!worlds.is_empty());
        for (w, record) in worlds {
            let mut replaced = w.clone();
            replaced
                .n()
                .members
                .iter_mut()
                .find(|m| m.endpoint.name == "a/data")
                .unwrap()
                .endpoint
                .identity
                .guid = Guid::new(999);
            let mut renamed = w.clone();
            {
                let n = renamed.n();
                let member = n
                    .members
                    .iter_mut()
                    .find(|m| m.endpoint.name == "a/data")
                    .unwrap();
                member.endpoint.name = "a/moved".into();
                for snapshot in &mut member.snapshots {
                    snapshot.name = snapshot.name.replace("a/data@", "a/moved@");
                }
                let properties = n.properties.remove("a/data").unwrap_or_default();
                n.properties.insert("a/moved".into(), properties);
            }
            for abandon in [false, true] {
                let error = refused(&mut replaced, &record, abandon);
                assert!(error.contains("rename it away"), "{error}");
                let error = refused(&mut renamed, &record, abandon);
                assert!(error.contains("a/data is now a/moved"), "{error}");
                assert!(error.contains("rename it back"), "{error}");
            }
            let mut destroyed = w.clone();
            destroyed
                .n()
                .members
                .retain(|m| m.endpoint.name != "a/data");
            destroyed.n().properties.remove("a/data");
            // Without the destination's pool, its markers cannot be seen.
            let mut away = destroyed.clone();
            away.export("b");
            let error = refused(&mut away, &record, true);
            assert!(error.contains("pool b of b/data"), "{error}");
            assert!(error.contains("is not imported as recorded"), "{error}");
            let error = refused(&mut destroyed, &record, false);
            let still = error.contains("still carries");
            assert!(still || error.contains("abandon the sync"), "{error}");
            if still {
                marked += 1;
                assert!(refused(&mut destroyed, &record, true).contains("still carries"));
                continue;
            }
            ended += 1;
            // A copy that still carries the nested pair's pending marker
            // keeps the sync from ending, as one of its own would.
            if destroyed.names("b/data").contains(&"b/data".to_string()) {
                let mut nested = destroyed.clone();
                nested
                    .n()
                    .properties
                    .entry("b/data".into())
                    .or_default()
                    .insert(
                        management::PENDING_PROPERTY.into(),
                        NativeProperty {
                            value: crate::transfer::bootstrap_pair_id(OP),
                            source: "local".into(),
                        },
                    );
                let error = refused(&mut nested, &record, true);
                assert!(
                    error.contains("b/data still carries")
                        && error.contains(management::PENDING_PROPERTY),
                    "{error}"
                );
                nested_marked += 1;
            }
            let mut dialogue = Vec::new();
            resume_with(record.clone(), true, &mut dialogue, &mut destroyed).unwrap();
            assert!(destroyed.records().is_empty());
            // Nothing of the sync is left: no marker of it or of a
            // bootstrap's nested pair, and no attachment.
            no_transfer_records(&destroyed, OP);
            assert!(
                String::from_utf8(dialogue)
                    .unwrap()
                    .contains("its source a/data is gone")
            );
        }
    }
    assert!(
        ended > 0 && marked > 0 && nested_marked > 0,
        "{ended} {marked} {nested_marked}"
    );
}

/// A plan attachment the record names that lost a chunk by hand is not a
/// write cut before its commit: resume and abandon refuse with every key and
/// the record unchanged.
#[test]
fn a_named_transfer_attachment_missing_a_chunk_is_not_discarded() {
    let worlds = cut_worlds(
        changed,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        |_| true,
    );
    let mut lost = 0;
    for (mut w, record) in worlds {
        if transfer_phase(&record).is_none_or(|phase| phase >= crate::transfer::Phase::Released) {
            continue;
        }
        lost += 1;
        let chunk = format!("{}0000", attachment::Key::new(OP, "plan").unwrap().prefix());
        assert!(
            w.n()
                .properties
                .get_mut("a/data")
                .unwrap()
                .remove(&chunk)
                .is_some()
        );
        let properties = w.n().properties.clone();
        for abandon in [false, true] {
            let error = resume_with(record.clone(), abandon, &mut Vec::new(), &mut w)
                .unwrap_err()
                .to_string();
            assert!(error.contains("does not read back"), "{error}");
        }
        assert_eq!(w.n().properties, properties);
        assert_eq!(w.records(), [record]);
    }
    assert!(lost > 0);
}

/// The phase of the transfer a sync or primary RECORD holds.
fn transfer_phase(record: &intent::Intent<serde_json::Value>) -> Option<crate::transfer::Phase> {
    serde_json::from_value::<crate::transfer::TransferProgress>(
        record.state.get("transfer")?.clone(),
    )
    .ok()
    .map(|t| t.phase)
}

/// A cut after the plan's write but before the advance naming it leaves a
/// record with no transfer and chunks nothing names. The verb's own resume
/// discards them and transfers again: a sync, a bootstrap, and a catch-up at
/// its step 3.
#[test]
fn a_cut_before_the_plan_is_named_resumes_through_the_record() {
    type Run = fn(&mut World) -> Result<(), Error>;
    type Case = (fn() -> World, Run, fn(&mut World), &'static str);
    let sync: Run = |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop);
    let catch_up: Run = |w| primary_now(w, "b/data").map(drop);
    let cases: [Case; 3] = [
        (changed, sync, |w| assert!(synced(w)), "a/data"),
        (
            || World::new(true),
            sync,
            |w| assert!(is_paired(w)),
            "a/data",
        ),
        (changed, catch_up, check_b_primary, "b/data"),
    ];
    for (setup, run, check, holder) in cases {
        let mut unnamed = 0;
        for (mut w, record) in cut_worlds(setup, run, |_| true) {
            if record.state.get("transfer").is_some() || w.t.chunks().is_empty() {
                continue;
            }
            unnamed += 1;
            assert!(w.t.chunks().iter().all(|(name, _)| name == holder));
            resume_with(record, false, &mut Vec::new(), &mut w)
                .unwrap_or_else(|e| panic!("{holder}: {e}"));
            assert!(w.records().is_empty());
            no_transfer_records(&w, OP);
            check(&mut w);
        }
        assert!(unnamed > 0, "{holder}: no cut left unnamed chunks");
    }
}

/// Through every cut of a catch-up, the plan its record names is whole on
/// the target, and no chunk is anywhere else.
#[test]
fn a_catch_ups_named_plan_is_whole_on_its_target_through_every_cut() {
    let mut named = 0;
    for (w, record) in cut_worlds(changed, |w| primary_now(w, "b/data").map(drop), |_| true) {
        assert!(w.t.chunks().iter().all(|(name, _)| name == "b/data"));
        let Some(plan) = record
            .state
            .get("transfer")
            .and_then(|t| t.get("plan"))
            .and_then(|p| p["chunks"].as_u64())
        else {
            continue;
        };
        named += 1;
        let prefix = attachment::Key::new(OP, "plan")
            .unwrap()
            .prefix()
            .to_owned();
        let have =
            w.t.chunks()
                .iter()
                .filter(|(_, key)| key.starts_with(&prefix))
                .count();
        assert_eq!(have as u64, plan, "step {}", record.step);
    }
    assert!(named > 0);
}

/// An abandon cut after it recorded its end, while its attachments were
/// removed, ends on the next abandon with the same account of what the sync
/// left: a new copy in its receive container or at its final name, or an
/// existing copy fenced with what it received.
#[test]
fn an_abandon_cut_after_its_end_still_names_what_the_sync_left() {
    use crate::transfer::Phase;
    let setups: [fn() -> World; 2] = [|| World::new(true), changed];
    let mut checked = 0;
    for setup in setups {
        let mut seen = std::collections::BTreeSet::new();
        for (w, record) in cut_worlds(
            setup,
            |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
            |_| true,
        ) {
            // One world per recorded phase and receive step.
            let progress = record.state.get("transfer").cloned();
            let Some(phase) = transfer_phase(&record).filter(|p| *p < Phase::Received) else {
                continue;
            };
            if !seen.insert(format!(
                "{phase:?} {}",
                progress.unwrap()["receive"]["step"]
            )) {
                continue;
            }
            let mut reference = w.clone();
            let mut told = Vec::new();
            resume_with(record.clone(), true, &mut told, &mut reference).unwrap();
            let told = String::from_utf8(told).unwrap();
            let base = w.effects();
            for n in 1..=reference.effects() - base {
                for after in [false, true] {
                    let mut cut = w.clone();
                    cut.t.native.cut = Some((base + n, after));
                    assert!(resume_with(record.clone(), true, &mut Vec::new(), &mut cut).is_err());
                    cut.restart();
                    let Some(again) = cut.records().into_iter().next() else {
                        continue;
                    };
                    if transfer_phase(&again) != Some(Phase::Abandoned) {
                        continue;
                    }
                    // What it left is named by incarnation: replaced at its
                    // name, it is no longer the abandon's.
                    if let Some(left) = again.state["transfer"]["left"]["name"].as_str() {
                        let mut replaced = cut.clone();
                        replaced
                            .n()
                            .members
                            .iter_mut()
                            .find(|m| m.endpoint.name == left)
                            .unwrap()
                            .endpoint
                            .identity
                            .guid = Guid::new(999);
                        let mut dialogue = Vec::new();
                        resume_with(again.clone(), true, &mut dialogue, &mut replaced).unwrap();
                        let text = String::from_utf8(dialogue).unwrap();
                        assert!(text.contains("it leaves no partial new copy"), "{text}");
                    }
                    let mut dialogue = Vec::new();
                    resume_with(again, true, &mut dialogue, &mut cut).unwrap();
                    assert_eq!(String::from_utf8(dialogue).unwrap(), told, "{phase:?} {n}");
                    assert!(cut.records().is_empty());
                    // The partial new copy keeps its container's markers.
                    no_chunks(&cut);
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 0, "no cut left an abandoned sync's record");
}

/// A sync cut after its transfer was released, before its copy lost the
/// staging marker, leaves that marker known only to its record. With the
/// copy's pool exported, resume and abandon refuse and keep the record,
/// naming the import and the hand steps for a pool lost for good; once the
/// pool is imported again either finishes and the marker goes.
#[test]
fn a_released_sync_whose_copy_is_away_keeps_its_record_until_the_copy_is_back() {
    use crate::transfer::Phase;
    for setup in [changed as fn() -> World, || World::new(true)] {
        let mut staged = 0;
        for (w, record) in cut_worlds(
            setup,
            |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
            |_| true,
        ) {
            let marked = |w: &World| {
                w.t.native
                    .properties
                    .get("b/data")
                    .and_then(|p| p.get(management::STAGING_PROPERTY))
                    .is_some_and(|p| p.source == "local" && p.value == OP)
            };
            if transfer_phase(&record) != Some(Phase::Released) || !marked(&w) {
                continue;
            }
            staged += 1;
            for abandon in [false, true] {
                let mut away = w.clone();
                away.export("b");
                let (effects, properties) = (away.effects(), away.n().properties.clone());
                let error = resume_with(record.clone(), abandon, &mut Vec::new(), &mut away)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("import pool b to finish"), "{error}");
                assert!(error.contains("If pool b is lost for good"), "{error}");
                assert!(
                    error.contains(&format!(
                        "run `{}`",
                        crate::recipe::inherit(management::STAGING_PROPERTY, "b/data")
                    )),
                    "{error}"
                );
                assert_eq!(away.effects(), effects);
                assert_eq!(away.n().properties, properties);
                assert_eq!(away.records(), std::slice::from_ref(&record));
                // Imported again.
                away.n().members = w.t.native.members.clone();
                away.n().mounted = w.t.native.mounted.clone();
                resume_with(record.clone(), abandon, &mut Vec::new(), &mut away)
                    .unwrap_or_else(|e| panic!("{abandon}: {e}"));
                assert!(!marked(&away));
                assert!(away.records().is_empty());
                no_transfer_records(&away, OP);
            }
        }
        assert!(staged > 0, "no cut left a released, still staged copy");
    }
}

/// A bootstrap cut once its new copy is at its final name, recorded so or
/// not, whose abandon is then cut between removing the copy's two markers:
/// abandoning again still finds the copy there, says so as the uncut
/// abandon does, and leaves no marker of the sync on it.
#[test]
fn an_abandon_cut_between_the_copys_markers_still_names_the_copy() {
    use crate::transfer::Phase;
    let marked = |w: &World, key: &str| {
        w.t.native
            .properties
            .get("b/data")
            .and_then(|p| p.get(key))
            .is_some_and(|p| p.source == "local" && p.value == OP)
    };
    let (pending, staging) = (management::PENDING_PROPERTY, management::STAGING_PROPERTY);
    let mut between = 0;
    for (w, record) in cut_worlds(
        || World::new(true),
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        |_| true,
    ) {
        if !(marked(&w, pending) && marked(&w, staging))
            || transfer_phase(&record).is_none_or(|p| p >= Phase::Received)
        {
            continue;
        }
        let mut reference = w.clone();
        let mut told = Vec::new();
        resume_with(record.clone(), true, &mut told, &mut reference).unwrap();
        let told = String::from_utf8(told).unwrap();
        assert!(
            told.contains("the partial new copy b/data stays fenced"),
            "{told}"
        );
        let base = w.effects();
        for n in 1..=reference.effects() - base {
            for after in [false, true] {
                let mut cut = w.clone();
                cut.t.native.cut = Some((base + n, after));
                assert!(resume_with(record.clone(), true, &mut Vec::new(), &mut cut).is_err());
                cut.restart();
                let Some(again) = cut.records().into_iter().next() else {
                    continue;
                };
                between += usize::from(!marked(&cut, pending) && marked(&cut, staging));
                let mut dialogue = Vec::new();
                resume_with(again, true, &mut dialogue, &mut cut)
                    .unwrap_or_else(|e| panic!("abandon after its cut {n}/{after}: {e}"));
                assert_eq!(String::from_utf8(dialogue).unwrap(), told, "{n}/{after}");
                assert!(cut.records().is_empty());
                assert!(
                    !marked(&cut, pending) && !marked(&cut, staging),
                    "{n}/{after}"
                );
            }
        }
    }
    assert!(between > 0, "no abandon was cut between the copy's markers");
}

/// A sync resumed once its transfer is released reports what an uncut one
/// does: a bootstrap names the pair it made.
#[test]
fn a_sync_resumed_at_released_reports_its_bootstrapped_pair() {
    let worlds = cut_worlds(
        || World::new(true),
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        |_| true,
    );
    let mut released = 0;
    let pair = crate::transfer::bootstrap_pair_id(OP);
    for (mut w, record) in worlds {
        if transfer_phase(&record) != Some(crate::transfer::Phase::Released) {
            continue;
        }
        released += 1;
        let result = resume_with(record, false, &mut Vec::new(), &mut w).unwrap();
        assert_eq!(result["bootstrapped"], serde_json::json!(pair));
        assert_eq!(result["pair_id"], serde_json::json!(pair));
        assert!(is_paired(&mut w));
    }
    assert!(released > 0);
}

/// Until the record releases its transfer, the copy keeps this sync's
/// staging marker: from its verified data on, through activation and a
/// bootstrap's nested pair, no other command (`primary` alone, or with the
/// pair, any verb admitted by ownership) acts on it.
#[test]
fn a_verified_copy_refuses_other_commands_until_its_record_releases_the_transfer() {
    use crate::transfer::Phase;
    let setups: [fn() -> World; 2] = [|| World::new(true), changed];
    for setup in setups {
        let worlds = cut_worlds(
            setup,
            |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
            |_| true,
        );
        let mut activating = 0;
        for (mut w, record) in worlds {
            let Some(phase) =
                transfer_phase(&record).filter(|p| (Phase::Received..Phase::Released).contains(p))
            else {
                continue;
            };
            activating += usize::from(phase >= Phase::Activating);
            let state = w.state();
            assert!(
                primary_plan_with(&state, "b/data", &mut w).is_err(),
                "{phase:?}"
            );
            assert!(management::ownership(&state, "b/data").is_err());
            // Only once the record is released is the copy released.
            let staging = state.dataset_properties["b/data"]
                .get(management::STAGING_PROPERTY)
                .map(|p| (p.value.as_str(), p.source.as_str()));
            assert_eq!(staging, Some((OP, "local")), "{phase:?}");
        }
        assert!(activating > 0, "no cut left an activating transfer");
    }
}

/// A verified sync is resumed, not abandoned. Once its copy is no longer the
/// one it received, abandon refuses with the commands that end it on the
/// source alone, and changes nothing.
#[test]
fn a_verified_sync_whose_copy_is_gone_refuses_abandon_with_its_source_only_steps() {
    let worlds = cut_worlds(
        changed,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        |_| true,
    );
    let mut verified = 0;
    for (mut w, record) in worlds {
        use crate::transfer::Phase;
        if transfer_phase(&record).is_none_or(|p| !(Phase::Received..Phase::Released).contains(&p))
        {
            continue;
        }
        verified += 1;
        let abandon = |w: &mut World| {
            let effects = w.effects();
            let error = resume_with(record.clone(), true, &mut Vec::new(), w)
                .unwrap_err()
                .to_string();
            assert_eq!(w.effects(), effects);
            assert_eq!(w.records(), std::slice::from_ref(&record));
            error
        };
        assert!(abandon(&mut w).contains("resume it to finish"));
        let mut exported = w.clone();
        exported.export("b");
        let error = abandon(&mut exported);
        assert!(error.contains("import pool b of b/data"), "{error}");
        assert!(error.contains("if pool b is lost for good, end it on a/data alone"));
        assert!(error.contains(&crate::recipe::inherit(intent::PROPERTY, "a")));
        // Renamed since: renamed back and resumed, with no steps offered.
        let mut renamed = w.clone();
        {
            let n = renamed.n();
            let member = n
                .members
                .iter_mut()
                .find(|m| m.endpoint.name == "b/data")
                .unwrap();
            member.endpoint.name = "b/moved".into();
            for snapshot in &mut member.snapshots {
                snapshot.name = snapshot.name.replace("b/data@", "b/moved@");
            }
            let properties = n.properties.remove("b/data").unwrap_or_default();
            n.properties.insert("b/moved".into(), properties);
        }
        let error = abandon(&mut renamed);
        assert!(
            error.contains("b/data is now b/moved: rename it back"),
            "{error}"
        );
        assert!(!error.contains("end it on"), "{error}");
        // Released from the sync by hand, or replaced.
        let mut released = w.clone();
        released
            .n()
            .properties
            .get_mut("b/data")
            .unwrap()
            .remove(management::STAGING_PROPERTY);
        let mut replaced = w.clone();
        replaced
            .n()
            .members
            .iter_mut()
            .find(|m| m.endpoint.name == "b/data")
            .unwrap()
            .endpoint
            .identity
            .guid = Guid::new(999);
        let error = abandon(&mut replaced);
        assert!(
            error.contains("is no longer the copy it received"),
            "{error}"
        );
        for error in [error, abandon(&mut released)] {
            assert!(error.contains("end it on a/data alone"), "{error}");
            let steps = error.split_once("alone: ").unwrap().1;
            assert!(!steps.contains("; "), "{steps}");
            assert!(
                steps.ends_with(&format!(
                    "zfs get -H -o value 'zboot:operation' 'a' | grep -qF '\"id\":\"{OP}\"' \
                     && zfs inherit 'zboot:operation' 'a'"
                )),
                "{steps}"
            );
            assert!(
                error.contains(&format!("grep '^zboot:attachment:{OP}:'")),
                "{error}"
            );
        }
    }
    assert!(verified > 0);
}

// ---- roles -----------------------------------------------------------------

/// Give `name` native boot-root shape and inactive placement.
fn boot(w: &mut World, name: &str) {
    let e = endpoint(&w.state(), name).unwrap();
    for (key, value) in [("mountpoint", "/"), ("canmount", "noauto")] {
        w.n().properties.entry(e.name.clone()).or_default().insert(
            key.into(),
            NativeProperty {
                value: value.into(),
                source: "local".into(),
            },
        );
    }
    w.n().mounted.remove(name);
}

#[test]
fn roles_are_set_on_every_member_at_creation_and_never_swept() {
    let canmount = |state: &NativeState, name: &str| dataset(state, name).unwrap().canmount;
    let readonly = |state: &NativeState, name: &str| dataset(state, name).unwrap().readonly;
    let mut w = World::new(true);
    let before = w.state();
    let source = (canmount(&before, "a/data"), readonly(&before, "a/data"));
    // A bootstrapping sync creates the secondary `noauto` and read-only.
    sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap();
    let state = w.state();
    assert_eq!(
        canmount(&state, "b/data"),
        Some(zfs_tools::engine::CanMount::NoAuto)
    );
    assert!(readonly(&state, "b/data"));
    // Nothing it did not create is swept: the primary and the pool roots
    // keep their own values.
    for name in ["a", "b", "a/data"] {
        assert_eq!(canmount(&state, name), canmount(&before, name), "{name}");
        assert_eq!(readonly(&state, name), readonly(&before, name), "{name}");
    }
    // `primary` swaps the two roles: the new secondary is fenced, the new
    // primary takes the placement the old one had. The copy shares A's
    // mountpoint; `primary` itself must unmount A before activating the copy.
    w.op = RERUN;
    primary_now(&mut w, "b/data").unwrap();
    let state = w.state();
    assert_eq!(
        canmount(&state, "a/data"),
        Some(zfs_tools::engine::CanMount::NoAuto)
    );
    assert!(readonly(&state, "a/data"));
    assert_eq!(
        (canmount(&state, "b/data"), readonly(&state, "b/data")),
        source
    );
}

// ---- resume ----------------------------------------------------------------

#[test]
fn resume_refuses_records_it_does_not_own() {
    let mut w = World::new(false);
    let record = intent::Intent::new(OP, "restore", serde_json::json!({}));
    let mut dialogue = Vec::new();
    assert!(resume_with(record, false, &mut dialogue, &mut w).is_err());
    let record = intent::Intent::new(OP, "pair", serde_json::json!({"left": 1}));
    assert!(resume_with(record, false, &mut dialogue, &mut w).is_err());
    assert!(KINDS.contains(&"release-anchors"));
}

// ---- the world changes between the interruption and the resume -------------

/// Cuts of `run` that leave a record at a step `keep` accepts, each restarted.
fn cut_worlds(
    setup: impl Fn() -> World,
    run: impl Fn(&mut World) -> Result<(), Error>,
    keep: impl Fn(u32) -> bool,
) -> Vec<(World, intent::Intent<serde_json::Value>)> {
    let mut reference = setup();
    let base = reference.effects();
    run(&mut reference).unwrap();
    let total = reference.effects() - base;
    let mut worlds = Vec::new();
    for n in 1..=total {
        for after in [false, true] {
            let mut w = setup();
            w.t.native.cut = Some((base + n, after));
            assert!(run(&mut w).is_err());
            w.restart();
            if let Some(record) = w.records().into_iter().next()
                && keep(record.step)
            {
                worlds.push((w, record));
            }
        }
    }
    worlds
}

#[test]
fn a_loss_free_takeover_never_rolls_back_a_write_made_before_the_fence() {
    // B has a snapshot A lacks and A is clean: a takeover that loses nothing,
    // so it runs unconfirmed.
    let setup = || {
        let mut w = paired();
        w.diverge("b/data", 901);
        w
    };
    let mut w = setup();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Takeover);
    assert!(!plan.confirms());
    let worlds = cut_worlds(setup, |w| primary_now(w, "b/data").map(drop), |s| s < 2);
    assert!(worlds.iter().any(|(_, r)| r.step == 1));
    for (mut w, record) in worlds {
        // An application writes A before the resumed switch fences it.
        w.n().written.insert("a/data".into(), 4096);
        let step = record.step;
        let mut dialogue = Vec::new();
        let error = resume_with(record, false, &mut dialogue, &mut w).unwrap_err();
        assert!(w.n().written.contains_key("a/data"), "step {step}: {error}");
        assert!(!b_is_primary(&mut w), "step {step}");
        no_split_brain(&mut w);
    }
}

#[test]
fn a_resumed_switch_refuses_once_another_primary_activated_the_peer() {
    // From step 2 the old primary is fenced: activating it again is a new
    // decision that the older switch must not override.
    let worlds = cut_worlds(changed, |w| primary_now(w, "b/data").map(drop), |s| s >= 2);
    let mut interleaved = 0;
    for (mut w, record) in worlds {
        let step = record.step;
        // Another operation makes A the working copy again.
        let state = w.state();
        let Ok(plan) = primary_plan_with(&state, "a/data", &mut w) else {
            continue;
        };
        let before = w.effects();
        if primary_with(&plan, "44444444-4444-4444-8444-444444444444", &mut w).is_err()
            || w.effects() == before
            || w.readonly("a/data")
        {
            continue;
        }
        interleaved += 1;
        let mut dialogue = Vec::new();
        let result = resume_with(record, false, &mut dialogue, &mut w);
        assert!(result.is_err(), "step {step}: the old switch went on");
        assert!(w.readonly("b/data"), "step {step}: both sides are writable");
        assert!(!w.mounted("b/data"), "step {step}");
        no_split_brain(&mut w);
    }
    assert!(interleaved > 0);
}

#[test]
fn a_resumed_catch_up_activates_only_the_leaf_that_received_it() {
    let worlds = cut_worlds(
        changed,
        |w| primary_now(w, "b/data").map(drop),
        |s| (4..6).contains(&s),
    );
    assert!(!worlds.is_empty());
    for replace in [true, false] {
        for (mut w, record) in worlds.clone() {
            let step = record.step;
            let leaf = w
                .n()
                .members
                .iter_mut()
                .find(|m| m.endpoint.name == "b/data")
                .unwrap();
            if replace {
                // Renamed away and recreated (even holding the same history).
                leaf.endpoint.identity.guid = Guid::new(777);
                leaf.endpoint.identity.objsetid = ObjsetId::new(777);
                leaf.placement.identity = leaf.endpoint.identity.clone();
                for snapshot in &mut leaf.snapshots {
                    snapshot.dataset_guid = Guid::new(777);
                }
            } else {
                // Native state reads the effective property, including the
                // local override published by inert receive. Mutating only
                // the fake's older placement would no longer change it.
                w.n().properties.entry("b/data".into()).or_default().insert(
                    "mountpoint".into(),
                    NativeProperty {
                        value: "/elsewhere".into(),
                        source: "local".into(),
                    },
                );
            }
            let (readonly, mounted) = (w.readonly("b/data"), w.mounted("b/data"));
            let before = w.effects();
            let mut dialogue = Vec::new();
            assert!(
                resume_with(record, false, &mut dialogue, &mut w).is_err(),
                "step {step} replace={replace}: resumed onto a changed leaf"
            );
            assert_eq!(w.effects(), before, "step {step} replace={replace}");
            assert_eq!(w.readonly("b/data"), readonly);
            assert_eq!(w.mounted("b/data"), mounted);
        }
    }
}

#[test]
fn a_catch_up_finished_without_its_receipt_never_activates() {
    // Step 3 after the transfer finished: nothing proves the fenced target
    // still holds only what it received, so resume activates nothing.
    // Earlier cuts run the rest of the transfer within the resume, as a
    // first run would, and activate the placement it then observes.
    let worlds = cut_worlds(changed, |w| primary_now(w, "b/data").map(drop), |s| s == 3);
    assert!(!worlds.is_empty());
    let mut refused = 0;
    for (mut w, record) in worlds {
        w.n()
            .members
            .iter_mut()
            .find(|m| m.endpoint.name == "b/data")
            .unwrap()
            .mountpoint = Some("/elsewhere".into());
        let mut dialogue = Vec::new();
        match resume_with(record.clone(), false, &mut dialogue, &mut w) {
            Ok(_) => assert!(w.mounted("b/data")),
            Err(error) => {
                assert!(w.readonly("b/data"), "{error}");
                assert!(!w.mounted("b/data"), "{error}");
                no_split_brain(&mut w);
                // A cut inside the transfer may be refused by the transfer
                // itself; the missing receipt is refused with a way out.
                if error.to_string().contains("receipt was not recorded") {
                    refused += 1;
                    resume_with(record, true, &mut dialogue, &mut w).unwrap();
                    assert!(w.records().is_empty());
                    w.op = RERUN;
                    primary_now(&mut w, "b/data").unwrap();
                    check_b_primary(&mut w);
                }
            }
        }
    }
    assert!(refused > 0, "no cut after the transfer reached the refusal");
}

#[test]
fn a_dead_peer_switch_refuses_when_the_peer_returns_as_primary() {
    let full = paired();
    let setup = || {
        let mut w = paired();
        w.export("a");
        w
    };
    let worlds = cut_worlds(setup, |w| primary_now(w, "b/data").map(drop), |_| true);
    assert!(worlds.iter().any(|(_, r)| r.step >= 5));
    for (mut w, record) in worlds {
        let step = record.step;
        // The "offline" pool is imported again, A still the primary.
        for m in &full.t.native.members {
            if history::contains_dataset("a", &m.endpoint.name)
                && !w
                    .n()
                    .members
                    .iter()
                    .any(|o| o.endpoint.name == m.endpoint.name)
            {
                w.n().members.push(m.clone());
            }
        }
        w.n().mounted.extend(
            full.t
                .native
                .mounted
                .iter()
                .filter(|m| history::contains_dataset("a", m))
                .cloned(),
        );
        let mut dialogue = Vec::new();
        let result = resume_with(record, false, &mut dialogue, &mut w);
        let error = result.unwrap_err();
        // From step 5 the survivor is being activated (the operator's
        // statement was acted on); before it, nothing is.
        if step < 5 {
            assert!(w.readonly("b/data"), "step {step}: {error}");
        }
    }
}

/// A child made under either leaf while a catch-up was cut: a pair joins
/// leaves, so the resumed switch activates nothing. Once the child is moved
/// out, the switch finishes as it would have.
#[test]
fn a_resumed_catch_up_refuses_a_child_made_since_it_began() {
    let worlds = cut_worlds(changed, |w| primary_now(w, "b/data").map(drop), |s| s < 6);
    assert!(worlds.iter().any(|(_, r)| r.step == 3));
    assert!(worlds.iter().any(|(_, r)| r.step == 5));
    let mut named = 0;
    for parent in ["a/data", "b/data"] {
        for (mut w, record) in worlds.clone() {
            let step = record.step;
            let child = w.add_child(parent);
            if parent == "b/data" {
                w.fence_child(&child);
            }
            let fenced = |w: &mut World, name: &str| (w.readonly(name), w.mounted(name));
            let (a, b) = (fenced(&mut w, "a/data"), fenced(&mut w, "b/data"));
            let before = w.effects();
            let Err(error) = resume_with(record.clone(), false, &mut Vec::new(), &mut w) else {
                panic!("step {step}: resumed with {child}");
            };
            // The refusal names the child and the way on.
            let text = error.to_string();
            if text.contains("members changed") {
                assert!(
                    text.contains(&format!("it now has {child} below it"))
                        && text.contains("then resume the switch"),
                    "step {step}: {text}"
                );
                named += 1;
            }
            // Only a catch-up transfer already in flight continues into
            // the fenced leaf before the switch refuses; nothing else runs.
            if !(step == 3 && parent == "b/data") {
                assert_eq!(w.effects(), before, "step {step} {child}: {error}");
            }
            assert_eq!(fenced(&mut w, "a/data"), a, "step {step} {child}: {error}");
            assert_eq!(fenced(&mut w, "b/data"), b, "step {step} {child}: {error}");
            assert_eq!(w.names("b/data").len(), 1 + usize::from(parent == "b/data"));
            assert_eq!(w.records().len(), 1);
            no_split_brain(&mut w);
            // Moved out, the child no longer stops the switch.
            w.n().members.retain(|m| m.endpoint.name != child);
            w.n().mounted.remove(&child);
            w.n().properties.remove(&child);
            let mut dialogue = Vec::new();
            if let Err(error) = resume_with(record.clone(), false, &mut dialogue, &mut w) {
                assert!(
                    error.to_string().contains("receipt was not recorded"),
                    "step {step} {child}, moved out: {error}"
                );
                resume_with(record, true, &mut dialogue, &mut w).unwrap();
                w.op = RERUN;
                primary_now(&mut w, "b/data").unwrap();
            }
            assert!(w.records().is_empty());
            check_b_primary(&mut w);
        }
    }
    assert!(named > 0, "no resume named the child");
}

#[test]
fn a_resumed_anchor_release_refuses_anchors_moved_since_the_plan() {
    let setup = || {
        let mut w = paired();
        unpair_now(&mut w, false).unwrap();
        w.t.native.effects = 0;
        w
    };
    let tag = format!("zboot:anchor:{ID}");
    let worlds = cut_worlds(setup, |w| unpair_now(w, true).map(drop), |s| s <= 1);
    assert!(!worlds.is_empty());
    for (mut w, record) in worlds {
        // A sync rotated an anchor: a newer snapshot now carries the tag.
        w.n()
            .holds
            .entry("a/data@s0".into())
            .or_default()
            .insert(tag.clone());
        let mut dialogue = Vec::new();
        assert!(resume_with(record, false, &mut dialogue, &mut w).is_err());
        assert!(w.holds(&tag).contains(&"a/data@s0".to_string()));
    }
}

#[test]
fn a_one_sided_release_never_releases_the_holds_of_a_peer_paired_elsewhere() {
    let mut w = paired();
    // B left this pair and now records another one.
    let mut other = w.record("b/data").unwrap();
    other.pair_id = "55555555-5555-4555-8555-555555555555".into();
    w.n().properties.get_mut("b/data").unwrap().insert(
        management::PAIR_PROPERTY.into(),
        NativeProperty {
            value: other.encode().unwrap(),
            source: "local".into(),
        },
    );
    assert!(unpair_plan_with(&w.state(), "a/data", true).is_err());
    // Without releasing, the one-sided unpair is still possible.
    let plan = unpair_plan_with(&w.state(), "a/data", false).unwrap();
    assert!(plan.one_sided);
    unpair_with(&plan, OP, &mut w).unwrap();
    assert_eq!(w.holds(&format!("zboot:anchor:{ID}")).len(), 2);
}

#[test]
fn a_primary_preview_works_on_read_only_pools_and_execution_refuses_before_any_effect() {
    for pool in ["a", "b"] {
        let mut w = changed();
        w.readonly.push(pool.into());
        let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
        assert_eq!(plan.mode, PrimaryMode::CatchUp);
        let error = primary_with(&plan, OP, &mut w).unwrap_err();
        assert!(error.to_string().contains("read-only"), "{error}");
        assert_eq!(w.effects(), 0);
        assert!(w.records().is_empty());
    }
    // Nothing to change needs no writable pool.
    let mut w = paired();
    w.readonly.push("a".into());
    assert!(primary_now(&mut w, "a/data").unwrap().already_primary);
}

/// The Menu plans on read-only pools and reopens them writable after the
/// typed answer; the plan made again there, and so its token, is unchanged.
#[test]
fn primary_and_unpair_plans_and_tokens_survive_a_read_only_to_writable_reopen() {
    let same = |w: &mut World, plan: &dyn Fn(&mut World) -> String| {
        w.readonly = vec!["a".into(), "b".into()];
        let readonly = plan(w);
        w.readonly.clear();
        assert_eq!(readonly, plan(w));
    };
    let primary = |w: &mut World| {
        let plan = primary_plan_with(&w.state(), "b/data", w).unwrap();
        assert!(plan.confirms());
        crate::consent::token(&plan).unwrap()
    };
    let mut w = paired();
    w.diverge("a/data", 900);
    w.diverge("b/data", 901);
    same(&mut w, &primary);
    let mut w = paired();
    w.export("a");
    same(&mut w, &primary);
    let unpair = |w: &mut World| {
        let plan = unpair_plan_with(&w.state(), "a/data", true).unwrap();
        assert!(plan.confirms());
        crate::consent::token(&plan).unwrap()
    };
    let mut w = paired();
    same(&mut w, &unpair);
    let mut w = paired();
    w.export("b");
    same(&mut w, &unpair);
}

#[test]
fn anchor_resume_rechecks_deferred_destroy_at_every_release_checkpoint() {
    let setup = || {
        let mut w = paired();
        unpair_now(&mut w, false).unwrap();
        w.t.native.effects = 0;
        w
    };
    let tag = format!("zboot:anchor:{ID}");
    let worlds = cut_worlds(setup, |w| unpair_now(w, true).map(drop), |s| s <= 1);
    let mut checked = 0;
    for (mut w, record) in worlds {
        let Some(point) = w.holds(&tag).first().cloned() else {
            continue;
        };
        w.n().deferred.insert(point.clone());
        let before = w.effects();
        assert!(resume_with(record, false, &mut std::io::sink(), &mut w).is_err());
        assert_eq!(w.effects(), before);
        assert!(w.holds(&tag).contains(&point));
        checked += 1;
    }
    assert!(checked > 4);
}

#[test]
fn release_resume_never_adopts_a_newly_imported_former_peer() {
    let setup = || {
        let mut w = paired();
        w.export("b");
        w.t.native.effects = 0;
        w
    };
    let worlds = cut_worlds(setup, |w| unpair_now(w, true).map(drop), |s| s == 1);
    assert!(!worlds.is_empty());
    for (mut w, record) in worlds {
        let mut peer = paired();
        unpair_now(&mut peer, false).unwrap();
        w.n().members.extend(
            peer.n()
                .members
                .iter()
                .filter(|m| m.endpoint.name == "b" || m.endpoint.name.starts_with("b/"))
                .cloned(),
        );
        w.n().properties.remove("b/data");
        let tag = format!("zboot:anchor:{ID}");
        let before: Vec<_> = w
            .holds(&tag)
            .into_iter()
            .filter(|p| p.starts_with("b/"))
            .collect();
        resume_with(record, false, &mut std::io::sink(), &mut w).unwrap();
        let after: Vec<_> = w
            .holds(&tag)
            .into_iter()
            .filter(|p| p.starts_with("b/"))
            .collect();
        assert_eq!(after, before);
        assert!(!after.is_empty());
    }
}

#[test]
fn nonpaired_resume_binds_members_and_saved_activation_beyond_step_zero() {
    for dead in [false, true] {
        let setup = || {
            let mut w = paired();
            if dead {
                w.export("a");
            } else {
                unpair_now(&mut w, false).unwrap();
            }
            w.t.native.effects = 0;
            w
        };
        let worlds = cut_worlds(
            setup,
            |w| primary_now(w, "b/data").map(drop),
            |step| step <= 5,
        );
        assert!(worlds.iter().any(|(_, r)| r.step == 1));
        for (w, record) in worlds {
            // A child made under the leaf since the switch began.
            let mut added = w.clone();
            added.add_child("b/data");
            let before = added.effects();
            assert!(resume_with(record.clone(), false, &mut std::io::sink(), &mut added).is_err());
            assert_eq!(added.effects(), before);
            let mut changed = w;
            let prop = changed
                .n()
                .properties
                .get_mut("b/data")
                .unwrap()
                .get_mut(management::PLACEMENT_PROPERTY)
                .unwrap();
            let mut placement = Placement::parse(&prop.value).unwrap();
            placement.canmount = Some(MountMode::Off);
            prop.value = placement.encode().unwrap();
            let before = changed.effects();
            assert!(resume_with(record, false, &mut std::io::sink(), &mut changed).is_err());
            assert_eq!(changed.effects(), before);
        }
    }
}

#[test]
fn a_failed_default_handoff_stays_typed_partial_and_resumable() {
    let mut w = World::new(false);
    boot(&mut w, "a/data");
    boot(&mut w, "b/data");
    w.bootfs.insert("a".into(), "a/data".into());
    link::pair_with(&pair_request(), ID, &mut w).unwrap();
    w.fail_default = true;
    let value = primary_now(&mut w, "b/data").unwrap();
    assert!(!value.complete());
    let record = w
        .records()
        .into_iter()
        .next()
        .expect("partial intent retained");
    let partial = resume_outcome_with(record.clone(), false, &mut std::io::sink(), &mut w).unwrap();
    assert!(!partial.complete);
    assert!(!w.records().is_empty());
    w.fail_default = false;
    assert!(
        resume_outcome_with(record, false, &mut std::io::sink(), &mut w)
            .unwrap()
            .complete
    );
    assert!(w.records().is_empty());
}

#[test]
fn release_checkpoints_are_bounded_with_many_anchors_and_name_former_peer() {
    let mut w = paired();
    unpair_now(&mut w, false).unwrap();
    let tag = format!("zboot:anchor:{ID}");
    for n in 0..100 {
        let mut point = w
            .n()
            .members
            .iter()
            .find(|m| m.endpoint.name == "a/data")
            .unwrap()
            .snapshots[0]
            .clone();
        point.name = format!("a/data@extra{n}");
        point.identity.guid = Guid::new(10000 + n);
        w.n()
            .members
            .iter_mut()
            .find(|m| m.endpoint.name == "a/data")
            .unwrap()
            .snapshots
            .push(point.clone());
        w.n()
            .holds
            .entry(point.name)
            .or_default()
            .insert(tag.clone());
    }
    w.t.native.effects = 0;
    w.n().cut = Some((1, true));
    assert!(unpair_now(&mut w, true).is_err());
    w.restart();
    let record = w.records().pop().unwrap();
    // A hundred anchors leave an unpair record within the pair verbs' budget.
    assert!(intent::encode(&record).unwrap().len() < super::RECORD_BUDGET);
    assert!(
        record.state["roots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "b/data")
    );
    assert!(record.state["anchor_pending"].is_null());
    resume_with(record, false, &mut std::io::sink(), &mut w).unwrap();
    assert!(w.holds(&tag).is_empty());
}

#[test]
fn oversized_release_checkpoint_refuses_before_first_effect() {
    let mut w = paired();
    unpair_now(&mut w, false).unwrap();
    let tag = format!("zboot:anchor:{ID}");
    let name = format!("a/data@{}", "x".repeat(intent::LIMIT));
    let mut point = w
        .n()
        .members
        .iter()
        .find(|m| m.endpoint.name == "a/data")
        .unwrap()
        .snapshots[0]
        .clone();
    point.name = name.clone();
    point.identity.guid = Guid::new(9999);
    w.n()
        .members
        .iter_mut()
        .find(|m| m.endpoint.name == "a/data")
        .unwrap()
        .snapshots
        .push(point);
    w.n()
        .holds
        .entry(name.clone())
        .or_default()
        .insert(tag.clone());
    w.t.native.effects = 0;
    assert!(unpair_now(&mut w, true).is_err());
    assert_eq!(w.effects(), 0);
    assert!(w.holds(&tag).contains(&name));
}

#[test]
fn pending_release_refuses_when_the_tree_was_paired_again() {
    let setup = || {
        let mut w = paired();
        unpair_now(&mut w, false).unwrap();
        w.t.native.effects = 0;
        w
    };
    let worlds = cut_worlds(setup, |w| unpair_now(w, true).map(drop), |s| s == 1);
    let mut checked = 0;
    for (mut w, record) in worlds {
        let Some(point) = record.state["anchor_pending"]["anchor"][0]["name"].as_str() else {
            continue;
        };
        let dataset = if point.starts_with("a/") {
            "a/data"
        } else {
            "b/data"
        }
        .to_owned();
        let mut other = paired();
        let original = other.n().properties[&dataset][management::PAIR_PROPERTY].clone();
        w.n()
            .properties
            .entry(dataset)
            .or_default()
            .insert(management::PAIR_PROPERTY.into(), original);
        let before = w.effects();
        let holds = w.holds(&format!("zboot:anchor:{ID}"));
        assert!(resume_with(record, false, &mut std::io::sink(), &mut w).is_err());
        assert_eq!(w.effects(), before);
        assert_eq!(w.holds(&format!("zboot:anchor:{ID}")), holds);
        checked += 1;
    }
    assert!(checked > 0);
}

#[test]
fn initial_dead_peer_plan_refuses_an_imported_primary_with_nonreciprocal_metadata() {
    let mut w = paired();
    let mut record = w.record("b/data").unwrap();
    record.role = Role::Primary;
    w.n()
        .properties
        .get_mut("b/data")
        .unwrap()
        .get_mut(management::PAIR_PROPERTY)
        .unwrap()
        .value = record.encode().unwrap();
    let before = w.effects();
    assert!(primary_plan_with(&w.state(), "b/data", &mut w).is_err());
    assert_eq!(w.effects(), before);
    assert!(w.readonly("b/data"));
}

#[test]
fn already_primary_resume_rechecks_members_after_partial_activation() {
    let setup = || {
        let mut w = paired();
        let identity = endpoint(&w.state(), "a/data").unwrap().identity;
        let placement = Placement {
            schema_version: 1,
            identity,
            readonly: false,
            canmount: Some(MountMode::On),
            volmode: None,
        };
        let props = w.n().properties.entry("a/data".into()).or_default();
        props.insert(
            management::PLACEMENT_PROPERTY.into(),
            NativeProperty {
                value: placement.encode().unwrap(),
                source: "local".into(),
            },
        );
        props.insert(
            "readonly".into(),
            NativeProperty {
                value: "on".into(),
                source: "local".into(),
            },
        );
        w.n().mounted.remove("a/data");
        w.t.native.effects = 0;
        w
    };
    let worlds = cut_worlds(
        setup,
        |w| primary_now(w, "a/data").map(drop),
        |step| (1..=5).contains(&step),
    );
    assert!(!worlds.is_empty());
    for (mut w, record) in worlds {
        // A child made under the leaf since the activation began.
        w.add_child("a/data");
        let before = w.effects();
        assert!(resume_with(record, false, &mut std::io::sink(), &mut w).is_err());
        assert_eq!(w.effects(), before);
    }
}

/// A catch-up's transfer keeps its attachments on the target, on the
/// record's own pool. At step 3 a transfer part way is resumed, never
/// abandoned; with its peer's pool exported both say so, and the abandon
/// prints the commands that end it on the target alone. Run, they leave no
/// marker, chunk or record, and `primary` then activates the target without
/// its peer. A catch-up not part way abandons and leaves no chunk.
#[test]
fn a_step_3_abandon_never_orphans_a_transfer_attachment_on_the_target() {
    let worlds = cut_worlds(changed, |w| primary_now(w, "b/data").map(drop), |s| s == 3);
    let (mut refused, mut ended) = (0, 0);
    let (mut keeps_partial, mut keeps_verified) = (0, 0);
    for (mut w, record) in worlds {
        assert!(w.t.chunks().iter().all(|(name, _)| name == "b/data"));
        w.export("a");
        let active =
            transfer_phase(&record).is_some_and(|phase| phase < crate::transfer::Phase::Released);
        let (effects, properties) = (w.effects(), w.n().properties.clone());
        let resumed = resume_with(record.clone(), false, &mut Vec::new(), &mut w);
        match resume_with(record.clone(), true, &mut Vec::new(), &mut w) {
            Err(error) => {
                let error = error.to_string();
                assert!(active, "{error}");
                refused += 1;
                let resumed = resumed.unwrap_err().to_string();
                for error in [&error, &resumed] {
                    assert!(
                        error.contains("pool a of a/data is not imported: import it"),
                        "{error}"
                    );
                }
                assert!(resumed.contains("abandon it to see how"), "{resumed}");
                assert_eq!(w.effects(), effects);
                assert_eq!(w.n().properties, properties);
                assert_eq!(w.records(), std::slice::from_ref(&record));
                // It says what the target keeps: what it received, with
                // the final capture only once the transfer verified it.
                let newest =
                    w.t.native
                        .members
                        .iter()
                        .find(|m| m.endpoint.name == "b/data");
                let newest = &newest.unwrap().snapshots.last().unwrap().name;
                let verified = transfer_phase(&record)
                    .is_some_and(|phase| phase >= crate::transfer::Phase::Received);
                let keeps = if verified {
                    format!(
                        "b/data keeps what it received, its newest snapshot {newest}, the \
                         catch-up's final capture of a/data included and verified"
                    )
                } else {
                    format!(
                        "b/data keeps only what it received, its newest snapshot {newest}, \
                         without the catch-up's final capture of a/data"
                    )
                };
                assert!(error.contains(&keeps), "{error}");
                if verified {
                    keeps_verified += 1;
                } else {
                    keeps_partial += 1;
                }
                // Renamed since, the target is renamed back first.
                let mut renamed = w.clone();
                {
                    let n = renamed.n();
                    let member = n
                        .members
                        .iter_mut()
                        .find(|m| m.endpoint.name == "b/data")
                        .unwrap();
                    member.endpoint.name = "b/moved".into();
                    for snapshot in &mut member.snapshots {
                        snapshot.name = snapshot.name.replace("b/data@", "b/moved@");
                    }
                    let props = n.properties.remove("b/data").unwrap_or_default();
                    n.properties.insert("b/moved".into(), props);
                }
                let moved = resume_with(record.clone(), true, &mut Vec::new(), &mut renamed)
                    .unwrap_err()
                    .to_string();
                assert!(
                    moved.contains("b/data is now b/moved: rename it back first"),
                    "{moved}"
                );
                assert!(!moved.contains("end it on b/data alone"), "{moved}");
                let steps = error
                    .split_once("end it on b/data alone: ")
                    .unwrap_or_else(|| panic!("{error}"))
                    .1
                    .split_once(". b/data keeps ")
                    .unwrap()
                    .0;
                run_steps(&mut w, steps);
                ended += 1;
                // The lost peer keeps its markers; the target keeps none.
                no_chunks(&w);
                assert!(w.records().is_empty());
                assert!(w.readonly("b/data"));
                for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
                    assert!(!w.t.native.effective("b/data").contains_key(key));
                }
                w.op = RERUN;
                let result = primary_now(&mut w, "b/data").unwrap();
                assert_eq!(result.mode, PrimaryMode::DeadPeer);
                assert!(!w.readonly("b/data"));
                assert!(w.records().is_empty());
            }
            Ok(_) => {
                assert!(!active);
                assert!(w.t.chunks().is_empty());
                assert!(w.records().is_empty());
            }
        }
    }
    assert!(
        refused > 0 && ended == refused,
        "no cut left the catch-up's transfer part way"
    );
    // Both what a transfer before Received and one past it leave are told.
    assert!(
        keeps_partial > 0 && keeps_verified > 0,
        "{keeps_partial} {keeps_verified}"
    );
}

/// Run the source- or target-only STEPS on W, as a shell would: each runs
/// only if the one before succeeded.
fn run_steps(w: &mut World, steps: &str) {
    for step in steps.split(" && ") {
        // These names hold no space or quote: each word is one quoted word
        // or bare. A real shell runs the recipes in `recipe`'s tests.
        let words: Vec<&str> = step
            .split_whitespace()
            .map(|word| word.trim_matches('\''))
            .collect();
        match words.as_slice() {
            ["zfs", "inherit", key, dataset] => {
                let props = w.n().properties.entry((*dataset).into()).or_default();
                props.remove(*key);
            }
            [
                "zfs",
                "get",
                "-H",
                "-o",
                "property",
                "-s",
                "local",
                "all",
                dataset,
                "|",
                "grep",
                pattern,
                ..,
            ] => {
                let prefix = pattern.trim_start_matches('^').to_string();
                let props = w.n().properties.entry((*dataset).into()).or_default();
                props.retain(|key, p| !(p.source == "local" && key.starts_with(&prefix)));
            }
            // The guard before the record's removal: the chain stops unless
            // the record still names the operation.
            [
                "zfs",
                "get",
                "-H",
                "-o",
                "value",
                record,
                pool,
                "|",
                "grep",
                "-qF",
                id,
            ] => {
                if !w.n().properties[*pool]
                    .get(*record)
                    .is_some_and(|p| p.value.contains(id))
                {
                    return;
                }
            }
            _ => panic!("unexpected step: {step}"),
        }
    }
}

#[test]
fn sync_refuses_a_read_only_pool_before_recording_anything() {
    for pool in ["a", "b"] {
        let mut w = changed();
        w.readonly.push(pool.into());
        let before = w.effects();
        let error = sync::sync_one(&sync_request(), OP, &[], &mut w).unwrap_err();
        assert!(error.to_string().contains("read-only"), "{error}");
        assert_eq!(w.effects(), before);
        assert!(w.records().is_empty());
    }
}

#[test]
fn a_secondary_nested_inside_another_boot_environment_is_refused_before_effects() {
    for default in [false, true] {
        let mut w = World::new(false);
        if default {
            w.bootfs.insert("b".into(), "b".into());
        } else {
            boot(&mut w, "b");
        }
        let before = format!("{:?}", w.state());
        let error = link::pair_with(&pair_request(), ID, &mut w)
            .unwrap_err()
            .to_string();
        assert!(error.contains("boot environment"), "{error}");
        assert_eq!(w.effects(), 0);
        assert_eq!(format!("{:?}", w.state()), before);
    }
    let mut w = paired();
    boot(&mut w, "a");
    let error = primary_plan_with(&w.state(), "b/data", &mut w)
        .unwrap_err()
        .to_string();
    assert!(error.contains("boot environment"), "{error}");
    assert_eq!(w.effects(), 0);
}

#[test]
fn a_resumed_pair_rechecks_its_secondary_boot_environment_ancestor() {
    let mut w = World::new(false);
    // Past the sync that precedes the record, and the record itself.
    w.n().cut = Some((2, true));
    assert!(link::pair_with(&pair_request(), ID, &mut w).is_err());
    w.restart();
    boot(&mut w, "b");
    let effects = w.effects();
    let record = w
        .records()
        .into_iter()
        .next()
        .expect("pair intent survives the cut");
    let error = super::resume_with(record, false, &mut Vec::new(), &mut w)
        .unwrap_err()
        .to_string();
    assert!(error.contains("boot environment"), "{error}");
    assert_eq!(w.effects(), effects);
}

/// The unpaired world with volumes instead of filesystems.
fn volumes(bootstrap: bool) -> World {
    let mut w = World::new(bootstrap);
    let mut fresh = Transfer::unpaired(bootstrap);
    for member in &mut fresh.native.members {
        member.placement.canmount = None;
        member.mountpoint = None;
    }
    fresh.native.mounted.clear();
    fresh.primary_mode = true;
    w.t = fresh;
    w
}

/// A dormant copy's volume has no device: a local `volmode=none` from
/// pairing to activation, and the inherited value again once it is primary.
#[test]
fn a_fenced_volume_keeps_volmode_none_at_rest_and_activation_inherits_it_again() {
    let mut w = volumes(false);
    let request = PairRequest {
        left: "a/data".into(),
        right: "b/data".into(),
        primary: Some(Side::Left),
    };
    link::pair_with(&request, ID, &mut w).unwrap();
    let volmode =
        |w: &mut World, name: &str| w.t.native.effective(name).get("volmode").cloned().unwrap();
    let none = NativeProperty {
        value: "none".into(),
        source: "local".into(),
    };
    assert_eq!(volmode(&mut w, "b/data"), none, "a paired copy is dormant");
    assert_ne!(volmode(&mut w, "a/data"), none);
    w.n().written.insert("a/data".into(), 4096);
    sync::sync_one(&sync_request(), SECOND, &[], &mut w).unwrap();
    assert_eq!(
        volmode(&mut w, "b/data"),
        none,
        "and stays dormant through a sync"
    );
    primary_now(&mut w, "b/data").unwrap();
    assert_ne!(
        volmode(&mut w, "b/data").source,
        "local",
        "activation inherits it"
    );
    assert_eq!(
        volmode(&mut w, "a/data"),
        none,
        "the fenced old primary is dormant"
    );
}

fn local_value(value: &str) -> NativeProperty {
    NativeProperty {
        value: value.into(),
        source: "local".into(),
    }
}
fn volmode_of(w: &World, name: &str) -> NativeProperty {
    w.t.native.effective(name)["volmode"].clone()
}
fn set_volmode(w: &mut World, name: &str, value: &str) {
    w.n()
        .properties
        .entry(name.into())
        .or_default()
        .insert("volmode".into(), local_value(value));
}
fn saved_volmode(w: &World, name: &str) -> Option<String> {
    let props = w.t.native.effective(name);
    let saved = props
        .get(management::PLACEMENT_PROPERTY)
        .filter(|p| p.source == "local")
        .expect("a saved placement");
    Placement::parse(&saved.value).unwrap().volmode
}
fn primary_is(w: &mut World, name: &str) -> bool {
    w.record(name).is_some_and(|r| r.role == Role::Primary) && !w.readonly(name)
}
/// Volumes paired with `a/data` primary, its `volmode=dev` set by hand.
fn hand_set_volumes() -> World {
    let mut w = volumes(false);
    set_volmode(&mut w, "a/data", "dev");
    link::pair_with(&pair_request(), ID, &mut w).unwrap();
    w.t.native.effects = 0;
    w
}
/// After `primary b/data`: `b/data` has the value `a/data` had set by hand.
fn switched_volumes() -> World {
    let mut w = hand_set_volumes();
    primary_now(&mut w, "b/data").unwrap();
    w.op = SECOND;
    w.t.native.effects = 0;
    w
}

/// A `volmode` set by hand on the working copy is saved when zboot fences
/// it, the new working copy takes it, and the fenced old one keeps it saved
/// for its next activation; a fenced copy never has a device.
#[test]
fn a_hand_set_volmode_follows_the_working_copy_through_primary_and_back() {
    let mut w = hand_set_volumes();
    assert_eq!(volmode_of(&w, "b/data"), local_value("none"));
    assert_eq!(saved_volmode(&w, "b/data"), None, "b/data had no value set");
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::CatchUp);
    let target = plan
        .activation
        .iter()
        .find(|a| a.dataset.name == "b/data")
        .unwrap();
    assert_eq!(
        target.placement.volmode.as_deref(),
        Some("dev"),
        "the plan, and so its token, names the volmode it sets"
    );
    assert!(target.changes);
    every_cut(
        hand_set_volumes,
        |w| primary_now(w, "b/data").map(drop),
        |w| primary_is(w, "b/data"),
        |w| {
            assert!(primary_is(w, "b/data"));
            assert_eq!(volmode_of(w, "b/data"), local_value("dev"));
            assert!(local_placements(w, "b/data").is_empty());
            assert_eq!(volmode_of(w, "a/data"), local_value("none"));
            assert_eq!(saved_volmode(w, "a/data").as_deref(), Some("dev"));
        },
    );
    every_cut(
        switched_volumes,
        |w| primary_now(w, "a/data").map(drop),
        |w| primary_is(w, "a/data"),
        |w| {
            assert!(primary_is(w, "a/data"));
            assert_eq!(volmode_of(w, "a/data"), local_value("dev"));
            assert!(local_placements(w, "a/data").is_empty());
            assert_eq!(volmode_of(w, "b/data"), local_value("none"));
            assert_eq!(saved_volmode(w, "b/data").as_deref(), Some("dev"));
        },
    );
}

/// The departing working copy's value, observed before its fence, wins over
/// the value the activated side saved when it was fenced itself: it is the
/// operator's latest intent, also when that is no value set by hand.
#[test]
fn a_switch_takes_the_departing_working_copys_volmode_over_the_saved_one() {
    let mut w = switched_volumes();
    assert_eq!(saved_volmode(&w, "a/data").as_deref(), Some("dev"));
    set_volmode(&mut w, "b/data", "full");
    primary_now(&mut w, "a/data").unwrap();
    assert_eq!(volmode_of(&w, "a/data"), local_value("full"));
    assert_eq!(saved_volmode(&w, "b/data").as_deref(), Some("full"));

    let mut w = switched_volumes();
    w.n()
        .properties
        .get_mut("b/data")
        .unwrap()
        .remove("volmode");
    primary_now(&mut w, "a/data").unwrap();
    assert_ne!(volmode_of(&w, "a/data").source, "local", "a/data inherits");
    assert_eq!(saved_volmode(&w, "b/data"), None);
    assert_eq!(volmode_of(&w, "b/data"), local_value("none"));

    // A takeover does the same.
    let mut w = hand_set_volumes();
    w.diverge("a/data", 900);
    w.diverge("b/data", 901);
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Takeover);
    primary_with(&plan, OP, &mut w).unwrap();
    assert_eq!(volmode_of(&w, "b/data"), local_value("dev"));
    assert_eq!(volmode_of(&w, "a/data"), local_value("none"));
}

/// A changed `volmode` on the working copy changes the switch's plan, so a
/// token for the old one is refused before any effect.
#[test]
fn the_primary_token_binds_the_volmode_it_sets() {
    let mut w = hand_set_volumes();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    set_volmode(&mut w, "a/data", "full");
    let fresh = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_ne!(
        crate::consent::token(&plan).unwrap(),
        crate::consent::token(&fresh).unwrap()
    );
    let before = w.effects();
    let error = primary_with(&plan, OP, &mut w).unwrap_err().to_string();
    assert!(error.contains("plan changed"), "{error}");
    assert_eq!(w.effects(), before);
}

/// `sync SECONDARY PRIMARY` is refused before any effect: the working copy
/// keeps its hand-set `volmode` and is never fenced for a receive.
#[test]
fn a_sync_into_the_working_copy_is_refused_before_any_effect() {
    let mut w = switched_volumes();
    w.diverge("a/data", 900);
    let back = TransferRequest {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    let before = w.effects();
    let error = sync::sync_one(&back, RERUN, &[], &mut w)
        .unwrap_err()
        .to_string();
    assert!(error.contains("`zboot primary a/data`"), "{error}");
    let error = sync_plan_with(
        &SyncTarget::Between {
            source: "a/data".into(),
            destination: "b/data".into(),
        },
        &mut w,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("a/data is the secondary of b/data"),
        "{error}"
    );
    assert_eq!(w.effects(), before);
    assert!(!w.guids("b/data").contains(&900));
    assert!(primary_is(&mut w, "b/data"));
    assert_eq!(volmode_of(&w, "b/data"), local_value("dev"));
    assert!(local_placements(&mut w, "b/data").is_empty());
}

/// A saved placement an earlier build left on the working copy, without the
/// `volmode` field, is retired by `primary`: the value set by hand stays.
#[test]
fn an_earlier_builds_saved_placement_on_the_working_copy_is_retired() {
    let mut w = switched_volumes();
    let state = w.state();
    let e = endpoint(&state, "b/data").unwrap();
    let old = Placement::from_dataset(dataset(&state, "b/data").unwrap());
    set(&mut w, &e, PropertyValue::Placement(old)).unwrap();
    assert!(primary_now(&mut w, "b/data").unwrap().already_primary);
    assert!(local_placements(&mut w, "b/data").is_empty());
    assert_eq!(volmode_of(&w, "b/data"), local_value("dev"));
}

/// With the peer gone, or after `unpair`, the fenced side gets back the value
/// saved when it was fenced.
#[test]
fn a_fenced_volume_activated_alone_gets_its_saved_volmode_back() {
    let mut w = switched_volumes();
    w.export("b");
    let plan = primary_plan_with(&w.state(), "a/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::DeadPeer);
    primary_with(&plan, SECOND, &mut w).unwrap();
    assert_eq!(volmode_of(&w, "a/data"), local_value("dev"));
    assert!(local_placements(&mut w, "a/data").is_empty());

    let mut w = switched_volumes();
    unpair_now(&mut w, false).unwrap();
    assert_eq!(
        saved_volmode(&w, "a/data").as_deref(),
        Some("dev"),
        "unpair leaves the saved placement"
    );
    let plan = primary_plan_with(&w.state(), "a/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Standalone);
    primary_with(&plan, RERUN, &mut w).unwrap();
    assert_eq!(volmode_of(&w, "a/data"), local_value("dev"));
    assert!(local_placements(&mut w, "a/data").is_empty());
}

/// A new copy saves its source's placement: activated alone after `unpair`,
/// it gets the `volmode` its source had set by hand.
#[test]
fn a_new_copy_of_a_volume_saves_its_sources_hand_set_volmode() {
    let mut w = volumes(true);
    set_volmode(&mut w, "a/data", "dev");
    sync::sync_one(&sync_request(), ID, &[], &mut w).unwrap();
    assert!(is_paired(&mut w));
    assert_eq!(volmode_of(&w, "b/data"), local_value("none"));
    assert_eq!(saved_volmode(&w, "b/data").as_deref(), Some("dev"));
    unpair_now(&mut w, false).unwrap();
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Standalone);
    primary_with(&plan, SECOND, &mut w).unwrap();
    assert_eq!(volmode_of(&w, "b/data"), local_value("dev"));
    assert!(local_placements(&mut w, "b/data").is_empty());
}

/// A volume hidden by hand (a local `none`, no saved placement) is not
/// activated: `primary` leaves it hidden and changes nothing.
#[test]
fn a_volume_hidden_by_hand_stays_hidden() {
    let mut w = volumes(false);
    set_volmode(&mut w, "a/data", "none");
    let plan = primary_plan_with(&w.state(), "a/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Standalone);
    assert!(plan.activation.iter().all(|a| !a.changes && !a.stored));
    assert!(
        primary_with(&plan, OP, &mut w)
            .unwrap()
            .operation_id
            .is_none()
    );
    assert_eq!(volmode_of(&w, "a/data"), local_value("none"));

    link::pair_with(&pair_request(), ID, &mut w).unwrap();
    let before = w.effects();
    let result = primary_now(&mut w, "a/data").unwrap();
    assert!(result.already_primary && result.operation_id.is_none());
    assert_eq!(w.effects(), before);
    assert_eq!(volmode_of(&w, "a/data"), local_value("none"));
}

/// A filesystem's placement record encodes byte for byte as before, even
/// with a local `volmode` on it, and a volume's only gains the field when a
/// value was set by hand.
#[test]
fn a_filesystem_placement_record_encodes_unchanged() {
    let mut w = paired();
    set_volmode(&mut w, "a/data", "dev");
    let state = w.state();
    let a = dataset(&state, "a/data").unwrap();
    let props = management::bound_properties(&state, "a/data").unwrap();
    assert_eq!(
        Placement::observed(a, props).encode().unwrap(),
        r#"{"schema_version":1,"identity":{"pool_guid":"1","guid":"10","createtxg":"1","objsetid":"10"},"readonly":false,"canmount":"on"}"#
    );
    assert_eq!(
        w.t.native.effective("b/data")[management::PLACEMENT_PROPERTY].value,
        r#"{"schema_version":1,"identity":{"pool_guid":"2","guid":"20","createtxg":"1","objsetid":"20"},"readonly":false,"canmount":"on"}"#,
        "the record pair saved on the fenced filesystem"
    );
    let w = hand_set_volumes();
    assert_eq!(
        w.t.native.effective("b/data")[management::PLACEMENT_PROPERTY].value,
        r#"{"schema_version":1,"identity":{"pool_guid":"2","guid":"20","createtxg":"1","objsetid":"20"},"readonly":false,"canmount":null}"#,
        "a volume with no value set by hand"
    );
    let w = switched_volumes();
    assert_eq!(
        w.t.native.effective("a/data")[management::PLACEMENT_PROPERTY].value,
        r#"{"schema_version":1,"identity":{"pool_guid":"1","guid":"10","createtxg":"1","objsetid":"10"},"readonly":false,"canmount":null,"volmode":"dev"}"#,
    );
}

/// A record an earlier build wrote, without the field, still parses and
/// encodes the same; a saved `volmode` that no fence writes refuses.
#[test]
fn an_old_placement_record_parses_and_an_impossible_volmode_refuses() {
    let identity = r#""identity":{"pool_guid":"2","guid":"20","createtxg":"1","objsetid":"20"}"#;
    for old in [
        format!(r#"{{"schema_version":1,{identity},"readonly":false,"canmount":"on"}}"#),
        format!(r#"{{"schema_version":1,{identity},"readonly":true,"canmount":null}}"#),
    ] {
        let placement = Placement::parse(&old).unwrap();
        assert_eq!(placement.volmode, None);
        assert_eq!(placement.encode().unwrap(), old);
    }
    let volume = format!(
        r#"{{"schema_version":1,{identity},"readonly":false,"canmount":null,"volmode":"full"}}"#
    );
    assert_eq!(
        Placement::parse(&volume).unwrap().volmode.as_deref(),
        Some("full")
    );
    // A filesystem's, the fence's own, an unknown value, an unknown field.
    for tail in [
        r#""canmount":"on","volmode":"dev""#,
        r#""canmount":null,"volmode":"none""#,
        r#""canmount":null,"volmode":"geom2""#,
        r#""canmount":null,"mode":"dev""#,
    ] {
        let refused = format!(r#"{{"schema_version":1,{identity},"readonly":false,{tail}}}"#);
        assert!(Placement::parse(&refused).is_err(), "{refused}");
    }
}

/// `unpair` leaves the fenced side's saved placement on it. A leaf below it
/// that is paired later inherits that record from above; it is not the
/// leaf's and never wedges its activation.
#[test]
fn a_placement_inherited_from_above_the_leaf_never_blocks_a_leaf_switch() {
    let mut w = paired();
    let state = w.state();
    let root = zfs_tools::engine::management::Endpoint {
        name: "b".into(),
        identity: dataset(&state, "b").unwrap().identity.clone(),
    };
    let old = Placement::from_dataset(dataset(&state, "b").unwrap());
    let value = PropertyValue::Placement(old.clone()).encode(&root).unwrap();
    w.n()
        .set(
            &root,
            &[(management::PLACEMENT_PROPERTY.into(), value.clone())],
        )
        .unwrap();
    primary_now(&mut w, "b/data").unwrap();
    check_b_primary(&mut w);
    assert_eq!(
        w.t.native.effective("b")[management::PLACEMENT_PROPERTY].value,
        value,
        "the old root keeps its own record"
    );
}

/// An interrupted sync can be abandoned before its data is verified: the copy
/// stays fenced with what it received, and nothing of the sync remains to
/// hold the pool's operation slot. A later sync continues from there.
#[test]
fn an_interrupted_sync_abandons_before_verification_and_the_next_sync_continues() {
    let fenced = changed();
    let mountpoint = fenced.t.native.effective("b/data")["mountpoint"].clone();
    let (mut abandoned, mut refused) = (0, 0);
    for (mut w, record) in cut_worlds(
        changed,
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        |_| true,
    ) {
        // A cut inside the abandon itself: abandoning again finishes it.
        if abandoned % 5 == 0 {
            let mut probe = w.clone();
            let base = probe.effects();
            if resume_with(record.clone(), true, &mut Vec::new(), &mut probe).is_ok() {
                for n in 1..=probe.effects() - base {
                    for after in [false, true] {
                        let mut cut = w.clone();
                        cut.t.native.cut = Some((base + n, after));
                        assert!(
                            resume_with(record.clone(), true, &mut Vec::new(), &mut cut).is_err()
                        );
                        cut.restart();
                        for left in cut.records() {
                            resume_with(left, true, &mut Vec::new(), &mut cut).unwrap_or_else(
                                |e| panic!("abandon after its own cut {n}/{after}: {e}"),
                            );
                        }
                        assert!(cut.records().is_empty());
                        no_chunks(&cut);
                        assert!(cut.readonly("b/data") && !cut.mounted("b/data"));
                    }
                }
            }
        }
        let mut dialogue = Vec::new();
        match resume_with(record.clone(), true, &mut dialogue, &mut w) {
            Ok(_) => abandoned += 1,
            Err(error) => {
                assert!(error.to_string().contains("resume"), "{error}");
                refused += 1;
                resume_with(record, false, &mut Vec::new(), &mut w).unwrap();
                assert!(synced(&mut w));
                continue;
            }
        }
        assert!(w.records().is_empty());
        no_chunks(&w);
        no_split_brain(&mut w);
        let copy = w.t.native.effective("b/data");
        assert!(w.readonly("b/data") && !w.mounted("b/data"));
        assert_eq!(copy["canmount"].value, "noauto");
        assert_eq!(copy["mountpoint"], mountpoint);
        for marker in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
            for name in ["a/data", "b/data"] {
                assert!(
                    w.t.native
                        .effective(name)
                        .get(marker)
                        .is_none_or(|p| p.value != OP),
                    "{name} keeps {marker}"
                );
            }
        }
        assert!(
            w.t.native
                .holds
                .values()
                .flatten()
                .all(|tag| !tag.starts_with("zboot:transfer:")),
            "transfer holds remain"
        );
        assert_eq!(
            w.holds(&format!("zboot:anchor:{ID}")).len(),
            2,
            "anchors stay"
        );
        sync::sync_one(&sync_request(), RERUN, &[], &mut w).unwrap();
        assert!(synced(&mut w));
        check_pair(&mut w);
    }
    assert!(
        abandoned > 10 && refused > 0,
        "{abandoned} abandoned, {refused} refused"
    );
}

/// An interrupted bootstrap abandons too: the partial new copy stays fenced
/// in its receive container, which the message names, and a new sync starts
/// afresh under another ID.
#[test]
fn an_interrupted_bootstrap_abandons_and_leaves_its_container_fenced() {
    let mut abandoned = 0;
    for (mut w, record) in cut_worlds(
        || World::new(true),
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
        |_| true,
    ) {
        let mut dialogue = Vec::new();
        if resume_with(record.clone(), true, &mut dialogue, &mut w).is_err() {
            continue;
        }
        abandoned += 1;
        assert!(w.records().is_empty());
        no_chunks(&w);
        if is_paired(&mut w) {
            // The transfer had completed and published the pair; only the
            // sync's own record was left.
            continue;
        }
        let text = String::from_utf8(dialogue).unwrap();
        let state = w.state();
        for d in state
            .inspection
            .datasets
            .iter()
            .filter(|d| d.name.starts_with("b/zboot-receive-"))
        {
            assert!(text.contains("zfs destroy -r b/zboot-receive-"), "{text}");
            assert!(
                d.readonly && d.mounted != Some(true),
                "{} is not fenced",
                d.name
            );
        }
        assert!(w.record("a/data").is_none() && w.record("b/data").is_none());
        if state.inspection.datasets.iter().any(|d| d.name == "b/data") {
            // Renamed already: fenced, unpaired, without the operation's
            // markers. Pairing it continues from what it received.
            assert!(text.contains("zboot pair a/data b/data"), "{text}");
            assert!(w.readonly("b/data") && !w.mounted("b/data"));
            for marker in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
                assert!(
                    !w.t.native.effective("b/data").contains_key(marker),
                    "{marker}"
                );
            }
            let request = PairRequest {
                left: "a/data".into(),
                right: "b/data".into(),
                primary: Some(Side::Left),
            };
            link::pair_with(&request, SECOND, &mut w).unwrap();
        }
        sync::sync_one(&sync_request(), RERUN, &[], &mut w).unwrap();
        assert!(is_paired(&mut w));
    }
    assert!(abandoned > 5, "{abandoned}");
}

/// A takeover lists the target's snapshots its peer pruned, as a catch-up
/// does: afterwards the target's own retention may delete them unreviewed.
#[test]
fn a_takeover_lists_and_confirms_snapshots_its_peer_pruned() {
    let mut w = paired();
    // The working copy pruned its oldest snapshot; only b/data keeps it.
    let pruned = w
        .n()
        .members
        .iter_mut()
        .find(|m| m.endpoint.name == "a/data")
        .unwrap()
        .snapshots
        .remove(0);
    w.diverge("a/data", 900);
    w.diverge("b/data", 901);
    let plan = primary_plan_with(&w.state(), "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::Takeover);
    let names: Vec<_> = plan.unreviewed.iter().map(|p| p.name.as_str()).collect();
    let kept = pruned.name.replace("a/data", "b/data");
    assert_eq!(names, [kept.as_str()]);
    assert!(plan.confirms());
}

// ---- attachments of a live operation ----------------------------------------

/// The attachments `status` lists as orphaned, judged as `restore::list`
/// does: every local attachment whose id no live record carries, with what
/// its pool records.
fn orphaned_attachments(w: &mut World) -> Vec<crate::restore::Orphan> {
    let state = w.state();
    let records = intent::find(w)
        .unwrap()
        .into_iter()
        .map(|(pool, found)| match found {
            intent::Found::Record(r) => (pool, Some(r.id)),
            intent::Found::Unreadable(_) => (pool, None),
        })
        .collect();
    crate::restore::orphaned_attachments(
        state.dataset_properties.iter().flat_map(|(name, props)| {
            props
                .iter()
                .filter(|(_, p)| p.source == "local")
                .map(move |(key, _)| (name.as_str(), key.as_str()))
        }),
        &records,
    )
}

/// An interrupted sync, bootstrap or catch-up keeps its attachments under
/// its record's own id, inherited below their holder: they belong to the
/// live record through every cut, and a foreign attachment beside them, cut
/// before its commit and its record since ended, is still an orphan.
#[test]
fn a_live_operations_attachments_are_not_orphans() {
    fn through_every_cut(setup: fn() -> World, run: fn(&mut World) -> Result<(), Error>) {
        let worlds = cut_worlds(setup, run, |_| true);
        assert!(!worlds.is_empty());
        let mut attached = 0;
        for (mut w, record) in worlds {
            attached += w
                .state()
                .dataset_properties
                .values()
                .flat_map(|props| props.keys())
                .filter(|key| key.starts_with(attachment::PREFIX))
                .count();
            assert_eq!(
                orphaned_attachments(&mut w),
                Vec::new(),
                "step {}",
                record.step
            );
            let foreign = "77777777-7777-4777-8777-777777777777";
            w.n().properties.entry("a/data".into()).or_default().insert(
                format!("{}{foreign}:plan:0000", attachment::PREFIX),
                NativeProperty {
                    value: "00".into(),
                    source: "local".into(),
                },
            );
            // Pool a records nothing, or this operation, which never names it.
            let on_a = intent::find(&mut w)
                .unwrap()
                .into_iter()
                .any(|(pool, _)| pool == "a");
            assert_eq!(
                orphaned_attachments(&mut w),
                [crate::restore::Orphan {
                    dataset: "a/data".into(),
                    attachment: format!("{foreign}:plan"),
                    pool: "a".into(),
                    record: if on_a {
                        crate::restore::PoolRecord::Other(record.id.clone())
                    } else {
                        crate::restore::PoolRecord::Nothing
                    },
                }]
            );
        }
        assert!(attached > 0);
    }
    through_every_cut(
        || World::new(true),
        |w| sync::sync_one(&sync_request(), OP, &[], w).map(drop),
    );
    through_every_cut(changed, |w| {
        sync::sync_one(&sync_request(), OP, &[], w).map(drop)
    });
    through_every_cut(changed, |w| primary_now(w, "b/data").map(drop));
}

/// UKI pool access: each pair verb's plan names exactly the pools it writes.
#[test]
fn pair_verb_plans_name_exactly_the_pools_they_write() {
    use crate::cli::access::{plan_pools, tests::reopened};
    type Walk = Box<dyn Fn(&mut World) -> crate::cli::access::Named>;
    fn walked(plan: &impl Serialize) -> crate::cli::access::Named {
        plan_pools(&serde_json::to_value(plan).unwrap())
    }
    let between = SyncTarget::Between {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    let mut cases: Vec<(&[&str], World, Walk)> = vec![
        (
            &["pair", "a/data", "b/data"],
            World::new(false),
            Box::new(|w: &mut World| {
                let state = w.state();
                walked(&plan::plan_with(&state, &pair_request(), w).unwrap())
            }),
        ),
        (
            &["sync", "a/data", "b/data"],
            changed(),
            Box::new(move |w: &mut World| walked(&sync_plan_with(&between, w).unwrap())),
        ),
        (
            &["sync", "a/data"],
            changed(),
            Box::new(|w: &mut World| walked(&sync_plan_with(&pair_target(), w).unwrap())),
        ),
        (
            &["sync", "--all"],
            with_second_pair(changed()),
            Box::new(|w: &mut World| walked(&sync_plan_with(&SyncTarget::All, w).unwrap())),
        ),
        (
            &["primary", "b/data"],
            changed(),
            Box::new(|w: &mut World| {
                let state = w.state();
                walked(&primary_plan_with(&state, "b/data", w).unwrap())
            }),
        ),
        (
            &["unpair", "a/data"],
            paired(),
            Box::new(|w: &mut World| {
                walked(&unpair_plan_with(&w.state(), "a/data", false).unwrap())
            }),
        ),
        (
            &["unpair", "a/data", "--release-anchors"],
            paired(),
            Box::new(|w: &mut World| {
                walked(&unpair_plan_with(&w.state(), "a/data", true).unwrap())
            }),
        ),
    ];
    // A bootstrap sync names the absent destination's parent.
    let absent = SyncTarget::Between {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    cases.push((
        &["sync", "a/data", "b/data"],
        World::new(true),
        Box::new(move |w: &mut World| walked(&sync_plan_with(&absent, w).unwrap())),
    ));
    for (args, mut w, plan) in cases {
        let state = w.state();
        let walked = plan(&mut w);
        assert_eq!(reopened(&state, walked), ["a", "b"], "{args:?}");
        assert_eq!(w.effects(), 0);
    }
}

/// A one-sided unpair and a dead-peer primary leave a live peer that no
/// longer reciprocates as it is: its pool is not reopened in the UKI.
#[test]
fn a_peer_left_as_it_is_is_never_reopened() {
    use crate::cli::access::{plan_pools, tests::reopened};
    let mut w = paired();
    w.n()
        .properties
        .get_mut("b/data")
        .unwrap()
        .remove(management::PAIR_PROPERTY);
    let state = w.state();
    let plan = unpair_plan_with(&state, "a/data", false).unwrap();
    assert!(plan.one_sided);
    assert_eq!(
        reopened(&state, plan_pools(&serde_json::to_value(&plan).unwrap())),
        ["a"]
    );
    let mut w = paired();
    w.n()
        .properties
        .get_mut("a/data")
        .unwrap()
        .remove(management::PAIR_PROPERTY);
    let state = w.state();
    let plan = primary_plan_with(&state, "b/data", &mut w).unwrap();
    assert_eq!(plan.mode, PrimaryMode::DeadPeer);
    assert_eq!(
        reopened(&state, plan_pools(&serde_json::to_value(&plan).unwrap())),
        ["b"]
    );
}
