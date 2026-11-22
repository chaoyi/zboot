//! UKI pool access for menu, shell and SSH invocations alike.
//!
//! A command plans on the read-only pools. Under its writer lock, after the
//! answer, it reopens writable the pools its plan names, and its close returns
//! them to read-only before that lock goes. The menu's displayed identities
//! are checked at entry and again under the lock.
use super::grammar::Verb;
use crate::menu::{RecoveryError, Result, pool_access};
use std::collections::{BTreeMap, BTreeSet};
use zfs_tools::engine::{DatasetIdentity, Guid, intent, pool_of, state::NativeState};

fn refuse(message: impl Into<String>) -> RecoveryError {
    RecoveryError::Refused(message.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Env {
    Host,
    Uki,
}
impl Env {
    /// The UKI's own command-line marker decides. A UKI whose RAM proof fails
    /// stays the UKI: its native effects refuse, and it never gets host rules.
    pub(crate) fn detect() -> Self {
        if crate::handoff::uki_marker() {
            Self::Uki
        } else {
            Self::Host
        }
    }

    pub(crate) fn admit(self, command: &Verb) -> Result<()> {
        match (self, command) {
            (Self::Host, Verb::Boot { .. } | Verb::Menu { .. }) => {
                let mut reason = "boot and menu require the zboot UKI".to_owned();
                if let Err(error) = crate::handoff::prove_ram() {
                    reason.push_str(&format!(". {error}"));
                }
                Err(refuse(reason))
            }
            (Self::Uki, Verb::Reboot { .. }) => Err(refuse(
                "reboot --menu requires a running host; use reboot at the menu",
            )),
            (Self::Uki, Verb::Factory { .. } | Verb::FactoryFinish { .. }) => Err(refuse(
                "factory runs on a running system, not in the zboot UKI",
            )),
            _ => Ok(()),
        }
    }
}

/// How a command finds, at its lock, the pools it reopens writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reopen {
    /// The host, a read-only verb, or one whose disk scope exports instead.
    Nothing,
    /// The pools its plan names.
    Plan,
    /// An interrupted operation's, from its record: [`operation_pools`].
    Operation { abandon: bool },
    /// chroot's BE pool, under a brief lock around the reopen and the close.
    Chroot,
}
impl Reopen {
    fn of(env: Env, command: &Verb) -> Self {
        if env == Env::Host {
            return Self::Nothing;
        }
        match command {
            Verb::Resume { .. } => Self::Operation { abandon: false },
            Verb::Abandon { .. } => Self::Operation { abandon: true },
            Verb::Chroot { .. } => Self::Chroot,
            Verb::Snapshot { .. }
            | Verb::Fork { .. }
            | Verb::Rename { .. }
            | Verb::Rollback { .. }
            | Verb::Drop { .. }
            | Verb::Pair { .. }
            | Verb::Primary { .. }
            | Verb::Unpair { .. }
            | Verb::Sync { .. }
            | Verb::Default { .. }
            | Verb::Cmdline { .. }
            | Verb::Restore { .. }
            | Verb::Deploy { into: Some(_), .. } => Self::Plan,
            _ => Self::Nothing,
        }
    }
}

/// The native identities a menu line was resolved against: the datasets its
/// numbers named, as displayed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Bindings {
    pub(crate) datasets: Vec<(String, DatasetIdentity)>,
}
impl Bindings {
    const fn new() -> Self {
        Self {
            datasets: Vec::new(),
        }
    }

    fn check(&self) -> Result<()> {
        if self.datasets.is_empty() {
            return Ok(());
        }
        self.check_state(&zfs_tools::engine::state::observe()?)
    }

    /// Every displayed dataset is still that native incarnation.
    pub(crate) fn check_state(&self, observed: &NativeState) -> Result<()> {
        for (name, expected) in &self.datasets {
            if observed
                .inspection
                .datasets
                .iter()
                .find(|d| &d.name == name)
                .is_none_or(|d| &d.identity != expected)
            {
                return Err(refuse(format!(
                    "{} changed since it was displayed; run status or rescan",
                    zfs_tools::engine::escape_display(name)
                )));
            }
        }
        Ok(())
    }
}

/// One invocation's pool access: the menu's displayed identities, how its
/// pools are found at the lock, and the pools it reopened.
pub(crate) struct Access {
    reopen: Reopen,
    bindings: Bindings,
    writable: pool_access::Writable,
}
impl Default for Access {
    fn default() -> Self {
        Self::new()
    }
}
impl Access {
    pub(crate) const fn new() -> Self {
        Self {
            reopen: Reopen::Nothing,
            bindings: Bindings::new(),
            writable: pool_access::Writable::new(),
        }
    }

    pub(crate) fn of(env: Env, command: &Verb, bindings: Bindings) -> Self {
        Self {
            reopen: Reopen::of(env, command),
            bindings,
            writable: pool_access::Writable::new(),
        }
    }

    /// The displayed identities against one fresh observation: at entry, for
    /// an early refusal, and again under the writer lock before any effect.
    pub(crate) fn check(&self) -> Result<()> {
        self.bindings.check()
    }

    /// Whether the pools to reopen come from the command's plan.
    pub(crate) fn reopens_plan(&self) -> bool {
        self.reopen == Reopen::Plan
    }

    /// Under the writer lock: reopen writable the pools `plan` names.
    pub(crate) fn open(&mut self, plan: &impl serde::Serialize) -> Result<()> {
        if !matches!(self.reopen, Reopen::Plan | Reopen::Operation { .. }) {
            return Ok(());
        }
        let plan = serde_json::to_value(plan)
            .map_err(|e| refuse(format!("the plan cannot be inspected: {e}")))?;
        let observed = zfs_tools::engine::state::observe()?;
        let named = match self.reopen {
            Reopen::Operation { abandon } => {
                let id = plan
                    .get("id")
                    .and_then(|id| id.as_str())
                    .ok_or_else(|| refuse("the operation plan names no operation id"))?;
                operation_pools(&observed, id, abandon)?
            }
            _ => plan_pools(&plan),
        };
        self.open_pools(&observed, named)
    }

    /// chroot runs a session and takes no writer lock: its BE's pool is
    /// reopened under a brief one, after the displayed identities are checked.
    pub(crate) fn open_chroot(&mut self, dataset: &str) -> Result<()> {
        if self.reopen != Reopen::Chroot {
            return Ok(());
        }
        let _lock = brief_lock("chroot pool reopen")?;
        self.check()?;
        let observed = zfs_tools::engine::state::observe()?;
        let mut named = Named::default();
        named.pools.extend(named_pool(&observed, dataset));
        self.open_pools(&observed, named)
    }

    fn open_pools(&mut self, observed: &NativeState, named: Named) -> Result<()> {
        let pools = imported(observed, named);
        if pools.is_empty() {
            return Ok(());
        }
        crate::menu::hostid_adopt::require_no_image()?;
        self.writable.open(&pools)
    }

    /// Return every reopened pool to read-only, by GUID. A pool the command
    /// exported stays exported. Retryable; it never imports a replaced GUID.
    pub(crate) fn close(&mut self) -> Result<()> {
        if self.writable.is_empty() {
            return Ok(());
        }
        let _lock = (self.reopen == Reopen::Chroot)
            .then(|| brief_lock("chroot pool cleanup"))
            .transpose()?;
        self.writable.close()
    }
}

fn brief_lock(purpose: &str) -> Result<Option<zfs_tools::engine::lock::WriterLock>> {
    crate::menu::after_imports(|| {
        zfs_tools::engine::lock::for_command("zboot", purpose).map_err(|e| refuse(e.to_string()))
    })
}

/// What a plan names: pools by GUID, and datasets by native identity. A
/// dataset's pool counts only while that exact incarnation is imported: a
/// record or a one-sided plan can name a peer that is gone or replaced.
#[derive(Debug, Default)]
pub(crate) struct Named {
    pools: BTreeSet<(String, Guid)>,
    datasets: Vec<(String, DatasetIdentity)>,
    spared: BTreeSet<Guid>,
}
impl Named {
    /// Every pool named, imported or not.
    #[cfg(test)]
    pub(crate) fn pools(&self) -> BTreeSet<(String, Guid)> {
        self.pools
            .iter()
            .cloned()
            .chain(
                self.datasets
                    .iter()
                    .map(|(name, identity)| (pool_of(name).to_owned(), identity.pool_guid)),
            )
            .filter(|(_, guid)| !self.spared.contains(guid))
            .collect()
    }
}

/// The pools and datasets a plan names: every `{name, identity}`, every
/// pool-level `{name, guid}` and every `{pool, new_pool}`. A pair ownership
/// is evidence about a peer, not a write to it. A restore writes its old pool
/// only to snapshot kept trees, so a plan whose `old_pool` keeps nothing
/// spares that GUID.
pub(crate) fn plan_pools(plan: &serde_json::Value) -> Named {
    fn walk(value: &serde_json::Value, named: &mut Named) {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    walk(value, named);
                }
            }
            serde_json::Value::Object(fields) => {
                if fields.contains_key("role") && fields.contains_key("record") {
                    return;
                }
                if let Some(name) = fields.get("name").and_then(|v| v.as_str()) {
                    let pool = name.split(['/', '@', '#']).next().unwrap();
                    let identity = fields.get("identity");
                    if let Some(identity) = identity.filter(|_| !name.contains(['@', '#'])) {
                        if let Ok(identity) = serde_json::from_value(identity.clone()) {
                            named.datasets.push((name.into(), identity));
                        }
                    } else if let Some(guid) = identity
                        .and_then(|v| v.get("pool_guid"))
                        .or_else(|| {
                            (!name.contains(['/', '@', '#']))
                                .then(|| fields.get("guid"))
                                .flatten()
                        })
                        .and_then(guid_value)
                    {
                        named.pools.insert((pool.into(), guid));
                    }
                }
                if let (Some(pool), Some(guid)) = (
                    fields.get("pool").and_then(|v| v.as_str()),
                    fields.get("new_pool").and_then(guid_value),
                ) {
                    named.pools.insert((pool.into(), guid));
                }
                if let Some(old) = fields
                    .get("old_pool")
                    .and_then(|v| v.get("guid"))
                    .and_then(guid_value)
                    && fields
                        .get("keep")
                        .and_then(|keep| keep.as_array())
                        .is_none_or(Vec::is_empty)
                {
                    named.spared.insert(old);
                }
                // A one-sided unpair and a dead-peer primary (plan or record)
                // name a peer they leave as it is.
                let left_alone = |key: &str| match key {
                    "record" => fields.get("one_sided") == Some(&serde_json::Value::Bool(true)),
                    "peer" => fields.get("mode").and_then(|v| v.as_str()) == Some("dead-peer"),
                    _ => false,
                };
                for (key, value) in fields {
                    if !left_alone(key) {
                        walk(value, named);
                    }
                }
            }
            _ => {}
        }
    }
    let mut named = Named::default();
    walk(plan, &mut named);
    named
}

/// What an interrupted operation writes: the pool holding its record, what
/// its record names, and for a sync the destination's pool by the GUID its
/// record gives it. Abandoning a restore never writes its old pool.
pub(crate) fn operation_pools(observed: &NativeState, id: &str, abandon: bool) -> Result<Named> {
    let mut named = Named::default();
    for (pool, found) in intent::find(&mut Observed(observed))? {
        let intent::Found::Record(record) = found else {
            continue;
        };
        if record.id != id {
            continue;
        }
        let mut state = record.state.clone();
        if record.kind == "restore"
            && abandon
            && let Some(fields) = state.as_object_mut()
        {
            fields.insert("keep".into(), serde_json::json!([]));
        }
        named = plan_pools(&state);
        named.pools.extend(named_pool(observed, &pool));
        if record.kind == "sync"
            && let Some(destination) = state.get("destination").and_then(|v| v.as_str())
        {
            // A sync record without it was written by an earlier zboot.
            let recorded = state
                .get("destination_pool")
                .and_then(guid_value)
                .ok_or_else(|| refuse(intent::earlier("sync", id)))?;
            let pool = pool_of(destination);
            match named_pool(observed, pool).map(|(_, guid)| guid) {
                Some(guid) if guid == recorded => {
                    named.pools.insert((pool.into(), guid));
                }
                // A pool that is gone stays the engine's to report. Abandon
                // never writes a destination it cannot identify.
                None => {}
                Some(_) if abandon => {}
                Some(_) => {
                    return Err(refuse(format!(
                        "pool {} is no longer the one sync {id} recorded for {}; nothing was reopened",
                        zfs_tools::engine::escape_display(pool),
                        zfs_tools::engine::escape_display(destination)
                    )));
                }
            }
        }
    }
    Ok(named)
}

/// The imported pools a plan made again under the lock names that the
/// reviewed plan did not: none of them would be reopened for it.
pub(crate) fn unreviewed_pools(
    planned: &impl serde::Serialize,
    fresh: &impl serde::Serialize,
) -> Result<Vec<String>> {
    let json = |plan: serde_json::Result<serde_json::Value>| {
        plan.map_err(|e| refuse(format!("the plan cannot be inspected: {e}")))
    };
    Ok(added_pools(
        &zfs_tools::engine::state::observe()?,
        &json(serde_json::to_value(planned))?,
        &json(serde_json::to_value(fresh))?,
    ))
}

fn added_pools(
    observed: &NativeState,
    planned: &serde_json::Value,
    fresh: &serde_json::Value,
) -> Vec<String> {
    let reviewed = imported(observed, plan_pools(planned));
    imported(observed, plan_pools(fresh))
        .into_iter()
        .filter(|(name, guid)| reviewed.get(name) != Some(guid))
        .map(|(name, _)| name)
        .collect()
}

/// The pool imported now under the pool name of `name`, with its GUID.
pub(crate) fn named_pool(observed: &NativeState, name: &str) -> Option<(String, Guid)> {
    let pool = pool_of(name);
    observed
        .inspection
        .pools
        .iter()
        .find(|p| p.name == pool)
        .map(|p| (p.name.clone(), p.guid))
}

/// The pools of `named` imported now under that name and GUID, and those
/// holding a named dataset as that exact incarnation. The others are gone or
/// replaced: a record can retain an erased pool or an absent peer, and the
/// owning engine admits those itself.
pub(crate) fn imported(observed: &NativeState, named: Named) -> BTreeMap<String, Guid> {
    let live_dataset = |name: &str, identity: &DatasetIdentity| {
        observed
            .inspection
            .datasets
            .iter()
            .any(|d| d.name == name && &d.identity == identity)
    };
    let live_datasets: BTreeSet<_> = named
        .datasets
        .iter()
        .filter(|(name, identity)| live_dataset(name, identity))
        .map(|(name, identity)| (pool_of(name).to_owned(), identity.pool_guid))
        .collect();
    named
        .pools
        .into_iter()
        .chain(live_datasets)
        .filter(|(name, guid)| {
            !named.spared.contains(guid)
                && observed
                    .inspection
                    .pools
                    .iter()
                    .any(|p| &p.name == name && p.guid == *guid)
        })
        .collect()
}

fn guid_value(value: &serde_json::Value) -> Option<Guid> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|v| v.parse().ok()))
        .map(Guid::new)
}

fn operation_property<'a>(state: &'a NativeState, pool: &str) -> Option<&'a str> {
    state
        .dataset_properties
        .get(pool)?
        .get(intent::PROPERTY)
        .filter(|p| p.source == "local")
        .map(|p| p.value.as_str())
}

/// Decode through the same intent reader as native execution, without I/O.
struct Observed<'a>(&'a NativeState);
impl intent::Backend for Observed<'_> {
    fn pools(&mut self) -> std::result::Result<Vec<String>, zfs_tools::engine::Error> {
        Ok(self
            .0
            .inspection
            .pools
            .iter()
            .map(|p| p.name.clone())
            .collect())
    }
    fn read(
        &mut self,
        pool: &str,
    ) -> std::result::Result<Option<String>, zfs_tools::engine::Error> {
        Ok(operation_property(self.0, pool).map(str::to_owned))
    }
    fn write(&mut self, _: &str, _: &str) -> std::result::Result<(), zfs_tools::engine::Error> {
        Err(zfs_tools::engine::Error::Inconsistent(
            "observation cannot write an intent".into(),
        ))
    }
    fn remove(&mut self, _: &str) -> std::result::Result<(), zfs_tools::engine::Error> {
        Err(zfs_tools::engine::Error::Inconsistent(
            "observation cannot remove an intent".into(),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        cli::grammar::Cli,
        tree::{Backend, fake::Fake},
    };
    use zfs_tools::engine::management;

    fn command(args: &[&str]) -> Verb {
        Cli::parse_from_args(std::iter::once("zboot").chain(args.iter().copied()))
            .unwrap()
            .command
    }

    fn fixture() -> Fake {
        let mut fake = Fake::new();
        for name in ["a/ROOT", "a/ROOT/be", "b/ROOT", "b/ROOT/be"] {
            fake.create(name);
        }
        fake
    }

    /// The pools a command reopens, of those its plan names: the ones
    /// imported now under that name and GUID.
    pub(crate) fn reopened(observed: &NativeState, named: Named) -> Vec<String> {
        imported(observed, named).into_keys().collect()
    }

    fn recorded(state: &NativeState, id: &str, abandon: bool) -> Result<Named> {
        operation_pools(state, id, abandon)
    }

    fn walked(plan: &impl serde::Serialize) -> Named {
        plan_pools(&serde_json::to_value(plan).unwrap())
    }

    #[test]
    fn boot_and_menu_are_refused_outside_the_uki() {
        for args in [&["boot"][..], &["menu"]] {
            let command = command(args);
            assert!(Env::Host.admit(&command).is_err());
            Env::Uki.admit(&command).unwrap();
        }
        let factory = command(&["factory", "/tmp/root.tar"]);
        assert!(Env::Uki.admit(&factory).is_err());
        Env::Host.admit(&factory).unwrap();
        let reboot = command(&["reboot", "--menu"]);
        assert!(Env::Uki.admit(&reboot).is_err());
        Env::Host.admit(&reboot).unwrap();
    }

    #[test]
    fn boot_and_menu_refusals_include_the_actual_ram_admission_failure() {
        let proof_error = crate::handoff::prove_ram()
            .err()
            .map(|error| error.to_string());
        for args in [&["boot"][..], &["menu"]] {
            let error = Env::Host.admit(&command(args)).unwrap_err().to_string();
            assert!(error.starts_with("boot and menu require the zboot UKI"));
            if let Some(reason) = &proof_error {
                assert!(error.ends_with(reason), "{error}");
            }
        }
        Env::Host.admit(&command(&["status"])).unwrap();
        Env::Host.admit(&command(&["sync", "a/ROOT/be"])).unwrap();
    }

    #[test]
    fn only_writing_verbs_in_the_uki_reopen_pools() {
        for args in [
            &["drop", "a/ROOT/be"][..],
            &["snapshot", "a/ROOT/be"],
            &["sync", "--all"],
            &["default", "a/ROOT/be"],
            &["restore", "a/ROOT/be@s", "/dev/sdz"],
            &["deploy", "into", "a", "--tar", "/root.tar"],
        ] {
            assert_eq!(
                Reopen::of(Env::Uki, &command(args)),
                Reopen::Plan,
                "{args:?}"
            );
            assert_eq!(Reopen::of(Env::Host, &command(args)), Reopen::Nothing);
        }
        assert_eq!(
            Reopen::of(Env::Uki, &command(&["resume"])),
            Reopen::Operation { abandon: false }
        );
        assert_eq!(
            Reopen::of(Env::Uki, &command(&["abandon"])),
            Reopen::Operation { abandon: true }
        );
        assert_eq!(
            Reopen::of(Env::Uki, &command(&["chroot", "a/ROOT/be"])),
            Reopen::Chroot
        );
        // A whole-disk verb exports its disk's pools instead.
        for args in [
            &["wipe", "/dev/sdz"][..],
            &["deploy", "/dev/sdz", "--tar", "/root.tar"],
            &["status"],
            &["boot", "a/ROOT/be"],
            &["esp", "/dev/sdz1"],
        ] {
            assert_eq!(
                Reopen::of(Env::Uki, &command(args)),
                Reopen::Nothing,
                "{args:?}"
            );
        }
    }

    #[test]
    fn tree_plans_name_exactly_the_pools_they_write() {
        let mut fake = fixture();
        fake.set("a/ROOT/be", "mountpoint", "/");
        fake.set("a/ROOT/be", "canmount", "noauto");
        fake.snap("a/ROOT/be@base");
        fake.write("a/ROOT/be");
        let state = fake.observe().unwrap();
        let drop = crate::tree::discard::plan_with(&mut fake, &["a/ROOT/be".into()]).unwrap();
        let rollback = crate::tree::rollback::plan_with(&mut fake, "a/ROOT/be@base").unwrap();
        let rename =
            crate::tree::rename::plan_with(&mut fake, "a/ROOT/be", "a/ROOT/renamed").unwrap();
        let fork = crate::tree::fork::plan_with(&mut fake, "a/ROOT/be@base", "a/ROOT/new").unwrap();
        let snapshot =
            super::super::trees::snapshot_plan(&state, &["a/ROOT/be@new".into()]).unwrap();
        for plan in [
            walked(&drop),
            walked(&rollback),
            walked(&rename),
            walked(&fork),
            walked(&snapshot),
            // chroot names no plan: it reopens the pool of its BE.
            Named {
                pools: named_pool(&state, "a/ROOT/be").into_iter().collect(),
                ..Named::default()
            },
        ] {
            assert_eq!(reopened(&state, plan), ["a"]);
        }
    }

    #[test]
    fn a_restore_that_keeps_nothing_never_names_its_old_pool() {
        let old = serde_json::json!({"name": "b", "guid": 2});
        let source = serde_json::json!({"name": "a/ROOT/be@s", "identity": {"pool_guid": 1}});
        let bare = serde_json::json!({"old_pool": old, "keep": [], "pool": "b", "source": source});
        let kept =
            serde_json::json!({"old_pool": old, "keep": [{"relative": "data"}], "source": source});
        let names = |plan| {
            plan_pools(&plan)
                .pools()
                .into_iter()
                .map(|(name, guid)| (name, guid.get()))
                .collect::<Vec<_>>()
        };
        assert_eq!(names(bare.clone()), [("a".to_owned(), 1)]);
        assert_eq!(names(kept), [("a".to_owned(), 1), ("b".to_owned(), 2)]);
        // A plan nests the record's state; the rule holds there too.
        assert_eq!(
            names(serde_json::json!({"state": bare})),
            [("a".to_owned(), 1)]
        );
    }

    #[test]
    fn a_plan_made_again_that_names_another_pool_is_seen_before_any_reopen() {
        let mut fake = fixture();
        let state = fake.observe().unwrap();
        let endpoint =
            |name: &str| serde_json::json!({"name": name, "identity": fake.identity(name)});
        let reviewed = serde_json::json!({"trees": [endpoint("a/ROOT/be")]});
        let same =
            serde_json::json!({"trees": [endpoint("a/ROOT/be")], "extra": [endpoint("a/ROOT")]});
        assert!(added_pools(&state, &reviewed, &same).is_empty());
        let wider = serde_json::json!({"trees": [endpoint("a/ROOT/be"), endpoint("b/ROOT/be")]});
        assert_eq!(added_pools(&state, &reviewed, &wider), ["b"]);
        assert!(added_pools(&state, &wider, &reviewed).is_empty());
    }

    #[test]
    fn a_pair_ownership_or_a_replaced_peer_reopens_nothing() {
        let mut fake = fixture();
        let state = fake.observe().unwrap();
        let endpoint =
            |name: &str| serde_json::json!({"name": name, "identity": fake.identity(name)});
        let mut stale = endpoint("b/ROOT/be");
        stale["identity"]["guid"] = serde_json::to_value(Guid::new(999)).unwrap();
        let record = serde_json::json!({
            "pair_id": "11111111-1111-4111-8111-111111111111",
            "endpoint": endpoint("a/ROOT/be"), "peer": endpoint("b/ROOT/be"), "role": "primary",
        });
        // cmdline's plan keeps its BE's ownership as evidence, not a write.
        let cmdline = serde_json::json!({
            "dataset": "a/ROOT/be", "scope": [endpoint("a/ROOT/be")],
            "owner": {"role": "primary", "record": record},
        });
        assert_eq!(reopened(&state, plan_pools(&cmdline)), ["a"]);
        // A one-sided unpair names a peer that is gone or another dataset now.
        let mut replaced = record.clone();
        replaced["peer"] = stale;
        let unpair = serde_json::json!({
            "dataset": endpoint("a/ROOT/be"), "record": replaced, "one_sided": true,
        });
        assert_eq!(reopened(&state, plan_pools(&unpair)), ["a"]);
        // A two-sided unpair writes its live peer.
        let unpair = serde_json::json!({
            "dataset": endpoint("a/ROOT/be"), "record": record, "one_sided": false,
        });
        assert_eq!(reopened(&state, plan_pools(&unpair)), ["a", "b"]);
    }

    #[test]
    fn an_anchor_release_names_the_former_peer_after_a_plain_unpair() {
        let mut fake = fixture();
        for name in ["a/ROOT/be", "b/ROOT/be"] {
            fake.snap(&format!("{name}@base"));
            fake.snapshots
                .get_mut(&format!("{name}@base"))
                .unwrap()
                .holds
                .insert("zboot:anchor:11111111-1111-4111-8111-111111111111".into());
        }
        let state = fake.observe().unwrap();
        let plan = crate::pairs::unpair_plan_with(&state, "a/ROOT/be", true).unwrap();
        assert_eq!(reopened(&state, walked(&plan)), ["a", "b"]);
    }

    #[test]
    fn an_operation_reopens_its_record_pool_and_only_matching_recorded_guids() {
        let mut fake = fixture();
        let id = "11111111-1111-4111-8111-111111111111";
        let record = |keep: serde_json::Value| {
            intent::Intent::new(
                id,
                "restore",
                serde_json::json!({
                    "pool": "b", "new_pool": "2", "old_pool": {"name":"b","guid":"999"},
                    "source":{"name":"a/ROOT/be","identity":fake.identity("a/ROOT/be")},
                    "unbound_name":"unrelated/data", "keep": keep,
                }),
            )
        };
        let record = record(serde_json::json!([]));
        fake.set("a", intent::PROPERTY, &intent::encode(&record).unwrap());
        let state = fake.observe().unwrap();
        for abandon in [false, true] {
            assert_eq!(
                reopened(&state, recorded(&state, id, abandon).unwrap()),
                ["a", "b"]
            );
        }
        assert!(
            recorded(&state, "22222222-2222-4222-8222-222222222222", false)
                .unwrap()
                .pools()
                .is_empty()
        );
        // Kept trees on the old pool reopen it for a resume, never an abandon.
        let mut kept = record;
        kept.state["old_pool"]["guid"] = serde_json::json!("2");
        kept.state["new_pool"] = serde_json::Value::Null;
        kept.state["keep"] = serde_json::json!([{"relative": "data"}]);
        fake.set("a", intent::PROPERTY, &intent::encode(&kept).unwrap());
        let state = fake.observe().unwrap();
        assert_eq!(
            reopened(&state, recorded(&state, id, false).unwrap()),
            ["a", "b"]
        );
        assert_eq!(reopened(&state, recorded(&state, id, true).unwrap()), ["a"]);
    }

    #[test]
    fn displayed_identities_are_checked_against_native_state() {
        let mut fake = fixture();
        let state = fake.observe().unwrap();
        let bindings = Bindings {
            datasets: vec![("a/ROOT/be".into(), fake.identity("a/ROOT/be"))],
        };
        bindings.check_state(&state).unwrap();
        let mut replaced = fake.clone();
        replaced.datasets.get_mut("a/ROOT/be").unwrap().guid += 1;
        let error = bindings
            .check_state(&replaced.observe().unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("a/ROOT/be changed since it was displayed"),
            "{error}"
        );
        let mut gone = fake.clone();
        gone.datasets.remove("a/ROOT/be");
        assert!(bindings.check_state(&gone.observe().unwrap()).is_err());
    }

    /// A sync record from apool/BE/be1 into DESTINATION, naming POOL's GUID
    /// as its destination's pool (none: as an earlier zboot wrote it). Its
    /// transfer has verified the copy, and names its plan on the source, the
    /// copy and, bootstrapping, its receive container, each with the
    /// identity the record's pools gave them.
    fn sync_record(state: &mut NativeState, destination: &str, pool: Option<Guid>) -> &'static str {
        let id = "11111111-1111-4111-8111-111111111111";
        let identity = |name: &str| {
            state
                .inspection
                .datasets
                .iter()
                .find(|d| d.name == name)
                .map(|d| d.identity.clone())
        };
        let origin = management::Endpoint {
            name: "apool/BE/be1".into(),
            identity: identity("apool/BE/be1").unwrap(),
        };
        let bootstrap = !destination.ends_with("be1");
        let mut transfer =
            crate::transfer::widest(id, &origin.name, destination, bootstrap).unwrap();
        use zfs_tools::engine::attachment::{Attachment, Key};
        let named = |slot| Attachment::widest(&Key::new(id, slot).unwrap(), origin.clone());
        transfer.plan = Some(named("plan"));
        transfer.pair = bootstrap.then(|| named("pair"));
        let on_destination_pool = |endpoint: &mut management::Endpoint| {
            if let Some(found) = identity(&endpoint.name) {
                endpoint.identity = found;
            }
            if let Some(pool) = pool {
                endpoint.identity.pool_guid = pool;
            }
        };
        on_destination_pool(&mut transfer.received.as_mut().unwrap().endpoint);
        if let Some(container) = transfer.receive.container.as_mut() {
            on_destination_pool(container);
        }
        let mut fields = serde_json::json!({
            "source":"apool/BE/be1", "destination":destination,
            "bootstrap":bootstrap, "origin":origin, "transfer":transfer,
        });
        if let Some(pool) = pool {
            fields["destination_pool"] = serde_json::to_value(pool).unwrap();
        }
        let record = intent::Intent::new(id, "sync", fields);
        state.dataset_properties.get_mut("apool").unwrap().insert(
            intent::PROPERTY.into(),
            zfs_tools::engine::native::NativeProperty {
                value: intent::encode(&record).unwrap(),
                source: "local".into(),
            },
        );
        id
    }

    /// The record alone binds the destination's pool: a pair record, the
    /// endpoints of the transfer it records or an absent destination change
    /// nothing.
    #[test]
    fn a_sync_resume_takes_its_destination_pool_from_its_record() {
        for destination in ["bpool/BE/be1", "bpool/BE/new"] {
            let mut state =
                crate::boot_support::tests::paired_bes("apool/BE/be1", "bpool/BE/be1", &[]);
            let bpool = named_pool(&state, "bpool").unwrap().1;
            let id = sync_record(&mut state, destination, Some(bpool));
            for abandon in [false, true] {
                assert_eq!(
                    reopened(&state, recorded(&state, id, abandon).unwrap()),
                    ["apool", "bpool"],
                    "{destination} {abandon}"
                );
            }
            // The destination's pool name now belongs to another GUID: resume
            // refuses with nothing reopened, and abandon leaves that pool alone.
            sync_record(&mut state, destination, Some(Guid::new(bpool.get() + 1)));
            let error = recorded(&state, id, false).unwrap_err().to_string();
            assert!(error.contains("no longer the one sync"), "{error}");
            assert_eq!(
                reopened(&state, recorded(&state, id, true).unwrap()),
                ["apool"]
            );
            // A record without the destination's pool is an earlier zboot's.
            sync_record(&mut state, destination, None);
            for abandon in [false, true] {
                let error = recorded(&state, id, abandon).unwrap_err().to_string();
                assert!(
                    error.contains(&intent::earlier("sync", id)),
                    "{destination} {abandon}: {error}"
                );
            }
        }
    }
}
