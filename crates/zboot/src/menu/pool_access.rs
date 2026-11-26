//! Writable access to the read-only recovery pools a command needs.
//!
//! The UKI imports every pool read-only. A command that writes reopens only
//! the pools its plan names, by GUID, and returns them to read-only when it
//! ends. The guard has an explicit close operation; there is deliberately no
//! `Drop` cleanup because recovery must surface a failed final export/import
//! instead of hiding it.

use super::{RecoveryError, Result};
use crate::handoff::prove_ram;
use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
};
use zfs_tools::engine::{DatasetKind, Guid, state, state::NativeState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolBinding {
    pub name: String,
    pub guid: Guid,
}

pub trait Backend {
    fn prove_ram(&mut self) -> Result<()>;
    fn observe(&mut self) -> Result<NativeState>;
    fn export(&mut self, pool: &str) -> Result<()>;
    fn import(&mut self, guid: Guid, readonly: bool) -> Result<()>;
}

struct NativeBackend;

impl Backend for NativeBackend {
    fn prove_ram(&mut self) -> Result<()> {
        prove_ram()
    }

    fn observe(&mut self) -> Result<NativeState> {
        Ok(state::observe()?)
    }

    fn export(&mut self, pool: &str) -> Result<()> {
        prove_ram()?;
        native_command(&export_args(pool))
    }

    fn import(&mut self, guid: Guid, readonly: bool) -> Result<()> {
        prove_ram()?;
        native_command(&import_args(guid, readonly))
    }
}

fn refuse(message: impl Into<String>) -> RecoveryError {
    RecoveryError::Refused(message.into())
}

pub fn native_command(args: &[String]) -> Result<()> {
    let mutates = command_mutates(args, |pool| {
        let properties = zfs_tools::engine::native::pool_properties_with(
            &[pool.to_owned()],
            zfs_tools::engine::native::run,
        )?;
        match properties
            .get(pool)
            .and_then(|properties| properties.get("readonly"))
            .map(|property| property.value.as_str())
        {
            Some("on") => Ok(true),
            Some("off") => Ok(false),
            _ => Err(refuse(format!(
                "selected pool readonly property was not observed: {pool}"
            ))),
        }
    })?;
    let child = zfs_tools::engine::native::announced(
        Command::new("/sbin/zpool")
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .spawn()?;
    if mutates {
        zfs_tools::engine::effect::mark();
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(RecoveryError::Command {
            program: "/sbin/zpool".into(),
            detail: format!(
                "status={}; {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(())
}

fn command_mutates(args: &[String], readonly: impl FnOnce(&str) -> Result<bool>) -> Result<bool> {
    match args {
        [command, pool] if command == "export" => Ok(!readonly(pool)?),
        [command, ..] if command == "import" => Ok(!args.iter().any(|arg| arg == "readonly=on")
            || args.iter().any(|arg| arg == "readonly=off")),
        _ => Ok(true),
    }
}

pub fn export_args(pool: &str) -> Vec<String> {
    vec!["export".into(), pool.into()]
}

pub fn import_args(guid: Guid, readonly: bool) -> Vec<String> {
    vec![
        "import".into(),
        "-N".into(),
        "-o".into(),
        format!("readonly={}", if readonly { "on" } else { "off" }),
        "-o".into(),
        "cachefile=none".into(),
        guid.to_string(),
    ]
}

pub fn imported_pool<'a>(
    state: &'a NativeState,
    binding: &PoolBinding,
) -> Result<&'a zfs_tools::engine::Pool> {
    let pool = state
        .inspection
        .pools
        .iter()
        .find(|pool| pool.name == binding.name)
        .ok_or_else(|| refuse(format!("selected pool disappeared: {}", binding.name)))?;
    if pool.guid != binding.guid {
        return Err(refuse(format!(
            "selected pool identity changed: {}",
            binding.name
        )));
    }
    Ok(pool)
}

fn current_pool<'a>(
    state: &'a NativeState,
    binding: &PoolBinding,
) -> Result<Option<&'a zfs_tools::engine::Pool>> {
    let named = state
        .inspection
        .pools
        .iter()
        .find(|pool| pool.name == binding.name);
    let guided = state
        .inspection
        .pools
        .iter()
        .find(|pool| pool.guid == binding.guid);
    match (named, guided) {
        (Some(pool), Some(by_guid)) if pool.name == by_guid.name && pool.guid == binding.guid => {
            Ok(Some(pool))
        }
        (Some(_) | None, Some(_)) => Err(refuse(format!(
            "selected pool identity changed: {}",
            binding.name
        ))),
        (Some(_), None) => Err(refuse(format!(
            "selected pool identity changed: {}",
            binding.name
        ))),
        (None, None) => Ok(None),
    }
}

pub fn pool_readonly(state: &NativeState, binding: &PoolBinding) -> Result<bool> {
    let properties = state.pool_properties.get(&binding.name).ok_or_else(|| {
        refuse(format!(
            "selected pool properties were not observed: {}",
            binding.name
        ))
    })?;
    if properties.get("guid").map(|p| p.value.as_str()) != Some(binding.guid.to_string().as_str()) {
        return Err(refuse(format!(
            "selected pool property GUID changed: {}",
            binding.name
        )));
    }
    match properties.get("readonly").map(|p| p.value.as_str()) {
        Some("on") => Ok(true),
        Some("off") => Ok(false),
        _ => Err(refuse(format!(
            "selected pool readonly property was not observed: {}",
            binding.name
        ))),
    }
}

pub fn no_active_mounts(state: &NativeState, binding: &PoolBinding) -> Result<()> {
    for dataset in state
        .inspection
        .datasets
        .iter()
        .filter(|dataset| dataset.identity.pool_guid == binding.guid)
    {
        if dataset.kind == DatasetKind::Filesystem {
            require_unmounted(dataset.mounted, &dataset.name)?;
        }
    }
    Ok(())
}

fn require_unmounted(mounted: Option<bool>, dataset: &str) -> Result<()> {
    match mounted {
        Some(false) => Ok(()),
        Some(true) => Err(refuse(format!("dataset {dataset} is mounted"))),
        None => Err(refuse(format!(
            "mount state is unknown for dataset {dataset}"
        ))),
    }
}

fn require_exported(state: &NativeState, binding: &PoolBinding) -> Result<()> {
    if state
        .inspection
        .pools
        .iter()
        .any(|pool| pool.name == binding.name || pool.guid == binding.guid)
    {
        return Err(refuse(format!(
            "selected pool remained imported after export: {}",
            binding.name
        )));
    }
    Ok(())
}

pub fn reopen_writable(backend: &mut dyn Backend, binding: &PoolBinding) -> Result<()> {
    backend.export(&binding.name)?;
    require_exported(&backend.observe()?, binding)?;
    backend.import(binding.guid, false)?;
    let state = backend.observe()?;
    imported_pool(&state, binding)?;
    if pool_readonly(&state, binding)? {
        return Err(refuse(format!(
            "selected pool did not reopen writable: {}",
            binding.name
        )));
    }
    Ok(())
}

/// The counterpart of [`reopen_writable`]: return the pool to a read-only
/// import (`allow_exported` accepts a pool the command exported).
pub fn close_readonly(
    backend: &mut dyn Backend,
    binding: &PoolBinding,
    allow_exported: bool,
) -> Result<()> {
    let state = backend.observe()?;
    match current_pool(&state, binding)? {
        Some(_) => {
            no_active_mounts(&state, binding).map_err(|error| {
                refuse(format!(
                    "{error}. In the recovery shell, verify {} has GUID {} with `zpool list -o name,guid,readonly` and inspect `zfs mount`. Once all mounts on this pool are identified and unused, unmount each with `zfs unmount DATASET`. Then run `zpool export {} && zpool import -N -o readonly=on -o cachefile=none {}`",
                    binding.name, binding.guid, binding.name, binding.guid
                ))
            })?;
            if !pool_readonly(&state, binding)? {
                backend.export(&binding.name)?;
                require_exported(&backend.observe()?, binding)?;
                backend.import(binding.guid, true)?;
            }
        }
        None if allow_exported => return Ok(()),
        None => backend.import(binding.guid, true)?,
    }
    let state = backend.observe()?;
    if allow_exported && current_pool(&state, binding)?.is_none() {
        return Ok(());
    }
    imported_pool(&state, binding)?;
    if !pool_readonly(&state, binding)? {
        return Err(refuse(format!(
            "selected pool did not restore read-only access: {}",
            binding.name
        )));
    }
    no_active_mounts(&state, binding)?;
    Ok(())
}

/// Pools reopened writable for one command. `close` must be called even when
/// the command failed: it returns each to read-only by its exact GUID.
pub struct Writable {
    /// Each pool attempted, and whether it reopened. A pool whose reopen
    /// failed after its export is imported read-only again at close.
    pools: Vec<(PoolBinding, bool)>,
    backend: Option<Box<dyn Backend>>,
}

impl Default for Writable {
    fn default() -> Self {
        Self::new()
    }
}

impl Writable {
    pub const fn new() -> Self {
        Self {
            pools: Vec::new(),
            backend: None,
        }
    }

    #[cfg(test)]
    fn with(backend: Box<dyn Backend>) -> Self {
        Self {
            pools: Vec::new(),
            backend: Some(backend),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }

    fn backend(&mut self) -> &mut dyn Backend {
        self.backend
            .get_or_insert_with(|| Box::new(NativeBackend))
            .as_mut()
    }

    /// Reopen `pools` writable, by GUID. Each must be imported read-only
    /// under that name and GUID with nothing mounted; all are checked before
    /// any is touched.
    pub fn open(&mut self, pools: &BTreeMap<String, Guid>) -> Result<()> {
        let bindings: Vec<_> = pools
            .iter()
            .map(|(name, guid)| PoolBinding {
                name: name.clone(),
                guid: *guid,
            })
            .collect();
        let backend = self.backend();
        backend.prove_ram()?;
        let before = backend.observe()?;
        for binding in &bindings {
            admit(&before, binding)?;
        }
        for binding in bindings {
            let backend = self.backend();
            backend.prove_ram()?;
            admit(&backend.observe()?, &binding)?;
            // Recorded before the export: if the import then fails, close
            // imports this exact GUID read-only again.
            self.pools.push((binding.clone(), false));
            reopen_writable(self.backend(), &binding)?;
            self.pools.last_mut().expect("just pushed").1 = true;
        }
        Ok(())
    }

    /// Return every pool to read-only. A reopened pool found absent stays
    /// exported: the command exported it. A same-name replacement refuses
    /// before any effect. A failed close stays retryable.
    pub fn close(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        let mut remaining = Vec::new();
        for (binding, opened) in std::mem::take(&mut self.pools) {
            let backend = self.backend();
            let result = backend
                .prove_ram()
                .and_then(|()| close_readonly(backend, &binding, opened));
            if let Err(error) = result {
                errors.push(format!("{} (GUID {}): {error}", binding.name, binding.guid));
                remaining.push((binding, opened));
            }
        }
        self.pools = remaining;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(refuse(format!(
                "pool cleanup failed: {}",
                errors.join("; ")
            )))
        }
    }
}

/// A pool reopens only from a read-only import with nothing mounted.
fn admit(state: &NativeState, binding: &PoolBinding) -> Result<()> {
    imported_pool(state, binding)?;
    if !pool_readonly(state, binding)? {
        return Err(refuse(format!(
            "selected pool is already imported writable; zboot reopens only read-only pools: {}",
            binding.name
        )));
    }
    no_active_mounts(state, binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    use zfs_tools::engine::{
        InspectRequest,
        native::{self, PropertyInventory},
    };

    #[derive(Clone)]
    struct PoolFixture {
        name: String,
        guid: u64,
        present: bool,
        readonly: bool,
        child: bool,
        child_mounted: Option<bool>,
    }

    fn fixture_state(pools: &[PoolFixture]) -> NativeState {
        let pool_output = pools
            .iter()
            .filter(|pool| pool.present)
            .map(|pool| format!("{}\t{}\t100\t1\t99\tONLINE\t-\n", pool.name, pool.guid))
            .collect::<String>();
        let mut dataset_output = String::new();
        for pool in pools.iter().filter(|pool| pool.present) {
            dataset_output.push_str(&format!(
                "{}\tfilesystem\t{}\t1\t2\t1\t/{}/root\t-\t{}\t{}\tno\t{}\ton\t-\toff\t-\t-\t-\t-\n",
                pool.name,
                pool.guid + 1,
                pool.name,
                pool.guid + 2,
                pool.guid + 3,
                if pool.readonly { "on" } else { "off" },
            ));
            if pool.child {
                let mounted = match pool.child_mounted {
                    Some(true) => "yes",
                    Some(false) => "no",
                    None => "-",
                };
                dataset_output.push_str(&format!(
                    "{}/ROOT/be\tfilesystem\t{}\t1\t2\t1\t/\t-\t{}\t{}\t{}\t{}\ton\t-\toff\t-\t-\t-\t-\n",
                    pool.name,
                    pool.guid + 10,
                    pool.guid + 11,
                    pool.guid + 12,
                    mounted,
                    if pool.readonly { "on" } else { "off" },
                ));
            }
        }
        let inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| match program {
                "zpool" => Ok(pool_output.clone()),
                "zfs" => Ok(dataset_output.clone()),
                _ => panic!("unexpected native query: {program}"),
            },
        )
        .unwrap();
        let names: Vec<_> = pools
            .iter()
            .filter(|pool| pool.present)
            .map(|pool| pool.name.clone())
            .collect();
        let properties = if names.is_empty() {
            PropertyInventory::new()
        } else {
            native::pool_properties_with(&names, |_, args| {
                let queried = args.last().unwrap();
                Ok(pools
                    .iter()
                    .filter(|pool| pool.present && &pool.name == queried)
                    .map(|pool| {
                        format!(
                            "{}\tguid\t{}\tlocal\n{}\treadonly\t{}\tlocal\n",
                            pool.name,
                            pool.guid,
                            pool.name,
                            if pool.readonly { "on" } else { "off" },
                        )
                    })
                    .collect::<String>())
            })
            .unwrap()
        };
        NativeState {
            inspection,
            dataset_properties: PropertyInventory::new(),
            pool_properties: properties,
        }
    }

    struct FakeState {
        pools: Vec<PoolFixture>,
        actions: Vec<String>,
        fail_writable_import: bool,
        observe_failures: usize,
        mount_second_after_first: bool,
    }

    #[derive(Clone)]
    struct Fake {
        state: Rc<RefCell<FakeState>>,
    }

    impl Fake {
        fn new(pools: Vec<PoolFixture>) -> Self {
            Self {
                state: Rc::new(RefCell::new(FakeState {
                    pools,
                    actions: Vec::new(),
                    fail_writable_import: false,
                    observe_failures: 0,
                    mount_second_after_first: false,
                })),
            }
        }

        fn observe_state(&self) -> NativeState {
            let state = self.state.borrow();
            fixture_state(&state.pools)
        }

        fn set_child(&self, name: &str, child: bool) {
            let mut state = self.state.borrow_mut();
            state
                .pools
                .iter_mut()
                .find(|pool| pool.name == name)
                .unwrap()
                .child = child;
        }

        fn set_present(&self, name: &str, present: bool) {
            let mut state = self.state.borrow_mut();
            state
                .pools
                .iter_mut()
                .find(|pool| pool.name == name)
                .unwrap()
                .present = present;
        }

        fn replace_guid(&self, name: &str, guid: u64) {
            let mut state = self.state.borrow_mut();
            state
                .pools
                .iter_mut()
                .find(|pool| pool.name == name)
                .unwrap()
                .guid = guid;
        }
    }

    impl Backend for Fake {
        fn prove_ram(&mut self) -> Result<()> {
            self.state.borrow_mut().actions.push("prove".into());
            Ok(())
        }

        fn observe(&mut self) -> Result<NativeState> {
            let mut state = self.state.borrow_mut();
            state.actions.push("observe".into());
            if state.observe_failures > 0 {
                state.observe_failures -= 1;
                return Err(refuse("injected cleanup observation failure"));
            }
            drop(state);
            Ok(self.observe_state())
        }

        fn export(&mut self, pool: &str) -> Result<()> {
            let mut state = self.state.borrow_mut();
            state.actions.push(format!("export:{pool}"));
            let selected = state
                .pools
                .iter_mut()
                .find(|candidate| candidate.name == pool)
                .ok_or_else(|| refuse("fake export pool missing"))?;
            if !selected.present {
                return Err(refuse("fake export pool already absent"));
            }
            selected.present = false;
            Ok(())
        }

        fn import(&mut self, guid: Guid, readonly: bool) -> Result<()> {
            let mut state = self.state.borrow_mut();
            state.actions.push(format!(
                "import:{guid}:{}",
                if readonly { "ro" } else { "rw" }
            ));
            let selected_index = state
                .pools
                .iter()
                .position(|candidate| candidate.guid == guid.get())
                .ok_or_else(|| refuse("fake import GUID missing"))?;
            if !readonly && state.fail_writable_import {
                return Err(refuse("fake writable import failure"));
            }
            state.pools[selected_index].present = true;
            state.pools[selected_index].readonly = readonly;
            if !readonly && state.mount_second_after_first {
                for (index, other) in state.pools.iter_mut().enumerate() {
                    if index != selected_index {
                        other.child_mounted = Some(true);
                    }
                }
            }
            Ok(())
        }
    }

    fn pool(name: &str, guid: u64, readonly: bool) -> PoolFixture {
        PoolFixture {
            name: name.into(),
            guid,
            present: true,
            readonly,
            child: true,
            child_mounted: Some(false),
        }
    }

    fn pools(selected: &[(&str, u64)]) -> BTreeMap<String, Guid> {
        selected
            .iter()
            .map(|(name, guid)| ((*name).into(), Guid::new(*guid)))
            .collect()
    }

    fn opened(fake: &Fake, selected: &[(&str, u64)]) -> Writable {
        let mut writable = Writable::with(Box::new(fake.clone()));
        writable.open(&pools(selected)).unwrap();
        writable
    }

    fn effects(fake: &Fake) -> Vec<String> {
        fake.state
            .borrow()
            .actions
            .iter()
            .filter(|action| action.starts_with("export:") || action.starts_with("import:"))
            .cloned()
            .collect()
    }

    #[test]
    fn plan_rejects_mounted_selected_readonly_pool() {
        assert!(require_unmounted(Some(true), "tank").is_err());
        assert!(require_unmounted(Some(false), "tank").is_ok());
        assert!(require_unmounted(None, "tank").is_err());
    }

    #[test]
    fn readonly_cleanup_rejects_an_active_mount_before_reopen() {
        let mut mounted = pool("tank", 11, true);
        mounted.child_mounted = Some(true);
        let fake = Fake::new(vec![mounted]);
        let binding = PoolBinding {
            name: "tank".into(),
            guid: Guid::new(11),
        };
        let mut backend = fake.clone();
        let error = close_readonly(&mut backend, &binding, false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("tank/ROOT/be is mounted"));
        assert!(message.contains("verify tank has GUID 11"));
        assert!(
            message.contains(
                "zpool export tank && zpool import -N -o readonly=on -o cachefile=none 11"
            )
        );
        assert!(effects(&fake).is_empty());
    }

    #[test]
    fn a_writable_mounted_or_replaced_pool_is_refused_before_any_pool_is_touched() {
        let mut mounted = pool("b", 22, true);
        mounted.child_mounted = Some(true);
        for (fixtures, selected) in [
            (
                vec![pool("a", 11, true), pool("b", 22, false)],
                [("a", 11), ("b", 22)],
            ),
            (vec![pool("a", 11, true), mounted], [("a", 11), ("b", 22)]),
            (
                vec![pool("a", 11, true), pool("b", 99, true)],
                [("a", 11), ("b", 22)],
            ),
        ] {
            let fake = Fake::new(fixtures);
            let mut writable = Writable::with(Box::new(fake.clone()));
            assert!(writable.open(&pools(&selected)).is_err());
            assert!(writable.is_empty());
            assert!(effects(&fake).is_empty());
        }
    }

    #[test]
    fn pools_return_to_read_only_after_a_failed_action() {
        let fake = Fake::new(vec![
            pool("a", 11, true),
            pool("b", 22, true),
            pool("c", 33, true),
        ]);
        let mut writable = opened(&fake, &[("a", 11), ("b", 22)]);
        let state = fake.observe_state();
        assert_eq!(state.pool_properties["a"]["readonly"].value, "off");
        assert_eq!(state.pool_properties["b"]["readonly"].value, "off");
        assert_eq!(state.pool_properties["c"]["readonly"].value, "on");
        // A failed command still takes the explicit close.
        writable.close().unwrap();
        let state = fake.observe_state();
        for (name, guid) in [("a", 11), ("b", 22), ("c", 33)] {
            let pool = state
                .inspection
                .pools
                .iter()
                .find(|pool| pool.name == name)
                .unwrap();
            assert_eq!(&pool.guid, &Guid::new(guid));
            assert_eq!(state.pool_properties[name]["readonly"].value, "on");
        }
        assert_eq!(
            effects(&fake),
            [
                "export:a",
                "import:11:rw",
                "export:b",
                "import:22:rw",
                "export:a",
                "import:11:ro",
                "export:b",
                "import:22:ro",
            ]
        );
    }

    #[test]
    fn cleanup_succeeds_when_a_dataset_is_removed_by_the_command() {
        let fake = Fake::new(vec![pool("tank", 11, true)]);
        let mut writable = opened(&fake, &[("tank", 11)]);
        fake.set_child("tank", false);
        writable.close().unwrap();
        let state = fake.observe_state();
        assert_eq!(&state.inspection.pools[0].guid, &Guid::new(11));
        assert_eq!(state.pool_properties["tank"]["readonly"].value, "on");
    }

    #[test]
    fn failed_writable_import_restores_the_attempted_exact_guid_readonly() {
        let fake = Fake::new(vec![pool("tank", 11, true)]);
        fake.state.borrow_mut().fail_writable_import = true;
        let mut writable = Writable::with(Box::new(fake.clone()));
        assert!(writable.open(&pools(&[("tank", 11)])).is_err());
        writable.close().unwrap();
        let state = fake.observe_state();
        assert_eq!(&state.inspection.pools[0].guid, &Guid::new(11));
        assert_eq!(state.pool_properties["tank"]["readonly"].value, "on");
        assert_eq!(
            effects(&fake),
            ["export:tank", "import:11:rw", "import:11:ro"]
        );
    }

    #[test]
    fn preflight_failure_before_second_reopen_closes_the_first_pool_only() {
        let fake = Fake::new(vec![pool("a", 11, true), pool("b", 22, true)]);
        fake.state.borrow_mut().mount_second_after_first = true;
        let mut writable = Writable::with(Box::new(fake.clone()));
        assert!(writable.open(&pools(&[("a", 11), ("b", 22)])).is_err());
        fake.state.borrow_mut().pools[1].child_mounted = Some(false);
        writable.close().unwrap();
        assert_eq!(
            effects(&fake),
            ["export:a", "import:11:rw", "export:a", "import:11:ro"]
        );
        assert_eq!(
            fake.observe_state().pool_properties["a"]["readonly"].value,
            "on"
        );
    }

    #[test]
    fn a_reopened_pool_the_command_exported_stays_exported() {
        let fake = Fake::new(vec![pool("tank", 11, true)]);
        let mut writable = opened(&fake, &[("tank", 11)]);
        fake.set_present("tank", false);
        writable.close().unwrap();
        assert!(!effects(&fake).iter().any(|action| action == "import:11:ro"));
        assert!(writable.is_empty());
        assert!(writable.close().is_ok());
    }

    #[test]
    fn close_restores_a_matching_present_pool_readonly() {
        let fake = Fake::new(vec![pool("tank", 11, true)]);
        let mut writable = opened(&fake, &[("tank", 11)]);
        writable.close().unwrap();
        assert_eq!(
            fake.observe_state().pool_properties["tank"]["readonly"].value,
            "on"
        );
        assert!(effects(&fake).iter().any(|action| action == "import:11:ro"));
    }

    #[test]
    fn close_refuses_a_same_name_pool_replacement() {
        let fake = Fake::new(vec![pool("tank", 11, true)]);
        let mut writable = opened(&fake, &[("tank", 11)]);
        fake.replace_guid("tank", 99);
        let before = effects(&fake).len();
        assert!(writable.close().is_err());
        assert!(!writable.is_empty());
        assert_eq!(effects(&fake).len(), before);
    }

    #[test]
    fn a_failed_close_observation_is_retryable_and_cannot_import_an_absent_pool() {
        for present in [true, false] {
            let fake = Fake::new(vec![pool("tank", 11, true)]);
            let mut writable = opened(&fake, &[("tank", 11)]);
            fake.set_present("tank", present);
            fake.state.borrow_mut().observe_failures = 1;
            let before = fake.state.borrow().actions.len();
            assert!(writable.close().is_err());
            assert!(!writable.is_empty());
            assert!(
                fake.state.borrow().actions[before..]
                    .iter()
                    .all(|action| action == "prove" || action == "observe")
            );
            writable.close().unwrap();
            assert!(writable.is_empty());
            if present {
                assert_eq!(
                    fake.observe_state().pool_properties["tank"]["readonly"].value,
                    "on"
                );
            } else {
                assert!(
                    !fake.state.borrow().actions[before..]
                        .iter()
                        .any(|action| action.starts_with("import:"))
                );
                assert!(fake.observe_state().inspection.pools.is_empty());
            }
        }
    }

    #[test]
    fn readonly_recovery_commands_do_not_count_as_durable_writers() {
        let observe = |_: &str| -> Result<bool> { panic!("imports do not query an imported pool") };
        assert!(!command_mutates(&import_args(Guid::new(11), true), observe).unwrap());
        assert!(command_mutates(&import_args(Guid::new(11), false), observe).unwrap());
        for readonly in [false, true] {
            let mut queried = false;
            let mutates = command_mutates(&export_args("tank"), |pool| {
                assert_eq!(pool, "tank");
                queried = true;
                Ok(readonly)
            })
            .unwrap();
            assert!(queried);
            assert_eq!(mutates, !readonly);
        }
        assert!(
            command_mutates(&export_args("tank"), |_| {
                Err(refuse("readonly could not be observed"))
            })
            .is_err()
        );
    }

    #[test]
    fn command_shapes_are_exact_and_never_force() {
        let export = export_args("tank");
        assert_eq!(export, ["export", "tank"]);
        assert!(!export.iter().any(|arg| arg == "-f"));
        let import = import_args(Guid::new(11), false);
        assert_eq!(
            import,
            [
                "import",
                "-N",
                "-o",
                "readonly=off",
                "-o",
                "cachefile=none",
                "11"
            ]
        );
        assert!(!import.iter().any(|arg| arg == "-f"));
    }
}
