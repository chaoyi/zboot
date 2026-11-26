//! Guarded boot metadata: saved kernel arguments and the boot default.
use crate::menu::{RecoveryError, Result};
use serde::Serialize;
use zfs_tools::engine::{
    management::{self, Ownership},
    native,
    operation::SnapshotScope,
    pool_of,
    state::{self, NativeState},
};

pub mod default;
pub(crate) mod once;

fn refuse(message: impl ToString) -> RecoveryError {
    RecoveryError::Refused(message.to_string())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootChange {
    pub dataset: String,
    pub property: String,
    pub value: String,
    pub complete: bool,
    pub detail: Option<String>,
}

pub fn saved_cmdline(dataset: &str) -> Result<Option<native::NativeProperty>> {
    let state = state::observe()?;
    if !state.dataset_properties.contains_key(dataset) {
        return Err(refuse("selected dataset was not observed"));
    }
    Ok(state.dataset_properties[dataset]
        .get("zboot:cmdline")
        .cloned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BootSetting {
    Default,
    /// Unset the pool's `bootfs`. Only the demoted-peer default handoff uses it.
    ClearDefault,
    Cmdline(String),
}
pub trait MetadataBackend {
    fn observe(&mut self) -> Result<NativeState>;
    /// Read-only evidence that this root currently contains a kernel/initrd
    /// pair. This grants no mutation authority or persistent asset identity.
    fn verify_boot_assets(&mut self, dataset: &str) -> Result<()>;
    fn set(&mut self, dataset: &str, setting: &BootSetting) -> Result<()>;
}
pub(crate) fn verify_native_assets(name: &str) -> Result<()> {
    NativeMetadata.verify_boot_assets(name)
}
struct NativeMetadata;
impl MetadataBackend for NativeMetadata {
    fn observe(&mut self) -> Result<NativeState> {
        Ok(state::observe()?)
    }
    fn verify_boot_assets(&mut self, dataset: &str) -> Result<()> {
        crate::hostid::readonly_view(dataset, |root| {
            crate::menu::inventory::kernel_choices(root)
                .map(|_| ())
                .map_err(std::io::Error::other)
        })
        .map_err(refuse)
    }
    fn set(&mut self, dataset: &str, setting: &BootSetting) -> Result<()> {
        let (program, args) = native_command(dataset, setting);
        native::run_mutating(program, &args)?;
        Ok(())
    }
}
/// The exact native command for one boot setting.
fn native_command(dataset: &str, setting: &BootSetting) -> (&'static str, Vec<String>) {
    let pool = pool_of(dataset);
    let (program, target, assignment) = match setting {
        BootSetting::Default => ("zpool", pool, format!("bootfs={dataset}")),
        // OpenZFS unsets bootfs only with an empty value (libzfs
        // bootfs_name_valid); `zpool get` then reports `-`, which is not a
        // valid value to set.
        BootSetting::ClearDefault => ("zpool", pool, "bootfs=".into()),
        BootSetting::Cmdline(value) => ("zfs", dataset, format!("zboot:cmdline={value}")),
    };
    (program, vec!["set".into(), assignment, target.into()])
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CmdlinePlan {
    pub dataset: String,
    pub value: String,
    scope: SnapshotScope,
    owner: Ownership,
    prior: Option<native::NativeProperty>,
}
pub fn cmdline_plan(dataset: &str, value: &str) -> Result<CmdlinePlan> {
    cmdline_plan_with(dataset, value, &mut NativeMetadata)
}
pub fn cmdline_plan_with(
    dataset: &str,
    value: &str,
    backend: &mut impl MetadataBackend,
) -> Result<CmdlinePlan> {
    crate::handoff::compose_cmdline(dataset, value)?;
    let state = backend.observe()?;
    let (scope, owner, _) = metadata_admit(&state, dataset, &BootSetting::Cmdline(value.into()))?;
    Ok(CmdlinePlan {
        dataset: dataset.into(),
        value: value.into(),
        scope,
        owner,
        prior: state.dataset_properties[dataset]
            .get("zboot:cmdline")
            .cloned(),
    })
}
pub fn apply_cmdline(plan: &CmdlinePlan) -> Result<BootChange> {
    apply_cmdline_with(plan, &mut NativeMetadata)
}
pub fn apply_cmdline_with(
    plan: &CmdlinePlan,
    backend: &mut impl MetadataBackend,
) -> Result<BootChange> {
    if cmdline_plan_with(&plan.dataset, &plan.value, backend)? != *plan {
        return Err(refuse("the kernel argument plan changed; preview it again"));
    }
    change_admitted(
        &plan.dataset,
        &BootSetting::Cmdline(plan.value.clone()),
        &plan.scope,
        &plan.owner,
        plan.prior.as_ref(),
        backend,
    )
}

/// The outcome of `default`: the selection, then each other pool default it
/// replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefaultChange {
    pub dataset: String,
    pub selected: BootChange,
    pub cleared: Vec<BootChange>,
    pub complete: bool,
    pub detail: Option<String>,
}
pub fn set_default_with(dataset: &str) -> Result<DefaultChange> {
    select_default_with(dataset, &mut NativeMetadata)
}
/// Every other imported pool that names a default, with that default.
pub fn other_defaults(state: &NativeState, dataset: &str) -> Vec<(String, String)> {
    let pool = pool_of(dataset);
    state
        .pool_properties
        .keys()
        .filter(|other| other.as_str() != pool)
        .filter_map(|other| pool_default(state, other).map(|d| (other.clone(), d.to_owned())))
        .collect()
}
/// Make `dataset` the host's one boot default: select it on its pool, and only
/// once that is verified, clear `bootfs` on every other imported pool. A
/// failed clear leaves two defaults (the Menu then refuses to autoboot) and is
/// reported; running `default` again repairs it.
pub fn select_default_with(
    dataset: &str,
    backend: &mut impl MetadataBackend,
) -> Result<DefaultChange> {
    let selected = change_with(dataset, &BootSetting::Default, backend)?;
    let mut outcome = DefaultChange {
        dataset: dataset.into(),
        complete: false,
        detail: selected.detail.clone(),
        selected,
        cleared: Vec::new(),
    };
    if !outcome.selected.complete {
        return Ok(outcome);
    }
    for (pool, other) in other_defaults(&backend.observe()?, dataset) {
        let cleared = clear_other_default_with(&pool, &other, dataset, backend);
        let ok = cleared.complete;
        if !ok {
            outcome.detail = Some(format!(
                "{} still names {} as its default: {}",
                pool,
                other,
                cleared.detail.as_deref().unwrap_or("not verified cleared")
            ));
        }
        outcome.cleared.push(cleared);
        if !ok {
            return Ok(outcome);
        }
    }
    outcome.complete = true;
    Ok(outcome)
}
fn clear_other_default_with(
    pool: &str,
    other: &str,
    selected: &str,
    backend: &mut impl MetadataBackend,
) -> BootChange {
    let mut outcome = BootChange {
        dataset: other.into(),
        property: "bootfs".into(),
        value: String::new(),
        complete: false,
        detail: None,
    };
    let current = match backend.observe() {
        Ok(current) => current,
        Err(error) => {
            outcome.detail = Some(error.to_string());
            return outcome;
        }
    };
    if let Some(reason) = crate::mounting::refusal(&current, None) {
        outcome.detail = Some(reason);
        return outcome;
    }
    if pool_default(&current, pool) != Some(other)
        || pool_default(&current, pool_of(selected)) != Some(selected)
    {
        outcome.detail = Some("boot defaults changed before clearing".into());
        return outcome;
    }
    if let Err(error) = backend.set(other, &BootSetting::ClearDefault) {
        outcome.detail = Some(error.to_string());
    }
    match backend.observe() {
        Ok(after) => {
            outcome.complete = pool_default(&after, pool).is_none()
                && pool_default(&after, pool_of(selected)) == Some(selected);
            if !outcome.complete && outcome.detail.is_none() {
                outcome.detail = Some("not verified cleared".into());
            }
        }
        Err(error) => outcome.detail = Some(format!("post-change observation failed: {error}")),
    }
    outcome
}
fn metadata_admit(
    state: &NativeState,
    dataset: &str,
    setting: &BootSetting,
) -> Result<(SnapshotScope, Ownership, String)> {
    if matches!(setting, BootSetting::Default)
        && let Some(reason) = crate::mounting::refusal(state, None)
    {
        return Err(refuse(reason));
    }
    if matches!(setting, BootSetting::Cmdline(_)) {
        // Permit repair of previously unsafe additions while retaining the
        // same dataset, ownership, and descendant admission requirements.
        let mut sanitized = state.clone();
        if let Some(properties) = sanitized.dataset_properties.get_mut(dataset) {
            properties.remove("zboot:cmdline");
        }
        crate::handoff::eligible(&sanitized, dataset)
    } else {
        crate::handoff::eligible(state, dataset)
    }
}
fn metadata_revalidate(
    state: &NativeState,
    dataset: &str,
    setting: &BootSetting,
    scope: &SnapshotScope,
    owner: &Ownership,
) -> Result<()> {
    scope.revalidate(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
    )?;
    if &metadata_admit(state, dataset, setting)?.1 != owner {
        return Err(refuse("BE ownership changed"));
    }
    Ok(())
}
/// Bound native admission surrounds the temporary read-only view. The view
/// owns cleanup, and no boot setting is dispatched if either readback drifts.
fn verify_default_assets(
    dataset: &str,
    scope: &SnapshotScope,
    owner: &Ownership,
    backend: &mut impl MetadataBackend,
) -> Result<()> {
    metadata_revalidate(
        &backend.observe()?,
        dataset,
        &BootSetting::Default,
        scope,
        owner,
    )?;
    backend.verify_boot_assets(dataset)?;
    metadata_revalidate(
        &backend.observe()?,
        dataset,
        &BootSetting::Default,
        scope,
        owner,
    )
}

pub fn change_with(
    dataset: &str,
    setting: &BootSetting,
    backend: &mut impl MetadataBackend,
) -> Result<BootChange> {
    let (property, pool_property) = match setting {
        BootSetting::Default => ("bootfs", true),
        BootSetting::ClearDefault => {
            return Err(refuse(
                "a pool default is cleared only by a reviewed primary handoff",
            ));
        }
        BootSetting::Cmdline(value) => {
            crate::handoff::compose_cmdline(dataset, value)?;
            ("zboot:cmdline", false)
        }
    };
    let before = backend.observe()?;
    let (scope, owner, _) = metadata_admit(&before, dataset, setting)?;
    let prior = if pool_property {
        before.pool_properties[pool_of(dataset)].get(property)
    } else {
        before.dataset_properties[dataset].get(property)
    }
    .cloned();
    change_admitted(dataset, setting, &scope, &owner, prior.as_ref(), backend)
}

fn change_admitted(
    dataset: &str,
    setting: &BootSetting,
    scope: &SnapshotScope,
    owner: &Ownership,
    prior: Option<&native::NativeProperty>,
    backend: &mut impl MetadataBackend,
) -> Result<BootChange> {
    let (property, value, pool_property) = match setting {
        BootSetting::Default => ("bootfs", dataset, true),
        BootSetting::Cmdline(value) => ("zboot:cmdline", value.as_str(), false),
        BootSetting::ClearDefault => {
            return Err(refuse(
                "a pool default is cleared only by a reviewed primary handoff",
            ));
        }
    };
    if matches!(setting, BootSetting::Default) {
        verify_default_assets(dataset, scope, owner, backend)?;
    }
    let current = backend.observe()?;
    metadata_revalidate(&current, dataset, setting, scope, owner)?;
    let now = if pool_property {
        current.pool_properties[pool_of(dataset)].get(property)
    } else {
        current.dataset_properties[dataset].get(property)
    }
    .cloned();
    if now.as_ref() != prior {
        return Err(refuse("boot property changed before effect"));
    }
    let target = if pool_property {
        pool_of(dataset)
    } else {
        dataset
    };
    let error = backend.set(dataset, setting).err();
    let mut outcome = BootChange {
        dataset: dataset.into(),
        property: property.into(),
        value: value.into(),
        complete: false,
        detail: error.as_ref().map(ToString::to_string),
    };
    let after = match backend.observe() {
        Ok(after) => after,
        Err(error) => {
            outcome.detail = Some(format!("post-change observation failed: {error}"));
            return Ok(outcome);
        }
    };
    if let Err(error) = metadata_revalidate(&after, dataset, setting, scope, owner) {
        outcome.detail = Some(format!("post-change identity/ownership changed: {error}"));
        return Ok(outcome);
    }
    let observed = if pool_property {
        after.pool_properties[target].get(property)
    } else {
        after.dataset_properties[dataset].get(property)
    };
    outcome.complete = error.is_none()
        && observed.is_some_and(|p| p.value == value && (pool_property || p.source == "local"));
    if !outcome.complete && outcome.detail.is_none() {
        outcome.detail = Some("requested boot value was not verified".into());
    }
    Ok(outcome)
}

/// Boot-default consequence of a pair ownership handoff.
///
/// Only the pair's primary may boot, so a pool default that still names the
/// demoted peer leaves the next boot without one eligible default. The handoff
/// selects the new primary through the ordinary `default` admission and then
/// clears the peer pool's stale default, leaving exactly one pool default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefaultHandoff {
    /// The pair member that becomes its pool's default.
    pub dataset: String,
    pub pool: String,
    /// Another default of `pool` that this selection replaces.
    pub replaces: Option<String>,
    /// The peer pool's default, cleared after `dataset` is verified.
    pub clears: Option<StaleDefault>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaleDefault {
    pub pool: String,
    pub dataset: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefaultHandoffOutcome {
    pub selected: Option<BootChange>,
    pub cleared: Option<BootChange>,
    pub complete: bool,
    pub detail: Option<String>,
}

fn pool_default<'a>(state: &'a NativeState, pool: &str) -> Option<&'a str> {
    state
        .pool_properties
        .get(pool)
        .and_then(|properties| properties.get("bootfs"))
        .map(|property| property.value.as_str())
        .filter(|value| !value.is_empty() && *value != "-")
}

/// Return the default move implied by making `target` its pair's primary.
///
/// The answer depends only on the pair relation, not on its current direction,
/// so a review before the handoff and a check after it agree. Unpaired targets
/// and pairs whose peer is not its pool's default leave defaults alone.
pub fn default_handoff(state: &NativeState, target: &str) -> Result<Option<DefaultHandoff>> {
    let peer = match management::ownership(state, target)? {
        Ownership::Primary { record } | Ownership::Secondary { record }
            if record.endpoint.name == target =>
        {
            record.peer.name
        }
        _ => return Ok(None),
    };
    let peer_pool = pool_of(&peer);
    if pool_default(state, peer_pool) != Some(peer.as_str()) {
        return Ok(None);
    }
    let pool = pool_of(target);
    Ok(Some(DefaultHandoff {
        dataset: target.into(),
        pool: pool.into(),
        replaces: pool_default(state, pool)
            .filter(|current| *current != target)
            .map(str::to_owned),
        clears: (peer_pool != pool).then(|| StaleDefault {
            pool: peer_pool.into(),
            dataset: peer.clone(),
        }),
    }))
}

pub fn hand_off_default(handoff: &DefaultHandoff) -> DefaultHandoffOutcome {
    hand_off_default_with(handoff, &mut NativeMetadata)
}

/// Apply a reviewed default handoff after the ownership handoff completed.
/// Failures are reported in the outcome: the ownership change already stands.
pub fn hand_off_default_with(
    handoff: &DefaultHandoff,
    backend: &mut impl MetadataBackend,
) -> DefaultHandoffOutcome {
    let mut outcome = DefaultHandoffOutcome {
        selected: None,
        cleared: None,
        complete: false,
        detail: None,
    };
    let reviewed = backend
        .observe()
        .and_then(|state| default_handoff(&state, &handoff.dataset));
    match reviewed {
        Ok(Some(current)) if current == *handoff => {}
        Ok(_) => {
            outcome.detail = Some("boot defaults changed since review; none were changed".into());
            return outcome;
        }
        Err(error) => {
            outcome.detail = Some(format!("boot defaults were not changed: {error}"));
            return outcome;
        }
    }
    let selected = match change_with(&handoff.dataset, &BootSetting::Default, backend) {
        Ok(selected) => selected,
        Err(error) => {
            outcome.detail = Some(format!("boot defaults were not changed: {error}"));
            return outcome;
        }
    };
    let verified = selected.complete;
    outcome.detail = selected.detail.clone();
    outcome.selected = Some(selected);
    if !verified {
        return outcome;
    }
    let Some(stale) = &handoff.clears else {
        outcome.complete = true;
        return outcome;
    };
    match clear_stale_default_with(stale, &handoff.dataset, backend) {
        Ok(cleared) => {
            outcome.complete = cleared.complete;
            outcome.detail = cleared.detail.clone();
            outcome.cleared = Some(cleared);
        }
        Err(error) => {
            outcome.detail = Some(format!(
                "stale default {} on {} was kept: {error}",
                stale.dataset, stale.pool
            ));
        }
    }
    outcome
}

/// Admit clearing `stale` only while it is still its pool's default, it is the
/// fenced secondary of `primary`, and `primary` is already the new default.
fn stale_admit(
    state: &NativeState,
    stale: &StaleDefault,
    primary: &str,
) -> Result<zfs_tools::engine::management::PairRecord> {
    if let Some(reason) = crate::mounting::refusal(state, None) {
        return Err(refuse(reason));
    }
    if pool_of(&stale.dataset) != stale.pool
        || pool_default(state, &stale.pool) != Some(stale.dataset.as_str())
    {
        return Err(refuse("stale boot default changed before clearing"));
    }
    if pool_default(state, pool_of(primary)) != Some(primary) {
        return Err(refuse("new boot default is not in place"));
    }
    match management::ownership(state, &stale.dataset)? {
        Ownership::Secondary { record }
            if record.endpoint.name == stale.dataset && record.peer.name == primary =>
        {
            Ok(record)
        }
        _ => Err(refuse(format!(
            "stale default is no longer the demoted secondary of {primary}"
        ))),
    }
}

fn clear_stale_default_with(
    stale: &StaleDefault,
    primary: &str,
    backend: &mut impl MetadataBackend,
) -> Result<BootChange> {
    let record = stale_admit(&backend.observe()?, stale, primary)?;
    if stale_admit(&backend.observe()?, stale, primary)? != record {
        return Err(refuse("BE ownership changed"));
    }
    let error = backend
        .set(&stale.dataset, &BootSetting::ClearDefault)
        .err();
    let mut outcome = BootChange {
        dataset: stale.dataset.clone(),
        property: "bootfs".into(),
        value: String::new(),
        complete: false,
        detail: error.as_ref().map(ToString::to_string),
    };
    let after = match backend.observe() {
        Ok(after) => after,
        Err(error) => {
            outcome.detail = Some(format!("post-change observation failed: {error}"));
            return Ok(outcome);
        }
    };
    let ownership = management::ownership(&after, &stale.dataset);
    if !matches!(&ownership, Ok(Ownership::Secondary { record: observed }) if *observed == record) {
        outcome.detail = Some("post-change ownership changed".into());
        return Ok(outcome);
    }
    outcome.complete = error.is_none()
        && pool_default(&after, &stale.pool).is_none()
        && pool_default(&after, pool_of(primary)) == Some(primary);
    if !outcome.complete && outcome.detail.is_none() {
        outcome.detail = Some("stale boot default was not verified cleared".into());
    }
    Ok(outcome)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zfs_tools::engine::InspectRequest;
    fn prop(value: impl ToString) -> native::NativeProperty {
        native::NativeProperty {
            value: value.to_string(),
            source: "local".into(),
        }
    }
    pub(crate) fn fixture() -> NativeState {
        fixture_with_mount_modes(&[("bpool/BE/proof", "off", "noauto")])
    }
    pub(crate) fn fixture_with_mount_modes(modes: &[(&str, &str, &str)]) -> NativeState {
        let rows = [
            ("apool", "none", 1),
            ("apool/home", "/home", 2),
            ("bpool", "none", 3),
            ("bpool/home", "none", 4),
            ("bpool/home/user", "/home/user", 5),
            ("bpool/BE", "none", 6),
            ("bpool/BE/proof", "/", 7),
        ];
        fixture_from(
            &rows,
            &[("apool", 100, None), ("bpool", 200, Some("bpool/BE/proof"))],
            modes,
        )
    }
    /// The native mount properties every fixture dataset carries.
    pub(crate) const FIXTURE_COLUMNS: [&str; 11] = [
        "mountpoint",
        "canmount",
        "atime",
        "relatime",
        "devices",
        "exec",
        "readonly",
        "setuid",
        "nbmand",
        "encryptionroot",
        "keylocation",
    ];
    pub(super) fn fixture_from(
        rows: &[(&str, &str, u64)],
        pools: &[(&str, u64, Option<&str>)],
        modes: &[(&str, &str, &str)],
    ) -> NativeState {
        let pool_rows = pools
            .iter()
            .map(|(name, guid, bootfs)| {
                format!(
                    "{name}\t{guid}\t1000\t0\t1000\tONLINE\t{}\n",
                    bootfs.unwrap_or("-")
                )
            })
            .collect::<String>();
        let output = rows.iter().map(|(name, mount, id)| {
            let (_, readonly, canmount) = modes.iter().find(|m| m.0 == *name).copied().unwrap_or((name, "off", "on"));
            format!("{name}\tfilesystem\t{id}\t0\t1000\t0\t{mount}\t-\t{}\t{}\tno\t{readonly}\t{canmount}\t-\toff\t-\t-\t-\t-\n",id+10,id+20)
        }).collect::<String>();
        let inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    pool_rows.clone()
                } else {
                    output.clone()
                })
            },
        )
        .unwrap();
        let mut properties = native::PropertyInventory::new();
        for d in &inspection.datasets {
            let mut p = BTreeMap::from([
                ("guid".into(), prop(d.identity.guid)),
                ("createtxg".into(), prop(d.identity.createtxg)),
                ("objsetid".into(), prop(d.identity.objsetid)),
            ]);
            for key in &FIXTURE_COLUMNS {
                p.insert(
                    (*key).into(),
                    prop(match *key {
                        "mountpoint" => d.mountpoint.as_deref().unwrap(),
                        "readonly" => {
                            if d.readonly {
                                "on"
                            } else {
                                "off"
                            }
                        }
                        "canmount" => match d.canmount.unwrap() {
                            zfs_tools::engine::CanMount::On => "on",
                            zfs_tools::engine::CanMount::Off => "off",
                            zfs_tools::engine::CanMount::NoAuto => "noauto",
                        },
                        "nbmand" => "off",
                        "encryptionroot" | "keylocation" => "-",
                        _ => "on",
                    }),
                );
            }
            properties.insert(d.name.clone(), p);
        }
        let pool_properties = pools
            .iter()
            .map(|(name, guid, bootfs)| {
                let mut p = BTreeMap::from([
                    ("guid".into(), prop(guid)),
                    ("readonly".into(), prop("off")),
                ]);
                if let Some(bootfs) = bootfs {
                    p.insert("bootfs".into(), prop(bootfs));
                }
                ((*name).into(), p)
            })
            .collect();
        NativeState {
            inspection,
            dataset_properties: properties,
            pool_properties,
        }
    }
    struct Fake {
        state: NativeState,
        calls: Vec<BootSetting>,
        drift: bool,
        observations: usize,
        automount_observation: Option<usize>,
        fail: bool,
        fail_clear: bool,
        valid_assets: std::collections::BTreeSet<String>,
        asset_probes: usize,
        drift_during_probe: bool,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                state: fixture(),
                calls: vec![],
                drift: false,
                observations: 0,
                automount_observation: None,
                fail: false,
                fail_clear: false,
                valid_assets: ["bpool/BE/proof".into()].into(),
                asset_probes: 0,
                drift_during_probe: false,
            }
        }
    }
    impl MetadataBackend for Fake {
        fn observe(&mut self) -> Result<NativeState> {
            self.observations += 1;
            if self.automount_observation == Some(self.observations) {
                self.state
                    .inspection
                    .datasets
                    .iter_mut()
                    .find(|dataset| dataset.name == "apool/home")
                    .unwrap()
                    .mountpoint = Some("/".into());
                self.state
                    .dataset_properties
                    .get_mut("apool/home")
                    .unwrap()
                    .insert("mountpoint".into(), prop("/"));
            }
            let mut state = self.state.clone();
            if self.drift && self.observations == 2 {
                state
                    .dataset_properties
                    .get_mut("bpool/BE/proof")
                    .unwrap()
                    .insert("zboot:pending".into(), prop("late"));
            }
            Ok(state)
        }
        fn verify_boot_assets(&mut self, dataset: &str) -> Result<()> {
            self.asset_probes += 1;
            if !self.valid_assets.contains(dataset) {
                return Err(refuse("no matching kernel/initrd pairs found"));
            }
            if self.drift_during_probe {
                self.state
                    .dataset_properties
                    .get_mut(dataset)
                    .unwrap()
                    .insert("guid".into(), prop("999"));
            }
            Ok(())
        }
        fn set(&mut self, dataset: &str, setting: &BootSetting) -> Result<()> {
            self.calls.push(setting.clone());
            if self.fail_clear && *setting == BootSetting::ClearDefault {
                return Err(refuse("injected clear failure"));
            }
            match setting {
                BootSetting::Default => {
                    self.state
                        .pool_properties
                        .get_mut(pool_of(dataset))
                        .unwrap()
                        .insert("bootfs".into(), prop(dataset));
                }
                BootSetting::ClearDefault => {
                    self.state
                        .pool_properties
                        .get_mut(pool_of(dataset))
                        .unwrap()
                        .insert(
                            "bootfs".into(),
                            native::NativeProperty {
                                value: "-".into(),
                                source: "default".into(),
                            },
                        );
                }
                BootSetting::Cmdline(value) => {
                    self.state
                        .dataset_properties
                        .get_mut(dataset)
                        .unwrap()
                        .insert("zboot:cmdline".into(), prop(value));
                }
            }
            if self.fail {
                Err(refuse("injected command failure"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn a_cmdline_preview_is_stable_and_rechecks_identity_ownership_and_prior_value() {
        let dataset = "bpool/BE/proof";
        for attack in 0..3 {
            let mut fake = Fake::new();
            let before = fake.state.dataset_properties.clone();
            let plan = cmdline_plan_with(dataset, "console=ttyS0", &mut fake).unwrap();
            assert_eq!(
                plan,
                cmdline_plan_with(dataset, "console=ttyS0", &mut fake).unwrap()
            );
            assert_eq!(fake.state.dataset_properties, before);
            assert!(fake.calls.is_empty());
            let properties = fake.state.dataset_properties.get_mut(dataset).unwrap();
            match attack {
                0 => {
                    properties.insert("guid".into(), prop("999"));
                }
                1 => {
                    properties.insert("zboot:pending".into(), prop("foreign"));
                }
                2 => {
                    properties.insert("zboot:cmdline".into(), prop("console=ttyS1"));
                }
                _ => unreachable!(),
            }
            let changed = fake.state.dataset_properties.clone();
            assert!(
                apply_cmdline_with(&plan, &mut fake).is_err(),
                "attack {attack}"
            );
            assert!(fake.calls.is_empty(), "attack {attack}");
            assert_eq!(fake.state.dataset_properties, changed);
        }
        let mut fake = Fake::new();
        let plan = cmdline_plan_with(dataset, "console=ttyS0", &mut fake).unwrap();
        assert!(apply_cmdline_with(&plan, &mut fake).unwrap().complete);
        assert_eq!(fake.calls, [BootSetting::Cmdline("console=ttyS0".into())]);
    }

    #[test]
    fn a_default_requires_boot_assets_and_rechecks_identity_after_the_probe() {
        let mut fake = Fake::new();
        fake.valid_assets.clear();
        let before = fake.state.pool_properties.clone();
        let error = change_with("bpool/BE/proof", &BootSetting::Default, &mut fake).unwrap_err();
        assert!(error.to_string().contains("kernel/initrd"));
        assert_eq!(fake.asset_probes, 1);
        assert!(fake.calls.is_empty());
        assert_eq!(fake.state.pool_properties, before);

        let mut fake = Fake::new();
        fake.drift_during_probe = true;
        assert!(change_with("bpool/BE/proof", &BootSetting::Default, &mut fake).is_err());
        assert_eq!(fake.asset_probes, 1);
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn a_cmdline_plan_names_exactly_the_pools_it_writes() {
        let mut fake = Fake::new();
        let state = fake.state.clone();
        let plan = cmdline_plan_with("bpool/BE/proof", "quiet", &mut fake).unwrap();
        assert_eq!(
            crate::cli::access::tests::reopened(
                &state,
                crate::cli::access::plan_pools(&serde_json::to_value(&plan).unwrap())
            ),
            ["bpool"]
        );
    }

    #[test]
    fn a_cmdline_plan_for_a_paired_be_never_reopens_its_peer() {
        let mut fake = Fake::new();
        fake.state = paired_bes("apool/BE/be1", "bpool/BE/be1", &[]);
        let state = fake.state.clone();
        let plan = cmdline_plan_with("apool/BE/be1", "quiet", &mut fake).unwrap();
        assert!(
            serde_json::to_string(&plan)
                .unwrap()
                .contains("bpool/BE/be1")
        );
        assert_eq!(
            crate::cli::access::tests::reopened(
                &state,
                crate::cli::access::plan_pools(&serde_json::to_value(&plan).unwrap())
            ),
            ["apool"]
        );
    }

    #[test]
    fn cmdline_repair_does_not_require_a_kernel_pair_or_open_an_asset_view() {
        let mut fake = Fake::new();
        fake.valid_assets.clear();
        fake.state
            .dataset_properties
            .get_mut("bpool/BE/proof")
            .unwrap()
            .insert("zboot:cmdline".into(), prop("root=unsafe"));
        let plan = cmdline_plan_with("bpool/BE/proof", "console=ttyS0", &mut fake).unwrap();
        assert!(apply_cmdline_with(&plan, &mut fake).unwrap().complete);
        assert_eq!(fake.calls, [BootSetting::Cmdline("console=ttyS0".into())]);
        assert_eq!(fake.asset_probes, 0);
    }

    #[test]
    fn the_default_setter_rechecks_host_wide_automount_hazards_before_its_effect() {
        for observation in [1, 2] {
            let mut fake = Fake::new();
            fake.automount_observation = Some(observation);
            let error =
                change_with("bpool/BE/proof", &BootSetting::Default, &mut fake).unwrap_err();
            assert!(error.to_string().contains("apool/home"), "{error}");
            assert!(fake.calls.is_empty());
            assert_eq!(pool_default(&fake.state, "bpool"), Some("bpool/BE/proof"));
        }
    }

    #[test]
    fn metadata_changes_never_relax_readonly_and_drift_blocks_effect() {
        let mut fake = Fake::new();
        let before = fake.state.dataset_properties.clone();
        assert!(
            change_with("bpool/BE/proof", &BootSetting::Default, &mut fake)
                .unwrap()
                .complete
        );
        assert_eq!(fake.calls, [BootSetting::Default]);
        assert_eq!(fake.state.dataset_properties, before);
        let mut fake = Fake::new();
        fake.drift = true;
        assert!(change_with("bpool/BE/proof", &BootSetting::Default, &mut fake).is_err());
        assert!(fake.calls.is_empty());
        let mut fake = Fake::new();
        fake.state
            .dataset_properties
            .get_mut("bpool/BE/proof")
            .unwrap()
            .insert("zboot:pending".into(), prop("operation"));
        assert!(change_with("bpool/BE/proof", &BootSetting::Default, &mut fake).is_err());
        assert!(fake.calls.is_empty());
    }
    #[test]
    fn clearing_saved_arguments_verifies_an_empty_native_user_property() {
        struct NativeReadback(Fake);
        impl MetadataBackend for NativeReadback {
            fn observe(&mut self) -> Result<NativeState> {
                let mut state = self.0.observe()?;
                let name = "bpool/BE/proof";
                if let Some(property) = state.dataset_properties[name].get("zboot:cmdline") {
                    let guid = &state
                        .inspection
                        .datasets
                        .iter()
                        .find(|d| d.name == name)
                        .unwrap()
                        .identity
                        .guid;
                    let row = format!(
                        "{name}\tguid\t{guid}\t-\n{name}\tzboot:cmdline\t{}\t{}\n",
                        property.value, property.source
                    );
                    let parsed =
                        native::dataset_properties_with(&[name.into()], |_, _| Ok(row.clone()))?;
                    state.dataset_properties.get_mut(name).unwrap().insert(
                        "zboot:cmdline".into(),
                        parsed[name]["zboot:cmdline"].clone(),
                    );
                }
                Ok(state)
            }
            fn verify_boot_assets(&mut self, dataset: &str) -> Result<()> {
                self.0.verify_boot_assets(dataset)
            }
            fn set(&mut self, dataset: &str, setting: &BootSetting) -> Result<()> {
                self.0.set(dataset, setting)
            }
        }
        let mut backend = NativeReadback(Fake::new());
        backend
            .0
            .state
            .dataset_properties
            .get_mut("bpool/BE/proof")
            .unwrap()
            .insert("zboot:cmdline".into(), prop("console=ttyS0"));
        let cleared = change_with(
            "bpool/BE/proof",
            &BootSetting::Cmdline(String::new()),
            &mut backend,
        )
        .unwrap();
        assert!(cleared.complete, "{:?}", cleared.detail);
        assert_eq!(cleared.value, "");
        assert_eq!(
            backend.0.state.dataset_properties["bpool/BE/proof"]["zboot:cmdline"],
            prop("")
        );
    }

    #[test]
    fn cmdline_repairs_unsafe_old_value_but_rejects_new_override_and_reports_uncertainty() {
        let mut fake = Fake::new();
        fake.state
            .dataset_properties
            .get_mut("bpool/BE/proof")
            .unwrap()
            .insert("zboot:cmdline".into(), prop("root=ZFS=wrong"));
        assert!(
            change_with(
                "bpool/BE/proof",
                &BootSetting::Cmdline("console=ttyS0".into()),
                &mut fake
            )
            .unwrap()
            .complete
        );
        let mut fake = Fake::new();
        assert!(
            change_with(
                "bpool/BE/proof",
                &BootSetting::Cmdline("rw".into()),
                &mut fake
            )
            .is_err()
        );
        assert!(fake.calls.is_empty());
        let mut fake = Fake::new();
        fake.fail = true;
        let outcome = change_with(
            "bpool/BE/proof",
            &BootSetting::Cmdline("quiet".into()),
            &mut fake,
        )
        .unwrap();
        assert!(!outcome.complete);
        assert!(outcome.detail.unwrap().contains("injected"));
    }

    /// One BE per pool (or two in one pool), paired with `primary` working,
    /// `secondary` fenced, and the given pool defaults.
    pub(crate) fn paired_bes(
        primary: &str,
        secondary: &str,
        defaults: &[(&str, &str)],
    ) -> NativeState {
        let rows = [
            ("apool", "none", 1),
            ("apool/BE", "none", 2),
            ("apool/BE/be1", "/", 3),
            ("bpool", "none", 4),
            ("bpool/BE", "none", 5),
            ("bpool/BE/be1", "/", 6),
            ("bpool/BE/be2", "/", 7),
        ];
        let default = |pool: &str| {
            defaults
                .iter()
                .find(|(name, _)| *name == pool)
                .map(|(_, be)| *be)
        };
        let mut state = fixture_from(
            &rows,
            &[
                ("apool", 100, default("apool")),
                ("bpool", 200, default("bpool")),
            ],
            &[
                (
                    "apool/BE/be1",
                    if secondary == "apool/BE/be1" {
                        "on"
                    } else {
                        "off"
                    },
                    "noauto",
                ),
                (
                    "bpool/BE/be1",
                    if secondary == "bpool/BE/be1" {
                        "on"
                    } else {
                        "off"
                    },
                    "noauto",
                ),
                (
                    "bpool/BE/be2",
                    if secondary == "bpool/BE/be2" {
                        "on"
                    } else {
                        "off"
                    },
                    "noauto",
                ),
            ],
        );
        let endpoint = |state: &NativeState, name: &str| management::Endpoint {
            name: name.into(),
            identity: state
                .inspection
                .datasets
                .iter()
                .find(|d| d.name == name)
                .unwrap()
                .identity
                .clone(),
        };
        let record = management::PairRecord {
            schema_version: 1,
            pair_id: "66666666-6666-4666-8666-666666666666".into(),
            endpoint: endpoint(&state, primary),
            peer: endpoint(&state, secondary),
            role: management::Role::Primary,
        };
        for record in [record.counterpart(), record] {
            let properties = state
                .dataset_properties
                .get_mut(&record.endpoint.name)
                .unwrap();
            properties.insert(
                management::PAIR_PROPERTY.into(),
                prop(record.encode().unwrap()),
            );
        }
        state
    }
    fn paired_fake(state: NativeState) -> Fake {
        let mut fake = Fake::new();
        fake.valid_assets = crate::boot_environment::roots(&state)
            .into_iter()
            .map(|dataset| dataset.name.clone())
            .collect();
        fake.state = state;
        fake
    }

    #[test]
    fn primary_handoff_moves_a_demoted_cross_pool_default_to_exactly_one_default() {
        // Before `primary apool/BE/be1`: B is primary and bpool's default.
        let before = paired_bes("bpool/BE/be1", "apool/BE/be1", &[("bpool", "bpool/BE/be1")]);
        let handoff = default_handoff(&before, "apool/BE/be1").unwrap().unwrap();
        assert_eq!(
            handoff,
            DefaultHandoff {
                dataset: "apool/BE/be1".into(),
                pool: "apool".into(),
                replaces: None,
                clears: Some(StaleDefault {
                    pool: "bpool".into(),
                    dataset: "bpool/BE/be1".into(),
                }),
            }
        );
        // An unfinished ownership handoff cannot select the still-fenced target.
        let mut fake = paired_fake(before);
        let outcome = hand_off_default_with(&handoff, &mut fake);
        assert!(!outcome.complete && outcome.selected.is_none());
        assert!(fake.calls.is_empty());

        // After the handoff the same review still applies, and completes.
        let after = paired_bes("apool/BE/be1", "bpool/BE/be1", &[("bpool", "bpool/BE/be1")]);
        assert_eq!(
            default_handoff(&after, "apool/BE/be1").unwrap(),
            Some(handoff.clone())
        );
        let mut fake = paired_fake(after);
        let outcome = hand_off_default_with(&handoff, &mut fake);
        assert!(outcome.complete, "{:?}", outcome.detail);
        assert_eq!(
            fake.calls,
            [BootSetting::Default, BootSetting::ClearDefault]
        );
        assert_eq!(pool_default(&fake.state, "apool"), Some("apool/BE/be1"));
        assert_eq!(pool_default(&fake.state, "bpool"), None);
        assert!(outcome.cleared.unwrap().complete);
        // A repeated `primary` on the settled primary has nothing left to move.
        assert_eq!(default_handoff(&fake.state, "apool/BE/be1").unwrap(), None);
    }

    #[test]
    fn a_pair_default_handoff_without_kernel_assets_keeps_both_defaults_untouched() {
        let state = paired_bes("apool/BE/be1", "bpool/BE/be1", &[("bpool", "bpool/BE/be1")]);
        let handoff = default_handoff(&state, "apool/BE/be1").unwrap().unwrap();
        let mut fake = paired_fake(state);
        fake.valid_assets.clear();
        let before = fake.state.pool_properties.clone();
        let outcome = hand_off_default_with(&handoff, &mut fake);
        assert!(!outcome.complete);
        assert!(outcome.selected.is_none() && outcome.cleared.is_none());
        assert!(outcome.detail.unwrap().contains("kernel/initrd"));
        assert!(fake.calls.is_empty());
        assert_eq!(fake.state.pool_properties, before);
    }

    #[test]
    fn primary_handoff_repairs_a_default_left_on_the_secondary_after_ownership_moved() {
        // The reported state: A already primary, the default still on fenced B.
        let state = paired_bes("apool/BE/be1", "bpool/BE/be1", &[("bpool", "bpool/BE/be1")]);
        let handoff = default_handoff(&state, "apool/BE/be1").unwrap().unwrap();
        let mut fake = paired_fake(state);
        assert!(hand_off_default_with(&handoff, &mut fake).complete);
        assert_eq!(pool_default(&fake.state, "bpool"), None);
    }

    #[test]
    fn primary_handoff_leaves_defaults_alone_when_the_peer_was_not_default() {
        for defaults in [
            &[][..],
            &[("apool", "apool/BE/be1")],
            &[("bpool", "bpool/BE/be2")],
        ] {
            let state = paired_bes("bpool/BE/be1", "apool/BE/be1", defaults);
            assert_eq!(default_handoff(&state, "apool/BE/be1").unwrap(), None);
        }
        // Unpaired targets never move defaults.
        assert_eq!(default_handoff(&fixture(), "bpool/BE/proof").unwrap(), None);
    }

    #[test]
    fn same_pool_primary_handoff_moves_the_default_without_clearing() {
        let state = paired_bes("bpool/BE/be2", "bpool/BE/be1", &[("bpool", "bpool/BE/be2")]);
        let handoff = default_handoff(&state, "bpool/BE/be1").unwrap().unwrap();
        assert_eq!(handoff.replaces.as_deref(), Some("bpool/BE/be2"));
        assert_eq!(handoff.clears, None);
        let after = paired_bes("bpool/BE/be1", "bpool/BE/be2", &[("bpool", "bpool/BE/be2")]);
        let mut fake = paired_fake(after);
        assert!(hand_off_default_with(&handoff, &mut fake).complete);
        assert_eq!(fake.calls, [BootSetting::Default]);
        assert_eq!(pool_default(&fake.state, "bpool"), Some("bpool/BE/be1"));
    }

    #[test]
    fn primary_handoff_refuses_defaults_changed_since_review_and_direct_clearing() {
        let state = paired_bes("bpool/BE/be1", "apool/BE/be1", &[("bpool", "bpool/BE/be1")]);
        let handoff = default_handoff(&state, "apool/BE/be1").unwrap().unwrap();
        let after = paired_bes("apool/BE/be1", "bpool/BE/be1", &[("bpool", "bpool/BE/be2")]);
        // The peer pool's default moved meanwhile: the review no longer matches.
        let mut fake = paired_fake(after);
        let outcome = hand_off_default_with(&handoff, &mut fake);
        assert!(!outcome.complete);
        assert!(outcome.detail.unwrap().contains("changed since review"));
        assert!(fake.calls.is_empty());
        assert!(change_with("bpool/BE/be1", &BootSetting::ClearDefault, &mut fake).is_err());
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn default_commands_use_exact_native_arguments() {
        assert_eq!(
            native_command("rpool/ROOT/be1", &BootSetting::ClearDefault),
            (
                "zpool",
                vec!["set".into(), "bootfs=".into(), "rpool".into()]
            )
        );
        assert_eq!(
            native_command("rpool2/ROOT/be1", &BootSetting::Default),
            (
                "zpool",
                vec![
                    "set".into(),
                    "bootfs=rpool2/ROOT/be1".into(),
                    "rpool2".into()
                ]
            )
        );
    }

    #[test]
    fn failed_clear_leaves_two_defaults_and_rerunning_primary_repairs_them() {
        let state = paired_bes("bpool/BE/be1", "apool/BE/be1", &[("bpool", "bpool/BE/be1")]);
        let handoff = default_handoff(&state, "apool/BE/be1").unwrap().unwrap();
        let after = paired_bes("apool/BE/be1", "bpool/BE/be1", &[("bpool", "bpool/BE/be1")]);
        let mut fake = paired_fake(after);
        fake.fail_clear = true;
        let outcome = hand_off_default_with(&handoff, &mut fake);
        assert!(!outcome.complete);
        assert!(outcome.selected.as_ref().unwrap().complete);
        assert!(!outcome.cleared.as_ref().unwrap().complete);
        assert!(outcome.detail.unwrap().contains("injected clear failure"));
        // Select succeeded, clear failed: both pools now name a default.
        assert_eq!(pool_default(&fake.state, "apool"), Some("apool/BE/be1"));
        assert_eq!(pool_default(&fake.state, "bpool"), Some("bpool/BE/be1"));

        // Rerunning explicit `primary apool/BE/be1` reviews the same repair.
        fake.fail_clear = false;
        fake.calls.clear();
        let rerun = default_handoff(&fake.state, "apool/BE/be1")
            .unwrap()
            .unwrap();
        assert_eq!(rerun, handoff);
        assert!(hand_off_default_with(&rerun, &mut fake).complete);
        assert_eq!(
            fake.calls,
            [BootSetting::Default, BootSetting::ClearDefault]
        );
        assert_eq!(pool_default(&fake.state, "bpool"), None);
    }

    #[test]
    fn unverified_new_default_never_clears_the_stale_default() {
        let state = paired_bes("apool/BE/be1", "bpool/BE/be1", &[("bpool", "bpool/BE/be1")]);
        let handoff = default_handoff(&state, "apool/BE/be1").unwrap().unwrap();
        let mut fake = paired_fake(state);
        fake.fail = true;
        let outcome = hand_off_default_with(&handoff, &mut fake);
        assert!(!outcome.complete && outcome.cleared.is_none());
        assert!(!outcome.selected.unwrap().complete);
        assert_eq!(fake.calls, [BootSetting::Default]);
        assert_eq!(pool_default(&fake.state, "bpool"), Some("bpool/BE/be1"));
    }

    #[test]
    fn default_is_the_host_wide_choice_and_clears_other_pool_defaults() {
        let rows = [
            ("apool", "none", 1),
            ("apool/BE", "none", 2),
            ("apool/BE/old", "/", 3),
            ("bpool", "none", 4),
            ("bpool/BE", "none", 5),
            ("bpool/BE/proof", "/", 6),
            ("cpool", "none", 7),
        ];
        let state = fixture_from(
            &rows,
            &[
                ("apool", 100, Some("apool/BE/old")),
                ("bpool", 200, None),
                ("cpool", 300, None),
            ],
            &[
                ("apool/BE/old", "off", "noauto"),
                ("bpool/BE/proof", "off", "noauto"),
            ],
        );
        let data_before = state.pool_properties["cpool"].clone();
        let mut fake = paired_fake(state.clone());
        let outcome = select_default_with("bpool/BE/proof", &mut fake).unwrap();
        assert!(outcome.complete, "{:?}", outcome.detail);
        assert_eq!(
            fake.calls,
            [BootSetting::Default, BootSetting::ClearDefault]
        );
        assert_eq!(pool_default(&fake.state, "bpool"), Some("bpool/BE/proof"));
        assert_eq!(pool_default(&fake.state, "apool"), None);
        assert_eq!(outcome.cleared.len(), 1);
        assert_eq!(outcome.cleared[0].dataset, "apool/BE/old");
        // A pool without a default is not touched.
        assert_eq!(fake.state.pool_properties["cpool"], data_before);

        // A failed clear keeps the new selection and reports the stale one.
        let mut fake = paired_fake(state);
        fake.fail_clear = true;
        let outcome = select_default_with("bpool/BE/proof", &mut fake).unwrap();
        assert!(!outcome.complete);
        assert!(outcome.selected.complete);
        assert!(
            outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("apool still names apool/BE/old"))
        );
        assert_eq!(pool_default(&fake.state, "bpool"), Some("bpool/BE/proof"));
        assert_eq!(pool_default(&fake.state, "apool"), Some("apool/BE/old"));
    }
}
