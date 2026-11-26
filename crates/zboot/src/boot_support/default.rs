//! The standalone host-wide default selection. Engines that already own an
//! intent use `set_default_with`; this entry records selection and cross-pool
//! clears before the first effect, so interruption has an explicit continuation.
//!
//! It is refused while any boot environment has a `canmount=on` descendant
//! ([`crate::mounting::refusal`]): the default would boot with
//! that child mounted over it.
use super::{
    BootChange, BootSetting, DefaultChange, MetadataBackend, NativeMetadata, metadata_admit,
    pool_default, pool_of, refuse, verify_default_assets,
};
use crate::{menu::Result, tree};
use serde::{Deserialize, Serialize};
use std::io::Write;
use zfs_tools::engine::{
    intent::{self, Intent},
    management::Endpoint,
    state::NativeState,
};

pub const KIND: &str = "default";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prior {
    pool: Endpoint,
    default: Endpoint,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    pool: Endpoint,
    selected: Endpoint,
    /// Exact recursive identities and ownership admitted before the record.
    binding: String,
    prior: Option<String>,
    clears: Vec<Prior>,
}

pub trait Backend: MetadataBackend + intent::Backend {}
impl<T: MetadataBackend + intent::Backend> Backend for T {}
impl intent::Backend for NativeMetadata {
    fn pools(&mut self) -> std::result::Result<Vec<String>, zfs_tools::engine::Error> {
        intent::Native.pools()
    }
    fn read(
        &mut self,
        pool: &str,
    ) -> std::result::Result<Option<String>, zfs_tools::engine::Error> {
        intent::Native.read(pool)
    }
    fn write(
        &mut self,
        pool: &str,
        value: &str,
    ) -> std::result::Result<(), zfs_tools::engine::Error> {
        intent::Native.write(pool, value)
    }
    fn remove(&mut self, pool: &str) -> std::result::Result<(), zfs_tools::engine::Error> {
        intent::Native.remove(pool)
    }
}

fn endpoint(state: &NativeState, name: &str) -> Result<Endpoint> {
    Ok(tree::endpoint(tree::dataset(state, name)?))
}
fn binding(state: &NativeState, name: &str) -> Result<String> {
    let (scope, owner, _) = metadata_admit(state, name, &BootSetting::Default)?;
    Ok(tree::digest(&(scope, owner))?)
}
pub(super) fn bound(state: &NativeState, expected: &Endpoint) -> Result<()> {
    let pool_guid = state
        .pool_properties
        .get(pool_of(&expected.name))
        .and_then(|p| p.get("guid"))
        .map(|p| p.value.as_str());
    let properties = state.dataset_properties.get(&expected.name);
    let native_ids = [
        ("guid", expected.identity.guid.to_string()),
        ("createtxg", expected.identity.createtxg.to_string()),
        ("objsetid", expected.identity.objsetid.to_string()),
    ];
    if endpoint(state, &expected.name)? != *expected
        || pool_guid != Some(expected.identity.pool_guid.to_string().as_str())
        || native_ids.iter().any(|(key, value)| {
            properties
                .and_then(|p| p.get(*key))
                .is_none_or(|p| p.value != *value)
        })
    {
        return Err(refuse(format!(
            "default selection identity changed: {}",
            expected.name
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    state: State,
}
impl Plan {
    pub fn dataset(&self) -> &str {
        &self.state.selected.name
    }
}

pub fn plan(dataset: &str) -> Result<Plan> {
    plan_with(dataset, &mut NativeMetadata)
}
pub fn plan_with(dataset: &str, backend: &mut impl Backend) -> Result<Plan> {
    let observed = backend.observe()?;
    if let Some(reason) = crate::mounting::refusal(&observed, None) {
        return Err(refuse(reason));
    }
    let (scope, owner, _) = metadata_admit(&observed, dataset, &BootSetting::Default)?;
    verify_default_assets(dataset, &scope, &owner, backend)?;
    let pool = pool_of(dataset);
    let state = State {
        pool: endpoint(&observed, pool)?,
        selected: endpoint(&observed, dataset)?,
        binding: binding(&observed, dataset)?,
        prior: pool_default(&observed, pool).map(str::to_owned),
        clears: super::other_defaults(&observed, dataset)
            .into_iter()
            .map(|(pool, default)| {
                Ok(Prior {
                    pool: endpoint(&observed, &pool)?,
                    default: endpoint(&observed, &default)?,
                })
            })
            .collect::<Result<_>>()?,
    };
    bound(&observed, &state.pool)?;
    bound(&observed, &state.selected)?;
    for prior in &state.clears {
        bound(&observed, &prior.pool)?;
        bound(&observed, &prior.default)?;
        if backend.read(&prior.pool.name)?.is_some() {
            return Err(refuse(format!(
                "pool {} has an unfinished operation; resume or abandon it first",
                prior.pool.name
            )));
        }
    }
    Ok(Plan { state })
}

#[cfg(test)]
pub fn start_with(dataset: &str, backend: &mut impl Backend) -> Result<DefaultChange> {
    let plan = plan_with(dataset, backend)?;
    execute_with(&plan, backend)
}
pub fn execute(plan: &Plan) -> Result<DefaultChange> {
    execute_with(plan, &mut NativeMetadata)
}
pub fn execute_with(plan: &Plan, backend: &mut impl Backend) -> Result<DefaultChange> {
    if plan_with(plan.dataset(), backend)? != *plan {
        return Err(refuse(
            "the default selection plan changed; preview it again",
        ));
    }
    let pool = plan.state.pool.name.clone();
    let record = Intent::new(tree::new_id(), KIND, plan.state.clone());
    let maximum = Intent {
        step: record.state.clears.len() as u32 + 1,
        ..record.clone()
    };
    intent::encode(&maximum)?;
    intent::begin(backend, &pool, &record)?;
    let id = record.id.clone();
    run(record, backend).map_err(|e| refuse(tree::stopped(&id, tree::refuse(e.to_string()))))
}

fn current(backend: &mut impl Backend, record: &Intent<State>) -> Result<()> {
    if backend.read(&record.state.pool.name)?.as_deref() != Some(intent::encode(record)?.as_str()) {
        return Err(refuse("default operation record changed; nothing changed"));
    }
    Ok(())
}
fn check(backend: &mut impl Backend, record: &Intent<State>) -> Result<NativeState> {
    current(backend, record)?;
    let state = backend.observe()?;
    if let Some(reason) = crate::mounting::refusal(&state, None) {
        return Err(refuse(reason));
    }
    let plan = &record.state;
    bound(&state, &plan.pool)?;
    bound(&state, &plan.selected)?;
    if binding(&state, &plan.selected.name)? != plan.binding {
        return Err(refuse("default selection members or ownership changed"));
    }
    let selected = pool_default(&state, &plan.pool.name);
    if selected != Some(plan.selected.name.as_str())
        && (record.step > 0 || selected != plan.prior.as_deref())
    {
        return Err(refuse(
            "selected pool default changed outside this operation",
        ));
    }
    for (index, prior) in plan.clears.iter().enumerate() {
        bound(&state, &prior.pool)?;
        bound(&state, &prior.default)?;
        let now = pool_default(&state, &prior.pool.name);
        if now.is_some()
            && (now != Some(prior.default.name.as_str()) || record.step > index as u32 + 1)
        {
            return Err(refuse(
                "another pool default changed outside this operation",
            ));
        }
        if backend.read(&prior.pool.name)?.is_some() {
            return Err(refuse(
                "another default pool now has an unfinished operation",
            ));
        }
    }
    if super::other_defaults(&state, &plan.selected.name)
        .iter()
        .any(|(pool, default)| {
            !plan
                .clears
                .iter()
                .any(|p| p.pool.name == *pool && p.default.name == *default)
        })
    {
        return Err(refuse(
            "an unplanned pool default appeared; nothing changed",
        ));
    }
    Ok(state)
}
fn check_assets(backend: &mut impl Backend, record: &Intent<State>) -> Result<NativeState> {
    let state = check(backend, record)?;
    let target = &record.state.selected.name;
    let (scope, owner, _) = metadata_admit(&state, target, &BootSetting::Default)?;
    verify_default_assets(target, &scope, &owner, backend)?;
    // The probe cannot adopt a changed record or another pool's new default.
    check(backend, record)
}

fn advance(backend: &mut impl Backend, record: &mut Intent<State>, step: u32) -> Result<()> {
    let next = Intent {
        step,
        ..record.clone()
    };
    intent::advance(backend, &record.state.pool.name, record, &next)?;
    *record = next;
    Ok(())
}
fn change(dataset: &str, value: &str, complete: bool) -> BootChange {
    BootChange {
        dataset: dataset.into(),
        property: "bootfs".into(),
        value: value.into(),
        complete,
        detail: None,
    }
}
fn stopped(mut outcome: DefaultChange, id: &str, detail: String) -> DefaultChange {
    zfs_tools::engine::effect::operation_hint(id);
    outcome.detail = Some(format!("{detail} (operation {id})"));
    outcome
}
fn run(mut record: Intent<State>, backend: &mut impl Backend) -> Result<DefaultChange> {
    let target = record.state.selected.name.clone();
    let mut outcome = DefaultChange {
        dataset: target.clone(),
        selected: change(&target, &target, false),
        cleared: Vec::new(),
        complete: false,
        detail: None,
    };
    let before = check_assets(backend, &record)?;
    if pool_default(&before, &record.state.pool.name) != Some(target.as_str()) {
        // Recheck the recorded binding immediately before the native effect;
        // do not re-plan against a replacement selected dataset.
        check_assets(backend, &record)?;
        let error = backend.set(&target, &BootSetting::Default).err();
        let after = check(backend, &record)?;
        outcome.selected.complete =
            pool_default(&after, &record.state.pool.name) == Some(target.as_str());
        if !outcome.selected.complete {
            let detail = error.map_or_else(
                || "selected default was not verified".into(),
                |e| e.to_string(),
            );
            return Ok(stopped(outcome, &record.id, detail));
        }
    }
    outcome.selected.complete = true;
    if record.step == 0 {
        advance(backend, &mut record, 1)?;
    }
    for index in 0..record.state.clears.len() {
        let before = check(backend, &record)?;
        let prior = &record.state.clears[index];
        let cleared = if pool_default(&before, &prior.pool.name).is_none() {
            change(&prior.default.name, "", true)
        } else {
            let name = prior.default.name.clone();
            let pool = prior.pool.name.clone();
            check_assets(backend, &record)?;
            let error = backend.set(&name, &BootSetting::ClearDefault).err();
            let after = check(backend, &record)?;
            let mut cleared = change(&name, "", pool_default(&after, &pool).is_none());
            if !cleared.complete {
                cleared.detail = Some(error.map_or_else(
                    || "other default was not verified cleared".into(),
                    |e| e.to_string(),
                ));
            }
            cleared
        };
        let complete = cleared.complete;
        let detail = cleared.detail.clone();
        outcome.cleared.push(cleared);
        if !complete {
            return Ok(stopped(
                outcome,
                &record.id,
                detail.unwrap_or_else(|| "other default was not verified cleared".into()),
            ));
        }
        let step = index as u32 + 2;
        if record.step < step {
            advance(backend, &mut record, step)?;
        }
    }
    let after = check(backend, &record)?;
    if pool_default(&after, &record.state.pool.name) != Some(target.as_str())
        || !super::other_defaults(&after, &target).is_empty()
    {
        return Err(refuse(
            "host-wide default completion was not verified; operation retained",
        ));
    }
    intent::finish(backend, &record.state.pool.name, &record)?;
    outcome.complete = true;
    Ok(outcome)
}

pub use crate::pairs::ResumeOutcome;
pub fn resume_outcome(
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
) -> std::result::Result<ResumeOutcome, zfs_tools::engine::Error> {
    resume_with(record, abandon, dialogue, &mut NativeMetadata)
}
pub fn resume_with(
    record: Intent<serde_json::Value>,
    abandon: bool,
    dialogue: &mut dyn Write,
    backend: &mut impl Backend,
) -> std::result::Result<ResumeOutcome, zfs_tools::engine::Error> {
    let record: Intent<State> = tree::decode(record, KIND)?;
    let id = record.id.clone();
    let result = (|| -> Result<ResumeOutcome> {
        if record.step > record.state.clears.len() as u32 + 1
            || record.state.pool.name != pool_of(&record.state.selected.name)
        {
            return Err(refuse("invalid default operation state"));
        }
        if abandon {
            current(backend, &record)?;
            bound(&backend.observe()?, &record.state.pool)?;
            intent::finish(backend, &record.state.pool.name, &record)?;
            let _ = writeln!(
                dialogue,
                "Default operation {id} abandoned; current pool defaults are unchanged. The Menu refuses automatic boot if more than one remains."
            );
            return Ok(ResumeOutcome {
                complete: true,
                result: serde_json::json!({"operation_id": id, "complete": true, "abandoned": true}),
            });
        }
        let _ = writeln!(dialogue, "Continuing default operation {id}.");
        let done = run(record, backend)?;
        Ok(ResumeOutcome {
            complete: done.complete,
            result: serde_json::to_value(done).map_err(|e| refuse(e.to_string()))?,
        })
    })();
    result.map_err(|e| tree::stopped(&id, tree::refuse(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zfs_tools::engine::{Error, native::NativeProperty};

    fn prop(value: &str) -> NativeProperty {
        NativeProperty {
            value: value.into(),
            source: "local".into(),
        }
    }
    struct Fake {
        state: NativeState,
        records: BTreeMap<String, String>,
        mutations: usize,
        cut: Option<(usize, bool)>,
        fail_clear: bool,
        valid_assets: std::collections::BTreeSet<String>,
        asset_probes: usize,
        missing_at_probe: Option<usize>,
    }
    impl Fake {
        fn new() -> Self {
            let state = super::super::tests::fixture_from(
                &[
                    ("apool", "none", 1),
                    ("apool/old", "/old", 2),
                    ("bpool", "none", 3),
                    ("bpool/BE", "none", 4),
                    ("bpool/BE/proof", "/", 5),
                    ("bpool/BE/old", "/old", 6),
                    ("cpool", "none", 7),
                    ("cpool/old", "/old", 8),
                ],
                &[
                    ("apool", 100, Some("apool/old")),
                    ("bpool", 200, Some("bpool/BE/old")),
                    ("cpool", 300, Some("cpool/old")),
                ],
                // Boot environments are `noauto`, as zboot creates them.
                &[
                    ("apool/old", "off", "noauto"),
                    ("bpool/BE/proof", "off", "noauto"),
                    ("bpool/BE/old", "off", "noauto"),
                    ("cpool/old", "off", "noauto"),
                ],
            );
            Self {
                state,
                records: BTreeMap::new(),
                mutations: 0,
                cut: None,
                fail_clear: false,
                valid_assets: ["bpool/BE/proof".into()].into(),
                asset_probes: 0,
                missing_at_probe: None,
            }
        }
        fn mutation(&mut self, apply: impl FnOnce(&mut Self)) -> std::result::Result<(), Error> {
            let index = self.mutations;
            self.mutations += 1;
            if self.cut == Some((index, false)) {
                return Err(tree::refuse("cut before effect"));
            }
            apply(self);
            if self.cut == Some((index, true)) {
                return Err(tree::refuse("lost effect reply"));
            }
            Ok(())
        }
        fn record(&self) -> Intent<serde_json::Value> {
            serde_json::from_str(self.records.get("bpool").unwrap()).unwrap()
        }
        fn assert_done(&mut self) {
            assert_eq!(pool_default(&self.state, "bpool"), Some("bpool/BE/proof"));
            assert!(super::super::other_defaults(&self.state, "bpool/BE/proof").is_empty());
            assert!(self.records.is_empty());
        }
    }
    impl MetadataBackend for Fake {
        fn observe(&mut self) -> Result<NativeState> {
            Ok(self.state.clone())
        }
        fn verify_boot_assets(&mut self, dataset: &str) -> Result<()> {
            self.asset_probes += 1;
            if self.missing_at_probe == Some(self.asset_probes) {
                self.valid_assets.remove(dataset);
            }
            if self.valid_assets.contains(dataset) {
                Ok(())
            } else {
                Err(refuse("no matching kernel/initrd pairs found"))
            }
        }
        fn set(&mut self, dataset: &str, setting: &BootSetting) -> Result<()> {
            if self.fail_clear && *setting == BootSetting::ClearDefault {
                return Err(refuse("clear refused"));
            }
            self.mutation(|this| {
                let value = match setting {
                    BootSetting::Default => dataset,
                    BootSetting::ClearDefault => "-",
                    _ => panic!(),
                };
                this.state
                    .pool_properties
                    .get_mut(pool_of(dataset))
                    .unwrap()
                    .insert("bootfs".into(), prop(value));
            })?;
            Ok(())
        }
    }
    impl intent::Backend for Fake {
        fn pools(&mut self) -> std::result::Result<Vec<String>, Error> {
            Ok(self.state.pool_properties.keys().cloned().collect())
        }
        fn read(&mut self, pool: &str) -> std::result::Result<Option<String>, Error> {
            Ok(self.records.get(pool).cloned())
        }
        fn write(&mut self, pool: &str, value: &str) -> std::result::Result<(), Error> {
            self.mutation(|this| {
                this.records.insert(pool.into(), value.into());
            })
        }
        fn remove(&mut self, pool: &str) -> std::result::Result<(), Error> {
            self.mutation(|this| {
                this.records.remove(pool);
            })
        }
    }
    #[test]
    fn a_default_plan_names_exactly_the_pools_it_writes() {
        let mut fake = Fake::new();
        let state = fake.state.clone();
        let plan = plan_with("bpool/BE/proof", &mut fake).unwrap();
        assert_eq!(
            crate::cli::access::tests::reopened(
                &state,
                crate::cli::access::plan_pools(&serde_json::to_value(&plan).unwrap())
            ),
            ["apool", "bpool", "cpool"]
        );
    }

    #[test]
    fn a_default_plan_names_only_the_pools_whose_default_it_clears() {
        let mut fake = Fake::new();
        fake.state
            .pool_properties
            .get_mut("cpool")
            .unwrap()
            .remove("bootfs");
        let state = fake.state.clone();
        let plan = plan_with("bpool/BE/proof", &mut fake).unwrap();
        assert_eq!(
            crate::cli::access::tests::reopened(
                &state,
                crate::cli::access::plan_pools(&serde_json::to_value(&plan).unwrap())
            ),
            ["apool", "bpool"]
        );
    }

    #[test]
    fn a_missing_kernel_pair_refuses_default_before_any_intent_or_effect() {
        let mut fake = Fake::new();
        fake.valid_assets.clear();
        let before = fake.state.pool_properties.clone();
        assert!(
            plan_with("bpool/BE/proof", &mut fake)
                .unwrap_err()
                .to_string()
                .contains("kernel/initrd")
        );
        assert_eq!(fake.mutations, 0);
        assert!(fake.records.is_empty());
        assert_eq!(fake.state.pool_properties, before);

        let mut fake = Fake::new();
        let plan = plan_with("bpool/BE/proof", &mut fake).unwrap();
        fake.valid_assets.clear();
        assert!(execute_with(&plan, &mut fake).is_err());
        assert_eq!(fake.mutations, 0);
        assert!(fake.records.is_empty());
    }

    #[test]
    fn unmarked_received_root_placement_with_assets_is_admitted_as_default() {
        let mut fake = Fake::new();
        fake.state
            .dataset_properties
            .get_mut("bpool/BE/proof")
            .unwrap()
            .get_mut("mountpoint")
            .unwrap()
            .source = "received".into();
        let plan = plan_with("bpool/BE/proof", &mut fake).unwrap();
        assert_eq!(plan.dataset(), "bpool/BE/proof");
        assert!(execute_with(&plan, &mut fake).unwrap().complete);
        fake.assert_done();
    }

    #[test]
    fn missing_assets_after_intent_leave_a_record_but_dispatch_no_bootfs_change() {
        for probe in [3, 4] {
            let mut fake = Fake::new();
            fake.missing_at_probe = Some(probe);
            let before = fake.state.pool_properties.clone();
            assert!(start_with("bpool/BE/proof", &mut fake).is_err());
            assert_eq!(
                fake.mutations, 1,
                "only the intent was written at probe {probe}"
            );
            assert_eq!(fake.record().step, 0);
            assert_eq!(fake.state.pool_properties, before);
        }
    }

    #[test]
    fn a_default_preview_is_stable_and_rechecks_every_named_default_before_intent() {
        for attack in 0..5 {
            let mut fake = Fake::new();
            let before = fake.state.pool_properties.clone();
            let plan = plan_with("bpool/BE/proof", &mut fake).unwrap();
            assert_eq!(plan, plan_with("bpool/BE/proof", &mut fake).unwrap());
            assert_eq!(fake.state.pool_properties, before);
            assert_eq!(fake.mutations, 0);
            assert!(fake.records.is_empty());
            match attack {
                0 => {
                    fake.state
                        .pool_properties
                        .get_mut("bpool")
                        .unwrap()
                        .insert("guid".into(), prop("999"));
                }
                1 => {
                    fake.state
                        .dataset_properties
                        .get_mut("bpool/BE/proof")
                        .unwrap()
                        .insert("guid".into(), prop("999"));
                }
                2 => {
                    fake.state
                        .dataset_properties
                        .get_mut("bpool/BE/proof")
                        .unwrap()
                        .insert("zboot:pending".into(), prop("foreign"));
                }
                3 => {
                    fake.state
                        .pool_properties
                        .get_mut("apool")
                        .unwrap()
                        .insert("bootfs".into(), prop("bpool/BE/old"));
                }
                4 => {
                    fake.state
                        .dataset_properties
                        .get_mut("apool/old")
                        .unwrap()
                        .insert("guid".into(), prop("999"));
                }
                _ => unreachable!(),
            }
            let changed = fake.state.pool_properties.clone();
            assert!(execute_with(&plan, &mut fake).is_err(), "attack {attack}");
            assert_eq!(fake.mutations, 0, "attack {attack}");
            assert!(fake.records.is_empty(), "attack {attack}");
            assert_eq!(fake.state.pool_properties, changed);
        }
        let mut fake = Fake::new();
        let plan = plan_with("bpool/BE/proof", &mut fake).unwrap();
        assert!(execute_with(&plan, &mut fake).unwrap().complete);
        fake.assert_done();
    }

    #[test]
    fn every_effect_and_record_cut_resumes_with_one_default() {
        let mut baseline = Fake::new();
        assert!(
            start_with("bpool/BE/proof", &mut baseline)
                .unwrap()
                .complete
        );
        let effects = baseline.mutations;
        baseline.assert_done();
        for cut in 0..effects {
            for after in [false, true] {
                let mut fake = Fake::new();
                fake.cut = Some((cut, after));
                let first = start_with("bpool/BE/proof", &mut fake);
                fake.cut = None;
                if !fake.records.is_empty() {
                    let record = fake.record();
                    assert!(
                        resume_with(record, false, &mut Vec::new(), &mut fake)
                            .unwrap()
                            .complete,
                        "cut {cut} after {after}"
                    );
                } else if first.is_err() {
                    assert!(start_with("bpool/BE/proof", &mut fake).unwrap().complete);
                }
                fake.assert_done();
            }
        }
    }
    fn paused() -> Fake {
        let mut fake = Fake::new();
        fake.fail_clear = true;
        let outcome = start_with("bpool/BE/proof", &mut fake).unwrap();
        assert!(!outcome.complete);
        assert!(outcome.detail.unwrap().contains(&fake.record().id));
        assert_eq!(fake.record().step, 1);
        fake.fail_clear = false;
        fake
    }
    #[test]
    fn changed_pool_dataset_members_or_new_defaults_refuse_without_effects() {
        for attack in 0..6 {
            let mut fake = paused();
            match attack {
                0 => {
                    fake.state
                        .pool_properties
                        .get_mut("apool")
                        .unwrap()
                        .insert("guid".into(), prop("999"));
                }
                1 => {
                    fake.state
                        .dataset_properties
                        .get_mut("bpool/BE/proof")
                        .unwrap()
                        .insert("guid".into(), prop("999"));
                }
                2 => {
                    fake.state
                        .dataset_properties
                        .get_mut("bpool/BE/proof")
                        .unwrap()
                        .insert("zboot:pending".into(), prop("foreign"));
                }
                3 => {
                    fake.state
                        .pool_properties
                        .get_mut("apool")
                        .unwrap()
                        .insert("bootfs".into(), prop("apool/new"));
                }
                4 => {
                    fake.state.pool_properties.insert(
                        "newpool".into(),
                        BTreeMap::from([("bootfs".into(), prop("newpool/BE/new"))]),
                    );
                }
                5 => {
                    fake.state
                        .dataset_properties
                        .get_mut("apool/old")
                        .unwrap()
                        .insert("guid".into(), prop("999"));
                }
                _ => unreachable!(),
            }
            let mutations = fake.mutations;
            let record = fake.record();
            assert!(
                resume_with(record, false, &mut Vec::new(), &mut fake).is_err(),
                "attack {attack}"
            );
            assert_eq!(fake.mutations, mutations, "attack {attack}");
            assert!(!fake.records.is_empty());
        }
    }
    #[test]
    fn a_resumed_default_without_assets_preserves_its_record_and_other_defaults() {
        let mut fake = paused();
        fake.valid_assets.clear();
        let before = fake.state.pool_properties.clone();
        let mutations = fake.mutations;
        let record = fake.record();
        assert!(resume_with(record, false, &mut Vec::new(), &mut fake).is_err());
        assert_eq!(fake.mutations, mutations);
        assert_eq!(fake.state.pool_properties, before);
        assert!(!fake.records.is_empty());
        let record = fake.record();
        assert!(
            resume_with(record, true, &mut Vec::new(), &mut fake)
                .unwrap()
                .complete
        );
        assert_eq!(fake.state.pool_properties, before);
        assert!(fake.records.is_empty());
    }

    #[test]
    fn a_resumed_default_refuses_a_new_host_wide_automount_hazard_without_effects() {
        let mut fake = paused();
        let hazard = "cpool/old";
        fake.state
            .inspection
            .datasets
            .iter_mut()
            .find(|d| d.name == hazard)
            .unwrap()
            .canmount = Some(zfs_tools::engine::CanMount::On);
        fake.state
            .dataset_properties
            .get_mut(hazard)
            .unwrap()
            .insert("canmount".into(), prop("on"));
        let before = fake.state.pool_properties.clone();
        let mutations = fake.mutations;
        let record = fake.record();
        let error = resume_with(record, false, &mut Vec::new(), &mut fake).unwrap_err();
        assert!(error.to_string().contains(hazard), "{error}");
        assert_eq!(fake.mutations, mutations);
        assert_eq!(fake.state.pool_properties, before);
        assert!(!fake.records.is_empty());
        fake.state
            .inspection
            .datasets
            .iter_mut()
            .find(|d| d.name == hazard)
            .unwrap()
            .canmount = Some(zfs_tools::engine::CanMount::NoAuto);
        fake.state
            .dataset_properties
            .get_mut(hazard)
            .unwrap()
            .insert("canmount".into(), prop("noauto"));
        let record = fake.record();
        assert!(
            resume_with(record, false, &mut Vec::new(), &mut fake)
                .unwrap()
                .complete
        );
        fake.assert_done();
    }

    #[test]
    fn partial_completion_has_typed_result_and_abandon_changes_no_defaults() {
        let mut fake = paused();
        fake.fail_clear = true;
        let record = fake.record();
        let result = resume_with(record, false, &mut Vec::new(), &mut fake).unwrap();
        assert!(!result.complete);
        let before = fake.state.pool_properties.clone();
        let record = fake.record();
        assert!(
            resume_with(record, true, &mut Vec::new(), &mut fake)
                .unwrap()
                .complete
        );
        assert_eq!(fake.state.pool_properties, before);
        assert!(fake.records.is_empty());
    }
    #[test]
    fn other_pool_operations_and_oversized_records_refuse_before_bootfs_effects() {
        let mut fake = Fake::new();
        fake.records.insert("apool".into(), "other".into());
        assert!(start_with("bpool/BE/proof", &mut fake).is_err());
        assert_eq!(fake.mutations, 0);
        let mut fake = Fake::new();
        let mut record = Intent::new(
            "id",
            KIND,
            State {
                pool: endpoint(&fake.state, "bpool").unwrap(),
                selected: endpoint(&fake.state, "bpool/BE/proof").unwrap(),
                binding: binding(&fake.state, "bpool/BE/proof").unwrap(),
                prior: None,
                clears: vec![],
            },
        );
        record.state.clears = vec![
            Prior {
                pool: endpoint(&fake.state, "apool").unwrap(),
                default: endpoint(&fake.state, "apool/old").unwrap()
            };
            100
        ];
        assert!(intent::begin(&mut fake, "bpool", &record).is_err());
        assert_eq!(fake.mutations, 0);
    }
}
