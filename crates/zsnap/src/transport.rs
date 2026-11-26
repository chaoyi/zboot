//! Versioned policy transport. Expected observations are comparisons, never authority:
//! native admission and the shared executor revalidate the reviewed state before
//! each effect.
use crate::{Config, properties};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zfs_tools::engine::{DatasetIdentity, state::NativeState};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyValue {
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExpected {
    pub dataset: String,
    pub identity: DatasetIdentity,
    pub policy: Option<PropertyValue>,
    pub local_value: Option<String>,
    /// Intended effective value/source after removing the local assignment.
    /// Bound along with the complete ancestor policy chain, including absence.
    pub inherited_policy: Option<PropertyValue>,
    /// Exact management and writable posture observations, including ancestors
    /// and pair peers. Unrelated management drift conservatively invalidates a plan.
    pub authority: BTreeMap<String, BTreeMap<String, PropertyValue>>,
    pub blocker: Option<String>,
}

pub use crate::properties::PolicyChange;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRequest {
    pub schema_version: u32,
    pub expected: PolicyExpected,
    pub change: PolicyChange,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResult {
    pub schema_version: u32,
    pub outcome: properties::PolicyOutcome,
}

pub fn observe_policy(state: &NativeState, dataset: &str) -> Result<PolicyExpected> {
    zfs_tools::engine::validate_dataset_name(dataset)?;
    let head = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == dataset)
        .ok_or_else(|| anyhow::anyhow!("dataset was not observed: {dataset}"))?;
    let props = state
        .dataset_properties
        .get(dataset)
        .ok_or_else(|| anyhow::anyhow!("dataset properties were not observed: {dataset}"))?;
    let policy = props.get(crate::POLICY_PROPERTY).map(|p| PropertyValue {
        value: p.value.clone(),
        source: p.source.clone(),
    });
    let local_value = policy
        .as_ref()
        .filter(|p| p.source == "local")
        .map(|p| p.value.clone());
    let mut authority = BTreeMap::new();
    for (prefix, inventory) in [
        ("dataset", &state.dataset_properties),
        ("pool", &state.pool_properties),
    ] {
        for (name, props) in inventory {
            let values = props
                .iter()
                .filter(|(key, _)| {
                    (prefix == "dataset"
                        && key.as_str() == crate::POLICY_PROPERTY
                        && is_ancestor(name, dataset))
                        || zfs_tools::engine::management::managed_key(key)
                        || matches!(
                            key.as_str(),
                            "guid" | "createtxg" | "objsetid" | "readonly" | "canmount"
                        )
                })
                .map(|(key, p)| {
                    (
                        key.clone(),
                        PropertyValue {
                            value: p.value.clone(),
                            source: p.source.clone(),
                        },
                    )
                })
                .collect();
            authority.insert(format!("{prefix}:{name}"), values);
        }
    }
    let mut blocker = properties::preview_policy(
        state,
        &properties::PolicyRequest {
            dataset: dataset.into(),
            change: properties::PolicyChange::Inherit,
        },
    )
    .err()
    .map(|e| e.to_string());
    let inherited_policy = match inherited_policy(state, dataset) {
        Ok(policy) => policy,
        Err(error) => {
            blocker.get_or_insert_with(|| error.to_string());
            None
        }
    };
    Ok(PolicyExpected {
        dataset: dataset.into(),
        identity: head.identity.clone(),
        policy,
        local_value,
        inherited_policy,
        authority,
        blocker,
    })
}

fn is_ancestor(ancestor: &str, dataset: &str) -> bool {
    dataset
        .strip_prefix(ancestor)
        .is_some_and(|tail| tail.starts_with('/'))
}

fn inherited_policy(state: &NativeState, dataset: &str) -> Result<Option<PropertyValue>> {
    let Some((parent, _)) = dataset.rsplit_once('/') else {
        return Ok(None);
    };
    let properties = state
        .dataset_properties
        .get(parent)
        .ok_or_else(|| anyhow::anyhow!("parent policy properties were not observed: {parent}"))?;
    let Some(policy) = properties.get(crate::POLICY_PROPERTY) else {
        return Ok(None);
    };
    let source = match policy.source.as_str() {
        "local" | "received" => format!("inherited from {parent}"),
        "-" if policy.value == "-" => return Ok(None),
        source
            if source
                .strip_prefix("inherited from ")
                .is_some_and(|origin| is_ancestor(origin, parent)) =>
        {
            source.to_owned()
        }
        _ => bail!("cannot predict inherited policy with unsupported source on {parent}"),
    };
    Ok(Some(PropertyValue {
        value: policy.value.clone(),
        source,
    }))
}

pub fn apply_policy(config: &Config, request: &PolicyRequest) -> Result<PolicyResult> {
    apply_policy_with(config, request, &mut properties::NativePolicy)
}

pub fn apply_policy_with(
    config: &Config,
    request: &PolicyRequest,
    backend: &mut impl properties::PolicyBackend,
) -> Result<PolicyResult> {
    if request.schema_version != SCHEMA_VERSION {
        bail!("unsupported policy request schema");
    }
    if request.expected.blocker.is_some() {
        bail!("reviewed dataset was not admitted for policy assignment");
    }
    let intended = match &request.change {
        PolicyChange::Set(value) => Some(PropertyValue {
            value: value.clone(),
            source: "local".into(),
        }),
        PolicyChange::Inherit => request.expected.inherited_policy.clone(),
    };
    let intended = properties::PolicyObservation {
        value: intended.as_ref().map(|p| p.value.clone()),
        source: intended.as_ref().map(|p| p.source.clone()),
    };
    let change = match &request.change {
        PolicyChange::Set(value) => {
            config.assignment(value)?;
            PolicyChange::Set(value.clone())
        }
        PolicyChange::Inherit => PolicyChange::Inherit,
    };
    struct ExpectedBackend<'a, B> {
        backend: &'a mut B,
        expected: &'a PolicyExpected,
        effected: bool,
    }
    impl<B: properties::PolicyBackend> properties::PolicyBackend for ExpectedBackend<'_, B> {
        fn observe(&mut self) -> Result<NativeState, zfs_tools::engine::Error> {
            let state = self.backend.observe()?;
            if !self.effected {
                let current = observe_policy(&state, &self.expected.dataset)
                    .map_err(|e| zfs_tools::engine::Error::Inconsistent(e.to_string()))?;
                if current.blocker.is_some() || &current != self.expected {
                    return Err(zfs_tools::engine::Error::Inconsistent(
                        "policy expected state changed; review again".into(),
                    ));
                }
            }
            Ok(state)
        }
        fn change(
            &mut self,
            request: &properties::PolicyRequest,
        ) -> Result<(), zfs_tools::engine::Error> {
            self.effected = true;
            self.backend.change(request)
        }
    }
    let mut outcome = properties::change_policy_with(
        &properties::PolicyRequest {
            dataset: request.expected.dataset.clone(),
            change,
        },
        &mut ExpectedBackend {
            backend,
            expected: &request.expected,
            effected: false,
        },
    )?;
    if outcome
        .effective
        .as_ref()
        .is_some_and(|effective| effective != &intended)
    {
        outcome.status = properties::PolicyStatus::Uncertain;
        let detail = "effective policy differs from the reviewed intended value/source";
        outcome.detail = Some(
            outcome
                .detail
                .map_or_else(|| detail.into(), |prior| format!("{prior}; {detail}")),
        );
    }
    Ok(PolicyResult {
        schema_version: SCHEMA_VERSION,
        outcome,
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyStatusReport {
    pub schema_version: u32,
    pub observed_at: i64,
    pub non_atomic: bool,
    pub policies: BTreeMap<String, crate::Policy>,
    pub datasets: Vec<DatasetStatus>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetStatus {
    pub expected: PolicyExpected,
    pub snapshots: usize,
    pub oldest_age_seconds: Option<i64>,
    pub newest_age_seconds: Option<i64>,
    pub used_by_snapshots_bytes: Option<u64>,
    pub accounting_error: Option<String>,
    pub written_since_newest_bytes: Option<u64>,
    pub diagnostic: String,
    pub diagnostic_error: Option<String>,
}

pub fn observe_status(
    state: &NativeState,
    config: &Config,
    dataset: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PolicyStatusReport> {
    observe_status_with(state, config, dataset, now, |head, point| {
        Ok(zfs_tools::engine::observe_written_since(head, point)?.referenced_new_bytes)
    })
}

/// Read-only scheduling heuristic; metric errors are never interpreted as zero.
pub fn observe_status_with(
    state: &NativeState,
    config: &Config,
    dataset: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
    mut written: impl FnMut(&zfs_tools::engine::Dataset, &zfs_tools::engine::SnapshotRef) -> Result<u64>,
) -> Result<PolicyStatusReport> {
    if let Some(dataset) = dataset {
        zfs_tools::engine::validate_dataset_name(dataset)?;
    }
    let snapshots = state
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("snapshot history was not observed"))?;
    let mut datasets = Vec::new();
    for head in state
        .inspection
        .datasets
        .iter()
        .filter(|d| dataset.is_none_or(|name| d.name == name))
    {
        let expected = observe_policy(state, &head.name)?;
        let mut owned: Vec<_> = snapshots
            .iter()
            .filter_map(|s| crate::owned_snap_time(&s.name, &head.name).map(|time| (time, s)))
            .collect();
        owned.sort_by_key(|(time, _)| *time);
        let accounting = state.dataset_properties[&head.name]
            .get("usedbysnapshots")
            .ok_or_else(|| "usedbysnapshots was not observed".to_string())
            .and_then(|p| {
                p.value
                    .parse::<u64>()
                    .map_err(|_| "usedbysnapshots is not known numeric accounting".to_string())
            });
        let mut row = DatasetStatus {
            expected,
            snapshots: owned.len(),
            oldest_age_seconds: owned.first().map(|(t, _)| (now - *t).num_seconds()),
            newest_age_seconds: owned.last().map(|(t, _)| (now - *t).num_seconds()),
            used_by_snapshots_bytes: accounting.as_ref().ok().copied(),
            accounting_error: accounting.err(),
            written_since_newest_bytes: None,
            diagnostic: "disabled".into(),
            diagnostic_error: None,
        };
        if row.expected.blocker.is_some() {
            // A read-only dataset is refused by snapshot admission, but it is
            // an ordinary state, not a blocked one: a fenced pair copy follows
            // its working copy through `zboot sync`.
            row.diagnostic = if !head.readonly {
                "blocked"
            } else if matches!(
                zfs_tools::engine::management::ownership(state, &head.name),
                Ok(zfs_tools::engine::management::Ownership::Secondary { .. })
            ) {
                "fenced"
            } else {
                "read_only"
            }
            .into();
        } else if let Some(value) = row
            .expected
            .policy
            .as_ref()
            .map(|p| p.value.trim())
            .filter(|v| !crate::is_disabled_policy(v))
        {
            if let Some(policy) = config.policies.get(value) {
                row.diagnostic = match owned.last() {
                    None => "no_snapshots",
                    Some((time, _)) if !diagnostic_overdue(*time, policy.frequency, now)? => {
                        "current"
                    }
                    Some((_, snapshot)) => match written(head, &snapshot.point()) {
                        Ok(bytes) => {
                            row.written_since_newest_bytes = Some(bytes);
                            if bytes == 0 {
                                "unchanged"
                            } else {
                                "changed_and_overdue"
                            }
                        }
                        Err(error) => {
                            row.diagnostic_error = Some(format!("{error:#}"));
                            "unknown"
                        }
                    },
                }
                .into();
            } else {
                row.diagnostic = "unknown_policy".into();
            }
        }
        datasets.push(row);
    }
    if let Some(dataset) = dataset
        && datasets.is_empty()
    {
        bail!("dataset was not observed: {dataset}");
    }
    datasets.sort_by(|a, b| a.expected.dataset.cmp(&b.expected.dataset));
    Ok(PolicyStatusReport {
        schema_version: SCHEMA_VERSION,
        observed_at: now.timestamp(),
        non_atomic: true,
        policies: config.policies.clone(),
        datasets,
    })
}

/// Operator warning has a two-frequency grace period; capture scheduling still
/// uses one frequency. An unrepresentably distant threshold cannot be overdue.
fn diagnostic_overdue(
    newest: chrono::DateTime<chrono::Utc>,
    frequency: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    if frequency <= 0 {
        bail!("policy frequency must be positive");
    }
    let threshold = chrono::Duration::try_seconds(frequency)
        .and_then(|duration| duration.checked_mul(2))
        .and_then(|duration| newest.checked_add_signed(duration));
    Ok(threshold.is_some_and(|threshold| now > threshold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::properties::PolicyBackend;
    use zfs_tools::engine::native::NativeProperty;
    fn fixture() -> NativeState {
        fixture_with_history(true)
    }
    fn fixture_with_history(history: bool) -> NativeState {
        let inspection = zfs_tools::engine::native::inspect_with(&zfs_tools::engine::InspectRequest::new(vec![], true).unwrap(), |program, args| {
            Ok(if program == "zpool" {
                "tank\t1\t1000\t100\t900\tONLINE\t-\n".into()
            } else if args[0] == "holds" { String::new() }
            else if args.iter().any(|a| a == "filesystem,volume") {
                "tank\tfilesystem\t1\t0\t900\t0\t/tank\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\t-\t-\n".into()
            } else if !history { String::new() } else {
                "tank@zsnap_2026-06-19-120000\t3\t1781870400\t0\t0\t10\t8\t0\toff\t-\n".into()
            })
        }).unwrap();
        let p = |value: &str, source: &str| NativeProperty {
            value: value.into(),
            source: source.into(),
        };
        NativeState {
            inspection,
            dataset_properties: BTreeMap::from([(
                "tank".into(),
                BTreeMap::from([
                    ("guid".into(), p("1", "-")),
                    ("createtxg".into(), p("5", "-")),
                    ("objsetid".into(), p("6", "-")),
                    (crate::POLICY_PROPERTY.into(), p("guard", "local")),
                    ("usedbysnapshots".into(), p("1024", "-")),
                ]),
            )]),
            pool_properties: BTreeMap::from([(
                "tank".into(),
                BTreeMap::from([("guid".into(), p("1", "-"))]),
            )]),
        }
    }
    struct Fake {
        state: NativeState,
        effects: usize,
        reads: usize,
        drift_on: usize,
        fail_after: bool,
    }
    impl PolicyBackend for Fake {
        fn observe(&mut self) -> Result<NativeState, zfs_tools::engine::Error> {
            self.reads += 1;
            if self.effects > 0 && self.fail_after {
                return Err(zfs_tools::engine::Error::Inconsistent("lost query".into()));
            }
            if self.reads == self.drift_on {
                self.state
                    .dataset_properties
                    .get_mut("tank")
                    .unwrap()
                    .get_mut(crate::POLICY_PROPERTY)
                    .unwrap()
                    .source = "received".into();
            }
            Ok(self.state.clone())
        }
        fn change(
            &mut self,
            request: &properties::PolicyRequest,
        ) -> Result<(), zfs_tools::engine::Error> {
            self.effects += 1;
            let props = self.state.dataset_properties.get_mut("tank").unwrap();
            match &request.change {
                properties::PolicyChange::Set(value) => {
                    props.insert(
                        crate::POLICY_PROPERTY.into(),
                        NativeProperty {
                            value: value.clone(),
                            source: "local".into(),
                        },
                    );
                }
                properties::PolicyChange::Inherit => {
                    props.remove(crate::POLICY_PROPERTY);
                }
            }
            Ok(())
        }
    }
    #[test]
    fn expected_state_binds_source_incarnation_and_authority_before_effect() {
        {
            let config = Config::from_override(None).unwrap();
            let request = PolicyRequest {
                schema_version: 1,
                expected: observe_policy(&fixture(), "tank").unwrap(),
                change: PolicyChange::Set("none".into()),
            };
            assert!(request.expected.blocker.is_none());
            let wire = serde_json::to_string(&request).unwrap();
            assert_eq!(request, serde_json::from_str(&wire).unwrap());
            let mut unknown: serde_json::Value = serde_json::from_str(&wire).unwrap();
            unknown["property"] = serde_json::json!("arbitrary:property");
            assert!(serde_json::from_value::<PolicyRequest>(unknown).is_err());
            let mut invalid = request.clone();
            invalid.schema_version = 99;
            let mut backend = Fake {
                state: fixture(),
                effects: 0,
                reads: 0,
                drift_on: 0,
                fail_after: false,
            };
            assert!(apply_policy_with(&config, &invalid, &mut backend).is_err());
            assert_eq!(backend.reads, 0);
            assert_eq!(backend.effects, 0);
            for drift_on in [1, 2] {
                let mut backend = Fake {
                    state: fixture(),
                    effects: 0,
                    reads: 0,
                    drift_on,
                    fail_after: false,
                };
                assert!(apply_policy_with(&config, &request, &mut backend).is_err());
                assert_eq!(backend.effects, 0);
            }
            for mutation in ["incarnation", "pending", "legacy", "unknown", "readonly"] {
                let mut backend = Fake {
                    state: fixture(),
                    effects: 0,
                    reads: 0,
                    drift_on: 0,
                    fail_after: false,
                };
                let key = match mutation {
                    "incarnation" => "objsetid",
                    "pending" => "zboot:pending",
                    "legacy" => "zboot:primary",
                    "unknown" => "zboot:mystery",
                    _ => "readonly",
                };
                backend
                    .state
                    .dataset_properties
                    .get_mut("tank")
                    .unwrap()
                    .insert(
                        key.into(),
                        NativeProperty {
                            value: "unexpected".into(),
                            source: "local".into(),
                        },
                    );
                assert!(
                    apply_policy_with(&config, &request, &mut backend).is_err(),
                    "{mutation}"
                );
                assert_eq!(backend.effects, 0);
            }
            let mut backend = Fake {
                state: fixture(),
                effects: 0,
                reads: 0,
                drift_on: 0,
                fail_after: true,
            };
            assert_eq!(
                apply_policy_with(&config, &request, &mut backend)
                    .unwrap()
                    .outcome
                    .status,
                properties::PolicyStatus::Uncertain
            );
            assert_eq!(backend.effects, 1);
            backend.fail_after = false;
            let mut request = request;
            request.expected = observe_policy(&backend.state, "tank").unwrap();
            request.change = PolicyChange::Set("guard".into());
            assert_eq!(
                apply_policy_with(&config, &request, &mut backend)
                    .unwrap()
                    .outcome
                    .status,
                properties::PolicyStatus::Complete
            );
            request.expected = observe_policy(&backend.state, "tank").unwrap();
            request.change = PolicyChange::Inherit;
            assert_eq!(
                apply_policy_with(&config, &request, &mut backend)
                    .unwrap()
                    .outcome
                    .status,
                properties::PolicyStatus::Complete
            );
        }
    }
    fn inherited_fixture() -> NativeState {
        let mut state = fixture_with_history(false);
        state.inspection = zfs_tools::engine::native::inspect_with(&zfs_tools::engine::InspectRequest::new(vec![], true).unwrap(), |program, args| {
            Ok(if program == "zpool" {
                "tank\t1\t1000\t100\t900\tONLINE\t-\n".into()
            } else if args.iter().any(|a| a == "filesystem,volume") {
                concat!(
                    "tank\tfilesystem\t1\t0\t900\t0\t/tank\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\t-\t-\n",
                    "tank/parent\tfilesystem\t2\t0\t900\t0\t/tank/parent\t-\t5\t7\tno\toff\ton\t-\toff\t-\t-\t-\t-\n",
                    "tank/parent/child\tfilesystem\t3\t0\t900\t0\t/tank/parent/child\t-\t5\t8\tno\toff\ton\t-\toff\t-\t-\t-\t-\n"
                ).into()
            } else { String::new() })
        }).unwrap();
        for (dataset, guid, objsetid, value, source) in [
            ("tank/parent", "2", "7", "guard", "inherited from tank"),
            ("tank/parent/child", "3", "8", "none", "local"),
        ] {
            let mut props = state.dataset_properties["tank"].clone();
            props.get_mut("guid").unwrap().value = guid.into();
            props.get_mut("objsetid").unwrap().value = objsetid.into();
            props.insert(
                crate::POLICY_PROPERTY.into(),
                NativeProperty {
                    value: value.into(),
                    source: source.into(),
                },
            );
            state.dataset_properties.insert(dataset.into(), props);
        }
        state
    }

    struct ScriptedPolicy {
        states: std::collections::VecDeque<NativeState>,
        effects: usize,
    }
    impl PolicyBackend for ScriptedPolicy {
        fn observe(&mut self) -> Result<NativeState, zfs_tools::engine::Error> {
            Ok(self.states.pop_front().expect("unexpected observation"))
        }
        fn change(
            &mut self,
            _: &properties::PolicyRequest,
        ) -> Result<(), zfs_tools::engine::Error> {
            self.effects += 1;
            Ok(())
        }
    }

    #[test]
    fn unassign_binds_ancestor_chain_at_both_pre_effect_observations() {
        {
            let before = inherited_fixture();
            let config = Config::from_override(None).unwrap();
            let request = PolicyRequest {
                schema_version: 1,
                expected: observe_policy(&before, "tank/parent/child").unwrap(),
                change: PolicyChange::Inherit,
            };
            assert!(request.expected.blocker.is_none());
            assert_eq!(request.expected.local_value.as_deref(), Some("none"));
            assert_eq!(
                request.expected.inherited_policy,
                Some(PropertyValue {
                    value: "guard".into(),
                    source: "inherited from tank".into()
                })
            );
            for ancestor in ["tank", "tank/parent"] {
                for drift_source in [false, true] {
                    for read in [0, 1] {
                        let mut drifted = before.clone();
                        let policy = drifted
                            .dataset_properties
                            .get_mut(ancestor)
                            .unwrap()
                            .get_mut(crate::POLICY_PROPERTY)
                            .unwrap();
                        if drift_source {
                            policy.source = "received".into();
                        } else {
                            policy.value = "history".into();
                        }
                        let mut states =
                            std::collections::VecDeque::from([before.clone(), before.clone()]);
                        states[read] = drifted;
                        let mut backend = ScriptedPolicy { states, effects: 0 };
                        assert!(
                            apply_policy_with(&config, &request, &mut backend).is_err(),
                            "{ancestor}, source={drift_source}, read={read}"
                        );
                        assert_eq!(backend.effects, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn unassign_verifies_the_reviewed_inherited_result_not_just_nonlocal_source() {
        {
            let before = inherited_fixture();
            let config = Config::from_override(None).unwrap();
            let request = PolicyRequest {
                schema_version: 1,
                expected: observe_policy(&before, "tank/parent/child").unwrap(),
                change: PolicyChange::Inherit,
            };
            for (value, source, status) in [
                (
                    "guard",
                    "inherited from tank",
                    properties::PolicyStatus::Complete,
                ),
                (
                    "history",
                    "inherited from tank",
                    properties::PolicyStatus::Uncertain,
                ),
                (
                    "guard",
                    "inherited from tank/parent",
                    properties::PolicyStatus::Uncertain,
                ),
            ] {
                let mut after = before.clone();
                after
                    .dataset_properties
                    .get_mut("tank/parent/child")
                    .unwrap()
                    .insert(
                        crate::POLICY_PROPERTY.into(),
                        NativeProperty {
                            value: value.into(),
                            source: source.into(),
                        },
                    );
                let mut backend = ScriptedPolicy {
                    states: std::collections::VecDeque::from([
                        before.clone(),
                        before.clone(),
                        after,
                    ]),
                    effects: 0,
                };
                let outcome = apply_policy_with(&config, &request, &mut backend)
                    .unwrap()
                    .outcome;
                assert_eq!(outcome.status, status);
                assert_eq!(backend.effects, 1);
                if status == properties::PolicyStatus::Uncertain {
                    assert!(
                        outcome
                            .detail
                            .unwrap()
                            .contains("reviewed intended value/source")
                    );
                }
            }
        }
    }

    #[test]
    fn overdue_warning_has_strictly_more_than_two_frequencies_of_grace() {
        let config = Config::from_override(None).unwrap();
        let newest = crate::snap_time("tank@zsnap_2026-06-19-120000").unwrap();
        let frequency = config.policies["guard"].frequency;
        for age in [frequency, frequency * 2] {
            let now = newest + chrono::Duration::seconds(age);
            assert!(crate::snapshot_due(Some(newest), frequency, now).unwrap());
            let report = observe_status_with(&fixture(), &config, None, now, |_, _| {
                panic!("warning queried writes inside its grace period")
            })
            .unwrap();
            assert_eq!(report.datasets[0].diagnostic, "current");
        }
        let beyond =
            newest + chrono::Duration::seconds(frequency * 2) + chrono::Duration::nanoseconds(1);
        for (written, diagnostic) in [(0, "unchanged"), (1, "changed_and_overdue")] {
            let report =
                observe_status_with(&fixture(), &config, None, beyond, |_, _| Ok(written)).unwrap();
            assert_eq!(report.datasets[0].diagnostic, diagnostic);
        }
    }

    #[test]
    fn diagnostics_distinguish_unchanged_overdue_missing_unknown_and_blocked() {
        let config = Config::from_override(None).unwrap();
        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        for (bytes, expected) in [(0, "unchanged"), (1, "changed_and_overdue")] {
            let status =
                observe_status_with(&fixture(), &config, None, now, |_, _| Ok(bytes)).unwrap();
            assert_eq!(status.datasets[0].diagnostic, expected);
            assert_eq!(status.datasets[0].used_by_snapshots_bytes, Some(1024));
            let wire = serde_json::to_value(&status).unwrap();
            let decoded: PolicyStatusReport = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(decoded.datasets[0].expected, status.datasets[0].expected);
            assert_eq!(decoded.policies, status.policies);
            let mut invalid = wire;
            invalid["unexpected"] = true.into();
            assert!(serde_json::from_value::<PolicyStatusReport>(invalid).is_err());
        }
        assert_eq!(
            observe_status_with(
                &fixture_with_history(false),
                &config,
                None,
                now,
                |_, _| panic!("empty history query")
            )
            .unwrap()
            .datasets[0]
                .diagnostic,
            "no_snapshots"
        );
        let mut state = fixture();
        state
            .dataset_properties
            .get_mut("tank")
            .unwrap()
            .get_mut("usedbysnapshots")
            .unwrap()
            .value = "-".into();
        let status = observe_status_with(&state, &config, None, now, |_, _| {
            bail!("metric unavailable")
        })
        .unwrap();
        assert_eq!(status.datasets[0].diagnostic, "unknown");
        assert!(status.datasets[0].accounting_error.is_some());
        assert!(status.datasets[0].used_by_snapshots_bytes.is_none());
        let recent = crate::snap_time("tank@zsnap_2026-06-19-120000").unwrap();
        assert_eq!(
            observe_status_with(&fixture(), &config, None, recent, |_, _| panic!(
                "recent query"
            ))
            .unwrap()
            .datasets[0]
                .diagnostic,
            "current"
        );
        state.dataset_properties.get_mut("tank").unwrap().insert(
            "zboot:pending".into(),
            NativeProperty {
                value: "unfinished".into(),
                source: "local".into(),
            },
        );
        assert_eq!(
            observe_status_with(&state, &config, None, now, |_, _| panic!("blocked query"))
                .unwrap()
                .datasets[0]
                .diagnostic,
            "blocked"
        );
    }

    /// Read-only datasets are ordinary states in status, not blocked ones: a
    /// fenced pair copy and an unpaired read-only dataset each get their own
    /// diagnostic, and the text view omits the repeated admission refusal.
    #[test]
    fn read_only_and_fenced_datasets_are_reported_plainly() {
        use zfs_tools::engine::management::{Endpoint, PAIR_PROPERTY, PairRecord, Role};
        let inspection = zfs_tools::engine::native::inspect_with(&zfs_tools::engine::InspectRequest::new(vec![], true).unwrap(), |program, args| {
            Ok(if program == "zpool" {
                "tank\t1\t1000\t100\t900\tONLINE\t-\n".into()
            } else if args[0] == "holds" { String::new() }
            else if args.iter().any(|a| a == "filesystem,volume") {
                concat!(
                    "tank\tfilesystem\t1\t0\t900\t0\t/tank\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\t-\t-\n",
                    "tank/copy\tfilesystem\t3\t0\t900\t0\t/tank/copy\t-\t8\t11\tno\ton\tnoauto\t-\toff\t-\t-\t-\t-\n",
                    "tank/data\tfilesystem\t2\t0\t900\t0\t/tank/data\t-\t7\t10\tno\toff\ton\t-\toff\t-\t-\t-\t-\n",
                    "tank/ro\tfilesystem\t4\t0\t900\t0\t/tank/ro\t-\t9\t12\tno\ton\ton\t-\toff\t-\t-\t-\t-\n",
                ).into()
            } else { String::new() })
        }).unwrap();
        let p = |value: &str, source: &str| NativeProperty {
            value: value.into(),
            source: source.into(),
        };
        let identity = |name: &str| {
            inspection
                .datasets
                .iter()
                .find(|d| d.name == name)
                .unwrap()
                .identity
                .clone()
        };
        let record = PairRecord {
            schema_version: 1,
            pair_id: "12345678-1234-4234-9234-1234567890ab".into(),
            endpoint: Endpoint {
                name: "tank/data".into(),
                identity: identity("tank/data"),
            },
            peer: Endpoint {
                name: "tank/copy".into(),
                identity: identity("tank/copy"),
            },
            role: Role::Primary,
        };
        let props = |guid: &str, txg: &str, objset: &str, pair: Option<&PairRecord>| {
            let mut props = BTreeMap::from([
                ("guid".into(), p(guid, "-")),
                ("createtxg".into(), p(txg, "-")),
                ("objsetid".into(), p(objset, "-")),
                ("usedbysnapshots".into(), p("0", "-")),
            ]);
            if let Some(pair) = pair {
                props.insert(PAIR_PROPERTY.into(), p(&pair.encode().unwrap(), "local"));
            }
            props
        };
        let state = NativeState {
            dataset_properties: BTreeMap::from([
                ("tank".into(), props("1", "5", "6", None)),
                ("tank/data".into(), props("2", "7", "10", Some(&record))),
                (
                    "tank/copy".into(),
                    props("3", "8", "11", Some(&record.counterpart())),
                ),
                ("tank/ro".into(), props("4", "9", "12", None)),
            ]),
            pool_properties: BTreeMap::from([(
                "tank".into(),
                BTreeMap::from([("guid".into(), p("1", "-"))]),
            )]),
            inspection,
        };
        let config = Config::from_override(None).unwrap();
        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let report = observe_status_with(&state, &config, None, now, |_, _| {
            panic!("no policy is assigned")
        })
        .unwrap();
        let diagnostics: Vec<_> = report
            .datasets
            .iter()
            .map(|row| (row.expected.dataset.as_str(), row.diagnostic.as_str()))
            .collect();
        assert_eq!(
            diagnostics,
            [
                ("tank", "disabled"),
                ("tank/copy", "fenced"),
                ("tank/data", "disabled"),
                ("tank/ro", "read_only"),
            ]
        );
        // The machine view keeps the exact admission refusal, without the
        // "inconsistent ZFS observation" prefix.
        for row in &report.datasets[1..] {
            if row.diagnostic != "disabled" {
                let blocker = row.expected.blocker.as_deref().unwrap();
                assert_eq!(
                    blocker,
                    format!(
                        "{} is read-only: snapshots are taken and deleted on a writable \
                         working copy; a fenced pair copy follows its working copy through \
                         `zboot sync`",
                        row.expected.dataset
                    )
                );
            }
        }
        let text = crate::status::render_diagnostics(&report, true).unwrap();
        assert!(text.contains("tank/copy  policy=- "), "{text}");
        assert!(text.contains(" status=fenced\n"), "{text}");
        assert!(text.contains(" status=read_only\n"), "{text}");
        assert!(!text.contains("is read-only:"), "{text}");
        assert!(!text.contains("inconsistent"), "{text}");
        assert!(text.contains("read_only = read-only dataset"), "{text}");
        assert!(text.contains("fenced = fenced pair copy"), "{text}");
        assert!(text.contains("Policies (frequency; retention):"), "{text}");
        let single = crate::status::render_diagnostics(&report, false).unwrap();
        assert!(
            !single.contains("Policies (frequency; retention):"),
            "{single}"
        );
        assert!(single.contains(" status=read_only\n"), "{single}");
        assert!(single.contains("read_only = read-only dataset"), "{single}");
    }
}
