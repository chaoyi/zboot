//! Identity-bound changes to the Zsnap assignment property only.
//! Clearing a local assignment can reveal an inherited policy; it does not mean
//! disabled. No generic user-property or management-metadata writer is exposed.

use serde::{Deserialize, Serialize};
use zfs_tools::engine::{
    Error, native,
    operation::{DatasetRef, SnapshotScope},
    state::{self, NativeState},
};

pub use crate::config::POLICY_PROPERTY;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyChange {
    Set(String),
    Inherit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRequest {
    pub dataset: String,
    pub change: PolicyChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyObservation {
    pub value: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyPreview {
    pub dataset: DatasetRef,
    pub before: PolicyObservation,
    pub change: PolicyChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Complete,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOutcome {
    pub dataset: DatasetRef,
    pub status: PolicyStatus,
    pub effective: Option<PolicyObservation>,
    pub detail: Option<String>,
}

pub trait PolicyBackend {
    fn observe(&mut self) -> Result<NativeState, Error>;
    fn change(&mut self, request: &PolicyRequest) -> Result<(), Error>;
}

pub struct NativePolicy;
impl PolicyBackend for NativePolicy {
    fn observe(&mut self) -> Result<NativeState, Error> {
        state::observe()
    }
    fn change(&mut self, request: &PolicyRequest) -> Result<(), Error> {
        let args = match &request.change {
            PolicyChange::Set(value) => vec![
                "set".into(),
                format!("{POLICY_PROPERTY}={value}"),
                request.dataset.clone(),
            ],
            PolicyChange::Inherit => vec![
                "inherit".into(),
                POLICY_PROPERTY.into(),
                request.dataset.clone(),
            ],
        };
        native::run_mutating("zfs", &args).map(|_| ())
    }
}

/// Read-only preview with the same admission as execution. Callers validate that
/// a named policy exists in their config; this layer permits only well-formed
/// assignment values, including the explicit disabled value `none`.
pub fn preview_policy(
    state: &NativeState,
    request: &PolicyRequest,
) -> Result<PolicyPreview, Error> {
    let scope = admit(state, request)?;
    Ok(PolicyPreview {
        dataset: scope.datasets()[0].clone(),
        before: observed(state, &request.dataset)?,
        change: request.change.clone(),
    })
}

pub fn change_policy(request: &PolicyRequest) -> Result<PolicyOutcome, Error> {
    change_policy_with(request, &mut NativePolicy)
}

pub fn change_policy_with(
    request: &PolicyRequest,
    backend: &mut impl PolicyBackend,
) -> Result<PolicyOutcome, Error> {
    let before = backend.observe()?;
    let plan = admit(&before, request)?;
    let original_property = observed(&before, &request.dataset)?;
    let current = backend.observe()?;
    plan.revalidate(
        &current.inspection,
        &current.dataset_properties,
        &current.pool_properties,
    )?;
    if observed(&current, &request.dataset)? != original_property {
        return Err(Error::Inconsistent(
            "policy assignment changed before effect".into(),
        ));
    }

    let execution_error = backend.change(request).err().map(|e| e.to_string());
    let mut outcome = PolicyOutcome {
        dataset: plan.datasets()[0].clone(),
        status: PolicyStatus::Uncertain,
        effective: None,
        detail: execution_error.clone(),
    };
    let append_detail = |detail: &mut Option<String>, message: String| {
        *detail = Some(match detail.take() {
            Some(prior) => format!("{prior}; {message}"),
            None => message,
        });
    };
    let after = match backend.observe() {
        Ok(after) => after,
        Err(error) => {
            append_detail(
                &mut outcome.detail,
                format!("post-change observation failed: {error}"),
            );
            return Ok(outcome);
        }
    };
    if let Err(error) = plan.revalidate(
        &after.inspection,
        &after.dataset_properties,
        &after.pool_properties,
    ) {
        append_detail(
            &mut outcome.detail,
            format!("post-change admission or incarnation changed: {error}"),
        );
        return Ok(outcome);
    }
    let effective = match observed(&after, &request.dataset) {
        Ok(effective) => effective,
        Err(error) => {
            append_detail(
                &mut outcome.detail,
                format!("post-change property observation failed: {error}"),
            );
            return Ok(outcome);
        }
    };
    let matches = match &request.change {
        PolicyChange::Set(value) => {
            effective.value.as_ref() == Some(value) && effective.source.as_deref() == Some("local")
        }
        PolicyChange::Inherit => match effective.source.as_deref() {
            None | Some("-") | Some("default") | Some("received") => true,
            Some(source) => source
                .strip_prefix("inherited from ")
                .is_some_and(|ancestor| {
                    zfs_tools::engine::validate_dataset_name(ancestor).is_ok()
                        && request
                            .dataset
                            .strip_prefix(ancestor)
                            .is_some_and(|tail| tail.starts_with('/'))
                }),
        },
    };
    outcome.effective = Some(effective);
    if matches && execution_error.is_none() {
        outcome.status = PolicyStatus::Complete;
    } else if outcome.detail.is_none() {
        outcome.detail =
            Some("native command did not establish the requested property value/source".into());
    }
    Ok(outcome)
}

fn admit(state: &NativeState, request: &PolicyRequest) -> Result<SnapshotScope, Error> {
    zfs_tools::engine::validate_dataset_name(&request.dataset)?;
    if let PolicyChange::Set(value) = &request.change
        && (value.is_empty()
            || value == "-"
            || value.trim() != value
            || value.chars().any(char::is_control))
    {
        return Err(Error::InvalidScope("policy value must be nonempty, unpadded and contain no controls; use 'none' to disable".into()));
    }
    SnapshotScope::plan_exact(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
        std::slice::from_ref(&request.dataset),
    )
}

fn observed(state: &NativeState, dataset: &str) -> Result<PolicyObservation, Error> {
    let values = state
        .dataset_properties
        .get(dataset)
        .ok_or_else(|| Error::Inconsistent("missing complete assignment properties".into()))?;
    let property = values.get(POLICY_PROPERTY);
    Ok(PolicyObservation {
        value: property.map(|p| p.value.clone()),
        source: property.map(|p| p.source.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zfs_tools::engine::{
        CanMount, Dataset, DatasetIdentity, DatasetKind, Encryption, Guid, Inspection, KeyStatus,
        ObjsetId, Pool, Txg, native::NativeProperty,
    };

    fn state() -> NativeState {
        let dataset = Dataset {
            name: "tank".into(),
            kind: DatasetKind::Filesystem,
            guid: Guid::new(1),
            identity: DatasetIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(1),
                createtxg: Txg::new(2),
                objsetid: ObjsetId::new(3),
            },
            used_bytes: 0,
            available_bytes: 100,
            referenced_bytes: 0,
            mountpoint: Some("/tank".into()),
            volume_size_bytes: None,
            mounted: Some(false),
            readonly: false,
            canmount: Some(CanMount::On),
            origin: None,
            encryption: Encryption::Off,
            keystatus: KeyStatus::Unencrypted,
            encryptionroot: None,
            staging: None,
            pending: None,
        };
        let p = |value: &str| NativeProperty {
            value: value.into(),
            source: "-".into(),
        };
        NativeState {
            inspection: Inspection {
                schema_version: 3,
                imported_only: true,
                non_atomic: true,
                recursive: true,
                requested_datasets: vec![],
                snapshots: Some(vec![]),
                pools: vec![Pool {
                    name: "tank".into(),
                    guid: Guid::new(1),
                    size_bytes: 100,
                    allocated_bytes: 0,
                    free_bytes: 100,
                    health: "ONLINE".into(),
                    bootfs: None,
                }],
                datasets: vec![dataset],
            },
            dataset_properties: BTreeMap::from([(
                "tank".into(),
                BTreeMap::from([
                    ("guid".into(), p("1")),
                    ("createtxg".into(), p("2")),
                    ("objsetid".into(), p("3")),
                ]),
            )]),
            pool_properties: BTreeMap::from([(
                "tank".into(),
                BTreeMap::from([("guid".into(), p("1"))]),
            )]),
        }
    }

    #[derive(Clone, Copy)]
    enum Behavior {
        Normal,
        NoEffect,
        LostReply,
        ReplaceAfter,
        FailPostquery,
        PendingBefore,
        InheritAncestor,
    }
    struct Fake {
        state: NativeState,
        behavior: Behavior,
        observations: usize,
        effects: usize,
    }
    impl PolicyBackend for Fake {
        fn observe(&mut self) -> Result<NativeState, Error> {
            self.observations += 1;
            if self.effects > 0 && matches!(self.behavior, Behavior::FailPostquery) {
                return Err(Error::Inconsistent("query failed".into()));
            }
            if self.observations == 2 && matches!(self.behavior, Behavior::PendingBefore) {
                self.state
                    .dataset_properties
                    .get_mut("tank")
                    .unwrap()
                    .insert(
                        "zboot:pending".into(),
                        NativeProperty {
                            value: "op".into(),
                            source: "local".into(),
                        },
                    );
            }
            Ok(self.state.clone())
        }
        fn change(&mut self, request: &PolicyRequest) -> Result<(), Error> {
            self.effects += 1;
            if !matches!(self.behavior, Behavior::NoEffect) {
                let properties = self
                    .state
                    .dataset_properties
                    .get_mut(&request.dataset)
                    .unwrap();
                match &request.change {
                    PolicyChange::Set(value) => {
                        properties.insert(
                            POLICY_PROPERTY.into(),
                            NativeProperty {
                                value: value.clone(),
                                source: "local".into(),
                            },
                        );
                    }
                    PolicyChange::Inherit => {
                        properties.remove(POLICY_PROPERTY);
                        if matches!(self.behavior, Behavior::InheritAncestor) {
                            properties.insert(
                                POLICY_PROPERTY.into(),
                                NativeProperty {
                                    value: "history".into(),
                                    source: "inherited from tank".into(),
                                },
                            );
                        }
                    }
                }
            }
            if matches!(self.behavior, Behavior::ReplaceAfter) {
                self.state.inspection.datasets[0].identity.objsetid = ObjsetId::new(99);
                self.state
                    .dataset_properties
                    .get_mut("tank")
                    .unwrap()
                    .get_mut("objsetid")
                    .unwrap()
                    .value = "99".into();
            }
            if matches!(self.behavior, Behavior::LostReply) {
                return Err(Error::Inconsistent("lost reply".into()));
            }
            Ok(())
        }
    }

    #[test]
    fn set_and_inherit_are_verified_and_distinct_from_disable() {
        {
            let mut backend = Fake {
                state: state(),
                behavior: Behavior::Normal,
                observations: 0,
                effects: 0,
            };
            for change in [
                PolicyChange::Set("guard".into()),
                PolicyChange::Set("none".into()),
                PolicyChange::Inherit,
            ] {
                let outcome = change_policy_with(
                    &PolicyRequest {
                        dataset: "tank".into(),
                        change: change.clone(),
                    },
                    &mut backend,
                )
                .unwrap();
                assert_eq!(outcome.status, PolicyStatus::Complete);
                assert_eq!(
                    outcome.effective.unwrap().value,
                    match change {
                        PolicyChange::Set(value) => Some(value),
                        PolicyChange::Inherit => None,
                    }
                );
            }
            assert_eq!(backend.effects, 3);
        }
    }

    #[test]
    fn post_effect_failures_never_claim_success_or_compensate() {
        {
            for behavior in [
                Behavior::NoEffect,
                Behavior::LostReply,
                Behavior::ReplaceAfter,
                Behavior::FailPostquery,
            ] {
                let mut backend = Fake {
                    state: state(),
                    behavior,
                    observations: 0,
                    effects: 0,
                };
                let outcome = change_policy_with(
                    &PolicyRequest {
                        dataset: "tank".into(),
                        change: PolicyChange::Set("guard".into()),
                    },
                    &mut backend,
                )
                .unwrap();
                assert_eq!(outcome.status, PolicyStatus::Uncertain);
                assert!(outcome.detail.is_some());
                assert_eq!(backend.effects, 1);
            }
        }
    }

    #[test]
    fn pending_drift_and_invalid_values_cause_no_effect() {
        {
            let mut backend = Fake {
                state: state(),
                behavior: Behavior::PendingBefore,
                observations: 0,
                effects: 0,
            };
            assert!(
                change_policy_with(
                    &PolicyRequest {
                        dataset: "tank".into(),
                        change: PolicyChange::Set("guard".into())
                    },
                    &mut backend
                )
                .is_err()
            );
            assert_eq!(backend.effects, 0);
            for value in ["", "-", " guard", "bad\npolicy"] {
                assert!(
                    preview_policy(
                        &state(),
                        &PolicyRequest {
                            dataset: "tank".into(),
                            change: PolicyChange::Set(value.into())
                        }
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn unassign_reports_the_revealed_inherited_policy() {
        {
            let mut initial = state();
            let mut child = initial.inspection.datasets[0].clone();
            child.name = "tank/data".into();
            child.guid = Guid::new(4);
            child.identity.guid = Guid::new(4);
            child.identity.objsetid = ObjsetId::new(5);
            initial.inspection.datasets.push(child);
            let mut values = initial.dataset_properties["tank"].clone();
            values.get_mut("guid").unwrap().value = "4".into();
            values.get_mut("objsetid").unwrap().value = "5".into();
            values.insert(
                POLICY_PROPERTY.into(),
                NativeProperty {
                    value: "none".into(),
                    source: "local".into(),
                },
            );
            initial
                .dataset_properties
                .insert("tank/data".into(), values);
            let mut backend = Fake {
                state: initial,
                behavior: Behavior::InheritAncestor,
                observations: 0,
                effects: 0,
            };
            let outcome = change_policy_with(
                &PolicyRequest {
                    dataset: "tank/data".into(),
                    change: PolicyChange::Inherit,
                },
                &mut backend,
            )
            .unwrap();
            assert_eq!(outcome.status, PolicyStatus::Complete);
            assert_eq!(
                outcome.effective.unwrap(),
                PolicyObservation {
                    value: Some("history".into()),
                    source: Some("inherited from tank".into())
                }
            );
        }
    }
}
