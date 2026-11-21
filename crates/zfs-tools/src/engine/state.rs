//! Complete native evidence bundle for cooperating operation admission.
//! Sequential queries may drift; plans revalidate immediately before effects.
#[cfg(feature = "internal")]
use crate::engine::{
    DatasetIdentity, Guid,
    management::{self, Ownership},
    operation::SnapshotScope,
    pool_of,
};
use crate::engine::{
    Error, InspectRequest, Inspection,
    native::{self, PropertyInventory},
};
#[cfg(feature = "internal")]
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct NativeState {
    pub inspection: Inspection,
    pub dataset_properties: PropertyInventory,
    pub pool_properties: PropertyInventory,
}

/// Frozen read-only inventory dependencies, derived only from a complete
/// admitted native observation. This is ephemeral read evidence, not a plan
/// for a writer and not a cache of unobserved native properties.
#[derive(Debug, Clone)]
#[cfg(feature = "internal")]
pub struct ReadonlyInventoryBinding {
    scope: SnapshotScope,
    recursive_roots: Vec<String>,
    exact_ancestors: Vec<String>,
    identities: BTreeMap<String, DatasetIdentity>,
    pools: BTreeMap<String, Guid>,
    ownership: BTreeMap<String, Ownership>,
    cmdlines: BTreeMap<String, Option<native::NativeProperty>>,
}
#[cfg(feature = "internal")]
const MAX_READONLY_MEMBERS: usize = 16_384;
#[cfg(feature = "internal")]
const MAX_READONLY_ROOTS: usize = 128;

#[cfg(feature = "internal")]
use crate::engine::contains_dataset as contains;
#[cfg(feature = "internal")]
fn scoped_refusal(message: impl Into<String>) -> Error {
    Error::Inconsistent(message.into())
}

#[cfg(feature = "internal")]
impl ReadonlyInventoryBinding {
    pub fn capture(state: &NativeState, scope: &SnapshotScope) -> Result<Self, Error> {
        if !scope.is_recursive_readonly() {
            return Err(scoped_refusal(
                "inventory binding requires an admitted recursive read-only scope",
            ));
        }
        scope.revalidate(
            &state.inspection,
            &state.dataset_properties,
            &state.pool_properties,
        )?;
        let mut recursive: BTreeSet<String> = scope.roots().iter().cloned().collect();
        let mut names: BTreeSet<String> = scope
            .datasets()
            .iter()
            .map(|dataset| dataset.name.clone())
            .collect();
        if names.len() > MAX_READONLY_MEMBERS || recursive.len() > MAX_READONLY_ROOTS {
            return Err(scoped_refusal(
                "read-only inventory dependency closure exceeds its bound",
            ));
        }
        loop {
            let before = (names.len(), recursive.len());
            for name in names.clone() {
                let mut parent = name.as_str();
                while let Some((ancestor, _)) = parent.rsplit_once('/') {
                    names.insert(ancestor.into());
                    parent = ancestor;
                }
                let properties = management::bound_properties(state, &name)?;
                management::validate_supported_properties(properties, &name)?;
                if let Some(property) = properties.get(management::PAIR_PROPERTY) {
                    let pair = management::PairRecord::parse(&property.value)?;
                    recursive.insert(pair.endpoint.name);
                    recursive.insert(pair.peer.name);
                }
                if let Some(property) = properties.get(management::PLACEMENT_PROPERTY)
                    && let Some(owner) = property.source.strip_prefix("inherited from ")
                {
                    names.insert(owner.into());
                }
            }
            for dataset in &state.inspection.datasets {
                if recursive.iter().any(|root| contains(root, &dataset.name)) {
                    names.insert(dataset.name.clone());
                }
            }
            if names.len() > MAX_READONLY_MEMBERS || recursive.len() > MAX_READONLY_ROOTS {
                return Err(scoped_refusal(
                    "read-only inventory dependency closure exceeds its bound",
                ));
            }
            if (names.len(), recursive.len()) == before {
                break;
            }
        }
        // Ancestors are exact queries, never recursive pool-root queries.
        let recursive_roots: Vec<_> = recursive
            .iter()
            .filter(|root| {
                !recursive
                    .iter()
                    .any(|parent| *root != parent && contains(parent, root))
            })
            .cloned()
            .collect();
        let exact_ancestors = names
            .iter()
            .filter(|name| !recursive_roots.iter().any(|root| contains(root, name)))
            .cloned()
            .collect();
        let mut identities = BTreeMap::new();
        let mut pools = BTreeMap::new();
        let mut ownership = BTreeMap::new();
        let mut cmdlines = BTreeMap::new();
        for name in names {
            let dataset = state
                .inspection
                .datasets
                .iter()
                .find(|dataset| dataset.name == name)
                .ok_or_else(|| {
                    scoped_refusal(format!("inventory dependency was not observed: {name}"))
                })?;
            identities.insert(name.clone(), dataset.identity.clone());
            let pool = pool_of(&name);
            pools.insert(pool.into(), dataset.identity.pool_guid);
            ownership.insert(name.clone(), management::ownership(state, &name)?);
            cmdlines.insert(
                name.clone(),
                state.dataset_properties[&name]
                    .get("zboot:cmdline")
                    .cloned(),
            );
        }
        let binding = Self {
            scope: scope.clone(),
            recursive_roots,
            exact_ancestors,
            identities,
            pools,
            ownership,
            cmdlines,
        };
        let mut selected = state.clone();
        selected
            .inspection
            .datasets
            .retain(|dataset| binding.identities.contains_key(&dataset.name));
        selected
            .inspection
            .pools
            .retain(|pool| binding.pools.contains_key(&pool.name));
        selected
            .dataset_properties
            .retain(|name, _| binding.identities.contains_key(name));
        selected
            .pool_properties
            .retain(|name, _| binding.pools.contains_key(name));
        binding.validate_dependencies(&selected)?;
        Ok(binding)
    }

    fn validate_dependencies(&self, state: &NativeState) -> Result<(), Error> {
        if state.inspection.datasets.len() > MAX_READONLY_MEMBERS {
            return Err(scoped_refusal(
                "read-only inventory dependency closure exceeds its bound",
            ));
        }
        let names: BTreeSet<_> = state
            .inspection
            .datasets
            .iter()
            .map(|dataset| dataset.name.clone())
            .collect();
        if names.len() != state.inspection.datasets.len()
            || names != self.identities.keys().cloned().collect()
            || state
                .dataset_properties
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != names
        {
            return Err(scoped_refusal(
                "read-only inventory dependency members changed",
            ));
        }
        if state.inspection.pools.len() != self.pools.len()
            || state.pool_properties.len() != self.pools.len()
        {
            return Err(scoped_refusal(
                "read-only inventory dependency pools changed",
            ));
        }
        for (name, guid) in &self.pools {
            let pool = state
                .inspection
                .pools
                .iter()
                .find(|pool| &pool.name == name)
                .ok_or_else(|| scoped_refusal("read-only inventory pool disappeared"))?;
            let properties = state
                .pool_properties
                .get(name)
                .ok_or_else(|| scoped_refusal("read-only inventory pool properties missing"))?;
            if &pool.guid != guid
                || properties
                    .get("guid")
                    .is_none_or(|property| property.value != guid.to_string())
                || properties
                    .get("readonly")
                    .is_none_or(|property| property.value != "on")
            {
                return Err(scoped_refusal(format!(
                    "read-only inventory pool identity or readonly changed: {name}"
                )));
            }
        }
        for dataset in &state.inspection.datasets {
            let name = &dataset.name;
            if self.identities.get(name) != Some(&dataset.identity)
                || self.pools.get(pool_of(name)) != Some(&dataset.identity.pool_guid)
            {
                return Err(scoped_refusal(format!(
                    "read-only inventory dependency identity changed: {name}"
                )));
            }
            if self.ownership.get(name) != Some(&management::ownership(state, name)?)
                || self.cmdlines[name]
                    != state.dataset_properties[name].get("zboot:cmdline").cloned()
            {
                return Err(scoped_refusal(format!(
                    "read-only inventory ownership or cmdline changed: {name}"
                )));
            }
        }
        Ok(())
    }

    /// Validate only the explicitly queried members and authority closure.
    /// Unrelated host hazards/defaults remain the listing snapshot and are
    /// observed globally again by the caller's complete handoff validation.
    pub fn revalidate(&self, state: &NativeState) -> Result<(), Error> {
        self.validate_dependencies(state)?;
        self.scope.revalidate_scoped_readonly(
            &state.inspection,
            &state.dataset_properties,
            &state.pool_properties,
        )
    }
}

#[cfg(feature = "internal")]
pub fn observe_scope(binding: &ReadonlyInventoryBinding) -> Result<NativeState, Error> {
    observe_scope_with(binding, &mut native::run)
}

#[cfg(feature = "internal")]
pub fn observe_scope_with(
    binding: &ReadonlyInventoryBinding,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<NativeState, Error> {
    let pool_names: Vec<_> = binding.pools.keys().cloned().collect();
    let inspection = native::inspect_readonly_scope_with(
        binding.scope.roots(),
        &binding.recursive_roots,
        &binding.exact_ancestors,
        &pool_names,
        run,
    )?;
    let names: Vec<_> = inspection
        .datasets
        .iter()
        .map(|dataset| dataset.name.clone())
        .collect();
    let dataset_properties = native::dataset_properties_with(&names, &mut *run)?;
    let pool_properties = native::pool_properties_with(&pool_names, &mut *run)?;
    let state = NativeState {
        inspection,
        dataset_properties,
        pool_properties,
    };
    binding.revalidate(&state)?;
    Ok(state)
}

pub fn observe() -> Result<NativeState, Error> {
    observe_with(&mut native::run)
}

pub fn observe_with(
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<NativeState, Error> {
    let inspection = native::inspect_with(&InspectRequest::new(vec![], true)?, &mut *run)?;
    let names: Vec<_> = inspection.datasets.iter().map(|d| d.name.clone()).collect();
    let pools: Vec<_> = inspection.pools.iter().map(|p| p.name.clone()).collect();
    let dataset_properties = if names.is_empty() {
        PropertyInventory::new()
    } else {
        native::dataset_properties_with(&names, &mut *run)?
    };
    let pool_properties = if pools.is_empty() {
        PropertyInventory::new()
    } else {
        native::pool_properties_with(&pools, &mut *run)?
    };
    Ok(NativeState {
        inspection,
        dataset_properties,
        pool_properties,
    })
}

#[cfg(all(test, feature = "internal"))]
mod tests {
    use super::*;
    fn scoped_fixture() -> NativeState {
        let pools = "tank\t100\t1000\t0\t1000\tONLINE\ttank/data\npeer\t200\t1000\t0\t1000\tONLINE\t-\nother\t300\t1000\t0\t1000\tONLINE\t-\n";
        let rows = [
            ("tank", 1, "none", "off"), ("tank/data", 10, "/", "off"),
            ("tank/data/child", 11, "/var", "off"), ("tank/unrelated", 12, "/data", "off"),
            ("peer", 2, "none", "off"), ("peer/backup", 20, "/", "on"),
            ("peer/backup/child", 21, "/var", "on"), ("other", 3, "none", "off"),
        ].into_iter().map(|(name, id, mountpoint, readonly)| {
            format!("{name}\tfilesystem\t{id}\t0\t1000\t0\t{mountpoint}\t-\t{}\t{}\tno\t{readonly}\tnoauto\t-\toff\t-\t-\t-\t-\n", id+100, id+200)
        }).collect::<String>();
        let inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    pools.into()
                } else {
                    rows.clone()
                })
            },
        )
        .unwrap();
        let property = |value: String, source: &str| native::NativeProperty {
            value,
            source: source.into(),
        };
        let mut dataset_properties: PropertyInventory = inspection
            .datasets
            .iter()
            .map(|dataset| {
                let properties = [
                    ("guid", dataset.identity.guid.to_string()),
                    ("createtxg", dataset.identity.createtxg.to_string()),
                    ("objsetid", dataset.identity.objsetid.to_string()),
                ]
                .into_iter()
                .map(|(key, value)| (key.into(), property(value, "-")))
                .collect();
                (dataset.name.clone(), properties)
            })
            .collect();
        let endpoint = |name: &str| management::Endpoint {
            name: name.into(),
            identity: inspection
                .datasets
                .iter()
                .find(|dataset| dataset.name == name)
                .unwrap()
                .identity
                .clone(),
        };
        let pair = management::PairRecord {
            schema_version: 1,
            pair_id: "11111111-1111-4111-8111-111111111111".into(),
            endpoint: endpoint("tank/data"),
            peer: endpoint("peer/backup"),
            role: management::Role::Primary,
        };
        for (name, record, source) in [
            ("tank/data", pair.clone(), "local"),
            ("tank/data/child", pair.clone(), "inherited from tank/data"),
            ("peer/backup", pair.counterpart(), "local"),
            (
                "peer/backup/child",
                pair.counterpart(),
                "inherited from peer/backup",
            ),
        ] {
            dataset_properties.get_mut(name).unwrap().insert(
                management::PAIR_PROPERTY.into(),
                property(record.encode().unwrap(), source),
            );
        }
        dataset_properties.get_mut("tank/data").unwrap().insert(
            "zboot:cmdline".into(),
            property("console=ttyS0".into(), "local"),
        );
        let pool_properties = inspection
            .pools
            .iter()
            .map(|pool| {
                (
                    pool.name.clone(),
                    BTreeMap::from([
                        ("guid".into(), property(pool.guid.to_string(), "-")),
                        ("readonly".into(), property("on".into(), "local")),
                    ]),
                )
            })
            .collect();
        NativeState {
            inspection,
            dataset_properties,
            pool_properties,
        }
    }

    fn scoped_reply(state: &NativeState, program: &str, args: &[String]) -> Result<String, Error> {
        let properties = |inventory: &PropertyInventory, names: &[String]| {
            let mut text = String::new();
            for name in names {
                let rows = inventory
                    .get(name)
                    .ok_or_else(|| scoped_refusal(format!("missing fixture object: {name}")))?;
                for (key, property) in rows {
                    text.push_str(&format!(
                        "{name}\t{key}\t{}\t{}\n",
                        property.value, property.source
                    ));
                }
            }
            Ok(text)
        };
        match (program, args[0].as_str()) {
            ("zpool", "list") => Ok(state
                .inspection
                .pools
                .iter()
                .filter(|pool| args[5..].contains(&pool.name))
                .map(|pool| {
                    format!(
                        "{}\t{}\t1000\t0\t1000\tONLINE\t{}\n",
                        pool.name,
                        pool.guid,
                        pool.bootfs.as_deref().unwrap_or("-")
                    )
                })
                .collect()),
            ("zpool", "get") => properties(&state.pool_properties, &args[6..]),
            ("zfs", "get") => properties(&state.dataset_properties, &args[6..]),
            ("zfs", "list") => {
                let recursive = args.get(7).is_some_and(|argument| argument == "-r");
                let roots = &args[if recursive { 8 } else { 7 }..];
                Ok(state.inspection.datasets.iter().filter(|dataset| {
                    roots.iter().any(|root| if recursive { contains(root, &dataset.name) } else { root == &dataset.name })
                }).map(|dataset| {
                    let id = &dataset.identity;
                    format!("{}\tfilesystem\t{}\t0\t1000\t0\t{}\t-\t{}\t{}\tno\t{}\tnoauto\t-\toff\t-\t-\t-\t-\n",
                        dataset.name, id.guid, dataset.mountpoint.as_deref().unwrap(), id.createtxg, id.objsetid,
                        if dataset.readonly { "on" } else { "off" })
                }).collect())
            }
            _ => panic!("unexpected scoped query: {program} {args:?}"),
        }
    }

    fn readonly_scope(state: &NativeState, root: &str) -> SnapshotScope {
        SnapshotScope::plan_readonly_working(
            &state.inspection,
            &state.dataset_properties,
            &state.pool_properties,
            &[root.into()],
        )
        .unwrap()
    }

    #[test]
    fn readonly_inventory_queries_only_its_recursive_authority_closure_and_exact_ancestors() {
        let state = scoped_fixture();
        let scope = readonly_scope(&state, "tank/data/child");
        let binding = ReadonlyInventoryBinding::capture(&state, &scope).unwrap();
        let mut calls = Vec::new();
        let fresh = observe_scope_with(&binding, &mut |program, args| {
            calls.push((program, args.to_vec()));
            scoped_reply(&state, program, args)
        })
        .unwrap();
        assert_eq!(&fresh.inspection.requested_datasets, scope.roots());
        assert!(fresh.inspection.snapshots.is_none());
        assert_eq!(fresh.inspection.datasets.len(), 6);
        assert!(
            fresh
                .inspection
                .datasets
                .iter()
                .all(|dataset| dataset.name != "tank/unrelated" && dataset.name != "other")
        );
        let pool_list = calls
            .iter()
            .find(|(program, args)| *program == "zpool" && args[0] == "list")
            .unwrap();
        assert_eq!(pool_list.1[5..], ["peer", "tank"]);
        let lists: Vec<_> = calls
            .iter()
            .filter(|(program, args)| *program == "zfs" && args[0] == "list")
            .collect();
        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0].1[7..], ["-r", "peer/backup", "tank/data"]);
        assert_eq!(lists[1].1[7..], ["peer", "tank"]);
        assert!(
            calls
                .iter()
                .all(|(_, args)| !args.iter().any(|arg| arg == "snapshot" || arg == "holds"))
        );
        scope
            .revalidate_scoped_readonly(
                &fresh.inspection,
                &fresh.dataset_properties,
                &fresh.pool_properties,
            )
            .unwrap();
        assert!(
            scope
                .revalidate(
                    &fresh.inspection,
                    &fresh.dataset_properties,
                    &fresh.pool_properties
                )
                .is_err()
        );
        assert!(
            SnapshotScope::plan(
                &fresh.inspection,
                &fresh.dataset_properties,
                &fresh.pool_properties,
                scope.roots()
            )
            .is_err()
        );
        assert!(
            SnapshotScope::plan_readonly_working(
                &fresh.inspection,
                &fresh.dataset_properties,
                &fresh.pool_properties,
                scope.roots()
            )
            .is_err()
        );
        let writer = SnapshotScope::plan(
            &state.inspection,
            &state.dataset_properties,
            &state.pool_properties,
            &["tank/data".into()],
        )
        .unwrap();
        assert!(
            writer
                .revalidate_scoped_readonly(
                    &fresh.inspection,
                    &fresh.dataset_properties,
                    &fresh.pool_properties
                )
                .is_err()
        );
        assert!(ReadonlyInventoryBinding::capture(&state, &writer).is_err());
    }

    #[test]
    fn readonly_inventory_refuses_member_authority_identity_cmdline_and_pool_drift() {
        let state = scoped_fixture();
        let scope = readonly_scope(&state, "tank/data");
        let binding = ReadonlyInventoryBinding::capture(&state, &scope).unwrap();
        for attack in 0..8 {
            let mut changed = state.clone();
            match attack {
                0 => {
                    let mut child = changed
                        .inspection
                        .datasets
                        .iter()
                        .find(|dataset| dataset.name == "tank/data/child")
                        .unwrap()
                        .clone();
                    child.name = "tank/data/new".into();
                    child.guid = Guid::new(999);
                    child.identity.guid = child.guid;
                    let mut properties = changed.dataset_properties["tank/data/child"].clone();
                    properties.get_mut("guid").unwrap().value = "999".into();
                    changed
                        .dataset_properties
                        .insert(child.name.clone(), properties);
                    changed.inspection.datasets.push(child);
                }
                1 => {
                    changed
                        .inspection
                        .datasets
                        .retain(|dataset| dataset.name != "tank/data/child");
                    changed.dataset_properties.remove("tank/data/child");
                }
                2 => {
                    let peer = changed
                        .inspection
                        .datasets
                        .iter_mut()
                        .find(|dataset| dataset.name == "peer/backup")
                        .unwrap();
                    peer.guid = Guid::new(999);
                    peer.identity.guid = peer.guid;
                    changed
                        .dataset_properties
                        .get_mut("peer/backup")
                        .unwrap()
                        .get_mut("guid")
                        .unwrap()
                        .value = "999".into();
                }
                3 => {
                    changed.dataset_properties.get_mut("tank").unwrap().insert(
                        "zboot:future-role".into(),
                        native::NativeProperty {
                            value: "unknown".into(),
                            source: "local".into(),
                        },
                    );
                }
                4 => {
                    changed
                        .dataset_properties
                        .get_mut("tank/data")
                        .unwrap()
                        .get_mut("zboot:cmdline")
                        .unwrap()
                        .value = "console=ttyS1".into();
                }
                5 => {
                    changed
                        .dataset_properties
                        .get_mut("tank/data")
                        .unwrap()
                        .get_mut("guid")
                        .unwrap()
                        .value = "999".into();
                }
                6 => {
                    changed
                        .pool_properties
                        .get_mut("tank")
                        .unwrap()
                        .get_mut("readonly")
                        .unwrap()
                        .value = "off".into();
                }
                7 => {
                    // The fenced leaf itself; a child under it is outside the pair.
                    changed
                        .inspection
                        .datasets
                        .iter_mut()
                        .find(|dataset| dataset.name == "peer/backup")
                        .unwrap()
                        .readonly = false;
                }
                _ => unreachable!(),
            }
            let result = observe_scope_with(&binding, &mut |program, args| {
                scoped_reply(&changed, program, args)
            });
            assert!(result.is_err(), "accepted authority drift {attack}");
        }
    }
}
