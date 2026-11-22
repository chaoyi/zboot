//! Pure admission and local-incarnation binding for future shared writers.
//!
//! Supported writers are unpaired trees and mutually validated versioned primaries.
//! Unknown management, passive copies and unfinished operations refuse admission. These plans do not
//! authorize a native effect and do not acquire coordination themselves.

use crate::engine::{Dataset, DatasetIdentity, Error, Inspection, native::PropertyInventory};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetRef {
    pub name: String,
    pub identity: DatasetIdentity,
}

/// Immutable admitted recursive scope. The selected dataset list binds every
/// descendant; later descendants, disappearance, rename and name reuse all
/// invalidate revalidation. No deserialization or unchecked constructor exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotScope {
    recursive: bool,
    require_writable: bool,
    roots: Vec<String>,
    datasets: Vec<DatasetRef>,
}

impl SnapshotScope {
    pub fn roots(&self) -> &[String] {
        &self.roots
    }
    pub fn datasets(&self) -> &[DatasetRef] {
        &self.datasets
    }

    /// Require a complete imported, recursive Inspection and native `get all`
    /// property observations for every selected dataset and ancestor, plus each
    /// containing pool. Property observations must be complete and trusted;
    /// this pure function cannot establish their provenance or freeze mutations.
    /// The maps are native observations, not user-supplied approval manifests.
    pub fn plan(
        inspection: &Inspection,
        dataset_properties: &PropertyInventory,
        pool_properties: &PropertyInventory,
        roots: &[String],
    ) -> Result<Self, Error> {
        Self::plan_mode(
            inspection,
            dataset_properties,
            pool_properties,
            roots,
            true,
            true,
        )
    }

    /// Capture exactly the selected datasets, without expanding descendants.
    /// Used by conventional per-dataset Zsnap assignments.
    pub fn plan_exact(
        inspection: &Inspection,
        dataset_properties: &PropertyInventory,
        pool_properties: &PropertyInventory,
        datasets: &[String],
    ) -> Result<Self, Error> {
        Self::plan_mode(
            inspection,
            dataset_properties,
            pool_properties,
            datasets,
            false,
            true,
        )
    }

    /// Admit the targets of caller-owned native effects: each root exactly,
    /// or with every descendant when `recursive`. Management and ownership
    /// admission are as for capture, but a read-only dataset is admitted,
    /// because the effects include unmounting and key handling.
    pub(crate) fn plan_effect(
        inspection: &Inspection,
        dataset_properties: &PropertyInventory,
        pool_properties: &PropertyInventory,
        roots: &[String],
        recursive: bool,
    ) -> Result<Self, Error> {
        Self::plan_mode(
            inspection,
            dataset_properties,
            pool_properties,
            roots,
            recursive,
            false,
        )
    }

    /// Bind a working recursive tree for read-only boot asset inspection. This
    /// retains ownership and management admission but permits native readonly
    /// mounts; it is not a capture authorization.
    pub fn plan_readonly_working(
        inspection: &Inspection,
        dataset_properties: &PropertyInventory,
        pool_properties: &PropertyInventory,
        roots: &[String],
    ) -> Result<Self, Error> {
        Self::plan_mode(
            inspection,
            dataset_properties,
            pool_properties,
            roots,
            true,
            false,
        )
    }

    fn plan_mode(
        inspection: &Inspection,
        dataset_properties: &PropertyInventory,
        pool_properties: &PropertyInventory,
        roots: &[String],
        recursive: bool,
        require_writable: bool,
    ) -> Result<Self, Error> {
        if !inspection.requested_datasets.is_empty() {
            return Err(refuse(
                "capture requires supported complete imported recursive inventory",
            ));
        }
        Self::admit_mode(
            inspection,
            dataset_properties,
            pool_properties,
            roots,
            recursive,
            require_writable,
        )
    }

    fn admit_mode(
        inspection: &Inspection,
        dataset_properties: &PropertyInventory,
        pool_properties: &PropertyInventory,
        roots: &[String],
        recursive: bool,
        require_writable: bool,
    ) -> Result<Self, Error> {
        if roots.is_empty() {
            return Err(Error::InvalidScope("empty capture scope".into()));
        }
        let mut roots = roots.to_vec();
        roots.sort();
        for (i, root) in roots.iter().enumerate() {
            crate::engine::validate_dataset_name(root)?;
            if roots[..i]
                .iter()
                .any(|other| other == root || (recursive && contains(other, root)))
            {
                return Err(Error::InvalidScope(
                    "duplicate or overlapping capture roots".into(),
                ));
            }
        }
        let mut inventory = BTreeMap::new();
        let mut identities = BTreeSet::new();
        for dataset in &inspection.datasets {
            crate::engine::validate_dataset_name(&dataset.name)?;
            let id = &dataset.identity;
            if id.guid != dataset.guid
                || !id.is_complete()
                || inventory.insert(dataset.name.as_str(), dataset).is_some()
                || !identities.insert((id.pool_guid, id.guid))
            {
                return Err(refuse("ambiguous or incomplete dataset identity inventory"));
            }
        }
        for root in &roots {
            if !inventory.contains_key(root.as_str()) {
                return Err(Error::MissingScope(root.clone()));
            }
        }
        let selected: Vec<_> = inspection
            .datasets
            .iter()
            .filter(|d| {
                roots
                    .iter()
                    .any(|root| root == &d.name || (recursive && contains(root, &d.name)))
            })
            .collect();
        let mut required = BTreeSet::new();
        for dataset in &selected {
            let mut name = dataset.name.as_str();
            loop {
                required.insert(name);
                let Some((parent, _)) = name.rsplit_once('/') else {
                    break;
                };
                name = parent;
            }
            if require_writable && dataset.readonly {
                // A plain refusal: a read-only dataset is an ordinary state,
                // not an inconsistent observation.
                return Err(Error::Refused(format!(
                    "{} is read-only: snapshots are taken and deleted on a writable working \
                     copy; a fenced pair copy follows its working copy through \
                     `zboot sync`",
                    dataset.name
                )));
            }
        }
        let mut checked_pools = BTreeSet::new();
        for name in required {
            let dataset = inventory
                .get(name)
                .ok_or_else(|| refuse(format!("missing ancestor observation: {name}")))?;
            admit_dataset(dataset, dataset_properties)?;
            let pool_name = crate::engine::pool_of(name);
            let matching: Vec<_> = inspection
                .pools
                .iter()
                .filter(|p| p.name == pool_name)
                .collect();
            if matching.len() != 1 || matching[0].guid != dataset.identity.pool_guid {
                return Err(refuse(format!(
                    "missing or changed pool identity: {pool_name}"
                )));
            }
            if checked_pools.insert(pool_name) {
                let pool = matching[0];
                let properties = pool_properties.get(pool_name).ok_or_else(|| {
                    refuse(format!("missing complete pool properties: {pool_name}"))
                })?;
                bind_property(properties, "guid", pool.guid.get(), pool_name)?;
                refuse_management(properties, pool_name)?;
            }
        }
        for dataset in &selected {
            crate::engine::management::admit_working_parts(
                &inspection.datasets,
                dataset_properties,
                &dataset.name,
            )?;
        }
        let mut datasets: Vec<_> = selected
            .into_iter()
            .map(|d| DatasetRef {
                name: d.name.clone(),
                identity: d.identity.clone(),
            })
            .collect();
        datasets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self {
            recursive,
            require_writable,
            roots,
            datasets,
        })
    }

    pub(crate) fn is_recursive_readonly(&self) -> bool {
        self.recursive && !self.require_writable
    }

    /// Revalidate an already admitted read-only scope against its explicit
    /// recursive inventory and fresh authority dependencies. This returns no
    /// scope or writer authority; full plans/revalidation still require global
    /// complete inventory. Unrelated host policy belongs to the listing and
    /// the full handoff checks, not this scoped read-only observation.
    pub fn revalidate_scoped_readonly(
        &self,
        inspection: &Inspection,
        dataset_properties: &PropertyInventory,
        pool_properties: &PropertyInventory,
    ) -> Result<(), Error> {
        if !self.is_recursive_readonly() || inspection.requested_datasets != self.roots {
            return Err(refuse(
                "read-only revalidation requires its exact scoped recursive inventory",
            ));
        }
        let current = Self::admit_mode(
            inspection,
            dataset_properties,
            pool_properties,
            &self.roots,
            true,
            false,
        )?;
        if current != *self {
            return Err(refuse(
                "read-only scope or local dataset incarnation changed since planning",
            ));
        }
        Ok(())
    }

    /// Re-run current admission and require the same exact recursive member set
    /// and local incarnations. The executor calls this again just
    /// before an effect; raw external mutations can still race sequential queries.
    pub fn revalidate(
        &self,
        inspection: &Inspection,
        dataset_properties: &PropertyInventory,
        pool_properties: &PropertyInventory,
    ) -> Result<(), Error> {
        let current = Self::plan_mode(
            inspection,
            dataset_properties,
            pool_properties,
            &self.roots,
            self.recursive,
            self.require_writable,
        )?;
        if current != *self {
            return Err(refuse(
                "capture scope or local dataset incarnation changed since planning",
            ));
        }
        Ok(())
    }
}

use crate::engine::contains_dataset as contains;

fn refuse(detail: impl Into<String>) -> Error {
    Error::Inconsistent(detail.into())
}

fn admit_dataset(dataset: &Dataset, observed: &PropertyInventory) -> Result<(), Error> {
    if dataset.staging.is_some() || dataset.pending.is_some() {
        return Err(refuse(format!(
            "managed, passive, staging or pending dataset requires supported management evidence: {}",
            dataset.name
        )));
    }
    let properties = observed.get(&dataset.name).ok_or_else(|| {
        refuse(format!(
            "missing complete dataset properties: {}",
            dataset.name
        ))
    })?;
    bind_property(
        properties,
        "guid",
        dataset.identity.guid.get(),
        &dataset.name,
    )?;
    bind_property(
        properties,
        "createtxg",
        dataset.identity.createtxg.get(),
        &dataset.name,
    )?;
    bind_property(
        properties,
        "objsetid",
        dataset.identity.objsetid.get(),
        &dataset.name,
    )?;
    crate::engine::management::validate_supported_properties(properties, &dataset.name)
}

fn bind_property(
    properties: &BTreeMap<String, crate::engine::native::NativeProperty>,
    property: &str,
    expected: u64,
    name: &str,
) -> Result<(), Error> {
    if properties.get(property).map(|p| p.value.as_str()) != Some(expected.to_string().as_str()) {
        return Err(refuse(format!(
            "missing or changed {property} in property observation: {name}"
        )));
    }
    Ok(())
}

fn refuse_management(
    properties: &BTreeMap<String, crate::engine::native::NativeProperty>,
    name: &str,
) -> Result<(), Error> {
    if let Some((property, value)) = properties
        .iter()
        .find(|(key, _)| crate::engine::management::managed_key(key))
    {
        return Err(refuse(format!(
            "unsupported management property {property} ({}) on {name}",
            value.source
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        CanMount, DatasetKind, Encryption, Guid, KeyStatus, ObjsetId, Pool, Txg,
        native::NativeProperty,
    };

    fn dataset(name: &str, guid: u64) -> Dataset {
        Dataset {
            name: name.into(),
            kind: DatasetKind::Filesystem,
            guid: Guid::new(guid),
            identity: DatasetIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(guid),
                createtxg: Txg::new(guid + 10),
                objsetid: ObjsetId::new(guid + 20),
            },
            used_bytes: 0,
            available_bytes: 100,
            referenced_bytes: 0,
            mountpoint: Some(format!("/{name}")),
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
        }
    }

    fn property(value: impl ToString) -> NativeProperty {
        NativeProperty {
            value: value.to_string(),
            source: "-".into(),
        }
    }

    fn fixture() -> (Inspection, PropertyInventory, PropertyInventory) {
        let inspection = Inspection {
            schema_version: 3,
            imported_only: true,
            non_atomic: true,
            recursive: true,
            requested_datasets: vec![],
            snapshots: None,
            pools: vec![Pool {
                name: "tank".into(),
                guid: Guid::new(1),
                size_bytes: 100,
                allocated_bytes: 0,
                free_bytes: 100,
                health: "ONLINE".into(),
                bootfs: None,
            }],
            datasets: vec![
                dataset("tank", 1),
                dataset("tank/data", 2),
                dataset("tank/data/child", 3),
                dataset("tank/database", 4),
            ],
        };
        let properties = evidence(&inspection);
        let pools = BTreeMap::from([(
            "tank".into(),
            BTreeMap::from([("guid".into(), property(1))]),
        )]);
        (inspection, properties, pools)
    }

    fn evidence(inspection: &Inspection) -> PropertyInventory {
        inspection
            .datasets
            .iter()
            .map(|d| {
                (
                    d.name.clone(),
                    BTreeMap::from([
                        ("guid".into(), property(d.identity.guid)),
                        ("createtxg".into(), property(d.identity.createtxg)),
                        ("objsetid".into(), property(d.identity.objsetid)),
                    ]),
                )
            })
            .collect()
    }

    fn plan(
        i: &Inspection,
        d: &PropertyInventory,
        p: &PropertyInventory,
    ) -> Result<SnapshotScope, Error> {
        SnapshotScope::plan(i, d, p, &["tank/data".into()])
    }

    #[test]
    fn read_only_working_scope_does_not_weaken_capture_admission() {
        let (mut i, d, p) = fixture();
        let read = SnapshotScope::plan_readonly_working(&i, &d, &p, &["tank/data".into()]).unwrap();
        let capture = plan(&i, &d, &p).unwrap();
        i.datasets[1].readonly = true;
        read.revalidate(&i, &d, &p).unwrap();
        assert!(capture.revalidate(&i, &d, &p).is_err());
        assert!(plan(&i, &d, &p).is_err());
        i.datasets[1].identity.objsetid = ObjsetId::new(999);
        assert!(read.revalidate(&i, &evidence(&i), &p).is_err());
    }

    #[test]
    fn binds_exact_recursive_scope_excluding_prefix_siblings() {
        let (i, d, p) = fixture();
        let scope = plan(&i, &d, &p).unwrap();
        assert_eq!(
            scope
                .datasets
                .iter()
                .map(|d| d.name.as_str())
                .collect::<Vec<_>>(),
            vec!["tank/data", "tank/data/child"]
        );
        scope.revalidate(&i, &d, &p).unwrap();
        for roots in [
            vec![],
            vec!["tank/data".into(), "tank/data".into()],
            vec!["tank/data".into(), "tank/data/child".into()],
        ] {
            assert!(SnapshotScope::plan(&i, &d, &p, &roots).is_err());
        }
    }

    #[test]
    fn requires_complete_inventory_and_ancestor_identity_evidence() {
        for case in 0..6 {
            let (mut i, mut d, mut p) = fixture();
            match case {
                0 => i.requested_datasets = vec!["tank/data".into()],
                1 => i.datasets.retain(|d| d.name != "tank"),
                2 => {
                    d.remove("tank");
                }
                3 => {
                    d.get_mut("tank/data").unwrap().remove("objsetid");
                }
                4 => {
                    p.clear();
                }
                _ => {
                    p.get_mut("tank")
                        .unwrap()
                        .insert("guid".into(), property(9));
                }
            }
            assert!(plan(&i, &d, &p).is_err(), "case {case}");
        }
    }

    #[test]
    fn all_management_sources_and_unknowns_refuse_even_disabled_literals() {
        for name in ["tank", "tank/data", "tank/data/child"] {
            for source in ["local", "received", "inherited from tank", "-"] {
                for key in [
                    "zboot:primary",
                    "zboot:pair",
                    "zboot:staging",
                    "zboot:pending",
                    "zboot:future",
                    "zboot:be",
                ] {
                    let (i, mut d, p) = fixture();
                    d.get_mut(name).unwrap().insert(
                        key.into(),
                        NativeProperty {
                            value: "-".into(),
                            source: source.into(),
                        },
                    );
                    assert!(plan(&i, &d, &p).is_err(), "{name} {key} {source}");
                }
            }
        }
        let (i, d, mut p) = fixture();
        p.get_mut("tank")
            .unwrap()
            .insert("zboot:role".into(), property("secondary"));
        assert!(plan(&i, &d, &p).is_err());
    }

    #[test]
    fn secondary_staging_pending_partial_and_unknown_scopes_refuse() {
        for case in 0..4 {
            let (mut i, mut d, p) = fixture();
            match case {
                0 => i.datasets[2].readonly = true,
                1 => i.datasets[2].staging = Some("archive".into()),
                2 => i.datasets[2].pending = Some("operation".into()),
                _ => {
                    d.get_mut("tank/data")
                        .unwrap()
                        .insert("zboot:legacy".into(), property("on"));
                }
            }
            assert!(plan(&i, &d, &p).is_err(), "case {case}");
        }
    }

    #[test]
    fn every_incarnation_field_and_recursive_membership_invalidates_plan() {
        for case in 0..7 {
            let (mut i, d, mut p) = fixture();
            let original = plan(&i, &d, &p).unwrap();
            match case {
                0 => {
                    i.pools[0].guid = Guid::new(99);
                    p.get_mut("tank")
                        .unwrap()
                        .insert("guid".into(), property(99));
                    for d in &mut i.datasets {
                        d.identity.pool_guid = Guid::new(99);
                    }
                }
                1 => {
                    i.datasets[1].identity.guid = Guid::new(99);
                    i.datasets[1].guid = Guid::new(99);
                }
                2 => i.datasets[1].identity.createtxg = Txg::new(99),
                3 => i.datasets[1].identity.objsetid = ObjsetId::new(99),
                4 => {
                    i.datasets.remove(2);
                }
                5 => i.datasets.push(dataset("tank/data/new", 99)),
                _ => i.datasets[2].name = "tank/data/renamed".into(),
            }
            assert!(
                original.revalidate(&i, &evidence(&i), &p).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn property_observation_replacement_and_late_pending_refuse() {
        let (i, mut d, p) = fixture();
        let original = plan(&i, &d, &p).unwrap();
        d.get_mut("tank/data")
            .unwrap()
            .insert("createtxg".into(), property(999));
        assert!(plan(&i, &d, &p).is_err());
        let mut d = evidence(&i);
        d.get_mut("tank/data/child")
            .unwrap()
            .insert("zboot:pending".into(), property("new-op"));
        assert!(original.revalidate(&i, &d, &p).is_err());
    }
}
