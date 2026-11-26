//! A storage model for the tree verbs with fault injection: a process cut
//! before or after any durable write (effect, record write, hold), a lost
//! reply (applied, but reported as failed) and a refusal (not applied).
use super::{Backend, Effect};
use crate::history::contains_dataset as contains;
use std::collections::{BTreeMap, BTreeSet};
use zfs_tools::engine::{
    CanMount, Dataset, DatasetIdentity, DatasetKind, Encryption, Error, Guid, Inspection,
    KeyStatus, ObjsetId, Pool, Snapshot, SnapshotIdentity, SnapshotRef, Txg, hold, intent,
    native::{NativeProperty, PropertyInventory},
    state::NativeState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ds {
    pub guid: u64,
    pub createtxg: u64,
    pub objsetid: u64,
    pub volume: bool,
    pub origin: Option<String>,
    pub mounted: bool,
    /// Locally set (or received) properties.
    pub props: BTreeMap<String, String>,
    /// Stands for the dataset's data.
    pub content: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snap {
    pub guid: u64,
    pub createtxg: u64,
    pub objsetid: u64,
    pub holds: BTreeSet<String>,
    pub defer: bool,
    pub content: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PoolModel {
    pub guid: u64,
    pub bootfs: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Fake {
    pub pools: BTreeMap<String, PoolModel>,
    pub datasets: BTreeMap<String, Ds>,
    pub snapshots: BTreeMap<String, Snap>,
    pub capture_markers: BTreeMap<String, (u64, NativeProperty)>,
    pub running: Option<String>,
    pub next: u64,
    /// Durable writes so far, and every effect in order.
    pub writes: usize,
    pub log: Vec<String>,
    /// Inject a property change just before observation N (pure read-race tests).
    pub observe_changes: BTreeMap<usize, (String, String, String)>,
    pub observations: usize,
    /// Inject a property change just before durable write N (a race with
    /// the effect itself).
    pub write_changes: BTreeMap<usize, (String, String, String)>,
    /// How many writes had been made when the last injected change landed.
    pub changed_at: Option<usize>,
    /// Cut the process before (`false`) or after (`true`) write N.
    pub cut: Option<(usize, bool)>,
    /// Apply write N but report failure.
    pub lose: Option<usize>,
    /// Refuse write N without applying it.
    pub fail: Option<usize>,
    /// Just before write N, another tool runs `zfs snapshot -r POOL@LABEL`.
    pub foreign_snapshot: Option<(usize, String)>,
    /// Snapshots other tools took, which keep zboot's own ids unchanged.
    pub foreign: u64,
    pub crashed: bool,
    /// Pools imported read-only, as the RAM Menu imports every pool. Such a
    /// pool reports `readonly=on`, and each of its datasets reports
    /// `readonly=on` (temporary), as if mounted read-only. Only what plans
    /// observe is modeled, not the native refusal of writes.
    pub readonly_pools: BTreeSet<String>,
    /// The tree model assumes fixture roots contain boot pairs unless a test
    /// explicitly removes them. It models asset availability, not file bytes.
    pub missing_boot_assets: BTreeSet<String>,
}

const INHERITABLE: [&str; 4] = ["readonly", "mountpoint", "compression", "volmode"];

impl Fake {
    pub(crate) fn new() -> Self {
        let mut fake = Self {
            next: 100,
            ..Self::default()
        };
        fake.pool("a", 1);
        fake.pool("b", 2);
        fake
    }
    pub(crate) fn pool(&mut self, name: &str, guid: u64) {
        self.pools
            .insert(name.into(), PoolModel { guid, bootfs: None });
        self.create(name);
    }
    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }
    pub(crate) fn create(&mut self, name: &str) {
        let id = self.id();
        self.datasets.insert(
            name.into(),
            Ds {
                guid: id,
                createtxg: id,
                objsetid: id,
                volume: false,
                origin: None,
                mounted: true,
                props: BTreeMap::new(),
                content: id,
            },
        );
    }
    pub(crate) fn snap(&mut self, name: &str) {
        let (dataset, _) = name.split_once('@').unwrap();
        let content = self.datasets[dataset].content;
        let id = self.id();
        self.snapshots.insert(
            name.into(),
            Snap {
                guid: id,
                createtxg: id,
                objsetid: id,
                holds: BTreeSet::new(),
                defer: false,
                content,
            },
        );
    }
    /// Another tool's snapshot. Its ids come from their own range, so every
    /// id zboot's effects allocate stays that of an uninterrupted run.
    pub(crate) fn foreign_snap(&mut self, name: &str) -> u64 {
        let (dataset, _) = name.split_once('@').unwrap();
        let content = self.datasets[dataset].content;
        self.foreign += 1;
        let id = 1_000_000 + self.foreign;
        self.snapshots.insert(
            name.into(),
            Snap {
                guid: id,
                createtxg: self.next,
                objsetid: id,
                holds: BTreeSet::new(),
                defer: false,
                content,
            },
        );
        id
    }
    /// Another tool's `zfs snapshot -r POOL@LABEL`.
    pub(crate) fn foreign_recursive(&mut self, point: &str) {
        let (pool, label) = point.split_once('@').unwrap();
        let names: Vec<_> = self
            .datasets
            .keys()
            .filter(|name| contains(pool, name))
            .cloned()
            .collect();
        for name in names {
            self.foreign_snap(&format!("{name}@{label}"));
        }
    }
    /// Change a dataset's data.
    pub(crate) fn write(&mut self, name: &str) {
        let id = self.id();
        self.datasets.get_mut(name).unwrap().content = id;
    }
    pub(crate) fn set(&mut self, name: &str, key: &str, value: &str) {
        self.datasets
            .get_mut(name)
            .unwrap()
            .props
            .insert(key.into(), value.into());
    }
    /// A fresh process after a cut.
    pub(crate) fn revive(&mut self) {
        self.crashed = false;
        self.cut = None;
        self.lose = None;
        self.fail = None;
    }
    fn alive(&self) -> Result<(), Error> {
        if self.crashed {
            Err(Error::Inconsistent("simulated process loss".into()))
        } else {
            Ok(())
        }
    }
    /// One durable write: `apply` runs unless refused or cut before.
    fn durable(
        &mut self,
        what: String,
        apply: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.alive()?;
        self.writes += 1;
        let n = self.writes;
        if let Some((at, point)) = self.foreign_snapshot.clone()
            && at == n
        {
            self.foreign_recursive(&point);
        }
        if let Some((dataset, key, value)) = self.write_changes.remove(&n) {
            self.set(&dataset, &key, &value);
            self.changed_at = Some(n - 1);
        }
        if self.cut == Some((n, false)) {
            self.crashed = true;
            return self.alive();
        }
        if self.fail == Some(n) {
            return Err(Error::Inconsistent(format!("simulated refusal of {what}")));
        }
        apply(self)?;
        self.log.push(what);
        if self.cut == Some((n, true)) {
            self.crashed = true;
            return self.alive();
        }
        if self.lose == Some(n) {
            return Err(Error::Inconsistent("simulated lost reply".into()));
        }
        Ok(())
    }

    fn pool_guid(&self, name: &str) -> u64 {
        // A pool root's snapshot is `POOL@LABEL`.
        self.pools[super::pool_of(name.split('@').next().unwrap())].guid
    }
    pub(crate) fn identity(&self, name: &str) -> DatasetIdentity {
        let d = &self.datasets[name];
        DatasetIdentity {
            pool_guid: Guid::new(self.pool_guid(name)),
            guid: Guid::new(d.guid),
            createtxg: Txg::new(d.createtxg),
            objsetid: ObjsetId::new(d.objsetid),
        }
    }
    pub(crate) fn point(&self, name: &str) -> SnapshotRef {
        let s = &self.snapshots[name];
        let dataset = name.split_once('@').unwrap().0;
        SnapshotRef {
            name: name.into(),
            dataset_guid: Guid::new(self.datasets[dataset].guid),
            identity: SnapshotIdentity {
                pool_guid: Guid::new(self.pool_guid(name)),
                guid: Guid::new(s.guid),
                createtxg: Txg::new(s.createtxg),
                objsetid: ObjsetId::new(s.objsetid),
            },
        }
    }
    fn bind(&self, endpoint: &zfs_tools::engine::management::Endpoint) -> Result<(), Error> {
        if !self.datasets.contains_key(&endpoint.name)
            || self.identity(&endpoint.name) != endpoint.identity
        {
            return Err(Error::Inconsistent(format!(
                "{} changed identity",
                endpoint.name
            )));
        }
        Ok(())
    }
    fn bind_point(&self, point: &SnapshotRef) -> Result<(), Error> {
        if !self.snapshots.contains_key(&point.name) || self.point(&point.name) != *point {
            return Err(Error::Inconsistent(format!("{} changed", point.name)));
        }
        Ok(())
    }
    /// Effective value and native source of `key` on `name`.
    pub(crate) fn effective(&self, name: &str, key: &str) -> Option<(String, String)> {
        if let Some(value) = self.datasets[name].props.get(key) {
            return Some((value.clone(), "local".into()));
        }
        if !(key.contains(':') || INHERITABLE.contains(&key)) {
            return None;
        }
        let mut parent = name;
        while let Some((up, _)) = parent.rsplit_once('/') {
            parent = up;
            if let Some(value) = self.datasets[parent].props.get(key) {
                let value = if key == "mountpoint" && value.starts_with('/') {
                    format!("{}{}", value.trim_end_matches('/'), &name[parent.len()..])
                } else {
                    value.clone()
                };
                return Some((value, format!("inherited from {parent}")));
            }
        }
        match key {
            "mountpoint" => Some((format!("/{name}"), "default".into())),
            "readonly" => Some(("off".into(), "default".into())),
            "compression" => Some(("on".into(), "default".into())),
            "volmode" => Some(("default".into(), "default".into())),
            _ => None,
        }
    }
    fn value(&self, name: &str, key: &str) -> Option<String> {
        self.effective(name, key).map(|(value, _)| value)
    }
    fn inert(&self, root: &str) -> Result<(), Error> {
        for (name, d) in self.datasets.iter().filter(|(n, _)| contains(root, n)) {
            if self.value(name, "readonly").as_deref() != Some("on")
                || self.value(name, "volmode").as_deref() != Some("none")
                || (!d.volume
                    && (d.mounted || self.value(name, "mountpoint").as_deref() != Some("none")))
            {
                return Err(super::refuse(format!("{name} is not inert")));
            }
        }
        Ok(())
    }

    pub(crate) fn state(&self) -> Result<NativeState, Error> {
        self.alive()?;
        let pools = self
            .pools
            .iter()
            .map(|(name, p)| Pool {
                name: name.clone(),
                guid: Guid::new(p.guid),
                size_bytes: 1000,
                allocated_bytes: 100,
                free_bytes: 900,
                health: "ONLINE".into(),
                bootfs: p.bootfs.clone(),
            })
            .collect();
        let mut datasets = Vec::new();
        let mut properties = PropertyInventory::new();
        for (name, d) in &self.datasets {
            let mut props = BTreeMap::new();
            for (key, value) in [
                ("guid", d.guid),
                ("createtxg", d.createtxg),
                ("objsetid", d.objsetid),
            ] {
                props.insert(
                    key.to_string(),
                    NativeProperty {
                        value: value.to_string(),
                        source: "-".into(),
                    },
                );
            }
            let mut keys: BTreeSet<String> = INHERITABLE.iter().map(|k| k.to_string()).collect();
            keys.insert("canmount".into());
            for (other, o) in &self.datasets {
                if contains(other, name) {
                    keys.extend(o.props.keys().cloned());
                }
            }
            for key in keys {
                if let Some((value, source)) = self.effective(name, &key) {
                    props.insert(key, NativeProperty { value, source });
                }
            }
            let readonly_pool = self.readonly_pools.contains(super::pool_of(name));
            if readonly_pool {
                props.insert(
                    "readonly".into(),
                    NativeProperty {
                        value: "on".into(),
                        source: "temporary".into(),
                    },
                );
            }
            properties.insert(name.clone(), props);
            let get = |key: &str| self.value(name, key);
            let canmount = match get("canmount").as_deref() {
                Some("off") => CanMount::Off,
                Some("noauto") => CanMount::NoAuto,
                _ => CanMount::On,
            };
            datasets.push(Dataset {
                name: name.clone(),
                kind: if d.volume {
                    DatasetKind::Volume
                } else {
                    DatasetKind::Filesystem
                },
                guid: Guid::new(d.guid),
                identity: self.identity(name),
                used_bytes: 0,
                available_bytes: 0,
                referenced_bytes: 0,
                mountpoint: (!d.volume).then(|| get("mountpoint").unwrap()),
                volume_size_bytes: d.volume.then_some(1024),
                mounted: (!d.volume).then_some(d.mounted),
                readonly: readonly_pool || get("readonly").as_deref() == Some("on"),
                canmount: (!d.volume).then_some(canmount),
                origin: d.origin.clone(),
                encryption: if get("encryption").is_some_and(|v| v != "off") {
                    Encryption::Aes256Gcm
                } else {
                    Encryption::Off
                },
                keystatus: if get("keystatus").as_deref() == Some("unavailable") {
                    KeyStatus::Unavailable
                } else if get("encryptionroot").is_some() {
                    KeyStatus::Available
                } else {
                    KeyStatus::Unencrypted
                },
                encryptionroot: get("encryptionroot"),
                staging: get("zboot:staging"),
                pending: get("zboot:pending"),
            });
        }
        let snapshots = self
            .snapshots
            .iter()
            .map(|(name, s)| {
                let point = self.point(name);
                Snapshot {
                    name: name.clone(),
                    guid: point.identity.guid,
                    dataset_guid: point.dataset_guid,
                    identity: point.identity,
                    userrefs: s.holds.len() as u64,
                    defer_destroy: s.defer,
                    clones: self
                        .datasets
                        .iter()
                        .filter(|(_, d)| d.origin.as_deref() == Some(name))
                        .map(|(n, _)| n.clone())
                        .collect(),
                    holds: s.holds.iter().cloned().collect(),
                    creation_epoch_seconds: 1_700_000_000,
                    used_bytes: 0,
                    referenced_bytes: 0,
                }
            })
            .collect();
        Ok(NativeState {
            inspection: Inspection {
                schema_version: 3,
                imported_only: true,
                non_atomic: true,
                recursive: true,
                requested_datasets: vec![],
                pools,
                datasets,
                snapshots: Some(snapshots),
            },
            dataset_properties: properties,
            pool_properties: self
                .pools
                .iter()
                .map(|(name, p)| {
                    (
                        name.clone(),
                        BTreeMap::from([
                            (
                                "guid".to_string(),
                                NativeProperty {
                                    value: p.guid.to_string(),
                                    source: "-".into(),
                                },
                            ),
                            (
                                "readonly".to_string(),
                                NativeProperty {
                                    value: if self.readonly_pools.contains(name) {
                                        "on"
                                    } else {
                                        "off"
                                    }
                                    .into(),
                                    source: "-".into(),
                                },
                            ),
                            (
                                "bootfs".to_string(),
                                NativeProperty {
                                    value: p.bootfs.clone().unwrap_or_else(|| "-".into()),
                                    source: "-".into(),
                                },
                            ),
                        ]),
                    )
                })
                .collect(),
        })
    }

    fn effect(&mut self, effect: &Effect) -> Result<(), Error> {
        let refuse = |what: String| Err(Error::Inconsistent(what));
        match effect {
            Effect::Set { at, key, value } => {
                self.bind(at)?;
                let d = self.datasets.get_mut(&at.name).unwrap();
                d.props.insert(key.clone(), value.clone());
            }
            Effect::Inherit { at, key } => {
                self.bind(at)?;
                self.datasets.get_mut(&at.name).unwrap().props.remove(key);
            }
            Effect::Snapshot {
                names,
                id: operation,
            } => {
                for name in names {
                    let dataset = name.split_once('@').unwrap().0;
                    if !self.datasets.contains_key(dataset) || self.snapshots.contains_key(name) {
                        return refuse(format!("cannot snapshot {name}"));
                    }
                }
                let txg = self.id();
                for name in names {
                    let content = self.datasets[name.split_once('@').unwrap().0].content;
                    let id = self.id();
                    self.snapshots.insert(
                        name.clone(),
                        Snap {
                            guid: id,
                            createtxg: txg,
                            objsetid: id,
                            holds: BTreeSet::new(),
                            defer: false,
                            content,
                        },
                    );
                    self.capture_markers.insert(
                        name.clone(),
                        (
                            id,
                            NativeProperty {
                                value: operation.clone(),
                                source: "local".into(),
                            },
                        ),
                    );
                }
            }
            Effect::DestroySnapshot(point) => {
                self.bind_point(point)?;
                let s = &self.snapshots[&point.name];
                if !s.holds.is_empty()
                    || self
                        .datasets
                        .values()
                        .any(|d| d.origin.as_deref() == Some(point.name.as_str()))
                {
                    return refuse(format!("{} is held or has clones", point.name));
                }
                self.snapshots.remove(&point.name);
            }
            Effect::DestroyDataset(at) => {
                self.bind(at)?;
                let prefix = format!("{}@", at.name);
                let child = format!("{}/", at.name);
                if self.snapshots.keys().any(|s| s.starts_with(&prefix))
                    || self.datasets.keys().any(|d| d.starts_with(&child))
                {
                    return refuse(format!("{} has snapshots or children", at.name));
                }
                if let Some(origin) = self.datasets.remove(&at.name).unwrap().origin {
                    let defer = self.snapshots.get(&origin).is_some_and(|s| s.defer);
                    if defer && self.snapshots[&origin].holds.is_empty() {
                        self.snapshots.remove(&origin);
                    }
                }
            }
            Effect::Rollback(point) => {
                self.bind_point(point)?;
                let (dataset, _) = point.name.split_once('@').unwrap();
                let txg = self.snapshots[&point.name].createtxg;
                let prefix = format!("{dataset}@");
                if self
                    .snapshots
                    .iter()
                    .any(|(n, s)| n.starts_with(&prefix) && s.createtxg > txg)
                {
                    return refuse(format!("{} is not the latest snapshot", point.name));
                }
                let content = self.snapshots[&point.name].content;
                self.datasets.get_mut(dataset).unwrap().content = content;
            }
            Effect::Rename { from, to } => {
                self.bind(from)?;
                let parent = to.rsplit_once('/').map(|p| p.0).unwrap_or_default();
                if super::pool_of(to) != super::pool_of(&from.name)
                    || !self.datasets.contains_key(parent)
                    || self.datasets.contains_key(to)
                {
                    return refuse(format!("cannot rename to {to}"));
                }
                let map = |name: &str| format!("{to}{}", &name[from.name.len()..]);
                let moved: Vec<_> = self
                    .datasets
                    .keys()
                    .filter(|n| contains(&from.name, n))
                    .cloned()
                    .collect();
                for name in moved {
                    let d = self.datasets.remove(&name).unwrap();
                    self.datasets.insert(map(&name), d);
                }
                let moved: Vec<_> = self
                    .snapshots
                    .keys()
                    .filter(|n| contains(&from.name, n.split_once('@').unwrap().0))
                    .cloned()
                    .collect();
                for name in moved {
                    let s = self.snapshots.remove(&name).unwrap();
                    let (dataset, label) = name.split_once('@').unwrap();
                    let renamed = format!("{}@{label}", map(dataset));
                    for d in self.datasets.values_mut() {
                        if d.origin.as_deref() == Some(name.as_str()) {
                            d.origin = Some(renamed.clone());
                        }
                    }
                    self.snapshots.insert(renamed, s);
                }
                for p in self.pools.values_mut() {
                    if let Some(bootfs) = p.bootfs.as_mut().filter(|b| contains(&from.name, b)) {
                        *bootfs = map(bootfs);
                    }
                }
            }
            Effect::CreateInert { parent, to, id } => {
                self.bind(parent)?;
                if to.rsplit_once('/').map(|p| p.0) != Some(parent.name.as_str())
                    || self.datasets.contains_key(to)
                {
                    return refuse("invalid inert create".into());
                }
                self.create(to);
                let d = self.datasets.get_mut(to).unwrap();
                d.content = 0;
                d.mounted = false;
                d.props.extend(crate::placement::inert_properties(false));
                d.props.insert("encryption".into(), "off".into());
                d.props.insert(
                    zfs_tools::engine::management::STAGING_PROPERTY.into(),
                    id.clone(),
                );
                d.props.insert(
                    zfs_tools::engine::management::PENDING_PROPERTY.into(),
                    id.clone(),
                );
            }
            Effect::RenameInert { from, parent, to } => {
                self.bind(parent)?;
                self.inert(&from.name)?;
                self.effect(&Effect::Rename {
                    from: from.clone(),
                    to: to.clone(),
                })?;
            }
            Effect::QuiesceInert { at, .. } => {
                self.bind(at)?;
                self.inert(&at.name)?;
            }
            Effect::Clone {
                origin,
                parent: bound_parent,
                to,
                properties,
            } => {
                self.bind_point(origin)?;
                self.bind(bound_parent)?;
                self.inert(&bound_parent.name)?;
                let parent = to.rsplit_once('/').map(|p| p.0).unwrap_or_default();
                if parent != bound_parent.name
                    || !self.datasets.contains_key(parent)
                    || self.datasets.contains_key(to)
                {
                    return refuse(format!("cannot clone to {to}"));
                }
                let id = self.id();
                let source = self.datasets[origin.name.split_once('@').unwrap().0].clone();
                let mut crypto = BTreeMap::new();
                for key in ["encryption", "encryptionroot", "keystatus"] {
                    if let Some(value) = source.props.get(key) {
                        crypto.insert(key.into(), value.clone());
                    }
                }
                crypto.extend(properties.iter().cloned());
                self.datasets.insert(
                    to.clone(),
                    Ds {
                        guid: id,
                        createtxg: id,
                        objsetid: id,
                        volume: source.volume,
                        origin: Some(origin.name.clone()),
                        mounted: false,
                        props: crypto,
                        content: self.snapshots[&origin.name].content,
                    },
                );
                self.inert(to)?;
            }
            Effect::Bootfs { pool, dataset } => {
                self.pools.get_mut(pool).unwrap().bootfs = dataset.clone();
            }
        }
        Ok(())
    }
}

impl intent::Backend for Fake {
    fn pools(&mut self) -> Result<Vec<String>, Error> {
        self.alive()?;
        Ok(self.pools.keys().cloned().collect())
    }
    fn read(&mut self, pool: &str) -> Result<Option<String>, Error> {
        self.alive()?;
        Ok(self.datasets[pool].props.get(intent::PROPERTY).cloned())
    }
    fn write(&mut self, pool: &str, value: &str) -> Result<(), Error> {
        let (pool, value) = (pool.to_string(), value.to_string());
        self.durable(format!("record {pool}"), move |f| {
            f.set(&pool, intent::PROPERTY, &value);
            Ok(())
        })
    }
    fn remove(&mut self, pool: &str) -> Result<(), Error> {
        let pool = pool.to_string();
        self.durable(format!("clear {pool}"), move |f| {
            f.datasets
                .get_mut(&pool)
                .unwrap()
                .props
                .remove(intent::PROPERTY);
            Ok(())
        })
    }
}
impl hold::Backend for Fake {
    fn resolve(&mut self, point: &SnapshotRef) -> Result<Option<hold::Seen>, Error> {
        self.alive()?;
        Ok(self
            .snapshots
            .keys()
            .find(|name| self.point(name).identity == point.identity)
            .map(|name| hold::Seen {
                name: name.clone(),
                holds: self.snapshots[name].holds.iter().cloned().collect(),
            }))
    }
    fn hold(&mut self, name: &str, tag: &str) -> Result<(), Error> {
        let (name, tag) = (name.to_string(), tag.to_string());
        self.durable(format!("hold {tag} {name}"), move |f| {
            f.snapshots.get_mut(&name).unwrap().holds.insert(tag);
            Ok(())
        })
    }
    fn release(&mut self, name: &str, tag: &str) -> Result<(), Error> {
        let (name, tag) = (name.to_string(), tag.to_string());
        self.durable(format!("release {tag} {name}"), move |f| {
            let s = f.snapshots.get_mut(&name).unwrap();
            s.holds.remove(&tag);
            if s.defer
                && s.holds.is_empty()
                && !f
                    .datasets
                    .values()
                    .any(|d| d.origin.as_deref() == Some(name.as_str()))
            {
                f.snapshots.remove(&name);
            }
            Ok(())
        })
    }
}
impl Backend for Fake {
    fn verify_boot_assets(&mut self, name: &str) -> Result<(), Error> {
        crate::boot_support::MetadataBackend::verify_boot_assets(self, name)
            .map_err(|error| super::refuse(error.to_string()))
    }
    fn observe(&mut self) -> Result<NativeState, Error> {
        self.observations += 1;
        if let Some((dataset, key, value)) = self.observe_changes.remove(&self.observations) {
            self.set(&dataset, &key, &value);
            self.changed_at = Some(self.writes);
        }
        self.state()
    }
    fn running_root(&mut self) -> Result<Option<String>, Error> {
        self.alive()?;
        Ok(self.running.clone())
    }
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error> {
        self.alive()?;
        self.bind_point(point)?;
        let marker = self
            .capture_markers
            .get(&point.name)
            .filter(|(guid, property)| {
                *guid == point.identity.guid.get() && property.source == "local"
            })
            .ok_or_else(|| super::refuse("capture marker is missing or not local"))?;
        Ok(marker.1.value.clone())
    }
    fn apply(&mut self, effect: &Effect) -> Result<(), Error> {
        if let Effect::Clone {
            origin,
            parent,
            to,
            properties,
        } = effect
        {
            // Native clone commits the DSL clone first, then applies a
            // fallible property ioctl; every one of these boundaries is cut.
            let bare = Effect::Clone {
                origin: origin.clone(),
                parent: parent.clone(),
                to: to.clone(),
                properties: vec![],
            };
            self.durable(format!("bare {bare:?}"), move |f| f.effect(&bare))?;
            for (key, value) in properties {
                let set = Effect::Set {
                    at: zfs_tools::engine::management::Endpoint {
                        name: to.clone(),
                        identity: self.identity(to),
                    },
                    key: key.clone(),
                    value: value.clone(),
                };
                self.durable(format!("clone property {set:?}"), move |f| f.effect(&set))?;
            }
            return Ok(());
        }
        let effect = effect.clone();
        self.durable(format!("{effect:?}"), move |f| f.effect(&effect))
    }
}

/// `default` on the same model: a pool's `bootfs` is one durable write.
impl crate::boot_support::MetadataBackend for Fake {
    fn observe(&mut self) -> crate::menu::Result<NativeState> {
        Ok(self.state()?)
    }
    fn verify_boot_assets(&mut self, dataset: &str) -> crate::menu::Result<()> {
        if !self.datasets.contains_key(dataset) || self.missing_boot_assets.contains(dataset) {
            return Err(super::refuse("no matching kernel/initrd pairs found").into());
        }
        Ok(())
    }
    fn set(
        &mut self,
        dataset: &str,
        setting: &crate::boot_support::BootSetting,
    ) -> crate::menu::Result<()> {
        use crate::boot_support::BootSetting;
        let pool = super::pool_of(dataset).to_string();
        let bootfs = match setting {
            BootSetting::Default => Some(dataset.to_string()),
            BootSetting::ClearDefault => None,
            BootSetting::Cmdline(_) => return Err(super::refuse("not modelled").into()),
        };
        self.durable(format!("bootfs {pool}"), move |f| {
            f.pools.get_mut(&pool).unwrap().bootfs = bootfs;
            Ok(())
        })?;
        Ok(())
    }
}

/// Everything an operation should leave the same, without the bookkeeping.
pub(crate) fn storage(fake: &Fake) -> String {
    let datasets: Vec<_> = fake
        .datasets
        .iter()
        .map(|(n, d)| {
            let props: BTreeMap<_, _> = d
                .props
                .iter()
                .filter(|(k, _)| k.as_str() != intent::PROPERTY)
                .collect();
            format!(
                "{n} {} {:?} {} {} {props:?}",
                d.guid, d.origin, d.mounted, d.content
            )
        })
        .collect();
    let snapshots: Vec<_> = fake
        .snapshots
        .iter()
        .map(|(n, s)| format!("{n} {} {:?} {}", s.guid, s.holds, s.content))
        .collect();
    let pools: Vec<_> = fake
        .pools
        .iter()
        .map(|(n, p)| format!("{n} {:?}", p.bootfs))
        .collect();
    format!("{datasets:#?}\n{snapshots:#?}\n{pools:?}")
}

/// The one record on any pool, as `resume` would find it.
pub(crate) fn record(fake: &mut Fake) -> Option<intent::Intent<serde_json::Value>> {
    intent::find(fake)
        .unwrap()
        .into_iter()
        .map(|(_, found)| match found {
            intent::Found::Record(record) => record,
            intent::Found::Unreadable(e) => panic!("{e}"),
        })
        .next()
}

/// A refusal case's fixture change.
pub(crate) type Setup = fn(&mut Fake);

/// Run `run` cut before and after every durable write of a clean run, then
/// resume from a fresh process (or rerun when nothing was recorded) and
/// require the clean run's final storage; then the same with each reply lost.
pub(crate) fn every_cut(
    setup: impl Fn() -> Fake,
    run: impl Fn(&mut Fake) -> Result<(), Error>,
    resume: impl Fn(&mut Fake, intent::Intent<serde_json::Value>) -> Result<(), Error>,
) {
    let mut clean = setup();
    run(&mut clean).expect("clean run");
    assert!(record(&mut clean).is_none(), "clean run left a record");
    let expected = storage(&clean);
    let total = clean.writes;
    assert!(total > 1);
    let finish = |fake: &mut Fake, label: &str| {
        fake.revive();
        match record(fake) {
            Some(found) => resume(fake, found).unwrap_or_else(|e| panic!("{label}: {e}")),
            None if storage(fake) != expected => {
                run(fake).unwrap_or_else(|e| panic!("{label} rerun: {e}"))
            }
            None => {}
        }
        assert!(record(fake).is_none(), "{label} left a record");
        assert_eq!(storage(fake), expected, "{label}");
    };
    for n in 1..=total {
        for after in [false, true] {
            let mut fake = setup();
            fake.cut = Some((n, after));
            assert!(run(&mut fake).is_err(), "cut {n} {after} did not stop");
            finish(
                &mut fake,
                &format!("cut {} write {n}", if after { "after" } else { "before" }),
            );
        }
        let mut fake = setup();
        fake.lose = Some(n);
        let _ = run(&mut fake);
        finish(&mut fake, &format!("lost reply {n}"));
    }
}
