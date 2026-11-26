//! Read-only inventory of one dataset tree: identities, kinds, mount facts,
//! native properties with their sources, and snapshots.
//!
//! Absence is a result only when successful native queries prove it. A failed
//! or malformed query is an error, never an empty tree. Queries are sequential
//! and take no writer lock; an inventory is evidence, not admission.
use crate::api::Error;
use crate::engine::{self, CanMount, native};
use crate::{DatasetIdentity, DatasetKind, Guid, SnapshotRef};
use std::{collections::BTreeMap, time::Duration};

/// What to observe under one root dataset. Datasets are always listed;
/// snapshot history and full property sets are opt-in because they cost one
/// root-scoped native query each (plus a hold query for held snapshots).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryRequest {
    root: String,
    snapshots: bool,
    properties: bool,
    pool_properties: bool,
    within: Option<Duration>,
}
impl InventoryRequest {
    /// Inventory ROOT and its descendants. ROOT may be a pool name.
    pub fn new(root: impl Into<String>) -> Result<Self, Error> {
        let root = root.into();
        engine::validate_dataset_name(&root)?;
        Ok(Self {
            root,
            snapshots: false,
            properties: false,
            pool_properties: false,
            within: None,
        })
    }
    /// Bound the whole observation, every query and the completion of its
    /// output included, by one deadline: on expiry the running query's
    /// group is sent SIGKILL and its leader reaped, and the error carries
    /// [`Error::observation_stop`]. Without it the queries have no deadline.
    /// A zero deadline is refused when observing.
    pub fn within(mut self, deadline: Duration) -> Self {
        self.within = Some(deadline);
        self
    }
    /// Also observe every snapshot under the root, with holds and clones.
    pub fn with_snapshots(mut self) -> Self {
        self.snapshots = true;
        self
    }
    /// Also observe every native property of each dataset, with its source.
    pub fn with_properties(mut self) -> Self {
        self.properties = true;
        self
    }
    /// Also observe every native property of the root's pool, with its
    /// source (for example `load_guid`, which names the import instance).
    pub fn with_pool_properties(mut self) -> Self {
        self.pool_properties = true;
        self
    }
    pub fn root(&self) -> &str {
        &self.root
    }
}

/// Observe one dataset tree in already imported pools. The root is absent
/// when its pool is not imported or the pool's successful listing lacks it;
/// every other failure is an error. Snapshot and property queries must
/// describe exactly the listed datasets, and the tree and pool are listed
/// again after them, so a concurrent create, destroy or replacement at the
/// same name is reported as an error. No writer lock is taken.
///
/// Free-text user property values are not part of the identity listing. With
/// properties requested, a user property value containing a tab and newline
/// can forge a row for a property its dataset lacks (never an identity, a
/// presence or a property the dataset has): trust only properties whose
/// writers you trust (DESIGN.md, Known limitations).
pub fn observe_inventory(request: &InventoryRequest) -> Result<Inventory, Error> {
    crate::api::observe_within(request.within, |mut run| {
        observe_inventory_with(request, &mut run)
    })
}

fn observe_inventory_with(
    request: &InventoryRequest,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, engine::Error>,
) -> Result<Inventory, Error> {
    let observed =
        native::inventory_with(&request.root, request.snapshots, request.properties, run)?;
    let mut properties = observed.properties;
    let datasets = observed
        .datasets
        .into_iter()
        .map(|dataset| {
            let properties = match properties.as_mut() {
                None => None,
                Some(all) => Some(parse_property_map(
                    all.remove(&dataset.name)
                        .expect("native inventory checked property completeness"),
                    &dataset.name,
                    "dataset",
                )?),
            };
            Ok(InventoryDataset {
                name: dataset.name,
                identity: dataset.identity,
                kind: dataset.kind,
                origin: dataset.origin,
                mountpoint: dataset.mountpoint,
                mounted: dataset.mounted,
                canmount: dataset.canmount,
                readonly: dataset.readonly,
                properties,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let snapshots = observed.snapshots.map(|snapshots| {
        snapshots
            .into_iter()
            .map(|snapshot| InventorySnapshot {
                point: snapshot.point(),
                defer_destroy: snapshot.defer_destroy,
                holds: snapshot.holds,
                clones: snapshot.clones,
                creation_epoch_seconds: snapshot.creation_epoch_seconds,
            })
            .collect()
    });
    Ok(Inventory {
        root: request.root.clone(),
        pool_properties: match (request.pool_properties, observed.pool) {
            (false, _) => None,
            (true, None) => Some(BTreeMap::new()),
            (true, Some(guid)) => Some(observe_pool_properties(&request.root, guid, run)?),
        },
        pool_guid: observed.pool,
        datasets,
        snapshots,
    })
}

/// One observed dataset tree. Lookups refuse names outside the root and
/// history that was not requested, so neither can be mistaken for absence.
/// Read the root's pool properties and require the pool incarnation the
/// tree was listed from: its GUID property names it.
fn observe_pool_properties(
    root: &str,
    guid: Guid,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, engine::Error>,
) -> Result<BTreeMap<String, Property>, Error> {
    let pool = engine::pool_of(root);
    let mut all = native::pool_properties_with(&[pool.to_string()], &mut *run)?;
    let observed = all
        .remove(pool)
        .expect("native pool properties are complete");
    if observed.get("guid").map(|p| p.value.as_str()) != Some(guid.to_string().as_str()) {
        return Err(Error::new(format!("pool changed during inventory: {pool}")));
    }
    parse_property_map(observed, pool, "pool")
}

fn parse_property_map(
    raw: BTreeMap<String, native::NativeProperty>,
    owner: &str,
    subject: &'static str,
) -> Result<BTreeMap<String, Property>, Error> {
    raw.into_iter()
        .map(|(key, property)| {
            Ok((
                key,
                Property {
                    source: PropertySource::parse(&property.source, owner, subject)?,
                    value: property.value,
                },
            ))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    root: String,
    pool_guid: Option<Guid>,
    datasets: Vec<InventoryDataset>,
    snapshots: Option<Vec<InventorySnapshot>>,
    pool_properties: Option<BTreeMap<String, Property>>,
}
impl Inventory {
    pub fn root(&self) -> &str {
        &self.root
    }
    /// The GUID of the imported pool named by the root's first component, or
    /// `None` when no pool of that name is imported. This tells "pool not
    /// imported" from "absent in pool G"; a present root's identity carries
    /// the same GUID.
    pub fn pool_guid(&self) -> Option<Guid> {
        self.pool_guid
    }
    /// The pool's native properties, empty when the pool is not imported.
    /// They were read after the tree and bound to the pool's GUID.
    pub fn pool_properties(&self) -> Result<&BTreeMap<String, Property>, Error> {
        self.pool_properties
            .as_ref()
            .ok_or_else(|| Error::new("pool properties were not observed"))
    }
    /// The root and its descendants, sorted by name; empty when the root is absent.
    pub fn datasets(&self) -> &[InventoryDataset] {
        &self.datasets
    }
    /// The exact dataset at NAME, or `None` when it is proven absent. NAME must
    /// be the root or lie below it.
    pub fn dataset(&self, name: &str) -> Result<Option<&InventoryDataset>, Error> {
        self.in_scope(name)?;
        Ok(self.datasets.iter().find(|dataset| dataset.name == name))
    }
    /// Every snapshot under the root, sorted by name. Refuses when snapshot
    /// history was not requested.
    pub fn snapshots(&self) -> Result<&[InventorySnapshot], Error> {
        self.snapshots
            .as_deref()
            .ok_or_else(|| Error::new("snapshot history was not observed"))
    }
    /// Snapshots of exactly this dataset (not its descendants), sorted by name.
    pub fn snapshots_of(&self, dataset: &str) -> Result<Vec<&InventorySnapshot>, Error> {
        self.in_scope(dataset)?;
        Ok(self
            .snapshots()?
            .iter()
            .filter(|snapshot| snapshot.dataset_name() == dataset)
            .collect())
    }
    /// The current snapshot at exactly NAME, or `None` when proven absent.
    pub fn snapshot(&self, name: &str) -> Result<Option<&InventorySnapshot>, Error> {
        engine::validate_snapshot_name(name)?;
        self.in_scope(name.split_once('@').expect("validated snapshot name").0)?;
        Ok(self
            .snapshots()?
            .iter()
            .find(|snapshot| snapshot.point.name == name))
    }
    fn in_scope(&self, name: &str) -> Result<(), Error> {
        engine::validate_dataset_name(name)?;
        if !engine::contains_dataset(&self.root, name) {
            return Err(Error::new(format!(
                "dataset is outside the observed inventory root {}: {name}",
                self.root
            )));
        }
        Ok(())
    }
}

/// One dataset's current incarnation with its kind and mount facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryDataset {
    name: String,
    identity: DatasetIdentity,
    kind: DatasetKind,
    origin: Option<String>,
    mountpoint: Option<String>,
    mounted: Option<bool>,
    canmount: Option<CanMount>,
    readonly: bool,
    properties: Option<BTreeMap<String, Property>>,
}
impl InventoryDataset {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn identity(&self) -> &DatasetIdentity {
        &self.identity
    }
    pub fn kind(&self) -> &DatasetKind {
        &self.kind
    }
    /// The snapshot this dataset was cloned from, by name.
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }
    /// The native `mountpoint` value (a path, `none` or `legacy`); `None` for
    /// a volume.
    pub fn mountpoint(&self) -> Option<&str> {
        self.mountpoint.as_deref()
    }
    /// Whether native ZFS reports the filesystem mounted; `None` for a volume.
    pub fn mounted(&self) -> Option<bool> {
        self.mounted
    }
    /// The native `canmount` value; `None` for a volume.
    pub fn canmount(&self) -> Option<CanMount> {
        self.canmount
    }
    pub fn readonly(&self) -> bool {
        self.readonly
    }
    /// Every native property with its source. Refuses when properties were
    /// not requested.
    pub fn properties(&self) -> Result<&BTreeMap<String, Property>, Error> {
        self.properties
            .as_ref()
            .ok_or_else(|| Error::new("dataset properties were not observed"))
    }
    /// One property, or `None` when the complete observed set lacks it (an
    /// unset user property). Refuses when properties were not requested.
    pub fn property(&self, key: &str) -> Result<Option<&Property>, Error> {
        Ok(self.properties()?.get(key))
    }
}

/// One snapshot's current incarnation and the facts that keep it alive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventorySnapshot {
    point: SnapshotRef,
    defer_destroy: bool,
    holds: Vec<String>,
    clones: Vec<String>,
    creation_epoch_seconds: i64,
}
impl InventorySnapshot {
    pub fn point(&self) -> &SnapshotRef {
        &self.point
    }
    pub fn name(&self) -> &str {
        &self.point.name
    }
    /// The dataset part of the snapshot name.
    pub fn dataset_name(&self) -> &str {
        self.point
            .name
            .split_once('@')
            .expect("observed snapshot name")
            .0
    }
    /// Marked for deferred destruction: it disappears once unheld and unused.
    pub fn defer_destroy(&self) -> bool {
        self.defer_destroy
    }
    /// User hold tags, sorted.
    pub fn holds(&self) -> &[String] {
        &self.holds
    }
    /// Datasets cloned from this snapshot, sorted.
    pub fn clones(&self) -> &[String] {
        &self.clones
    }
    pub fn creation_epoch_seconds(&self) -> i64 {
        self.creation_epoch_seconds
    }
}

/// A native property value as `zfs get -p` reports it, with its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    value: String,
    source: PropertySource,
}
impl Property {
    pub fn value(&self) -> &str {
        &self.value
    }
    pub fn source(&self) -> &PropertySource {
        &self.source
    }
}

/// Where a property's value comes from. An unknown native source is a
/// malformed observation, not a new variant guessed by this library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertySource {
    /// Native `-`: a read-only or intrinsic value.
    Intrinsic,
    Default,
    Local,
    Received,
    Temporary,
    /// Inherited from this strict ancestor dataset.
    Inherited(String),
}
impl PropertySource {
    fn parse(source: &str, dataset: &str, subject: &'static str) -> Result<Self, Error> {
        Ok(match source {
            "-" => Self::Intrinsic,
            "default" => Self::Default,
            "local" => Self::Local,
            "received" => Self::Received,
            "temporary" => Self::Temporary,
            _ => match source.strip_prefix("inherited from ") {
                Some(parent)
                    if parent != dataset
                        && engine::validate_dataset_name(parent).is_ok()
                        && engine::contains_dataset(parent, dataset) =>
                {
                    Self::Inherited(parent.into())
                }
                _ => {
                    return Err(Error::new(format!(
                        "invalid {subject} properties query output: unknown property source {source}"
                    )));
                }
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjsetId, Txg};

    const POOLS: &str =
        "other\t9\t1000\t100\t900\tONLINE\t-\ntank\t123\t1000\t100\t900\tONLINE\t-\n";
    const ROOT: &str =
        "tank\tfilesystem\t456\t100\t900\t80\tnone\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\n";
    const VM: &str =
        "tank/vm\tfilesystem\t457\t100\t900\t80\t/vm\t-\t7\t8\tyes\toff\tnoauto\t-\toff\t-\t-\n";
    const DISK: &str = "tank/vm/disk\tvolume\t458\t100\t900\t80\t-\t4096\t9\t10\t-\ton\t-\ttank/vm/base@v1\toff\t-\t-\n";
    const BASE: &str =
        "tank/vm/base\tvolume\t459\t100\t900\t80\t-\t4096\t11\t12\t-\toff\t-\t-\toff\t-\t-\n";
    const SIBLING: &str =
        "tank/vmx\tfilesystem\t460\t100\t900\t80\t/vmx\t-\t13\t14\tno\toff\ton\t-\toff\t-\t-\n";
    /// A volume left by an abandoned resumable receive reports no volsize.
    const RECEIVING: &str =
        "tank/vmx/recv\tvolume\t461\t100\t900\t80\t-\t-\t15\t16\t-\toff\t-\t-\toff\t-\t-\n";
    const SNAPS: &str = "tank/vm/base@v1\t789\t1700000000\t0\t20\t30\t40\t1\ton\ttank/vm/disk\ntank/vm@daily\t790\t1700000001\t0\t20\t31\t41\t0\toff\t-\n";
    const HOLDS: &str = "tank/vm/base@v1\tfleet:reader\tWed Nov 20 10:00 2026\n";
    const INVENTORY: &str = "name,type,guid,used,available,referenced,mountpoint,volsize,createtxg,objsetid,mounted,readonly,canmount,origin,encryption,keystatus,encryptionroot";

    fn pool() -> String {
        format!("{ROOT}{VM}{DISK}{BASE}{SIBLING}{RECEIVING}")
    }
    fn vm_rows() -> String {
        format!("{VM}{DISK}{BASE}")
    }
    fn properties(guids: &[(&str, u64)]) -> String {
        let mut out = String::new();
        for (name, guid) in guids {
            out.push_str(&format!("{name}\tguid\t{guid}\t-\n"));
            let from = if *name == "tank/vm" {
                "tank"
            } else {
                "tank/vm"
            };
            out.push_str(&format!(
                "{name}\tcompression\tlz4\tinherited from {from}\n"
            ));
            out.push_str(&format!("{name}\tfleet:role\t\tlocal\n"));
        }
        out
    }
    fn vm_properties() -> String {
        properties(&[
            ("tank/vm", 457),
            ("tank/vm/base", 459),
            ("tank/vm/disk", 458),
        ])
    }

    type Reply = Result<String, engine::Error>;
    /// Replies keyed by the native query, recording each argv. `pool` holds
    /// the whole pool's rows; the name probe and subtree listings are derived
    /// from it unless overridden. `relist` and `pools_again` answer the
    /// confirming queries after snapshot and property observation.
    struct Native {
        pools: Reply,
        pools_again: Option<Reply>,
        pool: String,
        names: Option<Reply>,
        subtree: Option<Reply>,
        relist: Option<Reply>,
        snapshots: Reply,
        holds: Reply,
        properties: Reply,
        pool_properties: Reply,
        calls: Vec<String>,
    }
    impl Default for Native {
        fn default() -> Self {
            Self {
                pools: Ok(POOLS.into()),
                pools_again: None,
                pool: pool(),
                names: None,
                subtree: None,
                relist: None,
                snapshots: Ok(SNAPS.into()),
                holds: Ok(HOLDS.into()),
                properties: Ok(vm_properties()),
                pool_properties: Ok(POOL_PROPERTIES.into()),
                calls: vec![],
            }
        }
    }
    impl Native {
        fn observe(&mut self, request: &InventoryRequest) -> Result<Inventory, Error> {
            let mut calls = vec![];
            let (mut zpools, mut subtrees) = (0, 0);
            let result = observe_inventory_with(request, &mut |program, args| {
                let call = format!("{program} {}", args.join(" "));
                calls.push(call.clone());
                let last = args.last().unwrap().as_str();
                match (program, args[0].as_str()) {
                    ("zpool", "list") => {
                        zpools += 1;
                        match (&self.pools_again, zpools) {
                            (Some(again), 2..) => again.clone(),
                            _ => self.pools.clone(),
                        }
                    }
                    ("zfs", "list") if call.contains("-t snapshot") => self.snapshots.clone(),
                    ("zfs", "list") if call.contains(" -o name -d ") => {
                        let depth: usize = args[args.len() - 2].parse().unwrap();
                        self.names.clone().unwrap_or_else(|| {
                            Ok(self
                                .pool
                                .lines()
                                .map(|row| row.split('\t').next().unwrap())
                                .filter(|name| {
                                    engine::contains_dataset(last, name)
                                        && name.matches('/').count() <= depth
                                })
                                .map(|name| format!("{name}\n"))
                                .collect())
                        })
                    }
                    ("zfs", "list") => {
                        assert!(call.contains(INVENTORY), "{call}");
                        subtrees += 1;
                        let derived = || {
                            Ok(self
                                .pool
                                .lines()
                                .filter(|row| {
                                    engine::contains_dataset(last, row.split('\t').next().unwrap())
                                })
                                .map(|row| format!("{row}\n"))
                                .collect())
                        };
                        match (subtrees, &self.subtree, &self.relist) {
                            (1, Some(reply), _) | (2.., _, Some(reply)) => reply.clone(),
                            _ => derived(),
                        }
                    }
                    ("zfs", "holds") => self.holds.clone(),
                    ("zfs", "get") => self.properties.clone(),
                    ("zpool", "get") => self.pool_properties.clone(),
                    _ => panic!("unexpected native call: {call}"),
                }
            });
            self.calls = calls;
            result
        }
    }
    const POOL_PROPERTIES: &str =
        "tank\tguid\t123\t-\ntank\tload_guid\t77\t-\ntank\tcachefile\tnone\tlocal\n";

    #[test]
    fn pool_properties_are_opt_in_and_bound_to_the_listed_pool() {
        let mut native = Native::default();
        let bare = native
            .observe(&InventoryRequest::new("tank/vm").unwrap())
            .unwrap();
        assert!(
            bare.pool_properties().is_err(),
            "not requested is not empty"
        );
        assert!(!native.calls.iter().any(|c| c.starts_with("zpool get")));
        let request = InventoryRequest::new("tank/vm")
            .unwrap()
            .with_pool_properties();
        let inventory = native.observe(&request).unwrap();
        let properties = inventory.pool_properties().unwrap();
        assert_eq!(properties["load_guid"].value(), "77");
        assert_eq!(properties["load_guid"].source(), &PropertySource::Intrinsic);
        assert_eq!(properties["cachefile"].source(), &PropertySource::Local);
        assert!(
            native
                .calls
                .contains(&"zpool get -H -p -o name,property,value,source all tank".into())
        );
        // Another incarnation of the pool, or a failed query, is an error.
        native.pool_properties = Ok(POOL_PROPERTIES.replace("\t123\t", "\t124\t"));
        assert!(native.observe(&request).is_err());
        native.pool_properties = failed("zpool get");
        assert!(native.observe(&request).is_err());
        // An absent pool has no properties, which is a result.
        native.pools = Ok(String::new());
        let absent = native.observe(&request).unwrap();
        assert!(absent.pool_properties().unwrap().is_empty());
    }

    fn failed(what: &str) -> Reply {
        Err(engine::Error::Command {
            program: "zfs",
            args: vec![],
            detail: format!("{what} failed"),
        })
    }
    fn request() -> InventoryRequest {
        InventoryRequest::new("tank/vm")
            .unwrap()
            .with_snapshots()
            .with_properties()
    }
    /// Every combination of the opt-in queries, datasets-only first.
    fn combinations() -> [InventoryRequest; 4] {
        let bare = InventoryRequest::new("tank/vm").unwrap();
        [
            bare.clone(),
            bare.clone().with_snapshots(),
            bare.clone().with_properties(),
            request(),
        ]
    }

    #[test]
    fn present_tree_reports_identity_kind_mount_facts_properties_and_snapshots() {
        let mut native = Native::default();
        let inventory = native.observe(&request()).unwrap();
        let zpool = "zpool list -H -p -o name,guid,size,allocated,free,health,bootfs".to_string();
        let subtree = format!("zfs list -H -p -t filesystem,volume -o {INVENTORY} -r tank/vm");
        assert_eq!(
            native.calls,
            [
                zpool.clone(),
                "zfs list -H -t filesystem,volume -o name -d 1 tank".into(),
                subtree.clone(),
                "zfs list -H -p -t snapshot -o name,guid,creation,used,referenced,createtxg,objsetid,userrefs,defer_destroy,clones -r tank/vm".into(),
                "zfs holds -H tank/vm/base@v1".into(),
                "zfs get -H -p -r -t filesystem,volume -o name,property,value,source all tank/vm".into(),
                subtree,
                zpool,
            ]
        );
        assert_eq!(inventory.root(), "tank/vm");
        assert_eq!(inventory.pool_guid(), Some(Guid::new(123)));
        let names: Vec<_> = inventory.datasets().iter().map(|d| d.name()).collect();
        assert_eq!(names, ["tank/vm", "tank/vm/base", "tank/vm/disk"]);

        let vm = inventory.dataset("tank/vm").unwrap().unwrap();
        assert_eq!(vm.kind(), &DatasetKind::Filesystem);
        assert_eq!(
            vm.identity(),
            &DatasetIdentity {
                pool_guid: Guid::new(123),
                guid: Guid::new(457),
                createtxg: Txg::new(7),
                objsetid: ObjsetId::new(8),
            }
        );
        assert_eq!(
            (vm.mountpoint(), vm.mounted(), vm.canmount(), vm.readonly()),
            (Some("/vm"), Some(true), Some(CanMount::NoAuto), false)
        );
        assert_eq!(vm.origin(), None);

        let disk = inventory.dataset("tank/vm/disk").unwrap().unwrap();
        assert_eq!(disk.kind(), &DatasetKind::Volume);
        assert_eq!(disk.origin(), Some("tank/vm/base@v1"));
        assert_eq!(
            (
                disk.mountpoint(),
                disk.mounted(),
                disk.canmount(),
                disk.readonly()
            ),
            (None, None, None, true)
        );
        let compression = disk.property("compression").unwrap().unwrap();
        assert_eq!(compression.value(), "lz4");
        assert_eq!(
            compression.source(),
            &PropertySource::Inherited("tank/vm".into())
        );
        let role = disk.property("fleet:role").unwrap().unwrap();
        assert_eq!((role.value(), role.source()), ("", &PropertySource::Local));
        assert_eq!(
            disk.property("guid").unwrap().unwrap().source(),
            &PropertySource::Intrinsic
        );
        assert_eq!(disk.property("fleet:unset").unwrap(), None);

        let all: Vec<_> = inventory
            .snapshots()
            .unwrap()
            .iter()
            .map(|s| s.name())
            .collect();
        assert_eq!(all, ["tank/vm/base@v1", "tank/vm@daily"]);
        let v1 = inventory.snapshot("tank/vm/base@v1").unwrap().unwrap();
        assert_eq!(v1.dataset_name(), "tank/vm/base");
        assert_eq!(v1.point().dataset_guid, Guid::new(459));
        assert_eq!(v1.point().identity.createtxg, Txg::new(30));
        assert!(v1.defer_destroy());
        assert_eq!(v1.holds(), ["fleet:reader"]);
        assert_eq!(v1.clones(), ["tank/vm/disk"]);
        assert_eq!(v1.creation_epoch_seconds(), 1_700_000_000);
        let own: Vec<_> = inventory
            .snapshots_of("tank/vm")
            .unwrap()
            .iter()
            .map(|s| s.name())
            .collect();
        assert_eq!(own, ["tank/vm@daily"]);
    }

    #[test]
    fn absent_root_and_absent_members_are_results() {
        // A pool that is not imported.
        let mut native = Native::default();
        let inventory = native
            .observe(
                &InventoryRequest::new("cpool/vm")
                    .unwrap()
                    .with_snapshots()
                    .with_properties(),
            )
            .unwrap();
        assert_eq!(native.calls.len(), 1);
        assert_eq!(inventory.pool_guid(), None);
        assert!(inventory.datasets().is_empty());
        assert_eq!(inventory.dataset("cpool/vm/disk").unwrap(), None);
        assert!(inventory.snapshots().unwrap().is_empty());
        assert_eq!(inventory.snapshot("cpool/vm@x").unwrap(), None);

        // A name the imported pool's successful listing lacks; tank/vmx is
        // a sibling, not a descendant of tank/v.
        let mut native = Native::default();
        let inventory = native
            .observe(&InventoryRequest::new("tank/v").unwrap().with_snapshots())
            .unwrap();
        assert_eq!(native.calls.len(), 2);
        assert_eq!(inventory.pool_guid(), Some(Guid::new(123)));
        assert!(inventory.datasets().is_empty());

        // A deep root below an absent ancestor.
        let mut native = Native::default();
        let inventory = native
            .observe(&InventoryRequest::new("tank/gone/a/b").unwrap())
            .unwrap();
        assert_eq!(
            native.calls[1],
            "zfs list -H -t filesystem,volume -o name -d 3 tank"
        );
        assert!(inventory.datasets().is_empty());

        // Members below a present root.
        let mut native = Native::default();
        let inventory = native.observe(&request()).unwrap();
        assert_eq!(inventory.dataset("tank/vm/missing").unwrap(), None);
        assert_eq!(inventory.snapshot("tank/vm/disk@v9").unwrap(), None);
        assert!(inventory.snapshots_of("tank/vm/disk").unwrap().is_empty());

        // An empty pool listing is absence too.
        let mut native = Native {
            pools: Ok(String::new()),
            ..Native::default()
        };
        let inventory = native.observe(&request()).unwrap();
        assert!(inventory.datasets().is_empty() && inventory.pool_guid().is_none());
    }

    #[test]
    fn lookups_refuse_names_outside_the_root_and_history_not_requested() {
        let mut native = Native::default();
        let inventory = native.observe(&request()).unwrap();
        for name in ["tank", "tank/vmx", "other/vm"] {
            assert!(inventory.dataset(name).is_err(), "{name}");
        }
        assert!(inventory.snapshot("tank@root").is_err());
        assert!(inventory.snapshot("tank/vm").is_err());
        assert!(inventory.snapshots_of("tank/vmx").is_err());
        assert!(inventory.dataset("tank/vm/-bad").is_err());

        let mut native = Native::default();
        let bare = native
            .observe(&InventoryRequest::new("tank/vm").unwrap())
            .unwrap();
        assert_eq!(
            native.calls.len(),
            4,
            "no snapshot, property or confirming subtree query"
        );
        assert!(bare.snapshots().is_err());
        assert!(bare.snapshot("tank/vm@daily").is_err());
        assert!(bare.snapshots_of("tank/vm").is_err());
        let vm = bare.dataset("tank/vm").unwrap().unwrap();
        assert!(vm.properties().is_err());
        assert!(vm.property("guid").is_err());
        assert_eq!(vm.mountpoint(), Some("/vm"));

        assert!(InventoryRequest::new("tank/vm@snap").is_err());
        assert!(InventoryRequest::new("").is_err());
    }

    #[test]
    fn a_failed_query_is_an_error_never_absence() {
        for native in [
            Native {
                pools: failed("zpool list"),
                ..Native::default()
            },
            Native {
                pools_again: Some(failed("zpool list")),
                ..Native::default()
            },
            Native {
                names: Some(failed("name probe")),
                ..Native::default()
            },
            Native {
                subtree: Some(failed("subtree list")),
                ..Native::default()
            },
            Native {
                relist: Some(failed("subtree relist")),
                ..Native::default()
            },
            Native {
                snapshots: failed("snapshot list"),
                ..Native::default()
            },
            Native {
                holds: failed("holds"),
                ..Native::default()
            },
            Native {
                properties: failed("property get"),
                ..Native::default()
            },
        ] {
            let mut native = native;
            let error = native.observe(&request()).unwrap_err().to_string();
            assert!(error.contains("failed"), "{error}");
        }
    }

    /// A member destroyed, recreated or renamed onto between the first
    /// listing and the last query is refused for every query combination
    /// that can observe it, and so is a replaced pool.
    #[test]
    fn a_tree_or_pool_changed_between_queries_is_an_error_in_every_combination() {
        let replaced = vm_rows().replace("\t459\t", "\t999\t");
        let destroyed = format!("{VM}{DISK}");
        let created = format!(
            "{}tank/vm/new\tvolume\t500\t1\t1\t1\t-\t4096\t20\t21\t-\toff\t-\t-\toff\t-\t-\n",
            vm_rows()
        );
        let recreated_root = vm_rows().replace("\t457\t", "\t998\t");
        for (index, request) in combinations().into_iter().enumerate() {
            let opted = index > 0;
            for relist in [&replaced, &destroyed, &created, &recreated_root] {
                let mut native = Native {
                    relist: Some(Ok(relist.clone())),
                    ..Native::default()
                };
                // Datasets-only runs one listing, so there is nothing between
                // queries to confirm.
                assert_eq!(native.observe(&request).is_err(), opted, "{index}");
            }
            let mut native = Native {
                pools_again: Some(Ok(POOLS.replace("\t123\t", "\t124\t"))),
                ..Native::default()
            };
            let error = native.observe(&request).unwrap_err().to_string();
            assert!(error.contains("pool changed"), "{error}");
            let mut native = Native {
                pools_again: Some(Ok("other\t9\t1000\t100\t900\tONLINE\t-\n".into())),
                ..Native::default()
            };
            assert!(native.observe(&request).is_err(), "pool exported mid-run");
        }
    }

    #[test]
    fn an_incomplete_receive_fails_only_an_inventory_that_lists_it_and_is_named() {
        // Outside the root: neither the name probe nor the subtree parses it.
        let mut native = Native::default();
        assert!(native.observe(&request()).is_ok());
        let mut native = Native::default();
        assert!(
            native
                .observe(&InventoryRequest::new("tank/vmx/other").unwrap())
                .unwrap()
                .datasets()
                .is_empty()
        );
        // Inside it: fail closed, naming the dataset and the likely cause.
        let mut native = Native::default();
        let error = native
            .observe(&InventoryRequest::new("tank/vmx").unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("tank/vmx/recv") && error.contains("incomplete or abandoned receive"),
            "{error}"
        );
    }

    #[test]
    fn malformed_or_partial_native_output_is_an_error() {
        let cases = [
            Native {
                pools: Ok("tank\t0\t1\n".into()),
                ..Native::default()
            },
            // The name probe: the pool's own root missing, a row deeper than
            // asked, a duplicate, an invalid name, a foreign pool, extra columns.
            Native {
                names: Ok("tank/vm\n".into()).into(),
                ..Native::default()
            },
            Native {
                names: Some(Ok("tank\ntank/vm\ntank/vm/disk\n".into())),
                ..Native::default()
            },
            Native {
                names: Some(Ok("tank\ntank/vm\ntank/vm\n".into())),
                ..Native::default()
            },
            Native {
                names: Some(Ok("tank\ntank/-vm\n".into())),
                ..Native::default()
            },
            Native {
                names: Some(Ok("tank\nother/vm\ntank/vm\n".into())),
                ..Native::default()
            },
            Native {
                names: Some(Ok("tank\ntank/vm\tx\n".into())),
                ..Native::default()
            },
            // The subtree listing.
            Native {
                subtree: Some(Ok(vm_rows().replace("\t458\t", "\t0\t"))),
                ..Native::default()
            },
            Native {
                subtree: Some(Ok(vm_rows().replace("volume", "bookmark"))),
                ..Native::default()
            },
            // The probe saw the root but the subtree lacks it.
            Native {
                subtree: Some(Ok(format!("{DISK}{BASE}"))),
                ..Native::default()
            },
            Native {
                subtree: Some(Ok(format!("{}{SIBLING}", vm_rows()))),
                ..Native::default()
            },
            // Full-width rows with management columns are not inventory rows.
            Native {
                subtree: Some(Ok(vm_rows().replace("\t-\t-\n", "\t-\t-\t-\t-\n"))),
                ..Native::default()
            },
            // A snapshot whose parent was not listed (created between queries).
            Native {
                snapshots: Ok(format!(
                    "{SNAPS}tank/vm/new@x\t800\t1700000002\t0\t1\t50\t51\t0\toff\t-\n"
                )),
                ..Native::default()
            },
            // A snapshot outside the root.
            Native {
                snapshots: Ok(format!(
                    "{SNAPS}tank/vmx@x\t801\t1700000002\t0\t1\t52\t53\t0\toff\t-\n"
                )),
                ..Native::default()
            },
            Native {
                snapshots: Ok(SNAPS.replace("\ton\t", "\tmaybe\t")),
                ..Native::default()
            },
            // Hold count differs from userrefs.
            Native {
                holds: Ok(String::new()),
                ..Native::default()
            },
            // A listed dataset missing from the property set (destroyed between queries).
            Native {
                properties: Ok(properties(&[("tank/vm", 457), ("tank/vm/disk", 458)])),
                ..Native::default()
            },
            // An unlisted dataset in the property set (created between queries).
            Native {
                properties: Ok(format!(
                    "{}{}",
                    vm_properties(),
                    properties(&[("tank/vm/new", 500)])
                )),
                ..Native::default()
            },
            // Name reuse between the listing and the property query.
            Native {
                properties: Ok(vm_properties().replace("\t458\t", "\t999\t")),
                ..Native::default()
            },
            // A forged duplicate of an observed property.
            Native {
                properties: Ok(format!("{}tank/vm/disk\tguid\t458\t-\n", vm_properties())),
                ..Native::default()
            },
            Native {
                properties: Ok(vm_properties().replace("inherited from tank/vm", "upstream")),
                ..Native::default()
            },
            Native {
                properties: Ok(
                    vm_properties().replace("inherited from tank/vm", "inherited from -x")
                ),
                ..Native::default()
            },
            // Inherited from a dataset that is not an ancestor.
            Native {
                properties: Ok(
                    vm_properties().replace("inherited from tank/vm", "inherited from tank/vmx")
                ),
                ..Native::default()
            },
            Native {
                properties: Ok(vm_properties().replace("\tlz4\t", "\tlz4\textra\t")),
                ..Native::default()
            },
        ];
        for (index, native) in cases.into_iter().enumerate() {
            let mut native = native;
            assert!(native.observe(&request()).is_err(), "case {index}");
        }
    }
}
