//! An in-memory pool model for restore tests. Property layers follow the
//! OpenZFS behaviour DESIGN records: local over received, an explicit inherit
//! masks a received value. A stream is one raw `send -w [-I]` of one dataset
//! into `zfs receive -u`: it carries snapshots with their GUIDs and no
//! property; `-o` values become local on a new dataset. A new raw copy of an
//! encrypted dataset is its own encryption root (`keylocation=prompt`)
//! wrapped like its source's root at the time of the send. Every effect and
//! record write can be cut before, after, or have its reply lost.
use super::{
    Backend, Candidate, DatasetView, DeploySpec, PoolView, Property, Scrub, SnapshotView, View,
    backend::within, refuse,
};
use crate::{
    device::{DiskIdentity, DiskReview, Partition},
    esp::FileIdentity,
    menu::Result,
};
use std::collections::{BTreeMap, BTreeSet};
use zfs_tools::engine::{
    DatasetIdentity, Guid, ObjsetId, SnapshotIdentity, SnapshotRef, Txg, hold,
    management::Endpoint,
    stream::{LeafStream, StreamOutcome},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// The process dies just before the effect.
    Before,
    /// The effect happens, then the process dies.
    After,
    /// The effect happens and its reply is lost; the process continues.
    Lost,
}

#[derive(Debug, Clone)]
pub struct FDataset {
    pub name: String,
    pub pool: u64,
    pub guid: u64,
    pub txg: u64,
    pub volume: bool,
    pub used: u64,
    pub mounted: bool,
    pub origin: Option<String>,
    pub encryption_root: Option<String>,
    pub local: BTreeMap<String, String>,
    pub received: BTreeMap<String, String>,
    /// Explicitly inherited: a received value here is not effective.
    pub masked: BTreeSet<String>,
    pub resume_token: bool,
    /// Bytes written since the newest snapshot (`written`).
    pub written: u64,
    /// An encryption root's wrapping: what opens it.
    pub key: Option<FKey>,
    /// Relinked to a root whose wrapping differs from its own: no key opens it.
    pub unopenable: bool,
}

/// How an encryption root's master keys are wrapped. Two datasets open with
/// the same key exactly when their wrappings are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FKey {
    /// The passphrase or key bytes.
    pub material: String,
    pub salt: String,
    pub iters: String,
}

#[derive(Debug, Clone)]
pub struct FSnapshot {
    pub name: String,
    pub pool: u64,
    pub dataset_guid: u64,
    pub guid: u64,
    pub txg: u64,
    pub holds: Vec<String>,
    pub defer_destroy: bool,
}

#[derive(Debug, Clone)]
pub struct FPool {
    pub name: String,
    pub guid: u64,
    pub imported: bool,
    pub readonly: bool,
    pub altroot: Option<String>,
    pub bootfs: Option<String>,
    /// Device number of the disk it lives on.
    pub disk: String,
    /// Device numbers of the other disks it spans.
    pub extra_disks: Vec<String>,
    pub capacity: u64,
    /// The hostid its labels record: the importing one.
    pub hostid: String,
}

#[derive(Debug, Clone)]
pub struct FDisk {
    pub identity: DiskIdentity,
    pub partitions: Vec<Partition>,
    pub table: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FScrub {
    pub state: String,
    pub start: u64,
    pub polls: u32,
    pub paused: bool,
}

#[derive(Debug, Clone)]
pub struct Fake {
    pub pools: Vec<FPool>,
    pub datasets: Vec<FDataset>,
    pub snapshots: Vec<FSnapshot>,
    pub disks: Vec<FDisk>,
    pub secondaries: BTreeSet<String>,
    pub running_root: Option<String>,
    /// Key files present here: path to the key material they hold.
    pub keys: BTreeMap<String, String>,
    /// The source BE's `/etc/hostid`; empty for none.
    pub hostid: String,
    /// The running system's effective OpenZFS hostid.
    pub spl_hostid: String,
    /// The source BE's `/usr/lib/zboot/zboot.efi`; `None` for none.
    pub loader: Option<FileIdentity>,
    /// A block device carrying a hibernation image.
    pub hibernation: Option<String>,
    pub now: u64,
    next: u64,
    pub scrubs: BTreeMap<String, FScrub>,
    /// Scrub errors the next finished scrub reports.
    pub scrub_errors: u64,
    /// Every effect attempted, in order.
    pub effects: Vec<String>,
    pub cut: Option<(usize, Cut)>,
    pub crashed: bool,
    /// Receives into this pool run out of space after this many bytes.
    pub space_limit: Option<(String, u64)>,
    /// Receives whose destination starts with this fail their last member.
    pub corrupt: Option<String>,
    pub export_error: bool,
    pub label_probe_error: bool,
    /// A native property setter fails without changing its target.
    pub denied_set: Option<(String, String)>,
    /// A pending old minor cannot be considered drained on property readback.
    pub exposed_volumes: BTreeSet<String>,
    pub quiesce_fails: bool,
    /// The receiver commits, but the sender does not report successful EOF.
    pub sender_failure: Option<String>,
    /// Runs once just before the next stream whose destination starts with
    /// its prefix: a change made by someone else while restore runs.
    pub before_stream: Option<(String, Interference)>,
    /// The key relink helper is missing or cannot load libzfs_core here.
    pub change_key_broken: bool,
    /// The inherit at this effect index reports success without applying.
    pub ignored_inherit: Option<usize>,
}

/// A change someone else makes while restore runs.
pub type Interference = fn(&mut Fake);

pub const ID: &str = "0123456789abcdef";
pub const HOSTID: &str = "0a0b0c0d";
const GIB: u64 = 1 << 30;

fn inheritable(key: &str) -> bool {
    !matches!(key, "canmount" | "keylocation" | "keyformat" | "volsize")
}

fn parent(name: &str) -> Option<&str> {
    name.rsplit_once('/').map(|(p, _)| p)
}

fn disk(path: &str, number: &str, serial: &str, bytes: u64) -> FDisk {
    FDisk {
        identity: DiskIdentity {
            path: path.into(),
            device_number: number.into(),
            sysfs_path: format!("/sys/devices/{number}"),
            bytes,
            logical_sector: 512,
            physical_sector: 4096,
            serial: Some(serial.into()),
            wwn: Some(format!("wwn-{serial}")),
            model: Some("FAKE".into()),
        },
        partitions: Vec::new(),
        table: None,
    }
}

fn partition(disk: &FDisk, index: usize, bytes: u64, filesystem: &str) -> Partition {
    Partition {
        path: format!("{}p{index}", disk.identity.path),
        device_number: format!("{}:{index}", disk.identity.device_number),
        bytes,
        partition_uuid: Some(format!("part-{}-{index}", disk.identity.device_number)),
        filesystem: Some(filesystem.into()),
        filesystem_uuid: None,
        filesystem_label: None,
    }
}

impl Fake {
    /// B (`bpool`, running `bpool/ROOT/debian`) on disk b; A (`rpool`) on
    /// disk a with `rpool/home` (two children), `rpool/srv` and the old BE.
    pub fn world() -> Self {
        let mut fake = Self {
            pools: Vec::new(),
            datasets: Vec::new(),
            snapshots: Vec::new(),
            disks: vec![
                disk("/dev/fake-a", "259:0", "SERIAL-A", 100 * GIB),
                disk("/dev/fake-b", "259:8", "SERIAL-B", 100 * GIB),
                disk("/dev/fake-c", "259:16", "SERIAL-C", 100 * GIB),
            ],
            secondaries: BTreeSet::new(),
            running_root: Some("bpool/ROOT/debian".into()),
            keys: BTreeMap::new(),
            hostid: HOSTID.into(),
            spl_hostid: HOSTID.into(),
            loader: Some(FileIdentity {
                sha256: "5a".repeat(32),
                bytes: 64 << 20,
            }),
            hibernation: None,
            now: 1_000,
            next: 100,
            scrubs: BTreeMap::new(),
            scrub_errors: 0,
            effects: Vec::new(),
            cut: None,
            crashed: false,
            space_limit: None,
            corrupt: None,
            export_error: false,
            label_probe_error: false,
            denied_set: None,
            exposed_volumes: BTreeSet::new(),
            quiesce_fails: false,
            sender_failure: None,
            before_stream: None,
            change_key_broken: false,
            ignored_inherit: None,
        };
        let a = fake.disks[0].clone();
        fake.disks[0].partitions = vec![
            partition(&a, 1, GIB, "vfat"),
            partition(&a, 2, 4 * GIB, "swap"),
            partition(&a, 3, 90 * GIB, "zfs_member"),
        ];
        fake.disks[0].table = Some("table-a".into());
        let b = fake.disks[1].clone();
        fake.disks[1].partitions = vec![
            partition(&b, 1, GIB, "vfat"),
            partition(&b, 2, 95 * GIB, "zfs_member"),
        ];
        fake.disks[1].table = Some("table-b".into());

        fake.add_pool("bpool", "259:8", 90 * GIB);
        fake.add("bpool/ROOT", &[("canmount", "off"), ("mountpoint", "none")]);
        fake.add(
            "bpool/ROOT/debian",
            &[("canmount", "noauto"), ("mountpoint", "/")],
        );
        fake.add("bpool/ROOT/debian/var", &[("canmount", "noauto")]);
        fake.dataset_mut("bpool/ROOT/debian").mounted = true;
        fake.dataset_mut("bpool/ROOT/debian").used = 4 * GIB;
        fake.snap("bpool/ROOT/debian@old", true);

        fake.add_pool("rpool", "259:0", 85 * GIB);
        fake.add("rpool/ROOT", &[("canmount", "off"), ("mountpoint", "none")]);
        fake.add(
            "rpool/ROOT/debian",
            &[("canmount", "noauto"), ("mountpoint", "/")],
        );
        fake.add(
            "rpool/home",
            &[("mountpoint", "/home"), ("compression", "zstd")],
        );
        fake.add("rpool/home/alice", &[]);
        fake.add(
            "rpool/home/bob",
            &[("canmount", "noauto"), ("readonly", "on")],
        );
        fake.add("rpool/srv", &[("mountpoint", "legacy")]);
        fake.dataset_mut("rpool/home/alice").used = 3 * GIB;
        fake.snap("rpool/home@daily", true);
        fake.snap("rpool/home/alice@hourly", false);
        fake
    }

    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    pub fn add_pool(&mut self, name: &str, disk: &str, capacity: u64) {
        let guid = self.id();
        self.pools.push(FPool {
            name: name.into(),
            guid,
            imported: true,
            readonly: false,
            altroot: None,
            bootfs: None,
            disk: disk.into(),
            extra_disks: Vec::new(),
            capacity,
            hostid: self.spl_hostid.clone(),
        });
        self.add(name, &[]);
    }

    pub fn add(&mut self, name: &str, local: &[(&str, &str)]) {
        let pool = self.pool_named(name.split('/').next().unwrap()).guid;
        let id = self.id();
        self.datasets.push(FDataset {
            name: name.into(),
            pool,
            guid: id,
            txg: id,
            volume: false,
            used: 64 << 20,
            mounted: false,
            origin: None,
            encryption_root: None,
            local: local
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            received: BTreeMap::new(),
            masked: BTreeSet::new(),
            resume_token: false,
            written: 0,
            key: None,
            unopenable: false,
        });
    }

    /// Make `name` an encryption root with key material `key-NAME`.
    pub fn encrypt(&mut self, name: &str, format: &str, location: &str) {
        let dataset = self.dataset_mut(name);
        dataset.encryption_root = Some(name.into());
        dataset.local.insert("keyformat".into(), format.into());
        dataset.local.insert("keylocation".into(), location.into());
        dataset.key = Some(FKey {
            material: format!("key-{name}"),
            salt: format!("salt-{name}"),
            iters: if format == "passphrase" {
                "350000"
            } else {
                "0"
            }
            .into(),
        });
    }

    /// Make `name` take its key from its parent's encryption root.
    pub fn inherit_key(&mut self, name: &str) {
        let root = self
            .dataset_ref(parent(name).unwrap())
            .encryption_root
            .clone();
        let dataset = self.dataset_mut(name);
        dataset.encryption_root = root;
        dataset.key = None;
        dataset.local.remove("keyformat");
        dataset.local.remove("keylocation");
    }

    /// The wrapping that opens `name`: its encryption root's.
    pub fn key_of(&self, name: &str) -> Option<&FKey> {
        let root = self.find(name)?.encryption_root.as_deref()?;
        self.find(root)?.key.as_ref()
    }

    pub fn snap(&mut self, name: &str, recursive: bool) {
        let (dataset, suffix) = name.split_once('@').unwrap();
        let members: Vec<_> = if recursive {
            self.tree(dataset)
                .iter()
                .map(|d| (d.name.clone(), d.guid, d.pool))
                .collect()
        } else {
            let d = self.dataset_ref(dataset);
            vec![(d.name.clone(), d.guid, d.pool)]
        };
        for (member, dataset_guid, pool) in members {
            let id = self.id();
            self.snapshots.push(FSnapshot {
                name: format!("{member}@{suffix}"),
                pool,
                dataset_guid,
                guid: id,
                txg: id,
                holds: Vec::new(),
                defer_destroy: false,
            });
        }
    }

    pub fn pool_named(&self, name: &str) -> &FPool {
        self.pools
            .iter()
            .find(|p| p.name == name && p.imported)
            .unwrap_or_else(|| panic!("no imported pool {name}"))
    }
    fn imported(&self, guid: u64) -> bool {
        self.pools.iter().any(|p| p.guid == guid && p.imported)
    }
    pub fn dataset_ref(&self, name: &str) -> &FDataset {
        self.find(name)
            .unwrap_or_else(|| panic!("no dataset {name}"))
    }
    pub fn dataset_mut(&mut self, name: &str) -> &mut FDataset {
        let index = self
            .find_index(name)
            .unwrap_or_else(|| panic!("no dataset {name}"));
        &mut self.datasets[index]
    }
    pub fn find(&self, name: &str) -> Option<&FDataset> {
        self.find_index(name).map(|i| &self.datasets[i])
    }
    fn find_index(&self, name: &str) -> Option<usize> {
        self.datasets
            .iter()
            .position(|d| d.name == name && self.imported(d.pool))
    }
    pub fn snapshot_ref(&self, name: &str) -> Option<&FSnapshot> {
        self.snapshots
            .iter()
            .find(|s| s.name == name && self.imported(s.pool))
    }
    pub fn tree(&self, root: &str) -> Vec<&FDataset> {
        let mut tree: Vec<_> = self
            .datasets
            .iter()
            .filter(|d| self.imported(d.pool) && within(root, &d.name))
            .collect();
        tree.sort_by(|a, b| a.name.cmp(&b.name));
        tree
    }

    /// Effective value and source, as `zfs get` reports them.
    pub fn effective(&self, name: &str, key: &str) -> Option<(String, String)> {
        let dataset = self.find(name)?;
        if dataset.volume && matches!(key, "mountpoint" | "canmount") {
            return None;
        }
        if let Some(value) = dataset.local.get(key) {
            return Some((value.clone(), "local".into()));
        }
        if !dataset.masked.contains(key)
            && let Some(value) = dataset.received.get(key)
        {
            return Some((value.clone(), "received".into()));
        }
        if inheritable(key) {
            let mut current = parent(name);
            while let Some(ancestor) = current {
                let Some(a) = self.find(ancestor) else { break };
                let value = a.local.get(key).cloned().or_else(|| {
                    (!a.masked.contains(key))
                        .then(|| a.received.get(key).cloned())
                        .flatten()
                });
                if let Some(value) = value {
                    let value = if key == "mountpoint" && value.starts_with('/') {
                        let tail = &name[ancestor.len()..];
                        if value == "/" {
                            tail.to_owned()
                        } else {
                            format!("{value}{tail}")
                        }
                    } else {
                        value
                    };
                    return Some((value, format!("inherited from {ancestor}")));
                }
                current = parent(ancestor);
            }
        }
        let default = match key {
            "canmount" => "on".to_string(),
            "readonly" => "off".into(),
            "volmode" => "default".into(),
            "compression" => "on".into(),
            "atime" => "on".into(),
            "mountpoint" => format!("/{name}"),
            _ => return None,
        };
        Some((default, "default".into()))
    }

    fn keys(&self, name: &str) -> BTreeSet<String> {
        let mut keys: BTreeSet<String> = [
            "canmount",
            "readonly",
            "volmode",
            "compression",
            "atime",
            "mountpoint",
        ]
        .map(String::from)
        .into();
        let mut current = Some(name);
        while let Some(n) = current {
            if let Some(d) = self.find(n) {
                keys.extend(d.local.keys().cloned());
                keys.extend(d.received.keys().cloned());
            }
            current = parent(n);
        }
        keys
    }

    fn used(&self, root: &str) -> u64 {
        self.tree(root).iter().map(|d| d.used).sum()
    }
    fn free(&self, pool: u64) -> u64 {
        let p = self.pools.iter().find(|p| p.guid == pool).unwrap();
        let used: u64 = self
            .datasets
            .iter()
            .filter(|d| d.pool == pool)
            .map(|d| d.used)
            .sum();
        p.capacity.saturating_sub(used)
    }

    fn check(&self) -> Result<()> {
        if self.crashed {
            return Err(refuse("fake process crashed"));
        }
        Ok(())
    }

    /// Run one effect under the configured cut.
    fn effect<T>(&mut self, what: String, apply: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.check()?;
        let index = self.effects.len();
        self.effects.push(what.clone());
        let cut = self.cut.filter(|(at, _)| *at == index).map(|(_, c)| c);
        if cut == Some(Cut::Before) {
            self.crashed = true;
            return Err(refuse(format!("cut before {what}")));
        }
        let result = apply(self);
        match cut {
            Some(Cut::After) => {
                self.crashed = true;
                Err(refuse(format!("cut after {what}")))
            }
            Some(Cut::Lost) => Err(refuse(format!("reply lost: {what}"))),
            _ => result,
        }
    }

    /// A new process: the crash and its cut are over.
    pub fn restart(&mut self) {
        self.crashed = false;
        self.cut = None;
    }

    fn writable(&self, name: &str) -> Result<()> {
        let pool = name.split('/').next().unwrap();
        let p = self
            .pools
            .iter()
            .find(|p| p.name == pool && p.imported)
            .ok_or_else(|| refuse(format!("pool {pool} is not imported")))?;
        if p.readonly {
            return Err(refuse(format!("pool {pool} is read-only")));
        }
        Ok(())
    }

    fn receive(&mut self, stream: &LeafStream) -> std::result::Result<(), String> {
        let source = self
            .find(&stream.source.name)
            .filter(|d| identity(d) == stream.source.identity)
            .ok_or("stream source incarnation changed")?
            .clone();
        for point in stream.base.iter().chain(std::iter::once(&stream.boundary)) {
            if self
                .snapshot_ref(&point.name)
                .is_none_or(|s| self.point(s) != *point)
            {
                return Err("stream snapshot identity or name changed".into());
            }
        }
        let destination = stream.destination.clone();
        self.writable(&destination).map_err(|e| e.to_string())?;
        let corrupt = self
            .corrupt
            .as_ref()
            .is_some_and(|prefix| destination.starts_with(prefix.as_str()));
        let mut history: Vec<FSnapshot> = self
            .snapshots
            .iter()
            .filter(|s| {
                self.imported(s.pool)
                    && s.name.split_once('@').unwrap().0 == source.name
                    && s.txg <= stream.boundary.identity.createtxg.get()
                    && stream
                        .base
                        .as_ref()
                        .is_none_or(|base| s.txg > base.identity.createtxg.get())
            })
            .cloned()
            .collect();
        history.sort_by_key(|s| s.txg);
        // The wrapping a raw stream carries: its source root's, now.
        let wrapping = source.encryption_root.as_ref().map(|root| {
            let root = self.find(root).unwrap();
            (
                root.key.clone().unwrap(),
                root.local.get("keyformat").cloned().unwrap_or_default(),
            )
        });
        let name = match &stream.base {
            None => {
                history.retain(|s| s.guid == stream.boundary.identity.guid.get());
                if self.find(&destination).is_some() {
                    return Err("destination exists".into());
                }
                let dest_parent = parent(&destination).ok_or("no destination parent")?;
                if self.find(dest_parent).is_none() {
                    return Err("destination parent does not exist".into());
                }
                let safe = [
                    ("mountpoint", "none"),
                    ("readonly", "on"),
                    ("volmode", "none"),
                ]
                .iter()
                .all(|(key, value)| {
                    self.effective(dest_parent, key)
                        .is_some_and(|(v, _)| v == *value)
                });
                if !safe {
                    return Err("receive parent is not inert".into());
                }
                if let Some((limit_pool, limit)) = &self.space_limit
                    && destination.starts_with(&format!("{limit_pool}/"))
                    && source.used > *limit
                {
                    return Err("cannot receive: out of space".into());
                }
                if corrupt {
                    return Err("cannot receive: invalid stream (checksum mismatch)".into());
                }
                let pool = self.dataset_ref(dest_parent).pool;
                let guid = self.id();
                let mut local: BTreeMap<String, String> = stream.create.iter().cloned().collect();
                let (encryption_root, key) = match &wrapping {
                    Some((key, format)) => {
                        local.insert("keylocation".into(), "prompt".into());
                        local.insert("keyformat".into(), format.clone());
                        (Some(destination.clone()), Some(key.clone()))
                    }
                    None => (None, None),
                };
                self.datasets.push(FDataset {
                    name: destination.clone(),
                    pool,
                    guid,
                    txg: guid,
                    volume: source.volume,
                    used: source.used,
                    mounted: false,
                    origin: None,
                    encryption_root,
                    local,
                    received: BTreeMap::new(),
                    masked: BTreeSet::new(),
                    resume_token: false,
                    written: 0,
                    key,
                    unopenable: source.unopenable,
                });
                let safe = [("readonly", "on"), ("volmode", "none")]
                    .iter()
                    .all(|(key, value)| {
                        self.effective(&destination, key)
                            .is_some_and(|(v, _)| v == *value)
                    })
                    && (source.volume
                        || self
                            .effective(&destination, "mountpoint")
                            .is_some_and(|(v, _)| v == "none"));
                if !safe {
                    return Err(format!("new dataset {destination} escaped inert placement"));
                }
                destination
            }
            Some(base) => {
                let target = self
                    .find(&destination)
                    .ok_or("destination does not exist")?
                    .clone();
                let newest = self
                    .snapshots
                    .iter()
                    .filter(|s| s.dataset_guid == target.guid && s.pool == target.pool)
                    .max_by_key(|s| s.txg)
                    .map(|s| s.guid);
                if newest != Some(base.identity.guid.get()) {
                    return Err("destination's newest snapshot is not the stream's base".into());
                }
                if target.written != 0 {
                    return Err("destination has been modified since most recent snapshot".into());
                }
                if corrupt {
                    // The receive commits snapshot by snapshot; the last fails.
                    history.pop();
                }
                if let Some((key, _)) = &wrapping
                    && target.encryption_root.as_deref() == Some(destination.as_str())
                {
                    self.dataset_mut(&destination).key = Some(key.clone());
                }
                destination
            }
        };
        let (pool, guid) = {
            let target = self.dataset_ref(&name);
            (target.pool, target.guid)
        };
        for snapshot in history {
            let txg = self.id();
            let (_, snap) = snapshot.name.split_once('@').unwrap();
            self.snapshots.push(FSnapshot {
                name: format!("{name}@{snap}"),
                pool,
                dataset_guid: guid,
                guid: snapshot.guid,
                txg,
                holds: Vec::new(),
                defer_destroy: false,
            });
        }
        if corrupt {
            return Err("cannot receive: invalid stream (checksum mismatch)".into());
        }
        Ok(())
    }

    /// The model's state for comparison across runs: names, effective
    /// boot/mount/key properties, encryption roots and snapshot GUID classes;
    /// fresh identities and import state are left out.
    pub fn normalized(&self) -> String {
        let mut labels: BTreeMap<u64, usize> = BTreeMap::new();
        let mut snapshots: Vec<_> = self.snapshots.iter().collect();
        snapshots.sort_by(|a, b| a.name.cmp(&b.name));
        for s in &snapshots {
            let next = labels.len();
            labels.entry(s.guid).or_insert(next);
        }
        let mut out = String::new();
        let mut pools: Vec<_> = self.pools.iter().collect();
        pools.sort_by(|a, b| a.name.cmp(&b.name));
        for pool in pools {
            out.push_str(&format!(
                "pool {} on {} bootfs {:?} hostid {}\n",
                pool.name, pool.disk, pool.bootfs, pool.hostid
            ));
            let mut datasets: Vec<_> = self
                .datasets
                .iter()
                .filter(|d| d.pool == pool.guid)
                .collect();
            datasets.sort_by(|a, b| a.name.cmp(&b.name));
            for d in datasets {
                let shadow = Fake {
                    pools: self
                        .pools
                        .iter()
                        .map(|p| FPool {
                            imported: p.guid == pool.guid,
                            ..p.clone()
                        })
                        .collect(),
                    ..self.clone()
                };
                out.push_str(&format!(
                    "  {} enc={:?} key={:?} unopenable={} origin={:?}\n",
                    d.name,
                    d.encryption_root,
                    d.key.as_ref().map(|k| (&k.material, &k.salt)),
                    d.unopenable,
                    d.origin
                ));
                for key in [
                    "mountpoint",
                    "canmount",
                    "readonly",
                    "volmode",
                    "compression",
                    "atime",
                    "copies",
                    "keylocation",
                    "keyformat",
                    "zboot:cmdline",
                    "zboot:placement",
                    "zboot:staging",
                    "zboot:operation",
                ] {
                    if let Some((value, source)) = shadow.effective(&d.name, key) {
                        let value = if key == "zboot:placement" {
                            let placement =
                                zfs_tools::engine::management::Placement::parse(&value).unwrap();
                            format!(
                                "own={} readonly={} canmount={:?}",
                                placement.identity.guid == Guid::new(d.guid),
                                placement.readonly,
                                placement.canmount
                            )
                        } else if key == "zboot:operation" {
                            "record".into()
                        } else {
                            value
                        };
                        let source = if source.starts_with("inherited") {
                            "inherited"
                        } else {
                            &source
                        };
                        out.push_str(&format!("    {key}={value} ({source})\n"));
                    }
                }
                // Chunked records and archives by name: none may outlive
                // its operation, and an archive must be the one expected.
                let chunked: Vec<_> = d
                    .local
                    .keys()
                    .filter(|key| {
                        [
                            "zboot:attachment:",
                            "zboot:journal:",
                            super::receipt::ARCHIVE_PREFIX,
                        ]
                        .iter()
                        .any(|prefix| key.starts_with(prefix))
                    })
                    .collect();
                if !chunked.is_empty() {
                    out.push_str(&format!("    chunked {chunked:?}\n"));
                }
                for s in snapshots.iter().filter(|s| s.dataset_guid == d.guid) {
                    out.push_str(&format!(
                        "    @{} guid#{} holds={:?} deferred={}\n",
                        s.name.split_once('@').unwrap().1,
                        labels[&s.guid],
                        s.holds,
                        s.defer_destroy,
                    ));
                }
            }
        }
        out
    }

    fn dataset_view(&self, d: &FDataset) -> DatasetView {
        let mut properties = BTreeMap::new();
        for key in self.keys(&d.name) {
            if let Some((value, source)) = self.effective(&d.name, &key) {
                properties.insert(key, Property { value, source });
            }
        }
        properties.insert(
            "written".into(),
            Property {
                value: d.written.to_string(),
                source: "-".into(),
            },
        );
        DatasetView {
            name: d.name.clone(),
            identity: identity(d),
            volume: d.volume,
            used: self.used(&d.name),
            available: self.free(d.pool),
            mounted: d.mounted,
            origin: d.origin.clone(),
            encrypted: d.encryption_root.is_some(),
            encryption_root: d.encryption_root.clone(),
            resume_token: d.resume_token,
            properties,
        }
    }
}

fn identity(d: &FDataset) -> DatasetIdentity {
    DatasetIdentity {
        pool_guid: Guid::new(d.pool),
        guid: Guid::new(d.guid),
        createtxg: Txg::new(d.txg),
        objsetid: ObjsetId::new(d.guid),
    }
}

impl Fake {
    fn has_clones(&self, point: &FSnapshot) -> bool {
        self.datasets
            .iter()
            .any(|member| member.pool == point.pool && member.origin.as_ref() == Some(&point.name))
    }

    fn point(&self, s: &FSnapshot) -> SnapshotRef {
        SnapshotRef {
            name: s.name.clone(),
            dataset_guid: Guid::new(s.dataset_guid),
            identity: SnapshotIdentity {
                pool_guid: Guid::new(s.pool),
                guid: Guid::new(s.guid),
                createtxg: Txg::new(s.txg),
                objsetid: ObjsetId::new(s.txg),
            },
        }
    }
    fn disk_index(&self, path: &str) -> Result<usize> {
        self.disks
            .iter()
            .position(|d| d.identity.path == path)
            .ok_or_else(|| refuse(format!("no disk {path}")))
    }
    fn review(&self, index: usize) -> DiskReview {
        let disk = &self.disks[index];
        DiskReview {
            schema_version: 2,
            identity: disk.identity.clone(),
            partitions: disk.partitions.clone(),
            filesystem: None,
            partition_table_uuid: disk.table.clone(),
            method: crate::device::Method::Clear {
                reason: crate::device::ClearReason::NotNvme,
                extents: Vec::new(),
            },
            loss_token: format!("loss:{}", disk.partitions.len()),
        }
    }
}

impl Backend for Fake {
    fn view(&mut self) -> Result<View> {
        self.check()?;
        let pools = self
            .pools
            .iter()
            .filter(|p| p.imported)
            .map(|p| PoolView {
                name: p.name.clone(),
                guid: Guid::new(p.guid),
                readonly: p.readonly,
                altroot: p.altroot.clone(),
                bootfs: p.bootfs.clone(),
            })
            .collect();
        let datasets = self
            .datasets
            .iter()
            .filter(|d| self.imported(d.pool))
            .map(|d| self.dataset_view(d))
            .collect();
        let snapshots = self
            .snapshots
            .iter()
            .filter(|s| self.imported(s.pool))
            .map(|s| SnapshotView {
                point: self.point(s),
                holds: s.holds.clone(),
                defer_destroy: s.defer_destroy,
            })
            .collect();
        let candidates = self
            .datasets
            .iter()
            .filter(|d| self.imported(d.pool))
            .filter(|d| {
                !d.volume
                    && self
                        .effective(&d.name, "mountpoint")
                        .is_some_and(|(value, _)| {
                            let altroot = self
                                .pools
                                .iter()
                                .find(|pool| pool.guid == d.pool)
                                .and_then(|pool| pool.altroot.as_deref());
                            super::strip_altroot(&value, altroot) == "/"
                        })
            })
            .map(|d| Candidate {
                dataset: d.name.clone(),
                refusal: None,
                writable_head: !self.secondaries.contains(&d.name),
            })
            .collect();
        Ok(View {
            pools,
            datasets,
            snapshots,
            candidates,
            running_root: self.running_root.clone(),
        })
    }
    fn disk_identity(&mut self, path: &str) -> Result<DiskIdentity> {
        self.check()?;
        Ok(self.disks[self.disk_index(path)?].identity.clone())
    }
    fn disk(&mut self, path: &str, owned: Option<&str>) -> Result<DiskReview> {
        self.check()?;
        let index = self.disk_index(path)?;
        let number = self.disks[index].identity.device_number.clone();
        if let Some(pool) = self
            .pools
            .iter()
            .find(|p| p.imported && p.disk == number && Some(p.name.as_str()) != owned)
        {
            return Err(refuse(format!("{path} is in use by pool {}", pool.name)));
        }
        Ok(self.review(index))
    }
    fn label_extents(&mut self, review: &DiskReview) -> Result<Vec<crate::device::Extent>> {
        self.check()?;
        let mut start = 1 << 20;
        let mut regions = Vec::new();
        for partition in &review.partitions {
            if partition.filesystem.as_deref() == Some("zfs_member") {
                regions.push(crate::device::Extent {
                    path: partition.path.clone(),
                    start,
                    bytes: partition.bytes,
                });
            }
            start += partition.bytes;
        }
        if regions.is_empty() {
            return Err(refuse("original ZFS member ranges are missing"));
        }
        Ok(regions)
    }
    fn labels_present(
        &mut self,
        disk: &DiskIdentity,
        regions: &[crate::device::Extent],
    ) -> Result<bool> {
        self.check()?;
        if self.label_probe_error {
            return Err(refuse("original ZFS labels are unreadable or unrecognized"));
        }
        if self.disks[self.disk_index(&disk.path)?].identity != *disk || regions.is_empty() {
            return Err(refuse("original ZFS label disk identity or ranges changed"));
        }
        // Exported pools still have labels. Merely disappearing from view()
        // must never authorize removing their surviving pair record.
        Ok(self
            .pools
            .iter()
            .any(|pool| pool.disk == disk.device_number))
    }
    fn pool_disks(&mut self, pool: &str, guid: Guid) -> Result<Vec<DiskIdentity>> {
        self.check()?;
        let p = self
            .pools
            .iter()
            .find(|p| p.imported && p.name == pool && Guid::new(p.guid) == guid)
            .ok_or_else(|| refuse(format!("pool {pool} is not imported")))?;
        Ok(self
            .disks
            .iter()
            .filter(|d| {
                d.identity.device_number == p.disk
                    || p.extra_disks.contains(&d.identity.device_number)
            })
            .map(|d| d.identity.clone())
            .collect())
    }
    fn scrub_status(&mut self, pool: &str) -> Result<Scrub> {
        self.check()?;
        let now = self.now;
        let errors = self.scrub_errors;
        let scrub = self.scrubs.entry(pool.into()).or_insert_with(|| FScrub {
            state: "NONE".into(),
            ..FScrub::default()
        });
        if scrub.state == "SCANNING" && !scrub.paused {
            scrub.polls = scrub.polls.saturating_sub(1);
            if scrub.polls == 0 {
                scrub.state = "FINISHED".into();
            }
        }
        Ok(Scrub {
            state: scrub.state.clone(),
            paused: scrub.paused,
            start_time: scrub.start,
            end_time: if scrub.state == "FINISHED" { now } else { 0 },
            examined: if scrub.state == "FINISHED" { 100 } else { 50 },
            to_examine: 100,
            errors: if scrub.state == "FINISHED" { errors } else { 0 },
            pool_errors: 0,
        })
    }
    fn snapshot_hostid(&mut self, point: &SnapshotRef) -> Result<String> {
        self.check()?;
        if self.hostid.is_empty() {
            return Err(refuse(format!("{} has no /etc/hostid", point.name)));
        }
        Ok(self.hostid.clone())
    }
    fn running_hostid(&mut self) -> Result<String> {
        self.check()?;
        if self.hostid.is_empty() {
            return Err(refuse("the running BE has no /etc/hostid"));
        }
        Ok(self.hostid.clone())
    }
    fn effective_hostid(&mut self) -> Result<String> {
        self.check()?;
        Ok(self.spl_hostid.clone())
    }
    fn loader(&mut self, snapshot: Option<&SnapshotRef>) -> Result<FileIdentity> {
        self.check()?;
        self.loader.clone().ok_or_else(|| {
            refuse(format!(
                "{} ships no zboot loader at /usr/lib/zboot/zboot.efi",
                snapshot.map_or("the running BE", |point| point.name.as_str())
            ))
        })
    }
    fn require_no_image(&mut self) -> Result<()> {
        self.check()?;
        match &self.hibernation {
            Some(device) => Err(refuse(format!("a hibernation image is on {device}"))),
            None => Ok(()),
        }
    }
    fn now(&mut self) -> u64 {
        self.now
    }
    fn pause(&mut self) {
        self.now += 1;
    }

    fn record_pools(&mut self) -> Result<Vec<String>> {
        self.check()?;
        Ok(self
            .pools
            .iter()
            .filter(|p| p.imported)
            .map(|p| p.name.clone())
            .collect())
    }
    fn record_read(&mut self, pool: &str) -> Result<Option<String>> {
        self.check()?;
        Ok(self
            .find(pool)
            .and_then(|d| d.local.get(zfs_tools::engine::intent::PROPERTY).cloned()))
    }
    fn record_write(&mut self, pool: &str, value: &str) -> Result<()> {
        let value = value.to_owned();
        self.effect(format!("record {pool}"), |f| {
            f.writable(pool)?;
            f.dataset_mut(pool)
                .local
                .insert(zfs_tools::engine::intent::PROPERTY.into(), value);
            Ok(())
        })
    }
    fn record_remove(&mut self, pool: &str) -> Result<()> {
        self.effect(format!("clear record {pool}"), |f| {
            f.writable(pool)?;
            f.dataset_mut(pool)
                .local
                .remove(zfs_tools::engine::intent::PROPERTY);
            Ok(())
        })
    }

    fn hold_resolve(&mut self, point: &SnapshotRef) -> Result<Option<hold::Seen>> {
        self.check()?;
        if !self.imported(point.identity.pool_guid.get()) {
            return Err(refuse("snapshot pool is not imported; absence unproven"));
        }
        Ok(self
            .snapshots
            .iter()
            .find(|s| {
                Guid::new(s.guid) == point.identity.guid
                    && Guid::new(s.pool) == point.identity.pool_guid
            })
            .map(|s| hold::Seen {
                name: s.name.clone(),
                holds: s.holds.clone(),
            }))
    }
    fn hold(&mut self, name: &str, tag: &str) -> Result<()> {
        let (name, tag) = (name.to_owned(), tag.to_owned());
        self.effect(format!("hold {tag} {name}"), move |f| {
            let index = f
                .snapshots
                .iter()
                .position(|s| s.name == name && f.imported(s.pool))
                .ok_or_else(|| refuse("no such snapshot"))?;
            let s = &mut f.snapshots[index];
            if s.holds.contains(&tag) {
                return Err(refuse("tag already exists on this dataset"));
            }
            s.holds.push(tag);
            Ok(())
        })
    }
    fn release(&mut self, name: &str, tag: &str) -> Result<()> {
        let (name, tag) = (name.to_owned(), tag.to_owned());
        self.effect(format!("release {tag} {name}"), move |f| {
            let index = f
                .snapshots
                .iter()
                .position(|s| s.name == name && f.imported(s.pool))
                .ok_or_else(|| refuse("no such snapshot"))?;
            let s = &mut f.snapshots[index];
            let before = s.holds.len();
            s.holds.retain(|t| *t != tag);
            if s.holds.len() == before {
                return Err(refuse("no such tag on this dataset"));
            }
            if s.holds.is_empty() && s.defer_destroy && !f.has_clones(&f.snapshots[index]) {
                f.snapshots.remove(index);
            }
            Ok(())
        })
    }

    fn check_key(&mut self, dataset: &str, keylocation: &str) -> Result<()> {
        self.check()?;
        let path = keylocation.strip_prefix("file://").unwrap_or(keylocation);
        let key = self
            .find(dataset)
            .filter(|d| d.encryption_root.as_deref() == Some(dataset))
            .and_then(|d| d.key.as_ref())
            .ok_or_else(|| {
                refuse(format!(
                    "Keys must be loaded for encryption root of '{dataset}'"
                ))
            })?;
        match self.keys.get(path) {
            Some(material) if *material == key.material => Ok(()),
            Some(_) => Err(refuse("Key load error: Incorrect key provided")),
            None => Err(refuse(format!(
                "Key load error: Failed to open key material file: {path}"
            ))),
        }
    }
    fn wrapping(&mut self, endpoint: &Endpoint) -> Result<crate::transfer::Wrapping> {
        self.check()?;
        let dataset = self
            .find(&endpoint.name)
            .filter(|d| identity(d) == endpoint.identity)
            .ok_or_else(|| refuse(format!("{} changed", endpoint.name)))?;
        let key = dataset
            .key
            .as_ref()
            .filter(|_| dataset.encryption_root.as_deref() == Some(endpoint.name.as_str()))
            .ok_or_else(|| refuse(format!("{} is not an encryption root", endpoint.name)))?;
        Ok(crate::transfer::Wrapping {
            keyformat: dataset.local.get("keyformat").cloned().unwrap_or_default(),
            keylocation: dataset
                .local
                .get("keylocation")
                .cloned()
                .unwrap_or_default(),
            pbkdf2iters: key.iters.clone(),
            pbkdf2salt: key.salt.clone(),
        })
    }
    fn change_key(&mut self, endpoint: &Endpoint, inherit: bool) -> Result<()> {
        let endpoint = endpoint.clone();
        let what = if inherit { "inherit" } else { "new" };
        self.effect(format!("change-key {what} {}", endpoint.name), move |f| {
            f.writable(&endpoint.name)?;
            if f.change_key_broken {
                return Err(refuse("/sbin/zboot-change-key: libzfs_core_init failed"));
            }
            let dataset = f
                .find(&endpoint.name)
                .filter(|d| identity(d) == endpoint.identity)
                .ok_or_else(|| refuse("dataset changed"))?
                .clone();
            let own = f.key_of(&endpoint.name).cloned();
            if inherit {
                let root = f
                    .find(parent(&endpoint.name).unwrap())
                    .and_then(|p| p.encryption_root.clone())
                    .ok_or_else(|| refuse("parent is not encrypted"))?;
                let theirs = f.key_of(&root).cloned();
                let target = f.dataset_mut(&endpoint.name);
                // Repointed without rewrapping: it opens only if both match.
                target.unopenable |= own != theirs;
                target.encryption_root = Some(root);
                target.key = None;
                target.local.remove("keylocation");
                target.local.remove("keyformat");
            } else {
                let format = dataset
                    .encryption_root
                    .as_deref()
                    .and_then(|root| f.find(root))
                    .and_then(|root| root.local.get("keyformat").cloned())
                    .ok_or_else(|| refuse("dataset is not encrypted"))?;
                let target = f.dataset_mut(&endpoint.name);
                target.encryption_root = Some(endpoint.name.clone());
                target.key = own;
                target.local.insert("keylocation".into(), "prompt".into());
                target.local.insert("keyformat".into(), format);
            }
            Ok(())
        })
    }

    fn change_key_ready(&mut self) -> Result<()> {
        self.check()?;
        if self.change_key_broken {
            return Err(refuse(
                "/sbin/zboot-change-key --check failed: libzfs_core_init: No such file or directory",
            ));
        }
        Ok(())
    }

    fn snapshot(&mut self, name: &str, recursive: bool) -> Result<()> {
        let name = name.to_owned();
        self.effect(format!("snapshot {name}"), move |f| {
            let (dataset, suffix) = name.split_once('@').unwrap();
            f.writable(dataset)?;
            if f.find(dataset).is_none() {
                return Err(refuse("dataset does not exist"));
            }
            let members: Vec<_> = if recursive {
                f.tree(dataset).iter().map(|d| d.name.clone()).collect()
            } else {
                vec![dataset.to_owned()]
            };
            if members
                .iter()
                .any(|m| f.snapshot_ref(&format!("{m}@{suffix}")).is_some())
            {
                return Err(refuse("snapshot already exists"));
            }
            f.snap(&name, recursive);
            Ok(())
        })
    }
    fn create(&mut self, dataset: &str, properties: &[(String, String)]) -> Result<()> {
        let dataset = dataset.to_owned();
        let properties = properties.to_vec();
        self.effect(format!("create {dataset}"), move |f| {
            f.writable(&dataset)?;
            if f.find(&dataset).is_some() {
                return Err(refuse("dataset already exists"));
            }
            if parent(&dataset).is_none_or(|p| f.find(p).is_none()) {
                return Err(refuse("parent does not exist"));
            }
            let local: Vec<(&str, &str)> = properties
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            f.add(&dataset, &local);
            f.dataset_mut(&dataset).used = 0;
            Ok(())
        })
    }
    fn set(&mut self, dataset: &str, key: &str, value: &str) -> Result<()> {
        let (dataset, key, value) = (dataset.to_owned(), key.to_owned(), value.to_owned());
        self.effect(format!("set {key}={value} {dataset}"), move |f| {
            f.writable(&dataset)?;
            if f.denied_set
                .as_ref()
                .is_some_and(|(name, property)| name == &dataset && property == &key)
            {
                return Err(refuse("native property setter refused"));
            }
            let d = f
                .find_index(&dataset)
                .ok_or_else(|| refuse("dataset does not exist"))?;
            f.datasets[d].local.insert(key, value);
            Ok(())
        })
    }
    fn inherit(&mut self, dataset: &str, key: &str) -> Result<()> {
        let (dataset, key) = (dataset.to_owned(), key.to_owned());
        self.effect(format!("inherit {key} {dataset}"), move |f| {
            f.writable(&dataset)?;
            if f.ignored_inherit == Some(f.effects.len() - 1) {
                return Ok(());
            }
            let d = f
                .find_index(&dataset)
                .ok_or_else(|| refuse("dataset does not exist"))?;
            let d = &mut f.datasets[d];
            d.local.remove(&key);
            if d.received.contains_key(&key) {
                d.masked.insert(key);
            }
            Ok(())
        })
    }
    fn receive_quiesce(&mut self, endpoint: &Endpoint, operation_id: &str) -> Result<()> {
        let endpoint = endpoint.clone();
        let operation_id = operation_id.to_owned();
        self.effect(
            format!("receive quiesce {} {operation_id}", endpoint.name),
            move |f| {
                let view = f.view()?;
                if !view
                    .dataset(&endpoint.name)
                    .is_some_and(|d| d.identity == endpoint.identity)
                {
                    return Err(refuse("quiesce target incarnation changed"));
                }
                if f.quiesce_fails {
                    return Err(refuse("zvol publication drain failed"));
                }
                for member in view.tree(&endpoint.name) {
                    let inert = crate::placement::Posture::Inert { parent: false };
                    if !inert.holds(member.volume, member.mounted, |key| {
                        member.value(key).map(|value| (value, false))
                    }) {
                        return Err(refuse("quiesce target is not inert"));
                    }
                }
                f.exposed_volumes
                    .retain(|name| !within(&endpoint.name, name));
                Ok(())
            },
        )
    }
    fn destroy_tree(&mut self, dataset: &str) -> Result<()> {
        let dataset = dataset.to_owned();
        self.effect(format!("destroy -r {dataset}"), move |f| {
            f.writable(&dataset)?;
            let members: BTreeSet<_> = f.tree(&dataset).iter().map(|d| d.guid).collect();
            if f.snapshots
                .iter()
                .any(|s| members.contains(&s.dataset_guid) && !s.holds.is_empty())
            {
                return Err(refuse("dataset is busy (held snapshot)"));
            }
            f.snapshots.retain(|s| !members.contains(&s.dataset_guid));
            f.datasets.retain(|d| !members.contains(&d.guid));
            Ok(())
        })
    }
    fn destroy_snapshot(&mut self, point: &SnapshotRef) -> Result<()> {
        let point = point.clone();
        self.effect(format!("destroy {}", point.name), move |f| {
            f.writable(&point.name)?;
            let index = f
                .snapshots
                .iter()
                .position(|s| f.imported(s.pool) && f.point(s) == point)
                .ok_or_else(|| refuse("snapshot changed or does not exist"))?;
            if !f.snapshots[index].holds.is_empty() || f.has_clones(&f.snapshots[index]) {
                return Err(refuse("snapshot is busy"));
            }
            f.snapshots.remove(index);
            Ok(())
        })
    }
    fn stream(&mut self, stream: &LeafStream) -> Result<StreamOutcome> {
        zfs_tools::engine::stream::leaf_arguments(stream)?;
        let stream = stream.clone();
        let what = match &stream.base {
            Some(base) => format!(
                "send -I {} {} | receive {}",
                base.name, stream.boundary.name, stream.destination
            ),
            None => format!(
                "send {} | receive {}",
                stream.boundary.name, stream.destination
            ),
        };
        if let Some((prefix, change)) = self.before_stream.clone()
            && stream.destination.starts_with(&prefix)
        {
            self.before_stream = None;
            change(self);
        }
        self.effect(what, move |f| {
            let result = f.receive(&stream);
            let sender_success = !f
                .sender_failure
                .as_ref()
                .is_some_and(|prefix| stream.destination.starts_with(prefix));
            Ok(StreamOutcome {
                sender_success,
                receiver_success: result.is_ok(),
                sender_status: if sender_success {
                    "exit status: 0"
                } else {
                    "exit status: 1"
                }
                .into(),
                receiver_status: if result.is_ok() {
                    "exit status: 0"
                } else {
                    "exit status: 1"
                }
                .into(),
                sender_stderr: if sender_success {
                    String::new()
                } else {
                    "native sender failed after receive".into()
                },
                receiver_stderr: result.err().unwrap_or_default(),
                output_truncated: false,
            })
        })
    }
    fn scrub(&mut self, pool: &str) -> Result<()> {
        let pool = pool.to_owned();
        self.effect(format!("scrub {pool}"), move |f| {
            let now = f.now;
            let scrub = f.scrubs.entry(pool).or_default();
            if scrub.state == "SCANNING" && !scrub.paused {
                return Err(refuse("currently scrubbing"));
            }
            if scrub.state == "SCANNING" && scrub.paused {
                scrub.paused = false;
                return Ok(());
            }
            *scrub = FScrub {
                state: "SCANNING".into(),
                start: now,
                polls: 2,
                paused: false,
            };
            Ok(())
        })
    }
    fn export(&mut self, pool: &str) -> Result<()> {
        let pool = pool.to_owned();
        self.effect(format!("export {pool}"), move |f| {
            if f.export_error {
                return Err(refuse("injected export failure"));
            }
            let index = f
                .pools
                .iter()
                .position(|p| p.name == pool && p.imported)
                .ok_or_else(|| refuse("no such pool"))?;
            let guid = f.pools[index].guid;
            if f.datasets.iter().any(|d| d.pool == guid && d.mounted) {
                return Err(refuse("pool is busy"));
            }
            f.pools[index].imported = false;
            Ok(())
        })
    }
    fn import(&mut self, guid: Guid, hostid: &str) -> Result<()> {
        let hostid = hostid.to_owned();
        self.effect(format!("import {guid}"), move |f| {
            let index = f
                .pools
                .iter()
                .position(|p| Guid::new(p.guid) == guid && !p.imported)
                .ok_or_else(|| refuse("no such pool available for import"))?;
            let name = f.pools[index].name.clone();
            if f.pools.iter().any(|p| p.imported && p.name == name) {
                return Err(refuse("a pool with that name is already imported"));
            }
            f.pools[index].imported = true;
            f.pools[index].readonly = false;
            f.pools[index].hostid = hostid;
            Ok(())
        })
    }
    fn wipe(&mut self, review: &DiskReview) -> Result<()> {
        let review = review.clone();
        self.effect(format!("wipe {}", review.identity.path), move |f| {
            let index = f.disk_index(&review.identity.path)?;
            if f.disks[index].identity != review.identity {
                return Err(refuse("disk identity changed"));
            }
            let number = review.identity.device_number.clone();
            if f.pools.iter().any(|p| p.imported && p.disk == number) {
                return Err(refuse("disk is in use"));
            }
            let gone: BTreeSet<_> = f
                .pools
                .iter()
                .filter(|p| p.disk == number)
                .map(|p| p.guid)
                .collect();
            f.pools.retain(|p| !gone.contains(&p.guid));
            f.datasets.retain(|d| !gone.contains(&d.pool));
            f.snapshots.retain(|s| !gone.contains(&s.pool));
            f.disks[index].partitions.clear();
            f.disks[index].table = None;
            Ok(())
        })
    }
    fn deploy(&mut self, spec: &DeploySpec) -> Result<Guid> {
        let spec = spec.clone();
        self.effect(
            format!("deploy {} on {}", spec.pool, spec.disk.path),
            move |f| {
                let index = f.disk_index(&spec.disk.path)?;
                if f.disks[index].identity != spec.disk || !f.disks[index].partitions.is_empty() {
                    return Err(refuse("deploy needs the erased disk"));
                }
                if f.loader.as_ref() != Some(&spec.loader) {
                    return Err(refuse(format!(
                        "{} ships another zboot loader than planned",
                        spec.snapshot.name
                    )));
                }
                let disk = f.disks[index].clone();
                let mut partitions = vec![partition(&disk, 1, spec.esp_bytes, "vfat")];
                if spec.swap_bytes > 0 {
                    partitions.push(partition(&disk, 2, spec.swap_bytes, "swap"));
                }
                let size = disk.identity.bytes - spec.esp_bytes - spec.swap_bytes;
                partitions.push(partition(&disk, 3, size, "zfs_member"));
                f.disks[index].partitions = partitions;
                f.disks[index].table = Some(format!("table-new-{}", f.next));
                f.add_pool(&spec.pool, &disk.identity.device_number, size / 16 * 15);
                // deploy creates the pool under its reviewed hostid.
                f.pools.last_mut().unwrap().hostid = spec.hostid.clone();
                let root = [
                    ("canmount", "off"),
                    ("mountpoint", "none"),
                    ("readonly", "on"),
                ];
                for (k, v) in root {
                    f.dataset_mut(&spec.pool).local.insert(k.into(), v.into());
                }
                f.add(&format!("{}/ROOT", spec.pool), &root);
                let guid = f.pool_named(&spec.pool).guid;
                f.pools
                    .iter_mut()
                    .find(|p| p.guid == guid)
                    .unwrap()
                    .imported = false;
                Ok(Guid::new(guid))
            },
        )
    }
    fn boot(&mut self, be: &str) -> Result<()> {
        let be = be.to_owned();
        self.effect(format!("boot {be}"), move |f| {
            let view = f.view()?;
            let dataset = view
                .dataset(&be)
                .ok_or_else(|| refuse(format!("{be} is missing")))?;
            let altroot = view
                .pool(be.split('/').next().unwrap())
                .and_then(|pool| pool.altroot.as_deref());
            if dataset.volume
                || dataset
                    .value("mountpoint")
                    .is_none_or(|mountpoint| super::strip_altroot(mountpoint, altroot) != "/")
            {
                return Err(refuse(format!("{be} is not an eligible BE")));
            }
            let pool = be.split('/').next().unwrap().to_owned();
            f.writable(&pool)?;
            // As `boot_support`: another imported pool's default that cannot
            // be cleared leaves the change incomplete, reported as an error.
            if let Some(other) = f
                .pools
                .iter()
                .find(|p| p.imported && p.name != pool && p.bootfs.is_some() && p.readonly)
            {
                return Err(refuse(format!(
                    "{be} is not yet the host's one boot default: {} still names {} as its default",
                    other.name,
                    other.bootfs.as_deref().unwrap_or_default()
                )));
            }
            for p in f.pools.iter_mut() {
                p.bootfs = (p.name == pool && p.imported).then(|| be.clone());
            }
            Ok(())
        })
    }
}
