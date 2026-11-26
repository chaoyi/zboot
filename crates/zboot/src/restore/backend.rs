//! Everything restore observes or changes, behind one trait, so every effect
//! and every record write can be cut in tests.
use crate::{
    device::{DiskIdentity, DiskReview},
    esp::FileIdentity,
    menu::Result,
};
use serde::Serialize;
use std::collections::BTreeMap;
use zfs_tools::engine::{DatasetIdentity, Guid, SnapshotRef, intent, management::Endpoint, stream};

/// A native property value and its `zfs get` source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Property {
    pub value: String,
    pub source: String,
}
impl Property {
    pub fn local(&self) -> bool {
        self.source == "local"
    }
    pub fn received(&self) -> bool {
        self.source == "received"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PoolView {
    pub name: String,
    pub guid: Guid,
    pub readonly: bool,
    pub altroot: Option<String>,
    pub bootfs: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatasetView {
    pub name: String,
    pub identity: DatasetIdentity,
    pub volume: bool,
    pub used: u64,
    pub available: u64,
    pub mounted: bool,
    pub origin: Option<String>,
    pub encrypted: bool,
    pub encryption_root: Option<String>,
    /// A partial resumable receive is present.
    pub resume_token: bool,
    /// Every native property with its source.
    pub properties: BTreeMap<String, Property>,
}
impl DatasetView {
    pub fn property(&self, key: &str) -> Option<&Property> {
        self.properties.get(key)
    }
    pub fn value(&self, key: &str) -> Option<&str> {
        self.property(key).map(|p| p.value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotView {
    pub point: SnapshotRef,
    pub holds: Vec<String>,
    pub defer_destroy: bool,
}

/// A boot environment as the Menu would list it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub dataset: String,
    pub refusal: Option<String>,
    /// Unpaired or primary: its head may be snapshotted in place.
    pub writable_head: bool,
}

/// One complete native observation of imported pools.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct View {
    pub pools: Vec<PoolView>,
    pub datasets: Vec<DatasetView>,
    pub snapshots: Vec<SnapshotView>,
    pub candidates: Vec<Candidate>,
    /// The dataset mounted at `/` in this namespace, if a ZFS one.
    pub running_root: Option<String>,
}
impl View {
    pub fn dataset(&self, name: &str) -> Option<&DatasetView> {
        self.datasets.iter().find(|d| d.name == name)
    }
    pub fn pool(&self, name: &str) -> Option<&PoolView> {
        self.pools.iter().find(|p| p.name == name)
    }
    /// `root` and its descendants, in name order.
    pub fn tree(&self, root: &str) -> Vec<&DatasetView> {
        let mut tree: Vec<_> = self
            .datasets
            .iter()
            .filter(|d| within(root, &d.name))
            .collect();
        tree.sort_by(|a, b| a.name.cmp(&b.name));
        tree
    }
    pub fn snapshot(&self, name: &str) -> Option<&SnapshotView> {
        self.snapshots.iter().find(|s| s.point.name == name)
    }
    /// Snapshots of exactly `dataset`, oldest first.
    pub fn snapshots_of(&self, dataset: &str) -> Vec<&SnapshotView> {
        let mut found: Vec<_> = self
            .snapshots
            .iter()
            .filter(|s| s.point.name.split_once('@').map(|(d, _)| d) == Some(dataset))
            .collect();
        found.sort_by_key(|s| s.point.identity.createtxg);
        found
    }
}

pub fn within(root: &str, name: &str) -> bool {
    zfs_tools::engine::contains_dataset(root, name)
}

/// A whole-disk pool's progress through its most recent scrub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Scrub {
    /// `SCANNING`, `FINISHED`, `CANCELED` or `NONE`.
    pub state: String,
    pub paused: bool,
    pub start_time: u64,
    pub end_time: u64,
    pub examined: u64,
    pub to_examine: u64,
    pub errors: u64,
    /// The pool's persistent error count.
    pub pool_errors: u64,
}

/// What `deploy` builds on A, for the backend to plan and apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeploySpec {
    pub disk: DiskIdentity,
    pub pool: String,
    pub hostid: String,
    pub esp_bytes: u64,
    pub swap_bytes: u64,
    /// The source snapshot whose shipped loader A's ESP gets.
    pub snapshot: SnapshotRef,
    /// That loader as planned.
    pub loader: FileIdentity,
    pub journal_directory: std::path::PathBuf,
}

/// Every native observation and effect. Effects return only after the native
/// command does; callers judge an uncertain outcome by observing again.
pub trait Backend {
    fn view(&mut self) -> Result<View>;
    fn disk_identity(&mut self, path: &str) -> Result<DiskIdentity>;
    /// Review of a whole disk; `owned` may be imported from it alone.
    fn disk(&mut self, path: &str, owned: Option<&str>) -> Result<DiskReview>;
    /// Original ZFS member byte ranges, saved before partition nodes vanish.
    fn label_extents(&mut self, review: &DiskReview) -> Result<Vec<crate::device::Extent>>;
    /// Whether any original ZFS label remains on this exact disk. Unknown or
    /// unreadable labels refuse; absence of an imported pool is not evidence.
    fn labels_present(
        &mut self,
        disk: &DiskIdentity,
        regions: &[crate::device::Extent],
    ) -> Result<bool>;
    /// Physical disks backing an imported pool.
    fn pool_disks(&mut self, pool: &str, guid: Guid) -> Result<Vec<DiskIdentity>>;
    fn scrub_status(&mut self, pool: &str) -> Result<Scrub>;
    /// The `/etc/hostid` installed in a BE snapshot, as eight hex digits;
    /// a missing, zero or malformed one refuses.
    fn snapshot_hostid(&mut self, point: &SnapshotRef) -> Result<String>;
    /// The `/etc/hostid` of the BE head mounted at `/`, likewise.
    fn running_hostid(&mut self) -> Result<String>;
    /// The effective OpenZFS hostid of the running system, `00000000` for none.
    fn effective_hostid(&mut self) -> Result<String>;
    /// The zboot UKI the BE ships at `/usr/lib/zboot/zboot.efi`, in the
    /// snapshot or, for `None`, in the BE head mounted at `/`. A BE without
    /// one, or with a file there that is not a zboot UKI, refuses.
    fn loader(&mut self, snapshot: Option<&SnapshotRef>) -> Result<FileIdentity>;
    /// Refuse while a hibernation image is present (see recovery).
    fn require_no_image(&mut self) -> Result<()>;
    fn now(&mut self) -> u64;
    fn pause(&mut self);

    // The operation record (zfs_tools::engine::intent::Backend).
    fn record_pools(&mut self) -> Result<Vec<String>>;
    fn record_read(&mut self, pool: &str) -> Result<Option<String>>;
    fn record_write(&mut self, pool: &str, value: &str) -> Result<()>;
    fn record_remove(&mut self, pool: &str) -> Result<()>;

    // Holds (zfs_tools::engine::hold::Backend).
    fn hold_resolve(
        &mut self,
        point: &SnapshotRef,
    ) -> Result<Option<zfs_tools::engine::hold::Seen>>;
    fn hold(&mut self, name: &str, tag: &str) -> Result<()>;
    fn release(&mut self, name: &str, tag: &str) -> Result<()>;

    /// Prove that the key file at `keylocation` (`file://`) unlocks the
    /// encryption root `dataset`, without loading it (`zfs load-key -n -L`).
    /// Never asks for a key.
    fn check_key(&mut self, dataset: &str, keylocation: &str) -> Result<()>;
    /// How the encryption root `endpoint`'s key is wrapped, read natively
    /// (`pbkdf2salt` is hidden and read by name).
    fn wrapping(&mut self, endpoint: &Endpoint) -> Result<crate::transfer::Wrapping>;
    /// Point `endpoint` at its parent's encryption root (`inherit`,
    /// `lzc_change_key` FORCE_INHERIT) or make it its own root (FORCE_NEW_KEY),
    /// through the helper `zboot-change-key`, only while its key is not
    /// loaded. Neither checks nor rewraps a key: the caller proves the
    /// wrapping first.
    fn change_key(&mut self, endpoint: &Endpoint, inherit: bool) -> Result<()>;
    /// Whether `change_key` can work here (`zboot-change-key --check` loads
    /// and initializes the host's libzfs_core). Changes nothing.
    fn change_key_ready(&mut self) -> Result<()>;

    fn snapshot(&mut self, name: &str, recursive: bool) -> Result<()>;
    fn create(&mut self, dataset: &str, properties: &[(String, String)]) -> Result<()>;
    /// `zfs set -u`: never mounts anything, whatever the property.
    fn set(&mut self, dataset: &str, property: &str, value: &str) -> Result<()>;
    fn inherit(&mut self, dataset: &str, property: &str) -> Result<()>;
    /// Drain prior zvol publication work and prove no raw minors remain in
    /// this identity-bound inert scope before moving or publishing data.
    fn receive_quiesce(&mut self, endpoint: &Endpoint, operation_id: &str) -> Result<()>;
    /// `zfs destroy -r` of a copy this operation made, under the
    /// destruction rule (`execute::partial_copy`).
    fn destroy_tree(&mut self, dataset: &str) -> Result<()>;
    /// `zfs destroy` of exactly this snapshot.
    fn destroy_snapshot(&mut self, point: &SnapshotRef) -> Result<()>;
    /// One property-free raw stream into the host's own `zfs receive -u`.
    fn stream(&mut self, stream: &stream::LeafStream) -> Result<stream::StreamOutcome>;
    fn scrub(&mut self, pool: &str) -> Result<()>;
    fn export(&mut self, pool: &str) -> Result<()>;
    /// Import by GUID without mounting anything, under `hostid`, which the
    /// pool then records.
    fn import(&mut self, guid: Guid, hostid: &str) -> Result<()>;
    /// The `wipe` chain: review the disk again, erase it by the reviewed
    /// method (an NVMe sanitize or metadata clearing) and verify the result.
    fn wipe(&mut self, review: &DiskReview) -> Result<()>;
    /// Plan and apply an empty-root deploy on the erased disk; returns the new
    /// pool's GUID. The pool is exported when this returns.
    fn deploy(&mut self, spec: &DeploySpec) -> Result<Guid>;
    /// Make `be` the host's one boot default.
    fn boot(&mut self, be: &str) -> Result<()>;
}

/// The record backend over a restore backend.
pub struct Records<'a, B: Backend + ?Sized>(pub &'a mut B);
impl<B: Backend + ?Sized> intent::Backend for Records<'_, B> {
    fn pools(&mut self) -> std::result::Result<Vec<String>, zfs_tools::engine::Error> {
        self.0.record_pools().map_err(native)
    }
    fn read(
        &mut self,
        pool: &str,
    ) -> std::result::Result<Option<String>, zfs_tools::engine::Error> {
        self.0.record_read(pool).map_err(native)
    }
    fn write(
        &mut self,
        pool: &str,
        value: &str,
    ) -> std::result::Result<(), zfs_tools::engine::Error> {
        self.0.record_write(pool, value).map_err(native)
    }
    fn remove(&mut self, pool: &str) -> std::result::Result<(), zfs_tools::engine::Error> {
        self.0.record_remove(pool).map_err(native)
    }
}

/// The hold backend over a restore backend.
pub struct Holds<'a, B: Backend + ?Sized>(pub &'a mut B);
impl<B: Backend + ?Sized> zfs_tools::engine::hold::Backend for Holds<'_, B> {
    fn resolve(
        &mut self,
        point: &SnapshotRef,
    ) -> std::result::Result<Option<zfs_tools::engine::hold::Seen>, zfs_tools::engine::Error> {
        self.0.hold_resolve(point).map_err(native)
    }
    fn hold(&mut self, name: &str, tag: &str) -> std::result::Result<(), zfs_tools::engine::Error> {
        self.0.hold(name, tag).map_err(native)
    }
    fn release(
        &mut self,
        name: &str,
        tag: &str,
    ) -> std::result::Result<(), zfs_tools::engine::Error> {
        self.0.release(name, tag).map_err(native)
    }
}

fn native(error: crate::menu::RecoveryError) -> zfs_tools::engine::Error {
    match error {
        crate::menu::RecoveryError::Native(error) => error,
        other => zfs_tools::engine::Error::Inconsistent(other.to_string()),
    }
}
