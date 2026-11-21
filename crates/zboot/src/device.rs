//! Disks: exact native identity, usage guards and whole-disk erasure. How a
//! disk is erased (NVMe sanitize or metadata clearing) lives in [`wipe`].
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};
use zfs_tools::engine::{Error, native};

mod wipe;
pub use wipe::{ClearReason, Extent, Method, WipeOutcome};
pub(crate) use wipe::{label_extents, labels_present};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskIdentity {
    pub path: String,
    pub device_number: String,
    pub sysfs_path: String,
    pub bytes: u64,
    pub logical_sector: u64,
    pub physical_sector: u64,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub model: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Partition {
    pub path: String,
    pub device_number: String,
    pub bytes: u64,
    pub partition_uuid: Option<String>,
    pub filesystem: Option<String>,
    pub filesystem_uuid: Option<String>,
    /// The filesystem label; a ZFS member's is its pool name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_label: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionIdentity {
    pub disk: DiskIdentity,
    pub partition: Partition,
    pub number: u32,
    pub partition_type: Option<String>,
    pub readonly: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskReview {
    pub schema_version: u32,
    pub identity: DiskIdentity,
    pub partitions: Vec<Partition>,
    pub filesystem: Option<String>,
    pub partition_table_uuid: Option<String>,
    pub method: Method,
    pub loss_token: String,
}
/// A pool selected for export before a whole-disk operation. Names locate the
/// pool; native GUIDs retain its identity throughout the reviewed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopedPool {
    pub name: String,
    pub guid: zfs_tools::engine::Guid,
}

/// Immutable read-only admission for imported pools wholly on one reviewed
/// disk. Keep this same value in confirmation even after its pools are exported.
/// This scope authorizes no writes to the disk and never relaxes wipe admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskScope {
    identity: DiskIdentity,
    pools: Vec<ScopedPool>,
}

/// Fresh facts for one imported pool. Empty storage means the pool does not
/// touch the selected disk. Every pool remains visible for GUID/name checks.
#[derive(Debug, Clone)]
pub struct DiskPoolFacts {
    pub pool: ScopedPool,
    pub readonly: bool,
    pub unmounted: bool,
    pub disks: Vec<DiskIdentity>,
}

/// Read-only disk observations plus the existing recovery export boundary.
/// A fake can model exports through the same pool-access trait as native code.
pub trait DiskScopeBackend: crate::menu::pool_access::Backend {
    fn disk_identity(&mut self, path: &str) -> Result<DiskIdentity, Error>;
    fn disk_pools(&mut self, disk: &DiskIdentity) -> Result<Vec<DiskPoolFacts>, Error>;
    fn disk_review(&mut self, path: &str, allowed: &[String]) -> Result<DiskReview, Error>;
}

impl DiskScope {
    pub fn identity(&self) -> &DiskIdentity {
        &self.identity
    }
    pub fn pools(&self) -> &[ScopedPool] {
        &self.pools
    }
    pub(crate) fn describe(&self) -> String {
        use std::fmt::Write;
        let mut text = String::new();
        for pool in &self.pools {
            let _ = writeln!(
                text,
                "  export read-only pool {} guid={} before erasing",
                zfs_tools::engine::escape_display(&pool.name),
                pool.guid,
            );
        }
        text
    }
    pub fn plan(path: &str) -> Result<Self, Error> {
        Self::plan_with(path, &mut NativeDiskScope)
    }
    pub fn plan_with(path: &str, backend: &mut impl DiskScopeBackend) -> Result<Self, Error> {
        let identity = backend.disk_identity(path)?;
        let facts = backend.disk_pools(&identity)?;
        let mut pools: Vec<_> = facts
            .iter()
            .filter(|pool| !pool.disks.is_empty())
            .map(|pool| pool.pool.clone())
            .collect();
        pools.sort_by(|a, b| a.name.cmp(&b.name));
        if pools.windows(2).any(|pair| pair[0].name == pair[1].name)
            || pools
                .iter()
                .map(|pool| pool.guid)
                .collect::<BTreeSet<_>>()
                .len()
                != pools.len()
        {
            return Err(refuse("ambiguous imported disk pool inventory"));
        }
        let scope = Self { identity, pools };
        scope.validate_facts(&facts)?;
        scope.review_with(backend)?;
        Ok(scope)
    }
    fn validate_facts(&self, facts: &[DiskPoolFacts]) -> Result<Vec<String>, Error> {
        let mut present = Vec::new();
        for pool in facts {
            let expected = self.pools.iter().find(|expected| {
                expected.name == pool.pool.name || expected.guid == pool.pool.guid
            });
            match expected {
                Some(expected) if expected != &pool.pool => {
                    return Err(refuse("reviewed disk pool name or GUID changed"));
                }
                Some(_) => {
                    if !pool.readonly
                        || !pool.unmounted
                        || pool.disks.as_slice() != std::slice::from_ref(&self.identity)
                    {
                        return Err(refuse(format!(
                            "reviewed disk pool is not read-only, unmounted and wholly on the target: {}",
                            pool.pool.name
                        )));
                    }
                    present.push(pool.pool.name.clone());
                }
                None if !pool.disks.is_empty() => {
                    return Err(refuse(
                        "an unreviewed imported pool now uses the target disk",
                    ));
                }
                None => {}
            }
        }
        present.sort();
        if present.windows(2).any(|names| names[0] == names[1]) {
            return Err(refuse("ambiguous reviewed disk pool inventory"));
        }
        Ok(present)
    }
    pub fn review(&self) -> Result<DiskReview, Error> {
        self.review_with(&mut NativeDiskScope)
    }
    pub fn review_with(&self, backend: &mut impl DiskScopeBackend) -> Result<DiskReview, Error> {
        if backend.disk_identity(&self.identity.path)? != self.identity {
            return Err(refuse("reviewed export disk identity changed"));
        }
        let allowed = self.validate_facts(&backend.disk_pools(&self.identity)?)?;
        let review = backend.disk_review(&self.identity.path, &allowed)?;
        if review.identity != self.identity {
            return Err(refuse("reviewed export disk changed during inventory"));
        }
        // The inventory's normal guards cover mounts, swap, holders, every
        // partition and unreviewed imported dependencies. Recheck pool facts
        // after those sequential observations, before returning a review.
        self.validate_facts(&backend.disk_pools(&self.identity)?)?;
        Ok(review)
    }
    /// Revalidate the complete set before the first export. Recheck before
    /// each later export too; no snapshot of facts coordinates external actors.
    pub fn export(&self) -> Result<(), Error> {
        self.export_with(&mut NativeDiskScope)
    }
    pub fn export_with(&self, backend: &mut impl DiskScopeBackend) -> Result<(), Error> {
        backend.prove_ram().map_err(|e| refuse(e.to_string()))?;
        self.review_with(backend)?;
        for pool in &self.pools {
            self.review_with(backend)?;
            let present = self.validate_facts(&backend.disk_pools(&self.identity)?)?;
            if present.contains(&pool.name) {
                backend
                    .export(&pool.name)
                    .map_err(|e| refuse(e.to_string()))?;
            }
        }
        self.review_with(backend)?;
        if !self
            .validate_facts(&backend.disk_pools(&self.identity)?)?
            .is_empty()
        {
            return Err(refuse("reviewed disk pool remained imported after export"));
        }
        Ok(())
    }
}

struct NativeDiskScope;
impl crate::menu::pool_access::Backend for NativeDiskScope {
    fn prove_ram(&mut self) -> crate::menu::Result<()> {
        crate::handoff::prove_ram()
    }
    fn observe(&mut self) -> crate::menu::Result<zfs_tools::engine::state::NativeState> {
        Ok(zfs_tools::engine::state::observe()?)
    }
    fn export(&mut self, pool: &str) -> crate::menu::Result<()> {
        <Self as crate::menu::pool_access::Backend>::prove_ram(self)?;
        crate::menu::pool_access::native_command(&crate::menu::pool_access::export_args(pool))
    }
    fn import(&mut self, _: zfs_tools::engine::Guid, _: bool) -> crate::menu::Result<()> {
        Err(crate::menu::RecoveryError::Refused(
            "disk export scope never imports pools".into(),
        ))
    }
}
impl DiskScopeBackend for NativeDiskScope {
    fn disk_identity(&mut self, path: &str) -> Result<DiskIdentity, Error> {
        observe_identity(path)
    }
    fn disk_review(&mut self, path: &str, allowed: &[String]) -> Result<DiskReview, Error> {
        plan_allowed(path, allowed)
    }
    fn disk_pools(&mut self, disk: &DiskIdentity) -> Result<Vec<DiskPoolFacts>, Error> {
        let state = zfs_tools::engine::state::observe()?;
        let mut facts = Vec::new();
        for pool in &state.inspection.pools {
            let binding = crate::menu::pool_access::PoolBinding {
                name: pool.name.clone(),
                guid: pool.guid,
            };
            let readonly = crate::menu::pool_access::pool_readonly(&state, &binding)
                .map_err(|e| refuse(e.to_string()))?;
            let mut touches = false;
            let mut landscape = None;
            for leaf in pool_leaves(&pool.name, &pool.guid)? {
                let metadata = fs::metadata(&leaf).map_err(io_error)?;
                let number = backing_device_number(&metadata);
                if number == disk.device_number {
                    touches = true;
                } else if metadata.file_type().is_block_device() {
                    let rows = match &landscape {
                        Some(rows) => rows,
                        None => landscape.insert(observe_landscape()?),
                    };
                    touches |= whole_disk_for(rows, &number)?.device_number == disk.device_number;
                }
            }
            let disks = if touches {
                observe_pool_storage(&pool.name, &pool.guid)?.disks
            } else {
                Vec::new()
            };
            let unmounted = crate::menu::pool_access::no_active_mounts(&state, &binding).is_ok();
            facts.push(DiskPoolFacts {
                pool: ScopedPool {
                    name: pool.name.clone(),
                    guid: pool.guid,
                },
                readonly,
                unmounted,
                disks,
            });
        }
        Ok(facts)
    }
}

/// Observed backing media, including auxiliary vdev classes. This is a fresh
/// observation, never by itself authorization to erase any device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolStorage {
    pub pool: String,
    pub guid: zfs_tools::engine::Guid,
    pub disks: Vec<DiskIdentity>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Landscape {
    pub blockdevices: Vec<Block>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub path: String,
    #[serde(rename = "maj:min")]
    pub device_number: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub size: u64,
    #[serde(rename = "log-sec")]
    pub logical_sector: u64,
    #[serde(rename = "phy-sec")]
    pub physical_sector: u64,
    pub ro: bool,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub model: Option<String>,
    pub fstype: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    pub uuid: Option<String>,
    pub partuuid: Option<String>,
    #[serde(default)]
    pub parttype: Option<String>,
    pub ptuuid: Option<String>,
    pub mountpoints: Vec<Option<String>>,
    #[serde(default)]
    pub children: Vec<Block>,
}
const COLUMNS: &str = "PATH,MAJ:MIN,TYPE,SIZE,LOG-SEC,PHY-SEC,RO,SERIAL,WWN,MODEL,FSTYPE,LABEL,UUID,PARTUUID,PARTTYPE,PTUUID,MOUNTPOINTS";
pub fn clean(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(String::from)
}
fn flatten<'a>(rows: &'a [Block], output: &mut Vec<&'a Block>) {
    for row in rows {
        output.push(row);
        flatten(&row.children, output);
    }
}
pub fn parse_landscape(text: &str) -> Result<Landscape, Error> {
    serde_json::from_str(text)
        .map_err(|e| refuse(format!("unsupported native block inventory: {e}")))
}
fn device_number(metadata: &fs::Metadata) -> String {
    format!(
        "{}:{}",
        libc::major(metadata.rdev()),
        libc::minor(metadata.rdev())
    )
}
fn sysfs_path(number: &str) -> Result<String, Error> {
    if number
        .split_once(':')
        .is_none_or(|(a, b)| a.parse::<u32>().is_err() || b.parse::<u32>().is_err())
    {
        return Err(refuse("invalid kernel device number"));
    }
    let path = fs::canonicalize(Path::new("/sys/dev/block").join(number)).map_err(io_error)?;
    if !path.starts_with("/sys/devices") {
        return Err(refuse("block device has unexpected sysfs ownership"));
    }
    Ok(path.to_string_lossy().into_owned())
}
// This exception is a capability for one exclusively created image, not a
// second physical-device admission policy. Its kernel backing is revalidated
// at every observer boundary, including ESP workers on another thread.
fn admitted_image_loop(
    disk: &Block,
    sysfs: impl FnOnce() -> Result<String, Error>,
) -> Result<bool, Error> {
    crate::deploy::image::admit_loop(disk, || {
        sysfs().map_err(|error| std::io::Error::other(error.to_string()))
    })
    .map_err(io_error)
}
fn identity_from(disk: &Block, sysfs: String) -> Result<DiskIdentity, Error> {
    let image = admitted_image_loop(disk, || Ok(sysfs.clone()))?;
    if disk.kind != "disk" && !image
        || disk.size == 0
        || ![512, 4096].contains(&disk.logical_sector)
        || !disk.size.is_multiple_of(disk.logical_sector)
        || disk.physical_sector < disk.logical_sector
    {
        return Err(refuse("physical identity needs a supported whole disk"));
    }
    let serial = clean(&disk.serial);
    let wwn = clean(&disk.wwn);
    if !image && serial.is_none() && wwn.is_none() {
        return Err(refuse(
            "stable serial or WWN required for physical identity",
        ));
    }
    Ok(DiskIdentity {
        path: disk.path.clone(),
        device_number: disk.device_number.clone(),
        sysfs_path: sysfs,
        bytes: disk.size,
        logical_sector: disk.logical_sector,
        physical_sector: disk.physical_sector,
        serial,
        wwn,
        model: clean(&disk.model),
    })
}
fn review_from(landscape: &Landscape, path: &str, sysfs: String) -> Result<DiskReview, Error> {
    let mut all = Vec::new();
    flatten(&landscape.blockdevices, &mut all);
    let matching: Vec<_> = all.iter().copied().filter(|d| d.path == path).collect();
    if matching.len() != 1 {
        return Err(refuse("whole-disk selection is missing or ambiguous"));
    }
    let disk = matching[0];
    let image = admitted_image_loop(disk, || Ok(sysfs.clone()))?;
    if disk.kind != "disk" && !image
        || disk.ro
        || disk.size == 0
        || ![512, 4096].contains(&disk.logical_sector)
        || !disk.size.is_multiple_of(disk.logical_sector)
        || disk.physical_sector < disk.logical_sector
    {
        return Err(refuse(
            "wipe requires a writable whole disk with a supported sector layout",
        ));
    }
    let serial = clean(&disk.serial);
    let wwn = clean(&disk.wwn);
    if !image && serial.is_none() && wwn.is_none() {
        return Err(refuse(
            "stable serial or WWN required for whole-disk consent",
        ));
    }
    if let Some(other) = all.iter().find(|other| {
        other.path != disk.path
            && other.kind == "disk"
            && (wwn.is_some() && clean(&other.wwn) == wwn
                || wwn.is_none() && serial.is_some() && clean(&other.serial) == serial)
    }) {
        let (what, value) = match &wwn {
            Some(wwn) => ("WWN", wwn),
            None => ("serial", serial.as_ref().expect("a serial is compared")),
        };
        return Err(refuse(format!(
            "physical disk identity is duplicated: {} reports the same {what} {value}, so \
             neither can be confirmed; attach only one of them",
            other.path
        )));
    }
    let mut descendants = Vec::new();
    flatten(&disk.children, &mut descendants);
    if disk.mountpoints.iter().any(Option::is_some)
        || descendants.iter().any(|d| {
            d.kind != "part"
                || d.ro
                || d.mountpoints.iter().any(Option::is_some)
                || !d.children.is_empty()
        })
    {
        return Err(refuse(
            "selected disk is mounted, readonly, or has stacked block consumers",
        ));
    }
    let mut numbers = BTreeSet::new();
    numbers.insert(&disk.device_number);
    let mut partitions = Vec::new();
    for d in descendants {
        if !numbers.insert(&d.device_number) {
            return Err(refuse("duplicate native block identity"));
        }
        partitions.push(Partition {
            path: d.path.clone(),
            device_number: d.device_number.clone(),
            bytes: d.size,
            partition_uuid: clean(&d.partuuid),
            filesystem: clean(&d.fstype),
            filesystem_uuid: clean(&d.uuid),
            filesystem_label: clean(&d.label),
        });
    }
    partitions.sort_by(|a, b| a.device_number.cmp(&b.device_number));
    let identity = identity_from(disk, sysfs)?;
    let mut review = DiskReview {
        schema_version: 2,
        identity,
        partitions,
        filesystem: clean(&disk.fstype),
        partition_table_uuid: clean(&disk.ptuuid),
        // `plan` selects the method once the disk passed its usage guards.
        method: Method::Clear {
            reason: ClearReason::NotNvme,
            extents: Vec::new(),
        },
        loss_token: String::new(),
    };
    seal(&mut review)?;
    Ok(review)
}
fn seal(review: &mut DiskReview) -> Result<(), Error> {
    review.loss_token.clear();
    review.loss_token = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&*review).map_err(|e| refuse(e.to_string()))?)
    );
    Ok(())
}
fn backing_device_number(metadata: &fs::Metadata) -> String {
    if metadata.file_type().is_block_device() {
        device_number(metadata)
    } else {
        format!(
            "{}:{}",
            libc::major(metadata.dev()),
            libc::minor(metadata.dev())
        )
    }
}

/// Parse `zpool status -j -P` and return its pool map after verifying schema version.
pub(crate) fn parse_zpool_status(
    text: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, Error> {
    let mut value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| refuse(e.to_string()))?;
    let version = &value["output_version"];
    if version["command"] != "zpool status"
        || version["vers_major"] != 0
        || version["vers_minor"] != 1
    {
        return Err(refuse("unsupported native zpool status JSON schema"));
    }
    match value["pools"].take() {
        serde_json::Value::Object(pools) => Ok(pools),
        _ => Err(refuse("native imported pool inventory missing")),
    }
}

/// Parse `zpool status -j -P POOL` that must list exactly POOL.
pub(crate) fn parse_single_pool_status(text: &str, pool: &str) -> Result<serde_json::Value, Error> {
    let mut pools = parse_zpool_status(text)?;
    if pools.len() == 1 {
        pools.remove(pool)
    } else {
        None
    }
    .ok_or_else(|| refuse("pool physical inventory does not match selected scope"))
}

fn pool_vdev_paths(pool: &serde_json::Value) -> Result<Vec<String>, Error> {
    fn visit(value: &serde_json::Value, output: &mut Vec<String>) -> Result<(), Error> {
        match value {
            serde_json::Value::Object(map) => {
                if map.contains_key("path")
                    && !matches!(
                        map.get("vdev_type").and_then(|v| v.as_str()),
                        Some("disk" | "file")
                    )
                {
                    return Err(refuse("native pool path lacks a supported leaf type"));
                }
                if let Some(kind) = map.get("vdev_type").and_then(|v| v.as_str()) {
                    match kind {
                        "disk" | "file" => output.push(
                            map.get("path")
                                .and_then(|v| v.as_str())
                                .filter(|p| p.starts_with('/'))
                                .ok_or_else(|| refuse("imported native leaf path missing"))?
                                .into(),
                        ),
                        "mirror" | "raidz" | "draid" | "root" | "replacing" | "spare" | "hole"
                        | "indirect" => {}
                        _ => {
                            return Err(refuse(format!(
                                "unsupported imported native vdev type: {kind}"
                            )));
                        }
                    }
                }
                for child in map.values() {
                    visit(child, output)?;
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, output)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    if !pool.is_object() {
        return Err(refuse("invalid imported pool record"));
    }
    if !pool.get("vdevs").is_some_and(serde_json::Value::is_object) {
        return Err(refuse("native pool vdev tree missing"));
    }
    let mut paths = Vec::new();
    visit(pool, &mut paths)?;
    if paths.is_empty() {
        return Err(refuse("imported pool has no resolved native leaves"));
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Extract every imported block/file leaf across data, log, cache, dedup and
/// spare trees. Unknown schema/leaf types refuse rather than omitting a class.
// Read status with -P, not -L: OpenZFS looks up vdev metadata by the display
// name, and resolving a configured by-id name can erase its identity fields.
// Preserve the configured path here; callers resolve its actual native device.
fn imported_paths(text: &str) -> Result<Vec<String>, Error> {
    let pools = parse_zpool_status(text)?;
    let mut paths = Vec::new();
    for pool in pools.values() {
        paths.extend(pool_vdev_paths(pool)?);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}
fn landscape_args() -> [String; 8] {
    [
        "--json",
        "--tree",
        "--properties-by",
        "blkid",
        "--bytes",
        "--paths",
        "--output",
        COLUMNS,
    ]
    .map(String::from)
}
fn kernel_serial<F>(mut read: F) -> Result<Option<String>, Error>
where
    F: FnMut(&str) -> Result<String, std::io::Error>,
{
    for suffix in ["serial", "device/serial"] {
        match read(suffix) {
            Ok(value) => {
                let value = value.trim();
                if !value.is_empty() && !value.chars().any(char::is_control) {
                    return Ok(Some(value.into()));
                }
            }
            // Some USB-SCSI bridges publish device/serial but return ENXIO
            // when read. Continue to the nearest physical USB device serial;
            // a missing serial there still refuses the disk identity.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ENXIO) => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    Ok(None)
}
fn serial_from_sysfs_with(
    path: &Path,
    mut read: impl FnMut(&Path) -> Result<String, std::io::Error>,
) -> Result<Option<String>, Error> {
    let exact = kernel_serial(|suffix| read(&path.join(suffix)))?;
    if exact.is_some() {
        return Ok(exact);
    }
    // USB-backed SCSI disks expose their serial on the enclosing USB device.
    // Stop at that nearest device even if it has no usable serial; a parent
    // hub/controller serial must never become the disk's identity.
    for ancestor in path.ancestors().skip(1) {
        if !ancestor.starts_with("/sys/devices") {
            break;
        }
        let uevent = match read(&ancestor.join("uevent")) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(error)),
        };
        if !uevent.lines().any(|line| line == "DEVTYPE=usb_device") {
            continue;
        }
        let hub = uevent.lines().any(|line| {
            matches!(
                line.strip_prefix("TYPE=").and_then(|v| v.split('/').next()),
                Some("9" | "09")
            )
        });
        let class = match read(&ancestor.join("bDeviceClass")) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(io_error(error)),
        };
        if hub || class.trim() == "09" {
            return Ok(None);
        }
        return kernel_serial(|suffix| {
            if suffix == "serial" {
                read(&ancestor.join(suffix))
            } else {
                Err(std::io::ErrorKind::NotFound.into())
            }
        });
    }
    Ok(None)
}
fn serial_from_sysfs(path: &Path) -> Result<Option<String>, Error> {
    serial_from_sysfs_with(path, |p| fs::read_to_string(p))
}
pub fn normalize_landscape_with(
    inventory: &mut Landscape,
    mut serial: impl FnMut(&str) -> Result<Option<String>, Error>,
) -> Result<(), Error> {
    fn supplement(
        rows: &mut [Block],
        serial: &mut impl FnMut(&str) -> Result<Option<String>, Error>,
    ) -> Result<(), Error> {
        for row in rows {
            row.serial = clean(&row.serial);
            row.wwn = clean(&row.wwn);
            row.model = clean(&row.model);
            if row.kind == "disk" && clean(&row.serial).is_none() {
                // Recovery may lack a udev database. Bind the kernel serial to
                // the exact major:minor node, never infer it from a /dev name.
                if let Some(value) = serial(&row.device_number)? {
                    row.serial = clean(&Some(value));
                }
            }
            supplement(&mut row.children, serial)?;
        }
        Ok(())
    }
    supplement(&mut inventory.blockdevices, &mut serial)
}
pub fn observe_landscape_with(
    mut run: impl FnMut(&'static str, &[String]) -> Result<String, Error>,
) -> Result<Landscape, Error> {
    let mut inventory = parse_landscape(&run("lsblk", &landscape_args())?)?;
    normalize_landscape_with(&mut inventory, |number| {
        let path = sysfs_path(number)?;
        serial_from_sysfs(Path::new(&path))
    })?;
    Ok(inventory)
}
pub fn observe_landscape() -> Result<Landscape, Error> {
    observe_landscape_with(|program, args| {
        crate::native_run::run(program, args, 4 * 1024 * 1024, 30)
    })
}
fn resolved_block(path: &str) -> Result<(String, String), Error> {
    let path = fs::canonicalize(path).map_err(io_error)?;
    let metadata = fs::metadata(&path).map_err(io_error)?;
    if !metadata.file_type().is_block_device() {
        return Err(refuse(
            "physical preservation proof requires block-backed storage",
        ));
    }
    Ok((
        path.to_str()
            .ok_or_else(|| refuse("device path is not UTF-8"))?
            .into(),
        device_number(&metadata),
    ))
}
/// Whether `text`, the serial or WWN typed to confirm `disk`, also names another
/// disk. docs/CLI.md: such a disk is confirmed only with `--confirm`. A failed
/// inventory counts as shared.
pub fn typed_identity_is_shared(disk: &DiskIdentity, text: &str) -> bool {
    let Ok(rows) = observe_landscape() else {
        return true;
    };
    let mut all = Vec::new();
    flatten(&rows.blockdevices, &mut all);
    all.iter().any(|other| {
        other.path != disk.path
            && other.kind == "disk"
            && (clean(&other.serial).as_deref() == Some(text)
                || clean(&other.wwn).as_deref() == Some(text))
    })
}
/// Read-only identity inspection also works while the disk is mounted or its
/// pools are imported; wipe admission remains the stricter `plan` operation.
pub fn observe_identity(path: &str) -> Result<DiskIdentity, Error> {
    let (path, number) = resolved_block(path)?;
    let rows = observe_landscape()?;
    let mut all = Vec::new();
    flatten(&rows.blockdevices, &mut all);
    let matching: Vec<_> = all
        .into_iter()
        .filter(|d| d.path == path && d.device_number == number)
        .collect();
    if matching.len() != 1 {
        return Err(refuse("disk identity is missing or ambiguous"));
    }
    let identity = identity_from(matching[0], sysfs_path(&number)?)?;
    if resolved_block(&path)? != (path, number) {
        return Err(refuse("disk changed during observation"));
    }
    Ok(identity)
}
/// Bind a real, directly disk-backed partition without formatting or changing
/// its mount state. Filesystem/type/UUID fields come from direct blkid probing.
pub fn observe_partition(path: &str) -> Result<PartitionIdentity, Error> {
    let (path, number) = resolved_block(path)?;
    let rows = observe_landscape()?;
    let disk = whole_disk_for(&rows, &number)?;
    let matches: Vec<_> = disk
        .children
        .iter()
        .filter(|p| {
            p.kind == "part" && p.device_number == number && p.path == path && p.children.is_empty()
        })
        .collect();
    if matches.len() != 1 {
        return Err(refuse(
            "partition is missing or not directly backed by one disk",
        ));
    }
    let part = matches[0];
    let identity = observe_identity(&disk.path)?;
    if identity.device_number != disk.device_number {
        return Err(refuse("partition's disk identity changed"));
    }
    let partition_number = fs::read_to_string(Path::new(&sysfs_path(&number)?).join("partition"))
        .map_err(io_error)?
        .trim()
        .parse::<u32>()
        .map_err(|_| refuse("invalid native partition number"))?;
    if partition_number == 0 || resolved_block(&path)? != (path.clone(), number.clone()) {
        return Err(refuse("partition changed during observation"));
    }
    Ok(PartitionIdentity {
        disk: identity,
        number: partition_number,
        partition_type: clean(&part.parttype),
        readonly: disk.ro || part.ro,
        partition: Partition {
            path,
            device_number: number,
            bytes: part.size,
            partition_uuid: clean(&part.partuuid),
            filesystem: clean(&part.fstype),
            filesystem_uuid: clean(&part.uuid),
            filesystem_label: clean(&part.label),
        },
    })
}

/// Compare the physical attributes that survive a reboot. Kernel paths,
/// sysfs locators and major/minor numbers are deliberately excluded: Linux may
/// enumerate the same namespace and controller differently after a boot while
/// its hardware attachment and geometry remain unchanged.
pub fn same_disk_stable(expected: &DiskIdentity, current: &DiskIdentity) -> bool {
    expected.bytes == current.bytes
        && expected.logical_sector == current.logical_sector
        && expected.physical_sector == current.physical_sector
        && expected.serial == current.serial
        && expected.wwn == current.wwn
        && expected.model == current.model
        && (expected.serial.is_some() || expected.wwn.is_some())
}

fn whole_disk_for<'a>(rows: &'a Landscape, number: &str) -> Result<&'a Block, Error> {
    let mut found = Vec::new();
    for disk in &rows.blockdevices {
        if disk.kind != "disk"
            && (disk.kind != "loop"
                || !admitted_image_loop(disk, || sysfs_path(&disk.device_number))?)
        {
            continue;
        }
        if disk.device_number == number
            || disk
                .children
                .iter()
                .any(|p| p.kind == "part" && p.device_number == number && p.children.is_empty())
        {
            found.push(disk);
        }
    }
    if found.len() != 1 {
        return Err(refuse(
            "pool leaf has ambiguous or unsupported physical ancestry",
        ));
    }
    Ok(found[0])
}
fn verify_pool_guid(
    pool: &str,
    expected: &zfs_tools::engine::Guid,
    context: &str,
) -> Result<(), Error> {
    let guid = native::run(
        "zpool",
        &[
            "get".into(),
            "-H".into(),
            "-p".into(),
            "-o".into(),
            "value".into(),
            "guid".into(),
            pool.into(),
        ],
    )?;
    if guid.trim() != expected.to_string() {
        return Err(refuse(format!("pool identity changed during {context}")));
    }
    Ok(())
}

/// The configured leaf paths of the imported pool `pool`, which must still be
/// `expected`.
pub fn pool_leaves(pool: &str, expected: &zfs_tools::engine::Guid) -> Result<Vec<String>, Error> {
    zfs_tools::engine::validate_pool_name(pool)?;
    verify_pool_guid(pool, expected, "leaf observation")?;
    imported_paths(&native::run(
        "zpool",
        &["status".into(), "-j".into(), "-P".into(), pool.into()],
    )?)
}
pub fn observe_pool_storage(
    pool: &str,
    expected: &zfs_tools::engine::Guid,
) -> Result<PoolStorage, Error> {
    observe_pool_storage_and_status(pool, expected).map(|(storage, _)| storage)
}
pub(crate) fn observe_pool_storage_and_status(
    pool: &str,
    expected: &zfs_tools::engine::Guid,
) -> Result<(PoolStorage, serde_json::Value), Error> {
    zfs_tools::engine::validate_pool_name(pool)?;
    verify_pool_guid(pool, expected, "physical observation")?;
    let status = native::run(
        "zpool",
        &["status".into(), "-j".into(), "-P".into(), pool.into()],
    )?;
    let pool_value = parse_single_pool_status(&status, pool)?;
    let rows = observe_landscape()?;
    let mut disks = std::collections::BTreeMap::new();
    for leaf in pool_vdev_paths(&pool_value)? {
        let (_, number) = resolved_block(&leaf)?;
        let disk = whole_disk_for(&rows, &number)?;
        let identity = observe_identity(&disk.path)?;
        if identity.device_number != disk.device_number {
            return Err(refuse("pool disk changed during physical observation"));
        }
        disks.insert(identity.device_number.clone(), identity);
    }
    if disks.is_empty() {
        return Err(refuse("pool storage proof has no physical leaves"));
    }
    verify_pool_guid(pool, expected, "physical observation")?;
    Ok((
        PoolStorage {
            pool: pool.into(),
            guid: *expected,
            disks: disks.into_values().collect(),
        },
        pool_value,
    ))
}
fn controller_path(disk: &DiskIdentity) -> &str {
    // Different NVMe namespaces on one controller are not independent media.
    let Some((parent, name)) = disk.sysfs_path.rsplit_once('/') else {
        return &disk.sysfs_path;
    };
    if name.starts_with("nvme")
        && parent
            .rsplit('/')
            .next()
            .is_some_and(|p| p.starts_with("nvme") && p[4..].chars().all(|c| c.is_ascii_digit()))
    {
        parent
    } else {
        &disk.sysfs_path
    }
}
/// All archive vdev classes must survive the target's complete erasure. Fail
/// closed on aliases, common serial/WWN, or namespaces sharing an NVMe controller.
#[cfg(test)]
pub fn require_independent(target: &DiskIdentity, archive: &PoolStorage) -> Result<(), Error> {
    require_disks_independent(target, &archive.disks)
}
pub fn require_disks_independent(
    target: &DiskIdentity,
    disks: &[DiskIdentity],
) -> Result<(), Error> {
    if disks.is_empty() {
        return Err(refuse("archive physical evidence is empty"));
    }
    for disk in disks {
        if disk.path == target.path
            || disk.device_number == target.device_number
            || controller_path(disk) == controller_path(target)
            || disk
                .serial
                .as_ref()
                .is_some_and(|v| Some(v) == target.serial.as_ref())
            || disk
                .wwn
                .as_ref()
                .is_some_and(|v| Some(v) == target.wwn.as_ref())
        {
            return Err(refuse(
                "archive storage is not physically independent of the wipe target",
            ));
        }
    }
    Ok(())
}
/// Every allowed imported pool must live on this disk alone. Restore permits
/// its one owned pool; a reviewed disk export scope may include several.
fn guard_usage(review: &DiskReview, owned: &[String]) -> Result<(), Error> {
    let mut numbers: BTreeSet<_> = review
        .partitions
        .iter()
        .map(|p| p.device_number.clone())
        .collect();
    numbers.insert(review.identity.device_number.clone());
    // PATH alone does not make lsblk emit a nested JSON tree. Independently
    // check kernel partition membership so a flat/partial inventory can never
    // make an imported or mounted partition disappear from the wipe scope.
    let mut kernel_partitions = BTreeSet::new();
    for child in fs::read_dir(&review.identity.sysfs_path).map_err(io_error)? {
        let child = child.map_err(io_error)?;
        if !child.file_type().map_err(io_error)?.is_dir() {
            continue;
        }
        let child = child.path();
        if child.join("partition").try_exists().map_err(io_error)? {
            kernel_partitions.insert(
                fs::read_to_string(child.join("dev"))
                    .map_err(io_error)?
                    .trim()
                    .to_owned(),
            );
        }
    }
    let observed_partitions: BTreeSet<_> = review
        .partitions
        .iter()
        .map(|p| p.device_number.clone())
        .collect();
    if kernel_partitions != observed_partitions {
        return Err(refuse(
            "whole-disk partition inventory differs from kernel topology",
        ));
    }
    for number in &numbers {
        let holders = Path::new("/sys/dev/block").join(number).join("holders");
        if fs::read_dir(&holders).map_err(io_error)?.next().is_some() {
            return Err(refuse("target has kernel block holders"));
        }
    }
    let mounts = zfs_tools::engine::mountinfo::current()
        .map_err(|e| refuse(format!("unreadable mount dependency inventory: {e}")))?;
    if mounts.iter().any(|mount| numbers.contains(&mount.device)) {
        return Err(refuse("target backs a mounted filesystem"));
    }
    for (index, line) in fs::read_to_string("/proc/swaps")
        .map_err(io_error)?
        .lines()
        .enumerate()
    {
        if index == 0 {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(refuse("unsupported swap inventory"));
        }
        let metadata = fs::metadata(fields[0]).map_err(io_error)?;
        if numbers.contains(&backing_device_number(&metadata)) {
            return Err(refuse("target backs active swap"));
        }
    }
    let status = native::run("zpool", &["status".into(), "-j".into(), "-P".into()])?;
    let mut pools = parse_zpool_status(&status)?;
    for pool in owned {
        let own = pools
            .remove(pool)
            .ok_or_else(|| refuse("the target's own pool is not imported"))?;
        for path in pool_vdev_paths(&own)? {
            let metadata = fs::metadata(&path).map_err(|e| {
                refuse(format!(
                    "cannot resolve imported pool dependency {path}: {e}"
                ))
            })?;
            if !metadata.file_type().is_block_device()
                || !numbers.contains(&device_number(&metadata))
            {
                return Err(refuse(format!(
                    "pool {pool} also uses devices outside the selected disk"
                )));
            }
        }
    }
    // Pool by pool, so the refusal can name the pool and the leaf it uses.
    for (pool, own) in &pools {
        for path in pool_vdev_paths(own)? {
            let metadata = fs::metadata(&path).map_err(|e| {
                refuse(format!(
                    "cannot resolve imported pool dependency {path}: {e}"
                ))
            })?;
            if numbers.contains(&backing_device_number(&metadata)) {
                return Err(refuse(imported_pool_refusal(pool, &path)));
            }
        }
    }
    Ok(())
}
/// The selected disk holds or backs `path`, a leaf of imported pool `pool`.
fn imported_pool_refusal(pool: &str, path: &str) -> String {
    format!("selected disk belongs to or backs imported pool {pool} (through {path})")
}
pub fn plan(path: &str) -> Result<DiskReview, Error> {
    plan_owned(path, None)
}
/// [`plan`], except that `pool`, if given, may be imported from this disk
/// alone. Never authority to erase: [`wipe()`] plans again with no pool.
pub fn plan_owned(path: &str, pool: Option<&str>) -> Result<DiskReview, Error> {
    plan_allowed(
        path,
        &pool.map(str::to_owned).into_iter().collect::<Vec<_>>(),
    )
}
fn plan_allowed(path: &str, pools: &[String]) -> Result<DiskReview, Error> {
    // Every erase (wipe, deploy DISK, restore) plans here, and again right
    // before its first effect.
    wipe::require_probe(Path::new(wipe::PROBE))?;
    let mut review = inventory_allowed(path, pools)?;
    review.method = wipe::select(&review, Path::new("/sys"), &mut wipe::Native)?;
    seal(&mut review)?;
    Ok(review)
}
/// The disk, what is on it and its usage guards, without choosing how it
/// would be erased.
fn inventory(path: &str, pool: Option<&str>) -> Result<DiskReview, Error> {
    inventory_allowed(
        path,
        &pool.map(str::to_owned).into_iter().collect::<Vec<_>>(),
    )
}
fn inventory_allowed(path: &str, pools: &[String]) -> Result<DiskReview, Error> {
    let resolved = fs::canonicalize(path).map_err(io_error)?;
    let metadata = fs::metadata(&resolved).map_err(io_error)?;
    if !metadata.file_type().is_block_device() {
        return Err(refuse("wipe accepts only a real whole block disk"));
    }
    let landscape = observe_landscape()?;
    let review = review_from(
        &landscape,
        resolved
            .to_str()
            .ok_or_else(|| refuse("device path is not UTF-8"))?,
        sysfs_path(&device_number(&metadata))?,
    )?;
    if review.identity.device_number != device_number(&metadata) {
        return Err(refuse("device path changed during inventory"));
    }
    guard_usage(&review, pools)?;
    Ok(review)
}
/// The confirmation token of a wipe plan: the plan without its own loss token.
pub fn wipe_consent(review: &DiskReview) -> std::io::Result<String> {
    let mut consent = review.clone();
    consent.loss_token.clear();
    crate::consent::token(&consent)
}

pub fn size(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes >> 20)
    }
}

/// The disk and what is on it now, as an erase plan shows it.
pub fn describe_disk(review: &DiskReview) -> String {
    let disk = &review.identity;
    let show = |value: &Option<String>| value.as_deref().unwrap_or("unknown").to_owned();
    let mut text = format!(
        "  Disk:   {} {} serial {} ({})\n",
        zfs_tools::engine::escape_display(&disk.path),
        zfs_tools::engine::escape_display(&show(&disk.model)),
        zfs_tools::engine::escape_display(&show(&disk.serial)),
        size(disk.bytes)
    );
    if review.partitions.is_empty() {
        text.push_str("  Now:    no partitions\n");
    }
    for part in &review.partitions {
        let label = part
            .filesystem_label
            .as_deref()
            .map_or(String::new(), |label| {
                let kind = if part.filesystem.as_deref() == Some("zfs_member") {
                    "pool"
                } else {
                    "label"
                };
                format!(" ({kind} {})", zfs_tools::engine::escape_display(label))
            });
        text.push_str(&format!(
            "  Now:    {} {} {}{}{label}\n",
            zfs_tools::engine::escape_display(&part.path),
            size(part.bytes),
            zfs_tools::engine::escape_display(&show(&part.filesystem)),
            part.filesystem_uuid
                .as_deref()
                .map_or(String::new(), |uuid| format!(
                    " {}",
                    zfs_tools::engine::escape_display(uuid)
                ))
        ));
    }
    text
}

pub fn describe_wipe(review: &DiskReview, token: &str) -> String {
    format!(
        "Erase disk\n{}{}  Token:  {token}\n",
        describe_disk(review),
        review.method.describe()
    )
}

/// A whole disk `wipe` could erase now, or why it cannot.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub path: String,
    pub bytes: u64,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub method: Option<String>,
    pub refused: Option<String>,
}

pub fn candidates() -> Result<Vec<Candidate>, Error> {
    Ok(observe_landscape()?
        .blockdevices
        .iter()
        .filter(|block| block.kind == "disk")
        .map(|block| {
            let (method, refused) = match plan(&block.path) {
                Ok(review) => (Some(review.method.summary()), None),
                Err(error) => (None, Some(error.to_string())),
            };
            Candidate {
                path: block.path.clone(),
                bytes: block.size,
                serial: block.serial.clone(),
                model: block.model.clone(),
                method,
                refused,
            }
        })
        .collect())
}

/// Erase the reviewed disk by its reviewed method, after planning it again.
pub fn wipe(review: &DiskReview, token: &str) -> Result<WipeOutcome, Error> {
    if token != review.loss_token {
        return Err(refuse("exact whole-disk loss token does not match"));
    }
    if plan(&review.identity.path)? != *review {
        return Err(refuse(
            "whole-disk identity, layout or erase scope changed since review",
        ));
    }
    wipe::execute(review, &mut wipe::Native)
}
#[allow(unsafe_code)]
pub(crate) fn reread_partitions(file: &std::fs::File) -> Result<(), Error> {
    use std::os::fd::AsRawFd;
    // SAFETY: BLKRRPART is Linux _IO(0x12,95), takes no pointer or payload,
    // and operates on the live exclusive block descriptor borrowed here.
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x125f) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(())
}
fn refuse(detail: impl Into<String>) -> Error {
    Error::Refused(detail.into())
}
fn io_error(error: std::io::Error) -> Error {
    refuse(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_shared_serial_refuses_both_disks_and_names_the_other() {
        let mut twin = disk();
        twin["path"] = "/dev/vdb".into();
        twin["maj:min"] = "252:16".into();
        twin["children"] = serde_json::json!([]);
        let error = review(vec![disk(), twin]).unwrap_err().to_string();
        assert!(
            error.contains(
                "physical disk identity is duplicated: /dev/vdb reports the same serial unique-A"
            ),
            "{error}"
        );
        let mut nameless = disk();
        nameless["serial"] = serde_json::Value::Null;
        let error = review(vec![nameless]).unwrap_err().to_string();
        assert!(error.contains("stable serial or WWN required"), "{error}");
    }
    #[test]
    fn an_imported_pool_refusal_names_the_pool_and_its_leaf() {
        assert_eq!(
            imported_pool_refusal("stick", "/dev/disk/by-id/usb-x-part2"),
            "selected disk belongs to or backs imported pool stick (through /dev/disk/by-id/usb-x-part2)"
        );
    }
    fn disk() -> serde_json::Value {
        serde_json::json!({
            "path":"/dev/vda", "maj:min":"252:0", "type":"disk", "size":2147483648_u64,
            "log-sec":512,"phy-sec":4096,"ro":false,"serial":"unique-A","wwn":null,
            "model":"QEMU","fstype":null,"uuid":null,"partuuid":null,"ptuuid":"table-A",
            "mountpoints":[null],"children":[{
                "path":"/dev/vda1","maj:min":"252:1","type":"part","size":1073741824_u64,
                "log-sec":512,"phy-sec":4096,"ro":false,"serial":null,"wwn":null,"model":null,
                "fstype":"zfs_member","uuid":"pool-A","partuuid":"part-A","ptuuid":"table-A","mountpoints":[null]
            }]
        })
    }
    fn landscape(rows: Vec<serde_json::Value>) -> Landscape {
        parse_landscape(&serde_json::json!({"blockdevices": rows}).to_string()).unwrap()
    }
    fn review(rows: Vec<serde_json::Value>) -> Result<DiskReview, Error> {
        review_from(
            &landscape(rows),
            "/dev/vda",
            "/sys/devices/pci/block/vda".into(),
        )
    }
    struct ScopeFake {
        review: DiskReview,
        facts: Vec<DiskPoolFacts>,
        exports: Vec<String>,
        guard_failed: bool,
        fail_export: Option<String>,
    }
    impl ScopeFake {
        fn new() -> Self {
            let review = review(vec![disk()]).unwrap();
            let facts = [("a", 1), ("b", 2)]
                .into_iter()
                .map(|(name, guid)| DiskPoolFacts {
                    pool: ScopedPool {
                        name: name.into(),
                        guid: zfs_tools::engine::Guid::new(guid),
                    },
                    readonly: true,
                    unmounted: true,
                    disks: vec![review.identity.clone()],
                })
                .collect();
            Self {
                review,
                facts,
                exports: Vec::new(),
                guard_failed: false,
                fail_export: None,
            }
        }
    }
    impl crate::menu::pool_access::Backend for ScopeFake {
        fn prove_ram(&mut self) -> crate::menu::Result<()> {
            Ok(())
        }
        fn observe(&mut self) -> crate::menu::Result<zfs_tools::engine::state::NativeState> {
            panic!("disk scope uses complete disk-pool facts")
        }
        fn export(&mut self, name: &str) -> crate::menu::Result<()> {
            self.exports.push(name.into());
            if self.fail_export.as_deref() == Some(name) {
                return Err(crate::menu::RecoveryError::Refused(
                    "injected export failure".into(),
                ));
            }
            self.facts.retain(|fact| fact.pool.name != name);
            Ok(())
        }
        fn import(&mut self, _: zfs_tools::engine::Guid, _: bool) -> crate::menu::Result<()> {
            panic!("disk scope must never import")
        }
    }
    impl DiskScopeBackend for ScopeFake {
        fn disk_identity(&mut self, _: &str) -> Result<DiskIdentity, Error> {
            Ok(self.review.identity.clone())
        }
        fn disk_pools(&mut self, _: &DiskIdentity) -> Result<Vec<DiskPoolFacts>, Error> {
            Ok(self.facts.clone())
        }
        fn disk_review(&mut self, _: &str, allowed: &[String]) -> Result<DiskReview, Error> {
            if self.guard_failed
                || self
                    .facts
                    .iter()
                    .any(|fact| !fact.disks.is_empty() && !allowed.contains(&fact.pool.name))
            {
                return Err(refuse("ordinary usage guards refused the disk"));
            }
            Ok(self.review.clone())
        }
    }

    #[test]
    fn an_erase_plan_names_the_pool_of_a_zfs_member() {
        let mut row = disk();
        row["children"][0]["label"] = "tank".into();
        let text = describe_disk(&review(vec![row]).unwrap());
        assert!(
            text.contains("  Now:    /dev/vda1 1.0 GiB zfs_member pool-A (pool tank)\n"),
            "{text}"
        );
        let text = describe_disk(&review(vec![disk()]).unwrap());
        assert!(text.contains("zfs_member pool-A\n"), "{text}");
    }

    #[test]
    fn an_unregistered_loop_does_not_gain_physical_disk_authority() {
        let mut block: Block = serde_json::from_value(disk()).unwrap();
        block.kind = "loop".into();
        block.serial = None;
        block.wwn = None;
        assert!(identity_from(&block, "/sys/devices/fake-unregistered-loop".into()).is_err());
        let mut queried = false;
        assert!(
            !admitted_image_loop(&block, || {
                queried = true;
                Ok("must not be read".into())
            })
            .unwrap()
        );
        assert!(
            !queried,
            "unregistered loops are refused without probing unrelated sysfs"
        );
    }

    #[test]
    fn disk_scope_preview_is_read_only_and_survives_all_reviewed_exports() {
        let mut fake = ScopeFake::new();
        let scope = DiskScope::plan_with("/dev/vda", &mut fake).unwrap();
        let before = scope.review_with(&mut fake).unwrap();
        let token = crate::consent::token(&(wipe_consent(&before).unwrap(), &scope)).unwrap();
        assert!(fake.exports.is_empty());
        assert_eq!(scope.pools().len(), 2);
        // The default host admission remains imported-none.
        assert!(fake.disk_review("/dev/vda", &[]).is_err());
        scope.export_with(&mut fake).unwrap();
        assert_eq!(fake.exports, ["a", "b"]);
        let after = scope.review_with(&mut fake).unwrap();
        assert_eq!(before, after);
        assert_eq!(
            token,
            crate::consent::token(&(wipe_consent(&after).unwrap(), &scope)).unwrap()
        );
        assert_ne!(
            token,
            crate::consent::token(&(
                wipe_consent(&after).unwrap(),
                DiskScope {
                    identity: scope.identity.clone(),
                    pools: Vec::new(),
                }
            ))
            .unwrap()
        );
        assert_eq!(fake.disk_review("/dev/vda", &[]).unwrap(), after);
    }

    #[test]
    fn disk_scope_checks_every_pool_and_native_usage_guard_before_first_export() {
        let changes: [fn(&mut ScopeFake); 8] = [
            |fake| fake.review.identity.serial = Some("replacement".into()),
            |fake| fake.facts[1].pool.guid = zfs_tools::engine::Guid::new(99),
            |fake| fake.facts[1].pool.name = "renamed".into(),
            |fake| fake.facts[1].readonly = false,
            |fake| fake.facts[1].unmounted = false,
            |fake| {
                fake.facts[1].disks.push(DiskIdentity {
                    path: "/dev/vdb".into(),
                    ..fake.review.identity.clone()
                })
            },
            |fake| {
                let mut other = fake.facts[0].clone();
                other.pool = ScopedPool {
                    name: "new".into(),
                    guid: zfs_tools::engine::Guid::new(3),
                };
                fake.facts.push(other);
            },
            |fake| fake.guard_failed = true,
        ];
        for (index, change) in changes.into_iter().enumerate() {
            let mut fake = ScopeFake::new();
            let scope = DiskScope::plan_with("/dev/vda", &mut fake).unwrap();
            change(&mut fake);
            assert!(scope.export_with(&mut fake).is_err(), "change {index}");
            assert!(fake.exports.is_empty(), "change {index}");
        }
    }

    #[test]
    fn disk_scope_partial_export_keeps_the_frozen_scope_and_never_imports() {
        let mut fake = ScopeFake::new();
        let scope = DiskScope::plan_with("/dev/vda", &mut fake).unwrap();
        let before = scope.review_with(&mut fake).unwrap();
        fake.fail_export = Some("b".into());
        assert!(scope.export_with(&mut fake).is_err());
        assert_eq!(fake.exports, ["a", "b"]);
        assert_eq!(scope.review_with(&mut fake).unwrap(), before);
        assert_eq!(scope.pools().len(), 2);
        fake.fail_export = None;
        scope.export_with(&mut fake).unwrap();
        assert_eq!(fake.exports, ["a", "b", "b"]);
        assert!(fake.facts.is_empty());
    }

    #[test]
    fn physical_inventory_uses_blkid_properties_and_stable_paths() {
        let args = landscape_args();
        assert_eq!(
            args.windows(2)
                .find(|pair| pair[0] == "--properties-by")
                .map(|pair| pair[1].as_str()),
            Some("blkid")
        );
        assert!(args.iter().any(|arg| arg == "--paths"));
        assert_eq!(args.last().map(String::as_str), Some(COLUMNS));
    }

    #[test]
    fn physical_inventory_propagates_bounded_native_timeout() {
        let error = observe_landscape_with(|program, args| {
            crate::native_run::run(program, args, 4 * 1024 * 1024, 0)
        })
        .expect_err("zero-second native inventory must refuse on timeout");
        assert!(
            error.to_string().contains("native command timed out"),
            "{error}"
        );
    }

    #[test]
    fn usb_serial_binds_nearest_device_and_never_a_hub() {
        let disk = Path::new("/sys/devices/pci/usb1/1-6/interface/scsi/block/sda");
        let usb = Path::new("/sys/devices/pci/usb1/1-6");
        let hub = Path::new("/sys/devices/pci/usb1");
        for (uevent, serial, class, expected) in [
            (
                Some("DEVTYPE=usb_device\nTYPE=0/0/0\n"),
                Some("FAKE0000000000000001\n"),
                None,
                Some("FAKE0000000000000001"),
            ),
            (Some("DEVTYPE=usb_device\nTYPE=0/0/0\n"), None, None, None),
            (
                Some("DEVTYPE=usb_device\nTYPE=0/0/0\n"),
                Some("bad\nserial"),
                None,
                None,
            ),
            (None, None, None, None),
            (
                Some("DEVTYPE=usb_device\nTYPE=9/0/1\n"),
                Some("hub-serial"),
                None,
                None,
            ),
            (
                Some("DEVTYPE=usb_device\n"),
                Some("hub-serial"),
                Some("09\n"),
                None,
            ),
        ] {
            let mut files = std::collections::BTreeMap::new();
            files.insert(hub.join("uevent"), "DEVTYPE=usb_device\nTYPE=9/0/1\n");
            files.insert(hub.join("serial"), "controller-serial");
            if let Some(v) = uevent {
                files.insert(usb.join("uevent"), v);
            }
            if let Some(v) = serial {
                files.insert(usb.join("serial"), v);
            }
            if let Some(v) = class {
                files.insert(usb.join("bDeviceClass"), v);
            }
            let actual = serial_from_sysfs_with(disk, |p| {
                assert!(p.starts_with("/sys/devices"));
                files
                    .get(p)
                    .map(|v| (*v).to_owned())
                    .ok_or_else(|| std::io::ErrorKind::NotFound.into())
            })
            .unwrap();
            assert_eq!(actual.as_deref(), expected);
        }
        let exact = serial_from_sysfs_with(disk, |p| {
            assert_eq!(p, disk.join("serial"));
            Ok("exact-disk-serial\n".into())
        })
        .unwrap();
        assert_eq!(exact.as_deref(), Some("exact-disk-serial"));
    }

    #[test]
    fn missing_udev_serial_falls_back_to_trimmed_kernel_serial() {
        let mut calls = Vec::new();
        let serial = kernel_serial(|suffix| {
            calls.push(suffix.to_owned());
            if suffix == "serial" {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            } else {
                Ok("  kernel-serial\n".into())
            }
        })
        .unwrap();
        assert_eq!(serial.as_deref(), Some("kernel-serial"));
        assert_eq!(calls, ["serial", "device/serial"]);
    }
    #[test]
    fn unreadable_scsi_serial_uses_only_the_nearest_usb_device() {
        let disk =
            Path::new("/sys/devices/usb1/1-10/1-10:1.0/host12/target12:0:0/12:0:0:0/block/sdb");
        let usb = Path::new("/sys/devices/usb1/1-10");
        let serial = serial_from_sysfs_with(disk, |path| {
            if path == disk.join("device/serial") {
                Err(std::io::Error::from_raw_os_error(libc::ENXIO))
            } else if path == usb.join("uevent") {
                Ok("DEVTYPE=usb_device\nTYPE=0/0/0\n".into())
            } else if path == usb.join("serial") {
                Ok("0123456789AB\n".into())
            } else {
                Err(std::io::ErrorKind::NotFound.into())
            }
        })
        .unwrap();
        assert_eq!(serial.as_deref(), Some("0123456789AB"));
    }
    #[test]
    fn exact_review_binds_physical_identity_size_and_old_partition_layout() {
        let good = review(vec![disk()]).unwrap();
        assert_eq!(good.partitions.len(), 1);
        assert_eq!(good.identity.serial.as_deref(), Some("unique-A"));
        assert_eq!(good.loss_token.len(), 71);
        for field in ["serial", "wwn", "model", "maj:min", "ptuuid"] {
            let mut changed = disk();
            changed[field] = "replacement".into();
            assert_ne!(
                review(vec![changed]).unwrap().loss_token,
                good.loss_token,
                "{field}"
            );
        }
        let mut changed = disk();
        changed["children"][0]["partuuid"] = "new-partition".into();
        assert_ne!(review(vec![changed]).unwrap().loss_token, good.loss_token);
        assert!(
            wipe(&good, "wrong-token").is_err(),
            "wrong consent must fail before native execution"
        );
    }
    #[test]
    fn mounted_stacked_readonly_ambiguous_and_partition_targets_refuse() {
        for case in 0..8 {
            let mut changed = disk();
            match case {
                0 => changed["mountpoints"] = serde_json::json!(["/"]),
                1 => changed["children"][0]["mountpoints"] = serde_json::json!(["/data"]),
                2 => changed["children"][0]["type"] = "crypt".into(),
                3 => changed["ro"] = true.into(),
                4 => changed["type"] = "part".into(),
                5 => changed["serial"] = serde_json::Value::Null,
                6 => changed["size"] = 513.into(),
                _ => changed["log-sec"] = 1234.into(),
            }
            assert!(review(vec![changed]).is_err(), "case {case}");
        }
        let mut duplicate = disk();
        duplicate["path"] = "/dev/vdb".into();
        duplicate["maj:min"] = "252:16".into();
        assert!(review(vec![disk(), duplicate]).is_err());
    }
    #[test]
    fn imported_leaf_inventory_covers_auxiliary_classes_and_refuses_omissions() {
        let native = serde_json::json!({"output_version":{"command":"zpool status","vers_major":0,"vers_minor":1},"pools":{
            "tank":{"vdevs":{"tank":{"vdevs":{"mirror":{"vdev_type":"mirror","vdevs":{
                "disk":{"vdev_type":"disk","path":"/dev/vda1"},"file":{"vdev_type":"file","path":"/data/pool.img"}
            }}}}},"spares":{"disk":{"vdev_type":"disk","path":"/dev/vdb"}},"logs":{"disk":{"vdev_type":"disk","path":"/dev/vdc"}}}
        }});
        assert_eq!(
            imported_paths(&native.to_string()).unwrap(),
            vec!["/data/pool.img", "/dev/vda1", "/dev/vdb", "/dev/vdc"]
        );
        for case in 0..4 {
            let mut changed = native.clone();
            match case {
                0 => changed["output_version"]["vers_major"] = 1.into(),
                1 => changed["pools"]["tank"]["spares"]["disk"]["vdev_type"] = "future".into(),
                2 => {
                    changed["pools"]["tank"]["spares"]["disk"]
                        .as_object_mut()
                        .unwrap()
                        .remove("vdev_type");
                }
                _ => {
                    changed["pools"]["tank"]
                        .as_object_mut()
                        .unwrap()
                        .remove("vdevs");
                }
            }
            assert!(imported_paths(&changed.to_string()).is_err(), "case {case}");
        }
    }

    #[test]
    fn retained_by_id_status_preserves_identity_and_refuses_lossy_resolved_output() {
        // Captured from the disposable native fixture.
        assert_eq!(
            imported_paths(include_str!("fixtures/native-by-id-status-configured.json")).unwrap(),
            ["/dev/disk/by-id/virtio-ZFS-E2E-B-part1"],
        );
        assert!(
            imported_paths(include_str!("fixtures/native-by-id-status-resolved.json")).is_err()
        );
    }
    #[test]
    fn physical_proof_accepts_mounted_disks_but_rejects_shared_media() {
        let mut mounted = disk();
        mounted["mountpoints"] = serde_json::json!(["/"]);
        mounted["ro"] = true.into();
        let rows = landscape(vec![mounted]);
        let target =
            identity_from(&rows.blockdevices[0], "/sys/devices/pci/block/vda".into()).unwrap();
        assert!(review_from(&rows, "/dev/vda", target.sysfs_path.clone()).is_err());
        let mut other = target.clone();
        other.path = "/dev/vdb".into();
        other.device_number = "252:16".into();
        other.sysfs_path = "/sys/devices/pci/block/vdb".into();
        other.serial = Some("unique-B".into());
        let mut archive = PoolStorage {
            pool: "archive".into(),
            guid: serde_json::from_str("\"12\"").unwrap(),
            disks: vec![other.clone()],
        };
        assert!(require_independent(&target, &archive).is_ok());
        for case in 0..4 {
            archive.disks[0] = other.clone();
            match case {
                0 => archive.disks[0].serial = target.serial.clone(),
                1 => archive.disks[0].device_number = target.device_number.clone(),
                2 => archive.disks[0].sysfs_path = target.sysfs_path.clone(),
                _ => archive.disks.push(target.clone()),
            }
            assert!(
                require_independent(&target, &archive).is_err(),
                "case {case}"
            );
        }
        let mut nvme = target;
        nvme.sysfs_path = "/sys/devices/pci/nvme/nvme0/nvme0n1".into();
        archive.disks = vec![other];
        archive.disks[0].sysfs_path = "/sys/devices/pci/nvme/nvme0/nvme0n2".into();
        assert!(require_independent(&nvme, &archive).is_err());
        archive.disks[0].sysfs_path = "/sys/devices/pci/nvme/nvme1/nvme1n1".into();
        assert!(require_independent(&nvme, &archive).is_ok());
    }
    #[test]
    fn physical_ancestry_resolves_partitions_and_refuses_stacked_or_missing_leaves() {
        let rows = landscape(vec![disk()]);
        assert_eq!(whole_disk_for(&rows, "252:1").unwrap().path, "/dev/vda");
        assert_eq!(whole_disk_for(&rows, "252:0").unwrap().path, "/dev/vda");
        assert!(whole_disk_for(&rows, "253:0").is_err());
        let mut stacked = disk();
        stacked["children"][0]["type"] = "crypt".into();
        assert!(whole_disk_for(&landscape(vec![stacked]), "252:1").is_err());
        assert!(whole_disk_for(&landscape(vec![disk(), disk()]), "252:1").is_err());
    }
}
