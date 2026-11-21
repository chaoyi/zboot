//! Fresh disk deployment. A deploy keeps no operation record and is never
//! resumed: it runs straight through, and after a failure it is planned,
//! confirmed and run again. Rebuilding a disk while keeping datasets is `restore`.
pub mod command;
mod identity;
pub mod image;
pub mod into;
pub mod labels;
pub mod layout;
pub mod overlay;
mod portable;
pub mod request;
use crate::{
    content::{self, ContentProof},
    device::{self, DiskIdentity, PartitionIdentity},
    esp,
    factory::{self, root_tar::RootTar},
    loader::EfiFile,
};
use layout::Layout;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zfs_tools::engine::{
    management::Endpoint,
    native,
    state::{self, NativeState},
};
fn refuse(value: impl ToString) -> io::Error {
    io::Error::other(value.to_string())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoreReview {
    pub schema_version: u32,
    pub operation_id: String,
    /// The hostid the pool labels and the BE's `/etc/hostid` carry.
    pub hostid: String,
    pub disk: DiskIdentity,
    pub layout: Layout,
    pub factory: Option<RootTar>,
    /// Every user overlay in order, followed by the mandatory portable overlay
    /// when selected.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub overlays: Vec<overlay::Overlay>,
    /// What was asked for: disk, pool, purpose, boot, swap and inputs.
    pub selection: request::DeployRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_esp: Option<esp::EspReview>,
    pub artifacts: EfiFile,
    pub loss_token: String,
}
/// What one run has made and observed so far, in memory only.
#[derive(Debug, Clone)]
struct Operation {
    review: CoreReview,
    swap: Option<PartitionIdentity>,
    esp: Option<PartitionIdentity>,
    zfs: Option<PartitionIdentity>,
    pool: Option<Endpoint>,
    root: Option<Endpoint>,
    be: Option<Endpoint>,
    esp_review: Option<esp::EspReview>,
    boot_files: BTreeMap<String, factory::ImageFile>,
    final_content: Option<ContentProof>,
    export_intent: Option<labels::Evidence>,
    /// Publication has begun: a member's `zboot:pending` fence may be cleared.
    published: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoreOutcome {
    pub operation_id: String,
    pub journal_directory: PathBuf,
    pub disk: DiskIdentity,
    pub pool: Endpoint,
    pub dataset: Option<Endpoint>,
    pub root: Endpoint,
    pub swap: Option<PartitionIdentity>,
    pub external_boot_dependency: bool,
    pub firmware_selection: String,
    pub esp: PartitionIdentity,
    pub complete: bool,
    pub exported: bool,
}
fn token(review: &CoreReview) -> io::Result<String> {
    let mut value = review.clone();
    value.loss_token.clear();
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&value).map_err(refuse)?)
    ))
}
/// The same publication-name admission is used before image allocation and
/// when validating the native review.
fn validate_names(pool: &str, dataset: &str, os: bool) -> io::Result<()> {
    zfs_tools::engine::validate_dataset_name(pool).map_err(refuse)?;
    zfs_tools::engine::validate_dataset_name(dataset).map_err(refuse)?;
    let atom = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.: ".contains(&b))
    };
    if pool.contains('/')
        || pool.len() >= 240
        || !atom(pool)
        || !pool.as_bytes()[0].is_ascii_alphabetic()
        || ["mirror", "raidz", "draid", "spare"]
            .iter()
            .any(|prefix| pool.starts_with(prefix))
        || pool == "log"
        || dataset.len() >= 256
        || !dataset.split('/').all(atom)
        || os
            && dataset
                .strip_prefix(&format!("{pool}/ROOT/"))
                .is_none_or(|s| s.is_empty() || s.contains('/'))
    {
        return Err(refuse("invalid or mismatched deploy review"));
    }
    Ok(())
}
/// Whether `review` is a well-formed review of its own selection.
pub fn validate(review: &CoreReview) -> io::Result<()> {
    request::validate_selection(review)?;
    let r = &review.selection;
    let os = review.factory.is_some();
    validate_names(&r.pool, r.dataset(), os)?;
    if uuid::Uuid::parse_str(&review.operation_id).is_err()
        || r.disk != review.disk.path
        || !r.journal_directory.is_absolute()
        || !os && !review.overlays.is_empty()
        || r.boot_artifact_directory != review.artifacts.efi
        || token(review)? != review.loss_token
    {
        return Err(refuse("invalid or mismatched deploy review"));
    }
    review.layout.validate(&review.disk)?;
    let esp_bytes = review.external_esp.as_ref().map_or(
        review.layout.esp_sectors * review.disk.logical_sector,
        |e| e.target.partition.bytes,
    );
    if review
        .artifacts
        .bytes
        .checked_mul(3)
        .and_then(|v| v.checked_add(16 * 1024 * 1024))
        .is_none_or(|v| v > esp_bytes)
    {
        return Err(refuse(
            "deploy ESP lacks space for both selected boot files and one atomic replacement",
        ));
    }
    if let Some(factory) = &review.factory {
        let required = factory
            .entries
            .checked_mul(16 * 1024)
            .and_then(|v| v.checked_add(factory.logical_bytes))
            .and_then(|v| v.checked_add(512 * 1024 * 1024));
        if required.is_none_or(|bytes| {
            bytes > (review.layout.zfs_sectors * review.disk.logical_sector) / 5 * 4
        }) {
            return Err(refuse(
                "deploy ZFS partition lacks conservative capacity for selected OS contents, metadata and configuration",
            ));
        }
    }
    Ok(())
}
fn fresh_image(review: &CoreReview) -> bool {
    review.selection.fresh_image
}
fn is_portable(review: &CoreReview) -> bool {
    review.selection.portable
}
fn publish_default_args(pool: &str, dataset: &str) -> Vec<String> {
    args(&["set", &format!("bootfs={dataset}"), pool])
}
fn publishes_default(review: &CoreReview) -> bool {
    review.factory.is_some() && !is_portable(review)
}
fn expected_label_hostid(review: &CoreReview) -> io::Result<Option<u32>> {
    let value = u32::from_str_radix(&review.hostid, 16).map_err(refuse)?;
    Ok((value != 0).then_some(value))
}
fn ordered_overlays(review: &CoreReview) -> Vec<&overlay::Overlay> {
    review.overlays.iter().collect()
}

fn hostid(id: &str) -> String {
    let digest = Sha256::digest(id.as_bytes());
    let mut bytes: [u8; 4] = digest[..4].try_into().unwrap();
    bytes[0] = (bytes[0] & 0x7f) | 1;
    format!("{:08x}", u32::from_le_bytes(bytes))
}
const SPL_HOSTID_PARAMETER: &str = "/sys/module/spl/parameters/spl_hostid";
const SPL_EFFECTIVE_HOSTID: &str = "/proc/sys/kernel/spl/hostid";

fn effective_hostid(path: &Path) -> io::Result<u32> {
    let value = fs::read_to_string(path)?;
    let value = value.trim();
    let value = value.strip_prefix("0x").unwrap_or(value);
    u32::from_str_radix(value, 16).map_err(|_| refuse("invalid effective OpenZFS hostid"))
}

/// OpenZFS captures zone_get_hostid() in spa_add() during pool creation, then
/// writes spa_hostid into its labels. The SPL parameter overrides /etc/hostid;
/// restore its raw value so a Rescue runtime using that fallback stays intact.
struct PoolCreateHostid<'a> {
    parameter: &'a Path,
    effective: &'a Path,
    original: Option<String>,
    previous_effective: u32,
    expected: u32,
}
impl<'a> PoolCreateHostid<'a> {
    fn new(parameter: &'a Path, effective: &'a Path, expected: u32) -> io::Result<Self> {
        let original = fs::read_to_string(parameter)?;
        let previous_effective = effective_hostid(effective)?;
        let mut guard = Self {
            parameter,
            effective,
            original: (previous_effective != expected).then_some(original),
            previous_effective,
            expected,
        };
        if guard.original.is_some() {
            let change = fs::write(parameter, expected.to_string()).and_then(|()| {
                if effective_hostid(effective)? == expected {
                    Ok(())
                } else {
                    Err(refuse("OpenZFS did not accept reviewed pool hostid"))
                }
            });
            if let Err(cause) = change {
                let restored = guard.restore();
                return match restored {
                    Ok(()) => Err(cause),
                    Err(restore) => Err(refuse(format!(
                        "OpenZFS hostid handoff failed: {cause}; Rescue hostid restoration also failed: {restore}"
                    ))),
                };
            }
        }
        Ok(guard)
    }

    fn restore(&mut self) -> io::Result<()> {
        let Some(original) = self.original.as_ref() else {
            return if effective_hostid(self.effective)? == self.expected {
                Ok(())
            } else {
                Err(refuse(
                    "OpenZFS effective hostid changed during pool operation",
                ))
            };
        };
        fs::write(self.parameter, original.trim())?;
        // The prior effective value may have come from /etc/hostid when the
        // raw parameter was zero. Verify the raw override was restored.
        let restored = fs::read_to_string(self.parameter)?;
        if restored.trim() != original.trim()
            || effective_hostid(self.effective)? != self.previous_effective
        {
            return Err(refuse("OpenZFS hostid parameter restoration failed"));
        }
        self.original = None;
        Ok(())
    }
}
impl Drop for PoolCreateHostid<'_> {
    fn drop(&mut self) {
        if self.original.is_some() {
            let _ = self.restore();
        }
    }
}

pub(crate) fn create_with_hostid<T>(
    expected: u32,
    create: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    if std::env::var_os("ZFS_HOSTID").is_some() {
        return Err(refuse(
            "ZFS_HOSTID userspace override conflicts with reviewed pool hostid",
        ));
    }
    create_with_hostid_at(
        Path::new(SPL_HOSTID_PARAMETER),
        Path::new(SPL_EFFECTIVE_HOSTID),
        expected,
        create,
    )
}
fn create_with_hostid_at<T>(
    parameter: &Path,
    effective: &Path,
    expected: u32,
    create: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let mut guard = PoolCreateHostid::new(parameter, effective, expected)?;
    let created = create();
    let restored = guard.restore();
    match (created, restored) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(cause), Ok(())) => Err(cause),
        (Ok(_), Err(cause)) => Err(refuse(format!(
            "native pool operation completed but Rescue hostid restoration failed: {cause}"
        ))),
        (Err(operation), Err(restore)) => Err(refuse(format!(
            "native pool operation failed: {operation}; Rescue hostid restoration also failed: {restore}"
        ))),
    }
}
/// Refuse unless every program of PROGRAMS is an executable file on PATH.
pub(crate) fn require_on_path(programs: &[&str], what: &str) -> io::Result<()> {
    let path =
        std::env::var_os("PATH").ok_or_else(|| refuse("deployment executable PATH is missing"))?;
    let directories: Vec<_> = std::env::split_paths(&path).collect();
    for program in programs {
        if !directories.iter().any(|p| {
            fs::metadata(p.join(program)).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
        }) {
            return Err(refuse(format!(
                "required {what} executable is missing: {program}; not found on PATH={}",
                path.to_string_lossy()
            )));
        }
    }
    Ok(())
}
fn require_native_tools() -> io::Result<()> {
    require_on_path(
        &[
            "zfs",
            "zpool",
            "zdb",
            "sgdisk",
            "sfdisk",
            "partprobe",
            "mkfs.vfat",
        ],
        "deployment",
    )
}
/// A disk deploy follows the caller's erase, whose metadata clearing runs
/// `wipefs`; `deploy DISK` checks for it in its preflight, before that erase.
fn require_erase_tools() -> io::Result<()> {
    require_on_path(&["wipefs"], "erase")
}
/// The attempt directory must preexist, be canonical, private and owned by
/// this effective user. It may be volatile; it holds only the post-install
/// logs of this run (`deploy-ID-post-install-N.log`).
fn attempt_directory(path: &Path) -> io::Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(refuse("deploy attempt directory must use a canonical path"));
    }
    let meta = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?
        .metadata()?;
    if !meta.is_dir() || meta.mode() & 0o077 != 0 || meta.uid() != fs::metadata("/proc/self")?.uid()
    {
        return Err(refuse(
            "deploy attempt directory must be private and owned by this effective user",
        ));
    }
    Ok(canonical)
}
fn bare(disk: &DiskIdentity) -> io::Result<()> {
    let review = device::plan(&disk.path).map_err(refuse)?;
    if review.identity != *disk
        || !review.partitions.is_empty()
        || review.filesystem.is_some()
        || review.partition_table_uuid.is_some()
    {
        return Err(refuse(
            "deploy accepts a bare unused whole disk; review wipe separately for existing layouts",
        ));
    }
    Ok(())
}
fn run(program: &'static str, args: &[String]) -> io::Result<String> {
    if matches!(program, "partprobe" | "mdev")
        || program == "zpool" && args.first().is_some_and(|arg| arg == "sync")
    {
        native::run(program, args).map_err(refuse)
    } else {
        native::run_mutating(program, args).map_err(refuse)
    }
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
/// `zfs create` of the BE with its role: the stock root-on-ZFS
/// `mountpoint=/ canmount=noauto`, so only booting it mounts it. The pool
/// root and `ROOT` are `canmount=off`; the member check refuses anything else.
/// `zpool create`: the pool root never mounts and holds no data.
fn pool_create(pool: &str, partition: &str, operation_id: &str) -> Vec<String> {
    args(&[
        "create",
        "-o",
        "ashift=12",
        "-o",
        "cachefile=none",
        "-O",
        "mountpoint=none",
        "-O",
        "canmount=off",
        "-O",
        "readonly=on",
        "-O",
        "acltype=posixacl",
        "-O",
        "xattr=sa",
        "-O",
        &format!("zboot:pending={operation_id}"),
        pool,
        partition,
    ])
}
/// `zfs create POOL/ROOT`: a container that never mounts.
fn root_create(pool: &str, operation_id: &str) -> Vec<String> {
    args(&[
        "create",
        "-o",
        "mountpoint=none",
        "-o",
        "canmount=off",
        "-o",
        "readonly=on",
        "-o",
        &format!("zboot:pending={operation_id}"),
        &format!("{pool}/ROOT"),
    ])
}
/// The one property deploy sets after creation: the published BE's
/// `readonly=off`.
fn be_publish(dataset: &str) -> Vec<String> {
    args(&["set", "readonly=off", dataset])
}
fn be_create(dataset: &str, operation_id: &str) -> Vec<String> {
    args(&[
        "create",
        "-o",
        "mountpoint=/",
        "-o",
        "canmount=noauto",
        "-o",
        "readonly=off",
        "-o",
        &format!("zboot:pending={operation_id}"),
        dataset,
    ])
}
fn disk_current(review: &CoreReview) -> io::Result<()> {
    if device::observe_identity(&review.disk.path).map_err(refuse)? != review.disk {
        return Err(refuse("deploy disk incarnation changed"));
    }
    Ok(())
}

fn partitions(review: &CoreReview) -> io::Result<(PartitionIdentity, PartitionIdentity)> {
    disk_current(review)?;
    let json = native::run("sfdisk", &args(&["--json", &review.disk.path])).map_err(refuse)?;
    let paths = review.layout.verify_json(&review.disk, &json)?;
    let esp = if let Some(external) = &review.external_esp {
        esp::verify_target(external)?;
        let observed =
            device::observe_partition(&external.target.partition.path).map_err(refuse)?;
        if observed != external.target {
            return Err(refuse("external ESP incarnation changed"));
        }
        observed
    } else {
        device::observe_partition(&paths[0]).map_err(refuse)?
    };
    let zfs = device::observe_partition(paths.last().unwrap()).map_err(refuse)?;
    observe_swap(review, &paths)?;
    if review.external_esp.is_none() {
        review
            .layout
            .verify_partition(&review.disk, &esp, true, false)?;
    }
    review
        .layout
        .verify_partition(&review.disk, &zfs, false, false)?;
    disk_current(review)?;
    Ok((esp, zfs))
}
fn observe_swap(review: &CoreReview, paths: &[String]) -> io::Result<Option<PartitionIdentity>> {
    if review.layout.swap.is_none() {
        return Ok(None);
    }
    let index = usize::from(review.layout.esp_sectors != 0);
    let part = device::observe_partition(&paths[index]).map_err(refuse)?;
    verify_swap(review, &part)?;
    Ok(Some(part))
}
fn verify_swap(review: &CoreReview, part: &PartitionIdentity) -> io::Result<()> {
    let swap = review
        .layout
        .swap
        .as_ref()
        .ok_or_else(|| refuse("unrequested swap partition"))?;
    if part.disk != review.disk
        || part.number != 1 + u32::from(review.layout.esp_sectors != 0)
        || part.readonly
        || part.partition.bytes != swap.sectors * review.disk.logical_sector
        || part
            .partition
            .partition_uuid
            .as_deref()
            .is_none_or(|id| !id.eq_ignore_ascii_case(&swap.uuid))
        || part
            .partition_type
            .as_deref()
            .is_none_or(|kind| !kind.eq_ignore_ascii_case(layout::SWAP_TYPE))
        || part.partition.filesystem.is_some()
        || part.partition.filesystem_uuid.is_some()
    {
        return Err(refuse(
            "deploy swap geometry, PARTUUID or unused contents changed",
        ));
    }
    Ok(())
}
fn observe_swap_current(review: &CoreReview) -> io::Result<Option<PartitionIdentity>> {
    if review.layout.swap.is_none() {
        return Ok(None);
    }
    disk_current(review)?;
    let json = native::run("sfdisk", &args(&["--json", &review.disk.path])).map_err(refuse)?;
    let paths = review.layout.verify_json(&review.disk, &json)?;
    observe_swap(review, &paths)
}
fn observe_member(
    op: &Operation,
    state: &NativeState,
    name: &str,
    saved: Option<&Endpoint>,
    allow_cleared: bool,
) -> io::Result<Endpoint> {
    let d = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == name)
        .ok_or_else(|| refuse(format!("deploy member is missing: {name}")))?;
    let endpoint = Endpoint {
        name: name.into(),
        identity: d.identity.clone(),
    };
    if saved.is_some_and(|e| e != &endpoint) {
        return Err(refuse("deploy native dataset incarnation changed"));
    }
    let props = state
        .dataset_properties
        .get(name)
        .ok_or_else(|| refuse("deploy dataset properties missing"))?;
    let marker = props.get("zboot:pending");
    if !(marker.is_some_and(|p| p.value == op.review.operation_id && p.source == "local")
        || allow_cleared && saved.is_some() && marker.is_none())
    {
        return Err(refuse("deploy does not own the native dataset marker"));
    }
    if d.mounted != Some(false)
        || d.origin.is_some()
        || d.encryption != zfs_tools::engine::Encryption::Off
    {
        return Err(refuse(
            "deploy member has unexpected mount, origin or encryption",
        ));
    }
    // Supported OpenZFS builds report SA xattrs as either `sa` or its
    // canonical alias `on`; directory-backed xattrs are reported as `dir`.
    let be = op.review.factory.is_some() && name == op.review.selection.dataset();
    if d.kind != zfs_tools::engine::DatasetKind::Filesystem
        || d.readonly == be
        || d.canmount
            != Some(if be {
                zfs_tools::engine::CanMount::NoAuto
            } else {
                zfs_tools::engine::CanMount::Off
            })
        || d.mountpoint.as_deref() != Some(if be { "/" } else { "none" })
        || props
            .get("xattr")
            .is_none_or(|p| !matches!(p.value.as_str(), "sa" | "on"))
        || props
            .get("acltype")
            .is_none_or(|p| !matches!(p.value.as_str(), "posix" | "posixacl"))
        || props
            .keys()
            .any(|key| zfs_tools::engine::management::managed_key(key) && key != "zboot:pending")
    {
        return Err(refuse(
            "deploy member properties differ from the declared fresh layout",
        ));
    }
    Ok(endpoint)
}
fn bound_members(op: &Operation, allow_cleared: bool) -> io::Result<NativeState> {
    disk_current(&op.review)?;
    let (esp, zfs) = partitions(&op.review)?;
    if op.review.external_esp.is_none() {
        op.review
            .layout
            .verify_partition(&op.review.disk, &esp, true, true)?;
    }
    if let Some(saved) = &op.swap
        && observe_swap_current(&op.review)?.as_ref() != Some(saved)
    {
        return Err(refuse("swap partition identity changed"));
    }
    if op
        .zfs
        .as_ref()
        .is_some_and(|p| p.partition.partition_uuid != zfs.partition.partition_uuid)
    {
        return Err(refuse("deploy pool partition changed"));
    }
    let state = state::observe().map_err(refuse)?;
    for saved in [&op.pool, &op.root, &op.be].into_iter().flatten() {
        observe_member(op, &state, &saved.name, Some(saved), allow_cleared)?;
    }
    if let Some(pool) = &op.pool {
        let (storage, pool_status) =
            device::observe_pool_storage_and_status(&pool.name, &pool.identity.pool_guid)
                .map_err(refuse)?;
        if storage.disks != [op.review.disk.clone()] {
            return Err(refuse("deploy pool storage escaped its declared disk"));
        }
        let leaf = single_pool_leaf_value(&pool_status)?;
        if fs::canonicalize(leaf)? != fs::canonicalize(&zfs.partition.path)? {
            return Err(refuse(
                "deploy pool is not backed by its exact declared ZFS partition",
            ));
        }
        let expected: Vec<_> = [&op.pool, &op.root, &op.be]
            .into_iter()
            .flatten()
            .map(|e| e.name.as_str())
            .collect();
        if state.inspection.datasets.iter().any(|d| {
            d.identity.pool_guid == pool.identity.pool_guid && !expected.contains(&d.name.as_str())
        }) {
            return Err(refuse("deploy pool contains unexpected datasets"));
        }
        // Only the BE's own @factory and @deployed markers may exist.
        let ours = [
            snapshot(op, FACTORY_SNAPSHOT),
            snapshot(op, DEPLOYED_SNAPSHOT),
        ];
        if state.inspection.snapshots.as_ref().is_none_or(|points| {
            points.iter().any(|p| {
                p.identity.pool_guid == pool.identity.pool_guid
                    && (op.review.factory.is_none() || !ours.contains(&p.name))
            })
        }) {
            return Err(refuse("deploy target has unexpected snapshots"));
        }
    }
    Ok(state)
}
#[cfg(test)]
fn single_pool_leaf(text: &str, pool: &str) -> io::Result<String> {
    single_pool_leaf_value(&device::parse_single_pool_status(text, pool).map_err(refuse)?)
}
fn single_pool_leaf_value(pool: &serde_json::Value) -> io::Result<String> {
    fn visit(value: &serde_json::Value, paths: &mut Vec<String>) -> io::Result<()> {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(path) = map.get("path") {
                    if map.get("vdev_type").and_then(|v| v.as_str()) != Some("disk") {
                        return Err(refuse("deploy pool has an unsupported storage leaf"));
                    }
                    paths.push(
                        path.as_str()
                            .filter(|p| p.starts_with("/dev/"))
                            .ok_or_else(|| refuse("deploy pool leaf is not a block path"))?
                            .into(),
                    );
                }
                if let Some(kind) = map.get("vdev_type").and_then(|v| v.as_str())
                    && !matches!(kind, "root" | "disk")
                {
                    return Err(refuse(
                        "deploy supports one direct disk partition vdev only",
                    ));
                }
                for child in map.values() {
                    visit(child, paths)?;
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    visit(child, paths)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut paths = Vec::new();
    visit(pool, &mut paths)?;
    if paths.len() != 1 {
        return Err(refuse("deploy pool gained additional storage leaves"));
    }
    Ok(paths.remove(0))
}
fn gap(stage: &str) -> io::Error {
    refuse(format!(
        "deploy {stage} result is not proven; preserve this target and inspect it before a separately reviewed restart"
    ))
}
fn gap_detail(stage: &str, cause: impl std::fmt::Display) -> io::Error {
    refuse(format!("{}: {cause}", gap(stage)))
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RootView {
    ReadOnly,
    Write,
    Configure,
}
fn root_view<T: Send>(
    op: &Operation,
    view: RootView,
    work: impl FnOnce(&Path) -> io::Result<T> + Send,
) -> io::Result<T> {
    use nix::mount::{MsFlags, mount};
    let be = op
        .be
        .as_ref()
        .ok_or_else(|| refuse("deploy BE identity missing"))?;
    bound_members(op, op.published)?;
    let flags = MsFlags::MS_NOSUID
        | MsFlags::MS_NODEV
        | if view == RootView::Configure {
            MsFlags::empty()
        } else {
            MsFlags::MS_NOEXEC
        }
        | if view == RootView::ReadOnly {
            MsFlags::MS_RDONLY
        } else {
            MsFlags::empty()
        };
    crate::mount_view::with_private_mount(
        "deploy",
        || Ok(()),
        |path| {
            mount(
                Some(be.name.as_str()),
                path,
                Some("zfs"),
                flags,
                Some("zfsutil"),
            )
            .map_err(refuse)
        },
        work,
    )
}
fn revalidate_overlays(review: &CoreReview) -> io::Result<()> {
    for selected in ordered_overlays(review) {
        if overlay::again(selected)? != *selected {
            return Err(refuse("deploy overlay changed before application"));
        }
    }
    Ok(())
}
fn revalidate_inputs(review: &CoreReview) -> io::Result<()> {
    revalidate_overlays(review)?;
    if review
        .factory
        .as_ref()
        .map(|f| factory::root_tar::inspect(&f.path).map(|now| now != *f))
        .transpose()?
        .unwrap_or(false)
        || review.artifacts.revalidate().is_err()
    {
        return Err(refuse("deploy selected OS or boot artifact changed"));
    }
    Ok(())
}
/// One deploy, start to finish. Every effect is followed by a fresh native
/// observation of what it made; nothing is recorded for a later run.
fn execute(review: &CoreReview, logs: &Path) -> io::Result<CoreOutcome> {
    let mut op = Operation {
        review: review.clone(),
        swap: None,
        esp: None,
        zfs: None,
        pool: None,
        root: None,
        be: None,
        esp_review: None,
        boot_files: BTreeMap::new(),
        final_content: None,
        export_intent: None,
        published: false,
    };

    // Partition. The caller's `device::wipe` left the disk bare and verified
    // it; it must still be the reviewed disk, bare and unused.
    bare(&op.review.disk)?;
    let r = &op.review;
    if !fresh_image(r) {
        // The one gap the wipe leaves: after an NVMe sanitize, LBA 0 holds
        // whatever the controller returns. A stray 0x55AA boot signature there
        // is no partition table to libblkid, so the wipe verifies, but sgdisk
        // then reads the disk as MBR and refuses to write a GPT ("Non-GPT
        // disk", exit 3). Zapping first leaves neither MBR nor GPT; after
        // metadata clearing it repeats what the wipe did. A new image file is
        // all zeros.
        run("sgdisk", &args(&["--zap-all", &r.disk.path]))?;
    }
    run("sgdisk", &r.layout.partition_args(&r.disk)?)?;
    run("partprobe", &args(&[&r.disk.path]))?;
    // The independent BusyBox recovery substrate has no udev daemon. Its
    // kernel partition inventory is authoritative, but /dev nodes need an
    // explicit refresh after rereading GPT.
    if std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|directory| {
            fs::metadata(directory.join("mdev"))
                .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
        })
    }) {
        run("mdev", &args(&["-s"]))?;
    }
    let (esp, zfs) =
        partitions(&op.review).map_err(|cause| gap_detail("partition table", cause))?;
    if op.review.external_esp.is_none() && esp.partition.filesystem.is_some()
        || zfs.partition.filesystem.is_some()
    {
        return Err(gap("new partition contents"));
    }
    op.swap = observe_swap_current(&op.review)?;
    if op
        .swap
        .as_ref()
        .is_some_and(|p| p.partition.filesystem.is_some())
    {
        return Err(gap("new swap partition contents"));
    }
    op.zfs = Some(zfs);

    // Format the ESP.
    if op.review.external_esp.is_none() {
        run(
            "mkfs.vfat",
            &args(&[
                "-F",
                "32",
                "-i",
                &op.review.layout.fat_id,
                "-n",
                "ZBOOT-ESP",
                &esp.partition.path,
            ]),
        )?;
    }
    let (esp, zfs) = partitions(&op.review)?;
    if op.review.external_esp.is_none() {
        op.review
            .layout
            .verify_partition(&op.review.disk, &esp, true, true)
            .map_err(|cause| gap_detail("ESP format", cause))?;
    }
    if Some(&zfs) != op.zfs.as_ref() {
        return Err(refuse("ZFS partition changed during ESP formatting"));
    }
    op.esp = Some(esp);

    // Create the pool, then ROOT.
    let state = state::observe().map_err(refuse)?;
    if state
        .inspection
        .pools
        .iter()
        .any(|p| p.name == op.review.selection.pool)
    {
        return Err(refuse("deploy pool name became occupied"));
    }
    let expected_hostid = u32::from_str_radix(&op.review.hostid, 16)
        .map_err(|_| refuse("invalid reviewed deploy hostid"))?;
    create_with_hostid(expected_hostid, || {
        run(
            "zpool",
            &pool_create(
                &op.review.selection.pool,
                &zfs.partition.path,
                &op.review.operation_id,
            ),
        )
    })?;
    let state = state::observe().map_err(refuse)?;
    let endpoint = observe_member(&op, &state, &op.review.selection.pool, None, false)
        .map_err(|cause| gap_detail("pool creation", cause))?;
    op.pool = Some(endpoint);
    bound_members(&op, false)?;
    read_labels(&op).map_err(|cause| gap_detail("pool creation hostid", cause))?;
    run(
        "zfs",
        &root_create(&op.review.selection.pool, &op.review.operation_id),
    )?;
    let state = state::observe().map_err(refuse)?;
    op.root = Some(
        observe_member(
            &op,
            &state,
            &format!("{}/ROOT", op.review.selection.pool),
            None,
            false,
        )
        .map_err(|cause| gap_detail("ROOT creation", cause))?,
    );
    bound_members(&op, false)?;

    let factory = op.review.factory.clone();
    if let Some(factory) = &factory {
        // Create the BE and extract the root tar into it.
        run(
            "zfs",
            &be_create(op.review.selection.dataset(), &op.review.operation_id),
        )?;
        let state = state::observe().map_err(refuse)?;
        op.be = Some(
            observe_member(&op, &state, op.review.selection.dataset(), None, false)
                .map_err(|cause| gap_detail("BE creation", cause))?,
        );
        bound_members(&op, false)?;
        root_view(&op, RootView::Write, |root| {
            factory::root_tar::extract(factory, root)
        })?;
        run("zpool", &args(&["sync", &op.review.selection.pool]))?;
        // The snapshot marks a complete extraction; a failed overlay goes
        // back to it.
        run(
            "zfs",
            &args(&["snapshot", &snapshot(&op, FACTORY_SNAPSHOT)]),
        )?;
        if !snapshot_exists(&op, FACTORY_SNAPSHOT)? {
            return Err(gap("OS extraction (no @factory snapshot)"));
        }
        root_view(&op, RootView::ReadOnly, |root| {
            factory::root_tar::boot_files(factory, root)
        })
        .map_err(|cause| gap_detail("OS extraction", cause))?;

        // Overlays, hooks and identity. A hook is never replayed: after a
        // failure the unpublished BE goes back to @factory.
        let configured = root_view(&op, RootView::Configure, |root| {
            configure(&mut NativeConfigure {
                op: &op,
                root,
                logs,
            })?;
            factory::root_tar::boot_files(factory, root)
        });
        match configured {
            Ok(files) => op.boot_files = files,
            Err(error) => {
                recreate(&mut op).map_err(|again| {
                    refuse(format!(
                        "{error}; and the BE could not go back to @factory: {again}"
                    ))
                })?;
                return Err(refuse(format!(
                    "{error}; the unpublished BE is back at @factory"
                )));
            }
        }
        if op.boot_files.values().any(|file| file.bytes == 0) {
            return Err(refuse("deploy configured boot evidence is invalid"));
        }

        // Seal: sync, record the content and snapshot @deployed.
        bound_members(&op, false)?;
        run("zpool", &args(&["sync", &op.review.selection.pool]))?;
        let (content, boot) = root_view(&op, RootView::ReadOnly, |root| {
            Ok((
                content::filesystem(root)?,
                factory::root_tar::boot_files(factory, root)?,
            ))
        })?;
        if boot != op.boot_files {
            return Err(refuse("deploy boot files changed after configuration"));
        }
        content.validate()?;
        run(
            "zfs",
            &args(&["snapshot", &snapshot(&op, DEPLOYED_SNAPSHOT)]),
        )?;
        op.final_content = Some(content);
    }

    // Install the loader on the ESP.
    bound_members(&op, false)?;
    let esp_review = if let Some(external) = &op.review.external_esp {
        esp::revalidate(external)?;
        external.clone()
    } else {
        esp::plan_loader(
            &op.esp.as_ref().unwrap().partition.path,
            &op.review.artifacts,
            true,
        )?
    };
    if esp_review.target != *op.esp.as_ref().unwrap()
        || op.review.external_esp.is_none() && esp_review.previous.values().any(Option::is_some)
    {
        return Err(refuse("new ESP unexpectedly contains owned boot files"));
    }
    esp::apply(&esp_review, &esp_review.loss_token)?;
    op.esp_review = Some(esp_review);
    verify_configured_root(&op)?;
    bound_members(&op, false)?;

    // Publish, once every check above has passed. From here a member's
    // pending fence may already be cleared.
    op.published = true;
    if op.review.factory.is_some() {
        run("zfs", &be_publish(op.review.selection.dataset()))?;
    }
    for name in [&op.pool, &op.root, &op.be]
        .into_iter()
        .flatten()
        .map(|e| &e.name)
    {
        bound_members(&op, true)?;
        let props = state::observe()
            .map_err(refuse)?
            .dataset_properties
            .remove(name)
            .ok_or_else(|| refuse("deploy properties missing"))?;
        if props.contains_key("zboot:pending") {
            run("zfs", &args(&["inherit", "zboot:pending", name]))?;
        }
    }
    // bootfs is published last, after every check and fence release.
    if publishes_default(&op.review) {
        bound_members(&op, true)?;
        run(
            "zpool",
            &publish_default_args(&op.review.selection.pool, op.review.selection.dataset()),
        )?;
    }
    run("zpool", &args(&["sync", &op.review.selection.pool]))?;
    verify_installed_state(&op)?;
    let evidence = read_labels(&op)?;
    if evidence.exported {
        return Err(refuse("deploy pool unexpectedly exported before handoff"));
    }
    op.export_intent = Some(evidence);

    // Export.
    let export = || run("zpool", &args(&["export", &op.review.selection.pool]));
    if is_portable(&op.review) {
        create_with_hostid(0, export)?;
    } else {
        export()?;
    }
    verify_exported(&op)?;
    Ok(outcome(op))
}
const FACTORY_SNAPSHOT: &str = "factory";
const DEPLOYED_SNAPSHOT: &str = "deployed";
fn snapshot(op: &Operation, name: &str) -> String {
    format!("{}@{name}", op.review.selection.dataset())
}
fn snapshot_exists(op: &Operation, name: &str) -> io::Result<bool> {
    let wanted = snapshot(op, name);
    Ok(bound_members(op, false)?
        .inspection
        .snapshots
        .iter()
        .flatten()
        .any(|s| s.name == wanted))
}
/// Put the unpublished BE back to its extracted factory state.
fn recreate(op: &mut Operation) -> io::Result<()> {
    if !snapshot_exists(op, FACTORY_SNAPSHOT)? {
        return Err(refuse("the BE has no @factory snapshot to go back to"));
    }
    run(
        "zfs",
        &args(&["rollback", "-r", &snapshot(op, FACTORY_SNAPSHOT)]),
    )?;
    op.boot_files.clear();
    Ok(())
}
/// Each user overlay's files and hook run together. Identity is enforced
/// afterwards; the portable layer is last and every rebuilt initrd is checked.
trait Configure {
    fn overlay_count(&self) -> usize;
    fn rootfs(&mut self, index: usize) -> io::Result<()>;
    fn post_install(&mut self, index: usize) -> io::Result<()>;
    fn enforce_identity(&mut self) -> io::Result<()>;
    fn portable(&mut self) -> io::Result<()>;
    fn verify_portable(&mut self) -> io::Result<()>;
}
fn configure(steps: &mut impl Configure) -> io::Result<()> {
    for index in 0..steps.overlay_count() {
        steps.rootfs(index)?;
        steps.post_install(index)?;
    }
    // Do not copy a user-supplied hostid into a portable initrd.
    steps.enforce_identity()?;
    steps.portable()?;
    steps.enforce_identity()?;
    steps.verify_portable()
}
struct NativeConfigure<'a> {
    op: &'a Operation,
    root: &'a Path,
    /// The attempt directory that receives each hook's log.
    logs: &'a Path,
}
impl NativeConfigure<'_> {
    fn hostid(&self) -> io::Result<u32> {
        u32::from_str_radix(&self.op.review.hostid, 16).map_err(refuse)
    }
    fn hostname(&self) -> Option<&str> {
        self.op.review.selection.hostname.as_deref()
    }
    fn overlays(&self) -> Vec<&overlay::Overlay> {
        let mut all = ordered_overlays(&self.op.review);
        if is_portable(&self.op.review) {
            all.pop();
        }
        all
    }
    fn install_hook(&self, overlay: &overlay::Overlay, index: usize) -> io::Result<()> {
        if overlay.post_install.is_none() {
            return Ok(());
        }
        let log = self.logs.join(format!(
            "deploy-{}-post-install-{index}.log",
            self.op.review.operation_id
        ));
        overlay::post_install(
            self.root,
            overlay,
            &[
                ("ZBOOT_HOSTID", self.op.review.hostid.clone()),
                ("ZBOOT_POOL", self.op.review.selection.pool.clone()),
                ("ZBOOT_BE", self.op.review.selection.dataset().to_owned()),
            ],
            &log,
        )
    }
}
impl Configure for NativeConfigure<'_> {
    fn overlay_count(&self) -> usize {
        self.overlays().len()
    }
    fn rootfs(&mut self, index: usize) -> io::Result<()> {
        overlay::apply(self.root, self.overlays()[index])
    }
    fn post_install(&mut self, index: usize) -> io::Result<()> {
        self.install_hook(self.overlays()[index], index)
    }
    fn enforce_identity(&mut self) -> io::Result<()> {
        if is_portable(&self.op.review) {
            identity::portable(self.root, self.hostname())
        } else {
            identity::enforce(self.root, self.hostid()?, self.hostname())
        }
    }
    fn portable(&mut self) -> io::Result<()> {
        if !is_portable(&self.op.review) {
            return Ok(());
        }
        portable::require_tools(self.root)?;
        let portable = self
            .op
            .review
            .overlays
            .last()
            .ok_or_else(|| refuse("portable overlay evidence missing"))?;
        overlay::apply(self.root, portable)?;
        self.install_hook(portable, self.overlays().len())
    }
    fn verify_portable(&mut self) -> io::Result<()> {
        if !is_portable(&self.op.review) {
            return Ok(());
        }
        portable::verify_every_initrd(
            self.root,
            self.op
                .review
                .overlays
                .last()
                .ok_or_else(|| refuse("portable overlay evidence missing"))?,
        )
    }
}

fn outcome(op: Operation) -> CoreOutcome {
    CoreOutcome {
        operation_id: op.review.operation_id,
        journal_directory: op.review.selection.journal_directory,
        disk: op.review.disk,
        pool: op.pool.unwrap(),
        dataset: op.be,
        root: op.root.unwrap(),
        swap: op.swap,
        external_boot_dependency: op.review.external_esp.is_some(),
        firmware_selection: "Select EFI/zboot/zboot.efi in firmware; no NVRAM changes were made"
            .into(),
        esp: op.esp.unwrap(),
        complete: true,
        exported: true,
    }
}
fn read_labels(op: &Operation) -> io::Result<labels::Evidence> {
    let (_, partition) = partitions(&op.review)?;
    let evidence = labels::parse(
        &native::run("zdb", &args(&["-lll", &partition.partition.path])).map_err(refuse)?,
    )?;
    if device::observe_partition(&partition.partition.path).map_err(refuse)? != partition
        || evidence.pool != op.review.selection.pool
        || evidence.hostid != expected_label_hostid(&op.review)?
        || op
            .pool
            .as_ref()
            .is_none_or(|p| p.identity.pool_guid.to_string() != evidence.pool_guid)
    {
        return Err(refuse(
            "deploy pool labels changed physical or native identity",
        ));
    }
    disk_current(&op.review)?;
    Ok(evidence)
}
fn verify_exported(op: &Operation) -> io::Result<()> {
    let (esp, _) = partitions(&op.review)?;
    if Some(&esp) != op.esp.as_ref() {
        return Err(refuse("deploy ESP incarnation changed after export"));
    }
    let state = state::observe().map_err(refuse)?;
    let pool = op
        .pool
        .as_ref()
        .ok_or_else(|| refuse("deploy exported pool identity missing"))?;
    if state
        .inspection
        .pools
        .iter()
        .any(|p| p.name == pool.name || p.guid == pool.identity.pool_guid)
    {
        return Err(refuse("deployed pool is not cleanly exported"));
    }
    let evidence = read_labels(op)?;
    if !evidence.exported
        || !evidence.same_incarnation(
            op.export_intent
                .as_ref()
                .ok_or_else(|| refuse("deploy export intent missing"))?,
        )
    {
        return Err(refuse(
            "deployed pool export generation changed or was not proven",
        ));
    }
    verify_esp(op)
}
fn verify_installed_state(op: &Operation) -> io::Result<()> {
    let state = bound_members(op, true)?;
    let pool = state
        .inspection
        .pools
        .iter()
        .find(|p| p.name == op.review.selection.pool)
        .ok_or_else(|| refuse("deploy pool disappeared"))?;
    if op.review.factory.is_none() {
        if pool.bootfs.is_some()
            || [&op.pool, &op.root]
                .into_iter()
                .flatten()
                .any(|e| state.dataset_properties[&e.name].contains_key("zboot:pending"))
        {
            return Err(refuse(
                "empty-root acquired bootfs or retained pending ownership",
            ));
        }
        return verify_esp(op);
    }
    let be = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == op.review.selection.dataset())
        .ok_or_else(|| refuse("deploy BE disappeared"))?;
    if pool.bootfs.as_deref()
        != if is_portable(&op.review) {
            None
        } else {
            Some(op.review.selection.dataset())
        }
        || be.readonly
        || be.canmount != Some(zfs_tools::engine::CanMount::NoAuto)
        || be.mountpoint.as_deref() != Some("/")
        || be.mounted != Some(false)
        || [&op.pool, &op.root, &op.be]
            .into_iter()
            .flatten()
            .any(|e| state.dataset_properties[&e.name].contains_key("zboot:pending"))
    {
        return Err(refuse(
            "deploy final boot selection or publication fence did not verify",
        ));
    }
    verify_esp(op)?;
    verify_configured_root(op)?;
    Ok(())
}
fn verify_esp(op: &Operation) -> io::Result<()> {
    let child = op
        .esp_review
        .as_ref()
        .ok_or_else(|| refuse("deploy ESP child evidence missing"))?;
    let installed = esp::inspect_reviewed(child)?;
    let expected = &op.review.artifacts.sha256;
    if child.target != *op.esp.as_ref().unwrap()
        || installed
            .values()
            .any(|f| f.as_ref().is_none_or(|f| f.sha256 != *expected))
    {
        return Err(refuse("deploy ESP final readback changed"));
    }
    Ok(())
}
fn verify_configured_root(op: &Operation) -> io::Result<()> {
    if op.review.factory.is_none() {
        return Ok(());
    }
    if op.final_content.as_ref() != Some(&root_view(op, RootView::ReadOnly, content::filesystem)?) {
        return Err(refuse(
            "configured deploy OS content changed before completion",
        ));
    }
    Ok(())
}
fn apply_core(review: &CoreReview, consent: &str) -> io::Result<CoreOutcome> {
    validate(review)?;
    if consent != review.loss_token {
        return Err(refuse(
            "exact deploy disk/layout/OS consent token does not match",
        ));
    }
    apply_with_core(review, consent)
}
fn apply_with_core(review: &CoreReview, consent: &str) -> io::Result<CoreOutcome> {
    if is_portable(review) {
        portable::without_hostid(|| apply_native_core(review, consent))
    } else {
        apply_native_core(review, consent)
    }
}
fn apply_native_core(review: &CoreReview, consent: &str) -> io::Result<CoreOutcome> {
    validate(review)?;
    if fresh_image(review) && !image::registered_disk(&review.disk)? {
        return Err(refuse(
            "new image deploy lost its created-file loop authority",
        ));
    }
    if consent != review.loss_token {
        return Err(refuse(
            "exact deploy disk/layout/OS consent token does not match",
        ));
    }
    require_native_tools()?;
    if let Some(external) = &review.external_esp {
        esp::revalidate(external)?;
    }
    let logs = attempt_directory(&review.selection.journal_directory)?;
    // The selected inputs are checked again before the first write.
    revalidate_inputs(review)?;
    execute(review, &logs).map_err(|e| {
        let recovery = if fresh_image(review) {
            "stopped; run deploy again"
        } else {
            "stopped after erasing; inspect the disk, then run deploy again"
        };
        refuse(format!("deploy {} {recovery}: {e}", review.operation_id))
    })
}
#[cfg(test)]
mod tests;
