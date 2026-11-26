//! zboot's loader files on an existing GPT/FAT ESP; formatting belongs to
//! deploy. zboot writes exactly two paths on an ESP, `EFI/zboot/zboot.efi`
//! and the firmware fallback `EFI/BOOT/BOOTX64.EFI`, and nothing else. Its
//! own UKIs under other names directly in `EFI/zboot/`, which earlier builds
//! refreshed in place, are reported as stale and left alone. The kernel's
//! vfat driver matches names without regard to case.
use crate::{
    device::{self, PartitionIdentity},
    loader::EfiFile,
};
use nix::mount::{MsFlags, mount};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use crate::deploy::layout::ESP_TYPE;
/// zboot's directory. Its own UKIs there under other names are stale.
const DIRECTORY: &str = "EFI/zboot";
/// The name firmware entries point at.
const CANONICAL: &str = "EFI/zboot/zboot.efi";
/// The firmware's default path, which boots a disk without a boot entry.
const FALLBACK: &str = "EFI/BOOT/BOOTX64.EFI";
/// zboot's two paths, as findings list them.
const PATHS: [&str; 2] = [CANONICAL, FALLBACK];
/// The ESP review's schema, as its JSON reports it.
const SCHEMA: u32 = 4;
const MIB: u64 = 1024 * 1024;
const METADATA_RESERVE: u64 = 16 * MIB;
fn refuse(value: impl ToString) -> std::io::Error {
    std::io::Error::other(value.to_string())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub sha256: String,
    pub bytes: u64,
}
/// One ESP's reviewed write: the partition, the UKI and the preimage of each
/// owned path it writes, bound by `loss_token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspReview {
    pub schema_version: u32,
    pub target: PartitionIdentity,
    pub artifacts: EfiFile,
    pub previous: BTreeMap<String, Option<FileIdentity>>,
    pub loss_token: String,
}
pub(crate) fn validate_target(target: &PartitionIdentity) -> std::io::Result<()> {
    if target
        .partition_type
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some(ESP_TYPE)
        || target.partition.filesystem.as_deref() != Some("vfat")
        || target
            .partition
            .partition_uuid
            .as_ref()
            .is_none_or(String::is_empty)
        || target
            .partition
            .filesystem_uuid
            .as_ref()
            .is_none_or(String::is_empty)
        || target.number == 0
    {
        return Err(refuse(
            "EFI installation requires an identity-bound existing GPT/FAT ESP; use deploy to create it",
        ));
    }
    Ok(())
}
fn writable_target(target: &PartitionIdentity) -> std::io::Result<()> {
    validate_target(target)?;
    if target.readonly {
        return Err(refuse("ESP device is readonly"));
    }
    Ok(())
}
fn available_bytes(root: &Path) -> std::io::Result<u64> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let info = rustix::fs::fstatvfs(&directory).map_err(refuse)?;
    info.f_bavail
        .checked_mul(info.f_frsize)
        .ok_or_else(|| refuse("ESP available capacity overflow"))
}
fn payload_allocation(bytes: u64) -> std::io::Result<u64> {
    if bytes == 0 {
        return Err(refuse("ESP payload is empty"));
    }
    bytes
        .checked_next_multiple_of(MIB)
        .ok_or_else(|| refuse("ESP payload capacity overflow"))
}
/// The free space REVIEW's writes need at their peak, in write order: each
/// stages a whole new copy before its rename frees the old file. A path
/// that already holds the new bytes is not written.
fn required_space(review: &EspReview) -> std::io::Result<u64> {
    let expected = review.artifacts.identity()?;
    let staged = i128::from(payload_allocation(expected.bytes)?);
    let (mut peak, mut growth) = (0_i128, 0_i128);
    for (_, previous) in ordered(review) {
        if previous.as_ref() == Some(&expected) {
            continue;
        }
        peak = peak.max(growth + staged);
        growth += staged - i128::from(previous.as_ref().map_or(0, |file| file.bytes));
    }
    if peak == 0 {
        return Ok(0);
    }
    u64::try_from(peak)
        .ok()
        .and_then(|bytes| bytes.checked_add(METADATA_RESERVE))
        .ok_or_else(|| refuse("ESP replacement capacity overflow"))
}
/// The one free-space check, made when the write is planned.
fn require_capacity(review: &EspReview, available: u64) -> std::io::Result<()> {
    let minimum = required_space(review)?;
    if available < minimum {
        return Err(refuse(format!(
            "ESP {} has {available} bytes free; writing zboot's loader needs {minimum}",
            zfs_tools::engine::escape_display(&review.target.partition.path)
        )));
    }
    Ok(())
}
pub(crate) fn current(target: &PartitionIdentity) -> std::io::Result<()> {
    if device::observe_partition(&target.partition.path).map_err(refuse)? != *target {
        return Err(refuse("ESP identity changed since review"));
    }
    Ok(())
}
pub(crate) fn mounted<T: Send>(
    target: &PartitionIdentity,
    writable: bool,
    f: impl FnOnce(&Path) -> std::io::Result<T> + Send,
) -> std::io::Result<T> {
    if !writable {
        validate_target(target)?;
        return crate::mount_view::readonly(
            crate::mount_view::Source::Vfat {
                path: &target.partition.path,
                device_number: &target.partition.device_number,
            },
            || current(target),
            f,
        );
    }
    writable_target(target)?;
    crate::mount_view::with_private_mount(
        "esp",
        || current(target),
        |root| {
            mount(
                Some(target.partition.path.as_str()),
                root,
                Some("vfat"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("uid=0,gid=0,umask=0077,utf8=1"),
            )
            .map_err(refuse)
        },
        |root| {
            current(target)?;
            let result = f(root)?;
            File::open(root)?.sync_all()?;
            current(target)?;
            Ok(result)
        },
    )
}
fn checked(root: &Path, relative: &str, create: bool) -> std::io::Result<PathBuf> {
    let mut path = root.to_path_buf();
    let names: Vec<_> = relative.split('/').collect();
    if names
        .iter()
        .any(|n| n.is_empty() || *n == "." || *n == "..")
    {
        return Err(refuse("invalid owned ESP path"));
    }
    for (i, name) in names.iter().enumerate() {
        path.push(name);
        if i + 1 == names.len() {
            break;
        }
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(refuse("ESP loader ancestor is not a directory")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                fs::DirBuilder::new().mode(0o700).create(&path)?;
                zfs_tools::engine::effect::mark();
                File::open(path.parent().unwrap())?.sync_all()?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(path)
}
/// The regular file at the ESP path PATH, opened without following a link,
/// or `None` when nothing is there.
fn open_existing(root: &Path, path: &str) -> std::io::Result<Option<File>> {
    let path = match checked(root, path, false) {
        Ok(path) => path,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 1024 * MIB {
        return Err(refuse(
            "existing EFI file is not a regular file of at most 1 GiB",
        ));
    }
    Ok(Some(file))
}
fn identity(root: &Path, path: &str) -> std::io::Result<Option<FileIdentity>> {
    let Some(mut file) = open_existing(root, path)? else {
        return Ok(None);
    };
    let (sha256, bytes) = crate::loader::hash(&mut file)?;
    Ok(Some(FileIdentity { sha256, bytes }))
}
/// Whose file the ESP path PATH holds, with its bytes; `None` when nothing
/// is there.
fn examine(root: &Path, path: &str) -> std::io::Result<Option<(LoaderOwner, FileIdentity)>> {
    let Some(mut file) = open_existing(root, path)? else {
        return Ok(None);
    };
    let before = file.metadata()?;
    let owner = loader_owner(&mut file)?;
    let (sha256, bytes) = crate::loader::hash(&mut file)?;
    if !crate::loader::stable(&before, &file.metadata()?) {
        return Err(refuse("ESP loader changed while it was read"));
    }
    Ok(Some((owner, FileIdentity { sha256, bytes })))
}
/// zboot's own UKIs directly in [`DIRECTORY`] under any name but
/// `zboot.efi`: names earlier builds refreshed in place. zboot no longer
/// writes them, so a firmware entry still pointed at one boots an old
/// loader. Subdirectories, other systems' files and staged copies `atomic`
/// left behind are not reported.
fn stale_at(root: &Path) -> std::io::Result<Vec<String>> {
    let directory = match checked(root, CANONICAL, false) {
        Ok(path) => path.parent().unwrap().to_path_buf(),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut stale = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        if lower == "zboot.efi"
            || lower.starts_with(".zboot-") && lower.ends_with(".tmp")
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(entry.path())
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(refuse(format!("{DIRECTORY}/{name}: {error}"))),
        };
        if file.metadata()?.is_file() && loader_owner(&mut file)? == LoaderOwner::Zboot {
            stale.push(format!("{DIRECTORY}/{name}"));
        }
    }
    stale.sort();
    Ok(stale)
}
fn token(review: &EspReview) -> std::io::Result<String> {
    let mut clean = review.clone();
    clean.loss_token.clear();
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&clean).map_err(refuse)?)
    ))
}
fn review(
    target: PartitionIdentity,
    artifacts: EfiFile,
    previous: BTreeMap<String, Option<FileIdentity>>,
    available: u64,
) -> std::io::Result<EspReview> {
    validate_target(&target)?;
    artifacts.validate()?;
    let mut review = EspReview {
        schema_version: SCHEMA,
        target,
        artifacts,
        previous,
        loss_token: String::new(),
    };
    require_capacity(&review, available)?;
    review.loss_token = token(&review)?;
    Ok(review)
}
/// Deploy's write of LOADER on the ESP at PARTITION: `EFI/zboot/zboot.efi`,
/// and the fallback only when REPLACE_FALLBACK. Deploy's own new ESP takes
/// both; an existing ESP on another disk (`--esp-partition`) keeps its
/// fallback. Another system's file at either path is refused in the same
/// observation that binds the write set; `esp PART` replaces one after a
/// typed answer.
pub fn plan_loader(
    partition: &str,
    loader: &EfiFile,
    replace_fallback: bool,
) -> std::io::Result<EspReview> {
    loader.revalidate()?;
    let target = device::observe_partition(partition).map_err(refuse)?;
    writable_target(&target)?;
    mounted(&target, false, |root| {
        deploy_review(
            target.clone(),
            loader,
            root,
            replace_fallback,
            available_bytes(root)?,
        )
    })
}
fn deploy_review(
    target: PartitionIdentity,
    loader: &EfiFile,
    root: &Path,
    replace_fallback: bool,
    available: u64,
) -> std::io::Result<EspReview> {
    let found = findings(root)?;
    if let Some(file) = found
        .iter()
        .find(|file| file.identity.is_some() && !file.owned)
    {
        return Err(refuse(format!(
            "ESP loader {} belongs to another system. Preserve that loader and choose another ESP for deployment",
            file.path
        )));
    }
    let previous = found
        .into_iter()
        .filter(|file| replace_fallback || file.path != FALLBACK)
        .map(|file| (file.path, file.identity))
        .collect();
    review(target, loader.clone(), previous, available)
}
/// Verify the physical partition identity without checking file preimages.
pub fn verify_target(review: &EspReview) -> std::io::Result<()> {
    current(&review.target)
}
/// Reobserve the reviewed paths' preimages without broadening the write set.
pub fn revalidate(review: &EspReview) -> std::io::Result<()> {
    writable_target(&review.target)?;
    mounted(&review.target, false, |root| {
        for (path, previous) in &review.previous {
            if identity(root, path)? != *previous {
                return Err(refuse(format!("ESP file {path} changed since review")));
            }
        }
        Ok(())
    })
}
/// Read only the reviewed paths; other files on the ESP are not dependencies.
pub fn inspect_reviewed(
    review: &EspReview,
) -> std::io::Result<BTreeMap<String, Option<FileIdentity>>> {
    validate_review(review)?;
    mounted(&review.target, false, |root| {
        review
            .previous
            .keys()
            .map(|path| Ok((path.clone(), identity(root, path)?)))
            .collect()
    })
}
pub(crate) fn validate_review(review: &EspReview) -> std::io::Result<()> {
    review.artifacts.validate()?;
    if review.previous.is_empty()
        || review
            .previous
            .keys()
            .any(|path| !PATHS.contains(&path.as_str()))
        || token(review)? != review.loss_token
    {
        return Err(refuse("invalid ESP review"));
    }
    validate_target(&review.target)
}

/// A loader belongs to zboot only when its PE os-release identifies zboot. A
/// pathname alone never establishes ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoaderOwner {
    Zboot,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct Loader {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<FileIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<LoaderOwner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches_installed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// One of zboot's own UKIs under another name in `EFI/zboot/`, which
    /// zboot no longer refreshes.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

pub struct LoaderInventory {
    pub target: PartitionIdentity,
    pub loaders: Vec<Loader>,
}

/// zboot's two paths, each present or not, then its stale loaders.
/// Comparison applies only to zboot's files at its two paths.
fn loaders_at(root: &Path, installed: Option<&FileIdentity>) -> std::io::Result<Vec<Loader>> {
    let mut loaders = Vec::new();
    for path in PATHS {
        let mut loader = Loader {
            path: path.into(),
            identity: None,
            owner: None,
            matches_installed: None,
            error: None,
            stale: false,
        };
        match examine(root, path) {
            Ok(None) => {}
            Ok(Some((owner, identity))) => {
                loader.matches_installed = installed
                    .filter(|_| owner == LoaderOwner::Zboot)
                    .map(|installed| *installed == identity);
                loader.owner = Some(owner);
                loader.identity = Some(identity);
            }
            Err(error) => loader.error = Some(error.to_string()),
        }
        loaders.push(loader);
    }
    for path in stale_at(root)? {
        loaders.push(Loader {
            path,
            identity: None,
            owner: Some(LoaderOwner::Zboot),
            matches_installed: None,
            error: None,
            stale: true,
        });
    }
    Ok(loaders)
}

pub fn inspect_loaders(
    partition: &str,
    installed: Option<&FileIdentity>,
) -> std::io::Result<LoaderInventory> {
    let target = device::observe_partition(partition).map_err(refuse)?;
    let loaders = mounted(&target, false, |root| loaders_at(root, installed))?;
    Ok(LoaderInventory { target, loaders })
}

/// Fallback first. An install that stops after it leaves an ESP whose only
/// zboot file is the fallback, which a rerun still installs on; one that
/// stopped after the canonical name would be refreshed by the rerun, which
/// keeps a foreign fallback.
fn ordered(review: &EspReview) -> impl Iterator<Item = (&String, &Option<FileIdentity>)> {
    let fallback = review.previous.get_key_value(FALLBACK);
    fallback.into_iter().chain(
        review
            .previous
            .iter()
            .filter(|(path, _)| path.as_str() != FALLBACK),
    )
}

pub(crate) fn loader_owner(file: &mut File) -> std::io::Result<LoaderOwner> {
    let sections = match crate::loader::sections(file) {
        Ok(sections) => sections,
        Err(_) => return Ok(LoaderOwner::Other),
    };
    let Some(&(offset, bytes)) = sections.get(".osrel") else {
        return Ok(LoaderOwner::Other);
    };
    if bytes > 64 * 1024 {
        return Ok(LoaderOwner::Other);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; bytes as usize];
    file.read_exact(&mut bytes)?;
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(LoaderOwner::Other);
    };
    let mut id = None;
    let mut saw_id = false;
    for line in text.trim_end_matches('\0').lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "ID" {
            continue;
        }
        // Duplicate keys do not establish a single ownership identity.
        if saw_id {
            return Ok(LoaderOwner::Other);
        }
        saw_id = true;
        let value = value.trim();
        let value = if let Some(quoted) = value.strip_prefix('"') {
            quoted.strip_suffix('"')
        } else if let Some(quoted) = value.strip_prefix('\'') {
            quoted.strip_suffix('\'')
        } else {
            Some(value)
        };
        id = value;
    }
    Ok(if id == Some("zboot") {
        LoaderOwner::Zboot
    } else {
        LoaderOwner::Other
    })
}

fn atomic(
    root: &Path,
    relative: &str,
    write: impl FnOnce(&mut File) -> std::io::Result<()>,
    before_publish: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    let path = checked(root, relative, true)?;
    let parent = path.parent().unwrap();
    let temporary = parent.join(format!(".zboot-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        // This temporary lives on the target ESP, unlike private construction
        // staging. Its creation is already a target filesystem effect.
        zfs_tools::engine::effect::mark();
        write(&mut file)?;
        file.sync_all()?;
        before_publish()?;
        fs::rename(&temporary, &path)?;
        // FAT rename dirties this inode at its new directory-entry position.
        // Sync that metadata even when another mount keeps the filesystem live.
        file.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
/// Write REVIEW's paths, fallback first. Every path must still hold its
/// reviewed preimage before anything is written, or already the new file
/// when an interrupted run of this review got that far; such a file is only
/// synced. CUT runs before each rename (tests interrupt there).
fn execute(
    root: &Path,
    review: &EspReview,
    source: &mut File,
    cut: &mut impl FnMut(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    validate_review(review)?;
    let expected = review.artifacts.identity()?;
    let observed = ordered(review)
        .map(|(path, previous)| {
            let observed = identity(root, path)?;
            if observed.as_ref() != Some(&expected) && observed != *previous {
                return Err(refuse(format!("ESP file {path} changed since review")));
            }
            Ok((path, observed))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    for (path, observed) in observed {
        if observed.as_ref() == Some(&expected) {
            sync_in_place(root, path)?;
        } else {
            source.seek(SeekFrom::Start(0))?;
            atomic(
                root,
                path,
                |file| {
                    let mut hash = Sha256::new();
                    let mut remaining = expected.bytes;
                    let mut buffer = vec![0; 1024 * 1024];
                    while remaining > 0 {
                        let n = remaining.min(buffer.len() as u64) as usize;
                        source.read_exact(&mut buffer[..n])?;
                        hash.update(&buffer[..n]);
                        file.write_all(&buffer[..n])?;
                        remaining -= n as u64;
                    }
                    if format!("{:x}", hash.finalize()) != expected.sha256 {
                        return Err(refuse("EFI input changed while copying"));
                    }
                    Ok(())
                },
                || {
                    cut(path)?;
                    if identity(root, path)? != observed {
                        return Err(refuse("ESP loader changed while replacement was staged"));
                    }
                    Ok(())
                },
            )?;
        }
        if identity(root, path)?.as_ref() != Some(&expected) {
            return Err(refuse("installed EFI bytes failed readback"));
        }
    }
    Ok(())
}
/// Make a file that already holds the new bytes durable: an interrupted run
/// may have renamed it into place without syncing it.
fn sync_in_place(root: &Path, path: &str) -> std::io::Result<()> {
    let path = checked(root, path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)?;
    zfs_tools::engine::effect::mark();
    rustix::fs::syncfs(&file).map_err(refuse)?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()
}

/// Write one reviewed ESP for deploy, which owns the frozen review.
pub fn apply(review: &EspReview, consent: &str) -> std::io::Result<()> {
    validate_review(review)?;
    if consent != review.loss_token {
        return Err(refuse("exact ESP file-replacement token does not match"));
    }
    let mut source = review.artifacts.open()?;
    mounted(&review.target, true, |root| {
        execute(root, review, &mut source, &mut |_| Ok(()))
    })
}

/// What one of zboot's two paths holds. The plan freezes classification as
/// well as bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub path: String,
    pub identity: Option<FileIdentity>,
    pub owned: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefreshTarget {
    pub review: EspReview,
    /// zboot's two paths, canonical name first.
    pub findings: Vec<Finding>,
    /// Another system's files this plan replaces: typed loss.
    pub foreign_replacements: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefreshPlan {
    pub schema_version: u32,
    pub efi: crate::loader::EfiFile,
    pub automatic: bool,
    pub imported_storage: Vec<device::PoolStorage>,
    /// The ESP this boot was loaded from (systemd-stub's volatile
    /// `LoaderDevicePartUUID`), when an automatic plan took it in.
    pub loader_partuuid: Option<String>,
    /// Why an automatic plan left the ESP this boot came from alone.
    pub loader_left_alone: Option<String>,
    pub targets: Vec<RefreshTarget>,
    /// zboot's stale loaders on the ESPs the plan inspected, left in place.
    pub stale_loaders: Vec<EspFile>,
}
/// A file on an ESP: another system's file at one of zboot's paths, or a
/// stale zboot loader; either is left in place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspFile {
    pub partition: String,
    pub path: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefreshOutcome {
    pub complete: bool,
    pub efi_sha256: String,
    pub partitions: Vec<String>,
    pub left_in_place: Vec<EspFile>,
    pub stale_loaders: Vec<EspFile>,
}
/// What zboot's two paths hold.
fn findings(root: &Path) -> std::io::Result<Vec<Finding>> {
    PATHS
        .into_iter()
        .map(|path| {
            let examined =
                examine(root, path).map_err(|error| refuse(format!("{path}: {error}")))?;
            Ok(Finding {
                path: path.into(),
                owned: matches!(examined, Some((LoaderOwner::Zboot, _))),
                identity: examined.map(|(_, identity)| identity),
            })
        })
        .collect()
}
/// Whether zboot is installed on an ESP: its loader is at the canonical
/// name. A zboot fallback alone does not count.
fn installed(found: &[Finding]) -> bool {
    found
        .iter()
        .any(|file| file.owned && file.path == CANONICAL)
}
/// What a plan writes on one ESP: each of zboot's paths that holds its
/// loader or nothing, leaving another system's file in place. An INSTALL
/// writes both paths, whatever holds them.
fn write_paths(found: &[Finding], install: bool) -> BTreeMap<String, Option<FileIdentity>> {
    found
        .iter()
        .filter(|file| install || file.owned || file.identity.is_none())
        .map(|file| (file.path.clone(), file.identity.clone()))
        .collect()
}
fn foreign_replacements(
    found: &[Finding],
    previous: &BTreeMap<String, Option<FileIdentity>>,
) -> Vec<String> {
    found
        .iter()
        .filter(|file| !file.owned && file.identity.is_some() && previous.contains_key(&file.path))
        .map(|file| file.path.clone())
        .collect()
}
/// Another system's files at zboot's paths that TARGET does not write.
fn kept(target: &RefreshTarget) -> impl Iterator<Item = &str> {
    target
        .findings
        .iter()
        .filter(|file| {
            !file.owned
                && file.identity.is_some()
                && !target.review.previous.contains_key(&file.path)
        })
        .map(|file| file.path.as_str())
}
/// What one ESP's inspection found: the write it needs, if any, and
/// zboot's stale loaders there.
struct Inspection {
    target: Option<RefreshTarget>,
    stale: Vec<String>,
}
/// Plan one ESP. A refresh takes an ESP that holds zboot's loader at either
/// path or a stale one; an install (EXPLICIT) takes any, and writes both
/// paths unless zboot is installed there.
fn refresh_target(
    target: PartitionIdentity,
    efi: &crate::loader::EfiFile,
    explicit: bool,
    root: &Path,
    available: u64,
) -> std::io::Result<Inspection> {
    validate_target(&target)?;
    let found = findings(root)?;
    let stale = stale_at(root)?;
    let previous = write_paths(&found, explicit && !installed(&found));
    if !explicit && stale.is_empty() && !found.iter().any(|file| file.owned) || previous.is_empty()
    {
        return Ok(Inspection {
            target: None,
            stale,
        });
    }
    writable_target(&target)?;
    let foreign_replacements = foreign_replacements(&found, &previous);
    Ok(Inspection {
        target: Some(RefreshTarget {
            review: review(target, efi.clone(), previous, available)?,
            findings: found,
            foreign_replacements,
        }),
        stale,
    })
}
fn imported_storage() -> std::io::Result<Vec<device::PoolStorage>> {
    let state = zfs_tools::engine::state::observe().map_err(refuse)?;
    let mut storage = Vec::new();
    for pool in &state.inspection.pools {
        storage.push(device::observe_pool_storage(&pool.name, &pool.guid).map_err(refuse)?);
    }
    storage.sort_by(|a, b| a.pool.cmp(&b.pool));
    Ok(storage)
}
fn on_imported_disk(target: &PartitionIdentity, pools: &[device::PoolStorage]) -> bool {
    pools.iter().any(|pool| pool.disks.contains(&target.disk))
}
fn is_loader_esp(target: &PartitionIdentity, loader: Option<&str>) -> bool {
    loader.is_some_and(|uuid| {
        target
            .partition
            .partition_uuid
            .as_deref()
            .is_some_and(|actual| actual.eq_ignore_ascii_case(uuid))
    })
}
/// An automatic plan selects ESPs on imported-pool disks and the loader ESP.
fn automatic_member(
    target: &PartitionIdentity,
    pools: &[device::PoolStorage],
    loader: Option<&str>,
) -> bool {
    on_imported_disk(target, pools) || is_loader_esp(target, loader)
}
/// A single immutable plan covers exactly the selected existing ESPs.
pub fn refresh_plan(partitions: &[String], efi: &Path) -> std::io::Result<RefreshPlan> {
    let efi = crate::loader::EfiFile::inspect(efi)?;
    let automatic = partitions.is_empty();
    let storage = if automatic {
        imported_storage()?
    } else {
        vec![]
    };
    let landscape = if automatic {
        device::observe_landscape().map_err(refuse)?.blockdevices
    } else {
        vec![]
    };
    // An unreadable variable leaves the loader ESP alone, not the pool members.
    let (loader, unreadable) = if automatic {
        match crate::remote_access::loader_partuuid() {
            Ok(loader) => (loader, None),
            Err(error) => (
                None,
                Some(format!("LoaderDevicePartUUID cannot be read: {error}")),
            ),
        }
    } else {
        (None, None)
    };
    let mut plan = refresh_plan_with(
        partitions,
        efi,
        storage,
        loader,
        &landscape,
        loader_refusal,
        |name| device::observe_partition(name).map_err(refuse),
        |target, efi, explicit| {
            mounted(target, false, |root| {
                refresh_target(target.clone(), efi, explicit, root, available_bytes(root)?)
            })
        },
    )?;
    plan.loader_left_alone = plan.loader_left_alone.or(unreadable);
    Ok(plan)
}
/// Why this boot must not refresh the ESP at PATH it was loaded from, or
/// `None` when it may. Only the host's own boot qualifies: its root is on a
/// writable pool, which neither a stick system (read-only pool) nor a rescue
/// in RAM has, and PATH is directly on a fixed NVMe or SATA disk, judged as
/// the menu judges local pools.
fn loader_refusal(path: &str) -> std::io::Result<Option<String>> {
    let shown = zfs_tools::engine::escape_display(path);
    let Some(root) = crate::status::running_root()? else {
        return Ok(Some(format!("{shown}: this boot does not run from a pool")));
    };
    let pool = root.split('/').next().unwrap_or_default();
    let readonly = crate::native_run::run(
        "zpool",
        &[
            "get".into(),
            "-H".into(),
            "-o".into(),
            "value".into(),
            "readonly".into(),
            pool.into(),
        ],
        4096,
        30,
    )
    .map_err(refuse)?;
    if readonly.trim_end() != "off" {
        return Ok(Some(format!(
            "{shown}: this boot runs from the read-only pool {}",
            zfs_tools::engine::escape_display(pool)
        )));
    }
    fixed_disk_refusal(path)
}
/// Why PATH is not directly on a fixed NVMe or SATA disk (a stick, a USB or
/// hot-plug disk, a disk that cannot be judged), or `None` when it is.
pub(crate) fn fixed_disk_refusal(path: &str) -> std::io::Result<Option<String>> {
    let stack = crate::menu::hostid_adopt::lsblk_inverse(path, "PATH,TYPE,TRAN,RM,HOTPLUG")
        .map_err(refuse)?;
    Ok(crate::menu::hostid_adopt::transport_refusal(path, &stack)
        .or_else(|| removable_refusal(path, &stack)))
}
/// Whether the ESP TARGET holds one of zboot's loaders: at either of its
/// paths, or a stale one, as `esp` and `status --devices` judge.
pub(crate) fn holds_zboot(target: &PartitionIdentity) -> std::io::Result<bool> {
    mounted(target, false, |root| {
        Ok(findings(root)?.iter().any(|file| file.owned) || !stale_at(root)?.is_empty())
    })
}
/// Whether BLOCK is a partition of the EFI system partition type.
fn is_esp_type(block: &device::Block) -> bool {
    block.kind == "part"
        && block
            .parttype
            .as_deref()
            .is_some_and(|id| id.eq_ignore_ascii_case(ESP_TYPE))
}
/// The zboot ESPs on this host's fixed disks, each as `PATH (MODEL)`: an
/// ESP holding one of zboot's files, directly on a fixed NVMe or SATA disk,
/// whether or not a pool there is imported. The firmware may start zboot
/// from any of them, and which one it picks next is not known here. An ESP
/// that cannot be read is left out.
pub(crate) fn fixed_zboot_esps() -> std::io::Result<Vec<String>> {
    fn walk(
        block: &device::Block,
        disk: Option<&device::Block>,
        found: &mut Vec<(String, String)>,
    ) {
        if is_esp_type(block) {
            let model = disk
                .and_then(|disk| disk.model.as_deref())
                .map(str::trim)
                .filter(|model| !model.is_empty())
                .unwrap_or("unknown model");
            found.push((block.path.clone(), model.to_owned()));
        }
        for child in &block.children {
            walk(child, disk.or(Some(block)), found);
        }
    }
    let mut found = Vec::new();
    for block in device::observe_landscape().map_err(refuse)?.blockdevices {
        walk(&block, None, &mut found);
    }
    found.sort();
    found.dedup();
    Ok(found
        .into_iter()
        .filter(|(path, _)| {
            device::observe_partition(path)
                .map_err(refuse)
                .and_then(|target| holds_zboot(&target))
                .unwrap_or(false)
                && matches!(fixed_disk_refusal(path), Ok(None))
        })
        .map(|(path, model)| format!("{path} ({model})"))
        .collect())
}
/// Why `lsblk --json --inverse` shows PATH on a disk not plainly fixed, such
/// as an NVMe enclosure or a SATA dock: any disk not reported with removable
/// and hot-plug both false. Pure for tests.
fn removable_refusal(path: &str, lsblk: &str) -> Option<String> {
    fn clear(node: &serde_json::Value, key: &str) -> bool {
        match node.get(key) {
            Some(serde_json::Value::Bool(flag)) => !flag,
            Some(serde_json::Value::String(flag)) => flag == "0",
            _ => false,
        }
    }
    fn fixed(node: &serde_json::Value) -> bool {
        let disk = node.get("type").and_then(|kind| kind.as_str()) == Some("disk");
        let flags = !disk || clear(node, "rm") && clear(node, "hotplug");
        let children = node
            .get("children")
            .and_then(|children| children.as_array())
            .is_none_or(|children| children.iter().all(fixed));
        flags && children
    }
    let shown = zfs_tools::engine::escape_display(path);
    let roots = serde_json::from_str::<serde_json::Value>(lsblk).ok();
    let roots = roots
        .as_ref()
        .and_then(|value| value.get("blockdevices"))
        .and_then(|roots| roots.as_array());
    match roots {
        Some(roots) if roots.iter().all(fixed) => None,
        Some(_) => Some(format!("{shown} is on a removable or hot-plug disk")),
        None => Some(format!("{shown}: device stack unreadable")),
    }
}
#[allow(clippy::too_many_arguments)]
fn refresh_plan_with(
    partitions: &[String],
    efi: crate::loader::EfiFile,
    storage: Vec<device::PoolStorage>,
    loader: Option<String>,
    landscape: &[device::Block],
    mut local: impl FnMut(&str) -> std::io::Result<Option<String>>,
    mut observe: impl FnMut(&str) -> std::io::Result<PartitionIdentity>,
    mut inspect: impl FnMut(
        &PartitionIdentity,
        &crate::loader::EfiFile,
        bool,
    ) -> std::io::Result<Inspection>,
) -> std::io::Result<RefreshPlan> {
    let automatic = partitions.is_empty();
    let loader = loader.filter(|_| automatic);
    let mut names = partitions.to_vec();
    let mut loader_partuuid = None;
    let mut loader_left_alone = None;
    let mut loader_esp = None;
    if automatic {
        fn walk<'a>(
            block: &'a device::Block,
            parent: Option<&device::Block>,
            storage: &[device::PoolStorage],
            loader: Option<&str>,
            names: &mut Vec<String>,
            booted: &mut Vec<&'a device::Block>,
        ) {
            if block.kind == "part" {
                if loader.is_some_and(|uuid| {
                    block
                        .partuuid
                        .as_deref()
                        .is_some_and(|actual| actual.eq_ignore_ascii_case(uuid))
                }) {
                    booted.push(block);
                }
                if is_esp_type(block)
                    && parent.is_some_and(|parent| {
                        storage.iter().any(|pool| {
                            pool.disks
                                .iter()
                                .any(|disk| disk.device_number == parent.device_number)
                        })
                    })
                {
                    names.push(block.path.clone());
                }
            }
            for child in &block.children {
                walk(child, Some(block), storage, loader, names, booted);
            }
        }
        let mut booted = Vec::new();
        for block in landscape {
            walk(
                block,
                None,
                &storage,
                loader.as_deref(),
                &mut names,
                &mut booted,
            );
        }
        // The ESP this boot came from joins only on a fixed local disk of the
        // host's own boot: a booted stick stays the untouched fallback and a
        // rescue writes nothing. Whatever stops it leaves the pool members be.
        loader_left_alone = match booted[..] {
            [] => None,
            [block] => {
                let shown = zfs_tools::engine::escape_display(&block.path);
                if names.contains(&block.path) {
                    None
                } else if !is_esp_type(block) {
                    Some(format!("{shown} is not an EFI system partition"))
                } else if storage.is_empty() {
                    Some(format!("{shown}: no pool is imported"))
                } else {
                    match local(&block.path) {
                        Ok(None) => {
                            loader_esp = Some(block.path.clone());
                            None
                        }
                        Ok(Some(reason)) => Some(reason),
                        Err(error) => {
                            Some(format!("{shown}: its disk could not be judged: {error}"))
                        }
                    }
                }
            }
            // Copied sticks share a PARTUUID; never pick one of them by guess.
            _ => Some(format!("{} partitions carry its PARTUUID", booted.len())),
        };
    }
    names.sort();
    names.dedup();
    let mut targets = Vec::new();
    let mut stale_loaders = Vec::new();
    let mut note_stale = |target: &PartitionIdentity, stale: Vec<String>| {
        stale_loaders.extend(stale.into_iter().map(|path| EspFile {
            partition: target.partition.path.clone(),
            path,
        }));
    };
    for name in names {
        let target = observe(&name)?;
        if automatic && !on_imported_disk(&target, &storage) {
            return Err(refuse(
                "automatically selected ESP disk identity changed during observation",
            ));
        }
        // An unformatted or differently formatted member cannot hold a FAT
        // loader. Explicit selections still reach strict target validation.
        if automatic && target.partition.filesystem.as_deref() != Some("vfat") {
            continue;
        }
        let inspected = inspect(&target, &efi, !automatic)?;
        note_stale(&target, inspected.stale);
        if let Some(planned) = inspected.target {
            if targets.iter().any(|old: &RefreshTarget| {
                old.review.target.partition.device_number
                    == planned.review.target.partition.device_number
            }) {
                return Err(refuse("the same ESP was selected through multiple paths"));
            }
            targets.push(planned);
        }
    }
    if let Some(path) = loader_esp {
        let planned = observe(&path).and_then(|target| {
            if !is_loader_esp(&target, loader.as_deref()) || on_imported_disk(&target, &storage) {
                return Err(refuse("its disk identity changed during observation"));
            }
            // Like a pool member, an ESP without a zboot loader is not touched.
            if target.partition.filesystem.as_deref() != Some("vfat") {
                return Ok(None);
            }
            let inspected = inspect(&target, &efi, false)?;
            note_stale(&target, inspected.stale);
            Ok(inspected.target)
        });
        match planned {
            Ok(Some(planned)) => {
                if targets.iter().any(|old| {
                    old.review.target.partition.device_number
                        == planned.review.target.partition.device_number
                }) {
                    return Err(refuse("the same ESP was selected through multiple paths"));
                }
                targets.push(planned);
                loader_partuuid = loader;
            }
            Ok(None) => {}
            Err(error) => {
                let shown = zfs_tools::engine::escape_display(&path);
                loader_left_alone = Some(format!("{shown}: {error}"));
            }
        }
    }
    Ok(RefreshPlan {
        schema_version: 1,
        efi,
        automatic,
        imported_storage: storage,
        loader_partuuid,
        loader_left_alone,
        targets,
        stale_loaders,
    })
}
pub fn refresh_consent(plan: &RefreshPlan) -> std::io::Result<String> {
    // Why the booted ESP was left alone is not consented to: nothing is written
    // there, and the reason may carry error text or free-space figures. Whether
    // it is written is bound by the targets and `loader_partuuid`.
    let mut consent = plan.clone();
    consent.loader_left_alone = None;
    crate::consent::token(&consent)
}
impl RefreshPlan {
    pub fn needs_confirmation(&self) -> bool {
        self.targets
            .iter()
            .any(|target| !target.foreign_replacements.is_empty())
    }
}
pub fn refresh_typed(plan: &RefreshPlan) -> crate::consent::Typed {
    if plan.targets.len() == 1 {
        let disk = &plan.targets[0].review.target.disk;
        crate::consent::disk_target(disk.serial.as_deref(), disk.wwn.as_deref())
    } else {
        crate::consent::Typed {
            what: "the plan summary",
            text: plan
                .targets
                .iter()
                .map(|target| target.review.target.partition.path.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}
/// The line that names a loader ESP an automatic plan left alone.
pub fn loader_note(plan: &RefreshPlan) -> Option<String> {
    plan.loader_left_alone.as_ref().map(|reason| {
        format!(
            "The ESP this boot was loaded from was left alone: {reason}. Name it to refresh it."
        )
    })
}
/// What `esp` and `status --devices` say about zboot's stale loader PATH
/// on the ESP PARTITION. Unescaped: the caller escapes it for a terminal.
pub fn stale_note(partition: &str, path: &str) -> String {
    format!(
        "ESP {partition}: {path} is a stale zboot loader; zboot no longer refreshes it. \
         Point the firmware boot entry at {CANONICAL} (efibootmgr), then remove {path}."
    )
}
/// Another system's files the plan leaves at zboot's paths.
pub fn left_in_place(plan: &RefreshPlan) -> Vec<EspFile> {
    plan.targets
        .iter()
        .flat_map(|target| {
            kept(target).map(|path| EspFile {
                partition: target.review.target.partition.path.clone(),
                path: path.into(),
            })
        })
        .collect()
}
pub fn describe_refresh(plan: &RefreshPlan, token: &str) -> String {
    let mut text = format!(
        "Refresh zboot loaders from {}\n  SHA256 {}\n",
        zfs_tools::engine::escape_display(&plan.efi.efi.to_string_lossy()),
        plan.efi.sha256
    );
    for target in &plan.targets {
        text.push_str(&format!(
            "  ESP {} on {}\n",
            zfs_tools::engine::escape_display(&target.review.target.partition.path),
            zfs_tools::engine::escape_display(&target.review.target.disk.path)
        ));
        for path in target.review.previous.keys() {
            text.push_str(&format!(
                "    {}{}\n",
                zfs_tools::engine::escape_display(path),
                if target.foreign_replacements.contains(path) {
                    " (replaces another system's loader)"
                } else {
                    ""
                }
            ));
        }
        for path in kept(target) {
            text.push_str(&format!(
                "    {} is another system's; left in place\n",
                zfs_tools::engine::escape_display(path)
            ));
        }
    }
    for stale in &plan.stale_loaders {
        text.push_str(&format!(
            "  {}\n",
            zfs_tools::engine::escape_display(&stale_note(&stale.partition, &stale.path))
        ));
    }
    if let Some(note) = loader_note(plan) {
        text.push_str(&format!("  {note}\n"));
    }
    text.push_str(&format!("  Token {token}\n"));
    text
}
/// TARGET's findings still hold, except that a planned path may already
/// hold the new file: an interrupted run of this plan wrote it.
fn admit_refresh(
    root: &Path,
    target: &RefreshTarget,
    expected: &FileIdentity,
) -> std::io::Result<()> {
    let now = findings(root)?;
    let done = |file: &Finding| {
        file.owned
            && file.identity.as_ref() == Some(expected)
            && target.review.previous.contains_key(&file.path)
    };
    if now.len() != target.findings.len()
        || now
            .iter()
            .zip(&target.findings)
            .any(|(file, old)| file != old && !done(file))
    {
        return Err(refuse("ESP ownership findings changed since review"));
    }
    Ok(())
}
fn apply_targets(
    plan: &RefreshPlan,
    mut apply: impl FnMut(&RefreshTarget) -> std::io::Result<()>,
) -> std::io::Result<RefreshOutcome> {
    for (index, target) in plan.targets.iter().enumerate() {
        if let Err(error) = apply(target) {
            let remaining = plan.targets[index..]
                .iter()
                .map(|target| target.review.target.partition.path.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(refuse(format!(
                "{error}; ESPs remaining: {remaining}; rerun zboot esp"
            )));
        }
    }
    Ok(RefreshOutcome {
        complete: true,
        efi_sha256: plan.efi.sha256.clone(),
        partitions: plan
            .targets
            .iter()
            .map(|target| target.review.target.partition.path.clone())
            .collect(),
        left_in_place: left_in_place(plan),
        stale_loaders: plan.stale_loaders.clone(),
    })
}
fn validate_refresh(plan: &RefreshPlan) -> std::io::Result<()> {
    if plan.targets.len() > 1024
        || !plan.automatic
            && (!plan.imported_storage.is_empty()
                || plan.loader_partuuid.is_some()
                || plan.loader_left_alone.is_some())
        || plan.loader_partuuid.is_some()
            && (plan.imported_storage.is_empty() || plan.loader_left_alone.is_some())
    {
        return Err(refuse("invalid ESP batch review"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for target in &plan.targets {
        let install = !plan.automatic && !installed(&target.findings);
        let previous = write_paths(&target.findings, install);
        let stale = plan
            .stale_loaders
            .iter()
            .any(|file| file.partition == target.review.target.partition.path);
        if target.review.artifacts != plan.efi
            || !seen.insert(target.review.target.partition.device_number.clone())
            || target
                .findings
                .iter()
                .map(|file| file.path.as_str())
                .ne(PATHS)
            || target.review.previous != previous
            || target.foreign_replacements != foreign_replacements(&target.findings, &previous)
            || plan.automatic
                && (!automatic_member(
                    &target.review.target,
                    &plan.imported_storage,
                    plan.loader_partuuid.as_deref(),
                ) || !stale && !target.findings.iter().any(|file| file.owned))
        {
            return Err(refuse(
                "ESP batch paths or source differ from their reviewed ownership",
            ));
        }
        validate_review(&target.review)?;
    }
    Ok(())
}
pub fn refresh_apply(plan: &RefreshPlan, consent: &str) -> std::io::Result<RefreshOutcome> {
    validate_refresh(plan)?;
    if consent != refresh_consent(plan)? {
        return Err(refuse("exact ESP batch token does not match"));
    }
    let mut source = plan.efi.open()?;
    let expected = plan.efi.identity()?;
    if plan.automatic
        && (imported_storage()? != plan.imported_storage
            || plan.loader_partuuid.is_some()
                && crate::remote_access::loader_partuuid()? != plan.loader_partuuid)
    {
        return Err(refuse(
            "imported pool disks or the loader ESP changed since ESP review",
        ));
    }
    // The plan was made just before; each ESP is admitted again as it is
    // written.
    apply_targets(plan, |target| {
        mounted(&target.review.target, true, |root| {
            admit_refresh(root, target, &expected)?;
            execute(root, &target.review, &mut source, &mut |_| Ok(()))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DiskIdentity, Partition};
    use std::os::unix::fs::{MetadataExt, symlink};
    const DESTINATIONS: [&str; 2] = [CANONICAL, FALLBACK];
    /// The name an older install wrote and firmware may still boot: stale.
    const RECOVERY: &str = "EFI/zboot/zboot-recovery.efi";
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("zboot-esp-tests-{}", uuid::Uuid::new_v4()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn loader_fixture(path: &Path, os_release: &[u8]) {
        let mut bytes = vec![0; 1024];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&128u32.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[134..136].copy_from_slice(&1u16.to_le_bytes());
        bytes[148..150].copy_from_slice(&240u16.to_le_bytes());
        bytes[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[220..222].copy_from_slice(&10u16.to_le_bytes());
        bytes[392..400].copy_from_slice(b".osrel\0\0");
        bytes[400..404].copy_from_slice(&(os_release.len() as u32).to_le_bytes());
        bytes[408..412].copy_from_slice(&512u32.to_le_bytes());
        bytes[412..416].copy_from_slice(&512u32.to_le_bytes());
        bytes[512..512 + os_release.len()].copy_from_slice(os_release);
        fs::write(path, bytes).unwrap();
    }
    /// A PE with OS_RELEASE at PATH under ROOT, creating its directories.
    fn put(root: &Path, path: &str, os_release: &[u8]) {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        loader_fixture(&root.join(path), os_release);
    }
    fn explicit_plan(efi: &EfiFile, targets: Vec<RefreshTarget>) -> RefreshPlan {
        RefreshPlan {
            schema_version: 1,
            efi: efi.clone(),
            automatic: false,
            imported_storage: vec![],
            loader_partuuid: None,
            loader_left_alone: None,
            targets,
            stale_loaders: vec![],
        }
    }
    /// The plan `esp` (or with EXPLICIT, `esp /dev/vda1`) makes for the one
    /// ESP at ROOT.
    fn plan_at(root: &Path, efi: &EfiFile, explicit: bool) -> RefreshPlan {
        let member = target_fixture();
        let names = if explicit {
            vec![member.partition.path.clone()]
        } else {
            vec![]
        };
        refresh_plan_with(
            &names,
            efi.clone(),
            if explicit {
                vec![]
            } else {
                member_storage(&member)
            },
            None,
            &if explicit {
                vec![]
            } else {
                member_landscape(&member)
            },
            |_| Ok(None),
            |_| Ok(member.clone()),
            |target, efi, explicit| inspect_fixture(root, target, efi, explicit),
        )
        .unwrap()
    }
    fn publish_at(
        root: &Path,
        target: &RefreshTarget,
        efi: &EfiFile,
        cut: &mut impl FnMut(&str) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let mut source = efi.open()?;
        admit_refresh(root, target, &efi.identity()?)?;
        execute(root, &target.review, &mut source, cut)
    }
    fn paths(target: &RefreshTarget) -> Vec<&str> {
        target.review.previous.keys().map(String::as_str).collect()
    }

    #[test]
    fn loader_ownership_uses_os_release() {
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("loader.efi");
        for release in [b"ID=zboot\n".as_slice(), b"ID=\"zboot\"\n", b"ID='zboot'\n"] {
            loader_fixture(&path, release);
            assert_eq!(
                loader_owner(&mut File::open(&path).unwrap()).unwrap(),
                LoaderOwner::Zboot
            );
        }
        for release in [
            b"ID=another-system\n".as_slice(),
            b"ID=zfs-tools\n",
            b"NAME=zboot\n",
            b"ID=zbootish\n",
            b"ID=zboot\nID=zboot\n",
            b"ID=\"broken\nID=zboot\n",
        ] {
            loader_fixture(&path, release);
            assert_eq!(
                loader_owner(&mut File::open(&path).unwrap()).unwrap(),
                LoaderOwner::Other
            );
        }
        fs::write(&path, b"filename alone is not ownership").unwrap();
        assert_eq!(
            loader_owner(&mut File::open(&path).unwrap()).unwrap(),
            LoaderOwner::Other
        );
    }

    #[test]
    fn the_esp_acceptance_case_seeds_a_loader_zboot_owns() {
        // ESP-NATIVE's automatic refresh only reaches ESPs whose loader is
        // zboot's; a stale stub silently leaves every target alone.
        let script = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/acceptance/guest/cases/ESP-NATIVE.sh"),
        )
        .unwrap();
        let escaped = script
            .lines()
            .find_map(|line| line.strip_prefix("STUB='")?.strip_suffix('\''))
            .expect("ESP-NATIVE defines STUB='...'");
        let bytes: Vec<u8> = escaped
            .split("\\0")
            .skip(1)
            .map(|octal| u8::from_str_radix(octal, 8).unwrap())
            .collect();
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("stub.efi");
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            loader_owner(&mut File::open(&path).unwrap()).unwrap(),
            LoaderOwner::Zboot
        );
    }

    #[test]
    fn a_stale_loader_note_names_the_path_and_the_firmware_fix() {
        assert_eq!(
            stale_note("/dev/nvme0n1p1", RECOVERY),
            "ESP /dev/nvme0n1p1: EFI/zboot/zboot-recovery.efi is a stale zboot loader; \
             zboot no longer refreshes it. Point the firmware boot entry at \
             EFI/zboot/zboot.efi (efibootmgr), then remove EFI/zboot/zboot-recovery.efi."
        );
    }

    #[test]
    fn a_refresh_writes_only_zboots_two_paths_and_reports_its_stale_loaders() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        let efi = source_fixture(root);
        put(root, CANONICAL, b"ID=zboot\nVERSION_ID=\"0.1.0\"\n");
        put(root, RECOVERY, b"ID=zboot\nVERSION_ID=\"0.1.0\"\n");
        put(root, "EFI/zboot/custom", b"ID=zboot\n");
        let temporary = format!("EFI/zboot/.zboot-{}.tmp", uuid::Uuid::new_v4());
        for (path, release) in [
            ("EFI/Linux/zboot.efi", b"ID=zboot\n".as_slice()),
            ("EFI/zboot/nested/zboot.efi", b"ID=zboot\n"),
            ("EFI/zboot/other.efi", b"ID=another-system\n"),
            ("EFI/nvidia-vram-oc/zboot.efi", b"ID=zboot\n"),
            (temporary.as_str(), b"ID=zboot\n"),
            (FALLBACK, b"ID=another-system\n"),
        ] {
            put(root, path, release);
        }
        let record = format!("EFI/zboot/operations/{}.json", uuid::Uuid::new_v4());
        fs::create_dir_all(root.join("EFI/zboot/operations")).unwrap();
        fs::write(root.join(&record), b"legacy record").unwrap();
        let untouched: Vec<_> = [
            RECOVERY,
            "EFI/zboot/custom",
            "EFI/Linux/zboot.efi",
            "EFI/zboot/nested/zboot.efi",
            "EFI/zboot/other.efi",
            "EFI/nvidia-vram-oc/zboot.efi",
            &temporary,
            FALLBACK,
            &record,
        ]
        .into_iter()
        .map(|path| (path.to_owned(), fs::read(root.join(path)).unwrap()))
        .collect();
        for explicit in [false, true] {
            let plan = plan_at(root, &efi, explicit);
            let [target] = &plan.targets[..] else {
                panic!("one target");
            };
            assert_eq!(paths(target), [CANONICAL]);
            assert!(target.foreign_replacements.is_empty());
            assert_eq!(kept(target).collect::<Vec<_>>(), [FALLBACK]);
            assert_eq!(
                plan.stale_loaders,
                ["EFI/zboot/custom", RECOVERY].map(|path| EspFile {
                    partition: "/dev/vda1".into(),
                    path: path.into()
                })
            );
            validate_refresh(&plan).unwrap();
            assert!(!plan.needs_confirmation());
            let text = describe_refresh(&plan, "token");
            assert!(
                text.contains("EFI/BOOT/BOOTX64.EFI is another system's; left in place"),
                "{text}"
            );
            assert!(
                text.contains(&stale_note("/dev/vda1", RECOVERY))
                    && text.contains(&stale_note("/dev/vda1", "EFI/zboot/custom")),
                "{text}"
            );
            let outcome = apply_targets(&plan, |target| {
                publish_at(root, target, &efi, &mut |_| Ok(()))
            })
            .unwrap();
            assert_eq!(
                outcome.left_in_place,
                [EspFile {
                    partition: "/dev/vda1".into(),
                    path: FALLBACK.into()
                }]
            );
            assert_eq!(outcome.stale_loaders, plan.stale_loaders);
            let json = serde_json::to_value(&outcome).unwrap();
            assert_eq!(
                json["stale_loaders"][1],
                serde_json::json!({"partition": "/dev/vda1", "path": RECOVERY})
            );
            assert_eq!(
                identity(root, CANONICAL).unwrap(),
                Some(efi.identity().unwrap())
            );
            for (path, bytes) in &untouched {
                assert_eq!(&fs::read(root.join(path)).unwrap(), bytes, "{path}");
            }
        }
        // The canonical name in another case is the canonical file, as the
        // vfat driver opens it, never a stale one.
        fs::rename(root.join(CANONICAL), root.join("EFI/zboot/ZBOOT.EFI")).unwrap();
        assert_eq!(stale_at(root).unwrap(), ["EFI/zboot/custom", RECOVERY]);
    }

    #[test]
    fn an_esp_with_only_a_stale_loader_gains_the_canonical_name_and_keeps_the_old_one() {
        // The firmware entry of an older install boots EFI/zboot/zboot-recovery.efi.
        let efi_root = Scratch::new();
        let efi = source_fixture(&efi_root.0);
        for explicit in [false, true] {
            let scratch = Scratch::new();
            let root = &scratch.0;
            put(root, RECOVERY, b"ID=zboot\nVERSION=old\n");
            put(root, FALLBACK, b"ID=zboot\nVERSION=old\n");
            let old = fs::read(root.join(RECOVERY)).unwrap();
            let plan = plan_at(root, &efi, explicit);
            let [target] = &plan.targets[..] else {
                panic!("one target");
            };
            assert_eq!(
                ordered(&target.review)
                    .map(|(path, _)| path.as_str())
                    .collect::<Vec<_>>(),
                [FALLBACK, CANONICAL]
            );
            assert!(!plan.needs_confirmation());
            assert_eq!(
                serde_json::to_value(&plan).unwrap()["stale_loaders"],
                serde_json::json!([{"partition": "/dev/vda1", "path": RECOVERY}])
            );
            assert!(describe_refresh(&plan, "token").contains(&stale_note("/dev/vda1", RECOVERY)));
            let outcome = apply_targets(&plan, |target| {
                publish_at(root, target, &efi, &mut |_| Ok(()))
            })
            .unwrap();
            assert_eq!(outcome.stale_loaders, plan.stale_loaders);
            for path in [CANONICAL, FALLBACK] {
                assert_eq!(identity(root, path).unwrap(), Some(efi.identity().unwrap()));
            }
            assert_eq!(fs::read(root.join(RECOVERY)).unwrap(), old);
            // A rerun still reports it: zboot never removes it.
            assert_eq!(plan_at(root, &efi, false).stale_loaders, plan.stale_loaders);
        }
        // Another system's fallback beside it: a refresh keeps it, an install
        // replaces it only after a typed answer.
        let scratch = Scratch::new();
        let root = &scratch.0;
        put(root, RECOVERY, b"ID=zboot\n");
        put(root, FALLBACK, b"ID=another-system\n");
        let refresh = plan_at(root, &efi, false);
        assert_eq!(paths(&refresh.targets[0]), [CANONICAL]);
        assert!(!refresh.needs_confirmation());
        let install = plan_at(root, &efi, true);
        assert_eq!(install.targets[0].foreign_replacements, [FALLBACK]);
        assert!(install.needs_confirmation());
        assert_eq!(install.stale_loaders.len(), 1);
        // With another system's files at both paths there is nothing a
        // refresh may write, and the stale loader is still reported.
        put(root, CANONICAL, b"ID=another-system\n");
        let plan = plan_at(root, &efi, false);
        assert!(plan.targets.is_empty());
        assert_eq!(plan.stale_loaders[0].path, RECOVERY);
        // An automatic plan binds the stale loader that selected the ESP.
        fs::remove_file(root.join(CANONICAL)).unwrap();
        let mut plan = plan_at(root, &efi, false);
        validate_refresh(&plan).unwrap();
        plan.stale_loaders.clear();
        assert!(validate_refresh(&plan).is_err());
    }

    #[test]
    fn esp_alone_writes_zboots_paths_where_empty_and_never_adopts_other_paths() {
        let efi_root = Scratch::new();
        let efi = source_fixture(&efi_root.0);
        // zboot's canonical file or its fallback: both paths are written.
        for seeded in [CANONICAL, FALLBACK] {
            let scratch = Scratch::new();
            put(&scratch.0, seeded, b"ID=zboot\n");
            let target = planned(&scratch.0, &efi, false).unwrap();
            assert_eq!(paths(&target), [FALLBACK, CANONICAL]);
            publish_at(&scratch.0, &target, &efi, &mut |_| Ok(())).unwrap();
            for path in DESTINATIONS {
                assert_eq!(
                    identity(&scratch.0, path).unwrap(),
                    Some(efi.identity().unwrap())
                );
            }
        }
        // Without one of zboot's own files at its paths or a stale one an
        // ESP is not selected: another system's files, zboot UKIs elsewhere,
        // a stray subdirectory or an old operations record.
        let scratch = Scratch::new();
        for path in DESTINATIONS {
            put(&scratch.0, path, b"ID=another-system\n");
        }
        for path in [
            "EFI/Linux/zboot.efi",
            "EFI/zboot/nested/zboot.efi",
            "EFI/zboot/operations/old.efi",
        ] {
            put(&scratch.0, path, b"ID=zboot\n");
        }
        assert!(planned(&scratch.0, &efi, false).is_none());
        assert!(stale_at(&scratch.0).unwrap().is_empty());
    }

    #[test]
    fn a_file_that_is_not_a_zboot_uki_is_another_systems() {
        let scratch = Scratch::new();
        fs::create_dir_all(scratch.0.join("EFI/zboot")).unwrap();
        fs::write(scratch.0.join(CANONICAL), b"zboot filename").unwrap();
        let efi = source_fixture(&scratch.0);
        let target = planned(&scratch.0, &efi, true).unwrap();
        assert_eq!(target.foreign_replacements, [CANONICAL]);
        let plan = explicit_plan(&efi, vec![target]);
        assert!(plan.needs_confirmation());
        assert_eq!(refresh_typed(&plan).text, "disk-A");
    }

    #[test]
    fn an_install_writes_both_paths_unless_zboot_is_installed() {
        let efi_root = Scratch::new();
        let efi = source_fixture(&efi_root.0);
        let other = b"ID=another-system\n".as_slice();
        let zboot = b"ID=zboot\n".as_slice();
        /// Seed, paths written in order, typed replacements, foreign left in place.
        type Case<'a> = (
            &'a [(&'a str, &'a [u8])],
            &'a [&'a str],
            &'a [&'a str],
            &'a [&'a str],
        );
        let cases: [Case; 5] = [
            (
                &[(FALLBACK, other)],
                &[FALLBACK, CANONICAL],
                &[FALLBACK],
                &[],
            ),
            // A zboot fallback alone does not make the ESP installed.
            (
                &[(CANONICAL, other), (FALLBACK, zboot)],
                &[FALLBACK, CANONICAL],
                &[CANONICAL],
                &[],
            ),
            // Installed: the install refreshes and keeps a foreign fallback.
            (&[(CANONICAL, zboot)], &[FALLBACK, CANONICAL], &[], &[]),
            (
                &[(CANONICAL, zboot), (FALLBACK, other)],
                &[CANONICAL],
                &[],
                &[FALLBACK],
            ),
            // A stale loader does not make the ESP installed.
            (
                &[(RECOVERY, zboot), (FALLBACK, other)],
                &[FALLBACK, CANONICAL],
                &[FALLBACK],
                &[],
            ),
        ];
        for (seed, expected, foreign, left) in cases {
            let scratch = Scratch::new();
            for (path, release) in seed {
                put(&scratch.0, path, release);
            }
            let target = planned(&scratch.0, &efi, true).unwrap();
            let written: Vec<_> = ordered(&target.review)
                .map(|(path, _)| path.as_str())
                .collect();
            assert_eq!(written, expected, "{seed:?}");
            assert_eq!(target.foreign_replacements, foreign, "{seed:?}");
            assert_eq!(kept(&target).collect::<Vec<_>>(), left, "{seed:?}");
            let plan = explicit_plan(&efi, vec![target.clone()]);
            validate_refresh(&plan).unwrap();
            assert_eq!(plan.needs_confirmation(), !foreign.is_empty());
            let before: Vec<_> = left
                .iter()
                .map(|path| fs::read(scratch.0.join(path)).unwrap())
                .collect();
            publish_at(&scratch.0, &target, &efi, &mut |_| Ok(())).unwrap();
            for path in written {
                assert_eq!(
                    identity(&scratch.0, path).unwrap(),
                    Some(efi.identity().unwrap())
                );
            }
            for (path, bytes) in left.iter().zip(before) {
                assert_eq!(fs::read(scratch.0.join(path)).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn deploy_writes_zboot_efi_and_the_fallback_only_when_asked() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        let efi = source_fixture(root);
        // Deploy's own new ESP: both paths, both empty.
        let fresh = deploy_review(target_fixture(), &efi, root, true, 512 * MIB).unwrap();
        assert_eq!(
            fresh.previous,
            [(CANONICAL.into(), None), (FALLBACK.into(), None)].into()
        );
        validate_review(&fresh).unwrap();
        // An existing ESP on another disk keeps its fallback.
        put(root, FALLBACK, b"ID=zboot\n");
        let fallback = identity(root, FALLBACK).unwrap();
        let kept = deploy_review(target_fixture(), &efi, root, false, 512 * MIB).unwrap();
        assert_eq!(kept.previous, [(CANONICAL.into(), None)].into());
        validate_review(&kept).unwrap();
        let mut source = efi.open().unwrap();
        execute(root, &kept, &mut source, &mut |_| Ok(())).unwrap();
        assert_eq!(identity(root, FALLBACK).unwrap(), fallback);
        assert_eq!(
            identity(root, CANONICAL).unwrap(),
            Some(efi.identity().unwrap())
        );
        // zboot's loader at the canonical name is refreshed in place; a stale
        // one under an old name is neither written nor a reason to refuse.
        put(root, RECOVERY, b"ID=zboot\n");
        let refreshed = deploy_review(target_fixture(), &efi, root, false, 512 * MIB).unwrap();
        assert_eq!(refreshed.previous.keys().collect::<Vec<_>>(), [CANONICAL]);
        assert!(refreshed.previous[CANONICAL].is_some());
        // Another system's file at either path is refused, fallback included
        // when deploy keeps it; another system's file elsewhere is not.
        put(root, "EFI/zboot/custom.efi", b"ID=another-system\n");
        put(root, "EFI/vendor/other.efi", b"ID=another-system\n");
        deploy_review(target_fixture(), &efi, root, false, 512 * MIB).unwrap();
        for path in DESTINATIONS {
            let before = fs::read(root.join(path)).unwrap();
            put(root, path, b"ID=another-system\n");
            for replace in [false, true] {
                let error = deploy_review(target_fixture(), &efi, root, replace, 512 * MIB)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("belongs to another system"), "{error}");
                assert!(error.contains(path), "{error}");
                assert!(error.contains("choose another ESP"), "{error}");
            }
            fs::write(root.join(path), before).unwrap();
        }
    }

    #[test]
    fn status_lists_both_paths_then_stale_loaders_only() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        put(root, CANONICAL, b"ID=zboot\nVERSION=now\n");
        put(root, RECOVERY, b"ID=zboot\nVERSION=old\n");
        put(root, "EFI/zboot/old.efi", b"ID=zboot\nVERSION=old\n");
        put(root, "EFI/zboot/other.efi", b"ID=another-system\n");
        put(root, "EFI/Linux/zboot.efi", b"ID=zboot\n");
        put(root, "EFI/zboot/operations/old.efi", b"ID=zboot\n");
        put(root, FALLBACK, b"ID=another-system\n");
        symlink("/outside", root.join("EFI/zboot/escape.efi")).unwrap();
        let installed = identity(root, CANONICAL).unwrap().unwrap();
        let loaders = loaders_at(root, Some(&installed)).unwrap();
        type Shown<'a> = (&'a str, Option<LoaderOwner>, Option<bool>, bool, bool, bool);
        fn shown(loader: &Loader) -> Shown<'_> {
            (
                loader.path.as_str(),
                loader.owner,
                loader.matches_installed,
                loader.identity.is_some(),
                loader.error.is_some(),
                loader.stale,
            )
        }
        assert_eq!(
            loaders.iter().map(shown).collect::<Vec<_>>(),
            [
                (
                    CANONICAL,
                    Some(LoaderOwner::Zboot),
                    Some(true),
                    true,
                    false,
                    false
                ),
                (FALLBACK, Some(LoaderOwner::Other), None, true, false, false),
                (
                    "EFI/zboot/old.efi",
                    Some(LoaderOwner::Zboot),
                    None,
                    false,
                    false,
                    true
                ),
                (RECOVERY, Some(LoaderOwner::Zboot), None, false, false, true),
            ]
        );
        assert_eq!(
            serde_json::to_value(&loaders[3]).unwrap(),
            serde_json::json!({"path": RECOVERY, "owner": "zboot", "stale": true})
        );
        assert!(
            serde_json::to_value(&loaders[0])
                .unwrap()
                .get("stale")
                .is_none()
        );
        assert!(
            loaders_at(root, None)
                .unwrap()
                .iter()
                .all(|loader| loader.matches_installed.is_none())
        );
    }

    #[test]
    fn a_cut_atomic_temporary_is_never_reported_or_adopted() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        for temporary in [
            format!("EFI/zboot/.zboot-{}.tmp", uuid::Uuid::new_v4()),
            format!("EFI/zboot/.ZBOOT-{}.TMP", uuid::Uuid::new_v4()),
        ] {
            put(&scratch.0, &temporary, b"ID=zboot\n");
        }
        assert!(stale_at(&scratch.0).unwrap().is_empty());
        assert!(planned(&scratch.0, &efi, false).is_none());
    }

    #[test]
    fn plans_bind_preimages_and_classification() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        let efi = source_fixture(root);
        put(root, CANONICAL, b"ID=zboot\n");
        put(root, FALLBACK, b"ID=another-system\n");
        let target = planned(root, &efi, false).unwrap();
        let expected = efi.identity().unwrap();
        admit_refresh(root, &target, &expected).unwrap();
        // The foreign fallback is left in place but bound: so is any change.
        for (path, release) in [
            (FALLBACK, b"ID=another-system\nVERSION=2\n".as_slice()),
            (FALLBACK, b"ID=zboot\n"),
            (CANONICAL, b"ID=zboot\nVERSION=2\n"),
            (CANONICAL, b"ID=another-system\n"),
        ] {
            let before = fs::read(root.join(path)).unwrap();
            put(root, path, release);
            let refused = publish_at(root, &target, &efi, &mut |_| Ok(())).unwrap_err();
            assert!(
                refused.to_string().contains("findings changed"),
                "{path}: {refused}"
            );
            assert_ne!(planned(root, &efi, false), Some(target.clone()));
            fs::write(root.join(path), before).unwrap();
        }
        assert_eq!(planned(root, &efi, false), Some(target.clone()));
        // An explicit plan validates; a path outside zboot's two is refused.
        let mut plan = explicit_plan(&efi, vec![planned(root, &efi, true).unwrap()]);
        validate_refresh(&plan).unwrap();
        let review = &mut plan.targets[0].review;
        review.previous.insert("EFI/Linux/zboot.efi".into(), None);
        review.loss_token = token(review).unwrap();
        assert!(validate_refresh(&plan).is_err());
        // A stale loader that appears is not written, so it does not stop a
        // reviewed write.
        put(root, RECOVERY, b"ID=zboot\n");
        publish_at(root, &target, &efi, &mut |_| Ok(())).unwrap();
        assert_eq!(identity(root, CANONICAL).unwrap(), Some(expected));
    }

    #[test]
    fn reviews_have_one_schema_and_write_only_zboots_paths() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        let valid = review(
            target_fixture(),
            efi,
            [(CANONICAL.into(), None), (FALLBACK.into(), None)].into(),
            512 * MIB,
        )
        .unwrap();
        validate_review(&valid).unwrap();
        let retoken = |mut review: EspReview| {
            review.loss_token = token(&review).unwrap();
            review
        };
        let mut empty = valid.clone();
        empty.previous.clear();
        assert!(validate_review(&retoken(empty)).is_err());
        let temporary = format!("EFI/zboot/.zboot-{}.tmp", uuid::Uuid::new_v4());
        for path in [
            RECOVERY,
            "EFI/zboot/ZBOOT.EFI",
            "efi/boot/bootx64.efi",
            "EFI/Linux/zboot.efi",
            "EFI/zboot/nested/zboot.efi",
            "EFI/zboot/",
            "EFI/zboot/..",
            "/EFI/zboot/zboot.efi",
            "EFI/BOOT/other.efi",
            temporary.as_str(),
        ] {
            let mut review = valid.clone();
            review.previous.insert(path.into(), None);
            assert!(validate_review(&retoken(review)).is_err(), "{path}");
        }
        let mut stale = valid.clone();
        stale.previous.remove(FALLBACK);
        assert!(validate_review(&stale).is_err());
        validate_review(&retoken(stale)).unwrap();
    }

    #[test]
    fn free_space_is_checked_once_when_planned() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        let efi = source_fixture(root);
        let refused = refresh_target(
            target_fixture(),
            &efi,
            true,
            root,
            2 * MIB + METADATA_RESERVE - 1,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(refused.contains("bytes free"), "{refused}");
        let target = refresh_target(
            target_fixture(),
            &efi,
            true,
            root,
            2 * MIB + METADATA_RESERVE,
        )
        .unwrap()
        .target
        .unwrap();
        publish_at(root, &target, &efi, &mut |_| Ok(())).unwrap();
        // Paths that already hold the new bytes need no space.
        assert_eq!(
            required_space(&planned(root, &efi, true).unwrap().review).unwrap(),
            0
        );
        refresh_target(target_fixture(), &efi, true, root, 0).unwrap();
    }
    fn target_fixture() -> PartitionIdentity {
        PartitionIdentity {
            disk: DiskIdentity {
                path: "/dev/vda".into(),
                device_number: "252:0".into(),
                sysfs_path: "/sys/devices/virtio/block/vda".into(),
                bytes: 2 * 1024 * MIB,
                logical_sector: 512,
                physical_sector: 4096,
                serial: Some("disk-A".into()),
                wwn: None,
                model: Some("fixture".into()),
            },
            partition: Partition {
                path: "/dev/vda1".into(),
                device_number: "252:1".into(),
                bytes: 512 * MIB,
                partition_uuid: Some("partition-A".into()),
                filesystem: Some("vfat".into()),
                filesystem_uuid: Some("FAT-A".into()),
                filesystem_label: None,
            },
            number: 1,
            partition_type: Some(ESP_TYPE.into()),
            readonly: false,
        }
    }
    fn source_fixture(root: &Path) -> crate::loader::EfiFile {
        let path = root.join("source.efi");
        let sections: [(&[u8], &[u8]); 4] = [
            (b".linux", b"kernel"),
            (b".initrd", b"initrd"),
            (b".cmdline", b"zboot.recovery=1"),
            (b".osrel", b"ID=zboot\n"),
        ];
        let mut bytes = vec![0; 1024 + 512 * sections.len()];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&128u32.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[134..136].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        bytes[148..150].copy_from_slice(&240u16.to_le_bytes());
        bytes[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[220..222].copy_from_slice(&10u16.to_le_bytes());
        for (index, (name, data)) in sections.iter().enumerate() {
            let at = 392 + index * 40;
            let raw = 1024 + index * 512;
            bytes[at..at + name.len()].copy_from_slice(name);
            bytes[at + 8..at + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            bytes[at + 16..at + 20].copy_from_slice(&512u32.to_le_bytes());
            bytes[at + 20..at + 24].copy_from_slice(&(raw as u32).to_le_bytes());
            bytes[raw..raw + data.len()].copy_from_slice(data);
        }
        fs::write(&path, bytes).unwrap();
        crate::loader::EfiFile::inspect(&path).unwrap()
    }
    fn planned(root: &Path, efi: &EfiFile, explicit: bool) -> Option<RefreshTarget> {
        refresh_target(target_fixture(), efi, explicit, root, 512 * MIB)
            .unwrap()
            .target
    }
    fn block(path: &str, number: &str, kind: &str, children: Vec<device::Block>) -> device::Block {
        device::Block {
            path: path.into(),
            device_number: number.into(),
            kind: kind.into(),
            size: 2 * 1024 * MIB,
            logical_sector: 512,
            physical_sector: 4096,
            ro: false,
            serial: None,
            wwn: None,
            model: None,
            fstype: None,
            label: None,
            uuid: None,
            partuuid: None,
            parttype: (kind == "part").then(|| ESP_TYPE.into()),
            ptuuid: None,
            mountpoints: vec![],
            children,
        }
    }
    fn member_landscape(target: &PartitionIdentity) -> Vec<device::Block> {
        vec![block(
            &target.disk.path,
            &target.disk.device_number,
            "disk",
            vec![block(
                &target.partition.path,
                &target.partition.device_number,
                "part",
                vec![],
            )],
        )]
    }
    fn member_storage(target: &PartitionIdentity) -> Vec<device::PoolStorage> {
        vec![device::PoolStorage {
            pool: "rpool".into(),
            guid: zfs_tools::engine::Guid::new(1),
            disks: vec![target.disk.clone()],
        }]
    }
    fn inspect_fixture(
        root: &Path,
        target: &PartitionIdentity,
        efi: &crate::loader::EfiFile,
        explicit: bool,
    ) -> std::io::Result<Inspection> {
        refresh_target(target.clone(), efi, explicit, root, 512 * MIB)
    }
    #[test]
    fn automatic_enumeration_never_observes_unrelated_unidentified_esps() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        fs::create_dir_all(scratch.0.join("EFI/zboot")).unwrap();
        loader_fixture(&scratch.0.join(CANONICAL), b"ID=zboot\n");
        let member = target_fixture();
        let mut landscape = member_landscape(&member);
        for (path, disk_number, part_number, kind) in [
            ("/dev/zd0", "230:0", "230:1", "disk"),
            ("/dev/vdb", "252:16", "252:17", "disk"),
            ("/dev/loop9", "7:9", "259:9", "loop"),
        ] {
            landscape.push(block(
                path,
                disk_number,
                kind,
                vec![block(&format!("{path}p1"), part_number, "part", vec![])],
            ));
        }
        let mut observed = Vec::new();
        let plan = refresh_plan_with(
            &[],
            efi,
            member_storage(&member),
            None,
            &landscape,
            |_| Ok(None),
            |name| {
                observed.push(name.to_owned());
                assert_eq!(name, member.partition.path);
                Ok(member.clone())
            },
            |target, efi, explicit| inspect_fixture(&scratch.0, target, efi, explicit),
        )
        .unwrap();
        assert_eq!(observed, [member.partition.path]);
        assert_eq!(plan.targets.len(), 1);
        assert!(plan.automatic);
    }
    fn loader_target_fixture() -> PartitionIdentity {
        let mut target = target_fixture();
        target.disk.path = "/dev/sda".into();
        target.disk.device_number = "8:0".into();
        target.disk.sysfs_path = "/sys/devices/sata/block/sda".into();
        target.disk.serial = Some("disk-S".into());
        target.partition.path = "/dev/sda1".into();
        target.partition.device_number = "8:1".into();
        target.partition.partition_uuid = Some("loader-uuid".into());
        target.partition.filesystem_uuid = Some("FAT-S".into());
        target
    }
    fn loader_landscape(
        member: &PartitionIdentity,
        uuids: &[(&str, &str, &str)],
    ) -> Vec<device::Block> {
        let mut landscape = member_landscape(member);
        for (disk, number, uuid) in uuids {
            let mut part = block(
                &format!("{disk}1"),
                &format!("{}1", &number[..number.len() - 1]),
                "part",
                vec![],
            );
            part.partuuid = Some((*uuid).into());
            landscape.push(block(disk, number, "disk", vec![part]));
        }
        landscape
    }
    #[test]
    fn automatic_plans_add_the_loader_esp_only_on_a_local_disk_of_a_running_host() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        fs::create_dir_all(scratch.0.join("EFI/zboot")).unwrap();
        loader_fixture(&scratch.0.join(CANONICAL), b"ID=zboot\n");
        let member = target_fixture();
        let booted = loader_target_fixture();
        // The booted ESP's disk carries no imported pool; another ESP is unrelated.
        let landscape = loader_landscape(
            &member,
            &[
                ("/dev/sda", "8:0", "LOADER-UUID"),
                ("/dev/sdb", "8:16", "other-uuid"),
            ],
        );
        let observe = |name: &str| match name {
            "/dev/vda1" => Ok(member.clone()),
            "/dev/sda1" => Ok(booted.clone()),
            other => panic!("unrelated ESP {other} must not be observed"),
        };
        // A local disk of a host with imported pools: refreshed with the pair.
        let mut asked = Vec::new();
        let plan = refresh_plan_with(
            &[],
            efi.clone(),
            member_storage(&member),
            Some("Loader-UUID".into()),
            &landscape,
            |path| {
                asked.push(path.to_owned());
                Ok(None)
            },
            observe,
            |target, efi, explicit| inspect_fixture(&scratch.0, target, efi, explicit),
        )
        .unwrap();
        assert_eq!(asked, ["/dev/sda1"]);
        assert_eq!(plan.loader_partuuid.as_deref(), Some("Loader-UUID"));
        assert_eq!(plan.loader_left_alone, None);
        assert_eq!(
            plan.targets
                .iter()
                .map(|target| target.review.target.partition.path.as_str())
                .collect::<Vec<_>>(),
            ["/dev/vda1", "/dev/sda1"]
        );
        validate_refresh(&plan).unwrap();
        // A review whose loader binding is dropped no longer admits the booted ESP.
        let mut unbound = plan.clone();
        unbound.loader_partuuid = None;
        assert!(validate_refresh(&unbound).is_err());
        let mut contradictory = plan.clone();
        contradictory.loader_left_alone = Some("x".into());
        assert!(validate_refresh(&contradictory).is_err());
        // A booted stick, a disk that cannot be judged, or a rescue in RAM with
        // no pool imported is left alone and named; the pool members are still
        // refreshed.
        for (storage, judged, expected) in [
            (member_storage(&member), true, "/dev/sda1 is on a usb disk"),
            (
                member_storage(&member),
                false,
                "/dev/sda1: its disk could not be judged: lsblk failed",
            ),
            (vec![], true, "/dev/sda1: no pool is imported"),
        ] {
            let plan = refresh_plan_with(
                &[],
                efi.clone(),
                storage.clone(),
                Some("loader-uuid".into()),
                &landscape,
                |path| {
                    if judged {
                        Ok(Some(format!("{path} is on a usb disk")))
                    } else {
                        Err(std::io::Error::other("lsblk failed"))
                    }
                },
                observe,
                |target, efi, explicit| inspect_fixture(&scratch.0, target, efi, explicit),
            )
            .unwrap();
            assert_eq!(plan.loader_partuuid, None);
            assert_eq!(plan.loader_left_alone.as_deref(), Some(expected));
            assert_eq!(plan.targets.len(), storage.len());
            assert!(
                loader_note(&plan)
                    .unwrap()
                    .contains("Name it to refresh it")
            );
            validate_refresh(&plan).unwrap();
            let mut reworded = plan.clone();
            reworded.loader_left_alone = Some("another reason".into());
            assert_eq!(
                refresh_consent(&reworded).unwrap(),
                refresh_consent(&plan).unwrap()
            );
        }
        // A loader ESP that cannot be observed, or turns out to be another
        // disk, is left alone too; it never stops the pool members.
        for swapped in [false, true] {
            let plan = refresh_plan_with(
                &[],
                efi.clone(),
                member_storage(&member),
                Some("loader-uuid".into()),
                &landscape,
                |_| Ok(None),
                |name| match name {
                    "/dev/vda1" => Ok(member.clone()),
                    "/dev/sda1" if swapped => {
                        let mut other = booted.clone();
                        other.partition.partition_uuid = Some("other-uuid".into());
                        Ok(other)
                    }
                    _ => Err(refuse("native loader identity unavailable")),
                },
                |target, efi, explicit| inspect_fixture(&scratch.0, target, efi, explicit),
            )
            .unwrap();
            assert_eq!(plan.loader_partuuid, None);
            assert_eq!(
                plan.loader_left_alone.as_deref(),
                Some(if swapped {
                    "/dev/sda1: its disk identity changed during observation"
                } else {
                    "/dev/sda1: native loader identity unavailable"
                })
            );
            assert_eq!(plan.targets.len(), 1);
            validate_refresh(&plan).unwrap();
        }
        // Without a loader variable the plan is the imported-pool selection alone.
        let plan = refresh_plan_with(
            &[],
            efi.clone(),
            member_storage(&member),
            None,
            &landscape,
            |_| panic!("no loader ESP to judge"),
            observe,
            |target, efi, explicit| inspect_fixture(&scratch.0, target, efi, explicit),
        )
        .unwrap();
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(
            (&plan.loader_partuuid, &plan.loader_left_alone),
            (&None, &None)
        );
        // Named partitions never bind the loader ESP.
        let plan = refresh_plan_with(
            &["/dev/vda1".into()],
            efi,
            vec![],
            Some("loader-uuid".into()),
            &[],
            |_| panic!("named partitions are not judged"),
            |_| Ok(member.clone()),
            |target, efi, explicit| inspect_fixture(&scratch.0, target, efi, explicit),
        )
        .unwrap();
        assert_eq!(
            (&plan.loader_partuuid, &plan.loader_left_alone),
            (&None, &None)
        );
        let mut named = plan.clone();
        named.loader_partuuid = Some("loader-uuid".into());
        assert!(validate_refresh(&named).is_err());
    }
    #[test]
    fn automatic_plans_leave_an_ambiguous_loader_esp_alone() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        fs::create_dir_all(scratch.0.join("EFI/zboot")).unwrap();
        loader_fixture(&scratch.0.join(CANONICAL), b"ID=zboot\n");
        let member = target_fixture();
        for other_type in [false, true] {
            let mut landscape = loader_landscape(
                &member,
                &[
                    ("/dev/sda", "8:0", "loader-uuid"),
                    ("/dev/sdb", "8:16", "loader-uuid"),
                ],
            );
            if other_type {
                // A copy that is not typed as an ESP still makes the UUID ambiguous.
                landscape[2].children[0].parttype =
                    Some("0fc63daf-8483-4772-8e79-3d69d8477de4".into());
            }
            let plan = refresh_plan_with(
                &[],
                efi.clone(),
                member_storage(&member),
                Some("loader-uuid".into()),
                &landscape,
                |_| panic!("an ambiguous loader ESP is not judged"),
                |name| {
                    assert_eq!(name, "/dev/vda1", "an ambiguous loader ESP is not observed");
                    Ok(member.clone())
                },
                |target, efi, explicit| inspect_fixture(&scratch.0, target, efi, explicit),
            )
            .unwrap();
            assert_eq!(plan.loader_partuuid, None);
            assert_eq!(
                plan.loader_left_alone.as_deref(),
                Some("2 partitions carry its PARTUUID")
            );
            assert_eq!(plan.targets.len(), 1);
        }
    }
    #[test]
    fn loader_esp_must_be_on_a_fixed_disk() {
        let stack = |rm: &str, hotplug: &str| {
            format!(
                r#"{{"blockdevices":[{{"path":"/dev/nvme1n1p1","type":"part","rm":false,"hotplug":false,"children":[{{"path":"/dev/nvme1n1","type":"disk","tran":"nvme","rm":{rm},"hotplug":{hotplug}}}]}}]}}"#
            )
        };
        assert_eq!(
            removable_refusal("/dev/nvme1n1p1", &stack("false", "false")),
            None
        );
        assert_eq!(
            removable_refusal("/dev/nvme1n1p1", &stack(r#""0""#, r#""0""#)),
            None
        );
        for (rm, hotplug) in [
            ("true", "false"),
            ("false", "true"),
            (r#""1""#, r#""0""#),
            ("null", "false"),
        ] {
            assert_eq!(
                removable_refusal("/dev/nvme1n1p1", &stack(rm, hotplug)).as_deref(),
                Some("/dev/nvme1n1p1 is on a removable or hot-plug disk"),
                "rm={rm} hotplug={hotplug}"
            );
        }
        assert_eq!(
            removable_refusal("/dev/nvme1n1p1", "not json").as_deref(),
            Some("/dev/nvme1n1p1: device stack unreadable")
        );
        // The flat shape util-linux prints for a SATA SSD and a USB stick.
        let host = |disk: &str, tran: &str, flag: bool| {
            format!(
                r#"{{"blockdevices":[{{"path":"{disk}","type":"disk","tran":"{tran}","rm":{flag},"hotplug":{flag}}},{{"path":"{disk}1","type":"part","tran":null,"rm":{flag},"hotplug":{flag}}}]}}"#
            )
        };
        let sata = host("/dev/sda", "sata", false);
        assert_eq!(
            crate::menu::hostid_adopt::transport_refusal("/dev/sda1", &sata),
            None
        );
        assert_eq!(removable_refusal("/dev/sda1", &sata), None);
        let stick = host("/dev/sdb", "usb", true);
        assert_eq!(
            removable_refusal("/dev/sdb1", &stick).as_deref(),
            Some("/dev/sdb1 is on a removable or hot-plug disk")
        );
        assert_eq!(
            crate::menu::hostid_adopt::transport_refusal("/dev/sdb1", &stick).as_deref(),
            Some("/dev/sdb1 is on a usb disk")
        );
    }
    #[test]
    fn automatic_members_still_require_fresh_native_disk_identity() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        let member = target_fixture();
        for native_error in [true, false] {
            let error = refresh_plan_with(
                &[],
                efi.clone(),
                member_storage(&member),
                None,
                &member_landscape(&member),
                |_| Ok(None),
                |_| {
                    if native_error {
                        return Err(refuse("native member identity unavailable"));
                    }
                    let mut changed = member.clone();
                    changed.disk.serial = Some("replacement".into());
                    Ok(changed)
                },
                |_, _, _| panic!("unbound member cannot be mounted"),
            )
            .unwrap_err();
            assert!(error.to_string().contains(if native_error {
                "native member identity unavailable"
            } else {
                "disk identity changed"
            }));
        }
    }
    #[test]
    fn automatic_unformatted_and_readonly_foreign_members_are_left_alone() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        fs::create_dir_all(scratch.0.join("EFI/BOOT")).unwrap();
        loader_fixture(&scratch.0.join(FALLBACK), b"ID=another-system\n");
        for unformatted in [true, false] {
            let mut member = target_fixture();
            member.readonly = true;
            if unformatted {
                member.partition.filesystem = None;
                member.partition.filesystem_uuid = None;
            }
            let mut inspected = false;
            let plan = refresh_plan_with(
                &[],
                efi.clone(),
                member_storage(&member),
                None,
                &member_landscape(&member),
                |_| Ok(None),
                |_| Ok(member.clone()),
                |target, efi, explicit| {
                    inspected = true;
                    assert!(!unformatted, "non-FAT members must not be mounted");
                    inspect_fixture(&scratch.0, target, efi, explicit)
                },
            )
            .unwrap();
            assert!(plan.targets.is_empty());
            assert_eq!(inspected, !unformatted);
        }
        loader_fixture(&scratch.0.join(FALLBACK), b"ID=zboot\n");
        let mut member = target_fixture();
        member.readonly = true;
        assert!(
            refresh_plan_with(
                &[],
                efi,
                member_storage(&member),
                None,
                &member_landscape(&member),
                |_| Ok(None),
                |_| Ok(member.clone()),
                |target, efi, explicit| inspect_fixture(&scratch.0, target, efi, explicit),
            )
            .unwrap_err()
            .to_string()
            .contains("readonly")
        );
    }
    #[test]
    fn explicit_partitions_keep_native_filesystem_and_writable_refusals() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        let names = ["/dev/vda1".into()];
        for mode in [0, 1, 2] {
            let error = refresh_plan_with(
                &names,
                efi.clone(),
                vec![],
                None,
                &[],
                |_| Ok(None),
                |_| {
                    if mode == 0 {
                        return Err(refuse("explicit native identity unavailable"));
                    }
                    let mut target = target_fixture();
                    if mode == 1 {
                        target.partition.filesystem = None;
                    } else {
                        target.readonly = true;
                    }
                    Ok(target)
                },
                |target, efi, explicit| {
                    assert!(explicit);
                    inspect_fixture(&scratch.0, target, efi, explicit)
                },
            )
            .unwrap_err();
            assert!(error.to_string().contains(match mode {
                0 => "explicit native identity unavailable",
                1 => "identity-bound existing GPT/FAT ESP",
                _ => "readonly",
            }));
        }
    }
    #[test]
    fn a_late_esp_failure_is_partial_and_names_what_remains() {
        let stderr = crate::factory::tests::classified_child("esp-batch-late", "esp", 4, |root| {
            let efi = source_fixture(root);
            let first = planned(root, &efi, true).unwrap();
            let mut second = first.clone();
            second.review.target.partition.path = "/dev/vdb1".into();
            second.review.target.disk.path = "/dev/vdb".into();
            let plan = explicit_plan(&efi, vec![first, second]);
            zfs_tools::engine::effect::reset();
            let mut count = 0;
            let done = apply_targets(&plan, |target| {
                count += 1;
                if count == 2 {
                    return Err(refuse("second ESP failed"));
                }
                publish_at(root, target, &efi, &mut |_| Ok(()))
            });
            assert_eq!(count, 2);
            assert!(identity(root, CANONICAL)?.is_some());
            done.map(|_| ())
        });
        assert!(stderr.contains("/dev/vdb1"));
        assert!(stderr.contains("ESPs remaining"));
    }
    #[test]
    fn every_publication_cut_finishes_on_a_rerun() {
        for foreign in [false, true] {
            publication_cuts_finish_on_a_rerun(foreign);
        }
    }
    fn publication_cuts_finish_on_a_rerun(foreign: bool) {
        let seed = |root: &Path| {
            if foreign {
                put(root, FALLBACK, b"ID=another-system\n");
            }
        };
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        seed(&scratch.0);
        let target = planned(&scratch.0, &efi, true).unwrap();
        let mut renames = Vec::new();
        publish_at(&scratch.0, &target, &efi, &mut |path| {
            renames.push(path.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(renames, [FALLBACK, CANONICAL]);
        for cut in 0..renames.len() {
            let scratch = Scratch::new();
            let efi = source_fixture(&scratch.0);
            seed(&scratch.0);
            let before = identity(&scratch.0, FALLBACK).unwrap();
            let target = planned(&scratch.0, &efi, true).unwrap();
            let mut step = 0;
            assert!(
                publish_at(&scratch.0, &target, &efi, &mut |_| {
                    step += 1;
                    if step > cut {
                        Err(refuse("lost reply"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            // The staged copy is gone; the fallback went first.
            let fallback = identity(&scratch.0, FALLBACK).unwrap();
            assert_eq!(
                fallback,
                if cut == 0 {
                    before
                } else {
                    Some(efi.identity().unwrap())
                }
            );
            assert!(!scratch.0.join(CANONICAL).exists());
            for directory in ["EFI/BOOT", DIRECTORY] {
                assert!(
                    fs::read_dir(scratch.0.join(directory))
                        .into_iter()
                        .flatten()
                        .all(|entry| !entry
                            .unwrap()
                            .file_name()
                            .to_str()
                            .unwrap()
                            .starts_with(".zboot-"))
                );
            }
            let fresh = planned(&scratch.0, &efi, true).unwrap();
            publish_at(&scratch.0, &fresh, &efi, &mut |_| Ok(())).unwrap();
            for path in DESTINATIONS {
                assert_eq!(
                    identity(&scratch.0, path).unwrap(),
                    Some(efi.identity().unwrap())
                );
            }
        }
    }
    #[test]
    fn drift_is_refused_and_the_changed_file_kept() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        let efi = source_fixture(root);
        let target = planned(root, &efi, true).unwrap();
        // Every path is checked before anything is written.
        put(root, CANONICAL, b"ID=another-system\n");
        let mut source = efi.open().unwrap();
        assert!(
            execute(root, &target.review, &mut source, &mut |_| Ok(()))
                .unwrap_err()
                .to_string()
                .contains("changed since review")
        );
        assert!(!root.join(FALLBACK).exists());
        // A change while the new copy is staged keeps that change.
        fs::remove_file(root.join(CANONICAL)).unwrap();
        assert!(
            execute(root, &target.review, &mut source, &mut |path| {
                if path == CANONICAL {
                    fs::write(root.join(CANONICAL), b"foreign update")?;
                }
                Ok(())
            })
            .is_err()
        );
        assert_eq!(fs::read(root.join(CANONICAL)).unwrap(), b"foreign update");
        assert_eq!(fs::read_dir(root.join(DIRECTORY)).unwrap().count(), 1);
    }
    #[test]
    fn matching_loaders_are_synced_without_rewrite() {
        let scratch = Scratch::new();
        let efi = source_fixture(&scratch.0);
        let first = planned(&scratch.0, &efi, true).unwrap();
        publish_at(&scratch.0, &first, &efi, &mut |_| Ok(())).unwrap();
        let fresh = planned(&scratch.0, &efi, true).unwrap();
        let before: Vec<_> = fresh
            .review
            .previous
            .keys()
            .map(|path| {
                let m = fs::metadata(scratch.0.join(path)).unwrap();
                (path.clone(), m.ino(), m.mtime(), m.mtime_nsec())
            })
            .collect();
        let mut source = efi.open().unwrap();
        execute(&scratch.0, &fresh.review, &mut source, &mut |_| {
            panic!("matching bytes are not staged again")
        })
        .unwrap();
        for (path, inode, mtime, nsec) in before {
            let m = fs::metadata(scratch.0.join(path)).unwrap();
            assert_eq!((m.ino(), m.mtime(), m.mtime_nsec()), (inode, mtime, nsec));
        }
        assert_eq!(source.stream_position().unwrap(), 0);
    }
    #[test]
    fn matching_loader_sync_failures_are_partial_in_a_fresh_process() {
        let stderr = crate::factory::tests::classified_child("esp-match-sync", "esp", 4, |root| {
            let efi = source_fixture(root);
            let first = planned(root, &efi, true).unwrap();
            publish_at(root, &first, &efi, &mut |_| Ok(())).unwrap();
            put(root, CANONICAL, b"ID=zboot\nVERSION=old\n");
            let fresh = planned(root, &efi, true).unwrap();
            let mut source = efi.open()?;
            zfs_tools::engine::effect::reset();
            execute(root, &fresh.review, &mut source, &mut |_| {
                Err(refuse(
                    "failure after admitted matching-loader synchronization",
                ))
            })
        });
        assert!(stderr.contains("failure after admitted matching-loader synchronization"));
    }
}
