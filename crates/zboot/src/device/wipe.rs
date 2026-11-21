//! How `wipe` erases a whole disk (docs/DESIGN.md, "Wiping a disk").
//!
//! A sanitize erases a whole NVM subsystem, so an NVMe disk is sanitized only
//! when that subsystem is exactly the disk: one PCIe controller, the disk its
//! only namespace, and crypto or block erase among the controller's sanitize
//! actions. Every other disk has its metadata cleared: ZFS labels, signatures
//! and partition tables, saved partition extents first, then the disk; the
//! data between them stays in place. Either way a fresh probe, never a
//! reread of the disk, checks the result.
use super::{DiskIdentity, DiskReview, refuse};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zfs_tools::engine::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Method {
    /// NVMe Sanitize of the disk's NVM subsystem, whose only namespace is
    /// the disk and whose only controller is `controller`.
    Sanitize {
        action: Action,
        /// The controller character device the admin commands go to.
        controller: String,
        /// Its kernel device number (`MAJ:MIN`), which the node must still
        /// have when the sanitize is submitted.
        device_number: String,
        /// The disk's namespace id.
        nsid: u32,
    },
    /// Clear ZFS labels, signatures and partition tables; the data between
    /// them is not erased.
    Clear {
        reason: ClearReason,
        /// The partitions' extents on the disk, saved before anything is
        /// cleared, so their ZFS labels are found after the table is gone.
        extents: Vec<Extent>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    CryptoErase,
    BlockErase,
}

impl Action {
    /// The Sanitize Action field (SANACT) of the command.
    fn sanact(self) -> u32 {
        match self {
            Action::BlockErase => 2,
            Action::CryptoErase => 4,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Action::BlockErase => "block erase",
            Action::CryptoErase => "crypto erase",
        }
    }
}

/// Why a disk gets metadata clearing rather than a sanitize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearReason {
    /// Not an NVMe namespace (SATA, SCSI, virtio, or a USB bridge whose NVMe
    /// admin path is not identified).
    NotNvme,
    /// NVMe over a fabric: the subsystem is remote and may be shared.
    Fabric,
    /// The kernel shows more than one controller of the subsystem, or the
    /// controller (CMIC) or namespace (NMIC) reports it may be shared.
    MultipleControllers,
    /// The subsystem holds, or may hold, a namespace besides the disk.
    MultipleNamespaces,
    /// The controller supports no sanitize action.
    NoSanitize,
    /// The controller supports only overwrite, which zboot does not use.
    OverwriteOnly,
}

impl ClearReason {
    fn text(self) -> &'static str {
        match self {
            ClearReason::NotNvme => "not an NVMe namespace",
            ClearReason::Fabric => "NVMe over a fabric",
            ClearReason::MultipleControllers => "its NVM subsystem may have other controllers",
            ClearReason::MultipleNamespaces => "its NVM subsystem may hold other namespaces",
            ClearReason::NoSanitize => "the controller has no sanitize",
            ClearReason::OverwriteOnly => "the controller sanitizes only by overwrite",
        }
    }
}

/// A byte range of the disk: a partition as the kernel saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extent {
    pub path: String,
    pub start: u64,
    pub bytes: u64,
}

/// What a completed `wipe` established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WipeOutcome {
    pub identity: DiskIdentity,
    pub method: Method,
    /// What was done, in the terms the evidence supports: a sanitize is what
    /// the controller reported, never an independent proof of erasure.
    pub report: String,
    pub complete: bool,
}

impl Method {
    /// One line for lists and plans.
    pub fn summary(&self) -> String {
        match self {
            Method::Sanitize { action, .. } => format!("NVMe sanitize ({})", action.name()),
            Method::Clear { reason, .. } => format!("metadata clearing ({})", reason.text()),
        }
    }
    /// The plan's description of the effect, every line indented.
    pub fn describe(&self) -> String {
        match self {
            Method::Sanitize {
                action,
                controller,
                nsid,
                ..
            } => format!(
                "  Effect: NVMe sanitize, {}, of namespace {nsid} through {}, the only\n          namespace and controller of its NVM subsystem\n  Note:   a sanitize cannot be aborted and resumes after power loss; one\n          already running is waited out first; the result is what the\n          controller reports\n",
                action.name(),
                zfs_tools::engine::escape_display(controller)
            ),
            Method::Clear { reason, .. } => format!(
                "  Effect: ZFS labels, signatures and partition tables are cleared\n          ({}); the data itself is not erased\n",
                reason.text()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Native access, faked in tests.

/// The `nvme` CLI (nvme-cli).
pub(crate) trait Nvme {
    /// A read-only admin query: `nvme ARGS --output-format=json`.
    fn query(&mut self, args: &[String]) -> Result<String, Error>;
    /// Submit Sanitize; `Ok` only when the controller accepted the command.
    fn sanitize(&mut self, controller: &str, action: Action) -> Result<(), Error>;
    /// Wait between sanitize log polls.
    fn pause(&mut self);
    /// The kernel device number (`MAJ:MIN`) of the character device at
    /// `path`; refuses anything else, a symlink included.
    fn node(&mut self, path: &str) -> Result<String, Error>;
}

/// Everything an erase does to the machine.
pub(crate) trait Effects: Nvme {
    type Claim;
    /// A fresh inventory of a disk and its usage guards.
    fn plan(&mut self, path: &str) -> Result<DiskReview, Error>;
    /// Open `path` exclusively and check it is still `device_number`.
    fn claim(&mut self, path: &str, device_number: &str) -> Result<Self::Claim, Error>;
    /// Have the kernel reread the claimed disk's partition table.
    fn reread(&mut self, claim: &Self::Claim) -> Result<(), Error>;
    /// Run a fixed native program.
    fn run(&mut self, program: &'static str, args: &[String]) -> Result<(), Error>;
    /// libblkid probe (`zboot-probe-signatures`): `Ok` only when it finds
    /// nothing.
    fn probe(&mut self, path: &str) -> Result<(), Error>;
    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> Result<(), Error>;
}

pub(crate) const PROBE: &str = "/sbin/zboot-probe-signatures";

/// An erase is verified by the probe, after the fact. A system without it
/// (the `zboot` package and the UKI both ship it) must refuse the plan, so
/// that no disk is erased and then left unverified.
pub(crate) fn require_probe(probe: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(probe) {
        Ok(metadata) if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 => Ok(()),
        _ => Err(refuse(format!(
            "{} is missing or not executable: an erase could not be verified, so none is planned (the zboot package installs it)",
            probe.display()
        ))),
    }
}

pub(crate) struct Native;

impl Nvme for Native {
    fn query(&mut self, args: &[String]) -> Result<String, Error> {
        let mut args = args.to_vec();
        args.push("--output-format=json".into());
        crate::native_run::run("nvme", &args, 1 << 20, 60)
    }
    fn sanitize(&mut self, controller: &str, action: Action) -> Result<(), Error> {
        let args = [
            "sanitize".into(),
            controller.into(),
            format!("--sanact={}", action.sanact()),
        ];
        let output = crate::native_run::run_status_mutating("nvme", &args, 64 << 10, 60)?;
        if !output.status.success() {
            return Err(refuse(format!(
                "{}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }
    fn pause(&mut self) {
        std::thread::sleep(std::time::Duration::from_secs(POLL_SECONDS));
    }
    fn node(&mut self, path: &str) -> Result<String, Error> {
        use std::os::unix::fs::FileTypeExt;
        let metadata = fs::symlink_metadata(path)
            .map_err(|e| refuse(format!("cannot inspect {path}: {e}")))?;
        if !metadata.file_type().is_char_device() {
            return Err(refuse(format!("{path} is not a character device")));
        }
        Ok(super::device_number(&metadata))
    }
}

impl Effects for Native {
    type Claim = fs::File;
    fn plan(&mut self, path: &str) -> Result<DiskReview, Error> {
        super::inventory(path, None)
    }
    fn claim(&mut self, path: &str, device_number: &str) -> Result<fs::File, Error> {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
        // Linux refuses an exclusive open of a mounted or claimed device.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| refuse(format!("cannot claim {path} exclusively: {e}")))?;
        let metadata = file.metadata().map_err(super::io_error)?;
        if !metadata.file_type().is_block_device()
            || super::device_number(&metadata) != device_number
        {
            return Err(refuse(format!("{path} is no longer the reviewed device")));
        }
        Ok(file)
    }
    fn reread(&mut self, claim: &fs::File) -> Result<(), Error> {
        super::reread_partitions(claim)
    }
    fn run(&mut self, program: &'static str, args: &[String]) -> Result<(), Error> {
        zfs_tools::engine::native::run_mutating(program, args).map(drop)
    }
    fn probe(&mut self, path: &str) -> Result<(), Error> {
        let output = crate::native_run::run_status(PROBE, &["--".into(), path.into()], 4096, 60)?;
        probe_result(path, output.status.code(), &output.stdout)
    }
    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> Result<(), Error> {
        use std::os::unix::fs::{FileExt, OpenOptionsExt};
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .and_then(|file| file.read_exact_at(buffer, offset))
            .map_err(|e| refuse(format!("cannot read {path} at {offset}: {e}")))
    }
}

/// The probe helper's protocol: exit 0 with its marker is absence; 2 is a
/// signature, 3 ambiguous signatures; anything else is a failed probe.
fn probe_result(path: &str, code: Option<i32>, stdout: &[u8]) -> Result<(), Error> {
    let path = zfs_tools::engine::escape_display(path);
    match code {
        Some(0) if stdout == b"zboot-signatures-v1:none\n" => Ok(()),
        Some(2) => Err(refuse(format!("{path} still carries a signature"))),
        Some(3) => Err(refuse(format!("{path} carries ambiguous signatures"))),
        _ => Err(refuse(format!(
            "the signature probe of {path} failed; nothing is known about it"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Planning.

/// OACS bit 3: namespace management, the only way a subsystem holds a
/// namespace that is allocated but not active on its controller.
const NAMESPACE_MANAGEMENT: u16 = 1 << 3;

/// Choose how `review`'s disk is erased; `sys` is the sysfs root.
///
/// A sanitize is chosen when its scope, the NVM subsystem, is the disk: the
/// kernel shows one PCIe controller of the subsystem, which reports no
/// multi-controller capability (CMIC 0); its active namespace list is the
/// disk's namespace alone, which is not shareable (NMIC 0); and the
/// subsystem can hold no other namespace (NN 1 without namespace management,
/// or the allocated list is the disk's namespace alone). Any other disk gets
/// metadata clearing with the reason. A query that fails or cannot be read
/// refuses the plan; it never counts as "unsupported".
pub(crate) fn select(
    review: &DiskReview,
    sys: &Path,
    nvme: &mut impl Nvme,
) -> Result<Method, Error> {
    let clear = |reason| -> Result<Method, Error> {
        Ok(Method::Clear {
            reason,
            extents: extents(review, sys)?,
        })
    };
    let Some(kernel) = kernel_namespace(Path::new(&review.identity.sysfs_path), sys)? else {
        return clear(ClearReason::NotNvme);
    };
    if kernel.controllers.iter().any(|c| c.transport != "pcie") {
        return clear(ClearReason::Fabric);
    }
    let [controller] = kernel.controllers.as_slice() else {
        return clear(ClearReason::MultipleControllers);
    };
    if !controller.live {
        return Err(refuse(format!(
            "NVMe controller {} is not live",
            zfs_tools::engine::escape_display(&controller.name)
        )));
    }
    let dev = format!("/dev/{}", controller.name);
    let nsid = kernel.nsid;
    let id = discover(nvme, &["id-ctrl", &dev], parse_id_ctrl)?;
    if id.cntlid != controller.cntlid {
        return Err(refuse(format!(
            "{dev} reports controller id {}, the kernel {}",
            id.cntlid, controller.cntlid
        )));
    }
    let action = if id.sanicap & 1 != 0 {
        Action::CryptoErase
    } else if id.sanicap & 2 != 0 {
        Action::BlockErase
    } else if id.sanicap & 4 != 0 {
        return clear(ClearReason::OverwriteOnly);
    } else {
        return clear(ClearReason::NoSanitize);
    };
    if id.cmic != 0 {
        return clear(ClearReason::MultipleControllers);
    }
    if discover(nvme, &["list-ns", &dev], parse_ns_list)? != [nsid] {
        return clear(ClearReason::MultipleNamespaces);
    }
    let namespace = format!("--namespace-id={nsid}");
    if discover(nvme, &["id-ns", &dev, &namespace], parse_id_ns)? != 0 {
        return clear(ClearReason::MultipleControllers);
    }
    let alone = if id.oacs & NAMESPACE_MANAGEMENT != 0 {
        discover(nvme, &["list-ns", &dev, "--all"], parse_ns_list)? == [nsid]
    } else {
        id.nn == 1
    };
    if !alone {
        return clear(ClearReason::MultipleNamespaces);
    }
    bind(
        nvme,
        &dev,
        controller,
        &id,
        review.identity.serial.as_deref(),
    )?;
    Ok(Method::Sanitize {
        action,
        controller: dev,
        device_number: controller.device_number.clone(),
        nsid,
    })
}

/// The kernel's own NQN for a controller whose SUBNQN it does not use (none
/// reported, or quirk IGNORE_DEV_SUBNQN, as for the XPG GAMMIX S11 Pro's
/// SX8200 controller). A real NQN reads `nqn.2014-08.org.nvmexpress:`.
const KERNEL_NQN: &str = "nqn.2014.08.org.nvmexpress:";

/// A sanitize goes to the character device `dev`, so it must be the kernel's
/// controller of the reviewed disk: the node has the kernel's device number,
/// and the controller answering through it reports the serial that sysfs and
/// the disk's identity show, and the subsystem NQN sysfs shows. Where sysfs
/// shows no NQN, or one the kernel made up, the serial alone binds.
fn bind(
    nvme: &mut impl Nvme,
    dev: &str,
    kernel: &KernelController,
    id: &IdCtrl,
    serial: Option<&str>,
) -> Result<(), Error> {
    let node = nvme.node(dev)?;
    if node != kernel.device_number {
        return Err(refuse(format!(
            "{dev} is device {node}, the kernel's controller {} is {}",
            zfs_tools::engine::escape_display(&kernel.name),
            kernel.device_number
        )));
    }
    if id.sn != kernel.serial || serial != Some(kernel.serial.as_str()) {
        return Err(refuse(format!(
            "the controller behind {dev} is not the reviewed disk's: serial {} (sysfs {}, disk {})",
            zfs_tools::engine::escape_display(&id.sn),
            zfs_tools::engine::escape_display(&kernel.serial),
            zfs_tools::engine::escape_display(serial.unwrap_or("none"))
        )));
    }
    match &kernel.subsysnqn {
        Some(nqn) if !nqn.starts_with(KERNEL_NQN) && id.subnqn.as_ref() != Some(nqn) => {
            Err(refuse(format!(
                "the controller behind {dev} reports another NVM subsystem than the kernel's {}",
                zfs_tools::engine::escape_display(nqn)
            )))
        }
        _ => Ok(()),
    }
}

/// One read-only query, parsed; any failure is a refused discovery.
fn discover<T>(
    nvme: &mut impl Nvme,
    args: &[&str],
    parse: impl FnOnce(&str) -> Result<T, Error>,
) -> Result<T, Error> {
    let failed = |e: Error| {
        refuse(format!(
            "NVMe discovery `nvme {}` failed: {e}",
            zfs_tools::engine::escape_display(&args.join(" "))
        ))
    };
    parse(&nvme.query(&words(args)).map_err(failed)?).map_err(failed)
}

fn failure_mode(dev: &str) -> String {
    format!(
        "{dev}: the last sanitize failed and the controller is in sanitize failure mode; \
         zboot does not leave it (`nvme sanitize {dev} --sanact=exit-failure` is the operator's call)"
    )
}

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

/// Original ZFS member ranges, retained before their partition nodes disappear.
pub(crate) fn label_extents(review: &DiskReview) -> Result<Vec<Extent>, Error> {
    let mut regions: Vec<_> = extents(review, Path::new("/sys"))?
        .into_iter()
        .filter(|extent| {
            review.partitions.iter().any(|partition| {
                partition.path == extent.path
                    && partition.filesystem.as_deref() == Some("zfs_member")
            })
        })
        .collect();
    if review.filesystem.as_deref() == Some("zfs_member") {
        regions.push(Extent {
            path: review.identity.path.clone(),
            start: 0,
            bytes: review.identity.bytes,
        });
    }
    if regions.is_empty() || regions.len() > 16 {
        return Err(refuse("cannot bind the original pool's ZFS label ranges"));
    }
    if super::observe_identity(&review.identity.path)? != review.identity {
        return Err(refuse(
            "disk identity changed while binding ZFS label ranges",
        ));
    }
    Ok(regions)
}

/// Read only the original member ranges on the same physical disk. An
/// exported pool is still present; missing partition nodes prove nothing.
pub(crate) fn labels_present(disk: &DiskIdentity, regions: &[Extent]) -> Result<bool, Error> {
    if super::observe_identity(&disk.path)? != *disk {
        return Err(refuse(
            "disk identity changed before reading original ZFS labels",
        ));
    }
    let present = labels_present_with(disk, regions, &mut Native)?;
    if super::observe_identity(&disk.path)? != *disk {
        return Err(refuse(
            "disk identity changed while reading original ZFS labels",
        ));
    }
    Ok(present)
}

fn labels_present_with(
    disk: &DiskIdentity,
    regions: &[Extent],
    effects: &mut impl Effects,
) -> Result<bool, Error> {
    if regions.is_empty() || regions.len() > 16 {
        return Err(refuse(
            "original ZFS label ranges are missing or exceed the bound",
        ));
    }
    for region in regions {
        if region.bytes < 4 * LABEL
            || region
                .start
                .checked_add(region.bytes)
                .is_none_or(|end| end > disk.bytes)
        {
            return Err(refuse(
                "original ZFS label range lies outside the bound disk",
            ));
        }
        if zfs_label(effects, &disk.path, region.start, region.bytes)?.is_some() {
            return Ok(true);
        }
        // An erased config header is zero. Unrecognized nonzero bytes may be
        // a damaged label, so they cannot authorize removal of a pair.
        let aligned = region.bytes & !(LABEL - 1);
        for offset in [0, LABEL, aligned - 2 * LABEL, aligned - LABEL] {
            let mut header = [0_u8; 12];
            effects.read_at(&disk.path, region.start + offset + (16 << 10), &mut header)?;
            if header != [0; 12] {
                return Err(refuse(
                    "original ZFS label header is unreadable or unrecognized",
                ));
            }
        }
    }
    Ok(false)
}

/// The partitions' extents on the disk, from the kernel.
fn extents(review: &DiskReview, sys: &Path) -> Result<Vec<Extent>, Error> {
    let mut extents = Vec::new();
    for partition in &review.partitions {
        let base = sys.join("dev/block").join(&partition.device_number);
        let sectors = |name: &str| -> Result<u64, Error> {
            read(&base.join(name))?
                .parse::<u64>()
                .map_err(|_| refuse(format!("invalid partition {name} in sysfs")))
        };
        let (start, size) = (sectors("start")?, sectors("size")?);
        // sysfs counts 512-byte sectors whatever the logical sector size.
        let (start, bytes) = (start.checked_mul(512), size.checked_mul(512));
        let (Some(start), Some(bytes)) = (start, bytes) else {
            return Err(refuse("partition extent overflows"));
        };
        if bytes != partition.bytes
            || start
                .checked_add(bytes)
                .is_none_or(|end| end > review.identity.bytes)
        {
            return Err(refuse(format!(
                "partition {} extent disagrees with the disk",
                zfs_tools::engine::escape_display(&partition.path)
            )));
        }
        extents.push(Extent {
            path: partition.path.clone(),
            start,
            bytes,
        });
    }
    Ok(extents)
}

fn read(path: &Path) -> Result<String, Error> {
    fs::read_to_string(path)
        .map(|v| v.trim().to_owned())
        .map_err(|e| refuse(format!("cannot read {}: {e}", path.display())))
}

fn entries(path: &Path) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| refuse(format!("{}: {e}", path.display())))? {
        let entry = entry.map_err(super::io_error)?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

fn numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(digits)
}

/// `nvmeXnY`: a namespace block device (not a hidden `nvmeXcYnZ` path).
fn namespace_name(name: &str) -> bool {
    name.strip_prefix("nvme")
        .and_then(|rest| rest.split_once('n'))
        .is_some_and(|(a, b)| digits(a) && digits(b))
}

#[derive(Debug)]
struct KernelController {
    name: String,
    /// The character device's number (`dev`).
    device_number: String,
    cntlid: u16,
    serial: String,
    /// `None` when sysfs shows none.
    subsysnqn: Option<String>,
    transport: String,
    live: bool,
}

/// What the kernel shows of an NVMe namespace: its id and every controller
/// of its NVM subsystem on this host.
#[derive(Debug)]
struct KernelNamespace {
    nsid: u32,
    controllers: Vec<KernelController>,
}

/// The kernel's view of the namespace whose sysfs directory is `disk`, or
/// `None` when the disk is not an NVMe namespace. A namespace sits under its
/// controller `nvmeN`, or under its `nvme-subsysN` when the kernel gives it a
/// multipath node; either way the subsystem lists its controllers.
fn kernel_namespace(disk: &Path, sys: &Path) -> Result<Option<KernelNamespace>, Error> {
    let name = disk.file_name().map(|n| n.to_string_lossy().into_owned());
    if !name.as_deref().is_some_and(namespace_name) {
        return Ok(None);
    }
    let unknown = || refuse("unrecognized NVMe sysfs topology");
    let parent = disk
        .parent()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(unknown)?;
    let class = sys.join("class/nvme-subsystem");
    let subsystem = if numbered(&parent, "nvme-subsys") {
        class.join(&parent)
    } else if numbered(&parent, "nvme") {
        let mut found = Vec::new();
        for entry in entries(&class)? {
            if class.join(&entry).join(&parent).exists() {
                found.push(class.join(entry));
            }
        }
        match <[PathBuf; 1]>::try_from(found) {
            Ok([one]) => one,
            Err(_) => return Err(unknown()),
        }
    } else {
        return Err(unknown());
    };
    let mut controllers = Vec::new();
    for entry in entries(&subsystem)? {
        if numbered(&entry, "nvme") {
            let dir = subsystem.join(&entry);
            let attribute = |name: &str| read(&dir.join(name));
            controllers.push(KernelController {
                device_number: attribute("dev")?,
                cntlid: attribute("cntlid")?
                    .parse()
                    .map_err(|_| refuse("invalid NVMe controller id in sysfs"))?,
                serial: attribute("serial")?,
                subsysnqn: attribute("subsysnqn").ok().filter(|v| !v.is_empty()),
                transport: attribute("transport")?,
                live: attribute("state")? == "live",
                name: entry,
            });
        }
    }
    if controllers.is_empty() {
        return Err(refuse("the NVMe subsystem has no controller here"));
    }
    let nsid = read(&disk.join("nsid"))?
        .parse()
        .ok()
        .filter(valid_nsid)
        .ok_or_else(|| refuse("invalid NVMe namespace id in sysfs"))?;
    Ok(Some(KernelNamespace { nsid, controllers }))
}

/// NSIDs 0 and FFFFFFFFh name no single namespace.
fn valid_nsid(nsid: &u32) -> bool {
    (1..u32::MAX).contains(nsid)
}

/// The Identify Controller fields `select` reads.
#[derive(Debug, PartialEq, Eq)]
struct IdCtrl {
    sanicap: u32,
    cntlid: u16,
    cmic: u8,
    oacs: u16,
    nn: u32,
    /// The serial, without its space padding.
    sn: String,
    /// The subsystem NQN, which nvme-cli omits when the controller has none.
    subnqn: Option<String>,
}

fn object(text: &str, what: &str) -> Result<serde_json::Map<String, serde_json::Value>, Error> {
    match serde_json::from_str(text) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => Err(refuse(format!("unsupported `nvme {what}` output"))),
    }
}

/// An unsigned field that fits `T`.
fn field<T: TryFrom<u64>>(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    what: &str,
) -> Result<T, Error> {
    map.get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| T::try_from(v).ok())
        .ok_or_else(|| refuse(format!("`nvme {what}` output lacks a valid {key}")))
}

/// `nvme id-ctrl -o json` (nvme-cli 2.x).
fn parse_id_ctrl(text: &str) -> Result<IdCtrl, Error> {
    let map = object(text, "id-ctrl")?;
    Ok(IdCtrl {
        sanicap: field(&map, "sanicap", "id-ctrl")?,
        cntlid: field(&map, "cntlid", "id-ctrl")?,
        cmic: field(&map, "cmic", "id-ctrl")?,
        oacs: field(&map, "oacs", "id-ctrl")?,
        nn: field(&map, "nn", "id-ctrl")?,
        sn: text_field(&map, "sn")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| refuse("`nvme id-ctrl` output lacks a serial"))?,
        subnqn: text_field(&map, "subnqn").filter(|v| !v.is_empty()),
    })
}

fn text_field(map: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(serde_json::Value::as_str)
        .map(|v| v.trim().to_owned())
}

/// `nvme id-ns -o json`: the namespace's NMIC.
fn parse_id_ns(text: &str) -> Result<u8, Error> {
    field(&object(text, "id-ns")?, "nmic", "id-ns")
}

/// `nvme list-ns [--all] -o json`: the namespace ids, sorted.
fn parse_ns_list(text: &str) -> Result<Vec<u32>, Error> {
    let map = object(text, "list-ns")?;
    let list = map
        .get("nsid_list")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| refuse("`nvme list-ns` output lacks nsid_list"))?;
    // One Identify page holds 1024 ids; a full page may continue.
    if list.len() >= 1024 {
        return Err(refuse("too many NVMe namespaces to enumerate"));
    }
    let mut ids = Vec::new();
    for item in list {
        let id = item
            .get("nsid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .filter(valid_nsid)
            .ok_or_else(|| refuse("`nvme list-ns` output has an invalid nsid"))?;
        ids.push(id);
    }
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != count {
        return Err(refuse("`nvme list-ns` output repeats an nsid"));
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// The sanitize status log.

/// The sanitize log as `wipe` reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Log {
    /// SSTAT bits 2:0.
    status: u8,
    /// SSTAT bit 8: nothing was written since the last successful sanitize
    /// (or since manufacture).
    global_erased: bool,
    /// Command dword 10 of the sanitize the log reports; bits 2:0 are its
    /// action.
    cdw10: u32,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Idle,
    InProgress,
    Failed,
    Unknown,
}

impl Log {
    fn state(&self) -> State {
        match self.status {
            // Never sanitized, or the last one succeeded (4: with
            // No-Deallocate inhibited).
            0 | 1 | 4 => State::Idle,
            2 => State::InProgress,
            3 => State::Failed,
            _ => State::Unknown,
        }
    }
    /// The log reports a successful sanitize by `action`.
    fn completed(&self, action: Action) -> bool {
        matches!(self.status, 1 | 4) && self.cdw10 & 7 == action.sanact()
    }
}

/// `nvme sanitize-log -o json` (nvme-cli 2.x): one object keyed by the
/// device name, `sstat` an object with `status` "(N) text" and
/// `global_erased`.
fn parse_sanitize_log(text: &str) -> Result<Log, Error> {
    let map = object(text, "sanitize-log")?;
    let bad = || refuse("unsupported `nvme sanitize-log` output");
    let [(_, serde_json::Value::Object(log))] =
        <[_; 1]>::try_from(map.into_iter().collect::<Vec<_>>()).map_err(|_| bad())?
    else {
        return Err(bad());
    };
    let sstat = log
        .get("sstat")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(bad)?;
    let status = sstat
        .get("status")
        .and_then(serde_json::Value::as_str)
        .and_then(|text| text.strip_prefix('('))
        .and_then(|rest| rest.split_once(')'))
        .and_then(|(n, _)| n.parse::<u8>().ok())
        .filter(|n| *n <= 7)
        .ok_or_else(bad)?;
    let global_erased = match sstat
        .get("global_erased")
        .and_then(serde_json::Value::as_u64)
    {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(bad()),
    };
    Ok(Log {
        status,
        global_erased,
        cdw10: field(&log, "cdw10_info", "sanitize-log")?,
    })
}

fn sanitize_log(nvme: &mut impl Nvme, dev: &str) -> Result<Log, Error> {
    let text = nvme
        .query(&words(&["sanitize-log", dev]))
        .map_err(|e| refuse(format!("cannot read the sanitize log of {dev}: {e}")))?;
    parse_sanitize_log(&text)
}

const POLL_SECONDS: u64 = 2;
/// How long `wipe` watches one sanitize (12 hours) before leaving the
/// controller to finish it on its own.
const WATCH_POLLS: u64 = 12 * 3600 / POLL_SECONDS;
/// Polls after the submission that may show the log unchanged before the
/// outcome counts as unknown.
const UNSEEN_POLLS: u64 = 5;

fn still_running(dev: &str) -> Error {
    refuse(format!(
        "the sanitize on {dev} is still running; the controller continues on its own, \
         even across power loss. Rerun wipe to watch it finish"
    ))
}

fn unknown_status(dev: &str, log: &Log) -> Error {
    refuse(format!(
        "the sanitize status of {dev} is {}, which zboot does not know",
        log.status
    ))
}

/// How a sanitize run ended.
#[derive(Debug, PartialEq, Eq)]
enum Completion {
    /// The log showed this submission complete.
    Observed,
    /// No new sanitize was observed, but the controller reports no user data
    /// written since its last successful crypto erase.
    NotWrittenSince,
}

/// Where the sanitize goes: the controller node, its kernel device number
/// and the disk's serial, all as reviewed.
struct Target<'a> {
    controller: &'a str,
    device_number: &'a str,
    serial: &'a str,
}

/// One straight run: wait out a sanitize already running (one resumes after
/// a power loss), check the node is still the reviewed disk's controller,
/// submit this one, and poll the log until it reports this submission's
/// outcome. Completion counts only when the log records this action and the
/// operation was seen running, or the log changed after the submission: an
/// earlier success left unchanged says nothing about this one, except as
/// below for a crypto erase. A failure, an unknown status, a rejected
/// submission or an outcome that never shows refuses; nothing falls back.
fn run_sanitize(
    nvme: &mut impl Nvme,
    target: &Target,
    action: Action,
) -> Result<Completion, Error> {
    let dev = target.controller;
    let mut before = sanitize_log(nvme, dev)?;
    let mut waited = 0;
    while before.state() == State::InProgress {
        waited += 1;
        if waited > WATCH_POLLS {
            return Err(still_running(dev));
        }
        nvme.pause();
        before = sanitize_log(nvme, dev)?;
    }
    match before.state() {
        State::Idle => {}
        State::Failed => return Err(refuse(failure_mode(dev))),
        State::InProgress | State::Unknown => return Err(unknown_status(dev, &before)),
    }
    // The submission goes to whatever answers at the node now.
    let node = nvme.node(dev)?;
    let sn = discover(nvme, &["id-ctrl", dev], parse_id_ctrl)?.sn;
    if node != target.device_number || sn != target.serial {
        return Err(refuse(format!(
            "{dev} is no longer the reviewed disk's controller (device {node}, serial {}); \
             nothing was submitted",
            zfs_tools::engine::escape_display(&sn)
        )));
    }
    nvme.sanitize(dev, action).map_err(|e| {
        refuse(format!(
            "the controller did not accept the sanitize command ({e}). zboot does not fall \
             back to clearing metadata: read `nvme sanitize-log {dev}`, then rerun wipe"
        ))
    })?;
    let mut running = false;
    for poll in 0..WATCH_POLLS {
        if poll > 0 {
            nvme.pause();
        }
        let log = sanitize_log(nvme, dev)?;
        match log.state() {
            State::InProgress => running = true,
            State::Failed => {
                return Err(refuse(format!(
                    "the controller reports that the sanitize failed; it stays in sanitize \
                     failure mode until the operator resolves it. {}",
                    failure_mode(dev)
                )));
            }
            State::Unknown => return Err(unknown_status(dev, &log)),
            State::Idle => {
                let changed = log != before;
                if log.completed(action) && (running || changed) {
                    return Ok(Completion::Observed);
                }
                if running || changed {
                    return Err(refuse(format!(
                        "the sanitize log of {dev} shows no completion of this {} \
                         (status {}, cdw10 {:#x}); its outcome is unknown",
                        action.name(),
                        log.status,
                        log.cdw10
                    )));
                }
                // Every poll so far showed the log as it was before.
                if poll + 1 >= UNSEEN_POLLS {
                    // A fast crypto erase on a drive nobody wrote since its
                    // last one can finish between polls and leave the log
                    // as it was. Global Data Erased (SSTAT bit 8) is the
                    // controller's own statement that no user data was
                    // written since a successful sanitize, which the log
                    // says was a crypto erase: the disk holds nothing to
                    // lose either way. Any write since, deploy's included,
                    // clears the bit, so this never stands in for a
                    // sanitize of data. Accepted only after the unchanged
                    // polls, so a sanitize that starts late is not left
                    // running; a block erase does not finish between polls.
                    if action == Action::CryptoErase && log.completed(action) && log.global_erased {
                        return Ok(Completion::NotWrittenSince);
                    }
                    return Err(refuse(format!(
                        "the controller accepted the sanitize on {dev} but its log never \
                         showed it: it still reports the earlier state (status {}, cdw10 \
                         {:#x}), which is not this run's completion; the outcome is unknown",
                        log.status, log.cdw10
                    )));
                }
            }
        }
    }
    Err(still_running(dev))
}

// ---------------------------------------------------------------------------
// Erasing and verifying.

const LABEL: u64 = 256 << 10;

/// The offset of the first of the four ZFS labels in `start..start+bytes`
/// whose packed config header (XDR nvlist, version 0, unique names) is
/// present. A region too small for a vdev holds none.
fn zfs_label(
    effects: &mut impl Effects,
    disk: &str,
    start: u64,
    bytes: u64,
) -> Result<Option<u64>, Error> {
    let aligned = bytes & !(LABEL - 1);
    if aligned < 4 * LABEL {
        return Ok(None);
    }
    for offset in [0, LABEL, aligned - 2 * LABEL, aligned - LABEL] {
        let mut header = [0_u8; 12];
        // vdev_phys_t (the config nvlist) follows 16 KiB of pad and boot header.
        effects.read_at(disk, start + offset + (16 << 10), &mut header)?;
        if header[0] == 1
            && header[1] <= 1
            && header[2..8] == [0; 6]
            && header[8..12] == [0, 0, 0, 1]
        {
            return Ok(Some(start + offset));
        }
    }
    Ok(None)
}

fn no_zfs_label(
    effects: &mut impl Effects,
    disk: &str,
    what: &str,
    start: u64,
    bytes: u64,
) -> Result<(), Error> {
    match zfs_label(effects, disk, start, bytes)? {
        None => Ok(()),
        Some(offset) => Err(refuse(format!(
            "a ZFS label remains on {} at byte {offset}",
            zfs_tools::engine::escape_display(what)
        ))),
    }
}

/// A GPT header ("EFI PART") at LBA 1 or the last LBA.
fn no_gpt(effects: &mut impl Effects, identity: &DiskIdentity) -> Result<(), Error> {
    let sector = identity.logical_sector;
    for (which, offset) in [("primary", sector), ("backup", identity.bytes - sector)] {
        let mut signature = [0_u8; 8];
        effects.read_at(&identity.path, offset, &mut signature)?;
        if &signature == b"EFI PART" {
            return Err(refuse(format!(
                "the {which} GPT header remains on {}",
                zfs_tools::engine::escape_display(&identity.path)
            )));
        }
    }
    Ok(())
}

/// A fresh plan of the disk, which should now be bare and unchanged.
fn bare(effects: &mut impl Effects, disk: &DiskIdentity) -> Result<(), Error> {
    let after = effects.plan(&disk.path)?;
    if after.identity != *disk {
        return Err(refuse(format!(
            "{} changed identity during the erase",
            zfs_tools::engine::escape_display(&disk.path)
        )));
    }
    if !after.partitions.is_empty()
        || after.filesystem.is_some()
        || after.partition_table_uuid.is_some()
    {
        return Err(refuse(format!(
            "{} still shows partitions or a filesystem",
            zfs_tools::engine::escape_display(&disk.path)
        )));
    }
    Ok(())
}

/// Erase `review`'s disk by its method. The caller has checked the consent
/// and that a fresh plan still equals `review`.
pub(crate) fn execute<E: Effects>(
    review: &DiskReview,
    effects: &mut E,
) -> Result<WipeOutcome, Error> {
    let report = match &review.method {
        Method::Sanitize {
            action,
            controller,
            device_number,
            nsid,
        } => {
            let serial = review
                .identity
                .serial
                .as_deref()
                .ok_or_else(|| refuse("a sanitize needs the disk's serial"))?;
            let target = Target {
                controller,
                device_number,
                serial,
            };
            match sanitize(review, *action, &target, effects)? {
                Completion::Observed => format!(
                    "the controller reported completion of a sanitize ({}) of namespace {nsid}, \
                     the only one of its NVM subsystem; signatures and ZFS labels are absent",
                    action.name()
                ),
                Completion::NotWrittenSince => format!(
                    "no new sanitize was observed; the controller reports no user data written \
                     since its last successful crypto erase of namespace {nsid}, the only one \
                     of its NVM subsystem; signatures and ZFS labels are absent"
                ),
            }
        }
        Method::Clear { extents, .. } => {
            clear(review, extents, effects)?;
            "ZFS labels, signatures and partition tables are cleared and absent; the data \
             between them is not erased"
                .to_owned()
        }
    };
    Ok(WipeOutcome {
        identity: review.identity.clone(),
        method: review.method.clone(),
        report,
        complete: true,
    })
}

fn sanitize<E: Effects>(
    review: &DiskReview,
    action: Action,
    target: &Target,
    effects: &mut E,
) -> Result<Completion, Error> {
    let disk = &review.identity;
    // Hold the disk exclusively from before the submission until the kernel
    // has reread its table.
    let claim = effects.claim(&disk.path, &disk.device_number)?;
    let completion = run_sanitize(effects, target, action)?;
    effects.reread(&claim)?;
    drop(claim);
    bare(effects, disk)?;
    effects.probe(&disk.path)?;
    no_zfs_label(effects, &disk.path, &disk.path, 0, disk.bytes)?;
    no_gpt(effects, disk)?;
    Ok(completion)
}

fn clear<E: Effects>(
    review: &DiskReview,
    extents: &[Extent],
    effects: &mut E,
) -> Result<(), Error> {
    let disk = &review.identity;
    // Partitions first, each cleared and checked while its node exists.
    for extent in extents {
        let partition = review
            .partitions
            .iter()
            .find(|p| p.path == extent.path)
            .ok_or_else(|| refuse("a saved extent names no reviewed partition"))?;
        drop(effects.claim(&partition.path, &partition.device_number)?);
        if zfs_label(effects, &disk.path, extent.start, extent.bytes)?.is_some() {
            effects.run("zpool", &words(&["labelclear", "-f", &partition.path]))?;
        }
        effects.run("wipefs", &words(&["--all", &partition.path]))?;
        effects.probe(&partition.path)?;
        no_zfs_label(
            effects,
            &disk.path,
            &partition.path,
            extent.start,
            extent.bytes,
        )?;
    }
    drop(effects.claim(&disk.path, &disk.device_number)?);
    if zfs_label(effects, &disk.path, 0, disk.bytes)?.is_some() {
        effects.run("zpool", &words(&["labelclear", "-f", &disk.path]))?;
    }
    effects.run("wipefs", &words(&["--all", &disk.path]))?;
    effects.run("sgdisk", &words(&["--zap-all", &disk.path]))?;
    let claim = effects.claim(&disk.path, &disk.device_number)?;
    effects.reread(&claim)?;
    drop(claim);
    bare(effects, disk)?;
    effects.probe(&disk.path)?;
    no_zfs_label(effects, &disk.path, &disk.path, 0, disk.bytes)?;
    for extent in extents {
        no_zfs_label(
            effects,
            &disk.path,
            &extent.path,
            extent.start,
            extent.bytes,
        )?;
    }
    no_gpt(effects, disk)
}

#[cfg(test)]
mod tests;
