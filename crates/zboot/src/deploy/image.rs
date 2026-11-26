//! A new image file is the authority for its loop, never a physical disk name.
//! Preview binds its absent leaf and parent directory; execution holds the file
//! opened exclusively, and the scoped loop capability is visible to ESP workers.
use super::{CoreOutcome, command, layout, refuse, request};
use crate::device::{self, DiskIdentity};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

const LOSETUP: &str = "/usr/sbin/losetup";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Destination {
    pub path: PathBuf,
    pub parent: PathBuf,
    pub parent_device: u64,
    pub parent_inode: u64,
    pub parent_owner: u32,
    pub parent_mode: u32,
}
impl Destination {
    fn inspect(path: &Path) -> io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| refuse("--image needs a file name"))?;
        if !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        ) {
            return Err(refuse("--image needs a normal file name"));
        }
        let parent = fs::canonicalize(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .map_err(crate::output::naming("--image", path))?;
        let metadata = fs::symlink_metadata(&parent)?;
        if !metadata.is_dir() {
            return Err(refuse("image parent is not a directory"));
        }
        let path = parent.join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(refuse(format!(
                    "--image {} already exists; deploy creates a new image file",
                    path.display()
                )));
            }
            Err(error) => return Err(error),
        }
        Ok(Self {
            path,
            parent,
            parent_device: metadata.dev(),
            parent_inode: metadata.ino(),
            parent_owner: metadata.uid(),
            parent_mode: metadata.mode(),
        })
    }
    fn open_parent(&self) -> io::Result<File> {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.parent)?;
        let metadata = parent.metadata()?;
        if !metadata.is_dir()
            || (
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.mode(),
            ) != (
                self.parent_device,
                self.parent_inode,
                self.parent_owner,
                self.parent_mode,
            )
            || fs::canonicalize(&self.parent)? != self.parent
        {
            return Err(refuse(
                "image parent directory identity changed since preview",
            ));
        }
        Ok(parent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub destination: Destination,
    pub bytes: u64,
    pub request: request::DeployRequest,
    pub inputs: request::Inputs,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
    pub image: PathBuf,
    pub bytes: u64,
    pub review: super::CoreReview,
    pub outcome: CoreOutcome,
    pub loop_detached: bool,
}

/// The ESP plus swap plus the unpacked content with headroom, rounded up to
/// a whole GiB.
fn image_size(request: &request::DeployRequest, inputs: &request::Inputs) -> io::Result<u64> {
    let request::Boot::OnTarget { esp_bytes } = request.boot else {
        return Err(refuse("an image cannot name an existing ESP"));
    };
    let swap = match request.swap {
        request::Swap::None => 0,
        request::Swap::Create { bytes } => bytes,
    };
    let overlay_bytes = inputs.overlays.iter().try_fold(0_u64, |total, overlay| {
        overlay.entries.iter().try_fold(total, |total, entry| {
            let file = match &entry.kind {
                super::overlay::Kind::File { bytes, .. } => *bytes,
                _ => 0,
            };
            total
                .checked_add(file)
                .and_then(|v| v.checked_add(16 * 1024))
                .ok_or_else(|| refuse("overlay image capacity overflow"))
        })
    })?;
    let required = if let Some(tar) = &inputs.factory {
        tar.entries
            .checked_mul(16 * 1024)
            .and_then(|v| v.checked_add(tar.logical_bytes))
            .and_then(|v| v.checked_add(overlay_bytes))
            .and_then(|v| v.checked_add(512 << 20))
            .and_then(|v| v.checked_mul(5))
            .map(|v| v.div_ceil(4))
            .ok_or_else(|| refuse("root content size overflow"))?
            .max(2 << 30)
    } else {
        2 << 30
    };
    let minimum = required
        .checked_add(esp_bytes)
        .and_then(|v| v.checked_add(swap))
        .and_then(|v| v.checked_add(2 << 20))
        .ok_or_else(|| refuse("image size overflow"))?;
    let bytes = minimum
        .checked_add((1 << 30) - 1)
        .map(|v| v / (1 << 30) * (1 << 30))
        .ok_or_else(|| refuse("image size overflow"))?;
    let geometry = DiskIdentity {
        path: String::new(),
        device_number: String::new(),
        sysfs_path: String::new(),
        bytes,
        logical_sector: 512,
        physical_sector: 512,
        serial: None,
        wwn: None,
        model: None,
    };
    layout::Layout::selected(
        &geometry,
        Some(esp_bytes),
        (swap != 0).then_some(swap),
        "image-preview",
    )?;
    if inputs
        .artifacts
        .bytes
        .checked_mul(3)
        .and_then(|v| v.checked_add(16 << 20))
        .is_none_or(|v| v > esp_bytes)
    {
        return Err(refuse("image ESP lacks loader replacement capacity"));
    }
    Ok(bytes)
}

pub fn plan_with(args: &command::Args, backend: &mut impl Backend) -> io::Result<Plan> {
    let command::Target::Image { file } = &args.target else {
        return Err(refuse("image planner needs --image"));
    };
    let destination = Destination::inspect(file)?;
    let mut request = command::request(args, backend.running_hostid()?, PathBuf::new())?;
    command::validate_cli_request(&request)?;
    backend.pool_available(&request.pool)?;
    let inputs = request::inputs(&request)?;
    if let (request::Purpose::Os { factory, .. }, Some(admitted)) =
        (&mut request.purpose, &inputs.factory)
    {
        factory.clone_from(&admitted.path);
    }
    request.boot_artifact_directory = inputs.artifacts.efi.clone();
    request.overlays = inputs
        .overlays
        .iter()
        .take(request.overlays.len())
        .map(|o| o.source.clone())
        .collect();
    let bytes = image_size(&request, &inputs)?;
    Ok(Plan {
        schema_version: 1,
        destination,
        bytes,
        request,
        inputs,
    })
}
pub fn describe(plan: &Plan) -> String {
    let mut text = format!(
        "Deploy into new image {} ({})\n  Pool: {}{}\n",
        zfs_tools::engine::escape_display(&plan.destination.path.display().to_string()),
        device::size(plan.bytes),
        zfs_tools::engine::escape_display(&plan.request.pool),
        if plan.request.portable {
            "; portable, no identity or boot default"
        } else {
            ""
        }
    );
    if let Some(tar) = &plan.inputs.factory {
        text.push_str(&format!(
            "  Root: {} {}\n",
            zfs_tools::engine::escape_display(&tar.path.display().to_string()),
            tar.sha256
        ));
    }
    text.push_str(&format!(
        "  EFI: {} ({}) {}\n",
        zfs_tools::engine::escape_display(&plan.inputs.artifacts.efi.display().to_string()),
        device::size(plan.inputs.artifacts.bytes),
        plan.inputs.artifacts.sha256
    ));
    match &plan.request.purpose {
        request::Purpose::Os { dataset, .. } => text.push_str(&format!(
            "  BE: {}{}\n",
            zfs_tools::engine::escape_display(dataset),
            if plan.request.portable {
                "; no boot default"
            } else {
                " as this pool's boot default"
            }
        )),
        request::Purpose::EmptyRoot { container } => text.push_str(&format!(
            "  Empty: {}; no boot default\n",
            zfs_tools::engine::escape_display(container)
        )),
    }
    if !plan.request.portable {
        text.push_str(&format!(
            "  Hostid: {}\n",
            plan.request.hostid.as_deref().unwrap_or("a new random one")
        ));
    }
    if let Some(hostname) = &plan.request.hostname {
        text.push_str(&format!(
            "  Hostname: {}\n",
            zfs_tools::engine::escape_display(hostname)
        ));
    }
    for overlay in &plan.inputs.overlays {
        text.push_str(&format!(
            "  Overlay: {} {}\n",
            zfs_tools::engine::escape_display(&overlay.source.display().to_string()),
            overlay.sha256
        ));
        for entry in &overlay.entries {
            text.push_str(&format!(
                "    {}  {}\n",
                zfs_tools::engine::escape_display(&entry.path),
                entry.kind
            ));
        }
    }
    text
}

pub struct OwnedFile {
    destination: Destination,
    parent: File,
    file: File,
    device: u64,
    inode: u64,
    bytes: u64,
    portable: bool,
    id: String,
}
impl OwnedFile {
    fn create(destination: &Destination, bytes: u64, portable: bool) -> io::Result<Arc<Self>> {
        use rustix::fs::{Mode, OFlags};
        let parent = destination.open_parent()?;
        let name = destination
            .path
            .file_name()
            .ok_or_else(|| refuse("image file name missing"))?;
        let file = File::from(
            rustix::fs::openat(
                &parent,
                name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|error| {
                let error = io::Error::from(error);
                io::Error::new(
                    error.kind(),
                    format!("--image {}: {error}", destination.path.display()),
                )
            })?,
        );
        // The public image exists now, even if allocation or cleanup fails.
        zfs_tools::engine::effect::mark();
        let metadata = file.metadata()?;
        let owned = Arc::new(Self {
            destination: destination.clone(),
            parent,
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes,
            portable,
            id: uuid::Uuid::new_v4().to_string(),
        });
        let result = (|| {
            owned.file.set_len(bytes)?;
            owned.file.sync_all()?;
            owned.parent.sync_all()?;
            owned.verify()
        })();
        if let Err(error) = result {
            let removed = owned.remove();
            return Err(match removed {
                Ok(()) => error,
                Err(cleanup) => refuse(format!("{error}; new image cleanup failed: {cleanup}")),
            });
        }
        Ok(owned)
    }
    fn held_identity(&self) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        if !metadata.is_file()
            || (metadata.dev(), metadata.ino(), metadata.len())
                != (self.device, self.inode, self.bytes)
        {
            return Err(refuse("created image descriptor identity changed"));
        }
        Ok(())
    }
    fn verify(&self) -> io::Result<()> {
        self.held_identity()?;
        self.destination.open_parent()?;
        let metadata = fs::symlink_metadata(&self.destination.path)?;
        if !metadata.is_file()
            || (metadata.dev(), metadata.ino(), metadata.len())
                != (self.device, self.inode, self.bytes)
        {
            return Err(refuse(
                "created image path no longer names the file zboot owns",
            ));
        }
        Ok(())
    }
    fn remove(&self) -> io::Result<()> {
        use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
        self.destination.open_parent()?;
        let held = self.file.metadata()?;
        let leaf = fs::symlink_metadata(&self.destination.path)?;
        if !held.is_file()
            || !leaf.is_file()
            || (held.dev(), held.ino()) != (self.device, self.inode)
            || (leaf.dev(), leaf.ino()) != (self.device, self.inode)
        {
            return Err(refuse("refusing to remove a replacement image file"));
        }
        // Move into our private directory before checking and unlinking. A
        // replacement raced into the public leaf is restored without deleting
        // it; another user cannot replace the protected leaf after the check.
        let quarantine = format!(".zboot-image-cleanup-{}", uuid::Uuid::new_v4());
        rustix::fs::mkdirat(
            &self.parent,
            quarantine.as_str(),
            Mode::from_raw_mode(0o700),
        )?;
        let directory = File::from(rustix::fs::openat(
            &self.parent,
            quarantine.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let name = self
            .destination
            .path
            .file_name()
            .ok_or_else(|| refuse("image leaf missing"))?;
        let result = (|| {
            rustix::fs::renameat_with(
                &self.parent,
                name,
                &directory,
                "image",
                RenameFlags::NOREPLACE,
            )?;
            let candidate = rustix::fs::statat(&directory, "image", AtFlags::SYMLINK_NOFOLLOW)?;
            if (candidate.st_dev, candidate.st_ino) != (self.device, self.inode) {
                rustix::fs::renameat_with(&directory,"image",&self.parent,name,RenameFlags::NOREPLACE).map_err(|error|refuse(format!("replacement image preserved in {quarantine}; restoring its name failed: {error}")))?;
                return Err(refuse(
                    "a replacement image was restored instead of removed",
                ));
            }
            rustix::fs::unlinkat(&directory, "image", AtFlags::empty())?;
            directory.sync_all()?;
            self.parent.sync_all()
        })();
        // Only this freshly-created, still-empty private directory is removed.
        let cleanup = rustix::fs::unlinkat(&self.parent, quarantine.as_str(), AtFlags::REMOVEDIR)
            .map_err(io::Error::from);
        result?;
        cleanup?;
        self.parent.sync_all()
    }
}

#[repr(C)]
struct LoopInfo {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    sizelimit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}
impl LoopInfo {
    fn empty() -> Self {
        Self {
            device: 0,
            inode: 0,
            rdevice: 0,
            offset: 0,
            sizelimit: 0,
            number: 0,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: 0,
            file_name: [0; 64],
            crypt_name: [0; 64],
            encrypt_key: [0; 32],
            init: [0; 2],
        }
    }
}
#[allow(unsafe_code)]
fn loop_info(path: &Path) -> io::Result<(LoopInfo, fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_block_device() || libc::major(metadata.rdev()) != 7 {
        return Err(refuse("image attachment is not a kernel loop device"));
    }
    let mut info = LoopInfo::empty();
    // Linux UAPI loop_info64 and LOOP_GET_STATUS64 (linux/loop.h). The kernel
    // writes exactly this initialized repr(C) payload borrowed for the call.
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x4c05, &mut info) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((info, metadata))
}
fn kernel_device(device: u64) -> u64 {
    let major = u64::from(libc::major(device));
    let minor = u64::from(libc::minor(device));
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
}
fn backing_matches(file: &OwnedFile, info: &LoopInfo) -> bool {
    info.device == kernel_device(file.device) && info.inode == file.inode && info.rdevice == 0
}
struct Authority {
    file: Arc<OwnedFile>,
    disk: DiskIdentity,
}
impl Authority {
    fn verify(&self, require_path: bool) -> io::Result<()> {
        if require_path {
            self.file.verify()?;
        } else {
            self.file.held_identity()?;
        }
        let (info, metadata) = loop_info(Path::new(&self.disk.path))?;
        if !backing_matches(&self.file, &info)
            || info.offset != 0
            || info.sizelimit != 0
            || info.encrypt_type != 0
            || info.flags & 1 != 0
            || info.flags & 8 == 0
            || info.number != libc::minor(metadata.rdev())
            || format!(
                "{}:{}",
                libc::major(metadata.rdev()),
                libc::minor(metadata.rdev())
            ) != self.disk.device_number
            || fs::canonicalize(Path::new("/sys/dev/block").join(&self.disk.device_number))?
                .to_string_lossy()
                != self.disk.sysfs_path
        {
            return Err(refuse(
                "image loop backing, offset, size, flags or device identity changed",
            ));
        }
        Ok(())
    }
}
static ATTACHED: OnceLock<Mutex<Option<Arc<Authority>>>> = OnceLock::new();
struct Guard {
    authority: Arc<Authority>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(lock) = ATTACHED.get() {
            let mut guard = match lock.lock() {
                Ok(guard) => guard,
                Err(poison) => poison.into_inner(),
            };
            if guard
                .as_ref()
                .is_some_and(|old| old.file.id == self.authority.file.id)
            {
                *guard = None;
            }
        }
    }
}
/// Called by the ordinary device observers, including ESP's scoped threads.
/// Unregistered loops remain unsupported, and every use checks the kernel's
/// backing inode against the open file created by this invocation.
pub(crate) fn admit_loop(
    block: &device::Block,
    sysfs: impl FnOnce() -> io::Result<String>,
) -> io::Result<bool> {
    if block.kind != "loop" {
        return Ok(false);
    }
    let guard = ATTACHED
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| refuse("image loop custody poisoned"))?;
    let Some(authority) = guard.as_ref() else {
        return Ok(false);
    };
    if block.path != authority.disk.path || block.device_number != authority.disk.device_number {
        return Ok(false);
    }
    authority.verify(true)?;
    let sysfs = sysfs()?;
    if block.ro
        || block.size != authority.disk.bytes
        || block.logical_sector != authority.disk.logical_sector
        || block.physical_sector != authority.disk.physical_sector
        || sysfs != authority.disk.sysfs_path
        || device::clean(&block.serial).is_some()
        || device::clean(&block.wwn).is_some()
    {
        return Err(refuse(
            "registered image loop geometry or physical identity changed",
        ));
    }
    Ok(true)
}

pub(super) fn registered_disk(disk: &DiskIdentity) -> io::Result<bool> {
    let guard = ATTACHED
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| refuse("image loop custody poisoned"))?;
    let Some(authority) = guard.as_ref() else {
        return Ok(false);
    };
    authority.verify(true)?;
    Ok(authority.disk == *disk)
}

pub struct Attachment {
    disk: String,
    guard: Option<Guard>,
}
pub trait Backend: command::Backend {
    fn pool_available(&mut self, _pool: &str) -> io::Result<()> {
        Ok(())
    }
    fn prepare_image(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn attach(&mut self, file: Arc<OwnedFile>) -> io::Result<Attachment>;
    fn detach(&mut self, attachment: &Attachment) -> io::Result<()>;
}
pub struct Native;
impl command::Backend for Native {
    fn wipe_plan(&mut self, _: &str) -> io::Result<device::DiskReview> {
        Err(refuse("image deployment never erases a disk"))
    }
    fn running_hostid(&mut self) -> io::Result<u32> {
        command::Backend::running_hostid(&mut command::Native)
    }
    fn attempt(&mut self) -> io::Result<PathBuf> {
        command::Backend::attempt(&mut command::Native)
    }
    fn release(&mut self, path: &Path) {
        command::Backend::release(&mut command::Native, path)
    }
    fn deploy_plan(&mut self, request: &request::DeployRequest) -> io::Result<super::CoreReview> {
        command::Backend::deploy_plan(&mut command::Native, request)
    }
    fn verify_loader(&mut self, loader: &crate::loader::EfiFile) -> io::Result<()> {
        command::Backend::verify_loader(&mut command::Native, loader)
    }
    fn wipe(&mut self, _: &device::DiskReview) -> io::Result<device::WipeOutcome> {
        Err(refuse("image deployment never erases a disk"))
    }
    fn deploy_apply(&mut self, review: &super::CoreReview) -> io::Result<CoreOutcome> {
        command::Backend::deploy_apply(&mut command::Native, review)
    }
}
fn attach_native(file: Arc<OwnedFile>) -> io::Result<Attachment> {
    file.verify()?;
    let output = zfs_tools::engine::native::run(
        LOSETUP,
        &[
            "--find".into(),
            "--show".into(),
            "--partscan".into(),
            file.destination
                .path
                .to_str()
                .ok_or_else(|| refuse("image path is not UTF-8"))?
                .to_owned(),
        ],
    )
    .map_err(refuse)?;
    let path = output.strip_suffix('\n').unwrap_or(&output);
    if !path
        .strip_prefix("/dev/loop")
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err(refuse(
            "losetup did not return exactly one kernel loop path",
        ));
    }
    // Establish ownership from the kernel before any cleanup can detach it.
    let (info, metadata) = loop_info(Path::new(path))?;
    if !backing_matches(&file, &info) {
        return Err(refuse("new loop does not back the created image inode"));
    }
    let registered = (|| {
        let number = format!(
            "{}:{}",
            libc::major(metadata.rdev()),
            libc::minor(metadata.rdev())
        );
        let sysfs = fs::canonicalize(Path::new("/sys/dev/block").join(&number))?;
        let rows = device::observe_landscape().map_err(refuse)?;
        let candidates: Vec<_> = rows
            .blockdevices
            .iter()
            .filter(|block| {
                block.path == path && block.device_number == number && block.kind == "loop"
            })
            .collect();
        let [block] = candidates.as_slice() else {
            return Err(refuse("created loop inventory is missing or ambiguous"));
        };
        let disk = DiskIdentity {
            path: path.into(),
            device_number: number,
            sysfs_path: sysfs.to_string_lossy().into_owned(),
            bytes: block.size,
            logical_sector: block.logical_sector,
            physical_sector: block.physical_sector,
            serial: None,
            wwn: None,
            model: device::clean(&block.model),
        };
        let authority = Arc::new(Authority {
            file: file.clone(),
            disk,
        });
        authority.verify(true)?;
        if authority.disk.bytes != file.bytes {
            return Err(refuse("created loop size differs from the image"));
        }
        let mut registered = ATTACHED
            .get_or_init(|| Mutex::new(None))
            .lock()
            .map_err(|_| refuse("image loop custody poisoned"))?;
        if registered.is_some() {
            return Err(refuse("another owned image loop is already attached"));
        }
        *registered = Some(authority.clone());
        Ok(Attachment {
            disk: path.into(),
            guard: Some(Guard { authority }),
        })
    })();
    match registered {
        Ok(attached) => Ok(attached),
        Err(error) => match detach_owned_path(&file, Path::new(path)) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(io::Error::other(UnclosedAttachment(refuse(format!(
                "{error}; known owned loop cleanup failed: {cleanup}"
            ))))),
        },
    }
}
impl Backend for Native {
    fn pool_available(&mut self, pool: &str) -> io::Result<()> {
        if zfs_tools::engine::state::observe()
            .map_err(refuse)?
            .inspection
            .pools
            .iter()
            .any(|present| present.name == pool)
        {
            return Err(refuse("image deploy pool name is already imported"));
        }
        Ok(())
    }
    fn prepare_image(&mut self) -> io::Result<()> {
        super::require_native_tools()?;
        let tool = fs::metadata(LOSETUP)?;
        if !tool.is_file() || tool.mode() & 0o111 == 0 {
            return Err(refuse("image deployment requires /usr/sbin/losetup"));
        }
        crate::native_run::run("/sbin/modprobe", &["loop".into()], 4096, 30).map_err(refuse)?;
        Ok(())
    }
    fn attach(&mut self, file: Arc<OwnedFile>) -> io::Result<Attachment> {
        match attach_native(file.clone()) {
            Ok(attached) => Ok(attached),
            Err(error) => match detach_created_loops(&file) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::other(UnclosedAttachment(refuse(format!(
                    "{error}; owned loop cleanup failed: {cleanup}"
                ))))),
            },
        }
    }
    fn detach(&mut self, attachment: &Attachment) -> io::Result<()> {
        let guard = attachment
            .guard
            .as_ref()
            .ok_or_else(|| refuse("native image loop custody is missing"))?;
        guard.authority.verify(false)?;
        let export = || export_created_pools(&guard.authority);
        let exported = if guard.authority.file.portable {
            super::portable::without_hostid(export)
        } else {
            export()
        };
        // Try detach even if an export observation failed, then retain the
        // image on any unproven cleanup rather than unlinking active backing.
        let detached = detach_created_loops(&guard.authority.file);
        exported.and(detached)
    }
}

#[derive(Debug)]
struct UnclosedAttachment(io::Error);
impl std::fmt::Display for UnclosedAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for UnclosedAttachment {}

fn no_binding(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || matches!(error.raw_os_error(), Some(libc::ENXIO | libc::ENODEV))
}
fn detach_owned_path(file: &OwnedFile, path: &Path) -> io::Result<()> {
    let info = match loop_info(path) {
        Ok((info, _)) => info,
        Err(error) if no_binding(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    if !backing_matches(file, &info) {
        return Ok(());
    }
    zfs_tools::engine::native::run(
        LOSETUP,
        &["--detach".into(), path.to_string_lossy().into_owned()],
    )
    .map_err(refuse)?;
    match loop_info(path) {
        Ok((after, _)) if backing_matches(file, &after) => {
            Err(refuse("created image loop remains attached"))
        }
        Ok(_) => Ok(()),
        Err(error) if no_binding(&error) => Ok(()),
        Err(error) => Err(error),
    }
}
fn detach_created_loops(file: &OwnedFile) -> io::Result<()> {
    let mut count = 0;
    for entry in fs::read_dir("/sys/block")? {
        count += 1;
        if count > 4096 {
            return Err(refuse("loop cleanup inventory exceeds its bound"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name
            .strip_prefix("loop")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let path = Path::new("/dev").join(name);
        detach_owned_path(file, &path)?;
    }
    Ok(())
}
fn export_created_pools(authority: &Authority) -> io::Result<()> {
    let observed = zfs_tools::engine::state::observe().map_err(refuse)?;
    for pool in &observed.inspection.pools {
        // Unknown storage never grants cleanup authority. The kernel loop
        // readback below still prevents deleting an unexported active image.
        let Ok(storage) = device::observe_pool_storage(&pool.name, &pool.guid) else {
            continue;
        };
        if storage.disks.as_slice() != std::slice::from_ref(&authority.disk) {
            continue;
        }
        authority.verify(false)?;
        let export = || {
            zfs_tools::engine::native::run("zpool", &["export".into(), pool.name.clone()])
                .map_err(refuse)
        };
        if authority.file.portable {
            super::create_with_hostid(0, export)?;
        } else {
            export()?;
        }
    }
    Ok(())
}

pub fn apply_with(plan: &Plan, backend: &mut impl Backend) -> io::Result<Applied> {
    // Recheck content before creating anything, including in no-typing mode.
    command::validate_cli_request(&plan.request)?;
    if request::inputs(&plan.request)? != plan.inputs
        || !plan.request.fresh_image
        || image_size(&plan.request, &plan.inputs)? != plan.bytes
    {
        return Err(refuse("image inputs or parameters changed since preview"));
    }
    backend.verify_loader(&plan.inputs.artifacts)?;
    backend.prepare_image()?;
    let file = OwnedFile::create(&plan.destination, plan.bytes, plan.request.portable)?;
    with_attachment(file.clone(), backend, |attachment, backend| {
        file.verify()?;
        let attempt = backend.attempt()?;
        let mut request = plan.request.clone();
        request.disk = attachment.disk.clone();
        request.journal_directory = attempt.clone();
        let review = match backend.deploy_plan(&request) {
            Ok(review) => review,
            Err(error) => {
                backend.release(&attempt);
                return Err(error);
            }
        };
        let mut selected = review.selection.clone();
        selected.disk.clear();
        selected.journal_directory.clear();
        if selected != plan.request
            || request::bound_inputs(&review) != plan.inputs
            || review.disk.bytes != plan.bytes
        {
            return Err(refuse(
                "created-image engine plan differs from the bound content and parameters",
            ));
        }
        let outcome = backend.deploy_apply(&review)?;
        if !outcome.complete || !outcome.exported {
            return Err(refuse("image deploy did not complete and export"));
        }
        file.verify()?;
        file.file.sync_all()?;
        file.parent.sync_all()?;
        Ok(Applied {
            image: plan.destination.path.clone(),
            bytes: plan.bytes,
            review,
            outcome,
            loop_detached: true,
        })
    })
}

fn with_attachment<T, B: Backend>(
    file: Arc<OwnedFile>,
    backend: &mut B,
    work: impl FnOnce(&Attachment, &mut B) -> io::Result<T>,
) -> io::Result<T> {
    let attachment = match backend.attach(file.clone()) {
        Ok(value) => value,
        Err(error) => {
            if error
                .get_ref()
                .is_some_and(|source| source.is::<UnclosedAttachment>())
            {
                return Err(refuse(format!(
                    "{error}; created image retained at {}",
                    file.destination.path.display()
                )));
            }
            let removed = file.remove();
            return Err(match removed {
                Ok(()) => error,
                Err(cleanup) => refuse(format!("{error}; created image cleanup failed: {cleanup}")),
            });
        }
    };
    let result = work(&attachment, backend);
    let detached = backend.detach(&attachment);
    drop(attachment); // clears the device capability on every return path
    match (result, detached) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => {
            let removed = file.remove();
            Err(match removed {
                Ok(()) => error,
                Err(cleanup) => refuse(format!("{error}; created image cleanup failed: {cleanup}")),
            })
        }
        (result, Err(cleanup)) => Err(refuse(format!(
            "{}; loop detach failed: {cleanup}; created image retained at {}",
            result
                .err()
                .map_or_else(|| "image deployment completed".into(), |e| e.to_string()),
            file.destination.path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    struct Fake {
        calls: Vec<&'static str>,
        attach_fails: bool,
        detach_fails: bool,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                attach_fails: false,
                detach_fails: false,
            }
        }
    }
    impl command::Backend for Fake {
        fn wipe_plan(&mut self, _: &str) -> io::Result<device::DiskReview> {
            panic!("image must never plan erasure")
        }
        fn running_hostid(&mut self) -> io::Result<u32> {
            Ok(0)
        }
        fn attempt(&mut self) -> io::Result<PathBuf> {
            panic!("lifecycle test does not run an engine")
        }
        fn release(&mut self, _: &Path) {}
        fn deploy_plan(
            &mut self,
            _: &request::DeployRequest,
        ) -> io::Result<super::super::CoreReview> {
            panic!("lifecycle test does not plan an engine")
        }
        fn verify_loader(&mut self, _: &crate::loader::EfiFile) -> io::Result<()> {
            Ok(())
        }
        fn wipe(&mut self, _: &device::DiskReview) -> io::Result<device::WipeOutcome> {
            panic!("image must never erase")
        }
        fn deploy_apply(&mut self, _: &super::super::CoreReview) -> io::Result<CoreOutcome> {
            panic!("lifecycle test does not run an engine")
        }
    }
    impl Backend for Fake {
        fn prepare_image(&mut self) -> io::Result<()> {
            self.calls.push("prepare");
            Ok(())
        }
        fn attach(&mut self, file: Arc<OwnedFile>) -> io::Result<Attachment> {
            self.calls.push("attach");
            file.verify()?;
            if self.attach_fails {
                Err(refuse("attach failed cleanly"))
            } else {
                Ok(Attachment {
                    disk: "/dev/fake-owned-image-loop".into(),
                    guard: None,
                })
            }
        }
        fn detach(&mut self, _: &Attachment) -> io::Result<()> {
            self.calls.push("detach");
            if self.detach_fails {
                Err(refuse("detach failed"))
            } else {
                Ok(())
            }
        }
    }
    fn args(root: &Path) -> command::Args {
        command::Args {
            target: command::Target::Image {
                file: root.join("image"),
            },
            efi: root.join("missing.efi"),
            factory: Some(root.join("missing.tar")),
            overlay: Vec::new(),
            portable: false,
            be: None,
            pool: None,
            hostid: None,
            hostname: None,
            esp: None,
            esp_partition: None,
            swap: None,
        }
    }

    #[test]
    fn invalid_image_requests_fail_before_preview_inputs_allocation_or_attachment() {
        let scratch = crate::factory::tests::Scratch::new();
        for (field, value, expected) in [
            ("hostname", "bad hostname", "deploy hostname"),
            ("hostid", "00000000", "deploy hostid"),
            ("pool", "1bad", "invalid or mismatched deploy review"),
            ("be", "bad%name", "invalid or mismatched deploy review"),
        ] {
            let mut args = args(&scratch.0);
            match field {
                "hostname" => args.hostname = Some(value.into()),
                "hostid" => args.hostid = Some(value.into()),
                "pool" => args.pool = Some(value.into()),
                "be" => args.be = Some(value.into()),
                _ => unreachable!(),
            }
            let mut fake = Fake::new();
            let error = plan_with(&args, &mut fake).unwrap_err();
            assert!(error.to_string().contains(expected), "{field}: {error}");
            assert!(fake.calls.is_empty());
            assert!(!scratch.0.join("image").exists());

            // The execute entry point independently rejects a supplied invalid
            // request before opening even its deliberately absent source tar.
            let review = super::super::tests::review(&scratch.0);
            let plan = Plan {
                schema_version: 1,
                destination: Destination::inspect(&scratch.0.join("image")).unwrap(),
                bytes: 8 << 30,
                request: command::request(&args, 0, PathBuf::new()).unwrap(),
                inputs: request::bound_inputs(&review),
            };
            let error = apply_with(&plan, &mut fake).unwrap_err();
            assert!(error.to_string().contains(expected), "{field}: {error}");
            assert!(fake.calls.is_empty());
            assert!(!scratch.0.join("image").exists());
        }
    }

    #[test]
    fn image_cli_refuses_an_efi_directory_before_preview_or_allocation() {
        let scratch = crate::factory::tests::Scratch::new();
        let mut args = args(&scratch.0);
        args.efi = scratch.0.join("artifacts");
        fs::create_dir(&args.efi).unwrap();
        let mut fake = Fake::new();
        let error = plan_with(&args, &mut fake).unwrap_err();
        assert!(error.to_string().contains("--efi takes a regular UKI file"));
        let request = command::request(&args, 0, PathBuf::new()).unwrap();
        // Request-level admission leaves the file check to the CLI.
        request::validate_request(&request).unwrap();
        let review = super::super::tests::review(&scratch.0);
        let plan = Plan {
            schema_version: 1,
            destination: Destination::inspect(&scratch.0.join("image")).unwrap(),
            bytes: 8 << 30,
            request,
            inputs: request::bound_inputs(&review),
        };
        let error = apply_with(&plan, &mut fake).unwrap_err();
        assert!(error.to_string().contains("--efi takes a regular UKI file"));
        assert!(fake.calls.is_empty());
        assert!(!scratch.0.join("image").exists());
    }

    #[test]
    fn an_image_is_created_exclusively_and_an_existing_file_is_refused() {
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("image");
        let destination = Destination::inspect(&path).unwrap();
        let file = OwnedFile::create(&destination, 4096, false).unwrap();
        assert!(OwnedFile::create(&destination, 4096, false).is_err());
        assert!(Destination::inspect(&path).is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), 4096);
        file.remove().unwrap();
        let other = scratch.0.join("other");
        fs::write(&other, b"preserved").unwrap();
        symlink(&other, &path).unwrap();
        assert!(OwnedFile::create(&destination, 4096, false).is_err());
        assert_eq!(fs::read(&other).unwrap(), b"preserved");
    }
    #[test]
    fn image_allocation_failure_after_exclusive_create_exits_partial() {
        crate::factory::tests::classified_child("image-allocation", "deploy --image", 4, |root| {
            use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
            let path = root.join("image");
            let destination = Destination::inspect(&path)?;
            // Bound this real ftruncate failure without filling a filesystem.
            // Its pending SIGXFSZ remains blocked until the child exits.
            let mut signals = SigSet::empty();
            signals.add(Signal::SIGXFSZ);
            pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
                .map_err(io::Error::other)?;
            rustix::process::setrlimit(
                rustix::process::Resource::Fsize,
                rustix::process::Rlimit {
                    current: Some(1024),
                    maximum: Some(1024),
                },
            )?;
            let error = OwnedFile::create(&destination, 4096, false)
                .err()
                .expect("allocation exceeds the isolated process file-size limit");
            assert_eq!(error.raw_os_error(), Some(libc::EFBIG));
            assert!(
                !path.exists(),
                "normal cleanup removes the exclusively created file"
            );
            Err(error)
        });
    }

    #[test]
    fn a_failed_image_deploy_removes_only_the_file_it_created() {
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("image");
        let destination = Destination::inspect(&path).unwrap();
        let file = OwnedFile::create(&destination, 4096, false).unwrap();
        let mut fake = Fake::new();
        let result = with_attachment::<(), _>(file, &mut fake, |_, fake| {
            fake.calls.push("deploy");
            Err(refuse("injected deployment failure"))
        });
        assert!(result.is_err());
        assert_eq!(fake.calls, ["attach", "deploy", "detach"]);
        assert!(!path.exists());
        let file = OwnedFile::create(&destination, 4096, false).unwrap();
        let mut fake = Fake::new();
        let preserved = scratch.0.join("original-image");
        let result = with_attachment::<(), _>(file, &mut fake, |_, _| {
            fs::rename(&path, &preserved)?;
            fs::write(&path, b"foreign replacement")?;
            Err(refuse("injected failure after replacement"))
        });
        assert!(result.is_err());
        assert_eq!(fake.calls, ["attach", "detach"]);
        assert_eq!(fs::read(&path).unwrap(), b"foreign replacement");
        assert_eq!(fs::metadata(preserved).unwrap().len(), 4096);
    }
    #[test]
    fn an_unproven_detach_retains_the_created_image_and_success_detaches() {
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("image");
        let destination = Destination::inspect(&path).unwrap();
        let file = OwnedFile::create(&destination, 4096, false).unwrap();
        let mut fake = Fake::new();
        fake.detach_fails = true;
        assert!(with_attachment(file, &mut fake, |_, _| Ok(())).is_err());
        assert!(path.exists());
        assert_eq!(fake.calls, ["attach", "detach"]);
        fs::remove_file(&path).unwrap();
        let file = OwnedFile::create(&destination, 4096, false).unwrap();
        let mut fake = Fake::new();
        assert_eq!(with_attachment(file, &mut fake, |_, _| Ok(42)).unwrap(), 42);
        assert!(path.exists());
        assert_eq!(fake.calls, ["attach", "detach"]);
    }
    #[test]
    fn an_image_parent_replacement_is_refused_before_file_creation() {
        let scratch = crate::factory::tests::Scratch::new();
        let parent = scratch.0.join("parent");
        fs::create_dir(&parent).unwrap();
        let destination = Destination::inspect(&parent.join("image")).unwrap();
        fs::rename(&parent, scratch.0.join("original-parent")).unwrap();
        fs::create_dir(&parent).unwrap();
        assert!(OwnedFile::create(&destination, 4096, false).is_err());
        assert!(!parent.join("image").exists());
    }
    #[test]
    fn image_loop_backing_checks_bind_inode_device_and_not_a_path_string() {
        let scratch = crate::factory::tests::Scratch::new();
        let destination = Destination::inspect(&scratch.0.join("image")).unwrap();
        let file = OwnedFile::create(&destination, 4096, false).unwrap();
        let mut info = LoopInfo::empty();
        info.device = kernel_device(file.device);
        info.inode = file.inode;
        assert!(backing_matches(&file, &info));
        info.inode += 1;
        assert!(!backing_matches(&file, &info));
        info.inode -= 1;
        info.device += 1;
        assert!(!backing_matches(&file, &info));
    }
}
