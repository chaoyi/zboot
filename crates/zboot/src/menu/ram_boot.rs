//! `boot --tar`: boot a root tar in RAM.
//!
//! The tar is admitted as deploy admits one, plus exactly one kernel, its
//! `modules.dep` and an init; the RAM must hold, with 256 MiB to spare, the
//! larger of the tar plus its unpacked size (the booted system) and three
//! copies of the tar (the staged initramfs and what `kexec` holds while it
//! loads it); every overlay is reviewed, and one with a
//! `post-install` is refused before anything is staged. zboot then builds an
//! initramfs of its bootstrap (`ram-init.sh` as `/init`), the busybox, `tar`
//! and `zstd` the UKI lists in `usr/lib/zboot/ram-boot.files`, the tar's
//! admitted bytes and one tar of each overlay's `rootfs/`, closes every pool
//! and starts the tar's own kernel with it. The bootstrap unpacks the tar onto
//! a tmpfs, applies the overlays in order and starts the tar's init; the
//! tar's own initrd is not used, and drivers load later from its modules.
//! The command line holds only the UKI's `console=` arguments and, under an
//! adopted identity, its hostid: no key, password or network setting.

use super::{Result, at, cleanup_error_for, refuse};
use crate::deploy::overlay::{self, Kind, Overlay};
use crate::factory::root_tar::{self, Members, RootTar};
use crate::handoff::{
    Action, RecoveryBackend, StagedKernel, digest_file, kexec_cmdline, readonly_pools,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const BOOTSTRAP: &[u8] = include_bytes!("ram-init.sh");
/// In the UKI: the bootstrap's programs and their libraries, one absolute
/// path per line.
const PROGRAMS: &str = "usr/lib/zboot/ram-boot.files";
const REQUIRED: [&str; 3] = ["bin/busybox", "bin/tar", "bin/zstd"];
const UPLOAD: &str = "/run/zboot/upload";
const HEADROOM: u64 = 256 << 20;

/// What the running UKI supplies.
struct Host {
    /// The UKI's root, which holds the bootstrap's programs.
    root: PathBuf,
    cmdline: String,
    /// Available RAM, read before anything was uploaded.
    available: u64,
}

/// `zboot boot --tar FILE|- [--overlay OVERLAY]...`, in the UKI.
pub(crate) fn boot(tar: &Path, overlays: &[PathBuf]) -> Result<()> {
    crate::handoff::prove_ram()?;
    let host = Host {
        root: PathBuf::from("/"),
        cmdline: std::fs::read_to_string("/proc/cmdline")?,
        available: available_memory()?,
    };
    let upload = if tar == Path::new("-") {
        Some(Upload::from_stdin()?)
    } else {
        None
    };
    let path = upload
        .as_ref()
        .map_or_else(|| tar.to_path_buf(), |upload| upload.0.clone());
    boot_with(
        &mut crate::handoff::NativeRecovery::for_ram_root(),
        &host,
        &path,
        upload,
        overlays,
        || {
            super::after_imports(|| {
                zfs_tools::engine::lock::for_command("zboot", "boot")
                    .map_err(|error| refuse(error.to_string()))
            })
        },
    )
}

fn available_memory() -> Result<u64> {
    std::fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .and_then(|kib| kib.checked_mul(1024))
        .ok_or_else(|| refuse("MemAvailable is missing from /proc/meminfo"))
}

/// The tar `-` read from stdin, kept in RAM until the boot; a boot that does
/// not happen removes it.
struct Upload(PathBuf);
impl Upload {
    fn from_stdin() -> Result<Self> {
        if io::stdin().is_terminal() {
            return Err(refuse(
                "boot --tar - reads the tar from stdin, which is a terminal; pipe or redirect the tar",
            ));
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(UPLOAD)?;
        let upload = Self(Path::new(UPLOAD).join(format!("{}.tar", uuid::Uuid::new_v4())));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&upload.0)?;
        io::copy(&mut io::stdin().lock(), &mut file)
            .map_err(|error| at("read the tar from stdin", error.into()))?;
        Ok(upload)
    }
}
impl Drop for Upload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Admit, stage, close the pools and `kexec`. A returning kexec is an error.
/// `upload`, the stdin copy of `tar`, is removed once the staged initramfs
/// holds the admitted bytes, before `kexec` copies them again.
fn boot_with<G>(
    backend: &mut impl RecoveryBackend,
    host: &Host,
    tar: &Path,
    upload: Option<Upload>,
    overlays: &[PathBuf],
    writer: impl FnOnce() -> Result<G>,
) -> Result<()> {
    backend
        .prove_ram()
        .map_err(|error| at("prove independent RAM runtime before a RAM boot", error))?;
    let (root, members) = root_tar::inspect_for_ram(tar)?;
    let need = root
        .bytes
        .saturating_add(root.logical_bytes)
        .max(root.bytes.saturating_mul(3))
        .saturating_add(HEADROOM);
    if host.available < need {
        return Err(refuse(format!(
            "booting this tar in RAM needs {} MiB of available RAM (the tar and its unpacked size, or three copies of the tar while staging, whichever is larger, plus 256 MiB); {} MiB is available; use a smaller tar or deploy it to a disk",
            need.div_ceil(1 << 20),
            host.available >> 20
        )));
    }
    let reviewed = overlays
        .iter()
        .map(|source| overlay::review(source))
        .collect::<io::Result<Vec<_>>>()?;
    if let Some(hooked) = reviewed.iter().find(|item| item.post_install.is_some()) {
        return Err(refuse(format!(
            "overlay {} has a post-install; boot --tar applies overlay files only and never skips a hook; drop the overlay or deploy the tar to a disk",
            zfs_tools::engine::escape_display(&hooked.source.display().to_string())
        )));
    }
    placement(&members, &reviewed)?;
    let programs = programs(&host.root)?;
    let _writer = writer()?;
    let identity = backend
        .identity()
        .map_err(|error| at("read the host identity before a RAM boot", error))?;
    let command_line = kexec_cmdline(&consoles(&host.cmdline), identity.0)?;
    let work = backend
        .workspace()
        .map_err(|error| at("prepare RAM workspace", error))?;
    let result = (|| {
        let assets = stage(
            &work,
            &root,
            &reviewed,
            &host.root,
            &programs,
            &command_line,
        )?;
        drop(upload);
        backend
            .action(&Action::Load { assets })
            .map_err(|error| at("load the tar's kernel into kexec", error))?;
        close_pools(backend)?;
        backend
            .prove_ram()
            .map_err(|error| at("prove independent RAM runtime before kexec execute", error))?;
        backend
            .action(&Action::Execute)
            .map_err(|error| at("execute loaded kexec kernel", error))?;
        Err(refuse("kexec returned; the RAM system did not start"))
    })();
    if let Err(error) = backend.cleanup(&work) {
        return Err(cleanup_error_for(
            "RAM boot",
            result,
            "remove RAM workspace",
            error,
        ));
    }
    result
}

/// The UKI's `console=` arguments name this machine's consoles. The rest of
/// its command line, keys included, is the UKI's own.
fn consoles(cmdline: &str) -> String {
    cmdline
        .split_whitespace()
        .filter(|word| word.starts_with("console="))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Export every imported pool without force; all of them must close.
fn close_pools(backend: &mut impl RecoveryBackend) -> Result<()> {
    let state = backend
        .observe()
        .map_err(|error| at("observe pools before a RAM boot", error))?;
    readonly_pools(&state)?;
    for pool in &state.inspection.pools {
        backend
            .action(&Action::Export {
                pool: pool.name.to_string(),
            })
            .map_err(|error| at("export read-only pool before kexec execute", error))?;
    }
    if !backend
        .observe()
        .map_err(|error| at("reobserve pools after export", error))?
        .inspection
        .pools
        .is_empty()
    {
        return Err(refuse("a pool is still imported after export"));
    }
    Ok(())
}

/// Overlays land as deploy puts them: a parent must be a real directory, a
/// directory never replaces anything else, nor anything else a directory.
/// The tar's members and the earlier entries decide what is there.
fn placement(members: &Members, overlays: &[Overlay]) -> Result<()> {
    // Path -> whether it is a directory, for the overlay entries so far.
    let mut placed = BTreeMap::new();
    let directory = |placed: &BTreeMap<String, bool>, path: &str| -> Option<bool> {
        if path.is_empty() {
            return Some(true);
        }
        if let Some(directory) = placed.get(path) {
            return Some(*directory);
        }
        if let Some(kind) = members.get(path) {
            return Some(kind.is_dir());
        }
        // A tar may leave a parent implicit; it is then a directory.
        let prefix = format!("{path}/");
        members
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(name, _)| name.starts_with(&prefix))
            .then_some(true)
    };
    for item in overlays {
        for entry in &item.entries {
            let parent = entry.path.rsplit_once('/').map_or("", |(parent, _)| parent);
            let is_directory = matches!(entry.kind, Kind::Directory);
            let problem = if directory(&placed, parent) != Some(true) {
                Some("its parent is not a real directory in the root")
            } else {
                match directory(&placed, &entry.path) {
                    Some(false) if is_directory => Some("it would replace a non-directory"),
                    Some(true) if !is_directory => Some("it would replace a directory"),
                    _ => None,
                }
            };
            if let Some(problem) = problem {
                return Err(refuse(format!(
                    "overlay {} cannot place {}: {problem}",
                    zfs_tools::engine::escape_display(&item.source.display().to_string()),
                    zfs_tools::engine::escape_display(&entry.path)
                )));
            }
            placed.insert(entry.path.clone(), is_directory);
        }
    }
    Ok(())
}

/// The UKI's list of the bootstrap's programs, relative to its root.
fn programs(root: &Path) -> Result<BTreeSet<String>> {
    let list = std::fs::read_to_string(root.join(PROGRAMS))
        .map_err(|error| at("read the UKI's RAM boot program list", error.into()))?;
    let mut programs = BTreeSet::new();
    for line in list.lines() {
        let path = line
            .strip_prefix('/')
            .filter(|path| path.split('/').all(|part| !matches!(part, "" | "." | "..")))
            .ok_or_else(|| {
                refuse(format!(
                    "RAM boot program list entry {} is not a normalized absolute path",
                    zfs_tools::engine::escape_display(line)
                ))
            })?;
        programs.insert(path.to_owned());
    }
    if let Some(missing) = REQUIRED.iter().find(|path| !programs.contains(**path)) {
        return Err(refuse(format!(
            "the UKI's RAM boot program list lacks /{missing}"
        )));
    }
    Ok(programs)
}

/// Write `work/initrd`, the initramfs, and `work/kernel`, the tar's kernel
/// read from the tar's copy in it.
fn stage(
    work: &Path,
    root: &RootTar,
    overlays: &[Overlay],
    uki: &Path,
    programs: &BTreeSet<String>,
    command_line: &str,
) -> Result<StagedKernel> {
    let initrd = work.join("initrd");
    let mut cpio = Newc::create(&initrd)?;
    cpio.file("init", 0o755, BOOTSTRAP.len() as u64, &mut &BOOTSTRAP[..])?;
    for path in programs {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(uki.join(path))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(refuse(format!("UKI program /{path} is not a regular file")));
        }
        use std::os::unix::fs::PermissionsExt;
        cpio.file(
            path,
            metadata.permissions().mode() & 0o7777,
            metadata.len(),
            &mut file,
        )?;
    }
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&root.path)?;
    let mut copy = Hashing::new(&mut source);
    let name = if root.zstd {
        "zboot/root.tar.zst"
    } else {
        "zboot/root.tar"
    };
    let offset = cpio.file(name, 0o600, root.bytes, &mut copy)?;
    if copy.finish() != (root.sha256.clone(), root.bytes) {
        return Err(refuse("the root tar changed since it was admitted"));
    }
    for (index, item) in overlays.iter().enumerate() {
        cpio.generated(&format!("zboot/overlay/{index:03}.tar"), |output| {
            overlay_tar(item, output)
        })?;
    }
    cpio.finish()?;
    let kernel = work.join("kernel");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&kernel)?;
    let bytes = root.bytes;
    root_tar::copy_kernel(
        root,
        &root.kernels[0],
        || {
            let mut file = File::open(&initrd)?;
            file.seek(SeekFrom::Start(offset))?;
            Ok(Box::new(file.take(bytes)) as Box<dyn Read>)
        },
        &mut output,
    )?;
    output.sync_all()?;
    Ok(StagedKernel {
        kernel_sha256: digest_file(&kernel)?,
        initrd_sha256: digest_file(&initrd)?,
        kernel,
        initrd,
        command_line: command_line.into(),
    })
}

/// One overlay's reviewed `rootfs/` entries as a tar the bootstrap extracts
/// over the root: owners, modes, link targets and xattrs (as pax records).
fn overlay_tar(item: &Overlay, output: &mut File) -> Result<()> {
    let mut builder = tar::Builder::new(output);
    overlay::members(item, &mut |entry, xattrs, content| {
        if !xattrs.is_empty() {
            pax(&mut builder, xattrs)?;
        }
        let mut header = tar::Header::new_ustar();
        header.set_mode(entry.mode);
        header.set_uid(entry.uid.into());
        header.set_gid(entry.gid.into());
        header.set_mtime(0);
        header.set_size(0);
        match &entry.kind {
            Kind::Directory => {
                header.set_entry_type(tar::EntryType::Directory);
                builder.append_data(&mut header, &entry.path, io::empty())
            }
            Kind::Symlink { target } => {
                header.set_entry_type(tar::EntryType::Symlink);
                builder.append_link(&mut header, &entry.path, target)
            }
            Kind::File { sha256, bytes } => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(*bytes);
                // One byte more shows content that grew since the review.
                let mut copy = Hashing::new(content.take(*bytes + 1));
                builder.append_data(&mut header, &entry.path, &mut copy)?;
                if copy.finish() != (sha256.clone(), *bytes) {
                    return Err(io::Error::other(format!(
                        "overlay {} changed since review",
                        entry.path
                    )));
                }
                Ok(())
            }
        }
    })?;
    builder.into_inner()?;
    Ok(())
}

/// A pax extended header holding `xattrs` for the member that follows.
fn pax<W: Write>(
    builder: &mut tar::Builder<W>,
    xattrs: &BTreeMap<String, Vec<u8>>,
) -> io::Result<()> {
    let mut records = Vec::new();
    for (name, value) in xattrs {
        // "LENGTH SCHILY.xattr.NAME=VALUE\n", LENGTH counting itself.
        let rest = format!(" SCHILY.xattr.{name}=").len() + value.len() + 1;
        let mut length = rest + 1;
        while length != rest + length.to_string().len() {
            length = rest + length.to_string().len();
        }
        records.extend_from_slice(format!("{length} SCHILY.xattr.{name}=").as_bytes());
        records.extend_from_slice(value);
        records.push(b'\n');
    }
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::XHeader);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_size(records.len() as u64);
    builder.append_data(&mut header, "PaxHeaders/entry", records.as_slice())
}

struct Hashing<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}
impl<R: Read> Hashing<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }
    fn finish(self) -> (String, u64) {
        (format!("{:x}", self.hasher.finalize()), self.bytes)
    }
}
impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.bytes += read as u64;
        Ok(read)
    }
}

/// A newc cpio archive, the initramfs format: each parent directory before
/// its members, root-owned, every time zero.
struct Newc {
    file: File,
    inode: u32,
    directories: BTreeSet<String>,
}
impl Newc {
    fn create(path: &Path) -> Result<Self> {
        Ok(Self {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?,
            inode: 0,
            directories: BTreeSet::new(),
        })
    }

    fn header(&mut self, name: &str, mode: u32, size: u64) -> Result<()> {
        // newc sizes are 32 bits.
        let size = u32::try_from(size).map_err(|_| {
            refuse(format!(
                "{name} is too large for an initramfs member (4 GiB)"
            ))
        })?;
        self.inode += 1;
        let links = if mode & 0o170000 == 0o040000 { 2 } else { 1 };
        let fields = [
            self.inode,
            mode,
            0,
            0,
            links,
            0,
            size,
            0,
            0,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ];
        let mut header = String::from("070701");
        for field in fields {
            header.push_str(&format!("{field:08x}"));
        }
        self.file.write_all(header.as_bytes())?;
        self.file.write_all(name.as_bytes())?;
        self.file.write_all(&[0])?;
        self.pad()
    }

    fn pad(&mut self) -> Result<()> {
        let position = self.file.stream_position()?;
        self.file
            .write_all(&[0; 3][..((4 - position % 4) % 4) as usize])?;
        Ok(())
    }

    fn parents(&mut self, name: &str) -> Result<()> {
        let mut end = 0;
        while let Some(slash) = name[end..].find('/') {
            end += slash;
            if self.directories.insert(name[..end].to_owned()) {
                self.header(&name[..end], 0o040755, 0)?;
            }
            end += 1;
        }
        Ok(())
    }

    /// A regular file of exactly `size` bytes from `content`; returns where
    /// its bytes start.
    fn file(&mut self, name: &str, mode: u32, size: u64, content: &mut dyn Read) -> Result<u64> {
        self.parents(name)?;
        self.header(name, 0o100000 | mode, size)?;
        let start = self.file.stream_position()?;
        if io::copy(&mut content.take(size), &mut self.file)? != size {
            return Err(refuse(format!("{name} changed size while it was staged")));
        }
        self.pad()?;
        Ok(start)
    }

    /// A regular file `write` produces, its size set once it is written.
    fn generated(&mut self, name: &str, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
        self.parents(name)?;
        let start = self.file.stream_position()?;
        let inode = self.inode;
        self.header(name, 0o100600, 0)?;
        let data = self.file.stream_position()?;
        write(&mut self.file)?;
        let end = self.file.stream_position()?;
        self.file.seek(SeekFrom::Start(start))?;
        self.inode = inode;
        self.header(name, 0o100600, end - data)?;
        self.file.seek(SeekFrom::Start(end))?;
        self.pad()
    }

    fn finish(mut self) -> Result<()> {
        self.header("TRAILER!!!", 0, 0)?;
        self.file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory::root_tar::tests::{ram_bootable, tar_of};
    use crate::factory::tests::Scratch;
    use crate::handoff::HandoffRequest;
    use crate::handoff::tests::{empty, fixture};
    use std::os::unix::fs::PermissionsExt;
    use zfs_tools::engine::state::NativeState;

    const UKI_CMDLINE: &str = "zboot.recovery=1 console=ttyS0,115200n8 console=tty0 quiet loglevel=3 ip=dhcp zboot.ssh_key=ssh-ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIA";

    struct Fake {
        work: PathBuf,
        state: NativeState,
        identity: (Option<u32>, Option<BTreeSet<String>>),
        actions: Vec<Action>,
        workspaces: usize,
        /// A path whose presence the kexec load records.
        watch: Option<PathBuf>,
        present_at_load: Option<bool>,
    }
    impl Fake {
        fn new(scratch: &Scratch) -> Self {
            Self {
                work: scratch.0.join("work"),
                state: fixture(true),
                identity: (None, None),
                actions: Vec::new(),
                workspaces: 0,
                watch: None,
                present_at_load: None,
            }
        }
        fn staged(&self) -> &StagedKernel {
            self.actions
                .iter()
                .find_map(|action| match action {
                    Action::Load { assets } => Some(assets),
                    _ => None,
                })
                .expect("a kernel was loaded")
        }
    }
    impl RecoveryBackend for Fake {
        fn prove_ram(&mut self) -> Result<()> {
            Ok(())
        }
        fn observe(&mut self) -> Result<NativeState> {
            Ok(self.state.clone())
        }
        fn identity(&mut self) -> Result<(Option<u32>, Option<BTreeSet<String>>)> {
            Ok(self.identity.clone())
        }
        fn workspace(&mut self) -> Result<PathBuf> {
            self.workspaces += 1;
            let work = self.work.join(self.workspaces.to_string());
            std::fs::create_dir_all(&work)?;
            Ok(work)
        }
        fn action(&mut self, action: &Action) -> Result<()> {
            self.actions.push(action.clone());
            if matches!(action, Action::Load { .. }) {
                self.present_at_load = self.watch.as_ref().map(|path| path.exists());
            }
            if matches!(action, Action::Export { .. }) {
                self.state = empty();
            }
            Ok(())
        }
        fn verify_mount(&mut self, _: &str, _: &Path) -> Result<()> {
            unreachable!("a RAM boot mounts no BE")
        }
        fn stage(
            &mut self,
            _: &Path,
            _: &Path,
            _: &HandoffRequest,
            _: &str,
        ) -> Result<StagedKernel> {
            unreachable!("a RAM boot stages its own initramfs")
        }
        fn cleanup(&mut self, _: &Path) -> Result<()> {
            // The scratch directory goes with the test; keep it to inspect.
            Ok(())
        }
    }

    /// A UKI root with its program list, and a RAM-bootable zstd root tar.
    fn setup() -> (Scratch, Host, PathBuf) {
        let scratch = Scratch::new();
        let uki = scratch.0.join("uki");
        for (path, mode) in [
            ("bin/busybox", 0o755),
            ("bin/tar", 0o755),
            ("bin/zstd", 0o755),
            ("lib/x86_64-linux-gnu/libc.so.6", 0o644),
        ] {
            let file = uki.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, path.as_bytes()).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        std::fs::create_dir_all(uki.join("usr/lib/zboot")).unwrap();
        std::fs::write(
            uki.join(PROGRAMS),
            "/bin/busybox\n/bin/tar\n/bin/zstd\n/lib/x86_64-linux-gnu/libc.so.6\n",
        )
        .unwrap();
        // Remote-access state of the running menu, which a RAM boot never takes.
        std::fs::create_dir_all(uki.join("run/zboot-connect")).unwrap();
        std::fs::write(
            uki.join("run/zboot-connect/authorized_keys"),
            b"ssh-ed25519 AAAA\n",
        )
        .unwrap();
        let tar = scratch.0.join("root.tar.zst");
        tar_of(&tar, &ram_bootable(), true);
        let host = Host {
            root: uki,
            cmdline: UKI_CMDLINE.into(),
            available: 1 << 40,
        };
        (scratch, host, tar)
    }

    fn returned(result: Result<()>) {
        let error = result.unwrap_err().to_string();
        assert!(error.contains("kexec returned"), "{error}");
    }

    /// The members of a newc archive: name, mode and bytes.
    fn newc(path: &Path) -> Vec<(String, u32, Vec<u8>)> {
        let bytes = std::fs::read(path).unwrap();
        let mut at = 0;
        let mut members = Vec::new();
        loop {
            assert_eq!(&bytes[at..at + 6], b"070701");
            let field = |index: usize| {
                let hex = &bytes[at + 6 + 8 * index..at + 14 + 8 * index];
                u32::from_str_radix(std::str::from_utf8(hex).unwrap(), 16).unwrap()
            };
            let (mode, size, length) = (field(1), field(6) as usize, field(11) as usize);
            let name = std::str::from_utf8(&bytes[at + 110..at + 109 + length])
                .unwrap()
                .to_owned();
            let data = (at + 110 + length).next_multiple_of(4);
            if name == "TRAILER!!!" {
                assert_eq!(data, bytes.len());
                return members;
            }
            members.push((name, mode, bytes[data..data + size].to_vec()));
            at = (data + size).next_multiple_of(4);
        }
    }

    fn member<'a>(members: &'a [(String, u32, Vec<u8>)], name: &str) -> &'a [u8] {
        &members
            .iter()
            .find(|member| member.0 == name)
            .unwrap_or_else(|| panic!("no {name}"))
            .2
    }

    /// Unpack the staged root and overlays in order, as the bootstrap does.
    fn unpack(members: &[(String, u32, Vec<u8>)], root: &Path) {
        std::fs::create_dir(root).unwrap();
        let tar = member(members, "zboot/root.tar.zst");
        tar::Archive::new(zstd::stream::read::Decoder::new(tar).unwrap())
            .unpack(root)
            .unwrap();
        for (name, _, bytes) in members {
            if name.starts_with("zboot/overlay/") {
                tar::Archive::new(bytes.as_slice()).unpack(root).unwrap();
            }
        }
    }

    fn directory_overlay(path: &Path, files: &[(&str, &[u8])]) {
        for (name, bytes) in files {
            let file = path.join("rootfs").join(name);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, bytes).unwrap();
        }
    }

    #[test]
    fn boot_tar_refuses_when_ram_is_short() {
        let (scratch, mut host, tar) = setup();
        let admitted = root_tar::inspect(&tar).unwrap();
        let need = (admitted.bytes + admitted.logical_bytes).max(3 * admitted.bytes) + (256 << 20);
        host.available = need - 1;
        let mut backend = Fake::new(&scratch);
        let mut locked = false;
        let error = boot_with(&mut backend, &host, &tar, None, &[], || {
            locked = true;
            Ok(())
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("MiB of available RAM"), "{error}");
        assert!(!locked);
        assert_eq!((backend.workspaces, backend.actions.len()), (0, 0));
        host.available = need;
        returned(boot_with(&mut backend, &host, &tar, None, &[], || Ok(())));
        assert!(matches!(backend.actions.last(), Some(Action::Execute)));
    }

    #[test]
    fn boot_tar_counts_three_copies_of_a_tar_that_barely_compresses() {
        let (scratch, mut host, _) = setup();
        let tar = scratch.0.join("root.tar");
        tar_of(&tar, &ram_bootable(), false);
        let admitted = root_tar::inspect(&tar).unwrap();
        assert!(2 * admitted.bytes > admitted.logical_bytes);
        // Enough for the booted system, not for staging it.
        host.available = admitted.bytes + admitted.logical_bytes + (256 << 20);
        let mut backend = Fake::new(&scratch);
        let error = boot_with(&mut backend, &host, &tar, None, &[], || Ok(()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("three copies of the tar"), "{error}");
        assert_eq!((backend.workspaces, backend.actions.len()), (0, 0));
        host.available = 3 * admitted.bytes + (256 << 20);
        returned(boot_with(&mut backend, &host, &tar, None, &[], || Ok(())));
    }

    #[test]
    fn boot_tar_removes_the_upload_before_kexec_loads_and_on_refusal() {
        let (scratch, mut host, tar) = setup();
        let upload = scratch.0.join("upload.tar");
        std::fs::copy(&tar, &upload).unwrap();
        let mut backend = Fake::new(&scratch);
        backend.watch = Some(upload.clone());
        returned(boot_with(
            &mut backend,
            &host,
            &upload,
            Some(Upload(upload.clone())),
            &[],
            || Ok(()),
        ));
        assert_eq!(backend.present_at_load, Some(false));
        std::fs::copy(&tar, &upload).unwrap();
        host.available = 0;
        boot_with(
            &mut backend,
            &host,
            &upload,
            Some(Upload(upload.clone())),
            &[],
            || Ok(()),
        )
        .unwrap_err();
        assert!(!upload.exists());
    }

    #[test]
    fn boot_tar_refuses_any_hook_before_staging_or_handoff() {
        let (scratch, host, tar) = setup();
        let files = scratch.0.join("files");
        directory_overlay(&files, &[("etc/motd", b"files\n")]);
        let hooked = scratch.0.join("hooked");
        directory_overlay(&hooked, &[("etc/motd", b"hooked\n")]);
        std::fs::write(hooked.join("post-install"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            hooked.join("post-install"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut backend = Fake::new(&scratch);
        let mut locked = false;
        let error = boot_with(
            &mut backend,
            &host,
            &tar,
            None,
            &[files.clone(), hooked],
            || {
                locked = true;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("post-install") && error.contains("hooked"),
            "{error}"
        );
        assert!(!locked);
        assert_eq!((backend.workspaces, backend.actions.len()), (0, 0));
        returned(boot_with(&mut backend, &host, &tar, None, &[files], || {
            Ok(())
        }));
    }

    #[test]
    fn boot_tar_applies_overlay_files_left_to_right() {
        let (scratch, host, tar) = setup();
        let first = scratch.0.join("first");
        directory_overlay(
            &first,
            &[("etc/motd", b"first\n"), ("etc/only-first", b"kept\n")],
        );
        // The second is a tar with an owner and an xattr, which it keeps.
        let second = scratch.0.join("second.tar");
        {
            let mut builder = tar::Builder::new(File::create(&second).unwrap());
            for (name, kind, data) in [
                ("rootfs/etc", tar::EntryType::Directory, &b""[..]),
                ("rootfs/etc/motd", tar::EntryType::Regular, &b"second\n"[..]),
            ] {
                if kind.is_file() {
                    pax(
                        &mut builder,
                        &BTreeMap::from([("user.zboot".to_owned(), b"value".to_vec())]),
                    )
                    .unwrap();
                }
                let mut header = tar::Header::new_ustar();
                header.set_entry_type(kind);
                header.set_mode(if kind.is_dir() { 0o755 } else { 0o640 });
                header.set_uid(1234);
                header.set_gid(5678);
                header.set_size(data.len() as u64);
                builder.append_data(&mut header, name, data).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut backend = Fake::new(&scratch);
        returned(boot_with(
            &mut backend,
            &host,
            &tar,
            None,
            &[first.clone(), second.clone()],
            || Ok(()),
        ));
        let members = newc(&backend.staged().initrd);
        let overlays: Vec<_> = members
            .iter()
            .map(|member| member.0.as_str())
            .filter(|name| name.starts_with("zboot/overlay/"))
            .collect();
        assert_eq!(overlays, ["zboot/overlay/000.tar", "zboot/overlay/001.tar"]);
        let bootstrap = std::str::from_utf8(member(&members, "init")).unwrap();
        assert!(
            bootstrap.find("/zboot/root.tar").unwrap()
                < bootstrap
                    .find("for overlay in /zboot/overlay/*.tar")
                    .unwrap()
        );
        let mut archive = tar::Archive::new(member(&members, "zboot/overlay/001.tar"));
        let mut motd = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| entry.path().unwrap() == Path::new("etc/motd"))
            .unwrap();
        let header = motd.header().clone();
        assert_eq!(
            (
                header.uid().unwrap(),
                header.gid().unwrap(),
                header.mode().unwrap()
            ),
            (1234, 5678, 0o640)
        );
        let xattrs: Vec<_> = motd
            .pax_extensions()
            .unwrap()
            .unwrap()
            .map(|extension| {
                let extension = extension.unwrap();
                (
                    extension.key().unwrap().to_owned(),
                    extension.value_bytes().to_vec(),
                )
            })
            .collect();
        assert_eq!(
            xattrs,
            [("SCHILY.xattr.user.zboot".to_owned(), b"value".to_vec())]
        );
        let unpacked = scratch.0.join("unpacked");
        unpack(&members, &unpacked);
        assert_eq!(
            std::fs::read(unpacked.join("etc/motd")).unwrap(),
            b"second\n"
        );
        assert_eq!(
            std::fs::read(unpacked.join("etc/only-first")).unwrap(),
            b"kept\n"
        );
        // Like deploy, an overlay never writes through or over the root's
        // links and directories.
        for (name, path) in [
            ("through-link", "usr/sbin/init/file"),
            ("over-directory", "usr/lib"),
        ] {
            let overlay = scratch.0.join(name);
            directory_overlay(&overlay, &[(path, b"x")]);
            let workspaces = backend.workspaces;
            let error = boot_with(
                &mut backend,
                &host,
                &tar,
                None,
                &[first.clone(), overlay],
                || Ok(()),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("cannot place"), "{error}");
            assert_eq!(backend.workspaces, workspaces);
        }
    }

    #[test]
    fn boot_tar_builtin_rescue_matches_deploy() {
        let (scratch, host, tar) = setup();
        let mut backend = Fake::new(&scratch);
        let rescue = PathBuf::from("builtin:rescue");
        returned(boot_with(
            &mut backend,
            &host,
            &tar,
            None,
            std::slice::from_ref(&rescue),
            || Ok(()),
        ));
        let members = newc(&backend.staged().initrd);
        // Deploy applies exactly the reviewed entries; the RAM root gets them.
        let reviewed = overlay::review(&rescue).unwrap();
        let mut archive = tar::Archive::new(member(&members, "zboot/overlay/000.tar"));
        let mut written = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let header = entry.header().clone();
            let kind = match header.entry_type() {
                tar::EntryType::Directory => Kind::Directory,
                tar::EntryType::Symlink => Kind::Symlink {
                    target: entry
                        .link_name()
                        .unwrap()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                },
                _ => {
                    let mut bytes = Vec::new();
                    entry.read_to_end(&mut bytes).unwrap();
                    Kind::File {
                        sha256: format!("{:x}", Sha256::digest(&bytes)),
                        bytes: bytes.len() as u64,
                    }
                }
            };
            written.push(overlay::Entry {
                path: entry.path().unwrap().to_str().unwrap().to_owned(),
                kind,
                mode: header.mode().unwrap(),
                uid: header.uid().unwrap() as u32,
                gid: header.gid().unwrap() as u32,
                xattrs: BTreeMap::new(),
            });
        }
        assert_eq!(written, reviewed.entries);
        assert_eq!(
            written
                .iter()
                .filter(|entry| !matches!(entry.kind, Kind::Directory))
                .count(),
            6
        );
    }

    #[test]
    fn factory_host_keys_are_ephemeral_in_ram_unless_an_overlay_supplies_them() {
        let (scratch, host, tar) = setup();
        let mut backend = Fake::new(&scratch);
        returned(boot_with(&mut backend, &host, &tar, None, &[], || Ok(())));
        returned(boot_with(&mut backend, &host, &tar, None, &[], || Ok(())));
        let initrds: Vec<_> = backend
            .actions
            .iter()
            .filter_map(|action| match action {
                Action::Load { assets } => Some(assets.initrd_sha256.clone()),
                _ => None,
            })
            .collect();
        // Every boot starts from the same bytes: staging makes no key.
        assert_eq!(initrds.len(), 2);
        assert_eq!(initrds[0], initrds[1]);
        let keys = |root: &Path| {
            std::fs::create_dir_all(root.join("etc/ssh")).unwrap();
            // The factory's missing-key unit runs exactly this at each boot.
            assert!(
                std::process::Command::new("ssh-keygen")
                    .args(["-A", "-f"])
                    .arg(root)
                    .status()
                    .unwrap()
                    .success()
            );
            std::fs::read(root.join("etc/ssh/ssh_host_ed25519_key")).unwrap()
        };
        let members = newc(&backend.staged().initrd);
        assert!(!members.iter().any(|member| member.0.contains("ssh_host_")));
        unpack(&members, &scratch.0.join("boot-one"));
        unpack(&members, &scratch.0.join("boot-two"));
        assert_ne!(
            keys(&scratch.0.join("boot-one")),
            keys(&scratch.0.join("boot-two"))
        );
        // An overlay's key is what every boot has.
        let supplied = scratch.0.join("keys");
        directory_overlay(
            &supplied,
            &[("etc/ssh/ssh_host_ed25519_key", b"supplied private key\n")],
        );
        let mut backend = Fake::new(&scratch);
        backend.work = scratch.0.join("work-keys");
        returned(boot_with(
            &mut backend,
            &host,
            &tar,
            None,
            &[supplied],
            || Ok(()),
        ));
        let members = newc(&backend.staged().initrd);
        for name in ["boot-three", "boot-four"] {
            unpack(&members, &scratch.0.join(name));
            assert_eq!(keys(&scratch.0.join(name)), b"supplied private key\n");
        }
    }

    #[test]
    fn boot_tar_passes_no_credentials() {
        let (scratch, host, tar) = setup();
        let mut backend = Fake::new(&scratch);
        returned(boot_with(&mut backend, &host, &tar, None, &[], || Ok(())));
        let staged = backend.staged();
        assert_eq!(staged.command_line, "console=ttyS0,115200n8 console=tty0");
        let names: BTreeSet<_> = newc(&staged.initrd)
            .into_iter()
            .map(|member| member.0)
            .collect();
        assert_eq!(
            names,
            BTreeSet::from(
                [
                    "init",
                    "bin",
                    "bin/busybox",
                    "bin/tar",
                    "bin/zstd",
                    "lib",
                    "lib/x86_64-linux-gnu",
                    "lib/x86_64-linux-gnu/libc.so.6",
                    "zboot",
                    "zboot/root.tar.zst",
                ]
                .map(str::to_owned)
            )
        );
        let members = newc(&staged.initrd);
        assert_eq!(member(&members, "bin/busybox"), b"bin/busybox");
        assert_eq!(
            member(&members, "zboot/root.tar.zst"),
            std::fs::read(&tar).unwrap()
        );
        assert_eq!(member(&members, "init"), BOOTSTRAP);
        assert_eq!(std::fs::read(&staged.kernel).unwrap(), b"x");
    }

    #[test]
    fn boot_tar_passes_a_hostid_only_when_one_was_adopted() {
        let (scratch, host, tar) = setup();
        let mut backend = Fake::new(&scratch);
        returned(boot_with(&mut backend, &host, &tar, None, &[], || Ok(())));
        assert!(!backend.staged().command_line.contains("spl.spl_hostid"));
        let mut backend = Fake::new(&scratch);
        backend.work = scratch.0.join("work-adopted");
        backend.identity = (Some(0x0174627a), Some(BTreeSet::from(["100".to_owned()])));
        returned(boot_with(&mut backend, &host, &tar, None, &[], || Ok(())));
        assert_eq!(
            backend.staged().command_line,
            "console=ttyS0,115200n8 console=tty0 spl.spl_hostid=0x0174627a"
        );
        // Pools close after the load and before the kernel starts.
        let order: Vec<_> = backend
            .actions
            .iter()
            .map(|action| match action {
                Action::Load { .. } => "load".to_owned(),
                Action::Export { pool } => format!("export {pool}"),
                Action::Execute => "execute".to_owned(),
                other => panic!("a RAM boot does not {other:?}"),
            })
            .collect();
        assert_eq!(order, ["load", "export tank", "execute"]);
    }
}
