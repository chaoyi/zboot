//! Explicit overlays for a new BE, applied in their reviewed order. Named
//! built-ins are files only; the non-nameable portable overlay has a hook.
//!
//! An overlay is `rootfs/`, copied over the BE root, and for a host overlay
//! an optional executable `post-install`. A tar keeps owners, modes and
//! xattrs; a directory is installed `root:root` with its modes. Existing
//! directories keep their owner and mode. The review lists every entry with
//! its kind, owner, mode, content digest, link target and xattr digests, and
//! the hook's bytes digest, never contents; its digest is bound into consent.
//! Writes never follow a symlink already in the BE: every parent is opened
//! beneath the root with no symlink step, and a leaf is replaced by rename.
use super::refuse;
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

/// Embedded file metadata, identical in the standalone and UKI binaries.
enum Base {
    File(&'static [u8]),
    Symlink(&'static str),
}

const RESCUE: &[(&str, Base)] = &[
    (
        "etc/issue",
        Base::File(include_bytes!("overlays/rescue/rootfs/etc/issue")),
    ),
    (
        "etc/ssh/sshd_config.d/zboot-rescue.conf",
        Base::File(include_bytes!(
            "overlays/rescue/rootfs/etc/ssh/sshd_config.d/zboot-rescue.conf"
        )),
    ),
    (
        "etc/systemd/network/89-zboot-rescue.network",
        Base::File(include_bytes!(
            "overlays/rescue/rootfs/etc/systemd/network/89-zboot-rescue.network"
        )),
    ),
    (
        "etc/systemd/system/getty@.service.d/zboot-rescue.conf",
        Base::File(include_bytes!(
            "overlays/rescue/rootfs/etc/systemd/system/getty@.service.d/zboot-rescue.conf"
        )),
    ),
    (
        "etc/systemd/system/multi-user.target.wants/systemd-networkd.service",
        Base::Symlink("/usr/lib/systemd/system/systemd-networkd.service"),
    ),
    (
        "etc/systemd/system/serial-getty@.service.d/zboot-rescue.conf",
        Base::File(include_bytes!(
            "overlays/rescue/rootfs/etc/systemd/system/serial-getty@.service.d/zboot-rescue.conf"
        )),
    ),
];
const PORTABLE: &[(&str, Base)] = &[
    (
        "etc/default/zfs",
        Base::File(include_bytes!("overlays/portable/rootfs/etc/default/zfs")),
    ),
    (
        "etc/initramfs-tools/modules",
        Base::File(include_bytes!(
            "overlays/portable/rootfs/etc/initramfs-tools/modules"
        )),
    ),
    (
        "etc/initramfs-tools/scripts/init-bottom/zboot-portable",
        Base::File(include_bytes!(
            "overlays/portable/rootfs/etc/initramfs-tools/scripts/init-bottom/zboot-portable"
        )),
    ),
];
const PORTABLE_HOOK: &[u8] = include_bytes!("overlays/portable/post-install");
const PORTABLE_SOURCE: &str = "builtin-internal:portable";

/// A builtin prefix is never interpreted as a disk path. CLI callers map an
/// unknown name to their ordinary usage error, preserving this names list.
pub fn validate_builtin_name(source: &Path) -> io::Result<()> {
    if source
        .as_os_str()
        .as_encoded_bytes()
        .starts_with(b"builtin:")
        && source.as_os_str().as_encoded_bytes() != b"builtin:rescue"
    {
        return Err(refuse(
            "unknown builtin overlay; available names: builtin:rescue",
        ));
    }
    Ok(())
}

fn embedded(source: &str, files: &[(&str, Base)], hook: Option<&[u8]>) -> Overlay {
    let mut entries = BTreeMap::new();
    for (path, item) in files {
        // Structural directories use the same reviewed metadata and put()
        // semantics as a directory overlay. Existing directories stay intact.
        let mut parent = *path;
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            entries.entry(prefix.to_owned()).or_insert_with(|| Entry {
                path: prefix.into(),
                kind: Kind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                xattrs: BTreeMap::new(),
            });
            parent = prefix;
        }
        let (kind, mode) = match item {
            Base::File(bytes) => (
                Kind::File {
                    sha256: digest(bytes),
                    bytes: bytes.len() as u64,
                },
                if path.starts_with("etc/initramfs-tools/scripts/") {
                    0o755
                } else {
                    0o644
                },
            ),
            Base::Symlink(target) => (
                Kind::Symlink {
                    target: (*target).into(),
                },
                0o777,
            ),
        };
        entries.insert(
            (*path).into(),
            Entry {
                path: (*path).into(),
                kind,
                mode,
                uid: 0,
                gid: 0,
                xattrs: BTreeMap::new(),
            },
        );
    }
    let entries = entries.into_values().collect();
    let hook = hook.map(|bytes| Hook {
        sha256: digest(bytes),
        bytes: bytes.len() as u64,
    });
    finish(Path::new(source), Form::Builtin, entries, hook).expect("embedded overlay is valid")
}

/// Mandatory final portable overlay. It is deliberately not a builtin name.
pub fn portable() -> Overlay {
    embedded(PORTABLE_SOURCE, PORTABLE, Some(PORTABLE_HOOK))
}

fn embedded_files(overlay: &Overlay) -> io::Result<&'static [(&'static str, Base)]> {
    match overlay.source.to_str() {
        Some("builtin:rescue") => Ok(RESCUE),
        Some(PORTABLE_SOURCE) => Ok(PORTABLE),
        _ => Err(refuse("recorded builtin overlay is not this zboot's")),
    }
}

const MAX_ENTRIES: usize = 20_000;
const MAX_BYTES: u64 = 1 << 30;
const MAX_HOOK: u64 = 16 * 1024 * 1024;
const MAX_XATTR: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Form {
    /// Embedded bytes selected by the recorded source.
    Builtin,
    Directory,
    Tar,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kind {
    Directory,
    File { sha256: String, bytes: u64 },
    Symlink { target: String },
}

/// The plan's wording, e.g. `file 154 bytes sha256 589a...`. Tokens bind the
/// serialized entry, never this text.
impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::Directory => write!(f, "directory"),
            Kind::File { sha256, bytes } => write!(f, "file {bytes} bytes sha256 {sha256}"),
            Kind::Symlink { target } => {
                write!(
                    f,
                    "symlink -> {}",
                    zfs_tools::engine::escape_display(target)
                )
            }
        }
    }
}

/// Unknown fields are refused by [`Kind`], which takes every field the
/// entry does not (serde cannot refuse them on a struct with a flatten).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Relative to the BE root.
    pub path: String,
    #[serde(flatten)]
    pub kind: Kind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Name -> SHA-256 of the value.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub xattrs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hook {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Overlay {
    pub source: PathBuf,
    pub form: Form,
    /// Digest of the entries and hook.
    pub sha256: String,
    pub entries: Vec<Entry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_install: Option<Hook>,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// A canonical contained relative path, without `.`/`..`/empty components.
fn canonical(path: &Path) -> io::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => parts.push(
                part.to_str()
                    .filter(|p| !p.contains(['\n', '\r', '\0']))
                    .ok_or_else(|| refuse("overlay paths must be UTF-8 without control breaks"))?,
            ),
            _ => return Err(refuse("overlay member is absolute or leaves its root")),
        }
    }
    let path = parts.join("/");
    if path.len() > 4096 {
        return Err(refuse("overlay path exceeds 4096 bytes"));
    }
    Ok(path)
}

fn finish(
    source: &Path,
    form: Form,
    mut entries: Vec<Entry>,
    hook: Option<Hook>,
) -> io::Result<Overlay> {
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for entry in &entries {
        if entry.path.is_empty() || !seen.insert(entry.path.clone()) {
            return Err(refuse(format!("overlay names {:?} twice", entry.path)));
        }
        // A parent must be a directory of this overlay or of the root itself.
        if let Some((parent, _)) = entry.path.rsplit_once('/')
            && seen.contains(parent)
            && entries
                .iter()
                .any(|e| e.path == parent && !matches!(e.kind, Kind::Directory))
        {
            return Err(refuse(format!(
                "overlay places {} under a non-directory",
                entry.path
            )));
        }
        if let Kind::File { bytes, .. } = entry.kind {
            total += bytes;
        }
        if entry.mode & !0o7777 != 0 {
            return Err(refuse("overlay mode is out of range"));
        }
    }
    if entries.len() > MAX_ENTRIES || total > MAX_BYTES {
        return Err(refuse(format!(
            "overlay exceeds {MAX_ENTRIES} entries or {} bytes",
            MAX_BYTES
        )));
    }
    let sha256 = digest(&serde_json::to_vec(&(&entries, &hook)).map_err(refuse)?);
    Ok(Overlay {
        source: source.to_path_buf(),
        form,
        sha256,
        entries,
        post_install: hook,
    })
}

/// Recheck a reviewed overlay against its source or embedded bytes.
pub fn again(overlay: &Overlay) -> io::Result<Overlay> {
    match overlay.form {
        Form::Builtin => match overlay.source.to_str() {
            Some(PORTABLE_SOURCE) => Ok(portable()),
            _ => review(&overlay.source),
        },
        Form::Directory | Form::Tar => review(&overlay.source),
    }
}

/// Review an overlay directory or tar.
pub fn review(source: &Path) -> io::Result<Overlay> {
    validate_builtin_name(source)?;
    if source.as_os_str().as_encoded_bytes() == b"builtin:rescue" {
        return Ok(embedded("builtin:rescue", RESCUE, None));
    }
    let source = fs::canonicalize(source)
        .map_err(|e| refuse(format!("overlay {}: {e}", source.display())))?;
    let meta = fs::symlink_metadata(&source)?;
    if meta.is_dir() {
        review_directory(&source)
    } else if meta.is_file() {
        review_tar(&source, &mut |_, _, _| Ok(()))
    } else {
        Err(refuse("an overlay is a directory or a tar file"))
    }
}

fn beneath(base: &File, path: &str, flags: OFlags) -> io::Result<File> {
    Ok(File::from(crate::openat2_scoped(
        base,
        if path.is_empty() { "." } else { path },
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        // openat2 refuses a mode without O_CREAT.
        if flags.contains(OFlags::CREATE) {
            Mode::from_raw_mode(0o600)
        } else {
            Mode::empty()
        },
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?))
}

fn hash_reader(mut reader: impl Read, limit: u64) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 16];
    let mut bytes = 0;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > limit {
            return Err(refuse("overlay file exceeds its size limit"));
        }
        hasher.update(&buffer[..n]);
    }
    Ok((format!("{:x}", hasher.finalize()), bytes))
}

fn review_directory(source: &Path) -> io::Result<Overlay> {
    let top = File::open(source).map_err(crate::output::naming("overlay", source))?;
    let mut entries = Vec::new();
    let mut hook = None;
    for name in fs::read_dir(source).map_err(crate::output::naming("overlay", source))? {
        let name = name?.file_name();
        match name.to_str() {
            Some("rootfs") => {}
            Some("post-install") => {
                let file = beneath(&top, "post-install", OFlags::RDONLY)?;
                let meta = file.metadata()?;
                if !meta.is_file() || meta.mode() & 0o111 == 0 {
                    return Err(refuse(
                        "overlay post-install must be an executable regular file",
                    ));
                }
                let (sha256, bytes) = hash_reader(file, MAX_HOOK)?;
                hook = Some(Hook { sha256, bytes });
            }
            _ => {
                return Err(refuse(format!(
                    "an overlay holds only rootfs/ and post-install, not {name:?}"
                )));
            }
        }
    }
    if fs::symlink_metadata(source.join("rootfs")).is_ok() {
        let rootfs = beneath(&top, "rootfs", OFlags::RDONLY | OFlags::DIRECTORY)?;
        walk(&rootfs, "", &mut entries)?;
    }
    finish(source, Form::Directory, entries, hook)
}

fn walk(rootfs: &File, relative: &str, entries: &mut Vec<Entry>) -> io::Result<()> {
    let directory = beneath(rootfs, relative, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&directory)? {
        let entry = entry?;
        let name = entry.file_name().to_str().map_err(refuse)?.to_owned();
        if name != "." && name != ".." {
            names.push(name);
        }
    }
    names.sort();
    for name in names {
        if entries.len() > MAX_ENTRIES {
            return Err(refuse("overlay has too many entries"));
        }
        let path = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        canonical(Path::new(&path))?;
        let stat = rustix::fs::statat(&directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        let mode = stat.st_mode & 0o7777;
        let entry = |kind| Entry {
            path: path.clone(),
            kind,
            mode,
            uid: 0,
            gid: 0,
            xattrs: BTreeMap::new(),
        };
        match kind {
            rustix::fs::FileType::Directory => {
                entries.push(entry(Kind::Directory));
                walk(rootfs, &path, entries)?;
            }
            rustix::fs::FileType::RegularFile => {
                let file = beneath(rootfs, &path, OFlags::RDONLY)?;
                let (sha256, bytes) = hash_reader(file, MAX_BYTES)?;
                entries.push(entry(Kind::File { sha256, bytes }));
            }
            rustix::fs::FileType::Symlink => {
                let target = rustix::fs::readlinkat(&directory, name.as_str(), Vec::new())?;
                let target = target
                    .into_string()
                    .map_err(|_| refuse("overlay link target is not UTF-8"))?;
                entries.push(Entry {
                    mode: 0o777,
                    ..entry(Kind::Symlink { target })
                });
            }
            _ => {
                return Err(refuse(format!(
                    "overlay {path} is not a file, directory or symlink"
                )));
            }
        }
    }
    Ok(())
}

fn tar_reader(file: File) -> io::Result<Box<dyn Read>> {
    let mut magic = [0_u8; 4];
    let mut peek = file.try_clone()?;
    let read = peek.read(&mut magic)?;
    use std::io::Seek;
    let mut file = file;
    file.seek(io::SeekFrom::Start(0))?;
    Ok(if read == 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Box::new(zstd::stream::read::Decoder::new(file)?)
    } else {
        Box::new(file)
    })
}

/// Called with each member as it streams: its entry, xattr values and bytes.
pub type Each<'a> =
    dyn FnMut(&Entry, &BTreeMap<String, Vec<u8>>, &mut dyn Read) -> io::Result<()> + 'a;

/// Review a tar overlay; `each` sees every rootfs entry with its reader,
/// in archive order, so apply can stream the same pass.
fn review_tar(source: &Path, each: &mut Each) -> io::Result<Overlay> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(crate::output::naming("overlay", source))?;
    let mut archive = tar::Archive::new(tar_reader(file)?);
    let mut entries = Vec::new();
    let mut hook = None;
    for member in archive.entries()? {
        let mut member = member?;
        let path = canonical(&member.path()?)?;
        let header = member.header().clone();
        let kind = header.entry_type();
        if path == "post-install" {
            if !kind.is_file() || header.mode()? & 0o111 == 0 || hook.is_some() {
                return Err(refuse(
                    "overlay post-install must be one executable regular file",
                ));
            }
            let (sha256, bytes) = hash_reader(&mut member, MAX_HOOK)?;
            hook = Some(Hook { sha256, bytes });
            continue;
        }
        if path == "rootfs" && kind.is_dir() {
            continue;
        }
        let Some(relative) = path.strip_prefix("rootfs/") else {
            return Err(refuse(format!(
                "an overlay holds only rootfs/ and post-install, not {path:?}"
            )));
        };
        let mut xattrs = BTreeMap::new();
        let mut values = BTreeMap::new();
        if let Some(extensions) = member.pax_extensions()? {
            for extension in extensions {
                let extension = extension?;
                if let Some(name) = extension
                    .key()
                    .map_err(refuse)?
                    .strip_prefix("SCHILY.xattr.")
                {
                    if extension.value_bytes().len() > MAX_XATTR {
                        return Err(refuse("overlay xattr exceeds its size limit"));
                    }
                    xattrs.insert(name.to_string(), digest(extension.value_bytes()));
                    values.insert(name.to_string(), extension.value_bytes().to_vec());
                }
            }
        }
        let kind = if kind.is_dir() {
            Kind::Directory
        } else if kind.is_file() {
            Kind::File {
                sha256: String::new(),
                bytes: 0,
            }
        } else if kind.is_symlink() {
            let target = member
                .link_name()?
                .and_then(|t| t.to_str().map(str::to_owned))
                .ok_or_else(|| refuse("overlay link target is missing or not UTF-8"))?;
            Kind::Symlink { target }
        } else {
            return Err(refuse(format!(
                "overlay {path} is not a file, directory or symlink (hardlinks and devices are refused)"
            )));
        };
        let mut entry = Entry {
            path: relative.to_string(),
            mode: if matches!(kind, Kind::Symlink { .. }) {
                0o777
            } else {
                header.mode()? & 0o7777
            },
            kind,
            uid: u32::try_from(header.uid()?).map_err(refuse)?,
            gid: u32::try_from(header.gid()?).map_err(refuse)?,
            xattrs,
        };
        if let Kind::File { .. } = entry.kind {
            let mut hasher = HashingReader::new(&mut member);
            each(&entry, &values, &mut hasher)?;
            io::copy(&mut hasher, &mut io::sink())?;
            let (sha256, bytes) = hasher.finish();
            entry.kind = Kind::File { sha256, bytes };
        } else {
            each(&entry, &values, &mut io::empty())?;
        }
        entries.push(entry);
    }
    finish(source, Form::Tar, entries, hook)
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}
impl<R: Read> HashingReader<R> {
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
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..n]);
        self.bytes += n as u64;
        if self.bytes > MAX_BYTES {
            return Err(refuse("overlay file exceeds its size limit"));
        }
        Ok(n)
    }
}

/// The parent of `path` in the BE, opened beneath the root through real
/// directories only; existing symlinks are refused, not followed.
fn parent<'a>(root: &File, path: &'a str) -> io::Result<(File, &'a str)> {
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    let directory = beneath(root, parent, OFlags::RDONLY | OFlags::DIRECTORY).map_err(|e| {
        refuse(format!(
            "overlay {path}: its parent in the BE is not a real directory ({e}); a destination symlink is never followed"
        ))
    })?;
    Ok((directory, name))
}

fn owner(fd: &File, entry: &Entry) -> io::Result<()> {
    rustix::fs::fchown(
        fd,
        Some(rustix::process::Uid::from_raw(entry.uid)),
        Some(rustix::process::Gid::from_raw(entry.gid)),
    )?;
    rustix::fs::fchmod(fd, Mode::from_raw_mode(entry.mode))?;
    Ok(())
}

fn temporary() -> String {
    format!(".zboot-overlay-{}", uuid::Uuid::new_v4())
}

/// Install one entry; `content` supplies a file's bytes, and `xattrs` the
/// values [`members`] checked against the review's digests.
fn put(
    root: &File,
    entry: &Entry,
    content: &mut dyn Read,
    xattrs: &BTreeMap<String, Vec<u8>>,
) -> io::Result<()> {
    let (directory, name) = parent(root, &entry.path)?;
    match &entry.kind {
        Kind::Directory => {
            match rustix::fs::mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let created = beneath(&directory, name, OFlags::RDONLY | OFlags::DIRECTORY)?;
                    owner(&created, entry)?;
                    set_xattrs(&created, xattrs)?;
                }
                Err(rustix::io::Errno::EXIST) => {
                    beneath(&directory, name, OFlags::RDONLY | OFlags::DIRECTORY).map_err(
                        |_| {
                            refuse(format!(
                                "overlay directory {} would replace a non-directory",
                                entry.path
                            ))
                        },
                    )?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Kind::File { sha256, bytes } => {
            let staged = temporary();
            let mut file = beneath(
                &directory,
                &staged,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            )?;
            let result = (|| {
                let mut hasher = HashingReader::new(content);
                io::copy(&mut hasher, &mut file)?;
                if hasher.finish() != (sha256.clone(), *bytes) {
                    return Err(refuse(format!(
                        "overlay {} changed since review",
                        entry.path
                    )));
                }
                owner(&file, entry)?;
                set_xattrs(&file, xattrs)?;
                file.sync_all()?;
                rename(&directory, &staged, name, &entry.path)
            })();
            if result.is_err() {
                let _ = rustix::fs::unlinkat(&directory, staged.as_str(), AtFlags::empty());
            }
            result?;
        }
        Kind::Symlink { target } => {
            if !xattrs.is_empty() {
                return Err(refuse("overlay symlinks carry no xattrs"));
            }
            let staged = temporary();
            rustix::fs::symlinkat(target.as_str(), &directory, staged.as_str())?;
            let result = rustix::fs::chownat(
                &directory,
                staged.as_str(),
                Some(rustix::process::Uid::from_raw(entry.uid)),
                Some(rustix::process::Gid::from_raw(entry.gid)),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)
            .and_then(|()| rename(&directory, &staged, name, &entry.path));
            if result.is_err() {
                let _ = rustix::fs::unlinkat(&directory, staged.as_str(), AtFlags::empty());
            }
            result?;
        }
    }
    directory.sync_all()
}

fn rename(directory: &File, staged: &str, name: &str, path: &str) -> io::Result<()> {
    if let Ok(stat) = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        && rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory
    {
        return Err(refuse(format!("overlay {path} would replace a directory")));
    }
    rustix::fs::renameat(directory, staged, directory, name)?;
    Ok(())
}

fn set_xattrs(fd: &File, xattrs: &BTreeMap<String, Vec<u8>>) -> io::Result<()> {
    for (name, value) in xattrs {
        rustix::fs::fsetxattr(fd, name.as_str(), value, rustix::fs::XattrFlags::empty())?;
    }
    Ok(())
}

/// Install the reviewed `rootfs/` into `root`. The source is read again and
/// every entry must match its review; a file's bytes are checked against its
/// digest as they are written, before the rename that installs them.
pub fn apply(root: &Path, overlay: &Overlay) -> io::Result<()> {
    let root = File::open(root)?;
    members(overlay, &mut |entry, values, content| {
        put(&root, entry, content, values)
    })
}

/// Each reviewed `rootfs/` entry, in order, read again from its source; every
/// entry and its xattr values must still match the review. The consumer
/// checks a file's bytes against the entry's digest.
pub fn members(overlay: &Overlay, each: &mut Each) -> io::Result<()> {
    let mut each = |entry: &Entry, xattrs: &BTreeMap<String, Vec<u8>>, content: &mut dyn Read| {
        if xattrs.len() != entry.xattrs.len()
            || xattrs
                .iter()
                .any(|(key, value)| entry.xattrs.get(key) != Some(&digest(value)))
        {
            return Err(refuse(format!("overlay {} xattrs changed", entry.path)));
        }
        each(entry, xattrs, content)
    };
    match overlay.form {
        Form::Builtin => {
            if again(overlay)? != *overlay {
                return Err(refuse("builtin overlay bytes changed since review"));
            }
            let files = embedded_files(overlay)?;
            for entry in &overlay.entries {
                let mut content: &[u8] = if matches!(entry.kind, Kind::Directory) {
                    &[]
                } else {
                    let (_, item) = files
                        .iter()
                        .find(|(path, _)| *path == entry.path)
                        .ok_or_else(|| refuse("builtin overlay member is absent"))?;
                    match item {
                        Base::File(bytes) => bytes,
                        _ => &[],
                    }
                };
                each(entry, &BTreeMap::new(), &mut content)?;
            }
            Ok(())
        }
        Form::Directory => {
            if review_directory(&overlay.source)? != *overlay {
                return Err(refuse("overlay directory changed since review"));
            }
            let top = File::open(&overlay.source)?;
            for entry in &overlay.entries {
                let mut content: Box<dyn Read> = match &entry.kind {
                    Kind::File { .. } => Box::new(beneath(
                        &beneath(&top, "rootfs", OFlags::RDONLY | OFlags::DIRECTORY)?,
                        &entry.path,
                        OFlags::RDONLY,
                    )?),
                    _ => Box::new(io::empty()),
                };
                each(entry, &BTreeMap::new(), &mut content)?;
            }
            Ok(())
        }
        Form::Tar => {
            let mut installed = 0;
            let streamed = review_tar(&overlay.source, &mut |entry, values, content| {
                let reviewed = overlay
                    .entries
                    .iter()
                    .find(|e| e.path == entry.path)
                    .ok_or_else(|| refuse(format!("overlay {} was not reviewed", entry.path)))?;
                // The consumer checks content; everything else must match now.
                let mut shape = reviewed.clone();
                if let (Kind::File { .. }, Kind::File { .. }) = (&reviewed.kind, &entry.kind) {
                    shape.kind = entry.kind.clone();
                }
                if shape != *entry {
                    return Err(refuse(format!(
                        "overlay {} changed since review",
                        entry.path
                    )));
                }
                installed += 1;
                each(reviewed, values, content)
            })?;
            if streamed != *overlay || installed != overlay.entries.len() {
                return Err(refuse("overlay tar changed since review"));
            }
            Ok(())
        }
    }
}

/// The reviewed hook's bytes, read again from its source.
fn hook_bytes(overlay: &Overlay) -> io::Result<Vec<u8>> {
    let expected = overlay
        .post_install
        .as_ref()
        .ok_or_else(|| refuse("overlay has no post-install"))?;
    let bytes = match overlay.form {
        Form::Builtin => {
            if overlay.source != Path::new(PORTABLE_SOURCE) || again(overlay)? != *overlay {
                return Err(refuse("this builtin overlay has no reviewed post-install"));
            }
            PORTABLE_HOOK.to_vec()
        }
        Form::Directory => {
            let mut bytes = Vec::new();
            beneath(
                &File::open(&overlay.source)?,
                "post-install",
                OFlags::RDONLY,
            )?
            .take(MAX_HOOK + 1)
            .read_to_end(&mut bytes)?;
            bytes
        }
        Form::Tar => {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&overlay.source)?;
            let mut archive = tar::Archive::new(tar_reader(file)?);
            let mut found = None;
            for member in archive.entries()? {
                let mut member = member?;
                if canonical(&member.path()?)? == "post-install" {
                    let mut bytes = Vec::new();
                    (&mut member).take(MAX_HOOK + 1).read_to_end(&mut bytes)?;
                    found = Some(bytes);
                }
            }
            found.ok_or_else(|| refuse("overlay post-install disappeared"))?
        }
    };
    if digest(&bytes) != expected.sha256 || bytes.len() as u64 != expected.bytes {
        return Err(refuse("overlay post-install changed since review"));
    }
    Ok(bytes)
}

/// Mounts made for the hook, undone in reverse.
struct Mounts(Vec<PathBuf>);
impl Mounts {
    fn add(
        &mut self,
        path: PathBuf,
        kind: &str,
        flags: nix::mount::MsFlags,
        options: &str,
    ) -> io::Result<()> {
        fs::create_dir_all(&path)?;
        nix::mount::mount(Some(kind), &path, Some(kind), flags, Some(options)).map_err(refuse)?;
        self.0.push(path);
        Ok(())
    }
    fn finish(&mut self) -> io::Result<()> {
        while let Some(path) = self.0.last() {
            nix::mount::umount2(path, nix::mount::MntFlags::UMOUNT_NOFOLLOW).map_err(refuse)?;
            self.0.pop();
        }
        Ok(())
    }
}
impl Drop for Mounts {
    fn drop(&mut self) {
        for path in self.0.iter().rev() {
            let _ = nix::mount::umount2(
                path,
                nix::mount::MntFlags::MNT_DETACH | nix::mount::MntFlags::UMOUNT_NOFOLLOW,
            );
        }
    }
}

/// Private `/dev` (fresh nodes, no host devices), `/dev/pts`, `/dev/shm`, a
/// read-only `/sys` and an empty `/run`, in the caller's private mount
/// namespace; `/proc` is the hook's own PID namespace's.
fn hook_mounts(root: &Path) -> io::Result<Mounts> {
    use nix::mount::MsFlags;
    let mut mounts = Mounts(Vec::new());
    mounts.add(
        root.join("dev"),
        "tmpfs",
        MsFlags::MS_NOSUID,
        "mode=755,size=16M",
    )?;
    for (name, major, minor, mode) in [
        ("null", 1, 3, 0o666),
        ("zero", 1, 5, 0o666),
        ("full", 1, 7, 0o666),
        ("random", 1, 8, 0o666),
        ("urandom", 1, 9, 0o666),
        ("tty", 5, 0, 0o666),
    ] {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            root.join("dev").join(name),
            rustix::fs::FileType::CharacterDevice,
            Mode::from_raw_mode(mode),
            rustix::fs::makedev(major, minor),
        )?;
        fs::set_permissions(
            root.join("dev").join(name),
            std::os::unix::fs::PermissionsExt::from_mode(mode),
        )?;
    }
    for (name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
        ("ptmx", "pts/ptmx"),
    ] {
        std::os::unix::fs::symlink(target, root.join("dev").join(name))?;
    }
    mounts.add(
        root.join("dev/pts"),
        "devpts",
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=620,gid=5",
    )?;
    mounts.add(
        root.join("dev/shm"),
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        "mode=1777,size=64M",
    )?;
    mounts.add(
        root.join("sys"),
        "sysfs",
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        "",
    )?;
    mounts.add(
        root.join("run"),
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        "mode=755,size=64M",
    )?;
    Ok(mounts)
}

pub(crate) const HOOK: &str = "/run/zboot-post-install";
const POLICY: &str = "usr/sbin/policy-rc.d";

/// The host-side paths the hook's mounts and `policy-rc.d` use must be the
/// root's own directories: an earlier overlay or hook could have made one a
/// link that resolves on the host.
fn require_directories(root: &Path) -> io::Result<()> {
    for name in ["usr", "usr/sbin", "usr/bin", "dev", "sys", "run"] {
        if !fs::symlink_metadata(root.join(name)).is_ok_and(|m| m.is_dir()) {
            return Err(refuse(format!(
                "post-install needs /{name} in the new root to be a directory, not a link"
            )));
        }
    }
    Ok(())
}

/// The hook runs as PID 1 of its own PID namespace (the root's own
/// util-linux `unshare`), so every descendant dies with it; `/proc` is that
/// namespace's.
pub(crate) fn hook_command(root: &Path) -> Command {
    let mut command = Command::new("chroot");
    command.arg(root).args([
        "/usr/bin/unshare",
        "--pid",
        "--fork",
        "--kill-child",
        "--mount-proc",
        "--",
        HOOK,
    ]);
    command
}

/// Run the reviewed `post-install` in `root` with private mounts, service
/// starts refused by `policy-rc.d`, `env`, and its output in `log` (0600),
/// never in the result. The caller holds a private mount namespace.
pub fn post_install(
    root: &Path,
    overlay: &Overlay,
    env: &[(&str, String)],
    log: &Path,
) -> io::Result<()> {
    let bytes = hook_bytes(overlay)?;
    require_directories(root)?;
    let unshare = root.join("usr/bin/unshare");
    if !fs::symlink_metadata(&unshare).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0) {
        return Err(refuse(
            "post-install needs the root's /usr/bin/unshare (util-linux)",
        ));
    }
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(log)?;
    let mut mounts = hook_mounts(root)?;
    let mut hook = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(root.join(HOOK.trim_start_matches('/')))?;
    hook.write_all(&bytes)?;
    hook.sync_all()?;
    drop(hook);
    let policy = root.join(POLICY);
    let saved = root.join(format!("{POLICY}.zboot-saved-{}", uuid::Uuid::new_v4()));
    let had_policy = fs::symlink_metadata(&policy).is_ok();
    if had_policy {
        fs::rename(&policy, &saved)?;
    }
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&policy)?;
        file.write_all(
            b"#!/bin/sh\n# zboot deploy: no service starts during post-install\nexit 101\n",
        )?;
        drop(file);
        let mut command = hook_command(root);
        command
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("LC_ALL", "C")
            .env("HOME", "/root")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output);
        for (key, value) in env {
            command.env(key, value);
        }
        let status = zfs_tools::engine::native::announced(&mut command).status()?;
        if !status.success() {
            return Err(refuse(format!(
                "post-install failed ({status}); its output is in {}",
                log.display()
            )));
        }
        Ok(())
    })();
    let cleanup = require_directories(root)
        .and_then(|()| fs::remove_file(&policy))
        .and_then(|()| {
            if had_policy {
                fs::rename(&saved, &policy)
            } else {
                Ok(())
            }
        });
    let unmounted = mounts.finish();
    result?;
    cleanup?;
    unmounted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory::tests::Scratch;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn plan_entries_read_as_words() {
        let file = Kind::File {
            sha256: "589a".into(),
            bytes: 154,
        };
        assert_eq!(file.to_string(), "file 154 bytes sha256 589a");
        let link = Kind::Symlink {
            target: "/usr/lib/x".into(),
        };
        assert_eq!(link.to_string(), "symlink -> /usr/lib/x");
        assert_eq!(Kind::Directory.to_string(), "directory");
    }

    fn ids() -> (u32, u32) {
        (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
    }

    enum Member<'a> {
        Dir,
        File(&'a [u8]),
        Link(&'a str),
        Hard(&'a str),
        Device,
    }

    /// A tar whose members the caller owns, so `apply` runs unprivileged.
    /// Names are written raw, so hostile ones can be tested.
    fn tar(path: &Path, members: &[(&str, u32, Member)]) {
        let (uid, gid) = ids();
        let mut builder = tar::Builder::new(File::create(path).unwrap());
        for (name, mode, member) in members {
            let mut header = tar::Header::new_ustar();
            let field = &mut header.as_old_mut().name;
            field.fill(0);
            field[..name.len()].copy_from_slice(name.as_bytes());
            header.set_mode(*mode);
            header.set_uid(uid.into());
            header.set_gid(gid.into());
            let data: &[u8] = match member {
                Member::Dir => {
                    header.set_entry_type(tar::EntryType::Directory);
                    &[]
                }
                Member::File(bytes) => {
                    header.set_entry_type(tar::EntryType::Regular);
                    bytes
                }
                Member::Link(target) | Member::Hard(target) => {
                    header.set_entry_type(if matches!(member, Member::Link(_)) {
                        tar::EntryType::Symlink
                    } else {
                        tar::EntryType::Link
                    });
                    header.set_size(0);
                    // Absolute fixture paths can exceed ustar's link field
                    // under a caller-selected TMPDIR. Emit the GNU extension.
                    builder.append_link(&mut header, name, target).unwrap();
                    continue;
                }
                Member::Device => {
                    header.set_entry_type(tar::EntryType::Char);
                    &[]
                }
            };
            header.set_size(data.len() as u64);
            header.set_cksum();
            builder.append(&header, data).unwrap();
        }
        builder.finish().unwrap();
    }

    fn host(path: &Path, content: &[u8]) {
        tar(
            path,
            &[
                ("rootfs/", 0o755, Member::Dir),
                ("rootfs/etc/", 0o755, Member::Dir),
                ("rootfs/etc/host.conf", 0o600, Member::File(content)),
                ("rootfs/etc/link", 0o777, Member::Link("host.conf")),
                ("post-install", 0o755, Member::File(b"#!/bin/sh\n")),
            ],
        );
    }

    #[test]
    fn builtin_rescue_holds_exactly_the_six_documented_files() {
        let rescue = review(Path::new("builtin:rescue")).unwrap();
        let leaves: Vec<_> = rescue
            .entries
            .iter()
            .filter(|entry| !matches!(entry.kind, Kind::Directory))
            .map(|entry| entry.path.as_str())
            .collect();
        assert_eq!(
            leaves,
            RESCUE.iter().map(|(path, _)| *path).collect::<Vec<_>>()
        );
        assert_eq!(leaves.len(), 6);
        assert!(rescue.post_install.is_none());
        assert_eq!(rescue.form, Form::Builtin);
        for (_, item) in RESCUE {
            if let Base::File(bytes) = item {
                let text = std::str::from_utf8(bytes).unwrap();
                assert!(!text.contains("Wants=systemd-networkd-wait-online"));
                assert!(!text.contains("After=systemd-networkd-wait-online"));
            }
        }
        let network =
            include_str!("overlays/rescue/rootfs/etc/systemd/network/89-zboot-rescue.network");
        assert!(network.contains("DHCP=ipv4\n"));
        assert!(network.contains("ClientIdentifier=mac\n"));
        assert!(include_str!("overlays/rescue/rootfs/etc/issue").contains("\\4"));
        assert_eq!(
            include_str!("overlays/rescue/rootfs/etc/ssh/sshd_config.d/zboot-rescue.conf"),
            "PermitRootLogin yes\n"
        );
    }

    #[test]
    fn builtin_rescue_is_identical_in_the_binary_and_uki() {
        // Both binaries compile this same include_bytes table; compare it to
        // the plain source overlay rather than claiming a built UKI was read.
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/deploy/overlays/rescue");
        let directory = review_directory(&source).unwrap();
        let embedded = review(Path::new("builtin:rescue")).unwrap();
        // Git tracks only whether a file is executable, not the checkout's
        // umask, so compare file modes the way Git records them.
        let leaves = |overlay: &Overlay| {
            overlay
                .entries
                .iter()
                .filter(|entry| !matches!(entry.kind, Kind::Directory))
                .cloned()
                .map(|mut entry| {
                    if matches!(entry.kind, Kind::File { .. }) {
                        entry.mode = if entry.mode & 0o111 == 0 {
                            0o644
                        } else {
                            0o755
                        };
                    }
                    entry
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(leaves(&directory), leaves(&embedded));
        assert_eq!(directory.post_install, embedded.post_install);
        assert_eq!(again(&embedded).unwrap(), embedded);
        let mut changed = embedded.clone();
        changed.entries[0].mode ^= 0o100;
        let scratch = Scratch::new();
        assert!(apply(&scratch.0, &changed).is_err());
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn a_hook_refuses_a_root_whose_mount_or_policy_directories_are_links() {
        let scratch = Scratch::new();
        let root = &scratch.0;
        for name in ["usr/sbin", "usr/bin", "dev", "sys", "run"] {
            fs::create_dir_all(root.join(name)).unwrap();
        }
        require_directories(root).unwrap();
        for name in ["run", "usr/sbin"] {
            fs::remove_dir(root.join(name)).unwrap();
            symlink("/", root.join(name)).unwrap();
            let error = require_directories(root).unwrap_err().to_string();
            assert!(error.contains(&format!("/{name} ")), "{error}");
            fs::remove_file(root.join(name)).unwrap();
            fs::create_dir(root.join(name)).unwrap();
        }
    }

    #[test]
    fn an_unknown_builtin_overlay_is_refused_with_the_names() {
        for name in [
            "builtin:unknown",
            "builtin:portable",
            "builtin:base",
            "builtin:rescue/",
        ] {
            let error = review(Path::new(name)).unwrap_err().to_string();
            assert!(error.contains("available names: builtin:rescue"), "{error}");
        }
        // The explicit relative prefix escapes the reserved-name grammar.
        validate_builtin_name(Path::new("./builtin:any-file")).unwrap();
    }

    #[test]
    fn portable_bytes_are_nonnameable_and_the_hook_rebuilds_all_kernels() {
        let overlay = portable();
        let leaves: Vec<_> = overlay
            .entries
            .iter()
            .filter(|entry| !matches!(entry.kind, Kind::Directory))
            .collect();
        assert_eq!(leaves.len(), 3);
        assert_eq!(
            hook_bytes(&overlay).unwrap(),
            b"#!/bin/sh\nset -eu\nexec /usr/sbin/update-initramfs -u -k all\n"
        );
        assert!(review(Path::new("builtin:portable")).is_err());
        assert_eq!(again(&overlay).unwrap(), overlay);
        let script = include_str!(
            "overlays/portable/rootfs/etc/initramfs-tools/scripts/init-bottom/zboot-portable"
        );
        assert!(script.contains("mount --move \"$rootmnt\" \"$base/lower\""));
        assert!(script.contains("mount -t tmpfs -o mode=0755"));
        assert!(!script.contains("size="));
        assert!(
            script.contains("lowerdir=$base/lower,upperdir=$base/ram/upper,workdir=$base/ram/work")
        );
        assert!(script.contains("panic \"zboot portable:"));
    }

    #[test]
    fn serial_and_console_banners_announce_a_late_lease_without_wait_online() {
        use std::os::unix::process::CommandExt;
        use std::time::{Duration, Instant};
        for name in ["getty@.service", "serial-getty@.service"] {
            let (_, Base::File(bytes)) =
                RESCUE.iter().find(|(path, _)| path.contains(name)).unwrap()
            else {
                panic!("getty source is not a file")
            };
            let unit = std::str::from_utf8(bytes).unwrap();
            assert!(unit.contains("KillMode=control-group\n"));
            assert!(!unit.contains("networkd-wait-online"));
            let joined = unit.replace("\\\n", "");
            let command = joined
                .lines()
                .find_map(|line| line.strip_prefix("ExecStart=-/bin/sh -c '"))
                .unwrap()
                .strip_suffix("'")
                .unwrap();
            // Undo systemd's escapes before the isolated shell seam. No real
            // getty, service or network interface is touched by the test.
            let script = command
                .replace("$$", "$")
                .replace("%%", "%")
                .replace("\\\\", "\\");
            let scratch = Scratch::new();
            // A stand-in hostname -I: nothing until DHCP, then IPv6 and
            // link-local before the address the banner must pick.
            let bin = scratch.0.join("bin");
            fs::create_dir(&bin).unwrap();
            let leased = scratch.0.join("leased");
            fs::write(
                bin.join("hostname"),
                format!(
                    "#!/bin/sh\n[ -e '{}' ] || exit 0\nprintf 'fec0::1 169.254.7.7 192.0.2.55 \\n'\n",
                    leased.display()
                ),
            )
            .unwrap();
            fs::set_permissions(bin.join("hostname"), fs::Permissions::from_mode(0o755)).unwrap();
            // The terminal is a file reached by its path: the inherited
            // descriptors go nowhere, as after login's vhangup.
            let output = scratch.0.join("output");
            File::create(&output).unwrap();
            let terminal = scratch.0.join("agetty");
            fs::write(
                &terminal,
                format!(
                    "#!/bin/sh\ntrap '' HUP\nsleep 0.2\nprintf 'CONSOLE_READY\\n' >> '{}'\nwhile :; do sleep 1; done\n",
                    output.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&terminal, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(script.contains("exec /sbin/agetty"));
            assert!(script.contains(">> /dev/%I;"));
            let script = script
                .replace("/sbin/agetty", terminal.to_str().unwrap())
                .replace("/dev/%I", output.to_str().unwrap());
            let mut child = Command::new("/bin/sh")
                .args(["-c", &script])
                .env("TERM", "vt100")
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap();
            let observed = (|| -> io::Result<String> {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut supplied = false;
                loop {
                    let text = fs::read_to_string(&output)?;
                    if !supplied && text.contains("CONSOLE_READY") {
                        // The hangup login sends at autologin, then the lease.
                        let _ = nix::sys::signal::killpg(
                            nix::unistd::Pid::from_raw(child.id() as i32),
                            nix::sys::signal::Signal::SIGHUP,
                        );
                        fs::write(&leased, b"")?;
                        supplied = true;
                    }
                    if text.contains("Rescue IPv4: 192.0.2.55") {
                        return Ok(text);
                    }
                    if Instant::now() >= deadline {
                        return Err(refuse("late lease banner did not arrive"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            })();
            // Kill the owned process group before reaping its leader, including
            // a watcher that would otherwise survive a failed assertion.
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            child.wait().unwrap();
            let text = observed.unwrap();
            assert!(
                text.find("CONSOLE_READY").unwrap() < text.find("Rescue IPv4: 192.0.2.55").unwrap()
            );
        }
    }

    #[test]
    fn a_cross_overlay_symlink_cannot_escape_the_root() {
        let scratch = Scratch::new();
        let root = scratch.0.join("root");
        fs::create_dir(&root).unwrap();
        // Exercise long link encoding even when TMPDIR itself is short.
        let outside = scratch.0.join("outside-".repeat(16));
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"untouched").unwrap();
        let first = scratch.0.join("first.tar");
        tar(
            &first,
            &[
                ("rootfs/etc", 0o755, Member::Dir),
                (
                    "rootfs/etc/escape",
                    0o777,
                    Member::Link(outside.to_str().unwrap()),
                ),
            ],
        );
        apply(&root, &review(&first).unwrap()).unwrap();
        let second = scratch.0.join("second.tar");
        tar(
            &second,
            &[
                ("rootfs/etc/escape", 0o755, Member::Dir),
                (
                    "rootfs/etc/escape/sentinel",
                    0o644,
                    Member::File(b"changed"),
                ),
            ],
        );
        assert!(apply(&root, &review(&second).unwrap()).is_err());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"untouched");
    }

    #[test]
    fn a_directory_overlay_is_root_owned_with_its_modes_and_nothing_else() {
        let scratch = Scratch::new();
        let dir = scratch.0.join("overlay");
        fs::create_dir_all(dir.join("rootfs/etc")).unwrap();
        fs::write(dir.join("rootfs/etc/secret"), b"s").unwrap();
        fs::set_permissions(
            dir.join("rootfs/etc/secret"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        symlink("secret", dir.join("rootfs/etc/link")).unwrap();
        fs::write(dir.join("post-install"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(dir.join("post-install"), fs::Permissions::from_mode(0o755)).unwrap();
        let overlay = review(&dir).unwrap();
        assert_eq!(overlay.form, Form::Directory);
        let secret = overlay
            .entries
            .iter()
            .find(|e| e.path == "etc/secret")
            .unwrap();
        assert_eq!((secret.uid, secret.gid, secret.mode), (0, 0, 0o640));
        let link = overlay
            .entries
            .iter()
            .find(|e| e.path == "etc/link")
            .unwrap();
        assert_eq!(
            link.kind,
            Kind::Symlink {
                target: "secret".into()
            }
        );
        assert_eq!(overlay.post_install.as_ref().unwrap().bytes, 10);
        // A hook must be executable; nothing but rootfs/ and post-install.
        fs::set_permissions(dir.join("post-install"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(review(&dir).is_err());
        fs::remove_file(dir.join("post-install")).unwrap();
        fs::write(dir.join("overlay.json"), b"{}").unwrap();
        assert!(review(&dir).is_err());
    }

    #[test]
    fn the_digest_binds_modes_owners_links_xattrs_and_the_hook() {
        let entry = Entry {
            path: "etc/a".into(),
            kind: Kind::File {
                sha256: "ab".repeat(32),
                bytes: 1,
            },
            mode: 0o644,
            uid: 0,
            gid: 0,
            xattrs: BTreeMap::new(),
        };
        let digest = |entries: Vec<Entry>, hook: Option<Hook>| {
            finish(Path::new("/o"), Form::Tar, entries, hook)
                .unwrap()
                .sha256
        };
        let original = digest(vec![entry.clone()], None);
        let mut changed = Vec::new();
        for change in 0..6 {
            let mut e = entry.clone();
            let mut hook = None;
            match change {
                0 => e.mode = 0o600,
                1 => e.uid = 1000,
                2 => e.gid = 1000,
                3 => e.kind = Kind::Symlink { target: "b".into() },
                4 => {
                    e.xattrs.insert("user.x".into(), "cd".repeat(32));
                }
                _ => {
                    hook = Some(Hook {
                        sha256: "ef".repeat(32),
                        bytes: 1,
                    })
                }
            }
            changed.push(digest(vec![e], hook));
        }
        assert!(changed.iter().all(|d| *d != original));
        // Its source path is not content: the same overlay elsewhere matches.
        let elsewhere = finish(Path::new("/p"), Form::Tar, vec![entry], None).unwrap();
        assert_eq!(elsewhere.sha256, original);
    }

    #[test]
    fn tar_members_stay_in_rootfs_and_are_plain() {
        let scratch = Scratch::new();
        let path = scratch.0.join("o.tar");
        host(&path, b"x");
        let overlay = review(&path).unwrap();
        let (uid, gid) = ids();
        let conf = overlay
            .entries
            .iter()
            .find(|e| e.path == "etc/host.conf")
            .unwrap();
        assert_eq!((conf.uid, conf.gid, conf.mode), (uid, gid, 0o600));
        assert!(overlay.post_install.is_some());
        for bad in [
            ("../escape", Member::File(b"x")),
            ("/etc/absolute", Member::File(b"x")),
            ("rootfs/../../escape", Member::File(b"x")),
            ("manifest.json", Member::File(b"x")),
            ("rootfs/etc/hard", Member::Hard("rootfs/etc/host.conf")),
            ("rootfs/dev/null", Member::Device),
        ] {
            tar(
                &path,
                &[("rootfs/", 0o755, Member::Dir), (bad.0, 0o644, bad.1)],
            );
            assert!(review(&path).is_err(), "{}", bad.0);
        }
        // The same path twice, and a file under a file.
        tar(
            &path,
            &[
                ("rootfs/a", 0o644, Member::File(b"1")),
                ("rootfs/a", 0o644, Member::File(b"2")),
            ],
        );
        assert!(review(&path).is_err());
        tar(
            &path,
            &[
                ("rootfs/a", 0o644, Member::File(b"1")),
                ("rootfs/a/b", 0o644, Member::File(b"2")),
            ],
        );
        assert!(review(&path).is_err());
    }

    #[test]
    fn existing_overlay_directories_keep_their_owner_and_mode() {
        let scratch = Scratch::new();
        let path = scratch.0.join("o.tar");
        host(&path, b"host");
        let overlay = review(&path).unwrap();
        let outside = scratch.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("host.conf"), b"untouched").unwrap();

        // etc in the BE is a symlink out of it: refused, nothing written.
        let escaped = scratch.0.join("escaped");
        fs::create_dir(&escaped).unwrap();
        symlink(&outside, escaped.join("etc")).unwrap();
        assert!(apply(&escaped, &overlay).is_err());
        assert_eq!(fs::read(outside.join("host.conf")).unwrap(), b"untouched");

        // A leaf symlink is replaced, not written through; etc keeps its mode.
        let root = scratch.0.join("root");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::set_permissions(root.join("etc"), fs::Permissions::from_mode(0o711)).unwrap();
        symlink(outside.join("host.conf"), root.join("etc/host.conf")).unwrap();
        apply(&root, &overlay).unwrap();
        assert_eq!(fs::read(outside.join("host.conf")).unwrap(), b"untouched");
        let meta = fs::symlink_metadata(root.join("etc/host.conf")).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!((meta.uid(), meta.gid()), ids());
        assert_eq!(fs::read(root.join("etc/host.conf")).unwrap(), b"host");
        assert_eq!(
            fs::read_link(root.join("etc/link")).unwrap(),
            Path::new("host.conf")
        );
        assert_eq!(
            fs::metadata(root.join("etc")).unwrap().mode() & 0o7777,
            0o711
        );
        assert_eq!(hook_bytes(&overlay).unwrap(), b"#!/bin/sh\n");

        // A file where the overlay puts a directory is refused.
        let clash = scratch.0.join("clash");
        fs::create_dir(&clash).unwrap();
        fs::write(clash.join("etc"), b"file").unwrap();
        assert!(apply(&clash, &overlay).is_err());
    }

    #[test]
    fn an_overlay_changed_after_review_is_refused_at_apply() {
        let scratch = Scratch::new();
        let path = scratch.0.join("o.tar");
        host(&path, b"host");
        let overlay = review(&path).unwrap();
        host(&path, b"evil");
        let root = scratch.0.join("root");
        fs::create_dir(&root).unwrap();
        assert!(apply(&root, &overlay).is_err());
        assert!(!root.join("etc/host.conf").exists());
        assert!(hook_bytes(&overlay).is_ok());
        assert_ne!(again(&overlay).unwrap(), overlay);
    }
}
