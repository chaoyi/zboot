//! Deterministic content evidence for a caller-owned immutable snapshot view.
//!
//! The digest covers raw relative names, types, mode/uid/gid/mtime, hardlink
//! equivalence, every visible native xattr (including ACLs/capabilities), file
//! bytes, symlink targets and special-node device numbers. It excludes local
//! inode numbers, atime/ctime, allocation, compression and encryption layout.
//! Ctime and local identities are nevertheless checked for traversal drift.
//!
//! Callers must bind the native snapshot, hold and read-only mount throughout.
//! CAP_SYS_ADMIN is mandatory because Linux silently hides trusted.* xattrs
//! without it. Unreadable or unsupported xattr enumeration is an error.
//! Initial Linux user-namespace membership is also required: capabilities in
//! a nested namespace do not establish visibility of trusted.* attributes.
//! No path is omitted by name: an exposed .zfs control tree is never silently
//! skipped. Automount nodes and every mount-ID transition are refused. Present
//! an actual snapshot root, not a live filesystem's .zfs control namespace.
use rustix::{
    fd::{AsRawFd, OwnedFd},
    fs::{self, AtFlags, Mode, OFlags, ResolveFlags, Statx, StatxFlags},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::File,
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const ENTRY_LIMIT: u64 = 1_000_000;
const NAME_BYTES_LIMIT: u64 = 64 * 1024 * 1024;
const DEPTH_LIMIT: usize = 512;
const XATTR_LIMIT: usize = 64 * 1024;
const BLOCK_SIZE: usize = 1024 * 1024;
const CAP_SYS_ADMIN: u64 = 1 << 21;
// Linux USER_NS_INIT_INO / PROC_USER_INIT_INO (include/uapi/linux/nsfs.h and
// include/linux/proc_ns.h). Fail closed if this reserved identity is absent.
const INITIAL_USER_NAMESPACE_INODE: u64 = 4_026_531_837;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentProof {
    pub schema_version: u32,
    pub algorithm: String,
    pub sha256: String,
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub special_nodes: u64,
    pub logical_bytes: u64,
    pub xattrs: u64,
}
impl ContentProof {
    pub fn validate(&self) -> io::Result<()> {
        if self.schema_version != 1
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(refuse("unsupported or malformed content proof"));
        }
        match self.algorithm.as_str() {
            "sha256-zboot-filesystem-v1" => {
                let total = self
                    .files
                    .checked_add(self.directories)
                    .and_then(|v| v.checked_add(self.symlinks))
                    .and_then(|v| v.checked_add(self.special_nodes));
                if total != Some(self.entries)
                    || self.directories == 0
                    || self.entries > ENTRY_LIMIT
                {
                    return Err(refuse("inconsistent filesystem proof counts"));
                }
            }
            _ => return Err(refuse("unsupported content proof algorithm")),
        }
        Ok(())
    }
    fn empty(algorithm: &str) -> Self {
        Self {
            schema_version: 1,
            algorithm: algorithm.into(),
            sha256: String::new(),
            entries: 0,
            files: 0,
            directories: 0,
            symlinks: 0,
            special_nodes: 0,
            logical_bytes: 0,
            xattrs: 0,
        }
    }
}
fn refuse(message: &str) -> io::Error {
    io::Error::other(message)
}
fn visibility() -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if std::fs::metadata("/proc/self/ns/user")?.ino() != INITIAL_USER_NAMESPACE_INODE {
        return Err(refuse(
            "complete xattr proof requires the initial Linux user namespace",
        ));
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    let values: Vec<_> = status
        .lines()
        .filter_map(|l| l.strip_prefix("CapEff:\t"))
        .collect();
    if values.len() != 1
        || u64::from_str_radix(values[0], 16)
            .map_err(|_| refuse("invalid capability observation"))?
            & CAP_SYS_ADMIN
            == 0
    {
        return Err(refuse(
            "complete xattr proof requires effective CAP_SYS_ADMIN",
        ));
    }
    Ok(())
}
/// Hash one complete, externally bound read-only filesystem snapshot root.
/// Memory is bounded by fixed file/xattr buffers, one million entries, 64 MiB
/// of aggregate entry names and a maximum depth of 512. Limit breaches refuse.
pub fn filesystem(root: &Path) -> io::Result<ContentProof> {
    visibility()?;
    let result = filesystem_with(root, &mut || Ok(()))?;
    visibility()?;
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stable {
    dev: (u32, u32),
    mount: u64,
    ino: u64,
    mode: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    mtime: (i64, u32),
    ctime: (i64, u32),
    rdev: (u32, u32),
    attributes: u64,
}
fn stable(s: Statx) -> io::Result<Stable> {
    let required = StatxFlags::TYPE
        | StatxFlags::MODE
        | StatxFlags::UID
        | StatxFlags::GID
        | StatxFlags::NLINK
        | StatxFlags::MTIME
        | StatxFlags::CTIME
        | StatxFlags::INO
        | StatxFlags::SIZE
        | StatxFlags::MNT_ID;
    if s.stx_mask & required.bits() != required.bits()
        || s.stx_mnt_id == 0
        || s.stx_ino == 0
        || s.stx_mtime.tv_nsec >= 1_000_000_000
        || s.stx_ctime.tv_nsec >= 1_000_000_000
    {
        return Err(refuse(
            "complete statx identity/metadata/mount-ID evidence unavailable",
        ));
    }
    if s.stx_attributes.contains(fs::StatxAttributes::AUTOMOUNT) {
        return Err(refuse("content traversal refuses an automount node"));
    }
    Ok(Stable {
        dev: (s.stx_dev_major, s.stx_dev_minor),
        mount: s.stx_mnt_id,
        ino: s.stx_ino,
        mode: s.stx_mode,
        uid: s.stx_uid,
        gid: s.stx_gid,
        nlink: s.stx_nlink,
        size: s.stx_size,
        mtime: (s.stx_mtime.tv_sec, s.stx_mtime.tv_nsec),
        ctime: (s.stx_ctime.tv_sec, s.stx_ctime.tv_nsec),
        rdev: (s.stx_rdev_major, s.stx_rdev_minor),
        attributes: s.stx_attributes.bits(),
    })
}
fn stat(fd: &impl std::os::fd::AsFd) -> io::Result<Stable> {
    stable(fs::statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )?)
}
fn stat_at(fd: &impl std::os::fd::AsFd, name: &CStr) -> io::Result<Stable> {
    stable(fs::statx(
        fd,
        name,
        AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )?)
}
fn same(before: &Stable, after: &Stable) -> io::Result<()> {
    if before != after {
        return Err(refuse("content identity or metadata changed during proof"));
    }
    Ok(())
}
fn field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}
fn metadata(hash: &mut Sha256, s: &Stable) {
    hash.update(s.mode.to_be_bytes());
    hash.update(s.uid.to_be_bytes());
    hash.update(s.gid.to_be_bytes());
    hash.update(s.mtime.0.to_be_bytes());
    hash.update(s.mtime.1.to_be_bytes());
}
fn add(value: &mut u64, amount: u64) -> io::Result<()> {
    *value = value
        .checked_add(amount)
        .ok_or_else(|| refuse("content proof count overflow"))?;
    Ok(())
}
fn names(fd: &OwnedFd) -> io::Result<Vec<CString>> {
    let mut entries = Vec::new();
    let mut bytes = 0u64;
    for entry in fs::Dir::read_from(fd)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if name.to_bytes().is_empty() || name.to_bytes().contains(&b'/') {
            return Err(refuse("invalid native directory name"));
        }
        add(&mut bytes, name.to_bytes().len() as u64)?;
        if bytes > NAME_BYTES_LIMIT || entries.len() >= ENTRY_LIMIT as usize {
            return Err(refuse("directory enumeration exceeds proof limits"));
        }
        entries.push(name.to_owned());
    }
    entries.sort_by(|a, b| a.to_bytes().cmp(b.to_bytes()));
    if entries.windows(2).any(|n| n[0] == n[1]) {
        return Err(refuse("duplicate native directory entry"));
    }
    Ok(entries)
}
fn parse_xattrs(bytes: &[u8]) -> io::Result<Vec<CString>> {
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err(refuse("malformed native xattr list"));
    }
    let mut result = Vec::new();
    if bytes.is_empty() {
        return Ok(result);
    }
    for name in bytes[..bytes.len() - 1].split(|b| *b == 0) {
        if name.is_empty() {
            return Err(refuse("empty native xattr name"));
        }
        result.push(CString::new(name).map_err(|_| refuse("invalid native xattr name"))?);
    }
    result.sort_by(|a, b| a.to_bytes().cmp(b.to_bytes()));
    if result.windows(2).any(|n| n[0] == n[1]) {
        return Err(refuse("duplicate native xattr name"));
    }
    Ok(result)
}
enum Attributes<'a> {
    Fd(&'a OwnedFd),
    Link(PathBuf),
}
impl Attributes<'_> {
    fn list(&self) -> io::Result<Vec<CString>> {
        let mut bytes = vec![0; XATTR_LIMIT];
        let len = match self {
            Self::Fd(fd) => fs::flistxattr(fd, &mut bytes[..])?,
            Self::Link(path) => fs::llistxattr(path, &mut bytes[..])?,
        };
        parse_xattrs(&bytes[..len])
    }
    fn value(&self, name: &CStr) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0; XATTR_LIMIT];
        let len = match self {
            Self::Fd(fd) => fs::fgetxattr(fd, name, &mut bytes[..])?,
            Self::Link(path) => fs::lgetxattr(path, name, &mut bytes[..])?,
        };
        bytes.truncate(len);
        Ok(bytes)
    }
    fn digest(&self) -> io::Result<(Vec<u8>, u64)> {
        let names = self.list()?;
        let mut hash = Sha256::new();
        hash.update(b"zboot-xattrs-v1\0");
        hash.update((names.len() as u64).to_be_bytes());
        for name in &names {
            field(&mut hash, name.to_bytes());
            field(&mut hash, &self.value(name)?);
        }
        if names != self.list()? {
            return Err(refuse("xattr membership changed during proof"));
        }
        Ok((hash.finalize().to_vec(), names.len() as u64))
    }
}
struct LinkGroup {
    first: [u8; 32],
    expected: u32,
    seen: u32,
    metadata: Stable,
}
// Progress is diagnostic only, never part of the proof or machine JSON output.
// Throttle updates and omit paths so traversal does not expose private names.
struct Progress {
    started: Instant,
    last: Instant,
    enabled: bool,
}
impl Progress {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            last: now,
            enabled: io::stderr().is_terminal(),
        }
    }
    fn report(&mut self, proof: &ContentProof, complete: bool) {
        if !self.enabled || (!complete && self.last.elapsed() < Duration::from_secs(5)) {
            return;
        }
        if complete && self.started.elapsed() < Duration::from_secs(1) {
            return;
        }
        eprintln!(
            "Verification{}: {} entries, {} MiB checked, {}s elapsed",
            if complete { " complete" } else { "" },
            proof.entries,
            proof.logical_bytes / (1024 * 1024),
            self.started.elapsed().as_secs()
        );
        self.last = Instant::now();
    }
}
struct Walker<'a> {
    hash: Sha256,
    proof: ContentProof,
    progress: Progress,
    mount: u64,
    dev: (u32, u32),
    names: u64,
    links: BTreeMap<u64, LinkGroup>,
    hook: &'a mut dyn FnMut() -> io::Result<()>,
}
impl Walker<'_> {
    fn node(
        &mut self,
        pin: &OwnedFd,
        parent: Option<(&OwnedFd, &CStr)>,
        relative: &[u8],
        depth: usize,
    ) -> io::Result<()> {
        if depth > DEPTH_LIMIT {
            return Err(refuse("content traversal depth limit exceeded"));
        }
        let before = stat(pin)?;
        if before.mount != self.mount || before.dev != self.dev {
            return Err(refuse("content traversal crossed a mount or filesystem"));
        }
        add(&mut self.proof.entries, 1)?;
        self.progress.report(&self.proof, false);
        if self.proof.entries > ENTRY_LIMIT {
            return Err(refuse("content entry count limit exceeded"));
        }
        field(&mut self.hash, b"entry");
        field(&mut self.hash, relative);
        metadata(&mut self.hash, &before);
        let kind = before.mode as u32 & libc::S_IFMT;
        let mut first = true;
        if kind != libc::S_IFDIR {
            if before.nlink == 0 {
                return Err(refuse("unlinked content entry cannot be certified"));
            }
            let group = self.links.entry(before.ino).or_insert_with(|| LinkGroup {
                first: Sha256::digest(relative).into(),
                expected: before.nlink,
                seen: 0,
                metadata: before.clone(),
            });
            same(&group.metadata, &before)?;
            if group.expected != before.nlink {
                return Err(refuse("hardlink count changed during proof"));
            }
            first = group.seen == 0;
            group.seen = group
                .seen
                .checked_add(1)
                .ok_or_else(|| refuse("hardlink count overflow"))?;
            self.hash.update(group.expected.to_be_bytes());
            self.hash.update(group.first);
        }
        let opened = if kind == libc::S_IFDIR {
            Some(crate::openat2_scoped(
                pin,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
            )?)
        } else if kind == libc::S_IFREG {
            // Reopen only an already-pinned, statx-verified regular inode.
            // The proc descriptor link is kernel-owned; no user symlink or
            // device node is opened through its mutable directory name.
            Some(fs::open(
                format!("/proc/self/fd/{}", pin.as_raw_fd()),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?)
        } else {
            None
        };
        if let Some(fd) = &opened {
            same(&before, &stat(fd)?)?;
        }
        let attributes = if let Some(fd) = &opened {
            Attributes::Fd(fd)
        } else {
            let (parent, name) =
                parent.ok_or_else(|| refuse("snapshot root is not a directory"))?;
            let mut path = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
            use std::os::unix::ffi::OsStrExt;
            path.push(std::ffi::OsStr::from_bytes(name.to_bytes()));
            Attributes::Link(path)
        };
        let attrs_before = attributes.digest()?;
        field(&mut self.hash, &attrs_before.0);
        add(&mut self.proof.xattrs, attrs_before.1)?;
        match kind {
            libc::S_IFDIR => {
                add(&mut self.proof.directories, 1)?;
                let fd = opened.as_ref().unwrap();
                let children = names(fd)?;
                self.hash.update((children.len() as u64).to_be_bytes());
                for name in &children {
                    add(&mut self.names, name.to_bytes().len() as u64)?;
                    if self.names > NAME_BYTES_LIMIT {
                        return Err(refuse("aggregate content names exceed proof limits"));
                    }
                    let child_before = stat_at(fd, name)?;
                    if child_before.mount != self.mount || child_before.dev != self.dev {
                        return Err(refuse("content traversal crossed a mount or filesystem"));
                    }
                    let child = crate::openat2_scoped(
                        fd,
                        name.as_c_str(),
                        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                        ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
                    )?;
                    same(&child_before, &stat(&child)?)?;
                    let mut path = relative.to_vec();
                    if !path.is_empty() {
                        path.push(b'/');
                    }
                    path.extend_from_slice(name.to_bytes());
                    self.node(&child, Some((fd, name)), &path, depth + 1)?;
                    same(&child_before, &stat_at(fd, name)?)?;
                }
                if children != names(fd)? {
                    return Err(refuse("directory membership changed during proof"));
                }
            }
            libc::S_IFREG => {
                add(&mut self.proof.files, 1)?;
                self.hash.update(before.size.to_be_bytes());
                self.hash.update([u8::from(first)]);
                if first {
                    let fd = opened.as_ref().unwrap();
                    let mut file = File::from(fd.try_clone()?);
                    let proof = &mut self.proof;
                    let progress = &mut self.progress;
                    read_exact_digest_with(&mut file, before.size, &mut self.hash, &mut |bytes| {
                        add(&mut proof.logical_bytes, bytes)?;
                        progress.report(proof, false);
                        Ok(())
                    })?;
                }
                (self.hook)()?;
            }
            libc::S_IFLNK => {
                add(&mut self.proof.symlinks, 1)?;
                let mut bytes = vec![0; XATTR_LIMIT];
                let n = fs::readlinkat_raw(pin, "", &mut bytes[..])?;
                if n == bytes.len() || n as u64 != before.size {
                    return Err(refuse("symlink target length is incomplete or changed"));
                }
                field(&mut self.hash, &bytes[..n]);
            }
            libc::S_IFBLK | libc::S_IFCHR | libc::S_IFIFO | libc::S_IFSOCK => {
                add(&mut self.proof.special_nodes, 1)?;
                self.hash.update(before.rdev.0.to_be_bytes());
                self.hash.update(before.rdev.1.to_be_bytes());
            }
            _ => return Err(refuse("unsupported native file type")),
        }
        if attrs_before != attributes.digest()? {
            return Err(refuse("xattr values changed during proof"));
        }
        same(&before, &stat(pin)?)?;
        if let Some(fd) = &opened {
            same(&before, &stat(fd)?)?;
        }
        Ok(())
    }
}
fn filesystem_with(
    root: &Path,
    hook: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<ContentProof> {
    let root_fd = fs::openat2(
        fs::CWD,
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    let before = stat(&root_fd)?;
    let mut walker = Walker {
        hash: Sha256::new(),
        proof: ContentProof::empty("sha256-zboot-filesystem-v1"),
        progress: Progress::new(),
        mount: before.mount,
        dev: before.dev,
        names: 0,
        links: BTreeMap::new(),
        hook,
    };
    walker.hash.update(b"zboot-filesystem-v1\0");
    walker.node(&root_fd, None, b"", 0)?;
    if walker.links.values().any(|g| g.expected != g.seen) {
        return Err(refuse("hardlinks escape the complete snapshot root"));
    }
    same(&before, &stat(&root_fd)?)?;
    same(
        &before,
        &stable(fs::statx(
            fs::CWD,
            root,
            AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
            StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
        )?)?,
    )?;
    walker.proof.sha256 = format!("{:x}", walker.hash.finalize());
    walker.progress.report(&walker.proof, true);
    Ok(walker.proof)
}
fn read_exact_digest_with(
    file: &mut impl Read,
    length: u64,
    hash: &mut Sha256,
    progress: &mut dyn FnMut(u64) -> io::Result<()>,
) -> io::Result<()> {
    let mut remaining = length;
    let mut bytes = vec![0; BLOCK_SIZE];
    while remaining > 0 {
        let n = file.read(&mut bytes[..remaining.min(BLOCK_SIZE as u64) as usize])?;
        if n == 0 {
            return Err(refuse("content reader ended before the bound byte count"));
        }
        hash.update(&bytes[..n]);
        remaining -= n as u64;
        progress(n as u64)?;
    }
    if file.read(&mut bytes[..1])? != 0 {
        return Err(refuse("content reader exceeds the bound byte count"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{
            ffi::OsStrExt,
            fs::{PermissionsExt, symlink},
        },
        time::{Duration, UNIX_EPOCH},
    };
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("content-proof-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
        fn tree(&self, name: &str) -> PathBuf {
            let p = self.0.join(name);
            std::fs::create_dir(&p).unwrap();
            p
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn stamp(path: &Path) {
        let t = fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: 100,
                tv_nsec: 123,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: 100,
                tv_nsec: 123,
            },
        };
        fs::utimensat(fs::CWD, path, &t, AtFlags::SYMLINK_NOFOLLOW).unwrap();
    }
    fn freeze(root: &Path) {
        for entry in std::fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                freeze(&path);
            }
            stamp(&path);
        }
        stamp(root);
    }
    fn proof(root: &Path) -> ContentProof {
        filesystem_with(root, &mut || Ok(())).unwrap()
    }
    fn populate(root: &Path, reverse: bool) {
        let files = if reverse { ["z", "a"] } else { ["a", "z"] };
        for name in files {
            std::fs::write(root.join(name), format!("bytes-{name}")).unwrap();
        }
        std::fs::create_dir(root.join("dir")).unwrap();
        std::fs::write(root.join("dir/data"), b"nested").unwrap();
        let nonutf = std::ffi::OsStr::from_bytes(b"raw-\xff");
        std::fs::write(root.join(nonutf), b"raw-name").unwrap();
        symlink(
            std::ffi::OsStr::from_bytes(b"missing-\xfe"),
            root.join("link"),
        )
        .unwrap();
        std::fs::hard_link(root.join("a"), root.join("hardlink")).unwrap();
        fs::setxattr(
            root.join("z"),
            "user.proof",
            b"xattr\0bytes",
            fs::XattrFlags::empty(),
        )
        .unwrap();
        freeze(root);
    }
    #[test]
    fn deterministic_tree_ignores_inode_numbers_and_creation_order_but_preserves_raw_names() {
        let s = Scratch::new();
        let a = s.tree("a");
        let b = s.tree("b");
        populate(&a, false);
        populate(&b, true);
        let first = proof(&a);
        assert_eq!(first, proof(&b));
        assert_eq!(first, proof(&a));
        assert_eq!(first.files, 5);
        assert_eq!(first.symlinks, 1);
        assert_eq!(first.directories, 2);
        let serialized = serde_json::to_string(&first).unwrap();
        assert!(!serialized.contains("bytes-a"));
        assert!(!serialized.contains("raw-"));
        assert_eq!(first.sha256.len(), 64);
    }
    #[test]
    fn file_bytes_deletion_mode_mtime_xattrs_and_symlink_targets_change_digest() {
        for case in 0..6 {
            let s = Scratch::new();
            let root = s.tree("tree");
            populate(&root, false);
            let before = proof(&root);
            match case {
                0 => {
                    std::fs::write(root.join("z"), b"changed").unwrap();
                    freeze(&root);
                }
                1 => {
                    std::fs::remove_file(root.join("z")).unwrap();
                    freeze(&root);
                }
                2 => {
                    std::fs::set_permissions(root.join("z"), std::fs::Permissions::from_mode(0o600))
                        .unwrap()
                }
                3 => {
                    File::open(root.join("z"))
                        .unwrap()
                        .set_times(
                            std::fs::FileTimes::new()
                                .set_modified(UNIX_EPOCH + Duration::from_secs(101)),
                        )
                        .unwrap();
                }
                4 => fs::setxattr(
                    root.join("z"),
                    "user.proof",
                    b"other",
                    fs::XattrFlags::empty(),
                )
                .unwrap(),
                _ => {
                    std::fs::remove_file(root.join("link")).unwrap();
                    symlink("different-target", root.join("link")).unwrap();
                    freeze(&root);
                }
            }
            assert_ne!(before.sha256, proof(&root).sha256, "case {case}");
        }
    }
    #[test]
    fn hardlink_equivalence_differs_from_independent_duplicate_files() {
        let s = Scratch::new();
        let a = s.tree("a");
        let b = s.tree("b");
        for root in [&a, &b] {
            std::fs::write(root.join("one"), b"same").unwrap();
        }
        std::fs::hard_link(a.join("one"), a.join("two")).unwrap();
        std::fs::write(b.join("two"), b"same").unwrap();
        freeze(&a);
        freeze(&b);
        assert_ne!(proof(&a).sha256, proof(&b).sha256);
        assert_eq!(proof(&a).logical_bytes, 4);
        assert_eq!(proof(&b).logical_bytes, 8);
    }
    #[test]
    fn external_hardlink_and_unreadable_attribute_contract_fail_closed() {
        let s = Scratch::new();
        let root = s.tree("tree");
        std::fs::write(root.join("a"), b"data").unwrap();
        std::fs::hard_link(root.join("a"), s.0.join("outside")).unwrap();
        assert!(
            filesystem_with(&root, &mut || Ok(()))
                .unwrap_err()
                .to_string()
                .contains("hardlinks escape")
        );
        if visibility().is_err() {
            assert!(
                filesystem(&root)
                    .unwrap_err()
                    .to_string()
                    .contains("CAP_SYS_ADMIN")
            );
        }
        assert!(parse_xattrs(b"not-terminated").is_err());
        assert!(parse_xattrs(b"user.a\0user.a\0").is_err());
        assert!(parse_xattrs(b"\0").is_err());
    }
    #[test]
    fn symlinks_are_hashed_without_following_and_real_dot_zfs_names_are_not_hidden() {
        let s = Scratch::new();
        let root = s.tree("tree");
        symlink("/dev/zero", root.join("device-link")).unwrap();
        std::fs::create_dir(root.join(".zfs")).unwrap();
        std::fs::write(root.join(".zfs/real-file"), b"one").unwrap();
        freeze(&root);
        let before = proof(&root);
        assert_eq!(before.logical_bytes, 3);
        std::fs::write(root.join(".zfs/real-file"), b"two").unwrap();
        freeze(&root);
        assert_ne!(before.sha256, proof(&root).sha256);
        let alias = s.0.join("alias");
        symlink(&root, &alias).unwrap();
        assert!(filesystem_with(&alias, &mut || Ok(())).is_err());
    }
    #[test]
    fn metadata_xattr_and_directory_drift_during_read_is_rejected() {
        for case in 0..3 {
            let s = Scratch::new();
            let root = s.tree("tree");
            populate(&root, false);
            let mut changed = false;
            let result = filesystem_with(&root, &mut || {
                if !changed {
                    changed = true;
                    match case {
                        0 => std::fs::write(root.join("a"), b"mutated")?,
                        1 => fs::setxattr(
                            root.join("a"),
                            "user.midread",
                            b"changed",
                            fs::XattrFlags::empty(),
                        )?,
                        _ => {
                            std::fs::write(root.join("late-entry"), b"late")?;
                        }
                    }
                }
                Ok(())
            });
            assert!(result.is_err(), "case {case}");
        }
    }
    #[test]
    fn file_content_is_streamed_and_exact_byte_counts_are_enforced() {
        let bytes = vec![19u8; BLOCK_SIZE * 3 + 17];
        let mut h = Sha256::new();
        read_exact_digest_with(
            &mut io::Cursor::new(&bytes),
            bytes.len() as u64,
            &mut h,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(h.finalize()[..], Sha256::digest(&bytes)[..]);
        for n in [bytes.len() - 1, bytes.len() + 1] {
            assert!(
                read_exact_digest_with(
                    &mut io::Cursor::new(&bytes),
                    n as u64,
                    &mut Sha256::new(),
                    &mut |_| Ok(())
                )
                .is_err()
            );
        }
    }
    #[test]
    fn metadata_identity_detects_mount_id_and_timestamp_drift() {
        let s = Scratch::new();
        let root = s.tree("tree");
        let fd = fs::open(&root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let original = stat(&fd).unwrap();
        for which in 0..4 {
            let mut changed = original.clone();
            match which {
                0 => changed.mount += 1,
                1 => changed.ino += 1,
                2 => changed.ctime.0 += 1,
                _ => changed.uid += 1,
            }
            assert!(same(&original, &changed).is_err());
        }
    }
}
