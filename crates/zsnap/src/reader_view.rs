//! Private, exact-snapshot mounts on a per-job tmpfs for a supervised reader.
//!
//! The caller owns a short writer session (including native writer custody),
//! snapshot protection, and the reader cgroup. It must prove that every reader
//! has died before calling `cleanup`, and retain protection when cleanup fails.
//! This module never starts readers or selects snapshots. Dropping a view does
//! not unmount anything or establish that its readers have died.
//! Only the empty mount anchor exists on the shared physical filesystem. It is
//! preserved so concurrent namespaces can independently use the same root path.
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};
use std::{
    cell::Cell,
    fmt,
    fs::{self, File},
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
use zfs_tools::engine::{
    SnapshotRef,
    mountinfo::{self, Mount},
    native,
};

fn refuse(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}

thread_local! {
    // Namespace identity, rather than a boolean, prevents accidental use after
    // the caller changes namespaces again on this thread.
    static PRIVATE_NAMESPACE: Cell<Option<u64>> = const { Cell::new(None) };
}

fn namespace_id() -> io::Result<u64> {
    Ok(fs::metadata("/proc/thread-self/ns/mnt")?.ino())
}

fn require_root_mount_capability(
    status: &str,
    user_namespace: (u64, u64),
    machine_user_namespace: (u64, u64),
) -> io::Result<()> {
    const CAP_SYS_ADMIN: u64 = 1 << 21;
    let field = |name: &str| -> io::Result<&str> {
        let mut values = status.lines().filter_map(|line| line.strip_prefix(name));
        let value = values
            .next()
            .ok_or_else(|| refuse("missing reader privilege evidence"))?;
        if values.next().is_some() {
            return Err(refuse("ambiguous reader privilege evidence"));
        }
        Ok(value.trim())
    };
    let ids: Vec<_> = field("Uid:")?.split_whitespace().collect();
    let cap = u64::from_str_radix(field("CapEff:")?, 16)
        .map_err(|_| refuse("invalid reader capability evidence"))?;
    if ids.len() != 4
        || ids[1] != "0"
        || cap & CAP_SYS_ADMIN == 0
        || user_namespace != machine_user_namespace
    {
        return Err(refuse(
            "snapshot views require root with CAP_SYS_ADMIN in the admitted machine's user namespace",
        ));
    }
    Ok(())
}

/// Isolate this thread before making any view directories or mounting sources.
/// Privilege checks precede the first effect; unsupported environments refuse.
/// Keep all subsequent view operations on this same thread.
/// The caller must first establish machine context, including that PID 1 is
/// the admitted machine's init process rather than a container init.
pub(crate) fn enter_private_namespace() -> io::Result<()> {
    let current_user_namespace = fs::metadata("/proc/thread-self/ns/user")?;
    let machine_user_namespace = fs::metadata("/proc/1/ns/user")?;
    require_root_mount_capability(
        &fs::read_to_string("/proc/thread-self/status")?,
        (current_user_namespace.dev(), current_user_namespace.ino()),
        (machine_user_namespace.dev(), machine_user_namespace.ino()),
    )?;
    use nix::{
        mount::{MsFlags, mount},
        sched::{CloneFlags, unshare},
    };
    unshare(CloneFlags::CLONE_FS | CloneFlags::CLONE_NEWNS)
        .map_err(|error| refuse(format!("reader mount namespace isolation failed: {error}")))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|error| {
        refuse(format!(
            "reader mount propagation isolation failed: {error}"
        ))
    })?;
    let namespace = namespace_id()?;
    PRIVATE_NAMESPACE.with(|slot| slot.set(Some(namespace)));
    Ok(())
}

fn require_private_namespace() -> io::Result<()> {
    if PRIVATE_NAMESPACE.with(|slot| slot.get()) != Some(namespace_id()?) {
        return Err(refuse(
            "snapshot view requires this thread's isolated private namespace",
        ));
    }
    Ok(())
}

/// An exact protected point and its location within the view. `relative_path`
/// is validated metadata for the caller; it is never interpolated into argv.
#[derive(Debug, Clone)]
pub(crate) struct ViewSource {
    pub snapshot: SnapshotRef,
    pub alias: PathBuf,
    pub relative_path: Option<PathBuf>,
}

fn relative_components(path: &Path) -> io::Result<Vec<&str>> {
    let value = path
        .to_str()
        .ok_or_else(|| refuse("view paths must be UTF-8"))?;
    let parts: Vec<_> = value.split('/').collect();
    if parts.iter().any(|part| {
        part.is_empty() || matches!(*part, "." | "..") || part.chars().any(char::is_control)
    }) {
        return Err(refuse(
            "view aliases and relative paths must contain only ordinary relative components",
        ));
    }
    Ok(parts)
}

fn validate_root(root: &Path) -> io::Result<()> {
    let value = root
        .to_str()
        .ok_or_else(|| refuse("view root must be UTF-8"))?;
    let Some(relative) = value.strip_prefix("/run/") else {
        return Err(refuse("view root must be an absolute directory below /run"));
    };
    relative_components(Path::new(relative))?;
    Ok(())
}

fn validate_aliases<'a>(aliases: impl IntoIterator<Item = &'a Path>) -> io::Result<()> {
    let mut accepted = Vec::<&Path>::new();
    for alias in aliases {
        relative_components(alias)?;
        if accepted
            .iter()
            .any(|other| alias.starts_with(other) || other.starts_with(alias))
        {
            return Err(refuse("view aliases overlap or duplicate a mount prefix"));
        }
        accepted.push(alias);
    }
    if accepted.is_empty() {
        return Err(refuse("snapshot view requires at least one alias"));
    }
    Ok(())
}

/// Check the complete layout before capture or protection effects. This is
/// purely lexical: neither the root nor its ancestors need to exist yet.
pub(crate) fn validate_layout(root: &Path, aliases: &[PathBuf]) -> io::Result<()> {
    validate_root(root)?;
    validate_aliases(aliases.iter().map(PathBuf::as_path))
}

fn validate_sources(sources: &[ViewSource]) -> io::Result<()> {
    validate_aliases(sources.iter().map(|source| source.alias.as_path()))?;
    for source in sources {
        zfs_tools::engine::validate_snapshot_name(&source.snapshot.name).map_err(refuse)?;
        if let Some(relative) = &source.relative_path {
            relative_components(relative)?;
        }
    }
    Ok(())
}

fn open_directory(parent: &File, relative: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::openat2(
        parent,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}

fn trusted_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(refuse(
            "view ancestor or directory is not root-owned and protected",
        ));
    }
    Ok(())
}

fn open_trusted_parent(root: &Path) -> io::Result<(File, PathBuf)> {
    validate_root(root)?;
    let mut directory = File::open("/")?;
    trusted_directory(&directory)?;
    let parent = root.parent().ok_or_else(|| refuse("missing view parent"))?;
    for component in parent.strip_prefix("/").map_err(refuse)?.components() {
        directory = open_directory(&directory, Path::new(component.as_os_str()))?;
        trusted_directory(&directory)?;
    }
    let name = root
        .file_name()
        .ok_or_else(|| refuse("missing view directory name"))?;
    Ok((directory, PathBuf::from(name)))
}

fn directory_empty(directory: &File) -> io::Result<bool> {
    // This controlled proc link is only used to enumerate the already opened
    // directory; filesystem writes always use held directory descriptors.
    Ok(
        fs::read_dir(format!("/proc/thread-self/fd/{}", directory.as_raw_fd()))?
            .next()
            .is_none(),
    )
}

#[derive(Debug)]
struct CreatedDirectory {
    relative: PathBuf,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct TrackedMount {
    target: PathBuf,
    snapshot: SnapshotRef,
    mount_id: Option<u64>,
}

#[derive(Debug)]
struct TrackedRootMount {
    mount_id: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct SnapshotView {
    root: PathBuf,
    parent: File,
    root_name: PathBuf,
    anchor_fd: File,
    root_fd: File,
    root_mount: Option<TrackedRootMount>,
    directories: Vec<CreatedDirectory>,
    mounts: Vec<TrackedMount>,
    sources: Vec<ViewSource>,
}

/// A partial view remains available even when a mount or its proof failed.
/// Recover it with `take_view`; retain snapshot protection until cleanup is
/// acknowledged. No destructor silently detaches mounts.
#[derive(Debug)]
pub(crate) struct MountFailure {
    pub error: io::Error,
    view: Option<Box<SnapshotView>>,
}
impl MountFailure {
    pub(crate) fn take_view(&mut self) -> Option<SnapshotView> {
        self.view.take().map(|view| *view)
    }
}
impl fmt::Display for MountFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}
impl std::error::Error for MountFailure {}
impl From<io::Error> for MountFailure {
    fn from(error: io::Error) -> Self {
        Self { error, view: None }
    }
}

impl SnapshotView {
    /// Requires caller-owned native writer custody and snapshot protection.
    /// `revalidate` must freshly prove the complete protected manifest before
    /// each effect. Native point identity and exact source spelling are also
    /// checked immediately before and after every mount.
    pub(crate) fn mount(
        root: &Path,
        sources: &[ViewSource],
        mut revalidate: impl FnMut() -> io::Result<()>,
    ) -> Result<Self, MountFailure> {
        validate_root(root)?;
        require_private_namespace()?;
        validate_sources(sources)?;
        let (parent, root_name) = open_trusted_parent(root)?;
        reject_mounts_below(&read_mounts()?, root, &[], None)?;
        let anchor_fd = match open_directory(&parent, &root_name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                revalidate()?;
                match rustix::fs::mkdirat(&parent, &root_name, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(io::Error::from(error).into()),
                }
                open_directory(&parent, &root_name)?
            }
            Err(error) => return Err(error.into()),
        };
        let mut view = Self {
            root: root.into(),
            parent,
            root_name,
            root_fd: anchor_fd.try_clone()?,
            anchor_fd,
            root_mount: None,
            directories: Vec::new(),
            mounts: Vec::new(),
            sources: sources.to_vec(),
        };
        let result = (|| -> io::Result<()> {
            trusted_directory(&view.root_fd)?;
            if !directory_empty(&view.root_fd)? {
                return Err(refuse("snapshot view root must be new or empty"));
            }
            revalidate()?;
            view.verify_root()?;
            view.verify_layout()?;
            view.root_mount = Some(TrackedRootMount { mount_id: None });
            native::run_mutating(
                "mount",
                &[
                    "-t".into(),
                    "tmpfs".into(),
                    "-o".into(),
                    "mode=0755,nosuid,nodev,size=16m,nr_inodes=4096".into(),
                    "zsnap-reader".into(),
                    root.to_str()
                        .ok_or_else(|| refuse("non-UTF-8 root"))?
                        .into(),
                ],
            )
            .map_err(refuse)?;
            revalidate()?;
            view.adopt_root_mount(true)?;
            for source in sources {
                view.create_alias(&source.alias, &mut revalidate)?;
            }
            for source in sources {
                revalidate()?;
                view.verify_root()?;
                view.verify_layout()?;
                exact_snapshot(&source.snapshot)?;
                view.verify_unmounted_alias(&source.alias)?;
                let target = view.root.join(&source.alias);
                // Record before spawning: a helper may mount successfully and
                // then report failure or lose its output.
                view.mounts.push(TrackedMount {
                    target: target.clone(),
                    snapshot: source.snapshot.clone(),
                    mount_id: None,
                });
                native::run_mutating(
                    "mount",
                    &[
                        "-t".into(),
                        "zfs".into(),
                        "-o".into(),
                        "ro,nosuid,nodev".into(),
                        source.snapshot.name.clone(),
                        target
                            .to_str()
                            .ok_or_else(|| refuse("non-UTF-8 target"))?
                            .into(),
                    ],
                )
                .map_err(refuse)?;
                revalidate()?;
                exact_snapshot(&source.snapshot)?;
                let mount_id = prove_mount(&read_mounts()?, &target, &source.snapshot.name)?.id;
                prove_visible_mount(&target, mount_id)?;
                view.mounts.last_mut().expect("recorded mount").mount_id = Some(mount_id);
                view.verify_layout()?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(view),
            Err(error) => Err(MountFailure {
                error,
                view: Some(Box::new(view)),
            }),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn sources(&self) -> &[ViewSource] {
        &self.sources
    }
    pub(crate) fn has_mounts(&self) -> bool {
        self.root_mount.is_some() || !self.mounts.is_empty()
    }

    fn verify_parent(&self) -> io::Result<()> {
        let (parent, _) = open_trusted_parent(&self.root)?;
        let current_parent = parent.metadata()?;
        let held_parent = self.parent.metadata()?;
        if current_parent.dev() != held_parent.dev() || current_parent.ino() != held_parent.ino() {
            return Err(refuse("the private view ancestor was replaced"));
        }
        Ok(())
    }

    fn verify_root(&self) -> io::Result<()> {
        self.verify_parent()?;
        let current = open_directory(&self.parent, &self.root_name)?;
        let original = self.root_fd.metadata()?;
        let current = current.metadata()?;
        if current.dev() != original.dev() || current.ino() != original.ino() {
            return Err(refuse("the private view root was replaced"));
        }
        trusted_directory(&self.root_fd)
    }

    fn verify_layout(&self) -> io::Result<()> {
        let mounts = read_mounts()?;
        reject_mounts_below(&mounts, &self.root, &self.mounts, self.root_mount.as_ref())?;
        if let Some(root) = &self.root_mount {
            let mount = prove_root_mount(&mounts, &self.root)?;
            if root.mount_id.is_some_and(|id| id != mount.id) {
                return Err(refuse("private tmpfs mount identity changed"));
            }
        }
        Ok(())
    }

    // A helper can report failure after its mount effect. Recover only the
    // exact expected substrate, and retain tracking on every proof failure.
    fn adopt_root_mount(&mut self, required: bool) -> io::Result<()> {
        self.verify_parent()?;
        let mounts = read_mounts()?;
        if !mounts.iter().any(|mount| mount.mount_point == self.root) {
            if required || !self.mounts.is_empty() || !self.directories.is_empty() {
                return Err(refuse("private tmpfs substrate is absent"));
            }
            reject_mounts_below(&mounts, &self.root, &[], None)?;
            self.root_fd = self.anchor_fd.try_clone()?;
            self.verify_anchor()?;
            self.root_mount = None;
            return Ok(());
        }
        let tracked = self
            .root_mount
            .as_ref()
            .ok_or_else(|| refuse("untracked private root mount"))?;
        let mount = prove_root_mount(&mounts, &self.root)?;
        if tracked.mount_id.is_some_and(|id| id != mount.id) {
            return Err(refuse("private tmpfs substrate was replaced"));
        }
        prove_visible_mount(&self.root, mount.id)?;
        let directory = open_directory(&self.parent, &self.root_name)?;
        trusted_directory(&directory)?;
        if directory.metadata()?.mode() & 0o7777 != 0o755 {
            return Err(refuse("private tmpfs root mode is not 0755"));
        }
        self.root_fd = directory;
        self.root_mount.as_mut().expect("tracked root").mount_id = Some(mount.id);
        self.verify_root()?;
        self.verify_layout()
    }

    fn verify_anchor(&self) -> io::Result<()> {
        self.verify_parent()?;
        let current = open_directory(&self.parent, &self.root_name)?.metadata()?;
        let anchor = self.anchor_fd.metadata()?;
        if current.dev() != anchor.dev() || current.ino() != anchor.ino() {
            return Err(refuse("the original private view anchor was replaced"));
        }
        trusted_directory(&self.anchor_fd)
    }

    fn verify_unmounted_alias(&self, alias: &Path) -> io::Result<()> {
        let target = open_directory(&self.root_fd, alias)?;
        let metadata = target.metadata()?;
        let expected = self
            .directories
            .iter()
            .find(|directory| directory.relative == alias)
            .ok_or_else(|| refuse("private mount target was not created by this view"))?;
        if metadata.dev() != expected.device || metadata.ino() != expected.inode {
            return Err(refuse("private mount target was replaced"));
        }
        trusted_directory(&target)
    }

    fn create_alias(
        &mut self,
        alias: &Path,
        revalidate: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut relative = PathBuf::new();
        let mut parent = self.root_fd.try_clone()?;
        for component in relative_components(alias)? {
            relative.push(component);
            let directory = match open_directory(&parent, Path::new(component)) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    revalidate()?;
                    self.verify_root()?;
                    self.verify_layout()?;
                    rustix::fs::mkdirat(&parent, component, Mode::from_raw_mode(0o755))?;
                    let directory = open_directory(&parent, Path::new(component))?;
                    let metadata = directory.metadata()?;
                    self.directories.push(CreatedDirectory {
                        relative: relative.clone(),
                        device: metadata.dev(),
                        inode: metadata.ino(),
                    });
                    revalidate()?;
                    self.verify_root()?;
                    self.verify_layout()?;
                    rustix::fs::fchmod(&directory, Mode::from_raw_mode(0o755))?;
                    directory
                }
                Err(error) => return Err(error),
            };
            trusted_directory(&directory)?;
            parent = directory;
        }
        Ok(())
    }

    /// Only call after positively proving the entire reader cgroup empty.
    /// Failure retains mount tracking and leaves snapshot protection to the
    /// caller. Unmounts are explicit, synchronous, and never lazy or forced.
    pub(crate) fn cleanup(
        &mut self,
        mut revalidate: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        require_private_namespace()?;
        if self.root_mount.is_some() {
            self.adopt_root_mount(false)?;
        }
        self.verify_root()?;
        while let Some(tracked) = self.mounts.last() {
            let mounts = read_mounts()?;
            self.verify_layout()?;
            if !mounts
                .iter()
                .any(|mount| mount.mount_point == tracked.target)
            {
                // A failed helper may never have mounted. Absence is accepted
                // only when no hidden descendant mount remains either.
                if mounts
                    .iter()
                    .any(|mount| mount.mount_point.starts_with(&tracked.target))
                {
                    return Err(refuse("unexpected mount remains below private target"));
                }
                self.mounts.pop();
                continue;
            }
            let mount = prove_mount(&mounts, &tracked.target, &tracked.snapshot.name)?;
            if tracked.mount_id.is_some_and(|id| id != mount.id) {
                return Err(refuse("private view mount identity changed before cleanup"));
            }
            prove_visible_mount(&tracked.target, mount.id)?;
            revalidate()?;
            self.verify_root()?;
            native::run_mutating(
                "umount",
                &[
                    "--".into(),
                    tracked
                        .target
                        .to_str()
                        .ok_or_else(|| refuse("non-UTF-8 target"))?
                        .into(),
                ],
            )
            .map_err(refuse)?;
            if read_mounts()?
                .iter()
                .any(|mount| mount.mount_point.starts_with(&tracked.target))
            {
                return Err(refuse(
                    "private view unmount did not remove its exact mount",
                ));
            }
            self.mounts.pop();
        }
        while let Some(directory) = self.directories.last() {
            revalidate()?;
            self.verify_root()?;
            self.verify_layout()?;
            let opened = open_directory(&self.root_fd, &directory.relative)?;
            let metadata = opened.metadata()?;
            if metadata.dev() != directory.device || metadata.ino() != directory.inode {
                return Err(refuse("private view directory was replaced before cleanup"));
            }
            let parent_path = directory
                .relative
                .parent()
                .expect("relative directory parent");
            let parent = if parent_path.as_os_str().is_empty() {
                self.root_fd.try_clone()?
            } else {
                open_directory(&self.root_fd, parent_path)?
            };
            let name = directory
                .relative
                .file_name()
                .expect("relative directory name");
            rustix::fs::unlinkat(&parent, name, AtFlags::REMOVEDIR)?;
            self.directories.pop();
        }
        if self.root_mount.is_some() {
            revalidate()?;
            self.verify_root()?;
            self.verify_layout()?;
            let mounts = read_mounts()?;
            let mount = prove_root_mount(&mounts, &self.root)?;
            prove_visible_mount(&self.root, mount.id)?;
            if !directory_empty(&self.root_fd)? {
                return Err(refuse(
                    "private tmpfs substrate is not empty before cleanup",
                ));
            }
            // A directory fd into tmpfs would keep a normal umount busy.
            // Keep only the underlying anchor descriptor across the helper.
            self.root_fd = self.anchor_fd.try_clone()?;
            native::run_mutating(
                "umount",
                &[
                    "--".into(),
                    self.root
                        .to_str()
                        .ok_or_else(|| refuse("non-UTF-8 root"))?
                        .into(),
                ],
            )
            .map_err(refuse)?;
            reject_mounts_below(&read_mounts()?, &self.root, &[], None)?;
            self.verify_anchor()?;
            self.root_mount = None;
        }
        // The shared physical anchor is deliberately preserved, including
        // when this invocation created it. Other namespaces may be using it.
        Ok(())
    }
}

fn exact_snapshot(point: &SnapshotRef) -> io::Result<()> {
    let observed = native::resolve_with(point, &mut native::run).map_err(refuse)?;
    if observed.name != point.name {
        return Err(refuse(
            "protected snapshot was renamed; the view refuses a changed source spelling",
        ));
    }
    Ok(())
}

// Mount id 0 is not a mount the kernel reports; a view refuses it as evidence.
fn parse_mounts(text: &(impl AsRef<[u8]> + ?Sized)) -> io::Result<Vec<Mount>> {
    let mounts = mountinfo::table(text)?;
    if mounts.iter().any(|mount| mount.id == 0) {
        return Err(refuse("invalid private view mount identity"));
    }
    Ok(mounts)
}

fn read_mounts() -> io::Result<Vec<Mount>> {
    parse_mounts(&fs::read("/proc/thread-self/mountinfo")?)
}

fn prove_mount<'a>(mounts: &'a [Mount], target: &Path, snapshot: &str) -> io::Result<&'a Mount> {
    let mut matches = mounts.iter().filter(|mount| mount.mount_point == target);
    let mount = matches
        .next()
        .ok_or_else(|| refuse("private snapshot mount is absent"))?;
    if matches.next().is_some()
        || mount.root != Path::new("/")
        || mount.filesystem != "zfs"
        || mount.source != snapshot
        || !["ro", "nosuid", "nodev"]
            .iter()
            .all(|flag| mount.has_option(flag))
        || mount.has_option("rw")
        || mount.has_super_option("rw")
    {
        return Err(refuse(
            "private mount is not the unambiguous exact read-only ZFS snapshot",
        ));
    }
    Ok(mount)
}

fn bounded_tmpfs_size(option: &str) -> bool {
    let Some(size) = option.strip_prefix("size=") else {
        return false;
    };
    let (number, multiplier) = match size.as_bytes().last() {
        Some(b'k' | b'K') => (&size[..size.len() - 1], 1024u64),
        Some(b'm' | b'M') => (&size[..size.len() - 1], 1024u64 * 1024),
        Some(b'g' | b'G') => (&size[..size.len() - 1], 1024u64 * 1024 * 1024),
        _ => (size, 1),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .is_some_and(|bytes| bytes > 0 && bytes <= 16 * 1024 * 1024)
}

fn prove_root_mount<'a>(mounts: &'a [Mount], target: &Path) -> io::Result<&'a Mount> {
    let mut matches = mounts.iter().filter(|mount| mount.mount_point == target);
    let mount = matches
        .next()
        .ok_or_else(|| refuse("private tmpfs substrate is absent"))?;
    let sizes: Vec<_> = mount
        .super_options
        .split(',')
        .filter(|option| option.starts_with("size="))
        .collect();
    if matches.next().is_some()
        || mount.root != Path::new("/")
        || mount.filesystem != "tmpfs"
        || mount.source != "zsnap-reader"
        || !["rw", "nosuid", "nodev"]
            .iter()
            .all(|flag| mount.has_option(flag))
        || mount.has_option("ro")
        || mount.has_super_option("ro")
        || sizes.len() != 1
        || !bounded_tmpfs_size(sizes[0])
    {
        return Err(refuse(
            "private root is not the exact bounded tmpfs substrate",
        ));
    }
    Ok(mount)
}

fn prove_visible_mount(target: &Path, expected_id: u64) -> io::Result<()> {
    let root = File::open("/")?;
    let directory = open_directory(&root, target.strip_prefix("/").map_err(refuse)?)?;
    let information = fs::read_to_string(format!(
        "/proc/thread-self/fdinfo/{}",
        directory.as_raw_fd()
    ))?;
    let ids: Vec<_> = information
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:"))
        .map(|id| id.trim().parse::<u64>().map_err(refuse))
        .collect::<io::Result<_>>()?;
    if ids != [expected_id] {
        return Err(refuse(
            "the visible private mount does not match mountinfo evidence",
        ));
    }
    Ok(())
}

fn reject_mounts_below(
    mounts: &[Mount],
    root: &Path,
    tracked: &[TrackedMount],
    root_mount: Option<&TrackedRootMount>,
) -> io::Result<()> {
    for mount in mounts
        .iter()
        .filter(|mount| mount.mount_point.starts_with(root))
    {
        if mount.mount_point == root
            && root_mount.is_some_and(|tracked| tracked.mount_id.is_none_or(|id| id == mount.id))
        {
            continue;
        }
        if !tracked.iter().any(|known| {
            known.target == mount.mount_point && known.mount_id.is_none_or(|id| id == mount.id)
        }) {
            return Err(refuse(
                "unexpected or nested mount collides with the private view",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zfs_tools::engine::{Guid, ObjsetId, SnapshotIdentity, Txg};

    fn source(alias: &str) -> ViewSource {
        ViewSource {
            snapshot: SnapshotRef {
                name: "tank/data@snap".into(),
                dataset_guid: Guid::new(2),
                identity: SnapshotIdentity {
                    pool_guid: Guid::new(1),
                    guid: Guid::new(3),
                    createtxg: Txg::new(4),
                    objsetid: ObjsetId::new(5),
                },
            },
            alias: alias.into(),
            relative_path: None,
        }
    }
    #[test]
    fn paths_are_strictly_scoped_and_alias_mounts_cannot_overlap() {
        let root = Path::new("/run/not-created-yet/view");
        assert!(validate_layout(root, &["tank/data".into(), "tank/other".into()]).is_ok());
        assert!(validate_layout(root, &[]).is_err());
        assert!(validate_layout(root, &["tank".into(), "tank/data".into()]).is_err());
        assert!(validate_layout(root, &["tank".into(), "tank".into()]).is_err());
        assert!(validate_layout(Path::new("/tmp/view"), &["data".into()]).is_err());
        for root in [
            "/",
            "/run",
            "/run/",
            "/run/../etc",
            "/tmp/view",
            "/run/view/",
            "/run//view",
            "/run/./view",
            "/run/x\n",
        ] {
            assert!(validate_root(Path::new(root)).is_err(), "{root:?}");
        }
        assert!(validate_root(Path::new("/run/vm-backup/src")).is_ok());
        assert!(validate_sources(&[source("tank/data"), source("tank/other")]).is_ok());
        for alias in ["", "/x", "../x", "x/../y", "x/./y", "x//y", "x/", "x\t"] {
            assert!(validate_sources(&[source(alias)]).is_err(), "{alias:?}");
        }
        for aliases in [["a", "a"], ["a", "a/b"], ["a/b", "a"]] {
            assert!(validate_sources(&aliases.map(source)).is_err());
        }
        let mut relative = source("safe");
        relative.relative_path = Some("../escape".into());
        assert!(validate_sources(&[relative]).is_err());
    }
    #[test]
    fn exact_snapshot_mount_proof_rejects_wrong_sources_rw_and_stacks() {
        let row = "42 1 0:57 / /run/view/data ro,nosuid,nodev - zfs tank/data@snap ro,zfsutil\n";
        let target = Path::new("/run/view/data");
        assert_eq!(
            prove_mount(&parse_mounts(row).unwrap(), target, "tank/data@snap")
                .unwrap()
                .id,
            42
        );
        for wrong in [
            row.replace(" ro,nosuid", " rw,nosuid"),
            row.replace(" ro,zfsutil", " rw,zfsutil"),
            row.replace(" - zfs ", " - tmpfs "),
            row.replace("tank/data@snap", "tank/data@other"),
            row.replace("0:57 / ", "0:57 /subdir "),
            row.replace("ro,nosuid,nodev", "ro,nodev"),
            format!("{row}{}", row.replace("42 1", "43 1")),
        ] {
            assert!(
                prove_mount(&parse_mounts(&wrong).unwrap(), target, "tank/data@snap").is_err(),
                "{wrong}"
            );
        }
    }
    #[test]
    fn mountinfo_decodes_escaped_fields_and_refuses_malformed_evidence() {
        let row = "42 1 0:57 / /run/view/a\\040b ro,nosuid,nodev - zfs tank/a\\040b@snap ro\n";
        let mounts = parse_mounts(row).unwrap();
        assert!(prove_mount(&mounts, Path::new("/run/view/a b"), "tank/a b@snap").is_ok());
        for wrong in [
            row.replace("42 1", "0 1"),
            row.replace("\\040", "\\999"),
            row.replace("\\040", "\\04"),
            "garbage".into(),
            format!("{row}{row}"),
        ] {
            assert!(parse_mounts(&wrong).is_err());
        }
    }
    #[test]
    fn mount_collisions_include_prefixes_and_nested_mounts() {
        let row = "42 1 0:57 / /run/view/data ro,nosuid,nodev - zfs tank/data@snap ro\n";
        let mounts = parse_mounts(row).unwrap();
        assert!(reject_mounts_below(&mounts, Path::new("/run/view"), &[], None).is_err());
        assert!(reject_mounts_below(&mounts, Path::new("/run/viewer"), &[], None).is_ok());
        let tracked = [TrackedMount {
            target: "/run/view/data".into(),
            snapshot: source("data").snapshot,
            mount_id: Some(42),
        }];
        assert!(reject_mounts_below(&mounts, Path::new("/run/view"), &tracked, None).is_ok());
        let nested = format!("{row}43 42 0:58 / /run/view/data/hidden ro - tmpfs tmpfs ro\n");
        assert!(
            reject_mounts_below(
                &parse_mounts(&nested).unwrap(),
                Path::new("/run/view"),
                &tracked,
                None,
            )
            .is_err()
        );
    }
    #[test]
    fn substrate_requires_its_own_exact_tmpfs_identity_and_bounded_size() {
        let target = Path::new("/run/view");
        let row =
            "40 1 0:55 / /run/view rw,nosuid,nodev - tmpfs zsnap-reader rw,size=16384k,mode=755\n";
        let mounts = parse_mounts(row).unwrap();
        assert_eq!(prove_root_mount(&mounts, target).unwrap().id, 40);
        let root = TrackedRootMount { mount_id: Some(40) };
        assert!(reject_mounts_below(&mounts, target, &[], Some(&root)).is_ok());
        assert!(reject_mounts_below(&mounts, target, &[], None).is_err());
        let wrong_id = TrackedRootMount { mount_id: Some(41) };
        assert!(reject_mounts_below(&mounts, target, &[], Some(&wrong_id)).is_err());
        for wrong in [
            row.replace("zsnap-reader", "tmpfs"),
            row.replace(" - tmpfs ", " - zfs "),
            row.replace("rw,nosuid,nodev", "rw,nodev"),
            row.replace("rw,nosuid,nodev", "ro,nosuid,nodev"),
            row.replace("size=16384k", "size=32m"),
            row.replace("size=16384k", "size=0"),
            row.replace("size=16384k", "size=16%"),
            row.replace("size=16384k", "size=16m,size=8m"),
            format!("{row}{}", row.replace("40 1", "41 1")),
        ] {
            assert!(
                prove_root_mount(&parse_mounts(&wrong).unwrap(), target).is_err(),
                "{wrong}"
            );
        }
        for size in ["size=16777216", "size=16384k", "size=16m"] {
            assert!(bounded_tmpfs_size(size));
        }
        for size in [
            "size=0",
            "size=17m",
            "size=1g",
            "size=18446744073709551615g",
            "size=50%",
        ] {
            assert!(!bounded_tmpfs_size(size));
        }
    }
    #[test]
    fn capability_admission_refuses_before_namespace_effects() {
        let status = "Uid:\t0\t0\t0\t0\nCapEff:\t0000000000200000\n";
        let expected = (11, 22);
        assert!(require_root_mount_capability(status, expected, expected).is_ok());
        assert!(require_root_mount_capability(status, (11, 23), expected).is_err());
        assert!(require_root_mount_capability(status, (12, 22), expected).is_err());
        assert!(
            require_root_mount_capability(
                &status.replace("0200000", "0000000"),
                expected,
                expected
            )
            .is_err()
        );
        assert!(
            require_root_mount_capability(
                &status.replace("0\t0\t0\t0", "0\t1000\t0\t0"),
                expected,
                expected,
            )
            .is_err()
        );
        assert!(
            require_root_mount_capability(
                &format!("{status}CapEff:\t200000\n"),
                expected,
                expected
            )
            .is_err()
        );
    }
}
