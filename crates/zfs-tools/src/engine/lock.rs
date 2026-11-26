//! The local writer lock. zboot and zsnap take it at the entry of every
//! mutating command and hold it through final revalidation, effects and
//! readback; library calls never take it, so callers cannot nest it. Waiting
//! for it drains a running zsnap job, which holds the same lock. It coordinates
//! writers on this host only: it is neither a cross-host fence nor application
//! quiescence, and raw `zfs`/`zpool` commands bypass it.
use rustix::{
    fs::{FlockOperation, flock},
    io::Errno,
};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

/// On tmpfs, so a lock never outlives the boot (or the RAM Menu) that took it.
pub const PATH: &str = "/run/zfs-tools/writer.lock";
const POLL: Duration = Duration::from_millis(200);
/// How long a command waits for another writer (a zsnap run, a sync) to finish.
pub const COMMAND_WAIT: Duration = Duration::from_secs(300);

/// The lock for a mutating command of `program`, saying on stderr when it
/// waits. A caller that is not root may still change pools through `zfs
/// allow` delegation, so it must join the same lock. Boot initialization
/// creates the readable inode; an unavailable lock refuses the command. Root
/// writers also create it when needed and repair its mode independently of umask.
pub fn for_command(program: &str, purpose: &str) -> Result<WriterLock, LockError> {
    let waiting = |holder: &str| {
        eprintln!(
            "{program}: waiting for the ZFS writer lock, held by {}",
            crate::engine::escape_display(holder)
        )
    };
    if !rustix::process::geteuid().is_root() {
        return WriterLock::join_at(Path::new(PATH), COMMAND_WAIT, waiting);
    }
    WriterLock::acquire(&format!("{program} {purpose}"), COMMAND_WAIT, waiting)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// Another writer kept the lock for the whole wait.
    Busy {
        holder: String,
    },
    Io(String),
}
impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy { holder } => write!(
                f,
                "another ZFS writer holds {PATH} ({}); try again when it finishes",
                crate::engine::escape_display(holder)
            ),
            Self::Io(detail) => write!(f, "writer lock {PATH}: {detail}"),
        }
    }
}
impl std::error::Error for LockError {}

/// Held until dropped. Native commands normally leave the close-on-exec
/// descriptor behind. `inherit_for` explicitly extends ownership to a child.
#[derive(Debug)]
pub struct WriterLock {
    _file: File,
}
impl WriterLock {
    /// Take the host's writer lock for `purpose` (shown to a waiting writer),
    /// waiting up to `wait`. `waiting` is called once, with the holder's
    /// purpose, if the lock is busy.
    pub fn acquire(
        purpose: &str,
        wait: Duration,
        waiting: impl FnOnce(&str),
    ) -> Result<Self, LockError> {
        // Root's first writer may run on a host without the tmpfiles rule yet.
        // Repair directory traversal as well as the inode's read permissions.
        let parent = Path::new(PATH).parent().expect("fixed writer lock parent");
        std::fs::create_dir_all(parent).map_err(|e| LockError::Io(e.to_string()))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| LockError::Io(e.to_string()))?;
        Self::acquire_at(Path::new(PATH), purpose, wait, waiting)
    }

    pub fn acquire_at(
        path: &Path,
        purpose: &str,
        wait: Duration,
        waiting: impl FnOnce(&str),
    ) -> Result<Self, LockError> {
        let io = |e: std::io::Error| LockError::Io(e.to_string());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o644)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(io)?;
        regular(&file)?;
        // OpenOptions::mode is filtered by umask, including root's common 077.
        // Keep the same inode so delegated readers and root share one flock.
        file.set_permissions(std::fs::Permissions::from_mode(0o644))
            .map_err(io)?;
        lock(&mut file, wait, waiting)?;
        // The holder text is advisory; the lock is the flock itself.
        file.set_len(0).map_err(io)?;
        file.rewind().map_err(io)?;
        writeln!(
            file,
            "pid {} {}",
            std::process::id(),
            purpose.replace('\n', " ")
        )
        .map_err(io)?;
        Ok(Self { _file: file })
    }

    /// Join an existing readable lock without creating or writing it. Failure
    /// to open it is a refusal, never permission to proceed without coordination.
    pub fn join_at(
        path: &Path,
        wait: Duration,
        waiting: impl FnOnce(&str),
    ) -> Result<Self, LockError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|e| LockError::Io(format!(
                "cannot join {}: {e}; root must initialize the readable writer lock before delegated writers run",
                path.display()
            )))?;
        regular(&file)?;
        lock(&mut file, wait, waiting)?;
        Ok(Self { _file: file })
    }

    /// Duplicate custody of the same flock open-file description without
    /// acquiring another lock. Used by a scoped native dispatch context.
    pub(crate) fn duplicate(&self) -> Result<Self, LockError> {
        Ok(Self {
            _file: self
                ._file
                .try_clone()
                .map_err(|error| LockError::Io(error.to_string()))?,
        })
    }

    /// Keep this lock held by a command after it starts, including when the
    /// original holder exits. The child shares the lock's open file description.
    ///
    /// The command owns a close-on-exec duplicate until it is dropped. Drop the
    /// command after spawning so the child and the original holder determine
    /// the remaining lifetime. An unsuccessful spawn also needs that drop.
    pub fn inherit_for(&self, command: &mut Command) -> Result<(), LockError> {
        let inherited = File::from(
            rustix::io::fcntl_dupfd_cloexec(&self._file, 3)
                .map_err(|error| LockError::Io(error.to_string()))?,
        );
        // SAFETY: the post-fork child only calls fcntl, updates its descriptor
        // flags and constructs raw OS errors. It allocates no memory and takes
        // no process locks. Capturing the owned file keeps its descriptor valid
        // through spawn. CLOEXEC stays set in every parent thread.
        #[allow(
            unsafe_code,
            reason = "clearing CLOEXEC on the inherited writer lock in pre_exec"
        )]
        unsafe {
            command.pre_exec(move || {
                let flags = rustix::io::fcntl_getfd(&inherited).map_err(std::io::Error::from)?;
                rustix::io::fcntl_setfd(&inherited, flags & !rustix::io::FdFlags::CLOEXEC)
                    .map_err(std::io::Error::from)
            });
        }
        Ok(())
    }
}

fn regular(file: &File) -> Result<(), LockError> {
    if !file
        .metadata()
        .map_err(|e| LockError::Io(e.to_string()))?
        .is_file()
    {
        return Err(LockError::Io("lock inode is not a regular file".into()));
    }
    Ok(())
}

fn lock(file: &mut File, wait: Duration, waiting: impl FnOnce(&str)) -> Result<(), LockError> {
    let deadline = Instant::now() + wait;
    let mut waiting = Some(waiting);
    loop {
        match flock(&*file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(Errno::WOULDBLOCK) => {}
            Err(error) => return Err(LockError::Io(std::io::Error::from(error).to_string())),
        }
        let holder = holder(file);
        if Instant::now() >= deadline {
            return Err(LockError::Busy { holder });
        }
        if let Some(waiting) = waiting.take() {
            waiting(&holder);
        }
        thread::sleep(POLL);
    }
}

fn holder(file: &mut File) -> String {
    let mut text = String::new();
    let _ = file.rewind();
    let _ = file.take(256).read_to_string(&mut text);
    match text.trim() {
        "" => "unknown holder".to_string(),
        text => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        process::{Child, Stdio},
        sync::mpsc,
    };

    fn dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zfs-tools-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_second_writer_waits_then_refuses_naming_the_holder() {
        let path = dir().join("writer.lock");
        let held = WriterLock::acquire_at(&path, "zsnap run", Duration::ZERO, |_| {}).unwrap();
        let mut seen = None;
        let error = WriterLock::acquire_at(&path, "zboot drop", Duration::from_millis(300), |h| {
            seen = Some(h.to_string())
        })
        .unwrap_err();
        let holder = format!("pid {} zsnap run", std::process::id());
        assert_eq!(seen.as_deref(), Some(holder.as_str()));
        assert_eq!(error, LockError::Busy { holder });
        drop(held);
        WriterLock::acquire_at(&path, "zboot drop", RELEASED, |_| {}).unwrap();
    }

    #[test]
    fn a_waiting_writer_proceeds_once_the_holder_finishes() {
        let path = dir().join("writer.lock");
        let held = WriterLock::acquire_at(&path, "first", Duration::ZERO, |_| {}).unwrap();
        let (tx, rx) = mpsc::channel();
        let waiter = {
            let path = path.clone();
            thread::spawn(move || {
                WriterLock::acquire_at(&path, "second", Duration::from_secs(10), |_| {
                    tx.send(()).unwrap()
                })
                .map(|_| ())
            })
        };
        rx.recv().unwrap();
        drop(held);
        waiter.join().unwrap().unwrap();
    }

    #[test]
    fn a_writer_that_is_not_root_joins_an_existing_lock_without_creating_one() {
        let path = dir().join("writer.lock");
        let absent = WriterLock::join_at(&path, Duration::ZERO, |_| {}).unwrap_err();
        assert!(matches!(absent, LockError::Io(_)));
        assert!(!path.exists());
        let held = WriterLock::acquire_at(&path, "zboot sync", Duration::ZERO, |_| {}).unwrap();
        // Read-only, as a delegated user opens root's 0644 file.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let error = WriterLock::join_at(&path, Duration::from_millis(300), |_| {}).unwrap_err();
        let holder = format!("pid {} zboot sync", std::process::id());
        assert_eq!(error, LockError::Busy { holder });
        drop(held);
        let joined = WriterLock::join_at(&path, RELEASED, |_| {}).unwrap();
        // While joined, a root writer waits for it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = WriterLock::acquire_at(&path, "zsnap run", Duration::ZERO, |_| {}).unwrap_err();
        assert!(matches!(error, LockError::Busy { .. }), "{error:?}");
        drop(joined);
    }

    #[test]
    fn root_creation_repairs_restrictive_mode_without_replacing_the_inode() {
        use std::os::unix::fs::MetadataExt;
        let path = dir().join("writer.lock");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();
        let _held = WriterLock::acquire_at(&path, "root", Duration::ZERO, |_| {}).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.ino(), inode);
        assert_eq!(metadata.mode() & 0o777, 0o644);
    }

    #[test]
    fn neither_writer_follows_a_symlink_lock() {
        let dir = dir();
        let target = dir.join("target");
        std::fs::write(&target, "untouched").unwrap();
        let path = dir.join("writer.lock");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(WriterLock::acquire_at(&path, "root", Duration::ZERO, |_| {}).is_err());
        assert!(WriterLock::join_at(&path, Duration::ZERO, |_| {}).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "untouched");
    }

    #[test]
    fn the_lock_is_not_inherited_by_native_commands() {
        let path = dir().join("writer.lock");
        let _held = WriterLock::acquire_at(&path, "parent", Duration::ZERO, |_| {}).unwrap();
        let flags = rustix::io::fcntl_getfd(&_held._file).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    /// How long a check that the lock is free again may wait. Another test's
    /// concurrent fork can briefly retain a copy of this CLOEXEC file until
    /// its exec, so a release is eventual, not immediate.
    const RELEASED: Duration = Duration::from_secs(2);

    struct LockChild(Child);

    impl LockChild {
        fn stop(&mut self) {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }

    impl Drop for LockChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn lock_child(held: Option<&WriterLock>, ready: &Path) -> LockChild {
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf ready > \"$1\"; read -r finished",
                "zfs-tools-lock-test",
            ])
            .arg(ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(held) = held {
            held.inherit_for(&mut command).unwrap();
        }
        let mut child = LockChild(
            crate::engine::native::announced(&mut command)
                .spawn()
                .unwrap(),
        );
        drop(command);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "lock child exited early"
            );
            assert!(Instant::now() < deadline, "lock child did not become ready");
            thread::sleep(Duration::from_millis(10));
        }
        child
    }

    #[test]
    fn an_inherited_lock_survives_the_parent_guard_until_the_child_exits() {
        let dir = dir();
        let path = dir.join("writer.lock");
        let held = WriterLock::acquire_at(&path, "import batch", Duration::ZERO, |_| {}).unwrap();
        let mut child = lock_child(Some(&held), &dir.join("ready"));
        let flags = rustix::io::fcntl_getfd(&held._file).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        drop(held);
        assert!(matches!(
            WriterLock::acquire_at(&path, "export", Duration::ZERO, |_| {}),
            Err(LockError::Busy { .. })
        ));
        child.stop();
        let next = WriterLock::acquire_at(&path, "export", RELEASED, |_| {}).unwrap();
        drop(next);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_ordinary_child_leaves_the_lock_close_on_exec() {
        let dir = dir();
        let path = dir.join("writer.lock");
        let held = WriterLock::acquire_at(&path, "parent", Duration::ZERO, |_| {}).unwrap();
        let mut child = lock_child(None, &dir.join("ready"));
        drop(held);
        let next = WriterLock::acquire_at(&path, "second", RELEASED, |_| {}).unwrap();
        child.stop();
        drop(next);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_failed_exec_releases_its_inherited_lock_when_the_command_is_dropped() {
        let dir = dir();
        let path = dir.join("writer.lock");
        let held = WriterLock::acquire_at(&path, "parent", Duration::ZERO, |_| {}).unwrap();
        let mut command = Command::new(dir.join("absent-program"));
        held.inherit_for(&mut command).unwrap();
        drop(held);
        assert_eq!(
            crate::engine::native::announced(&mut command)
                .spawn()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(matches!(
            WriterLock::acquire_at(&path, "second", Duration::ZERO, |_| {}),
            Err(LockError::Busy { .. })
        ));
        drop(command);
        // The assertion above still requires custody while Command owns the
        // descriptor.
        let next = WriterLock::acquire_at(&path, "second", RELEASED, |_| {}).unwrap();
        drop(next);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_delegated_readonly_join_can_hold_the_barrier_through_a_child() {
        let dir = dir();
        let path = dir.join("writer.lock");
        drop(WriterLock::acquire_at(&path, "initialize", Duration::ZERO, |_| {}).unwrap());
        let joined = WriterLock::join_at(&path, Duration::ZERO, |_| {}).unwrap();
        let mut child = lock_child(Some(&joined), &dir.join("ready"));
        drop(joined);
        assert!(matches!(
            WriterLock::join_at(&path, Duration::ZERO, |_| {}),
            Err(LockError::Busy { .. })
        ));
        assert!(matches!(
            WriterLock::acquire_at(&path, "root writer", Duration::ZERO, |_| {}),
            Err(LockError::Busy { .. })
        ));
        child.stop();
        let next = WriterLock::join_at(&path, RELEASED, |_| {}).unwrap();
        drop(next);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
