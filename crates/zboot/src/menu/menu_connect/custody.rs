//! Closed ownership of SSH descendants, including setsid/double-fork jobs.
//!
//! A fixed reserved parent owns only our UUID leaves. Creating the leaf before
//! spawn closes the record-sealing window: restart can recover every owned
//! child, even if the menu died immediately after mkdir. No PID file, foreign
//! process scan, namespace split or resource controller is involved.
//!
//! The stop barrier is successful rmdir, after cgroup.kill and populated=0.
//! Empty alone is insufficient: a pre-exec child may still hold cgroup.procs.
//! Linux rejects migration through that held FD after the node is removed.

use super::{Result, refuse};
use rustix::fs::{self as fd, AtFlags, Mode, OFlags};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ROOT: &str = "/sys/fs/cgroup";
const PARENT: &str = "zboot-connect";
const BOUND: Duration = Duration::from_secs(5);
const MAX_LEAVES: usize = 128;

pub(super) struct Owned {
    parent: File,
    directory: File,
    name: String,
    child: Option<Child>,
    closed: bool,
}

fn open_dir(at: &impl std::os::fd::AsFd, name: &str) -> Result<File> {
    fd::openat(
        at,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|e| io::Error::from(e).into())
}

fn verify(directory: &File) -> Result<()> {
    let stat = fd::fstat(directory).map_err(io::Error::from)?;
    let fs = fd::fstatfs(directory).map_err(io::Error::from)?;
    if fs.f_type != 0x6367_7270 || stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
        return Err(refuse(
            "Menu SSH custody is not a root-owned cgroup2 directory",
        ));
    }
    Ok(())
}

fn root() -> Result<File> {
    let directory = fd::open(
        ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)?;
    verify(&directory)?;
    Ok(directory)
}

pub(super) fn available() -> bool {
    root().is_ok()
}

fn control(directory: &File, name: &str, write: bool) -> Result<File> {
    fd::openat(
        directory,
        name,
        (if write {
            OFlags::WRONLY
        } else {
            OFlags::RDONLY
        }) | OFlags::NOFOLLOW
            | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|e| io::Error::from(e).into())
}

fn read_control(directory: &File, name: &str) -> Result<String> {
    let mut value = String::new();
    control(directory, name, false)?
        .take(4097)
        .read_to_string(&mut value)?;
    if value.len() > 4096 {
        return Err(refuse("Menu SSH cgroup control exceeds its bound"));
    }
    Ok(value)
}

fn parent(create: bool) -> Result<Option<File>> {
    let root = match root() {
        Ok(root) => root,
        Err(error) => {
            // Missing optional cgroup2 support must not disable an otherwise
            // ordinary Menu. Existing reserved custody, however, cannot be
            // declared closed on an unsupported or replaced mount.
            if !create && !std::path::Path::new(ROOT).join(PARENT).try_exists()? {
                return Ok(None);
            }
            return Err(error);
        }
    };
    if create {
        match fd::mkdirat(&root, PARENT, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
    }
    let parent = match open_dir(&root, PARENT) {
        Ok(parent) => parent,
        Err(super::RecoveryError::Io(error))
            if !create && error.kind() == io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    verify(&parent)?;
    if fd::fstat(&parent).map_err(io::Error::from)?.st_mode & 0o077 != 0 {
        return Err(refuse("Menu SSH reserved cgroup parent is not private"));
    }
    if !read_control(&parent, "cgroup.procs")?.trim().is_empty() {
        return Err(refuse(
            "Menu SSH reserved cgroup parent contains unexpected processes",
        ));
    }
    Ok(Some(parent))
}

fn leaf_name(name: &str) -> bool {
    name.strip_prefix("ssh-").is_some_and(|id| {
        id.len() == 36 && uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == id)
    })
}

fn populated(events: &str) -> Result<bool> {
    let mut result = None;
    for line in events.lines() {
        if let Some(value) = line.strip_prefix("populated ") {
            if result.is_some() || !matches!(value, "0" | "1") {
                return Err(refuse("invalid SSH cgroup populated evidence"));
            }
            result = Some(value == "1");
        }
    }
    result.ok_or_else(|| refuse("missing SSH cgroup populated evidence"))
}

fn linked(parent: &File, directory: &File, name: &str) -> Result<bool> {
    let held = fd::fstat(directory).map_err(io::Error::from)?;
    let actual = match fd::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => return Err(io::Error::from(error).into()),
    };
    if held.st_dev != actual.st_dev || held.st_ino != actual.st_ino {
        return Err(refuse(
            "owned SSH cgroup was replaced; no replacement was modified",
        ));
    }
    Ok(true)
}

// The narrow effect seam tests the actual retry/timeout policy without a
// cgroup mount, process, wall-clock sleep or native write in the test runner.
trait Teardown {
    fn linked(&mut self) -> Result<bool>;
    fn kill(&mut self) -> Result<()>;
    fn populated(&mut self) -> Result<bool>;
    fn remove(&mut self) -> Result<bool>;
}
struct NativeTeardown<'a> {
    parent: &'a File,
    directory: &'a File,
    name: &'a str,
}
impl Teardown for NativeTeardown<'_> {
    fn linked(&mut self) -> Result<bool> {
        linked(self.parent, self.directory, self.name)
    }
    fn kill(&mut self) -> Result<()> {
        control(self.directory, "cgroup.kill", true)?
            .write_all(b"1")
            .map_err(Into::into)
    }
    fn populated(&mut self) -> Result<bool> {
        populated(&read_control(self.directory, "cgroup.events")?)
    }
    fn remove(&mut self) -> Result<bool> {
        if !self.linked()? {
            return Ok(true);
        }
        match fd::unlinkat(self.parent, self.name, AtFlags::REMOVEDIR) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(true),
            Err(rustix::io::Errno::BUSY) | Err(rustix::io::Errno::NOTEMPTY) => Ok(false),
            Err(error) => Err(io::Error::from(error).into()),
        }
    }
}
fn close_with(
    effects: &mut impl Teardown,
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut pause: impl FnMut(),
) -> Result<()> {
    loop {
        if !effects.linked()? {
            return Ok(());
        }
        if let Err(error) = effects.kill() {
            // No process was ever admitted when the optional kernel kill
            // interface is unsupported. Empty + successful rmdir still proves
            // closure, including against any later inherited-FD admission.
            if !effects.linked()? {
                return Ok(());
            }
            if effects.populated()? || !effects.remove()? {
                return Err(error);
            }
            return Ok(());
        }
        if !effects.populated()? && effects.remove()? {
            return Ok(());
        }
        if now() >= deadline {
            return Err(refuse(
                "owned SSH cgroup has not closed; authentication and automatic boot remain held",
            ));
        }
        pause();
    }
}
fn close(parent: &File, directory: &File, name: &str, deadline: Instant) -> Result<()> {
    close_with(
        &mut NativeTeardown {
            parent,
            directory,
            name,
        },
        deadline,
        Instant::now,
        || thread::sleep(Duration::from_millis(10)),
    )
}

/// Enumerate only the fixed reserved parent. This includes a generation whose
/// creator died after mkdir but before producing any RAM metadata or child.
pub(super) fn recover() -> Result<()> {
    let Some(parent) = parent(false)? else {
        return Ok(());
    };
    let mut names = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            return Err(refuse("unexpected symlink in SSH custody parent"));
        }
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| refuse("invalid SSH custody leaf name"))?;
        if !leaf_name(&name) || names.len() == MAX_LEAVES {
            return Err(refuse(
                "unexpected or excessive children in SSH custody parent",
            ));
        }
        names.push(name);
    }
    names.sort();
    let mut leaves = Vec::new();
    for name in names {
        let directory = open_dir(&parent, &name)?;
        verify(&directory)?;
        leaves.push((name, directory));
    }
    // Cut every known owned generation before waiting on a stuck member of
    // one leaf. The same deadline bounds the whole recovery batch.
    for (name, directory) in &leaves {
        let _ = NativeTeardown {
            parent: &parent,
            directory,
            name,
        }
        .kill();
    }
    let deadline = Instant::now() + BOUND;
    let mut failed = None;
    for (name, directory) in leaves {
        if let Err(error) = close(&parent, &directory, &name, deadline)
            && failed.is_none()
        {
            failed = Some(error);
        }
    }
    if let Some(error) = failed {
        return Err(error);
    }
    Ok(())
}

impl Owned {
    pub(super) fn new() -> Result<Self> {
        let parent = parent(true)?.expect("create returns parent");
        let name = format!("ssh-{}", uuid::Uuid::new_v4());
        fd::mkdirat(&parent, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(io::Error::from)?;
        let directory = open_dir(&parent, &name)?;
        verify(&directory)?;
        // Require native kill + events before admitting any child. If absent,
        // preserve the empty owned leaf for explicit recovery/refusal.
        control(&directory, "cgroup.kill", true)?;
        populated(&read_control(&directory, "cgroup.events")?)?;
        Ok(Self {
            parent,
            directory,
            name,
            child: None,
            closed: false,
        })
    }

    #[allow(unsafe_code)]
    pub(super) fn admit(&self, command: &mut Command) -> Result<()> {
        if self.closed || !linked(&self.parent, &self.directory, &self.name)? {
            return Err(refuse("SSH custody admission is already closed"));
        }
        let procs: OwnedFd = control(&self.directory, "cgroup.procs", true)?.into();
        let parent_tgid = nix::unistd::getpid();
        // SAFETY: only prctl/getppid/write syscalls and raw OS errors occur
        // after fork. No allocation, path lookup, formatting or process locks.
        // The held FD rejects a late migration after cleanup removes the leaf.
        unsafe {
            command.pre_exec(move || {
                nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
                    .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                if nix::unistd::getppid() != parent_tgid {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                loop {
                    let count = libc::write(procs.as_raw_fd(), b"0".as_ptr().cast(), 1);
                    if count == 1 {
                        return Ok(());
                    }
                    if count < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(error);
                    }
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
            });
        }
        Ok(())
    }

    pub(super) fn spawn(&mut self, config: &str, stderr: Stdio) -> Result<()> {
        let mut command = Command::new("/usr/sbin/sshd");
        command
            .args(["-D", "-e", "-f", config])
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .process_group(0);
        self.admit(&mut command)?;
        self.child = Some(zfs_tools::engine::native::announced(&mut command).spawn()?);
        Ok(())
    }

    pub(super) fn listener_pid(&self) -> u32 {
        self.child.as_ref().expect("spawned listener").id()
    }
    pub(super) fn exited(&mut self) -> Result<bool> {
        self.child
            .as_mut()
            .expect("spawned listener")
            .try_wait()
            .map(|s| s.is_some())
            .map_err(Into::into)
    }
    pub(super) fn stop(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let deadline = Instant::now() + BOUND;
        close(&self.parent, &self.directory, &self.name, deadline)?;
        if let Some(child) = self.child.as_mut() {
            while child.try_wait()?.is_none() {
                if Instant::now() >= deadline {
                    return Err(refuse(
                        "closed SSH cgroup listener has not reaped; custody remains held",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        self.closed = true;
        Ok(())
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        // Unexpected unwinding attempts cleanup; any unproven leaf remains
        // discoverable under the reserved parent on the next Menu startup.
        if !self.closed {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        live: std::collections::VecDeque<bool>,
        removed: std::collections::VecDeque<bool>,
        operations: Vec<&'static str>,
        kill_fails: bool,
    }
    impl Teardown for Fake {
        fn linked(&mut self) -> Result<bool> {
            self.operations.push("linked");
            Ok(true)
        }
        fn kill(&mut self) -> Result<()> {
            self.operations.push("kill");
            if self.kill_fails {
                Err(refuse("unsupported native kill"))
            } else {
                Ok(())
            }
        }
        fn populated(&mut self) -> Result<bool> {
            self.operations.push("population");
            Ok(self.live.pop_front().expect("population input"))
        }
        fn remove(&mut self) -> Result<bool> {
            self.operations.push("rmdir");
            Ok(self.removed.pop_front().expect("rmdir input"))
        }
    }
    #[test]
    fn an_empty_observation_followed_by_a_late_join_is_killed_again_until_rmdir() {
        let now = Instant::now();
        let mut fake = Fake {
            live: [false, true, false].into(),
            removed: [false, true].into(),
            operations: Vec::new(),
            kill_fails: false,
        };
        close_with(&mut fake, now + BOUND, || now, || {}).unwrap();
        assert_eq!(
            fake.operations,
            [
                "linked",
                "kill",
                "population",
                "rmdir",
                "linked",
                "kill",
                "population",
                "linked",
                "kill",
                "population",
                "rmdir"
            ]
        );
        assert!(fake.live.is_empty() && fake.removed.is_empty());
    }
    #[test]
    fn a_stuck_member_times_out_without_claiming_closed_or_removing_the_leaf() {
        let now = Instant::now();
        let mut fake = Fake {
            live: [true].into(),
            removed: [].into(),
            operations: Vec::new(),
            kill_fails: false,
        };
        assert!(close_with(&mut fake, now, || now, || panic!("no sleep after deadline")).is_err());
        assert_eq!(fake.operations, ["linked", "kill", "population"]);
    }
    #[test]
    fn persistent_busy_rmdir_times_out_without_claiming_custody_closed() {
        let now = Instant::now();
        let mut fake = Fake {
            live: [false].into(),
            removed: [false].into(),
            operations: Vec::new(),
            kill_fails: false,
        };
        assert!(close_with(&mut fake, now, || now, || panic!("no sleep after deadline")).is_err());
        assert_eq!(fake.operations, ["linked", "kill", "population", "rmdir"]);
    }
    #[test]
    fn missing_optional_kill_support_is_safe_only_if_empty_rmdir_succeeds() {
        let now = Instant::now();
        for (live, removed, success) in [
            (false, true, true),
            (false, false, false),
            (true, false, false),
        ] {
            let mut fake = Fake {
                live: [live].into(),
                removed: [removed].into(),
                operations: Vec::new(),
                kill_fails: true,
            };
            assert_eq!(close_with(&mut fake, now, || now, || {}).is_ok(), success);
        }
        for input in ["", "populated 2\n", "populated 0\npopulated 1\n"] {
            assert!(populated(input).is_err());
        }
        assert!(populated("populated 1\nfrozen 0\n").unwrap());
    }
    #[test]
    fn recovery_names_only_generations_below_our_reserved_parent() {
        assert!(leaf_name("ssh-11111111-1111-4111-8111-111111111111"));
        for name in [
            "foreign",
            "../sshd",
            "ssh-../foreign",
            "ssh-11111111111141118111111111111111",
        ] {
            assert!(!leaf_name(name));
        }
    }
}
