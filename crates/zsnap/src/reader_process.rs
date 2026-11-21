//! Private reader launch barrier and credential transition. No reader may exec
//! until its parent has authenticated its cgroup placement and durable intent.
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{Gid, Uid, User};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use zfs_tools::engine::native::Announced;

const MAX_LAUNCH: u64 = 4 * 1024 * 1024;
static INTERRUPTED: AtomicI32 = AtomicI32::new(0);

// Reader argv can contain credentials. Keep the process-announcement contract
// without copying launch data into diagnostics or changing the child env.
fn announced(command: &mut Command) -> Announced<'_> {
    Announced::withheld(command, "supervised reader")
}

extern "C" fn interrupted(signal: i32) {
    INTERRUPTED.store(signal, Ordering::SeqCst);
}
pub(crate) fn install_signals() -> io::Result<()> {
    INTERRUPTED.store(0, Ordering::SeqCst);
    let action = SigAction::new(
        SigHandler::Handler(interrupted),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    for signal in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP] {
        // SAFETY: handler only writes a lock-free atomic; this dedicated CLI
        // process owns these handlers for its complete job lifetime.
        #[allow(
            unsafe_code,
            reason = "installing atomic-flag signal handler via sigaction"
        )]
        unsafe { signal::sigaction(signal, &action) }.map_err(io::Error::from)?;
    }
    Ok(())
}
pub(crate) fn interruption() -> i32 {
    INTERRUPTED.load(Ordering::SeqCst)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReaderLaunch {
    argv: Vec<Vec<u8>>,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    environment: BTreeMap<String, Vec<u8>>,
}
fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_uppercase() || (i > 0 && c.is_ascii_digit()))
        && !name.starts_with("LD_")
        && !matches!(
            name,
            "ENV"
                | "BASH_ENV"
                | "PYTHONPATH"
                | "PYTHONHOME"
                | "PERL5OPT"
                | "RUBYOPT"
                | "NODE_OPTIONS"
                | "GCONV_PATH"
                | "LOCPATH"
                | "IFS"
        )
}
impl ReaderLaunch {
    pub(crate) fn set_manifest(&mut self, fd: i32) {
        self.environment
            .insert("ZSNAP_MANIFEST_FD".into(), fd.to_string().into_bytes());
    }
    pub(crate) fn set_job(&mut self, id: &str) {
        self.environment
            .insert("ZSNAP_JOB".into(), id.as_bytes().to_vec());
    }
    pub(crate) fn prepare(
        argv: &[OsString],
        user: Option<&str>,
        copy_environment: &[String],
        view: &std::path::Path,
    ) -> io::Result<Self> {
        if argv.is_empty() || argv.iter().any(|a| a.as_bytes().contains(&0)) {
            return Err(io::Error::other("reader command is empty or contains NUL"));
        }
        let account = match user {
            Some(name) => User::from_name(name),
            None => User::from_uid(Uid::effective()),
        }
        .map_err(io::Error::from)?
        .ok_or_else(|| io::Error::other("reader account was not found"))?;
        let name = CString::new(account.name.as_bytes()).map_err(io::Error::other)?;
        let groups = nix::unistd::getgrouplist(&name, account.gid).map_err(io::Error::from)?;
        let mut environment = BTreeMap::new();
        for key in ["LANG", "LC_ALL", "TZ", "TERM"] {
            if let Some(value) = std::env::var_os(key) {
                environment.insert(key.into(), value.as_bytes().to_vec());
            }
        }
        for key in copy_environment {
            if !matches!(
                key.as_str(),
                "SSH_AUTH_SOCK"
                    | "XDG_RUNTIME_DIR"
                    | "CREDENTIALS_DIRECTORY"
                    | "GNUPGHOME"
                    | "PASSWORD_STORE_DIR"
                    | "LANG"
                    | "LC_ALL"
                    | "TZ"
                    | "TERM"
            ) {
                return Err(io::Error::other(
                    "reader environment name is not an approved nonsecret account path or locale; pass credentials through files/descriptors",
                ));
            }
            if let Some(value) = std::env::var_os(key) {
                environment.insert(key.clone(), value.as_bytes().to_vec());
            }
        }
        // Target account identity and native program search are never selected
        // by ambient sudo variables or reader-controlled environment values.
        environment.insert(
            "PATH".into(),
            b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec(),
        );
        environment.insert("HOME".into(), account.dir.as_os_str().as_bytes().to_vec());
        environment.insert("USER".into(), account.name.as_bytes().to_vec());
        environment.insert("LOGNAME".into(), account.name.as_bytes().to_vec());
        environment.insert("ZSNAP_VIEW".into(), view.as_os_str().as_bytes().to_vec());
        Ok(Self {
            argv: argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
            uid: account.uid.as_raw(),
            gid: account.gid.as_raw(),
            groups: groups.into_iter().map(Gid::as_raw).collect(),
            environment,
        })
    }
}

pub(crate) struct BlockedReader {
    pub(crate) child: Child,
    control: UnixStream,
}
impl BlockedReader {
    pub(crate) fn spawn(manifest: &std::fs::File) -> io::Result<Self> {
        let manifest_descriptor = manifest.as_raw_fd();
        let (control, child_control) = UnixStream::pair()?;
        control.set_write_timeout(Some(Duration::from_secs(10)))?;
        let descriptor = child_control.as_raw_fd();
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("__protect-child")
            .arg(descriptor.to_string())
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        // SAFETY: this hook performs only fcntl on the live control socket and
        // manifest descriptors; it neither blocks waiting for the parent nor
        // allocates after fork.
        #[allow(
            unsafe_code,
            reason = "clearing CLOEXEC on inherited launch and manifest descriptors in pre_exec"
        )]
        unsafe {
            command.pre_exec(move || {
                for raw in [descriptor, manifest_descriptor] {
                    let borrowed = BorrowedFd::borrow_raw(raw);
                    let flags = rustix::io::fcntl_getfd(borrowed).map_err(io::Error::from)?;
                    rustix::io::fcntl_setfd(borrowed, flags & !rustix::io::FdFlags::CLOEXEC)
                        .map_err(io::Error::from)?;
                }
                Ok(())
            });
        }
        let child = announced(&mut command).spawn()?;
        drop(child_control);
        Ok(Self { child, control })
    }
    pub(crate) fn start(mut self, launch: &ReaderLaunch) -> io::Result<Child> {
        let bytes = serde_json::to_vec(launch).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_LAUNCH {
            return Err(io::Error::other("reader launch exceeds bounded channel"));
        }
        self.control.write_all(&bytes)?;
        self.control.shutdown(std::net::Shutdown::Write)?;
        Ok(self.child)
    }
    pub(crate) fn abort(mut self) -> io::Result<()> {
        // This exact child is blocked before exec/fork. Closing the launch
        // channel makes it refuse; kill/wait bounds fixture or kernel failure.
        drop(self.control);
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }
}

/// Hidden re-exec entry point. This is not a public command or an arbitrary
/// privileged execution service: its only input is the inherited root peer.
pub(crate) fn child_entry(fd: i32) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    if !rustix::process::geteuid().is_root() || fd < 3 {
        return Err(io::Error::other(
            "reader child requires its root-owned launch channel",
        ));
    }
    // A malformed manual hidden-entry invocation must not manufacture an
    // OwnedFd from a nonexistent or non-socket descriptor.
    let meta = std::fs::metadata(format!("/proc/self/fd/{fd}"))?;
    if !meta.file_type().is_socket() {
        return Err(io::Error::other(
            "reader launch channel descriptor is not a socket",
        ));
    }
    // SAFETY: this hidden standalone entry owns the verified open socket
    // descriptor supplied by its root parent; ownership is transferred once.
    #[allow(
        unsafe_code,
        reason = "adopting inherited launch socket descriptor validated via /proc/self/fd"
    )]
    let mut channel = unsafe { UnixStream::from_raw_fd(fd) };
    let peer = getsockopt(&channel, PeerCredentials).map_err(io::Error::from)?;
    if peer.uid() != 0 || peer.pid() != nix::unistd::getppid().as_raw() {
        return Err(io::Error::other(
            "reader launch peer is not its root parent",
        ));
    }
    channel.set_read_timeout(Some(Duration::from_secs(120)))?;
    let mut bytes = Vec::new();
    (&mut channel)
        .take(MAX_LAUNCH + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LAUNCH {
        return Err(io::Error::other("reader launch exceeds bounded channel"));
    }
    let launch: ReaderLaunch = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if launch.argv.is_empty()
        || launch.argv.iter().any(|arg| arg.contains(&0))
        || launch
            .environment
            .iter()
            .any(|(key, value)| !valid_environment_name(key) || value.contains(&0))
    {
        return Err(io::Error::other("invalid reader launch"));
    }
    drop(channel);
    let groups: Vec<_> = launch.groups.into_iter().map(Gid::from_raw).collect();
    nix::unistd::setgroups(&groups).map_err(io::Error::from)?;
    nix::unistd::setresgid(
        Gid::from_raw(launch.gid),
        Gid::from_raw(launch.gid),
        Gid::from_raw(launch.gid),
    )
    .map_err(io::Error::from)?;
    nix::unistd::setresuid(
        Uid::from_raw(launch.uid),
        Uid::from_raw(launch.uid),
        Uid::from_raw(launch.uid),
    )
    .map_err(io::Error::from)?;
    nix::sys::prctl::set_no_new_privs().map_err(io::Error::from)?;
    let argv: Vec<_> = launch.argv.into_iter().map(OsString::from_vec).collect();
    let mut reader = Command::new(&argv[0]);
    reader.args(&argv[1..]).env_clear();
    for (key, value) in launch.environment {
        reader.env(key, OsString::from_vec(value));
    }
    // exec preserves stdin/stdout/stderr. Launch data and environment are never
    // written to job intent, progress, results or diagnostics.
    Err(announced(&mut reader).exec())
}

pub(crate) fn wait_reader(
    mut child: Child,
    cgroup: &super::reader_cgroup::ReaderCgroup,
    stop_timeout: Duration,
) -> io::Result<(ExitStatus, bool)> {
    let mut stopping = None;
    let mut status = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        if (interruption() != 0 || status.is_some()) && stopping.is_none() {
            stopping = Some(Instant::now());
            if status.is_none() {
                // Unreaped Child reserves this PID. Descendants are covered by
                // the authenticated cgroup, not by an assumed process group.
                let _ = signal::kill(
                    nix::unistd::Pid::from_raw(child.id() as i32),
                    Signal::SIGTERM,
                );
            }
        }
        if cgroup.wait_empty(Duration::ZERO)? {
            let status = match status {
                Some(status) => status,
                None => child.wait()?,
            };
            return Ok((status, stopping.is_some_and(|_| interruption() != 0)));
        }
        if stopping.is_some_and(|since| since.elapsed() >= stop_timeout) {
            cgroup.kill_owned()?;
            if !cgroup.wait_empty(stop_timeout)? {
                return Err(io::Error::other(
                    "reader subtree did not become empty; protection retained",
                ));
            }
            let status = match status {
                Some(status) => status,
                None => child.wait()?,
            };
            return Ok((status, true));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn launch_environment_cannot_replace_credentials_or_loader() {
        for key in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "BASH_ENV",
            "PYTHONPATH",
            "NODE_OPTIONS",
            "",
            "a",
            "0BAD",
            "HOME=X",
        ] {
            assert!(!valid_environment_name(key), "{key}");
        }
        for key in [
            "SSH_AUTH_SOCK",
            "XDG_RUNTIME_DIR",
            "CREDENTIALS_DIRECTORY",
            "LANG",
            "ZSNAP_VIEW",
        ] {
            assert!(valid_environment_name(key), "{key}");
        }
    }
}
