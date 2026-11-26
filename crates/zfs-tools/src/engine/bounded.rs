//! Read-only native queries under one caller-set deadline for a whole
//! observation, and the pipe and child handling the effect runner shares.
//!
//! Every query of the observation shares one deadline, fixed when the
//! observation starts. It covers the spawn, both pipes reaching end of file,
//! the leader's exit and the caller's use of the output: the clock is checked
//! again before a query's output is accepted and before the observation's
//! result is returned. Pipes are read on the calling thread with `poll`, one
//! bounded read per ready pipe per wakeup, so neither a busy writer nor a
//! descendant that keeps a pipe open can hold the caller past the deadline,
//! and no reader thread can outlive a query. A query's stdout is capped.
//!
//! The leader is waited for with `WNOWAIT` and reaped only at the end, so
//! until then its PID still names its process group. That needs the process
//! to keep its children waitable: a bounded run refuses when SIGCHLD is
//! ignored or `SA_NOCLDWAIT` is set, and nothing is ever signalled once the
//! leader is not known to be this process's unreaped child. Callers must not
//! reap the library's children themselves (`waitpid(-1)` and the like).
//!
//! On a stop the group is sent SIGKILL and the leader reaped within a grace.
//! That proves the leader gone, not the group's other members: a member that
//! moved to another group is not reached. A leader that is not reaped is kept
//! here and reaped by a later bounded query or effect dispatch, never dropped. Output of a query
//! that did not finish is discarded, and once an observation stopped every
//! later query of it is refused without a spawn.
//!
//! The `-v` announcement is written to the caller's stderr before each spawn;
//! its time counts against the deadline, but a blocked stderr is not
//! interrupted. zboot and zsnap's own reads use `native::run`, which has no
//! deadline.
use crate::engine::{Error, native::announced};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
};
use std::{
    io::Read,
    os::unix::process::CommandExt,
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

/// How long a killed query's leader may take to be reaped.
pub(crate) const REAP_GRACE: Duration = Duration::from_secs(10);
pub(crate) const STDERR_LIMIT: usize = 64 * 1024;
/// The most standard output one bounded query may produce: 64 MiB. Parsing
/// allocates rows and fields well beyond the raw bytes; a host with tens of
/// thousands of snapshots emits a few MiB.
pub const MAX_QUERY_OUTPUT: usize = 64 << 20;
pub(crate) const POLL: Duration = Duration::from_millis(10);
/// The longest single `poll`; a longer deadline is waited for in steps.
const MAX_WAIT: Duration = Duration::from_secs(3600);
/// One read per ready pipe per wakeup.
const READ: usize = 16 * 1024;

/// Children a stop signalled but could not reap within its grace. The library
/// owns them until a later bounded query or effect dispatch reaps them.
static LATE: Mutex<Vec<Child>> = Mutex::new(Vec::new());

/// Whether a child is still ours to wait for after `try_wait`: only its reap
/// or ECHILD (it is no longer our child) ends that; a transient error does not.
pub(crate) fn still_owned(waited: &std::io::Result<Option<ExitStatus>>) -> bool {
    match waited {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(error) => error.raw_os_error() != Some(libc::ECHILD),
    }
}

/// Reap every late child that has ended. Returns how many are still kept.
pub(crate) fn reap_late() -> usize {
    let mut late = LATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    late.retain_mut(|child| still_owned(&child.try_wait()));
    late.len()
}

pub(crate) fn keep_late(child: Child) {
    LATE.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(child);
}

/// Kill a late child through its owned handle (tests only).
#[cfg(test)]
pub(crate) fn kill_late(pid: u32) {
    let mut late = LATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let child = late.iter_mut().find(|child| child.id() == pid).unwrap();
    child.kill().unwrap();
}

#[cfg(test)]
pub(crate) fn late_pids() -> Vec<u32> {
    let late = LATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    late.iter().map(Child::id).collect()
}

/// Whether this process keeps its children waitable. With SIGCHLD ignored or
/// `SA_NOCLDWAIT` set the kernel reaps them at exit, so a leader's PID could
/// be reused before the library signals its group.
#[allow(unsafe_code, reason = "querying a signal disposition")]
pub(crate) fn children_waitable() -> Result<(), String> {
    // SAFETY: an all-zero `sigaction` is a valid out-parameter, and a null new
    // action only reads the current disposition.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current) } != 0 {
        return Err(format!(
            "querying SIGCHLD failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if current.sa_sigaction == libc::SIG_IGN || current.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(
            "SIGCHLD is ignored or SA_NOCLDWAIT is set, so this process's children \
                    are reaped without it and their PIDs cannot be kept from reuse"
                .into(),
        );
    }
    Ok(())
}

/// Why an observation stopped without a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cause {
    Deadline,
    OutputLimit,
    /// Reading a pipe or waiting for the leader failed.
    Failed,
    NotWaitable,
}

/// What a stop established about the query it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cleanup {
    /// No query was running; nothing was signalled.
    NoneRunning,
    /// SIGKILL was sent to the group and the leader reaped.
    LeaderReaped,
    /// The signal or the reap could not be confirmed.
    Unconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stopped {
    pub(crate) cause: Cause,
    pub(crate) cleanup: Cleanup,
    pub(crate) detail: String,
}

/// One observation's queries under one deadline.
pub(crate) struct Query {
    within: Duration,
    until: Instant,
    grace: Duration,
    signal: Signal,
    output_limit: usize,
    hooks: Hooks,
    stopped: Option<Stopped>,
}

/// Test stand-ins for a caller descheduled at a bad moment and for a failed
/// wait; production compiles to a zero-sized no-op.
#[derive(Debug, Clone, Copy, Default)]
struct Hooks {
    #[cfg(test)]
    pause_after_announce: Duration,
    #[cfg(test)]
    pause_after_exit: Duration,
    #[cfg(test)]
    fail_after_exit: bool,
}
impl Hooks {
    #[inline]
    fn after_announce(self) {
        #[cfg(test)]
        if !self.pause_after_announce.is_zero() {
            thread::sleep(self.pause_after_announce);
        }
    }
    #[inline]
    fn after_exit(self) -> Result<(), Stop> {
        #[cfg(test)]
        {
            if !self.pause_after_exit.is_zero() {
                thread::sleep(self.pause_after_exit);
            }
            if self.fail_after_exit {
                return Err(Stop::Broken("waiting for the child failed (test)".into()));
            }
        }
        Ok(())
    }
}

impl Query {
    /// Start an observation that must finish `within` from now.
    pub(crate) fn new(within: Duration) -> Self {
        let now = Instant::now();
        Self {
            within,
            until: now
                .checked_add(within)
                .unwrap_or_else(|| now + Duration::from_secs(u64::from(u32::MAX))),
            grace: REAP_GRACE,
            signal: Signal::KILL,
            output_limit: MAX_QUERY_OUTPUT,
            hooks: Hooks::default(),
            stopped: None,
        }
    }

    #[cfg(test)]
    fn with_reap(mut self, grace: Duration, signal: Signal) -> Self {
        self.grace = grace;
        self.signal = signal;
        self
    }
    #[cfg(test)]
    fn with_output_limit(mut self, limit: usize) -> Self {
        self.output_limit = limit;
        self
    }
    #[cfg(test)]
    fn pausing_after_exit(mut self, pause: Duration) -> Self {
        self.hooks.pause_after_exit = pause;
        self
    }
    #[cfg(test)]
    fn pausing_after_announce(mut self, pause: Duration) -> Self {
        self.hooks.pause_after_announce = pause;
        self
    }
    #[cfg(test)]
    fn failing_after_exit(mut self) -> Self {
        self.hooks.fail_after_exit = true;
        self
    }

    /// Why this observation stopped, if it did.
    pub(crate) fn stopped(&self) -> Option<&Stopped> {
        self.stopped.as_ref()
    }

    /// Record a stop unless the observation finished in time: called with
    /// the observation's result in hand, so a result that took too long to
    /// produce is not returned.
    pub(crate) fn check_finished(&mut self) {
        if self.stopped.is_none() && Instant::now() >= self.until {
            self.stopped = Some(Stopped {
                cause: Cause::Deadline,
                cleanup: Cleanup::NoneRunning,
                detail: format!(
                    "the observation's {:?} deadline passed while no query was running",
                    self.within
                ),
            });
        }
    }

    /// Run one read-only query; its stdout only when it exited 0 with both
    /// pipes complete before the deadline.
    pub(crate) fn run(&mut self, program: &'static str, args: &[String]) -> Result<String, Error> {
        let failure = |detail: String| Error::Command {
            program,
            args: args.to_vec(),
            detail,
        };
        if let Some(stopped) = &self.stopped {
            return Err(failure(format!("not started: {}", stopped.detail)));
        }
        if let Err(why) = children_waitable() {
            let error = failure(why.clone());
            self.stopped = Some(Stopped {
                cause: Cause::NotWaitable,
                cleanup: Cleanup::NoneRunning,
                detail: why,
            });
            return Err(error);
        }
        reap_late();
        self.check_finished();
        if let Some(stopped) = &self.stopped {
            return Err(failure(format!(
                "{program} not started: {}",
                stopped.detail
            )));
        }
        let mut command = Command::new(program);
        command
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let launch = announced(&mut command);
        self.hooks.after_announce();
        // The announcement may have blocked on the caller's stderr.
        self.check_finished();
        if let Some(stopped) = &self.stopped {
            return Err(failure(format!(
                "{program} not started: {}",
                stopped.detail
            )));
        }
        let mut child = launch.spawn().map_err(|error| failure(error.to_string()))?;
        let (stdout, stderr) = match collect(&mut child, self.until, self.output_limit, self.hooks)
        {
            Ok(output) => output,
            Err(stop) => {
                let (cause, why) = match stop {
                    Stop::Deadline(why) => (Cause::Deadline, why.to_string()),
                    Stop::Output => (
                        Cause::OutputLimit,
                        format!(
                            "{program} wrote more than {} bytes of output",
                            self.output_limit
                        ),
                    ),
                    Stop::Broken(why) => (Cause::Failed, why),
                };
                let why = match cause {
                    Cause::Deadline => format!(
                        "{program} {why} the observation's {:?} deadline",
                        self.within
                    ),
                    _ => why,
                };
                let ended = terminate(child, self.grace, self.signal);
                let detail = format!("{why}; {}", ended.detail);
                // Recorded whatever the cause, so the observation reports
                // what the cleanup established, not a later clock check.
                self.stopped = Some(Stopped {
                    cause,
                    cleanup: ended.cleanup,
                    detail: detail.clone(),
                });
                return Err(failure(detail));
            }
        };
        let status = reap_exited(child, program).map_err(failure)?;
        finish(status, stdout, stderr).map_err(failure)
    }
}

/// Collect the status of an already-exited, unreaped leader. If reaping fails
/// while the child is still ours, keep it in `LATE` so a later run can reap it.
pub(crate) fn reap_exited(mut child: Child, program: &str) -> Result<ExitStatus, String> {
    match child.try_wait() {
        Ok(Some(status)) => Ok(status),
        other => {
            let detail = format!("{program} exited, but its reap failed: {other:?}");
            if still_owned(&other) {
                keep_late(child);
            }
            Err(detail)
        }
    }
}

fn finish(status: ExitStatus, stdout: Vec<u8>, stderr: Vec<u8>) -> Result<String, String> {
    if !status.success() {
        return Err(format!(
            "{status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    String::from_utf8(stdout).map_err(|error| format!("stdout is not UTF-8: {error}"))
}

enum Stop {
    /// How the query stood at the deadline ("was still running at", ...).
    Deadline(&'static str),
    Output,
    Broken(String),
}

/// Read both pipes to end of file, then wait (without reaping) for the leader
/// to exit, all before `until`; the clock is checked once more after the exit.
fn collect(
    child: &mut Child,
    until: Instant,
    output_limit: usize,
    hooks: Hooks,
) -> Result<(Vec<u8>, Vec<u8>), Stop> {
    let running = || Stop::Deadline("was still running at");
    let mut pipes = Pipes::take(child, Some(output_limit)).map_err(Stop::Broken)?;
    while pipes.open() {
        let left = left_duration(until).ok_or_else(running)?;
        match pipes.pump(left) {
            Ok(()) => {}
            Err(Pump::Output) => return Err(Stop::Output),
            Err(Pump::Broken(why)) => return Err(Stop::Broken(why)),
        }
    }
    loop {
        if exited(child).map_err(Stop::Broken)? {
            hooks.after_exit()?;
            if left_duration(until).is_none() {
                return Err(Stop::Deadline("exited after"));
            }
            return Ok((pipes.out, pipes.err));
        }
        thread::sleep(POLL.min(left_duration(until).ok_or_else(running)?));
    }
}

/// Time left before `until`, or `None` once it passed.
fn left_duration(until: Instant) -> Option<Duration> {
    let left = until.saturating_duration_since(Instant::now());
    (!left.is_zero()).then(|| left.min(MAX_WAIT))
}

/// Whether the leader has exited, leaving it unreaped (`WNOWAIT`), so its PID
/// keeps naming its process group until the caller reaps it. An error
/// (ECHILD included) means it is not known to be waitable.
pub(crate) fn exited(child: &Child) -> Result<bool, String> {
    loop {
        match waitable(child) {
            Err(Errno::INTR) => {}
            Ok(found) => return Ok(found),
            Err(error) => return Err(format!("waiting for the child to exit failed: {error}")),
        }
    }
}

/// `Ok(exited)` while the child is this process's unreaped child.
fn waitable(child: &Child) -> Result<bool, Errno> {
    let pid = i32::try_from(child.id())
        .ok()
        .and_then(Pid::from_raw)
        .ok_or(Errno::INVAL)?;
    waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map(|found| found.is_some())
}

pub(crate) enum Pump {
    /// Kept stdout would exceed its limit.
    Output,
    Broken(String),
}

/// A child's stdout and stderr, read on the calling thread: no reader thread
/// or descriptor outlives the owner, which closes both when dropped. Stderr
/// keeps its first 64 KiB; stdout is kept, up to its limit, only when asked.
pub(crate) struct Pipes {
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    stdout_limit: Option<usize>,
    pub(crate) out: Vec<u8>,
    pub(crate) err: Vec<u8>,
}
impl Pipes {
    pub(crate) fn take(child: &mut Child, stdout_limit: Option<usize>) -> Result<Self, String> {
        let pipes = Self {
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            stdout_limit,
            out: Vec::new(),
            err: Vec::new(),
        };
        for fd in [
            pipes.stdout.as_ref().map(rustix::fd::AsFd::as_fd),
            pipes.stderr.as_ref().map(rustix::fd::AsFd::as_fd),
        ]
        .into_iter()
        .flatten()
        {
            rustix::io::ioctl_fionbio(fd, true)
                .map_err(|e| format!("making a pipe nonblocking failed: {e}"))?;
        }
        Ok(pipes)
    }
    /// Whether either pipe has not reached end of file.
    pub(crate) fn open(&self) -> bool {
        self.stdout.is_some() || self.stderr.is_some()
    }
    /// Whether stderr reached end of file or its bound.
    pub(crate) fn stderr_complete(&self) -> bool {
        self.stderr.is_none() || self.err.len() >= STDERR_LIMIT
    }
    /// Wait up to `wait` for output, then make at most one read from each
    /// ready pipe, so one call takes about `wait` whatever the writers do.
    pub(crate) fn pump(&mut self, wait: Duration) -> Result<(), Pump> {
        if !self.open() {
            thread::sleep(wait);
            return Ok(());
        }
        let timeout = Timespec::try_from(wait.min(MAX_WAIT))
            .map_err(|e| Pump::Broken(format!("converting the deadline failed: {e}")))?;
        let poll_pipes = |fds: &mut [PollFd<'_>]| match poll(fds, Some(&timeout)) {
            Ok(_) | Err(Errno::INTR) => Ok(()),
            Err(error) => Err(Pump::Broken(format!("waiting for output failed: {error}"))),
        };
        let (stdout_ready, stderr_ready) = match (&self.stdout, &self.stderr) {
            (Some(out), Some(err)) => {
                let mut fds = [
                    PollFd::new(out, PollFlags::IN),
                    PollFd::new(err, PollFlags::IN),
                ];
                poll_pipes(&mut fds)?;
                (!fds[0].revents().is_empty(), !fds[1].revents().is_empty())
            }
            (Some(out), None) => {
                let mut fds = [PollFd::new(out, PollFlags::IN)];
                poll_pipes(&mut fds)?;
                (!fds[0].revents().is_empty(), false)
            }
            (None, Some(err)) => {
                let mut fds = [PollFd::new(err, PollFlags::IN)];
                poll_pipes(&mut fds)?;
                (false, !fds[0].revents().is_empty())
            }
            (None, None) => (false, false),
        };
        let mut buffer = [0u8; READ];
        if stdout_ready {
            let bytes = read_once(&mut self.stdout, &mut buffer)?;
            if let Some(limit) = self.stdout_limit {
                if self.out.len() + bytes.len() > limit {
                    return Err(Pump::Output);
                }
                self.out.extend_from_slice(bytes);
            }
        }
        if stderr_ready {
            let bytes = read_once(&mut self.stderr, &mut buffer)?;
            // Beyond the bound it is read and dropped, so the child never blocks on it.
            let room = STDERR_LIMIT.saturating_sub(self.err.len());
            self.err.extend_from_slice(&bytes[..bytes.len().min(room)]);
        }
        Ok(())
    }
}

/// One read; end of file closes the pipe. Nothing available is no bytes.
fn read_once<'b>(pipe: &mut Option<impl Read>, buffer: &'b mut [u8]) -> Result<&'b [u8], Pump> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(&[]);
    };
    match reader.read(buffer) {
        Ok(0) => {
            *pipe = None;
            Ok(&[])
        }
        Ok(n) => Ok(&buffer[..n]),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(&[])
        }
        Err(error) => Err(Pump::Broken(format!("reading output failed: {error}"))),
    }
}

/// What `terminate` established, and its account for an error message.
pub(crate) struct Termination {
    pub(crate) cleanup: Cleanup,
    pub(crate) detail: String,
}

/// Send `signal` to the unreaped leader's whole group, then reap the leader
/// within `grace`. Nothing is signalled unless the leader is known to be this
/// process's unreaped child, so its PID still names its group. A leader that
/// is not reaped is kept in `LATE`, unless it is no longer ours (ECHILD).
pub(crate) fn terminate(mut child: Child, grace: Duration, signal: Signal) -> Termination {
    let name = if signal == Signal::KILL {
        "SIGKILL"
    } else {
        "a signal"
    };
    if let Err(error) = waitable(&child) {
        let detail = if error == Errno::CHILD {
            "it is no longer this process's child (something else reaped it), \
             so nothing was signalled"
                .to_string()
        } else {
            keep_late(child);
            format!(
                "checking it is still this process's child failed: {error}, so nothing was \
                 signalled; it may still run, and the library keeps it to reap later"
            )
        };
        return Termination {
            cleanup: Cleanup::Unconfirmed,
            detail,
        };
    }
    let group = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
    let signalled = match group {
        Some(group) => kill_process_group(group, signal).map_err(|error| error.to_string()),
        None => Err("invalid process ID".into()),
    };
    let mut detail = match &signalled {
        Ok(()) => format!("{name} was sent to its process group"),
        Err(error) => {
            // The leader, still known to be ours, is killed directly.
            let leader = match child.kill() {
                Ok(()) => "its leader was killed".to_string(),
                Err(error) => format!("killing its leader failed: {error}"),
            };
            format!("signalling its process group failed: {error}; {leader}")
        }
    };
    let started = Instant::now();
    let reaped = loop {
        let waited = child.try_wait();
        match &waited {
            Ok(Some(_)) => break Ok(()),
            Ok(None) if started.elapsed() < grace => thread::sleep(POLL),
            Ok(None) => break Err((format!("its leader was not reaped within {grace:?}"), true)),
            Err(error) => {
                break Err((
                    format!("reaping its leader failed: {error}"),
                    still_owned(&waited),
                ));
            }
        }
    };
    let cleanup = match reaped {
        Ok(()) if signalled.is_ok() => {
            detail.push_str(" and its leader reaped");
            Cleanup::LeaderReaped
        }
        Ok(()) => {
            detail.push_str("; its leader was reaped, but other members may still run");
            Cleanup::Unconfirmed
        }
        Err((problem, owned)) => {
            if owned {
                detail.push_str(&format!(
                    "; {problem}; it may still run, and the library keeps it to reap later"
                ));
                keep_late(child);
            } else {
                detail.push_str(&format!(
                    "; {problem}; it is no longer this process's child"
                ));
            }
            Cleanup::Unconfirmed
        }
    };
    Termination { cleanup, detail }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zfs-tools-bounded-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn sh(script: &str) -> Vec<String> {
        vec!["-c".into(), script.into(), "zfs-tools-bounded-test".into()]
    }
    fn command_detail(result: Result<String, Error>) -> String {
        match result {
            Err(Error::Command {
                program: "/bin/sh",
                detail,
                ..
            }) => detail,
            other => panic!("{other:?}"),
        }
    }
    /// A process this test made, read from its PID file.
    fn pid_in(file: &Path) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(text) = std::fs::read_to_string(file)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            assert!(Instant::now() < deadline, "no pid in {}", file.display());
            thread::sleep(Duration::from_millis(10));
        }
    }
    /// Gone, or a zombie its new parent has not yet reaped: either way killed.
    fn ended(pid: i32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(_) => return true,
                Ok(stat) => {
                    let state = stat.rsplit_once(") ").map(|(_, rest)| &rest[..1]);
                    if state == Some("Z") {
                        return true;
                    }
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }
    fn stopped(query: &Query) -> Option<(Cause, Cleanup)> {
        query.stopped().map(|s| (s.cause, s.cleanup))
    }
    const KILLED: &str = "SIGKILL was sent to its process group and its leader reaped";

    #[test]
    fn a_query_that_finishes_returns_its_exact_output_and_status() {
        let mut query = Query::new(Duration::from_secs(10));
        assert_eq!(
            query.run("/bin/sh", &sh("printf 'a\\tb\\n'; echo noise >&2")),
            Ok("a\tb\n".to_string())
        );
        assert_eq!(
            command_detail(query.run("/bin/sh", &sh("echo bad >&2; exit 3"))),
            "exit status: 3: bad"
        );
        // Large output on both pipes completes without a reader thread.
        let big = query
            .run(
                "/bin/sh",
                &sh("head -c 300000 /dev/zero | tr '\\0' x; head -c 300000 /dev/zero >&2"),
            )
            .unwrap();
        assert_eq!(big.len(), 300_000);
        query.check_finished();
        assert_eq!(query.stopped(), None);
    }

    #[test]
    fn a_descendant_holding_the_pipe_is_killed_with_the_group_and_output_discarded() {
        let dir = dir();
        let pidfile = dir.join("descendant");
        // The leader prints a partial result and exits at once; its background
        // child keeps stdout open.
        let script = format!("sleep 30 & echo $! > {}; echo partial", pidfile.display());
        let mut query = Query::new(Duration::from_millis(300));
        let started = Instant::now();
        let detail = command_detail(query.run("/bin/sh", &sh(&script)));
        assert!(started.elapsed() < Duration::from_secs(5));
        let expected =
            format!("/bin/sh was still running at the observation's 300ms deadline; {KILLED}");
        assert_eq!(detail, expected);
        assert_eq!(
            query.stopped(),
            Some(&Stopped {
                cause: Cause::Deadline,
                cleanup: Cleanup::LeaderReaped,
                detail: expected.clone()
            })
        );
        assert!(ended(pid_in(&pidfile)), "the descendant was killed");
        // Every later query of this observation is refused without a spawn.
        let marker = dir.join("marker");
        let refused =
            command_detail(query.run("/bin/sh", &sh(&format!("touch {}", marker.display()))));
        assert_eq!(refused, format!("not started: {expected}"));
        assert!(!marker.exists());
    }

    #[test]
    fn a_leader_that_never_exits_is_killed_and_reaped() {
        let dir = dir();
        let pidfile = dir.join("leader");
        let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
        let mut query = Query::new(Duration::from_millis(300));
        let detail = command_detail(query.run("/bin/sh", &sh(&script)));
        assert_eq!(
            detail,
            format!("/bin/sh was still running at the observation's 300ms deadline; {KILLED}")
        );
        let leader = pid_in(&pidfile);
        assert!(!Path::new(&format!("/proc/{leader}")).exists(), "reaped");
    }

    #[test]
    fn a_busy_writer_cannot_hold_the_caller_past_the_deadline() {
        // `yes` never stops writing; stderr past its bound is read and dropped.
        let mut query = Query::new(Duration::from_millis(300));
        let started = Instant::now();
        let detail = command_detail(query.run("/bin/sh", &sh("exec yes >&2")));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            detail,
            format!("/bin/sh was still running at the observation's 300ms deadline; {KILLED}")
        );
        assert_eq!(
            stopped(&query),
            Some((Cause::Deadline, Cleanup::LeaderReaped))
        );
    }

    #[test]
    fn stdout_beyond_its_limit_is_a_typed_stop_never_a_truncated_result() {
        let mut query = Query::new(Duration::from_secs(10)).with_output_limit(1000);
        assert_eq!(
            query.run("/bin/sh", &sh("head -c 1000 /dev/zero | tr '\\0' x")),
            Ok("x".repeat(1000))
        );
        let detail = command_detail(query.run("/bin/sh", &sh("head -c 5000 /dev/zero")));
        assert_eq!(
            detail,
            format!("/bin/sh wrote more than 1000 bytes of output; {KILLED}")
        );
        assert_eq!(
            stopped(&query),
            Some((Cause::OutputLimit, Cleanup::LeaderReaped))
        );
    }

    #[test]
    fn an_exit_seen_after_the_deadline_is_not_accepted() {
        let mut query =
            Query::new(Duration::from_millis(200)).pausing_after_exit(Duration::from_millis(300));
        let detail = command_detail(query.run("/bin/sh", &sh("echo row")));
        assert_eq!(
            detail,
            format!("/bin/sh exited after the observation's 200ms deadline; {KILLED}")
        );
        assert_eq!(
            stopped(&query),
            Some((Cause::Deadline, Cleanup::LeaderReaped))
        );
    }

    #[test]
    fn a_deadline_passed_during_the_announcement_starts_nothing() {
        let dir = dir();
        let marker = dir.join("marker");
        let mut query = Query::new(Duration::from_millis(100))
            .pausing_after_announce(Duration::from_millis(150));
        let detail =
            command_detail(query.run("/bin/sh", &sh(&format!("touch {}", marker.display()))));
        assert_eq!(
            detail,
            "/bin/sh not started: the observation's 100ms deadline passed while no query was \
             running"
        );
        assert_eq!(
            stopped(&query),
            Some((Cause::Deadline, Cleanup::NoneRunning))
        );
        assert!(!marker.exists());
    }

    #[test]
    fn a_failed_query_keeps_its_cleanup_past_the_deadline() {
        let mut query = Query::new(Duration::from_millis(200)).failing_after_exit();
        let detail = command_detail(query.run("/bin/sh", &sh("echo row")));
        assert_eq!(
            detail,
            format!("waiting for the child failed (test); {KILLED}")
        );
        thread::sleep(Duration::from_millis(250));
        query.check_finished();
        assert_eq!(
            stopped(&query),
            Some((Cause::Failed, Cleanup::LeaderReaped))
        );
    }

    #[test]
    fn an_exhausted_deadline_starts_nothing_and_signals_nothing() {
        let dir = dir();
        let marker = dir.join("marker");
        let mut query = Query::new(Duration::from_nanos(1));
        thread::sleep(Duration::from_millis(5));
        let detail =
            command_detail(query.run("/bin/sh", &sh(&format!("touch {}", marker.display()))));
        assert_eq!(
            detail,
            "/bin/sh not started: the observation's 1ns deadline passed while no query was running"
        );
        assert_eq!(
            stopped(&query),
            Some((Cause::Deadline, Cleanup::NoneRunning))
        );
        assert!(!marker.exists());
        // A deadline that passes after the last query is caught at the end.
        let mut late = Query::new(Duration::from_millis(100));
        late.run("/bin/sh", &sh("exit 0")).unwrap();
        thread::sleep(Duration::from_millis(150));
        late.check_finished();
        assert_eq!(
            stopped(&late),
            Some((Cause::Deadline, Cleanup::NoneRunning))
        );
    }

    #[test]
    fn an_unreaped_leader_is_reported_and_kept_until_it_is_reaped() {
        let dir = dir();
        let pidfile = dir.join("leader");
        // TERM stands in for a kill that does not end the child in time.
        let script = format!(
            "trap '' TERM; echo $$ > {}; while :; do sleep 0.05; done",
            pidfile.display()
        );
        let mut query = Query::new(Duration::from_millis(300))
            .with_reap(Duration::from_millis(200), Signal::TERM);
        let detail = command_detail(query.run("/bin/sh", &sh(&script)));
        assert_eq!(
            detail,
            "/bin/sh was still running at the observation's 300ms deadline; \
             a signal was sent to its process group; its leader was not reaped within 200ms; \
             it may still run, and the library keeps it to reap later"
        );
        assert_eq!(
            stopped(&query),
            Some((Cause::Deadline, Cleanup::Unconfirmed))
        );
        let leader = pid_in(&pidfile);
        assert!(late_pids().contains(&(leader as u32)));
        // Once it ends, the next reap collects it.
        kill_late(leader as u32);
        let deadline = Instant::now() + Duration::from_secs(5);
        while late_pids().contains(&(leader as u32)) {
            assert!(Instant::now() < deadline, "late child was not reaped");
            reap_late();
            thread::sleep(Duration::from_millis(20));
        }
        assert!(!Path::new(&format!("/proc/{leader}")).exists());
    }

    #[test]
    fn a_late_child_is_kept_through_transient_errors_and_dropped_only_when_gone() {
        use std::io::Error as IoError;
        assert!(still_owned(&Ok(None)));
        assert!(still_owned(&Err(IoError::from_raw_os_error(libc::EINTR))));
        assert!(still_owned(&Err(IoError::from_raw_os_error(libc::EIO))));
        assert!(!still_owned(&Err(IoError::from_raw_os_error(libc::ECHILD))));
        let exited = Command::new("/bin/sh").args(sh("exit 0")).status().unwrap();
        assert!(!still_owned(&Ok(Some(exited))));
    }

    #[test]
    fn a_leader_reaped_elsewhere_is_never_signalled() {
        let mut child = Command::new("/bin/sh")
            .args(sh("exit 0"))
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id() as i32).unwrap();
        // Something other than `Child` reaps it, as an embedding application
        // calling waitpid(-1) would; its PID may now name anything.
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()).unwrap();
        assert_eq!(
            exited(&child),
            Err("waiting for the child to exit failed: No child processes (os error 10)".into())
        );
        let _ = child.stdout.take();
        let ended = terminate(child, REAP_GRACE, Signal::KILL);
        assert_eq!(ended.cleanup, Cleanup::Unconfirmed);
        assert_eq!(
            ended.detail,
            "it is no longer this process's child (something else reaped it), so nothing was \
             signalled"
        );
    }

    /// Rerun `test_name` in its own single-threaded process, ignore SIGCHLD,
    /// run `body`, and restore `SIG_DFL` even on panic.
    #[allow(unsafe_code, reason = "setting SIGCHLD in an isolated test process")]
    pub(crate) fn run_with_ignored_sigchld(env_key: &str, test_name: &str, body: impl FnOnce()) {
        if std::env::var_os(env_key).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([test_name, "--exact", "--test-threads=1"])
                .env(env_key, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "{stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let passed = format!("test {test_name} ... ok");
            assert_eq!(
                stdout.lines().filter(|l| *l == passed).count(),
                1,
                "{stdout}"
            );
            return;
        }
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                // SAFETY: this process runs only this test, on one thread.
                unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
            }
        }
        assert_eq!(children_waitable(), Ok(()));
        // SAFETY: this process runs only this test, on one thread.
        unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
        let _restore = Restore;
        body();
        drop(_restore);
        assert_eq!(children_waitable(), Ok(()));
    }

    const ISOLATED: &str = "ZFS_TOOLS_BOUNDED_ISOLATED";
    const IGNORED: &str = "engine::bounded::tests::ignored_sigchld_refuses_before_any_spawn";

    /// Changing SIGCHLD is process-wide, so the test binary reruns just this
    /// test in a process of its own.
    #[test]
    fn ignored_sigchld_refuses_before_any_spawn() {
        run_with_ignored_sigchld(ISOLATED, IGNORED, || {
            let why = "SIGCHLD is ignored or SA_NOCLDWAIT is set, so this process's children are \
                       reaped without it and their PIDs cannot be kept from reuse";
            assert_eq!(children_waitable(), Err(why.into()));
            let marker = dir().join("marker");
            let mut query = Query::new(Duration::from_secs(10));
            let detail =
                command_detail(query.run("/bin/sh", &sh(&format!("touch {}", marker.display()))));
            assert_eq!(detail, why);
            assert_eq!(
                stopped(&query),
                Some((Cause::NotWaitable, Cleanup::NoneRunning))
            );
            assert!(!marker.exists());
        });
    }
}
