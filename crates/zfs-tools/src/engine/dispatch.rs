//! One native effect child under a writer session's own lock.
//!
//! The child inherits the session's flock open-file description directly, not
//! a thread-local custody stack, so it holds the critical section on any
//! thread and after its caller dies. It runs in its own process group: a
//! deadline kills the whole group and waits for the reap, and a reap that
//! cannot be confirmed is reported as such so the session can stop
//! dispatching. Its pipes are read on the calling thread (`bounded::Pipes`),
//! one bounded read per ready pipe per wakeup, and the leader is waited for
//! unreaped until it exits, so neither a busy writer nor a descendant that
//! keeps a pipe open can hold the caller past the deadline or leave a reader
//! thread or descriptor behind; after the exit, stderr gets two seconds to
//! complete or is reported unavailable. Like a bounded query, nothing runs
//! while SIGCHLD is ignored, and nothing is signalled once the leader is not
//! known to be this process's unreaped child. A stop short of a confirmed
//! group kill and leader reap is `Unreaped`, and an unreaped leader stays
//! owned by the library.
use crate::engine::{
    bounded::{self, POLL, Pipes},
    effect,
    lock::WriterLock,
    native::announced,
};
use rustix::process::Signal;
use std::{
    io::Write,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) use crate::engine::bounded::REAP_GRACE;
/// The largest standard input an effect takes: one atomic pipe write, so the
/// write never blocks on a child that does not read.
pub(crate) const MAX_INPUT: usize = 4096;
/// How long the readers may take after the child exits. A descendant that
/// kept a pipe open only loses its diagnostics.
const DRAIN: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ran {
    /// No child ran: custody or the launch failed before any effect.
    NotStarted(String),
    /// The child exited with this status.
    Exited { code: i32, stderr: String },
    /// The child ran and was reaped, but its outcome is unknown.
    Uncertain(String),
    /// The child may still be running and holding the lock.
    Unreaped(String),
}

/// Run `program` with `args` as a child that holds `held`'s lock.
pub(crate) fn run_in_custody(
    held: &WriterLock,
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    deadline: Duration,
    reap_grace: Duration,
) -> Ran {
    run_with(
        held,
        program,
        args,
        input,
        deadline,
        reap_grace,
        Signal::KILL,
    )
}

/// `run_in_custody` with the signal a stop sends; tests use one that the
/// child ignores to stand in for a kill that does not end it in time.
fn run_with(
    held: &WriterLock,
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    deadline: Duration,
    reap_grace: Duration,
    signal: Signal,
) -> Ran {
    if input.is_some_and(|bytes| bytes.len() > MAX_INPUT) {
        return Ran::NotStarted("effect input exceeds its bound".into());
    }
    // The group kill relies on the leader staying this process's child.
    if let Err(why) = bounded::children_waitable() {
        return Ran::NotStarted(why);
    }
    bounded::reap_late();
    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Err(error) = held.inherit_for(&mut command) {
        return Ran::NotStarted(format!("writer lock custody unavailable: {error}"));
    }
    let spawned = announced(&mut command).spawn();
    // The command owns a duplicate of the lock until it is dropped.
    drop(command);
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return Ran::NotStarted(error.to_string()),
    };
    effect::mark();
    let started = Instant::now();
    // Output is read on this thread, so a descendant that keeps a pipe open
    // can leave no reader thread or descriptor behind. A pipe that cannot be
    // read only loses the diagnostics; the child is still waited for.
    let (mut pipes, mut lost) = match Pipes::take(&mut child, None) {
        Ok(pipes) => (Some(pipes), false),
        Err(_) => (None, true),
    };
    let mut problem = None;
    if let Some(bytes) = input {
        match child.stdin.take() {
            Some(mut stdin) => {
                if let Err(error) = stdin.write_all(bytes) {
                    problem = Some(format!("input delivery failed: {error}"));
                }
            }
            None => problem = Some("input pipe unavailable".into()),
        }
    }
    let pump = |pipes: &mut Option<Pipes>, lost: &mut bool, wait: Duration| match pipes {
        Some(open) => {
            if open.pump(wait).is_err() {
                *pipes = None;
                *lost = true;
            }
        }
        None => thread::sleep(wait),
    };
    // The leader is waited for unreaped, so until the reap its PID still
    // names its group for the kill.
    loop {
        match bounded::exited(&child) {
            Ok(true) => break,
            Ok(false) if started.elapsed() < deadline => {
                let wait = POLL.min(deadline.saturating_sub(started.elapsed()));
                pump(&mut pipes, &mut lost, wait);
            }
            Ok(false) => {
                return stop(
                    child,
                    format!("{program} exceeded its {deadline:?} deadline"),
                    reap_grace,
                    signal,
                );
            }
            Err(error) => {
                return stop(
                    child,
                    format!("{program} status unavailable: {error}"),
                    reap_grace,
                    signal,
                );
            }
        }
    }
    // A descendant that kept stderr open only loses the diagnostics.
    let drained = Instant::now();
    while pipes.as_ref().is_some_and(|open| !open.stderr_complete()) {
        let left = DRAIN.saturating_sub(drained.elapsed());
        if left.is_zero() {
            lost = true;
            break;
        }
        pump(&mut pipes, &mut lost, left);
    }
    let stderr = match pipes.take() {
        Some(pipes) if !lost && pipes.stderr_complete() => {
            String::from_utf8_lossy(&pipes.err).trim().to_string()
        }
        _ => "(stderr unavailable)".into(),
    };
    // The leader has exited and is unreaped; this only collects its status.
    let status = match bounded::reap_exited(child, program) {
        Ok(status) => status,
        Err(why) => return Ran::Unreaped(why),
    };
    if let Some(problem) = problem {
        return Ran::Uncertain(format!(
            "{problem}; {program} then exited {status}: {stderr}"
        ));
    }
    match status.code() {
        Some(code) => Ran::Exited { code, stderr },
        None => Ran::Uncertain(format!("{program} ended without an exit code: {status}")),
    }
}

/// Kill the group and reap the leader. Anything short of a confirmed group
/// kill and reap may leave a member running with the lock: `Unreaped`, which
/// poisons the session. An unreaped leader stays owned by `bounded`'s late list.
fn stop(child: std::process::Child, why: String, grace: Duration, signal: Signal) -> Ran {
    let ended = bounded::terminate(child, grace, signal);
    let why = format!("{why}; {}", ended.detail);
    match ended.cleanup {
        bounded::Cleanup::LeaderReaped => Ran::Uncertain(why),
        bounded::Cleanup::NoneRunning | bounded::Cleanup::Unconfirmed => Ran::Unreaped(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        bounded::STDERR_LIMIT,
        lock::{LockError, WriterLock},
    };
    use std::path::{Path, PathBuf};

    fn lock_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zfs-tools-dispatch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("writer.lock")
    }
    fn sh(script: &str) -> Vec<String> {
        vec!["-c".into(), script.into(), "zfs-tools-dispatch-test".into()]
    }
    fn busy(path: &Path) -> bool {
        matches!(
            WriterLock::acquire_at(path, "probe", Duration::ZERO, |_| {}),
            Err(LockError::Busy { .. })
        )
    }
    /// A forked test's CLOEXEC copy can linger until its exec.
    fn eventually_free(path: &Path) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !busy(path) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn exit_status_and_stderr_are_reported() {
        let path = lock_path();
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh("echo out; echo bad >&2; exit 3"),
            None,
            Duration::from_secs(10),
            REAP_GRACE,
        );
        assert_eq!(
            ran,
            Ran::Exited {
                code: 3,
                stderr: "bad".into()
            }
        );
        let ok = run_in_custody(
            &held,
            "/bin/sh",
            &sh("exit 0"),
            None,
            Duration::from_secs(10),
            REAP_GRACE,
        );
        assert_eq!(
            ok,
            Ran::Exited {
                code: 0,
                stderr: String::new()
            }
        );
    }

    #[test]
    fn stderr_beyond_its_bound_is_drained_not_blocking() {
        let path = lock_path();
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh("head -c 300000 /dev/zero | tr '\\0' x >&2; exit 4"),
            None,
            Duration::from_secs(10),
            REAP_GRACE,
        );
        match ran {
            Ran::Exited { code: 4, stderr } => assert_eq!(stderr.len(), STDERR_LIMIT),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn input_reaches_standard_input_and_nothing_else_does() {
        let path = lock_path();
        let out = path.with_file_name("input");
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh(&format!("cat > {}", out.display())),
            Some(b"secret\n"),
            Duration::from_secs(10),
            REAP_GRACE,
        );
        assert_eq!(
            ran,
            Ran::Exited {
                code: 0,
                stderr: String::new()
            }
        );
        assert_eq!(std::fs::read(&out).unwrap(), b"secret\n");
        // Without input the child reads end of file at once.
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh(&format!("cat > {}", out.display())),
            None,
            Duration::from_secs(10),
            REAP_GRACE,
        );
        assert_eq!(
            ran,
            Ran::Exited {
                code: 0,
                stderr: String::new()
            }
        );
        assert!(std::fs::read(&out).unwrap().is_empty());
        let large = vec![b'x'; MAX_INPUT + 1];
        assert!(matches!(
            run_in_custody(
                &held,
                "/bin/sh",
                &sh("exit 0"),
                Some(&large),
                Duration::from_secs(10),
                REAP_GRACE
            ),
            Ran::NotStarted(_)
        ));
    }

    #[test]
    fn a_missing_program_is_not_an_effect() {
        let path = lock_path();
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        assert!(matches!(
            run_in_custody(
                &held,
                "/zfs-tools-missing-program",
                &[],
                None,
                Duration::from_secs(1),
                REAP_GRACE
            ),
            Ran::NotStarted(_)
        ));
        drop(held);
        assert!(eventually_free(&path));
    }

    #[test]
    fn the_child_and_its_descendants_hold_the_session_lock() {
        let path = lock_path();
        let ready = path.with_file_name("ready");
        let release = path.with_file_name("release");
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        // A background descendant outlives the dispatched child and the
        // session; it still holds the lock until it ends.
        let script = format!(
            "(while [ ! -e {release} ]; do sleep 0.05; done) >/dev/null 2>&1 & printf ready > {ready}",
            release = release.display(),
            ready = ready.display()
        );
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh(&script),
            None,
            Duration::from_secs(10),
            REAP_GRACE,
        );
        assert_eq!(
            ran,
            Ran::Exited {
                code: 0,
                stderr: String::new()
            }
        );
        assert!(ready.exists());
        drop(held);
        assert!(busy(&path), "the descendant inherited the session's lock");
        std::fs::write(&release, "").unwrap();
        assert!(eventually_free(&path));
    }

    #[test]
    fn a_deadline_kills_the_whole_group_and_reaps_it() {
        let path = lock_path();
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        let started = Instant::now();
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh("sleep 30 >/dev/null 2>&1 & sleep 30"),
            None,
            Duration::from_millis(300),
            REAP_GRACE,
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(
            ran,
            Ran::Uncertain(
                "/bin/sh exceeded its 300ms deadline; SIGKILL was sent to its process group and its leader reaped"
                    .into()
            )
        );
        drop(held);
        // The background sleep was in the group: nothing holds the lock now.
        assert!(eventually_free(&path));
    }

    fn entries(dir: &str) -> usize {
        std::fs::read_dir(dir).unwrap().count()
    }

    const ISOLATED: &str = "ZFS_TOOLS_DISPATCH_ISOLATED";
    const PIPE_HOLDER: &str =
        "engine::dispatch::tests::a_descendant_holding_the_pipes_leaves_no_thread_or_descriptor";

    /// Counted alone: the test binary reruns just this test, single-threaded,
    /// so the descriptor and thread counts are its own.
    #[test]
    fn a_descendant_holding_the_pipes_leaves_no_thread_or_descriptor() {
        if std::env::var_os(ISOLATED).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([PIPE_HOLDER, "--exact", "--test-threads=1"])
                .env(ISOLATED, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "{stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let passed = format!("test {PIPE_HOLDER} ... ok");
            assert_eq!(
                stdout.lines().filter(|line| *line == passed).count(),
                1,
                "{stdout}"
            );
            return;
        }
        let path = lock_path();
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        let (fds, threads) = (entries("/proc/self/fd"), entries("/proc/self/task"));
        // The child exits at once; its background sleep keeps both pipes
        // past the drain grace, then ends by itself.
        let script = "sleep 3 & echo out; echo err >&2; exit 0";
        let started = Instant::now();
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh(script),
            None,
            Duration::from_secs(10),
            REAP_GRACE,
        );
        let elapsed = started.elapsed();
        assert_eq!(
            ran,
            Ran::Exited {
                code: 0,
                stderr: "(stderr unavailable)".into()
            }
        );
        assert!(elapsed >= DRAIN && elapsed < DRAIN + Duration::from_secs(3));
        assert_eq!(entries("/proc/self/fd"), fds, "no descriptor left behind");
        assert_eq!(entries("/proc/self/task"), threads, "no reader thread left");

        // At the deadline the whole group goes, the pipe holder included.
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh("sleep 30 & sleep 30"),
            None,
            Duration::from_millis(300),
            REAP_GRACE,
        );
        assert_eq!(
            ran,
            Ran::Uncertain(
                "/bin/sh exceeded its 300ms deadline; SIGKILL was sent to its process group and its leader reaped"
                    .into()
            )
        );
        assert_eq!(entries("/proc/self/fd"), fds, "no descriptor left behind");
        assert_eq!(entries("/proc/self/task"), threads, "no reader thread left");
        drop(held);
        // The first case's sleep holds the lock until it ends by itself.
        let until = Instant::now() + Duration::from_secs(5);
        while busy(&path) {
            assert!(Instant::now() < until, "something still holds the lock");
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn a_busy_writer_cannot_hold_the_effect_past_its_deadline() {
        let path = lock_path();
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        let started = Instant::now();
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh("exec yes"),
            None,
            Duration::from_millis(300),
            REAP_GRACE,
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            ran,
            Ran::Uncertain(
                "/bin/sh exceeded its 300ms deadline; SIGKILL was sent to its process group \
                 and its leader reaped"
                    .into()
            )
        );
        // A descendant writing without end after the exit costs only stderr.
        let started = Instant::now();
        let ran = run_in_custody(
            &held,
            "/bin/sh",
            &sh("yes & exit 0"),
            None,
            Duration::from_secs(10),
            REAP_GRACE,
        );
        let elapsed = started.elapsed();
        assert_eq!(
            ran,
            Ran::Exited {
                code: 0,
                stderr: "(stderr unavailable)".into()
            }
        );
        assert!(
            elapsed >= DRAIN && elapsed < DRAIN + Duration::from_secs(2),
            "{elapsed:?}"
        );
        // Once its pipes are closed the writer ends on EPIPE by itself.
    }

    #[test]
    fn an_unconfirmed_reap_is_unreaped_and_the_child_stays_owned() {
        let path = lock_path();
        let pidfile = path.with_file_name("leader");
        let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
        let script = format!(
            "trap '' TERM; echo $$ > {}; while :; do sleep 0.05; done",
            pidfile.display()
        );
        let ran = run_with(
            &held,
            "/bin/sh",
            &sh(&script),
            None,
            Duration::from_millis(300),
            Duration::from_millis(200),
            Signal::TERM,
        );
        assert_eq!(
            ran,
            Ran::Unreaped(
                "/bin/sh exceeded its 300ms deadline; a signal was sent to its process group; \
                 its leader was not reaped within 200ms; it may still run, and the library \
                 keeps it to reap later"
                    .into()
            )
        );
        let leader: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(bounded::late_pids().contains(&(leader as u32)));
        bounded::kill_late(leader as u32);
        let until = Instant::now() + Duration::from_secs(5);
        while bounded::late_pids().contains(&(leader as u32)) {
            assert!(Instant::now() < until, "the late child was not reaped");
            bounded::reap_late();
            thread::sleep(Duration::from_millis(20));
        }
        drop(held);
        assert!(eventually_free(&path));
    }

    const SIGCHLD_ISOLATED: &str = "ZFS_TOOLS_DISPATCH_SIGCHLD_ISOLATED";
    const SIGCHLD_IGNORED: &str = "engine::dispatch::tests::ignored_sigchld_starts_no_effect";

    /// SIGCHLD is process-wide: rerun just this test in its own process.
    #[test]
    fn ignored_sigchld_starts_no_effect() {
        bounded::tests::run_with_ignored_sigchld(SIGCHLD_ISOLATED, SIGCHLD_IGNORED, || {
            let path = lock_path();
            let marker = path.with_file_name("marker");
            let held = WriterLock::acquire_at(&path, "t", Duration::ZERO, |_| {}).unwrap();
            let ran = run_in_custody(
                &held,
                "/bin/sh",
                &sh(&format!("touch {}", marker.display())),
                None,
                Duration::from_secs(10),
                REAP_GRACE,
            );
            assert_eq!(
                ran,
                Ran::NotStarted(
                    "SIGCHLD is ignored or SA_NOCLDWAIT is set, so this process's children are \
                     reaped without it and their PIDs cannot be kept from reuse"
                        .into()
                )
            );
            assert!(!marker.exists());
        });
    }
}
