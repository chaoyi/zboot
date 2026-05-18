//! Shared subprocess helpers for `zfs` / `zpool` / arbitrary commands.
//!
//! **Trace policy:** mutating calls (`pub fn run`, `pub fn cmd`, `pub fn zfs`)
//! echo `+ prog arg1 arg2 ...` to stderr so the operator sees exactly what
//! ran and can reproduce by hand. Read-only calls (`pub fn capture`,
//! `*_capture`) do *not* trace — they're internal probing, not actions.
//!
//! Two shapes:
//! - `*_run` / `cmd` / `zfs` — fire-and-forget; failure → `Err`. Used for
//!   mutating `zfs set …` / `zpool set …` / `zfs clone …` etc. **Traces.**
//! - `*_capture` — capture stdout. Used for `zfs get …` / `zpool list …`
//!   that we then parse. **No trace.**
//!
//! The runtime path is `SystemRunner`. Tests that want to simulate
//! subprocess output can implement `Runner` themselves — but in this
//! codebase, runtime behavior is exercised by the e2e shell scripts
//! against real ZFS, not by mocked cargo tests. Pure-data parsing and
//! plan composition remain unit-testable without `Runner`.

use std::process::Command;

use anyhow::{Context, Result, anyhow};

/// Captured output of a single command invocation.
#[derive(Debug, Clone)]
pub struct RunOutput {
    pub rc: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Subprocess runner. The runtime impl shells out via `Command`. Tests
/// can substitute a fake to record the call list and feed canned output.
pub trait Runner {
    fn run(&mut self, prog: &str, args: &[&str]) -> Result<RunOutput>;
}

/// Real `Command::output()` runner. **Does not trace** — tracing is the
/// `pub fn run` wrapper's job, so read-only `capture` paths stay quiet.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, prog: &str, args: &[&str]) -> Result<RunOutput> {
        let out = Command::new(prog)
            .args(args)
            .output()
            .with_context(|| format!("spawning `{prog} {}`", args.join(" ")))?;
        Ok(RunOutput {
            rc: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Generic helpers (runner-parameterized — for verbs that thread a Runner
// through to keep their planning logic unit-testable).
// ---------------------------------------------------------------------------

/// Run a (mutating) command; trace `+ prog args` to stderr; return `()`
/// on success, `Err` (with stderr) on non-zero rc.
pub fn run<R: Runner + ?Sized>(r: &mut R, prog: &str, args: &[&str]) -> Result<()> {
    eprintln!("+ {prog} {}", args.join(" "));
    let out = r.run(prog, args)?;
    if out.rc != 0 {
        return Err(err_msg(prog, args, &out));
    }
    Ok(())
}

/// Run a (read-only) command; return captured stdout on success, `Err`
/// on non-zero rc. Does not trace.
pub fn capture<R: Runner + ?Sized>(r: &mut R, prog: &str, args: &[&str]) -> Result<String> {
    let out = r.run(prog, args)?;
    if out.rc != 0 {
        return Err(err_msg(prog, args, &out));
    }
    Ok(out.stdout)
}

fn err_msg(prog: &str, args: &[&str], out: &RunOutput) -> anyhow::Error {
    anyhow!(
        "`{prog} {}` exited rc={}: {}",
        args.join(" "),
        out.rc,
        out.stderr.trim()
    )
}

// ---------------------------------------------------------------------------
// Convenience entry points — runtime, no runner threading.
// ---------------------------------------------------------------------------

/// `zfs <args>` — fire-and-forget; failure → `Err`.
pub fn zfs(args: &[&str]) -> Result<()> {
    run(&mut SystemRunner, "zfs", args)
}

/// `zfs <args>` — capture stdout.
pub fn zfs_capture(args: &[&str]) -> Result<String> {
    capture(&mut SystemRunner, "zfs", args)
}

/// `zpool <args>` — capture stdout.
pub fn zpool_capture(args: &[&str]) -> Result<String> {
    capture(&mut SystemRunner, "zpool", args)
}

/// Arbitrary command — fire-and-forget.
pub fn cmd(prog: &str, args: &[&str]) -> Result<()> {
    run(&mut SystemRunner, prog, args)
}

/// Arbitrary command — capture stdout.
pub fn cmd_capture(prog: &str, args: &[&str]) -> Result<String> {
    capture(&mut SystemRunner, prog, args)
}
