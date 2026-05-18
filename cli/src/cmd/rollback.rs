//! `zboot rollback` — convenience composition: `fork <NAME> --from
//! <SNAP>` followed by `default <NAME>`.
//!
//! Per `DESIGN.md` § "CLI surface": *rollback is the one workflow shortcut
//! earned by frequency — mechanically `fork + default` with auto-generated BE
//! name.* This module is intentionally thin.
//!
//! ## Composition strategy: subprocess re-spawn
//!
//! `rollback` re-invokes the running `zboot` binary as `zboot fork ...` and
//! `zboot default ...`, rather than calling into `cmd::fork::run` /
//! `cmd::default::run` directly. Two reasons:
//!
//! 1. **Module isolation.** Importing `cmd::fork` / `cmd::default`
//!    internals would make this module fragile against their refactors.
//!    Re-spawning treats each verb as its own contract.
//! 2. **Behavioural fidelity.** A fresh subprocess re-runs each verb's full
//!    state-discovery + side-effect pipeline. No cross-call state caching
//!    to get wrong.
//!
//! The current executable's path comes from `std::env::current_exe()`. If
//! that probe fails we fall back to invoking `zboot` from `$PATH`.
//!
//! ## Failure semantics
//!
//! - **Fork failure** → don't switch; surface the fork error verbatim.
//! - **Switch failure post-fork** → log a `warning:` line to stderr noting
//!   the BE was created but not activated, and bubble the switch error. We
//!   do **not** auto-cleanup the half-applied state; per DESIGN.md
//!   "Operations idempotent; retry is recovery", the user re-runs
//!   `zboot default <NAME>` (or drops the BE).
//!
//! ## Default `--name`
//!
//! `rollback-<UTC-timestamp>` where the timestamp is RFC-3339-compact UTC
//! (`YYYYMMDDTHHMMSSZ`), mirroring `snapshot`'s default naming. The
//! compact form is filesystem- / ZFS-safe (no `:`) and lexicographically
//! sortable.
//!
//! ## Snapshot acceptance
//!
//! `--to <SNAP>` accepts *any* reachable snapshot, not just snapshots of the
//! currently-active BE. DESIGN.md doesn't restrict this — `fork` accepts
//! arbitrary snapshots, so `rollback` (which is a thin wrapper) inherits the
//! same surface. Practical use cases include rolling forward to a snapshot
//! taken on a sibling BE, or to a snapshot from a recovery import.
//!
//! ## Tests
//!
//! Pure-data unit tests cover the timestamp formatter and CLI-arg validation.
//! End-to-end behaviour (the actual `fork` + `default` chain across reboots)
//! is exercised by `scripts/lifecycle.sh`.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;

use zboot_core::SnapshotRef;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct RollbackArgs {
    /// Source snapshot (`dataset@snap`).
    #[arg(long)]
    pub to: String,
    /// New BE name. Default: `rollback-<UTC-timestamp>`.
    #[arg(long)]
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: &RollbackArgs, mut w: &mut dyn Write) -> Result<()> {
    // `&mut dyn Write` is itself Sized + Write (blanket impl), so `&mut w`
    // satisfies `&mut impl Write` on the internal helper. Avoids touching
    // the helper's signature, which would ripple through every test.
    run_with_spawner(args, &mut w, &SystemSpawner, &SystemClock)
}

// ---------------------------------------------------------------------------
// Internals — split out so unit tests can exercise the composition logic
// without re-spawning real `zboot fork` / `zboot default` subprocesses.
// ---------------------------------------------------------------------------

/// Result of running a sub-verb subprocess.
#[derive(Debug, Clone)]
struct SubResult {
    rc: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Abstraction over spawning sub-verbs (`zboot fork`, `zboot default`). Lets
/// cargo unit tests record the call sequence and inject fake outcomes.
trait Spawner {
    /// Run a sub-verb. `args` is the full argv tail (e.g.
    /// `["fork", "BE", "--from", "rpool/ROOT/be1@snap1"]`); the spawner
    /// resolves `zboot`'s own path.
    fn run(&self, args: &[&str]) -> Result<SubResult>;

    /// Emit a warning line. Tests record these instead of touching real stderr.
    fn warn(&self, msg: &str);
}

trait Clock {
    fn unix_secs(&self) -> u64;
}

struct SystemSpawner;

impl Spawner for SystemSpawner {
    fn run(&self, args: &[&str]) -> Result<SubResult> {
        let exe = current_zboot_exe();
        let out = Command::new(&exe)
            .args(args)
            .output()
            .with_context(|| format!("spawning `{} {}`", exe.display(), args.join(" ")))?;
        Ok(SubResult {
            rc: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    fn warn(&self, msg: &str) {
        eprintln!("{msg}");
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// Resolve the path to the current `zboot` executable.
///
/// Prefers `std::env::current_exe()` so a freshly-built binary in
/// `target/debug/` re-spawns itself, not a stale system install. Falls back
/// to bare `"zboot"` (resolved via `$PATH`) if the probe fails — rare on
/// linux, but keeps the verb usable in degraded environments.
fn current_zboot_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("zboot"))
}

fn run_with_spawner(
    args: &RollbackArgs,
    w: &mut impl Write,
    spawner: &dyn Spawner,
    clock: &dyn Clock,
) -> Result<()> {
    // ----- validation --------------------------------------------------------
    //
    // Catch malformed `--to` *before* spawning fork. `cmd::fork` would catch
    // it too, but a local check keeps the error text close to where the user
    // typed the bad value.
    if SnapshotRef::parse(&args.to).is_none() {
        bail!(
            "rollback: --to must be `<dataset>@<snapshot>` (got {:?})",
            args.to
        );
    }

    let be_name = args
        .name
        .clone()
        .unwrap_or_else(|| default_rollback_name(clock.unix_secs()));

    // Validate the BE name shape early. `cmd::fork` enforces the same rule;
    // we duplicate it here so an invalid `--name` fails before we spawn.
    validate_be_name(&be_name)?;

    writeln!(w, "rollback: forking {} from {}", be_name, args.to).context("write")?;

    // ----- fork --------------------------------------------------------------
    let fork_res = spawner
        .run(&["fork", &be_name, "--from", &args.to])
        .context("spawning `zboot fork`")?;

    // Forward sub-verb output verbatim so the user sees fork's per-bound-
    // dataset summary. stderr always forwarded so error chains aren't lost
    // when fork fails.
    w.write_all(&fork_res.stdout)
        .context("forwarding fork stdout")?;
    forward_stderr(&fork_res.stderr);

    if fork_res.rc != 0 {
        let stderr_text = String::from_utf8_lossy(&fork_res.stderr).into_owned();
        // Don't wrap the trimmed message in extra prose — the fork error
        // already explains itself (target-exists / orphaned-origin / etc.).
        return Err(anyhow!(
            "rollback: `zboot fork {} --from {}` failed rc={}: {}",
            be_name,
            args.to,
            fork_res.rc,
            stderr_text.trim()
        ));
    }

    // ----- switch ------------------------------------------------------------
    writeln!(w, "rollback: switching to {be_name}").context("write")?;
    let switch_res = spawner
        .run(&["default", &be_name])
        .context("spawning `zboot default`")?;

    w.write_all(&switch_res.stdout)
        .context("forwarding switch stdout")?;
    forward_stderr(&switch_res.stderr);

    if switch_res.rc != 0 {
        // The BE exists but isn't active. Surface the partial-state
        // condition explicitly so the user knows what to retry. Per
        // DESIGN.md "Operations idempotent; retry is recovery", the
        // canonical recovery is `zboot default <be_name>` again.
        spawner.warn(&format!(
            "warning: rollback created BE {be_name:?} but `zboot default` failed (rc={}); \
             the new BE was not activated. Retry with `zboot default {be_name}`, \
             or `zboot drop {be_name}` to discard.",
            switch_res.rc
        ));
        let stderr_text = String::from_utf8_lossy(&switch_res.stderr).into_owned();
        return Err(anyhow!(
            "rollback: `zboot default {}` failed rc={}: {}",
            be_name,
            switch_res.rc,
            stderr_text.trim()
        ));
    }

    writeln!(w, "rollback: complete — {be_name} is now active").context("write")?;
    Ok(())
}

/// Reject names that `cmd::fork` would itself reject. Keeping this aligned
/// with `cmd::fork::run`'s validation avoids a confusing "fork said no" exit
/// for an invalid `--name` rollback flag.
fn validate_be_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("rollback: --name must be non-empty");
    }
    if name.contains('/') || name.contains('@') {
        bail!("rollback: --name must be a bare BE name (no `/` or `@`); got {name:?}");
    }
    Ok(())
}

/// Forward sub-verb stderr to the parent process's stderr. Kept as a free
/// function (rather than a `Spawner` method) so the spawner abstraction
/// stays focused on the sub-verb call itself; tests use `Spawner::warn` to
/// capture rollback's own warnings.
fn forward_stderr(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    // Best-effort: sub-verb output may contain a trailing newline already;
    // we don't normalise. Failure to write to stderr (e.g. closed pipe) is
    // not propagated — stderr forwarding is informational.
    let _ = std::io::stderr().lock().write_all(bytes);
}

// ---------------------------------------------------------------------------
// Default-name formatter (mirrors `cmd::snapshot`'s timestamp shape).
//
// `cmd::snapshot::default_snap_name` is private to that module; we vendor the
// civil-time conversion here rather than expose it. Per CLAUDE.md "Right way":
// verb modules stay independent — copying ~25 lines is cheaper than
// negotiating a shared helper across module boundaries.
// ---------------------------------------------------------------------------

/// Compact RFC-3339 UTC: `rollback-YYYYMMDDTHHMMSSZ`.
fn default_rollback_name(unix_secs: u64) -> String {
    let (year, month, day, hour, minute, second) = civil_from_unix(unix_secs);
    format!("rollback-{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// Convert UNIX seconds → (year, month, day, hour, minute, second) UTC.
///
/// Howard Hinnant's `days_from_civil` inverse, as used in `cmd::snapshot`.
/// Operates entirely in unsigned arithmetic for the post-1970 range.
fn civil_from_unix(unix_secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    const SECS_PER_DAY: u64 = 86_400;
    let days = unix_secs / SECS_PER_DAY;
    let secs_of_day = u32::try_from(unix_secs % SECS_PER_DAY).unwrap_or(0);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y_civil = i64::try_from(yoe + era * 400).unwrap_or(0);
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = if month <= 2 { y_civil + 1 } else { y_civil };
    (year, month, day, hour, minute, second)
}

// ===========================================================================
// Tests — pure-data: name formatter, validation, and the composition harness
// driven by a `FakeSpawner`. ZFS-touching paths are exercised by
// `scripts/lifecycle.sh`.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // --- default_rollback_name ---------------------------------------------

    #[test]
    fn default_name_unix_epoch() {
        assert_eq!(default_rollback_name(0), "rollback-19700101T000000Z");
    }

    #[test]
    fn default_name_known_timestamp() {
        // 2026-05-09 14:30:00 UTC — same anchor as snapshot's analogous test.
        let unix = unix_for(2026, 5, 9, 14, 30, 0);
        assert_eq!(default_rollback_name(unix), "rollback-20260509T143000Z");
    }

    #[test]
    fn default_name_format_invariants() {
        let name = default_rollback_name(1_700_000_000);
        assert!(name.starts_with("rollback-"));
        let stamp = &name["rollback-".len()..];
        assert_eq!(stamp.len(), "YYYYMMDDTHHMMSSZ".len());
        assert!(stamp.ends_with('Z'));
        assert_eq!(stamp.chars().nth(8), Some('T'));
    }

    /// Test-only helper to compute UNIX seconds from a civil UTC tuple
    /// (the inverse of `civil_from_unix`).
    fn unix_for(year: u64, month: u64, day: u64, hour: u64, minute: u64, second: u64) -> u64 {
        let y_civil = if month <= 2 { year - 1 } else { year };
        let era = y_civil / 400;
        let yoe = y_civil - era * 400;
        let mp = if month > 2 { month - 3 } else { month + 9 };
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        days * 86_400 + hour * 3600 + minute * 60 + second
    }

    // --- validate_be_name ---------------------------------------------------

    #[test]
    fn validate_be_name_accepts_simple() {
        assert!(validate_be_name("be1").is_ok());
        assert!(validate_be_name("rollback-20260509T143000Z").is_ok());
    }

    #[test]
    fn validate_be_name_rejects_empty() {
        let err = validate_be_name("").unwrap_err();
        assert!(format!("{err}").contains("non-empty"));
    }

    #[test]
    fn validate_be_name_rejects_slash() {
        let err = validate_be_name("ROOT/foo").unwrap_err();
        assert!(format!("{err}").contains("bare BE name"));
    }

    #[test]
    fn validate_be_name_rejects_at() {
        let err = validate_be_name("foo@bar").unwrap_err();
        assert!(format!("{err}").contains("bare BE name"));
    }

    // --- fake spawner -------------------------------------------------------

    #[derive(Default)]
    struct FakeSpawner {
        /// Queued outcomes for each call, in order. Each call pops one.
        outcomes: RefCell<Vec<SubResult>>,
        /// Recorded argv tails passed to `run`.
        calls: RefCell<Vec<Vec<String>>>,
        /// Captured warning lines.
        warnings: RefCell<Vec<String>>,
    }

    impl FakeSpawner {
        fn queue(&self, rc: i32, stdout: &str, stderr: &str) {
            self.outcomes.borrow_mut().push(SubResult {
                rc,
                stdout: stdout.as_bytes().to_vec(),
                stderr: stderr.as_bytes().to_vec(),
            });
        }
    }

    impl Spawner for FakeSpawner {
        fn run(&self, args: &[&str]) -> Result<SubResult> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).to_owned()).collect());
            Ok(self.outcomes.borrow_mut().remove(0))
        }
        fn warn(&self, msg: &str) {
            self.warnings.borrow_mut().push(msg.to_owned());
        }
    }

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn unix_secs(&self) -> u64 {
            self.0
        }
    }

    // --- happy path: explicit --name, fork ok, switch ok --------------------

    #[test]
    fn happy_path_named_runs_fork_then_switch() {
        let spawner = FakeSpawner::default();
        spawner.queue(0, "fork: created BE\n", "");
        spawner.queue(0, "switch: bootfs set\n", "");
        let clock = FixedClock(0);
        let mut buf: Vec<u8> = Vec::new();
        run_with_spawner(
            &RollbackArgs {
                to: "rpool/ROOT/BE1@snap1".into(),
                name: Some("my-rollback".into()),
            },
            &mut buf,
            &spawner,
            &clock,
        )
        .unwrap();

        let calls = spawner.calls.borrow();
        assert_eq!(calls.len(), 2, "expected fork + switch, got {calls:?}");
        assert_eq!(
            calls[0],
            vec!["fork", "my-rollback", "--from", "rpool/ROOT/BE1@snap1"]
        );
        assert_eq!(calls[1], vec!["default", "my-rollback"]);
        assert!(spawner.warnings.borrow().is_empty());

        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("forking my-rollback from rpool/ROOT/BE1@snap1"),
            "{out}"
        );
        assert!(out.contains("switching to my-rollback"), "{out}");
        assert!(out.contains("complete"), "{out}");
    }

    // --- default name uses the clock ---------------------------------------

    #[test]
    fn default_name_used_when_flag_absent() {
        let spawner = FakeSpawner::default();
        spawner.queue(0, "", "");
        spawner.queue(0, "", "");
        // 2026-05-09 14:30:00 UTC.
        let clock = FixedClock(unix_for(2026, 5, 9, 14, 30, 0));
        let mut buf: Vec<u8> = Vec::new();
        run_with_spawner(
            &RollbackArgs {
                to: "rpool/ROOT/BE1@snap1".into(),
                name: None,
            },
            &mut buf,
            &spawner,
            &clock,
        )
        .unwrap();

        let calls = spawner.calls.borrow();
        assert_eq!(calls[0][1], "rollback-20260509T143000Z");
        assert_eq!(calls[1][1], "rollback-20260509T143000Z");
    }

    // --- malformed --to is caught before fork is spawned --------------------

    #[test]
    fn malformed_to_fails_before_spawning_fork() {
        let spawner = FakeSpawner::default();
        let clock = FixedClock(0);
        let mut buf: Vec<u8> = Vec::new();
        let err = run_with_spawner(
            &RollbackArgs {
                to: "no_at_sign".into(),
                name: None,
            },
            &mut buf,
            &spawner,
            &clock,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--to"));
        assert!(
            spawner.calls.borrow().is_empty(),
            "fork must not be spawned"
        );
    }

    // --- fork failure → no switch, error surfaces --------------------------

    #[test]
    fn fork_failure_skips_switch_and_propagates_error() {
        let spawner = FakeSpawner::default();
        spawner.queue(
            1,
            "",
            "fork: target dataset already exists: rpool/ROOT/BE2\n",
        );
        let clock = FixedClock(0);
        let mut buf: Vec<u8> = Vec::new();
        let err = run_with_spawner(
            &RollbackArgs {
                to: "rpool/ROOT/BE1@snap1".into(),
                name: Some("BE2".into()),
            },
            &mut buf,
            &spawner,
            &clock,
        )
        .unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains("rollback"), "{msg}");
        assert!(msg.contains("fork"), "{msg}");
        assert!(msg.contains("rc=1"), "{msg}");

        let calls = spawner.calls.borrow();
        assert_eq!(calls.len(), 1, "no switch after fork failure: {calls:?}");
        assert!(
            spawner.warnings.borrow().is_empty(),
            "no warning on fork failure"
        );
    }

    // --- switch failure → warning + error ---------------------------------

    #[test]
    fn switch_failure_post_fork_warns_and_errors() {
        let spawner = FakeSpawner::default();
        spawner.queue(0, "fork: created\n", "");
        spawner.queue(2, "", "switch: zfs failed\n");
        let clock = FixedClock(0);
        let mut buf: Vec<u8> = Vec::new();
        let err = run_with_spawner(
            &RollbackArgs {
                to: "rpool/ROOT/BE1@snap1".into(),
                name: Some("rb".into()),
            },
            &mut buf,
            &spawner,
            &clock,
        )
        .unwrap_err();

        let msg = format!("{err}");
        assert!(msg.contains("default"), "{msg}");
        assert!(msg.contains("rc=2"), "{msg}");

        let warnings = spawner.warnings.borrow();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let w = &warnings[0];
        assert!(w.contains("not activated"), "{w}");
        assert!(w.contains("rb"), "{w}");

        let calls = spawner.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0], "default");
    }

    // --- bad --name is rejected before fork -------------------------------

    #[test]
    fn invalid_name_rejected_before_fork() {
        let spawner = FakeSpawner::default();
        let clock = FixedClock(0);
        let mut buf: Vec<u8> = Vec::new();
        let err = run_with_spawner(
            &RollbackArgs {
                to: "rpool/ROOT/BE1@snap1".into(),
                name: Some("ROOT/foo".into()),
            },
            &mut buf,
            &spawner,
            &clock,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("bare BE name"));
        assert!(spawner.calls.borrow().is_empty());
    }

    // --- run() entry-point smoke (just argument plumbing) -----------------

    #[test]
    fn run_rejects_malformed_to_via_public_entry() {
        let mut buf: Vec<u8> = Vec::new();
        let err = run(
            &RollbackArgs {
                to: "missing-at-sign".into(),
                name: None,
            },
            &mut buf,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("--to"));
    }
}
