//! Post-halt boot shell — `rustyline`-driven REPL that replaces the
//! single-keystroke menu pick once the U-Boot-style countdown is halted.
//!
//! One UX paradigm: boot, recovery ops, kernel-pick, and cmdline edits
//! all live behind verbs in the same prompt. Read-only verbs (`boot`,
//! `ls`, `snapshots`, `help`, one-shot `cmdline`) are native — they have
//! to call into `kexec::handoff` / `discover` directly. Mutating verbs
//! shell out to `/sbin/zboot` (the same binary bundled into the initrd
//! by `boot/build.sh`) so the bootloader and the running system share
//! one CLI implementation per DESIGN.md § "Code sharing".
//!
//! The helper struct owns a `Vec<BootTarget>` snapshot for tab-completion
//! and verb dispatch. Numeric picks index this list 1..=N.

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use rustyline::Editor;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context as RlContext, Helper};

use zboot_core::BootEnvironment;

use crate::kexec::{self, SystemKexec};

// ---------------------------------------------------------------------------
// BootTarget — one row per BE.
//
// Numbering is BE-level: `boot 3` picks BE 3 and boots its default
// kernel (the file `<be>/boot/vmlinuz` symlinks to). Picking a
// non-default kernel uses the composite form `boot <ds>:<kernel>`.
// The menu renders each BE's kernels as a tree under the BE row but
// only the BE row carries a number — the kernels don't.
// ---------------------------------------------------------------------------

/// One bootable kernel inside a BE — populated from `discover::KernelEntry`
/// by `menu::build_targets`. `is_default` flags the file pointed at by
/// the `<be>/boot/vmlinuz` symlink.
#[derive(Debug, Clone)]
pub struct KernelChoice {
    pub vmlinuz: String,
    pub initrd: String,
    pub is_default: bool,
}

/// One selectable BE. `idx` is 1-based and continuous across pools.
/// `is_active` is true when the BE's dataset == its pool's `bootfs`,
/// the autoboot target.
#[derive(Debug, Clone)]
pub struct BootTarget {
    pub idx: usize,
    pub pool: String,
    pub dataset: String,
    pub name: String,
    pub mount_root: PathBuf,
    pub kernels: Vec<KernelChoice>,
    pub is_active: bool,
    /// `readonly=on` — a mirror replica. Shown as `[mirror]` in the menu;
    /// `default` clears it when promoting this BE to active.
    pub readonly: bool,
    /// Short form of the clone parent for menu display: `<be>@<snap>`
    /// stripped of the dataset's pool prefix. `None` for root BEs.
    pub origin_short: Option<String>,
}

impl BootTarget {
    /// Kernel pointed at by `<be>/boot/vmlinuz`. Falls back to the first
    /// kernel if none is flagged default — `build_targets` always
    /// synthesizes at least one entry, so the unwrap is safe.
    ///
    /// # Panics
    ///
    /// Panics if `self.kernels` is empty. `menu::build_targets` is the
    /// only producer of `BootTarget` and always populates at least one
    /// `KernelChoice` (synthetic `vmlinuz`/`initrd.img` for BEs whose
    /// mount-time enumeration failed), so this is a programmer error,
    /// not a runtime path.
    pub fn default_kernel(&self) -> &KernelChoice {
        self.kernels
            .iter()
            .find(|k| k.is_default)
            .or_else(|| self.kernels.first())
            .expect("build_targets guarantees ≥1 kernel per BootTarget")
    }

    /// Look up a kernel by filename (`vmlinuz`, `vmlinuz-X.Y.Z`, etc.).
    pub fn find_kernel(&self, vmlinuz: &str) -> Option<&KernelChoice> {
        self.kernels.iter().find(|k| k.vmlinuz == vmlinuz)
    }
}

// ---------------------------------------------------------------------------
// Public entry — readline loop.
// ---------------------------------------------------------------------------

/// Run the shell until the user types `quit`, hits Ctrl-D, or a `boot`
/// verb successfully kexecs (which doesn't return).
///
/// `targets` is a snapshot — the menu render that produced the numbered
/// list captured BE+kernel state at one point in time. Mutating verbs
/// shell out to `/sbin/zboot`, which re-reads ZFS; the next `ls` after
/// a mutation reflects the change. Re-discovering live state inside
/// the shell loop is intentionally out of scope here.
pub fn run(targets: &[BootTarget], w: &mut dyn Write) -> Result<()> {
    let helper = ShellHelper {
        targets: targets.to_vec(),
        verbs: VERBS.iter().map(|v| (*v).to_owned()).collect(),
    };

    let mut editor: Editor<ShellHelper, DefaultHistory> =
        Editor::new().context("rustyline Editor::new")?;
    editor.set_helper(Some(helper));

    // Re-imported pools (export+import without `readonly=on`). First
    // mutating verb against a given pool pays the cost; subsequent ones
    // are no-ops. Lives across the shell session, dropped on exit.
    let mut rw_pools: HashSet<String> = HashSet::new();

    loop {
        match editor.readline("zboot-boot> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = editor.add_history_entry(line);
                if let Err(e) = dispatch(line, targets, &mut rw_pools, w) {
                    writeln!(w, "error: {e:#}").context("write error")?;
                }
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D: returning would unwind out of PID 1 and panic
                // the kernel. There's no "parent shell" to drop back to.
                writeln!(
                    w,
                    "(Ctrl-D ignored — PID 1 has no exit. Use `boot N`, `reboot`, or `chroot N`.)"
                )
                .ok();
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C: cancel the current line, re-prompt. rustyline
                // already prints ^C and our blank line is enough visual.
                writeln!(w).ok();
            }
            Err(e) => return Err(anyhow!("readline: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Verb dispatch.
// ---------------------------------------------------------------------------

const VERBS: &[&str] = &[
    "boot",
    "cmdline",
    "default",
    "rollback",
    "drop",
    "chroot",
    "snapshots",
    "ls",
    "sh",
    "reboot",
    "help",
];

fn dispatch(
    line: &str,
    targets: &[BootTarget],
    rw_pools: &mut HashSet<String>,
    w: &mut dyn Write,
) -> Result<()> {
    let tokens = tokenize(line).context("parse input line")?;
    let Some((verb, args)) = tokens.split_first() else {
        return Ok(());
    };
    match verb.as_str() {
        "boot" => verb_boot(args, targets, w),
        "cmdline" => verb_cmdline(args, targets, rw_pools, w),
        "default" => verb_default(args, targets, rw_pools),
        "rollback" => verb_rollback(args, targets, rw_pools, w),
        "drop" => verb_drop(args, targets, rw_pools, w),
        "chroot" => verb_chroot(args, targets, rw_pools, w),
        "snapshots" => verb_snapshots(args, targets, w),
        "ls" => verb_ls(targets, w),
        "sh" => verb_sh(args, w),
        "reboot" => verb_reboot(w),
        "help" => verb_help(args, w),
        // Returning from these would unwind PID 1 and panic the kernel.
        "quit" | "exit" => {
            writeln!(
                w,
                "(`{verb}` ignored — PID 1 has no exit. Use `boot N`, `reboot`, or `chroot N`.)"
            )
            .context("write quit-ignored")
        }
        other => writeln!(w, "unknown verb: {other:?}; try `help`").context("write unknown"),
    }
}

// ---------------------------------------------------------------------------
// Native verbs.
// ---------------------------------------------------------------------------

/// `boot N|<ds>:<kernel> [<extras>...]` — kexec into the chosen
/// target. Numeric N picks BE N's default kernel; composite picks a
/// specific kernel within a BE. Extra tokens (everything after the
/// first arg) are passed as a **one-shot cmdline override** for this
/// kexec only — they replace the bootloader's default extras but
/// don't touch the persistent `zboot:kernel-cmdline` property. For
/// persistent changes use `cmdline N "<extras>"`.
fn verb_boot(
    args: &[String],
    targets: &[BootTarget],
    w: &mut dyn Write,
) -> Result<()> {
    let arg = args
        .first()
        .ok_or_else(|| anyhow!("boot: missing argument; try `help boot`"))?;
    let (be, kernel) = resolve_pick(arg, targets)?;
    let extras = (args.len() > 1).then(|| args[1..].join(" "));
    handoff(be, kernel, extras.as_deref(), w)
}

/// `snapshots N` — list snapshots of BE N's dataset via `zfs list`.
fn verb_snapshots(args: &[String], targets: &[BootTarget], w: &mut dyn Write) -> Result<()> {
    let arg = args
        .first()
        .ok_or_else(|| anyhow!("snapshots: missing argument; try `help snapshots`"))?;
    let target = resolve_be(arg, targets)?;
    let out = Command::new("zfs")
        .args([
            "list",
            "-H",
            "-t",
            "snapshot",
            "-o",
            "name,used,creation",
            "-r",
            &target.dataset,
        ])
        .output()
        .context("spawn zfs list")?;
    if !out.status.success() {
        bail!(
            "`zfs list -t snapshot {}` rc={:?}: {}",
            target.dataset,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    w.write_all(&out.stdout).context("write snapshots stdout")?;
    Ok(())
}

/// `ls` — re-render the numbered tree the menu showed at startup.
/// One number per BE; kernels render as tree children below.
fn verb_ls(targets: &[BootTarget], w: &mut dyn Write) -> Result<()> {
    if targets.is_empty() {
        writeln!(w, "(no boot targets)").context("write empty ls")?;
        return Ok(());
    }
    let mut last_pool: Option<&str> = None;
    for t in targets {
        if let Some(prev) = last_pool
            && prev != t.pool
        {
            writeln!(w, "  ─────────────────────────────────").context("write pool sep")?;
        }
        last_pool = Some(t.pool.as_str());

        let marker = if t.is_active { "*" } else { " " };
        writeln!(w, "  {idx}) {marker} {ds}", idx = t.idx, ds = t.dataset)
            .context("write be header")?;
        for (i, k) in t.kernels.iter().enumerate() {
            let last = i == t.kernels.len() - 1;
            let connector = if last { "└" } else { "├" };
            let tag = if k.is_default { "  (default)" } else { "" };
            writeln!(w, "       {connector} {kernel}{tag}", kernel = k.vmlinuz)
                .context("write kernel row")?;
        }
    }
    Ok(())
}

/// `reboot` — sync, export all pools, then restart immediately via
/// `reboot(RB_AUTOBOOT)`. PID-1's normal "exit returns to nothing"
/// gives a kernel panic; this verb is the clean way out of the
/// bootloader shell.
///
/// `sync` flushes any pending writes. `zpool export -a` exports every
/// imported pool — leaves the on-disk pool in a clean state so the
/// next boot's initramfs doesn't replay ZIL against a pool that was
/// rw-imported under PID-1's hostid. Both are best-effort: a failure
/// is logged but doesn't block reboot — preserving the operator's
/// ability to escape a weird state.
fn verb_reboot(w: &mut dyn Write) -> Result<()> {
    use nix::sys::reboot::{RebootMode, reboot};
    writeln!(w, "rebooting...").ok();
    let _ = Command::new("sync").status();
    let rc = Command::new("zpool").args(["export", "-a"]).status();
    if !rc.map(|s| s.success()).unwrap_or(false) {
        writeln!(w, "(warning: `zpool export -a` failed; continuing)").ok();
    }
    reboot(RebootMode::RB_AUTOBOOT).context("reboot(RB_AUTOBOOT)")?;
    bail!("reboot returned unexpectedly")
}

/// `sh [<command>]` — spawn busybox `/bin/sh` for ad-hoc inspection
/// (zpool/zfs/modprobe/dmesg). Stdio inherited; returns to the
/// `zboot-boot> ` prompt when the shell exits. With arguments, runs
/// `sh -c "<args joined>"` non-interactively.
///
/// Wrapped in `setsid -c` so the child becomes a session leader and
/// acquires stdin's tty as its controlling terminal — busybox sh
/// otherwise prints "can't access tty: job control turned off"
/// because PID-1's child inherits no ctty. setsid lives in the
/// initrd's busybox applets (see boot/build.sh).
///
/// Diagnostics-only escape hatch — use when `chroot N` isn't viable
/// (no BE discovered, broken module load, …). Non-zero exit is
/// reported but doesn't fail the verb.
fn verb_sh(args: &[String], w: &mut dyn Write) -> Result<()> {
    let mut cmd = Command::new("/bin/setsid");
    cmd.args(["-c", "/bin/sh"]);
    if !args.is_empty() {
        cmd.arg("-c").arg(args.join(" "));
    }
    let status = cmd.status().context("spawn `setsid -c /bin/sh`")?;
    if !status.success() {
        writeln!(w, "(sh exited rc={:?})", status.code()).ok();
    }
    Ok(())
}

/// `help [verb]` — usage. `help` alone lists verbs; `help <verb>` shows
/// one-line usage.
fn verb_help(args: &[String], w: &mut dyn Write) -> Result<()> {
    if let Some(v) = args.first() {
        writeln!(w, "{v}: {}", help_for(v.as_str())).context("write help line")?;
        return Ok(());
    }
    writeln!(w, "verbs:").context("write help banner")?;
    for v in VERBS {
        writeln!(w, "  {v:<16} {}", help_for(v)).context("write help row")?;
    }
    Ok(())
}

fn help_for(verb: &str) -> &'static str {
    match verb {
        "boot" => "boot N|<ds>:<kernel> [<extras>...] — kexec; trailing tokens = one-shot cmdline override",
        "cmdline" => "cmdline N [--clear | <extras>...] — show (no args) / persist (extras) / drop local (--clear)",
        "default" => "default N — set the pool's bootfs to BE N's dataset",
        "rollback" => "rollback N <snap> — fork+switch to a snapshot of BE N",
        "drop" => "drop N — destroy BE N (typed-target confirmation)",
        "chroot" => "chroot N — mount BE N RW + drop into a shell inside it (remounts on exit)",
        "snapshots" => "snapshots N — list snapshots of BE N's dataset",
        "ls" => "ls — render the numbered boot menu",
        "sh" => "sh [<command>] — spawn /bin/sh (diagnostics; interactive if no args)",
        "reboot" => "reboot — sync + immediate restart (reboot(2) RB_AUTOBOOT)",
        "help" => "help [verb] — show usage",
        _ => "(unknown verb)",
    }
}

// ---------------------------------------------------------------------------
// Mutating verbs — call zboot_cli verb functions directly (no /sbin/zboot
// fork). The CLI's verb modules are exposed as a library precisely so
// the bootloader shell doesn't need to ship a copy of the CLI binary
// inside the initrd. See `cli/Cargo.toml` for the embed-feature split.
// ---------------------------------------------------------------------------

/// `cmdline N` (no args)   — show the effective `zboot:kernel-cmdline`
/// `cmdline N --clear`     — drop the local property (revert to
///                           inherited or unset)
/// `cmdline N "<extras>"`  — persist (write `zboot:kernel-cmdline`)
///
/// One-shot override at boot time is `boot N "<extras>"` — different
/// code path (kexec with override extras, don't touch the property).
fn verb_cmdline(
    args: &[String],
    targets: &[BootTarget],
    rw_pools: &mut HashSet<String>,
    w: &mut dyn Write,
) -> Result<()> {
    let arg = args
        .first()
        .ok_or_else(|| anyhow!("cmdline: usage `cmdline N [--clear | <extras>...]`"))?;
    let target = resolve_be(arg, targets)?;
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    const CLEAR_FLAG: &str = "--clear";
    let clear = rest.iter().any(|&s| s == CLEAR_FLAG);
    let extras: Vec<&str> = rest.iter().copied().filter(|&s| s != CLEAR_FLAG).collect();

    let action = if clear {
        if !extras.is_empty() {
            bail!("cmdline: `--clear` cannot combine with extras (got {extras:?})");
        }
        ensure_pool_rw(&target.pool, rw_pools)?;
        zboot_cli::cmd::cmdline::CmdlineAction::Clear
    } else if !extras.is_empty() {
        ensure_pool_rw(&target.pool, rw_pools)?;
        zboot_cli::cmd::cmdline::CmdlineAction::Set {
            value: extras.join(" "),
        }
    } else {
        zboot_cli::cmd::cmdline::CmdlineAction::Get
    };
    let cli_args = zboot_cli::cmd::cmdline::CmdlineArgs {
        action: Some(action),
        be: Some(target.dataset.clone()),
        root: None,
    };
    zboot_cli::cmd::cmdline::run(&cli_args, w)
}

/// `default N` — set the pool's `bootfs`. Native `zpool set` is
/// equivalent to `/sbin/zboot switch` for the bootfs-only case; we
/// invoke `zpool` directly here because the spec calls for it and it's
/// a simple atomic property write — no need for the full `switch`
/// mountpoint dance from a bootloader-stage shell.
fn verb_default(
    args: &[String],
    targets: &[BootTarget],
    rw_pools: &mut HashSet<String>,
) -> Result<()> {
    let arg = args
        .first()
        .ok_or_else(|| anyhow!("default: missing argument"))?;
    let target = resolve_be(arg, targets)?;
    ensure_pool_rw(&target.pool, rw_pools)?;
    spawn(
        "zpool",
        &["set", &format!("bootfs={}", target.dataset), &target.pool],
    )
}

fn verb_rollback(
    args: &[String],
    targets: &[BootTarget],
    rw_pools: &mut HashSet<String>,
    w: &mut dyn Write,
) -> Result<()> {
    if args.len() < 2 {
        bail!("rollback: usage `rollback N <snap>`");
    }
    let target = resolve_be(&args[0], targets)?;
    ensure_pool_rw(&target.pool, rw_pools)?;
    let snap = &args[1];
    let cli_args = zboot_cli::cmd::rollback::RollbackArgs {
        to: format!("{ds}@{snap}", ds = target.dataset),
        name: None,
    };
    zboot_cli::cmd::rollback::run(&cli_args, w)
}

fn verb_drop(
    args: &[String],
    targets: &[BootTarget],
    rw_pools: &mut HashSet<String>,
    w: &mut dyn Write,
) -> Result<()> {
    let arg = args
        .first()
        .ok_or_else(|| anyhow!("drop: missing argument"))?;
    let target = resolve_be(arg, targets)?;
    ensure_pool_rw(&target.pool, rw_pools)?;
    // `zboot drop` owns the typed-target confirmation flow — it reads
    // from stdin which we inherit. Pass the fully-qualified dataset
    // path so drop's locate logic picks the exact target regardless
    // of bare-name ambiguity across pools.
    let cli_args = zboot_cli::cmd::drop::DropArgs {
        name: format!("{}/ROOT/{}", target.pool, target.name),
    };
    zboot_cli::cmd::drop::run(&cli_args, w)
}

/// `chroot N` — mount BE N RW, bind /dev /proc /sys, drop into a shell
/// inside it. `zboot_cli::cmd::chroot::run` does the mount + bind +
/// spawn + RAII teardown; we just resolve N → name and flip the pool
/// writable beforehand.
fn verb_chroot(
    args: &[String],
    targets: &[BootTarget],
    rw_pools: &mut HashSet<String>,
    w: &mut dyn Write,
) -> Result<()> {
    let arg = args
        .first()
        .ok_or_else(|| anyhow!("chroot: missing argument; try `help chroot`"))?;
    let target = resolve_be(arg, targets)?;
    ensure_pool_rw(&target.pool, rw_pools)?;
    let cli_args = zboot_cli::cmd::chroot::ChrootArgs {
        name: target.name.clone(),
        shell: "/bin/bash".to_string(),
    };
    let result = zboot_cli::cmd::chroot::run(&cli_args, w);

    // chroot is a scoped operation: enter → mutate → exit → CLEAN UP.
    // The pool was rw-imported under PID-1's hostid; if we leave it
    // that way and the user reboots, the next boot's initramfs sees a
    // stale-RW-imported pool with a foreign hostid + possible ZIL
    // entries from the chroot's writes, and may panic during import.
    //
    // Downgrade back to readonly: export the pool and re-import
    // `-N -f -o readonly=on` (same shape preinit used). Drops the pool
    // from `rw_pools` so a subsequent mutating verb re-promotes via
    // `ensure_pool_rw`. Then remount the BE at the discover-time path
    // so `boot N` still finds /boot/<kernel>. Best-effort: failures
    // print a warning but don't fail the verb.
    if let Err(e) = downgrade_pool_readonly(&target.pool, rw_pools) {
        writeln!(w, "(warning: pool {} not downgraded to ro: {e:#})", target.pool).ok();
    }
    if let Some(mp_str) = target.mount_root.to_str() {
        let rc = Command::new("mount")
            .args(["-t", "zfs", "-o", "zfsutil,ro", &target.dataset, mp_str])
            .status();
        if !rc.map(|s| s.success()).unwrap_or(false) {
            writeln!(
                w,
                "(warning: failed to remount {} at {mp_str} — `boot {}` may fail)",
                target.dataset, target.idx,
            )
            .ok();
        }
    }
    result
}

/// Export `pool` and re-import readonly via the same arg shape preinit
/// uses (`-N -f -o readonly=on`). Removes the pool from `rw_pools` so
/// subsequent mutating verbs re-promote. Returns Err if the import
/// re-attempt fails — the export may have succeeded but the pool would
/// then be unimported, so the caller should surface this.
fn downgrade_pool_readonly<S: std::hash::BuildHasher>(
    pool: &str,
    rw_pools: &mut HashSet<String, S>,
) -> Result<()> {
    spawn("zpool", &["export", pool])
        .with_context(|| format!("export {pool} for ro downgrade"))?;
    spawn(
        "zpool",
        &["import", "-N", "-f", "-o", "readonly=on", pool],
    )
    .with_context(|| format!("reimport {pool} readonly"))?;
    rw_pools.remove(pool);
    Ok(())
}

fn spawn(prog: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("spawn `{prog} {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`{prog} {}` rc={:?}", args.join(" "), status.code());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pool-RW lazy reimport.
// ---------------------------------------------------------------------------

/// First mutating verb against `pool` triggers `zpool export <pool> &&
/// zpool import -N <pool>` so subsequent writes don't fail with
/// `cannot set property: pool is read-only`. Subsequent mutators are
/// no-ops. The export drops the readonly-imported state created by
/// `preinit`; the import restores it without `readonly=on`.
pub fn ensure_pool_rw<S: std::hash::BuildHasher>(
    pool: &str,
    rw_pools: &mut HashSet<String, S>,
) -> Result<()> {
    if rw_pools.contains(pool) {
        return Ok(());
    }
    spawn("zpool", &["export", pool]).with_context(|| format!("export {pool} for rw reimport"))?;
    // `-f` matches `preinit`'s import: the initrd has no persistent
    // /etc/hostid, so PID-1's runtime hostid never matches the pool's
    // last-RW-imported hostid (the deployed system's). Without -f,
    // ZFS refuses with "pool was previously in use from another
    // system." -N keeps mountpoints off until chroot/zfs mount does
    // it explicitly.
    spawn("zpool", &["import", "-N", "-f", pool])
        .with_context(|| format!("reimport {pool} read-write"))?;
    rw_pools.insert(pool.to_owned());
    Ok(())
}

// ---------------------------------------------------------------------------
// Resolution + tokenization.
// ---------------------------------------------------------------------------

/// Resolve to a BE. Accepts 1-based numeric, bare dataset, or composite
/// `<dataset>:<kernel>` (kernel part ignored — see `resolve_pick` for
/// the BE+kernel form).
fn resolve_be<'a>(arg: &str, targets: &'a [BootTarget]) -> Result<&'a BootTarget> {
    if let Ok(n) = arg.parse::<usize>() {
        return targets
            .iter()
            .find(|t| t.idx == n)
            .ok_or_else(|| anyhow!("no BE at index {n}"));
    }
    let dataset = arg.split_once(':').map_or(arg, |(d, _)| d);
    targets
        .iter()
        .find(|t| t.dataset == dataset)
        .ok_or_else(|| anyhow!("no BE matching {arg:?} (try `ls`)"))
}

/// Resolve to a (BE, kernel) pair. Numeric → BE N's default kernel;
/// composite `<dataset>:<kernel>` → that specific kernel. Bare dataset
/// → BE by dataset, default kernel.
fn resolve_pick<'a>(
    arg: &str,
    targets: &'a [BootTarget],
) -> Result<(&'a BootTarget, &'a KernelChoice)> {
    let be = resolve_be(arg, targets)?;
    let kernel = if let Some((_, kn)) = arg.split_once(':') {
        be.find_kernel(kn)
            .ok_or_else(|| anyhow!("BE {} has no kernel {kn:?}", be.dataset))?
    } else {
        be.default_kernel()
    };
    Ok((be, kernel))
}

/// Whitespace tokenizer with double-quoted-string support. Mirrors
/// the minimum shell-quoting needed for `cmdline ... "..."` — backslash
/// escapes and single quotes are out of scope.
fn tokenize(line: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quote = false;
    for c in line.chars() {
        match (c, in_quote) {
            ('"', _) => in_quote = !in_quote,
            (c, false) if c.is_whitespace() => {
                if !buf.is_empty() {
                    out.push(std::mem::take(&mut buf));
                }
            }
            (c, _) => buf.push(c),
        }
    }
    if in_quote {
        bail!("unterminated quoted string");
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// kexec bridge — drives `kexec::plan_with_kernel` so the BootTarget's
// specific kernel + initrd filenames + one-shot extras are honored.
// ---------------------------------------------------------------------------

/// Drive `kexec::handoff_plan` for a (BE, kernel) pair.
/// `extras_override` (the one-shot `cmdline ... "..."` form) replaces
/// the bootloader's default `zboot.be=<name> console=...` extras when
/// `Some`; persisted `zboot:kernel-cmdline` is still layered in by `plan_with_kernel`.
fn handoff(
    target: &BootTarget,
    kernel: &KernelChoice,
    extras_override: Option<&str>,
    w: &mut dyn Write,
) -> Result<()> {
    let mut be = BootEnvironment::new(&target.pool, &target.name);
    be.dataset.clone_from(&target.dataset);
    let plan = kexec::plan_with_kernel(
        &be,
        &target.mount_root,
        &kernel.vmlinuz,
        &kernel.initrd,
        extras_override,
    )?;
    let mut sysk = SystemKexec::new();
    kexec::handoff_plan(&plan, &mut sysk, w)
}

// ---------------------------------------------------------------------------
// Tab completion.
// ---------------------------------------------------------------------------

/// Helper bundle for rustyline. Hand-rolled `Completer`; `Hinter`,
/// `Highlighter`, `Validator` are no-ops via empty impls.
struct ShellHelper {
    targets: Vec<BootTarget>,
    verbs: Vec<String>,
}

impl Helper for ShellHelper {}
impl Highlighter for ShellHelper {}
impl Hinter for ShellHelper {
    type Hint = String;
}
impl Validator for ShellHelper {}

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &RlContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let prefix = &line[..pos];
        let (start, frag) = word_under_cursor(prefix);
        let words = words_before(prefix, start);

        let candidates = match words.first().map(String::as_str) {
            None => self
                .verbs
                .iter()
                .filter(|v| v.starts_with(frag))
                .map(|v| Pair {
                    display: v.clone(),
                    replacement: v.clone(),
                })
                .collect(),
            Some(verb) => self.complete_arg(verb, &words, frag),
        };
        Ok((start, candidates))
    }
}

impl ShellHelper {
    /// Argument-position completion. Verb-aware so the right source
    /// (numeric, composite, snapshot) is offered depending on which
    /// verb is being typed.
    fn complete_arg(&self, verb: &str, words: &[String], frag: &str) -> Vec<Pair> {
        let argpos = words.len(); // 1 = first arg, 2 = second, ...
        match (verb, argpos) {
            // First arg of any target-taking verb: numeric + composite.
            ("boot", 1) => self.target_candidates(frag, true),
            ("cmdline" | "default" | "rollback" | "drop" | "chroot" | "snapshots", 1) => {
                self.target_candidates(frag, false)
            }
            // `rollback N <TAB>` → snapshot names of BE N's dataset.
            ("rollback", 2) => self.snapshot_candidates(&words[1], frag),
            // `help <TAB>` → verb names.
            ("help", 1) => self
                .verbs
                .iter()
                .filter(|v| v.starts_with(frag))
                .map(|v| Pair {
                    display: v.clone(),
                    replacement: v.clone(),
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Numeric indices (one per BE) + (optionally) `<dataset>:<kernel>`
    /// composites (one per (BE, kernel) pair). Composites only surface
    /// for verbs that can pick a specific kernel (`boot`, `cmdline`);
    /// the others act per-BE so we just expose the numbers.
    fn target_candidates(&self, frag: &str, with_composite: bool) -> Vec<Pair> {
        let mut out = Vec::new();
        for t in &self.targets {
            let n = t.idx.to_string();
            if n.starts_with(frag) {
                out.push(Pair {
                    display: format!("{} ({})", n, t.dataset),
                    replacement: n,
                });
            }
            if with_composite {
                for k in &t.kernels {
                    let c = format!("{}:{}", t.dataset, k.vmlinuz);
                    if c.starts_with(frag) {
                        out.push(Pair {
                            display: c.clone(),
                            replacement: c,
                        });
                    }
                }
            }
        }
        out
    }

    /// Live `zfs list` of snapshots under BE `n`'s dataset. Failures
    /// (no zfs, BE not found) silently yield an empty completion list —
    /// completion is a convenience, not a place to surface errors.
    fn snapshot_candidates(&self, n_arg: &str, frag: &str) -> Vec<Pair> {
        let Ok(n) = n_arg.parse::<usize>() else {
            return Vec::new();
        };
        let Some(t) = self.targets.iter().find(|t| t.idx == n) else {
            return Vec::new();
        };
        let Ok(out) = Command::new("zfs")
            .args([
                "list", "-H", "-o", "name", "-t", "snapshot", "-r", &t.dataset,
            ])
            .output()
        else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }
        String::from_utf8_lossy(&out.stdout)
            .lines()
            // `zfs list -t snapshot` emits `<dataset>@<snap>`; strip to
            // bare `<snap>` for completion since the verb form is
            // `rollback N <snap>`.
            .filter_map(|line| line.split_once('@').map(|(_, s)| s.to_owned()))
            .filter(|s| s.starts_with(frag))
            .map(|s| Pair {
                display: s.clone(),
                replacement: s,
            })
            .collect()
    }
}

/// Find the start byte index and contents of the word under the cursor.
/// Trailing whitespace yields an empty fragment at the end of the line
/// — i.e. "completing the *next* word".
fn word_under_cursor(prefix: &str) -> (usize, &str) {
    let start = prefix.rfind(char::is_whitespace).map_or(0, |i| i + 1);
    (start, &prefix[start..])
}

/// Tokens before the cursor's word, ignoring quoting subtleties.
/// Completion only needs to know which arg position we're in — exact
/// quoted-token reconstruction isn't required.
fn words_before(prefix: &str, start: usize) -> Vec<String> {
    prefix[..start]
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

// ===========================================================================
// Tests — pure parser + completer. The readline loop and the kexec/zfs
// shell-outs are exercised at the integration layer (M-end milestone).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn kc(name: &str, default: bool) -> KernelChoice {
        KernelChoice {
            vmlinuz: name.to_owned(),
            initrd: name.replace("vmlinuz", "initrd.img"),
            is_default: default,
        }
    }

    fn t(idx: usize, ds: &str, name: &str, kernels: Vec<KernelChoice>) -> BootTarget {
        BootTarget {
            idx,
            pool: ds.split('/').next().unwrap_or("rpool").to_owned(),
            dataset: ds.to_owned(),
            name: name.to_owned(),
            mount_root: PathBuf::from("/"),
            is_active: false,
            kernels,
            readonly: false,
            origin_short: None,
        }
    }

    #[test]
    fn tokenize_handles_quoted_extras() {
        let toks = tokenize(r#"cmdline 1 "loglevel=4 quiet""#).unwrap();
        assert_eq!(toks, vec!["cmdline", "1", "loglevel=4 quiet"]);
    }

    #[test]
    fn tokenize_rejects_unterminated_quote() {
        assert!(tokenize(r#"cmdline 1 "open"#).is_err());
    }

    #[test]
    fn resolve_be_numeric_picks_target() {
        let targets = vec![t(1, "rpool/ROOT/be1", "be1", vec![kc("vmlinuz", true)])];
        let r = resolve_be("1", &targets).unwrap();
        assert_eq!(r.dataset, "rpool/ROOT/be1");
    }

    #[test]
    fn resolve_pick_numeric_returns_default_kernel() {
        let targets = vec![t(
            1,
            "rpool/ROOT/be1",
            "be1",
            vec![kc("vmlinuz", false), kc("vmlinuz-6.13.0", true)],
        )];
        let (be, k) = resolve_pick("1", &targets).unwrap();
        assert_eq!(be.dataset, "rpool/ROOT/be1");
        assert_eq!(k.vmlinuz, "vmlinuz-6.13.0");
        assert!(k.is_default);
    }

    #[test]
    fn resolve_pick_composite_picks_specific_kernel() {
        let targets = vec![t(
            1,
            "rpool/ROOT/be1",
            "be1",
            vec![kc("vmlinuz", true), kc("vmlinuz.old", false)],
        )];
        let (be, k) = resolve_pick("rpool/ROOT/be1:vmlinuz.old", &targets).unwrap();
        assert_eq!(be.dataset, "rpool/ROOT/be1");
        assert_eq!(k.vmlinuz, "vmlinuz.old");
    }

    #[test]
    fn resolve_unknown_errors() {
        let targets = vec![t(1, "rpool/ROOT/be1", "be1", vec![kc("vmlinuz", true)])];
        assert!(resolve_be("99", &targets).is_err());
        assert!(resolve_pick("nope:vmlinuz", &targets).is_err());
        assert!(resolve_pick("rpool/ROOT/be1:missing", &targets).is_err());
    }

    #[test]
    fn ls_renders_kernels_under_be() {
        let targets = vec![
            t(
                1,
                "rpool/ROOT/be1",
                "be1",
                vec![kc("vmlinuz", true), kc("vmlinuz.old", false)],
            ),
            t(2, "rpool/ROOT/be2", "be2", vec![kc("vmlinuz", true)]),
        ];
        let mut buf: Vec<u8> = Vec::new();
        verb_ls(&targets, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("rpool/ROOT/be1"), "{s}");
        assert!(s.contains("rpool/ROOT/be2"), "{s}");
        assert!(s.contains("(default)"), "{s}");
        assert!(s.contains("vmlinuz.old"), "{s}");
        // BE-level numbering: 1) and 2), not 1)..3).
        assert!(s.contains("1) "), "{s}");
        assert!(s.contains("2) "), "{s}");
        assert!(!s.contains("3) "), "{s}");
    }

    #[test]
    fn help_lists_verbs() {
        let mut buf: Vec<u8> = Vec::new();
        verb_help(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("boot"), "{s}");
        assert!(s.contains("rollback"), "{s}");
        assert!(s.contains("reboot"), "{s}");
        assert!(s.contains("sh "), "{s}");
    }

    #[test]
    fn sh_verb_registered() {
        assert!(VERBS.contains(&"sh"));
        assert_ne!(help_for("sh"), "(unknown verb)");
    }

    #[test]
    fn ensure_pool_rw_skips_when_already_recorded() {
        // If the pool is in the set we never spawn zpool — so this test
        // works even on a host without ZFS.
        let mut set = HashSet::new();
        set.insert("rpool".to_owned());
        ensure_pool_rw("rpool", &mut set).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn word_under_cursor_at_end_returns_empty_fragment() {
        let (start, frag) = word_under_cursor("boot ");
        assert_eq!(start, 5);
        assert_eq!(frag, "");
    }

    #[test]
    fn word_under_cursor_picks_partial_word() {
        let (start, frag) = word_under_cursor("boot rpoo");
        assert_eq!(start, 5);
        assert_eq!(frag, "rpoo");
    }

    #[test]
    fn helper_completes_verbs_at_start() {
        let helper = ShellHelper {
            targets: vec![],
            verbs: VERBS.iter().map(|v| (*v).to_owned()).collect(),
        };
        let history = DefaultHistory::new();
        let ctx = RlContext::new(&history);
        let (start, cands) = helper.complete("bo", 2, &ctx).unwrap();
        assert_eq!(start, 0);
        assert!(cands.iter().any(|c| c.replacement == "boot"));
    }

    #[test]
    fn helper_completes_numeric_after_boot() {
        let helper = ShellHelper {
            targets: vec![
                t(
                    1,
                    "rpool/ROOT/be1",
                    "be1",
                    vec![kc("vmlinuz", true), kc("vmlinuz.old", false)],
                ),
                t(2, "rpool/ROOT/be2", "be2", vec![kc("vmlinuz", true)]),
            ],
            verbs: VERBS.iter().map(|v| (*v).to_owned()).collect(),
        };
        let history = DefaultHistory::new();
        let ctx = RlContext::new(&history);
        let (start, cands) = helper.complete("boot ", 5, &ctx).unwrap();
        assert_eq!(start, 5);
        // Numeric picks (one per BE) + composite picks (one per kernel).
        let reps: Vec<&str> = cands.iter().map(|c| c.replacement.as_str()).collect();
        assert!(reps.contains(&"1"), "{reps:?}");
        assert!(reps.contains(&"2"), "{reps:?}");
        assert!(reps.iter().any(|r| r.contains("vmlinuz.old")), "{reps:?}");
    }

    #[test]
    fn helper_completes_help_argument_with_verb() {
        let helper = ShellHelper {
            targets: vec![],
            verbs: VERBS.iter().map(|v| (*v).to_owned()).collect(),
        };
        let history = DefaultHistory::new();
        let ctx = RlContext::new(&history);
        let (_, cands) = helper.complete("help bo", 7, &ctx).unwrap();
        assert!(cands.iter().any(|c| c.replacement == "boot"));
    }

    #[test]
    fn boot_numeric_works() {
        let targets = vec![t(1, "rpool/ROOT/be1", "be1", vec![kc("vmlinuz", true)])];
        let tmp = std::env::temp_dir().join(format!("zboot-shell-boot-numeric-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("boot")).unwrap();
        std::fs::write(tmp.join("boot/vmlinuz"), b"k").unwrap();
        std::fs::write(tmp.join("boot/initrd.img"), b"i").unwrap();
        let mut targets = targets;
        targets[0].mount_root = tmp.clone();
        let mut buf: Vec<u8> = Vec::new();
        verb_boot(&["1".to_owned()], &targets, &mut buf as &mut dyn Write).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("would kexec rpool/ROOT/be1"), "{s}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
