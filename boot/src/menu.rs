//! Boot-time menu + countdown for `zboot-boot menu`.
//!
//! Two render paths share a single layout pass:
//!
//! - **Text-mode menu** (TTY stdout): modelled on U-Boot's
//!   `common/autoboot.c::abortboot_single_key`. Termios `~ICANON &
//!   ~ECHO`; per-second redraw of a single prompt line via `\r\x1b[K`;
//!   100 × `poll(stdin, 10ms)` per second so any byte halts the
//!   countdown immediately — matching the bootloader convention every
//!   operator already has muscle memory for. On halt we drop into the
//!   post-halt shell (`shell::run`); on timeout we kexec the default
//!   target.
//! - **Plain-text** (no TTY — `cargo test`, CI, piped stdout): the same
//!   layout pass is dumped as text to the writer and the function returns
//!   `Ok(())` with no selection. Gives integration tests a deterministic
//!   snapshot to assert on without a pty.
//!
//! ## Render style
//!
//! Per DESIGN.md § "Boot UX → Default view (during countdown)":
//!
//! ```text
//!   1) * rpool/ROOT/be1
//!        ├ vmlinuz      → 6.13.0   (default)
//!        └ vmlinuz.old  → 6.12.86
//!   2)   rpool/ROOT/be2
//!        └ vmlinuz      → 6.13.0
//!   ─────────────────────────────────
//!   3)   rpool2/ROOT/be3
//!        └ vmlinuz      → 6.13.0
//! ```
//!
//! Numbering is **per-BE** and continuous across pools — `boot 3` from
//! the shell picks BE 3 and boots its default kernel. A `─────` separator
//! line groups by pool. Each BE shows its kernels as a tree under it;
//! the kernel pointed at by `<be>/boot/vmlinuz` is annotated `(default)`.
//! Picking a non-default kernel uses `boot <ds>:<kernel>` — the composite
//! is *not* numbered. The countdown line redraws below the menu
//! (`\r\x1b[K`); the menu above stays put.
//!
//! ## Two row models
//!
//! `MenuRow` is the BE-tree layout (origin lineage with `├── └── │   `
//! connectors) reused by the legacy plain-text dump. It's still the right
//! shape for the lineage view inside `status`.
//!
//! `shell::BootTarget` is the per-BE row carrying a `Vec<KernelChoice>`
//! of bootable kernels found in the BE's `/boot`. The shell drops to a
//! `Vec<BootTarget>`; `boot 3` resolves to `targets[2]`'s default kernel.
//!
//! ## Fake data
//!
//! When `--features fake-data` is on, or when discovery fails on a
//! dev-host (no `zfs`/`zpool` available), we synthesize a tiny set of
//! `BootTarget`s so `cargo run -p zboot-boot -- menu` still produces
//! something to look at. Real bootloader use never hits this branch.

use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

use zboot_core::{BootEnvironment, Forest};

use crate::discover::{BeJson, DiscoverV1, KernelEntry, PoolJson};
use crate::kexec::{self, KexecBackend, SystemKexec};
use crate::shell::{self, BootTarget, KernelChoice};

/// Public entry point — `zboot-boot menu` calls this from `main`.
///
/// `fake-data` cargo feature still synthesizes a forest for dev runs
/// (`cargo run --features fake-data`). At runtime, however: if discovery
/// fails or finds no `zboot:role=root` pools, we drop straight into the
/// recovery shell with an empty target list — the operator can then run
/// `sh`, `dmesg`, `modprobe`, `zpool import`, etc. to diagnose. Faking
/// a forest at runtime would mask the very failure the operator is
/// trying to debug.
pub fn run(w: &mut impl Write) -> Result<()> {
    if cfg!(feature = "fake-data") {
        let payload = fake_payload();
        return run_with_payload(&payload, w);
    }
    match crate::discover::collect_for_menu() {
        Ok(payload) if !payload.bes.is_empty() => run_with_payload(&payload, w),
        Ok(_) => {
            eprintln!("zboot-boot: no `zboot:role=root` pools discovered — recovery shell");
            shell::run(&[], w as &mut dyn Write)
        }
        Err(e) => {
            eprintln!("zboot-boot: discovery failed ({e:#}) — recovery shell");
            shell::run(&[], w as &mut dyn Write)
        }
    }
}

/// Inner entry point — accepts a fully-populated discover payload (with
/// kernels per BE) and dispatches to one of three render paths.
///
/// Three render paths:
/// - **`ZBOOT_BOOT_SELECT=<dataset>` set** — non-interactive scripted
///   selection. Skip the menu entirely; resolve the named target and
///   call `kexec::handoff`. Used by the e2e shell scripts and by
///   anyone scripting the bootloader.
/// - **stdin + stdout both ttys** — countdown menu (U-Boot-style). On
///   halt we drop to `shell::run`; on timeout we kexec the default.
/// - **otherwise** — plain-text dump (CI / piped stdout / `cargo test`).
fn run_with_payload(payload: &DiscoverV1, w: &mut impl Write) -> Result<()> {
    let targets = build_targets(payload);

    if let Some(ds) = std::env::var_os("ZBOOT_BOOT_SELECT") {
        let target = ds.to_string_lossy().into_owned();
        return run_scripted_selection(&targets, &target, w);
    }

    if std::io::stdout().is_terminal() && std::io::stdin().is_terminal() {
        run_text_menu(&targets, w)
    } else {
        render_targets_plain(&targets, w)
    }
}

/// Non-interactive selection path. Accepts either a BE dataset
/// (`rpool/ROOT/be1`) — boots its default kernel — or a composite
/// `<dataset>:<kernel>` to pick a specific kernel within a BE.
fn run_scripted_selection(
    targets: &[BootTarget],
    selector: &str,
    w: &mut impl Write,
) -> Result<()> {
    let (be, kernel) = if let Some((ds, kn)) = selector.split_once(':') {
        let be = targets.iter().find(|t| t.dataset == ds).ok_or_else(|| {
            anyhow::anyhow!("ZBOOT_BOOT_SELECT={selector:?}: no BE matching dataset {ds:?}")
        })?;
        let k = be.find_kernel(kn).ok_or_else(|| {
            anyhow::anyhow!("ZBOOT_BOOT_SELECT={selector:?}: BE {ds} has no kernel {kn:?}")
        })?;
        (be, k)
    } else if let Some(be) = targets.iter().find(|t| t.dataset == selector) {
        (be, be.default_kernel())
    } else {
        writeln!(
            w,
            "ZBOOT_BOOT_SELECT={selector:?} not found; available targets:"
        )
        .context("write selection-miss header")?;
        for t in targets {
            writeln!(w, "  - {} ({})", t.idx, t.dataset).context("write selection-miss row")?;
        }
        anyhow::bail!("scripted selection {selector:?} did not match any boot target");
    };
    let mut sysk = SystemKexec::new();
    handoff_target(be, kernel, &mut sysk, w)
}

// ---------------------------------------------------------------------------
// BootTarget assembly from the discover payload.
// ---------------------------------------------------------------------------

/// Build one `BootTarget` per BE (BE-level numbering). Each target
/// carries its full kernel list inline — the menu renders the kernels
/// as tree children but only the BE row gets a number. `boot 3` from
/// the shell resolves to `targets[2]` (idx==3) and boots that BE's
/// default kernel; picking a non-default kernel uses the composite
/// `boot <ds>:<kernel>` form.
///
/// Order:
/// 1. Pools sorted alphabetically (matches `discover::assemble`).
/// 2. BEs in `payload.bes` order — discover already emits them in
///    `zfs list -r` order which is sorted by dataset.
/// 3. Kernels in the order `enumerate_kernels` produced — `vmlinuz`,
///    then `vmlinuz.old`, then versioned files newest-first.
///
/// BEs whose `kernels` list is empty (mount failed, dev-host fallback)
/// get a single synthetic `vmlinuz`/`initrd.img` kernel so the menu
/// has something to render — kexec will fail at handoff if those
/// files don't actually exist, surfacing the underlying issue.
pub fn build_targets(payload: &DiscoverV1) -> Vec<BootTarget> {
    let mut out: Vec<BootTarget> = Vec::new();
    let mut pools: Vec<&str> = payload.bes.iter().map(|b| b.pool.as_str()).collect();
    pools.sort_unstable();
    pools.dedup();
    let mut idx = 1usize;
    for pool in pools {
        for be in payload.bes.iter().filter(|b| b.pool == pool) {
            let mount_root = be
                .mount_root
                .as_deref()
                .map_or_else(|| PathBuf::from("/"), PathBuf::from);
            let kernels: Vec<KernelChoice> = if be.kernels.is_empty() {
                vec![KernelChoice {
                    vmlinuz: "vmlinuz".to_owned(),
                    initrd: "initrd.img".to_owned(),
                    is_default: true,
                }]
            } else {
                be.kernels
                    .iter()
                    .map(|k| KernelChoice {
                        vmlinuz: k.vmlinuz.clone(),
                        initrd: k
                            .initrd
                            .clone()
                            .unwrap_or_else(|| pair_initrd_for_display(&k.vmlinuz)),
                        is_default: k.default,
                    })
                    .collect()
            };
            // Strip "<pool>/ROOT/" prefix off origin for compact display:
            // `rpool/ROOT/be1@s1` → `be1@s1`. Falls back to the full
            // string if the pattern doesn't match (lineage from a
            // non-`ROOT/` dataset, etc.).
            let origin_short = be.origin.as_ref().map(|o| {
                let prefix = format!("{}/ROOT/", be.pool);
                o.strip_prefix(&prefix).unwrap_or(o.as_str()).to_owned()
            });
            out.push(BootTarget {
                idx,
                pool: be.pool.clone(),
                dataset: be.dataset.clone(),
                name: be.name.clone(),
                mount_root,
                kernels,
                is_active: be.active,
                readonly: be.readonly,
                origin_short,
            });
            idx += 1;
        }
    }
    out
}

/// Mirror of `discover::pair_initrd`'s naming (without the file-existence
/// check) — used as a fallback when the discover payload didn't pair
/// the kernel with an initrd. The handoff path may still fail, but the
/// menu renders something sensible meanwhile.
fn pair_initrd_for_display(vmlinuz: &str) -> String {
    if vmlinuz == "vmlinuz" {
        "initrd.img".to_owned()
    } else if vmlinuz == "vmlinuz.old" {
        "initrd.img.old".to_owned()
    } else if let Some(suffix) = vmlinuz.strip_prefix("vmlinuz-") {
        format!("initrd.img-{suffix}")
    } else {
        "initrd.img".to_owned()
    }
}

// ---------------------------------------------------------------------------
// Text-mode menu — print-once tree + per-second countdown redraw.
// ---------------------------------------------------------------------------

fn run_text_menu(targets: &[BootTarget], w: &mut impl Write) -> Result<()> {
    if targets.is_empty() {
        writeln!(w, "no boot targets found").context("write empty")?;
        return Ok(());
    }
    print_target_menu(w, targets)?;
    let default_idx = default_target_idx(targets);

    // ZBOOT_BOOT_TIMEOUT overrides the default 10s autoboot. Set it
    // to 0 to skip the countdown entirely (drop straight to shell).
    let timeout_secs: u64 = std::env::var("ZBOOT_BOOT_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    let halted = if timeout_secs > 0 {
        let h = {
            let _guard = RawStdin::enter().context("setup raw stdin")?;
            countdown_then_halt(w, default_idx + 1, timeout_secs)?
        }; // _guard drops here — termios restored before any further I/O.
        if h {
            writeln!(w).context("nl after halt")?;
        }
        h
    } else {
        // No countdown — straight to shell.
        true
    };

    if !halted {
        let target = &targets[default_idx];
        let kernel = target.default_kernel();
        writeln!(
            w,
            "\n[timeout — auto-booting target {} ({})]",
            default_idx + 1,
            target.dataset,
        )
        .context("write timeout")?;
        let mut sysk = SystemKexec::new();
        return handoff_target(target, kernel, &mut sysk, w);
    }

    // Halted — drop into the post-halt shell. The shell loop owns
    // user input from here; `boot N` triggers kexec inside it.
    shell::run(targets, w as &mut dyn Write)
}

/// Default target index (0-based) — first BE flagged `is_active` (its
/// dataset == its pool's `bootfs`), or 0 if no BE is active.
fn default_target_idx(targets: &[BootTarget]) -> usize {
    targets.iter().position(|t| t.is_active).unwrap_or(0)
}

/// Print the BE+kernel tree per DESIGN.md "Default view (during
/// countdown)". One numbered row per BE; kernels render as tree
/// children below (unnumbered). A `─────` line separates pools.
pub fn print_target_menu(w: &mut impl Write, targets: &[BootTarget]) -> Result<()> {
    writeln!(
        w,
        "================================================================"
    )
    .context("write header")?;
    writeln!(w, "  zboot-boot").context("write header")?;
    writeln!(
        w,
        "================================================================"
    )
    .context("write header")?;

    let mut last_pool: Option<&str> = None;
    for t in targets {
        if let Some(prev) = last_pool
            && prev != t.pool
        {
            writeln!(w, "  ─────────────────────────────────").context("write pool sep")?;
        }
        last_pool = Some(t.pool.as_str());

        let marker = if t.is_active { "*" } else { " " };
        let ro_tag = if t.readonly { "  [mirror]" } else { "" };
        let origin_tag = match &t.origin_short {
            Some(o) => format!("   ← {o}"),
            None => String::new(),
        };
        writeln!(
            w,
            "  {idx}) {marker} {ds}{ro_tag}{origin_tag}",
            idx = t.idx,
            ds = t.dataset,
        )
        .context("write be header")?;

        let max_name = t.kernels.iter().map(|k| k.vmlinuz.len()).max().unwrap_or(0);
        for (i, k) in t.kernels.iter().enumerate() {
            let last = i == t.kernels.len() - 1;
            let connector = if last { "└" } else { "├" };
            let version = kernel_version_label(&k.vmlinuz);
            let tag = if k.is_default { "  (default)" } else { "" };
            writeln!(
                w,
                "       {connector} {kernel:<width$}  -> {version}{tag}",
                kernel = k.vmlinuz,
                width = max_name,
            )
            .context("write kernel row")?;
        }
    }
    writeln!(w).context("write blank")?;
    Ok(())
}

/// Pull a human-readable version string off a vmlinuz filename. Used
/// for the right-hand annotation of each kernel row.
///
/// - `vmlinuz`            → empty (the symlink target carries the version)
/// - `vmlinuz.old`        → `(prev)`
/// - `vmlinuz-X.Y.Z`      → `X.Y.Z`
fn kernel_version_label(filename: &str) -> &str {
    if filename == "vmlinuz" {
        ""
    } else if filename == "vmlinuz.old" {
        "(prev)"
    } else if let Some(s) = filename.strip_prefix("vmlinuz-") {
        s
    } else {
        filename
    }
}

/// Mirrors U-Boot `common/autoboot.c::abortboot_single_key`:
/// per-second redraw, 100 × `poll(stdin, 10ms)` per tick, any byte halts.
/// Returns `true` if a byte was received, `false` on timeout.
fn countdown_then_halt(w: &mut impl Write, default_n: usize, mut secs: u64) -> Result<bool> {
    use std::time::Instant;

    print_countdown(w, default_n, secs)?;
    // Pre-flight: drain any byte buffered before we entered raw mode.
    if poll_stdin_byte(0)?.is_some() {
        return Ok(true);
    }
    while secs > 0 {
        let tick = Instant::now();
        while tick.elapsed() < std::time::Duration::from_secs(1) {
            if poll_stdin_byte(10)?.is_some() {
                return Ok(true);
            }
        }
        secs -= 1;
        print_countdown(w, default_n, secs)?;
    }
    Ok(false)
}

fn print_countdown(w: &mut impl Write, default_n: usize, secs: u64) -> Result<()> {
    // `\r\x1b[K` = CR + erase-to-EOL. Same effect as U-Boot's `\e[2K\r`.
    write!(
        w,
        "\r\x1b[KHit any key to stop autoboot — booting ({default_n}) in {secs:>2}s",
    )
    .context("write prompt")?;
    w.flush().ok();
    Ok(())
}

/// `poll(2)` stdin for `timeout_ms`, returning `Some(byte)` on input,
/// `None` on timeout or EOF. Errors propagate.
fn poll_stdin_byte(timeout_ms: u16) -> Result<Option<u8>> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::io::Read;
    use std::os::fd::AsFd;

    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    let mut pfd = [PollFd::new(fd, PollFlags::POLLIN)];
    if poll(&mut pfd, PollTimeout::from(timeout_ms)).context("poll stdin")? == 0 {
        return Ok(None);
    }
    let mut buf = [0u8; 1];
    match stdin.lock().read(&mut buf) {
        Ok(0) => Ok(None), // EOF
        Ok(_) => Ok(Some(buf[0])),
        Err(e) => Err(anyhow::Error::new(e).context("read stdin byte")),
    }
}

/// Termios guard — saves canonical/echo flags on entry, restores on
/// drop. Drop fires on panic too, so the terminal is always returned
/// to its prior state.
struct RawStdin {
    saved: nix::sys::termios::Termios,
}

impl RawStdin {
    fn enter() -> Result<Self> {
        use nix::sys::termios::{self, LocalFlags, SetArg, SpecialCharacterIndices as Cc};
        use std::os::fd::AsFd;

        let stdin = std::io::stdin();
        let fd = stdin.as_fd();
        let saved = termios::tcgetattr(fd).context("tcgetattr stdin")?;
        let mut raw = saved.clone();
        raw.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO);
        raw.control_chars[Cc::VMIN as usize] = 1;
        raw.control_chars[Cc::VTIME as usize] = 0;
        termios::tcsetattr(fd, SetArg::TCSANOW, &raw).context("tcsetattr raw")?;
        Ok(Self { saved })
    }
}

impl Drop for RawStdin {
    fn drop(&mut self) {
        use nix::sys::termios::{self, SetArg};
        use std::os::fd::AsFd;
        let stdin = std::io::stdin();
        let _ = termios::tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &self.saved);
    }
}

// ---------------------------------------------------------------------------
// MenuRow + lineage layout — kept for the legacy plain-text dump and
// for callers that want the BE forest tree shape (origin connectors).
// ---------------------------------------------------------------------------

/// One renderable row in the lineage view. `prefix` already contains
/// the connectors + active marker; `label` is the BE's short name.
/// `dataset` is the value the selection eventually feeds to kexec —
/// kept on the row so callers don't need a second lookup against the
/// forest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuRow {
    pub prefix: String,
    pub label: String,
    pub dataset: String,
    pub active: bool,
    /// Pool the BE lives in — useful for header rows + grouping.
    pub pool: String,
    /// `Header` rows are pool labels (`pool rpool:`); not selectable.
    pub kind: RowKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    Header,
    Be,
}

impl MenuRow {
    /// Plain-text rendering of one row — `<prefix><marker><label>` for BE
    /// rows, `pool <name>:` for headers.
    fn render(&self) -> String {
        match self.kind {
            RowKind::Header => format!("pool {}:", self.pool),
            RowKind::Be => {
                let marker = if self.active { "* " } else { "  " };
                format!("{}{marker}{}", self.prefix, self.label)
            }
        }
    }
}

/// Group BEs by pool (sorted), then for each pool emit a header row plus
/// a tree-walk of root BEs (sorted by name) and their descendants.
///
/// "Root" here is local-to-the-pool — a BE is local-root if its origin's
/// dataset isn't another BE in the *same* pool. That keeps cross-pool
/// clones from getting buried under a foreign-pool ancestor; they show
/// up at the top of their own pool with their origin still rendered in
/// the detail pane.
pub fn build_rows(forest: &Forest, bootfs: Option<&str>) -> Vec<MenuRow> {
    let active: Vec<&str> = bootfs.into_iter().collect();
    build_rows_with_active(forest, &active)
}

/// Multi-pool layout pass — every dataset in `active` gets the `*`
/// marker. The legacy single-pool `build_rows(... Option<&str> ...)`
/// is a thin shim; this is the canonical implementation.
pub fn build_rows_with_active(forest: &Forest, active: &[&str]) -> Vec<MenuRow> {
    let active_set: HashSet<&str> = active.iter().copied().collect();

    let mut pools: Vec<&str> = forest.bes.iter().map(|b| b.pool.as_str()).collect();
    pools.sort_unstable();
    pools.dedup();

    let mut rows = Vec::new();
    for pool in pools {
        rows.push(MenuRow {
            prefix: String::new(),
            label: String::new(),
            dataset: String::new(),
            active: false,
            pool: pool.to_owned(),
            kind: RowKind::Header,
        });

        let mut local_roots: Vec<&BootEnvironment> = forest
            .bes
            .iter()
            .filter(|be| be.pool == pool && !has_local_parent(forest, be))
            .collect();
        local_roots.sort_by(|a, b| a.name.cmp(&b.name));

        let last_root = local_roots.len().saturating_sub(1);
        for (i, root) in local_roots.iter().enumerate() {
            walk(forest, root, "  ", i == last_root, &active_set, &mut rows);
        }
    }
    rows
}

fn walk(
    forest: &Forest,
    be: &BootEnvironment,
    indent: &str,
    is_last: bool,
    active: &HashSet<&str>,
    out: &mut Vec<MenuRow>,
) {
    let connector = if is_last { "└── " } else { "├── " };
    let prefix = format!("{indent}{connector}");
    out.push(MenuRow {
        prefix,
        label: be.name.clone(),
        dataset: be.dataset.clone(),
        active: active.contains(be.dataset.as_str()),
        pool: be.pool.clone(),
        kind: RowKind::Be,
    });

    let next_indent = format!("{indent}{}", if is_last { "    " } else { "│   " });
    let mut children: Vec<&BootEnvironment> = forest
        .bes
        .iter()
        .filter(|c| c.pool == be.pool && c.origin.as_ref().is_some_and(|s| s.dataset == be.dataset))
        .collect();
    children.sort_by(|a, b| a.name.cmp(&b.name));

    let last_child = children.len().saturating_sub(1);
    for (i, child) in children.iter().enumerate() {
        walk(forest, child, &next_indent, i == last_child, active, out);
    }
}

/// True iff `be`'s origin points at another BE in the same pool that is
/// also tracked in this forest. Cross-pool origins (or origins whose
/// dataset isn't a BE) treat `be` as a local root.
fn has_local_parent(forest: &Forest, be: &BootEnvironment) -> bool {
    let Some(origin) = &be.origin else {
        return false;
    };
    forest
        .bes
        .iter()
        .any(|other| other.pool == be.pool && other.dataset == origin.dataset)
}

// ---------------------------------------------------------------------------
// Plain-text fallback (no tty).
// ---------------------------------------------------------------------------

/// CI / `cargo test` path. Header banner + each row on its own line.
/// Stable shape — integration tests `assert!(out.contains("..."))` against it.
pub fn render_plain(rows: &[MenuRow], w: &mut impl Write) -> Result<()> {
    writeln!(w, "zboot-boot menu (no tty — plain text)").context("write banner")?;
    writeln!(w).context("write blank")?;
    if rows.is_empty() {
        writeln!(w, "(no boot environments found)").context("write empty notice")?;
        return Ok(());
    }
    for row in rows {
        writeln!(w, "{}", row.render()).context("write row")?;
    }
    writeln!(w).context("write blank")?;
    writeln!(
        w,
        "(interactive selection requires a tty; pipe stdout to a terminal)"
    )
    .context("write tty notice")?;
    Ok(())
}

/// Plain-text dump of `Vec<BootTarget>` — same call site as
/// `render_plain` but per-target instead of per-BE. Used by the no-tty
/// path in `run_with_payload`.
fn render_targets_plain(targets: &[BootTarget], w: &mut impl Write) -> Result<()> {
    writeln!(w, "zboot-boot menu (no tty — plain text)").context("write banner")?;
    writeln!(w).context("write blank")?;
    if targets.is_empty() {
        writeln!(w, "(no boot targets found)").context("write empty notice")?;
        return Ok(());
    }
    print_target_menu(w, targets)?;
    writeln!(
        w,
        "(interactive selection requires a tty; pipe stdout to a terminal)"
    )
    .context("write tty notice")?;
    Ok(())
}

/// Mount the BE (PID 1 only) and hand off to kexec. Used by the
/// scripted-selection path and the timeout-default path; the post-halt
/// shell drives `kexec::handoff` itself via `shell::run`.
fn handoff_target(
    target: &BootTarget,
    kernel: &KernelChoice,
    backend: &mut dyn KexecBackend,
    w: &mut impl Write,
) -> Result<()> {
    let mut be = BootEnvironment::new(&target.pool, &target.name);
    be.dataset.clone_from(&target.dataset);
    let mount_root = resolve_mount_root_for(target)?;
    let plan = kexec::plan_with_kernel(&be, &mount_root, &kernel.vmlinuz, &kernel.initrd, None)?;
    let mut writer: &mut dyn Write = w;
    kexec::handoff_plan(&plan, backend, &mut writer)
}

/// Where `kexec::plan` will look for `boot/{vmlinuz,initrd.img}`.
///
/// PID 1 (real boot): if the discover payload already gave us a
/// mount root, use it. Otherwise fall back to mounting the BE
/// read-only at `/zboot/be-mount/<name>` (idempotent — second hit
/// reuses the existing mountpoint).
/// Anything else (dev-host `cargo run`): return `/`, so the
/// "would kexec" message picks up the dev's own kernel.
fn resolve_mount_root_for(target: &BootTarget) -> Result<PathBuf> {
    if nix::unistd::getpid().as_raw() != 1 {
        return Ok(PathBuf::from("/"));
    }
    if target.mount_root.as_os_str() != "/" {
        return Ok(target.mount_root.clone());
    }
    let target_path = PathBuf::from(format!("/zboot/be-mount/{}", target.name));
    if target_path.join("boot").is_dir() {
        return Ok(target_path);
    }
    std::fs::create_dir_all(&target_path)
        .with_context(|| format!("mkdir {}", target_path.display()))?;
    let target_str = target_path.to_str().context("non-utf8 mount path")?;
    let status = std::process::Command::new("/bin/mount")
        .args(["-t", "zfs", "-o", "ro,zfsutil", &target.dataset, target_str])
        .status()
        .context("spawn mount")?;
    if !status.success() {
        anyhow::bail!(
            "mount {} -> {}: rc={:?}",
            target.dataset,
            target_path.display(),
            status.code(),
        );
    }
    Ok(target_path)
}

// ---------------------------------------------------------------------------
// Fake data — dev-host fallback.
// ---------------------------------------------------------------------------

/// Synthetic discover payload exercising the edge cases the layout has
/// to handle:
///
/// - `rpool`: two BEs (`be1`, `be2`); `be1` carries two kernels (the
///   default + a `vmlinuz.old` previous-kernel pointer); `be2` carries
///   one. Active marker is on `rpool/ROOT/be1`.
/// - `rpool2`: one BE (`be3`) so the pool-separator `─────` exercises.
fn fake_payload() -> DiscoverV1 {
    DiscoverV1 {
        pools: vec![
            PoolJson {
                name: "rpool".into(),
                role: "root".into(),
                bootfs: Some("rpool/ROOT/be1".into()),
                guid: Some(1),
            },
            PoolJson {
                name: "rpool2".into(),
                role: "root".into(),
                bootfs: Some("rpool2/ROOT/be3".into()),
                guid: Some(2),
            },
        ],
        bes: vec![
            BeJson {
                pool: "rpool".into(),
                dataset: "rpool/ROOT/be1".into(),
                name: "be1".into(),
                origin: None,
                active: true,
                readonly: false,
                bound_to: vec![],
                kernels: vec![
                    KernelEntry {
                        vmlinuz: "vmlinuz".into(),
                        initrd: Some("initrd.img".into()),
                        default: false,
                    },
                    KernelEntry {
                        vmlinuz: "vmlinuz-6.13.0".into(),
                        initrd: Some("initrd.img-6.13.0".into()),
                        default: true,
                    },
                    KernelEntry {
                        vmlinuz: "vmlinuz.old".into(),
                        initrd: Some("initrd.img.old".into()),
                        default: false,
                    },
                ],
                mount_root: None,
            },
            BeJson {
                pool: "rpool".into(),
                dataset: "rpool/ROOT/be2".into(),
                name: "be2".into(),
                origin: Some("rpool/ROOT/be1@snap1".into()),
                active: false,
                readonly: false,
                bound_to: vec![],
                kernels: vec![KernelEntry {
                    vmlinuz: "vmlinuz".into(),
                    initrd: Some("initrd.img".into()),
                    default: true,
                }],
                mount_root: None,
            },
            BeJson {
                pool: "rpool2".into(),
                dataset: "rpool2/ROOT/be3".into(),
                name: "be3".into(),
                origin: None,
                active: true,
                readonly: false,
                bound_to: vec![],
                kernels: vec![KernelEntry {
                    vmlinuz: "vmlinuz".into(),
                    initrd: Some("initrd.img".into()),
                    default: true,
                }],
                mount_root: None,
            },
        ],
    }
}

// ===========================================================================
// Tests — pure layout. Interactive path is not unit-testable without a
// pty; the e2e shell scripts cover that.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zboot_core::SnapshotRef;

    fn be(pool: &str, name: &str, origin: Option<&str>) -> BootEnvironment {
        let mut b = BootEnvironment::new(pool, name);
        b.origin = origin.and_then(SnapshotRef::parse);
        b
    }

    fn forest(bes: Vec<BootEnvironment>) -> Forest {
        Forest::from_origins(bes)
    }

    // --- build_rows / build_rows_with_active (legacy lineage layout) -------

    #[test]
    fn empty_forest_yields_no_rows() {
        assert!(build_rows(&Forest::default(), None).is_empty());
    }

    #[test]
    fn single_be_yields_header_and_row() {
        let f = forest(vec![be("rpool", "be1", None)]);
        let rows = build_rows(&f, Some("rpool/ROOT/be1"));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind, RowKind::Header);
        assert_eq!(rows[0].pool, "rpool");
        assert_eq!(rows[1].kind, RowKind::Be);
        assert_eq!(rows[1].label, "be1");
        assert!(rows[1].active);
    }

    #[test]
    fn pools_sort_alphabetically() {
        let f = forest(vec![be("rpool", "be1", None), be("dpool", "be1", None)]);
        let rows = build_rows(&f, None);
        let pool_headers: Vec<&str> = rows
            .iter()
            .filter(|r| r.kind == RowKind::Header)
            .map(|r| r.pool.as_str())
            .collect();
        assert_eq!(pool_headers, vec!["dpool", "rpool"]);
    }

    #[test]
    fn lineage_indents_under_parent() {
        let f = forest(vec![
            be("rpool", "be1", None),
            be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
        ]);
        let rows = build_rows(&f, Some("rpool/ROOT/be1"));
        assert_eq!(rows.len(), 3);
        let be1_prefix_len = rows[1].prefix.len();
        let be2_prefix_len = rows[2].prefix.len();
        assert!(
            be2_prefix_len > be1_prefix_len,
            "be2 ({be2_prefix_len}) should be more deeply indented than be1 ({be1_prefix_len})"
        );
    }

    #[test]
    fn lineage_depth_two() {
        let f = forest(vec![
            be("rpool", "be1", None),
            be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
            be("rpool", "be3", Some("rpool/ROOT/be2@snap1")),
        ]);
        let rows = build_rows(&f, None);
        assert_eq!(rows.len(), 4);
        let prefixes: Vec<usize> = rows
            .iter()
            .filter(|r| r.kind == RowKind::Be)
            .map(|r| r.prefix.len())
            .collect();
        assert_eq!(prefixes.len(), 3);
        assert!(prefixes[0] < prefixes[1] && prefixes[1] < prefixes[2]);
    }

    #[test]
    fn external_origin_is_local_root() {
        let f = forest(vec![be("dpool", "recovery", Some("dpool/foreign@x"))]);
        let rows = build_rows(&f, None);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].label, "recovery");
        assert!(rows[1].prefix.contains("└── "));
    }

    #[test]
    fn cross_pool_origin_does_not_nest_across_pools() {
        let f = forest(vec![
            be("rpool", "be1", None),
            be("rpool2", "mirror", Some("rpool/ROOT/be1@snap1")),
        ]);
        let rows = build_rows(&f, None);
        let pool_headers: Vec<&str> = rows
            .iter()
            .filter(|r| r.kind == RowKind::Header)
            .map(|r| r.pool.as_str())
            .collect();
        assert_eq!(pool_headers, vec!["rpool", "rpool2"]);
        let mirror = rows.iter().find(|r| r.label == "mirror").unwrap();
        assert!(
            mirror.prefix.starts_with("  └── "),
            "expected mirror at top-level, got prefix {:?}",
            mirror.prefix
        );
    }

    #[test]
    fn active_marker_only_on_bootfs_dataset() {
        let f = forest(vec![
            be("rpool", "be1", None),
            be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
        ]);
        let rows = build_rows(&f, Some("rpool/ROOT/be2"));
        let be1 = rows.iter().find(|r| r.label == "be1").unwrap();
        let be2 = rows.iter().find(|r| r.label == "be2").unwrap();
        assert!(!be1.active);
        assert!(be2.active);
    }

    #[test]
    fn sibling_connectors_use_branch_then_corner() {
        let f = forest(vec![
            be("rpool", "be1", None),
            be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
            be("rpool", "be1-staging", Some("rpool/ROOT/be1@snap1")),
        ]);
        let rows = build_rows(&f, None);
        let staging = rows.iter().find(|r| r.label == "be1-staging").unwrap();
        let be2 = rows.iter().find(|r| r.label == "be2").unwrap();
        assert!(staging.prefix.contains("├── "), "{:?}", staging.prefix);
        assert!(be2.prefix.contains("└── "), "{:?}", be2.prefix);
    }

    #[test]
    fn plain_render_contains_dataset_paths() {
        let f = forest(vec![be("rpool", "be1", None)]);
        let rows = build_rows(&f, Some("rpool/ROOT/be1"));
        let mut buf = Vec::new();
        render_plain(&rows, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("pool rpool:"), "{s}");
        assert!(s.contains("* be1"), "{s}");
        assert!(s.contains("zboot-boot menu"), "{s}");
    }

    #[test]
    fn plain_render_empty_emits_explicit_message() {
        let mut buf = Vec::new();
        render_plain(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("no boot environments"), "{s}");
    }

    // --- build_targets + print_target_menu --------------------------------

    #[test]
    fn fake_payload_has_expected_shape() {
        let payload = fake_payload();
        let targets = build_targets(&payload);
        // BE-level numbering: 3 BEs (be1, be2, be3) → 3 BootTargets.
        assert_eq!(targets.len(), 3);
        let idxs: Vec<usize> = targets.iter().map(|t| t.idx).collect();
        assert_eq!(idxs, vec![1, 2, 3]);
        // Pool grouping: 2 BEs in rpool, 1 in rpool2.
        let pools: Vec<&str> = targets.iter().map(|t| t.pool.as_str()).collect();
        assert_eq!(pools, vec!["rpool", "rpool", "rpool2"]);
        // be1 has 3 kernels in the fake payload.
        assert_eq!(targets[0].kernels.len(), 3);
        // be1 is active (matches rpool/bootfs).
        assert!(targets[0].is_active);
    }

    #[test]
    fn build_targets_synthesizes_target_for_be_without_kernels() {
        // BE with kernels=[] gets one BootTarget with a single synthetic
        // vmlinuz/initrd.img kernel so the menu still shows it; kexec
        // will surface the missing file at handoff time if it's not
        // actually there.
        let payload = DiscoverV1 {
            pools: vec![PoolJson {
                name: "rpool".into(),
                role: "root".into(),
                bootfs: Some("rpool/ROOT/be1".into()),
                guid: None,
            }],
            bes: vec![BeJson {
                pool: "rpool".into(),
                dataset: "rpool/ROOT/be1".into(),
                name: "be1".into(),
                origin: None,
                active: true,
                readonly: false,
                bound_to: vec![],
                kernels: vec![],
                mount_root: None,
            }],
        };
        let targets = build_targets(&payload);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kernels.len(), 1);
        assert_eq!(targets[0].kernels[0].vmlinuz, "vmlinuz");
        assert_eq!(targets[0].kernels[0].initrd, "initrd.img");
        assert!(targets[0].kernels[0].is_default);
        assert!(targets[0].is_active);
    }

    #[test]
    fn print_target_menu_matches_design_shape() {
        let targets = build_targets(&fake_payload());
        let mut buf: Vec<u8> = Vec::new();
        print_target_menu(&mut buf, &targets).unwrap();
        let s = String::from_utf8(buf).unwrap();

        // Banner + numbered BE rows + tree connectors per DESIGN.md.
        assert!(s.contains("zboot-boot"), "{s}");
        assert!(s.contains("1)"), "{s}");
        assert!(s.contains("rpool/ROOT/be1"), "{s}");
        // Tree connectors `├` / `└` and version annotations.
        assert!(s.contains("├ "), "{s}");
        assert!(s.contains("└ "), "{s}");
        assert!(s.contains("(default)"), "{s}");
        assert!(s.contains("(prev)"), "{s}");
        // Pool separator between rpool and rpool2.
        assert!(s.contains("─────────────────────────────────"), "{s}");
        // BE-level numbering stops at 3 (three BEs across two pools).
        assert!(s.contains("3)"), "{s}");
        assert!(!s.contains("5)"), "{s}");
        // Active BE gets the `*` marker.
        assert!(s.contains("1) * rpool/ROOT/be1"), "{s}");
    }

    #[test]
    fn default_target_idx_picks_active_be() {
        let targets = build_targets(&fake_payload());
        let i = default_target_idx(&targets);
        // fake_payload marks rpool/ROOT/be1 active.
        assert_eq!(targets[i].dataset, "rpool/ROOT/be1");
        assert!(targets[i].is_active);
    }

    #[test]
    fn kernel_version_label_handles_three_shapes() {
        assert_eq!(kernel_version_label("vmlinuz"), "");
        assert_eq!(kernel_version_label("vmlinuz.old"), "(prev)");
        assert_eq!(kernel_version_label("vmlinuz-6.13.0"), "6.13.0");
    }

    #[test]
    fn pair_initrd_for_display_mirrors_discover() {
        assert_eq!(pair_initrd_for_display("vmlinuz"), "initrd.img");
        assert_eq!(pair_initrd_for_display("vmlinuz.old"), "initrd.img.old");
        assert_eq!(
            pair_initrd_for_display("vmlinuz-6.13.0"),
            "initrd.img-6.13.0",
        );
    }

    #[test]
    fn render_targets_plain_includes_banner_and_rows() {
        let targets = build_targets(&fake_payload());
        let mut buf: Vec<u8> = Vec::new();
        render_targets_plain(&targets, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("plain text"), "{s}");
        assert!(s.contains("rpool/ROOT/be1"), "{s}");
        assert!(s.contains("rpool2/ROOT/be3"), "{s}");
    }

}
