//! kexec the chosen BE's kernel.
//!
//! `handoff(be, mount_root)` is the public entry point. It:
//!
//! 1. Resolves the BE's kernel + initramfs paths (under `mount_root`,
//!    where the bootloader has already mounted the BE dataset
//!    read-only).
//! 2. Builds the kernel command line: `root=ZFS=<dataset> ro`,
//!    plus a fixed `zboot.be=<name> console=ttyS0,115200`, plus any
//!    `zboot:kernel-cmdline` extras read from the BE / its ROOT container.
//! 3. Invokes the `kexec(8)` userspace tool to load + execute the new
//!    kernel: `kexec -l <kernel> --initrd=<initrd> --command-line=...`
//!    followed by `kexec -e` (which calls
//!    `reboot(LINUX_REBOOT_CMD_KEXEC)` for us).
//!
//! On success this never returns — control is transferred to the BE's
//! kernel mid-`reboot(2)`. On failure the function returns an error,
//! and the caller falls back to the shell.
//!
//! ## ABI choice — `kexec(8)` userspace tool, not direct syscall
//!
//! Two constraints push us to the userspace-tool path:
//!
//! 1. **Workspace `unsafe_code = "forbid"`.** The
//!    `kexec_load(2)` / `kexec_file_load(2)` syscalls have no safe
//!    wrapper in `nix` (only `reboot(RB_KEXEC)` does). Wrapping
//!    them ourselves requires `unsafe libc::syscall(...)`, which the
//!    workspace lint forbids — and `forbid` cannot be lifted at the
//!    crate level.
//! 2. **ABI fragility.** `kexec_load(2)` requires us to parse the
//!    target kernel's bzImage layout into purgatory segments
//!    ourselves; `kexec_file_load(2)` is simpler but still gates on
//!    `CONFIG_KEXEC_FILE_LOAD=y` and a kernel-supplied signature
//!    check. The userspace `kexec` tool already does the right thing
//!    on every supported kernel.
//!
//! Initrd assembly (`boot/build.sh`) bundles `kexec` from debian's
//! `kexec-tools` package. The public `handoff` signature stays stable
//! across a future swap to `kexec_file_load` because the trait below
//! isolates the syscall surface.
//!
//! ## Dev-host gate
//!
//! `cargo run -p zboot-boot -- menu` on the developer's laptop must
//! not actually kexec — that would reboot their machine. We gate the
//! real syscall path behind two checks (either-of):
//!
//! - **PID 1.** When zboot-boot runs in production it is the
//!   initrd's `/init`, i.e. PID 1. `getpid() == 1` is the normal
//!   bootloader case.
//! - **`ZBOOT_BOOT_REAL_KEXEC=1` env var.** Explicit override — used
//!   by integration tests that drive `zboot-boot` from inside the sim
//!   VM where it is *not* PID 1 (sshd shells it as a normal child).
//!   Tests set the env var, accept the resulting reboot.
//!
//! Outside both gates we print `would kexec <kernel> <cmdline>` to
//! the supplied writer and return `Ok(())`. The dev-host menu UX
//! lands here; `cargo run` produces a deterministic transcript.
//!
//! ## Testability
//!
//! [`KexecBackend`] is the seam: production wires the trait to
//! [`SystemKexec`] (which spawns `/usr/bin/kexec`); cargo unit tests
//! pass [`RecordingBackend`] (which captures `(kernel, initrd,
//! cmdline)` tuples without spawning anything). The kexec arg-builder
//! is exercised purely against recorded text — no /sbin/kexec needed
//! in cargo's sandbox.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};

use zboot_core::BootEnvironment;

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Where the BE's kernel + initramfs live under the mount root, plus
/// the cmdline we'll boot it with. Pure data — built by [`plan`],
/// consumed by [`KexecBackend::load`] / [`KexecBackend::exec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexecPlan {
    /// Absolute path on the bootloader-side filesystem to the kernel
    /// image (`vmlinuz` or `vmlinuz-X.Y.Z`).
    pub kernel: PathBuf,
    /// Absolute path to the initramfs (`initrd.img` or
    /// `initrd.img-X.Y.Z`).
    pub initrd: PathBuf,
    /// Full kernel command line, ready to hand to `kexec --command-line=`.
    pub cmdline: String,
    /// The BE's dataset name — handy for log lines and for the
    /// "would kexec" dev-host message.
    pub dataset: String,
}

/// Backend for the actual `kexec` syscall sequence. Production uses
/// [`SystemKexec`]; tests use [`RecordingBackend`].
pub trait KexecBackend {
    /// Load the kernel + initrd into kernel memory (`kexec -l` /
    /// `kexec_file_load(2)`).
    fn load(&mut self, plan: &KexecPlan) -> Result<()>;
    /// Transfer control to the loaded kernel (`kexec -e` /
    /// `reboot(RB_KEXEC)`). On success this **does not return**.
    fn exec(&mut self) -> Result<()>;
}

/// One-shot top-level: locate kernel + initrd, build cmdline, hand off.
///
/// On success, never returns — the BE's kernel is now PID 1.
/// `mount_root` is where the BE dataset has been mounted read-only by
/// the bootloader (typically `/zboot/be-mount`); tests pass a tempdir.
///
/// Behaviour by gate:
/// - **Real kexec gate open** (PID 1 or `ZBOOT_BOOT_REAL_KEXEC=1`):
///   loads + executes via the supplied backend; on failure returns Err.
/// - **Gate closed** (the normal `cargo run` case): writes
///   `would kexec ...` to `w` and returns `Ok(())` without touching
///   the backend.
pub fn handoff(
    be: &BootEnvironment,
    mount_root: &Path,
    backend: &mut dyn KexecBackend,
    w: &mut dyn Write,
) -> Result<()> {
    handoff_with_gate(be, mount_root, backend, w, gate_from_environment())
}

/// Same as [`handoff`] but with the dev-host gate explicitly supplied.
/// Tests use [`Gate::Open`] / [`Gate::Closed`] directly so they don't
/// have to mutate `getpid()` or environment variables.
pub fn handoff_with_gate(
    be: &BootEnvironment,
    mount_root: &Path,
    backend: &mut dyn KexecBackend,
    w: &mut dyn Write,
    gate: Gate,
) -> Result<()> {
    let plan = plan(be, mount_root)?;
    handoff_plan_with_gate(&plan, backend, w, gate)
}

/// Hand off a pre-built [`KexecPlan`]. Used by `menu.rs` and
/// `shell.rs`, where the kernel/initrd filenames come from a specific
/// `BootTarget` (not the default `vmlinuz` symlink) and the cmdline
/// has already been composed by [`plan_with_kernel`].
pub fn handoff_plan(
    plan: &KexecPlan,
    backend: &mut dyn KexecBackend,
    w: &mut dyn Write,
) -> Result<()> {
    handoff_plan_with_gate(plan, backend, w, gate_from_environment())
}

fn handoff_plan_with_gate(
    plan: &KexecPlan,
    backend: &mut dyn KexecBackend,
    w: &mut dyn Write,
    gate: Gate,
) -> Result<()> {
    if matches!(gate, Gate::Closed) {
        writeln!(
            w,
            "would kexec {} (kernel={}, initrd={}, cmdline={:?})",
            plan.dataset,
            plan.kernel.display(),
            plan.initrd.display(),
            plan.cmdline,
        )
        .context("write would-kexec line")?;
        return Ok(());
    }

    backend.load(plan).with_context(|| {
        format!(
            "kexec load failed (kernel={}, initrd={})",
            plan.kernel.display(),
            plan.initrd.display(),
        )
    })?;
    writeln!(w, "kexec'ing into {}", plan.dataset).context("write kexec line")?;
    backend.exec().context("kexec exec failed")?;
    // On success the kernel never gives us back the stack frame.
    // If we *do* return from `exec`, the syscall failed silently —
    // surface it as an error instead of pretending it worked.
    bail!("kexec exec returned without rebooting — the new kernel did not take");
}

/// Whether the real kexec syscalls fire, or the dev-host
/// "would kexec" message is printed instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Real `kexec(2)` path — used inside the initrd and inside the
    /// sim VM with `ZBOOT_BOOT_REAL_KEXEC=1` set.
    Open,
    /// Dev-host path — print "would kexec" and return.
    Closed,
}

/// Decide the gate from runtime state: PID + environment.
///
/// Open iff:
/// - we're PID 1 (bootloader / initrd init), or
/// - `ZBOOT_BOOT_REAL_KEXEC=1` is set (test override).
fn gate_from_environment() -> Gate {
    let env_override =
        std::env::var_os("ZBOOT_BOOT_REAL_KEXEC").as_deref() == Some(std::ffi::OsStr::new("1"));
    let pid_one = nix::unistd::getpid().as_raw() == 1;
    decide_gate(pid_one, env_override)
}

/// Pure decision function — separated from the I/O wrappers so unit
/// tests can drive every combination without touching real PIDs or
/// env vars.
fn decide_gate(pid_one: bool, env_override: bool) -> Gate {
    if pid_one || env_override {
        Gate::Open
    } else {
        Gate::Closed
    }
}

// ---------------------------------------------------------------------------
// Plan builder — pure (no I/O beyond reading the BE's /boot directory).
// ---------------------------------------------------------------------------

/// Locate kernel + initrd under `mount_root/boot`, build the cmdline.
///
/// `mount_root` is where the BE dataset is mounted (read-only) by the
/// bootloader. The BE's kernel layout matches debian's standard:
/// `<root>/boot/vmlinuz` symlink → `vmlinuz-<ver>`, plus a parallel
/// `initrd.img` → `initrd.img-<ver>` symlink.
///
/// Default-kernel path: this is a thin shim over [`plan_with_kernel`]
/// that picks `vmlinuz` / `initrd.img` (debian's symlink-driven defaults)
/// and lets cmdline extras come from the hardcoded `zboot.be=<name>
/// console=ttyS0,115200` plus inherited `zboot:kernel-cmdline`. Multi-kernel
/// callers (the boot shell with an explicit `<be>:<kernel>` pick) take
/// the wider entry point directly.
pub fn plan(be: &BootEnvironment, mount_root: &Path) -> Result<KexecPlan> {
    plan_with_kernel(be, mount_root, "vmlinuz", "initrd.img", None)
}

/// Wider entry point: pick a specific kernel + initrd by filename, with
/// optional one-shot cmdline override. Used by `shell.rs`'s `boot
/// <be>:<kernel>` and `cmdline N "..."` verbs.
///
/// Filename semantics:
/// - `kernel_filename` is resolved relative to `<mount_root>/boot/`.
///   `vmlinuz` (the symlink) and `vmlinuz-<ver>` (regular file) both
///   work; the path is taken as-is — no version-fallback walk.
/// - `initrd_filename` follows the same rule. `kexec.rs` deliberately
///   does *not* invent a pairing here; callers (or the `plan()` shim)
///   pass the right pair.
///
/// Cmdline composition order, from base to most specific:
///   1. `root=ZFS=<dataset> ro` (always, from `build_cmdline`).
///   2. Inherited `zboot:kernel-cmdline` ZFS user-property on the BE dataset
///      (respects ROOT-container default + per-BE override). Empty/
///      missing → skipped.
///   3. `extras_override` if `Some`, else the bootloader-default
///      `zboot.be=<name> console=ttyS0,115200`. Override replaces the
///      default rather than appending — matches the "one-shot edit"
///      semantics of the shell's `cmdline ... "..."` verb.
pub fn plan_with_kernel(
    be: &BootEnvironment,
    mount_root: &Path,
    kernel_filename: &str,
    initrd_filename: &str,
    extras_override: Option<&str>,
) -> Result<KexecPlan> {
    let boot_dir = mount_root.join("boot");
    let kernel = boot_dir.join(kernel_filename);
    if !kernel.exists() {
        anyhow::bail!(
            "kernel `{kernel_filename}` not found under {} for BE {}",
            boot_dir.display(),
            be.dataset,
        );
    }
    let initrd = boot_dir.join(initrd_filename);
    if !initrd.exists() {
        anyhow::bail!(
            "initrd `{initrd_filename}` not found under {} for BE {}",
            boot_dir.display(),
            be.dataset,
        );
    }
    let cmdline = compose_cmdline(be, extras_override);
    Ok(KexecPlan {
        kernel,
        initrd,
        cmdline,
        dataset: be.dataset.clone(),
    })
}

/// Build the full cmdline for `be`, layering the persistent
/// `zboot:kernel-cmdline` user-property and either an explicit `extras_override`
/// or the bootloader's default extras. See [`plan_with_kernel`] for the
/// composition order.
fn compose_cmdline(be: &BootEnvironment, extras_override: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(build_cmdline(&be.dataset, None));
    if let Some(persist) = read_zboot_cmdline(&be.dataset)
        && !persist.is_empty()
    {
        parts.push(persist);
    }
    let extras = extras_override.map_or_else(
        // Both `tty0` (screen) and `ttyS0` (serial) so kernel panics
        // print SOMEWHERE visible on any host. The kernel registers
        // both and silently drops the missing one (laptops without
        // serial hardware still get caps-lock LED panic indicator
        // PLUS a screen message).
        || format!("zboot.be={} console=tty0 console=ttyS0,115200", be.name),
        str::to_owned,
    );
    if !extras.is_empty() {
        parts.push(extras);
    }
    if let Some(h) = read_runtime_hostid() {
        // BE's initramfs may carry a stale /etc/hostid (factory-tar-built
        // initrd has the build host's hostid; tar deploy never touches
        // it). Pass the correct hostid as an SPL module parameter via
        // the kernel cmdline. The `spl.` prefix is required syntax for
        // loadable-module params on the kernel cmdline (kernel-
        // parameters.txt: `<mod>.<param>=<val>`); bare `spl_hostid=`
        // doesn't get associated with the spl module. When SPL loads
        // (via initramfs's modprobe), the kernel applies this value;
        // gethostid() returns it; pool import in initramfs sees a
        // matching stamp. PID-1's /etc/hostid was set by preinit's
        // `adopt_hostid_from_pool`, so it's already authoritative.
        parts.push(format!("spl.spl_hostid=0x{h:08x}"));
    }
    parts.join(" ")
}

/// Read PID-1's runtime `/etc/hostid` (set by `preinit::adopt_hostid_from_pool`)
/// and decode as a little-endian u32. Returns `None` if absent or malformed.
fn read_runtime_hostid() -> Option<u32> {
    let bytes = std::fs::read("/etc/hostid").ok()?;
    if bytes.len() != 4 {
        return None;
    }
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read the `zboot:kernel-cmdline` ZFS user-property on `dataset`. Returns
/// `None` if the property is unset / `-` / errored — callers treat
/// "no value" the same as "empty extras".
///
/// `zfs get -H -o value` returns `-` for the unset case (and respects
/// inheritance, which is what we want — set on `<pool>/ROOT` for a slot
/// default, override per-BE).
///
/// Resolves `zfs` to an absolute path because PID 1's PATH lookup is
/// unreliable (see `discover.rs::run_cmd` for the same workaround).
/// Without this, `Command::new("zfs")` silently fails to find the
/// binary at boot, `read_zboot_cmdline` returns None, and neither
/// slot-wide nor per-BE `zboot:kernel-cmdline` reaches the kernel.
fn read_zboot_cmdline(dataset: &str) -> Option<String> {
    let zfs = ["/usr/sbin/zfs", "/sbin/zfs", "/usr/bin/zfs", "/bin/zfs"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or("zfs");
    let out = Command::new(zfs)
        .args(["get", "-H", "-o", "value", "zboot:kernel-cmdline", dataset])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8(out.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "-" {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Build the kernel cmdline.
///
/// Defaults: `root=ZFS=<dataset> ro`. The `ZFS=` prefix is the
/// debian `zfs-initramfs` convention; combined with the per-slot
/// cachefile imported by the standard initramfs, this is enough for
/// the BE's kernel to find its rootfs.
///
/// `quiet` is intentionally NOT a default — when a fresh BE panics on
/// first boot, you want the message on screen, not silenced. Operators
/// who want a clean boot can append `quiet` via
/// `zboot:kernel-cmdline=quiet` on the BE/ROOT (or pass via
/// `zboot deploy --cmdline 'quiet'`).
///
/// `extras` carries `zboot:kernel-cmdline` content (per-BE override
/// or slot-wide ROOT-container default) when present.
pub fn build_cmdline(dataset: &str, extras: Option<&str>) -> String {
    let base = format!("root=ZFS={dataset} ro");
    match extras {
        Some(e) if !e.is_empty() => format!("{base} {e}"),
        _ => base,
    }
}

// ---------------------------------------------------------------------------
// Production backend — shell out to `kexec(8)`.
// ---------------------------------------------------------------------------

/// Production [`KexecBackend`]: spawns `/usr/sbin/kexec` from
/// kexec-tools. Bundled into the initrd by `boot/build.sh`.
#[derive(Debug, Default)]
pub struct SystemKexec {
    /// Override path for tests / non-standard initrd layouts.
    pub kexec_bin: Option<PathBuf>,
}

impl SystemKexec {
    /// Default: probe `kexec` on `$PATH`, fall back to
    /// `/usr/sbin/kexec` (debian's kexec-tools install path).
    pub fn new() -> Self {
        Self { kexec_bin: None }
    }

    fn binary(&self) -> &Path {
        self.kexec_bin
            .as_deref()
            .unwrap_or_else(|| Path::new("kexec"))
    }
}

impl KexecBackend for SystemKexec {
    fn load(&mut self, plan: &KexecPlan) -> Result<()> {
        let mut cmd = Command::new(self.binary());
        cmd.arg("-l")
            .arg(&plan.kernel)
            .arg(format!("--initrd={}", plan.initrd.display()))
            .arg(format!("--command-line={}", plan.cmdline));
        let out = cmd
            .output()
            .with_context(|| format!("spawn `{} -l ...`", self.binary().display()))?;
        if !out.status.success() {
            return Err(anyhow!(
                "`kexec -l` exited rc={:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim(),
            ));
        }
        Ok(())
    }

    fn exec(&mut self) -> Result<()> {
        // We use `kexec -e` here rather than calling
        // `nix::sys::reboot::reboot(RB_KEXEC)` directly so that the
        // load + exec pair come from the same binary — kexec-tools
        // does some last-minute purgatory cleanup in `-e` that the
        // raw syscall path skips. If `kexec -e` returns at all, it
        // didn't succeed.
        let mut cmd = Command::new(self.binary());
        cmd.arg("-e");
        let err = cmd.status();
        match err {
            Ok(status) => Err(anyhow!(
                "`kexec -e` returned rc={:?} (should never return on success)",
                status.code(),
            )),
            Err(e) => Err(anyhow!("spawn `kexec -e`: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Test backend — records syscall args without invoking kexec.
// ---------------------------------------------------------------------------

/// Recording [`KexecBackend`] for cargo tests. Captures every
/// `(plan)` tuple passed to `load` and every `exec` call so the test
/// can assert on argv without rebooting the runner.
#[derive(Debug, Default)]
pub struct RecordingBackend {
    pub loads: Vec<KexecPlan>,
    pub exec_calls: usize,
    /// If set, `exec` returns `Err(this)` instead of "succeeding"
    /// (default). Lets tests exercise the "kexec returned without
    /// rebooting" error branch.
    pub exec_returns_err: Option<String>,
}

impl KexecBackend for RecordingBackend {
    fn load(&mut self, plan: &KexecPlan) -> Result<()> {
        self.loads.push(plan.clone());
        Ok(())
    }
    fn exec(&mut self) -> Result<()> {
        self.exec_calls += 1;
        if let Some(msg) = self.exec_returns_err.as_deref() {
            return Err(anyhow!("{msg}"));
        }
        // "Successful" exec from the trait's perspective means the
        // syscall happened — which in production never returns. The
        // [`handoff`] caller upgrades a successful return here into
        // an error ("kexec exec returned without rebooting"). Tests
        // assert on that branch.
        Ok(())
    }
}

// ===========================================================================
// Tests — pure data over [`KexecPlan`] + the recording backend.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn be(dataset: &str) -> BootEnvironment {
        // Skip the canonical `<pool>/ROOT/<name>` constructor — we
        // want full control over `dataset` for testing edge cases.
        let mut b = BootEnvironment::new("rpool", "be1");
        b.dataset = dataset.to_owned();
        b
    }

    fn make_boot(tmp: &Path, kernel: &str, initrd: &str, with_symlink: bool) -> PathBuf {
        let boot = tmp.join("boot");
        fs::create_dir_all(&boot).unwrap();
        fs::write(boot.join(kernel), b"vmlinuz-bytes").unwrap();
        fs::write(boot.join(initrd), b"initrd-bytes").unwrap();
        if with_symlink {
            // Mirror debian's standard layout: `vmlinuz` → `vmlinuz-X`.
            symlink(kernel, boot.join("vmlinuz")).unwrap();
            symlink(initrd, boot.join("initrd.img")).unwrap();
        }
        boot
    }

    // --- build_cmdline ------------------------------------------------------

    #[test]
    fn cmdline_default_shape() {
        let s = build_cmdline("rpool/ROOT/be1", None);
        assert_eq!(s, "root=ZFS=rpool/ROOT/be1 ro");
    }

    #[test]
    fn cmdline_appends_extras() {
        let s = build_cmdline("rpool/ROOT/be1", Some("loglevel=4 nosplash"));
        assert_eq!(s, "root=ZFS=rpool/ROOT/be1 ro loglevel=4 nosplash");
    }

    #[test]
    fn cmdline_ignores_empty_extras() {
        let s = build_cmdline("rpool/ROOT/be1", Some(""));
        assert_eq!(s, "root=ZFS=rpool/ROOT/be1 ro");
    }

    // --- plan / plan_with_kernel -------------------------------------------

    #[test]
    fn plan_resolves_via_symlink_filenames() {
        let tmp = tempdir_for("plan_combines");
        make_boot(
            &tmp,
            "vmlinuz-6.1.0-22-amd64",
            "initrd.img-6.1.0-22-amd64",
            true,
        );
        let p = plan(&be("rpool/ROOT/be1"), &tmp).unwrap();
        // plan() picks the `vmlinuz` / `initrd.img` symlinks.
        assert!(p.kernel.ends_with("vmlinuz"));
        assert!(p.initrd.ends_with("initrd.img"));
        // Default extras come from the bootloader: `zboot.be=<name>
        // console=tty0 console=ttyS0,115200`.
        assert!(p.cmdline.starts_with("root=ZFS=rpool/ROOT/be1 ro"));
        assert!(p.cmdline.contains("zboot.be=be1"));
        assert!(p.cmdline.contains("console=tty0"));
        assert!(p.cmdline.contains("console=ttyS0,115200"));
        assert_eq!(p.dataset, "rpool/ROOT/be1");
    }

    #[test]
    fn plan_propagates_missing_kernel_error() {
        let tmp = tempdir_for("plan_no_kernel");
        let boot = tmp.join("boot");
        fs::create_dir_all(&boot).unwrap();
        // Only initrd, no kernel — `vmlinuz` (the default symlink path)
        // is missing.
        fs::write(boot.join("initrd.img"), b"i").unwrap();
        let e = plan(&be("rpool/ROOT/be1"), &tmp).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("kernel `vmlinuz` not found"), "{msg}");
        assert!(msg.contains("rpool/ROOT/be1"), "{msg}");
    }

    #[test]
    fn plan_with_kernel_picks_specific_filenames() {
        let tmp = tempdir_for("plan_with_kernel_specific");
        let boot = tmp.join("boot");
        fs::create_dir_all(&boot).unwrap();
        // Two kernels staged side-by-side. plan_with_kernel must pick
        // the one we asked for verbatim, not "highest-version".
        fs::write(boot.join("vmlinuz-6.13.0"), b"new").unwrap();
        fs::write(boot.join("initrd.img-6.13.0"), b"new").unwrap();
        fs::write(boot.join("vmlinuz.old"), b"old").unwrap();
        fs::write(boot.join("initrd.img.old"), b"old").unwrap();

        let p = plan_with_kernel(
            &be("rpool/ROOT/be1"),
            &tmp,
            "vmlinuz.old",
            "initrd.img.old",
            None,
        )
        .unwrap();
        assert!(p.kernel.ends_with("vmlinuz.old"));
        assert!(p.initrd.ends_with("initrd.img.old"));
    }

    #[test]
    fn plan_with_kernel_extras_override_replaces_default() {
        let tmp = tempdir_for("plan_with_kernel_extras");
        make_boot(&tmp, "vmlinuz-6.13.0", "initrd.img-6.13.0", true);

        let p = plan_with_kernel(
            &be("rpool/ROOT/be1"),
            &tmp,
            "vmlinuz",
            "initrd.img",
            Some("loglevel=4 nosplash"),
        )
        .unwrap();
        assert!(p.cmdline.starts_with("root=ZFS=rpool/ROOT/be1 ro"));
        assert!(p.cmdline.contains("loglevel=4 nosplash"));
        // Override replaces the default; no `zboot.be=` from us.
        assert!(!p.cmdline.contains("zboot.be="));
        assert!(!p.cmdline.contains("console=ttyS0,115200"));
    }

    #[test]
    fn plan_with_kernel_missing_kernel_carries_filename_in_error() {
        let tmp = tempdir_for("plan_with_kernel_missing");
        let boot = tmp.join("boot");
        fs::create_dir_all(&boot).unwrap();
        let e = plan_with_kernel(
            &be("rpool/ROOT/be1"),
            &tmp,
            "vmlinuz-nope",
            "initrd.img-nope",
            None,
        )
        .unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("vmlinuz-nope"), "{msg}");
    }

    // --- compose_cmdline: structure (stand-alone, no zfs spawn) ------------

    #[test]
    fn compose_cmdline_default_extras_match_legacy_plan() {
        // Without a real `zfs`, `read_zboot_cmdline` returns None — so
        // the composed cmdline must be base + console only (plus
        // spl_hostid if the test host has /etc/hostid — environment
        // dependent, so we don't assert exact equality).
        let s = compose_cmdline(&be("rpool/ROOT/be1"), None);
        assert!(s.starts_with("root=ZFS=rpool/ROOT/be1 ro"));
        assert!(s.contains("zboot.be=be1"));
        assert!(s.contains("console=tty0"));
        assert!(s.contains("console=ttyS0,115200"));
        // zboot.be / console come before spl_hostid (composition order).
        let be_pos = s.find("zboot.be=be1").unwrap();
        if let Some(splh) = s.find("spl_hostid=") {
            assert!(be_pos < splh);
        }
    }

    #[test]
    fn compose_cmdline_override_replaces_default_extras() {
        let s = compose_cmdline(&be("rpool/ROOT/be1"), Some("debug systemd.log_level=debug"));
        assert!(!s.contains("zboot.be="));
        // Operator override comes after base, before any auto-appended
        // spl_hostid. So `debug ...` is contained, and if spl_hostid is
        // present it follows after.
        assert!(s.contains("debug systemd.log_level=debug"));
        let dbg_pos = s.find("debug systemd").unwrap();
        if let Some(splh) = s.find("spl_hostid=") {
            assert!(dbg_pos < splh);
        }
    }

    #[test]
    fn compose_cmdline_appends_spl_hostid_from_runtime_etc_hostid() {
        // Only meaningful when the test host has /etc/hostid (CI runners,
        // dev boxes — most do). When it doesn't, nothing to assert.
        if std::fs::metadata("/etc/hostid")
            .ok()
            .is_some_and(|m| m.len() == 4)
        {
            let s = compose_cmdline(&be("rpool/ROOT/be1"), None);
            assert!(s.contains("spl_hostid=0x"), "{s}");
        }
    }

    // --- decide_gate: pure logic ------------------------------------------

    #[test]
    fn gate_default_closed_on_dev_host() {
        assert_eq!(decide_gate(false, false), Gate::Closed);
    }

    #[test]
    fn gate_open_when_pid_one() {
        assert_eq!(decide_gate(true, false), Gate::Open);
    }

    #[test]
    fn gate_open_with_env_override() {
        assert_eq!(decide_gate(false, true), Gate::Open);
    }

    #[test]
    fn gate_open_when_both_signals_fire() {
        assert_eq!(decide_gate(true, true), Gate::Open);
    }

    // --- handoff_with_gate: closed → "would kexec" without touching backend.

    #[test]
    fn handoff_closed_gate_writes_would_kexec_and_skips_backend() {
        let tmp = tempdir_for("handoff_dev_host");
        make_boot(
            &tmp,
            "vmlinuz-6.1.0-22-amd64",
            "initrd.img-6.1.0-22-amd64",
            true,
        );

        let mut backend = RecordingBackend::default();
        let mut buf: Vec<u8> = Vec::new();
        handoff_with_gate(
            &be("rpool/ROOT/be1"),
            &tmp,
            &mut backend,
            &mut buf,
            Gate::Closed,
        )
        .unwrap();

        // No syscalls happened — backend untouched.
        assert!(backend.loads.is_empty());
        assert_eq!(backend.exec_calls, 0);

        // Caller-visible message is present + actionable.
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("would kexec rpool/ROOT/be1"), "{s}");
        assert!(s.contains("vmlinuz"), "{s}");
        assert!(s.contains("initrd.img"), "{s}");
        assert!(s.contains("root=ZFS=rpool/ROOT/be1 ro"), "{s}");
    }

    // --- handoff_with_gate: open → backend sees the load + exec. -----------

    #[test]
    fn handoff_open_gate_invokes_backend() {
        let tmp = tempdir_for("handoff_env_override");
        make_boot(
            &tmp,
            "vmlinuz-6.1.0-22-amd64",
            "initrd.img-6.1.0-22-amd64",
            true,
        );

        let mut backend = RecordingBackend::default();
        let mut buf: Vec<u8> = Vec::new();
        // exec returns Ok in the recording backend → handoff promotes
        // that to "kexec exec returned without rebooting" Err.
        let err = handoff_with_gate(
            &be("rpool/ROOT/be1"),
            &tmp,
            &mut backend,
            &mut buf,
            Gate::Open,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("returned without rebooting"));

        // Both syscalls happened; the load argv carries the BE's
        // dataset in the cmdline.
        assert_eq!(backend.loads.len(), 1);
        let p = &backend.loads[0];
        // plan() appends `zboot.be=<name>` (so the BE-side initrd can
        // identify itself) and `console=tty0 console=ttyS0,115200`.
        assert!(p.cmdline.starts_with("root=ZFS=rpool/ROOT/be1 ro"));
        assert!(p.cmdline.contains("zboot.be=be1"));
        assert!(p.cmdline.contains("console=tty0"));
        assert!(p.cmdline.contains("console=ttyS0,115200"));
        assert_eq!(p.dataset, "rpool/ROOT/be1");
        assert!(p.kernel.ends_with("vmlinuz"));
        assert!(p.initrd.ends_with("initrd.img"));
        assert_eq!(backend.exec_calls, 1);
    }

    // --- handoff_with_gate: load failure surfaces with kernel+initrd context.

    /// Backend whose `load` always fails — used to assert the error
    /// path in `handoff` carries kernel/initrd context.
    struct FailLoad;
    impl KexecBackend for FailLoad {
        fn load(&mut self, _plan: &KexecPlan) -> Result<()> {
            Err(anyhow!("syscall ENOMEM"))
        }
        fn exec(&mut self) -> Result<()> {
            unreachable!("load failed; exec should not run")
        }
    }

    #[test]
    fn handoff_load_error_carries_kernel_path() {
        let tmp = tempdir_for("handoff_load_err");
        make_boot(
            &tmp,
            "vmlinuz-6.1.0-22-amd64",
            "initrd.img-6.1.0-22-amd64",
            true,
        );

        let mut backend = FailLoad;
        let mut buf: Vec<u8> = Vec::new();
        let err = handoff_with_gate(
            &be("rpool/ROOT/be1"),
            &tmp,
            &mut backend,
            &mut buf,
            Gate::Open,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("kexec load failed"), "{msg}");
        assert!(msg.contains("vmlinuz"), "{msg}");
        assert!(msg.contains("syscall ENOMEM"), "{msg}");
    }

    // --- system_kexec_binary_default ---------------------------------------

    #[test]
    fn system_kexec_binary_default_is_kexec() {
        let s = SystemKexec::new();
        assert_eq!(s.binary(), Path::new("kexec"));
    }

    #[test]
    fn system_kexec_binary_override_honored() {
        let s = SystemKexec {
            kexec_bin: Some(PathBuf::from("/opt/zboot/kexec")),
        };
        assert_eq!(s.binary(), Path::new("/opt/zboot/kexec"));
    }

    // --- helpers ------------------------------------------------------------

    fn tempdir_for(slug: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zboot-kexec-{slug}-{pid}-{nanos}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
