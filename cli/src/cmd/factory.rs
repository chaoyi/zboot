//! `zboot factory` — build the host-agnostic factory BE tar that
//! `zboot deploy --source tar://...` consumes.
//!
//! With no `--packages`, this produces zboot's *stock* factory tar
//! (kernel + zfs.ko via DKMS + sshd binary + NetworkManager + ESP
//! tooling + firmware-linux) — used as the test fixture for zboot's
//! own `scripts/*.sh` e2e suite.  Downstream wrappers layer the
//! production package set on top via `--packages a,b,c`.
//!
//! Always runs the host-direct path: debootstrap + chroot + apt install
//! + tar.  ~5min.  Needs root + `debootstrap` on PATH.
//!
//! For sandboxed/in-VM execution (no host root, no host debootstrap,
//! cross-build) use the standalone `scripts/internal/factory-in-vm.sh`
//! — it boots a vanilla Debian cloud image in QEMU, cloud-init injects
//! the operator's SSH key + installs `debootstrap`, then runs
//! `zboot factory` inside.  That script is *not* embedded into this
//! binary — it's an operator-facing wrapper, run as
//! `bash scripts/internal/factory-in-vm.sh`.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args;

const SCRIPT_HOST: &str = include_str!("../../../scripts/internal/build-factory-tar.sh");

#[derive(Debug, Args)]
pub struct FactoryArgs {
    /// Output tar path. Default: ~/.cache/zboot/factory.tar.zst (created if missing).
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Debian release suite to debootstrap.  Default: trixie (Debian 13).
    /// Use `testing` or `sid` to track the moving train.
    #[arg(long, default_value = "trixie")]
    pub suite: String,

    /// Extra Debian packages to apt-install in the chroot, on top of the
    /// stock zboot floor (kernel + zfs-dkms + sshd binary + NetworkManager
    /// + firmware-linux + ESP tooling).  Repeatable, comma-separated also
    /// accepted.  Used by downstream wrappers to layer additional packages
    /// (secrets management, backup, vendor firmware, …) without zboot owning
    /// the list.  No `--packages` → stock factory tar (zboot's own e2e fixture).
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub packages: Vec<String>,

    /// After the kernel install (which compiles zfs.ko via DKMS), purge
    /// linux-headers + DKMS sources.  Saves ~300MB of tar size.  Trade:
    /// the BE can't auto-rebuild zfs.ko on kernel updates — operator
    /// must manually `apt install linux-headers-amd64 && dpkg-reconfigure
    /// zfs-dkms`.  Test/smoke-only — not for production.
    #[arg(long)]
    pub no_headers: bool,

    /// Install zfs-dkms (and siblings) from this apt suite instead of
    /// `--suite`.  Use when --suite's kernel ships ahead of its zfs-dkms
    /// (testing's 7.0.4 + zfs 2.4.1 fails — kernel range 4.18-6.19;
    /// `--zfs-from-suite sid` pulls 2.4.2 which supports up to 7.0).
    /// Adds the suite as an extra apt source with apt-pinning so only
    /// zfs-related packages come from it.
    #[arg(long)]
    pub zfs_from_suite: Option<String>,
}

pub fn run(args: &FactoryArgs, w: &mut impl Write) -> Result<()> {
    check_prereqs()?;

    let output = resolve_output(args)?;
    let zboot_self = std::env::current_exe().context("locate this CLI binary")?;
    let extras = args.packages.join(" ");

    let label = if extras.is_empty() { "stock" } else { "factory" };
    writeln!(w, "[zboot factory] debootstrap + chroot (~5min) — {label} tar")?;
    writeln!(w, "  output:      {}", output.display())?;
    writeln!(w, "  suite:       {}", args.suite)?;
    writeln!(w, "  zboot bin:   {}", zboot_self.display())?;
    if !extras.is_empty() {
        writeln!(w, "  extra pkgs:  {extras}")?;
    }
    if args.no_headers {
        writeln!(w, "  --no-headers: purging linux-headers + DKMS sources after compile")?;
    }
    writeln!(w)?;

    if let Some(s) = &args.zfs_from_suite {
        writeln!(w, "  zfs from:    {s} (pinned via apt preferences)")?;
    }

    let script_path = stage_script(SCRIPT_HOST, "zboot-factory-tar")?;
    let mut cmd = Command::new("bash");
    cmd.arg(&script_path)
        .env("ZBOOT_BIN", &zboot_self)
        .env("FACTORY_TAR", &output)
        .env("DEBIAN_SUITE", &args.suite)
        .env("EXTRA_PACKAGES", &extras)
        .env("NO_HEADERS", if args.no_headers { "1" } else { "" })
        .env("ZFS_FROM_SUITE", args.zfs_from_suite.as_deref().unwrap_or(""));
    let status = cmd.status().context("spawn embedded build-factory-tar script")?;
    let _ = std::fs::remove_file(&script_path);

    if !status.success() {
        bail!("{label} tar build failed (rc={:?})", status.code());
    }
    writeln!(w, "✓ {label} tar ready: {}", output.display())?;
    Ok(())
}

/// Resolve `--output` against the default cache location.  Default:
/// `~/.cache/zboot/factory.tar.zst` — the no-extras default produces
/// zboot's stock factory tar (test fixture).  The parent dir is created
/// if it doesn't exist (so first-time users don't have to mkdir).
fn resolve_output(args: &FactoryArgs) -> Result<PathBuf> {
    let path = match &args.output {
        Some(p) => p.clone(),
        None => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .context("HOME env var not set")?;
            home.join(".cache/zboot/factory.tar.zst")
        }
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", path.display()))?;
    }
    Ok(path)
}

/// Preflight: fail fast with a single batched error listing every
/// missing dep + an actionable install hint.  If host can't run
/// debootstrap directly (no root, missing tool, cross-build),
/// the message points at `scripts/internal/factory-in-vm.sh` as the workaround.
fn check_prereqs() -> Result<()> {
    let mut missing: Vec<String> = Vec::new();
    if !is_executable("debootstrap") {
        missing.push("debootstrap (apt install debootstrap)".into());
    }
    for tool in ["chroot", "mount", "umount", "tar"] {
        if !is_executable(tool) {
            missing.push(format!("{tool} (core util)"));
        }
    }
    if !missing.is_empty() {
        bail!(
            "prereqs missing:\n  - {}\n\n\
             Install them, or run from within a Debian VM via \
             `bash scripts/internal/factory-in-vm.sh` (clean cloud image, \
             no host install needed).",
            missing.join("\n  - "),
        );
    }
    if !is_root() {
        bail!(
            "needs root (debootstrap + chroot + bind-mount).\n  \
             Re-run via: sudo -E zboot factory\n  \
             (or run sandboxed via `bash scripts/internal/factory-in-vm.sh` — \
             builds inside a clean Debian cloud-image VM, no host root needed)",
        );
    }
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────

fn is_root() -> bool {
    // Workspace forbids unsafe; can't call libc::geteuid.  Read
    // /proc/self/status's `Uid:` line — second column is effective UID
    // on Linux.  /proc absence → assume not-root (only flips the
    // helpful-hint message; not a correctness bug).
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|fields| fields.split_whitespace().nth(1).map(str::to_owned))
        })
        .is_some_and(|euid| euid == "0")
}

fn is_executable(name: &str) -> bool {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join(name).is_file() {
                return true;
            }
        }
    }
    for prefix in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        if Path::new(prefix).join(name).is_file() {
            return true;
        }
    }
    false
}

fn stage_script(content: &str, prefix: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("{prefix}-{}.sh", std::process::id()));
    std::fs::write(&path, content)
        .with_context(|| format!("write embedded script to {}", path.display()))?;
    let mut perms = std::fs::metadata(&path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms)?;
    Ok(path)
}
