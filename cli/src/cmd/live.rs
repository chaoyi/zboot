//! `zboot live` — build a minimal Debian Live image plus the surrounding
//! PXE-staging tree (zboot-boot.efi at the root, optional `menu.ipxe`).
//!
//! With no `--packages`, this produces zboot's *minimal* live image:
//! kernel + live-boot + sshd (live-build's vanilla `live`/`live` user)
//! + zfsutils + kexec + a recovery toolkit (gdisk, parted, cryptsetup,
//! lvm2, efibootmgr, …) + the bundled `zboot` CLI.  Downstream wrappers
//! layer extras via `--packages`, `--hooks-dir`, `--includes-dir` —
//! same shape as `zboot factory`.
//!
//! Output tree (at `--output`, default `~/.cache/zboot/pxe/`):
//!
//! ```text
//! <output>/
//! ├── zboot-boot.efi              ← extracted from the CLI's embedded copy
//! ├── menu.ipxe                   ← generated; suppress with --no-menu
//! └── debianlive/
//!     ├── vmlinuz
//!     ├── initrd.img
//!     └── filesystem.squashfs
//! ```
//!
//! `rsync -av <output>/ root@router:/srv/tftpboot/zboot/` deploys the
//! whole tree.  Operators chain from a parent menu via
//! `chain ${boot-url}zboot/menu.ipxe`.
//!
//! Needs `live-build` on PATH and `sudo` (live-build invokes a chroot
//! that requires root; the script uses `sudo lb build` rather than
//! requiring the operator to run zboot as root).
//!
//! For sandboxed/in-VM execution (no host live-build, mount-namespace
//! confinement that blocks mknod-in-chroot, cross-build) use the
//! standalone `scripts/internal/live-in-vm.sh` — it boots a vanilla
//! Debian cloud image in QEMU, cloud-init injects the operator's SSH
//! key + installs `live-build`, then runs `zboot live` inside.  That
//! script is *not* embedded into this binary — it's an operator-facing
//! wrapper, run as `bash scripts/internal/live-in-vm.sh`.
//!
//! Wall clock: ~10–20 min (host or in-VM, the inner work is the same).

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::cmd::efi;

const SCRIPT: &str = include_str!("../../../scripts/internal/build-debian-live.sh");

#[derive(Debug, Args)]
pub struct LiveArgs {
    /// Output dir (created if missing).  Default: ~/.cache/zboot/pxe.
    /// Writes a complete PXE-staging tree: zboot-boot.efi at the root,
    /// menu.ipxe (unless --no-menu), and debianlive/{vmlinuz,initrd.img,
    /// filesystem.squashfs}.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Debian release suite. Default: testing.
    #[arg(long, default_value = "testing")]
    pub suite: String,

    /// Extra apt packages to add on top of the minimal floor.  Repeatable,
    /// comma-separated also accepted.  Used by downstream wrappers to layer
    /// extras (operator-convenience packages, vendor firmware, hardware-
    /// specific tools, …) without zboot owning the list.  No `--packages`
    /// → minimal live.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub packages: Vec<String>,

    /// Caller-supplied hooks dir.  Files copied into
    /// `config/hooks/normal/` before `lb build`.  Use for chroot-time
    /// installers (e.g. download a binary, install a CA cert).
    #[arg(long)]
    pub hooks_dir: Option<PathBuf>,

    /// Caller-supplied includes dir.  Merged into
    /// `config/includes.chroot_after_packages/`.  Use for files dropped
    /// into the live filesystem (e.g. dotfiles under /etc/skel/).
    #[arg(long)]
    pub includes_dir: Option<PathBuf>,

    /// Install zfs-dkms (and siblings) from this apt suite instead of
    /// `--suite`.  Mirrors `zboot factory --zfs-from-suite`.  Default:
    /// sid (testing's kernel currently outpaces its zfs-dkms; sid is
    /// where the working version lives).  Empty string disables the
    /// override (use only `--suite`'s zfs).
    #[arg(long, default_value = "sid")]
    pub zfs_from_suite: String,

    /// Skip writing `<output>/menu.ipxe`.  Use when integrating into a
    /// downstream PXE setup that has its own multi-OS menu and just
    /// wants the zboot artifacts (zboot-boot.efi + debianlive/).
    #[arg(long)]
    pub no_menu: bool,
}

pub fn run(args: &LiveArgs, w: &mut impl Write) -> Result<()> {
    check_prereqs()?;

    let output = resolve_output(args)?;
    let zboot_self = std::env::current_exe().context("locate this CLI binary")?;
    let extras = args.packages.join(",");

    let label = if extras.is_empty() { "minimal" } else { "extended" };
    writeln!(w, "[zboot live] live-build → {label} debian live (~10-20min)")?;
    writeln!(w, "  output:      {}", output.display())?;
    writeln!(w, "  suite:       {}", args.suite)?;
    writeln!(w, "  zboot bin:   {}", zboot_self.display())?;
    if !extras.is_empty() {
        writeln!(w, "  extra pkgs:  {extras}")?;
    }
    if let Some(d) = &args.hooks_dir {
        writeln!(w, "  hooks dir:   {}", d.display())?;
    }
    if let Some(d) = &args.includes_dir {
        writeln!(w, "  includes:    {}", d.display())?;
    }
    if !args.zfs_from_suite.is_empty() {
        writeln!(w, "  zfs from:    {} (apt-pinned)", args.zfs_from_suite)?;
    }
    writeln!(w, "  menu.ipxe:   {}", if args.no_menu { "no (--no-menu)" } else { "yes" })?;
    writeln!(w)?;

    let script_path = stage_script(SCRIPT, "zboot-debian-live")?;
    let mut cmd = Command::new("bash");
    cmd.arg(&script_path)
        .env("ZBOOT_BIN", &zboot_self)
        .env("OUTPUT_DIR", &output)
        .env("DEBIAN_SUITE", &args.suite)
        .env("EXTRA_PACKAGES", &extras)
        .env("ZFS_FROM_SUITE", &args.zfs_from_suite)
        .env("GENERATE_MENU", if args.no_menu { "" } else { "1" });
    if let Some(d) = &args.hooks_dir {
        cmd.env("EXTRA_HOOKS_DIR", d);
    }
    if let Some(d) = &args.includes_dir {
        cmd.env("EXTRA_INCLUDES_DIR", d);
    }
    let status = cmd.status().context("spawn embedded build-debian-live script")?;
    let _ = std::fs::remove_file(&script_path);

    if !status.success() {
        bail!("debian-live build failed (rc={:?})", status.code());
    }

    // Drop the embedded EFI bundle into the staging root so the output
    // tree is self-contained.  Done by the CLI rather than the script
    // because the bundle is bytes baked into this binary, not a file
    // the script can find.
    let efi_dest = output.join("zboot-boot.efi");
    efi::write_embedded(&efi_dest)
        .with_context(|| format!("write zboot-boot.efi to {}", efi_dest.display()))?;
    writeln!(w, "  + zboot-boot.efi  ({} B, from embedded copy)",
        efi::EMBEDDED_EFI_BYTES.len())?;

    writeln!(w, "✓ {label} debian live ready: {}/", output.display())?;
    Ok(())
}

/// Resolve `--output` against the default cache location and ensure it
/// exists. Default: `~/.cache/zboot/pxe/`.
fn resolve_output(args: &LiveArgs) -> Result<PathBuf> {
    let path = match &args.output {
        Some(p) => p.clone(),
        None => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .context("HOME env var not set")?;
            home.join(".cache/zboot/pxe")
        }
    };
    std::fs::create_dir_all(&path)
        .with_context(|| format!("create output dir {}", path.display()))?;
    Ok(path)
}

/// Preflight: fail fast with a single batched error listing missing
/// host tools.  The script does its own preflight too, so this is just
/// the host-tool gate that's visible at the CLI layer.
///
/// Mirrors `cmd::factory`: if the host can't satisfy the prereqs, point
/// the operator at `scripts/internal/live-in-vm.sh`, which boots a
/// clean Debian cloud-image VM and runs `zboot live` inside.  Use
/// that path for sandboxed environments where live-build's chroot
/// can't `mknod /dev/null` (mount-namespace confinement), or for
/// cross-builds without `live-build` on the host.
fn check_prereqs() -> Result<()> {
    let mut missing: Vec<String> = Vec::new();
    if !is_executable("lb") {
        missing.push("lb (apt install live-build)".into());
    }
    if !is_executable("sudo") {
        missing.push("sudo".into());
    }
    if !missing.is_empty() {
        bail!(
            "prereqs missing:\n  - {}\n\n\
             Install them, or run sandboxed via \
             `bash scripts/internal/live-in-vm.sh` — \
             builds inside a clean Debian cloud-image VM, no host live-build needed.",
            missing.join("\n  - "),
        );
    }
    Ok(())
}

// ── helpers (mirror cmd::factory's; duplicated per the verb-isolation rule) ──

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_output_explicit_path_creates_dir() {
        let tmp = tempdir_for_test();
        let target = tmp.join("subdir");
        let args = LiveArgs {
            output: Some(target.clone()),
            suite: "testing".into(),
            packages: vec![],
            hooks_dir: None,
            includes_dir: None,
            zfs_from_suite: "sid".into(),
            no_menu: false,
        };
        let resolved = resolve_output(&args).unwrap();
        assert_eq!(resolved, target);
        assert!(resolved.is_dir(), "explicit --output dir should be created");
    }

    fn tempdir_for_test() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "zboot-live-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
