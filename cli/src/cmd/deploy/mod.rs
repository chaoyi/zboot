//! `zboot deploy` — fresh-disk install.
//!
//! Partition (sfdisk GPT) → zpool create → populate the initial BE
//! from a `tar://` or `debootstrap://` source → install `zboot-boot`
//! to the ESP → register an NVRAM entry via `efibootmgr`.
//!
//! Source URL: `tar://<path>` or `debootstrap://<suite>[?mirror=<url>]`.
//! `zfs-recv://` and `restic://` are reserved (rejected at parse time)
//! per DESIGN.md § Sources.
//!
//! Live deploy requires typing the disk basename (`vda` for `/dev/vda`)
//! on stdin. Env bypass: `ZBOOT_DEPLOY_CONFIRM_DISK=<basename>` for the
//! e2e scripts. EFI bundle discovery: `ZBOOT_EFI_BUNDLE` env or
//! `/usr/share/zboot/zboot-boot.efi`.
//!
//! Submodules:
//! - [`source`] — URL parsing (Source enum, debootstrap constants)
//! - [`plan`]   — operation list + Display rendering
//! - [`be`]     — BE population (tar / debootstrap+DKMS)
//! - [`esp`]    — ESP install + NVRAM register

use std::fmt::Write as _;
use std::io::{BufRead, Write};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args;

mod be;
pub(crate) mod esp;
pub(crate) mod plan;
mod source;

use plan::{Mode, Plan};

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)] // CLI args; each bool is independently meaningful
pub struct DeployArgs {
    /// Target block device (`/dev/nvme0n1`, `/dev/vda`). Default layout:
    /// partition into ESP (512MiB) + root pool (rest). With `--no-efi`,
    /// the whole disk is given to ZFS — no partitioning, no ESP.
    /// Must be empty (preflight) unless `ZBOOT_DEPLOY_ALLOW_NONEMPTY=1`.
    #[arg(long)]
    pub target: Option<String>,

    /// Skip the ESP partition + `zboot-boot.efi` write + `efibootmgr`
    /// entry. The target becomes a whole-disk pool with no local
    /// bootloader — boot is recovered via another disk's ESP. Use for
    /// failover slots or pool-prep workflows where EFI lives elsewhere.
    #[arg(long)]
    pub no_efi: bool,

    /// Skip BE installation. Pool + `zboot:role=root` tag + `ROOT`
    /// container land; nothing else. Useful for prepping a target that
    /// `zboot mirror --to` will populate later. Mutually exclusive with
    /// `--source` / `--mirror-from` / `--cmdline`.
    #[arg(long, conflicts_with_all = ["source", "mirror_from", "cmdline"])]
    pub empty: bool,

    /// Hostname — drives `hostid = sha256(hostname)[:4]` and `/etc/hostname`.
    #[arg(long)]
    pub hostname: String,

    /// Initial BE name. Lives at `<pool>/ROOT/<be>`. Default `be1`.
    /// Ignored when `--mirror-from` is set (mirror brings the BE name
    /// from the source pool) or `--empty` is set (no BE).
    #[arg(long, default_value = "be1")]
    pub be: String,

    /// Source URL — `tar://<path>` or `debootstrap://<suite>[?mirror=...]`.
    /// Optional: when omitted (and `--empty` / `--mirror-from` aren't
    /// set), defaults to `debootstrap://<--suite value>`.
    #[arg(long, conflicts_with = "mirror_from")]
    pub source: Option<String>,

    /// Debian suite for the implicit debootstrap source. Ignored when
    /// `--source` is explicitly set. Default `trixie` (current stable).
    #[arg(long, default_value = "trixie")]
    pub suite: String,

    /// Populate the new pool by mirroring from an existing root pool.
    /// Skips the source/populate/identity steps; runs
    /// `zboot mirror --to <new-pool>` after pool creation.
    #[arg(long, conflicts_with = "source")]
    pub mirror_from: Option<String>,

    /// Initial slot-wide cmdline. Written to `zboot:kernel-cmdline` on
    /// `<pool>/ROOT`. Ignored when `--mirror-from` is set.
    #[arg(long)]
    pub cmdline: Option<String>,

    /// Pool name. Default `rpool`.
    #[arg(long, default_value = "rpool")]
    pub pool: String,

    /// Print the plan and exit 0. No disk writes.
    #[arg(long)]
    pub check: bool,

    /// Alias for `--check`.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the `@deploy` rollback snapshot at the end. Default-on
    /// because a fresh BE with no rollback point is a footgun (one
    /// `passwd` typo and you can't recover). Opt out for ephemeral
    /// installs / CI / scenarios where the snapshot churn is noise.
    #[arg(long)]
    pub no_snapshot: bool,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

pub fn run(args: &DeployArgs, w: &mut impl Write) -> Result<()> {
    let stdin = std::io::stdin();
    let mut locked = stdin.lock();
    run_inner(args, &mut locked, w)
}

fn run_inner<R: BufRead, W: Write>(args: &DeployArgs, stdin: &mut R, out: &mut W) -> Result<()> {
    let plan = Plan::compose(args)?;

    writeln!(out, "{plan}").context("write deploy plan")?;

    if args.check || args.dry_run {
        ensure_disk_empty(plan.pool_disk_for_preflight(), out)?;
        return Ok(());
    }

    ensure_disk_empty(plan.pool_disk_for_preflight(), out)?;
    ensure_no_pool_name_collision(&args.pool, out)?;
    let env_bypass = std::env::var("ZBOOT_DEPLOY_CONFIRM_DISK").ok();
    confirm_target(&plan.target_basename, env_bypass.as_deref(), stdin, out)?;
    execute_live(args, &plan, out)
}

/// Refuse to deploy if a pool with the target name already exists
/// anywhere visible — currently imported OR importable from a disk.
/// ZFS resolves pools by name at boot time; two same-named pools means
/// BE's initramfs picks one arbitrarily, and a fresh `zpool create`
/// would fail outright.
fn ensure_no_pool_name_collision<W: Write>(target_pool: &str, out: &mut W) -> Result<()> {
    writeln!(out, "[ ] preflight: no other `{target_pool}` visible").ok();
    if crate::pools::is_pool_imported(target_pool)? {
        anyhow::bail!(
            "pool `{target_pool}` is CURRENTLY IMPORTED on this system. \
             `zpool create {target_pool} ...` would fail. \
             Resolve by one of: \
             (a) `zpool export {target_pool}` then re-run deploy; \
             (b) `zpool destroy {target_pool}` if the existing pool is disposable; \
             (c) re-run deploy with `--pool <other-name>` for a multi-pool host."
        )
    }
    let importable = crate::pools::importable_pools()?;
    if importable.iter().any(|n| n == target_pool) {
        anyhow::bail!(
            "an importable pool named `{target_pool}` already exists on another disk. \
             Deploy refuses to proceed — at boot time, ZFS would resolve `{target_pool}` to one of \
             them arbitrarily. Resolve by one of: \
             (a) `zpool import {target_pool}` to confirm which disk, then `zpool destroy {target_pool}`; \
             (b) `wipefs -a <disk>` on the conflicting disk to remove ZFS labels; \
             (c) re-run deploy with `--pool <other-name>` for a multi-pool host."
        )
    }
    writeln!(out, "[x] preflight: no other `{target_pool}` visible").ok();
    Ok(())
}

#[allow(clippy::too_many_lines)] // step-by-step orchestration is more readable inline
fn execute_live<W: Write>(args: &DeployArgs, plan: &Plan, out: &mut W) -> Result<()> {
    writeln!(out, "\n=== executing deploy ===").context("write exec header")?;

    if plan.has_esp() {
        let d = plan.disk.clone();
        step(out, "wipe target + sfdisk GPT", move || {
            wipe_and_partition(&d)
        })?;
    } else {
        let d = plan.disk.clone();
        step(out, "wipe target disk labels", move || wipe_disk_labels(&d))?;
    }

    step(out, "write host hostid", || {
        write_host_hostid(&plan.hostid_hex)
    })?;
    step(out, "zpool create", || {
        create_pool(&args.pool, &plan.pool_partition)
    })?;
    step(out, "tag pool role=root", || {
        zpool_set("zboot:role=root", &args.pool)
    })?;
    step(out, "create ROOT container", || {
        create_root_container(&args.pool)
    })?;

    match &plan.mode {
        Mode::MirrorFrom(src_pool) => {
            writeln!(out, "[ ] mirror from {src_pool} → {}", args.pool).ok();
            let exe =
                std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("zboot"));
            let st = Command::new(&exe)
                .args(["mirror", "--to", &args.pool])
                .status()
                .with_context(|| format!("spawn `{} mirror --to {}`", exe.display(), args.pool))?;
            if !st.success() {
                bail!("`zboot mirror --to {}` rc={:?}", args.pool, st.code());
            }
            writeln!(out, "[x] mirror complete").ok();
        }
        Mode::Source(src) => {
            step(out, "create BE dataset", || {
                create_be_dataset(&plan.be_dataset)
            })?;
            step(out, "tag BE", || zfs_set("zboot:be=true", &plan.be_dataset))?;

            let mountpoint = format!("/tmp/zboot-deploy-{}", std::process::id());
            step(out, &format!("mount BE at {mountpoint}"), || {
                mount_be(&plan.be_dataset, &mountpoint)
            })?;

            // Identity (/etc/hostid + /etc/hostname) is threaded into populate
            // so the debootstrap path can write it BEFORE `update-initramfs`
            // runs — otherwise zfs-initramfs bakes the wrong hostid into the
            // BE's initramfs.
            writeln!(out, "[ ] populate from {}", src.render()).ok();
            be::populate_be(src, &mountpoint, &plan.hostid_hex, &args.hostname, out)?;
            writeln!(out, "[x] populate complete").ok();

            // For tar sources, the archive may have overwritten or never
            // populated /etc/hostid + /etc/hostname. Re-write unconditionally
            // — idempotent for debootstrap (which already wrote the same bytes).
            step(out, "write BE hostid + hostname", || {
                be::write_be_identity(&mountpoint, &plan.hostid_hex, &args.hostname)
            })?;

            step(out, "empty root password (first-boot access)", || {
                be::empty_root_password(&mountpoint)
            })?;

            // Append cpio-newc overlay carrying per-host /etc/hostid to
            // every /boot/initrd.img-*. See DESIGN.md § "Hostid handling".
            writeln!(out, "[ ] cpio-overlay /etc/hostid in BE's initrds").ok();
            be::overlay_hostid_in_initrds(&mountpoint, &plan.hostid_hex, out)?;
            writeln!(out, "[x] cpio-overlay /etc/hostid in BE's initrds").ok();

            if let Some(c) = &args.cmdline {
                step(out, "set zboot:kernel-cmdline on ROOT", || {
                    zfs_set(
                        &format!("zboot:kernel-cmdline={c}"),
                        &format!("{}/ROOT", args.pool),
                    )
                })?;
            }

            step(out, "set bootfs", || {
                zpool_set(&format!("bootfs={}", plan.be_dataset), &args.pool)
            })?;

            if !args.no_snapshot {
                step(out, "snapshot @deploy (rollback point)", || {
                    zfs_snapshot(&format!("{}@deploy", plan.be_dataset))
                })?;
            }

            step(out, "unmount BE", || unmount_be(&mountpoint))?;
        }
        Mode::Empty => {
            writeln!(
                out,
                "[ ] --empty: no BE installed; bootfs left unset",
            )
            .ok();
        }
    }

    // ESP install + NVRAM. Skipped entirely when `--no-efi` strips the
    // ESP. When `--empty` is set without `--no-efi`, the bootloader is
    // still written — `zboot-boot.efi` handles a missing `bootfs`
    // gracefully, so a future `zfs send | receive` + `zpool set bootfs`
    // produces a bootable slot without re-touching the ESP.
    if plan.has_esp() {
        match esp::resolve_efi_bundle() {
            Ok(bundle) => {
                writeln!(out, "[ ] EFI bundle: {}", bundle.display()).ok();
                esp::install_efi_for_layout(plan, &bundle, out)?;
            }
            Err(e) => {
                writeln!(
                    out,
                    "[!] ESP install skipped: {e:#}\n    set ZBOOT_EFI_BUNDLE=/path/to/zboot-boot.efi \
                     or place the bundle at /usr/share/zboot/zboot-boot.efi to enable.",
                )
                .ok();
            }
        }
    } else {
        writeln!(
            out,
            "[ ] ESP/bootloader skipped (--no-efi — boot via another disk's bootloader)",
        )
        .ok();
    }

    writeln!(out, "\n=== deploy complete ===").ok();
    Ok(())
}

/// Wrap a unit of work with `[ ] step / [x] step` framing on `out`. Errors
/// bubble — failure on any step aborts the deploy with a partial-state
/// disk; user runs `wipefs` and retries.
fn step<F, W: Write>(out: &mut W, label: &str, f: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    writeln!(out, "[ ] {label}").ok();
    f().with_context(|| format!("step `{label}` failed"))?;
    writeln!(out, "[x] {label}").ok();
    Ok(())
}

// ---------------------------------------------------------------------------
// Disk + pool primitives — kept here because they're orchestrated tightly
// with `execute_live`'s step sequence.
// ---------------------------------------------------------------------------

fn wipe_disk_labels(disk: &str) -> Result<()> {
    spawn("wipefs", &["-a", disk])?;
    spawn("sgdisk", &["-Z", disk])
}

fn wipe_and_partition(disk: &str) -> Result<()> {
    spawn("wipefs", &["-a", disk])?;
    spawn("sgdisk", &["-Z", disk])?;
    let script = "label: gpt\n,512MiB,U\n,,L\n";
    let mut child = Command::new("sfdisk")
        .arg(disk)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawn sfdisk")?;
    {
        use std::io::Write as _;
        let stdin = child.stdin.as_mut().context("sfdisk has no stdin")?;
        stdin
            .write_all(script.as_bytes())
            .context("write sfdisk script")?;
    }
    let st = child.wait().context("wait sfdisk")?;
    if !st.success() {
        bail!("sfdisk {disk} rc={:?}", st.code());
    }
    let _ = spawn("partprobe", &[disk]).or_else(|_| spawn("partx", &["-u", disk]));
    // Wait for udev to create partition device nodes — without this,
    // `zpool create /dev/vda2` immediately after `sfdisk` races udev
    // and fails with "cannot resolve path /dev/vda2".
    let _ = spawn("udevadm", &["settle", "--timeout=30"]);
    Ok(())
}

/// Write 4 raw bytes (little-endian from the 8-hex digest) to
/// `/etc/hostid`. Affects the deploy *host* — `zpool create` reads
/// this at pool-create time.
fn write_host_hostid(hex8: &str) -> Result<()> {
    let bytes = hex_to_bytes_le(hex8)?;
    std::fs::write("/etc/hostid", bytes).context("write /etc/hostid")
}

pub(super) fn hex_to_bytes_le(hex8: &str) -> Result<[u8; 4]> {
    if hex8.len() != 8 {
        bail!("hostid hex must be 8 chars, got {}", hex8.len());
    }
    let mut out = [0u8; 4];
    for (i, chunk) in (0..4).zip(hex8.as_bytes().chunks(2)) {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)
            .with_context(|| format!("non-hex byte at offset {i}"))?;
    }
    Ok(out)
}

fn create_pool(pool: &str, partition: &str) -> Result<()> {
    // `compatibility=openzfs-2.1-linux` pins the feature set the pool
    // is created with. Without it, the host running deploy may enable
    // newer features that the BE's own ZFS doesn't understand, making
    // the boot-time `zpool import` refuse.
    spawn(
        "zpool",
        &[
            "create",
            "-f",
            "-o",
            "ashift=12",
            "-o",
            "cachefile=none",
            "-o",
            "compatibility=openzfs-2.1-linux",
            "-O",
            "canmount=off",
            "-O",
            "mountpoint=none",
            "-O",
            "compression=zstd",
            "-O",
            "xattr=sa",
            "-O",
            "acltype=posixacl",
            pool,
            partition,
        ],
    )
}

fn create_root_container(pool: &str) -> Result<()> {
    spawn(
        "zfs",
        &[
            "create",
            "-o",
            "canmount=off",
            "-o",
            "mountpoint=none",
            &format!("{pool}/ROOT"),
        ],
    )
}

fn create_be_dataset(dataset: &str) -> Result<()> {
    spawn(
        "zfs",
        &[
            "create",
            "-o",
            "canmount=noauto",
            "-o",
            "mountpoint=/",
            dataset,
        ],
    )
}

fn mount_be(dataset: &str, mountpoint: &str) -> Result<()> {
    std::fs::create_dir_all(mountpoint).with_context(|| format!("mkdir {mountpoint}"))?;
    spawn(
        "mount",
        &["-t", "zfs", "-o", "zfsutil", dataset, mountpoint],
    )
}

pub(crate) fn unmount_be(mountpoint: &str) -> Result<()> {
    spawn("umount", &[mountpoint])
}

fn zpool_set(prop: &str, pool: &str) -> Result<()> {
    spawn("zpool", &["set", prop, pool])
}

fn zfs_set(prop: &str, dataset: &str) -> Result<()> {
    spawn("zfs", &["set", prop, dataset])
}

fn zfs_snapshot(snap: &str) -> Result<()> {
    spawn("zfs", &["snapshot", snap])
}

/// Minimal `spawn-and-check` — inherits stdio so progress + errors land
/// on the user's terminal.
pub(crate) fn spawn(prog: &str, args: &[&str]) -> Result<()> {
    eprintln!("+ {prog} {}", args.join(" "));
    let st = Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("spawn `{prog} {}`", args.join(" ")))?;
    if !st.success() {
        bail!("`{prog} {}` rc={:?}", args.join(" "), st.code());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Empty-disk preflight
// ---------------------------------------------------------------------------

/// Refuse to deploy onto a disk that already carries a partition table,
/// a filesystem signature, or child block devices.
///
/// `ZBOOT_DEPLOY_ALLOW_NONEMPTY=1` bypasses the check (loud notice).
fn ensure_disk_empty<W: Write>(disk: &str, out: &mut W) -> Result<()> {
    if std::env::var("ZBOOT_DEPLOY_ALLOW_NONEMPTY").as_deref() == Ok("1") {
        writeln!(
            out,
            "[ZBOOT_DEPLOY_ALLOW_NONEMPTY=1 — skipping empty-disk preflight]",
        )
        .context("write nonempty-bypass notice")?;
        return Ok(());
    }
    let children = lsblk_children(disk)?;
    let signatures = wipefs_signatures(disk)?;
    if children.is_empty() && signatures.is_empty() {
        return Ok(());
    }
    let mut msg = format!("refusing to deploy onto {disk}: not empty.\n");
    if !children.is_empty() {
        writeln!(
            msg,
            "  existing partitions/children: {}",
            children.join(", "),
        )
        .ok();
    }
    if !signatures.is_empty() {
        writeln!(
            msg,
            "  disk signature(s) detected   : {}",
            signatures.join(", "),
        )
        .ok();
    }
    writeln!(msg, "  clear with: wipefs -a {disk} && sgdisk -Z {disk}").ok();
    msg.push_str("  bypass with: ZBOOT_DEPLOY_ALLOW_NONEMPTY=1 (loud)");
    bail!(msg);
}

fn lsblk_children(disk: &str) -> Result<Vec<String>> {
    let out = Command::new("lsblk")
        .args(["-nro", "NAME", disk])
        .output()
        .context("spawn lsblk")?;
    if !out.status.success() {
        bail!(
            "lsblk {disk} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    let text = String::from_utf8(out.stdout).context("non-utf8 lsblk output")?;
    Ok(text
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

fn wipefs_signatures(disk: &str) -> Result<Vec<String>> {
    let out = Command::new("wipefs")
        .args(["--noheadings", "--output=TYPE", "-n", disk])
        .output()
        .context("spawn wipefs")?;
    if !out.status.success() {
        bail!(
            "wipefs -n {disk} rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    let text = String::from_utf8(out.stdout).context("non-utf8 wipefs output")?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

// ---------------------------------------------------------------------------
// Typed-target confirmation
// ---------------------------------------------------------------------------

fn confirm_target<R: BufRead, W: Write>(
    expected: &str,
    env_bypass: Option<&str>,
    stdin: &mut R,
    out: &mut W,
) -> Result<()> {
    if let Some(v) = env_bypass {
        if v == expected {
            writeln!(out, "[confirmed via ZBOOT_DEPLOY_CONFIRM_DISK={expected}]")
                .context("write env-bypass notice")?;
            return Ok(());
        }
        bail!("ZBOOT_DEPLOY_CONFIRM_DISK={v:?} does not match target basename {expected:?}");
    }
    writeln!(
        out,
        "This will WIPE the target disk. Type {expected:?} to proceed (Ctrl-C to abort):",
    )
    .context("write confirmation prompt")?;
    let mut line = String::new();
    stdin.read_line(&mut line).context("read confirmation")?;
    let got = line.trim();
    if got != expected {
        bail!("confirmation mismatch: expected exactly {expected:?}, got {got:?}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — pure parsers + plan rendering + confirmation logic.  Live disk
// orchestration (debootstrap + ESP install + reboot-into-BE) is covered
// by the QEMU e2e in `scripts/deploy.sh`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use source::Source;

    // --- Source URL parsing ------------------------------------------------

    #[test]
    fn parse_tar_url() {
        let s = Source::parse("tar:///payload/root.tar.zst").unwrap();
        assert!(matches!(s, Source::Tar { .. }));
        if let Source::Tar { path } = s {
            assert_eq!(path, "/payload/root.tar.zst");
        }
    }

    #[test]
    fn parse_debootstrap_bare_suite() {
        let s = Source::parse("debootstrap://trixie").unwrap();
        if let Source::Debootstrap { suite, mirror } = s {
            assert_eq!(suite, "trixie");
            assert!(mirror.is_none());
        } else {
            panic!("expected Debootstrap variant");
        }
    }

    #[test]
    fn parse_debootstrap_with_mirror() {
        let s = Source::parse("debootstrap://testing?mirror=http://deb.debian.org/debian").unwrap();
        if let Source::Debootstrap { suite, mirror } = s {
            assert_eq!(suite, "testing");
            assert_eq!(mirror.as_deref(), Some("http://deb.debian.org/debian"));
        } else {
            panic!("expected Debootstrap variant");
        }
    }

    #[test]
    fn parse_unknown_scheme() {
        assert!(Source::parse("ftp://example.com/x").is_err());
        assert!(Source::parse("zfs-recv://host:rpool/be@s").is_err());
        assert!(Source::parse("restic://repo/snap").is_err());
    }

    #[test]
    fn parse_debootstrap_rejects_unknown_query() {
        let e = Source::parse("debootstrap://trixie?include=htop").unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("only accepts `mirror=`"),
            "error doesn't mention the only-mirror constraint: {msg}",
        );
    }

    #[test]
    fn parse_tar_empty_path() {
        assert!(Source::parse("tar://").is_err());
    }

    // --- partition_path / disk_of_partition --------------------------------

    #[test]
    fn partition_path_sata() {
        assert_eq!(plan::partition_path("/dev/vda", 1), "/dev/vda1");
        assert_eq!(plan::partition_path("/dev/sda", 2), "/dev/sda2");
    }

    #[test]
    fn partition_path_nvme() {
        assert_eq!(plan::partition_path("/dev/nvme0n1", 1), "/dev/nvme0n1p1");
        assert_eq!(plan::partition_path("/dev/nvme0n1", 2), "/dev/nvme0n1p2");
    }

    // --- hex_to_bytes_le ---------------------------------------------------

    #[test]
    fn hex_to_bytes_basic() {
        assert_eq!(hex_to_bytes_le("00112233").unwrap(), [0x00, 0x11, 0x22, 0x33]);
        assert_eq!(hex_to_bytes_le("deadbeef").unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_to_bytes_wrong_length() {
        assert!(hex_to_bytes_le("123").is_err());
        assert!(hex_to_bytes_le("123456789").is_err());
    }

    #[test]
    fn hex_to_bytes_non_hex() {
        assert!(hex_to_bytes_le("0g000000").is_err());
    }

    // --- confirmation ------------------------------------------------------

    #[test]
    fn confirm_via_env() {
        let mut out = Vec::new();
        let mut stdin = std::io::Cursor::new(Vec::new());
        confirm_target("vda", Some("vda"), &mut stdin, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("[confirmed via ZBOOT_DEPLOY_CONFIRM_DISK=vda]"));
    }

    #[test]
    fn confirm_env_mismatch_errors() {
        let mut out = Vec::new();
        let mut stdin = std::io::Cursor::new(Vec::new());
        let e = confirm_target("vda", Some("nvme0n1"), &mut stdin, &mut out).unwrap_err();
        assert!(format!("{e:#}").contains("does not match"));
    }

    #[test]
    fn confirm_via_stdin() {
        let mut out = Vec::new();
        let mut stdin = std::io::Cursor::new(b"vda\n".to_vec());
        confirm_target("vda", None, &mut stdin, &mut out).unwrap();
    }

    #[test]
    fn confirm_stdin_mismatch_errors() {
        let mut out = Vec::new();
        let mut stdin = std::io::Cursor::new(b"sda\n".to_vec());
        let e = confirm_target("vda", None, &mut stdin, &mut out).unwrap_err();
        assert!(format!("{e:#}").contains("confirmation mismatch"));
    }

    // --- Plan composition: mode + layout matrix ----------------------------

    fn args_with_target(t: &str) -> DeployArgs {
        DeployArgs {
            target: Some(t.into()),
            no_efi: false,
            empty: false,
            hostname: "h".into(),
            be: "be1".into(),
            source: None,
            suite: "trixie".into(),
            mirror_from: None,
            cmdline: None,
            pool: "rpool".into(),
            check: false,
            dry_run: false,
            no_snapshot: true,
        }
    }

    #[test]
    fn plan_default_partitions_disk_and_uses_p2() {
        let a = args_with_target("/dev/vda");
        let p = Plan::compose(&a).unwrap();
        assert_eq!(p.disk, "/dev/vda");
        assert_eq!(p.pool_partition, "/dev/vda2");
        assert_eq!(p.esp_partition.as_deref(), Some("/dev/vda1"));
        assert!(matches!(p.mode, Mode::Source(_)));
        assert!(p.has_esp());
        assert!(p.installs_be());
    }

    #[test]
    fn plan_no_efi_uses_whole_disk_no_esp() {
        let mut a = args_with_target("/dev/nvme0n1");
        a.no_efi = true;
        let p = Plan::compose(&a).unwrap();
        assert_eq!(p.pool_partition, "/dev/nvme0n1");
        assert!(p.esp_partition.is_none());
        assert!(!p.has_esp());
        assert!(p.installs_be());
    }

    #[test]
    fn plan_empty_mode_skips_be_keeps_esp() {
        let mut a = args_with_target("/dev/vdb");
        a.empty = true;
        let p = Plan::compose(&a).unwrap();
        assert!(matches!(p.mode, Mode::Empty));
        assert!(!p.installs_be());
        // --empty alone keeps the ESP partition (bootloader written for future BE):
        assert!(p.has_esp());
    }

    #[test]
    fn plan_empty_with_no_efi_strips_everything() {
        let mut a = args_with_target("/dev/vdb");
        a.empty = true;
        a.no_efi = true;
        let p = Plan::compose(&a).unwrap();
        assert!(matches!(p.mode, Mode::Empty));
        assert!(!p.installs_be());
        assert!(!p.has_esp());
        assert_eq!(p.pool_partition, "/dev/vdb");
    }

    #[test]
    fn plan_empty_rejects_source() {
        let mut a = args_with_target("/dev/vdb");
        a.empty = true;
        a.source = Some("tar:///x".into());
        let e = Plan::compose(&a).unwrap_err();
        assert!(format!("{e:#}").contains("--empty is incompatible with --source"));
    }

    #[test]
    fn plan_empty_rejects_mirror_from() {
        let mut a = args_with_target("/dev/vdb");
        a.empty = true;
        a.mirror_from = Some("rpool".into());
        let e = Plan::compose(&a).unwrap_err();
        assert!(format!("{e:#}").contains("--empty is incompatible with --mirror-from"));
    }

    #[test]
    fn plan_mirror_from_skips_source() {
        let mut a = args_with_target("/dev/vda");
        a.mirror_from = Some("rpool".into());
        let p = Plan::compose(&a).unwrap();
        assert!(matches!(p.mode, Mode::MirrorFrom(ref s) if s == "rpool"));
        assert!(p.has_esp());
        assert!(p.installs_be());
    }

    #[test]
    fn plan_default_falls_back_to_debootstrap_suite() {
        let a = args_with_target("/dev/vda");
        let p = Plan::compose(&a).unwrap();
        match p.mode {
            Mode::Source(Source::Debootstrap { suite, .. }) => assert_eq!(suite, "trixie"),
            other => panic!("expected debootstrap source, got {other:?}"),
        }
    }

    #[test]
    fn plan_missing_target_errors() {
        let mut a = args_with_target("/dev/vda");
        a.target = None;
        let e = Plan::compose(&a).unwrap_err();
        assert!(format!("{e:#}").contains("--target"));
    }
}
