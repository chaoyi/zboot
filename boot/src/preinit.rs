//! PID-1 early-init: mount /proc /sys /dev, set PATH, load zfs.ko, run
//! udev, import pools. After this returns, the userspace environment
//! looks the way `Command::new` and `zpool` expect.
//!
//! `#![allow(unsafe_code)]` is for the one `unsafe { set_var("PATH") }`
//! call (Rust 2024 unsafe); workspace lint is `unsafe_code = "deny"`.

#![allow(unsafe_code)]

use std::ffi::OsString;
use std::path::Path;

use anyhow::{Context, Result};
use nix::NixPath;
use nix::mount::{MsFlags, mount};

/// Run the PID-1 bootstrap. Idempotent — re-runs are no-ops (EBUSY
/// on already-mounted filesystems is ignored).
pub fn run() -> Result<()> {
    mount_pseudo_fs()?;
    // SAFETY: main() is single-threaded at this point.
    unsafe {
        std::env::set_var("PATH", "/sbin:/usr/sbin:/bin:/usr/bin");
    }
    load_kmods()?;
    Ok(())
}

fn mount_pseudo_fs() -> Result<()> {
    try_mount(None::<&str>, "/proc", Some("proc"), MsFlags::empty(), None)
        .context("mount /proc")?;
    try_mount(None::<&str>, "/sys", Some("sysfs"), MsFlags::empty(), None).context("mount /sys")?;
    let _ = std::fs::create_dir_all("/dev");
    try_mount(
        None::<&str>,
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None,
    )
    .context("mount /dev")?;
    Ok(())
}

/// `mount(2)` wrapper that ignores "already mounted" (EBUSY).
fn try_mount<P: NixPath + ?Sized>(
    source: Option<&P>,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
    data: Option<&str>,
) -> Result<()> {
    // EBUSY = already mounted (re-run, or kernel auto-mount).
    match mount(source, target, fstype, flags, data) {
        Ok(()) | Err(nix::errno::Errno::EBUSY) => Ok(()),
        Err(e) => Err(e).context(format!("mount({target}, {fstype:?})")),
    }
}

/// Run depmod (if needed), udev, then modprobe storage drivers + zfs.
/// We shell out to `modprobe` rather than `finit_module(2)` because
/// debian ships `zfs.ko.xz` and `finit_module` rejects compressed blobs
/// unless `CONFIG_MODULE_DECOMPRESS=y` (debian's kernel: no).
fn load_kmods() -> Result<()> {
    let modroot = Path::new("/lib/modules");
    let kver: OsString = std::fs::read_dir(modroot)
        .context("read /lib/modules")?
        .find_map(std::result::Result::ok)
        .context("/lib/modules empty")?
        .file_name();
    let kver_str = kver.to_string_lossy().into_owned();

    let dep_path = format!("/lib/modules/{kver_str}/modules.dep");
    if !Path::new(&dep_path).exists() {
        run_or_warn("/sbin/depmod", &["-a", &kver_str], "depmod");
    }

    start_udev_and_settle();

    // Storage drivers for real hardware. Most are =y on debian's amd64
    // kernel so these are no-ops; real NVMe/SATA/USB/MMC boxes need
    // them explicitly. Misses ("not in modules.dep") are silenced.
    for m in [
        "nvme",
        "nvme_core",
        "ahci",
        // SCSI disk class — required for /dev/sd* nodes on SATA/SAS/USB
        // disks. ahci/libata register SCSI devices; without sd_mod the
        // SCSI device exists but no block node is created. udev's auto-
        // modprobe-by-MODALIAS doesn't fire in this minimal initrd.
        "sd_mod",
        "usb_storage",
        "uas",
        "mmc_core",
        "mmc_block",
        "sdhci",
        "sdhci_pci",
        "sdhci_acpi",
        "virtio_blk",
        // USB host controllers + HID class — needed for USB-keyboard
        // input in the bootloader menu/shell on hosts without PS/2.
        // modprobe pulls in usbcore/hid/input transitively.  Order
        // matters only loosely: host controllers before HID class.
        "xhci_pci",
        "xhci_hcd",
        "ehci_pci",
        "ehci_hcd",
        "ohci_pci",
        "ohci_hcd",
        "uhci_hcd",
        "usbhid",
        "hid_generic",
    ] {
        run_or_warn("/sbin/modprobe", &[m], &format!("modprobe {m}"));
    }
    udevadm_settle();

    // zfs pulls spl as a dep; modprobe handles xz decompression.
    run_or_warn("/sbin/modprobe", &["zfs"], "modprobe zfs");
    udevadm_settle();

    // Read-only, no auto-mount. -f because we own the host.
    run_or_warn(
        "/sbin/zpool",
        &[
            "import",
            "-a",
            "-N",
            "-o",
            "readonly=on",
            "-d",
            "/dev",
            "-f",
        ],
        "zpool import",
    );

    let list = std::process::Command::new("/sbin/zpool")
        .args(["list", "-H", "-o", "name"])
        .output();
    match list {
        Ok(o) => eprintln!(
            "zboot-boot/preinit: imported pools: {}",
            String::from_utf8_lossy(&o.stdout).trim(),
        ),
        Err(e) => eprintln!("zboot-boot/preinit: post-import list err: {e}"),
    }

    // Adopt the deployed host's `/etc/hostid` so subsequent RW imports
    // (via `ensure_pool_rw` in the post-halt shell) stamp the pool
    // with the right value instead of `0` (which is what
    // `gethostid()` returns when /etc/hostid is absent — the case in
    // this stateless initrd).
    //
    // Without this: chroot/cmdline/rollback/drop re-stamp the
    // pool with 0, and the next boot's BE-side initramfs hits a
    // stamp/expected mismatch — works fine if ZIL is empty, panics if
    // ZIL has uncommitted writes from before the reboot.
    //
    // Source of truth: BE's /etc/hostid (written by `zboot deploy`).
    // All BEs on a `zboot:role=root` pool share the host's hostid per
    // DESIGN.md "/etc/hostid per slot". We try each root pool's
    // bootfs in turn; first success wins.
    if let Err(e) = adopt_hostid_from_pool() {
        eprintln!("zboot-boot/preinit: hostid-adopt skipped: {e:#}");
    }

    Ok(())
}

/// Iterate every `zboot:role=root` pool, find its `bootfs` BE, mount
/// the BE readonly to a scratch path, copy `/etc/hostid` into
/// `/etc/hostid`, unmount. First success wins.
fn adopt_hostid_from_pool() -> Result<()> {
    // List pools with their bootfs in one shot.
    let out = std::process::Command::new("/sbin/zpool")
        .args(["list", "-H", "-o", "name,bootfs"])
        .output()
        .context("spawn `zpool list`")?;
    if !out.status.success() {
        anyhow::bail!(
            "`zpool list` rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let listing = String::from_utf8_lossy(&out.stdout);

    for line in listing.lines() {
        let mut cols = line.split_whitespace();
        let pool = match cols.next() {
            Some(p) => p,
            None => continue,
        };
        let bootfs = cols.next().unwrap_or("-");
        if bootfs == "-" || bootfs.is_empty() {
            continue;
        }
        // Filter to pools we own (zboot:role=root).
        let role = std::process::Command::new("/sbin/zpool")
            .args(["get", "-Hp", "-o", "value", "zboot:role", pool])
            .output();
        let is_root = matches!(role, Ok(o) if o.status.success()
            && String::from_utf8_lossy(&o.stdout).trim() == "root");
        if !is_root {
            continue;
        }
        // Mount the bootfs BE readonly to a scratch path, copy hostid.
        let scratch = format!("/run/zboot-hostid-probe-{}", std::process::id());
        if std::fs::create_dir_all(&scratch).is_err() {
            continue;
        }
        let mount_rc = std::process::Command::new("/bin/mount")
            .args(["-t", "zfs", "-o", "ro,zfsutil", bootfs, &scratch])
            .status();
        if !mount_rc.map(|s| s.success()).unwrap_or(false) {
            let _ = std::fs::remove_dir(&scratch);
            continue;
        }
        let read_result = std::fs::read(format!("{scratch}/etc/hostid"));
        let _ = std::process::Command::new("/bin/umount")
            .arg(&scratch)
            .status();
        let _ = std::fs::remove_dir(&scratch);
        if let Ok(bytes) = read_result
            && !bytes.is_empty()
        {
            std::fs::write("/etc/hostid", &bytes).context("write /etc/hostid")?;
            eprintln!(
                "zboot-boot/preinit: adopted /etc/hostid from {bootfs} ({} bytes)",
                bytes.len()
            );
            return Ok(());
        }
    }
    anyhow::bail!("no zboot:role=root pool yielded a readable /etc/hostid")
}

/// Start systemd-udevd + trigger an initial scan + settle. udev replays
/// uevents for already-registered devices and `udevadm settle` blocks
/// until the queue drains — deterministic device readiness.
fn start_udev_and_settle() {
    use std::process::Command;

    let udevd = [
        "/lib/systemd/systemd-udevd",
        "/usr/lib/systemd/systemd-udevd",
    ]
    .iter()
    .map(Path::new)
    .find(|p| p.exists());
    let Some(udevd) = udevd else {
        eprintln!("zboot-boot/preinit: WARN: no systemd-udevd; device readiness unreliable");
        return;
    };
    match Command::new(udevd).arg("--daemon").output() {
        Ok(o) if o.status.success() => {}
        Ok(o) => eprintln!(
            "zboot-boot/preinit: udevd start failed rc={:?}: {}",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim(),
        ),
        Err(e) => eprintln!("zboot-boot/preinit: udevd spawn err: {e}"),
    }
    run_or_warn(
        "/usr/bin/udevadm",
        &["trigger", "--action=add"],
        "udevadm trigger",
    );
    udevadm_settle();
}

fn udevadm_settle() {
    run_or_warn(
        "/usr/bin/udevadm",
        &["settle", "--timeout=10"],
        "udevadm settle",
    );
}

/// Spawn a helper, log on failure, never bail — best-effort.
fn run_or_warn(prog: &str, args: &[&str], label: &str) {
    use std::process::Command;

    let resolved = ["/sbin", "/usr/sbin", "/bin", "/usr/bin"]
        .iter()
        .map(|d| {
            Path::new(d).join(
                prog.trim_start_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or(prog),
            )
        })
        .find(|p| p.exists());

    let Some(p) = resolved else {
        eprintln!("zboot-boot/preinit: {label}: helper {prog} not found in initrd");
        return;
    };
    match Command::new(p).args(args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Silence misses for hardware-specific modules not in this initrd.
            if stderr.contains("not found in modules.dep") {
                return;
            }
            eprintln!(
                "zboot-boot/preinit: {label}: rc={:?} stderr={:?}",
                out.status.code(),
                stderr.trim(),
            );
        }
        Err(e) => eprintln!("zboot-boot/preinit: {label}: spawn error: {e}"),
    }
}
