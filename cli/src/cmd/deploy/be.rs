//! BE population: tar extract or debootstrap + DKMS.

use std::io::Write;
use std::process::Command;

use anyhow::{Context, Result, bail};

use super::source::{
    DEBOOTSTRAP_COMPONENTS, DEBOOTSTRAP_PACKAGES, DEFAULT_DEBOOTSTRAP_MIRROR, Source,
};
use super::{hex_to_bytes_le, spawn};

pub(super) fn populate_be<W: Write>(
    source: &Source,
    be_root: &str,
    hostid_hex: &str,
    hostname: &str,
    out: &mut W,
) -> Result<()> {
    match source {
        Source::Tar { path } => populate_from_tar(path, be_root, out),
        Source::Debootstrap { suite, mirror } => {
            populate_from_debootstrap(suite, mirror.as_deref(), be_root, hostid_hex, hostname, out)
        }
    }
}

/// `zstd -dc <path> | tar -xf - -C <be_root>`. Detects `.tar.zst` vs
/// plain `.tar` by extension; defers gzip/xz until needed.
fn populate_from_tar<W: Write>(path: &str, be_root: &str, out: &mut W) -> Result<()> {
    writeln!(out, "    tar source: {path} → {be_root}").ok();
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase);
    let is_zst = matches!(ext.as_deref(), Some("zst" | "tzst"));
    if is_zst {
        // Pipeline: zstd decompresses to stdout, tar reads from stdin.
        let mut zstd = Command::new("zstd")
            .args(["-dc", path])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .context("spawn zstd")?;
        let zstd_out = zstd.stdout.take().context("zstd stdout missing")?;
        let mut tar = Command::new("tar")
            .args(["-xf", "-", "-C", be_root])
            .stdin(std::process::Stdio::from(zstd_out))
            .spawn()
            .context("spawn tar")?;
        let tar_st = tar.wait().context("wait tar")?;
        let zstd_st = zstd.wait().context("wait zstd")?;
        if !zstd_st.success() {
            bail!("zstd -dc {path} rc={:?}", zstd_st.code());
        }
        if !tar_st.success() {
            bail!("tar -xf - -C {be_root} rc={:?}", tar_st.code());
        }
    } else {
        spawn("tar", &["-xf", path, "-C", be_root])?;
    }
    Ok(())
}

/// Two-phase install producing a bootable BE:
///
/// 1. **`debootstrap --variant=minbase`** lays down the base trixie rootfs.
/// 2. **chroot apt install** pulls in kernel + zfs-dkms + zfs-initramfs.
///    Done as a second pass (rather than `debootstrap --include=`) because
///    the postinst chain for `linux-image-amd64` + `zfs-dkms` +
///    `zfs-initramfs` runs `update-initramfs`, which needs `/proc`,
///    `/sys`, and `/dev/null` properly populated — bind-mounted from the
///    deploy host into the chroot.
///
/// The chroot environment is set up via:
/// - bind mounts: `/dev`, `/dev/pts`, `/proc`, `/sys`
/// - `dpkg-divert` of `update-initramfs` → `/bin/true` for the duration
///   of the apt call, so spurious initramfs rebuilds don't fail
///   mid-install before zfs.ko exists. After the apt call we restore
///   `update-initramfs` and run it once explicitly.
fn populate_from_debootstrap<W: Write>(
    suite: &str,
    mirror: Option<&str>,
    be_root: &str,
    hostid_hex: &str,
    hostname: &str,
    out: &mut W,
) -> Result<()> {
    let m = mirror.unwrap_or(DEFAULT_DEBOOTSTRAP_MIRROR);
    writeln!(out, "    [debootstrap] suite={suite} mirror={m}").ok();

    // Phase 1: minbase rootfs.
    writeln!(out, "    [phase 1] debootstrap minbase").ok();
    spawn(
        "debootstrap",
        &[
            "--variant=minbase",
            &format!("--components={DEBOOTSTRAP_COMPONENTS}"),
            suite,
            be_root,
            m,
        ],
    )?;

    // Phase 2: bring sources.list up to spec so apt sees contrib (where
    // zfs-* lives).
    let sources_list = format!(
        "deb {m} {suite} {}\n",
        DEBOOTSTRAP_COMPONENTS.replace(',', " ")
    );
    std::fs::write(format!("{be_root}/etc/apt/sources.list"), sources_list)
        .context("write sources.list")?;

    // Phase 2.5: write /etc/hostid and /etc/hostname BEFORE
    // update-initramfs runs — zfs-initramfs's hook copies /etc/hostid
    // into the initramfs, and a missing-or-mismatched hostid here makes
    // the BE's boot-time `zpool import` refuse with "previously in use
    // from another system".
    writeln!(
        out,
        "    [phase 2.5] write /etc/hostid + /etc/hostname (pre-initramfs)"
    )
    .ok();
    write_be_identity(be_root, hostid_hex, hostname)?;

    // Phase 3: bind mounts so update-initramfs / DKMS have a real /proc,
    // /sys, /dev. RAII guard cleans them up even on early-exit error
    // paths.
    let _guard = ChrootMounts::enter(be_root, out)?;

    // Phase 4: divert update-initramfs.
    writeln!(out, "    [phase 4] divert update-initramfs").ok();
    spawn(
        "chroot",
        &[
            be_root,
            "dpkg-divert",
            "--local",
            "--rename",
            "--add",
            "/usr/sbin/update-initramfs",
        ],
    )?;
    std::fs::copy(
        format!("{be_root}/bin/true"),
        format!("{be_root}/usr/sbin/update-initramfs"),
    )
    .context("stub update-initramfs with /bin/true")?;

    // Phase 5: apt install — kernel, headers, zfs-dkms, zfs-initramfs.
    writeln!(
        out,
        "    [phase 5] apt install kernel + zfs (DKMS builds zfs.ko)"
    )
    .ok();
    spawn("chroot", &[be_root, "apt-get", "update", "-y"])?;
    let pkgs: Vec<&str> = DEBOOTSTRAP_PACKAGES.split(',').collect();
    let mut apt_args: Vec<&str> = vec![
        be_root,
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "install",
        "-y",
        "--no-install-recommends",
    ];
    apt_args.extend(pkgs);
    spawn("chroot", &apt_args)?;

    // Phase 6: restore update-initramfs and run it explicitly.
    writeln!(out, "    [phase 6] restore + run update-initramfs").ok();
    std::fs::remove_file(format!("{be_root}/usr/sbin/update-initramfs"))
        .context("remove stub update-initramfs")?;
    spawn(
        "chroot",
        &[
            be_root,
            "dpkg-divert",
            "--local",
            "--rename",
            "--remove",
            "/usr/sbin/update-initramfs",
        ],
    )?;
    spawn("chroot", &[be_root, "update-initramfs", "-c", "-k", "all"])?;

    Ok(())
}

/// RAII guard for bind-mounting `/dev`, `/dev/pts`, `/proc`, `/sys`
/// into a chroot and unmounting them on drop. Order matters: enter is
/// outermost-first, drop is reverse.
struct ChrootMounts {
    be_root: String,
    mounted: Vec<&'static str>,
}

impl ChrootMounts {
    fn enter<W: Write>(be_root: &str, out: &mut W) -> Result<Self> {
        const MOUNTS: &[&str] = &["/dev", "/dev/pts", "/proc", "/sys"];
        writeln!(out, "    [phase 3] bind mounts for chroot").ok();
        let mut g = ChrootMounts {
            be_root: be_root.to_owned(),
            mounted: Vec::new(),
        };
        for src in MOUNTS {
            let dst = format!("{be_root}{src}");
            std::fs::create_dir_all(&dst).with_context(|| format!("mkdir {dst}"))?;
            spawn("mount", &["--bind", src, &dst])
                .with_context(|| format!("bind {src} → {dst}"))?;
            g.mounted.push(src);
        }
        Ok(g)
    }
}

impl Drop for ChrootMounts {
    fn drop(&mut self) {
        // Reverse order so /sys unmounts before /proc, etc. `-l` lazy
        // to avoid blocking on stuck refs left by DKMS subprocesses.
        for src in self.mounted.iter().rev() {
            let dst = format!("{}{src}", self.be_root);
            let _ = Command::new("umount").args(["-l", &dst]).status();
        }
    }
}

pub(super) fn write_be_identity(be_root: &str, hostid_hex: &str, hostname: &str) -> Result<()> {
    let bytes = hex_to_bytes_le(hostid_hex)?;
    std::fs::write(format!("{be_root}/etc/hostid"), bytes)
        .with_context(|| format!("write {be_root}/etc/hostid"))?;
    std::fs::write(format!("{be_root}/etc/hostname"), format!("{hostname}\n"))
        .with_context(|| format!("write {be_root}/etc/hostname"))?;
    Ok(())
}

/// Append a cpio-newc overlay carrying the per-host `/etc/hostid` to
/// every `<be_root>/boot/initrd.img-*` file. Belt-and-suspenders for
/// `kexec.rs`'s `spl.spl_hostid=` cmdline injection: the cmdline is
/// authoritative for boots driven by zboot-boot, but the overlay makes
/// the initramfs file self-consistent for boot paths that BYPASS
/// zboot-boot (recovery via `efibootmgr` direct-to-BE, GRUB chainload
/// from a rescue ISO, etc.).
///
/// Linux's `init/initramfs.c::unpack_to_rootfs` processes concatenated
/// cpio archives within the initrd if each archive begins on a 4-byte
/// boundary (`this_header & 3 == 0`). We pad with NULL bytes between
/// the existing initramfs and the appended cpio newc archive to land
/// on alignment; the kernel's `if (!*buf)` branch skips the nulls
/// while incrementing the alignment counter.
///
/// Idempotent (best-effort): if the initrd already ends with an
/// identical overlay (4-byte alignment + same hostid bytes), do
/// nothing. Otherwise append.
pub(super) fn overlay_hostid_in_initrds<W: Write>(
    be_root: &str,
    hostid_hex: &str,
    out: &mut W,
) -> Result<()> {
    let bytes = hex_to_bytes_le(hostid_hex)?;
    let overlay = build_hostid_cpio_overlay(&bytes);
    let boot_dir = format!("{be_root}/boot");
    let entries = match std::fs::read_dir(&boot_dir) {
        Ok(d) => d,
        Err(_) => {
            // No /boot — fresh BE with no kernel; nothing to overlay.
            return Ok(());
        }
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("initrd.img-") {
            continue;
        }
        let path = entry.path();
        let size = entry.metadata()?.len();
        let pad = ((4 - (size % 4)) % 4) as usize;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .with_context(|| format!("open {} for append", path.display()))?;
        if pad > 0 {
            f.write_all(&vec![0u8; pad])
                .with_context(|| format!("write pad to {}", path.display()))?;
        }
        f.write_all(&overlay)
            .with_context(|| format!("write cpio overlay to {}", path.display()))?;
        writeln!(
            out,
            "    cpio-overlay /etc/hostid into {} (+{} bytes pad, +{} bytes overlay)",
            path.display(),
            pad,
            overlay.len()
        )
        .ok();
    }
    Ok(())
}

/// Build a self-contained cpio newc archive (in memory) containing a
/// single regular file `etc/hostid` with `bytes` as content, followed
/// by the required `TRAILER!!!` end marker.
///
/// cpio-newc grammar (`man 5 cpio`):
/// - 110-byte ASCII header (magic "070701" + 13 × hex-8 fields)
/// - filename + NUL
/// - pad to 4-byte boundary
/// - file content
/// - pad to 4-byte boundary
/// - (repeat per entry)
/// - final entry: header with filename "TRAILER!!!\0", filesize=0
fn build_hostid_cpio_overlay(bytes: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    // /etc/hostid entry
    write_newc_header(
        &mut buf,
        /* ino */ 1,
        /* mode (S_IFREG | 0644) */ 0o100_644,
        /* nlink */ 1,
        /* filesize */ bytes.len() as u32,
        /* namesize incl NUL */ (b"etc/hostid".len() + 1) as u32,
    );
    buf.extend_from_slice(b"etc/hostid\0");
    pad_to_4(&mut buf);
    buf.extend_from_slice(bytes);
    pad_to_4(&mut buf);
    // TRAILER!!! end marker
    write_newc_header(
        &mut buf,
        /* ino */ 0,
        /* mode */ 0,
        /* nlink */ 1,
        /* filesize */ 0,
        /* namesize incl NUL */ (b"TRAILER!!!".len() + 1) as u32,
    );
    buf.extend_from_slice(b"TRAILER!!!\0");
    pad_to_4(&mut buf);
    buf
}

fn write_newc_header(
    buf: &mut Vec<u8>,
    ino: u32,
    mode: u32,
    nlink: u32,
    filesize: u32,
    namesize: u32,
) {
    buf.extend_from_slice(b"070701");
    for n in [
        ino, mode, /* uid */ 0, /* gid */ 0, nlink, /* mtime */ 0, filesize,
        /* devmajor */ 0, /* devminor */ 0, /* rdevmajor */ 0, /* rdevminor */ 0,
        namesize, /* check */ 0,
    ] {
        buf.extend_from_slice(format!("{n:08x}").as_bytes());
    }
}

fn pad_to_4(buf: &mut Vec<u8>) {
    let pad = (4 - buf.len() % 4) % 4;
    for _ in 0..pad {
        buf.push(0);
    }
}

/// Empty root's password in `/etc/shadow` so the operator can log in
/// after a fresh deploy without an overlay step.  Golden tars from
/// debootstrap ship `root:*:...` (locked) — no way to log in until a
/// password is set. For zboot's "deploy then overlay or chroot+passwd"
/// flow, an empty password on first boot is the pragmatic default —
/// the BE is not network-exposed until the operator decides what to
/// do with it.
///
/// In-place rewrite of `/etc/shadow`: the second field (password hash)
/// of the `root` line becomes empty. PAM's `pam_unix` accepts empty
/// passwords by default on Debian, so `root` can log in by pressing
/// Enter at the password prompt.
pub(super) fn empty_root_password(be_root: &str) -> Result<()> {
    let path = format!("{be_root}/etc/shadow");
    let content = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    let mut out = String::with_capacity(content.len());
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim_end_matches('\n');
        if let Some(rest) = trimmed.strip_prefix("root:") {
            // `root:HASH:rest...` → `root::rest...`
            if let Some(after_hash) = rest.split_once(':') {
                let _hash = after_hash.0;
                let trailing = after_hash.1;
                out.push_str("root::");
                out.push_str(trailing);
                if line.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
        }
        out.push_str(line);
    }
    std::fs::write(&path, out).with_context(|| format!("write {path}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The overlay should start with cpio newc magic and contain etc/hostid.
    #[test]
    fn build_hostid_cpio_overlay_has_newc_magic_and_filename() {
        let bytes = [0x5e, 0xec, 0x0d, 0xc4];
        let buf = build_hostid_cpio_overlay(&bytes);
        assert_eq!(&buf[..6], b"070701", "newc magic");
        // filename should appear right after the 110-byte header
        let after_header = &buf[110..];
        assert!(after_header.starts_with(b"etc/hostid\0"), "{:?}", &after_header[..15]);
    }

    /// The overlay should be 4-byte-aligned overall (own size mod 4 == 0)
    /// so that if it's appended after another aligned chunk, the next
    /// section also starts on a 4-byte boundary.
    #[test]
    fn build_hostid_cpio_overlay_total_size_is_4byte_aligned() {
        let bytes = [0x5e, 0xec, 0x0d, 0xc4];
        let buf = build_hostid_cpio_overlay(&bytes);
        assert_eq!(buf.len() % 4, 0, "overlay length {} not 4-aligned", buf.len());
    }

    /// The overlay should contain the TRAILER!!! end marker.
    #[test]
    fn build_hostid_cpio_overlay_has_trailer() {
        let bytes = [0x5e, 0xec, 0x0d, 0xc4];
        let buf = build_hostid_cpio_overlay(&bytes);
        let found = buf.windows(11).any(|w| w == b"TRAILER!!!\0");
        assert!(found, "no TRAILER!!! sentinel in overlay");
    }

    /// The host file content should appear verbatim somewhere in the
    /// overlay (between the etc/hostid filename and the TRAILER!!!).
    #[test]
    fn build_hostid_cpio_overlay_contains_hostid_bytes() {
        let bytes = [0xab, 0xcd, 0xef, 0x42];
        let buf = build_hostid_cpio_overlay(&bytes);
        let found = buf.windows(4).any(|w| w == bytes);
        assert!(found, "hostid bytes not found in overlay");
    }

    /// External `cpio -t` (if available on the host) should parse the
    /// overlay and list `etc/hostid`. Skipped if cpio is missing.
    #[test]
    fn overlay_parses_with_system_cpio() {
        if Command::new("cpio").arg("--version").output().is_err() {
            return;
        }
        let bytes = [0x5e, 0xec, 0x0d, 0xc4];
        let buf = build_hostid_cpio_overlay(&bytes);

        let mut child = Command::new("cpio")
            .args(["--quiet", "-t"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn cpio");
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(&buf).unwrap();
        let out = child.wait_with_output().expect("wait cpio");
        assert!(out.status.success(), "cpio -t failed: {:?}", out.stderr);
        let listed = String::from_utf8_lossy(&out.stdout);
        assert!(listed.contains("etc/hostid"), "cpio listed: {listed}");
    }
}
