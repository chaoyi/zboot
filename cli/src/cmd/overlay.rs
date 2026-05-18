//! `zboot overlay <tar>` — apply a host-specific data tar to a deployed BE.
//!
//! Convention for the data tar (directory layout, transparent):
//!
//! ```text
//! data/                          (top-level wrapper optional)
//! ├── rootfs/                    untarred onto the BE rootfs
//! │   ├── etc/ssh/ssh_host_*
//! │   ├── etc/NetworkManager/system-connections/*.nmconnection
//! │   └── root/.ssh/authorized_keys
//! └── post-install.sh            chroot-run inside the BE
//! ```
//!
//! Operation:
//! 1. Extract tar to a staging dir (tmpfs).
//! 2. Mount the target BE (defaults to the only BE on the only
//!    `zboot:role=root` pool; explicit via `--be`/`--pool`).
//! 3. tar-pipe `staging/rootfs/` → BE root (preserves xattrs + ACLs).
//! 4. If `staging/post-install.sh` exists: copy into BE, bind-mount
//!    /dev /proc /sys, `chroot` run, remove.
//! 5. Unmount BE, drop staging.
//!
//! Refuses to overlay onto the live `/` — overlay is intended for
//! freshly-deployed BEs, invoked from a recovery medium (debian-live).
//! Catches the "I accidentally pointed at my running root" case.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::sub;

#[derive(Debug, Args)]
pub struct OverlayArgs {
    /// Path to the data tar (`.tar.zst` or `.tar`).
    pub tar: String,

    /// Target BE dataset (e.g., `rpool/ROOT/be1`). Default: the only
    /// BE on the only `zboot:role=root` pool. Errors on ambiguity —
    /// pass the full dataset path to disambiguate across multiple pools.
    #[arg(long)]
    pub be: Option<String>,

    /// Skip the `@overlay-pre-<UTC>` rollback snapshot taken before
    /// applying. Default-on: a fresh rollback point matters most when
    /// the overlay tar contains risky per-host customization (sshd
    /// config, key material, post-install.sh). Opt out for ephemeral
    /// / scripted re-applies.
    #[arg(long)]
    pub no_snapshot: bool,
}

pub fn run(args: &OverlayArgs, w: &mut impl Write) -> Result<()> {
    let target_dataset = resolve_target(args)?;

    if is_live_root(&target_dataset) {
        bail!(
            "overlay: refusing — `{target_dataset}` is the live `/`. \
             Overlay is for freshly-deployed BEs; run from a rescue medium."
        );
    }

    // Take a pre-overlay rollback point unless --no-snapshot. Captured
    // before any mutation so the operator can `zfs rollback` the BE
    // back to the exact pre-overlay state if the overlay's
    // post-install.sh or rootfs files break something. Suffix with
    // UTC nanoseconds so re-applies don't collide.
    if !args.no_snapshot {
        let utc_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let snap = format!("{target_dataset}@overlay-pre-{utc_ns}");
        writeln!(w, "→ snapshot {snap} (rollback point; --no-snapshot to skip)").ok();
        sub::cmd("zfs", &["snapshot", &snap])
            .with_context(|| format!("snapshot {snap}"))?;
    }

    let pid = std::process::id();
    let staging = PathBuf::from(format!("/tmp/zboot-overlay-staging-{pid}"));
    std::fs::create_dir_all(&staging).with_context(|| format!("mkdir {}", staging.display()))?;
    let _staging_guard = StagingGuard {
        path: staging.clone(),
    };

    writeln!(w, "→ extracting {} → {}", args.tar, staging.display()).ok();
    extract_tar(&args.tar, &staging)?;

    let layout = locate_layout(&staging)?;

    let be_mp = PathBuf::from(format!("/tmp/zboot-overlay-be-{pid}"));
    std::fs::create_dir_all(&be_mp).with_context(|| format!("mkdir {}", be_mp.display()))?;
    sub::cmd(
        "mount",
        &[
            "-t",
            "zfs",
            "-o",
            "zfsutil",
            &target_dataset,
            be_mp.to_str().context("mountpoint not utf8")?,
        ],
    )
    .with_context(|| format!("mount {target_dataset} → {}", be_mp.display()))?;
    let _mount_guard = MountGuard {
        path: be_mp.clone(),
    };

    writeln!(w, "→ overlay → {target_dataset} (mounted at {})", be_mp.display()).ok();

    if let Some(rootfs) = &layout.rootfs {
        writeln!(w, "  applying rootfs/").ok();
        apply_rootfs(rootfs, &be_mp)?;
    } else {
        writeln!(w, "  no rootfs/ in tar — skipping file layering").ok();
    }

    if let Some(pi_path) = &layout.post_install {
        writeln!(w, "  running post-install.sh in chroot").ok();
        run_post_install(pi_path, &be_mp, w)?;
    } else {
        writeln!(w, "  no post-install.sh — skipping").ok();
    }

    writeln!(w, "✓ overlay complete on {target_dataset}").ok();
    Ok(())
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

fn resolve_target(args: &OverlayArgs) -> Result<String> {
    if let Some(ds) = &args.be {
        return Ok(ds.clone());
    }

    let pool_text = sub::zpool_capture(&["list", "-Hp", "-o", "name"])?;
    let pools: Vec<String> = pool_text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if pools.is_empty() {
        bail!("overlay: no pools imported (run `zpool import` first)");
    }

    let root_pools: Vec<String> = pools
        .into_iter()
        .filter(|p| {
            sub::zpool_capture(&["get", "-Hp", "-o", "value", "zboot:role", p])
                .map(|v| v.trim() == "root")
                .unwrap_or(false)
        })
        .collect();

    let target_pools: Vec<String> = root_pools;
    if target_pools.is_empty() {
        bail!("overlay: no `zboot:role=root` pools found; tag a pool first or pass --be");
    }

    let mut candidates: Vec<String> = Vec::new();
    for pool in &target_pools {
        let listing = sub::zfs_capture(&[
            "get",
            "-Hpr",
            "-t",
            "filesystem",
            "-o",
            "name,property,value",
            "zboot:be",
            pool,
        ])?;
        for line in listing.lines() {
            let mut parts = line.split('\t');
            let ds = parts.next().unwrap_or("");
            let _prop = parts.next();
            let value = parts.next().unwrap_or("").trim();
            if value == "true" {
                candidates.push(ds.to_owned());
            }
        }
    }

    match candidates.len() {
        0 => bail!(
            "overlay: no BEs found (no datasets with zboot:be=true on root pools); \
             did `zboot deploy` complete?"
        ),
        1 => Ok(candidates.remove(0)),
        n => bail!(
            "overlay: target is ambiguous — {n} BEs found: {}. \
             Pass `--be <full-dataset-path>` to disambiguate.",
            candidates.join(", ")
        ),
    }
}

fn is_live_root(dataset: &str) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return false;
    };
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let source = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        if target == "/" && source == dataset {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tar extraction + layout
// ---------------------------------------------------------------------------

fn extract_tar(path: &str, dest: &Path) -> Result<()> {
    let ext = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase);
    let is_zst = matches!(ext.as_deref(), Some("zst" | "tzst"));
    let dest_str = dest.to_str().context("dest path not utf8")?;
    eprintln!("+ tar -xf {path} -C {dest_str}");
    if is_zst {
        let mut zstd = Command::new("zstd")
            .args(["-dc", path])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .context("spawn zstd")?;
        let zstd_out = zstd.stdout.take().context("zstd stdout")?;
        let mut tar = Command::new("tar")
            .args([
                "--xattrs",
                "--xattrs-include=*",
                "--acls",
                "-xf",
                "-",
                "-C",
                dest_str,
            ])
            .stdin(std::process::Stdio::from(zstd_out))
            .spawn()
            .context("spawn tar")?;
        let tar_st = tar.wait()?;
        let zstd_st = zstd.wait()?;
        if !zstd_st.success() {
            bail!("zstd -dc {path} rc={:?}", zstd_st.code());
        }
        if !tar_st.success() {
            bail!("tar -xf rc={:?}", tar_st.code());
        }
    } else {
        sub::cmd(
            "tar",
            &[
                "--xattrs",
                "--xattrs-include=*",
                "--acls",
                "-xf",
                path,
                "-C",
                dest_str,
            ],
        )?;
    }
    Ok(())
}

#[derive(Debug)]
struct Layout {
    rootfs: Option<PathBuf>,
    post_install: Option<PathBuf>,
}

/// Locate `rootfs/` + optional `post-install.sh` inside the staging dir.
/// Accepts two shapes:
/// - Flat: staging contains `rootfs/` and optionally `post-install.sh` at top.
/// - Wrapped: staging contains a single directory (e.g., `data/`) which
///   contains `rootfs/` + optional `post-install.sh`.
fn locate_layout(staging: &Path) -> Result<Layout> {
    if staging.join("rootfs").is_dir() {
        let pi = staging.join("post-install.sh");
        return Ok(Layout {
            rootfs: Some(staging.join("rootfs")),
            post_install: pi.is_file().then_some(pi),
        });
    }

    let entries: Vec<_> = std::fs::read_dir(staging)
        .with_context(|| format!("read_dir {}", staging.display()))?
        .filter_map(Result::ok)
        .collect();
    if entries.len() == 1 {
        let wrapper = entries[0].path();
        if wrapper.is_dir() && wrapper.join("rootfs").is_dir() {
            let pi = wrapper.join("post-install.sh");
            return Ok(Layout {
                rootfs: Some(wrapper.join("rootfs")),
                post_install: pi.is_file().then_some(pi),
            });
        }
    }

    // Allow a "post-install.sh only, no rootfs" tar — useful for re-running
    // just the chroot step. But the tar can't be empty.
    if staging.join("post-install.sh").is_file() {
        return Ok(Layout {
            rootfs: None,
            post_install: Some(staging.join("post-install.sh")),
        });
    }

    bail!(
        "overlay tar layout invalid: expected `rootfs/` and/or `post-install.sh` \
         at top of tar (or wrapped in a single top-level directory). Got entries: {:?}",
        entries
            .iter()
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    )
}

// ---------------------------------------------------------------------------
// Rootfs application
// ---------------------------------------------------------------------------

/// `tar -c <rootfs>/. | tar -x -C <be_root>` — preserves xattrs, ACLs,
/// ownership, permissions. Same approach the deploy path uses for tar
/// sources; consistent semantics.
fn apply_rootfs(rootfs: &Path, be_root: &Path) -> Result<()> {
    let src = rootfs.to_str().context("rootfs path not utf8")?;
    let dst = be_root.to_str().context("be_root path not utf8")?;
    eprintln!("+ tar -c {src}/. | tar -x -C {dst}");

    let mut tar_create = Command::new("tar")
        .args([
            "--xattrs",
            "--xattrs-include=*",
            "--acls",
            "-cf",
            "-",
            "-C",
            src,
            ".",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("spawn tar -c")?;
    let create_out = tar_create.stdout.take().context("tar -c stdout")?;
    let mut tar_extract = Command::new("tar")
        .args([
            "--xattrs",
            "--xattrs-include=*",
            "--acls",
            "-xf",
            "-",
            "-C",
            dst,
        ])
        .stdin(std::process::Stdio::from(create_out))
        .spawn()
        .context("spawn tar -x")?;
    let extract_st = tar_extract.wait()?;
    let create_st = tar_create.wait()?;
    if !create_st.success() {
        bail!("tar -c rootfs rc={:?}", create_st.code());
    }
    if !extract_st.success() {
        bail!("tar -x onto BE rc={:?}", extract_st.code());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// post-install.sh execution
// ---------------------------------------------------------------------------

fn run_post_install(pi_path: &Path, be_root: &Path, w: &mut impl Write) -> Result<()> {
    // Copy script into BE so chroot can see it.
    let in_be_rel = "tmp/zboot-post-install.sh";
    let in_be = be_root.join(in_be_rel);
    std::fs::create_dir_all(in_be.parent().unwrap())
        .with_context(|| format!("mkdir {}/tmp", be_root.display()))?;
    std::fs::copy(pi_path, &in_be)
        .with_context(|| format!("copy post-install.sh → {}", in_be.display()))?;
    let perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(&in_be, perms)
        .with_context(|| format!("chmod 755 {}", in_be.display()))?;

    // Bind /dev /dev/pts /proc /sys so the script can run systemctl,
    // chpasswd, etc. RAII guard unwinds on any exit path.
    let _bind_guard = BindGuard::enter(be_root, w)?;

    writeln!(
        w,
        "    + chroot {} /{in_be_rel}",
        be_root.display()
    )
    .ok();
    let st = Command::new("chroot")
        .args([
            be_root.to_str().context("be_root not utf8")?,
            &format!("/{in_be_rel}"),
        ])
        .status()
        .context("spawn chroot post-install.sh")?;

    // Remove the script regardless of outcome — don't leave it in the BE.
    let _ = std::fs::remove_file(&in_be);

    if !st.success() {
        bail!("post-install.sh failed rc={:?}", st.code());
    }
    Ok(())
}

struct BindGuard {
    mounts: Vec<PathBuf>,
}

impl BindGuard {
    fn enter(be_root: &Path, w: &mut impl Write) -> Result<Self> {
        const BINDS: &[&str] = &["/dev", "/dev/pts", "/proc", "/sys"];
        let mut g = BindGuard { mounts: Vec::new() };
        for src in BINDS {
            let dst = be_root.join(src.trim_start_matches('/'));
            std::fs::create_dir_all(&dst)
                .with_context(|| format!("mkdir {}", dst.display()))?;
            let dst_str = dst.to_str().context("bind dst not utf8")?;
            writeln!(w, "    + mount --bind {src} {dst_str}").ok();
            sub::cmd("mount", &["--bind", src, dst_str])
                .with_context(|| format!("bind {src} → {dst_str}"))?;
            g.mounts.push(dst);
        }
        Ok(g)
    }
}

impl Drop for BindGuard {
    fn drop(&mut self) {
        for m in self.mounts.iter().rev() {
            if let Some(s) = m.to_str() {
                let _ = Command::new("umount").args(["-l", s]).status();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RAII guards for the outer mount + staging dir
// ---------------------------------------------------------------------------

struct StagingGuard {
    path: PathBuf,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct MountGuard {
    path: PathBuf,
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Some(s) = self.path.to_str() {
            let _ = Command::new("umount").args(["-l", s]).status();
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Tests — pure-data layout detection. End-to-end overlay (mount + chroot)
// is covered by `scripts/overlay.sh`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mktemp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "zboot-overlay-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    #[test]
    fn layout_flat_rootfs_only() {
        let d = mktemp_dir();
        std::fs::create_dir_all(d.join("rootfs/etc")).unwrap();
        let l = locate_layout(&d).unwrap();
        assert_eq!(l.rootfs, Some(d.join("rootfs")));
        assert_eq!(l.post_install, None);
        cleanup(&d);
    }

    #[test]
    fn layout_flat_with_post_install() {
        let d = mktemp_dir();
        std::fs::create_dir_all(d.join("rootfs")).unwrap();
        std::fs::write(d.join("post-install.sh"), "#!/bin/sh\n").unwrap();
        let l = locate_layout(&d).unwrap();
        assert!(l.rootfs.is_some());
        assert!(l.post_install.is_some());
        cleanup(&d);
    }

    #[test]
    fn layout_wrapped_in_top_dir() {
        let d = mktemp_dir();
        std::fs::create_dir_all(d.join("data/rootfs/etc")).unwrap();
        std::fs::write(d.join("data/post-install.sh"), "#!/bin/sh\n").unwrap();
        let l = locate_layout(&d).unwrap();
        assert_eq!(l.rootfs, Some(d.join("data/rootfs")));
        assert_eq!(l.post_install, Some(d.join("data/post-install.sh")));
        cleanup(&d);
    }

    #[test]
    fn layout_post_install_only_is_ok() {
        let d = mktemp_dir();
        std::fs::write(d.join("post-install.sh"), "#!/bin/sh\n").unwrap();
        let l = locate_layout(&d).unwrap();
        assert!(l.rootfs.is_none());
        assert!(l.post_install.is_some());
        cleanup(&d);
    }

    #[test]
    fn layout_empty_errors() {
        let d = mktemp_dir();
        assert!(locate_layout(&d).is_err());
        cleanup(&d);
    }

    #[test]
    fn layout_unknown_top_dir_errors() {
        let d = mktemp_dir();
        std::fs::create_dir_all(d.join("data/somethingelse")).unwrap();
        let e = locate_layout(&d).unwrap_err();
        assert!(format!("{e:#}").contains("rootfs"));
        cleanup(&d);
    }

    // is_live_root tests would require mocking /proc/self/mounts;
    // exercised by the e2e shell scripts.
}
