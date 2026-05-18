//! `zboot chroot <NAME>` — mount a BE RW, bind /dev /proc /sys, drop the
//! caller into an interactive shell inside it. RAII guard unwinds bind
//! mounts and the BE mount on exit.
//!
//! Usable from two contexts:
//! - From inside a running BE (debug a sibling BE without rebooting into it).
//! - From the bootloader's post-halt shell (`chroot N` shells out to
//!   `/sbin/zboot chroot <NAME>`; the bootloader handles the pool-RW
//!   import beforehand).
//!
//! Refuses on the live `/` (you'd be chroot'ing into your own root —
//! pointless and risky). Otherwise: `mount → bind → spawn /bin/bash →
//! unwind`. Exit code from bash is propagated.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::sub;

#[derive(Debug, Args)]
pub struct ChrootArgs {
    /// Target BE name (last component of `<pool>/ROOT/<name>`).
    pub name: String,
    /// Shell to execute inside the chroot. Default `/bin/bash`; falls
    /// back to `/bin/sh` if bash isn't present in the BE.
    #[arg(long, default_value = "/bin/bash")]
    pub shell: String,
}

pub fn run(args: &ChrootArgs, w: &mut dyn Write) -> Result<()> {
    let target = locate_be(&args.name)?;

    if is_live_root(&target.dataset) {
        bail!(
            "chroot: refusing — `{name}` is the live `/` (chroot'ing into your own root is pointless). \
             Use a different BE.",
            name = args.name,
        );
    }

    let mp = PathBuf::from(format!("/tmp/zboot-chroot-{}", target.name));
    std::fs::create_dir_all(&mp).with_context(|| format!("mkdir {}", mp.display()))?;

    sub::cmd(
        "mount",
        &[
            "-t",
            "zfs",
            "-o",
            "zfsutil,rw",
            &target.dataset,
            mp.to_str().context("mountpoint not utf8")?,
        ],
    )
    .with_context(|| format!("mount {} → {}", target.dataset, mp.display()))?;

    // RAII guard: bind mounts + the BE mount unwound in reverse order on
    // any exit path (success, bash crash, panic).
    let _guard = MountGuard::enter(&mp)?;

    writeln!(
        w,
        "→ chroot {} ({}). Tip: `zboot snapshot --name pre-chroot` first if you want a clean revert.",
        target.name, target.dataset,
    )
    .ok();
    writeln!(w, "→ exit (Ctrl-D, `exit`) to return.").ok();

    let shell = pick_shell(&mp, &args.shell);
    // `setsid -c` makes the spawned shell a session leader with stdin
    // as its controlling terminal. Without this, bash inherits no
    // ctty from PID-1 (the bootloader-shell case) and disables job
    // control, which on some setups manifests as a stuck shell that
    // never prints a prompt. `setsid` is in busybox in the zboot-boot
    // initrd; the operator-workstation case has it from util-linux.
    let st = Command::new("setsid")
        .arg("-c")
        .arg("chroot")
        .arg(&mp)
        .arg(&shell)
        .status()
        .with_context(|| format!("spawn `setsid -c chroot {} {}`", mp.display(), shell))?;

    writeln!(w, "← exited chroot rc={:?}", st.code()).ok();
    Ok(())
}

/// Pick a shell that exists in the BE. Prefer the requested one; fall
/// back to `/bin/sh` (which busybox provides at minimum).
fn pick_shell(be_root: &std::path::Path, requested: &str) -> String {
    let primary = be_root.join(requested.trim_start_matches('/'));
    if primary.exists() {
        return requested.to_owned();
    }
    let fallback = be_root.join("bin/sh");
    if fallback.exists() {
        return "/bin/sh".to_owned();
    }
    // Last resort: hand requested back; chroot will surface the error.
    requested.to_owned()
}

// ---------------------------------------------------------------------------
// BE locator
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TargetBe {
    name: String,
    dataset: String,
}

/// Find the BE whose name (last path component) matches. Errors on
/// no-match or multi-pool ambiguity.
fn locate_be(name: &str) -> Result<TargetBe> {
    let listing = sub::zfs_capture(&[
        "get", "-Hp", "-o", "name,property,value", "zboot:be", "-t", "filesystem",
    ])
    .context("`zfs get zboot:be` failed")?;

    let mut matches: Vec<TargetBe> = Vec::new();
    for line in listing.lines() {
        let mut cols = line.splitn(3, '\t');
        let dataset = cols.next().unwrap_or("");
        let _prop = cols.next().unwrap_or("");
        let value = cols.next().unwrap_or("").trim();
        if value != "true" {
            continue;
        }
        let last = dataset.rsplit('/').next().unwrap_or(dataset);
        if last == name {
            matches.push(TargetBe {
                name: last.to_owned(),
                dataset: dataset.to_owned(),
            });
        }
    }

    match matches.len() {
        0 => bail!(
            "chroot: no BE named {name:?} (looked for datasets with zboot:be=true)"
        ),
        1 => Ok(matches.remove(0)),
        n => bail!(
            "chroot: BE name {name:?} is ambiguous across {n} pools; pass the full \
             dataset path instead. Matches: {}",
            matches
                .iter()
                .map(|b| b.dataset.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `true` if `dataset` is mounted as `/`. Reads `/proc/self/mounts`.
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
// Mount + bind-mount guard
// ---------------------------------------------------------------------------

/// RAII guard. Enters: bind /dev /dev/pts /proc /sys into `<be_root>`.
/// Drops: lazy-umount each in reverse order, then lazy-umount the BE
/// itself. Lazy because DKMS/systemd subprocesses inside the chroot can
/// leave open fds; `umount -l` detaches the mount but lets the kernel
/// free it once those fds close.
struct MountGuard {
    be_root: PathBuf,
    bind_mounted: Vec<&'static str>,
}

impl MountGuard {
    fn enter(be_root: &std::path::Path) -> Result<Self> {
        const BINDS: &[&str] = &["/dev", "/dev/pts", "/proc", "/sys"];
        let mut g = MountGuard {
            be_root: be_root.to_path_buf(),
            bind_mounted: Vec::new(),
        };
        for src in BINDS {
            let dst = format!("{}{src}", be_root.display());
            std::fs::create_dir_all(&dst).with_context(|| format!("mkdir {dst}"))?;
            sub::cmd("mount", &["--bind", src, &dst])
                .with_context(|| format!("bind {src} → {dst}"))?;
            g.bind_mounted.push(src);
        }
        Ok(g)
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        for src in self.bind_mounted.iter().rev() {
            let dst = format!("{}{src}", self.be_root.display());
            let _ = Command::new("umount").args(["-l", &dst]).status();
        }
        if let Some(s) = self.be_root.to_str() {
            let _ = Command::new("umount").args(["-l", s]).status();
            let _ = std::fs::remove_dir(&self.be_root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_shell_returns_requested_when_present() {
        let tmp = tempdir();
        std::fs::create_dir_all(tmp.path().join("bin")).unwrap();
        std::fs::write(tmp.path().join("bin/bash"), "").unwrap();
        assert_eq!(pick_shell(tmp.path(), "/bin/bash"), "/bin/bash");
    }

    #[test]
    fn pick_shell_falls_back_to_sh_when_requested_missing() {
        let tmp = tempdir();
        std::fs::create_dir_all(tmp.path().join("bin")).unwrap();
        std::fs::write(tmp.path().join("bin/sh"), "").unwrap();
        assert_eq!(pick_shell(tmp.path(), "/bin/bash"), "/bin/sh");
    }

    #[test]
    fn pick_shell_returns_requested_when_neither_present() {
        let tmp = tempdir();
        // no bin/bash, no bin/sh — chroot will surface the failure.
        assert_eq!(pick_shell(tmp.path(), "/bin/bash"), "/bin/bash");
    }

    fn tempdir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "zboot-chroot-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
