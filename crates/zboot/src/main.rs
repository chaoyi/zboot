//! Shared userspace and recovery application contracts.
#![cfg_attr(test, allow(clippy::disallowed_methods, reason = "test fixtures"))]
// First, so its `print!` family shadows std's in every module below.
#[macro_use]
mod output;
mod boot_environment;
mod boot_support;
mod build_identity;
mod cli;
mod consent;
mod history;
mod hostid;
mod menu;
mod mount_view;
mod mounting;
mod observation;
mod pairs;
mod placement;
mod recipe;
mod selection;
mod status;
mod tree;

mod transfer;

mod device;
mod native_run;

mod loader;
mod maintenance;

mod content;
mod esp;
mod handoff;
mod reboot;
mod remote_access;

mod factory;

mod deploy;

mod restore;

/// The zboot command: its CLI and menu. It owns command parsing, interaction
/// and command-level locking, and must not run beneath an existing writer
/// session.
fn main() {
    std::process::exit(cli::main(std::env::args_os()));
}

/// `openat2` for a scoped (`RESOLVE_BENEATH` or `RESOLVE_IN_ROOT`) lookup. The
/// kernel answers EAGAIN when a rename or mount anywhere on the host races a
/// `..` step of such a lookup, and openat2(2) asks the caller to retry.
pub(crate) fn openat2_scoped<Fd: std::os::fd::AsFd, P: rustix::path::Arg + Copy>(
    dirfd: Fd,
    path: P,
    oflags: rustix::fs::OFlags,
    mode: rustix::fs::Mode,
    resolve: rustix::fs::ResolveFlags,
) -> rustix::io::Result<std::os::fd::OwnedFd> {
    let dirfd = dirfd.as_fd();
    let mut retries = 0;
    loop {
        match rustix::fs::openat2(dirfd, path, oflags, mode, resolve) {
            Err(rustix::io::Errno::AGAIN) if retries < 64 => retries += 1,
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use std::{
        fs,
        os::unix::fs::symlink,
        sync::atomic::{AtomicBool, Ordering},
    };

    /// Unretried, about 2% of these lookups fail with EAGAIN on this kernel.
    #[test]
    fn scoped_lookup_through_dotdot_survives_concurrent_renames() {
        let root = std::env::temp_dir().join(format!("zboot-scoped-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/target"), b"x").unwrap();
        symlink("../target", root.join("a/b/link")).unwrap();
        let dir = fs::File::open(&root).unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let (x, y) = (root.join("x"), root.join("y"));
                fs::write(&x, b"").unwrap();
                while !stop.load(Ordering::Relaxed) {
                    fs::rename(&x, &y).unwrap();
                    fs::rename(&y, &x).unwrap();
                }
            });
            for _ in 0..20_000 {
                super::openat2_scoped(
                    &dir,
                    "a/b/link",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::IN_ROOT,
                )
                .unwrap();
            }
            stop.store(true, Ordering::Relaxed);
        });
        fs::remove_dir_all(&root).unwrap();
    }
}
