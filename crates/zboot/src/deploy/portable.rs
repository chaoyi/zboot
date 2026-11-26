//! Portable deployment's private hostid view and verification of every initrd.
use super::{overlay, refuse};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Every program in `work`, including child mount workers, inherits this view.
/// Parameter changes still happen only around the native pool operations.
pub(super) fn without_hostid<T: Send>(
    work: impl FnOnce() -> io::Result<T> + Send,
) -> io::Result<T> {
    std::thread::scope(|scope| {
        scope.spawn(move || {
        crate::mount_view::enter_private_namespace()?;
        crate::mount_view::check_runtime_dir()?;
        let empty = Path::new("/run").join(format!("zboot-portable-hostid-{}",uuid::Uuid::new_v4()));
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&empty)?;
        file.sync_all()?;
        let mut covered = None;
        let result = (|| {
            match fs::symlink_metadata("/etc/hostid") {
                Ok(_) => {
                    let target = fs::canonicalize("/etc/hostid")?;
                    if !fs::metadata(&target)?.is_file() { return Err(refuse("portable deploy requires /etc/hostid to be a regular file or absent")); }
                    mount(Some(empty.as_path()), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(refuse)?;
                    covered = Some(target);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
            work()
        })();
        let unmounted = covered.map_or(Ok(()), |path| umount2(&path,MntFlags::empty()).map_err(refuse));
        let removed = fs::remove_file(&empty);
        match (result,unmounted.and(removed)) {
            (Ok(value),Ok(())) => Ok(value),
            (Err(error),Ok(())) | (Ok(_),Err(error)) => Err(error),
            (Err(error),Err(cleanup)) => Err(refuse(format!("{error}; portable hostid namespace cleanup failed: {cleanup}"))),
        }
    }).join().map_err(|_|refuse("portable deployment mount worker failed"))?
    })
}

fn beneath(root: &Path, path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    let root = File::open(root)?;
    Ok(File::from(crate::openat2_scoped(
        &root,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}

pub(super) fn require_tools(root: &Path) -> io::Result<()> {
    for path in [
        "usr/sbin/update-initramfs",
        "usr/bin/unmkinitramfs",
        "usr/bin/lsinitramfs",
    ] {
        let metadata = beneath(root, Path::new(path))?.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return Err(refuse(
                "portable deploy requires an initramfs-tools root with update-initramfs, unmkinitramfs and lsinitramfs",
            ));
        }
    }
    Ok(())
}

fn regular_digest(root: &Path, path: &str) -> io::Result<String> {
    let file = beneath(root, Path::new(path))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err(refuse(
            "portable initrd policy file is not bounded regular content",
        ));
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn expected_digest(portable: &overlay::Overlay, path: &str) -> io::Result<String> {
    match portable
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| &entry.kind)
    {
        Some(overlay::Kind::File { sha256, .. }) => Ok(sha256.clone()),
        _ => Err(refuse("portable overlay lacks its reviewed policy file")),
    }
}

pub(super) fn verify_contents(
    extracted: &Path,
    listing: &str,
    release: &str,
    portable: &overlay::Overlay,
) -> io::Result<()> {
    // Debian unmkinitramfs separates early cpio archives from the main image.
    let main = match fs::symlink_metadata(extracted.join("main")) {
        Ok(metadata) if metadata.is_dir() => extracted.join("main"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => extracted.to_path_buf(),
        _ => {
            return Err(refuse(
                "portable initrd main archive is not a contained directory",
            ));
        }
    };
    for (source, member) in [
        ("etc/default/zfs", "etc/default/zfs"),
        (
            "etc/initramfs-tools/scripts/init-bottom/zboot-portable",
            "scripts/init-bottom/zboot-portable",
        ),
    ] {
        if regular_digest(&main, member)? != expected_digest(portable, source)? {
            return Err(refuse(format!(
                "portable initrd {release} lacks the exact read-only import or RAM-layer policy"
            )));
        }
    }
    let module = format!("lib/modules/{release}/kernel/fs/overlayfs/overlay.ko");
    if !listing.lines().any(|line| {
        let line = line.trim().trim_start_matches("./").trim_start_matches('/');
        let line = line.strip_prefix("usr/").unwrap_or(line);
        line.strip_prefix(&module)
            .is_some_and(|suffix| matches!(suffix, "" | ".xz" | ".zst" | ".gz"))
    }) {
        return Err(refuse(format!(
            "portable initrd {release} lacks the overlay kernel module"
        )));
    }
    Ok(())
}

fn initrds(root: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let boot = beneath(root, Path::new("boot"))?;
    if !boot.metadata()?.is_dir() {
        return Err(refuse("portable root has no boot directory"));
    }
    let mut images = Vec::new();
    for entry in fs::read_dir(root.join("boot"))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| refuse("portable initrd filename is not UTF-8"))?;
        let Some(release) = name.strip_prefix("initrd.img-") else {
            continue;
        };
        if release.is_empty()
            || !release
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
            || !entry.file_type()?.is_file()
            || images.len() >= 1024
        {
            return Err(refuse(
                "portable initrd inventory contains an unsupported member",
            ));
        }
        images.push((release.to_owned(), PathBuf::from("boot").join(name)));
    }
    if images.is_empty() {
        return Err(refuse("portable root has no initrd to verify"));
    }
    images.sort();
    Ok(images)
}

fn verify_each_initrd(
    root: &Path,
    mut verify: impl FnMut(&str, &Path) -> io::Result<()>,
) -> io::Result<()> {
    for (release, image) in initrds(root)? {
        verify(&release, &image)?;
    }
    Ok(())
}

pub(super) fn verify_every_initrd(root: &Path, portable: &overlay::Overlay) -> io::Result<()> {
    require_tools(root)?;
    verify_each_initrd(root, |release, image| {
        let inside = format!("/run/zboot-portable-check-{}", uuid::Uuid::new_v4());
        let extracted = root.join(inside.trim_start_matches('/'));
        let run = beneath(root, Path::new("run"))?;
        if !run.metadata()?.is_dir() {
            return Err(refuse("portable root's run directory is not contained"));
        }
        fs::DirBuilder::new().mode(0o700).create(&extracted)?;
        let checked = (|| {
            let root = root
                .to_str()
                .ok_or_else(|| refuse("portable root path is not UTF-8"))?;
            let image = format!("/{}", image.display());
            let listing = crate::native_run::run(
                "chroot",
                &[root.into(), "/usr/bin/lsinitramfs".into(), image.clone()],
                16 * 1024 * 1024,
                600,
            )
            .map_err(refuse)?;
            if listing.len() > 16 * 1024 * 1024 {
                return Err(refuse("portable initrd listing exceeds its bound"));
            }
            crate::native_run::run(
                "chroot",
                &[
                    root.into(),
                    "/usr/bin/unmkinitramfs".into(),
                    image,
                    inside.clone(),
                ],
                16 * 1024 * 1024,
                600,
            )
            .map_err(refuse)?;
            verify_contents(&extracted, &listing, release, portable)
        })();
        let removed = fs::remove_dir_all(&extracted);
        checked?;
        removed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_ram_root_preserves_dev_when_udev_has_already_moved_it() {
        use std::{os::unix::fs::symlink, process::Command};

        let scratch = crate::factory::tests::Scratch::new();
        let original = include_str!(
            "overlays/portable/rootfs/etc/initramfs-tools/scripts/init-bottom/zboot-portable"
        );
        let mut script = original.to_owned();
        // Redirect only the fixed initramfs paths into this private fixture.
        for (from, to) in [
            (". /scripts/functions", ". \"$ZT_TEST_FUNCTIONS\""),
            ("dev=/dev\n", "dev=\"$ZT_TEST_DEV\"\n"),
            ("base=/run/zboot-portable\n", "base=\"$ZT_TEST_BASE\"\n"),
        ] {
            assert_eq!(script.matches(from).count(), 1);
            script = script.replacen(from, to, 1);
        }
        let script_path = scratch.0.join("portable");
        fs::write(&script_path, script).unwrap();
        let functions = scratch.0.join("functions");
        fs::write(
            &functions,
            b"panic() { printf '%s\\n' \"$*\" >&2; return 1; }\n\
              mount() { printf 'mount' >> \"$ZT_TEST_MOUNTS\"; \
              for arg do printf '<%s>' \"$arg\" >> \"$ZT_TEST_MOUNTS\"; done; \
              printf '\\n' >> \"$ZT_TEST_MOUNTS\"; }\n",
        )
        .unwrap();
        for udev_first in [false, true] {
            let fixture = scratch.0.join(if udev_first { "after" } else { "before" });
            let root = fixture.join("target root");
            let base = fixture.join("portable");
            let dev = fixture.join("initramfs-dev");
            let mounts = fixture.join("mounts");
            fs::create_dir_all(root.join("dev")).unwrap();
            if udev_first {
                symlink(root.join("dev"), &dev).unwrap();
            } else {
                fs::create_dir(&dev).unwrap();
            }
            let output = Command::new("/bin/sh")
                .arg(&script_path)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("rootmnt", &root)
                .env("ZT_TEST_FUNCTIONS", &functions)
                .env("ZT_TEST_DEV", &dev)
                .env("ZT_TEST_BASE", &base)
                .env("ZT_TEST_MOUNTS", &mounts)
                .output()
                .unwrap();
            assert!(output.status.success(), "{:?}", output);
            let trace = fs::read_to_string(mounts).unwrap();
            let calls = trace.lines().collect::<Vec<_>>();
            assert_eq!(calls.len(), if udev_first { 4 } else { 3 });
            assert_eq!(
                calls[0],
                format!(
                    "mount<--move><{}><{}>",
                    root.display(),
                    base.join("lower").display()
                )
            );
            assert!(calls[2].starts_with("mount<-t><overlay>"));
            if udev_first {
                assert_eq!(
                    calls[3],
                    format!(
                        "mount<--move><{}><{}>",
                        base.join("lower/dev").display(),
                        root.join("dev").display()
                    )
                );
                assert_eq!(fs::read_link(dev).unwrap(), root.join("dev"));
            }
        }
    }

    #[test]
    fn the_portable_overlay_is_applied_last_and_regenerates_every_initrd() {
        let scratch = crate::factory::tests::Scratch::new();
        fs::create_dir(scratch.0.join("boot")).unwrap();
        for release in ["first", "second"] {
            fs::write(
                scratch.0.join(format!("boot/initrd.img-{release}")),
                b"fixture",
            )
            .unwrap();
        }
        let mut checked = Vec::new();
        let result = verify_each_initrd(&scratch.0, |release, _| {
            checked.push(release.to_owned());
            if release == "second" {
                Err(refuse("missing second initrd policy"))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(checked, ["first", "second"]);
        let policy = overlay::portable();
        let hook = policy.post_install.as_ref().unwrap();
        let bytes = include_bytes!("overlays/portable/post-install");
        assert_eq!(hook.sha256, format!("{:x}", Sha256::digest(bytes)));
        assert!(
            std::str::from_utf8(bytes)
                .unwrap()
                .contains("update-initramfs -u -k all")
        );
    }

    #[test]
    fn an_initrd_without_the_option_or_the_script_fails_the_deploy() {
        let scratch = crate::factory::tests::Scratch::new();
        let portable = overlay::portable();
        // File-only unmkinitramfs fixture; no root ownership operation, chroot,
        // initrd program or native pool is needed to verify the frozen bytes.
        fs::create_dir_all(scratch.0.join("etc/default")).unwrap();
        fs::create_dir_all(scratch.0.join("scripts/init-bottom")).unwrap();
        fs::write(
            scratch.0.join("etc/default/zfs"),
            include_bytes!("overlays/portable/rootfs/etc/default/zfs"),
        )
        .unwrap();
        fs::write(
            scratch.0.join("scripts/init-bottom/zboot-portable"),
            include_bytes!(
                "overlays/portable/rootfs/etc/initramfs-tools/scripts/init-bottom/zboot-portable"
            ),
        )
        .unwrap();
        let listing = "usr/lib/modules/test/kernel/fs/overlayfs/overlay.ko.zst\n";
        verify_contents(&scratch.0, listing, "test", &portable).unwrap();
        assert!(verify_contents(&scratch.0, "", "test", &portable).is_err());
        for path in ["etc/default/zfs", "scripts/init-bottom/zboot-portable"] {
            let before = fs::read(scratch.0.join(path)).unwrap();
            fs::write(scratch.0.join(path), b"wrong policy\n").unwrap();
            assert!(verify_contents(&scratch.0, listing, "test", &portable).is_err());
            fs::write(scratch.0.join(path), before).unwrap();
        }
    }
    #[test]
    fn portable_refuses_a_root_that_is_not_initramfs_tools() {
        let scratch = crate::factory::tests::Scratch::new();
        assert!(require_tools(&scratch.0).is_err());
    }
}
