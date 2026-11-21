//! Private, read-only whole-filesystem observations. A bind view of an
//! existing mount changes only the private target's VFS flags, never the
//! original mount, superblock or persistent filesystem properties.
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::{
    fs::{self, File},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};
use zfs_tools::engine::mountinfo::{self, Mount};

fn refuse(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}

#[derive(Clone, Copy)]
pub(crate) enum Source<'a> {
    Zfs(&'a str),
    /// The caller must admit and revalidate the complete partition identity.
    Vfat {
        path: &'a str,
        device_number: &'a str,
    },
}
impl Source<'_> {
    fn matches(self, mount: &Mount) -> bool {
        match self {
            Self::Zfs(name) => mount.filesystem == "zfs" && mount.source == name,
            Self::Vfat { device_number, .. } => {
                mount.filesystem == "vfat" && mount.device == device_number
            }
        }
    }

    fn mount_new(self, target: &Path, flags: nix::mount::MsFlags) -> nix::Result<()> {
        match self {
            Self::Zfs(name) => {
                nix::mount::mount(Some(name), target, Some("zfs"), flags, Some("zfsutil"))
            }
            Self::Vfat { path, .. } => nix::mount::mount(
                Some(path),
                target,
                Some("vfat"),
                flags,
                Some("uid=0,gid=0,umask=0077,utf8=1"),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ViewStrategy {
    NewFilesystem,
    Bind(Mount),
}

fn view_strategy(mounts: &[Mount], source: Source<'_>) -> io::Result<ViewStrategy> {
    // Snapshot views already have a read-only superblock. Preserve their
    // existing direct-mount path rather than selecting a live dataset view.
    if matches!(source, Source::Zfs(name) if name.contains('@')) {
        return Ok(ViewStrategy::NewFilesystem);
    }
    let matching: Vec<_> = mounts
        .iter()
        .filter(|mount| source.matches(mount))
        .collect();
    if matching.is_empty() {
        return Ok(ViewStrategy::NewFilesystem);
    }
    let mut whole: Vec<_> = matching
        .into_iter()
        .filter(|mount| {
            mount.root == Path::new("/")
                && mount.mount_point.is_absolute()
                && mounts
                    .iter()
                    .filter(|row| row.mount_point == mount.mount_point)
                    .count()
                    == 1
        })
        .collect();
    whole.sort_by(|left, right| {
        left.mount_point
            .components()
            .count()
            .cmp(&right.mount_point.components().count())
            .then_with(|| left.mount_point.cmp(&right.mount_point))
    });
    whole
        .first()
        .map(|mount| ViewStrategy::Bind((*mount).clone()))
        .ok_or_else(|| refuse("the source has no unambiguous whole-filesystem mount for a view"))
}

fn exact_view<'a>(mounts: &'a [Mount], path: &Path, source: Source<'_>) -> Option<&'a Mount> {
    let mut at_path = mounts.iter().filter(|mount| mount.mount_point == path);
    let mount = at_path.next()?;
    (at_path.next().is_none() && mount.root == Path::new("/") && source.matches(mount))
        .then_some(mount)
}

fn mounted_exactly(mounts: &[Mount], path: &Path, source: Source<'_>) -> bool {
    exact_view(mounts, path, source).is_some_and(|mount| {
        ["ro", "nosuid", "nodev", "noexec"]
            .iter()
            .all(|required| mount.has_option(required))
            && !mount.has_option("rw")
    })
}

fn original_view_unchanged(mounts: &[Mount], original: &Mount) -> io::Result<()> {
    if mounts.iter().find(|mount| mount.id == original.id) == Some(original)
        && mounts
            .iter()
            .filter(|mount| mount.mount_point == original.mount_point)
            .count()
            == 1
    {
        Ok(())
    } else {
        Err(refuse(
            "the original source mount changed during inspection",
        ))
    }
}

fn with_mounted_view<T>(
    inspect: impl FnOnce() -> io::Result<T>,
    unmount: impl FnOnce() -> io::Result<()>,
) -> io::Result<T> {
    let value = inspect();
    let cleanup = unmount();
    match (value, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Err(cleanup)) => Err(refuse(format!("{error}; {cleanup}"))),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn bind_source(original: &Mount) -> io::Result<File> {
    use std::os::fd::AsRawFd;
    let root = File::open("/")?;
    let relative = original
        .mount_point
        .strip_prefix("/")
        .map_err(|_| refuse("the source mount is not absolute"))?;
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    let fd = File::from(crate::openat2_scoped(
        &root,
        relative,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    let fdinfo = fs::read_to_string(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd()))?;
    let mount_id = fdinfo.lines().find_map(|line| {
        line.strip_prefix("mnt_id:")
            .and_then(|id| id.trim().parse::<u64>().ok())
    });
    if mount_id != Some(original.id) {
        return Err(refuse(
            "the opened view source is not the selected whole-filesystem mount",
        ));
    }
    original_view_unchanged(&mountinfo::current()?, original)?;
    Ok(fd)
}

/// Isolate the current thread's mount table and mark all mounts private.
pub(crate) fn enter_private_namespace() -> io::Result<()> {
    use nix::{
        mount::{MsFlags, mount},
        sched::{CloneFlags, unshare},
    };
    unshare(CloneFlags::CLONE_FS | CloneFlags::CLONE_NEWNS)
        .map_err(|e| refuse(format!("view isolation failed: {e}")))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| refuse(format!("private mount failed: {e}")))?;
    Ok(())
}

/// Verify `/run` is a root-owned, non-symlink, non-world-writable directory
/// before creating private mountpoints or runtime files beneath it.
pub(crate) fn check_runtime_dir() -> io::Result<()> {
    let run = fs::symlink_metadata("/run")?;
    if !run.is_dir() || run.file_type().is_symlink() || run.uid() != 0 || run.mode() & 0o022 != 0 {
        return Err(refuse("runtime directory /run is not trusted"));
    }
    Ok(())
}

/// Run `work` against a mount created inside an isolated private mount
/// namespace on a fresh `0o700` `/run/zboot-<tag>-<uuid>` directory, always
/// unmounting (with `MNT_DETACH` fallback) and removing the directory.
pub(crate) fn with_private_mount<T: Send>(
    tag: &str,
    prepare: impl FnOnce() -> io::Result<()> + Send,
    mount_fn: impl FnOnce(&Path) -> io::Result<()> + Send,
    work: impl FnOnce(&Path) -> io::Result<T> + Send,
) -> io::Result<T> {
    let tag = tag.to_owned();
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> io::Result<T> {
                use nix::mount::{MntFlags, umount2};
                enter_private_namespace()?;
                prepare()?;
                check_runtime_dir()?;
                let directory =
                    Path::new("/run").join(format!("zboot-{tag}-{}", uuid::Uuid::new_v4()));
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                let result = (|| -> io::Result<T> {
                    mount_fn(&directory)?;
                    let result = work(&directory);
                    let unmounted = umount2(&directory, MntFlags::empty()).map_err(refuse);
                    if unmounted.is_err() {
                        let _ = umount2(&directory, MntFlags::MNT_DETACH);
                    }
                    let value = result?;
                    unmounted?;
                    Ok(value)
                })();
                let cleanup = fs::remove_dir(&directory);
                let value = result?;
                cleanup?;
                Ok(value)
            })
            .join()
            .map_err(|_| refuse("private mount worker failed"))?
    })
}

pub(crate) fn readonly<T: Send>(
    source: Source<'_>,
    check: impl Fn() -> io::Result<()> + Send,
    read: impl FnOnce(&Path) -> io::Result<T> + Send,
) -> io::Result<T> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> io::Result<T> {
                use nix::mount::{MntFlags, MsFlags, mount, umount2};
                enter_private_namespace()?;
                check()?;
                check_runtime_dir()?;
                let directory =
                    Path::new("/run").join(format!("zboot-view-{}", uuid::Uuid::new_v4()));
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                let result = (|| -> io::Result<T> {
                    use std::os::fd::AsRawFd;
                    // Observe and open only after namespace isolation: a bind
                    // source fd must refer to this namespace's cloned mount.
                    let strategy = view_strategy(&mountinfo::current()?, source)?;
                    let source_fd = match &strategy {
                        ViewStrategy::Bind(original) => Some(bind_source(original)?),
                        ViewStrategy::NewFilesystem => None,
                    };
                    let readonly = MsFlags::MS_RDONLY
                        | MsFlags::MS_NOSUID
                        | MsFlags::MS_NODEV
                        | MsFlags::MS_NOEXEC;
                    if let Some(fd) = &source_fd {
                        let held =
                            PathBuf::from(format!("/proc/thread-self/fd/{}", fd.as_raw_fd()));
                        mount(
                            Some(held.as_path()),
                            &directory,
                            None::<&str>,
                            MsFlags::MS_BIND,
                            None::<&str>,
                        )
                    } else {
                        source.mount_new(&directory, readonly)
                    }
                    .map_err(|e| refuse(format!("read-only view failed: {e}")))?;
                    // From here every failure, including a failed read-only
                    // remount, must unmount the private target before return.
                    with_mounted_view(
                        || -> io::Result<T> {
                            if let ViewStrategy::Bind(original) = &strategy {
                                let mounts = mountinfo::current()?;
                                original_view_unchanged(&mounts, original)?;
                                if !exact_view(&mounts, &directory, source)
                                    .is_some_and(|mount| mount.device == original.device)
                                {
                                    return Err(refuse(
                                        "the bind view is not the whole source filesystem",
                                    ));
                                }
                                // MS_BIND makes this a per-mount change. It must
                                // never remount the original or its superblock.
                                mount(
                                    None::<&str>,
                                    &directory,
                                    None::<&str>,
                                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | readonly,
                                    None::<&str>,
                                )
                                .map_err(|e| {
                                    refuse(format!("read-only bind remount failed: {e}"))
                                })?;
                            }
                            let verify = || -> io::Result<()> {
                                let mounts = mountinfo::current()?;
                                if !mounted_exactly(&mounts, &directory, source) {
                                    return Err(refuse(
                                        "the view did not mount exactly the read-only source",
                                    ));
                                }
                                if let ViewStrategy::Bind(original) = &strategy {
                                    original_view_unchanged(&mounts, original)?;
                                    if exact_view(&mounts, &directory, source)
                                        .is_none_or(|mount| mount.device != original.device)
                                    {
                                        return Err(refuse("the view's native filesystem changed"));
                                    }
                                }
                                Ok(())
                            };
                            verify()?;
                            check()?;
                            let value = read(&directory)?;
                            verify()?;
                            check()?;
                            Ok(value)
                        },
                        || {
                            if let Err(error) = umount2(&directory, MntFlags::empty()) {
                                // Only this generated private target is detached;
                                // the original source mount is never touched.
                                let detail = match umount2(&directory, MntFlags::MNT_DETACH) {
                                    Ok(()) => format!("view unmount failed: {error}"),
                                    Err(detach) => format!(
                                        "view unmount failed: {error}; view detach failed: {detach}"
                                    ),
                                };
                                return Err(refuse(detail));
                            }
                            Ok(())
                        },
                    )
                })();
                let cleanup = fs::remove_dir(&directory);
                let value = result?;
                cleanup?;
                Ok(value)
            })
            .join()
            .map_err(|_| refuse("view thread failed"))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zfs_strategy(mounts: &[Mount], source: &str) -> io::Result<ViewStrategy> {
        view_strategy(mounts, Source::Zfs(source))
    }
    fn zfs_mounted_exactly(text: &str, path: &Path, source: &str) -> bool {
        mountinfo::table(text)
            .is_ok_and(|mounts| mounted_exactly(&mounts, path, Source::Zfs(source)))
    }
    #[test]
    fn the_view_requires_an_exact_read_only_mount() {
        let path = Path::new("/run/zboot-hostid-test");
        let row = "42 1 0:57 / /run/zboot-hostid-test ro,nosuid,nodev,noexec - zfs tank/ROOT/be@save ro,zfsutil\n";
        assert!(zfs_mounted_exactly(row, path, "tank/ROOT/be@save"));
        assert!(!zfs_mounted_exactly(row, path, "tank/ROOT/be"));
        assert!(!zfs_mounted_exactly(
            &row.replace(" ro,nosuid", " rw,nosuid"),
            path,
            "tank/ROOT/be@save"
        ));
        assert!(!zfs_mounted_exactly(
            &row.replace(" - zfs ", " - tmpfs "),
            path,
            "tank/ROOT/be@save"
        ));
    }

    #[test]
    fn mounted_filesystem_views_bind_the_whole_source_without_changing_its_mode() {
        for options in ["rw,relatime", "ro,relatime"] {
            let row = format!("42 1 0:57 / / {options} - zfs tank/ROOT/be rw,zfsutil\n");
            let mounts = mountinfo::table(&row).unwrap();
            let ViewStrategy::Bind(original) = zfs_strategy(&mounts, "tank/ROOT/be").unwrap()
            else {
                panic!("an existing filesystem must use a per-mount bind view");
            };
            assert_eq!(original.mount_point, Path::new("/"));
            assert_eq!(original.options, options);
            assert_eq!(original.super_options, "rw,zfsutil");
            let combined = format!(
                "{row}43 1 0:57 / /run/view ro,nosuid,nodev,noexec - zfs tank/ROOT/be rw,zfsutil\n"
            );
            assert!(zfs_mounted_exactly(
                &combined,
                Path::new("/run/view"),
                "tank/ROOT/be"
            ));
            original_view_unchanged(&mountinfo::table(&combined).unwrap(), &original).unwrap();
            assert!(
                original_view_unchanged(
                    &mountinfo::table(&combined.replacen(options, "ro,nosuid", 1)).unwrap(),
                    &original,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn whole_mount_selection_decodes_names_and_rejects_subdirectories_or_stacked_mounts() {
        let source = "tank/ROOT/a b";
        let whole = "42 1 0:57 / /srv/a\\040b rw - zfs tank/ROOT/a\\040b rw\n";
        let mounts = mountinfo::table(whole).unwrap();
        let ViewStrategy::Bind(selected) = zfs_strategy(&mounts, source).unwrap() else {
            panic!("decoded exact source was not selected");
        };
        assert_eq!(selected.mount_point, Path::new("/srv/a b"));
        assert!(
            zfs_strategy(
                &mountinfo::table(&whole.replace("0:57 / ", "0:57 /boot ")).unwrap(),
                source
            )
            .is_err()
        );
        let stacked = format!("{whole}43 1 0:60 / /srv/a\\040b rw - tmpfs tmpfs rw\n");
        assert!(zfs_strategy(&mountinfo::table(&stacked).unwrap(), source).is_err());
        assert!(mountinfo::table(&whole.replace("\\040", "\\999")).is_err());
        assert_eq!(
            zfs_strategy(&mounts, "tank/ROOT/other").unwrap(),
            ViewStrategy::NewFilesystem
        );
        let snapshot = whole.replace("a\\040b rw\n", "a\\040b@snap ro\n");
        assert_eq!(
            zfs_strategy(&mountinfo::table(&snapshot).unwrap(), "tank/ROOT/a b@snap").unwrap(),
            ViewStrategy::NewFilesystem
        );
    }

    #[test]
    fn a_read_only_view_requires_the_whole_source_and_per_mount_security_flags() {
        let row = "43 1 0:57 / /run/view ro,nosuid,nodev,noexec - zfs tank/ROOT/be rw\n";
        let path = Path::new("/run/view");
        assert!(zfs_mounted_exactly(row, path, "tank/ROOT/be"));
        for changed in [
            row.replace("0:57 / ", "0:57 /boot "),
            row.replace("ro,nosuid,nodev,noexec", "rw,nosuid,nodev,noexec"),
            row.replace("ro,nosuid,nodev,noexec", "ro,nosuid,nodev"),
            row.replace("tank/ROOT/be", "tank/ROOT/other"),
            format!("{row}44 1 0:58 / /run/view ro - tmpfs tmpfs ro\n"),
        ] {
            assert!(
                !zfs_mounted_exactly(&changed, path, "tank/ROOT/be"),
                "{changed}"
            );
        }
    }

    #[test]
    fn vfat_views_match_native_partition_number_not_device_path_spelling() {
        let source = Source::Vfat {
            path: "/dev/disk/by-partuuid/esp-id",
            device_number: "252:1",
        };
        let row = "42 1 252:1 / /boot/efi rw,relatime - vfat /dev/vda1 rw,utf8\n";
        let mounts = mountinfo::table(row).unwrap();
        let ViewStrategy::Bind(original) = view_strategy(&mounts, source).unwrap() else {
            panic!("an already mounted ESP must get a per-mount bind view");
        };
        assert_eq!(original.mount_point, Path::new("/boot/efi"));
        let target = "43 1 252:1 / /run/view ro,nosuid,nodev,noexec - vfat /dev/vda1 rw,utf8\n";
        let exactly = |text: &str| {
            mounted_exactly(
                &mountinfo::table(text).unwrap(),
                Path::new("/run/view"),
                source,
            )
        };
        assert!(exactly(target));
        original_view_unchanged(
            &mountinfo::table(&format!("{row}{target}")).unwrap(),
            &original,
        )
        .unwrap();
        for changed in [
            target.replace("252:1", "252:2"),
            target.replace(" - vfat ", " - ext4 "),
            target.replace("252:1 / ", "252:1 /EFI "),
        ] {
            assert!(!exactly(&changed));
        }
        assert!(
            view_strategy(
                &mountinfo::table(&row.replace("252:1 / ", "252:1 /EFI ")).unwrap(),
                source
            )
            .is_err()
        );
        assert_eq!(
            view_strategy(&[], source).unwrap(),
            ViewStrategy::NewFilesystem
        );
    }

    #[test]
    fn a_failed_read_only_remount_still_unmounts_the_private_target() {
        let unmounted = std::cell::Cell::new(false);
        let result: io::Result<()> = with_mounted_view(
            || Err(refuse("read-only bind remount failed")),
            || {
                unmounted.set(true);
                Ok(())
            },
        );
        assert!(unmounted.get());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("bind remount failed")
        );
        let result: io::Result<()> = with_mounted_view(
            || Err(refuse("view changed")),
            || Err(refuse("view unmount failed")),
        );
        let error = result.unwrap_err().to_string();
        assert!(error.contains("view changed") && error.contains("view unmount failed"));
    }
}
