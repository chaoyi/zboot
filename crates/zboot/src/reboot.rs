//! Publish a one-boot request on the ESP the next boot loads zboot from (the
//! booted one when it is on a fixed disk, otherwise `--esp`), then ask the host's
//! service manager to reboot. Planning and request publication are independent
//! of the reboot command so admission is complete before its first effect.
use crate::{
    device::PartitionIdentity,
    remote_access::{self, PublicKeys},
};
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
fn refuse(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}

/// Which ESP the request goes to: the one this boot was loaded from, or the
/// one `--esp` names. Bound by the token with the ESP's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Chosen {
    Booted,
    Esp,
}

#[derive(Clone, Debug, Serialize)]
pub struct Review {
    pub target: PartitionIdentity,
    pub chosen: Chosen,
    pub fingerprints: Vec<String>,
    pub authorized_keys_sha256: String,
    #[serde(skip)]
    keys: PublicKeys,
}
fn review(target: PartitionIdentity, chosen: Chosen, keys: PublicKeys) -> io::Result<Review> {
    if target.readonly {
        return Err(refuse(format!(
            "ESP {} is read-only",
            zfs_tools::engine::escape_display(&target.partition.path)
        )));
    }
    Ok(Review {
        target,
        chosen,
        fingerprints: keys.fingerprints().to_vec(),
        authorized_keys_sha256: format!("{:x}", Sha256::digest(keys.authorized_keys())),
        keys,
    })
}
/// The ESP the Menu reads the request from on the next boot. With ESP, that
/// partition, which must hold zboot's loader. Without, the ESP this boot was
/// loaded from, unless it is not directly on a fixed disk: the next ordinary
/// boot follows the firmware's boot order and is unlikely to load a stick.
fn select(
    esp: Option<&str>,
    booted: impl FnOnce() -> io::Result<Option<PartitionIdentity>>,
    observe: impl FnOnce(&str) -> io::Result<PartitionIdentity>,
    holds_zboot: impl FnOnce(&PartitionIdentity) -> io::Result<bool>,
    disk_refusal: impl FnOnce(&str) -> io::Result<Option<String>>,
    fixed_esps: impl FnOnce() -> io::Result<Vec<String>>,
) -> io::Result<(PartitionIdentity, Chosen)> {
    if let Some(path) = esp {
        let shown = zfs_tools::engine::escape_display(path);
        let target = observe(path).map_err(|error| refuse(format!("--esp {shown}: {error}")))?;
        if crate::esp::validate_target(&target).is_err() {
            return Err(refuse(format!(
                "--esp {shown} is not a GPT EFI system partition with a FAT filesystem"
            )));
        }
        if !holds_zboot(&target).map_err(|error| refuse(format!("--esp {shown}: {error}")))? {
            return Err(refuse(format!(
                "--esp {shown} holds none of zboot's loader files (EFI/zboot/zboot.efi or \
                 zboot's EFI/BOOT/BOOTX64.EFI), so zboot's menu does not start from it"
            )));
        }
        return Ok((target, Chosen::Esp));
    }
    let target = booted()?.ok_or_else(|| {
        refuse(
            "reboot --menu requires a loader ESP; this boot has no LoaderDevicePartUUID \
             (a network boot), so name one with --esp PART",
        )
    })?;
    crate::esp::validate_target(&target)?;
    let path = &target.partition.path;
    let shown = zfs_tools::engine::escape_display(path);
    let reason = match disk_refusal(path) {
        Ok(None) => return Ok((target, Chosen::Booted)),
        Ok(Some(reason)) => reason,
        Err(error) => format!("{shown}: its disk could not be judged: {error}"),
    };
    let next = match fixed_esps() {
        Ok(paths) if paths.is_empty() => format!(
            "This host has no zboot ESP on a fixed disk; \
             pass --esp {shown} to keep using this one"
        ),
        Ok(paths) => format!(
            "Pass --esp PART for one of this host's zboot ESPs on fixed disks ({}), \
             or --esp {shown} to keep using this one",
            paths
                .iter()
                .map(|path| zfs_tools::engine::escape_display(path))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Err(error) => format!(
            "This host's zboot ESPs could not be listed ({error}); pass --esp PART for one \
             on a fixed disk, or --esp {shown} to keep using this one"
        ),
    };
    Err(refuse(format!(
        "the ESP this system booted from is not on a fixed disk ({reason}); the next \
         ordinary boot follows the firmware's boot order and is unlikely to load it, so \
         the menu would not see the request. {next}"
    )))
}
fn read_keys(path: Option<&Path>) -> io::Result<PublicKeys> {
    let Some(path) = path else {
        return remote_access::parse_public_keys(b"");
    };
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(crate::output::naming("--key", path))?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > remote_access::MAX_KEY_FILE_BYTES as u64 {
        return Err(refuse("--key requires a bounded regular public key file"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((remote_access::MAX_KEY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(refuse("--key file changed during read"));
    }
    let keys = remote_access::parse_public_keys(&bytes)?;
    if keys.is_empty() {
        return Err(refuse("--key requires at least one plain public key"));
    }
    Ok(keys)
}
pub fn plan(key: Option<&Path>, esp: Option<&str>) -> io::Result<Review> {
    let keys = read_keys(key)?;
    let (target, chosen) = select(
        esp,
        remote_access::loader_esp,
        |path| crate::device::observe_partition(path).map_err(refuse),
        crate::esp::holds_zboot,
        crate::esp::fixed_disk_refusal,
        crate::esp::fixed_zboot_esps,
    )?;
    review(target, chosen, keys)
}
pub fn consent(review: &Review) -> io::Result<String> {
    crate::consent::token(review)
}
pub fn describe(review: &Review, token: &str) -> String {
    let keys = if review.fingerprints.is_empty() {
        "no SSH; temporary menu wait".into()
    } else {
        review.fingerprints.join(", ")
    };
    let chosen = match review.chosen {
        Chosen::Booted => "the ESP this system booted from",
        Chosen::Esp => "given by --esp",
    };
    format!(
        "Reboot into menu via {} (PARTUUID {}), {chosen}\nKeys: {keys}\nToken: {token}\n",
        zfs_tools::engine::escape_display(&review.target.partition.path),
        zfs_tools::engine::escape_display(
            review
                .target
                .partition
                .partition_uuid
                .as_deref()
                .unwrap_or("")
        )
    )
}

fn publish_at(
    root: &Path,
    review: &Review,
    revalidate: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let root = remote_access::open_directory(root)?;
    let directory = match remote_access::key_directory(&root) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            revalidate()?;
            zfs_tools::engine::effect::mark();
            rustix::fs::mkdirat(&root, "zboot", Mode::from_raw_mode(0o700))
                .map_err(io::Error::from)?;
            root.sync_all()?;
            remote_access::key_directory(&root)?
        }
        Err(error) => return Err(error),
    };
    // Refuse a nonregular or linked existing request; rename must not turn an
    // unsafe path into a successful publication by silently replacing it.
    match crate::openat2_scoped(
        &directory,
        "authorized_keys",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => {
            if !File::from(fd).metadata()?.is_file() {
                return Err(refuse("existing authorized_keys is not a regular file"));
            }
        }
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(error) => return Err(io::Error::from(error)),
    }
    let temporary = format!(".authorized_keys-{}", uuid::Uuid::new_v4());
    revalidate()?;
    zfs_tools::engine::effect::mark();
    let fd = rustix::fs::openat(
        &directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(io::Error::from)?;
    let result = (|| {
        let mut file = File::from(fd);
        file.write_all(review.keys.authorized_keys())?;
        file.sync_all()?;
        revalidate()?;
        rustix::fs::renameat(
            &directory,
            temporary.as_str(),
            &directory,
            "authorized_keys",
        )
        .map_err(io::Error::from)?;
        // FAT publication requires the held inode after rename, then directory
        // and filesystem durability before the caller is allowed to reboot.
        file.sync_all()?;
        directory.sync_all()?;
        rustix::fs::syncfs(&directory).map_err(refuse)?;
        revalidate()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&directory, temporary.as_str(), AtFlags::empty());
    }
    result
}

pub fn apply(review: &Review, token: &str) -> io::Result<()> {
    crate::consent::unchanged(token, &consent(review)?)?;
    match review.chosen {
        Chosen::Booted => {
            if remote_access::loader_esp()?.as_ref() != Some(&review.target) {
                return Err(refuse("loader ESP changed since review"));
            }
        }
        Chosen::Esp => crate::esp::current(&review.target)?,
    }
    let publish = crate::esp::mounted(&review.target, true, |root| {
        publish_at(root, review, || crate::esp::current(&review.target))
    });
    let retained_request = |error| {
        refuse(format!(
            "{error}; a one-boot menu request may remain at zboot/authorized_keys on {} (PARTUUID {}). Retry the reviewed reboot command to replace the request and reboot, or remove that exact file before a later reboot",
            zfs_tools::engine::escape_display(&review.target.partition.path),
            zfs_tools::engine::escape_display(
                review
                    .target
                    .partition
                    .partition_uuid
                    .as_deref()
                    .unwrap_or("")
            ),
        ))
    };
    publish.map_err(retained_request)?;
    let mut command = Command::new("systemctl");
    command
        .arg("reboot")
        .env("SYSTEMCTL_SKIP_AUTO_KEXEC", "1")
        .env("SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT", "1");
    let output = zfs_tools::engine::native::announced(&mut command)
        .output()
        .map_err(retained_request)?;
    if !output.status.success() {
        return Err(retained_request(refuse(format!(
            "systemctl reboot failed: {}; {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> PartitionIdentity {
        PartitionIdentity {
            disk: crate::device::DiskIdentity {
                path: "/dev/test".into(),
                device_number: "8:0".into(),
                sysfs_path: "/sys/test".into(),
                bytes: 1_048_576,
                logical_sector: 512,
                physical_sector: 512,
                serial: Some("disk".into()),
                wwn: None,
                model: None,
            },
            partition: crate::device::Partition {
                path: "/dev/test1".into(),
                device_number: "8:1".into(),
                bytes: 524_288,
                partition_uuid: Some("12345678-1234-1234-1234-123456789abc".into()),
                filesystem: Some("vfat".into()),
                filesystem_uuid: Some("ABCD-EF12".into()),
                filesystem_label: None,
            },
            number: 1,
            partition_type: Some("c12a7328-f81f-11d2-ba4b-00a0c93ec93b".into()),
            readonly: false,
        }
    }
    fn stick() -> PartitionIdentity {
        let mut stick = target();
        stick.disk.path = "/dev/sdb".into();
        stick.partition.path = "/dev/sdb1".into();
        stick.partition.partition_uuid = Some("87654321-4321-4321-4321-cba987654321".into());
        stick
    }
    /// `select` with the booted ESP BOOTED, whose disk DISK judges, and the
    /// fixed zboot ESPs FIXED; `--esp` observes TARGET holding zboot when ZBOOT.
    fn pick(
        esp: Option<&str>,
        booted: Option<PartitionIdentity>,
        disk: Option<&str>,
        fixed: Vec<String>,
        given: io::Result<PartitionIdentity>,
        zboot: bool,
    ) -> io::Result<(PartitionIdentity, Chosen)> {
        select(
            esp,
            || Ok(booted),
            |_| given,
            |_| Ok(zboot),
            |_| Ok(disk.map(str::to_string)),
            || Ok(fixed),
        )
    }
    #[test]
    fn reboot_menu_is_refused_without_a_loader_esp() {
        let error = pick(None, None, None, vec![], Ok(target()), true).unwrap_err();
        assert!(error.to_string().contains("loader ESP"), "{error}");
    }
    #[test]
    fn the_booted_esp_on_a_fixed_disk_is_used_without_esp() {
        let (chosen, how) = pick(
            None,
            Some(target()),
            None,
            vec![],
            Err(refuse("unused")),
            false,
        )
        .unwrap();
        assert_eq!((chosen, how), (target(), Chosen::Booted));
    }
    #[test]
    fn a_booted_stick_is_refused_and_the_fixed_zboot_esps_are_listed() {
        let error = pick(
            None,
            Some(stick()),
            Some("/dev/sdb1 is on a usb disk"),
            vec!["/dev/nvme0n1p1".into(), "/dev/nvme1n1p1".into()],
            Ok(target()),
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("(/dev/sdb1 is on a usb disk)"), "{error}");
        assert!(
            error.contains(
                "Pass --esp PART for one of this host's zboot ESPs on fixed disks \
                 (/dev/nvme0n1p1, /dev/nvme1n1p1), or --esp /dev/sdb1 to keep using this one"
            ),
            "{error}"
        );
        let error = pick(
            None,
            Some(stick()),
            Some("/dev/sdb1 is on a removable or hot-plug disk"),
            vec![],
            Ok(target()),
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("no zboot ESP on a fixed disk"), "{error}");
        assert!(error.contains("--esp /dev/sdb1"), "{error}");
        // A disk that cannot be judged is refused the same way, not used.
        let error = select(
            None,
            || Ok(Some(stick())),
            |_| Ok(target()),
            |_| Ok(true),
            |_| Err(refuse("lsblk failed")),
            || Err(refuse("no pools")),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("could not be judged: lsblk failed"),
            "{error}"
        );
        assert!(error.contains("could not be listed (no pools)"), "{error}");
    }
    #[test]
    fn an_explicit_esp_must_be_an_esp_holding_zboots_loader() {
        // Accepted even when this boot came from a stick, or from no ESP.
        for booted in [Some(stick()), None] {
            let (chosen, how) = pick(
                Some("/dev/test1"),
                booted,
                Some("stick"),
                vec![],
                Ok(target()),
                true,
            )
            .unwrap();
            assert_eq!((chosen, how), (target(), Chosen::Esp));
        }
        let error = pick(Some("/dev/test1"), None, None, vec![], Ok(target()), false)
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("--esp /dev/test1 holds none of zboot's loader files"),
            "{error}"
        );
        let mut data = target();
        data.partition_type = Some("0fc63daf-8483-4772-8e79-3d69d8477de4".into());
        let error = pick(Some("/dev/test1"), None, None, vec![], Ok(data), true)
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("--esp /dev/test1 is not a GPT EFI system partition"),
            "{error}"
        );
        let error = pick(
            Some("/dev/nope"),
            None,
            None,
            vec![],
            Err(refuse("no such device")),
            true,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "--esp /dev/nope: no such device");
        let mut readonly = target();
        readonly.readonly = true;
        assert!(
            review(readonly, Chosen::Esp, read_keys(None).unwrap())
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );
    }
    #[test]
    fn the_token_binds_the_chosen_esp_and_how_it_was_chosen() {
        let keys = || read_keys(None).unwrap();
        let booted = consent(&review(target(), Chosen::Booted, keys()).unwrap()).unwrap();
        let given = consent(&review(target(), Chosen::Esp, keys()).unwrap()).unwrap();
        let other = consent(&review(stick(), Chosen::Esp, keys()).unwrap()).unwrap();
        let mut reformatted = target();
        reformatted.partition.filesystem_uuid = Some("1234-5678".into());
        let reformatted = consent(&review(reformatted, Chosen::Esp, keys()).unwrap()).unwrap();
        assert_ne!(booted, given);
        assert_ne!(given, other);
        assert_ne!(given, reformatted);
        assert_eq!(
            given,
            consent(&review(target(), Chosen::Esp, keys()).unwrap()).unwrap()
        );
        let planned = review(target(), Chosen::Booted, keys()).unwrap();
        assert!(describe(&planned, &booted).starts_with(
            "Reboot into menu via /dev/test1 (PARTUUID 12345678-1234-1234-1234-123456789abc), \
                 the ESP this system booted from\n"
        ));
        let planned = review(target(), Chosen::Esp, keys()).unwrap();
        assert!(describe(&planned, &given).contains("), given by --esp\n"));
    }
    #[test]
    fn a_missing_key_file_is_named() {
        let error = read_keys(Some(Path::new("/nonexistent/zboot-test.pub"))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error
                .to_string()
                .starts_with("--key /nonexistent/zboot-test.pub: "),
            "{error}"
        );
    }
    #[test]
    fn reboot_menu_needs_a_valid_key_and_writes_only_the_esp_this_boot_came_from() {
        let root = std::env::temp_dir().join(format!("zboot-reboot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let key = root.join("key");
        std::fs::write(&key, b"").unwrap();
        assert!(read_keys(Some(&key)).is_err());
        std::fs::write(&key, b"ssh-ed25519 AAAA\n").unwrap();
        assert!(read_keys(Some(&key)).is_err());
        std::fs::write(
            &key,
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\n",
        )
        .unwrap();
        let keys = read_keys(Some(&key)).unwrap();
        let link = root.join("key-link");
        std::os::unix::fs::symlink("key", &link).unwrap();
        assert_eq!(read_keys(Some(&link)).unwrap(), keys);
        let requested = review(target(), Chosen::Booted, keys).unwrap();
        publish_at(&root, &requested, || Ok(())).unwrap();
        assert_eq!(
            std::fs::read(root.join("zboot/authorized_keys")).unwrap(),
            requested.keys.authorized_keys()
        );
        let planned = review(target(), Chosen::Booted, read_keys(None).unwrap()).unwrap();
        publish_at(&root, &planned, || Ok(())).unwrap();
        assert_eq!(
            std::fs::read(root.join("zboot/authorized_keys")).unwrap(),
            b""
        );
        let before = std::fs::read(root.join("zboot/authorized_keys")).unwrap();
        assert!(publish_at(&root, &planned, || Err(refuse("identity changed"))).is_err());
        assert_eq!(
            std::fs::read(root.join("zboot/authorized_keys")).unwrap(),
            before
        );
        std::fs::remove_file(root.join("zboot/authorized_keys")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("zboot/authorized_keys")).unwrap();
        assert!(publish_at(&root, &planned, || Ok(())).is_err());
        assert_eq!(
            std::fs::read_link(root.join("zboot/authorized_keys")).unwrap(),
            Path::new("/etc/passwd")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
