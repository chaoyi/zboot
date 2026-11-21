//! The identity `deploy` gives a new BE: `/etc/hostid` (four bytes, little
//! endian, the reviewed hostid) and, when given, `/etc/hostname`. Written
//! after all user hooks. Portable deployment removes hostid before rebuilding
//! its initrds and checks again after the mandatory hook.
use super::refuse;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn etc(root: &Path) -> io::Result<File> {
    let root = File::open(root)?;
    Ok(File::from(crate::openat2_scoped(
        &root,
        "etc",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}

fn replace(etc: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    let staged = format!(".{name}.zboot-{}", uuid::Uuid::new_v4());
    let mut file = File::from(rustix::fs::openat(
        etc,
        staged.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )?);
    let result = (|| {
        file.write_all(bytes)?;
        rustix::fs::fchmod(&file, Mode::from_raw_mode(0o644))?;
        file.sync_all()?;
        rustix::fs::renameat(etc, staged.as_str(), etc, name)?;
        etc.sync_all()
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(etc, staged.as_str(), rustix::fs::AtFlags::empty());
    }
    result
}

fn read(etc: &File, name: &str) -> io::Result<Option<Vec<u8>>> {
    // Only a regular file is the identity. A FIFO or device in its place is
    // never opened (opening a FIFO waits for a writer); it is replaced.
    match rustix::fs::statat(etc, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => {}
        Ok(_) | Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    match rustix::fs::openat(
        etc,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let mut bytes = Vec::new();
            File::from(fd).take(4096).read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        }
        // Absent, or a symlink left in its place: either way not the identity.
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::LOOP) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn wanted(hostid: u32, hostname: Option<&str>) -> Vec<(&'static str, Vec<u8>)> {
    let mut files = vec![("hostid", hostid.to_le_bytes().to_vec())];
    if let Some(name) = hostname {
        files.push(("hostname", format!("{name}\n").into_bytes()));
    }
    files
}

/// After the hook: restore the identity if it was changed, then check it.
pub(crate) fn enforce(root: &Path, hostid: u32, hostname: Option<&str>) -> io::Result<()> {
    let etc = etc(root)?;
    for (name, bytes) in wanted(hostid, hostname) {
        if read(&etc, name)?.as_ref() != Some(&bytes) {
            replace(&etc, name, &bytes)?;
        }
        if read(&etc, name)?.as_ref() != Some(&bytes) {
            return Err(refuse(format!("the BE's /etc/{name} did not take")));
        }
    }
    Ok(())
}

/// Portable roots and their rebuilt initrds carry no persistent host identity.
pub(crate) fn portable(root: &Path, hostname: Option<&str>) -> io::Result<()> {
    let etc = etc(root)?;
    match rustix::fs::unlinkat(&etc, "hostid", rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
    }
    if read(&etc, "hostid")?.is_some() {
        return Err(refuse("portable BE retained /etc/hostid"));
    }
    if let Some(name) = hostname {
        replace(&etc, "hostname", format!("{name}\n").as_bytes())?;
    }
    etc.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_written_little_endian_and_restored_after_a_hook() {
        let scratch = crate::factory::tests::Scratch::new();
        let root = &scratch.0;
        std::fs::create_dir(root.join("etc")).unwrap();
        enforce(root, 0x0a0b0c0d, Some("host1")).unwrap();
        assert_eq!(
            std::fs::read(root.join("etc/hostid")).unwrap(),
            [0x0d, 0x0c, 0x0b, 0x0a]
        );
        assert_eq!(
            std::fs::read(root.join("etc/hostname")).unwrap(),
            b"host1\n"
        );
        // A hook that rewrote the hostid, or left a symlink in its place.
        std::fs::remove_file(root.join("etc/hostid")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("etc/hostid")).unwrap();
        enforce(root, 0x0a0b0c0d, Some("host1")).unwrap();
        assert!(
            std::fs::symlink_metadata(root.join("etc/hostid"))
                .unwrap()
                .is_file()
        );
        assert_eq!(
            std::fs::read(root.join("etc/hostid")).unwrap(),
            [0x0d, 0x0c, 0x0b, 0x0a]
        );
        // A FIFO in its place is replaced without waiting for a writer.
        std::fs::remove_file(root.join("etc/hostid")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            root.join("etc/hostid").as_path(),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        enforce(root, 0x0a0b0c0d, Some("host1")).unwrap();
        assert_eq!(
            std::fs::read(root.join("etc/hostid")).unwrap(),
            [0x0d, 0x0c, 0x0b, 0x0a]
        );
        // An /etc that is a symlink is refused, not followed.
        let other = crate::factory::tests::Scratch::new();
        std::os::unix::fs::symlink(&scratch.0, other.0.join("etc")).unwrap();
        assert!(enforce(&other.0, 1, None).is_err());
    }
    #[test]
    fn identity_is_enforced_after_all_hooks_and_portable_removes_hostid() {
        let scratch = crate::factory::tests::Scratch::new();
        let root = &scratch.0;
        std::fs::create_dir(root.join("etc")).unwrap();
        enforce(root, 0x01020304, Some("before-hook")).unwrap();
        std::fs::write(root.join("etc/hostid"), [9, 9, 9, 9]).unwrap();
        std::fs::write(root.join("etc/hostname"), b"hook-value\n").unwrap();
        portable(root, Some("selected-hostname")).unwrap();
        assert!(!root.join("etc/hostid").exists());
        assert_eq!(
            std::fs::read(root.join("etc/hostname")).unwrap(),
            b"selected-hostname\n"
        );
        std::os::unix::fs::symlink("/etc/hostid", root.join("etc/hostid")).unwrap();
        portable(root, None).unwrap();
        assert!(std::fs::symlink_metadata(root.join("etc/hostid")).is_err());
    }
}
