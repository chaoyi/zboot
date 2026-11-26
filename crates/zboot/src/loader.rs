//! A reviewed boot loader: one standalone zboot UKI, carrying real file
//! evidence, and the one a root ships at [`SHIPPED`].
use crate::esp::{FileIdentity, LoaderOwner};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// Where a root ships zboot's loader (the package's `zboot.efi`).
pub const SHIPPED: &str = "usr/lib/zboot/zboot.efi";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EfiFile {
    pub efi: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

fn refuse(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}
pub(crate) fn stable(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}
pub(crate) fn hash(file: &mut File) -> std::io::Result<(String, u64)> {
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(refuse("artifact hash requires a regular file"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut h = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        h.update(&buffer[..n]);
    }
    if count != before.len() || !stable(&before, &file.metadata()?) {
        return Err(refuse("artifact changed while hashing"));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((format!("{:x}", h.finalize()), count))
}
pub(crate) fn header(file: &mut File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut b = vec![0; len];
    file.read_exact(&mut b)?;
    Ok(b)
}
fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes(b[..2].try_into().unwrap())
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}
pub(crate) fn sections(file: &mut File) -> std::io::Result<BTreeMap<String, (u64, u64)>> {
    let size = file.metadata()?.len();
    let dos = header(file, 0, 64)?;
    if &dos[..2] != b"MZ" {
        return Err(refuse("EFI artifact lacks a DOS/PE header"));
    }
    let offset = u32le(&dos[60..]) as u64;
    if offset > 1024 * 1024 {
        return Err(refuse("EFI header offset exceeds supported bound"));
    }
    let pe = header(file, offset, 24)?;
    let count = u16le(&pe[6..]) as u64;
    let optional = u16le(&pe[20..]) as u64;
    if &pe[..4] != b"PE\0\0"
        || u16le(&pe[4..]) != 0x8664
        || !(1..=96).contains(&count)
        || !(70..=4096).contains(&optional)
    {
        return Err(refuse(
            "EFI artifact is not a supported x86-64 PE application",
        ));
    }
    let opt = header(file, offset + 24, optional as usize)?;
    if u16le(&opt) != 0x20b || u16le(&opt[68..]) != 10 {
        return Err(refuse(
            "EFI artifact has an unsupported optional header/subsystem",
        ));
    }
    let headers_end = offset + 24 + optional + 40 * count;
    let table = header(file, offset + 24 + optional, (40 * count) as usize)?;
    let mut result = BTreeMap::new();
    let mut ranges = Vec::new();
    for entry in table.as_chunks::<40>().0 {
        let name = std::str::from_utf8(&entry[..8])
            .map_err(refuse)?
            .trim_end_matches('\0')
            .to_owned();
        let virtual_size = u32le(&entry[8..]) as u64;
        let raw_size = u32le(&entry[16..]) as u64;
        let start = u32le(&entry[20..]) as u64;
        if raw_size == 0 {
            continue;
        }
        if start < headers_end
            || virtual_size > raw_size
            || start.checked_add(raw_size).is_none_or(|end| end > size)
            || ranges
                .iter()
                .any(|(a, b)| start < *b && *a < start + raw_size)
        {
            return Err(refuse("EFI section range is invalid or overlaps"));
        }
        ranges.push((start, start + raw_size));
        if result.insert(name, (start, virtual_size)).is_some() {
            return Err(refuse("duplicate EFI section name"));
        }
    }
    Ok(result)
}
fn open_file(path: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )?))
}
impl EfiFile {
    pub fn inspect(path: &Path) -> io::Result<Self> {
        let path = std::fs::canonicalize(path).map_err(crate::output::naming("UKI", path))?;
        let mut file = open_file(&path).map_err(crate::output::naming("UKI", &path))?;
        Self::read(&path, &mut file)
    }
    fn read(path: &Path, file: &mut File) -> io::Result<Self> {
        let before = file.metadata()?;
        if !before.is_file() || before.len() == 0 || before.len() > 1024 * 1024 * 1024 {
            return Err(refuse(
                "--efi needs a nonempty regular UKI no larger than 1 GiB",
            ));
        }
        let sections = sections(file)?;
        for name in [".linux", ".initrd", ".osrel", ".cmdline"] {
            if sections.get(name).is_none_or(|(_, bytes)| *bytes == 0) {
                return Err(refuse(format!("--efi UKI lacks a nonempty {name} section")));
            }
        }
        if crate::esp::loader_owner(file)? != LoaderOwner::Zboot {
            return Err(refuse("--efi needs a zboot UKI (ID=zboot)"));
        }
        file.seek(SeekFrom::Start(0))?;
        let (sha256, bytes) = hash(file)?;
        let after = file.metadata()?;
        if (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) || bytes != after.len()
        {
            return Err(refuse("EFI file changed while it was inspected"));
        }
        Ok(Self {
            efi: path.to_path_buf(),
            sha256,
            bytes,
        })
    }
    /// The reviewed file, opened again without following a symlink and
    /// checked unchanged, at its start.
    pub fn open(&self) -> io::Result<File> {
        self.validate()?;
        let mut file = open_file(&self.efi)?;
        if Self::read(&self.efi, &mut file)? != *self {
            return Err(refuse("EFI file changed since review"));
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
    pub(crate) fn validate(&self) -> io::Result<()> {
        if !self.efi.is_absolute()
            || self.efi.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || self.bytes == 0
            || self.bytes > 1024 * 1024 * 1024
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refuse("invalid standalone EFI evidence"));
        }
        Ok(())
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.open().map(drop)
    }
    pub fn identity(&self) -> io::Result<FileIdentity> {
        self.validate()?;
        Ok(FileIdentity {
            sha256: self.sha256.clone(),
            bytes: self.bytes,
        })
    }
}

/// The zboot UKI `root` ships at [`SHIPPED`], opened beneath `root` with no
/// symlink step and checked as `--efi` is: the open file, at its start, and
/// its identity.
pub(crate) fn shipped(root: &File) -> io::Result<(File, FileIdentity)> {
    let fd = crate::openat2_scoped(
        root,
        SHIPPED,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|error| match error {
        rustix::io::Errno::NOENT => refuse(format!(
            "/{SHIPPED} is missing: the source ships no zboot loader"
        )),
        error => refuse(format!("/{SHIPPED}: {error}")),
    })?;
    let mut file = File::from(fd);
    let efi = EfiFile::read(&Path::new("/").join(SHIPPED), &mut file)
        .map_err(|error| refuse(format!("/{SHIPPED}: {error}")))?;
    file.seek(SeekFrom::Start(0))?;
    Ok((file, efi.identity()?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn a_missing_uki_is_named() {
        let error = EfiFile::inspect(Path::new("/nonexistent/zboot-test.efi")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(
            error
                .to_string()
                .starts_with("UKI /nonexistent/zboot-test.efi: "),
            "{error}"
        );
    }
    /// Minimal x86-64 UKI with all four reviewed nonempty sections.
    pub(crate) fn uki(path: &Path) {
        let parts: [(&[u8; 8], &[u8]); 4] = [
            (b".linux\0\0", b"kernel"),
            (b".initrd\0", b"initrd"),
            (b".osrel\0\0", b"ID=zboot\n"),
            (b".cmdline", b"zboot.recovery=1"),
        ];
        let mut bytes = vec![0; 5 * 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&128u32.to_le_bytes());
        bytes[128..132].copy_from_slice(b"PE\0\0");
        bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[134..136].copy_from_slice(&4u16.to_le_bytes());
        bytes[148..150].copy_from_slice(&240u16.to_le_bytes());
        bytes[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[220..222].copy_from_slice(&10u16.to_le_bytes());
        // Four table entries end after byte 512; payload starts at 1024.
        bytes.resize(6 * 512, 0);
        for (index, (name, data)) in parts.into_iter().enumerate() {
            let table = 392 + index * 40;
            let start = 1024 + index * 512;
            bytes[table..table + 8].copy_from_slice(name);
            bytes[table + 8..table + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            bytes[table + 16..table + 20].copy_from_slice(&512u32.to_le_bytes());
            bytes[table + 20..table + 24].copy_from_slice(&(start as u32).to_le_bytes());
            bytes[start..start + data.len()].copy_from_slice(data);
        }
        std::fs::write(path, bytes).unwrap();
    }
    #[test]
    fn a_standalone_uki_needs_no_manifest_and_rejects_changed_bytes() {
        let root = crate::factory::tests::Scratch::new();
        let path = root.0.join("standalone.efi");
        uki(&path);
        let loader = EfiFile::inspect(&path).unwrap();
        loader.open().unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[1024] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(
            loader
                .open()
                .unwrap_err()
                .to_string()
                .contains("changed since review")
        );
    }
    #[test]
    fn reviewed_efi_open_follows_no_replacement_symlink() {
        use std::os::unix::fs::symlink;
        let root = crate::factory::tests::Scratch::new();
        let path = root.0.join("standalone.efi");
        uki(&path);
        let loader = EfiFile::inspect(&path).unwrap();
        std::fs::rename(&path, root.0.join("other.efi")).unwrap();
        symlink("other.efi", &path).unwrap();
        assert!(loader.open().is_err());
    }
    #[test]
    fn a_loader_symlink_out_of_the_snapshot_is_refused() {
        use std::os::unix::fs::symlink;
        let scratch = crate::factory::tests::Scratch::new();
        let root = scratch.0.join("root");
        std::fs::create_dir_all(root.join("usr/lib/zboot")).unwrap();
        let outside = scratch.0.join("outside.efi");
        uki(&outside);
        let open = || shipped(&File::open(&root).unwrap());
        assert!(
            open()
                .unwrap_err()
                .to_string()
                .contains("ships no zboot loader")
        );
        // A link to a zboot UKI outside the root, as a file or a directory.
        symlink(&outside, root.join(SHIPPED)).unwrap();
        assert!(open().is_err());
        std::fs::remove_file(root.join(SHIPPED)).unwrap();
        std::fs::remove_dir(root.join("usr/lib/zboot")).unwrap();
        std::fs::create_dir(scratch.0.join("lib")).unwrap();
        uki(&scratch.0.join("lib/zboot.efi"));
        symlink(scratch.0.join("lib"), root.join("usr/lib/zboot")).unwrap();
        assert!(open().is_err());
        // The file itself is admitted with the identity `--efi` would bind.
        std::fs::remove_file(root.join("usr/lib/zboot")).unwrap();
        std::fs::create_dir(root.join("usr/lib/zboot")).unwrap();
        uki(&root.join(SHIPPED));
        let (_, identity) = open().unwrap();
        assert_eq!(
            identity,
            EfiFile::inspect(&root.join(SHIPPED))
                .unwrap()
                .identity()
                .unwrap()
        );
    }
    #[test]
    fn a_plain_efi_application_or_foreign_uki_is_not_a_zboot_loader() {
        let root = crate::factory::tests::Scratch::new();
        let path = root.0.join("foreign.efi");
        uki(&path);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[2048..2057].copy_from_slice(b"ID=other\n");
        std::fs::write(&path, &bytes).unwrap();
        assert!(
            EfiFile::inspect(&path)
                .unwrap_err()
                .to_string()
                .contains("zboot UKI")
        );
        bytes[392..400].copy_from_slice(b".other\0\0");
        std::fs::write(&path, bytes).unwrap();
        assert!(
            EfiFile::inspect(&path)
                .unwrap_err()
                .to_string()
                .contains(".linux")
        );
    }
}
