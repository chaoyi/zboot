//! Private, bounded reader-job records. Durability is file fsync, atomic rename
//! and directory fsync; it is not protection against filesystem rollback.
//! The store owns no reader lifecycle and never removes a job or its lock.
use rustix::fs::{self as fd, AtFlags, FileType, FlockOperation, Mode, OFlags};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

const MAX_RECORD: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const RECORD: &str = "intent.json";
const LOCK: &str = "owner.lock";

pub(super) struct ReaderStore {
    root: Arc<Root>,
}

struct Root {
    path: PathBuf,
    anchor_path: PathBuf,
    anchor: File,
    directory: File,
    uid: u32,
}

/// Exclusive custody of one authenticated job directory and its stable lock
/// inode. Dropping this value closes descriptors without deleting any audit.
pub(super) struct JobLock {
    root: Arc<Root>,
    id: String,
    directory: File,
    lock: File,
}

fn refuse(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn canonical_components(path: &Path) -> io::Result<Vec<&OsStr>> {
    let mut rebuilt = PathBuf::from("/");
    let mut result = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if result.is_empty() => {}
            Component::Normal(name) => {
                rebuilt.push(name);
                result.push(name);
            }
            _ => return Err(refuse("reader store path must be absolute and canonical")),
        }
    }
    if !path.is_absolute() || path.as_os_str() != rebuilt.as_os_str() || result.is_empty() {
        return Err(refuse("reader store path must be absolute and canonical"));
    }
    Ok(result)
}

fn open_dir(parent: &File, name: &OsStr) -> io::Result<File> {
    fd::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(Into::into)
}

fn authentic_directory(stat: &fd::Stat, uid: u32, private: bool) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || stat.st_mode & 0o022 != 0
        || (private && stat.st_mode & 0o7777 != 0o700)
    {
        return Err(refuse(
            "reader store directory ownership or permissions are unsafe",
        ));
    }
    Ok(())
}

fn authentic_file(stat: &fd::Stat, uid: u32) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(refuse(
            "reader job file must be owned, private, regular and single-linked",
        ));
    }
    Ok(())
}

fn same_inode(a: &fd::Stat, b: &fd::Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

fn linked(parent: &File, name: &OsStr, held: &File) -> io::Result<()> {
    let actual = fd::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    let expected = fd::fstat(held)?;
    if !same_inode(&actual, &expected) {
        return Err(refuse(
            "reader store object was replaced; held identity no longer matches",
        ));
    }
    Ok(())
}

fn open_chain(anchor: &File, parts: &[&OsStr], create: bool, uid: u32) -> io::Result<File> {
    let mut current = anchor.try_clone()?;
    authentic_directory(&fd::fstat(&current)?, uid, false)?;
    for (index, name) in parts.iter().enumerate() {
        let private = index + 1 == parts.len();
        let next = match open_dir(&current, name) {
            Ok(directory) => directory,
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                let mode = Mode::from_raw_mode(if private { 0o700 } else { 0o755 });
                fd::mkdirat(&current, *name, mode)?;
                let directory = open_dir(&current, name)?;
                // Only a directory this call created may have its mode set.
                fd::fchmod(&directory, mode)?;
                directory.sync_all()?;
                current.sync_all()?;
                directory
            }
            Err(error) => return Err(error),
        };
        authentic_directory(&fd::fstat(&next)?, uid, private)?;
        linked(&current, name, &next)?;
        current = next;
    }
    Ok(current)
}

impl ReaderStore {
    /// Production paths always start at the real root and require effective
    /// UID zero. Existing permissions and symlinks are refused, never repaired.
    pub(super) fn open(path: &Path, create: bool) -> io::Result<Self> {
        if !rustix::process::geteuid().is_root() {
            return Err(refuse("reader job state requires root"));
        }
        canonical_components(path)?;
        let anchor = File::from(fd::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        Self::from_anchor(Path::new("/"), anchor, path, create, 0)
    }

    fn from_anchor(
        anchor_path: &Path,
        anchor: File,
        path: &Path,
        create: bool,
        uid: u32,
    ) -> io::Result<Self> {
        canonical_components(path)?;
        let relative = path
            .strip_prefix(anchor_path)
            .map_err(|_| refuse("reader store path is outside its trusted anchor"))?;
        let parts = relative
            .components()
            .map(|part| match part {
                Component::Normal(name) => Ok(name),
                _ => Err(refuse("invalid reader store component")),
            })
            .collect::<io::Result<Vec<_>>>()?;
        if parts.is_empty() {
            return Err(refuse("reader store requires a private leaf directory"));
        }
        let directory = open_chain(&anchor, &parts, create, uid)?;
        let store = Self {
            root: Arc::new(Root {
                path: path.into(),
                anchor_path: anchor_path.into(),
                anchor,
                directory,
                uid,
            }),
        };
        store.root.verify()?;
        Ok(store)
    }

    pub(super) fn create_job(&self, id: &str) -> io::Result<JobLock> {
        valid_id(id)?;
        self.root.verify()?;
        fd::mkdirat(&self.root.directory, id, Mode::from_raw_mode(0o700))?;
        let directory = open_dir(&self.root.directory, OsStr::new(id))?;
        fd::fchmod(&directory, Mode::from_raw_mode(0o700))?;
        authentic_directory(&fd::fstat(&directory)?, self.root.uid, true)?;
        directory.sync_all()?;
        self.root.directory.sync_all()?;
        self.lock_job(id, directory, true)
    }

    pub(super) fn open_job(&self, id: &str) -> io::Result<JobLock> {
        valid_id(id)?;
        self.root.verify()?;
        let directory = open_dir(&self.root.directory, OsStr::new(id))?;
        self.lock_job(id, directory, false)
    }

    fn lock_job(&self, id: &str, directory: File, create: bool) -> io::Result<JobLock> {
        authentic_directory(&fd::fstat(&directory)?, self.root.uid, true)?;
        linked(&self.root.directory, OsStr::new(id), &directory)?;
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let lock = File::from(fd::openat(
            &directory,
            LOCK,
            flags
                | if create {
                    OFlags::CREATE | OFlags::EXCL
                } else {
                    OFlags::empty()
                },
            if create {
                Mode::from_raw_mode(0o600)
            } else {
                Mode::empty()
            },
        )?);
        if create {
            fd::fchmod(&lock, Mode::from_raw_mode(0o600))?;
        }
        authentic_file(&fd::fstat(&lock)?, self.root.uid)?;
        fd::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
        let result = JobLock {
            root: Arc::clone(&self.root),
            id: id.into(),
            directory,
            lock,
        };
        result.verify()?;
        if create {
            result.lock.sync_all()?;
            result.directory.sync_all()?;
        }
        Ok(result)
    }

    /// Unknown names are ignored. Every entry counts against the scan bound;
    /// a canonical job name with unsafe metadata is an error, not cleanup authority.
    pub(super) fn list_ids(&self) -> io::Result<Vec<String>> {
        self.root.verify()?;
        let mut directory = fd::Dir::read_from(&self.root.directory)?;
        let mut ids = Vec::new();
        let mut entries = 0;
        while let Some(entry) = directory.read() {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            entries += 1;
            if entries > MAX_ENTRIES {
                return Err(io::Error::other(
                    "reader job directory exceeds its scan bound",
                ));
            }
            let Ok(name) = std::str::from_utf8(name) else {
                continue;
            };
            if valid_id(name).is_err() {
                continue;
            }
            let job = open_dir(&self.root.directory, OsStr::new(name))?;
            authentic_directory(&fd::fstat(&job)?, self.root.uid, true)?;
            linked(&self.root.directory, OsStr::new(name), &job)?;
            ids.push(name.into());
        }
        self.root.verify()?;
        ids.sort();
        Ok(ids)
    }
}

impl Root {
    fn verify(&self) -> io::Result<()> {
        let anchor = File::from(fd::open(
            &self.anchor_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        if !same_inode(&fd::fstat(&anchor)?, &fd::fstat(&self.anchor)?) {
            return Err(refuse("reader store anchor was replaced"));
        }
        let relative = self
            .path
            .strip_prefix(&self.anchor_path)
            .map_err(|_| refuse("reader store anchor changed"))?;
        let parts = relative
            .components()
            .map(|part| part.as_os_str())
            .collect::<Vec<_>>();
        let current = open_chain(&anchor, &parts, false, self.uid)?;
        if !same_inode(&fd::fstat(&current)?, &fd::fstat(&self.directory)?) {
            return Err(refuse("reader store directory was replaced"));
        }
        authentic_directory(&fd::fstat(&self.directory)?, self.uid, true)
    }
}

fn valid_id(id: &str) -> io::Result<()> {
    let parsed = uuid::Uuid::parse_str(id).map_err(|_| refuse("invalid reader job UUID"))?;
    if parsed.to_string() != id
        || parsed.get_version_num() != 4
        || parsed.get_variant() != uuid::Variant::RFC4122
    {
        return Err(refuse("reader job UUID must be canonical UUIDv4"));
    }
    Ok(())
}

impl JobLock {
    #[cfg(test)]
    pub(super) fn path(&self) -> PathBuf {
        self.root.path.join(&self.id)
    }

    #[cfg(test)]
    pub(super) fn record_path(&self) -> PathBuf {
        self.path().join(RECORD)
    }

    fn verify(&self) -> io::Result<()> {
        self.root.verify()?;
        authentic_directory(&fd::fstat(&self.directory)?, self.root.uid, true)?;
        linked(&self.root.directory, OsStr::new(&self.id), &self.directory)?;
        authentic_file(&fd::fstat(&self.lock)?, self.root.uid)?;
        linked(&self.directory, OsStr::new(LOCK), &self.lock)
    }

    fn record(&self) -> io::Result<File> {
        let file = File::from(fd::openat(
            &self.directory,
            RECORD,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        authentic_file(&fd::fstat(&file)?, self.root.uid)?;
        linked(&self.directory, OsStr::new(RECORD), &file)?;
        Ok(file)
    }

    pub(super) fn read<T: DeserializeOwned>(&self) -> io::Result<T> {
        self.verify()?;
        let file = self.record()?;
        let mut bytes = Vec::new();
        (&file)
            .take((MAX_RECORD + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reader job record exceeds 4 MiB",
            ));
        }
        self.verify()?;
        linked(&self.directory, OsStr::new(RECORD), &file)?;
        serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Publish the job's one reader manifest without replacing any existing
    /// artifact. Only the reopened read-only descriptor is returned to callers.
    pub(super) fn save_reader_manifest<T: Serialize>(&self, value: &T) -> io::Result<File> {
        const MANIFEST: &str = "reader.json";
        self.verify()?;
        let mut encoded = Bounded(Vec::new());
        serde_json::to_writer(&mut encoded, value).map_err(io::Error::other)?;
        encoded.write_all(b"\n")?;
        self.verify()?;
        let mut writer = File::from(fd::openat(
            &self.directory,
            MANIFEST,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        fd::fchmod(&writer, Mode::from_raw_mode(0o600))?;
        authentic_file(&fd::fstat(&writer)?, self.root.uid)?;
        writer.write_all(&encoded.0)?;
        writer.sync_all()?;
        self.directory.sync_all()?;
        self.verify()?;
        linked(&self.directory, OsStr::new(MANIFEST), &writer)?;
        let reader = File::from(fd::openat(
            &self.directory,
            MANIFEST,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        authentic_file(&fd::fstat(&reader)?, self.root.uid)?;
        if !same_inode(&fd::fstat(&reader)?, &fd::fstat(&writer)?) {
            return Err(refuse("reader manifest was replaced during publication"));
        }
        self.verify()?;
        linked(&self.directory, OsStr::new(MANIFEST), &reader)?;
        Ok(reader)
    }

    /// Atomically publish one bounded typed record. Publication failures may
    /// leave the new record durable; callers must reconcile instead of retrying
    /// native effects. Neither success nor fsync establishes rollback immunity.
    pub(super) fn save<T: Serialize>(&self, value: &T) -> io::Result<()> {
        self.verify()?;
        let mut encoded = Bounded(Vec::new());
        serde_json::to_writer(&mut encoded, value).map_err(io::Error::other)?;
        encoded.write_all(b"\n")?;
        self.verify()?;
        let previous = match self.record() {
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let temporary = format!(".intent-{}.tmp", uuid::Uuid::new_v4());
        let mut file = File::from(fd::openat(
            &self.directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let result = (|| {
            fd::fchmod(&file, Mode::from_raw_mode(0o600))?;
            authentic_file(&fd::fstat(&file)?, self.root.uid)?;
            file.write_all(&encoded.0)?;
            file.sync_all()?;
            self.verify()?;
            linked(&self.directory, OsStr::new(&temporary), &file)?;
            match &previous {
                Some(previous) => {
                    authentic_file(&fd::fstat(previous)?, self.root.uid)?;
                    linked(&self.directory, OsStr::new(RECORD), previous)?;
                }
                None => match fd::statat(&self.directory, RECORD, AtFlags::SYMLINK_NOFOLLOW) {
                    Err(rustix::io::Errno::NOENT) => {}
                    Ok(_) => return Err(refuse("reader record appeared during publication")),
                    Err(error) => return Err(error.into()),
                },
            }
            fd::renameat(&self.directory, temporary.as_str(), &self.directory, RECORD)?;
            file.sync_all()?;
            self.directory.sync_all()?;
            self.verify()?;
            linked(&self.directory, OsStr::new(RECORD), &file)
        })();
        if result.is_err()
            && self.verify().is_ok()
            && linked(&self.directory, OsStr::new(&temporary), &file).is_ok()
        {
            // Only our unpublished, identity-checked staging file is removed.
            let _ = fd::unlinkat(&self.directory, temporary.as_str(), AtFlags::empty());
        }
        result
    }
}

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RECORD.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reader job record exceeds 4 MiB",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{fs, os::unix::fs::PermissionsExt};

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let base = std::env::temp_dir();
            let path = base.join(format!("zsnap-store-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn open(&self, relative: &str, create: bool) -> io::Result<ReaderStore> {
            // Test-only trust anchor and UID expectation. Production always
            // starts at / and insists on effective UID zero and root ownership.
            ReaderStore::from_anchor(
                &self.0,
                File::open(&self.0)?,
                &self.0.join(relative),
                create,
                rustix::process::geteuid().as_raw(),
            )
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Audit {
        phase: String,
        sequence: u64,
    }
    fn audit(sequence: u64) -> Audit {
        Audit {
            phase: "prepared".into(),
            sequence,
        }
    }
    fn id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    #[test]
    fn creates_private_state_and_atomically_retains_completed_audit() {
        let root = TestRoot::new();
        let store = root.open("parent/state", true).unwrap();
        assert_eq!(
            fd::fstat(&store.root.directory).unwrap().st_mode & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.0.join("parent"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        let id = id();
        let job = store.create_job(&id).unwrap();
        assert_eq!(job.path(), root.0.join("parent/state").join(&id));
        assert_eq!(job.record_path(), job.path().join(RECORD));
        assert_eq!(
            job.read::<Audit>().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        job.save(&audit(1)).unwrap();
        assert_eq!(job.read::<Audit>().unwrap(), audit(1));
        job.save(&Audit {
            phase: "complete".into(),
            sequence: 2,
        })
        .unwrap();
        assert_eq!(
            fd::fstat(job.record().unwrap()).unwrap().st_mode & 0o7777,
            0o600
        );
        assert!(
            matches!(store.open_job(&id), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        assert!(store.create_job(&id).is_err());
        drop(job);
        let reopened = store.open_job(&id).unwrap();
        assert_eq!(reopened.read::<Audit>().unwrap().phase, "complete");
        assert_eq!(store.list_ids().unwrap(), vec![id]);
    }

    #[test]
    fn failed_serialization_and_oversized_save_preserve_previous_record() {
        struct Failed;
        impl Serialize for Failed {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("injected serialization failure"))
            }
        }
        let root = TestRoot::new();
        let store = root.open("state", true).unwrap();
        let job = store.create_job(&id()).unwrap();
        job.save(&audit(1)).unwrap();
        assert!(job.save(&Failed).is_err());
        assert_eq!(job.read::<Audit>().unwrap(), audit(1));
        assert!(job.save(&"x".repeat(MAX_RECORD)).is_err());
        assert_eq!(job.read::<Audit>().unwrap(), audit(1));
        assert_eq!(fs::read_dir(job.path()).unwrap().count(), 2);
    }

    #[test]
    fn reader_manifest_is_once_only_private_bounded_and_read_only() {
        let root = TestRoot::new();
        let store = root.open("state", true).unwrap();
        let job = store.create_job(&id()).unwrap();
        job.save(&audit(1)).unwrap();
        let mut reader = job.save_reader_manifest(&audit(2)).unwrap();
        assert!(reader.write_all(b"modified").is_err());
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(serde_json::from_slice::<Audit>(&bytes).unwrap(), audit(2));
        assert_eq!(fd::fstat(&reader).unwrap().st_mode & 0o7777, 0o600);
        assert!(job.save_reader_manifest(&audit(3)).is_err());
        assert_eq!(job.read::<Audit>().unwrap(), audit(1));
        let second = store.create_job(&id()).unwrap();
        assert!(
            second
                .save_reader_manifest(&"x".repeat(MAX_RECORD))
                .is_err()
        );
        assert!(!second.path().join("reader.json").exists());
    }

    #[test]
    fn reads_are_bounded_and_payload_schema_belongs_to_the_caller() {
        let root = TestRoot::new();
        let store = root.open("state", true).unwrap();
        let job = store.create_job(&id()).unwrap();
        job.save(&serde_json::json!({"unexpected": true})).unwrap();
        assert!(job.read::<Audit>().is_err());
        File::options()
            .write(true)
            .open(job.record_path())
            .unwrap()
            .set_len((MAX_RECORD + 1) as u64)
            .unwrap();
        assert_eq!(
            job.read::<serde_json::Value>().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn canonical_paths_permissions_and_ownership_are_refused_without_repair() {
        let root = TestRoot::new();
        let store = root.open("state", true).unwrap();
        for path in ["state/../state", "state/./other", "state//other", "state/"] {
            assert!(root.open(path, false).is_err(), "{path}");
        }
        fs::set_permissions(&store.root.path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(root.open("state", true).is_err());
        assert_eq!(
            fs::metadata(&store.root.path).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        let mut stat = fd::fstat(&store.root.directory).unwrap();
        assert!(authentic_directory(&stat, stat.st_uid.wrapping_add(1), false).is_err());
        stat.st_mode |= 0o020;
        assert!(authentic_directory(&stat, stat.st_uid, false).is_err());
        if !rustix::process::geteuid().is_root() {
            assert!(ReaderStore::open(&store.root.path, false).is_err());
        }
    }

    #[test]
    fn symlinked_ancestors_and_record_files_are_never_followed() {
        let root = TestRoot::new();
        let store = root.open("state", true).unwrap();
        std::os::unix::fs::symlink("state", root.0.join("alias")).unwrap();
        assert!(root.open("alias/child", true).is_err());
        let job = store.create_job(&id()).unwrap();
        let outside = root.0.join("outside.json");
        fs::write(&outside, "untouched").unwrap();
        std::os::unix::fs::symlink(&outside, job.record_path()).unwrap();
        assert!(job.read::<Audit>().is_err());
        assert!(job.save(&audit(1)).is_err());
        assert_eq!(fs::read_to_string(&outside).unwrap(), "untouched");
        assert!(
            fs::symlink_metadata(job.record_path())
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn linked_records_and_lock_files_are_refused() {
        let root = TestRoot::new();
        let store = root.open("state", true).unwrap();
        let id = id();
        let job = store.create_job(&id).unwrap();
        job.save(&audit(1)).unwrap();
        fs::hard_link(job.record_path(), root.0.join("record-copy")).unwrap();
        assert!(job.read::<Audit>().is_err());
        assert!(job.save(&audit(2)).is_err());
        fs::hard_link(job.path().join(LOCK), root.0.join("lock-copy")).unwrap();
        assert!(job.save(&audit(2)).is_err());
        drop(job);
        assert!(store.open_job(&id).is_err());
    }

    #[test]
    fn replaced_store_job_and_lock_fail_against_held_identities() {
        for replacement in ["store", "job", "lock"] {
            let root = TestRoot::new();
            let store = root.open("state", true).unwrap();
            let job = store.create_job(&id()).unwrap();
            job.save(&audit(1)).unwrap();
            let replaced = match replacement {
                "store" => store.root.path.clone(),
                "job" => job.path().to_owned(),
                _ => job.path().join(LOCK),
            };
            fs::rename(&replaced, root.0.join("original")).unwrap();
            if replacement == "lock" {
                File::create(&replaced).unwrap();
                fs::set_permissions(&replaced, fs::Permissions::from_mode(0o600)).unwrap();
            } else {
                fs::create_dir(&replaced).unwrap();
                fs::set_permissions(&replaced, fs::Permissions::from_mode(0o700)).unwrap();
            }
            assert!(job.read::<Audit>().is_err(), "{replacement}");
            assert!(job.save(&audit(2)).is_err(), "{replacement}");
            assert!(!replaced.join(RECORD).exists());
        }
    }

    #[test]
    fn listing_is_bounded_ignores_unknown_names_and_refuses_fake_job_directories() {
        let root = TestRoot::new();
        let store = root.open("state", true).unwrap();
        fs::write(store.root.path.join("unrelated"), "keep").unwrap();
        assert!(store.list_ids().unwrap().is_empty());
        for bad in [
            "../outside",
            "12345678-1234-1234-9234-1234567890ab",
            "not-a-uuid",
        ] {
            assert!(store.create_job(bad).is_err());
            assert!(store.open_job(bad).is_err());
        }
        let fake = store.root.path.join(id());
        fs::write(&fake, "not a job directory").unwrap();
        assert!(store.list_ids().is_err());
        fs::remove_file(fake).unwrap();
        for index in 0..MAX_ENTRIES {
            fs::write(store.root.path.join(format!("unknown-{index}")), "").unwrap();
        }
        assert!(store.list_ids().is_err());
        assert_eq!(
            fs::read_to_string(store.root.path.join("unrelated")).unwrap(),
            "keep"
        );
    }
}
