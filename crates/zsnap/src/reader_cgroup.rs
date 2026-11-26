//! Private Linux cgroup-v2 custody for one protected reader job.
//!
//! Each job owns two leaves beneath the fixed parent /sys/fs/cgroup/zsnap-protect
//! and serializes their creation, recovery and removal. Root processes outside
//! that ownership contract must not rename, replace, alias or re-permission its
//! groups. A record is evidence, never authority.
//! There is intentionally no Drop cleanup: every uncertainty retains custody.
//!
//! Admission runs once per job. Every later control access goes through a held
//! leaf descriptor, so a reused path cannot redirect it. After the supervisor
//! enters Setup, its own /proc/self/cgroup entry proves where the held parent
//! sits in the global hierarchy.

use rustix::fs::{self as fd, AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const CGROUP2_MAGIC: u32 = 0x6367_7270;
const MAX_CONTROL_BYTES: u64 = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const ROOT: &str = "/sys/fs/cgroup";
const PARENT: &str = "zsnap-protect";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CgroupIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CgroupRecord {
    pub(crate) parent: PathBuf,
    pub(crate) name: String,
    pub(crate) identity: CgroupIdentity,
}

struct Hierarchy {
    root: File,
    parent: File,
}

/// One job's admission of the global cgroup-v2 root and the fixed parent.
/// Its leaves share these descriptors; no path is resolved again from `/`.
#[derive(Clone)]
pub(crate) struct CgroupParent(Arc<Hierarchy>);

pub(crate) struct ReaderCgroup {
    parent: CgroupParent,
    record: CgroupRecord,
    group: File,
}

/// Live authority to return only the current supervisor to the cgroup it
/// left. This is never serializable and has no Drop effects. Losing the
/// handle keeps the supervisor counted in Setup.
pub(crate) struct SupervisorReturn {
    setup: ReaderCgroup,
    original_procs: File,
}

fn refusal(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn identity(metadata: &fs::Metadata) -> CgroupIdentity {
    CgroupIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn trusted_permissions(uid: u32, mode: u32) -> bool {
    // A POSIX ACL granting write is reflected in the group mask's write bit.
    uid == 0 && mode & 0o022 == 0
}

fn parent_path() -> PathBuf {
    Path::new(ROOT).join(PARENT)
}

fn open_at(directory: &File, name: &OsStr, flags: OFlags) -> io::Result<File> {
    fd::openat(
        directory,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)
}

fn open_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    open_at(parent, name, OFlags::RDONLY | OFlags::DIRECTORY)
}

/// Open `name` only while it still links the recorded inode. A removed and
/// recreated group of the same name is a new inode within the boot.
fn open_recorded(parent: &File, name: &str, expected: &CgroupIdentity) -> io::Result<File> {
    let group = open_directory(parent, OsStr::new(name))?;
    if identity(&group.metadata()?) != *expected {
        return Err(refusal("reader cgroup identity changed"));
    }
    Ok(group)
}

fn require_cgroup2(file: &File) -> io::Result<()> {
    if fd::fstatfs(file).map_err(io::Error::from)?.f_type as u64 != u64::from(CGROUP2_MAGIC) {
        return Err(refusal("reader custody requires cgroup v2"));
    }
    Ok(())
}

fn require_private_cgroup(directory: &File) -> io::Result<()> {
    require_cgroup2(directory)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || !trusted_permissions(metadata.uid(), metadata.mode()) {
        return Err(refusal(
            "reader custody requires root-owned cgroups without group or other write",
        ));
    }
    Ok(())
}

/// Migration needs write on the destination's and the common ancestor's
/// cgroup.procs. Out of a leaf, that is the parent's (staying beneath it) or
/// the root's (leaving it), so both must be closed to ordinary users.
fn require_private_procs(directory: &File) -> io::Result<()> {
    let procs = open_at(directory, OsStr::new("cgroup.procs"), OFlags::RDONLY)?.metadata()?;
    if !procs.is_file() || !trusted_permissions(procs.uid(), procs.mode()) {
        return Err(refusal(
            "reader custody requires root-owned cgroup.procs without group or other write",
        ));
    }
    Ok(())
}

fn unified_membership(text: &str) -> io::Result<&str> {
    let mut lines = text.lines();
    let path = lines
        .next()
        .and_then(|line| line.strip_prefix("0::"))
        .ok_or_else(|| refusal("cannot observe unified cgroup membership"))?;
    if lines.next().is_some()
        || !path.starts_with('/')
        || path.bytes().any(|byte| byte < 32 || byte == 127)
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(refusal("malformed unified cgroup membership"));
    }
    Ok(path)
}

/// Relative to our cgroup namespace, which admission requires to be PID 1's.
fn current_membership() -> io::Result<String> {
    unified_membership(&fs::read_to_string("/proc/self/cgroup")?).map(str::to_owned)
}

fn require_domain(text: &str) -> io::Result<()> {
    if !matches!(text, "domain" | "domain\n") {
        return Err(refusal("reader custody requires an ordinary domain cgroup"));
    }
    Ok(())
}

fn parse_kv_u64<'a>(
    text: &'a str,
    name: &str,
) -> io::Result<std::collections::BTreeMap<&'a str, (&'a str, u64)>> {
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 2
            || !fields[1].bytes().all(|byte| byte.is_ascii_digit())
            || values.contains_key(fields[0])
        {
            return Err(refusal(format!("malformed {name}")));
        }
        let value = fields[1]
            .parse::<u64>()
            .map_err(|_| refusal(format!("invalid {name} value")))?;
        values.insert(fields[0], (fields[1], value));
    }
    Ok(values)
}

fn parse_no_descendants(text: &str) -> io::Result<bool> {
    let values = parse_kv_u64(text, "cgroup.stat")?;
    let (_, descendants) = values
        .get("nr_descendants")
        .copied()
        .ok_or_else(|| refusal("cgroup.stat lacks descendant count"))?;
    let (_, dying) = values
        .get("nr_dying_descendants")
        .copied()
        .ok_or_else(|| refusal("cgroup.stat lacks dying descendant count"))?;
    Ok(descendants == 0 && dying == 0)
}

fn group_name(job_id: &str) -> io::Result<String> {
    if job_id.is_empty()
        || job_id.len() > 64
        || !job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return Err(refusal("invalid reader job identifier"));
    }
    Ok(format!("zsnap-reader-{job_id}"))
}

fn validate_group_name(name: &str) -> io::Result<()> {
    let job_id = name
        .strip_prefix("zsnap-reader-")
        .ok_or_else(|| refusal("invalid reader cgroup name"))?;
    if group_name(job_id)? != name {
        return Err(refusal("invalid reader cgroup name"));
    }
    Ok(())
}

fn write_membership_once(writer: &mut impl Write, pid: u32) -> io::Result<()> {
    // kernfs parses every write as a complete control command. write_fmt /
    // writeln may split the PID and newline into separate syscalls; the latter
    // would fail after membership already changed. Never retry a short write.
    let command = format!("{pid}\n");
    if writer.write(command.as_bytes())? != command.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete cgroup membership control write",
        ));
    }
    Ok(())
}

fn read_control(mut file: File) -> io::Result<String> {
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_CONTROL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONTROL_BYTES {
        return Err(refusal("oversized cgroup control file"));
    }
    String::from_utf8(bytes).map_err(|_| refusal("non-UTF8 cgroup control file"))
}

/// `populated` is the kernel's recursive state, including child cgroups.
fn parse_populated(text: &str) -> io::Result<bool> {
    let values = parse_kv_u64(text, "cgroup.events")?;
    match values
        .get("populated")
        .map(|(raw, _)| *raw)
        .ok_or_else(|| refusal("cgroup.events lacks populated state"))?
    {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(refusal("invalid cgroup populated state")),
    }
}

fn parse_processes(text: &str) -> io::Result<BTreeSet<u32>> {
    let mut processes = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() || !line.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(refusal("malformed cgroup.procs"));
        }
        let pid = line
            .parse::<u32>()
            .map_err(|_| refusal("invalid cgroup process ID"))?;
        if pid == 0 || !processes.insert(pid) {
            return Err(refusal("invalid or duplicate cgroup process ID"));
        }
    }
    Ok(processes)
}

impl CgroupParent {
    /// The once-per-job admission, before any child, membership change or
    /// native hold. Only `create` makes the fixed parent; it never changes
    /// controllers, delegation or the membership of any existing group.
    pub(crate) fn admit(create: bool) -> io::Result<Self> {
        if fs::read_link("/proc/self/ns/cgroup")? != fs::read_link("/proc/1/ns/cgroup")? {
            return Err(refusal(
                "reader custody requires the machine's global cgroup namespace",
            ));
        }
        let root = fd::open(
            ROOT,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(io::Error::from)?;
        require_private_cgroup(&root)?;
        require_private_procs(&root)?;
        if create {
            match fd::mkdirat(&root, PARENT, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let parent = open_directory(&root, OsStr::new(PARENT))?;
        require_private_cgroup(&parent)?;
        require_private_procs(&parent)?;
        Ok(Self(Arc::new(Hierarchy { root, parent })))
    }

    pub(crate) fn create(&self, job_id: &str) -> io::Result<ReaderCgroup> {
        let name = group_name(job_id)?;
        // Existing groups are never adopted here.
        fd::mkdirat(&self.0.parent, name.as_str(), Mode::from_raw_mode(0o700))
            .map_err(io::Error::from)?;
        // On any failure after mkdir, retain the group rather than guessing
        // whether it is empty or still ours. The caller records the failure.
        let group = open_directory(&self.0.parent, OsStr::new(&name))?;
        let custody = ReaderCgroup {
            parent: self.clone(),
            record: CgroupRecord {
                parent: parent_path(),
                name,
                identity: identity(&group.metadata()?),
            },
            group,
        };
        custody.require_controls()?;
        if custody.populated()? {
            return Err(refusal("new reader cgroup is already populated"));
        }
        Ok(custody)
    }

    /// The caller must read `record` from its authenticated job file while
    /// holding that job's exclusion. Only the group now linked under the
    /// recorded name with the recorded inode is opened.
    pub(crate) fn open_recovery(&self, record: &CgroupRecord) -> io::Result<ReaderCgroup> {
        validate_group_name(&record.name)?;
        if record.parent != parent_path() {
            return Err(refusal(
                "recovery cgroup parent differs from the fixed custody parent",
            ));
        }
        let group = open_recorded(&self.0.parent, &record.name, &record.identity)?;
        let custody = ReaderCgroup {
            parent: self.clone(),
            record: record.clone(),
            group,
        };
        custody.require_controls()?;
        Ok(custody)
    }
}

impl ReaderCgroup {
    pub(crate) fn identity(&self) -> &CgroupRecord {
        &self.record
    }

    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            parent: self.parent.clone(),
            record: self.record.clone(),
            group: self.group.try_clone()?,
        })
    }

    fn control(&self, name: &str, writable: bool) -> io::Result<File> {
        let access = if writable {
            OFlags::WRONLY
        } else {
            OFlags::RDONLY
        };
        open_at(&self.group, OsStr::new(name), access)
    }

    fn read(&self, name: &str) -> io::Result<String> {
        read_control(self.control(name, false)?)
    }

    fn require_controls(&self) -> io::Result<()> {
        require_private_cgroup(&self.group)?;
        self.control("cgroup.kill", true)?;
        self.control("cgroup.procs", true)?;
        parse_processes(&self.read("cgroup.procs")?)?;
        self.populated()?;
        require_domain(&self.read("cgroup.type")?)?;
        parse_no_descendants(&self.read("cgroup.stat")?)?;
        Ok(())
    }

    /// The Setup group is safe for normal cleanup only when no other process
    /// or descendant group can still own this job's namespace or native work.
    /// Our own membership proves the leaf's place in the global hierarchy.
    pub(crate) fn contains_only_current_process(&self) -> io::Result<bool> {
        let no_descendants = parse_no_descendants(&self.read("cgroup.stat")?)?;
        let members = parse_processes(&self.read("cgroup.procs")?)?;
        let populated = self.populated()?;
        let own = current_membership()?;
        Ok(no_descendants
            && populated
            && members == BTreeSet::from([std::process::id()])
            && own == format!("/{PARENT}/{}", self.record.name))
    }

    /// Enter a fresh Setup group before creating private namespaces or native
    /// children. Every subsequent child inherits its membership atomically.
    /// The caller must persist both sibling group records before native work.
    pub(crate) fn enter_supervisor(&self) -> io::Result<SupervisorReturn> {
        if self.populated()? || !parse_no_descendants(&self.read("cgroup.stat")?)? {
            return Err(refusal("supervisor requires a fresh empty Setup group"));
        }
        let original = current_membership()?;
        let procs = Path::new(original.trim_start_matches('/')).join("cgroup.procs");
        // Capture every fallible descriptor before moving. No error path
        // automatically moves the supervisor out of counted custody.
        let returned = SupervisorReturn {
            setup: self.try_clone()?,
            original_procs: open_at(&self.parent.0.root, procs.as_os_str(), OFlags::WRONLY)?,
        };
        write_membership_once(&mut self.control("cgroup.procs", true)?, 0)?;
        if !self.contains_only_current_process()? {
            return Err(refusal("supervisor Setup membership could not be verified"));
        }
        Ok(returned)
    }

    fn populated(&self) -> io::Result<bool> {
        parse_populated(&self.read("cgroup.events")?)
    }

    /// Only an owned child, blocked before exec/fork, may be moved. The
    /// caller keeps its blocking gate closed until this succeeds. `Child`
    /// reserves the unreaped PID across the membership write.
    pub(crate) fn move_blocked_child(&self, child: &mut Child) -> io::Result<()> {
        if child.try_wait()?.is_some() {
            return Err(refusal("blocked reader child already exited"));
        }
        write_membership_once(&mut self.control("cgroup.procs", true)?, child.id())?;
        if !parse_processes(&self.read("cgroup.procs")?)?.contains(&child.id()) {
            return Err(refusal("reader child membership could not be verified"));
        }
        Ok(())
    }

    /// `Ok(false)` means the deadline expired while recursively populated.
    /// Missing, removed, inaccessible or malformed state is an error, never
    /// evidence of emptiness. No signals or cleanup happen while waiting.
    pub(crate) fn wait_empty(&self, timeout: Duration) -> io::Result<bool> {
        let started = Instant::now();
        loop {
            if !self.populated()? {
                return Ok(true);
            }
            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                return Ok(false);
            };
            if remaining.is_zero() {
                return Ok(false);
            }
            thread::sleep(remaining.min(POLL_INTERVAL));
        }
    }

    /// Kill only this held group and its descendants. A successful write is
    /// not proof of termination: the caller must subsequently wait_empty.
    pub(crate) fn kill_owned(&self) -> io::Result<()> {
        self.control("cgroup.kill", true)?.write_all(b"1\n")
    }

    /// Remove only the held, recursively empty group. Descendant groups are
    /// never recursively removed: the kernel's ENOTEMPTY is conservative.
    pub(crate) fn retire_empty(self) -> io::Result<()> {
        if self.populated()? {
            return Err(refusal("reader cgroup remains populated"));
        }
        // Never remove a replacement that reuses the name.
        open_recorded(
            &self.parent.0.parent,
            &self.record.name,
            &self.record.identity,
        )?;
        fd::unlinkat(
            &self.parent.0.parent,
            self.record.name.as_str(),
            AtFlags::REMOVEDIR,
        )
        .map_err(io::Error::from)
    }
}

impl SupervisorReturn {
    /// Return only this supervisor after all protected work is complete. A
    /// removed original group refuses through its held descriptor. No
    /// arbitrary PID is ever moved or killed.
    pub(crate) fn restore(mut self) -> io::Result<()> {
        if !self.setup.contains_only_current_process()? {
            return Err(refusal("Setup still has other namespace or native owners"));
        }
        write_membership_once(&mut self.original_procs, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("reader-cgroup-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn membership_is_one_complete_kernel_control_write() {
        #[derive(Default)]
        struct Capture {
            calls: Vec<Vec<u8>>,
        }
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls.push(bytes.to_vec());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut captured = Capture::default();
        write_membership_once(&mut captured, 700).unwrap();
        write_membership_once(&mut captured, 0).unwrap();
        assert_eq!(captured.calls, vec![b"700\n".to_vec(), b"0\n".to_vec()]);
    }

    #[test]
    fn events_use_recursive_populated_and_allow_additive_numeric_fields() {
        assert!(!parse_populated("populated 0\nfrozen 0\nfuture 27\n").unwrap());
        assert!(parse_populated("frozen 0\npopulated 1\n").unwrap());
        for invalid in [
            "",
            "frozen 0\n",
            "populated 2\n",
            "populated 00\n",
            "populated 0\npopulated 1\n",
            "populated 0 extra\n",
            "populated -1\n",
            "populated 0\nfuture nope\n",
            "populated 0\n\n",
        ] {
            assert!(parse_populated(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn process_inventory_refuses_ambiguous_ids() {
        assert_eq!(
            parse_processes("17\n28\n").unwrap(),
            BTreeSet::from([17, 28])
        );
        assert!(parse_processes("").unwrap().is_empty());
        for invalid in ["0\n", "17\n17\n", "17 28\n", "-1\n", "4294967296\n", "\n"] {
            assert!(parse_processes(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn setup_requires_ordinary_domain_and_no_live_or_dying_descendants() {
        require_domain("domain\n").unwrap();
        for invalid in [
            "threaded\n",
            "domain threaded\n",
            "domain invalid\n",
            "",
            "domain\nextra\n",
        ] {
            assert!(require_domain(invalid).is_err());
        }
        assert!(
            parse_no_descendants("nr_descendants 0\nnr_dying_descendants 0\nfuture 4\n").unwrap()
        );
        assert!(!parse_no_descendants("nr_descendants 1\nnr_dying_descendants 0\n").unwrap());
        assert!(!parse_no_descendants("nr_descendants 0\nnr_dying_descendants 1\n").unwrap());
        for invalid in [
            "",
            "nr_descendants 1\n",
            "nr_dying_descendants 0\n",
            "nr_descendants 0\nnr_descendants 0\nnr_dying_descendants 0\n",
            "nr_descendants -1\nnr_dying_descendants 0\n",
        ] {
            assert!(parse_no_descendants(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn group_names_are_one_owned_component() {
        assert_eq!(group_name("abc-123_4").unwrap(), "zsnap-reader-abc-123_4");
        for invalid in ["", ".", "..", "a/b", "a\nb", "a b", "a\0b"] {
            assert!(group_name(invalid).is_err());
        }
        assert!(group_name(&"a".repeat(65)).is_err());
        assert!(validate_group_name("system.slice").is_err());
        assert!(validate_group_name("zsnap-reader-").is_err());
    }

    #[test]
    fn custody_directories_are_root_owned_without_group_or_other_write() {
        // Applied to the cgroup root, the fixed parent and each leaf, and to
        // the root's and parent's cgroup.procs.
        assert!(trusted_permissions(0, 0o40755));
        assert!(trusted_permissions(0, 0o40700));
        assert!(trusted_permissions(0, 0o100644));
        assert!(!trusted_permissions(1000, 0o40755));
        assert!(!trusted_permissions(0, 0o40775));
        assert!(!trusted_permissions(0, 0o40757));
        assert!(!trusted_permissions(0, 0o100646));
        assert!(!trusted_permissions(0, 0o100664));
        assert!(!trusted_permissions(1000, 0o100644));
    }

    #[test]
    fn writable_or_foreign_membership_files_refuse_admission() {
        use std::os::unix::fs::PermissionsExt;
        // An ordinary directory stands in for a held cgroup directory; only
        // its cgroup.procs entry is inspected here.
        let fixture = Fixture::new();
        let directory = File::open(&fixture.0).unwrap();
        assert!(require_private_procs(&directory).is_err());
        let procs = fixture.0.join("cgroup.procs");
        fs::write(&procs, "").unwrap();
        // A non-root test runner owns the file, which is itself refused.
        let root = rustix::process::geteuid().is_root();
        for (mode, trusted) in [(0o644, true), (0o600, true), (0o646, false), (0o664, false)] {
            fs::set_permissions(&procs, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                require_private_procs(&directory).is_ok(),
                trusted && root,
                "{mode:o}"
            );
        }
        fs::remove_file(&procs).unwrap();
        fs::create_dir(&procs).unwrap();
        assert!(require_private_procs(&directory).is_err());
    }

    #[test]
    fn unified_membership_is_one_absolute_v2_path() {
        assert_eq!(
            unified_membership("0::/init.scope\n").unwrap(),
            "/init.scope"
        );
        assert_eq!(unified_membership("0::/\n").unwrap(), "/");
        assert_eq!(
            unified_membership("0::/zsnap-protect/zsnap-reader-a\n").unwrap(),
            "/zsnap-protect/zsnap-reader-a"
        );
        for malformed in [
            "",
            "0::relative\n",
            "1:cpu:/init.scope\n",
            "0::/init.scope\n0::/other\n",
            "0::/../init.scope\n",
            "0::/init\tscope\n",
        ] {
            assert!(unified_membership(malformed).is_err(), "{malformed:?}");
        }
    }

    #[test]
    fn ordinary_filesystem_is_never_accepted_as_cgroup() {
        let directory = File::open(std::env::current_dir().unwrap()).unwrap();
        assert!(require_cgroup2(&directory).is_err());
        assert!(require_private_cgroup(&directory).is_err());
    }

    #[test]
    fn recorded_inode_refuses_a_reused_name() {
        // Ordinary directory fixtures test only the held-parent lookup and
        // inode comparison; they are never presented as cgroup filesystems.
        let fixture = Fixture::new();
        let parent = File::open(&fixture.0).unwrap();
        fs::create_dir(fixture.0.join("group")).unwrap();
        let held = open_directory(&parent, OsStr::new("group")).unwrap();
        let expected = identity(&held.metadata().unwrap());
        open_recorded(&parent, "group", &expected).unwrap();
        fs::rename(fixture.0.join("group"), fixture.0.join("old-group")).unwrap();
        fs::create_dir(fixture.0.join("group")).unwrap();
        assert!(open_recorded(&parent, "group", &expected).is_err());
        assert_eq!(identity(&held.metadata().unwrap()), expected);
        let wrong_device = CgroupIdentity {
            device: expected.device.wrapping_add(1),
            inode: expected.inode,
        };
        assert!(open_recorded(&parent, "old-group", &wrong_device).is_err());
        assert!(open_recorded(&parent, "missing", &expected).is_err());
    }

    #[test]
    fn records_keep_three_fields_and_refuse_any_other() {
        let written = r#"{"parent":"/sys/fs/cgroup/zsnap-protect",
            "name":"zsnap-reader-a","identity":{"device":7,"inode":9}}"#;
        let other = written.replacen('{', r#"{"parent_identity":{"device":7,"inode":2},"#, 1);
        assert!(serde_json::from_str::<CgroupRecord>(&other).is_err());
        let record: CgroupRecord = serde_json::from_str(written).unwrap();
        assert_eq!(record.parent, parent_path());
        assert_eq!(record.name, "zsnap-reader-a");
        assert_eq!(
            record.identity,
            CgroupIdentity {
                device: 7,
                inode: 9
            }
        );
        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            serde_json::json!({"parent":"/sys/fs/cgroup/zsnap-protect",
                "name":"zsnap-reader-a","identity":{"device":7,"inode":9}})
        );
        let current = serde_json::to_string(&record).unwrap();
        assert!(serde_json::from_str::<CgroupRecord>(&current).is_ok());
        let unknown = current.replace("\"name\"", "\"future\":1,\"name\"");
        assert!(serde_json::from_str::<CgroupRecord>(&unknown).is_err());
        let incomplete = r#"{"parent":"/sys/fs/cgroup/zsnap-protect","name":"zsnap-reader-a"}"#;
        assert!(serde_json::from_str::<CgroupRecord>(incomplete).is_err());
    }

    #[test]
    fn serialized_identity_changes_are_observable() {
        let original = CgroupIdentity {
            device: 7,
            inode: 9,
        };
        let decoded: CgroupIdentity =
            serde_json::from_str(&serde_json::to_string(&original).unwrap()).unwrap();
        assert_eq!(decoded, original);
        assert_ne!(
            original,
            CgroupIdentity {
                device: 8,
                inode: 9
            }
        );
        assert_ne!(
            original,
            CgroupIdentity {
                device: 7,
                inode: 10
            }
        );
        assert!(
            serde_json::from_str::<CgroupIdentity>(r#"{"device":7,"inode":9,"extra":1}"#).is_err()
        );
    }
}
