//! Complete protected reader jobs. CLI task state is separate from native
//! receipt data: only an authenticated job proves its reader custody kind.
use super::reader_cgroup::{CgroupParent, CgroupRecord, ReaderCgroup};
use super::reader_process::{self, BlockedReader, ReaderLaunch};
use super::reader_store::{JobLock, ReaderStore};
use super::reader_view::{self, SnapshotView, ViewSource};
use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use rustix::fs::{Mode, OFlags, ResolveFlags, mkdirat, open, openat2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use zfs_tools::{
    DatasetIdentity, DatasetKind, DatasetTarget, ReaderReceipt, ReleasePolicy, SnapshotRef,
    WriterSession,
};

const MAX_INPUT: u64 = 4 * 1024 * 1024;
const MAX_SOURCES: usize = 256;

#[derive(Debug, Args)]
pub(crate) struct ProtectOptions {
    /// Exact existing snapshots; --capture instead selects exact datasets.
    #[arg(value_name="SOURCE", num_args=0.., required_unless_present="request_json")]
    pub sources: Vec<String>,
    /// Capture an exact nonrecursive filesystem set before protecting readers.
    #[arg(long, conflicts_with = "request_json")]
    pub capture: bool,
    /// Bounded version-1 request file; cannot be combined with argv sources.
    #[arg(long, conflicts_with_all=["sources", "capture", "end_protection"])]
    pub request_json: Option<PathBuf>,
    /// Reader account; defaults to the authorized root caller.
    #[arg(long)]
    pub user: Option<String>,
    /// Namespace-local stable view root beneath /run.
    #[arg(long, default_value = "/run/zsnap/view")]
    pub view: PathBuf,
    /// Native receipt consumer; a label, not permission to read snapshots.
    #[arg(long, default_value = "backup")]
    pub consumer: String,
    /// Acknowledge that cleanup may complete deferred snapshot deletion.
    #[arg(long)]
    pub end_protection: bool,
    /// Separate atomic machine result; reader stdout remains untouched.
    #[arg(long)]
    pub result: Option<PathBuf>,
    /// Persistent, root-owned control state; must survive source rollback.
    #[arg(long, default_value = "/var/lib/zsnap/protect")]
    pub state_dir: PathBuf,
    /// Forward this named non-loader environment variable to the reader.
    #[arg(long = "env")]
    pub environment: Vec<String>,
    #[arg(long, default_value_t = 30)]
    pub stop_timeout: u64,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(last=true, num_args=1.., required_unless_present="dry_run")]
    pub command: Vec<OsString>,
}
#[derive(Debug, Args)]
pub(crate) struct RecoverOptions {
    /// Omit to list outstanding authenticated jobs.
    pub job: Option<String>,
    #[arg(long, default_value = "/var/lib/zsnap/protect")]
    pub state_dir: PathBuf,
    /// Stop only the authenticated orphan reader subtree before cleanup.
    #[arg(long, requires = "job")]
    pub stop: bool,
    #[arg(long, requires = "job", conflicts_with = "dry_run")]
    pub confirm: Option<String>,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long, default_value_t = 30)]
    pub stop_timeout: u64,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    #[default]
    PreserveSnapshots,
    EndProtection,
}
impl From<Disposition> for ReleasePolicy {
    fn from(value: Disposition) -> Self {
        match value {
            Disposition::PreserveSnapshots => Self::PreserveSnapshots,
            Disposition::EndProtection => Self::EndProtection,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum SourceInput {
    Snapshot {
        snapshot: SnapshotRef,
        #[serde(default)]
        alias: Option<PathBuf>,
    },
    Capture {
        dataset: String,
        identity: DatasetIdentity,
        #[serde(default)]
        alias: Option<PathBuf>,
    },
}
impl SourceInput {
    fn dataset(&self) -> &str {
        match self {
            Self::Snapshot { snapshot, .. } => {
                snapshot.name.split_once('@').map(|p| p.0).unwrap_or("")
            }
            Self::Capture { dataset, .. } => dataset,
        }
    }
    fn alias(&self) -> PathBuf {
        match self {
            Self::Snapshot { alias, .. } | Self::Capture { alias, .. } => {
                alias.clone().unwrap_or_else(|| self.dataset().into())
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderRequest {
    schema_version: u32,
    sources: Vec<SourceInput>,
    #[serde(default)]
    release: Disposition,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    pid: u32,
    start_time: u64,
    pid_namespace: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Armed,
    Capturing,
    Acquiring,
    Mounting,
    Reading,
    ReaderEnded,
    Releasing,
    Retained,
    Released,
    Complete,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobRecord {
    schema_version: u32,
    id: String,
    host: String,
    boot: String,
    owner: Owner,
    custody_kind: String,
    cgroup: CgroupRecord,
    setup_cgroup: CgroupRecord,
    view_root: PathBuf,
    sources: Vec<SourceInput>,
    release: Disposition,
    phase: Phase,
    intent: Option<ReaderReceipt>,
    acquired: Option<ReaderReceipt>,
    child_exit: Option<i32>,
    child_signal: Option<i32>,
    failure: Option<String>,
    result: Option<serde_json::Value>,
}
fn io_error(error: impl ToString) -> io::Error {
    io::Error::other(error.to_string())
}
fn root() -> Result<()> {
    if !rustix::process::geteuid().is_root() {
        bail!(
            "protected readers and recovery require an authorized root task; do not grant wildcard sudo access to arbitrary readers"
        );
    }
    Ok(())
}
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    // O_NONBLOCK prevents blocking indefinitely if `path` is a FIFO before
    // `is_file()` rejects it; regular files ignore O_NONBLOCK for reads.
    let mut input = fs::File::from(open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !input.metadata()?.is_file() {
        bail!("request must be a regular file");
    }
    let mut bytes = Vec::new();
    (&mut input).take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT {
        bail!("reader request exceeds 4 MiB");
    }
    Ok(bytes)
}
fn machine_identity() -> Result<String> {
    let s = fs::read_to_string("/etc/machine-id")?.trim().to_string();
    if s.len() != 32
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        bail!("trusted machine identity is unavailable");
    }
    Ok(s)
}
fn boot_identity() -> Result<String> {
    let s = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_string();
    uuid::Uuid::parse_str(&s)?;
    Ok(s)
}
fn process_start(pid: u32) -> Result<Option<u64>> {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let tail = text
        .rsplit_once(')')
        .ok_or_else(|| anyhow!("malformed process identity"))?
        .1;
    let start = tail
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow!("incomplete process identity"))?
        .parse()?;
    Ok(Some(start))
}
fn current_owner() -> Result<Owner> {
    let pid = std::process::id();
    Ok(Owner {
        pid,
        start_time: process_start(pid)?.context("current owner disappeared")?,
        pid_namespace: fs::read_link("/proc/self/ns/pid")?
            .to_string_lossy()
            .into_owned(),
    })
}
fn owner_alive(owner: &Owner) -> Result<bool> {
    if fs::read_link("/proc/self/ns/pid")?.to_string_lossy() != owner.pid_namespace {
        bail!("owner PID namespace is not observable from this recovery context");
    }
    Ok(process_start(owner.pid)? == Some(owner.start_time))
}
fn ensure_running(job: &JobLock) -> Result<(), zfs_tools::Error> {
    let _: serde_json::Value = job
        .read()
        .map_err(|e| zfs_tools::Error::new(e.to_string()))?;
    if reader_process::interruption() != 0 {
        return Err(zfs_tools::Error::new("protected reader was interrupted"));
    }
    Ok(())
}
fn ensure_setup(setup: &ReaderCgroup, job: &JobLock) -> Result<(), zfs_tools::Error> {
    ensure_running(job)?;
    if !setup
        .contains_only_current_process()
        .map_err(|e| zfs_tools::Error::new(e.to_string()))?
    {
        return Err(zfs_tools::Error::new(
            "unexpected setup process or descendant remains",
        ));
    }
    Ok(())
}
fn ensure_empty(
    group: &ReaderCgroup,
    setup: &ReaderCgroup,
    job: &JobLock,
) -> Result<(), zfs_tools::Error> {
    let _: serde_json::Value = job
        .read()
        .map_err(|e| zfs_tools::Error::new(e.to_string()))?;
    if !group
        .wait_empty(Duration::ZERO)
        .map_err(|e| zfs_tools::Error::new(e.to_string()))?
        || !setup
            .contains_only_current_process()
            .map_err(|e| zfs_tools::Error::new(e.to_string()))?
    {
        return Err(zfs_tools::Error::new(
            "reader or setup subtree still has another namespace holder",
        ));
    }
    Ok(())
}

fn ensure_view_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() || !path.starts_with("/run") {
        bail!("view parent must be beneath /run");
    }
    if !path.components().all(|c| {
        matches!(
            c,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )
    }) {
        bail!("view path is not canonical");
    }
    let mut dir = fs::File::open("/")?;
    let meta = dir.metadata()?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        bail!("view parent is not root-owned and protected");
    }
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        let created = match mkdirat(&dir, part, Mode::from_raw_mode(0o755)) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(e) => return Err(io::Error::from(e).into()),
        };
        let next = fs::File::from(openat2(
            &dir,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let metadata = next.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("view parent is not root-owned and protected");
        }
        if created {
            next.set_permissions(fs::Permissions::from_mode(0o755))?;
        }
        dir = next;
    }
    Ok(())
}

fn prepare_request(options: &ProtectOptions) -> Result<ReaderRequest> {
    let from_json = options.request_json.is_some();
    let request = if let Some(path) = &options.request_json {
        if path == Path::new("-") {
            bail!("request must be a file; reader stdin is preserved");
        }
        serde_json::from_slice::<ReaderRequest>(&read_bounded(path)?)?
    } else {
        let mut sources = Vec::new();
        for source in &options.sources {
            if options.capture {
                let observed = zfs_tools::observe_dataset(source)?;
                if *observed.kind() != DatasetKind::Filesystem {
                    bail!("file readers require exact filesystem targets");
                }
                sources.push(SourceInput::Capture {
                    dataset: source.clone(),
                    identity: observed.identity().clone(),
                    alias: None,
                });
            } else {
                let snapshot = zfs_tools::observe_snapshot(source)?;
                let parent = snapshot.name.split_once('@').map_or("", |(ds, _)| ds);
                let observed = zfs_tools::observe_dataset(parent)?;
                if *observed.kind() != DatasetKind::Filesystem {
                    bail!("file readers require filesystem targets");
                }
                if snapshot.dataset_guid != observed.identity().guid
                    || snapshot.identity.pool_guid != observed.identity().pool_guid
                {
                    bail!("reviewed reader snapshot incarnation changed");
                }
                sources.push(SourceInput::Snapshot {
                    snapshot,
                    alias: None,
                });
            }
        }
        ReaderRequest {
            schema_version: 1,
            sources,
            release: if options.end_protection {
                Disposition::EndProtection
            } else {
                Disposition::PreserveSnapshots
            },
        }
    };
    if request.schema_version != 1
        || request.sources.is_empty()
        || request.sources.len() > MAX_SOURCES
    {
        bail!("invalid reader request version or source count");
    }
    let aliases: Vec<_> = request.sources.iter().map(SourceInput::alias).collect();
    reader_view::validate_layout(&options.view, &aliases)?;
    if from_json {
        for source in &request.sources {
            let observed = zfs_tools::observe_dataset(source.dataset())?;
            if *observed.kind() != DatasetKind::Filesystem {
                bail!("file readers require filesystem targets");
            }
            match source {
                SourceInput::Snapshot { snapshot, .. } => {
                    let exact = zfs_tools::observe_snapshot(&snapshot.name)?;
                    if &exact != snapshot
                        || exact.dataset_guid != observed.identity().guid
                        || exact.identity.pool_guid != observed.identity().pool_guid
                    {
                        bail!("reviewed reader snapshot incarnation changed");
                    }
                }
                SourceInput::Capture { identity, .. } => {
                    if observed.identity() != identity {
                        bail!("reviewed capture dataset incarnation changed");
                    }
                }
            }
        }
    }
    Ok(request)
}
fn capture_points(
    session: &mut WriterSession,
    job: &JobLock,
    record: &mut JobRecord,
) -> Result<Vec<SnapshotRef>> {
    let mut targets = Vec::new();
    for input in &record.sources {
        if let SourceInput::Capture {
            dataset, identity, ..
        } = input
        {
            targets.push(
                DatasetTarget::new(dataset, identity.clone())?
                    .requiring_kind(DatasetKind::Filesystem),
            );
        }
    }
    let mut captured = Vec::new();
    if !targets.is_empty() {
        record.phase = Phase::Capturing;
        job.save(record)?;
        let mut scope = session.admit_guarded(&targets, || ensure_running(job))?;
        let now: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
        let name = super::snap_suffix(now);
        let outcome = scope.capture(&name)?;
        if outcome.status() != zfs_tools::CaptureStatus::Complete {
            record.result = Some(serde_json::to_value(&outcome)?);
            bail!("checkpoint capture is partial or uncertain; reader not started");
        }
        captured.extend_from_slice(outcome.points());
    }
    let mut points = Vec::new();
    for input in &record.sources {
        points.push(match input {
            SourceInput::Snapshot { snapshot, .. } => snapshot.clone(),
            SourceInput::Capture { dataset, .. } => captured
                .iter()
                .find(|p| {
                    p.name
                        .split_once('@')
                        .is_some_and(|(name, _)| name == dataset)
                })
                .context("capture omitted an exact target")?
                .clone(),
        });
    }
    Ok(points)
}
fn write_result(path: Option<&Path>, value: &serde_json::Value) -> Result<()> {
    if let Some(path) = path {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            Some(_) => Path::new("."),
            None => bail!("result needs a parent directory"),
        };
        let tmp = parent.join(format!(".zsnap-result-{}", uuid::Uuid::new_v4()));
        let bytes = serde_json::to_vec(value)?;
        let outcome = (|| -> Result<()> {
            let mut file = fs::File::from(open(
                &tmp,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?);
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&tmp, path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        outcome?;
    }
    Ok(())
}

pub(crate) fn protect(options: ProtectOptions) -> u8 {
    let result = protect_inner(&options);
    let (code, value) = match result {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "zsnap protect: {}",
                zfs_tools::engine::escape_display(&e.to_string())
            );
            (
                1,
                serde_json::json!({"schema_version":1,"status":"refused","error":e.to_string()}),
            )
        }
    };
    if let Err(error) = write_result(options.result.as_deref(), &value) {
        eprintln!("zsnap protect: result publication failed: {error}");
        return 4;
    }
    code
}
fn protect_inner(options: &ProtectOptions) -> Result<(u8, serde_json::Value)> {
    root()?;
    if options.stop_timeout == 0 || options.stop_timeout > 3600 {
        bail!("stop timeout must be 1..3600 seconds");
    }
    if options.consumer.is_empty()
        || options.consumer.len() > 20
        || !options
            .consumer
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        bail!("invalid reader consumer label");
    }
    let request = prepare_request(options)?;
    if options.dry_run {
        let value = serde_json::json!({"schema_version":1,"status":"preview","sources":request.sources,"release":request.release,"view":options.view});
        println!("{value}");
        return Ok((0, value));
    }
    let mut launch = ReaderLaunch::prepare(
        &options.command,
        options.user.as_deref(),
        &options.environment,
        &options.view,
    )?;
    let host = machine_identity()?;
    let boot = boot_identity()?;
    let owner = current_owner()?;
    let store = ReaderStore::open(&options.state_dir, true)?;
    let id = uuid::Uuid::new_v4().to_string();
    launch.set_job(&id);
    let job = store.create_job(&id)?;
    let custody = CgroupParent::admit(true)?;
    let group = custody.create(&id)?;
    let setup = custody.create(&uuid::Uuid::new_v4().to_string())?;
    let mut record = JobRecord {
        schema_version: 1,
        id: id.clone(),
        host,
        boot,
        owner,
        custody_kind: "cgroup-v2".into(),
        cgroup: group.identity().clone(),
        setup_cgroup: setup.identity().clone(),
        view_root: options.view.clone(),
        sources: request.sources,
        release: request.release,
        phase: Phase::Prepared,
        intent: None,
        acquired: None,
        child_exit: None,
        child_signal: None,
        failure: None,
        result: None,
    };
    job.save(&record)?;
    reader_process::install_signals()?;
    let mut original_membership = None;
    let run = (|| -> Result<()> {
        // All subsequent native children and blocked helpers inherit Setup
        // atomically at fork, before inheriting a protected mount namespace.
        original_membership = Some(setup.enter_supervisor()?);
        record.phase = Phase::Armed;
        job.save(&record)?;
        ensure_setup(&setup, &job)?;
        let mut session = WriterSession::acquire("zsnap protected reader acquisition")?;
        let points = capture_points(&mut session, &job, &mut record)?;
        let protection = match session.protect_reader_guarded(
            &points,
            &options.consumer,
            |intent| {
                record.intent = Some(intent.clone());
                record.phase = Phase::Acquiring;
                job.save(&record)
                    .map_err(|e| zfs_tools::Error::new(e.to_string()))
            },
            || ensure_setup(&setup, &job),
        ) {
            Ok(p) => p,
            Err(e) => {
                record.result = Some(serde_json::to_value(&e)?);
                return Err(e.into());
            }
        };
        record.acquired = Some(protection.receipt().clone());
        record.phase = Phase::Mounting;
        job.save(&record)?;
        ensure_view_parent(options.view.parent().context("view root has no parent")?)?;
        reader_view::enter_private_namespace()?;
        let sources: Vec<_> = record
            .sources
            .iter()
            .zip(&points)
            .map(|(input, expected)| {
                let point = protection
                    .receipt()
                    .points()
                    .iter()
                    .find(|p| {
                        p.dataset_guid == expected.dataset_guid && p.identity == expected.identity
                    })
                    .expect("complete protection covers each exact input");
                ViewSource {
                    snapshot: point.clone(),
                    alias: input.alias(),
                    relative_path: None,
                }
            })
            .collect();
        let mounted = session.with_native_writer_mut(|session| {
            SnapshotView::mount(&options.view, &sources, || {
                session
                    .revalidate_reader(protection.receipt(), || ensure_setup(&setup, &job))
                    .map(|_| ())
                    .map_err(io_error)
            })
        })?;
        let mut view = match mounted {
            Ok(view) => view,
            Err(mut failure) => {
                let _ = failure.take_view();
                return Err(failure.error.into());
            }
        };
        session.revalidate_reader(protection.receipt(), || ensure_setup(&setup, &job))?;
        let manifest = serde_json::json!({"schema_version":1,"job":id,"consumer":options.consumer,"view_root":view.root(),"sources":view.sources().iter().map(|source|serde_json::json!({"snapshot":source.snapshot,"alias":source.alias})).collect::<Vec<_>>()});
        let manifest_file = job.save_reader_manifest(&manifest)?;
        use std::os::fd::AsRawFd;
        launch.set_manifest(manifest_file.as_raw_fd());
        drop(session);
        let mut blocked = BlockedReader::spawn(&manifest_file)?;
        if let Err(error) = group.move_blocked_child(&mut blocked.child) {
            let _ = blocked.abort();
            return Err(error.into());
        }
        record.phase = Phase::Reading;
        job.save(&record)?;
        ensure_running(&job)?;
        let child = blocked.start(&launch)?;
        drop(manifest_file);
        let (status, terminated) =
            reader_process::wait_reader(child, &group, Duration::from_secs(options.stop_timeout))?;
        use std::os::unix::process::ExitStatusExt;
        record.child_exit = status.code();
        record.child_signal = status.signal();
        record.phase = Phase::ReaderEnded;
        job.save(&record)?;
        let mut session = WriterSession::acquire("zsnap protected reader cleanup")?;
        ensure_empty(&group, &setup, &job)?;
        session.with_native_writer_mut(|_| {
            view.cleanup(|| ensure_empty(&group, &setup, &job).map_err(io_error))
        })??;
        if view.has_mounts() {
            bail!("view teardown remains incomplete");
        }
        record.phase = Phase::Releasing;
        job.save(&record)?;
        match session.end_reader(protection, record.release.into(), || {
            ensure_empty(&group, &setup, &job)
        }) {
            Ok(outcome) => record.result = Some(serde_json::to_value(outcome)?),
            Err(error) => {
                record.result = Some(serde_json::to_value(&error)?);
                return Err(error.into());
            }
        }
        record.phase = Phase::Released;
        record.failure = if !status.success() || terminated {
            Some("reader failed or required termination; cleanup verified".into())
        } else {
            None
        };
        job.save(&record)?;
        Ok(())
    })();
    let append_failure = |slot: &mut Option<String>, message: String| {
        *slot = Some(match slot.take() {
            Some(prior) => format!("{prior}; {message}"),
            None => message,
        });
    };
    let mut code = if let Err(error) = run {
        record.phase = Phase::Retained;
        append_failure(&mut record.failure, error.to_string());
        let _ = job.save(&record);
        4
    } else if record.failure.is_some() {
        1
    } else {
        0
    };
    if let Some(original) = original_membership
        && let Err(error) = original.restore()
    {
        code = 4;
        record.phase = Phase::Retained;
        append_failure(
            &mut record.failure,
            format!("setup custody retained: {error}"),
        );
        let _ = job.save(&record);
    }
    if code != 4 {
        let retired = group.retire_empty().and_then(|()| setup.retire_empty());
        if let Err(error) = retired {
            code = 4;
            record.phase = Phase::Retained;
            append_failure(
                &mut record.failure,
                format!("empty custody retained: {error}"),
            );
            let _ = job.save(&record);
        } else {
            record.phase = Phase::Complete;
            job.save(&record)?;
        }
    }
    if code == 4 {
        eprintln!(
            "zsnap protect: protection or evidence retained; inspect `zsnap recover {id}`: {}",
            zfs_tools::engine::escape_display(
                record.failure.as_deref().unwrap_or("incomplete task")
            )
        );
    }
    let value = serde_json::json!({"schema_version":1,"job":id,"status":if code==4{"retained"}else if code==0{"complete"}else{"reader_failed"},"child_exit":record.child_exit,"child_signal":record.child_signal,"cleanup_complete":code!=4,"error":record.failure,"protection":record.result});
    Ok((code, value))
}

fn snapshot_review(receipt: Option<&ReaderReceipt>) -> Result<serde_json::Value> {
    let mut facts = Vec::new();
    if let Some(receipt) = receipt {
        for point in receipt.points() {
            match zfs_tools::engine::native::resolve_with(point,&mut zfs_tools::engine::native::run) {
            Ok(snapshot)=>facts.push(serde_json::json!({"point":snapshot.point(),"status":"observed","held":snapshot.holds.iter().any(|tag|tag==receipt.tag()),"deferred":&snapshot.defer_destroy,"clones":&snapshot.clones})),
            Err(zfs_tools::engine::Error::NotFound(_))=>facts.push(serde_json::json!({"point":point,"status":"not_found"})),
            Err(zfs_tools::engine::Error::Inconsistent(message))=>facts.push(serde_json::json!({"point":point,"status":"changed","error":message})),
            Err(error)=>return Err(error.into()),
        }
        }
    }
    Ok(serde_json::Value::Array(facts))
}

/// A record this build cannot read is unknown custody: never complete, and
/// `recover JOB` refuses it, so its protection is retained.
fn job_record(raw: serde_json::Value) -> Result<JobRecord> {
    serde_json::from_value(raw).map_err(|error| {
        anyhow!("job record is not a reader task record ({error}); protection retained")
    })
}
fn listed_job(id: &str, raw: serde_json::Value) -> Option<serde_json::Value> {
    match job_record(raw) {
        Ok(record) if matches!(record.phase, Phase::Complete) => None,
        Ok(record) => {
            Some(serde_json::json!({"job":id,"phase":record.phase,"failure":record.failure}))
        }
        Err(error) => {
            Some(serde_json::json!({"job":id,"status":"unknown_custody","error":error.to_string()}))
        }
    }
}
fn recovery_token(review: &serde_json::Value) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(review)?)))
}
pub(crate) fn recover(options: RecoverOptions) -> u8 {
    match recover_inner(&options) {
        Ok((code, value)) => {
            if options.json {
                println!("{value}");
            } else {
                print!("{}", render_recovery(options.job.as_deref(), &value));
            }
            code
        }
        Err(error) => {
            eprintln!(
                "zsnap recover: {}",
                zfs_tools::engine::escape_display(&error.to_string())
            );
            1
        }
    }
}
/// Plain-text view of a recovery result; `--json` prints the value itself.
/// Every string is display-escaped, and a shape this view does not know
/// falls back to the JSON so nothing is hidden.
fn render_recovery(job: Option<&str>, value: &serde_json::Value) -> String {
    use std::fmt::Write;
    let text = |value: &serde_json::Value| match value {
        serde_json::Value::String(s) => zfs_tools::engine::escape_display(s),
        serde_json::Value::Null => "-".into(),
        other => zfs_tools::engine::escape_display(&other.to_string()),
    };
    let field = |name: &str| text(&value[name]);
    let job = value["job"]
        .as_str()
        .or(job)
        .map_or_else(|| "JOB".into(), zfs_tools::engine::escape_display);
    let mut out = String::new();
    if let Some(jobs) = value["jobs"].as_array() {
        if jobs.is_empty() {
            out.push_str("no outstanding reader jobs\n");
        }
        for entry in jobs {
            let id = text(&entry["job"]);
            if entry["phase"].is_null() {
                let _ = writeln!(
                    out,
                    "{id}  status={}  error={}",
                    text(&entry["status"]),
                    text(&entry["error"])
                );
            } else {
                let _ = writeln!(
                    out,
                    "{id}  phase={}  failure={}",
                    text(&entry["phase"]),
                    text(&entry["failure"])
                );
            }
        }
        return out;
    }
    let token = field("token");
    let _ = match value["status"].as_str().unwrap_or_default() {
        "complete" => writeln!(out, "{job}: complete; protection ended"),
        "readers_active" => writeln!(
            out,
            "{job}: readers_active; its orphan readers must be stopped first\n\
             next: zsnap recover {job} --stop --confirm {token}\ntoken: {token}"
        ),
        "stop_confirmation_required" => writeln!(
            out,
            "{job}: stop_confirmation_required; nothing changed\n\
             next: zsnap recover {job} --stop --confirm {token}\ntoken: {token}"
        ),
        "stopped_review_required" => writeln!(
            out,
            "{job}: stopped_review_required; readers stopped, protection retained\n\
             next: zsnap recover {job} --dry-run"
        ),
        "preview" => {
            let review = &value["review"];
            let _ = writeln!(
                out,
                "{job}: preview; ending protection, release={}",
                text(&review["release"])
            );
            for snapshot in review["snapshots"].as_array().into_iter().flatten() {
                let _ = writeln!(
                    out,
                    "  {}  {}",
                    text(&snapshot["point"]["name"]),
                    text(&snapshot["status"])
                );
            }
            writeln!(
                out,
                "next: zsnap recover {job} --confirm {token}\ntoken: {token}"
            )
        }
        "review_changed" => writeln!(
            out,
            "{job}: review_changed; nothing changed\nnext: zsnap recover {job} --dry-run"
        ),
        "retained" => writeln!(
            out,
            "{job}: retained; protection kept: {}",
            if value["reason"].is_null() {
                "recovery did not complete".into()
            } else {
                field("reason")
            }
        ),
        _ => writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".into())
        ),
    };
    out
}
fn recover_inner(options: &RecoverOptions) -> Result<(u8, serde_json::Value)> {
    root()?;
    if options.stop_timeout == 0 || options.stop_timeout > 3600 {
        bail!("stop timeout must be 1..3600 seconds");
    }
    let store = ReaderStore::open(&options.state_dir, false)?;
    let Some(id) = &options.job else {
        let mut jobs = Vec::new();
        for id in store.list_ids()? {
            let result = store
                .open_job(&id)
                .and_then(|job| job.read::<serde_json::Value>());
            match result {
                Ok(raw) => jobs.extend(listed_job(&id, raw)),
                Err(error)=>jobs.push(serde_json::json!({"job":id,"status":"busy_or_unobservable","error":error.to_string()})),
            }
        }
        return Ok((0, serde_json::json!({"schema_version":1,"jobs":jobs})));
    };
    let job = store.open_job(id)?;
    let raw: serde_json::Value = job.read()?;
    let mut record = job_record(raw)?;
    if record.schema_version != 1
        || record.id != *id
        || record.host != machine_identity()?
        || record.custody_kind != "cgroup-v2"
    {
        bail!("job lacks authenticated local reader custody; protection retained");
    }
    if matches!(record.phase, Phase::Complete) {
        return Ok((
            0,
            serde_json::json!({"schema_version":1,"status":"complete","job":id,"protection":record.result}),
        ));
    }
    let same_boot = record.boot == boot_identity()?;
    if same_boot && owner_alive(&record.owner)? {
        bail!("protected owner is live; interrupt its original command through its native owner");
    }
    let groups = if same_boot {
        let custody = CgroupParent::admit(false)?;
        Some((
            custody.open_recovery(&record.cgroup)?,
            custody.open_recovery(&record.setup_cgroup)?,
        ))
    } else {
        None
    };
    let populated = match &groups {
        Some((reader, setup)) => {
            !reader.wait_empty(Duration::ZERO)? || !setup.wait_empty(Duration::ZERO)?
        }
        None => false,
    };
    if populated {
        let review = serde_json::json!({"action":"stop_owned_orphan","job":id,"owner":record.owner,"boot":record.boot,"readers":record.cgroup,"setup":record.setup_cgroup,"receipt":record.acquired.as_ref().or(record.intent.as_ref())});
        let token = recovery_token(&review)?;
        if options.confirm.is_none() || options.dry_run {
            return Ok((
                if options.dry_run { 0 } else { 3 },
                serde_json::json!({"schema_version":1,"status":"readers_active","review":review,"token":token,"requires_stop":true}),
            ));
        }
        if options.confirm.as_deref() != Some(&token) || !options.stop {
            return Ok((
                3,
                serde_json::json!({"schema_version":1,"status":"stop_confirmation_required","token":token}),
            ));
        }
        let (reader, setup) = groups.as_ref().expect("current-boot populated groups");
        setup.kill_owned()?;
        reader.kill_owned()?;
        if !setup.wait_empty(Duration::from_secs(options.stop_timeout))?
            || !reader.wait_empty(Duration::from_secs(options.stop_timeout))?
        {
            return Ok((
                4,
                serde_json::json!({"schema_version":1,"status":"retained","job":id,"reason":"owned subtree did not become empty"}),
            ));
        }
        record.phase = Phase::ReaderEnded;
        job.save(&record)?;
        return Ok((
            3,
            serde_json::json!({"schema_version":1,"status":"stopped_review_required","job":id,"next":"preview recovery again before ending protection"}),
        ));
    }
    let mut session = WriterSession::acquire("zsnap reader recovery review")?;
    let receipt = record.acquired.as_ref().or(record.intent.as_ref());
    let review = serde_json::json!({"action":"end_protection","job":id,"host":record.host,"boot":record.boot,"readers":record.cgroup,"setup":record.setup_cgroup,"same_boot":same_boot,"release":record.release,"receipt":receipt,"snapshots":snapshot_review(receipt)?});
    let token = recovery_token(&review)?;
    if options.confirm.is_none() || options.dry_run {
        return Ok((
            if options.dry_run { 0 } else { 3 },
            serde_json::json!({"schema_version":1,"status":"preview","review":review,"token":token}),
        ));
    }
    if options.confirm.as_deref() != Some(&token) {
        return Ok((
            3,
            serde_json::json!({"schema_version":1,"status":"review_changed","token":token}),
        ));
    }
    let guard = || -> Result<(), zfs_tools::Error> {
        let _: serde_json::Value = job
            .read()
            .map_err(|e| zfs_tools::Error::new(e.to_string()))?;
        if let Some((reader, setup)) = &groups
            && (!reader
                .wait_empty(Duration::ZERO)
                .map_err(|e| zfs_tools::Error::new(e.to_string()))?
                || !setup
                    .wait_empty(Duration::ZERO)
                    .map_err(|e| zfs_tools::Error::new(e.to_string()))?)
        {
            return Err(zfs_tools::Error::new(
                "reader or setup subtree became populated",
            ));
        }
        Ok(())
    };
    if let Some(receipt) = receipt {
        match session.recover_reader(receipt, record.release.into(), guard) {
            Ok(outcome) => record.result = Some(serde_json::to_value(outcome)?),
            Err(error) => {
                record.phase = Phase::Retained;
                record.failure = Some(error.to_string());
                record.result = Some(serde_json::to_value(error)?);
                job.save(&record)?;
                return Ok((
                    4,
                    serde_json::json!({"schema_version":1,"status":"retained","job":id,"protection":record.result}),
                ));
            }
        }
    }
    record.phase = Phase::Released;
    record.failure = None;
    job.save(&record)?;
    if let Some((reader, setup)) = groups {
        reader.retire_empty()?;
        setup.retire_empty()?;
    }
    record.phase = Phase::Complete;
    job.save(&record)?;
    Ok((
        0,
        serde_json::json!({"schema_version":1,"status":"complete","job":id,"protection":record.result}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn machine_request_rejects_unknown_fields_and_executable_data() {
        for json in [
            r#"{"schema_version":1,"sources":[],"command":"rm"}"#,
            r#"{"schema_version":1,"sources":[],"release":"force"}"#,
        ] {
            assert!(serde_json::from_str::<ReaderRequest>(json).is_err());
        }
    }
    #[test]
    fn confirmation_binds_every_review_fact() {
        let a = serde_json::json!({"receipt":"a","populated":false});
        let b = serde_json::json!({"receipt":"a","populated":true});
        assert_ne!(recovery_token(&a).unwrap(), recovery_token(&b).unwrap());
    }
    #[test]
    fn retained_job_records_stay_protected_until_complete() {
        let cgroup = |name: &str, inode: u64| {
            serde_json::json!({"parent":"/sys/fs/cgroup/zsnap-protect","name":name,
                "identity":{"device":7,"inode":inode}})
        };
        let id = "6f0c3f2e-8d1b-4c3a-9e2f-0a1b2c3d4e5f";
        let mut raw = serde_json::json!({"schema_version":1,"id":id,
            "host":"ee401eaa5dc94fdf9a739a6bcfd87a81",
            "boot":"0b6c1c52-6f5e-4c8e-9a4b-3d2e1f0a9b8c",
            "owner":{"pid":700,"start_time":9,"pid_namespace":"pid:[4026531836]"},
            "custody_kind":"cgroup-v2","cgroup":cgroup(&format!("zsnap-reader-{id}"), 9),
            "setup_cgroup":cgroup("zsnap-reader-1f0c3f2e-8d1b-4c3a-9e2f-0a1b2c3d4e5f", 10),
            "view_root":"/run/zsnap/view","sources":[],"release":"preserve_snapshots",
            "phase":"retained","intent":null,"acquired":null,"child_exit":null,
            "child_signal":null,"failure":"owner died","result":null});
        // A retained job stays listed by phase; its recovery uses the
        // recorded name and inode.
        let record = job_record(raw.clone()).unwrap();
        assert_eq!(record.cgroup.identity.inode, 9);
        assert_eq!(record.setup_cgroup.identity.inode, 10);
        assert_eq!(
            listed_job(id, raw.clone()).unwrap(),
            serde_json::json!({"job":id,"phase":"retained","failure":"owner died"})
        );
        raw["phase"] = "complete".into();
        assert!(listed_job(id, raw.clone()).is_none());
        // A record this build cannot read is unknown custody, never complete,
        // and single-job recovery refuses it.
        raw["cgroup"]["future"] = 1.into();
        assert_eq!(
            listed_job(id, raw.clone()).unwrap()["status"],
            "unknown_custody"
        );
        assert!(
            job_record(raw)
                .unwrap_err()
                .to_string()
                .contains("protection retained")
        );
    }

    #[test]
    fn recovery_text_names_jobs_next_steps_and_tokens() {
        let render = |job: Option<&str>, value: serde_json::Value| render_recovery(job, &value);
        assert_eq!(
            render(None, serde_json::json!({"schema_version":1,"jobs":[]})),
            "no outstanding reader jobs\n"
        );
        assert_eq!(
            render(
                None,
                serde_json::json!({"schema_version":1,"jobs":[
                    {"job":"a","phase":"retained","failure":"owner died"},
                    {"job":"b","phase":"reading","failure":null},
                    {"job":"c","status":"unknown_custody","error":"old\u{1b}record"}]})
            ),
            format!(
                "a  phase=retained  failure=owner died\nb  phase=reading  failure=-\n\
                 c  status=unknown_custody  error={}\n",
                zfs_tools::engine::escape_display("old\u{1b}record")
            )
        );
        assert!(!zfs_tools::engine::escape_display("old\u{1b}record").contains('\u{1b}'));
        let preview = render(
            Some("j"),
            serde_json::json!({"schema_version":1,"status":"preview","token":"t0",
                "review":{"release":"preserve_snapshots","snapshots":[
                    {"point":{"name":"tank/a@s"},"status":"observed","held":true}]}}),
        );
        assert_eq!(
            preview,
            "j: preview; ending protection, release=preserve_snapshots\n  tank/a@s  observed\n\
             next: zsnap recover j --confirm t0\ntoken: t0\n"
        );
        let active = render(
            Some("j"),
            serde_json::json!({"schema_version":1,"status":"readers_active","review":{},
                "token":"t1","requires_stop":true}),
        );
        assert!(active.contains("next: zsnap recover j --stop --confirm t1\ntoken: t1\n"));
        for (value, expected) in [
            (
                serde_json::json!({"schema_version":1,"status":"complete","job":"j","protection":null}),
                "j: complete; protection ended\n",
            ),
            (
                serde_json::json!({"schema_version":1,"status":"retained","job":"j",
                    "reason":"owned subtree did not become empty"}),
                "j: retained; protection kept: owned subtree did not become empty\n",
            ),
            (
                serde_json::json!({"schema_version":1,"status":"stopped_review_required","job":"j",
                    "next":"preview recovery again before ending protection"}),
                "j: stopped_review_required; readers stopped, protection retained\n\
                 next: zsnap recover j --dry-run\n",
            ),
            (
                serde_json::json!({"schema_version":1,"status":"review_changed","token":"t2"}),
                "j: review_changed; nothing changed\nnext: zsnap recover j --dry-run\n",
            ),
        ] {
            assert_eq!(render(Some("j"), value), expected);
        }
        // An unknown shape is shown whole rather than hidden.
        assert!(render(Some("j"), serde_json::json!({"status":"future"})).contains("\"future\""));
    }
    #[test]
    fn start_time_parser_tracks_current_process() {
        assert!(process_start(std::process::id()).unwrap().unwrap() > 0);
    }
}
