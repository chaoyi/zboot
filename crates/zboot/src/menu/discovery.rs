//! Background read-only imports, serialized with every foreground writer.
//!
//! The batch owns the writer lock through identity adoption, child imports and
//! final readback. Import children inherit its open file description, so a
//! dying menu cannot release the barrier while an import still runs.
use super::{RecoveryError, Result, hostid_adopt, refuse};
use crate::handoff::{prove_ram, readonly_pools};
use crate::hostid::Label;
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::{FileTypeExt, MetadataExt},
    panic::{AssertUnwindSafe, catch_unwind},
    process::{Command, Stdio},
    sync::{Arc, LazyLock, Mutex, Weak},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zfs_tools::engine::{lock::WriterLock, state};

const CONCURRENT_IMPORTS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ImportState {
    Queued,
    Importing,
    Imported,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PoolJob {
    guid: u64,
    name: String,
    local: bool,
    state: ImportState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Progress {
    jobs: Vec<PoolJob>,
    pub(super) local_ready: bool,
    finished: bool,
    error: Option<String>,
    revision: u64,
}

impl Progress {
    pub(super) fn countdown_ready(&self) -> bool {
        self.local_ready
            && self.error.is_none()
            && self
                .jobs
                .iter()
                .filter(|job| job.local)
                .all(|job| job.state == ImportState::Imported)
    }

    pub(super) fn settled(&self) -> bool {
        self.finished
    }

    pub(super) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn render(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        if self.jobs.is_empty() && !self.finished {
            writeln!(out, "Looking for pools (importing)")?;
        }
        for job in &self.jobs {
            let detail = match &job.state {
                ImportState::Queued | ImportState::Importing => "importing",
                ImportState::Imported => continue,
                ImportState::Failed(reason) => reason,
            };
            writeln!(
                out,
                "Pool {} guid={}  {}",
                zfs_tools::engine::escape_display(&job.name),
                job.guid,
                zfs_tools::engine::escape_display(detail)
            )?;
        }
        if let Some(error) = &self.error {
            writeln!(
                out,
                "Pool discovery failed: {}",
                zfs_tools::engine::escape_display(error)
            )?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Manager {
    batch: Option<JoinHandle<Result<()>>>,
    progress: Arc<Mutex<Progress>>,
}

impl Manager {
    /// Only an explicit rescan replaces a completed fatal result. Foreground
    /// draining consumes the handle, never the failure that guards effects.
    fn schedule(
        &mut self,
        work: impl FnOnce(&Mutex<Progress>) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        if self
            .batch
            .as_ref()
            .is_some_and(|batch| !batch.is_finished())
        {
            return Ok(());
        }
        if let Some(batch) = self.batch.take() {
            let _ = batch.join();
        }
        let revision = self
            .progress
            .lock()
            .map_err(|_| refuse("import progress failed"))?
            .revision
            + 1;
        self.progress = Arc::new(Mutex::new(Progress {
            revision,
            ..Progress::default()
        }));
        let progress = Arc::clone(&self.progress);
        self.batch = Some(thread::spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| work(&progress)))
                .unwrap_or_else(|_| Err(refuse("pool import worker failed")));
            update(&progress, |progress| {
                progress.finished = true;
                progress.error = result.as_ref().err().map(ToString::to_string);
                if progress.error.is_some() {
                    progress.local_ready = false;
                }
            });
            result
        }));
        Ok(())
    }

    fn drain(&mut self) -> Result<()> {
        if let Some(batch) = self.batch.take() {
            let result = batch
                .join()
                .unwrap_or_else(|_| Err(refuse("pool import worker failed")));
            if let Err(error) = result {
                update(&self.progress, |progress| {
                    progress.error = Some(error.to_string());
                    progress.finished = true;
                    progress.local_ready = false;
                });
            }
        }
        let error = self
            .progress
            .lock()
            .map_err(|_| refuse("import progress failed"))?
            .error
            .clone();
        match error {
            Some(error) => Err(refuse(error)),
            None => Ok(()),
        }
    }
}

static MANAGER: LazyLock<Mutex<Manager>> = LazyLock::new(|| {
    Mutex::new(Manager {
        batch: None,
        progress: Arc::new(Mutex::new(Progress {
            jobs: Vec::new(),
            local_ready: true,
            finished: true,
            error: None,
            revision: 0,
        })),
    })
});

// A weak reference shares the batch's existing open file description only
// during a listing. It preserves the normal close-based flock lifetime.
static INVENTORY_WRITER: Mutex<Weak<WriterLock>> = Mutex::new(Weak::new());

fn publish_inventory_writer<G>(
    published: &Mutex<Weak<G>>,
    writer: &Arc<G>,
    progress: &Mutex<Progress>,
) -> Result<()> {
    *published
        .lock()
        .map_err(|_| refuse("menu inventory coordination failed"))? = Arc::downgrade(writer);
    // A first listing can race acquisition before publication and see Busy.
    // Publication gives that caller a fresh revision to render promptly.
    update(progress, |_| {});
    Ok(())
}

fn inventory_with<T, G>(
    published: &Mutex<Weak<G>>,
    acquire: impl FnOnce() -> Result<G>,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let shared = published
        .lock()
        .map_err(|_| refuse("menu inventory coordination failed"))?
        .upgrade();
    // The publication mutex is released before acquisition or the callback.
    // Rendering and progress snapshots can therefore take their own locks.
    let _writer = match shared {
        Some(writer) => writer,
        None => Arc::new(acquire()?),
    };
    action()
}

/// Read one inventory while excluding ordinary cooperating writers. During
/// local discovery this shares its already-held writer guard, keeping progress
/// listings responsive while imports run. Other writers cause a prompt refusal.
/// The callback performs reads and rendering, and never enters a writer/barrier
/// path. Existing boot and handoff callers retain their own writer boundaries.
pub(super) fn inventory<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    inventory_with(
        &INVENTORY_WRITER,
        || {
            WriterLock::acquire("zboot menu inventory", Duration::ZERO, |_| {})
                .map_err(|error| refuse(error.to_string()))
        },
        action,
    )
}

fn update(progress: &Mutex<Progress>, change: impl FnOnce(&mut Progress)) {
    let mut progress = progress.lock().unwrap_or_else(|error| error.into_inner());
    change(&mut progress);
    progress.revision += 1;
}

pub(super) fn progress() -> Progress {
    let manager = MANAGER.lock().unwrap_or_else(|error| error.into_inner());
    manager
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
}

/// Schedule one batch. Repeated rescan while it runs only refreshes its view.
pub(super) fn start() -> Result<()> {
    prove_ram()?;
    MANAGER
        .lock()
        .map_err(|_| refuse("import manager failed"))?
        .schedule(batch)
}

/// Drain the local batch before taking the foreground lock. Keeping the
/// scheduling mutex until that lock is acquired prevents a new local batch
/// from taking it first. Other processes join the same native flock.
pub(crate) fn barrier<T, E: From<RecoveryError>>(
    action: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let mut manager = MANAGER
        .lock()
        .map_err(|_| E::from(refuse("import manager failed")))?;
    manager.drain().map_err(E::from)?;
    action()
}

pub(super) fn wait() -> Result<()> {
    barrier(|| Ok(()))
}

fn pool_jobs(
    labels: &[Label],
    allowed: Option<&BTreeSet<u64>>,
    imported: &[(u64, String)],
    devices: &BTreeMap<String, u64>,
    mut local_transport: impl FnMut(&Label) -> Result<bool>,
) -> Result<Vec<PoolJob>> {
    let mut pools: BTreeMap<u64, Vec<&Label>> = BTreeMap::new();
    for label in labels {
        pools.entry(label.pool_guid).or_default().push(label);
    }
    let mut jobs = Vec::new();
    for (guid, labels) in pools {
        let name = labels[0].name.clone();
        let mut local = true;
        for label in &labels {
            local &= local_transport(label)?;
        }
        let mut vdevs: BTreeMap<u64, BTreeMap<u64, BTreeSet<&str>>> = BTreeMap::new();
        for label in &labels {
            let device = devices
                .get(&label.path)
                .ok_or_else(|| refuse("pool label lacks an observed block device identity"))?;
            if let Some(vdev) = label.vdev_guid {
                vdevs
                    .entry(vdev)
                    .or_default()
                    .entry(*device)
                    .or_default()
                    .insert(&label.path);
            }
        }
        let copied = vdevs
            .iter()
            .find(|(_, paths)| paths.len() > 1)
            .map(|(vdev, devices)| {
                let paths: Vec<_> = devices
                    .values()
                    .flat_map(|paths| paths.iter().copied())
                    .collect();
                format!("copied vdev identity {vdev} on {}", paths.join(", "))
            });
        let state =
            if labels.iter().any(|label| label.name != name) {
                ImportState::Failed("damaged or inconsistent pool name labels".into())
            } else if let Some(reason) = copied {
                ImportState::Failed(reason)
            } else if imported.iter().any(|(imported_guid, imported_name)| {
                *imported_guid == guid && imported_name != &name
            }) {
                ImportState::Failed("pool GUID is already imported under another name".into())
            } else if imported.iter().any(|(imported_guid, imported_name)| {
                *imported_guid != guid && imported_name == &name
            }) {
                ImportState::Failed("name taken by an imported pool".into())
            } else if allowed.is_some_and(|allowed| !allowed.contains(&guid)) {
                ImportState::Failed("last used by another host".into())
            } else if imported
                .iter()
                .any(|(imported_guid, _)| *imported_guid == guid)
            {
                ImportState::Imported
            } else {
                ImportState::Queued
            };
        jobs.push(PoolJob {
            guid,
            name,
            local,
            state,
        });
    }
    // Refuse both ambiguous names before racing two imports for one name.
    let mut counts = BTreeMap::new();
    for job in &jobs {
        *counts.entry(job.name.clone()).or_insert(0) += 1;
    }
    for job in &mut jobs {
        if counts[&job.name] > 1 && job.state == ImportState::Queued {
            job.state = ImportState::Failed("name is also used by another discovered pool".into());
        }
    }
    Ok(jobs)
}

/// Kernel device identity collapses block-device aliases without confusing
/// two copied partitions on separate devices. This I/O stays outside inventory.
fn device_identities(labels: &[Label]) -> Result<BTreeMap<String, u64>> {
    let mut devices = BTreeMap::new();
    for label in labels {
        if devices.contains_key(&label.path) {
            continue;
        }
        let metadata = std::fs::metadata(&label.path)?;
        if !metadata.file_type().is_block_device() {
            return Err(refuse("pool label path is not a block device"));
        }
        devices.insert(label.path.clone(), metadata.rdev());
    }
    Ok(devices)
}

fn local_transport(label: &Label) -> Result<bool> {
    let stack = hostid_adopt::lsblk_inverse(&label.path, "PATH,TYPE,TRAN")?;
    Ok(hostid_adopt::transport_refusal(&label.path, &stack).is_none())
}

trait ImportBackend: Sync {
    fn import(&self, job: &PoolJob) -> Result<()>;
}

struct NativeImports<'a> {
    writer: &'a WriterLock,
}

fn batch(progress: &Mutex<Progress>) -> Result<()> {
    use hostid_adopt::{Failure, Import};
    let writer = Arc::new(
        zfs_tools::engine::lock::for_command("zboot", "read-only pool discovery")
            .map_err(|error| refuse(error.to_string()))?,
    );
    publish_inventory_writer(&INVENTORY_WRITER, &writer, progress)?;
    prove_ram()?;
    readonly_pools(&state::observe()?)?;
    let import = match hostid_adopt::automatic() {
        Ok(import) => import,
        Err(Failure::Unchanged(error)) => {
            eprintln!(
                "menu hostid: {}",
                zfs_tools::engine::escape_display(&error.to_string())
            );
            Import::All
        }
        Err(Failure::Inconsistent(error)) => return Err(error),
    };
    let labels = match &import {
        Import::ThenDefault(labels) => labels.clone(),
        _ => hostid_adopt::pool_labels()?,
    };
    let allowed = match &import {
        Import::Host(guids) => Some(guids),
        _ => None,
    };
    let observed = state::observe()?;
    readonly_pools(&observed)?;
    let imported: Vec<_> = observed
        .inspection
        .pools
        .iter()
        .map(|pool| (pool.guid.get(), pool.name.clone()))
        .collect();
    let devices = device_identities(&labels)?;
    let jobs = pool_jobs(&labels, allowed, &imported, &devices, local_transport)?;
    update(progress, |progress| progress.jobs = jobs);
    let imports = NativeImports {
        writer: writer.as_ref(),
    };
    run_group(progress, &imports, true)?;
    if let Import::ThenDefault(labels) = &import {
        finish_adoption(labels)?;
        exclude_other_hosts(progress)?;
    }
    update(progress, |progress| progress.local_ready = true);
    run_group(progress, &imports, false)?;
    if let Import::ThenDefault(labels) = &import {
        // A default may have arrived on a non-local device. An existing
        // adoption is retained, including its immutable host identity.
        if hostid_adopt::adopted().is_none() {
            finish_adoption(labels)?;
            exclude_other_hosts(progress)?;
        }
    }
    readonly_pools(&state::observe()?)
}

fn exclude_other_hosts(progress: &Mutex<Progress>) -> Result<()> {
    if let (_, Some(guids)) = hostid_adopt::binding()? {
        update(progress, |progress| {
            for job in &mut progress.jobs {
                if !guids.contains(&job.guid.to_string()) {
                    job.state = ImportState::Failed("last used by another host".into());
                }
            }
        });
    }
    Ok(())
}

fn finish_adoption(labels: &[Label]) -> Result<()> {
    use hostid_adopt::Failure;
    let observed = state::observe()?;
    readonly_pools(&observed)?;
    let mut backend = crate::handoff::NativeRecovery::new();
    let close = match hostid_adopt::adopt_default(labels, &observed) {
        Ok(close) => close,
        Err(Failure::Unchanged(error)) => {
            eprintln!(
                "menu hostid: {}",
                zfs_tools::engine::escape_display(&error.to_string())
            );
            return Ok(());
        }
        Err(Failure::Inconsistent(error)) => {
            use crate::handoff::RecoveryBackend;
            for pool in &observed.inspection.pools {
                if let Err(cleanup) = backend.action(&crate::handoff::Action::Export {
                    pool: pool.name.clone(),
                }) {
                    eprintln!(
                        "menu export: {}",
                        zfs_tools::engine::escape_display(&cleanup.to_string())
                    );
                }
            }
            return Err(error);
        }
    };
    use crate::handoff::RecoveryBackend;
    for pool in close {
        backend.action(&crate::handoff::Action::Export { pool })?;
    }
    Ok(())
}

fn run_group(progress: &Mutex<Progress>, backend: &impl ImportBackend, local: bool) -> Result<()> {
    let jobs: Vec<_> = progress
        .lock()
        .map_err(|_| refuse("import progress failed"))?
        .jobs
        .iter()
        .filter(|job| job.local == local && job.state == ImportState::Queued)
        .cloned()
        .collect();
    for group in jobs.chunks(CONCURRENT_IMPORTS) {
        thread::scope(|scope| {
            let mut children = Vec::new();
            for job in group {
                update(progress, |progress| {
                    progress
                        .jobs
                        .iter_mut()
                        .find(|row| row.guid == job.guid)
                        .unwrap()
                        .state = ImportState::Importing;
                });
                children.push((
                    job.guid,
                    scope.spawn(move || {
                        let result = backend.import(job);
                        update(progress, |progress| {
                            progress
                                .jobs
                                .iter_mut()
                                .find(|row| row.guid == job.guid)
                                .unwrap()
                                .state = match result {
                                Ok(()) => ImportState::Imported,
                                Err(error) => ImportState::Failed(error.to_string()),
                            };
                        });
                    }),
                ));
            }
            let mut failed = false;
            for (guid, child) in children {
                if child.join().is_err() {
                    failed = true;
                    update(progress, |progress| {
                        progress
                            .jobs
                            .iter_mut()
                            .find(|row| row.guid == guid)
                            .unwrap()
                            .state = ImportState::Failed("pool import worker failed".into());
                        progress.error = Some("pool import worker failed".into());
                        progress.local_ready = false;
                    });
                }
            }
            if failed {
                Err(refuse("pool import worker failed"))
            } else {
                Ok::<(), RecoveryError>(())
            }
        })?;
    }
    Ok(())
}

impl ImportBackend for NativeImports<'_> {
    fn import(&self, job: &PoolJob) -> Result<()> {
        let observed = state::observe()?;
        if let Some(pool) = observed
            .inspection
            .pools
            .iter()
            .find(|pool| pool.guid.get() == job.guid)
        {
            if pool.name != job.name {
                return Err(refuse("pool GUID is already imported under another name"));
            }
            readonly_pools(&observed)?;
            return Ok(());
        }
        if observed
            .inspection
            .pools
            .iter()
            .any(|pool| pool.name == job.name)
        {
            return Err(refuse("name taken by an imported pool"));
        }
        let (_, adopted) = hostid_adopt::binding()?;
        if adopted
            .as_ref()
            .is_some_and(|guids| !guids.contains(&job.guid.to_string()))
        {
            return Err(refuse("last used by another host"));
        }
        let started = Instant::now();
        let mut command = Command::new("/sbin/zpool");
        command
            .args(super::pool_access::import_args(
                zfs_tools::engine::Guid::new(job.guid),
                true,
            ))
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.writer
            .inherit_for(&mut command)
            .map_err(|error| refuse(error.to_string()))?;
        let child = zfs_tools::engine::native::announced(&mut command).spawn();
        drop(command);
        let output = child?.wait_with_output()?;
        eprintln!(
            "Pool {} import finished in {:.3}s",
            zfs_tools::engine::escape_display(&job.name),
            started.elapsed().as_secs_f64()
        );
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            return Err(refuse(format!(
                "import refused or pool damaged ({}): {}",
                output.status,
                detail.chars().take(4096).collect::<String>().trim()
            )));
        }
        let observed = state::observe()?;
        let pool = observed
            .inspection
            .pools
            .iter()
            .find(|pool| pool.name == job.name && pool.guid.get() == job.guid)
            .ok_or_else(|| refuse("imported pool identity was not observed"))?;
        if observed
            .pool_properties
            .get(&pool.name)
            .and_then(|properties| properties.get("readonly"))
            .map(|property| property.value.as_str())
            != Some("on")
        {
            return Err(refuse("imported pool is not read-only"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
    use std::time::Duration;

    const DEADLINE: Duration = Duration::from_secs(5);

    fn job(guid: u64, local: bool) -> PoolJob {
        PoolJob {
            guid,
            name: format!("pool{guid}"),
            local,
            state: ImportState::Queued,
        }
    }

    fn label(guid: u64, name: &str, path: &str) -> Label {
        Label {
            path: path.into(),
            name: name.into(),
            pool_guid: guid,
            vdev_guid: None,
            state: 1,
            hostid: 1,
        }
    }

    fn device_map(labels: &[Label]) -> BTreeMap<String, u64> {
        let paths: BTreeSet<_> = labels.iter().map(|label| label.path.clone()).collect();
        paths
            .into_iter()
            .enumerate()
            .map(|(index, path)| (path, index as u64 + 1))
            .collect()
    }

    struct GatedImport {
        slow: u64,
        entered: Sender<()>,
        release: Mutex<Receiver<()>>,
    }

    impl ImportBackend for GatedImport {
        fn import(&self, job: &PoolJob) -> Result<()> {
            if job.guid == self.slow {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv()
                    .map_err(|_| refuse("test import gate disconnected"))?;
            }
            Ok(())
        }
    }

    fn gated_import(slow: u64) -> (GatedImport, Receiver<()>, Sender<()>) {
        let (entered, waiting) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        (
            GatedImport {
                slow,
                entered,
                release: Mutex::new(gate),
            },
            waiting,
            release,
        )
    }

    fn local_writer(path: &std::path::Path) -> Result<WriterLock> {
        WriterLock::acquire_at(path, "menu inventory fixture", Duration::ZERO, |_| {
            panic!("zero-wait inventory must return without a waiting dialogue")
        })
        .map_err(|error| refuse(error.to_string()))
    }

    #[test]
    fn inventory_borrows_the_batch_flock_through_the_entire_callback() {
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("writer.lock");
        let writer = Arc::new(local_writer(&path).unwrap());
        let published = Mutex::new(Weak::new());
        let progress = Mutex::new(Progress::default());
        publish_inventory_writer(&published, &writer, &progress).unwrap();
        assert_eq!(progress.lock().unwrap().revision(), 1);
        let value = inventory_with(
            &published,
            || panic!("a published discovery guard must avoid nested acquisition"),
            || {
                assert!(published.try_lock().is_ok());
                // Ending the batch's own lifetime still leaves this inventory
                // callback holding the same real flock open file description.
                drop(writer);
                assert!(
                    local_writer(&path)
                        .unwrap_err()
                        .to_string()
                        .contains("another ZFS writer")
                );
                assert_eq!(progress.lock().unwrap().revision(), 1);
                Ok(7)
            },
        )
        .unwrap();
        assert_eq!(value, 7);
        assert!(published.lock().unwrap().upgrade().is_none());
        local_writer(&path).unwrap();
    }

    #[test]
    fn inventory_refuses_an_ordinary_writer_before_running_the_callback() {
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("writer.lock");
        let foreign = local_writer(&path).unwrap();
        let published: Mutex<Weak<WriterLock>> = Mutex::new(Weak::new());
        let invoked = std::cell::Cell::new(false);
        let error = inventory_with(
            &published,
            || local_writer(&path),
            || {
                invoked.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("another ZFS writer"));
        assert!(!invoked.get());
        drop(foreign);
        inventory_with(&published, || local_writer(&path), || Ok(())).unwrap();
        assert!(published.lock().unwrap().upgrade().is_none());
    }

    #[test]
    fn inventory_releases_a_fresh_guard_when_the_callback_refuses() {
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("writer.lock");
        let published: Mutex<Weak<WriterLock>> = Mutex::new(Weak::new());
        let acquired = std::cell::Cell::new(0);
        let result: Result<()> = inventory_with(
            &published,
            || {
                acquired.set(acquired.get() + 1);
                local_writer(&path)
            },
            || {
                assert!(published.try_lock().is_ok());
                assert!(local_writer(&path).is_err());
                Err(refuse("inventory changed"))
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("inventory changed")
        );
        assert_eq!(acquired.get(), 1);
        local_writer(&path).unwrap();
    }

    #[test]
    fn inventory_lists_while_the_real_batch_flock_holds_a_slow_import() {
        let scratch = crate::factory::tests::Scratch::new();
        let path = scratch.0.join("writer.lock");
        let worker_path = path.clone();
        let published = Arc::new(Mutex::new(Weak::new()));
        let worker_published = Arc::clone(&published);
        let (imports, waiting, release) = gated_import(1);
        let mut manager = Manager::default();
        manager
            .schedule(move |progress| {
                let writer = Arc::new(local_writer(&worker_path)?);
                publish_inventory_writer(&worker_published, &writer, progress)?;
                update(progress, |progress| progress.jobs = vec![job(1, true)]);
                run_group(progress, &imports, true)
            })
            .unwrap();
        waiting.recv_timeout(DEADLINE).unwrap();
        let listing = inventory_with(
            &published,
            || panic!("a live discovery batch supplies its existing flock"),
            || {
                assert!(local_writer(&path).is_err());
                let progress = manager.progress.lock().unwrap().clone();
                assert!(progress.revision() >= 3);
                let mut out = Vec::new();
                progress.render(&mut out)?;
                Ok(String::from_utf8(out).unwrap())
            },
        )
        .unwrap();
        assert_eq!(listing, "Pool pool1 guid=1  importing\n");
        assert!(!manager.batch.as_ref().unwrap().is_finished());
        release.send(()).unwrap();
        manager.drain().unwrap();
        assert!(published.lock().unwrap().upgrade().is_none());
        local_writer(&path).unwrap();
    }

    #[test]
    fn inventory_coordination_poison_refuses_both_reader_and_publication() {
        let published: Mutex<Weak<()>> = Mutex::new(Weak::new());
        let progress = Mutex::new(Progress::default());
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let _held = published.lock().unwrap();
                panic!("injected publication failure");
            }))
            .is_err()
        );
        let result: Result<()> = inventory_with(
            &published,
            || panic!("poison must refuse before lock acquisition"),
            || panic!("poison must refuse before inventory"),
        );
        assert!(result.is_err());
        assert!(publish_inventory_writer(&published, &Arc::new(()), &progress).is_err());
        assert_eq!(progress.lock().unwrap().revision(), 0);
    }

    #[test]
    fn the_listing_does_not_wait_for_a_slow_import() {
        let (imports, waiting, release) = gated_import(2);
        let mut manager = Manager::default();
        manager
            .schedule(move |progress| {
                update(progress, |progress| {
                    progress.jobs = vec![job(1, true), job(2, false)]
                });
                run_group(progress, &imports, true)?;
                update(progress, |progress| progress.local_ready = true);
                run_group(progress, &imports, false)
            })
            .unwrap();
        waiting.recv_timeout(DEADLINE).unwrap();
        // This is the same bounded snapshot/render path used by the listing.
        // The slow job remains blocked until after the view is inspected.
        let progress = manager.progress.lock().unwrap().clone();
        assert_eq!(progress.jobs[0].state, ImportState::Imported);
        assert_eq!(progress.jobs[1].state, ImportState::Importing);
        assert!(progress.countdown_ready());
        assert!(!manager.batch.as_ref().unwrap().is_finished());
        let mut listing = Vec::new();
        progress.render(&mut listing).unwrap();
        assert_eq!(
            String::from_utf8(listing).unwrap(),
            "Pool pool2 guid=2  importing\n"
        );
        release.send(()).unwrap();
        manager.drain().unwrap();
        assert!(manager.progress.lock().unwrap().finished);
    }

    #[test]
    fn a_late_import_cannot_race_an_export_or_an_erase() {
        for effect in ["export", "erase"] {
            let (imports, waiting, release) = gated_import(1);
            let mut manager = Manager::default();
            manager
                .schedule(move |progress| {
                    update(progress, |progress| progress.jobs = vec![job(1, true)]);
                    run_group(progress, &imports, true)
                })
                .unwrap();
            waiting.recv_timeout(DEADLINE).unwrap();
            let (draining, started) = mpsc::channel();
            let (performed, effects) = mpsc::channel();
            let foreground = thread::spawn(move || {
                draining.send(()).unwrap();
                manager.drain().unwrap();
                performed.send(effect).unwrap();
            });
            started.recv_timeout(DEADLINE).unwrap();
            assert_eq!(effects.try_recv(), Err(TryRecvError::Empty));
            release.send(()).unwrap();
            assert_eq!(effects.recv_timeout(DEADLINE).unwrap(), effect);
            foreground.join().unwrap();
        }
    }

    #[test]
    fn a_completed_failure_blocks_every_effect_until_an_explicit_rescan() {
        let mut manager = Manager::default();
        manager
            .schedule(|_| Err(refuse("final readback failed")))
            .unwrap();
        for _ in 0..2 {
            let mut effect = false;
            if manager.drain().is_ok() {
                effect = true;
            }
            assert!(!effect);
            let progress = manager.progress.lock().unwrap();
            assert!(
                progress
                    .error
                    .as_deref()
                    .unwrap()
                    .contains("final readback failed")
            );
            assert!(!progress.countdown_ready());
        }
        assert!(manager.batch.is_none());
        manager
            .schedule(|progress| {
                update(progress, |progress| progress.local_ready = true);
                Ok(())
            })
            .unwrap();
        manager.drain().unwrap();
        assert!(manager.progress.lock().unwrap().countdown_ready());
    }

    #[test]
    fn a_worker_panic_is_visible_and_keeps_the_barrier_closed() {
        struct Panics;
        impl ImportBackend for Panics {
            fn import(&self, _: &PoolJob) -> Result<()> {
                panic!("injected import worker panic")
            }
        }
        let mut manager = Manager::default();
        manager
            .schedule(|progress| {
                update(progress, |progress| {
                    progress.jobs = vec![job(1, false)];
                    progress.local_ready = true;
                });
                run_group(progress, &Panics, false)
            })
            .unwrap();
        assert!(manager.drain().is_err());
        assert!(manager.drain().is_err());
        let progress = manager.progress.lock().unwrap();
        assert!(progress.finished);
        assert!(!progress.countdown_ready());
        assert!(
            progress
                .error
                .as_deref()
                .unwrap()
                .contains("pool import worker failed")
        );
        assert!(matches!(progress.jobs[0].state, ImportState::Failed(_)));
    }

    #[test]
    fn a_batch_panic_before_any_import_is_visible() {
        let mut manager = Manager::default();
        manager
            .schedule(|_| panic!("injected batch panic"))
            .unwrap();
        assert!(manager.drain().is_err());
        assert!(manager.drain().is_err());
        let progress = manager.progress.lock().unwrap();
        assert!(progress.finished && progress.error.is_some());
        assert!(!progress.countdown_ready());
    }

    #[test]
    fn a_failed_local_pool_keeps_countdown_off_but_a_failed_nonlocal_pool_does_not() {
        let mut progress = Progress {
            local_ready: true,
            ..Progress::default()
        };
        let mut failed = job(1, false);
        failed.state = ImportState::Failed("damaged pool".into());
        progress.jobs.push(failed);
        assert!(progress.countdown_ready());
        progress.jobs[0].local = true;
        assert!(!progress.countdown_ready());
        progress.jobs[0].state = ImportState::Imported;
        assert!(progress.countdown_ready());
        progress.error = Some("final identity readback failed".into());
        assert!(!progress.countdown_ready());
    }

    #[test]
    fn copied_vdevs_refuse_while_device_aliases_and_mirror_members_are_distinct() {
        let mut first = label(1, "stick", "/dev/sda1");
        first.vdev_guid = Some(9);
        let mut second = first.clone();
        second.path = "/dev/sdb1".into();
        let labels = [first.clone(), second.clone()];
        let distinct = device_map(&labels);
        let jobs = pool_jobs(&labels, None, &[], &distinct, |_| Ok(false)).unwrap();
        let ImportState::Failed(reason) = &jobs[0].state else {
            panic!("copied vdev was accepted")
        };
        assert!(reason.contains("copied vdev identity 9"));
        assert!(reason.contains("/dev/sda1") && reason.contains("/dev/sdb1"));
        let aliases = BTreeMap::from([(first.path.clone(), 17), (second.path.clone(), 17)]);
        assert_eq!(
            pool_jobs(&labels, None, &[], &aliases, |_| Ok(false)).unwrap()[0].state,
            ImportState::Queued
        );
        second.vdev_guid = Some(10);
        let mirror = [first, second];
        assert_eq!(
            pool_jobs(&mirror, None, &[], &distinct, |_| Ok(false)).unwrap()[0].state,
            ImportState::Queued
        );
        assert!(pool_jobs(&mirror, None, &[], &BTreeMap::new(), |_| Ok(false)).is_err());
    }

    #[test]
    fn a_pool_whose_name_is_taken_is_listed_with_the_reason() {
        let labels = [label(2, "pool", "usb")];
        let jobs = pool_jobs(
            &labels,
            None,
            &[(1, "pool".into())],
            &device_map(&labels),
            |_| Ok(false),
        )
        .unwrap();
        assert_eq!(
            jobs[0].state,
            ImportState::Failed("name taken by an imported pool".into())
        );
        let progress = Progress {
            jobs,
            ..Progress::default()
        };
        let mut out = Vec::new();
        progress.render(&mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("name taken by an imported pool")
        );
    }

    #[test]
    fn inventory_keeps_duplicate_names_host_refusals_and_transport_separate() {
        let labels = [
            label(1, "duplicate", "nvme"),
            label(2, "duplicate", "usb"),
            label(3, "foreign", "sata"),
            label(4, "mixed", "nvme"),
            label(4, "mixed", "usb"),
        ];
        let allowed = BTreeSet::from([1, 2, 4]);
        let jobs = pool_jobs(
            &labels,
            Some(&allowed),
            &[],
            &device_map(&labels),
            |label| Ok(label.path != "usb"),
        )
        .unwrap();
        assert_eq!(
            jobs[0].state,
            ImportState::Failed("name is also used by another discovered pool".into())
        );
        assert_eq!(jobs[1].state, jobs[0].state);
        assert_eq!(
            jobs[2].state,
            ImportState::Failed("last used by another host".into())
        );
        assert_eq!(jobs[3].state, ImportState::Queued);
        assert!(jobs[0].local && !jobs[1].local && jobs[2].local && !jobs[3].local);
        let inconsistent = [label(5, "first", "nvme"), label(5, "other", "nvme")];
        assert_eq!(
            pool_jobs(
                &inconsistent,
                None,
                &[],
                &device_map(&inconsistent),
                |_| Ok(true)
            )
            .unwrap()[0]
                .state,
            ImportState::Failed("damaged or inconsistent pool name labels".into())
        );
        assert!(
            pool_jobs(&labels, None, &[], &device_map(&labels), |_| Err(refuse(
                "transport unknown"
            )))
            .is_err()
        );
    }
    #[test]
    fn local_prefix_readiness_and_batch_settlement_are_distinct() {
        let mut progress = Progress {
            jobs: vec![job(1, false)],
            ..Progress::default()
        };
        assert!(!progress.countdown_ready());
        assert!(!progress.settled());
        progress.local_ready = true;
        assert!(progress.countdown_ready());
        assert!(!progress.settled());
        progress.local_ready = false;
        progress.finished = true;
        progress.error = Some("import failed".into());
        assert!(!progress.countdown_ready());
        assert!(progress.settled());
    }
}
