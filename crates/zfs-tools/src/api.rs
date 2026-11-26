//! Native, identity-bound checkpoint operations under one host writer session.
//!
//! Observations are sequential. This coordinates cooperating local writers;
//! callers must also fence external writers and quiesce applications as needed.
use crate::engine::{self, capture, delete, lock, native, operation::SnapshotScope, state};
use crate::{DatasetIdentity, DatasetKind, SnapshotRef};
use std::fmt;

/// A refused operation or a failed native observation. Incomplete effects are
/// reported in the operation's outcome whenever they can be reconciled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    detail: String,
    busy: Option<String>,
    stop: Option<ObservationStop>,
}
impl Error {
    /// Explain why an application lifecycle guard refuses to continue.
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            busy: None,
            stop: None,
        }
    }
    /// Why a bounded observation (one with a caller-set deadline) stopped
    /// without a result; `None` for every other error. A stopped observation
    /// returns nothing: the running query's output is discarded, never parsed.
    pub fn observation_stop(&self) -> Option<ObservationStop> {
        self.stop
    }
    /// The holder label of the writer lock when [`WriterSession::acquire`]
    /// waited its whole bound for another writer (for example
    /// `pid 812 zsnap run`). The label is advisory text the holder wrote; it
    /// is `None` for every other error.
    pub fn busy_holder(&self) -> Option<&str> {
        self.busy.as_deref()
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&engine::escape_display(&self.detail))
    }
}
impl std::error::Error for Error {}
pub use crate::engine::bounded::MAX_QUERY_OUTPUT;

/// Why a bounded observation stopped without a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationStop {
    /// Its deadline passed: during a query, or with none running (between
    /// queries, or while the observation's result was being prepared).
    Deadline(QueryCleanup),
    /// A query wrote more than [`MAX_QUERY_OUTPUT`] bytes to standard output.
    OutputLimit(QueryCleanup),
    /// Reading the running query's output or waiting for it failed, so it
    /// was stopped like an expired one.
    QueryFailed(QueryCleanup),
    /// SIGCHLD is ignored or `SA_NOCLDWAIT` is set in this process, so the
    /// kernel would reap the library's children itself and their PIDs could
    /// be reused before a kill; refused before any query started.
    ChildrenNotWaitable,
}

/// What a stop established about the query it ended. The library never
/// signals a process it does not know to be its own unreaped child; callers
/// must not reap the library's children themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryCleanup {
    /// No query was running, so nothing was signalled.
    NoneRunning,
    /// SIGKILL was sent to the running query's process group and its leader
    /// was reaped. Members that left the group are not proven gone; a
    /// read-only query holds no writer lock.
    LeaderReaped,
    /// The group signal or the leader's reap within ten seconds could not be
    /// confirmed; the query may still run. When the leader is still this
    /// process's child the library keeps it and reaps it during a later
    /// bounded query. The error's text says which step failed.
    Unconfirmed,
}

/// Run one observation's queries with no deadline (`None`), or under one
/// deadline for all of them, every pipe's completion and the observation's
/// own result included.
pub(crate) fn observe_within<T>(
    within: Option<std::time::Duration>,
    observe: impl FnOnce(
        &mut dyn FnMut(&'static str, &[String]) -> Result<String, engine::Error>,
    ) -> Result<T, Error>,
) -> Result<T, Error> {
    let Some(within) = within else {
        return observe(&mut native::run);
    };
    if within.is_zero() {
        return Err(Error::new("an observation deadline must be nonzero"));
    }
    let mut query = engine::bounded::Query::new(within);
    let result = observe(&mut |program, args| query.run(program, args));
    query.check_finished();
    match query.stopped() {
        // Whatever the observation made of the failed query, it is not a result.
        Some(stopped) => {
            use engine::bounded::{Cause, Cleanup};
            let cleanup = match stopped.cleanup {
                Cleanup::NoneRunning => QueryCleanup::NoneRunning,
                Cleanup::LeaderReaped => QueryCleanup::LeaderReaped,
                Cleanup::Unconfirmed => QueryCleanup::Unconfirmed,
            };
            let (stop, what) = match stopped.cause {
                Cause::Deadline => (
                    ObservationStop::Deadline(cleanup),
                    format!("observation exceeded its {within:?} deadline"),
                ),
                Cause::OutputLimit => (
                    ObservationStop::OutputLimit(cleanup),
                    "observation query output exceeded its limit".to_string(),
                ),
                Cause::Failed => (
                    ObservationStop::QueryFailed(cleanup),
                    "observation query failed".to_string(),
                ),
                Cause::NotWaitable => (
                    ObservationStop::ChildrenNotWaitable,
                    "bounded observation refused".to_string(),
                ),
            };
            Err(Error {
                stop: Some(stop),
                ..Error::new(format!("{what}: {}", stopped.detail))
            })
        }
        None => result,
    }
}

impl From<engine::Error> for Error {
    fn from(error: engine::Error) -> Self {
        Self::new(error.to_string())
    }
}

/// Immutable observation of one exact dataset's current local incarnation.
/// This is sequential read evidence, not admission or writer authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetObservation {
    name: String,
    identity: DatasetIdentity,
    kind: DatasetKind,
}
impl DatasetObservation {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn identity(&self) -> &DatasetIdentity {
        &self.identity
    }
    pub fn kind(&self) -> &DatasetKind {
        &self.kind
    }
}

/// Observe exactly this dataset in already imported pools. Native queries are
/// read-only and sequential; a later admission must bind and revalidate the
/// returned identity. Descendants never substitute for a missing exact name.
pub fn observe_dataset(name: &str) -> Result<DatasetObservation, Error> {
    observe_dataset_with(name, native::run)
}

/// Observe the current snapshot at exactly this name in already imported
/// pools. A reused name returns its current identity, without claiming it is
/// an earlier incarnation. Query failures are errors, never proven absence.
/// This read-only observation grants no mutation authority.
pub fn observe_snapshot(name: &str) -> Result<SnapshotRef, Error> {
    observe_snapshot_with(name, &mut native::run)
}

fn observe_dataset_with(
    name: &str,
    run: impl FnMut(&'static str, &[String]) -> Result<String, engine::Error>,
) -> Result<DatasetObservation, Error> {
    let request = engine::InspectRequest::new(vec![name.into()], false)?;
    let observed = native::inspect_with(&request, run)?;
    let mut exact = observed
        .datasets
        .iter()
        .filter(|dataset| dataset.name == name);
    let dataset = exact
        .next()
        .ok_or_else(|| Error::new(format!("dataset was not observed: {name}")))?;
    if exact.next().is_some() {
        return Err(Error::new("ambiguous exact dataset observation"));
    }
    // Reject incomplete native identity rather than turning it into an expected
    // incarnation that the caller could mistakenly retain for later admission.
    DatasetTarget::new(name, dataset.identity.clone())?;
    Ok(DatasetObservation {
        name: dataset.name.clone(),
        identity: dataset.identity.clone(),
        kind: dataset.kind.clone(),
    })
}

fn observe_snapshot_with(
    name: &str,
    run: &mut impl FnMut(&'static str, &[String]) -> Result<String, engine::Error>,
) -> Result<SnapshotRef, Error> {
    let point = native::observe_with(name, run)?.point();
    if point.name != name || !point.is_complete() {
        return Err(Error::new(
            "incomplete or mismatched exact snapshot observation",
        ));
    }
    Ok(point)
}

/// One exact dataset name and its expected local incarnation. A target never
/// expands to descendants. Volumes are accepted, including an explicit
/// `DatasetKind::Volume` requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetTarget {
    name: String,
    identity: DatasetIdentity,
    required_kind: Option<DatasetKind>,
}
impl DatasetTarget {
    pub fn new(name: impl Into<String>, identity: DatasetIdentity) -> Result<Self, Error> {
        let name = name.into();
        engine::validate_dataset_name(&name)?;
        if !identity.is_complete() {
            return Err(Error::new(
                "dataset target requires a complete nonzero identity",
            ));
        }
        Ok(Self {
            name,
            identity,
            required_kind: None,
        })
    }
    pub fn requiring_kind(mut self, kind: DatasetKind) -> Self {
        self.required_kind = Some(kind);
        self
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn identity(&self) -> &DatasetIdentity {
        &self.identity
    }
}

fn lock_error(error: lock::LockError) -> Error {
    let busy = match &error {
        lock::LockError::Busy { holder } => Some(holder.clone()),
        lock::LockError::Io(_) => None,
    };
    Error {
        busy,
        ..Error::new(error.to_string())
    }
}

/// Opaque custody of the host's cooperating-writer lock. Reuse one session for
/// sequential scopes; dropping it releases the lock after native children have
/// released their inherited custody.
pub struct WriterSession {
    pub(crate) held: lock::WriterLock,
    /// Why this session no longer admits or dispatches: an effect child
    /// whose reap could not be confirmed may still hold the lock and run.
    pub(crate) poisoned: Option<String>,
}
impl WriterSession {
    pub(crate) fn with_native_writer<T>(&self, run: impl FnOnce() -> T) -> Result<T, Error> {
        self.usable()?;
        native::with_writer_lock(&self.held, run).map_err(Error::from)
    }

    /// Unsupported: zsnap runs its reader view setup and teardown under this
    /// session's writer custody.
    #[doc(hidden)]
    pub fn with_native_writer_mut<T>(
        &mut self,
        run: impl FnOnce(&mut Self) -> T,
    ) -> Result<T, Error> {
        self.usable()?;
        let held = self
            .held
            .duplicate()
            .map_err(|error| Error::new(error.to_string()))?;
        native::with_writer_lock(&held, || run(self)).map_err(Error::from)
    }

    /// Wait for the standard host writer lock. Delegated writers join the same
    /// existing inode; an unavailable lock is a refusal.
    pub fn acquire(purpose: &str) -> Result<Self, Error> {
        let held = lock::for_command("zfs-tools", purpose).map_err(lock_error)?;
        Ok(Self {
            held,
            poisoned: None,
        })
    }

    pub(crate) fn usable(&self) -> Result<(), Error> {
        match &self.poisoned {
            Some(why) => Err(Error::new(format!(
                "writer session is poisoned and refuses further work: {why}"
            ))),
            None => Ok(()),
        }
    }

    /// Admit fresh native evidence for exactly these expected incarnations.
    pub fn admit<'a>(
        &'a mut self,
        targets: &[DatasetTarget],
    ) -> Result<CheckpointScope<'a>, Error> {
        self.admit_guarded(targets, || Ok(()))
    }

    /// Recheck application lifecycle authority before every observation and
    /// immediately before each effect. The guard cannot supply ZFS evidence or
    /// native commands. Refusals after an effect retain incomplete outcomes.
    pub fn admit_guarded<'a>(
        &'a mut self,
        targets: &[DatasetTarget],
        mut guard: impl FnMut() -> Result<(), Error> + 'a,
    ) -> Result<CheckpointScope<'a>, Error> {
        self.usable()?;
        validate_targets(targets)?;
        let scope = native::with_writer_lock(&self.held, || {
            guard()?;
            let observed = state::observe()?;
            admit_state(targets, &observed).map_err(Error::from)
        })
        .map_err(Error::from)??;
        Ok(CheckpointScope {
            session: self,
            targets: targets.to_vec(),
            scope,
            guard: Box::new(guard),
        })
    }
}

/// Fresh, exact checkpoint scope borrowed from a writer session. It exposes
/// immutable targets, never raw native observations or a mutable engine plan.
///
/// An admitted scope cannot survive its session:
/// ```compile_fail
/// use zfs_tools::{DatasetTarget, WriterSession};
/// fn cannot_escape(target: DatasetTarget) {
///     let mut scope;
///     {
///         let mut session = WriterSession::acquire("checkpoint").unwrap();
///         scope = session.admit(&[target]).unwrap();
///     }
///     scope.capture("after-session").unwrap();
/// }
/// ```
pub struct CheckpointScope<'a> {
    session: &'a mut WriterSession,
    targets: Vec<DatasetTarget>,
    scope: SnapshotScope,
    guard: Box<dyn FnMut() -> Result<(), Error> + 'a>,
}
impl CheckpointScope<'_> {
    pub fn targets(&self) -> &[DatasetTarget] {
        &self.targets
    }

    /// Capture an exact member list with a fresh invocation marker. This does
    /// not promise cross-pool atomicity or retry an incomplete operation.
    pub fn capture(&mut self, name: &str) -> Result<CaptureOutcome, Error> {
        let mut backend = Guarded {
            backend: capture::NativeCapture,
            targets: &self.targets,
            scope: &self.scope,
            guard: &mut *self.guard,
        };
        let operation_id = uuid::Uuid::new_v4().to_string();
        native::with_writer_lock(&self.session.held, || {
            capture::capture_prepared_with(&self.scope, name, &operation_id, &mut backend)
        })
        .map_err(Error::from)?
        .map_err(Error::from)
    }

    /// Bind an immutable loss review to fresh native snapshot incarnations and
    /// protections. Each point must belong to one exact admitted dataset.
    pub fn review_delete(&mut self, points: &[SnapshotRef]) -> Result<DeleteReview, Error> {
        bind_points(&self.targets, points)?;
        let mut backend = Guarded {
            backend: delete::NativeDelete,
            targets: &self.targets,
            scope: &self.scope,
            guard: &mut *self.guard,
        };
        let plan = native::with_writer_lock(&self.session.held, || {
            delete::plan_snapshots_with(points, &mut backend)
        })
        .map_err(Error::from)??;
        Ok(DeleteReview {
            targets: self.targets.clone(),
            plan,
        })
    }

    /// Apply this scope's exact review and matching loss token. Identity,
    /// management posture, holds, clones and deferred destruction are checked
    /// again before each individual destroy. No recursive destroy is issued.
    pub fn apply_delete(
        &mut self,
        review: &DeleteReview,
        loss_token: &str,
    ) -> Result<DeleteOutcome, Error> {
        if review.targets != self.targets {
            return Err(Error::new(
                "delete review belongs to a different admitted target scope",
            ));
        }
        let mut backend = Guarded {
            backend: delete::NativeDelete,
            targets: &self.targets,
            scope: &self.scope,
            guard: &mut *self.guard,
        };
        native::with_writer_lock(&self.session.held, || {
            delete::execute_snapshot_delete_with(&review.plan, loss_token, &mut backend)
        })
        .map_err(Error::from)?
        .map_err(Error::from)
    }
}

/// In-memory identity-bound loss review. It cannot be constructed from a file.
/// The token represents this review; it does not replace native revalidation.
pub struct DeleteReview {
    targets: Vec<DatasetTarget>,
    plan: delete::SnapshotDeletePlan,
}
impl DeleteReview {
    pub fn points(&self) -> Vec<SnapshotRef> {
        self.plan.points()
    }
    pub fn loss_token(&self) -> &str {
        self.plan.loss_token()
    }
}

/// Capture completion state, serialized as a snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    Complete,
    Partial,
    Uncertain,
}
/// Immutable capture report. Serialization preserves decimal-string native
/// identities and explicit null optional fields for worker/audit JSON. Reports
/// cannot be deserialized into admission or execution authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CaptureOutcome {
    pub(crate) operation_id: String,
    pub(crate) status: CaptureStatus,
    pub(crate) points: Vec<SnapshotRef>,
    pub(crate) missing: Vec<String>,
    pub(crate) detail: Option<String>,
}
impl CaptureOutcome {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn status(&self) -> CaptureStatus {
        self.status
    }
    pub fn points(&self) -> &[SnapshotRef] {
        &self.points
    }
    pub fn missing(&self) -> &[String] {
        &self.missing
    }
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
    /// Unsupported: a report for the workspace applications' own tests. It
    /// grants no authority; only native capture produces real outcomes.
    #[doc(hidden)]
    pub fn from_parts(
        operation_id: String,
        status: CaptureStatus,
        points: Vec<SnapshotRef>,
        missing: Vec<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            operation_id,
            status,
            points,
            missing,
            detail,
        }
    }
}

/// Deletion completion state, serialized as a snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteStatus {
    Complete,
    Partial,
    Uncertain,
}
/// One exact deletion target's observed state, serialized as a snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletePointStatus {
    /// Exact incarnation was no longer observed after a destroy was issued.
    /// A failed reply is retained separately, not silently called native success.
    AbsentAfterCommand,
    StillPresent,
    Changed,
    Uncertain,
    NotAttempted,
}
/// Immutable per-point deletion report with Serialize-only worker/audit JSON.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeletePointOutcome {
    pub(crate) point: SnapshotRef,
    pub(crate) status: DeletePointStatus,
    pub(crate) command_error: Option<String>,
    pub(crate) detail: Option<String>,
}
impl DeletePointOutcome {
    pub fn point(&self) -> &SnapshotRef {
        &self.point
    }
    pub fn status(&self) -> DeletePointStatus {
        self.status
    }
    pub fn command_error(&self) -> Option<&str> {
        self.command_error.as_deref()
    }
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}
/// Immutable deletion report. Serialization preserves decimal-string native
/// identities and explicit null optional fields; it cannot recreate a review.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeleteOutcome {
    pub(crate) status: DeleteStatus,
    pub(crate) points: Vec<DeletePointOutcome>,
}
impl DeleteOutcome {
    pub fn status(&self) -> DeleteStatus {
        self.status
    }
    pub fn points(&self) -> &[DeletePointOutcome] {
        &self.points
    }
}
fn validate_targets(targets: &[DatasetTarget]) -> Result<(), Error> {
    if targets.is_empty() {
        return Err(Error::new("empty checkpoint scope"));
    }
    let mut names = std::collections::BTreeSet::new();
    for target in targets {
        if !names.insert(&target.name) {
            return Err(Error::new("duplicate exact checkpoint dataset"));
        }
    }
    Ok(())
}
pub(crate) fn bind_targets(
    targets: &[DatasetTarget],
    observed: &state::NativeState,
) -> Result<(), engine::Error> {
    for target in targets {
        let mut matching = observed
            .inspection
            .datasets
            .iter()
            .filter(|dataset| dataset.name == target.name);
        let dataset = matching
            .next()
            .ok_or_else(|| engine::Error::MissingScope(target.name.clone()))?;
        if matching.next().is_some()
            || dataset.identity != target.identity
            || target
                .required_kind
                .as_ref()
                .is_some_and(|kind| kind != &dataset.kind)
        {
            return Err(engine::Error::Inconsistent(format!(
                "dataset target identity or required kind changed: {}",
                target.name
            )));
        }
    }
    Ok(())
}
fn admit_state(
    targets: &[DatasetTarget],
    observed: &state::NativeState,
) -> Result<SnapshotScope, engine::Error> {
    bind_targets(targets, observed)?;
    SnapshotScope::plan_exact(
        &observed.inspection,
        &observed.dataset_properties,
        &observed.pool_properties,
        &targets
            .iter()
            .map(|target| target.name.clone())
            .collect::<Vec<_>>(),
    )
}
fn bind_points(targets: &[DatasetTarget], points: &[SnapshotRef]) -> Result<(), Error> {
    for point in points {
        engine::validate_snapshot_name(&point.name)?;
        let parent = point
            .name
            .split_once('@')
            .expect("validated snapshot name")
            .0;
        if !targets.iter().any(|target| {
            target.name == parent
                && target.identity.guid == point.dataset_guid
                && target.identity.pool_guid == point.identity.pool_guid
        }) {
            return Err(Error::new(
                "snapshot deletion target is outside admitted exact dataset identities",
            ));
        }
    }
    Ok(())
}

/// Private adapters retain native observation/effect seams for tests. Public
/// callers can only refuse lifecycle progression, never replace native data.
struct Guarded<'a, B> {
    backend: B,
    targets: &'a [DatasetTarget],
    scope: &'a SnapshotScope,
    guard: &'a mut dyn FnMut() -> Result<(), Error>,
}
impl<B> Guarded<'_, B> {
    fn check(&mut self) -> Result<(), engine::Error> {
        (self.guard)().map_err(|error| {
            engine::Error::Inconsistent(format!("application lifecycle guard refused: {error}"))
        })
    }
    fn bind(&self, observed: &state::NativeState) -> Result<(), engine::Error> {
        bind_targets(self.targets, observed)?;
        self.scope.revalidate(
            &observed.inspection,
            &observed.dataset_properties,
            &observed.pool_properties,
        )
    }
}
impl<B: capture::CaptureBackend> capture::CaptureBackend for Guarded<'_, B> {
    fn observe(&mut self) -> Result<state::NativeState, engine::Error> {
        self.check()?;
        let observed = self.backend.observe()?;
        self.bind(&observed)?;
        Ok(observed)
    }
    fn snapshot(&mut self, names: &[String], operation_id: &str) -> Result<(), engine::Error> {
        self.check()?;
        self.backend.snapshot(names, operation_id)
    }
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, engine::Error> {
        self.check()?;
        self.backend.capture_marker(point)
    }
}
impl<B: delete::DeleteBackend> delete::DeleteBackend for Guarded<'_, B> {
    fn observe(&mut self) -> Result<state::NativeState, engine::Error> {
        self.check()?;
        let observed = self.backend.observe()?;
        self.bind(&observed)?;
        Ok(observed)
    }
    fn observe_point(&mut self, point: &SnapshotRef) -> Result<engine::Snapshot, engine::Error> {
        self.check()?;
        self.backend.observe_point(point)
    }
    fn destroy(&mut self, name: &str) -> Result<(), engine::Error> {
        self.check()?;
        self.backend.destroy(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        CanMount, Dataset, Encryption, Guid, Inspection, KeyStatus, ObjsetId, Pool, Snapshot,
        SnapshotIdentity, Txg,
        native::{NativeProperty, PropertyInventory},
    };
    use std::collections::BTreeMap;

    #[test]
    fn a_result_finished_after_the_deadline_is_a_typed_stop() {
        let error = observe_within(Some(std::time::Duration::from_millis(100)), |run| {
            run("/bin/sh", &["-c".to_string(), "echo row".to_string()])?;
            // Parsing that outlasts the deadline.
            std::thread::sleep(std::time::Duration::from_millis(150));
            Ok(1)
        })
        .unwrap_err();
        assert_eq!(
            error.observation_stop(),
            Some(ObservationStop::Deadline(QueryCleanup::NoneRunning))
        );
        assert_eq!(
            error.to_string(),
            "observation exceeded its 100ms deadline: the observation's 100ms deadline passed \
             while no query was running"
        );
        assert_eq!(
            observe_within(Some(std::time::Duration::from_secs(10)), |run| {
                Ok(run("/bin/sh", &["-c".to_string(), "echo row".to_string()])?)
            }),
            Ok("row\n".to_string())
        );
    }

    const OBS_POOL: &str = "tank\t123\t1000\t100\t900\tONLINE\t-\n";
    const OBS_ROOT: &str =
        "tank\tfilesystem\t456\t100\t900\t80\t/tank\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\t-\t-\n";
    const OBS_CHILD: &str = "tank/child\tfilesystem\t457\t100\t900\t80\t/tank/child\t-\t7\t8\tno\toff\ton\t-\toff\t-\t-\t-\t-\n";
    const OBS_VOLUME: &str =
        "tank/volume\tvolume\t458\t100\t900\t80\t-\t4096\t9\t10\t-\toff\t-\t-\toff\t-\t-\t-\t-\n";
    const OBS_SNAPSHOT: &str = "tank@s\t789\t1700000000\t0\t20\t30\t40\t0\toff\t-\n";

    fn query_replies<'a>(
        replies: &'a [&'a str],
    ) -> impl FnMut(&'static str, &[String]) -> Result<String, engine::Error> + 'a {
        let mut replies = replies.iter();
        move |program, args| {
            assert!(matches!(program, "zpool" | "zfs"));
            assert_eq!(args[0], "list");
            Ok(replies.next().expect("unexpected native query").to_string())
        }
    }

    #[test]
    fn a_busy_lock_names_its_holder_and_other_errors_do_not() {
        let busy = lock_error(lock::LockError::Busy {
            holder: "pid 812 zsnap run".into(),
        });
        assert_eq!(busy.busy_holder(), Some("pid 812 zsnap run"));
        assert!(busy.to_string().contains("pid 812 zsnap run"));
        assert_eq!(
            lock_error(lock::LockError::Io("denied".into())).busy_holder(),
            None
        );
        assert_eq!(Error::new("guard refused").busy_holder(), None);
    }

    #[test]
    fn dataset_observation_preserves_current_identity_kind_and_exact_name() {
        let rows = format!("{OBS_ROOT}{OBS_CHILD}");
        let observed = observe_dataset_with("tank", query_replies(&[OBS_POOL, &rows])).unwrap();
        assert_eq!(observed.name(), "tank");
        assert_eq!(observed.kind(), &DatasetKind::Filesystem);
        assert_eq!(
            observed.identity(),
            &DatasetIdentity {
                pool_guid: Guid::new(123),
                guid: Guid::new(456),
                createtxg: Txg::new(5),
                objsetid: ObjsetId::new(6),
            }
        );
        let volume =
            observe_dataset_with("tank/volume", query_replies(&[OBS_POOL, OBS_VOLUME])).unwrap();
        assert_eq!(volume.name(), "tank/volume");
        assert_eq!(volume.kind(), &DatasetKind::Volume);
        assert_eq!(volume.identity().objsetid, ObjsetId::new(10));
        assert!(observe_dataset_with("tank", query_replies(&[OBS_POOL, OBS_CHILD])).is_err());
        assert!(observe_dataset_with("tank", query_replies(&[""])).is_err());
        assert!(
            observe_dataset_with("-invalid", |_, _| panic!("invalid name queried native ZFS"))
                .is_err()
        );
    }

    #[test]
    fn dataset_observation_refuses_malformed_or_incomplete_native_identity() {
        for (pool, rows) in [
            (OBS_POOL.to_string(), OBS_ROOT.replace("\t456\t", "\t0\t")),
            (
                OBS_POOL.to_string(),
                OBS_ROOT.replace("\t5\t6\t", "\t0\t6\t"),
            ),
            (OBS_POOL.replace("\t123\t", "\t0\t"), OBS_ROOT.to_string()),
            (
                OBS_POOL.to_string(),
                OBS_ROOT.replace("filesystem", "unknown"),
            ),
            (OBS_POOL.to_string(), format!("{OBS_ROOT}{OBS_ROOT}")),
        ] {
            assert!(observe_dataset_with("tank", query_replies(&[&pool, &rows])).is_err());
        }
        let error = observe_dataset_with("tank", |_, _| {
            Err(engine::Error::Inconsistent("native unavailable".into()))
        })
        .unwrap_err();
        assert!(error.to_string().contains("native unavailable"));
    }

    #[test]
    fn snapshot_observation_reports_current_incarnation_without_following_rename() {
        let point = observe_snapshot_with(
            "tank@s",
            &mut query_replies(&[OBS_POOL, OBS_ROOT, OBS_SNAPSHOT]),
        )
        .unwrap();
        assert_eq!(point.name, "tank@s");
        assert_eq!(point.dataset_guid, Guid::new(456));
        assert_eq!(
            point.identity,
            SnapshotIdentity {
                pool_guid: Guid::new(123),
                guid: Guid::new(789),
                createtxg: Txg::new(30),
                objsetid: ObjsetId::new(40),
            }
        );
        let reused = OBS_SNAPSHOT.replace("\t789\t", "\t790\t");
        let current =
            observe_snapshot_with("tank@s", &mut query_replies(&[OBS_POOL, OBS_ROOT, &reused]))
                .unwrap();
        assert_ne!(current.identity, point.identity);
        let renamed = OBS_SNAPSHOT.replace("tank@s", "tank@renamed");
        assert!(
            observe_snapshot_with(
                "tank@s",
                &mut query_replies(&[OBS_POOL, OBS_ROOT, &renamed])
            )
            .is_err()
        );
        assert!(
            observe_snapshot_with("tank@s", &mut query_replies(&[OBS_POOL, OBS_ROOT, ""])).is_err()
        );
        assert!(
            observe_snapshot_with("tank@bad/name", &mut |_, _| panic!(
                "invalid name queried native ZFS"
            ))
            .is_err()
        );
    }

    #[test]
    fn snapshot_observation_refuses_zero_identity_and_failed_queries() {
        for rows in [
            OBS_SNAPSHOT.replace("\t789\t", "\t0\t"),
            OBS_SNAPSHOT.replace("\t30\t40\t", "\t0\t40\t"),
            OBS_SNAPSHOT.replace("\t30\t40\t", "\t30\t0\t"),
            OBS_SNAPSHOT.replace("\toff\t", "\tunknown\t"),
        ] {
            assert!(
                observe_snapshot_with("tank@s", &mut query_replies(&[OBS_POOL, OBS_ROOT, &rows]))
                    .is_err()
            );
        }
        let error = observe_snapshot_with("tank@s", &mut |_, _| {
            Err(engine::Error::Inconsistent("query failed".into()))
        })
        .unwrap_err();
        assert!(error.to_string().contains("query failed"));
    }

    /// Consumers store and compare these bytes; field order, status strings,
    /// explicit nulls and decimal-string identities are all part of the wire.
    #[test]
    fn public_outcome_json_bytes_are_pinned() {
        let point = SnapshotRef {
            name: "tank/volume@checkpoint".into(),
            dataset_guid: Guid::new(u64::MAX),
            identity: SnapshotIdentity {
                pool_guid: Guid::new(9_007_199_254_740_993),
                guid: Guid::new(u64::MAX - 1),
                createtxg: Txg::new(9_007_199_254_740_995),
                objsetid: ObjsetId::new(u64::MAX - 2),
            },
        };
        let point_json = r#"{"name":"tank/volume@checkpoint","dataset_guid":"18446744073709551615","identity":{"pool_guid":"9007199254740993","guid":"18446744073709551614","createtxg":"9007199254740995","objsetid":"18446744073709551613"}}"#;
        fn json(value: &impl serde::Serialize) -> String {
            serde_json::to_string(value).unwrap()
        }
        assert_eq!(json(&point), point_json);

        for (status, wire) in [
            (CaptureStatus::Complete, r#""complete""#),
            (CaptureStatus::Partial, r#""partial""#),
            (CaptureStatus::Uncertain, r#""uncertain""#),
        ] {
            assert_eq!(json(&status), wire);
        }
        let complete = CaptureOutcome {
            operation_id: "00112233-4455-4677-8899-aabbccddeeff".into(),
            status: CaptureStatus::Complete,
            points: vec![point.clone()],
            missing: vec![],
            detail: None,
        };
        assert_eq!(
            json(&complete),
            format!(
                r#"{{"operation_id":"00112233-4455-4677-8899-aabbccddeeff","status":"complete","points":[{point_json}],"missing":[],"detail":null}}"#
            )
        );
        for (status, wire) in [
            (CaptureStatus::Partial, "partial"),
            (CaptureStatus::Uncertain, "uncertain"),
        ] {
            let incomplete = CaptureOutcome {
                status,
                missing: vec!["tank/other@checkpoint".into()],
                detail: Some("native reply lost\nreadback retained".into()),
                ..complete.clone()
            };
            assert_eq!(
                json(&incomplete),
                format!(
                    r#"{{"operation_id":"00112233-4455-4677-8899-aabbccddeeff","status":"{wire}","points":[{point_json}],"missing":["tank/other@checkpoint"],"detail":"native reply lost\nreadback retained"}}"#
                )
            );
        }
        let empty = CaptureOutcome {
            points: vec![],
            ..complete.clone()
        };
        assert_eq!(
            json(&empty),
            r#"{"operation_id":"00112233-4455-4677-8899-aabbccddeeff","status":"complete","points":[],"missing":[],"detail":null}"#
        );

        for (status, wire) in [
            (DeleteStatus::Complete, r#""complete""#),
            (DeleteStatus::Partial, r#""partial""#),
            (DeleteStatus::Uncertain, r#""uncertain""#),
        ] {
            assert_eq!(json(&status), wire);
        }
        for (status, wire) in [
            (
                DeletePointStatus::AbsentAfterCommand,
                "absent_after_command",
            ),
            (DeletePointStatus::StillPresent, "still_present"),
            (DeletePointStatus::Changed, "changed"),
            (DeletePointStatus::Uncertain, "uncertain"),
            (DeletePointStatus::NotAttempted, "not_attempted"),
        ] {
            assert_eq!(json(&status), format!(r#""{wire}""#));
            let item = DeletePointOutcome {
                point: point.clone(),
                status,
                command_error: None,
                detail: None,
            };
            assert_eq!(
                json(&item),
                format!(
                    r#"{{"point":{point_json},"status":"{wire}","command_error":null,"detail":null}}"#
                )
            );
        }
        let deleted = DeleteOutcome {
            status: DeleteStatus::Partial,
            points: vec![
                DeletePointOutcome {
                    point: point.clone(),
                    status: DeletePointStatus::AbsentAfterCommand,
                    command_error: Some("lost destroy reply".into()),
                    detail: None,
                },
                DeletePointOutcome {
                    point: point.clone(),
                    status: DeletePointStatus::NotAttempted,
                    command_error: None,
                    detail: Some("exact absence \"remains\" unproven".into()),
                },
            ],
        };
        assert_eq!(
            json(&deleted),
            format!(
                r#"{{"status":"partial","points":[{{"point":{point_json},"status":"absent_after_command","command_error":"lost destroy reply","detail":null}},{{"point":{point_json},"status":"not_attempted","command_error":null,"detail":"exact absence \"remains\" unproven"}}]}}"#
            )
        );
        let nothing = DeleteOutcome {
            status: DeleteStatus::Complete,
            points: vec![],
        };
        assert_eq!(json(&nothing), r#"{"status":"complete","points":[]}"#);
    }

    /// The same bytes through the engine's capture and delete paths.
    #[test]
    fn executed_outcome_json_bytes_are_pinned() {
        let created = r#"{"name":"tank/data@checkpoint","dataset_guid":"2","identity":{"pool_guid":"1","guid":"102","createtxg":"99","objsetid":"202"}}"#;
        let targets = targets();
        let scope = admit_state(&targets, &fixture()).unwrap();
        for (mode, tail) in [
            (CaptureMode::Complete, r#""missing":[],"detail":null}"#),
            (
                CaptureMode::LostReply,
                r#""missing":[],"detail":"inconsistent ZFS observation: lost native reply"}"#,
            ),
        ] {
            let (outcome, _) = capture_fake(
                &targets,
                &scope,
                Fake {
                    mode,
                    ..Fake::default()
                },
            );
            assert_eq!(
                serde_json::to_string(&outcome).unwrap(),
                format!(
                    r#"{{"operation_id":"00112233-4455-4677-8899-aabbccddeeff","status":"complete","points":[{created}],{tail}"#
                )
            );
        }

        let point = |name: &str, guid: u64, objsetid: u64| {
            format!(
                r#"{{"name":"{name}","dataset_guid":"2","identity":{{"pool_guid":"1","guid":"{guid}","createtxg":"99","objsetid":"{objsetid}"}}}}"#
            )
        };
        let (a, b) = (
            point("tank/data@a", 102, 202),
            point("tank/data@b", 102, 202),
        );
        for (mode, expected) in [
            (
                0,
                format!(
                    r#"{{"status":"complete","points":[{{"point":{a},"status":"absent_after_command","command_error":"inconsistent ZFS observation: lost destroy reply","detail":null}},{{"point":{b},"status":"absent_after_command","command_error":"inconsistent ZFS observation: lost destroy reply","detail":null}}]}}"#
                ),
            ),
            (
                1,
                format!(
                    r#"{{"status":"partial","points":[{{"point":{a},"status":"still_present","command_error":null,"detail":"snapshot still present after destroy command"}},{{"point":{b},"status":"not_attempted","command_error":null,"detail":"stopped after an incomplete or uncertain deletion"}}]}}"#
                ),
            ),
        ] {
            let mut fake = delete_fixture();
            let points: Vec<_> = fake
                .state
                .inspection
                .snapshots
                .as_ref()
                .unwrap()
                .iter()
                .map(Snapshot::point)
                .collect();
            let plan = delete::plan_snapshots_with(&points, &mut fake).unwrap();
            fake.fail_destroy_reply = mode == 0;
            fake.missing_after_destroy = mode != 1;
            let mut guard = || Ok(());
            let mut adapter = Guarded {
                backend: fake,
                targets: &targets,
                scope: &scope,
                guard: &mut guard,
            };
            let outcome: DeleteOutcome =
                delete::execute_snapshot_delete_with(&plan, plan.loss_token(), &mut adapter)
                    .unwrap();
            assert_eq!(serde_json::to_string(&outcome).unwrap(), expected);
        }
    }

    fn identity(id: u64) -> DatasetIdentity {
        DatasetIdentity {
            pool_guid: Guid::new(1),
            guid: Guid::new(id),
            createtxg: Txg::new(id + 10),
            objsetid: ObjsetId::new(id + 20),
        }
    }
    fn dataset(name: &str, id: u64) -> Dataset {
        Dataset {
            name: name.into(),
            kind: DatasetKind::Filesystem,
            guid: Guid::new(id),
            identity: identity(id),
            used_bytes: 0,
            available_bytes: 1000,
            referenced_bytes: 0,
            mountpoint: Some(format!("/{name}")),
            volume_size_bytes: None,
            mounted: Some(false),
            readonly: false,
            canmount: Some(CanMount::On),
            origin: None,
            encryption: Encryption::Off,
            keystatus: KeyStatus::Unencrypted,
            encryptionroot: None,
            staging: None,
            pending: None,
        }
    }
    fn property(value: impl ToString) -> NativeProperty {
        NativeProperty {
            value: value.to_string(),
            source: "-".into(),
        }
    }
    fn fixture() -> state::NativeState {
        let datasets = vec![
            dataset("tank", 1),
            dataset("tank/data", 2),
            dataset("tank/data/child", 3),
            dataset("tank/volume", 4),
        ];
        let dataset_properties = datasets
            .iter()
            .map(|dataset| {
                (
                    dataset.name.clone(),
                    BTreeMap::from([
                        ("guid".into(), property(dataset.identity.guid)),
                        ("createtxg".into(), property(dataset.identity.createtxg)),
                        ("objsetid".into(), property(dataset.identity.objsetid)),
                    ]),
                )
            })
            .collect();
        state::NativeState {
            inspection: Inspection {
                schema_version: 3,
                imported_only: true,
                non_atomic: true,
                recursive: true,
                requested_datasets: vec![],
                pools: vec![Pool {
                    name: "tank".into(),
                    guid: Guid::new(1),
                    size_bytes: 1000,
                    allocated_bytes: 0,
                    free_bytes: 1000,
                    health: "ONLINE".into(),
                    bootfs: None,
                }],
                datasets,
                snapshots: Some(vec![]),
            },
            dataset_properties,
            pool_properties: PropertyInventory::from([(
                "tank".into(),
                BTreeMap::from([("guid".into(), property(1))]),
            )]),
        }
    }
    fn targets() -> Vec<DatasetTarget> {
        vec![DatasetTarget::new("tank/data", identity(2)).unwrap()]
    }
    fn snapshot(name: &str, dataset_guid: Guid) -> Snapshot {
        Snapshot {
            name: name.into(),
            guid: Guid::new(dataset_guid.get() + 100),
            dataset_guid,
            identity: SnapshotIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(dataset_guid.get() + 100),
                createtxg: Txg::new(99),
                objsetid: ObjsetId::new(dataset_guid.get() + 200),
            },
            userrefs: 0,
            defer_destroy: false,
            clones: vec![],
            holds: vec![],
            creation_epoch_seconds: 1,
            used_bytes: 0,
            referenced_bytes: 0,
        }
    }
    #[derive(Default)]
    enum CaptureMode {
        #[default]
        Complete,
        Partial,
        ForeignMarker,
        LostReply,
        FailedReadback,
    }
    struct Fake {
        state: state::NativeState,
        writes: Vec<String>,
        marker: String,
        mode: CaptureMode,
        missing_after_destroy: bool,
        fail_destroy_reply: bool,
        fail_post_destroy_query: bool,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                state: fixture(),
                writes: vec![],
                marker: String::new(),
                mode: CaptureMode::Complete,
                missing_after_destroy: true,
                fail_destroy_reply: false,
                fail_post_destroy_query: false,
            }
        }
    }
    impl capture::CaptureBackend for Fake {
        fn observe(&mut self) -> Result<state::NativeState, engine::Error> {
            if !self.writes.is_empty() && matches!(self.mode, CaptureMode::FailedReadback) {
                return Err(engine::Error::Inconsistent("readback unavailable".into()));
            }
            Ok(self.state.clone())
        }
        fn snapshot(&mut self, names: &[String], operation_id: &str) -> Result<(), engine::Error> {
            self.writes.extend_from_slice(names);
            self.marker = operation_id.into();
            for (index, name) in names.iter().enumerate() {
                if index > 0 && matches!(self.mode, CaptureMode::Partial) {
                    continue;
                }
                let parent = name.split_once('@').unwrap().0;
                let dataset = self
                    .state
                    .inspection
                    .datasets
                    .iter()
                    .find(|dataset| dataset.name == parent)
                    .unwrap();
                self.state
                    .inspection
                    .snapshots
                    .as_mut()
                    .unwrap()
                    .push(snapshot(name, dataset.guid));
            }
            if matches!(self.mode, CaptureMode::LostReply) {
                Err(engine::Error::Inconsistent("lost native reply".into()))
            } else {
                Ok(())
            }
        }
        fn capture_marker(&mut self, _: &SnapshotRef) -> Result<String, engine::Error> {
            Ok(if matches!(self.mode, CaptureMode::ForeignMarker) {
                "foreign".into()
            } else {
                self.marker.clone()
            })
        }
    }
    impl delete::DeleteBackend for Fake {
        fn observe(&mut self) -> Result<state::NativeState, engine::Error> {
            Ok(self.state.clone())
        }
        fn observe_point(&mut self, point: &SnapshotRef) -> Result<Snapshot, engine::Error> {
            if !self.writes.is_empty() && self.fail_post_destroy_query {
                return Err(engine::Error::Command {
                    program: "zfs",
                    args: vec![],
                    detail: "query unavailable".into(),
                });
            }
            self.state
                .inspection
                .snapshots
                .as_ref()
                .unwrap()
                .iter()
                .find(|snapshot| snapshot.name == point.name)
                .cloned()
                .ok_or_else(|| engine::Error::NotFound(point.name.clone()))
        }
        fn destroy(&mut self, name: &str) -> Result<(), engine::Error> {
            self.writes.push(name.into());
            if self.missing_after_destroy {
                self.state
                    .inspection
                    .snapshots
                    .as_mut()
                    .unwrap()
                    .retain(|snapshot| snapshot.name != name);
            }
            if self.fail_destroy_reply {
                Err(engine::Error::Inconsistent("lost destroy reply".into()))
            } else {
                Ok(())
            }
        }
    }
    fn capture_fake(
        targets: &[DatasetTarget],
        scope: &SnapshotScope,
        fake: Fake,
    ) -> (CaptureOutcome, Fake) {
        let mut guard = || Ok(());
        let mut adapter = Guarded {
            backend: fake,
            targets,
            scope,
            guard: &mut guard,
        };
        let outcome = capture::capture_prepared_with(
            scope,
            "checkpoint",
            "00112233-4455-4677-8899-aabbccddeeff",
            &mut adapter,
        )
        .unwrap();
        (outcome, adapter.backend)
    }

    #[test]
    fn exact_identity_and_kind_admission_includes_volumes() {
        let targets = targets();
        let observed = fixture();
        let scope = admit_state(&targets, &observed).unwrap();
        assert_eq!(scope.datasets().len(), 1);
        assert_eq!(scope.datasets()[0].name, "tank/data");
        for field in 0..4 {
            let mut changed = observed.clone();
            let id = &mut changed.inspection.datasets[1].identity;
            match field {
                0 => id.pool_guid = Guid::new(900),
                1 => id.guid = Guid::new(900),
                2 => id.createtxg = Txg::new(900),
                _ => id.objsetid = ObjsetId::new(900),
            }
            assert!(admit_state(&targets, &changed).is_err());
        }
        let mut volume = observed;
        volume.inspection.datasets[3].kind = DatasetKind::Volume;
        volume.inspection.datasets[3].mountpoint = None;
        volume.inspection.datasets[3].mounted = None;
        volume.inspection.datasets[3].canmount = None;
        volume.inspection.datasets[3].volume_size_bytes = Some(1000);
        let target = DatasetTarget::new("tank/volume", identity(4))
            .unwrap()
            .requiring_kind(DatasetKind::Volume);
        assert!(admit_state(std::slice::from_ref(&target), &volume).is_ok());
        assert!(admit_state(&[target.requiring_kind(DatasetKind::Filesystem)], &volume).is_err());
        assert!(validate_targets(&[]).is_err());
        assert!(validate_targets(&[targets[0].clone(), targets[0].clone()]).is_err());
    }

    #[test]
    fn capture_rechecks_identity_kind_and_management_before_effect() {
        let targets = targets();
        let scope = admit_state(&targets, &fixture()).unwrap();
        for drift in 0..3 {
            let mut fake = Fake::default();
            match drift {
                0 => fake.state.inspection.datasets[1].identity.objsetid = ObjsetId::new(999),
                1 => fake.state.inspection.datasets[1].pending = Some("foreign".into()),
                _ => fake.state.inspection.datasets[1].kind = DatasetKind::Volume,
            }
            let required = [targets[0].clone().requiring_kind(DatasetKind::Filesystem)];
            let mut guard = || Ok(());
            let mut adapter = Guarded {
                backend: fake,
                targets: &required,
                scope: &scope,
                guard: &mut guard,
            };
            assert!(
                capture::capture_prepared_with(
                    &scope,
                    "checkpoint",
                    "00112233-4455-4677-8899-aabbccddeeff",
                    &mut adapter
                )
                .is_err()
            );
            assert!(adapter.backend.writes.is_empty());
        }
    }

    #[test]
    fn lifecycle_guard_runs_immediately_before_effect_and_during_readback() {
        let targets = targets();
        let scope = admit_state(&targets, &fixture()).unwrap();
        for refusal in [2, 3] {
            let mut checks = 0;
            let mut guard = || {
                checks += 1;
                if checks == refusal {
                    Err(Error::new("lifecycle changed"))
                } else {
                    Ok(())
                }
            };
            let mut adapter = Guarded {
                backend: Fake::default(),
                targets: &targets,
                scope: &scope,
                guard: &mut guard,
            };
            let outcome = capture::capture_prepared_with(
                &scope,
                "checkpoint",
                "00112233-4455-4677-8899-aabbccddeeff",
                &mut adapter,
            )
            .unwrap();
            if refusal == 2 {
                assert!(adapter.backend.writes.is_empty());
                assert_eq!(outcome.status(), CaptureStatus::Partial);
            } else {
                assert_eq!(adapter.backend.writes.len(), 1);
                assert_eq!(outcome.status(), CaptureStatus::Uncertain);
            }
            assert!(outcome.detail().unwrap().contains("lifecycle changed"));
        }
    }

    #[test]
    fn capture_outcomes_preserve_partial_uncertain_and_lost_reply_evidence() {
        let targets = vec![
            targets()[0].clone(),
            DatasetTarget::new("tank/volume", identity(4)).unwrap(),
        ];
        let scope = admit_state(&targets, &fixture()).unwrap();
        for mode in [
            CaptureMode::Complete,
            CaptureMode::Partial,
            CaptureMode::ForeignMarker,
            CaptureMode::LostReply,
            CaptureMode::FailedReadback,
        ] {
            let expected = match mode {
                CaptureMode::Partial => CaptureStatus::Partial,
                CaptureMode::ForeignMarker | CaptureMode::FailedReadback => {
                    CaptureStatus::Uncertain
                }
                _ => CaptureStatus::Complete,
            };
            let lost_reply = matches!(mode, CaptureMode::LostReply);
            let (outcome, fake) = capture_fake(
                &targets,
                &scope,
                Fake {
                    mode,
                    ..Fake::default()
                },
            );
            assert_eq!(outcome.status(), expected);
            assert_eq!(
                fake.writes,
                ["tank/data@checkpoint", "tank/volume@checkpoint"]
            );
            if lost_reply {
                assert!(outcome.detail().unwrap().contains("lost native reply"));
            }
            assert_eq!(
                outcome.operation_id(),
                "00112233-4455-4677-8899-aabbccddeeff"
            );
        }
    }

    fn delete_fixture() -> Fake {
        let mut fake = Fake::default();
        fake.state.inspection.snapshots.as_mut().unwrap().extend([
            snapshot("tank/data@a", Guid::new(2)),
            snapshot("tank/data@b", Guid::new(2)),
        ]);
        fake
    }
    #[test]
    fn delete_review_refuses_protection_stale_points_and_outside_members() {
        let targets = targets();
        let scope = admit_state(&targets, &fixture()).unwrap();
        for protection in 0..4 {
            let mut fake = delete_fixture();
            let points = [fake.state.inspection.snapshots.as_ref().unwrap()[0].point()];
            let snapshot = &mut fake.state.inspection.snapshots.as_mut().unwrap()[0];
            match protection {
                0 => snapshot.holds.push("foreign:hold".into()),
                1 => snapshot.userrefs = 1,
                2 => snapshot.clones.push("tank/clone".into()),
                _ => snapshot.defer_destroy = true,
            }
            let mut guard = || Ok(());
            let mut adapter = Guarded {
                backend: fake,
                targets: &targets,
                scope: &scope,
                guard: &mut guard,
            };
            assert!(delete::plan_snapshots_with(&points, &mut adapter).is_err());
            assert!(adapter.backend.writes.is_empty());
        }
        let mut fake = delete_fixture();
        let mut point = fake.state.inspection.snapshots.as_ref().unwrap()[0].point();
        assert!(bind_points(&targets, std::slice::from_ref(&point)).is_ok());
        point.name = "tank/data/child@a".into();
        assert!(bind_points(&targets, &[point]).is_err());
        let points = [fake.state.inspection.snapshots.as_ref().unwrap()[0].point()];
        let plan = delete::plan_snapshots_with(&points, &mut fake).unwrap();
        fake.state.inspection.snapshots.as_mut().unwrap()[0]
            .identity
            .objsetid = ObjsetId::new(999);
        let mut guard = || Ok(());
        let mut adapter = Guarded {
            backend: fake,
            targets: &targets,
            scope: &scope,
            guard: &mut guard,
        };
        assert!(
            delete::execute_snapshot_delete_with(&plan, plan.loss_token(), &mut adapter).is_err()
        );
        assert!(adapter.backend.writes.is_empty());
    }

    #[test]
    fn deletion_rechecks_new_protections_after_review_before_any_destroy() {
        let targets = targets();
        let scope = admit_state(&targets, &fixture()).unwrap();
        for protection in 0..4 {
            let mut fake = delete_fixture();
            let points = [fake.state.inspection.snapshots.as_ref().unwrap()[0].point()];
            let plan = delete::plan_snapshots_with(&points, &mut fake).unwrap();
            let snapshot = &mut fake.state.inspection.snapshots.as_mut().unwrap()[0];
            match protection {
                0 => snapshot.holds.push("late:foreign".into()),
                1 => snapshot.userrefs = 1,
                2 => snapshot.clones.push("tank/late-clone".into()),
                _ => snapshot.defer_destroy = true,
            }
            let mut guard = || Ok(());
            let mut adapter = Guarded {
                backend: fake,
                targets: &targets,
                scope: &scope,
                guard: &mut guard,
            };
            assert!(
                delete::execute_snapshot_delete_with(&plan, plan.loss_token(), &mut adapter)
                    .is_err()
            );
            assert!(adapter.backend.writes.is_empty());
        }
    }

    #[test]
    fn deletion_retains_reply_failure_and_stops_after_uncertain_or_partial_effect() {
        let targets = targets();
        let scope = admit_state(&targets, &fixture()).unwrap();
        for mode in 0..3 {
            let mut fake = delete_fixture();
            let points: Vec<_> = fake
                .state
                .inspection
                .snapshots
                .as_ref()
                .unwrap()
                .iter()
                .map(Snapshot::point)
                .collect();
            let plan = delete::plan_snapshots_with(&points, &mut fake).unwrap();
            fake.fail_destroy_reply = mode == 0;
            fake.missing_after_destroy = mode != 1;
            fake.fail_post_destroy_query = mode == 2;
            let mut guard = || Ok(());
            let mut adapter = Guarded {
                backend: fake,
                targets: &targets,
                scope: &scope,
                guard: &mut guard,
            };
            assert!(
                delete::execute_snapshot_delete_with(&plan, "stale-token", &mut adapter).is_err()
            );
            assert!(adapter.backend.writes.is_empty());
            let outcome: DeleteOutcome =
                delete::execute_snapshot_delete_with(&plan, plan.loss_token(), &mut adapter)
                    .unwrap();
            assert_eq!(
                outcome.status(),
                match mode {
                    0 => DeleteStatus::Complete,
                    1 => DeleteStatus::Partial,
                    _ => DeleteStatus::Uncertain,
                }
            );
            if mode == 0 {
                assert_eq!(adapter.backend.writes.len(), 2);
                assert_eq!(
                    outcome.points()[0].status(),
                    DeletePointStatus::AbsentAfterCommand
                );
                assert!(
                    outcome.points()[0]
                        .command_error()
                        .unwrap()
                        .contains("lost destroy reply")
                );
            } else {
                assert_eq!(adapter.backend.writes.len(), 1);
                assert_eq!(
                    outcome.points()[1].status(),
                    DeletePointStatus::NotAttempted
                );
            }
        }
    }
}
