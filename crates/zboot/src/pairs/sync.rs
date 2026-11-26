//! `sync DATASET | SRC DEST | --all` on the `transfer` engine.
//! The intent record on the source's pool holds the transfer's progress, a
//! bootstrap's nested pair phases included, and names the destination's
//! pool, so `zboot resume` finds an interrupted sync by one ID; the
//! transfer's frozen plan, and a bootstrap's pair plan, are attachments on
//! the source.
//!
//! Around the transfer, from native state alone ([`super::prune`]): before
//! it, the reviewed pending deletions are deleted and common snapshots get
//! the working copy's names; after it, zboot's own older boundary snapshots
//! go. The plan lists the pending deletions, so its token binds them.
use super::{
    Backend, Journal, Recorded, Transferring, local_record, new_id, peer_status, pool_of,
    prune::{self, Cleanup, Kept, Pending, Prepared, Renamed},
    refuse,
};
use crate::{
    pairs::plan::PairBackend,
    transfer::{self, NativeTransfer, Phase, TransferOutcome, TransferProgress, TransferRequest},
};
use serde::{Deserialize, Serialize};
use zfs_tools::engine::{
    Error, Guid, SnapshotRef, attachment, intent,
    management::{self, Endpoint, Role},
    state::NativeState,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SyncTarget {
    /// The pair rooted at this dataset, from its working copy.
    Pair(String),
    Between {
        source: String,
        destination: String,
    },
    All,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncResult {
    #[serde(flatten)]
    pub transfer: TransferOutcome,
    /// Set when DEST was absent: it was created and paired with SRC.
    pub bootstrapped: Option<String>,
    /// Common snapshots renamed on the copy to the working copy's names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub renamed: Vec<Renamed>,
    /// Reviewed pending deletions deleted before the transfer.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<SnapshotRef>,
    /// Reviewed pending deletions that stay, with the reason.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kept: Vec<Kept>,
    /// Pending deletions still on the copy after this sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    /// zboot's own older boundary snapshots, deleted after the transfer.
    #[serde(skip_serializing_if = "Cleanup::is_empty")]
    pub boundaries: Cleanup,
}
#[derive(Debug, Clone, Serialize)]
pub struct SyncEntry {
    pub source: String,
    pub destination: String,
    pub result: Option<SyncResult>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SyncAll {
    pub pairs: Vec<SyncEntry>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SyncState {
    source: String,
    destination: String,
    /// The destination did not exist; this sync creates and pairs it.
    bootstrap: bool,
    /// The source's incarnation, which holds the transfer's attachments.
    origin: Endpoint,
    /// The GUID of the destination's pool, which a UKI resume reopens.
    destination_pool: Guid,
    /// The transfer's progress, from its commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transfer: Option<TransferProgress>,
}
impl Recorded for SyncState {
    fn pool(&self) -> String {
        pool_of(&self.source).into()
    }
}
impl Transferring for SyncState {
    fn holder(&self) -> &Endpoint {
        &self.origin
    }
    fn transfer(&self) -> Option<&TransferProgress> {
        self.transfer.as_ref()
    }
    fn set_transfer(&mut self, transfer: Option<TransferProgress>) {
        self.transfer = transfer;
    }
}

/// The direction `sync DATASET` uses: from the pair's working copy.
pub fn direction(state: &NativeState, dataset: &str) -> Result<TransferRequest, Error> {
    let record = local_record(state, dataset)?.ok_or_else(|| {
        refuse(format!(
            "{dataset} is not a pair root; name both sides with `sync SRC DEST`"
        ))
    })?;
    if peer_status(state, &record) != super::PeerStatus::Mutual {
        return Err(refuse(format!(
            "{dataset}'s peer {} is not available as its mutual peer",
            record.peer.name
        )));
    }
    management::ownership(state, dataset)?;
    let (source, destination) = match record.role {
        Role::Primary => (record.endpoint.name, record.peer.name),
        Role::Secondary => (record.peer.name, record.endpoint.name),
    };
    Ok(TransferRequest {
        source,
        destination,
    })
}
/// Every mutual pair, primary first.
pub fn all_pairs(state: &NativeState) -> Vec<TransferRequest> {
    let mut pairs = Vec::new();
    for name in super::link::pair_roots(state) {
        if let Ok(Some(record)) = local_record(state, &name)
            && record.role == Role::Primary
        {
            pairs.push(TransferRequest {
                source: record.endpoint.name,
                destination: record.peer.name,
            });
        }
    }
    pairs
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncPlan {
    pub target: SyncTarget,
    pub entries: Vec<SyncAdmission>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncAdmission {
    pub source: String,
    pub destination: String,
    pub admitted: Option<transfer::Admission>,
    pub error: Option<String>,
    /// Snapshots only on the copy that the working copy no longer has. The
    /// sync deletes them only when this plan was confirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
}
impl SyncPlan {
    /// What the token binds: everything but the space each pending deletion
    /// holds now, which changes without changing what is consented to.
    fn bound(&self) -> Self {
        let mut plan = self.clone();
        for snapshot in plan
            .entries
            .iter_mut()
            .filter_map(|e| e.pending.as_mut())
            .flat_map(|p| &mut p.snapshots)
        {
            snapshot.used_bytes = 0;
        }
        plan
    }
    /// The consent token: the copies' identities and every pending
    /// deletion's name, GUID and creation txg are part of it.
    pub fn token(&self) -> std::io::Result<String> {
        crate::consent::token(&self.bound())
    }
    /// What the operator types to delete every pending deletion in the plan:
    /// `3 snapshots on bpool/data`, or `5 snapshots on 2 copies`. None when
    /// there are none.
    pub fn summary(&self) -> Option<String> {
        let pending: Vec<&Pending> = self
            .entries
            .iter()
            .filter_map(|e| e.pending.as_ref())
            .collect();
        let count: usize = pending.iter().map(|p| p.snapshots.len()).sum();
        let snapshots = if count == 1 { "snapshot" } else { "snapshots" };
        match pending.as_slice() {
            [] => None,
            [one] => Some(format!("{count} {snapshots} on {}", one.copy.name)),
            many => Some(format!("{count} {snapshots} on {} copies", many.len())),
        }
    }
}

fn requests(target: &SyncTarget, state: &NativeState) -> Result<Vec<TransferRequest>, Error> {
    match target {
        SyncTarget::Pair(dataset) => Ok(vec![direction(state, dataset)?]),
        SyncTarget::Between {
            source,
            destination,
        } => Ok(vec![TransferRequest {
            source: source.clone(),
            destination: destination.clone(),
        }]),
        SyncTarget::All => {
            let pairs = all_pairs(state);
            if pairs.is_empty() {
                return Err(refuse("no managed pair is imported"));
            }
            Ok(pairs)
        }
    }
}

pub fn sync_plan(target: &SyncTarget) -> Result<SyncPlan, Error> {
    sync_plan_with(target, &mut NativeTransfer::new())
}
pub fn sync_plan_with(target: &SyncTarget, backend: &mut impl Backend) -> Result<SyncPlan, Error> {
    let state = PairBackend::observe(backend)?;
    let mut entries = Vec::new();
    for request in requests(target, &state)? {
        let admitted = transfer::admission_with(&request, backend).and_then(|admission| {
            let pending = match admission.destination {
                transfer::Destination::Existing { .. } => {
                    prune::pending(&state, &request.source, &request.destination)?
                }
                transfer::Destination::Absent { .. } => None,
            };
            Ok((admission, pending))
        });
        let admitted = if *target == SyncTarget::All {
            admitted
        } else {
            Ok(admitted?)
        };
        let (admitted, pending, error) = match admitted {
            Ok((admission, pending)) => (Some(admission), pending, None),
            Err(error) => (None, None, Some(error.to_string())),
        };
        entries.push(SyncAdmission {
            source: request.source,
            destination: request.destination,
            admitted,
            error,
            pending,
        });
    }
    Ok(SyncPlan {
        target: target.clone(),
        entries,
    })
}

/// Run `plan`. With `delete` (the plan was confirmed: typed or by token) each
/// pair first deletes exactly the pending deletions the plan lists; without
/// it nothing is deleted and they are reported again.
pub fn sync_prepared(plan: &SyncPlan, delete: bool) -> Result<Vec<SyncEntry>, Error> {
    sync_prepared_with(plan, delete, &mut NativeTransfer::new())
}
pub fn sync_prepared_with(
    plan: &SyncPlan,
    delete: bool,
    backend: &mut impl Backend,
) -> Result<Vec<SyncEntry>, Error> {
    if sync_plan_with(&plan.target, backend)?.bound() != plan.bound() {
        return Err(refuse("the sync plan changed; preview it again"));
    }
    let mut entries = Vec::new();
    for entry in &plan.entries {
        let request = TransferRequest {
            source: entry.source.clone(),
            destination: entry.destination.clone(),
        };
        let reviewed = match (&entry.pending, delete) {
            (Some(pending), true) => pending.points(),
            _ => Vec::new(),
        };
        let result = match &entry.admitted {
            Some(admitted) => (|| {
                if transfer::admission_with(&request, backend)? != *admitted {
                    return Err(refuse(
                        "the sync endpoint changed before its operation began",
                    ));
                }
                sync_one(&request, &new_id(), &reviewed, backend)
            })(),
            None => Err(refuse(
                entry.error.as_deref().unwrap_or("sync was not admitted"),
            )),
        };
        let result = if plan.target == SyncTarget::All {
            result
        } else {
            Ok(result?)
        };
        entries.push(SyncEntry {
            source: entry.source.clone(),
            destination: entry.destination.clone(),
            error: result.as_ref().err().map(ToString::to_string),
            result: result.ok(),
        });
    }
    Ok(entries)
}

/// One entry per pair synced; `Pair` and `Between` refuse instead of
/// returning a failed entry.
#[cfg(test)]
pub fn sync_with(target: &SyncTarget, b: &mut impl Backend) -> Result<Vec<SyncEntry>, Error> {
    let state = PairBackend::observe(b)?;
    let requests = requests(target, &state)?;
    let single = !matches!(target, SyncTarget::All);
    let mut entries = Vec::new();
    for request in requests {
        let result = sync_one(&request, &new_id(), &[], b);
        let result = if single { Ok(result?) } else { result };
        entries.push(SyncEntry {
            source: request.source.clone(),
            destination: request.destination.clone(),
            error: result.as_ref().err().map(|e| e.to_string()),
            result: result.ok(),
        });
    }
    Ok(entries)
}
/// Sync one direction under operation `id`, which is also the transfer's ID.
/// REVIEWED are the pending deletions the operator confirmed; each is deleted
/// first while it is still exactly that snapshot and may go.
pub(crate) fn sync_one(
    request: &TransferRequest,
    id: &str,
    reviewed: &[SnapshotRef],
    b: &mut impl Backend,
) -> Result<SyncResult, Error> {
    let state = PairBackend::observe(b)?;
    let bootstrap = !state
        .inspection
        .datasets
        .iter()
        .any(|d| d.name == request.destination);
    transfer::admit_with(request, b).map_err(|e| {
        let text = e.to_string();
        if bootstrap
            || !(text.contains("destination is ahead")
                || text.contains("both sides have newer snapshots")
                || text.contains("receiving head has unreviewed changes"))
        {
            e
        } else {
            // `rollback` refuses a pair member, so it is no way out here.
            let (source, destination) = (
                zfs_tools::engine::escape_display(&request.source),
                zfs_tools::engine::escape_display(&request.destination),
            );
            refuse(format!(
                "{e}; sync never overwrites the receiver's history: `zboot primary {destination}` \
                 keeps {destination}'s side; to keep {source}'s, remove by hand what only \
                 {destination} has after their last common snapshot (`zfs destroy` its newer \
                 snapshots, `zfs rollback` its unsnapshotted changes), then sync again"
            ))
        }
    })?;
    // Both pools are written; a read-only one would leave a record its
    // resume could not finish, and that a Menu resume would not reopen.
    for name in [&request.source, &request.destination] {
        crate::pairs::plan::writable_pool_of(&state, name)?;
    }
    // The pool's operation slot is checked before the first effect, as
    // `Journal::begin` checks it again.
    let pool = pool_of(&request.source);
    if intent::Backend::read(b, pool)?.is_some() {
        return Err(refuse(format!(
            "pool {pool} already records an operation; resume or abandon it first"
        )));
    }
    let destination_pool = pool_of(&request.destination);
    let s = SyncState {
        source: request.source.clone(),
        destination: request.destination.clone(),
        bootstrap,
        origin: super::endpoint(&state, &request.source)?,
        destination_pool: state
            .inspection
            .pools
            .iter()
            .find(|p| p.name == destination_pool)
            .map(|p| p.guid)
            .ok_or_else(|| refuse(format!("pool {destination_pool} is not imported")))?,
        transfer: None,
    };
    // The record stays at step 0 and grows only as the transfer records its
    // progress: at its widest it must fit before the renames and deletions
    // below.
    intent::encode(&intent::Intent::new(id, "sync", widest(&s, id)?))?;
    // Before the plan, from native state and outside the record: a cut
    // leaves only finished renames and deletions; the rest is shown again.
    let prepared = if bootstrap {
        Prepared::default()
    } else {
        prune::prepare(b, &request.source, &request.destination, reviewed)?
    };
    let mut journal = Journal::begin(b, id, "sync", s)?;
    let outcome =
        transfer::transfer_with_id(request, &mut journal, b).map_err(|e| interrupted(id, e))?;
    finish(b, journal, outcome, prepared)
}
/// S as it records its transfer at the widest.
fn widest(s: &SyncState, id: &str) -> Result<SyncState, Error> {
    Ok(SyncState {
        transfer: Some(transfer::widest(
            id,
            &s.origin.name,
            &s.destination,
            s.bootstrap,
        )?),
        ..s.clone()
    })
}
/// What an abandoned bootstrap left, as its record names it: its new copy
/// or the receive container, found again by its incarnation. An existing
/// copy stays where it is.
fn left_behind(state: &NativeState, s: &SyncState) -> Option<String> {
    let left = s.transfer.as_ref()?.left.as_ref()?;
    state
        .inspection
        .datasets
        .iter()
        .find(|d| d.identity == left.identity)
        .map(|d| d.name.clone())
}
fn interrupted(id: &str, e: Error) -> Error {
    zfs_tools::engine::effect::operation_hint(id);
    refuse(format!("sync operation {id} was interrupted: {e}"))
}
fn finish(
    b: &mut impl Backend,
    journal: Journal<SyncState>,
    mut transfer: TransferOutcome,
    prepared: Prepared,
) -> Result<SyncResult, Error> {
    let s = journal.intent.state.clone();
    // Resumed at Released, the transfer no longer reads its plan; a
    // bootstrap's pair id is derived from the operation's.
    if s.bootstrap && transfer.pair_id.is_none() {
        transfer.pair_id = Some(transfer::bootstrap_pair_id(journal.id()));
    }
    // The transfer is verified: zboot's own older boundary snapshots go.
    // Still inside the record, so a cut here is resumed and cleaned again.
    let id = journal.id().to_string();
    let boundaries =
        prune::clean_boundaries(b, &s.source, &s.destination).map_err(|e| interrupted(&id, e))?;
    let pending = prune::pending(&PairBackend::observe(b)?, &s.source, &s.destination)
        .map_err(|e| interrupted(&id, e))?;
    // The transfer completed: the sync is done.
    journal.finish(b)?;
    Ok(SyncResult {
        bootstrapped: if s.bootstrap {
            transfer.pair_id.clone()
        } else {
            None
        },
        transfer,
        renamed: prepared.renamed,
        deleted: prepared.deleted,
        kept: prepared.kept,
        pending,
        boundaries,
    })
}
/// The source of sync `id` is not imported as recorded. Renamed or replaced
/// at its name, it is brought back first. Gone, nothing tells how far its
/// transfer got: only an abandon goes on, and only while the destination's
/// pool is imported as recorded and no dataset carries a marker or
/// attachment of the sync.
fn source_gone(state: &NativeState, s: &SyncState, id: &str, abandon: bool) -> Result<(), Error> {
    let unchanged = "nothing was changed";
    if let Some(moved) = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.identity == s.origin.identity)
    {
        return Err(refuse(format!(
            "{} is now {}, and only it holds sync {id}'s transfer attachments: rename it back \
             to resume or abandon the sync; {unchanged}",
            s.source, moved.name
        )));
    }
    if state.inspection.datasets.iter().any(|d| d.name == s.source) {
        return Err(refuse(format!(
            "{} is another dataset than the one sync {id} began from; rename it away to \
             abandon the sync; {unchanged}",
            s.source
        )));
    }
    // The destination's pool may carry the sync's markers or its receive
    // container: only with it imported does their absence show.
    let pool = pool_of(&s.destination);
    if !state
        .inspection
        .pools
        .iter()
        .any(|p| p.name == pool && p.guid == s.destination_pool)
    {
        return Err(refuse(format!(
            "{} is gone, and pool {pool} of {}, which may still carry sync {id}'s markers, \
             is not imported as recorded: import it to abandon the sync; {unchanged}",
            s.source, s.destination
        )));
    }
    let attached = format!("{}{id}:", attachment::PREFIX);
    // A bootstrap's nested pair marks both leaves with its own id.
    let ids = [id.to_owned(), transfer::bootstrap_pair_id(id)];
    let marked = state.dataset_properties.iter().find_map(|(name, props)| {
        props
            .iter()
            .find(|(key, p)| {
                p.source == "local"
                    && (key.starts_with(&attached)
                        || (matches!(
                            key.as_str(),
                            management::PENDING_PROPERTY | management::STAGING_PROPERTY
                        ) && ids.contains(&p.value)))
            })
            .map(|(key, _)| (name, key))
    });
    if let Some((name, key)) = marked {
        return Err(refuse(format!(
            "{} is gone, but {name} still carries sync {id}'s {key}; inspect it and remove \
             that with `{}` to abandon the sync; {unchanged}",
            s.source,
            crate::recipe::inherit(key, name)
        )));
    }
    if !abandon {
        return Err(refuse(format!(
            "{} is gone with sync {id}'s transfer attachments; abandon the sync",
            s.source
        )));
    }
    Ok(())
}
pub(crate) fn resume_sync(
    mut journal: Journal<SyncState>,
    abandon: bool,
    dialogue: &mut dyn std::io::Write,
    b: &mut impl Backend,
) -> Result<SyncResult, Error> {
    let s = journal.intent.state.clone();
    let id = journal.id().to_string();
    // Only the source holds the transfer's attachments: a source that is not
    // the recorded incarnation refuses, as nothing else shows them, except
    // for an abandon once the source is gone with every mark of the sync.
    let state = PairBackend::observe(b)?;
    let present = super::endpoint(&state, &s.source).is_ok_and(|source| source == s.origin);
    if !present {
        source_gone(&state, &s, &id, abandon)?;
    }
    let phase = s.transfer.as_ref().map(|t| t.phase);
    if abandon {
        let message = if !present {
            format!(
                "abandoned sync {id}: its source {} is gone, and no dataset carries the sync",
                s.source
            )
        } else if phase.is_some_and(|phase| phase < Phase::Released || phase == Phase::Abandoned) {
            let left = transfer::abandon_between_with(&s.source, &s.destination, &mut journal, b)?;
            // An abandon cut after it recorded its end finds what it left
            // again, since its record names nothing any more.
            let left = if phase == Some(Phase::Abandoned) {
                left_behind(&PairBackend::observe(b)?, &s)
            } else {
                left
            };
            match left {
                Some(left) if left == s.destination => format!(
                    "abandoned sync {id}: the partial new copy {left} stays fenced and unpaired; \
                     pair it with `zboot pair {} {left}` and sync again, or destroy it",
                    s.source
                ),
                Some(container) => format!(
                    "abandoned sync {id}: the partial new copy stays fenced in {container}; \
                     destroy it with `zfs destroy -r {container}`"
                ),
                None if s.bootstrap => {
                    format!("abandoned sync {id}: it leaves no partial new copy")
                }
                None => format!(
                    "abandoned sync {id}: {} stays fenced with the snapshots it received; \
                     the next sync continues from them",
                    s.destination
                ),
            }
        } else {
            transfer::abandon_between_with(&s.source, &s.destination, &mut journal, b)?;
            format!("abandoned sync {id}: no transfer is in progress; snapshots it made stay")
        };
        writeln!(dialogue, "{message}").map_err(|e| refuse(e.to_string()))?;
        let source = s.origin.clone();
        journal.finish(b)?;
        return Ok(SyncResult {
            transfer: TransferOutcome {
                operation_id: id,
                source,
                destination: None,
                status: transfer::TransferStatus::AlreadyComplete,
                pair_id: None,
                completed_operation: None,
                capture: None,
                unmirrored: Vec::new(),
                unapplied: Vec::new(),
            },
            bootstrapped: None,
            renamed: Vec::new(),
            deleted: Vec::new(),
            kept: Vec::new(),
            pending: None,
            boundaries: Cleanup::default(),
        });
    }
    let request = TransferRequest {
        source: s.source.clone(),
        destination: s.destination.clone(),
    };
    let mut prepared = Prepared::default();
    let outcome = match phase {
        // Interrupted before the transfer recorded its plan: drop what that
        // write left and run it again, after the renames it needs. Nothing
        // is deleted without a review.
        None => (|| {
            transfer::discard(&journal, b)?;
            if !s.bootstrap {
                prepared = prune::prepare(b, &s.source, &s.destination, &[])?;
            }
            transfer::transfer_with_id(&request, &mut journal, b)
        })(),
        Some(Phase::Abandoned) => Err(refuse(format!(
            "sync {id}'s transfer was abandoned; abandon the sync to finish"
        ))),
        Some(_) => transfer::resume_between_with(&s.source, &s.destination, &mut journal, b),
    }
    .map_err(|e| interrupted(&id, e))?;
    finish(b, journal, outcome, prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zfs_tools::engine::{DatasetIdentity, ObjsetId, Txg};

    /// A sync record grows only as its transfer records progress. At its
    /// widest, a bootstrap with its plan and pair attachments, 255-byte names
    /// and the largest identities, it fits; `sync_one` checks that bound
    /// before any effect.
    #[test]
    fn a_sync_record_at_its_widest_fits_one_intent() {
        let name = |pool: &str| format!("{pool}/{}", "x".repeat(254 - pool.len()));
        let wide = Guid::new(u64::MAX);
        for bootstrap in [false, true] {
            let state = SyncState {
                source: name("a"),
                destination: name("b"),
                bootstrap,
                origin: Endpoint {
                    name: name("a"),
                    identity: DatasetIdentity {
                        pool_guid: wide,
                        guid: wide,
                        createtxg: Txg::new(u64::MAX),
                        objsetid: ObjsetId::new(u64::MAX),
                    },
                },
                destination_pool: wide,
                transfer: None,
            };
            assert_eq!(state.source.len(), 255);
            let id = new_id();
            let widest = widest(&state, &id).unwrap();
            let progress = widest.transfer.as_ref().unwrap();
            assert_eq!(progress.pair.is_some(), bootstrap);
            assert_eq!(progress.receive.container.is_some(), bootstrap);
            let encoded = intent::encode(&intent::Intent::new(&id, "sync", widest)).unwrap();
            assert!(
                encoded.len() < super::super::RECORD_BUDGET,
                "{bootstrap}: {}",
                encoded.len()
            );
            println!("bootstrap={bootstrap}: {} bytes", encoded.len());
            // Abandoned, it names only what it left: a far smaller record.
            let abandoned = SyncState {
                transfer: Some(TransferProgress {
                    phase: Phase::Abandoned,
                    plan: None,
                    pair: None,
                    pair_phase: None,
                    receive: Default::default(),
                    received: None,
                    left: Some(state.origin.clone()),
                }),
                ..state.clone()
            };
            let encoded = intent::encode(&intent::Intent::new(&id, "sync", abandoned)).unwrap();
            assert!(encoded.len() < 2048, "{bootstrap}: {}", encoded.len());
        }
    }
}
