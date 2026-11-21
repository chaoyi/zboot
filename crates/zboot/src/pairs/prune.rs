//! What a sync does around its transfer on a pair's copy. Before the stream
//! it deletes the reviewed pending deletions that may go and renames common
//! snapshots to the working copy's names; after a verified transfer it
//! deletes zboot's own older boundary snapshots on both sides.
//!
//! Native state is the only record. Every step is planned again from it and
//! is idempotent, so a cut leaves nothing to resume: the next sync renames
//! what is left and shows the remaining pending deletions for a new review.
use super::{Backend, refuse};
use crate::pairs::plan::PairBackend;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use zfs_tools::engine::{
    Error, Guid, Snapshot, SnapshotRef,
    management::{self, Endpoint, Ownership},
    state::NativeState,
};

/// A snapshot only on the copy and older than the pair's anchor: the working
/// copy no longer has it, so after deletion it exists nowhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingDeletion {
    pub snapshot: SnapshotRef,
    pub creation_epoch_seconds: i64,
    /// The space it alone holds now. Shown, never bound by a token.
    pub used_bytes: u64,
    /// Its name is needed by a newer snapshot arriving from the working copy
    /// or by a common snapshot renamed to it: kept, it stops the pair.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub collides: bool,
}

/// The pending deletions of one pair, on its copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pending {
    pub copy: Endpoint,
    pub snapshots: Vec<PendingDeletion>,
}
impl Pending {
    pub fn points(&self) -> Vec<SnapshotRef> {
        self.snapshots.iter().map(|s| s.snapshot.clone()).collect()
    }
}

/// A common snapshot renamed on the copy to the working copy's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Renamed {
    pub from: String,
    pub to: String,
}

/// A snapshot that was to be deleted and stays, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Kept {
    pub snapshot: String,
    pub reason: String,
}

/// What a sync did before its transfer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Prepared {
    pub(crate) renamed: Vec<Renamed>,
    pub(crate) deleted: Vec<SnapshotRef>,
    pub(crate) kept: Vec<Kept>,
}

/// zboot's own older boundary snapshots after a verified transfer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Cleanup {
    /// Deleted, each unmarked side's before the marked side's.
    pub deleted: Vec<String>,
    pub kept: Vec<Kept>,
}
impl Cleanup {
    pub fn is_empty(&self) -> bool {
        self.deleted.is_empty() && self.kept.is_empty()
    }
}

/// How the operator reviews the pending deletions on COPY.
pub fn review_command(copy: &str) -> String {
    format!(
        "`zboot sync {copy}` on a terminal, or `zboot sync {copy} --dry-run` then `--confirm TOKEN`"
    )
}

fn suffix(name: &str) -> &str {
    name.split_once('@').map_or("", |(_, s)| s)
}

/// Both leaves' snapshots in creation order.
struct View<'a> {
    source: Vec<&'a Snapshot>,
    copy: Vec<&'a Snapshot>,
}
impl<'a> View<'a> {
    fn of(state: &'a NativeState, source: &str, copy: &str) -> Result<Self, Error> {
        let all = state
            .inspection
            .snapshots
            .as_ref()
            .ok_or_else(|| refuse("snapshot history was not observed"))?;
        let of = |dataset: &str| {
            let mut found: Vec<&Snapshot> = all
                .iter()
                .filter(|s| {
                    s.name
                        .split_once('@')
                        .is_some_and(|(owner, _)| owner == dataset)
                })
                .collect();
            found.sort_by_key(|s| s.identity.createtxg);
            found
        };
        Ok(Self {
            source: of(source),
            copy: of(copy),
        })
    }
    fn on_source(&self, snapshot: &Snapshot) -> Option<&'a Snapshot> {
        self.source
            .iter()
            .copied()
            .find(|s| s.identity.guid == snapshot.identity.guid)
    }
    /// The newest snapshot both sides have: (the working copy's, the copy's).
    fn anchor(&self) -> Option<(&'a Snapshot, &'a Snapshot)> {
        self.copy
            .iter()
            .rev()
            .find_map(|c| self.on_source(c).map(|s| (s, *c)))
    }
    /// Snapshots only on the copy, older than the anchor.
    fn pending(&self) -> Vec<&'a Snapshot> {
        let Some((_, anchor)) = self.anchor() else {
            return Vec::new();
        };
        self.copy
            .iter()
            .copied()
            .filter(|c| {
                c.identity.createtxg < anchor.identity.createtxg && self.on_source(c).is_none()
            })
            .collect()
    }
    /// Common snapshots the copy names differently, with the working copy's name.
    fn renames(&self) -> Vec<(&'a Snapshot, &'a str)> {
        self.copy
            .iter()
            .filter_map(|c| {
                self.on_source(c)
                    .filter(|s| suffix(&s.name) != suffix(&c.name))
                    .map(|s| (*c, suffix(&s.name)))
            })
            .collect()
    }
    /// Names the copy must be free to take: those of the working copy's
    /// snapshots newer than the anchor, and of renamed common snapshots.
    fn incoming(&self) -> BTreeSet<&'a str> {
        let Some((anchor, _)) = self.anchor() else {
            return BTreeSet::new();
        };
        let mut names: BTreeSet<&str> = self
            .source
            .iter()
            .filter(|s| s.identity.createtxg > anchor.identity.createtxg)
            .map(|s| suffix(&s.name))
            .collect();
        names.extend(self.renames().into_iter().map(|(_, name)| name));
        names
    }
}

/// The pending deletions of the pair SOURCE -> COPY, if any.
pub(crate) fn pending(
    state: &NativeState,
    source: &str,
    copy: &str,
) -> Result<Option<Pending>, Error> {
    let view = View::of(state, source, copy)?;
    let incoming = view.incoming();
    let snapshots: Vec<_> = view
        .pending()
        .into_iter()
        .map(|s| PendingDeletion {
            snapshot: s.point(),
            creation_epoch_seconds: s.creation_epoch_seconds,
            used_bytes: s.used_bytes,
            collides: incoming.contains(suffix(&s.name)),
        })
        .collect();
    if snapshots.is_empty() {
        return Ok(None);
    }
    Ok(Some(Pending {
        copy: super::endpoint(state, copy)?,
        snapshots,
    }))
}

/// Pending deletions on COPY whose names a transfer from SOURCE needs.
pub(crate) fn collisions(
    state: &NativeState,
    source: &str,
    copy: &str,
) -> Result<Vec<String>, Error> {
    Ok(pending(state, source, copy)?
        .map(|p| {
            p.snapshots
                .into_iter()
                .filter(|s| s.collides)
                .map(|s| s.snapshot.name)
                .collect()
        })
        .unwrap_or_default())
}

/// Why a snapshot cannot be deleted now, if it cannot.
fn protected(s: &Snapshot) -> Option<String> {
    if !s.holds.is_empty() {
        Some(format!("it is held ({})", s.holds.join(", ")))
    } else if s.userrefs != 0 {
        Some("it is held".into())
    } else if !s.clones.is_empty() {
        Some(format!("it has a clone ({})", s.clones.join(", ")))
    } else if s.defer_destroy {
        Some("it is marked for deferred destruction".into())
    } else {
        None
    }
}

/// Why no pending deletion of this pair may go now: the anchor must carry
/// the pair's hold on both sides, so deleting older snapshots can never
/// leave the two sides without a common one.
fn anchor_unheld(state: &NativeState, view: &View, source: &str) -> Result<Option<String>, Error> {
    let tag = match management::ownership(state, source)? {
        Ownership::Primary { record } | Ownership::Secondary { record } => {
            format!("zboot:anchor:{}", record.pair_id)
        }
        Ownership::Unpaired => return Ok(Some(format!("{source} is not paired"))),
    };
    let held = view
        .anchor()
        .is_some_and(|(s, c)| s.holds.contains(&tag) && c.holds.contains(&tag));
    Ok((!held).then(|| format!("the anchor's hold {tag} is not on both sides")))
}

/// Destroy one exact snapshot. A failure is judged from native state: gone
/// is done, still there is kept with the reason; an observation that fails
/// stops the sync.
fn destroy(b: &mut impl Backend, point: &SnapshotRef) -> Result<Option<String>, Error> {
    let Err(error) = b.destroy_snapshot(point) else {
        return Ok(None);
    };
    let state = PairBackend::observe(b)?;
    let present = state
        .inspection
        .snapshots
        .as_ref()
        .into_iter()
        .flatten()
        .any(|s| s.name == point.name || s.point() == *point);
    Ok(present.then(|| error.to_string()))
}

/// The renames that give every common snapshot on the copy the working
/// copy's name, in an order that never reuses a name still taken: a swap or
/// longer cycle goes through `zboot_rename_<guid>`. Pure planning.
fn rename_steps(view: &View, deleted: &[SnapshotRef]) -> Result<Vec<(SnapshotRef, String)>, Error> {
    let mut taken: BTreeSet<String> = view
        .copy
        .iter()
        .filter(|c| !deleted.iter().any(|d| *d == c.point()))
        .map(|c| suffix(&c.name).to_owned())
        .collect();
    let reserved: BTreeSet<&str> = view.source.iter().map(|s| suffix(&s.name)).collect();
    let mut todo: Vec<(SnapshotRef, String)> = view
        .renames()
        .into_iter()
        .map(|(c, to)| (c.point(), to.to_owned()))
        .collect();
    let bound = 2 * todo.len() + 1;
    let mut steps: Vec<(SnapshotRef, String)> = Vec::new();
    while !todo.is_empty() {
        if steps.len() > bound {
            return Err(refuse(
                "the copy's snapshot names cannot be matched to the working copy's; inspect both",
            ));
        }
        let (point, to) = match todo.iter().position(|(_, to)| !taken.contains(to)) {
            Some(at) => todo.remove(at),
            None => {
                // Every wanted name is another renamed snapshot's: a cycle.
                let (point, to) = todo.remove(0);
                let temporary = format!("zboot_rename_{}", point.identity.guid);
                if taken.contains(&temporary) || reserved.contains(temporary.as_str()) {
                    return Err(refuse(format!(
                        "temporary snapshot name {temporary} is taken; rename it first"
                    )));
                }
                todo.push((
                    SnapshotRef {
                        name: format!("{}@{temporary}", point.name.split_once('@').unwrap().0),
                        ..point.clone()
                    },
                    to,
                ));
                (point, temporary)
            }
        };
        taken.remove(suffix(&point.name));
        taken.insert(to.clone());
        steps.push((point, to));
    }
    Ok(steps)
}

/// Before a transfer from SOURCE into its pair's copy COPY: delete the
/// REVIEWED pending deletions that may go, then rename common snapshots to
/// SOURCE's names, each step judged from native state. A pending deletion
/// whose name the transfer needs and that stays (unreviewed, held, or cloned)
/// refuses the pair before any effect, naming the review command.
pub(crate) fn prepare(
    b: &mut impl Backend,
    source: &str,
    copy: &str,
    reviewed: &[SnapshotRef],
) -> Result<Prepared, Error> {
    let state = PairBackend::observe(b)?;
    let view = View::of(&state, source, copy)?;
    let incoming = view.incoming();
    let unheld = anchor_unheld(&state, &view, source)?;
    let mut prepared = Prepared::default();
    let mut delete = Vec::new();
    let mut blocked = Vec::new();
    for s in view.pending() {
        let point = s.point();
        let collides = incoming.contains(suffix(&s.name));
        if !reviewed.contains(&point) {
            if collides {
                blocked.push(format!("{} (not reviewed)", s.name));
            }
            continue;
        }
        match protected(s).or_else(|| unheld.clone()) {
            None => delete.push(point),
            Some(reason) => {
                if collides {
                    blocked.push(format!("{} (reviewed, but {reason})", s.name));
                }
                prepared.kept.push(Kept {
                    snapshot: s.name.clone(),
                    reason,
                });
            }
        }
    }
    if !blocked.is_empty() {
        return Err(collision(source, copy, &blocked));
    }
    let steps = rename_steps(&view, &delete)?;
    let renamed: Vec<_> = view
        .renames()
        .into_iter()
        .map(|(c, to)| Renamed {
            from: c.name.clone(),
            to: format!("{copy}@{to}"),
        })
        .collect();
    // Deletion comes first: it frees a name the transfer or a rename needs.
    for point in delete {
        match destroy(b, &point)? {
            None => prepared.deleted.push(point),
            Some(reason) => {
                if incoming.contains(suffix(&point.name)) {
                    return Err(collision(
                        source,
                        copy,
                        &[format!("{} (not deleted: {reason})", point.name)],
                    ));
                }
                prepared.kept.push(Kept {
                    snapshot: point.name,
                    reason,
                });
            }
        }
    }
    for (point, name) in steps {
        b.rename_snapshot(&point, &name)?;
    }
    prepared.renamed = renamed;
    Ok(prepared)
}

fn collision(source: &str, copy: &str, names: &[String]) -> Error {
    refuse(format!(
        "{copy} cannot receive from {source}: {} {} only on {copy} under {} that {source} needs \
         for newer or renamed snapshots. After deletion {} nowhere; review it with {}",
        names.join(", "),
        if names.len() == 1 { "exists" } else { "exist" },
        if names.len() == 1 { "a name" } else { "names" },
        if names.len() == 1 {
            "it exists"
        } else {
            "they exist"
        },
        review_command(copy)
    ))
}

/// zboot's own boundary snapshot names: one per writable sync and one per
/// `primary` catch-up.
fn boundary(name: &str) -> bool {
    if let Some(id) = name.strip_prefix("zboot_transfer_") {
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    } else if let Some(id) = name.strip_prefix("zboot_primary_") {
        super::valid_id(id).is_ok()
    } else {
        false
    }
}

/// After a verified transfer from SOURCE into COPY: delete zboot's own
/// boundary snapshots older than the anchor, on both sides. A snapshot is
/// zboot's only when it has a boundary name and the local `zboot:capture`
/// marker of the side that captured it; after a `primary` switch that side
/// is the copy. The unmarked side is deleted first, so a cut leaves the
/// marked one, which the next sync still recognizes. A held or cloned one on
/// either side keeps both. No review.
pub(crate) fn clean_boundaries(
    b: &mut impl Backend,
    source: &str,
    copy: &str,
) -> Result<Cleanup, Error> {
    let state = PairBackend::observe(b)?;
    let view = View::of(&state, source, copy)?;
    let mut cleanup = Cleanup::default();
    let Some((anchor_source, anchor_copy)) = view.anchor() else {
        return Ok(cleanup);
    };
    let older = |side: &[&'_ Snapshot], anchor: &Snapshot| -> Vec<Snapshot> {
        side.iter()
            .filter(|s| {
                boundary(suffix(&s.name)) && s.identity.createtxg < anchor.identity.createtxg
            })
            .map(|s| (*s).clone())
            .collect()
    };
    // By GUID: the working copy's and the copy's incarnation of one snapshot.
    let mut own: BTreeMap<Guid, (Option<Snapshot>, Option<Snapshot>)> = BTreeMap::new();
    for s in older(&view.source, anchor_source) {
        let guid = s.identity.guid;
        own.entry(guid).or_default().0 = Some(s);
    }
    for c in older(&view.copy, anchor_copy) {
        let guid = c.identity.guid;
        own.entry(guid).or_default().1 = Some(c);
    }
    for (s, c) in own.into_values() {
        let sides: Vec<Snapshot> = [c, s].into_iter().flatten().collect();
        let marked: Vec<bool> = sides
            .iter()
            .map(|side| b.capture_marker(&side.point()).is_ok_and(|m| !m.is_empty()))
            .collect();
        if !marked.contains(&true) {
            continue;
        }
        if let Some((snapshot, reason)) = sides
            .iter()
            .find_map(|side| protected(side).map(|r| (side.name.clone(), r)))
        {
            cleanup.kept.push(Kept { snapshot, reason });
            continue;
        }
        // Unmarked first, the marked one last.
        let mut order: Vec<(Snapshot, bool)> = sides.into_iter().zip(marked).collect();
        order.sort_by_key(|(_, marked)| *marked);
        for (side, _) in order {
            match destroy(b, &side.point())? {
                None => cleanup.deleted.push(side.name.clone()),
                Some(reason) => {
                    cleanup.kept.push(Kept {
                        snapshot: side.name.clone(),
                        reason,
                    });
                    break;
                }
            }
        }
    }
    Ok(cleanup)
}
