//! `primary DATASET`: activate DATASET's side.
//!
//! - Already primary, or unpaired: restore any fenced member from its saved
//!   placement and move the boot default with ownership.
//! - A clean secondary behind (or level with) its reachable primary catches up:
//!   the primary is fenced, captured once more and transferred, the records
//!   are reversed, then DATASET is activated. Nothing is lost, so it runs
//!   directly.
//! - Otherwise (DATASET ahead, or histories diverged) the peer is rolled back
//!   to the common base. That loses the peer's later snapshots and
//!   unsnapshotted changes, so it is † with the peer as typed target.
//! - A peer whose pool is not imported, or that is gone, replaced or no longer
//!   reciprocates, cannot be fenced: the operator states it is offline (†,
//!   typed target DATASET), DATASET's record is removed one-sided with its
//!   anchor holds kept, and DATASET is activated standalone.
use super::{
    Activation, Backend, Journal, PeerStatus, Recorded, Transferring, activate, activation,
    bound_pool, dataset, departing_placement, digest, endpoint, fence, local_record, membership,
    peer_status, pool_of, refuse, remove_record, retire_activation_placements, set,
    switch_activation, tree, verify_fenced, writable_pool,
};
use crate::{
    boot_support::{self, DefaultHandoff, DefaultHandoffOutcome},
    history::{self, Head, Side},
    observation,
    pairs::plan::PairBackend,
    placement::Posture,
    transfer::{self, NativeTransfer, Phase, TransferProgress, TransferRequest, TransferStatus},
};
use serde::{Deserialize, Serialize};
use zfs_tools::engine::{
    Error, SnapshotRef, intent,
    management::{self, Endpoint, Ownership, PairRecord, Placement, Role},
    mutation::PropertyValue,
    state::NativeState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    AlreadyPrimary,
    Standalone,
    CatchUp,
    Takeover,
    DeadPeer,
}

/// What a takeover costs the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerLoss {
    pub dataset: String,
    /// Peer snapshots after the common base, destroyed by the rollback.
    pub snapshots: Vec<SnapshotRef>,
    /// Peer members whose changes since their last snapshot are discarded.
    pub unsnapshotted: Vec<String>,
    /// The common base each changed peer member is rolled back to.
    pub rollback: Vec<SnapshotRef>,
}
impl PeerLoss {
    fn is_empty(&self) -> bool {
        self.snapshots.is_empty() && self.unsnapshotted.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrimaryPlan {
    pub schema_version: u32,
    pub target: Endpoint,
    pub mode: Mode,
    pub peer: Option<Endpoint>,
    pub pair_id: Option<String>,
    pub peer_status: Option<PeerStatus>,
    pub loss: Option<PeerLoss>,
    /// The operator's statement for a dead peer.
    pub statement: Option<String>,
    pub activation: Vec<Activation>,
    pub boot_default: Option<DefaultHandoff>,
    /// Snapshots the working copy no longer has that only the target keeps:
    /// pending deletions not yet reviewed in `sync`. After the switch the
    /// target's own retention may delete them, so the switch confirms them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unreviewed: Vec<SnapshotRef>,
    /// Space limits the pair's fenced side does not hold as its working copy
    /// sets them, as `status` lists them, for review. They lose nothing, so
    /// the token does not bind them ([`PrimaryPlan::bound`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub space_differences: Vec<transfer::props::SpaceDifference>,
}
impl PrimaryPlan {
    /// What the token, the switch's fresh plan and its record bind: all but
    /// the space differences, which are informational (docs/DESIGN.md,
    /// "Consent").
    pub(crate) fn bound(&self) -> Self {
        Self {
            space_differences: Vec::new(),
            ..self.clone()
        }
    }
    /// The consent token of [`PrimaryPlan::bound`].
    pub fn token(&self) -> std::io::Result<String> {
        crate::consent::token(&self.bound())
    }
    /// Loss-capable plans need typed confirmation.
    pub fn confirms(&self) -> bool {
        self.mode == Mode::DeadPeer
            || self.loss.as_ref().is_some_and(|l| !l.is_empty())
            || !self.unreviewed.is_empty()
    }
    /// The dataset typed to confirm: the one whose changes are lost, or the
    /// surviving dataset when the peer is stated offline.
    pub fn typed_target(&self) -> &str {
        match (&self.loss, &self.peer) {
            (Some(loss), _) if self.mode == Mode::Takeover => &loss.dataset,
            _ => &self.target.name,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PrimaryResult {
    pub operation_id: Option<String>,
    pub target: Endpoint,
    pub former_primary: Option<Endpoint>,
    pub already_primary: bool,
    pub mode: Mode,
    pub boot_default: Option<DefaultHandoffOutcome>,
}
impl PrimaryResult {
    /// The ownership change stands; a default handoff that failed is
    /// repaired by running `primary` again.
    pub fn complete(&self) -> bool {
        self.boot_default.as_ref().is_none_or(|h| h.complete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrimaryState {
    target: Endpoint,
    mode: Mode,
    peer: Option<Endpoint>,
    pair_id: Option<String>,
    /// Digest (the consent token) of the plan the operation began from.
    plan: String,
    target_members: String,
    /// Approved activation before effects; step 6 also binds its completed
    /// native roles/mount paths before local receipt retirement can begin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_activation: Option<String>,
    peer_members: Option<String>,
    /// Takeover: the newest peer snapshot's createtxg when planned; a later
    /// snapshot was never confirmed for destruction.
    boundary_txg: Option<u64>,
    /// Takeover: digest of the planned peer loss. Once the peer is fenced its
    /// loss must still be exactly this, so a write that landed between the
    /// plan and the fence is never rolled back unconfirmed.
    loss: Option<String>,
    /// Catch-up: digest of the target's verified received members and their
    /// approved activation, recorded with step 4. Later steps act only on
    /// exactly that tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    received: Option<String>,
    /// Catch-up, step 3: the transfer's progress, from its commit until the
    /// step 4 write. Its attachments are on the target, on this record's pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transfer: Option<TransferProgress>,
}
impl Recorded for PrimaryState {
    fn pool(&self) -> String {
        pool_of(&self.target.name).into()
    }
}
impl Transferring for PrimaryState {
    fn holder(&self) -> &Endpoint {
        &self.target
    }
    fn transfer(&self) -> Option<&TransferProgress> {
        self.transfer.as_ref()
    }
    fn set_transfer(&mut self, transfer: Option<TransferProgress>) {
        self.transfer = transfer;
    }
}

pub fn primary_plan(target: &str) -> Result<PrimaryPlan, Error> {
    let mut b = NativeTransfer::new();
    let state = PairBackend::observe(&mut b)?;
    primary_plan_with(&state, target, &mut b)
}
pub fn primary_plan_with(
    state: &NativeState,
    target: &str,
    b: &mut impl PairBackend,
) -> Result<PrimaryPlan, Error> {
    zfs_tools::engine::validate_dataset_name(target)?;
    let t = endpoint(state, target)?;
    // A plan is also a preview on read-only pools (the Menu's `--dry-run`);
    // `primary_with` requires them writable before any effect.
    bound_pool(state, &t)?;
    let record = local_record(state, target)?;
    let mut plan = PrimaryPlan {
        schema_version: 1,
        target: t.clone(),
        mode: Mode::Standalone,
        peer: None,
        pair_id: None,
        peer_status: None,
        loss: None,
        statement: None,
        activation: vec![],
        boot_default: None,
        unreviewed: vec![],
        space_differences: vec![],
    };
    let running = b.running_root()?;
    let runs_in = |root: &str| {
        running
            .as_deref()
            .is_some_and(|r| history::contains_dataset(root, r))
    };
    let Some(record) = record else {
        if let Ownership::Primary { record } | Ownership::Secondary { record } =
            management::ownership(state, target)?
        {
            return Err(refuse(format!(
                "{target} is inside the pair rooted at {}; name the pair root",
                record.endpoint.name
            )));
        }
        plan.activation = activation(state, target, None)?;
        if runs_in(target) && plan.activation.iter().any(|a| a.changes) {
            return Err(refuse(
                "activation would change the running root; use the Menu",
            ));
        }
        return Ok(plan);
    };
    plan.peer = Some(record.peer.clone());
    plan.pair_id = Some(record.pair_id.clone());
    let status = peer_status(state, &record);
    plan.peer_status = Some(status);
    if status != PeerStatus::Mutual {
        if returned_primary(state, &record.peer, &t, Some(&record.pair_id)) {
            return Err(refuse(format!(
                "{} is still this pair's primary; unpair it there before activating {target}",
                record.peer.name
            )));
        }
        plan.mode = Mode::DeadPeer;
        let peer = &record.peer.name;
        let gone = match status {
            PeerStatus::PoolNotImported => format!(
                "You are stating that {peer} is offline and will not be used as this pair again \
                 (its pool is not imported). It cannot be fenced from here."
            ),
            PeerStatus::Absent => format!(
                "You are stating that {peer} is gone (it is not in its imported pool) and will \
                 not be used as this pair again."
            ),
            PeerStatus::Replaced => {
                format!("{peer} is now another dataset; you are stating that the old peer is gone.")
            }
            _ => format!(
                "{peer} no longer names {target} as its peer: it has left this pair and is left \
                 as it is."
            ),
        };
        let be = dataset(state, target)?.mountpoint.as_deref() == Some("/");
        plan.statement = Some(format!(
            "{gone} {target}'s pair record is removed one-sided, its anchor holds stay, and it \
             becomes a standalone working copy.{}",
            if be {
                format!(
                    " The boot default is not moved: if {peer} was it, run `zboot default {target}`."
                )
            } else {
                String::new()
            }
        ));
        plan.activation = activation(state, target, None)?;
        if runs_in(target) && plan.activation.iter().any(|a| a.changes) {
            return Err(refuse(
                "activation would change the running root; use the Menu",
            ));
        }
        return Ok(plan);
    }
    match management::ownership(state, target)? {
        Ownership::Primary { .. } => {
            plan.mode = Mode::AlreadyPrimary;
            plan.activation = activation(state, target, None)?;
            plan.boot_default = handoff(state, target)?;
            plan.space_differences =
                transfer::props::space_differences(state, target, &record.peer.name)
                    .unwrap_or_default();
            if runs_in(target) && plan.activation.iter().any(|a| a.changes) {
                return Err(refuse(
                    "activation would change the running root; use the Menu",
                ));
            }
            return Ok(plan);
        }
        Ownership::Secondary { .. } => {}
        Ownership::Unpaired => return Err(refuse("pair ownership changed while planning")),
    }
    let peer = record.peer.clone();
    crate::mounting::require_outside_boot_environment(state, target)?;
    crate::mounting::require_outside_boot_environment(state, &peer.name)?;
    bound_pool(state, &peer)?;
    if runs_in(target) || runs_in(&peer.name) {
        return Err(refuse(
            "an ownership switch cannot quiesce the running root; switch from the Menu",
        ));
    }
    let source = observation::tree(state, &peer.name, b)?;
    let receiver = observation::tree(state, target, b)?;
    let children: std::collections::BTreeSet<String> = source
        .nodes
        .keys()
        .chain(receiver.nodes.keys())
        .filter(|relative| !relative.is_empty())
        .cloned()
        .collect();
    crate::pairs::plan::refuse_children(
        &peer.name,
        target,
        &children.into_iter().collect::<Vec<_>>(),
    )?;
    if source
        .nodes
        .values()
        .chain(receiver.nodes.values())
        .any(|n| n.origin.is_some() || !n.clone_dependents.is_empty())
    {
        return Err(refuse(
            "a clone-connected tree cannot switch ownership; drop the clones first, or unpair \
             before promoting one (a promoted fork takes the pair's snapshots with it)",
        ));
    }
    if let Some((rel, _)) = receiver.nodes.iter().find(|(_, n)| n.head != Head::Clean) {
        return Err(refuse(format!(
            "{} has changes since its last snapshot; roll it back first",
            mapped(target, rel)
        )));
    }
    plan.boot_default = handoff(state, target)?;
    plan.space_differences =
        transfer::props::space_differences(state, &peer.name, target).unwrap_or_default();
    // Snapshots only on the target, older than the pair's anchor: its peer
    // deleted them. Once the target is the working copy its own retention may
    // delete them unreviewed, so `primary` lists and confirms them, in either
    // mode.
    if let Some(pending) = super::prune::pending(state, &peer.name, target)? {
        plan.unreviewed = pending.snapshots.into_iter().map(|p| p.snapshot).collect();
    }
    match history::admit_pair(&source, &receiver) {
        Ok(admission) if admission.ahead != Some(Side::Right) => {
            // A snapshot only on the target under a name the catch-up needs
            // would make its receive fail after the peer is fenced. Only a
            // reviewed deletion in `sync` removes it.
            let collisions = super::prune::collisions(state, &peer.name, target)?;
            if !collisions.is_empty() {
                return Err(refuse(format!(
                    "{} {} only on {target} under {} that the catch-up from {} needs; review \
                     {} first with {}",
                    collisions.join(", "),
                    if collisions.len() == 1 {
                        "exists"
                    } else {
                        "exist"
                    },
                    if collisions.len() == 1 {
                        "a name"
                    } else {
                        "names"
                    },
                    peer.name,
                    if collisions.len() == 1 {
                        "its deletion"
                    } else {
                        "their deletion"
                    },
                    super::prune::review_command(target)
                )));
            }
            plan.mode = Mode::CatchUp;
            plan.activation =
                super::activation_before_fencing(state, target, Some(&peer.name), &peer)?;
        }
        _ => {
            plan.mode = Mode::Takeover;
            plan.loss = Some(peer_loss(state, &source, &receiver, &peer.name)?);
            plan.activation = super::activation_before_fencing(state, target, None, &peer)?;
        }
    }
    Ok(plan)
}
/// The refusal for a pair member whose datasets differ from the ones the
/// switch began with. A dataset created below a leaf is the usual cause and
/// has a way on, so name what is there now.
fn members_changed(state: &NativeState, name: &str) -> Error {
    let below: Vec<_> = super::tree(state, name)
        .into_iter()
        .filter(|dataset| dataset.name != name)
        .map(|dataset| zfs_tools::engine::escape_display(&dataset.name))
        .collect();
    let name = zfs_tools::engine::escape_display(name);
    if below.is_empty() {
        refuse(format!("{name}'s members changed since the switch began"))
    } else {
        refuse(format!(
            "{name}'s members changed since the switch began: it now has {} below it; move \
             that out of the pair (`zfs rename`), then resume the switch",
            below.join(", ")
        ))
    }
}
fn handoff(state: &NativeState, target: &str) -> Result<Option<DefaultHandoff>, Error> {
    boot_support::default_handoff(state, target).map_err(|e| refuse(e.to_string()))
}
fn mapped(root: &str, relative: &str) -> String {
    if relative.is_empty() {
        root.into()
    } else {
        format!("{root}/{relative}")
    }
}
fn point(
    state: &NativeState,
    dataset: &str,
    guid: zfs_tools::engine::Guid,
) -> Result<zfs_tools::engine::Snapshot, Error> {
    state
        .inspection
        .snapshots
        .as_ref()
        .and_then(|all| {
            all.iter().find(|s| {
                s.identity.guid == guid && s.name.split_once('@').map(|(n, _)| n) == Some(dataset)
            })
        })
        .cloned()
        .ok_or_else(|| refuse(format!("a snapshot of {dataset} disappeared")))
}
/// Per peer member: the snapshots after the common base with the target and
/// whether its head changed. Refuses what a rollback cannot do exactly.
fn peer_loss(
    state: &NativeState,
    source: &history::Tree,
    receiver: &history::Tree,
    peer: &str,
) -> Result<PeerLoss, Error> {
    let mut loss = PeerLoss {
        dataset: peer.into(),
        snapshots: vec![],
        unsnapshotted: vec![],
        rollback: vec![],
    };
    for (rel, node) in &source.nodes {
        let name = mapped(peer, rel);
        let Some(target) = receiver.nodes.get(rel) else {
            return Err(refuse(format!(
                "{name} exists only on the peer and would be lost; move or drop it first"
            )));
        };
        let on_target: std::collections::BTreeSet<_> = target.snapshots.iter().collect();
        let common = node
            .snapshots
            .iter()
            .rposition(|guid| on_target.contains(guid))
            .map_or(0, |at| at + 1);
        if common == 0 {
            return Err(refuse(format!(
                "{name} shares no snapshot with the target; there is no base to roll back to"
            )));
        }
        let extras = &node.snapshots[common..];
        let dirty = node.head != Head::Clean;
        if extras.is_empty() && !dirty {
            continue;
        }
        for guid in extras {
            let s = point(state, &name, *guid)?;
            if !s.holds.is_empty() || !s.clones.is_empty() {
                return Err(refuse(format!(
                    "{} is held ({}) or cloned ({}); release or drop it first",
                    s.name,
                    s.holds.join(", "),
                    s.clones.join(", ")
                )));
            }
            loss.snapshots.push(s.point());
        }
        if dirty {
            loss.unsnapshotted.push(name.clone());
        }
        loss.rollback
            .push(point(state, &name, node.snapshots[common - 1])?.point());
    }
    Ok(loss)
}

pub fn primary(plan: &PrimaryPlan) -> Result<PrimaryResult, Error> {
    primary_with(plan, &super::new_id(), &mut NativeTransfer::new())
}
/// Apply a plan made (and, when it confirms, confirmed) moments ago. It is
/// made again here and must be unchanged.
pub fn primary_with(
    plan: &PrimaryPlan,
    id: &str,
    b: &mut impl Backend,
) -> Result<PrimaryResult, Error> {
    super::valid_id(id)?;
    let state = PairBackend::observe(b)?;
    let fresh = primary_plan_with(&state, &plan.target.name, b)?;
    if fresh.bound() != plan.bound() {
        return Err(refuse(
            "the primary plan changed; nothing changed, run it again",
        ));
    }
    let s = PrimaryState {
        target: plan.target.clone(),
        mode: plan.mode,
        peer: plan.peer.clone(),
        pair_id: plan.pair_id.clone(),
        plan: digest(&plan.bound())?,
        target_members: membership(&state, &plan.target.name)?,
        target_activation: (!matches!(plan.mode, Mode::CatchUp | Mode::Takeover))
            .then(|| activation_digest(&state, &plan.target.name, None, None))
            .transpose()?,
        peer_members: match (&plan.peer, plan.mode) {
            (Some(p), Mode::CatchUp | Mode::Takeover) => Some(membership(&state, &p.name)?),
            _ => None,
        },
        boundary_txg: match (&plan.peer, plan.mode) {
            (Some(p), Mode::Takeover) => Some(newest_txg(&state, &p.name)),
            _ => None,
        },
        loss: match (&plan.loss, plan.mode) {
            (Some(loss), Mode::Takeover) => Some(digest(loss)?),
            _ => None,
        },
        received: None,
        transfer: None,
    };
    let activation_effects = match plan.mode {
        Mode::AlreadyPrimary | Mode::Standalone => {
            plan.activation.iter().any(|a| a.changes || a.stored)
        }
        _ => true,
    };
    // Even an already active tree needs a record when its default handoff
    // can fail after an effect. Preserve the no-op fast path.
    let effects = activation_effects
        || (matches!(
            plan.mode,
            Mode::AlreadyPrimary | Mode::CatchUp | Mode::Takeover
        ) && handoff(&state, &plan.target.name)?.is_some());
    if effects {
        writable_pool(&state, &plan.target)?;
        if let (Some(peer), Mode::CatchUp | Mode::Takeover) = (&plan.peer, plan.mode) {
            writable_pool(&state, peer)?;
        }
    }
    let journal = if effects {
        // Both approvals must fit before the first effect: catch-up adds its
        // transfer's progress at step 3 and its receive digest at step 4,
        // and all modes add active approval at 6.
        let receipt = PrimaryState {
            target_activation: Some(digest(&())?),
            received: if s.mode == Mode::CatchUp {
                Some(digest(&())?)
            } else {
                s.received.clone()
            },
            transfer: (s.mode == Mode::CatchUp)
                .then(|| transfer::widest(id, &s.target.name, &s.target.name, false))
                .transpose()?,
            ..s.clone()
        };
        zfs_tools::engine::intent::encode(&zfs_tools::engine::intent::Intent::new(
            id, "primary", receipt,
        ))?;
        Some(Journal::begin(b, id, "primary", s.clone())?)
    } else {
        None
    };
    run(b, &s, journal).map_err(|e| {
        if effects {
            zfs_tools::engine::effect::operation_hint(id);
            refuse(format!(
                "primary operation {id} on {} was interrupted: {e}",
                plan.target.name
            ))
        } else {
            e
        }
    })
}
fn newest_txg(state: &NativeState, root: &str) -> u64 {
    state
        .inspection
        .snapshots
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|s| {
            s.name
                .split_once('@')
                .is_some_and(|(n, _)| history::contains_dataset(root, n))
        })
        .map(|s| s.identity.createtxg.get())
        .max()
        .unwrap_or(0)
}
/// Ignore progress (changes/mounted) while binding the exact approved
/// placements and mount paths throughout a partially completed activation.
/// A switch names its DEPARTING old primary, whose saved `volmode` it binds.
fn activation_digest(
    state: &NativeState,
    root: &str,
    peer: Option<&str>,
    departing: Option<&str>,
) -> Result<String, Error> {
    digest(
        &switch_activation(state, root, peer, departing)?
            .into_iter()
            .map(|member| {
                let mountpoint = dataset(state, &member.dataset.name)?.mountpoint.clone();
                Ok((member.dataset, member.placement, member.mounts, mountpoint))
            })
            .collect::<Result<Vec<_>, Error>>()?,
    )
}
/// Reconstruct approval only from native active roles, never from receipts
/// that an earlier cleanup attempt may already have removed.
fn active_digest(state: &NativeState, root: &str) -> Result<String, Error> {
    digest(
        &tree(state, root)
            .into_iter()
            .map(|d| {
                let placement =
                    Placement::observed(d, management::bound_properties(state, &d.name)?);
                let mountpoint = d.mountpoint.clone();
                let mounts = placement.canmount == Some(management::MountMode::On)
                    && mountpoint
                        .as_deref()
                        .is_some_and(|path| path.starts_with('/') && path != "/");
                if mounts && d.mounted != Some(true) {
                    return Err(refuse("approved active member is no longer mounted"));
                }
                Ok((endpoint(state, &d.name)?, placement, mounts, mountpoint))
            })
            .collect::<Result<Vec<_>, Error>>()?,
    )
}
fn saved_placement(
    state: &NativeState,
    d: &zfs_tools::engine::Dataset,
) -> Result<Placement, Error> {
    management::bound_properties(state, &d.name)?
        .get(management::PLACEMENT_PROPERTY)
        .filter(|p| p.source == "local")
        .map(|p| Placement::parse(&p.value))
        .transpose()?
        .filter(|p| p.identity == d.identity)
        .ok_or_else(|| refuse(format!("{}'s saved placement is missing", d.name)))
}
fn capture_name(member: &str, id: &str) -> String {
    format!("{member}@zboot_primary_{id}")
}
/// Steps: 1 peer placements saved, 2 peer fenced, 3 captured (catch-up) or
/// rolled back (takeover), 4 transferred, 5 records reversed (or removed
/// one-sided), 6 activated; the default handoff finishes the record.
fn run(
    b: &mut impl Backend,
    s: &PrimaryState,
    mut journal: Option<Journal<PrimaryState>>,
) -> Result<PrimaryResult, Error> {
    let step = journal.as_ref().map_or(0, Journal::step);
    let id = journal.as_ref().map(|j| j.id().to_string());
    let reach = |journal: &mut Option<Journal<PrimaryState>>, b: &mut _, step| match journal {
        Some(j) => j.reach(b, step),
        None => Ok(()),
    };
    let paired = matches!(s.mode, Mode::CatchUp | Mode::Takeover);
    let state = PairBackend::observe(b)?;
    if paired {
        crate::mounting::require_outside_boot_environment(&state, &s.target.name)?;
        crate::mounting::require_outside_boot_environment(&state, &s.peer.as_ref().unwrap().name)?;
    }
    if endpoint(&state, &s.target.name)? != s.target {
        return Err(refuse(format!("{} was replaced", s.target.name)));
    }
    if s.mode == Mode::DeadPeer
        && let Some(peer) = &s.peer
        && returned_primary(&state, peer, &s.target, s.pair_id.as_deref())
    {
        return Err(refuse(format!(
            "{} is back as this pair's primary; nothing activated",
            peer.name
        )));
    }
    // From step 6 the target is active: only the default handoff is left, so the plan's other datasets are not
    // rechecked (the peer may since be exported or changed).
    let activated = step >= 6;
    if !paired && !activated {
        if membership(&state, &s.target.name)? != s.target_members {
            return Err(members_changed(&state, &s.target.name));
        }
        if s.target_activation.as_ref()
            != Some(&activation_digest(&state, &s.target.name, None, None)?)
        {
            return Err(refuse(format!(
                "{}'s approved activation changed since the switch began",
                s.target.name
            )));
        }
        // All modes now recheck their complete plan at step zero. Checkpoint
        // before any activation/record removal so a legitimate partial effect
        // cannot make that original preview appear to have drifted.
        reach(&mut journal, b, 1)?;
    }
    // Activated: a peer still imported must still be fenced, or another
    // operation made it the working copy since and the handoff is not ours.
    if let Some(peer) = s.peer.as_ref().filter(|_| paired && activated)
        && endpoint(&state, &peer.name).is_ok_and(|e| e == *peer)
    {
        verify_fenced(&state, &peer.name).map_err(|e| {
            refuse(format!(
                "{e}: {} changed after this switch fenced it; inspect it before resuming or abandoning",
                peer.name
            ))
        })?;
    }
    if paired && !activated {
        let peer = s.peer.as_ref().unwrap();
        if endpoint(&state, &peer.name)? != *peer
            || Some(membership(&state, &peer.name)?) != s.peer_members
        {
            return Err(members_changed(&state, &peer.name));
        }
        // A catch-up copies the leaf only, so the target's membership is
        // fixed until the reversal.
        if (s.mode == Mode::Takeover || step < 4)
            && membership(&state, &s.target.name)? != s.target_members
        {
            return Err(members_changed(&state, &s.target.name));
        }
        // From step 2 the peer is fenced. Another operation (`primary` of the
        // peer) may have activated it since the interruption: then this switch
        // must not go on to activate the target as well.
        if step >= 2 {
            verify_fenced(&state, &peer.name).map_err(|e| {
                refuse(format!(
                    "{e}: {} changed after this switch fenced it; inspect it before resuming or abandoning",
                    peer.name
                ))
            })?;
        }
        // After the catch-up the target must still be exactly the tree that
        // received it: same incarnations, captures and approved activation.
        // Until the reversal nothing may have written it.
        if s.mode == Mode::CatchUp && (4..6).contains(&step) {
            let id = id.as_deref().unwrap_or_default();
            verify_received(b, &state, &peer.name, &s.target.name, id, step == 4)?;
            if s.received != Some(received_digest(&state, &s.target.name, &peer.name)?) {
                return Err(refuse(format!(
                    "{} changed since it received the catch-up; nothing activated",
                    s.target.name
                )));
            }
        }
    }
    let id_str = id.clone().unwrap_or_default();
    let mut received = s.received.clone();
    if paired {
        let peer = s.peer.clone().unwrap();
        if step < 1 {
            for d in tree(&state, &peer.name) {
                let e = endpoint(&state, &d.name)?;
                set(
                    b,
                    &e,
                    PropertyValue::Placement(departing_placement(&state, d)?),
                )?;
            }
            reach(&mut journal, b, 1)?;
        }
        if step < 2 {
            let state = PairBackend::observe(b)?;
            for d in tree(&state, &peer.name).into_iter().rev() {
                let e = endpoint(&state, &d.name)?;
                fence(b, &e, Some(&saved_placement(&state, d)?), Posture::AtRest)?;
            }
            let fenced = PairBackend::observe(b)?;
            verify_fenced(&fenced, &peer.name)?;
            if s.mode == Mode::Takeover {
                // The peer can no longer change: its loss now must be the
                // planned one (a write since the plan would be lost
                // unconfirmed).
                let source = observation::tree(&fenced, &peer.name, b)?;
                let receiver = observation::tree(&fenced, &s.target.name, b)?;
                let loss = peer_loss(&fenced, &source, &receiver, &peer.name)?;
                if Some(digest(&loss)?) != s.loss {
                    return Err(refuse(format!(
                        "{} changed between the plan and its fence, so the takeover would lose \
                         more than planned; nothing was rolled back. Abandon this operation and \
                         plan again",
                        peer.name
                    )));
                }
            }
            reach(&mut journal, b, 2)?;
        }
        if s.mode == Mode::CatchUp {
            if step < 3 {
                capture(b, &peer.name, &id_str)?;
                reach(&mut journal, b, 3)?;
            }
            if step < 4 {
                let j = journal
                    .as_mut()
                    .ok_or_else(|| refuse("a catch-up transfer runs only under its record"))?;
                catch_up(b, j, &peer, &s.target.name, &id_str)?;
                let state = PairBackend::observe(b)?;
                received = Some(received_digest(&state, &s.target.name, &peer.name)?);
                let next = PrimaryState {
                    received: received.clone(),
                    transfer: None,
                    ..s.clone()
                };
                // The receipt and its step are one write: a resume
                // before it re-verifies the transfer, never trusts it.
                j.reach_with(b, 4, next)?;
            }
        } else if step < 3 {
            roll_back(b, &peer.name, &s.target.name, s.boundary_txg.unwrap_or(0))?;
            reach(&mut journal, b, 3)?;
        }
        if step < 5 {
            reverse(
                b,
                &s.target,
                &peer,
                s.pair_id.as_deref().unwrap_or_default(),
            )?;
            reach(&mut journal, b, 5)?;
        }
    } else if s.mode == Mode::DeadPeer && step < 5 {
        let state = PairBackend::observe(b)?;
        if let Some(record) = local_record(&state, &s.target.name)? {
            if Some(&record.pair_id) != s.pair_id.as_ref() {
                return Err(refuse(format!(
                    "{} now belongs to another pair",
                    s.target.name
                )));
            }
            remove_record(b, &s.target, &record)?;
        }
        reach(&mut journal, b, 5)?;
    }
    let approved = if step < 6 {
        let state = PairBackend::observe(b)?;
        if paired {
            // Activate only the verified primary of this pair, with its peer
            // still fenced.
            let peer = s.peer.as_ref().unwrap();
            let owner = management::ownership(&state, &s.target.name)?;
            if !matches!(&owner, Ownership::Primary { record }
                if Some(&record.pair_id) == s.pair_id.as_ref() && record.peer == *peer)
            {
                return Err(refuse(format!(
                    "{} is not the primary of this pair any more; nothing activated",
                    s.target.name
                )));
            }
            verify_fenced(&state, &peer.name)?;
        }
        let peer = (s.mode == Mode::CatchUp).then(|| s.peer.as_ref().unwrap().name.as_str());
        if let Some(peer) = peer {
            verify_received(b, &state, peer, &s.target.name, &id_str, false)?;
            if journal.is_some() && received != Some(received_digest(&state, &s.target.name, peer)?)
            {
                return Err(refuse(format!(
                    "{} changed since it received the catch-up; nothing activated",
                    s.target.name
                )));
            }
        }
        let departing = s.peer.as_ref().filter(|_| paired).map(|p| p.name.as_str());
        let approved = activation_digest(&state, &s.target.name, peer, departing)?;
        let members = switch_activation(&state, &s.target.name, peer, departing)?;
        activate(b, &members)?;
        if active_digest(&PairBackend::observe(b)?, &s.target.name)? != approved {
            return Err(refuse(
                "complete native activation differs from its approval",
            ));
        }
        if let Some(j) = &mut journal {
            let mut next = j.intent.state.clone();
            next.target_activation = Some(approved.clone());
            j.reach_with(b, 6, next)?;
        }
        approved
    } else {
        // `resume_primary` refuses a step-6 record without its approval.
        s.target_activation
            .clone()
            .ok_or_else(|| refuse("primary record lacks its activation approval"))?
    };
    if active_digest(&PairBackend::observe(b)?, &s.target.name)? != approved {
        return Err(refuse(
            "active native roles changed before placement retirement",
        ));
    }
    retire_activation_placements(b, &s.target.name)?;
    let state = PairBackend::observe(b)?;
    let boot_default = match s.mode {
        Mode::AlreadyPrimary | Mode::CatchUp | Mode::Takeover => {
            // The handoff reads the pair relation, so it needs the peer.
            handoff(&state, &s.target.name)
                .map_err(|e| {
                    refuse(format!(
                        "{e}; {} is active, but its boot default handoff needs its peer: \
                         import the peer's pool and resume, or abandon",
                        s.target.name
                    ))
                })?
                .map(|h| b.hand_off_default(&h))
        }
        _ => None,
    };
    // A handoff that did not complete is redone on resume.
    if let Some(journal) = journal
        && boot_default.as_ref().is_none_or(|h| h.complete)
    {
        journal.finish(b)?;
    }
    Ok(PrimaryResult {
        operation_id: id,
        target: s.target.clone(),
        former_primary: if paired { s.peer.clone() } else { None },
        already_primary: s.mode == Mode::AlreadyPrimary,
        mode: s.mode,
        boot_default,
    })
}
/// Whether `peer` (the same incarnation) is imported and still records itself
/// as the primary of pair `pair_id` with `target`.
fn returned_primary(
    state: &NativeState,
    peer: &Endpoint,
    target: &Endpoint,
    pair_id: Option<&str>,
) -> bool {
    endpoint(state, &peer.name).is_ok_and(|e| e == *peer)
        && management::bound_properties(state, &peer.name)
            .ok()
            .and_then(|props| props.get(management::PAIR_PROPERTY).cloned())
            .filter(|p| p.source == "local")
            .and_then(|p| PairRecord::parse(&p.value).ok())
            .is_some_and(|r| {
                r.role == Role::Primary && Some(r.pair_id.as_str()) == pair_id && r.peer == *target
            })
}
/// One recursive snapshot of the fenced peer, marked with the operation ID;
/// a capture that already happened is verified, never repeated.
fn capture(b: &mut impl Backend, peer: &str, id: &str) -> Result<Vec<SnapshotRef>, Error> {
    let state = PairBackend::observe(b)?;
    let names: Vec<_> = tree(&state, peer)
        .iter()
        .map(|d| capture_name(&d.name, id))
        .collect();
    let present = |state: &NativeState| {
        state
            .inspection
            .snapshots
            .as_ref()
            .into_iter()
            .flatten()
            .filter(|s| names.contains(&s.name))
            .count()
    };
    match present(&state) {
        0 => {
            let result = b.snapshot(&names, id);
            if present(&PairBackend::observe(b)?) != names.len() {
                return Err(result
                    .err()
                    .unwrap_or_else(|| refuse("the final capture of the peer did not appear")));
            }
        }
        n if n == names.len() => {}
        _ => return Err(refuse("the final capture is partial; inspect the peer")),
    }
    let state = PairBackend::observe(b)?;
    let mut points = Vec::new();
    for d in tree(&state, peer) {
        let name = capture_name(&d.name, id);
        let snap = state
            .inspection
            .snapshots
            .as_ref()
            .into_iter()
            .flatten()
            .find(|s| s.name == name)
            .ok_or_else(|| refuse(format!("{name} disappeared")))?;
        let p = snap.point();
        if p.dataset_guid != d.identity.guid || b.capture_marker(&p)? != id {
            return Err(refuse(format!("{name} is not this operation's capture")));
        }
        if b.written(d, &p)? != 0 {
            return Err(refuse(format!(
                "{} changed after its final capture",
                d.name
            )));
        }
        points.push(p);
    }
    Ok(points)
}
/// Transfer the captured peer to the target under the operation's record,
/// or continue the transfer that record holds.
fn catch_up(
    b: &mut impl Backend,
    journal: &mut Journal<PrimaryState>,
    peer: &Endpoint,
    target: &str,
    id: &str,
) -> Result<(), Error> {
    let points = capture(b, &peer.name, id)?;
    if journal.intent.state.transfer.is_none() {
        // Chunks a write cut before the transfer recorded its plan left on
        // the target go first: they would refuse the plan below.
        transfer::discard(journal, b)?;
        // Common snapshots take the peer's names first, or a renamed
        // one would make the receive fail with EEXIST.
        super::prune::prepare(b, &peer.name, target, &[])?;
        let state = PairBackend::observe(b)?;
        let request = TransferRequest {
            source: peer.name.clone(),
            destination: target.into(),
        };
        let plan = transfer::plan_with(&state, &request, id, b)?;
        if plan.boundary.name != capture_name(&peer.name, id) {
            return Err(refuse(
                "the final capture is no longer the peer's newest snapshot",
            ));
        }
        transfer::apply_with_id(&plan, journal, b)?;
    } else {
        // A transfer released before an interruption, its receipt not yet
        // recorded, has no proof left that the target holds only what it
        // received: activate nothing, and let the operator start over.
        let resumed = transfer::resume_between_with(&peer.name, target, journal, b)?;
        if resumed.status == TransferStatus::AlreadyComplete {
            return Err(refuse(format!(
                "the catch-up into {target} finished before an interruption but its \
                 receipt was not recorded; nothing activated. Abandon this operation \
                 (`zboot abandon {id}`) and run `zboot primary {target}` again"
            )));
        }
    }
    let state = PairBackend::observe(b)?;
    if points.len() != tree(&state, &peer.name).len() {
        return Err(refuse("the peer's members changed during the catch-up"));
    }
    verify_received(b, &state, &peer.name, target, id, true)
}
/// Exactly the peer's members exist under `target`, each holding this
/// operation's capture of its peer counterpart (and, while `unchanged`
/// applies, nothing written since).
fn verify_received(
    b: &mut impl Backend,
    state: &NativeState,
    peer: &str,
    target: &str,
    id: &str,
    unchanged: bool,
) -> Result<(), Error> {
    let relative = |root: &str| -> Vec<String> {
        tree(state, root)
            .iter()
            .map(|d| d.name[root.len()..].to_string())
            .collect()
    };
    if relative(peer) != relative(target) {
        return Err(refuse(format!(
            "{target}'s members no longer match the caught-up peer {peer}"
        )));
    }
    for d in tree(state, peer) {
        let capture = capture_name(&d.name, id);
        let source = state
            .inspection
            .snapshots
            .as_ref()
            .into_iter()
            .flatten()
            .find(|s| s.name == capture && s.point().dataset_guid == d.identity.guid)
            .ok_or_else(|| refuse(format!("{capture} disappeared")))?;
        let name = format!("{target}{}", &d.name[peer.len()..]);
        let member = dataset(state, &name)?;
        let received = point(state, &name, source.identity.guid)?;
        if received.name != capture_name(&name, id)
            || (unchanged && b.written(member, &received.point())? != 0)
        {
            return Err(refuse(format!(
                "{name} did not receive the final capture cleanly"
            )));
        }
    }
    Ok(())
}
fn received_digest(state: &NativeState, target: &str, peer: &str) -> Result<String, Error> {
    digest(&(
        membership(state, target)?,
        activation_digest(state, target, Some(peer), Some(peer))?,
    ))
}
/// Roll each changed peer member back to its common base with the target.
fn roll_back(b: &mut impl Backend, peer: &str, target: &str, boundary: u64) -> Result<(), Error> {
    let state = PairBackend::observe(b)?;
    let source = observation::tree(&state, peer, b)?;
    let receiver = observation::tree(&state, target, b)?;
    let loss = peer_loss(&state, &source, &receiver, peer)?;
    if let Some(late) = loss
        .snapshots
        .iter()
        .find(|s| s.identity.createtxg.get() > boundary)
    {
        return Err(refuse(format!(
            "{} was made after the takeover was confirmed; nothing more is destroyed",
            late.name
        )));
    }
    for base in &loss.rollback {
        let result = b.rollback(base);
        let after = PairBackend::observe(b)?;
        let name = base.name.split_once('@').unwrap().0;
        let d = dataset(&after, name)?;
        let newest = after
            .inspection
            .snapshots
            .as_ref()
            .into_iter()
            .flatten()
            .filter(|s| s.name.split_once('@').map(|(n, _)| n) == Some(name))
            .max_by_key(|s| s.identity.createtxg)
            .map(|s| s.point());
        if newest.as_ref() != Some(base) || b.written(d, base)? != 0 {
            return Err(result
                .err()
                .unwrap_or_else(|| refuse(format!("{name} did not roll back to {}", base.name))));
        }
    }
    Ok(())
}
/// The peer's record becomes secondary first, then the target's primary.
fn reverse(
    b: &mut impl Backend,
    target: &Endpoint,
    peer: &Endpoint,
    pair_id: &str,
) -> Result<(), Error> {
    let state = PairBackend::observe(b)?;
    let current = |name: &str| -> Result<PairRecord, Error> {
        local_record(&state, name)?
            .ok_or_else(|| refuse(format!("{name}'s pair record disappeared")))
    };
    let peer_record = current(&peer.name)?;
    let target_record = current(&target.name)?;
    if peer_record.pair_id != pair_id
        || target_record.pair_id != pair_id
        || peer_record.endpoint != *peer
        || peer_record.peer != *target
        || target_record.endpoint != *target
        || target_record.peer != *peer
    {
        return Err(refuse("the pair records changed during the switch"));
    }
    let mut demoted = peer_record.clone();
    demoted.role = Role::Secondary;
    set(b, peer, PropertyValue::Pair(demoted.clone()))?;
    set(b, target, PropertyValue::Pair(demoted.counterpart()))?;
    match management::ownership(&PairBackend::observe(b)?, &target.name)? {
        Ownership::Primary { .. } => Ok(()),
        _ => Err(refuse(format!(
            "{} is not the verified primary",
            target.name
        ))),
    }
}
/// Why catch-up ID, its transfer part way at step 3, can neither resume nor
/// abandon while its peer is not imported as recorded, or None while it is.
/// A peer renamed is renamed back. A peer that cannot come back ends the
/// catch-up on the target alone (an abandon names the commands), while the
/// target is still this pair's fenced secondary: nothing was activated yet.
fn peer_away(state: &NativeState, s: &PrimaryState, id: &str, abandon: bool) -> Option<String> {
    let peer = s.peer.as_ref()?;
    let target = &s.target.name;
    if endpoint(state, &peer.name).is_ok_and(|e| e == *peer) {
        return None;
    }
    let what = format!(
        "the catch-up {id} from {} to {target} is part way through its transfer",
        peer.name
    );
    if let Some(moved) = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.identity == peer.identity)
    {
        return Some(format!(
            "{what}, and {} is now {}: rename it back to resume it; nothing was changed",
            peer.name, moved.name
        ));
    }
    let pool = pool_of(&peer.name);
    // How the operator brings the peer back, and the condition to end the
    // catch-up without it.
    let (back, otherwise) = if super::pool_imported(state, pool) {
        (
            format!("{} is gone or was replaced", peer.name),
            "it cannot be resumed".to_string(),
        )
    } else {
        (
            format!(
                "pool {pool} of {} is not imported: import it to resume the catch-up",
                peer.name
            ),
            format!("if {} is lost for good", peer.name),
        )
    };
    if !abandon {
        return Some(format!(
            "{what}, and {back}; {otherwise}, abandon it to see how to end it on {target} \
             alone; nothing was changed"
        ));
    }
    // The target must still be the incarnation the catch-up began on.
    if endpoint(state, target).ok().as_ref() != Some(&s.target) {
        if let Some(moved) = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.identity == s.target.identity)
        {
            return Some(format!(
                "{what}, and {back}; {target} is now {}: rename it back first; nothing was \
                 changed",
                moved.name
            ));
        }
        return Some(format!(
            "{what}, and {back}; {target} is no longer the dataset the catch-up began on: \
             inspect it; nothing was changed"
        ));
    }
    let secondary = management::bound_properties(state, target)
        .ok()
        .and_then(|props| props.get(management::PAIR_PROPERTY))
        .filter(|p| p.source == "local")
        .and_then(|p| PairRecord::parse(&p.value).ok())
        .is_some_and(|r| {
            r.role == Role::Secondary
                && Some(&r.pair_id) == s.pair_id.as_ref()
                && r.endpoint == s.target
                && r.peer == *peer
        });
    if !secondary || verify_fenced(state, target).is_err() {
        return Some(format!(
            "{what}, and {back}; {target} is no longer this pair's fenced secondary, so \
             nothing ends it on {target} alone: inspect it; nothing was changed"
        ));
    }
    // What the target keeps: the snapshots it received so far. Before the
    // transfer's Received phase they lack the catch-up's final capture of
    // the peer; from it on, that capture is among them, verified.
    let newest = state
        .inspection
        .snapshots
        .iter()
        .flatten()
        .filter(|p| p.name.split_once('@').map(|(owner, _)| owner) == Some(target.as_str()))
        .max_by_key(|p| p.identity.createtxg)
        .map_or_else(
            || "no snapshot".to_string(),
            |p| format!("its newest snapshot {}", p.name),
        );
    let keeps = if s
        .transfer
        .as_ref()
        .is_some_and(|t| t.phase >= Phase::Received)
    {
        format!(
            "{target} keeps what it received, {newest}, the catch-up's final capture of {} \
             included and verified",
            peer.name
        )
    } else {
        format!(
            "{target} keeps only what it received, {newest}, without the catch-up's final \
             capture of {}",
            peer.name
        )
    };
    Some(format!(
        "{what}, and {back}; {otherwise}, end it on {target} alone: {}. {keeps}. Then `zboot \
         primary {target}` activates it without its peer; nothing was changed",
        target_only_steps(state, target, id)
    ))
}
/// The commands that end catch-up ID on its TARGET alone, each run only if
/// the one before succeeded: remove its markers and its attachments there,
/// and last its record, while that still names ID. The target keeps the
/// snapshots it received and its pair record, and stays fenced.
fn target_only_steps(state: &NativeState, target: &str, id: &str) -> String {
    let props = state.dataset_properties.get(target);
    let markers: Vec<&str> = [management::PENDING_PROPERTY, management::STAGING_PROPERTY]
        .into_iter()
        .filter(|marker| {
            props
                .and_then(|props| props.get(*marker))
                .is_some_and(|p| p.source == "local" && p.value == id)
        })
        .collect();
    crate::recipe::target_only(target, pool_of(target), &markers, id)
}
/// A primary records steps 0 to 6 and binds each approval before the step
/// that relies on it, and a transfer only during a catch-up's step 3; any
/// other record was written by an earlier zboot.
fn written_here(s: &PrimaryState, step: u32) -> bool {
    let paired = matches!(s.mode, Mode::CatchUp | Mode::Takeover);
    step <= 6
        && (s.target_activation.is_some() || (paired && step < 6))
        && (s.mode != Mode::Takeover || (s.loss.is_some() && s.boundary_txg.is_some()))
        && (s.mode != Mode::CatchUp || step < 4 || s.received.is_some())
        && (s.transfer.is_none() || (s.mode == Mode::CatchUp && step == 3))
}
pub(crate) fn resume_primary(
    journal: Journal<PrimaryState>,
    abandon: bool,
    dialogue: &mut dyn std::io::Write,
    b: &mut impl Backend,
) -> Result<PrimaryResult, Error> {
    let s = journal.intent.state.clone();
    let id = journal.id().to_string();
    let step = journal.step();
    if !written_here(&s, step) {
        return Err(refuse(intent::earlier("primary", &id)));
    }
    // A catch-up's transfer part way reads its peer, the source.
    let part_way = s.mode == Mode::CatchUp
        && step == 3
        && s.transfer
            .as_ref()
            .is_some_and(|t| t.phase < Phase::Released);
    if part_way && let Some(away) = peer_away(&PairBackend::observe(b)?, &s, &id, abandon) {
        return Err(refuse(away));
    }
    if abandon {
        // A part-way transfer is resumed; one not begun or released only
        // leaves chunks its record does not name, on the target.
        if part_way {
            return Err(refuse(format!(
                "the transfer from {} to {} is part way through; resume it rather \
                 than abandon it",
                s.peer.as_ref().map_or("-", |p| p.name.as_str()),
                s.target.name
            )));
        }
        if s.mode == Mode::CatchUp && step == 3 {
            transfer::discard(&journal, b)?;
        }
        let peer = s.peer.as_ref().map_or("-", |p| p.name.as_str());
        let left = match (s.mode, step) {
            (Mode::CatchUp | Mode::Takeover, 0) => "nothing was fenced yet".to_string(),
            (Mode::CatchUp | Mode::Takeover, 1..=4) => format!(
                "{peer} stays read-only but is still the primary: `zboot primary {peer}` makes it writable again"
            ),
            (_, 5) => format!(
                "ownership already moved; `zboot primary {}` finishes activating it",
                s.target.name
            ),
            (_, 6) => format!(
                "{} is active; `zboot primary {}` finishes its boot default handoff",
                s.target.name, s.target.name
            ),
            _ => format!(
                "{} may be partly activated; `zboot primary {}` finishes it",
                s.target.name, s.target.name
            ),
        };
        writeln!(dialogue, "abandoned primary {id}: {left}").map_err(|e| refuse(e.to_string()))?;
        journal.finish(b)?;
        return Ok(PrimaryResult {
            operation_id: Some(id),
            target: s.target.clone(),
            former_primary: None,
            already_primary: false,
            mode: s.mode,
            boot_default: None,
        });
    }
    if s.mode == Mode::DeadPeer {
        let state = PairBackend::observe(b)?;
        if step < 5
            && let Some(record) = local_record(&state, &s.target.name)?
            && peer_status(&state, &record) == PeerStatus::Mutual
        {
            return Err(refuse(format!(
                "{} is reachable again; abandon operation {id} and run `zboot primary {}`",
                record.peer.name, s.target.name
            )));
        }
        // The operator stated the peer offline. A peer back as this pair's
        // primary is not offline, whether or not our record is gone yet.
        if let Some(peer) = &s.peer
            && returned_primary(&state, peer, &s.target, s.pair_id.as_deref())
        {
            return Err(refuse(format!(
                "{} is back as this pair's primary, so it is not offline; unpair it there \
                 (`zboot unpair {}`) or abandon operation {id}",
                peer.name, peer.name
            )));
        }
    }
    if step == 0 {
        // Nothing but the peer's saved placements has changed: the plan must
        // be the one consented to.
        let state = PairBackend::observe(b)?;
        let plan = primary_plan_with(&state, &s.target.name, b)?;
        if digest(&plan.bound())? != s.plan {
            return Err(refuse(format!(
                "{} changed since operation {id} began; abandon it with `zboot abandon {id}` and plan again",
                s.target.name
            )));
        }
    }
    run(b, &s, Some(journal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zfs_tools::engine::{DatasetIdentity, Guid, ObjsetId, Txg};

    /// A catch-up record at its widest, with 255-byte names, the largest
    /// identities, every approval and digest and its transfer's widest
    /// progress at once, fits one intent; `primary_with` encodes this bound
    /// before any effect.
    #[test]
    fn a_catch_up_record_at_its_widest_fits_one_intent() {
        let name = |pool: &str| format!("{pool}/{}", "x".repeat(254 - pool.len()));
        let wide = |name: String| Endpoint {
            name,
            identity: DatasetIdentity {
                pool_guid: Guid::new(u64::MAX),
                guid: Guid::new(u64::MAX),
                createtxg: Txg::new(u64::MAX),
                objsetid: ObjsetId::new(u64::MAX),
            },
        };
        let id = super::super::new_id();
        let token = digest(&()).unwrap();
        let state = PrimaryState {
            target: wide(name("b")),
            mode: Mode::CatchUp,
            peer: Some(wide(name("a"))),
            pair_id: Some(super::super::new_id()),
            plan: token.clone(),
            target_members: token.clone(),
            target_activation: Some(token.clone()),
            peer_members: Some(token.clone()),
            boundary_txg: Some(u64::MAX),
            loss: Some(token.clone()),
            received: Some(token),
            transfer: Some(transfer::widest(&id, &name("b"), &name("b"), false).unwrap()),
        };
        assert_eq!(state.target.name.len(), 255);
        let encoded = intent::encode(&intent::Intent::new(id, "primary", state)).unwrap();
        assert!(
            encoded.len() < super::super::RECORD_BUDGET,
            "{}",
            encoded.len()
        );
        println!("catch-up: {} bytes", encoded.len());
    }
}
