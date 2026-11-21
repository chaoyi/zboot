//! The restore steps over a [`Backend`]. Each step first observes native
//! state, so a step whose outcome was lost (a cut, a lost reply) is judged
//! from what exists rather than repeated blindly or assumed done.
//!
//! Data moves dataset by dataset, parents first ([`Run::copy_tree`]): a full
//! raw stream of a dataset's first snapshot creates it inside a fenced
//! parent, it is fenced locally at once, then one incremental stream brings
//! it to the boundary. A retry recomputes what is missing from native state.
//! zboot destroys a dataset only under the destruction rule ([`Run::discard`]).
use super::{
    Backend, DatasetView, DeploySpec, Intent, KIND, Phase, SnapshotView, State, View,
    backend::{Holds, Records, within},
    manifest, receipt, refuse, tree_digest,
};
use crate::{menu::Result, placement::Posture};
use serde::Serialize;
use sha2::Digest;
use std::{collections::BTreeMap, io::Write};
use zfs_tools::engine::{
    SnapshotRef, hold, intent,
    management::{Endpoint, Placement, Role},
    stream::LeafStream,
};

const POLL_SECONDS: u64 = 5;

fn join(root: &str, relative: &str) -> String {
    if relative.is_empty() {
        root.to_owned()
    } else {
        format!("{root}/{relative}")
    }
}

fn parent_of(name: &str) -> Result<&str> {
    name.rsplit_once('/')
        .map(|(parent, _)| parent)
        .ok_or_else(|| refuse(format!("{name} has no parent")))
}

/// One tree restore copies, from `source` to `destination`, with every
/// member the manifest lists, up to `@suffix`.
#[derive(Debug, Clone)]
struct TreeCopy {
    source: String,
    destination: String,
    suffix: String,
    members: BTreeMap<String, receipt::Member>,
}
impl TreeCopy {
    fn encrypted(&self) -> bool {
        self.members.values().any(|m| m.encryption.is_some())
    }
}

/// The outcome of a wrapping proof.
enum Proof {
    Proven,
    /// A copy is wrapped otherwise than its root: its key changed.
    Differs(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Completed {
    pub id: String,
    pub be: String,
    pub pool: String,
    pub staging: String,
    pub source_snapshot: String,
    pub notes: Vec<String>,
}

fn source_be_placement(member: &receipt::Member) -> Result<Option<Placement>> {
    member
        .managed
        .get(zfs_tools::engine::management::PLACEMENT_PROPERTY)
        .map(|value| {
            let saved = Placement::parse(value)?;
            if saved.identity != member.identity {
                return Err(refuse("source placement belongs to another incarnation"));
            }
            Ok(saved)
        })
        .transpose()
}

/// A disabled BE container stays disabled: stock initramfs explicitly mounts
/// every descendant with canmount!=off, including noauto.
fn restored_canmount(member: &receipt::Member, be_member: bool, root: bool) -> Result<String> {
    let original = member
        .placement
        .canmount
        .as_ref()
        .ok_or_else(|| refuse("filesystem receipt lacks its canmount placement"))?;
    if !be_member {
        return Ok(original.value.clone());
    }
    let disabled = source_be_placement(member)?.map_or_else(
        || original.value == "off",
        |saved| saved.canmount == Some(zfs_tools::engine::management::MountMode::Off),
    );
    Ok(if !root && disabled { "off" } else { "noauto" }.into())
}

/// One run of the restore steps, from wherever the record stands.
pub struct Run<'a, B: Backend> {
    backend: &'a mut B,
    pool: String,
    record: Intent,
    progress: &'a mut dyn Write,
    /// The layout of A the operator consented to erase in this run.
    erase_layout: Option<String>,
    notes: Vec<String>,
}

/// Every run starts as the BE's host, with no hibernation image to resume
/// over its writes; the erase and every import of A check again.
fn admit(backend: &mut impl Backend, hostid: &str) -> Result<()> {
    super::require_host(backend, hostid)?;
    backend.require_no_image()
}

impl<'a, B: Backend> Run<'a, B> {
    /// Record a confirmed plan on B's pool root, then run every step.
    pub fn start(
        backend: &'a mut B,
        plan: &super::Plan,
        progress: &'a mut dyn Write,
    ) -> Result<Completed> {
        admit(backend, &plan.state.hostid)?;
        let view = backend.view()?;
        super::admit_staging_parent(&view, plan.state.source_pool())?;
        super::admit_source_automounts(&view.tree(&plan.state.source.name))?;
        let intent = plan.intent();
        let pool = plan.state.source_pool().to_owned();
        intent::begin(&mut Records(backend), &pool, &intent)?;
        writeln!(progress, "operation {}", plan.id)?;
        let mut run = Self {
            backend,
            pool,
            record: intent,
            progress,
            erase_layout: Some(plan.state.disk.layout.clone()),
            notes: Vec::new(),
        };
        run.run()
    }

    /// Continue operation `id`. `erase_layout` is A's layout as freshly
    /// confirmed ([`ResumePlan::erase_layout`]); it is required while erasing
    /// is still ahead or was interrupted, and unused afterwards.
    pub fn resume(
        backend: &'a mut B,
        id: &str,
        erase_layout: Option<String>,
        progress: &'a mut dyn Write,
    ) -> Result<Completed> {
        let (pool, record) = find(backend, id)?;
        admit(backend, &record.state.hostid)?;
        if Phase::from_step(record.step)? < Phase::Erased {
            let identity = backend.disk_identity(&record.state.disk.path)?;
            super::validate_deploy_geometry(
                &identity,
                record.state.esp_bytes,
                record.state.swap_bytes,
                id,
            )?;
        }
        let mut run = Self {
            backend,
            pool,
            record,
            progress,
            erase_layout,
            notes: Vec::new(),
        };
        run.run()
    }

    fn state(&self) -> &State {
        &self.record.state
    }
    fn id(&self) -> String {
        self.record.id.clone()
    }
    fn phase(&self) -> Result<Phase> {
        Phase::from_step(self.record.step)
    }

    fn advance(&mut self, phase: Phase, change: impl FnOnce(&mut State)) -> Result<()> {
        let mut next = self.record.clone();
        next.step = phase as u32;
        change(&mut next.state);
        intent::advance(&mut Records(self.backend), &self.pool, &self.record, &next)?;
        let named = self.record.step != next.step;
        self.record = next;
        if named {
            writeln!(self.progress, "  {}", phase.name())?;
        }
        Ok(())
    }

    fn run(&mut self) -> Result<Completed> {
        loop {
            if self.phase()? < Phase::Configured {
                let view = self.backend.view()?;
                super::admit_source_automounts(&self.source_members(&view)?)?;
            }
            if self.phase()? < Phase::Staged {
                super::admit_staging_parent(&self.backend.view()?, self.state().source_pool())?;
            }
            if (Phase::Quiesced..Phase::Configured).contains(&self.phase()?) {
                self.ensure_receipt()?;
            }
            match self.phase()? {
                Phase::Recorded => self.snapshot_source()?,
                Phase::Snapshotted => self.quiesce()?,
                Phase::Quiesced => self.stage()?,
                Phase::Staged => self.verify_staging()?,
                Phase::Verified | Phase::Scrubbing => self.scrub()?,
                Phase::Scrubbed => {
                    if self.erase_layout.is_none() {
                        return Err(refuse(
                            "erasing the target disk needs a confirmation in this run",
                        ));
                    }
                    if !self.state().keep.is_empty() {
                        let view = self.backend.view()?;
                        self.old_pool(&view)?;
                    }
                    self.erase_gate()?;
                    self.advance(Phase::Erasing, |_| {})?;
                    self.erase()?
                }
                Phase::Erasing => self.erase()?,
                Phase::Erased => self.restore()?,
                Phase::Restored => self.configure()?,
                Phase::Configured => self.boot()?,
                Phase::Booted => return self.complete(),
            }
        }
    }

    fn suffix(&self) -> String {
        State::suffix(&self.record.id)
    }
    fn tag(&self) -> String {
        State::tag(&self.record.id)
    }
    fn source_suffix(&self) -> String {
        self.state()
            .snapshot
            .split_once('@')
            .map(|(_, s)| s.to_owned())
            .unwrap_or_default()
    }

    /// The source BE's members this restore copies: every member until the
    /// source is snapshotted, then those its held boundary snapshot covers.
    fn source_members<'v>(&self, view: &'v View) -> Result<Vec<&'v DatasetView>> {
        let source = &self.state().source.name;
        Ok(if self.phase()? >= Phase::Snapshotted {
            super::planned(view, source, &self.source_suffix(), &self.tag())
        } else {
            view.tree(source)
        })
    }

    /// Datasets made under the source BE after it was snapshotted: not part
    /// of it, left out and reported.
    fn left_out(&self, view: &View) -> Vec<String> {
        let source = &self.state().source.name;
        let planned = super::planned(view, source, &self.source_suffix(), &self.tag());
        view.tree(source)
            .into_iter()
            .filter(|member| !planned.iter().any(|p| p.name == member.name))
            .map(|member| member.name.clone())
            .collect()
    }

    fn source_unchanged(&self, view: &View, snapshotted: bool) -> Result<()> {
        let state = self.state();
        let changed = || {
            refuse("the captured source BE identities or snapshots changed; abandon and plan again")
        };
        let members = if snapshotted {
            super::planned(view, &state.source.name, &self.source_suffix(), &self.tag())
        } else {
            view.tree(&state.source.name)
        };
        if view
            .pool(state.source_pool())
            .is_none_or(|p| p.guid != state.source.identity.pool_guid)
            || view
                .dataset(&state.source.name)
                .is_none_or(|d| d.identity != state.source.identity)
            || state.source_identities != super::identities(&members)
        {
            return Err(changed());
        }
        if snapshotted {
            let boundary = state.boundary.as_ref().ok_or_else(changed)?;
            if view
                .snapshot(&state.snapshot)
                .is_none_or(|s| s.point != *boundary)
                || state.source_digest.as_deref()
                    != Some(tree_digest(view, &state.source.name, &self.source_suffix()).as_str())
            {
                return Err(changed());
            }
            for member in members {
                let point = view
                    .snapshot(&format!("{}@{}", member.name, self.source_suffix()))
                    .ok_or_else(changed)?;
                if point.point.identity.pool_guid != state.source.identity.pool_guid {
                    return Err(changed());
                }
            }
        }
        Ok(())
    }

    // Step 1: the source BE snapshot, in place on B.
    fn snapshot_source(&mut self) -> Result<()> {
        let state = self.state().clone();
        let view = self.backend.view()?;
        self.source_unchanged(&view, false)?;
        if view.snapshot(&state.snapshot).is_none() {
            if !state.created {
                return Err(refuse(format!("{} disappeared", state.snapshot)));
            }
            self.backend.snapshot(&state.snapshot, true)?;
        }
        let view = self.backend.view()?;
        let point = view
            .snapshot(&state.snapshot)
            .ok_or_else(|| refuse(format!("{} was not created", state.snapshot)))?
            .point
            .clone();
        if point.dataset_guid != state.source.identity.guid
            || state.boundary.as_ref().is_some_and(|b| *b != point)
        {
            return Err(refuse(format!("{} changed since the plan", state.snapshot)));
        }
        let suffix = self.source_suffix();
        let tag = self.tag();
        for member in view.tree(&state.source.name) {
            let Some(snapshot) = view.snapshot(&format!("{}@{suffix}", member.name)) else {
                continue;
            };
            if snapshot.point.dataset_guid == member.identity.guid {
                hold::hold(&mut Holds(self.backend), &snapshot.point, &tag)?;
            }
        }
        // The held boundary now fixes the BE's members; one made since the
        // plan was snapshotted with them, and this restore stops before
        // anything is erased.
        let view = self.backend.view()?;
        if super::identities(&super::planned(&view, &state.source.name, &suffix, &tag))
            != state.source_identities
        {
            return Err(refuse(
                "the source BE's datasets changed since the plan; abandon and plan again",
            ));
        }
        let digest = tree_digest(&view, &state.source.name, &suffix);
        let hostid = self.backend.snapshot_hostid(&point)?;
        if hostid != state.hostid {
            return Err(refuse(format!(
                "{} has hostid {hostid}, not {} as planned; abandon this restore",
                state.snapshot, state.hostid
            )));
        }
        if self.backend.loader(Some(&point))? != state.loader {
            return Err(refuse(format!(
                "{} ships another zboot loader than planned; abandon this restore",
                state.snapshot
            )));
        }
        self.advance(Phase::Snapshotted, |s| {
            s.boundary = Some(point);
            s.source_digest = Some(digest);
        })
    }

    fn old_pool(&mut self, view: &View) -> Result<String> {
        let old = self
            .state()
            .old_pool
            .clone()
            .ok_or_else(|| refuse("restore keeps data but recorded no target pool"))?;
        match view.pool(&old.name) {
            Some(pool) if pool.guid == old.guid => Ok(old.name),
            _ => Err(refuse(format!(
                "pool {} (guid {}) on the target disk is not imported; import it without mounting and resume",
                old.name, old.guid
            ))),
        }
    }

    // Step 2: snapshot each kept tree on A, unmounted, so nothing is missed.
    fn quiesce(&mut self) -> Result<()> {
        let suffix = self.suffix();
        let mut digests = Vec::new();
        if !self.state().keep.is_empty() {
            let view = self.backend.view()?;
            let pool = self.old_pool(&view)?;
            if view.pool(&pool).is_some_and(|p| p.readonly) {
                return Err(refuse(format!(
                    "pool {pool} is imported read-only; reopen it writable and resume"
                )));
            }
            for kept in self.state().keep.clone() {
                let root = format!("{pool}/{}", kept.relative);
                view.dataset(&root)
                    .filter(|d| d.identity.guid == kept.guid)
                    .ok_or_else(|| refuse(format!("{root} was replaced or removed")))?;
                super::admit_tree(&view, &root, "a kept tree")?;
                if let Some(mounted) = view.tree(&root).iter().find(|d| d.mounted) {
                    return Err(refuse(format!(
                        "{} is mounted; unmount it and resume",
                        mounted.name
                    )));
                }
                let name = format!("{root}@{suffix}");
                if view.snapshot(&name).is_none() {
                    self.backend.snapshot(&name, true)?;
                }
            }
            let view = self.backend.view()?;
            for kept in &self.state().keep {
                let root = format!("{pool}/{}", kept.relative);
                if let Some(missing) = view
                    .tree(&root)
                    .iter()
                    .find(|d| view.snapshot(&format!("{}@{suffix}", d.name)).is_none())
                {
                    return Err(refuse(format!(
                        "{} appeared after its tree was snapshotted; abandon and plan again",
                        missing.name
                    )));
                }
                digests.push(tree_digest(&view, &root, &suffix));
            }
        }
        self.advance(Phase::Quiesced, |s| {
            for (kept, digest) in s.keep.iter_mut().zip(digests) {
                kept.digest = Some(digest);
            }
        })
    }

    /// Create the missing parents of `container/relative` as inert datasets.
    fn parents(&mut self, container: &str, relative: &str) -> Result<()> {
        let parts: Vec<_> = relative.split('/').collect();
        for depth in 1..parts.len() {
            let name = format!("{container}/{}", parts[..depth].join("/"));
            if self.backend.view()?.dataset(&name).is_none() {
                let result = self
                    .backend
                    .create(&name, &crate::placement::inert_properties(false));
                if self.backend.view()?.dataset(&name).is_none() {
                    result?;
                }
            }
            self.verify_inert(&name, true)?;
        }
        Ok(())
    }

    fn verify_inert(&mut self, root: &str, local_parent: bool) -> Result<()> {
        let view = self.backend.view()?;
        let tree = view.tree(root);
        if tree.is_empty() {
            return Err(refuse(format!("inert receive parent {root} disappeared")));
        }
        let holds = |posture: Posture, member: &DatasetView| {
            posture.holds(member.volume, member.mounted, |key| {
                member.property(key).map(|p| (p.value.as_str(), p.local()))
            })
        };
        for member in tree {
            if !holds(Posture::Inert { parent: false }, member) {
                return Err(refuse(format!(
                    "{} is not an inert receive workspace; nothing published",
                    member.name
                )));
            }
        }
        if local_parent && !holds(Posture::Inert { parent: true }, view.dataset(root).unwrap()) {
            return Err(refuse(format!(
                "{root}'s inert values are not local inert parent authority"
            )));
        }
        Ok(())
    }

    fn quiesce_receive(&mut self, root: &str) -> Result<()> {
        let view = self.backend.view()?;
        let member = view
            .dataset(root)
            .ok_or_else(|| refuse("inert receive scope disappeared"))?;
        let endpoint = Endpoint {
            name: root.into(),
            identity: member.identity.clone(),
        };
        let id = self.id();
        self.backend.receive_quiesce(&endpoint, &id)
    }

    /// Empty preparation is recoverable even if property application or its
    /// reply failed. Data may move only after the complete posture is read back.
    fn staging_container(&mut self) -> Result<()> {
        let name = self.state().staging.clone();
        let id = self.id();
        if self.backend.view()?.dataset(&name).is_none() {
            let mut properties = crate::placement::inert_properties(false);
            properties.push((
                zfs_tools::engine::management::STAGING_PROPERTY.into(),
                id.clone(),
            ));
            let result = self.backend.create(&name, &properties);
            if self.backend.view()?.dataset(&name).is_none() {
                result?;
            }
        }
        let view = self.backend.view()?;
        let owner = view
            .dataset(&name)
            .ok_or_else(|| refuse("staging container was not created"))?;
        if owner.identity.pool_guid != self.state().source.identity.pool_guid
            || !owner
                .property(zfs_tools::engine::management::STAGING_PROPERTY)
                .is_some_and(|p| p.local() && p.value == id)
        {
            return Err(refuse(format!(
                "{name} is not this restore's staging container"
            )));
        }
        let empty = view.tree(&name).len() == 1 && view.snapshots_of(&name).is_empty();
        if empty {
            for (key, value) in crate::placement::inert_properties(false) {
                self.set_if(&view, &name, &key, &value)?;
            }
        }
        self.verify_inert(&name, true)
    }

    /// The receipt's commit point is the Quiesced advance that names it:
    /// until then A is untouched and a pass captures it again, writing it
    /// over whatever an interrupted write left; from then on every pass
    /// reads it where the record names it, before any further effect.
    fn ensure_receipt(&mut self) -> Result<()> {
        if self.state().receipt.is_some() {
            self.manifest()?;
            return self.staging_container();
        }
        if self.phase()? != Phase::Quiesced || self.state().staged != 0 {
            let only_copy = only_copy(self.state(), self.phase()?);
            return Err(receipt::unnamed(self.state(), &self.id(), only_copy));
        }
        self.staging_container()?;
        let state = self.state().clone();
        let id = self.id();
        let payload = receipt::capture(self.backend, &state, &id)?;
        let named = receipt::write(self.backend, &state, &id, &payload)?;
        self.advance(Phase::Quiesced, |s| s.receipt = Some(named))
    }

    /// The receipt's payload: placement and the manifest. A receipt that
    /// does not read refuses, naming what can be done.
    fn manifest(&mut self) -> Result<receipt::Receipt> {
        let state = self.state().clone();
        let id = self.id();
        let only_copy = only_copy(&state, self.phase()?);
        if state.receipt.is_none() {
            return Err(receipt::unnamed(&state, &id, only_copy));
        }
        receipt::read(self.backend, &state, &id).map_err(|error| {
            receipt::damaged(self.backend, &state, &id, only_copy, "abandon", error)
        })
    }

    /// The trees this restore stages: each kept tree from A into staging.
    fn staging_copies(&mut self, pool: &str) -> Result<Vec<TreeCopy>> {
        let manifest = self.manifest()?;
        let staging = self.state().staging.clone();
        let suffix = self.suffix();
        self.state()
            .keep
            .iter()
            .map(|kept| {
                Ok(TreeCopy {
                    source: format!("{pool}/{}", kept.relative),
                    destination: format!("{staging}/{}", kept.relative),
                    suffix: suffix.clone(),
                    members: manifest
                        .kept
                        .get(&kept.relative)
                        .ok_or_else(|| refuse("restore placement receipt lacks a kept tree"))?
                        .members
                        .clone(),
                })
            })
            .collect()
    }

    /// The trees this restore returns to A: the BE from B, then each staged
    /// kept tree.
    fn return_copies(&mut self, pool: &str) -> Result<Vec<TreeCopy>> {
        let manifest = self.manifest()?;
        let state = self.state().clone();
        let mut copies = vec![TreeCopy {
            source: state.source.name.clone(),
            destination: state.restored_be(),
            suffix: self.source_suffix(),
            members: manifest.source_tree.members.clone(),
        }];
        for kept in &state.keep {
            copies.push(TreeCopy {
                source: format!("{}/{}", state.staging, kept.relative),
                destination: format!("{pool}/{}", kept.relative),
                suffix: self.suffix(),
                members: manifest
                    .kept
                    .get(&kept.relative)
                    .ok_or_else(|| refuse("restore placement receipt lacks a kept tree"))?
                    .members
                    .clone(),
            });
        }
        Ok(copies)
    }

    /// The destruction rule: destroy `destination` and everything in it only
    /// when both hold. Ownership: it lies in a scope this operation made and
    /// records, its staging container (local `zboot:staging` and this record)
    /// or the pool it deployed on A (by GUID). Content: nothing was added
    /// since, every dataset in it being a copy of the matching one under
    /// `source` with only its snapshots and `written=0` ([`partial_copy`]).
    /// Neither alone authorizes anything. This operation's holds on it are
    /// released only after both are proved. Staging is discarded only while
    /// every key file it was made under still opens from off A
    /// ([`Run::keys_available`]): staging it again must not depend on a key
    /// the erase would destroy.
    fn discard(&mut self, destination: &str, source: &str) -> Result<()> {
        let state = self.state().clone();
        let id = self.id();
        let view = self.backend.view()?;
        let in_staging = within(&state.staging, destination)
            && destination != state.staging
            && view.dataset(&state.staging).is_some_and(|owner| {
                owner.identity.pool_guid == state.source.identity.pool_guid
                    && owner
                        .property(zfs_tools::engine::management::STAGING_PROPERTY)
                        .is_some_and(|p| p.local() && p.value == id)
            });
        let in_new_pool = state.new_pool.is_some_and(|guid| {
            view.pools.iter().any(|pool| {
                pool.guid == guid && within(&pool.name, destination) && pool.name != destination
            })
        });
        if !in_staging && !in_new_pool {
            return Err(refuse(format!(
                "{destination} is not in a place this restore made; it is left as it is"
            )));
        }
        if in_staging {
            self.keys_available()?;
        }
        partial_copy(&view, destination, source)?;
        let tag = self.tag();
        for member in view.tree(destination) {
            for snapshot in view.snapshots_of(&member.name) {
                if snapshot.holds.contains(&tag) {
                    hold::release(&mut Holds(self.backend), &snapshot.point, &tag)?;
                }
            }
        }
        writeln!(
            self.progress,
            "  discarding {} to send it again in one attempt",
            zfs_tools::engine::escape_display(destination)
        )?;
        self.backend.destroy_tree(destination)
    }

    /// One stream, with its outcome judged.
    fn stream(&mut self, stream: LeafStream) -> Result<()> {
        writeln!(
            self.progress,
            "  sending {} to {}",
            zfs_tools::engine::escape_display(&stream.boundary.name),
            zfs_tools::engine::escape_display(&stream.destination)
        )?;
        if within(&self.state().source.name, &stream.source.name) {
            let view = self.backend.view()?;
            self.source_unchanged(&view, true)?;
        }
        match self.backend.stream(&stream) {
            Ok(outcome) if outcome.complete() => Ok(()),
            Ok(outcome) => Err(refuse(format!(
                "receive of {} into {} did not complete: {} {}",
                stream.boundary.name,
                stream.destination,
                outcome.sender_stderr.trim(),
                outcome.receiver_stderr.trim()
            ))),
            Err(error) => Err(refuse(format!(
                "receive of {} into {} failed: {error}",
                stream.boundary.name, stream.destination
            ))),
        }
    }

    /// Local fences on a new copy: set and read back on every attempt, before
    /// anything else could happen to it.
    fn fence(&mut self, name: &str, volume: bool) -> Result<()> {
        let inert = Posture::Inert { parent: true };
        for (key, value) in inert.properties(volume) {
            let view = self.backend.view()?;
            self.set_if(&view, name, key, value)?;
        }
        Ok(())
    }

    /// Copy one member of `copy`: a full stream of its first snapshot when
    /// the copy has none, fences, then one incremental to the boundary from
    /// the copy's newest snapshot. Every step before data runs on every
    /// attempt; a dataset already there continues only as this operation's
    /// own partial copy.
    fn send_member(
        &mut self,
        copy: &TreeCopy,
        relative: &str,
        member: &receipt::Member,
    ) -> Result<()> {
        let source = join(&copy.source, relative);
        let destination = join(&copy.destination, relative);
        let view = self.backend.view()?;
        let dataset = view
            .dataset(&source)
            .ok_or_else(|| refuse(format!("{source} disappeared")))?;
        if dataset.volume != member.volume {
            return Err(refuse(format!("{source} changed type")));
        }
        let endpoint = Endpoint {
            name: source.clone(),
            identity: dataset.identity.clone(),
        };
        let history = history(&view, &source, &copy.suffix)?;
        self.verify_inert(parent_of(&destination)?, true)?;
        if let Some(existing) = view.dataset(&destination) {
            adoptable(&view, existing, &source, &history)?;
            if let Some(key) = manifest::write_time_differs(&member.properties, existing) {
                writeln!(
                    self.progress,
                    "  {} received data while its {key} differed from {source}'s",
                    zfs_tools::engine::escape_display(&destination)
                )?;
                self.discard(&destination, &source)?;
            }
        }
        if self.backend.view()?.dataset(&destination).is_none() {
            self.stream(LeafStream {
                source: endpoint.clone(),
                base: None,
                boundary: history[0].clone(),
                destination: destination.clone(),
                create: manifest::creation(member.volume, &member.properties),
            })?;
        }
        self.fence(&destination, member.volume)?;
        let view = self.backend.view()?;
        let newest = view
            .snapshots_of(&destination)
            .last()
            .map(|s| s.point.identity.guid)
            .ok_or_else(|| refuse(format!("{destination} has no snapshot after its stream")))?;
        let at = history
            .iter()
            .position(|p| p.identity.guid == newest)
            .ok_or_else(|| {
                refuse(format!(
                    "{destination}'s newest snapshot is not in {source}'s history"
                ))
            })?;
        if at + 1 < history.len() {
            self.stream(LeafStream {
                source: endpoint,
                base: Some(history[at].clone()),
                boundary: history[history.len() - 1].clone(),
                destination: destination.clone(),
                create: Vec::new(),
            })?;
        }
        let view = self.backend.view()?;
        let held: Vec<_> = view
            .snapshots_of(&destination)
            .iter()
            .map(|s| (suffix_of(&s.point.name), s.point.identity.guid))
            .collect();
        let sent: Vec<_> = history
            .iter()
            .map(|p| (suffix_of(&p.name), p.identity.guid))
            .collect();
        if held != sent {
            return Err(refuse(format!(
                "{destination} does not hold {source}'s snapshots after its streams"
            )));
        }
        Ok(())
    }

    /// Copy every member of `copy`, parents first. An encrypted tree is
    /// copied in one attempt: what an earlier attempt left of it is
    /// discarded under the destruction rule first, so a key changed between
    /// attempts cannot mix wrappings.
    fn copy_tree(&mut self, copy: &TreeCopy) -> Result<()> {
        if copy.encrypted() && self.backend.view()?.dataset(&copy.destination).is_some() {
            self.discard(&copy.destination, &copy.source)?;
        }
        let parent = parent_of(&copy.destination)?.to_owned();
        self.quiesce_receive(&parent)?;
        self.verify_inert(&parent, true)?;
        for (relative, member) in &copy.members {
            self.send_member(copy, relative, member)?;
        }
        let view = self.backend.view()?;
        if let Some(foreign) = view.tree(&copy.destination).into_iter().find(|d| {
            !copy
                .members
                .contains_key(d.name[copy.destination.len()..].trim_start_matches('/'))
        }) {
            return Err(refuse(format!(
                "{} is not part of the copy of {}; move it out and resume",
                foreign.name, copy.source
            )));
        }
        self.verify_inert(&copy.destination, false)?;
        self.quiesce_receive(&copy.destination)
    }

    // Step 3: stage every kept tree on B, dataset by dataset.
    fn stage(&mut self) -> Result<()> {
        if !self.state().keep.is_empty() {
            let view = self.backend.view()?;
            let pool = self.old_pool(&view)?;
            let copies = self.staging_copies(&pool)?;
            for (index, copy) in copies.iter().enumerate() {
                if (index as u32) < self.state().staged {
                    continue;
                }
                let relative = self.state().keep[index].relative.clone();
                let staging = self.state().staging.clone();
                self.parents(&staging, &relative)?;
                self.copy_tree(copy).map_err(|e| {
                    refuse(format!(
                        "{e}; A is unchanged: fix the cause (such as space on B) and resume, or abandon"
                    ))
                })?;
                self.advance(Phase::Quiesced, |s| s.staged = index as u32 + 1)?;
            }
        }
        self.advance(Phase::Staged, |_| {})
    }

    /// `copy`'s destination holds every member the manifest lists and
    /// nothing else, the members' snapshot GUIDs (`digest`), their
    /// stream-carried and write-time values and their encryption: on staging
    /// each encrypted copy is its own root (`relinked` false), on A it takes
    /// its key from its copied root. Staged copies are fenced.
    fn verify_copy(&mut self, copy: &TreeCopy, digest: &str, relinked: bool) -> Result<()> {
        let view = self.backend.view()?;
        let root = &copy.destination;
        if view.dataset(root).is_none() {
            return Err(refuse(format!("{root} is missing; abandon this restore")));
        }
        if let Some(partial) = view.tree(root).iter().find(|d| d.resume_token) {
            return Err(refuse(format!("{} holds a partial receive", partial.name)));
        }
        if tree_digest(&view, root, &copy.suffix) != digest {
            return Err(refuse(format!(
                "{root} does not match the members and snapshot GUIDs of {}; abandon this restore",
                copy.source
            )));
        }
        let present: Vec<_> = view
            .tree(root)
            .iter()
            .map(|d| d.name[root.len()..].trim_start_matches('/').to_owned())
            .collect();
        if present.iter().ne(copy.members.keys()) {
            return Err(refuse(format!(
                "{root} does not hold exactly the datasets its manifest lists"
            )));
        }
        for (relative, member) in &copy.members {
            let name = join(root, relative);
            let dataset = view.dataset(&name).unwrap();
            if dataset.volume != member.volume {
                return Err(refuse(format!("{name} changed type")));
            }
            manifest::verify_data(&member.properties, dataset)?;
            match &member.encryption {
                None if dataset.encrypted => {
                    return Err(refuse(format!("{name} is encrypted, its source was not")));
                }
                None => {}
                Some(keys) => {
                    let intended = if relinked {
                        join(root, &keys.root)
                    } else {
                        name.clone()
                    };
                    if dataset.encryption_root.as_deref() != Some(intended.as_str())
                        || (keys.root == *relative
                            && dataset.value("keyformat") != Some(keys.keyformat.as_str()))
                    {
                        return Err(refuse(format!(
                            "{name}'s encryption is not its manifest's (root {intended}, {})",
                            keys.keyformat
                        )));
                    }
                }
            }
            if !relinked {
                let fences = Posture::Inert { parent: true }.properties(member.volume);
                if dataset.mounted
                    || fences.iter().any(|(key, value)| {
                        !dataset
                            .property(key)
                            .is_some_and(|p| p.local() && p.value == *value)
                    })
                {
                    return Err(refuse(format!("{name} is not fenced")));
                }
            }
        }
        Ok(())
    }

    /// Prove without asking for any key that every dataset in `copies` is
    /// wrapped like the encryption root `root`: a passphrase by equal
    /// format, salt and iterations (a key change always makes a new salt); a
    /// raw or hex key by `location`, a file, opening `root` and every copy
    /// (`zfs load-key -n`, which checks only the dataset it names). A key at
    /// a prompt, or a file that does not open `root`, cannot be proved.
    fn prove(&mut self, root: &str, copies: &[String], location: &str) -> Result<Proof> {
        let view = self.backend.view()?;
        let endpoint = |name: &str| -> Result<Endpoint> {
            Ok(Endpoint {
                name: name.into(),
                identity: view
                    .dataset(name)
                    .ok_or_else(|| refuse(format!("{name} disappeared")))?
                    .identity
                    .clone(),
            })
        };
        let reference = self.backend.wrapping(&endpoint(root)?)?;
        if reference.keyformat != "passphrase" {
            if !location.starts_with("file://") {
                return Err(refuse(format!(
                    "the {} key of {root} is entered at a prompt; restore cannot prove its copies \
                     are wrapped like it without asking for it",
                    reference.keyformat
                )));
            }
            self.backend.check_key(root, location).map_err(|error| {
                refuse(format!(
                    "{location} does not open {root} ({error}); restore cannot prove its copies' keys"
                ))
            })?;
        }
        for copy in copies {
            let wrapping = self.backend.wrapping(&endpoint(copy)?)?;
            let same = wrapping.keyformat == reference.keyformat
                && if reference.keyformat == "passphrase" {
                    wrapping.pbkdf2salt == reference.pbkdf2salt
                        && wrapping.pbkdf2iters == reference.pbkdf2iters
                } else {
                    self.backend.check_key(copy, location).is_ok()
                };
            if !same {
                return Ok(Proof::Differs(format!(
                    "{copy} is wrapped otherwise than {root}"
                )));
            }
        }
        Ok(Proof::Proven)
    }

    /// Prove every staged dataset of `copy` wrapped like its intended root on
    /// A, which still exists.
    fn prove_staged(&mut self, copy: &TreeCopy) -> Result<Proof> {
        let mut roots: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
        for (relative, member) in &copy.members {
            if let Some(keys) = &member.encryption {
                roots
                    .entry(keys.root.clone())
                    .or_insert_with(|| (keys.keylocation.clone(), Vec::new()))
                    .1
                    .push(join(&copy.destination, relative));
            }
        }
        for (root, (location, staged)) in roots {
            if let Proof::Differs(why) =
                self.prove(&join(&copy.source, &root), &staged, &location)?
            {
                return Ok(Proof::Differs(why));
            }
        }
        Ok(Proof::Proven)
    }

    /// Verify every staged copy against the manifest, which needs no A, and
    /// with `prove` (A's pool imported) prove it still wrapped like A's live
    /// root. A completely staged tree whose key changed since is never
    /// staged again: the new key may live only on A, and the erase would
    /// destroy it with A. The operator changes the key back or abandons.
    fn check_staging(&mut self, prove: bool) -> Result<()> {
        let pool = self
            .state()
            .old_pool
            .clone()
            .ok_or_else(|| refuse("restore keeps data but recorded no target pool"))?
            .name;
        let copies = self.staging_copies(&pool)?;
        for (index, copy) in copies.iter().enumerate() {
            let digest = self.state().keep[index].digest.clone().unwrap_or_default();
            self.verify_copy(copy, &digest, false)?;
            if !prove {
                continue;
            }
            if let Proof::Differs(why) = self.prove_staged(copy)? {
                let passphrase = copy
                    .members
                    .values()
                    .filter_map(|m| m.encryption.as_ref())
                    .any(|keys| keys.keyformat == "passphrase");
                return Err(refuse(format!(
                    "the key of {} changed since it was staged ({why}); change it back, or abandon \
                     this restore and plan it again. Nothing was erased or discarded{}",
                    copy.source,
                    if passphrase {
                        ". A passphrase cannot be changed back: `zfs change-key` always makes a new salt"
                    } else {
                        ""
                    }
                )));
            }
        }
        Ok(())
    }

    /// The plan's off-A key check, repeated before any staging is discarded
    /// and before the erase. For every encryption root of a kept tree:
    /// while A's pool is imported, nothing of it is mounted (so a file found
    /// now is not on A) and the root's key format and location are still
    /// the manifest's, which the returned root takes; and a key in a file,
    /// passphrase or raw or hex alike, opens from here A's root and the
    /// tree's complete staged copy (`zfs load-key -n -L`). The source BE's
    /// key files open its root on B. A key only A holds would be erased
    /// with it, leaving the only copy unopenable.
    fn keys_available(&mut self) -> Result<()> {
        let state = self.state().clone();
        let manifest = self.manifest()?;
        let view = self.backend.view()?;
        let live = state
            .old_pool
            .as_ref()
            .filter(|old| view.pool(&old.name).is_some_and(|p| p.guid == old.guid))
            .map(|old| old.name.clone());
        if let Some(pool) = &live
            && let Some(mounted) = view.tree(pool).into_iter().find(|d| d.mounted)
        {
            return Err(refuse(format!(
                "{} on the target disk is mounted, so a key file found now may be on it; unmount \
                 everything on it and resume",
                mounted.name
            )));
        }
        let mut checks = Vec::new();
        for (relative, member) in &manifest.source_tree.members {
            if let Some(keys) = member.encryption.as_ref().filter(|k| k.root == *relative) {
                checks.push((join(&state.source.name, relative), keys.clone()));
            }
        }
        for (index, kept) in state.keep.iter().enumerate() {
            let tree = manifest
                .kept
                .get(&kept.relative)
                .ok_or_else(|| refuse("restore placement receipt lacks a kept tree"))?;
            for (relative, member) in &tree.members {
                let Some(keys) = member.encryption.as_ref().filter(|k| k.root == *relative) else {
                    continue;
                };
                if let Some(pool) = &live {
                    let root = join(&format!("{pool}/{}", kept.relative), relative);
                    let dataset = view
                        .dataset(&root)
                        .ok_or_else(|| refuse(format!("{root} disappeared after it was staged")))?;
                    let format = dataset.value("keyformat").unwrap_or("-");
                    let location = dataset.value("keylocation").unwrap_or("-");
                    if format != keys.keyformat || location != keys.keylocation {
                        return Err(refuse(format!(
                            "the key of {root} changed since it was staged (keyformat {format}, \
                             keylocation {location}; staged as {}, {}): change it back, or abandon \
                             this restore and plan it again. Nothing was erased or discarded",
                            keys.keyformat, keys.keylocation
                        )));
                    }
                    checks.push((root, keys.clone()));
                }
                if (index as u32) < state.staged {
                    let staged = join(&format!("{}/{}", state.staging, kept.relative), relative);
                    checks.push((staged, keys.clone()));
                }
            }
        }
        for (dataset, keys) in checks {
            if !keys.keylocation.starts_with("file://") {
                continue;
            }
            self.backend
                .check_key(&dataset, &keys.keylocation)
                .map_err(|error| {
                    refuse(format!(
                        "the key file {} does not open {dataset} from here ({error}); a key only A \
                         holds would be erased with it. Nothing was erased or discarded: put a copy \
                         of the key off A at that path and resume, or abandon",
                        keys.keylocation
                    ))
                })?;
        }
        Ok(())
    }

    /// Before A is erased, checked when the erase is confirmed and again
    /// before the wipe of every attempt, whether or not A's pool is still
    /// imported. While A is still there (imported, or its disk unchanged
    /// since the plan): each kept tree still what was staged (when
    /// imported), staging proved against A, every key file off A, and every
    /// pair record the plan ends still as planned, since after the wipe
    /// restore must not stop for any of these. Always: staging matches the
    /// manifest, and the key relink helper works when the return needs it.
    /// Nothing here changes anything.
    fn erase_gate(&mut self) -> Result<()> {
        let state = self.state().clone();
        let view = self.backend.view()?;
        let live = state
            .old_pool
            .as_ref()
            .filter(|old| view.pool(&old.name).is_some_and(|p| p.guid == old.guid))
            .map(|old| old.name.clone());
        let intact = live.is_some() || self.erase_layout.as_ref() == Some(&state.disk.layout);
        if !state.keep.is_empty() {
            if let Some(pool) = &live {
                self.kept_unchanged(&view, pool)?;
            }
            self.check_staging(live.is_some())?;
            if intact {
                self.keys_available()?;
            }
        }
        if intact {
            for ended in &state.ended_pairs {
                if let Ending::Changed(why) = ending(&view, ended) {
                    return Err(refuse(format!(
                        "{why}; restore ends that pair record once A is erased, so nothing was \
                         erased: put it back and resume, or abandon this restore and plan it again"
                    )));
                }
            }
        }
        self.relink_ready()
    }

    /// The returned trees need `lzc_change_key` when an encrypted dataset
    /// takes its key from another one ([`Run::relink`]). Its helper is a
    /// separate, dynamically linked program; it must work here before A is
    /// erased.
    fn relink_ready(&mut self) -> Result<()> {
        let manifest = self.manifest()?;
        let relinks = std::iter::once(&manifest.source_tree)
            .chain(manifest.kept.values())
            .flat_map(|tree| tree.members.iter())
            .any(|(relative, member)| {
                member
                    .encryption
                    .as_ref()
                    .is_some_and(|k| k.root != *relative)
            });
        if relinks {
            self.backend.change_key_ready().map_err(|error| {
                refuse(format!(
                    "{}; restore needs it to relink encryption keys on A, so nothing was erased",
                    super::change_key_unavailable(&error)
                ))
            })?;
        }
        Ok(())
    }

    // Step 4: verify staging against the manifest and prove its wrapping,
    // without keys, then hold it.
    fn verify_staging(&mut self) -> Result<()> {
        let tag = self.tag();
        if !self.state().keep.is_empty() {
            let view = self.backend.view()?;
            self.old_pool(&view)?;
            self.check_staging(true)?;
            self.keys_available()?;
            let view = self.backend.view()?;
            for kept in self.state().keep.clone() {
                let root = format!("{}/{}", self.state().staging, kept.relative);
                // Every staged snapshot is held, not only the boundary: once A
                // is erased, staging is the only copy of A's whole history.
                for member in view.tree(&root) {
                    for snapshot in view.snapshots_of(&member.name) {
                        hold::hold(&mut Holds(self.backend), &snapshot.point, &tag)?;
                    }
                }
            }
        }
        self.advance(Phase::Verified, |_| {})
    }

    // Step 5: a complete clean scrub of B, begun after staging.
    fn scrub(&mut self) -> Result<()> {
        if self.state().keep.is_empty() {
            return self.advance(Phase::Scrubbed, |_| {});
        }
        let pool = self.pool.clone();
        if self.phase()? == Phase::Verified {
            let now = self.backend.now();
            self.advance(Phase::Scrubbing, |s| s.scrub_after = Some(now))?;
        }
        let after = self.state().scrub_after.unwrap_or_default();
        let mut shown = None;
        loop {
            let scrub = self.backend.scrub_status(&pool)?;
            if scrub.state == "FINISHED" && scrub.start_time >= after {
                if scrub.errors != 0 || scrub.pool_errors != 0 {
                    return Err(refuse(format!(
                        "the scrub of {pool} found {} errors ({} in the pool error log); staging is not trusted and A is unchanged",
                        scrub.errors, scrub.pool_errors
                    )));
                }
                return self.advance(Phase::Scrubbed, |_| {});
            }
            if scrub.state == "SCANNING" && !scrub.paused {
                let percent = (scrub.examined * 100)
                    .checked_div(scrub.to_examine)
                    .unwrap_or(0)
                    .min(100);
                if shown != Some(percent) {
                    writeln!(
                        self.progress,
                        "  scrubbing {pool}: {percent}% (interrupt and `zboot resume {}` at any time)",
                        self.record.id
                    )?;
                    shown = Some(percent);
                }
            } else if scrub.state != "BUSY" {
                // None yet, an older one, cancelled, or paused: (re)start it.
                // A resilver in progress (BUSY) is waited for.
                self.backend.scrub(&pool)?;
            }
            for _ in 0..POLL_SECONDS {
                self.backend.pause();
            }
        }
    }

    /// Before A is erased: each kept tree is still exactly what was staged,
    /// with no snapshot, member or write after its boundary, which would
    /// otherwise be lost although the operator chose to keep it, and with the
    /// encryption roots its manifest records.
    fn kept_unchanged(&mut self, view: &View, pool: &str) -> Result<()> {
        let suffix = self.suffix();
        let manifest = self.manifest()?;
        for kept in &self.state().keep {
            let root = format!("{pool}/{}", kept.relative);
            let changed = |what: String| {
                refuse(format!(
                    "{what} after it was staged, so staging would not keep it; nothing was erased: abandon and plan again"
                ))
            };
            if view.dataset(&root).map(|d| d.identity.guid) != Some(kept.guid)
                || Some(tree_digest(view, &root, &suffix)) != kept.digest
            {
                return Err(changed(format!("{root} was replaced or changed")));
            }
            // A new member or snapshot is named before any write: creating a
            // child also makes its parent's `written` nonzero.
            let members = view.tree(&root);
            for member in &members {
                let newest = view.snapshots_of(&member.name).last().map(|s| {
                    s.point
                        .name
                        .split_once('@')
                        .map_or("", |(_, n)| n)
                        .to_owned()
                });
                if newest.as_deref() != Some(suffix.as_str()) {
                    return Err(changed(format!(
                        "{} gained a snapshot or was created",
                        member.name
                    )));
                }
            }
            if let Some(member) = members.iter().find(|m| m.value("written") != Some("0")) {
                return Err(changed(format!("{} was written", member.name)));
            }
            let tree = manifest
                .kept
                .get(&kept.relative)
                .ok_or_else(|| refuse("restore placement receipt lacks a kept tree"))?;
            for member in &members {
                let relative = member.name[root.len()..].trim_start_matches('/');
                let recorded = tree
                    .members
                    .get(relative)
                    .and_then(|m| m.encryption.as_ref())
                    .map(|keys| join(&root, &keys.root));
                if member.encryption_root != recorded {
                    return Err(changed(format!(
                        "{}'s encryption root changed",
                        member.name
                    )));
                }
            }
        }
        Ok(())
    }

    // Step 6: erase A and deploy an empty root pool with the bound Menu.
    fn erase(&mut self) -> Result<()> {
        let layout = self.erase_layout.clone().ok_or_else(|| {
            refuse(
                "erasure of the target disk was interrupted; continuing needs a fresh confirmation",
            )
        })?;
        let state = self.state().clone();
        super::require_host(self.backend, &state.hostid)?;
        self.backend.require_no_image()?;
        let identity = self.backend.disk_identity(&state.disk.path)?;
        if !state.disk.same_disk(&identity) {
            return Err(refuse(
                "the target disk is not the one confirmed; nothing more was erased",
            ));
        }
        super::validate_deploy_geometry(&identity, state.esp_bytes, state.swap_bytes, &self.id())?;
        let view = self.backend.view()?;
        self.source_unchanged(&view, true)?;
        self.erase_gate()?;
        for pool in &view.pools {
            let disks = self.backend.pool_disks(&pool.name, pool.guid)?;
            if !disks
                .iter()
                .any(|d| d.device_number == identity.device_number)
            {
                continue;
            }
            if pool.name == state.source_pool() || disks.len() != 1 {
                return Err(refuse(format!(
                    "pool {} uses the target disk and another device",
                    pool.name
                )));
            }
            self.backend.export(&pool.name)?;
        }
        let review = self.backend.disk(&state.disk.path, None)?;
        if super::DiskBinding::of(&review)?.layout != layout {
            return Err(refuse(
                "the target disk's layout changed since it was confirmed; nothing more was erased",
            ));
        }
        writeln!(
            self.progress,
            "  erasing {} ({} bytes)",
            zfs_tools::engine::escape_display(&state.disk.path),
            state.disk.bytes
        )?;
        let view = self.backend.view()?;
        self.source_unchanged(&view, true)?;
        let snapshot = state
            .boundary
            .clone()
            .ok_or_else(|| refuse("restore record lacks its source snapshot"))?;
        self.backend.wipe(&review)?;
        // The old peers are gone now, even if deploying the replacement fails.
        self.end_pairs()?;
        // Erased: the confirmation is spent; a later cut needs a fresh one.
        self.erase_layout = None;
        let spec = DeploySpec {
            disk: review.identity.clone(),
            pool: state.pool.clone(),
            hostid: state.hostid.clone(),
            esp_bytes: state.esp_bytes,
            swap_bytes: state.swap_bytes,
            snapshot,
            loader: state.loader.clone(),
            journal_directory: format!("/run/zboot/restore-{}", self.record.id).into(),
        };
        writeln!(
            self.progress,
            "  partitioning and creating pool {}",
            state.pool
        )?;
        let guid = self.backend.deploy(&spec)?;
        self.backend.import(guid, &state.hostid)?;
        self.advance(Phase::Erased, |s| s.new_pool = Some(guid))
    }

    /// The new pool, imported writable.
    fn new_pool(&mut self) -> Result<String> {
        let state = self.state().clone();
        let guid = state
            .new_pool
            .ok_or_else(|| refuse("restore record lacks the new pool"))?;
        super::require_host(self.backend, &state.hostid)?;
        // A writable import made while the UKI had no hostid recorded none.
        // Only an import under the BE's own hostid is kept as it is.
        let as_host = self.backend.effective_hostid()? == state.hostid;
        let view = self.backend.view()?;
        match view.pools.iter().find(|p| p.guid == guid) {
            Some(pool) if pool.name != state.pool => {
                return Err(refuse(format!(
                    "pool guid {guid} is imported as {}, not {}",
                    pool.name, state.pool
                )));
            }
            Some(pool) if !pool.readonly && as_host => return Ok(pool.name.clone()),
            Some(pool) => {
                self.backend.export(&pool.name.clone())?;
                self.backend.import(guid, &state.hostid)?;
            }
            None => self.backend.import(guid, &state.hostid)?,
        }
        let view = self.backend.view()?;
        match view.pools.iter().find(|p| p.guid == guid) {
            Some(pool) if !pool.readonly && pool.name == state.pool => Ok(pool.name.clone()),
            _ => Err(refuse(format!(
                "pool {} (guid {guid}) could not be imported writable",
                state.pool
            ))),
        }
    }

    // Step 7: the BE from B and the staged trees, at their original names,
    // dataset by dataset; then their encryption and copied properties.
    fn restore(&mut self) -> Result<()> {
        let pool = self.new_pool()?;
        // The freshly deployed pool and its ROOT shell belong to this
        // restore. Prepare only empty shells; never sweep data into safety.
        for name in [&pool, &format!("{pool}/ROOT")] {
            let view = self.backend.view()?;
            if view.dataset(name).is_none() {
                return Err(refuse("new restore parent disappeared"));
            }
            if view.snapshots_of(name).is_empty()
                && view
                    .tree(name)
                    .iter()
                    .all(|d| d.name == *name || view.snapshots_of(&d.name).is_empty())
            {
                for (key, value) in crate::placement::inert_properties(false) {
                    self.set_if(&view, name, &key, &value)?;
                }
            }
            // Pool-root scopes can contain a DEV probe left by a cut. Its
            // identity-bound recovery must run before recursive admission.
            self.quiesce_receive(name)?;
            self.verify_inert(name, true)?;
        }
        // A is erased, so a pair whose other side was on A has lost it.
        self.end_pairs()?;
        let state = self.state().clone();
        let view = self.backend.view()?;
        self.source_unchanged(&view, true)?;
        let members = self.source_members(&view)?;
        super::admit_members(&view, &state.source.name, &members, "the source BE")?;
        for name in self.left_out(&view) {
            writeln!(
                self.progress,
                "  {} appeared under the source BE after it was snapshotted; it is left out",
                zfs_tools::engine::escape_display(&name)
            )?;
        }
        let copies = self.return_copies(&pool)?;
        for (index, copy) in copies.iter().enumerate() {
            if (index as u32) < self.state().returned {
                continue;
            }
            if index > 0 {
                self.parents(&pool, &state.keep[index - 1].relative)?;
            }
            self.copy_tree(copy)?;
            self.relink(copy)?;
            self.copy_properties(copy)?;
            self.advance(Phase::Erased, |s| s.returned = index as u32 + 1)?;
        }
        self.advance(Phase::Restored, |_| {})
    }

    /// Point every encrypted dataset of `copy` on A at its copied encryption
    /// root: a raw receive makes each new dataset its own root. A dataset that
    /// inherited its key is relinked to its parent's root (FORCE_INHERIT)
    /// only after its wrapping is proved equal to that root's, since the
    /// relink checks nothing; a root that inherits is made its own root
    /// again (FORCE_NEW_KEY). Parents first; then each root gets the key
    /// location its source had.
    fn relink(&mut self, copy: &TreeCopy) -> Result<()> {
        for (relative, member) in &copy.members {
            let Some(keys) = &member.encryption else {
                continue;
            };
            let name = join(&copy.destination, relative);
            let intended = join(&copy.destination, &keys.root);
            let view = self.backend.view()?;
            let dataset = view
                .dataset(&name)
                .ok_or_else(|| refuse(format!("{name} disappeared")))?;
            if dataset.encryption_root.as_deref() == Some(intended.as_str()) {
                continue;
            }
            let endpoint = Endpoint {
                name: name.clone(),
                identity: dataset.identity.clone(),
            };
            if intended == name {
                self.backend.change_key(&endpoint, false)?;
            } else {
                let parent = parent_of(&name)?;
                if view
                    .dataset(parent)
                    .and_then(|p| p.encryption_root.as_deref())
                    != Some(intended.as_str())
                    || dataset.encryption_root.as_deref() != Some(name.as_str())
                {
                    return Err(refuse(format!(
                        "{name} cannot be relinked to {intended}: it or its parent takes its key elsewhere"
                    )));
                }
                let location = copy
                    .members
                    .get(&keys.root)
                    .and_then(|root| root.encryption.as_ref())
                    .map_or(keys.keylocation.clone(), |root| root.keylocation.clone());
                if let Proof::Differs(why) =
                    self.prove(&intended, std::slice::from_ref(&name), &location)?
                {
                    return Err(refuse(format!(
                        "{why}, so {name} is not relinked; resume to send {} again in one attempt",
                        copy.destination
                    )));
                }
                writeln!(
                    self.progress,
                    "  {} takes its key from {} again",
                    zfs_tools::engine::escape_display(&name),
                    zfs_tools::engine::escape_display(&intended)
                )?;
                self.backend.change_key(&endpoint, true)?;
            }
            if self
                .backend
                .view()?
                .dataset(&name)
                .and_then(|d| d.encryption_root.clone())
                != Some(intended.clone())
            {
                return Err(refuse(format!(
                    "{name}'s encryption root is not {intended} after relinking it"
                )));
            }
        }
        for (relative, member) in &copy.members {
            let Some(keys) = member.encryption.as_ref().filter(|k| k.root == *relative) else {
                continue;
            };
            let name = join(&copy.destination, relative);
            let view = self.backend.view()?;
            self.set_if(&view, &name, "keylocation", &keys.keylocation)?;
        }
        Ok(())
    }

    /// Give every dataset of `copy` on A its manifest's properties, parents
    /// first: the desired state per key, then a local value where the copy's
    /// own inheritance gives another. A space limit A cannot take is reported
    /// and does not stop the restore.
    fn copy_properties(&mut self, copy: &TreeCopy) -> Result<()> {
        for (relative, member) in &copy.members {
            let name = join(&copy.destination, relative);
            let view = self.backend.view()?;
            let current = view
                .dataset(&name)
                .ok_or_else(|| refuse(format!("{name} disappeared")))?
                .clone();
            for (key, value) in manifest::changes(&member.properties, &current) {
                self.copy_property(&view, &name, &key, value.as_deref())?;
            }
            let view = self.backend.view()?;
            let current = view.dataset(&name).unwrap().clone();
            for (key, value) in manifest::materialize(&member.properties, &current) {
                self.copy_property(&view, &name, &key, value.as_deref())?;
            }
            let view = self.backend.view()?;
            for key in manifest::verify(&member.properties, view.dataset(&name).unwrap())? {
                let note = format!(
                    "{name} could not take its source's {key}; set it once A has room (`zfs set {key}=... {name}`)"
                );
                if !self.notes.contains(&note) {
                    self.notes.push(note);
                }
            }
        }
        Ok(())
    }

    fn copy_property(
        &mut self,
        view: &View,
        name: &str,
        key: &str,
        value: Option<&str>,
    ) -> Result<()> {
        let result = match value {
            Some(value) => self.set_if(view, name, key, value),
            None => {
                let result = self.backend.inherit(name, key);
                let explicit = self
                    .backend
                    .view()?
                    .dataset(name)
                    .and_then(|d| d.property(key))
                    .is_some_and(|p| p.local() || p.received());
                match (result, explicit) {
                    (_, false) => Ok(()),
                    (Err(error), true) => Err(error),
                    (Ok(()), true) => Err(refuse(format!("{name}'s {key} was not inherited"))),
                }
            }
        };
        match result {
            Err(_) if crate::transfer::props::SPACE.contains(&key) => Ok(()),
            result => result,
        }
    }

    /// Remove each record the plan names whose other side was on A, as
    /// `unpair` does for a gone peer: only those records, holds kept, and
    /// only one still exactly as planned. The erase gate refused anything
    /// else before the wipe; an owner gone, replaced or paired otherwise
    /// since is left as it is and reported ([`ending_note`]), because A is
    /// erased by now and nothing here may stop its restore. Repeating it
    /// after it succeeded is a no-op.
    fn end_pairs(&mut self) -> Result<()> {
        for ended in self.state().ended_pairs.clone() {
            if !matches!(ending(&self.backend.view()?, &ended), Ending::Pending) {
                continue;
            }
            self.backend.inherit(
                &ended.owner.name,
                zfs_tools::engine::management::PAIR_PROPERTY,
            )?;
            if self
                .backend
                .view()?
                .dataset(&ended.owner.name)
                .and_then(|d| d.property(zfs_tools::engine::management::PAIR_PROPERTY))
                .is_some()
            {
                return Err(refuse(format!(
                    "{} still has a pair record after removal",
                    ended.owner.name
                )));
            }
        }
        Ok(())
    }

    fn set_if(&mut self, view: &View, dataset: &str, key: &str, value: &str) -> Result<()> {
        let expected = view
            .dataset(dataset)
            .ok_or_else(|| refuse(format!("{dataset} disappeared")))?
            .identity
            .clone();
        let fresh = self.backend.view()?;
        let current = fresh
            .dataset(dataset)
            .filter(|d| d.identity == expected)
            .ok_or_else(|| refuse(format!("{dataset} incarnation changed")))?;
        if current
            .property(key)
            .is_some_and(|p| p.local() && p.value == value)
        {
            return Ok(());
        }
        let result = self.backend.set(dataset, key, value);
        let after = self.backend.view()?;
        if after.dataset(dataset).is_some_and(|d| {
            d.identity == expected
                && d.property(key)
                    .is_some_and(|p| p.local() && p.value == value)
        }) {
            return Ok(());
        }
        Err(result.err().unwrap_or_else(|| {
            refuse(format!(
                "{dataset}'s {key} was not verified after setting it"
            ))
        }))
    }

    // Step 8: verify every role while all copies are still inert, then
    // publish original placement from B's durable receipt. The intent binds
    // those exact target incarnations before the first publication write.
    fn configure(&mut self) -> Result<()> {
        let pool = self.new_pool()?;
        let state = self.state().clone();
        let manifest = self.manifest()?;
        let mut targets = Vec::new();
        let be = state.restored_be();
        for (relative, member) in &manifest.source_tree.members {
            targets.push((join(&be, relative), member.clone(), true));
        }
        for (relative, tree) in &manifest.kept {
            let root = format!("{pool}/{relative}");
            for (tail, member) in &tree.members {
                targets.push((join(&root, tail), member.clone(), false));
            }
        }
        let view = self.backend.view()?;
        if tree_digest(&view, &be, &self.source_suffix()) != manifest.source_tree.digest {
            return Err(refuse(
                "restored BE ancestry differs from its placement receipt",
            ));
        }
        for (relative, tree) in &manifest.kept {
            if tree_digest(&view, &format!("{pool}/{relative}"), &self.suffix()) != tree.digest {
                return Err(refuse(
                    "restored kept ancestry differs from its placement receipt",
                ));
            }
        }
        let mut identities = Vec::new();
        for (name, member, _) in &targets {
            let target = view
                .dataset(name)
                .filter(|d| {
                    d.volume == member.volume && Some(d.identity.pool_guid) == state.new_pool
                })
                .ok_or_else(|| {
                    refuse(format!(
                        "restored receipt member {name} is missing or changed type"
                    ))
                })?;
            identities.push((name, &target.identity));
        }
        let identity_digest = super::hex(&sha2::Sha256::digest(
            serde_json::to_vec(&identities).map_err(|e| refuse(e.to_string()))?,
        ));
        if let Some(expected) = &state.receive_targets {
            if expected != &identity_digest {
                return Err(refuse(
                    "restored incarnations changed after role verification",
                ));
            }
        } else {
            // No publication has been authorized yet. Setter failure here
            // leaves mountpoint=none and volmode=none, with originals intact
            // in the receipt, even for a fully received native filesystem.
            for (name, _, _) in &targets {
                self.verify_inert(name, false)?;
            }
            self.quiesce_receive(&pool)?;
            // The copy on A against the manifest, while it is still inert:
            // members, snapshot GUIDs, encryption and copied properties.
            for (index, copy) in self.return_copies(&pool)?.iter().enumerate() {
                let digest = if index == 0 {
                    manifest.source_tree.digest.clone()
                } else {
                    manifest.kept[&state.keep[index - 1].relative]
                        .digest
                        .clone()
                };
                self.verify_copy(copy, &digest, true)?;
                let view = self.backend.view()?;
                for (relative, member) in &copy.members {
                    let target = view.dataset(&join(&copy.destination, relative)).unwrap();
                    manifest::verify(&member.properties, target)?;
                }
            }
            for (name, member, be_member) in &targets {
                if !member.volume {
                    let mode = restored_canmount(member, *be_member, name == &be)?;
                    self.set_if(&view, name, "canmount", &mode)?;
                } else {
                    for (key, value) in Posture::AtRest.properties(true) {
                        self.set_if(&view, name, key, value)?;
                    }
                }
            }
            self.verify_roles(&targets)?;
            self.advance(Phase::Restored, |s| {
                s.receive_targets = Some(identity_digest.clone())
            })?;
        }
        self.verify_roles(&targets)?;
        for (name, member, be_member) in &targets {
            let mut readonly = member.placement.readonly.value.clone();
            if *be_member && let Some(placement) = source_be_placement(member)? {
                readonly = if placement.readonly { "on" } else { "off" }.into();
            }
            self.set_if(&view, name, "readonly", &readonly)?;
            if let Some(mountpoint) = &member.placement.mountpoint {
                self.set_if(
                    &view,
                    name,
                    "mountpoint",
                    if *be_member && name == &be {
                        "/"
                    } else {
                        &mountpoint.value
                    },
                )?;
            }
            self.set_if(&view, name, "volmode", &member.placement.volmode.value)?;
            let managed = member
                .managed
                .iter()
                .filter(|(key, _)| {
                    !*be_member || key.as_str() != zfs_tools::engine::management::PLACEMENT_PROPERTY
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            self.apply_managed(&view, name, managed)?;
        }
        self.verify_roles(&targets)?;
        self.restore_internal_inheritance(&view, &targets)?;
        self.retire_shell_volume_fences(&pool)?;
        self.advance(Phase::Configured, |_| {})
    }

    /// First publish all intended values locally and verify the final roles.
    /// Only then remove compatible descendant pins, parents first. The durable
    /// receipt and receive_targets checkpoint also authorize retrying a partial
    /// inheritance pass; no new or hidden received layer is invented.
    fn restore_internal_inheritance(
        &mut self,
        identities: &View,
        targets: &[(String, receipt::Member, bool)],
    ) -> Result<()> {
        let mut ordered: Vec<_> = targets.iter().collect();
        ordered.sort_by(|a, b| a.0.cmp(&b.0));
        for key in ["mountpoint", "volmode", "readonly"] {
            let mut planned: BTreeMap<String, crate::placement::SavedProperty> = BTreeMap::new();
            for (name, member, be_member) in &ordered {
                let saved = match key {
                    "mountpoint" => member.placement.mountpoint.as_ref(),
                    "volmode" => Some(&member.placement.volmode),
                    "readonly" => Some(&member.placement.readonly),
                    _ => unreachable!(),
                };
                let Some(saved) = saved else { continue };
                let mut intended = saved.value.clone();
                if *be_member {
                    if key == "mountpoint" && *name == self.state().restored_be() {
                        intended = "/".into();
                    } else if key == "readonly"
                        && let Some(placement) = source_be_placement(member)?
                    {
                        intended = if placement.readonly { "on" } else { "off" }.into();
                    }
                }
                let parent = name
                    .rsplit_once('/')
                    .and_then(|(name, _)| planned.get(name).map(|property| (name, property)));
                let mut property =
                    crate::placement::new_member_property(key, saved, &intended, name, parent);
                if key == "mountpoint"
                    && restored_canmount(member, *be_member, *name == self.state().restored_be())?
                        == "on"
                {
                    // OpenZFS inherit has no -u and its mountpoint changelist
                    // mounts canmount=on filesystems. Keep the verified value
                    // local rather than introduce a mount during restore.
                    property.source = "local".into();
                }
                if property.source != "local" {
                    self.inherit_placement_if(identities, name, key, &property)?;
                }
                planned.insert(name.to_string(), property);
            }
        }
        Ok(())
    }

    fn inherit_placement_if(
        &mut self,
        identities: &View,
        name: &str,
        key: &str,
        expected: &crate::placement::SavedProperty,
    ) -> Result<()> {
        let identity = &identities
            .dataset(name)
            .ok_or_else(|| refuse("publication member identity is missing"))?
            .identity;
        let before = self.backend.view()?;
        let current = before
            .dataset(name)
            .filter(|d| d.identity == *identity && !d.mounted)
            .ok_or_else(|| refuse(format!("{name}'s publication identity or mount changed")))?;
        if current
            .property(key)
            .is_some_and(|p| p.value == expected.value && p.source == expected.source)
        {
            return Ok(());
        }
        if !current
            .property(key)
            .is_some_and(|p| p.local() && p.value == expected.value)
        {
            return Err(refuse(format!(
                "{name}'s {key} changed before restoring inheritance"
            )));
        }
        let result = self.backend.inherit(name, key);
        let after = self.backend.view()?;
        if after.dataset(name).is_some_and(|d| {
            d.identity == *identity
                && !d.mounted
                && d.property(key)
                    .is_some_and(|p| p.value == expected.value && p.source == expected.source)
        }) {
            return Ok(());
        }
        Err(result
            .err()
            .unwrap_or_else(|| refuse(format!("{name}'s {key} inheritance was not verified"))))
    }

    /// Deploy creates these two empty filesystem shells with native default
    /// volmode. Restore temporarily fences them before receiving any data.
    /// Only the new pool's shells are ours to inherit, after the receipt's
    /// exact target identities have authorized publication. Members already
    /// have verified placement; this cleanup never changes their properties.
    fn retire_shell_volume_fences(&mut self, pool: &str) -> Result<()> {
        let state = self.state();
        if state.receive_targets.is_none() {
            return Err(refuse("shell volume fences lack publication authorization"));
        }
        let guid = state
            .new_pool
            .ok_or_else(|| refuse("shell volume fences lack the new pool identity"))?;
        let inspect =
            |view: &View, name: &str| -> Result<(zfs_tools::engine::DatasetIdentity, bool)> {
                if view.pool(pool).is_none_or(|p| p.guid != guid || p.readonly) {
                    return Err(refuse("new restore pool changed before shell cleanup"));
                }
                let shell = view
                    .dataset(name)
                    .filter(|d| {
                        d.identity.pool_guid == guid
                            && !d.volume
                            && !d.mounted
                            && d.origin.is_none()
                            && !d.encrypted
                            && !d.resume_token
                            && view.snapshots_of(name).is_empty()
                            && [
                                ("readonly", "on"),
                                ("canmount", "off"),
                                ("mountpoint", "none"),
                            ]
                            .iter()
                            .all(|(key, value)| {
                                d.property(key)
                                    .is_some_and(|p| p.local() && p.value == *value)
                            })
                    })
                    .ok_or_else(|| refuse(format!("{name}'s deploy shell bounds changed")))?;
                let pending = match shell.property("volmode") {
                    Some(p) if p.local() && p.value == "none" => true,
                    Some(p) if p.source == "default" && p.value == "default" => false,
                    _ => return Err(refuse(format!("{name}'s shell volume fence changed"))),
                };
                Ok((shell.identity.clone(), pending))
            };
        let view = self.backend.view()?;
        let shells = [pool.to_owned(), format!("{pool}/ROOT")]
            .into_iter()
            .map(|name| inspect(&view, &name).map(|(identity, _)| (name, identity)))
            .collect::<Result<Vec<_>>>()?;
        for (name, identity) in shells {
            let (current, pending) = inspect(&self.backend.view()?, &name)?;
            if current != identity {
                return Err(refuse(format!("{name}'s shell incarnation changed")));
            }
            if !pending {
                continue;
            }
            let result = self.backend.inherit(&name, "volmode");
            let (current, pending) = inspect(&self.backend.view()?, &name)?;
            if current == identity && !pending {
                // A lost successful reply is already complete; a cut before
                // the write leaves local none and can be retried on resume.
                continue;
            }
            return Err(result.err().unwrap_or_else(|| {
                refuse(format!("{name}'s native default volmode was not verified"))
            }));
        }
        Ok(())
    }

    fn verify_roles(&mut self, targets: &[(String, receipt::Member, bool)]) -> Result<()> {
        let view = self.backend.view()?;
        let root = self.state().restored_be();
        for (name, member, be) in targets {
            let target = view
                .dataset(name)
                .ok_or_else(|| refuse(format!("{name} disappeared before publication")))?;
            if target.volume != member.volume || target.mounted {
                return Err(refuse(format!("{name}'s restored role changed")));
            }
            if !member.volume {
                let expected = restored_canmount(member, *be, name == &root)?;
                if !target
                    .property("canmount")
                    .is_some_and(|p| p.local() && p.value == expected)
                {
                    return Err(refuse(format!(
                        "{name}'s canmount role was not verified; original placement is not published"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Set boot properties locally, and placement rebound to the restored
    /// dataset's own identity.
    fn apply_managed(
        &mut self,
        view: &View,
        dataset: &str,
        values: BTreeMap<String, String>,
    ) -> Result<()> {
        let identity = view
            .dataset(dataset)
            .map(|d| d.identity.clone())
            .ok_or_else(|| refuse(format!("{dataset} is missing on A")))?;
        for (key, value) in values {
            if !super::MANAGED.contains(&key.as_str()) {
                return Err(refuse("unsupported restored managed property"));
            }
            let value = if key == zfs_tools::engine::management::PLACEMENT_PROPERTY {
                let mut placement = Placement::parse(&value)?;
                placement.identity = identity.clone();
                placement.encode()?
            } else {
                value
            };
            self.set_if(view, dataset, &key, &value)?;
        }
        Ok(())
    }

    // Step 9: the host's one boot default.
    fn boot(&mut self) -> Result<()> {
        let pool = self.new_pool()?;
        self.retire_restore_snapshots(&pool)?;
        let be = self.state().restored_be();
        self.backend.boot(&be)?;
        self.advance(Phase::Booted, |_| {})
    }

    /// A former fenced pair copy came back with this restore's own snapshot,
    /// newer than its peer's newest: delete it there, so the two sides'
    /// newest common snapshot is their anchor again and `pair` can join them.
    /// Only the snapshot whose GUID is the staged one's.
    fn retire_restore_snapshots(&mut self, pool: &str) -> Result<()> {
        let suffix = self.suffix();
        let state = self.state().clone();
        let manifest = self.manifest()?;
        for kept in &state.keep {
            let Some(tree) = manifest.kept.get(&kept.relative) else {
                continue;
            };
            for (relative, member) in &tree.members {
                if member.role != Some(Role::Secondary) {
                    continue;
                }
                let root = join(&format!("{pool}/{}", kept.relative), relative);
                let view = self.backend.view()?;
                let Some(returned) = view.snapshot(&format!("{root}@{suffix}")) else {
                    continue;
                };
                let staged = join(&format!("{}/{}", state.staging, kept.relative), relative);
                let staged = view
                    .snapshot(&format!("{staged}@{suffix}"))
                    .ok_or_else(|| refuse(format!("{staged}@{suffix} disappeared")))?;
                if returned.point.identity.guid != staged.point.identity.guid
                    || view
                        .dataset(&root)
                        .is_none_or(|d| d.identity.guid != returned.point.dataset_guid)
                {
                    return Err(refuse(format!(
                        "{root}@{suffix} is not the snapshot this restore made"
                    )));
                }
                let point = returned.point.clone();
                writeln!(
                    self.progress,
                    "  deleting {} from the former fenced copy",
                    zfs_tools::engine::escape_display(&point.name)
                )?;
                self.backend.destroy_snapshot(&point)?;
            }
        }
        Ok(())
    }

    /// Each returned kept leaf whose pair the plan ended gets its pair's
    /// anchor hold back. Its peer keeps `zboot:anchor:PAIR` on the anchor,
    /// and raw streams kept the anchor's GUID, so the same tag on the
    /// returned snapshot with that GUID keeps a copied retention policy from
    /// pruning what `zboot pair` needs to join the two again without a full
    /// copy; `zboot unpair PEER --release-anchors` releases both. A returned
    /// leaf whose anchor cannot be found (its peer gone, or the snapshot) is
    /// reported instead.
    fn hold_anchors(&mut self, pool: &str) -> Result<Vec<String>> {
        let state = self.state().clone();
        let Some(old) = &state.old_pool else {
            return Ok(Vec::new());
        };
        let mut notes = Vec::new();
        for ended in &state.ended_pairs {
            let kept = ended.peer.identity.pool_guid == old.guid
                && state
                    .keep
                    .iter()
                    .any(|k| within(&format!("{}/{}", old.name, k.relative), &ended.peer.name));
            let Some(relative) = ended
                .peer
                .name
                .strip_prefix(&format!("{}/", old.name))
                .filter(|_| kept)
            else {
                continue;
            };
            let returned = format!("{pool}/{relative}");
            let tag = format!("zboot:anchor:{}", ended.pair_id);
            let view = self.backend.view()?;
            let anchors: Vec<_> = view
                .dataset(&ended.owner.name)
                .filter(|owner| owner.identity == ended.owner.identity)
                .map(|_| {
                    view.snapshots_of(&ended.owner.name)
                        .into_iter()
                        .filter(|s| s.holds.contains(&tag))
                        .map(|s| s.point.identity.guid)
                        .collect()
                })
                .unwrap_or_default();
            let points: Vec<_> = view
                .snapshots_of(&returned)
                .into_iter()
                .filter(|s| anchors.contains(&s.point.identity.guid))
                .map(|s| s.point.clone())
                .collect();
            if points.is_empty() {
                notes.push(format!(
                    "{returned} came back without its pair's anchor ({tag} on {owner}) held: pair it with \
                     {owner} again soon, before a retention policy prunes the snapshot `zboot pair` \
                     needs to join them without a full copy",
                    owner = ended.owner.name,
                ));
                continue;
            }
            for point in points {
                hold::hold(&mut Holds(self.backend), &point, &tag)?;
            }
        }
        Ok(notes)
    }

    fn source_holds(&mut self) -> Result<Vec<SnapshotView>> {
        let view = self.backend.view()?;
        let pool = self.state().source.identity.pool_guid;
        if !view.pools.iter().any(|p| p.guid == pool) {
            return Err(refuse(
                "the source pool is not imported; its holds cannot be released",
            ));
        }
        let tag = self.tag();
        // The source may have been renamed. Find our tag by native identity,
        // while preserving staging even if its marked root was renamed too.
        let protected: Vec<_> = view
            .datasets
            .iter()
            .filter(|d| {
                d.identity.pool_guid == pool
                    && d.property(zfs_tools::engine::management::STAGING_PROPERTY)
                        .is_some_and(|p| p.local() && p.value == self.id())
            })
            .map(|d| d.name.as_str())
            .collect();
        Ok(view
            .snapshots
            .iter()
            .filter(|s| {
                let dataset = s
                    .point
                    .name
                    .split_once('@')
                    .map_or(s.point.name.as_str(), |(d, _)| d);
                s.point.identity.pool_guid == pool
                    && s.holds.contains(&tag)
                    && !within(&self.state().staging, dataset)
                    && !protected.iter().any(|root| within(root, dataset))
            })
            .cloned()
            .collect())
    }

    fn release_holds(
        &mut self,
        snapshots: Vec<SnapshotView>,
        preserve_deferred: bool,
    ) -> Result<Vec<SnapshotRef>> {
        let tag = self.tag();
        let mut retained = Vec::new();
        for snapshot in snapshots {
            // Other holds and clones can disappear before the release. A
            // recursive send, for example, releases its temporary holds
            // when the send finishes.
            if preserve_deferred && snapshot.defer_destroy {
                retained.push(snapshot.point);
                continue;
            }
            hold::release(&mut Holds(self.backend), &snapshot.point, &tag)?;
        }
        Ok(retained)
    }

    fn release_source(&mut self, preserve_deferred: bool) -> Result<Vec<SnapshotRef>> {
        let snapshots = self.source_holds()?;
        let retained = self.release_holds(snapshots, preserve_deferred)?;
        if self
            .source_holds()?
            .iter()
            .any(|s| !retained.contains(&s.point))
        {
            return Err(refuse(
                "the source BE's restore holds were not all released",
            ));
        }
        Ok(retained)
    }

    fn release_staging(&mut self, preserve_deferred: bool) -> Result<Vec<SnapshotRef>> {
        let tag = self.tag();
        let view = self.backend.view()?;
        let mut snapshots = Vec::new();
        for member in view.tree(&self.state().staging) {
            for s in view.snapshots_of(&member.name) {
                if s.holds.contains(&tag) {
                    snapshots.push(s.clone());
                }
            }
        }
        self.release_holds(snapshots, preserve_deferred)
    }

    fn release_all(&mut self) -> Result<()> {
        self.release_source(false)?;
        self.release_staging(false)?;
        Ok(())
    }

    fn unmark_staging(&mut self) -> Result<()> {
        let staging = self.state().staging.clone();
        let view = self.backend.view()?;
        if view.dataset(&staging).is_some_and(|d| {
            d.property(zfs_tools::engine::management::STAGING_PROPERTY)
                .is_some_and(|p| p.local())
        }) {
            self.backend
                .inherit(&staging, zfs_tools::engine::management::STAGING_PROPERTY)?;
        }
        Ok(())
    }

    fn complete(&mut self) -> Result<Completed> {
        let state = self.state().clone();
        // Do not finish over a renamed marked workspace: its active receipt
        // and holds would become orphaned. No cleanup precedes this admission.
        let id = self.id();
        receipt::admit_cleanup_location(self.backend, &state, &id, false)?;
        // Booted is the first step no path reads the receipt in: retire it
        // before any other cleanup, so a receipt that will not retire
        // refuses with nothing done; the record is cleared last.
        receipt::remove(self.backend, &state, &id, "resume")?;
        let mut notes = std::mem::take(&mut self.notes);
        let view = self.backend.view()?;
        for name in self.left_out(&view) {
            notes.push(format!(
                "{name} appeared under the source BE after it was snapshotted and was left out; \
                 the restore copied that snapshot, so A's BE does not have it"
            ));
        }
        if let Some(pool) = view
            .pools
            .iter()
            .find(|p| Some(p.guid) == state.new_pool)
            .map(|p| p.name.clone())
        {
            notes.extend(self.hold_anchors(&pool)?);
            // Export is required work: leave the Booted record and staging
            // protection intact if it fails, so resume can retry it.
            self.backend.export(&pool)?;
        }
        if self
            .backend
            .view()?
            .pools
            .iter()
            .any(|p| Some(p.guid) == state.new_pool)
        {
            return Err(refuse("A is still imported; resume to finish exporting it"));
        }
        self.release_all()?;
        self.unmark_staging()?;
        intent::finish(&mut Records(self.backend), &self.pool, &self.record)?;
        notes.push(format!(
            "pool {} is exported so that A's own boot imports it; reboot (or `rescan` in the Menu) to boot {}",
            state.pool, state.restored_be()
        ));
        notes.push(format!(
            "{} is the host's one boot default; no other pool names one. If A does not boot, select {} in the Menu, or make it the default again with `zboot default`",
            state.restored_be(),
            state.source.name
        ));
        if view.dataset(&state.staging).is_some() {
            notes.push(format!(
                "{} keeps the staged copy; once A boots and its data is usable, remove it with `zboot drop {}`",
                state.staging, state.staging
            ));
        }
        let archive = format!("{}{id}:", receipt::ARCHIVE_PREFIX);
        if view
            .dataset(&state.staging)
            .is_some_and(|d| d.property(&format!("{archive}manifest")).is_some())
        {
            notes.push(format!(
                "{} also keeps {archive}, a copy of the placement receipt an abandon made before \
                 this restore was resumed instead; it is inert and goes with the staging",
                state.staging
            ));
        }
        if state.created {
            notes.push(format!("{} stays on B", state.snapshot));
        }
        for ended in &state.ended_pairs {
            notes.push(ending_note(&view, ended));
        }
        Ok(Completed {
            id: self.record.id.clone(),
            be: state.restored_be(),
            pool: state.pool.clone(),
            staging: state.staging.clone(),
            source_snapshot: state.snapshot.clone(),
            notes,
        })
    }
}

/// What became of a pair record the plan ends, as observed now.
enum Ending {
    /// Its owner still holds exactly the planned record: restore ends it.
    Pending,
    /// Its owner holds no record: ended, by restore or by the operator.
    Ended,
    /// Its owner is gone, replaced, or holds another record. Restore may
    /// end nothing there; the reason says what changed.
    Changed(String),
}

fn ending(view: &View, ended: &super::EndedPair) -> Ending {
    use zfs_tools::engine::management::{PAIR_PROPERTY, PairRecord};
    let name = &ended.owner.name;
    let Some(owner) = view.dataset(name) else {
        return Ending::Changed(format!("{name} is not imported, or was removed"));
    };
    if owner.identity != ended.owner.identity {
        return Ending::Changed(format!("{name} was replaced"));
    }
    let Some(property) = owner.property(PAIR_PROPERTY) else {
        return Ending::Ended;
    };
    let planned = property.local()
        && PairRecord::parse(&property.value).is_ok_and(|record| {
            record.endpoint == ended.owner
                && record.pair_id == ended.pair_id
                && record.peer == ended.peer
                && record.role == ended.role
        });
    if planned {
        Ending::Pending
    } else {
        Ending::Changed(format!("{name}'s pair record changed since the plan"))
    }
}

/// The report on a pair record the plan ends, once A is erased.
fn ending_note(view: &View, ended: &super::EndedPair) -> String {
    let (owner, peer) = (&ended.owner.name, &ended.peer.name);
    match ending(view, ended) {
        Ending::Ended => format!(
            "{owner} is no longer paired (its peer {peer} was erased); it keeps its mount and read-only properties and \
             its anchor holds. `zboot primary {owner}` makes it writable; \
             `zboot unpair {owner} --release-anchors` releases the holds"
        ),
        Ending::Pending => format!(
            "{owner} still records its pair with {peer}, which was erased; `zboot unpair {owner}` ends it"
        ),
        Ending::Changed(why) => format!(
            "{why}, so restore left its pair record as it is; its peer {peer} was erased. Where \
             {owner} is imported and still names {peer}, `zboot unpair {owner}` ends that record"
        ),
    }
}

/// The content half of the destruction rule: every dataset at `destination`
/// is a copy of the matching dataset under `source` this operation left,
/// holding only that dataset's snapshots (names and GUIDs), no clone, no
/// partial receive and unwritten since its newest snapshot. A dataset made
/// or written after an interruption is never destroyed.
fn partial_copy(view: &View, destination: &str, source: &str) -> Result<()> {
    for member in view.tree(destination) {
        let origin = format!("{source}{}", &member.name[destination.len()..]);
        let sent: BTreeMap<_, _> = view
            .snapshots_of(&origin)
            .into_iter()
            .map(|s| (suffix_of(&s.point.name), s.point.identity.guid))
            .collect();
        let snapshots = view.snapshots_of(&member.name);
        let ours = view.dataset(&origin).is_some()
            && member.origin.is_none()
            && !member.resume_token
            && !snapshots.is_empty()
            && snapshots
                .iter()
                .all(|s| sent.get(&suffix_of(&s.point.name)) == Some(&s.point.identity.guid))
            && member.value("written") == Some("0");
        if !ours {
            return Err(refuse(format!(
                "{} exists and is not a partial copy of {source} left by this operation \
                 (other snapshots, or written since); move it aside or remove it yourself and resume, or abandon",
                member.name
            )));
        }
    }
    Ok(())
}

/// A dataset already at a copy's destination continues only as this
/// operation's own partial copy: no clone, no partial receive, unwritten,
/// and holding a prefix of the source's snapshots up to the boundary.
/// Anything else stays as it is for the operator.
fn adoptable(
    view: &View,
    existing: &DatasetView,
    source: &str,
    history: &[SnapshotRef],
) -> Result<()> {
    let held = view.snapshots_of(&existing.name);
    let prefix = !held.is_empty()
        && held.len() <= history.len()
        && held.iter().zip(history).all(|(have, sent)| {
            have.point.identity.guid == sent.identity.guid
                && suffix_of(&have.point.name) == suffix_of(&sent.name)
        });
    if !prefix
        || existing.origin.is_some()
        || existing.resume_token
        || existing.value("written") != Some("0")
    {
        return Err(refuse(format!(
            "{} exists and is not a partial copy of {source} left by this operation \
             (other snapshots, or written since); move it aside or remove it yourself and resume, or abandon",
            existing.name
        )));
    }
    Ok(())
}

/// `dataset`'s snapshots up to and including `@suffix`, oldest first.
fn history(view: &View, dataset: &str, suffix: &str) -> Result<Vec<SnapshotRef>> {
    let mut points = Vec::new();
    for snapshot in view.snapshots_of(dataset) {
        points.push(snapshot.point.clone());
        if suffix_of(&snapshot.point.name) == suffix {
            return Ok(points);
        }
    }
    Err(refuse(format!("{dataset}@{suffix} disappeared")))
}

fn suffix_of(name: &str) -> String {
    name.split_once('@').map_or("", |(_, s)| s).to_owned()
}

/// The record `id` as stored, of any kind, and the pool holding it.
pub fn record(
    backend: &mut impl Backend,
    id: &str,
) -> Result<Option<(String, intent::Intent<serde_json::Value>)>> {
    for (pool, found) in intent::find(&mut Records(backend))? {
        if let intent::Found::Record(record) = found
            && record.id == id
        {
            return Ok(Some((pool, record)));
        }
    }
    Ok(None)
}

/// The restore record `id` and the pool holding it.
fn find(backend: &mut impl Backend, id: &str) -> Result<(String, Intent)> {
    let Some((pool, record)) = record(backend, id)? else {
        return Err(refuse(format!("no restore operation {id}")));
    };
    if record.kind != KIND {
        return Err(refuse(format!(
            "operation {id} is a {} operation, not a restore",
            record.kind
        )));
    }
    if !super::valid_id(id) {
        return Err(refuse(format!("restore record {id} has an invalid id")));
    }
    // A record that does not decode as this build's was written by an
    // earlier one and is neither resumed nor abandoned.
    let state: State = serde_json::from_value(record.state)
        .map_err(|e| refuse(format!("{} ({e})", intent::earlier(KIND, id))))?;
    let mut intent = Intent::new(record.id, record.kind, state);
    intent.step = record.step;
    Phase::from_step(intent.step)?;
    Ok((pool, intent))
}

/// Every operation record and orphaned attachment, for status and operation
/// selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listing {
    pub operations: Vec<Listed>,
    /// Attachments no live record names ([`orphaned_attachments`]); reported,
    /// never continued.
    pub orphans: Vec<Orphan>,
}
/// An attachment whose operation id no readable record carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Orphan {
    pub dataset: String,
    /// `ID:SLOT`.
    pub attachment: String,
    /// The pool of its dataset, which by rule holds its operation's record.
    pub pool: String,
    pub record: PoolRecord,
}
/// What the root of an orphan's pool records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolRecord {
    /// No record: the attachment's operation has ended, and only here may
    /// it be removed.
    Nothing,
    /// A record this build cannot read, such as one a later zboot wrote:
    /// it may be the attachment's own operation, so it is never removed.
    Unreadable,
    /// Another operation, which never names it.
    Other(String),
}
impl Orphan {
    /// How status, the menu and operation selection report it. Only while
    /// its pool records nothing does the report say how to remove it.
    pub fn describe(&self) -> String {
        let (attachment, dataset, pool) = (&self.attachment, &self.dataset, &self.pool);
        match &self.record {
            PoolRecord::Nothing => format!(
                "orphaned attachment {attachment} on {dataset}: no operation owns it; \
                 reported, not continued; remove it with {}",
                orphan_cleanup(dataset, attachment)
            ),
            PoolRecord::Unreadable => format!(
                "attachment {attachment} on {dataset} belongs to the unreadable operation \
                 record on pool {pool}; do not remove it"
            ),
            PoolRecord::Other(id) => format!(
                "orphaned attachment {attachment} on {dataset}: no operation owns it; \
                 reported, not continued; pool {pool} records operation {id}, so remove it \
                 only once that has ended"
            ),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listed {
    pub pool: String,
    pub id: Option<String>,
    pub kind: Option<String>,
    pub step: Option<String>,
    pub detail: Option<String>,
}

pub fn list(backend: &mut impl Backend) -> Result<Listing> {
    let mut operations = Vec::new();
    let mut records = std::collections::BTreeMap::new();
    let view = backend.view()?;
    for (pool, found) in intent::find(&mut Records(backend))? {
        records.insert(
            pool.clone(),
            match &found {
                intent::Found::Record(record) => Some(record.id.clone()),
                intent::Found::Unreadable(_) => None,
            },
        );
        operations.push(match found {
            intent::Found::Record(record) => {
                let step = if record.kind == KIND {
                    Phase::from_step(record.step)
                        .map(|p| p.name().to_owned())
                        .ok()
                } else {
                    Some(record.step.to_string())
                };
                let detail = serde_json::from_value::<State>(record.state.clone())
                    .ok()
                    .map(|s| format!("{} onto {}", s.snapshot, s.disk.path));
                Listed {
                    pool,
                    id: Some(record.id),
                    kind: Some(record.kind),
                    step,
                    detail,
                }
            }
            intent::Found::Unreadable(reason) => Listed {
                pool,
                id: None,
                kind: None,
                step: None,
                detail: Some(reason),
            },
        });
    }
    let orphans = orphaned_attachments(
        view.datasets.iter().flat_map(|member| {
            member
                .properties
                .iter()
                .filter(|(_, property)| property.local())
                .map(|(key, _)| (member.name.as_str(), key.as_str()))
        }),
        &records,
    );
    Ok(Listing {
        operations,
        orphans,
    })
}

/// Each attachment among LOCAL, the `(dataset, property)` pairs set
/// locally, whose operation id no readable record among RECORDS (each pool's
/// record id, `None` for one that does not decode) carries. An attachment
/// belongs to the live record of its id, whose resume or abandon removes
/// it. A write cut before its commit leaves one when its record then ends
/// from elsewhere or by hand: its dataset and every descendant then refuse
/// every admission. An attachment and its record share a pool, so one on a
/// pool whose record does not decode may still be owned: a later zboot's
/// restore past its erase keeps the only record of A's properties so.
pub(crate) fn orphaned_attachments<'a>(
    local: impl IntoIterator<Item = (&'a str, &'a str)>,
    records: &std::collections::BTreeMap<String, Option<String>>,
) -> Vec<Orphan> {
    let live: std::collections::BTreeSet<&str> =
        records.values().flatten().map(String::as_str).collect();
    let mut orphans: Vec<Orphan> = local
        .into_iter()
        .filter_map(|(dataset, key)| {
            let rest = key.strip_prefix(zfs_tools::engine::attachment::PREFIX)?;
            let name = rest.rsplit_once(':').map_or(rest, |(name, _)| name);
            let id = name.split(':').next().unwrap_or(name);
            if live.contains(id) {
                return None;
            }
            let pool = zfs_tools::engine::pool_of(dataset);
            Some(Orphan {
                dataset: dataset.to_owned(),
                attachment: name.to_owned(),
                pool: pool.to_owned(),
                record: match records.get(pool) {
                    None => PoolRecord::Nothing,
                    Some(None) => PoolRecord::Unreadable,
                    Some(Some(other)) => PoolRecord::Other(other.clone()),
                },
            })
        })
        .collect();
    orphans.sort_by(|a, b| (&a.dataset, &a.attachment).cmp(&(&b.dataset, &b.attachment)));
    orphans.dedup();
    orphans
}
/// The command that removes orphaned attachment NAME (`ID:SLOT`) from
/// DATASET by hand: every one of its chunks, set locally there.
pub fn orphan_cleanup(dataset: &str, name: &str) -> String {
    crate::recipe::orphan_cleanup(dataset, name)
}

/// What continuing `id` involves. While erasing A is ahead or was interrupted,
/// continuing is loss-capable: `token` binds A's current identity and layout,
/// confirmed by typing A's serial (WWN fallback).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResumePlan {
    pub id: String,
    pub pool: String,
    pub phase: Phase,
    pub step: String,
    pub state: State,
    pub erase: Option<crate::device::DiskReview>,
    pub token: Option<String>,
}
impl ResumePlan {
    pub fn typed(&self) -> Option<crate::consent::Typed> {
        self.erase.as_ref().map(|review| {
            crate::consent::disk_target(
                review.identity.serial.as_deref(),
                review.identity.wwn.as_deref(),
            )
        })
    }
    pub fn erase_layout(&self) -> Result<Option<String>> {
        self.erase
            .as_ref()
            .map(super::DiskBinding::of)
            .transpose()
            .map(|b| b.map(|b| b.layout))
    }
}

pub fn resume_plan(backend: &mut impl Backend, id: &str) -> Result<ResumePlan> {
    let (pool, record) = find(backend, id)?;
    let phase = Phase::from_step(record.step)?;
    let state = record.state.clone();
    super::require_host(backend, &state.hostid)?;
    let (erase, token) = if phase < Phase::Erased {
        let identity = backend.disk_identity(&state.disk.path)?;
        if !state.disk.same_disk(&identity) {
            return Err(refuse(format!(
                "{} is no longer the disk this restore was erasing; abandon it",
                state.disk.path
            )));
        }
        super::validate_deploy_geometry(&identity, state.esp_bytes, state.swap_bytes, id)?;
        let view = backend.view()?;
        let mut owned = None;
        for p in &view.pools {
            let disks = backend.pool_disks(&p.name, p.guid)?;
            if disks
                .iter()
                .any(|d| d.device_number == identity.device_number)
            {
                if owned.is_some() {
                    return Err(refuse("more than one imported pool uses the target disk"));
                }
                super::single_disk(&p.name, &disks)?;
                owned = Some(p.name.clone());
            }
        }
        let review = backend.disk(&state.disk.path, owned.as_deref())?;
        if phase < Phase::Erasing && super::DiskBinding::of(&review)?.layout != state.disk.layout {
            return Err(refuse(format!(
                "{} changed since the plan and nothing on it was erased; abandon this restore",
                state.disk.path
            )));
        }
        let token = crate::consent::token(&(id, &state.token, super::DiskBinding::of(&review)?))?;
        (Some(review), Some(token))
    } else {
        // After the erase the recorded replacement must be wholly on A, not
        // merely match its recorded name and GUID.
        for p in &backend.view()?.pools {
            if p.name != state.pool || Some(p.guid) != state.new_pool {
                continue;
            }
            let disks = backend.pool_disks(&p.name, p.guid)?;
            if disks.len() != 1 || !state.disk.same_disk(&disks[0]) {
                return Err(refuse(format!(
                    "the imported restore replacement {} is not on its recorded target disk alone",
                    p.name
                )));
            }
        }
        (None, None)
    };
    Ok(ResumePlan {
        id: id.into(),
        pool,
        phase,
        step: phase.name().into(),
        state,
        erase,
        token,
    })
}

/// What `abandon` left; it destroys nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Abandoned {
    pub id: String,
    pub step: String,
    /// All restore holds were released. False when only-copy staging or
    /// deferred snapshots retained holds, as described in `left`.
    pub released: bool,
    pub left: Vec<String>,
}

/// What `abandon ID` would do, and its token (typed: the id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbandonPlan {
    pub id: String,
    pub step: String,
    /// Staging is eligible for hold and marker release. False while it may
    /// be the only complete copy. Holds on observed deferred snapshots stay.
    pub releases: bool,
    pub token: String,
}

/// From the erase until `configure` has verified A against the manifest,
/// staging may be the only good copy of the kept data: returned is not
/// verified.
fn only_copy(state: &State, phase: Phase) -> bool {
    !state.keep.is_empty() && (Phase::Erasing..=Phase::Restored).contains(&phase)
}

pub fn abandon_plan(backend: &mut impl Backend, id: &str) -> Result<AbandonPlan> {
    let (_, record) = find(backend, id)?;
    let phase = Phase::from_step(record.step)?;
    let token = crate::consent::token(&("abandon", id, record.step, &record.state.token))?;
    Ok(AbandonPlan {
        id: id.into(),
        step: phase.name().into(),
        releases: !only_copy(&record.state, phase),
        token,
    })
}

/// End operation `id` without continuing it. Never destroys anything: while
/// A may lack the kept data (erasure begun, restore not verified) the staged
/// copy stays held and marked. On the source BE and redundant staging, holds
/// on snapshots observed as deferred stay to prevent destruction on release.
pub fn abandon(backend: &mut impl Backend, id: &str) -> Result<Abandoned> {
    let (pool, record) = find(backend, id)?;
    let phase = Phase::from_step(record.step)?;
    let state = record.state.clone();
    let only_copy = only_copy(&state, phase);
    receipt::admit_cleanup_location(backend, &state, id, only_copy)?;
    let retained = only_copy
        .then(|| receipt::prepare_abandon_archive(backend, &state, id))
        .transpose()?;
    let mut left = Vec::new();
    let mut sink = std::io::sink();
    let mut run = Run {
        backend,
        pool: pool.clone(),
        record: record.clone(),
        progress: &mut sink,
        erase_layout: None,
        notes: Vec::new(),
    };
    // Every pair the plan ends had its other side on A: end them only once A
    // is known erased. An owner gone, replaced or paired otherwise since is
    // reported and left as it is, never a reason to keep the operation. An
    // erase whose outcome is unknown refuses here, before any effect.
    let view = run.backend.view()?;
    let endings: Vec<_> = state
        .ended_pairs
        .iter()
        .map(|ended| ending(&view, ended))
        .collect();
    let pending: Vec<_> = endings
        .iter()
        .map(|ending| matches!(ending, Ending::Pending))
        .collect();
    let erased = if !pending.iter().any(|p| *p) {
        false
    } else if phase >= Phase::Erased {
        true
    } else if phase == Phase::Erasing {
        let identity = run.backend.disk_identity(&state.disk.path)?;
        if !state.disk.same_disk(&identity) {
            return Err(refuse(
                "the target disk changed; the source pair is left unchanged",
            ));
        }
        !run.backend
            .labels_present(&identity, &state.label_extents)?
    } else {
        false
    };
    // No cleanup, hold release or pair mutation precedes preservation of
    // original metadata that may exist nowhere outside this receipt. A
    // receipt that is not the only copy is retired first, so one that will
    // not retire refuses with nothing done.
    match &retained {
        Some(retained) => receipt::publish_archive(run.backend, &state, id, retained)?,
        None => receipt::remove(run.backend, &state, id, "abandon")?,
    }
    if erased {
        run.end_pairs()?;
        for (ended, pending) in state.ended_pairs.iter().zip(pending) {
            if pending {
                left.push(format!(
                    "{} is no longer paired (its peer {} was erased); it keeps its mount and read-only properties and its anchor holds",
                    ended.owner.name, ended.peer.name
                ));
            }
        }
    }
    if phase >= Phase::Erasing {
        for (ended, ending) in state.ended_pairs.iter().zip(endings) {
            if let Ending::Changed(why) = ending {
                left.push(format!(
                    "{why}, so its pair record with {} on the target disk was left as it is",
                    ended.peer.name
                ));
            }
        }
    }
    let mut retained_holds = run.release_source(true)?;
    if !only_copy {
        retained_holds.extend(run.release_staging(true)?);
    }
    let tag = run.tag();
    for point in &retained_holds {
        left.push(format!(
            "{} is marked for deferred destruction. Hold {tag} stays because releasing it can destroy the snapshot",
            point.name
        ));
    }
    // Preserve the only copy's original placement as inert data before
    // retiring coordination. This never grants broader drop authority.
    if let Some(retained) = &retained {
        receipt::preserve_abandoned(run.backend, &state, id, retained)?;
    }
    if !only_copy {
        run.unmark_staging()?;
    }
    let view = run.backend.view()?;
    let placement_note = "Its exact original placement remains in org.zfs-tools:restore-placement metadata on this staging root. Copy the staged data and that metadata elsewhere first";
    if view.dataset(&state.staging).is_some() {
        let deferred: Vec<_> = view
            .snapshots
            .iter()
            .filter(|s| {
                s.defer_destroy
                    && s.point
                        .name
                        .split_once('@')
                        .is_some_and(|(dataset, _)| within(&state.staging, dataset))
            })
            .map(|s| s.point.name.as_str())
            .collect();
        let drop_note = if deferred.is_empty() {
            format!("Use `zboot drop {}` to remove it", state.staging)
        } else {
            format!(
                "Resolve the deferred snapshots ({}) before using `zboot drop {}`",
                deferred.join(", "),
                state.staging
            )
        };
        left.push(if only_copy {
            format!(
                "{} is the only complete copy of the kept data. Every snapshot in it stays held ({tag}) and it stays marked. {placement_note}. {drop_note}",
                state.staging
            )
        } else {
            format!(
                "{} holds a redundant staged copy. {drop_note}",
                state.staging
            )
        });
    }
    if state.created && view.snapshot(&state.snapshot).is_some() {
        left.push(format!("{} stays on B", state.snapshot));
    }
    if phase < Phase::Erasing {
        if let Some(old) = &state.old_pool {
            for kept in &state.keep {
                let name = format!("{}/{}@{}", old.name, kept.relative, State::suffix(id));
                if view.snapshot(&name).is_some() {
                    left.push(format!("{name} stays on A, which is otherwise unchanged"));
                }
            }
        }
    } else if phase < Phase::Booted {
        left.push(format!(
            "the target disk {} is partly restored (step {}); restore it again or wipe it",
            state.disk.path,
            phase.name()
        ));
    }
    if phase >= Phase::Configured {
        left.push(format!(
            "{} may already be the host's one boot default; `zboot default` picks another",
            state.restored_be()
        ));
    }
    intent::finish(&mut Records(run.backend), &pool, &record)?;
    Ok(Abandoned {
        id: id.into(),
        step: phase.name().into(),
        released: !only_copy && retained_holds.is_empty(),
        left,
    })
}
