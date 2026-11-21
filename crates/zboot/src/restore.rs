//! Guided restore: rebuild disk A from a boot environment on surviving disk
//! B, keeping selected datasets of A (DESIGN, "Guided restore").
//!
//! Data moves dataset by dataset, parents first, as property-free raw
//! streams (`zfs send -w [-I]`) into the host's own `zfs receive -u`, so
//! encrypted datasets need no keys and no stream changes a property. Kept
//! trees are staged under one fenced container on B, `B/zboot-restore-<id>`,
//! under their pool-relative names; each new dataset is fenced locally right
//! after its first stream, before anything could take it out of its
//! container. Before data moves, a receipt on that container records every
//! source and kept dataset's placement, copied properties and encryption (the
//! manifest): staged copies carry no properties, so once A is erased it is
//! the only record of them. One `zfs_tools::engine::intent` record on B's
//! pool root names the roots, boundaries and digests; it is written before
//! the first effect, advanced after each step and cleared on completion. The
//! receipt is a write-once attachment that the record names once step 2 is
//! done; that advance commits it.
//!
//! Steps (the record's `step` is the last one completed):
//! 1. snapshot the source BE in place (or adopt `BE@SNAP`) and hold it;
//! 2. snapshot each kept tree on A;
//! 3. stage each kept tree on B, dataset by dataset;
//! 4. verify staging against the manifest, prove its key wrapping, hold it;
//! 5. scrub B;
//! 6. check A and the staged wrapping again, erase A (wipe chain) and deploy
//!    an empty root pool whose ESP gets the zboot loader the BE ships
//!    (`/usr/lib/zboot/zboot.efi`);
//! 7. send the BE and the staged trees to A dataset by dataset, relink their
//!    encryption and copy their properties from the manifest;
//! 8. verify A against the manifest, then restore roles and placement;
//! 9. make A's BE the host's one boot default;
//!
//! then export A, release the holds and clear the record. Failures leave the
//! operation resumable. Staging stays for `zboot drop`.
mod backend;
mod execute;
#[cfg(test)]
mod fake;
mod manifest;
mod native;
mod receipt;
pub mod restore_plan;
#[cfg(test)]
mod tests;

pub use backend::{
    Backend, Candidate, DatasetView, DeploySpec, PoolView, Property, Scrub, SnapshotView, View,
};
#[cfg(test)]
pub(crate) use execute::orphaned_attachments;
#[cfg(test)]
pub(crate) use execute::{Abandoned, Listed, Orphan, PoolRecord, orphan_cleanup};
pub use execute::{
    Completed, Listing, ResumePlan, Run, abandon, abandon_plan, list, record, resume_plan,
};
pub use native::Native;

use crate::{
    device::{self, DiskIdentity, DiskReview},
    esp::FileIdentity,
    menu::{RecoveryError, Result},
};
use backend::{Records, within};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zfs_tools::engine::{
    DatasetIdentity, Guid, SnapshotRef, attachment::Attachment, intent, management::Endpoint,
    pool_of,
};

pub const KIND: &str = "restore";
const MIB: u64 = 1024 * 1024;
pub const DEFAULT_POOL: &str = "rpool";
pub const DEFAULT_ESP: u64 = 1024 * MIB;
/// Room deploy leaves for its GPT and alignment.
const LAYOUT_SLACK: u64 = 16 * MIB;
/// Boot and placement properties restore sets itself.
const MANAGED: &[&str] = &["zboot:placement", "zboot:cmdline"];

fn refuse(message: impl Into<String>) -> RecoveryError {
    RecoveryError::Refused(message.into())
}

/// Why restore cannot relink keys here: `zboot-change-key --check` failed.
fn change_key_unavailable(error: &RecoveryError) -> String {
    format!(
        "the key relink helper zboot-change-key does not work here ({error}); install the \
         complete zboot package, or restore from its UKI"
    )
}

/// What the operator asked for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    /// `BE` (snapshotted in place) or `BE@SNAP`.
    pub source: String,
    /// Whole-disk path of A.
    pub disk: String,
    /// Dataset roots of A's pool to keep.
    pub keep: Vec<String>,
    pub pool: Option<String>,
    pub esp_bytes: Option<u64>,
    pub swap_bytes: Option<u64>,
}

/// Steps, as stored in the record's `step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Recorded = 0,
    Snapshotted = 1,
    Quiesced = 2,
    Staged = 3,
    Verified = 4,
    /// A scrub of B was requested at `scrub_after`.
    Scrubbing = 5,
    Scrubbed = 6,
    /// Erasure of A has begun; continuing needs a fresh typed confirmation.
    Erasing = 7,
    Erased = 8,
    Restored = 9,
    Configured = 10,
    Booted = 11,
}
impl Phase {
    pub fn from_step(step: u32) -> Result<Self> {
        use Phase::*;
        [
            Recorded,
            Snapshotted,
            Quiesced,
            Staged,
            Verified,
            Scrubbing,
            Scrubbed,
            Erasing,
            Erased,
            Restored,
            Configured,
            Booted,
        ]
        .get(step as usize)
        .copied()
        .ok_or_else(|| refuse(format!("restore record has unknown step {step}")))
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Snapshotted => "source snapshotted",
            Self::Quiesced => "kept data snapshotted",
            Self::Staged => "staged",
            Self::Verified => "staging verified",
            Self::Scrubbing => "scrubbing",
            Self::Scrubbed => "scrubbed",
            Self::Erasing => "erasing",
            Self::Erased => "erased",
            Self::Restored => "restored",
            Self::Configured => "properties restored",
            Self::Booted => "boot prepared",
        }
    }
}

/// A's whole-disk identity as consented to; the layout is a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskBinding {
    pub path: String,
    pub device_number: String,
    pub sysfs_path: String,
    pub bytes: u64,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub layout: String,
}
impl DiskBinding {
    pub fn of(review: &DiskReview) -> Result<Self> {
        let identity = &review.identity;
        Ok(Self {
            path: identity.path.clone(),
            device_number: identity.device_number.clone(),
            sysfs_path: identity.sysfs_path.clone(),
            bytes: identity.bytes,
            serial: identity.serial.clone(),
            wwn: identity.wwn.clone(),
            layout: layout_digest(review)?,
        })
    }
    /// The same physical disk, whatever its layout now.
    pub fn same_disk(&self, identity: &DiskIdentity) -> bool {
        self.device_number == identity.device_number
            && self.sysfs_path == identity.sysfs_path
            && self.bytes == identity.bytes
            && self.serial == identity.serial
            && self.wwn == identity.wwn
    }
}
fn layout_digest(review: &DiskReview) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        &review.identity,
        &review.partitions,
        &review.filesystem,
        &review.partition_table_uuid,
    ))
    .map_err(|e| refuse(e.to_string()))?;
    Ok(hex(&Sha256::digest(bytes)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolRef {
    pub name: String,
    pub guid: Guid,
}

/// One kept tree, by its pool-relative root name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kept {
    pub relative: String,
    /// GUID of the root on A when planned.
    pub guid: Guid,
    /// Members, their snapshot GUIDs and whether each is encrypted, set once
    /// A is snapshotted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The root's effective values on A, set locally on the restored root.
    pub mountpoint: Option<String>,
    pub readonly: bool,
}

/// The record's state. Names roots, boundaries and digests, never members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub token: String,
    pub source: Endpoint,
    /// `BE@SNAP` sent to A.
    pub snapshot: String,
    /// This operation creates `snapshot`.
    pub created: bool,
    /// The snapshot as adopted or created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<SnapshotRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    /// Full native identities of the planned source members, in one compact hash.
    pub source_identities: String,
    pub disk: DiskBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_pool: Option<PoolRef>,
    pub pool: String,
    pub esp_bytes: u64,
    pub swap_bytes: u64,
    pub hostid: String,
    /// The loader A's ESP gets: the BE's `/usr/lib/zboot/zboot.efi`.
    pub loader: FileIdentity,
    pub staging: String,
    pub keep: Vec<Kept>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_after: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_pool: Option<Guid>,
    /// Pair records on surviving pools whose other side is on A: each ends
    /// one-sided after the erase, its anchor holds kept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ended_pairs: Vec<EndedPair>,
    /// Other imported pools naming a boot default when planned: the last
    /// step clears it, so A's BE is the host's one default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clears: Vec<PoolRef>,
    /// A's original pool-member ranges, read from the whole disk even after
    /// its partition table is gone; abandon judges the erase by them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub label_extents: Vec<device::Extent>,
    /// The placement receipt and manifest, an attachment on the staging
    /// container: named by the Quiesced advance that commits it, before any
    /// data moves, and from then on at every step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Attachment>,
    /// Exact restored incarnations whose roles passed before publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_targets: Option<String>,
    /// Kept trees, in `keep` order, staged completely in one attempt.
    pub staged: u32,
    /// Trees returned to A completely in one attempt: the BE, then `keep`.
    pub returned: u32,
}
/// The surviving side of a pair whose other side is on A. After the erase
/// the record is removed from `owner` (one-sided: the peer is gone) and its
/// anchor holds stay, as `unpair` does for a gone peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndedPair {
    pub owner: Endpoint,
    pub pair_id: String,
    pub peer: Endpoint,
    /// `owner`'s role.
    pub role: zfs_tools::engine::management::Role,
}
impl State {
    pub fn tag(id: &str) -> String {
        format!("zboot:restore:{id}")
    }
    pub fn suffix(id: &str) -> String {
        format!("zboot-restore-{id}")
    }
    /// The restored BE on A.
    pub fn restored_be(&self) -> String {
        let leaf = self.source.name.rsplit('/').next().unwrap_or_default();
        format!("{}/ROOT/{leaf}", self.pool)
    }
    pub fn source_pool(&self) -> &str {
        pool_of(&self.source.name)
    }
    /// The record at its largest: every optional field present at its widest.
    fn worst_case(&self, id: &str) -> Result<Intent> {
        let mut state = self.clone();
        let wide = Guid::new(u64::MAX);
        let txg = zfs_tools::engine::Txg::new(u64::MAX);
        let objset = zfs_tools::engine::ObjsetId::new(u64::MAX);
        state.boundary = Some(SnapshotRef {
            name: self.snapshot.clone(),
            dataset_guid: wide,
            identity: zfs_tools::engine::SnapshotIdentity {
                pool_guid: wide,
                guid: wide,
                createtxg: txg,
                objsetid: objset,
            },
        });
        state.source_digest = Some("f".repeat(64));
        state.source_identities = "f".repeat(64);
        state.scrub_after = Some(u64::MAX);
        state.new_pool = Some(wide);
        state.receive_targets = Some("f".repeat(64));
        state.staged = u32::MAX;
        state.returned = u32::MAX;
        for kept in &mut state.keep {
            kept.digest = Some("f".repeat(64));
        }
        let identity = DatasetIdentity {
            pool_guid: wide,
            guid: wide,
            createtxg: txg,
            objsetid: objset,
        };
        for ended in &mut state.ended_pairs {
            for endpoint in [&mut ended.owner, &mut ended.peer] {
                endpoint.identity = identity.clone();
            }
        }
        // The receipt's name, on the staging this plan names, at its widest.
        state.receipt = Some(Attachment::widest(
            &receipt::key(id)?,
            Endpoint {
                name: self.staging.clone(),
                identity,
            },
        ));
        let mut intent = Intent::new(id, KIND, state);
        intent.step = Phase::Booted as u32;
        Ok(intent)
    }
}
pub type Intent = intent::Intent<State>;

/// One encryption root of a kept tree, as the plan shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EncryptionRoot {
    pub dataset: String,
    pub keyformat: String,
    pub keylocation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeptPlan {
    pub root: Endpoint,
    pub members: usize,
    pub used_bytes: u64,
    pub encryption_roots: Vec<EncryptionRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Space {
    pub staging_available: u64,
    pub staging_needed: u64,
    pub target_usable: u64,
    pub target_needed: u64,
}

/// A reviewed restore: what changes, what is lost, what is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub id: String,
    pub token: String,
    pub source_members: usize,
    pub source_used_bytes: u64,
    pub disk: DiskReview,
    pub keep: Vec<KeptPlan>,
    /// Datasets of A's pool that are not kept, and their space.
    pub lost_datasets: usize,
    pub lost_bytes: u64,
    pub space: Space,
    pub warnings: Vec<String>,
    pub state: State,
}
impl Plan {
    pub fn typed(&self) -> crate::consent::Typed {
        let identity = &self.disk.identity;
        crate::consent::disk_target(identity.serial.as_deref(), identity.wwn.as_deref())
    }
    pub fn intent(&self) -> Intent {
        Intent::new(&self.id, KIND, self.state.clone())
    }
}

/// What the token hashes: identities, loss scope and the loader, never the
/// operation id or free space.
#[derive(Serialize)]
struct Consent<'a> {
    source: &'a Endpoint,
    source_members: String,
    snapshot: Option<&'a SnapshotRef>,
    created: bool,
    disk: &'a DiskBinding,
    old_pool: &'a Option<PoolRef>,
    pool: &'a str,
    esp_bytes: u64,
    swap_bytes: u64,
    hostid: &'a str,
    loader: &'a FileIdentity,
    keep: Vec<(&'a str, &'a DatasetIdentity, String)>,
    lost: String,
    ended_pairs: &'a [EndedPair],
}

/// A fresh operation id: 64 random bits as 16 lowercase hex digits.
pub fn new_id() -> String {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    hex(&bytes[..8])
}
pub fn valid_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

use zfs_tools::engine::attachment::hex;

fn margin(bytes: u64) -> u64 {
    bytes / 10 + 128 * MIB
}

/// The geometry deploy will accept, shared by initial planning and every
/// pre-erase resume boundary. This planner is pure and changes nothing.
fn validate_deploy_geometry(
    identity: &DiskIdentity,
    esp_bytes: u64,
    swap_bytes: u64,
    id: &str,
) -> Result<()> {
    crate::deploy::layout::Layout::selected(
        identity,
        Some(esp_bytes),
        (swap_bytes != 0).then_some(swap_bytes),
        id,
    )?;
    Ok(())
}

/// Plan a restore. Observes only; any refusal leaves everything unchanged.
/// The running system may import A only as the host whose BE it restores:
/// its effective hostid is that BE's, or none (a Menu that adopted nothing),
/// and every import of A then records the BE's hostid.
pub(crate) fn require_host(backend: &mut (impl Backend + ?Sized), hostid: &str) -> Result<()> {
    let running = backend.effective_hostid()?;
    if running != "00000000" && running != hostid {
        return Err(refuse(format!(
            "the running hostid is {running}, not {hostid} of the BE being restored; restore from a zboot Menu booted on this host"
        )));
    }
    Ok(())
}

// The source remains on B after restore. Its owner-boots exception is useful
// for repair, but cannot authorize a restore whose final default would refuse.
fn admit_source_automounts(members: &[&DatasetView]) -> Result<()> {
    if let Some(member) = members
        .iter()
        .find(|d| !d.volume && d.value("canmount") == Some("on"))
    {
        let name = zfs_tools::engine::escape_display(&member.name);
        return Err(refuse(format!(
            "{name} has canmount=on and would prevent the restored boot default; fix with `zfs set canmount=noauto {name}` before restoring",
        )));
    }
    Ok(())
}

// Preparation is a direct pool child. Debian's initramfs mounts noauto
// descendants of its bootfs too, and mountpoint=none may use org.zol:mountpoint.
// A bootable pool root therefore cannot contain a new inert receive workspace.
fn admit_staging_parent(view: &View, pool: &str) -> Result<()> {
    let root = view.dataset(pool).is_some_and(|dataset| {
        !dataset.volume
            && dataset.value("mountpoint").is_some_and(|mountpoint| {
                strip_altroot(
                    mountpoint,
                    view.pool(pool).and_then(|pool| pool.altroot.as_deref()),
                ) == "/"
            })
    });
    let default = view
        .pool(pool)
        .is_some_and(|p| p.bootfs.as_deref() == Some(pool));
    if root || default {
        return Err(refuse(format!(
            "{} is a boot environment; restore staging must be outside a boot environment because its initramfs mounts noauto descendants",
            zfs_tools::engine::escape_display(pool),
        )));
    }
    Ok(())
}

/// The pool on the target disk is erased with it, so it must live on that
/// disk alone.
fn single_disk(pool: &str, disks: &[DiskIdentity]) -> Result<()> {
    if disks.len() != 1 {
        return Err(refuse(format!(
            "pool {pool} on the target disk spans another disk; restore erases only a pool wholly on A"
        )));
    }
    Ok(())
}

pub fn plan(backend: &mut impl Backend, request: &Request, id: &str) -> Result<Plan> {
    if !valid_id(id) {
        return Err(refuse("invalid restore operation id"));
    }
    let argument = crate::restore::restore_plan::SourceArgument::parse(&request.source)?;
    let view = backend.view()?;
    let be = argument.dataset.clone();
    let candidate = view
        .candidates
        .iter()
        .find(|c| c.dataset == be)
        .ok_or_else(|| refuse(format!("{be} is not a boot environment")))?;
    if let Some(reason) = &candidate.refusal {
        return Err(refuse(format!("{be} cannot be restored: {reason}")));
    }
    if crate::restore::restore_plan::Mapping::new(&be, DEFAULT_POOL, &[]).is_err() {
        return Err(refuse("restore source must be POOL/ROOT/BE"));
    }
    let source_pool = pool_of(&be).to_owned();
    admit_staging_parent(&view, &source_pool)?;
    let source_root = view
        .dataset(&be)
        .ok_or_else(|| refuse(format!("{be} is not imported")))?;
    let source = Endpoint {
        name: be.clone(),
        identity: source_root.identity.clone(),
    };
    let source_tree = view.tree(&be);
    admit_source_automounts(&source_tree)?;
    admit_tree(&view, &be, "the source BE")?;
    // The BE goes to A directly: only a relink inside it needs a proof.
    encryption_roots(backend, &view, &be, false)?;
    // A paired BE carries its pair's placement; the restored BE takes its
    // values instead (see `configure`), so it must be this incarnation's.
    for member in &source_tree {
        if let Some(property) = member
            .property(zfs_tools::engine::management::PLACEMENT_PROPERTY)
            .filter(|p| p.local())
            && zfs_tools::engine::management::Placement::parse(&property.value)?.identity
                != member.identity
        {
            return Err(refuse(format!(
                "{} carries a placement record for another incarnation; resume or abandon the operation that left it",
                member.name
            )));
        }
    }
    let (snapshot, created, boundary) = match &argument.snapshot {
        Some(suffix) => {
            let name = format!("{be}@{suffix}");
            let point = view
                .snapshot(&name)
                .ok_or_else(|| refuse(format!("{name} does not exist")))?
                .point
                .clone();
            if point.dataset_guid != source.identity.guid {
                return Err(refuse(format!("{name} belongs to a replaced dataset")));
            }
            for member in &source_tree {
                if view
                    .snapshot(&format!("{}@{suffix}", member.name))
                    .is_none()
                {
                    return Err(refuse(format!(
                        "{name} is not recursive: {} lacks it",
                        member.name
                    )));
                }
            }
            (name, false, Some(point))
        }
        None => {
            if !candidate.writable_head {
                return Err(refuse(format!(
                    "{be} is a paired secondary; name a snapshot (BE@SNAP) to restore"
                )));
            }
            (format!("{be}@{}", State::suffix(id)), true, None)
        }
    };
    // The identity A boots with is the BE's own /etc/hostid, resolved
    // before anything is erased and carried through every import of A.
    let hostid = match &boundary {
        Some(point) => backend.snapshot_hostid(point)?,
        None if view.running_root.as_deref() == Some(be.as_str()) => backend.running_hostid()?,
        None => {
            return Err(refuse(format!(
                "{be} is not the running system; name a snapshot (BE@SNAP) so its hostid can be read"
            )));
        }
    };
    require_host(backend, &hostid)?;
    // A's ESP gets the zboot loader the BE ships, read the same way; a BE
    // without one is refused here.
    let loader = backend.loader(boundary.as_ref())?;

    // Disk A, its pool and its independence from B.
    let identity = backend.disk_identity(&request.disk)?;
    let mut owners = Vec::new();
    for pool in &view.pools {
        let disks = backend.pool_disks(&pool.name, pool.guid)?;
        if disks
            .iter()
            .any(|d| d.device_number == identity.device_number)
        {
            owners.push((pool.clone(), disks));
        }
    }
    let old_pool = match owners.as_slice() {
        [] => None,
        [(pool, disks)] => {
            single_disk(&pool.name, disks)?;
            Some(pool.clone())
        }
        _ => return Err(refuse("more than one imported pool uses the target disk")),
    };
    if old_pool.as_ref().is_some_and(|p| p.name == source_pool) {
        return Err(refuse(
            "the source BE's pool is on the target disk; A must share no device with B",
        ));
    }
    let source_pool_view = view
        .pool(&source_pool)
        .ok_or_else(|| refuse(format!("pool {source_pool} is not imported")))?;
    let source_disks = backend.pool_disks(&source_pool, source_pool_view.guid)?;
    device::require_disks_independent(&identity, &source_disks).map_err(|_| {
        refuse(format!(
            "the target disk shares a device with pool {source_pool}"
        ))
    })?;
    let review = backend.disk(&request.disk, old_pool.as_ref().map(|p| p.name.as_str()))?;
    if review.identity != identity {
        return Err(refuse("the target disk changed during planning"));
    }
    if let Some(pool) = &old_pool {
        if view
            .running_root
            .as_deref()
            .is_some_and(|root| within(&pool.name, root))
        {
            return Err(refuse("the target disk holds the running system"));
        }
        if let Some(mounted) = view.tree(&pool.name).iter().find(|d| d.mounted) {
            return Err(refuse(format!(
                "{} on the target disk is mounted; unmount everything on it first",
                mounted.name
            )));
        }
    }

    // Kept trees.
    let keep_roots = crate::selection::normalize_roots(&request.keep)
        .map_err(|e| refuse(format!("invalid --keep: {e}")))?;
    let leaf = be.rsplit('/').next().unwrap();
    let restored_relative = format!("ROOT/{leaf}");
    let mut kept = Vec::new();
    let mut kept_plans = Vec::new();
    let mut kept_used = 0u64;
    let mut warnings = Vec::new();
    for root in &keep_roots {
        let pool = old_pool
            .as_ref()
            .ok_or_else(|| refuse("the target disk has no imported pool to keep datasets from"))?;
        let relative = root
            .strip_prefix(&format!("{}/", pool.name))
            .ok_or_else(|| refuse(format!("{root} is not in {}, the target's pool", pool.name)))?
            .to_owned();
        if within(&relative, &restored_relative)
            || within(&restored_relative, &relative)
            || relative == "ROOT"
        {
            return Err(refuse(format!(
                "{root} overlaps the restored BE {}/{restored_relative}",
                request.pool.as_deref().unwrap_or(&pool.name)
            )));
        }
        let dataset = view
            .dataset(root)
            .ok_or_else(|| refuse(format!("{root} does not exist")))?;
        admit_tree(&view, root, "a kept tree")?;
        let encryption_roots = encryption_roots(backend, &view, root, true)?;
        if view.dataset(&source_pool).is_some_and(|d| d.encrypted)
            && let Some(plain) = view.tree(root).into_iter().find(|d| !d.encrypted)
        {
            return Err(refuse(format!(
                "{} is not encrypted, but pool {source_pool}'s root is, so staging would encrypt it with B's key; restore cannot keep it",
                plain.name
            )));
        }
        let pool_view = view.pool(&pool.name).unwrap();
        let mountpoint = match dataset.volume {
            true => None,
            false => dataset
                .value("mountpoint")
                .map(|m| strip_altroot(m, pool_view.altroot.as_deref())),
        };
        let readonly = dataset.value("readonly") == Some("on");
        kept_used += dataset.used;
        kept_plans.push(KeptPlan {
            root: Endpoint {
                name: root.clone(),
                identity: dataset.identity.clone(),
            },
            members: view.tree(root).len(),
            used_bytes: dataset.used,
            encryption_roots,
        });
        kept.push(Kept {
            relative,
            guid: dataset.identity.guid,
            digest: None,
            mountpoint,
            readonly,
        });
    }

    // A returned dataset that takes its key from another is relinked with
    // the helper; it must work here before anything changes.
    if std::iter::once(&be)
        .chain(&keep_roots)
        .flat_map(|root| view.tree(root))
        .any(|d| d.encrypted && d.encryption_root.as_deref() != Some(d.name.as_str()))
    {
        backend.change_key_ready().map_err(|error| {
            refuse(format!(
                "{}; restore needs it to relink encryption keys on A",
                change_key_unavailable(&error)
            ))
        })?;
    }

    // The new pool and its layout.
    let pool = request
        .pool
        .clone()
        .or_else(|| old_pool.as_ref().map(|p| p.name.clone()))
        .unwrap_or_else(|| DEFAULT_POOL.into());
    zfs_tools::engine::validate_dataset_name(&pool)?;
    if pool.contains('/') {
        return Err(refuse("--pool names one pool"));
    }
    if view
        .pools
        .iter()
        .any(|p| p.name == pool && old_pool.as_ref().is_none_or(|o| o.guid != p.guid))
    {
        return Err(refuse(format!(
            "pool name {pool} is already imported from another disk"
        )));
    }
    let esp_bytes = request.esp_bytes.unwrap_or_else(|| {
        review
            .partitions
            .iter()
            .find(|p| p.filesystem.as_deref() == Some("vfat"))
            .map_or(DEFAULT_ESP, |p| p.bytes)
    });
    let swap_bytes = request.swap_bytes.unwrap_or_else(|| {
        review
            .partitions
            .iter()
            .find(|p| p.filesystem.as_deref() == Some("swap"))
            .map_or(0, |p| p.bytes)
    });

    // Use deploy's pure planner now, before recording or erasing anything.
    // Content fitting A is insufficient if its ESP/swap leaves a layout the
    // deploy step cannot create (for example, less than 2 GiB for ZFS).
    validate_deploy_geometry(&identity, esp_bytes, swap_bytes, id)?;

    // Space.
    let staging_available = view.dataset(&source_pool).map_or(0, |d| d.available);
    let staging_needed = if kept_used == 0 {
        0
    } else {
        kept_used + margin(kept_used)
    };
    if staging_available < staging_needed {
        return Err(refuse(format!(
            "pool {source_pool} has {staging_available} bytes free; staging the kept data needs {staging_needed}"
        )));
    }
    let source_used = source_root.used;
    let target_usable = identity
        .bytes
        .saturating_sub(esp_bytes + swap_bytes + LAYOUT_SLACK)
        / 16
        * 15;
    let target_needed = source_used + kept_used + margin(source_used + kept_used);
    if target_usable < target_needed {
        return Err(refuse(format!(
            "the target disk can hold about {target_usable} bytes; the BE and kept data need {target_needed}"
        )));
    }

    // Lost data.
    let lost: Vec<_> = old_pool.as_ref().map_or_else(Vec::new, |pool| {
        view.tree(&pool.name)
            .into_iter()
            .filter(|d| !keep_roots.iter().any(|root| within(root, &d.name)))
            .collect()
    });
    let lost_bytes = old_pool
        .as_ref()
        .and_then(|p| view.dataset(&p.name))
        .map_or(0, |root| root.used.saturating_sub(kept_used));
    // The loss scope binds every dataset and snapshot that is not kept.
    let mut lost_snapshots = old_pool.as_ref().map_or_else(Vec::new, |pool| {
        view.snapshots
            .iter()
            .filter(|s| {
                let dataset = s.point.name.split('@').next().unwrap_or_default();
                within(&pool.name, dataset) && !keep_roots.iter().any(|root| within(root, dataset))
            })
            .map(|s| format!("{}\t{}\n", s.point.name, s.point.identity.guid))
            .collect::<Vec<_>>()
    });
    lost_snapshots.sort();
    let lost_digest = hex(&Sha256::digest(
        lost.iter()
            .map(|d| format!("{}\t{}\n", d.name, d.identity.guid))
            .chain(lost_snapshots)
            .collect::<String>(),
    ));

    // Existing records refuse before anything changes.
    let mut records = Records(backend);
    for (pool_name, _) in intent::find(&mut records)? {
        if pool_name == source_pool || old_pool.as_ref().is_some_and(|p| p.name == pool_name) {
            return Err(refuse(format!(
                "pool {pool_name} already records an operation; resume or abandon it first"
            )));
        }
    }

    if source_tree.iter().any(|d| d.encrypted) {
        warnings.push(format!(
            "{be} is encrypted; booting A needs its key as booting B does"
        ));
    }
    let ended_pairs = ended_pairs(
        &view,
        &be,
        old_pool.as_ref().map(|p| p.guid),
        &keep_roots,
        &mut warnings,
    )?;
    let label_extents = if ended_pairs.is_empty() {
        Vec::new()
    } else {
        backend.label_extents(&review)?
    };
    if !ended_pairs
        .iter()
        .any(|ended| within(&ended.owner.name, &be) || within(&be, &ended.owner.name))
        && source_tree
            .iter()
            .any(|d| d.property("zboot:pair").is_some_and(Property::local))
    {
        let mut warning =
            format!("{be} is paired; the restored BE is unpaired, pair it again afterwards");
        // A record whose peer's pool is not imported cannot be matched to the
        // target disk, so it stays: say how to end it if that disk held the peer.
        for member in &source_tree {
            let Some(property) = member.property("zboot:pair").filter(|p| p.local()) else {
                continue;
            };
            let record = zfs_tools::engine::management::PairRecord::parse(&property.value)?;
            if !view
                .pools
                .iter()
                .any(|pool| pool.guid == record.peer.identity.pool_guid)
            {
                warning.push_str(&format!(
                    ". Its peer {peer} is on a pool that is not imported, so restore cannot tell \
                     whether the target disk holds it: if it does, `zboot unpair {owner}` afterwards \
                     removes the record that still names it",
                    peer = record.peer.name,
                    owner = member.name,
                ));
                break;
            }
        }
        warnings.push(warning);
    }

    let disk = DiskBinding::of(&review)?;
    let clears = view
        .pools
        .iter()
        .filter(|p| {
            p.bootfs.is_some()
                && p.name != pool
                && old_pool.as_ref().is_none_or(|old| old.name != p.name)
        })
        .map(|p| PoolRef {
            name: p.name.clone(),
            guid: p.guid,
        })
        .collect();
    let old_pool = old_pool.map(|p| PoolRef {
        name: p.name,
        guid: p.guid,
    });
    let consent = Consent {
        source: &source,
        source_members: tree_identities(&view, &be),
        snapshot: boundary.as_ref(),
        created,
        disk: &disk,
        old_pool: &old_pool,
        pool: &pool,
        esp_bytes,
        swap_bytes,
        hostid: &hostid,
        loader: &loader,
        keep: kept_plans
            .iter()
            .map(|k| {
                (
                    k.root.name.as_str(),
                    &k.root.identity,
                    tree_identities(&view, &k.root.name),
                )
            })
            .collect(),
        lost: lost_digest,
        ended_pairs: &ended_pairs,
    };
    let token = crate::consent::token(&consent)?;
    let state = State {
        token: token.clone(),
        source,
        snapshot,
        created,
        boundary,
        source_digest: None,
        source_identities: tree_identities(&view, &be),
        disk,
        old_pool,
        pool,
        esp_bytes,
        swap_bytes,
        hostid,
        loader,
        staging: format!("{source_pool}/{}", State::suffix(id)),
        keep: kept,
        scrub_after: None,
        new_pool: None,
        ended_pairs,
        clears,
        label_extents,
        receipt: None,
        receive_targets: None,
        staged: 0,
        returned: 0,
    };
    intent::encode(&state.worst_case(id)?)
        .map_err(|e| refuse(format!("{e}; keep fewer or shorter dataset roots")))?;
    Ok(Plan {
        id: id.into(),
        token,
        source_members: source_tree.len(),
        source_used_bytes: source_used,
        disk: review,
        keep: kept_plans,
        lost_datasets: lost.len(),
        lost_bytes,
        space: Space {
            staging_available,
            staging_needed,
            target_usable,
            target_needed,
        },
        warnings,
        state,
    })
}

/// Pair records on surviving pools whose other side is on A, the pool this
/// restore erases: the record that owns `be` (its own or an ancestor's) when
/// its peer is on A, and the peer's record of every paired dataset of a kept
/// tree. Kept datasets return as new incarnations, unpaired; the plan names
/// every record it ends, and anything it cannot end in `warnings`.
fn ended_pairs(
    view: &View,
    be: &str,
    erased: Option<Guid>,
    kept: &[String],
    warnings: &mut Vec<String>,
) -> Result<Vec<EndedPair>> {
    use zfs_tools::engine::management::{PAIR_PROPERTY, PairRecord, Role};
    let Some(erased) = erased else {
        return Ok(Vec::new());
    };
    let mut ended: Vec<EndedPair> = Vec::new();
    let mut name = Some(be);
    while let Some(current) = name {
        if let Some(property) = view
            .dataset(current)
            .and_then(|d| d.property(PAIR_PROPERTY))
            .filter(|p| p.local())
        {
            let record = PairRecord::parse(&property.value)?;
            if record.endpoint.name != current
                || view.dataset(current).map(|d| &d.identity) != Some(&record.endpoint.identity)
            {
                return Err(refuse(format!(
                    "{current}'s pair record names another dataset"
                )));
            }
            if record.peer.identity.pool_guid == erased {
                warnings.push(format!(
                    "{owner} is paired with {peer}, which this restore erases: after the erase {owner}'s \
                     pair record is removed (its anchor holds stay; `zboot unpair {owner} --release-anchors` \
                     releases them). {owner} keeps its current mount and read-only properties; `zboot primary {owner}` makes it writable",
                    owner = record.endpoint.name,
                    peer = record.peer.name,
                ));
                ended.push(EndedPair {
                    owner: record.endpoint,
                    pair_id: record.pair_id,
                    peer: record.peer,
                    role: record.role,
                });
            }
            break;
        }
        name = current.rsplit_once('/').map(|(parent, _)| parent);
    }
    for root in kept {
        for member in view.tree(root) {
            let Some(property) = member.property(PAIR_PROPERTY).filter(|p| p.local()) else {
                continue;
            };
            let record = PairRecord::parse(&property.value)?;
            if record.endpoint.name != member.name || record.endpoint.identity != member.identity {
                return Err(refuse(format!(
                    "{}'s pair record names another dataset",
                    member.name
                )));
            }
            if record.peer.identity.pool_guid == erased
                || ended.iter().any(|e| e.pair_id == record.pair_id)
            {
                continue;
            }
            let returns = match record.role {
                Role::Secondary => "fenced, with its saved placement",
                Role::Primary => "active",
            };
            let counterpart = view
                .dataset(&record.peer.name)
                .filter(|peer| peer.identity == record.peer.identity)
                .and_then(|peer| peer.property(PAIR_PROPERTY).filter(|p| p.local()))
                .map(|p| PairRecord::parse(&p.value))
                .transpose()?;
            if counterpart.as_ref() != Some(&record.counterpart()) {
                warnings.push(format!(
                    "{member} is paired with {peer}, which is not imported here or does not name it: \
                     restore cannot end that record. {member} returns unpaired and {returns}; \
                     run `zboot unpair {peer}` where it is imported",
                    member = member.name,
                    peer = record.peer.name,
                ));
                continue;
            }
            warnings.push(format!(
                "{peer} is paired with {member}, which this restore erases: after the erase {peer}'s \
                 pair record is removed (its anchor holds stay). {member} returns unpaired and {returns}; \
                 `zboot pair` joins them again without a full copy",
                member = member.name,
                peer = record.peer.name,
            ));
            ended.push(EndedPair {
                owner: record.peer,
                pair_id: record.pair_id,
                peer: record.endpoint,
                role: record.role.opposite(),
            });
        }
    }
    Ok(ended)
}

fn identities(members: &[&DatasetView]) -> String {
    hex(&Sha256::digest(
        members
            .iter()
            .map(|d| {
                format!(
                    "{}\t{}\t{}\t{}\t{}\n",
                    d.name,
                    d.identity.pool_guid,
                    d.identity.guid,
                    d.identity.createtxg,
                    d.identity.objsetid
                )
            })
            .collect::<String>(),
    ))
}

/// The source BE's members this restore copies: those its boundary snapshot
/// covers and this restore holds (`tag`). A dataset made under the BE after
/// that is not part of the BE and is left out.
pub(crate) fn planned<'a>(
    view: &'a View,
    root: &str,
    suffix: &str,
    tag: &str,
) -> Vec<&'a DatasetView> {
    view.tree(root)
        .into_iter()
        .filter(|member| {
            view.snapshot(&format!("{}@{suffix}", member.name))
                .is_some_and(|s| {
                    s.point.dataset_guid == member.identity.guid
                        && s.holds.iter().any(|hold| hold == tag)
                })
        })
        .collect()
}

fn tree_identities(view: &View, root: &str) -> String {
    identities(&view.tree(root))
}

fn strip_altroot(mountpoint: &str, altroot: Option<&str>) -> String {
    match altroot.filter(|a| *a != "/" && !a.is_empty() && *a != "-") {
        Some(altroot) if mountpoint.starts_with('/') => match mountpoint.strip_prefix(altroot) {
            Some("") => "/".into(),
            Some(rest) if rest.starts_with('/') => rest.into(),
            _ => mountpoint.into(),
        },
        _ => mountpoint.into(),
    }
}

/// Shapes per-dataset raw streams can carry: no clones (each dataset is sent
/// on its own, so a clone would become an independent copy), encryption roots
/// inside the tree and no plaintext dataset under an encrypted one, no
/// partial receives, and only the management properties restore re-creates.
/// Paired datasets may be kept: restore is a copy of its own, and a kept one
/// returns unpaired while restore ends its peer's record (`ended_pairs`).
pub(crate) fn admit_tree(view: &View, root: &str, what: &str) -> Result<()> {
    let tree = view.tree(root);
    if tree.is_empty() {
        return Err(refuse(format!("{root} does not exist")));
    }
    admit_members(view, root, &tree, what)
}

pub(crate) fn admit_members(
    view: &View,
    root: &str,
    members: &[&DatasetView],
    what: &str,
) -> Result<()> {
    for member in members {
        let name = &member.name;
        if let Some(origin) = &member.origin {
            let origin_dataset = origin.split('@').next().unwrap_or_default();
            if !within(root, origin_dataset) {
                return Err(refuse(format!(
                    "{name} in {what} is a clone of {origin}, outside {root}; promote it or keep its origin too"
                )));
            }
            return Err(refuse(format!(
                "{name} in {what} is a clone of {origin}; restore copies each dataset on its own and would make it an independent copy. Promote it (`zfs promote {name}`) or leave it out"
            )));
        }
        if let Some(encryption_root) = &member.encryption_root
            && !within(root, encryption_root)
        {
            return Err(refuse(format!(
                "{name} in {what} is encrypted under {encryption_root}, outside {root}; keep the encryption root instead"
            )));
        }
        if !member.encrypted
            && name != root
            && let Some((parent, _)) = name.rsplit_once('/')
            && view.dataset(parent).is_some_and(|p| p.encrypted)
        {
            return Err(refuse(format!(
                "{name} in {what} is not encrypted but its parent is; restore cannot receive it there"
            )));
        }
        if member.resume_token {
            return Err(refuse(format!("{name} in {what} holds a partial receive")));
        }
        for (key, property) in &member.properties {
            if !zfs_tools::engine::management::managed_key(key) {
                continue;
            }
            match key.as_str() {
                intent::PROPERTY if !property.local() || !name.contains('/') => {}
                "zboot:placement"
                | zfs_tools::engine::management::RETIRED_MARKER
                | "zboot:cmdline"
                | zfs_tools::engine::management::PAIR_PROPERTY => {}
                // An operation's own marks: its record, its fences, its attachment.
                intent::PROPERTY
                | zfs_tools::engine::management::PENDING_PROPERTY
                | zfs_tools::engine::management::STAGING_PROPERTY => {
                    return Err(unfinished(name, what, key));
                }
                _ if key.starts_with("zboot:attachment:") => {
                    return Err(unfinished(name, what, key));
                }
                _ => {
                    let holder = property
                        .source
                        .strip_prefix("inherited from ")
                        .unwrap_or(name);
                    return Err(refuse(format!(
                        "{name} in {what} carries {key}, which this zboot does not read; once \
                         it is known to be obsolete, `zfs inherit {key} {holder}` removes it"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn unfinished(name: &str, what: &str, key: &str) -> RecoveryError {
    refuse(format!(
        "{name} in {what} carries {key}; finish or abandon that operation first"
    ))
}

/// Encryption roots of a tree. Restore proves without asking for any key
/// that every copy is wrapped like its intended root, so a raw or hex key
/// it must prove (every one of a kept tree, which is staged; one the BE's
/// datasets are relinked to) has to be in a file, and that file must open
/// the root from here (`zfs load-key -n`). Nothing of A is mounted (the plan
/// refuses that), so a file found now is not on A, and a key A alone holds
/// (in an unmounted BE or home) fails the check. A passphrase is proved by
/// its salt and iterations.
fn encryption_roots(
    backend: &mut impl Backend,
    view: &View,
    root: &str,
    staged: bool,
) -> Result<Vec<EncryptionRoot>> {
    let mut roots = Vec::new();
    let tree = view.tree(root);
    for member in &tree {
        if !member.encrypted || member.encryption_root.as_deref() != Some(member.name.as_str()) {
            continue;
        }
        let keyformat = member.value("keyformat").unwrap_or("-").to_owned();
        let keylocation = member.value("keylocation").unwrap_or("-").to_owned();
        let relinked = tree.iter().any(|other| {
            other.name != member.name
                && other.encryption_root.as_deref() == Some(member.name.as_str())
        });
        if keyformat != "passphrase" && (staged || relinked) && !keylocation.starts_with("file://")
        {
            return Err(refuse(format!(
                "the {keyformat} key of {} is entered at a prompt, so restore cannot prove its copies \
                 are wrapped like it without asking for it; put the key in a file off A and set \
                 keylocation=file://PATH first",
                member.name
            )));
        }
        if keylocation.starts_with("file://") {
            backend
                .check_key(&member.name, &keylocation)
                .map_err(|error| {
                    refuse(format!(
                        "the key of {} ({keylocation}) does not unlock it from here ({error}); \
                     put a copy of the key off A at that path, or set keylocation, first",
                        member.name
                    ))
                })?;
        }
        roots.push(EncryptionRoot {
            dataset: member.name.clone(),
            keyformat,
            keylocation,
        });
    }
    Ok(roots)
}

/// Members, snapshot GUIDs up to the boundary, and whether each member is
/// encrypted, relative to `root`: this proves data history only. Staged and
/// returned copies are their own encryption roots until relinked, so the
/// encryption hierarchy is checked against the receipt's manifest instead.
/// Members created after the root's boundary have no boundary snapshot, are
/// not sent and are left out.
pub(crate) fn tree_digest(view: &View, root: &str, suffix: &str) -> String {
    let mut text = String::new();
    let boundary = view
        .snapshot(&format!("{root}@{suffix}"))
        .map(|s| s.point.identity.createtxg);
    for member in view.tree(root) {
        if boundary.is_some_and(|txg| member.identity.createtxg > txg)
            && view
                .snapshot(&format!("{}@{suffix}", member.name))
                .is_none()
        {
            continue;
        }
        let relative = &member.name[root.len()..];
        let encrypted = u8::from(member.encrypted);
        text.push_str(&format!("{relative}\tenc={encrypted}\n"));
        let mut reached = false;
        for snapshot in view.snapshots_of(&member.name) {
            let (_, name) = snapshot.point.name.split_once('@').unwrap();
            text.push_str(&format!(
                "{relative}@{name}\t{}\n",
                snapshot.point.identity.guid
            ));
            if name == suffix {
                reached = true;
                break;
            }
        }
        if !reached {
            text.push_str(&format!("{relative}\tno-boundary\n"));
        }
    }
    hex(&Sha256::digest(text))
}

/// Human plan, with the token.
pub fn render(plan: &Plan) -> String {
    use std::fmt::Write;
    let e = zfs_tools::engine::escape_display;
    let state = &plan.state;
    let mut out = String::new();
    let disk = &plan.disk.identity;
    let _ = writeln!(
        out,
        "Restore {} (operation {})",
        e(&state.restored_be()),
        plan.id
    );
    let _ = writeln!(
        out,
        "  Source: {} ({}, {} datasets, {} bytes)",
        e(&state.snapshot),
        if state.created {
            "snapshotted now"
        } else {
            "existing snapshot"
        },
        plan.source_members,
        plan.source_used_bytes,
    );
    let _ = writeln!(
        out,
        "  Target disk: {} {} serial {} wwn {} ({} bytes)",
        e(&disk.path),
        e(disk.model.as_deref().unwrap_or("-")),
        e(disk.serial.as_deref().unwrap_or("-")),
        e(disk.wwn.as_deref().unwrap_or("-")),
        disk.bytes
    );
    match &state.old_pool {
        Some(pool) => {
            let _ = writeln!(
                out,
                "  ERASED: all of pool {} on that disk: {} datasets not kept ({} bytes), and every partition",
                e(&pool.name),
                plan.lost_datasets,
                plan.lost_bytes
            );
        }
        None => {
            let _ = writeln!(
                out,
                "  ERASED: every partition on that disk ({} present)",
                plan.disk.partitions.len()
            );
        }
    }
    let _ = writeln!(
        out,
        "  New layout: pool {}, ESP {} bytes, swap {} bytes, hostid {}",
        e(&state.pool),
        state.esp_bytes,
        state.swap_bytes,
        state.hostid
    );
    for pool in &state.clears {
        let _ = writeln!(out, "  Clears the boot default on pool {}", e(&pool.name));
    }
    let _ = writeln!(
        out,
        "  Loader: {}:/{} sha256 {} ({} bytes)",
        e(&state.snapshot),
        crate::loader::SHIPPED,
        state.loader.sha256,
        state.loader.bytes
    );
    if plan.keep.is_empty() {
        let _ = writeln!(out, "  Kept: nothing");
    }
    for kept in &plan.keep {
        let _ = writeln!(
            out,
            "  Kept: {} ({} datasets, {} bytes) via {}/{}",
            e(&kept.root.name),
            kept.members,
            kept.used_bytes,
            e(&state.staging),
            e(&kept.root.name[kept.root.name.find('/').map_or(0, |i| i + 1)..])
        );
        for root in &kept.encryption_roots {
            let _ = writeln!(
                out,
                "    encryption root {}: keyformat {}, keylocation {}",
                e(&root.dataset),
                e(&root.keyformat),
                e(&root.keylocation)
            );
        }
    }
    let _ = writeln!(
        out,
        "  Space: staging needs {} of {} free; the BE and kept data need {} of about {} usable",
        plan.space.staging_needed,
        plan.space.staging_available,
        plan.space.target_needed,
        plan.space.target_usable
    );
    for warning in &plan.warnings {
        let _ = writeln!(out, "  Note: {}", e(warning));
    }
    let _ = writeln!(out, "  Token: {}", plan.token);
    out
}
