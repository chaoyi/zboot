//! The host identity of the one neutral recovery Menu.
//!
//! The Menu boots with hostid 0. OpenZFS then refuses an ordinary import of
//! every pool its own host left active, which is every pool of a host that
//! does not export at shutdown. The Menu instead takes on the identity of one
//! host and keeps its ordinary non-force read-only import:
//!
//! - when active pools record one hostid, it adopts that hostid from their
//!   labels (`Decision::Adopt`); a second hostid, an active pool recording
//!   none, a hibernation image or a Menu that already has a hostid needs the
//!   operator (the rescue can force-import one with `zpool import -f`);
//! - when no pool is active, it imports every exported pool and adopts the
//!   default BE's `/etc/hostid`, unless that file is missing, zero,
//!   malformed, unreadable or contradicts the default pool's labels, which is
//!   reported and leaves the Menu at hostid 0.
//!
//! Either way the adopted host is one hostid and one pool set: the pools whose
//! labels record that hostid, plus exported pools recording none. Pools of
//! another host, exported ones included, stay closed (or are closed again).
//! The set is recorded with the hostid before import, so the boot handoff
//! refuses a pool imported from outside it before it mounts anything.
//!
//! An adopted hostid turns off OpenZFS's only guard against a second writer
//! of a non-multihost pool, and a hibernation image resumed after a write
//! would damage the pool. A known image therefore blocks every writable
//! handoff and Menu action; places that could hold one unseen (encrypted,
//! LVM or RAID volumes, filesystems that can carry a swapfile) and members
//! not directly on a local NVMe or SATA disk keep the countdown off, so only
//! an operator's explicit selection boots.

use super::{RecoveryError, Result, refuse};
use crate::{
    device::{self, Block},
    hostid::{self, Installed, Label, POOL_STATE_ACTIVE},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use zfs_tools::engine::state::NativeState;

const HOSTID_FILE: &str = "/etc/hostid";
const SPL_HOSTID: &str = "/sys/module/spl/parameters/spl_hostid";
/// Present once this Menu runs under an adopted identity, until the next boot.
const ADOPTED_RECORD: &str = "/run/zboot-hostid-adopted";
const MAX_MEMBERS: usize = 256;
/// Transports whose disks belong to this machine alone.
const LOCAL_TRANSPORTS: [&str; 3] = ["nvme", "sata", "ata"];
/// Filesystems that can hold a swapfile, and so a hibernation image the Menu
/// does not examine.
const SWAPFILE_FILESYSTEMS: [&str; 8] = [
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Decision {
    /// No active pool records a hostid other than the Menu's.
    NotNeeded,
    Adopt {
        hostid: u32,
        /// The host's pools by GUID.
        pools: BTreeMap<u64, String>,
    },
    /// Adoption needs an operator decision; the text explains why.
    Attended(String),
}

/// What the Menu adopted: the host's hostid and its pools, kept for the
/// banner, the countdown and every handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Adoption {
    pub(super) hostid: String,
    /// Where the hostid came from.
    pub(super) source: String,
    pub(super) pools: Vec<String>,
    pub(super) pool_guids: Vec<String>,
    /// Why the boot countdown stays off; `None` permits it.
    pub(super) autoboot_refusal: Option<String>,
}

/// An adoption failure. `Unchanged` left the Menu's identity as it was;
/// `Inconsistent` could not restore it, so no pool may be imported.
#[derive(Debug)]
pub(super) enum Failure {
    Unchanged(RecoveryError),
    Inconsistent(RecoveryError),
}

/// How the Menu imports its pools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Import {
    /// Exactly these pools (GUIDs) of the adopted host.
    Host(BTreeSet<u64>),
    /// No pool is active: every pool, then the default BE's hostid.
    ThenDefault(Vec<Label>),
    /// Every pool under the current identity; nothing is adopted.
    All,
}

/// Places a hibernation image could be.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Hazards {
    /// Swap signatures holding a hibernation image.
    pub(super) images: Vec<String>,
    /// Places the Menu does not look into: encrypted, LVM and RAID volumes,
    /// and filesystems that can hold a swapfile.
    pub(super) unexamined: Vec<String>,
}

/// Classify every block device. Pure for tests.
pub(super) fn hazards(rows: &[Block]) -> Hazards {
    fn walk(rows: &[Block], hazards: &mut Hazards) {
        for row in rows {
            match device::clean(&row.fstype).as_deref() {
                Some("swsuspend") => hazards.images.push(row.path.clone()),
                Some("crypto_LUKS" | "LVM2_member" | "linux_raid_member") => {
                    hazards.unexamined.push(row.path.clone())
                }
                Some(fs) if SWAPFILE_FILESYSTEMS.contains(&fs) => {
                    hazards.unexamined.push(row.path.clone())
                }
                _ => {}
            }
            walk(&row.children, hazards);
        }
    }
    let mut found = Hazards::default();
    walk(rows, &mut found);
    found
}

fn zfs_members(rows: &[Block], members: &mut Vec<String>) {
    for row in rows {
        if device::clean(&row.fstype).as_deref() == Some("zfs_member") {
            members.push(row.path.clone());
        }
        zfs_members(&row.children, members);
    }
}

struct Observation {
    labels: Vec<Label>,
    hazards: Hazards,
}

/// Read every ZFS member label and every place a hibernation image could be.
fn observe() -> Result<Observation> {
    let landscape = device::observe_landscape()?;
    let mut paths = Vec::new();
    zfs_members(&landscape.blockdevices, &mut paths);
    if paths.len() > MAX_MEMBERS {
        return Err(refuse("more than 256 ZFS member devices"));
    }
    let mut labels = Vec::new();
    for path in paths {
        labels.extend(hostid::read_labels(&path).map_err(|e| refuse(e.to_string()))?);
    }
    Ok(Observation {
        labels,
        hazards: hazards(&landscape.blockdevices),
    })
}

/// Labels for per-pool import jobs. The discovery coordinator owns the writer
/// barrier while it observes these and chooses the identity-bound import set.
pub(super) fn pool_labels() -> Result<Vec<Label>> {
    Ok(observe()?.labels)
}

fn names(pools: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut names: Vec<String> = pools.into_iter().collect();
    names.sort();
    names.dedup();
    names
}

fn listing(pools: &[String]) -> String {
    pools
        .iter()
        .map(|pool| zfs_tools::engine::escape_display(pool))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Active pools by owner hostid (0: none recorded).
fn active_owners(labels: &[Label]) -> BTreeMap<u32, BTreeMap<u64, String>> {
    let mut owners: BTreeMap<u32, BTreeMap<u64, String>> = BTreeMap::new();
    for label in labels.iter().filter(|l| l.state == POOL_STATE_ACTIVE) {
        owners
            .entry(label.hostid)
            .or_default()
            .insert(label.pool_guid, label.name.clone());
    }
    owners
}

/// The pools of the host `hostid`: every label records it, or the pool is
/// exported and records no hostid. Pure for tests.
pub(super) fn members(labels: &[Label], hostid: u32) -> BTreeMap<u64, String> {
    let mut pools: BTreeMap<u64, (String, bool)> = BTreeMap::new();
    for label in labels {
        let fits = label.hostid == hostid || label.hostid == 0 && label.state != POOL_STATE_ACTIVE;
        let entry = pools
            .entry(label.pool_guid)
            .or_insert_with(|| (label.name.clone(), true));
        entry.1 &= fits;
    }
    pools
        .into_iter()
        .filter(|(_, (_, fits))| *fits)
        .map(|(guid, (name, _))| (guid, name))
        .collect()
}

/// Decide automatic adoption from the observed labels. Pure for tests.
pub(super) fn decide(current: u32, labels: &[Label], images: &[String]) -> Decision {
    let mut owners = active_owners(labels);
    let anonymous = owners.remove(&0);
    owners.remove(&current);
    if owners.is_empty() {
        return Decision::NotNeeded;
    }
    let listed = owners
        .iter()
        .map(|(hostid, pools)| {
            format!(
                "{} ({})",
                hostid::format(*hostid),
                listing(&names(pools.values().cloned()))
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    if current != 0 {
        return Decision::Attended(format!(
            "this Menu has hostid {}; pools are active under {listed}; make sure the previous writer is stopped, then force-import one from the shell with zpool import -f",
            hostid::format(current)
        ));
    }
    if !images.is_empty() {
        return Decision::Attended(format!(
            "a hibernation image is present on {}; resuming it after a pool import would damage the pool; pools are active under {listed}",
            listing(images)
        ));
    }
    if owners.len() > 1 {
        return Decision::Attended(format!(
            "pools are active under more than one hostid: {listed}; make sure the previous writer is stopped, then force-import one from the shell with zpool import -f"
        ));
    }
    // Under any nonzero hostid OpenZFS refuses an active pool that records
    // none, so adoption would silently drop it from the menu.
    if let Some(anonymous) = anonymous {
        return Decision::Attended(format!(
            "pools are active under {listed}, but adopting would hide active pools with no hostid: {}; make sure the previous writer is stopped, then force-import one from the shell with zpool import -f",
            listing(&names(anonymous.into_values()))
        ));
    }
    let hostid = *owners.keys().next().expect("one owner");
    Decision::Adopt {
        hostid,
        pools: members(labels, hostid),
    }
}

/// Why `lsblk --json -s` shows a member that is not directly on a local
/// disk, or `None` when it is. Pure for tests.
pub(crate) fn transport_refusal(path: &str, lsblk: &str) -> Option<String> {
    fn walk<'a>(node: &'a serde_json::Value, nodes: &mut Vec<&'a serde_json::Value>) {
        nodes.push(node);
        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
            for child in children {
                walk(child, nodes);
            }
        }
    }
    let shown = zfs_tools::engine::escape_display(path);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(lsblk) else {
        return Some(format!("{shown}: device stack unreadable"));
    };
    let mut nodes = Vec::new();
    for root in value
        .get("blockdevices")
        .and_then(|b| b.as_array())
        .into_iter()
        .flatten()
    {
        walk(root, &mut nodes);
    }
    let mut disks = 0;
    for node in nodes {
        let kind = node.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match kind {
            "part" => {}
            "disk" => {
                disks += 1;
                let tran = node.get("tran").and_then(|t| t.as_str()).unwrap_or("");
                if !LOCAL_TRANSPORTS.contains(&tran) {
                    let tran = if tran.is_empty() { "unknown" } else { tran };
                    return Some(format!(
                        "{shown} is on a {} disk",
                        zfs_tools::engine::escape_display(tran)
                    ));
                }
            }
            other => {
                return Some(format!(
                    "{shown} is on a {} device",
                    zfs_tools::engine::escape_display(other)
                ));
            }
        }
    }
    (disks != 1).then(|| format!("{shown}: no single backing disk"))
}

pub(crate) fn lsblk_inverse(path: &str, columns: &str) -> Result<String> {
    Ok(crate::native_run::run(
        "lsblk",
        &[
            "--json".into(),
            "--inverse".into(),
            "--output".into(),
            columns.into(),
            path.into(),
        ],
        1024 * 1024,
        30,
    )?)
}

/// Why the countdown must stay off for the active pools adopted as `hostid`.
fn transport_gate(labels: &[Label], hostid: u32) -> Result<Option<String>> {
    for label in labels {
        if label.state != POOL_STATE_ACTIVE || label.hostid != hostid {
            continue;
        }
        let stack = lsblk_inverse(&label.path, "PATH,TYPE,TRAN")?;
        if let Some(reason) = transport_refusal(&label.path, &stack) {
            return Ok(Some(format!(
                "pool {} is not only on local NVMe/SATA disks: {reason}",
                zfs_tools::engine::escape_display(&label.name)
            )));
        }
    }
    Ok(None)
}

pub(super) fn current() -> Result<u32> {
    hostid::effective().map_err(|e| refuse(e.to_string()))
}

fn write_spl(hostid: u32) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .open(SPL_HOSTID)
        .and_then(|mut spl| spl.write_all(hostid.to_string().as_bytes()))
        .map_err(|error| refuse(format!("set SPL hostid: {error}")))
}

fn write_hostid_file(hostid: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(HOSTID_FILE)
        .map_err(|error| refuse(format!("write /etc/hostid: {error}")))?;
    file.write_all(&hostid.to_le_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn verify(hostid: u32) -> Result<()> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(HOSTID_FILE)?
        .take(5)
        .read_to_end(&mut bytes)?;
    if bytes != hostid.to_le_bytes() || current()? != hostid {
        return Err(refuse("adopted hostid did not take effect"));
    }
    Ok(())
}

/// Restore hostid 0: the Menu had none before adoption.
fn rollback() -> Result<()> {
    write_spl(0)?;
    match std::fs::remove_file(HOSTID_FILE) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(refuse(format!("remove /etc/hostid: {error}"))),
    }
    if current()? != 0 {
        return Err(refuse("hostid 0 did not take effect"));
    }
    std::fs::remove_file(ADOPTED_RECORD)
        .map_err(|error| refuse(format!("remove adoption record: {error}")))
}

/// Record the adoption first, so a partial change is always visible as one,
/// then set the identity for both the kernel and libzfs.
fn set(adoption: &Adoption, hostid: u32) -> std::result::Result<(), Failure> {
    let unchanged = |error| Failure::Unchanged(error);
    crate::handoff::prove_ram().map_err(unchanged)?;
    if std::env::var_os("ZFS_HOSTID").is_some() {
        return Err(unchanged(refuse(
            "ZFS_HOSTID overrides the system hostid; unset it before adopting",
        )));
    }
    let record =
        serde_json::to_vec(adoption).map_err(|error| unchanged(refuse(error.to_string())))?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ADOPTED_RECORD)
        .and_then(|mut file| file.write_all(&record).and_then(|()| file.sync_all()))
        .map_err(|error| unchanged(refuse(format!("record adopted hostid: {error}"))))?;
    match write_spl(hostid)
        .and_then(|()| write_hostid_file(hostid))
        .and_then(|()| verify(hostid))
    {
        Ok(()) => Ok(()),
        Err(error) => match rollback() {
            Ok(()) => Err(Failure::Unchanged(error)),
            Err(rollback) => Err(Failure::Inconsistent(refuse(format!(
                "{error}; restoring hostid 0 failed: {rollback}; no pool is imported; reboot the Menu"
            )))),
        },
    }
}

/// Add pools that appeared since the adoption (a `rescan`) to its record.
fn extend(adoption: &mut Adoption, pools: &BTreeMap<u64, String>) -> Result<()> {
    let mut guids: BTreeSet<String> = adoption.pool_guids.iter().cloned().collect();
    let mut changed = false;
    for (guid, name) in pools {
        if guids.insert(guid.to_string()) {
            adoption.pools.push(name.clone());
            changed = true;
        }
    }
    if !changed {
        return Ok(());
    }
    adoption.pool_guids = guids.into_iter().collect();
    adoption.pools = names(adoption.pools.drain(..));
    let staged = format!("{ADOPTED_RECORD}.new");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&staged)
        .and_then(|mut file| {
            file.write_all(&serde_json::to_vec(adoption)?)
                .and_then(|()| file.sync_all())
        })
        .and_then(|()| std::fs::rename(&staged, ADOPTED_RECORD))
        .map_err(|error| refuse(format!("extend the adoption record: {error}")))
}

/// The adoption in effect, if any. An unreadable record still counts as an
/// adoption, with the countdown off and no pool of its host.
pub(super) fn adopted() -> Option<Adoption> {
    let mut bytes = Vec::new();
    let read = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ADOPTED_RECORD);
    match read {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(unreadable()),
        Ok(file) => match file.take(65536).read_to_end(&mut bytes) {
            Ok(_) => Some(serde_json::from_slice(&bytes).unwrap_or_else(|_| unreadable())),
            Err(_) => Some(unreadable()),
        },
    }
}

fn unreadable() -> Adoption {
    Adoption {
        hostid: "unknown".into(),
        source: "unknown".into(),
        pools: Vec::new(),
        pool_guids: Vec::new(),
        autoboot_refusal: Some("the adoption record is unreadable".into()),
    }
}

fn report(reason: &str) {
    eprintln!("menu hostid: {}", zfs_tools::engine::escape_display(reason));
}

/// Before the Menu's read-only import: adopt when unambiguous, otherwise
/// explain, and say which pools to import.
pub(super) fn automatic() -> std::result::Result<Import, Failure> {
    let inconsistent = |error: RecoveryError| {
        Failure::Inconsistent(refuse(format!(
            "the recorded hostid adoption is not in effect ({error}); no pool is imported; reboot the Menu"
        )))
    };
    // A record left behind by a failed rollback keeps every import blocked
    // until the Menu reboots.
    if let Some(mut adoption) = adopted() {
        let hostid = hostid::parse(&adoption.hostid)
            .map_err(|e| refuse(e.to_string()))
            .and_then(|hostid| verify(hostid).map(|()| hostid))
            .map_err(inconsistent)?;
        let observation = observe().map_err(Failure::Unchanged)?;
        let pools = members(&observation.labels, hostid);
        extend(&mut adoption, &pools).map_err(Failure::Unchanged)?;
        return Ok(Import::Host(pools.into_keys().collect()));
    }
    let current = current().map_err(Failure::Unchanged)?;
    let observation = observe().map_err(Failure::Unchanged)?;
    match decide(current, &observation.labels, &observation.hazards.images) {
        Decision::NotNeeded => {
            let active = observation
                .labels
                .iter()
                .any(|label| label.state == POOL_STATE_ACTIVE);
            Ok(if current == 0 && !active {
                Import::ThenDefault(observation.labels)
            } else {
                Import::All
            })
        }
        Decision::Attended(reason) => {
            report(&reason);
            Ok(Import::All)
        }
        Decision::Adopt { hostid, pools } => {
            let autoboot_refusal = transport_gate(&observation.labels, hostid)
                .unwrap_or_else(|error| Some(format!("device transport unavailable: {error}")));
            let adoption = Adoption {
                hostid: hostid::format(hostid),
                source: "the labels of its active pools".into(),
                pools: names(pools.values().cloned()),
                pool_guids: pools.keys().map(u64::to_string).collect(),
                autoboot_refusal,
            };
            set(&adoption, hostid)?;
            Ok(Import::Host(pools.into_keys().collect()))
        }
    }
}

/// The one boot default among the imported pools.
fn default_be(state: &NativeState) -> std::result::Result<(String, u64), String> {
    let defaults = state
        .inspection
        .pools
        .iter()
        .filter_map(|pool| pool.bootfs.as_ref().map(|be| (be.clone(), pool.guid.get())))
        .collect::<Vec<_>>();
    match &defaults[..] {
        [one] => Ok(one.clone()),
        [] => Err("no imported pool has a boot default".into()),
        _ => Err("more than one imported pool has a boot default".into()),
    }
}

/// With every pool exported, the host is the default BE's: its
/// `/etc/hostid`, which must agree with its pool's labels. Pure for tests.
pub(super) fn from_default(
    labels: &[Label],
    default: std::result::Result<(String, u64), String>,
    installed: impl FnOnce(&str) -> Installed,
) -> std::result::Result<(u32, String), String> {
    let (be, pool) = default.map_err(|why| format!("{why}; no host identity is adopted"))?;
    let shown = zfs_tools::engine::escape_display(&be);
    let hostid = installed(&be)
        .require(&format!("the default BE {shown}"))
        .map_err(|error| format!("{error}; no host identity is adopted"))?;
    match hostid::recorded_in(labels, be.split('/').next().unwrap_or(&be), pool) {
        Ok(recorded) if recorded != 0 && recorded != hostid => Err(format!(
            "the default BE {shown} has /etc/hostid {} but its pool's labels record {}; no host identity is adopted",
            hostid::format(hostid),
            hostid::format(recorded)
        )),
        Ok(_) => Ok((hostid, be)),
        Err(error) => Err(format!("{error}; no host identity is adopted")),
    }
}

/// After importing every exported pool: adopt the default BE's hostid and
/// return the pools of other hosts, which the caller closes again.
pub(super) fn adopt_default(
    labels: &[Label],
    state: &NativeState,
) -> std::result::Result<Vec<String>, Failure> {
    let (hostid, be) = match from_default(labels, default_be(state), hostid::installed_in) {
        Ok(found) => found,
        Err(reason) => {
            report(&reason);
            return Ok(Vec::new());
        }
    };
    let pools = members(labels, hostid);
    let adoption = Adoption {
        hostid: hostid::format(hostid),
        source: format!("the default BE {be}"),
        pools: names(pools.values().cloned()),
        pool_guids: pools.keys().map(u64::to_string).collect(),
        autoboot_refusal: None,
    };
    set(&adoption, hostid)?;
    Ok(state
        .inspection
        .pools
        .iter()
        .filter(|pool| !pools.contains_key(&pool.guid.get()))
        .map(|pool| pool.name.to_string())
        .collect())
}

/// An adopted handoff identity and its host pool GUIDs. Without adoption,
/// the target initrd handles a portable pool without an injected hostid.
pub(crate) fn binding() -> Result<(Option<u32>, Option<BTreeSet<String>>)> {
    match adopted() {
        None => Ok((None, None)),
        Some(adoption) => {
            let hostid = hostid::parse(&adoption.hostid).map_err(|e| refuse(e.to_string()))?;
            verify(hostid)?;
            Ok((
                Some(hostid),
                Some(adoption.pool_guids.into_iter().collect()),
            ))
        }
    }
}

fn observe_hazards() -> Result<Hazards> {
    Ok(hazards(&device::observe_landscape()?.blockdevices))
}

/// Refuse a write while a hibernation image is present: resuming it later
/// would damage every pool written since. Checked before every explicit
/// writable action: Menu actions, restore and deploy.
pub(crate) fn require_no_image() -> Result<()> {
    require_none(&observe_hazards()?)
}

pub(super) fn require_none(hazards: &Hazards) -> Result<()> {
    if hazards.images.is_empty() {
        return Ok(());
    }
    Err(refuse(format!(
        "a hibernation image is on {}; resuming it after a pool write would damage the pool; resolve it from the shell (resume it, or mkswap the device), then rescan",
        listing(&hazards.images)
    )))
}

/// Why the countdown must stay off now, rechecked when it would start.
pub(crate) fn countdown_refusal() -> Option<String> {
    let hazards = match observe_hazards() {
        Ok(hazards) => hazards,
        Err(error) => return Some(format!("the devices are unreadable: {error}")),
    };
    countdown_refusal_with(&hazards, adopted().as_ref())
}

pub(super) fn countdown_refusal_with(
    hazards: &Hazards,
    adoption: Option<&Adoption>,
) -> Option<String> {
    if !hazards.images.is_empty() {
        return Some(format!(
            "a hibernation image is on {}",
            listing(&hazards.images)
        ));
    }
    if !hazards.unexamined.is_empty() {
        return Some(format!(
            "{} could hide a hibernation image",
            listing(&hazards.unexamined)
        ));
    }
    adoption.and_then(|adoption| adoption.autoboot_refusal.clone())
}

/// Menu banner lines for the adoption in effect.
pub(super) fn banner(adoption: &Adoption) -> Vec<String> {
    vec![format!(
        "Hostid {} adopted from {}; pools {} (ordinary import, never forced).",
        zfs_tools::engine::escape_display(&adoption.hostid),
        zfs_tools::engine::escape_display(&adoption.source),
        listing(&adoption.pools)
    )]
}

/// A BE whose `/etc/hostid` disagrees with the hostid the Menu boots it with
/// is diagnosed, never rewritten: `spl.spl_hostid` decides, and the verbs that
/// write a BE (deploy, restore) keep the file consistent.
pub(crate) fn disagreement(be: &str, installed: &Installed, booted: u32) -> Option<String> {
    if booted == 0 || *installed == Installed::Hostid(booted) {
        return None;
    }
    let file = match installed {
        Installed::Hostid(found) => format!("/etc/hostid {}", hostid::format(*found)),
        Installed::Missing => "no /etc/hostid".into(),
        Installed::Zero => "a zero /etc/hostid".into(),
        Installed::Malformed => "a malformed /etc/hostid".into(),
        Installed::Unreadable(why) => format!("an unreadable /etc/hostid ({why})"),
    };
    Some(format!(
        "note: {} has {file}; it boots with hostid {} (spl.spl_hostid), the one its pools record",
        zfs_tools::engine::escape_display(be),
        hostid::format(booted)
    ))
}

/// The banner line for an off countdown.
pub(super) fn countdown_line(reason: &str) -> String {
    format!(
        "Automatic boot is off: {}. Select N to boot.",
        zfs_tools::engine::escape_display(reason)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(name: &str, guid: u64, state: u64, hostid: u32) -> Label {
        Label {
            path: format!("/dev/{name}"),
            name: name.into(),
            pool_guid: guid,
            vdev_guid: None,
            state,
            hostid,
        }
    }

    fn pools(list: &[(u64, &str)]) -> BTreeMap<u64, String> {
        list.iter().map(|(g, n)| (*g, n.to_string())).collect()
    }

    #[test]
    fn unique_active_hostid_is_adopted_with_its_hosts_pools_only() {
        let labels = [
            label("rpool", 1, 0, 0x0174627a),
            label("spool", 2, 0, 0x0174627a),
            label("spool", 2, 0, 0x0174627a),
            label("ours", 5, 1, 0x0174627a),
            label("moved", 3, 1, 0x11111111),
            label("exported", 4, 1, 0),
        ];
        // The other host's exported pool is not mixed in; an exported pool
        // recording no hostid belongs to no other host.
        assert_eq!(
            decide(0, &labels, &[]),
            Decision::Adopt {
                hostid: 0x0174627a,
                pools: pools(&[(1, "rpool"), (2, "spool"), (4, "exported"), (5, "ours")]),
            }
        );
    }

    #[test]
    fn a_pool_whose_labels_mix_hosts_is_not_the_hosts() {
        let labels = [
            label("a", 1, 1, 7),
            label("a", 1, 1, 8),
            label("b", 2, 1, 7),
        ];
        assert_eq!(members(&labels, 7), pools(&[(2, "b")]));
        // An active pool recording no hostid never joins an adopted host.
        assert_eq!(members(&[label("c", 3, 0, 0)], 7), pools(&[]));
    }

    #[test]
    fn nothing_to_adopt_when_pools_are_exported_anonymous_or_already_ours() {
        let labels = [
            label("a", 1, 1, 7),
            label("b", 2, 0, 0),
            label("c", 3, 0, 9),
        ];
        assert_eq!(decide(9, &labels, &[]), Decision::NotNeeded);
        assert_eq!(decide(0, &labels[..2], &[]), Decision::NotNeeded);
    }

    #[test]
    fn conflicts_hibernation_bound_identity_and_hidden_pools_need_an_operator() {
        let two = [label("a", 1, 0, 7), label("b", 2, 0, 8)];
        assert!(
            matches!(decide(0, &two, &[]), Decision::Attended(text) if text.contains("00000007 (a); 00000008 (b)"))
        );
        let one = [label("a", 1, 0, 7)];
        assert!(matches!(
            decide(0, &one, &["/dev/sda3".into()]),
            Decision::Attended(text) if text.contains("hibernation")
        ));
        assert!(
            matches!(decide(5, &one, &[]), Decision::Attended(text) if text.contains("has hostid 00000005"))
        );
        let hiding = [label("a", 1, 0, 7), label("anon", 2, 0, 0)];
        assert!(
            matches!(decide(0, &hiding, &[]), Decision::Attended(text) if text.contains("no hostid: anon"))
        );
    }

    #[test]
    fn with_every_pool_exported_the_default_bes_hostid_is_the_hosts() {
        let labels = [label("rpool", 1, 1, 0x0174627a), label("other", 2, 1, 9)];
        let default = || Ok(("rpool/ROOT/be".to_string(), 1));
        let found = |value| {
            move |be: &str| {
                assert_eq!(be, "rpool/ROOT/be");
                value
            }
        };
        assert_eq!(
            from_default(&labels, default(), found(Installed::Hostid(0x0174627a))),
            Ok((0x0174627a, "rpool/ROOT/be".into()))
        );
        // A pool recording no hostid takes the file's.
        let anonymous = [label("rpool", 1, 1, 0)];
        assert_eq!(
            from_default(&anonymous, default(), found(Installed::Hostid(5))),
            Ok((5, "rpool/ROOT/be".into()))
        );
        // Missing, zero, malformed, unreadable and conflicting files are
        // reported, never replaced by an invented identity.
        for (installed, text) in [
            (Installed::Missing, "has no /etc/hostid"),
            (Installed::Zero, "zero /etc/hostid"),
            (Installed::Malformed, "malformed /etc/hostid"),
            (Installed::Unreadable("no key".into()), "unreadable: no key"),
            (Installed::Hostid(5), "its pool's labels record 0174627a"),
        ] {
            let error = from_default(&labels, default(), found(installed)).unwrap_err();
            assert!(
                error.contains(text) && error.ends_with("no host identity is adopted"),
                "{error}"
            );
        }
        let error = from_default(
            &labels,
            Err("no imported pool has a boot default".into()),
            |_| unreachable!("no BE is read without one default"),
        )
        .unwrap_err();
        assert!(
            error.starts_with("no imported pool has a boot default"),
            "{error}"
        );
    }

    #[test]
    fn hibernation_hazards_include_swapfile_filesystems_and_opaque_volumes() {
        let block = |path: &str, fstype: Option<&str>, children: Vec<Block>| Block {
            path: path.into(),
            device_number: "8:0".into(),
            kind: "part".into(),
            size: 1,
            logical_sector: 512,
            physical_sector: 512,
            ro: false,
            serial: None,
            wwn: None,
            model: None,
            fstype: fstype.map(str::to_owned),
            label: None,
            uuid: None,
            partuuid: None,
            parttype: None,
            ptuuid: None,
            mountpoints: Vec::new(),
            children,
        };
        let rows = [block(
            "/dev/sda",
            None,
            vec![
                block("/dev/sda1", Some("vfat"), vec![]),
                block("/dev/sda2", Some("swap"), vec![]),
                block("/dev/sda3", Some("swsuspend"), vec![]),
                block("/dev/sda4", Some("zfs_member"), vec![]),
                block("/dev/sda5", Some("ext4"), vec![]),
                block(
                    "/dev/sda6",
                    Some("crypto_LUKS"),
                    vec![block("/dev/dm-0", Some("xfs"), vec![])],
                ),
            ],
        )];
        let found = hazards(&rows);
        assert_eq!(found.images, ["/dev/sda3"]);
        assert_eq!(found.unexamined, ["/dev/sda5", "/dev/sda6", "/dev/dm-0"]);
        let error = require_none(&found).unwrap_err().to_string();
        assert!(
            error.contains("hibernation image is on /dev/sda3"),
            "{error}"
        );
        require_none(&Hazards {
            unexamined: found.unexamined.clone(),
            ..Hazards::default()
        })
        .unwrap();
    }

    #[test]
    fn the_countdown_needs_no_hazard_and_an_adoption_that_permits_it() {
        let adoption = Adoption {
            hostid: "0174627a".into(),
            source: "the labels of its active pools".into(),
            pools: vec!["rpool".into()],
            pool_guids: vec!["1".into()],
            autoboot_refusal: None,
        };
        let none = Hazards::default();
        assert_eq!(countdown_refusal_with(&none, None), None);
        assert_eq!(countdown_refusal_with(&none, Some(&adoption)), None);
        let image = Hazards {
            images: vec!["/dev/sda3".into()],
            ..Hazards::default()
        };
        assert!(
            countdown_refusal_with(&image, None)
                .unwrap()
                .contains("/dev/sda3")
        );
        let unseen = Hazards {
            unexamined: vec!["/dev/sda5".into()],
            ..Hazards::default()
        };
        assert!(
            countdown_refusal_with(&unseen, None)
                .unwrap()
                .contains("/dev/sda5 could hide")
        );
        let remote = Adoption {
            autoboot_refusal: Some("pool rpool is on a usb disk".into()),
            ..adoption
        };
        assert_eq!(
            countdown_refusal_with(&none, Some(&remote)).as_deref(),
            Some("pool rpool is on a usb disk")
        );
    }

    #[test]
    fn countdown_needs_members_directly_on_local_nvme_or_sata() {
        let nvme = r#"{"blockdevices":[{"path":"/dev/nvme3n1p1","type":"part","tran":"nvme","children":[{"path":"/dev/nvme3n1","type":"disk","tran":"nvme"}]}]}"#;
        assert_eq!(transport_refusal("/dev/nvme3n1p1", nvme), None);
        let sata = nvme.replace("\"nvme\"", "\"sata\"");
        assert_eq!(transport_refusal("p", &sata), None);
        for (tran, expected) in [
            ("usb", "usb disk"),
            ("iscsi", "iscsi disk"),
            ("", "unknown disk"),
        ] {
            let other = nvme.replace(
                r#""type":"disk","tran":"nvme""#,
                &format!(r#""type":"disk","tran":"{tran}""#),
            );
            assert!(
                transport_refusal("p", &other).unwrap().contains(expected),
                "{tran}"
            );
        }
        let virtio = r#"{"blockdevices":[{"path":"/dev/vda1","type":"part","tran":null,"children":[{"path":"/dev/vda","type":"disk","tran":null}]}]}"#;
        assert!(
            transport_refusal("/dev/vda1", virtio)
                .unwrap()
                .contains("unknown disk")
        );
        let mpath = r#"{"blockdevices":[{"path":"/dev/dm-0","type":"mpath","tran":null,"children":[{"path":"/dev/sda","type":"disk","tran":"sas"}]}]}"#;
        assert!(
            transport_refusal("/dev/dm-0", mpath)
                .unwrap()
                .contains("mpath device")
        );
        assert!(transport_refusal("p", "not json").is_some());
        let none = r#"{"blockdevices":[{"path":"/dev/x","type":"part","tran":null}]}"#;
        assert!(
            transport_refusal("p", none)
                .unwrap()
                .contains("no single backing disk")
        );
    }

    #[test]
    fn a_be_hostid_that_differs_from_the_booted_one_is_diagnosed() {
        let booted = 0x0174627a;
        assert_eq!(
            disagreement("p/ROOT/be", &Installed::Hostid(booted), booted),
            None
        );
        assert_eq!(disagreement("p/ROOT/be", &Installed::Missing, 0), None);
        let other = disagreement("p/ROOT/be", &Installed::Hostid(7), booted).unwrap();
        assert!(
            other.contains("has /etc/hostid 00000007; it boots with hostid 0174627a"),
            "{other}"
        );
        for (installed, shown) in [
            (Installed::Missing, "no /etc/hostid"),
            (Installed::Zero, "a zero /etc/hostid"),
            (Installed::Malformed, "a malformed /etc/hostid"),
            (
                Installed::Unreadable("EIO".into()),
                "an unreadable /etc/hostid (EIO)",
            ),
        ] {
            let note = disagreement("p/ROOT/be", &installed, booted).unwrap();
            assert!(note.contains(shown), "{note}");
        }
    }

    #[test]
    fn banner_names_the_identity_its_source_and_pools() {
        let adoption = Adoption {
            hostid: "0174627a".into(),
            source: "the default BE rpool/ROOT/be".into(),
            pools: vec!["rpool".into(), "spool".into()],
            pool_guids: vec!["1".into(), "2".into()],
            autoboot_refusal: None,
        };
        assert_eq!(
            banner(&adoption),
            [
                "Hostid 0174627a adopted from the default BE rpool/ROOT/be; pools rpool, spool (ordinary import, never forced)."
            ]
        );
        assert!(countdown_line("x").starts_with("Automatic boot is off: x"));
    }
}
