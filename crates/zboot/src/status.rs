//! Read-only presentation of imported native state. Displayed properties are
//! observations, never proof that a relationship is safe to mutate.
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    io,
    path::{Path, PathBuf},
};
use zfs_tools::engine::{
    Inspection, escape_display as esc,
    mountinfo::{self, Mount},
    pool_of,
};

/// The menu's displayed BE numbers, each attached to the exact native
/// dataset incarnation it showed.
#[derive(Debug, Clone, Default)]
pub(crate) struct Numbering {
    pub(crate) boot: BTreeMap<String, (String, zfs_tools::engine::DatasetIdentity)>,
}

impl Numbering {
    fn prefix(&self, name: &str, identity: &zfs_tools::engine::DatasetIdentity) -> String {
        self.boot
            .get(name)
            .filter(|(_, shown)| shown == identity)
            .map_or_else(String::new, |(label, _)| format!("{}: ", esc(label)))
    }
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub schema_version: u32,
    pub inventory: Inspection,
    pub running_root: Option<String>,
    pub properties: Option<zfs_tools::engine::native::PropertyInventory>,
    pub devices: Option<serde_json::Value>,
    pub relationships: BTreeMap<String, Relationship>,
    pub operations: crate::restore::Listing,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esps: Option<Vec<Esp>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disks: Option<Vec<crate::device::Candidate>>,
    pub boot_environments: Vec<String>,
    pub kernels: BTreeMap<String, KernelInventory>,
    pub attention: Vec<String>,
    /// Space limits a pair's copy does not hold as its working copy sets
    /// them; each is also in `attention`.
    pub space_differences: Vec<crate::transfer::props::SpaceDifference>,
    /// Datasets below a boot environment or a paired leaf; each parent is
    /// also in `attention`.
    pub child_datasets: Vec<Children>,
    /// Boot environments `boot_environment::admit` refuses; each one's
    /// reason is in `attention`.
    #[serde(skip)]
    blocked: BTreeSet<String>,
}

/// The datasets below one boot environment or paired leaf, which fork, pair
/// and `primary` refuse and a sync does not copy (docs/DESIGN.md, "Pairs").
#[derive(Debug, Serialize)]
pub struct Children {
    /// The boot environment or paired leaf.
    pub parent: String,
    pub boot_environment: bool,
    /// The parent's pair peer, when it is a pair root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paired_with: Option<String>,
    pub children: Vec<String>,
}
impl Children {
    /// The attention item: what the children are under and what that means.
    fn attention(&self) -> String {
        let one = self.children.len() == 1;
        let what = match (self.boot_environment, self.paired_with.is_some()) {
            (true, false) => "boot environment",
            (true, true) => "paired boot environment",
            _ => "paired dataset",
        };
        let them = if one { "it" } else { "them" };
        let meaning = match (self.boot_environment, self.paired_with.is_some()) {
            (true, false) => "fork and pair refuse a boot environment with children".into(),
            (true, true) => format!(
                "fork refuses a boot environment with children, a sync does not copy {them}, \
                 and a primary switch refuses while either side has one"
            ),
            _ => format!(
                "a sync does not copy {them}, and a primary switch refuses while either side has one"
            ),
        };
        format!(
            "{what} {} has {} {}: {meaning}",
            self.parent,
            if one {
                "child dataset"
            } else {
                "child datasets"
            },
            self.children.join(", ")
        )
    }
}

#[derive(Debug, Serialize)]
pub struct Esp {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<crate::device::PartitionIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub loaders: Vec<crate::esp::Loader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Kernel {
    /// The version accepted by `boot --kernel NAME`.
    pub name: String,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub default: bool,
}
#[derive(Debug, Default, Serialize)]
pub struct KernelInventory {
    pub kernels: Vec<Kernel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The shipped loader: `../lib/zboot/zboot.efi` from the running zboot's
/// directory, `/usr/lib/zboot/zboot.efi` when installed.
pub fn shipped_efi() -> io::Result<PathBuf> {
    shipped_efi_at(&std::env::current_exe()?)
}
fn shipped_efi_at(executable: &Path) -> io::Result<PathBuf> {
    let path = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("the running executable has no parent directory"))?
        .join("lib/zboot/zboot.efi");
    match std::fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(path),
        Ok(_) => Err(io::Error::other(format!(
            "{} is not a regular EFI file",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no shipped zboot.efi at {}", path.display()),
        )),
        Err(error) => Err(error),
    }
}

/// The mount-free portion of status is made from complete native state. Only
/// explicit dataset selection requests BE kernel views; only devices requests
/// the existing read-only ESP inspection path.
pub fn observe(
    datasets: Vec<String>,
    snapshots: bool,
    devices: bool,
) -> Result<Status, Box<dyn std::error::Error>> {
    let state = zfs_tools::engine::state::observe()?;
    let running = running_root()?;
    let operations = crate::restore::list(&mut crate::restore::Native::new())?;
    let relationships = relationships(&state);
    let mut status = from_state(
        &state,
        datasets,
        snapshots,
        running,
        operations,
        relationships,
    )?;
    add_kernels(&mut status, inspect_kernels);
    if devices {
        let args = ["--json", "--bytes", "--output", DEVICE_COLUMNS].map(String::from);
        let blocks: serde_json::Value =
            serde_json::from_str(&zfs_tools::engine::native::run("lsblk", &args)?)?;
        let shipped = shipped_efi().and_then(|path| {
            let mut file = std::fs::File::open(path)?;
            let (sha256, bytes) = crate::loader::hash(&mut file)?;
            Ok(crate::esp::FileIdentity { sha256, bytes })
        });
        let esps = esp_paths(&blocks)
            .into_iter()
            .map(|path| {
                let comparison_error = shipped.as_ref().err().map(ToString::to_string);
                match crate::esp::inspect_loaders(&path, shipped.as_ref().ok()) {
                    Ok(found) => Esp {
                        path,
                        target: Some(found.target),
                        loaders: found.loaders,
                        error: None,
                        comparison_error,
                    },
                    Err(error) => Esp {
                        path,
                        target: None,
                        loaders: vec![],
                        error: Some(error.to_string()),
                        comparison_error,
                    },
                }
            })
            .collect::<Vec<_>>();
        status.attention.extend(loader_attention(&esps));
        status.esps = Some(esps);
        status.disks = Some(crate::device::candidates()?);
        status.devices = Some(blocks);
    }
    Ok(status)
}

fn from_state(
    state: &zfs_tools::engine::state::NativeState,
    datasets: Vec<String>,
    snapshots: bool,
    running_root: Option<String>,
    mut operations: crate::restore::Listing,
    mut relationships: BTreeMap<String, Relationship>,
) -> Result<Status, Box<dyn std::error::Error>> {
    let selected = |name: &str| {
        datasets.is_empty()
            || datasets
                .iter()
                .any(|root| crate::history::contains_dataset(root, name))
    };
    let intersects = |name: &str| {
        selected(name)
            || datasets
                .iter()
                .any(|root| crate::history::contains_dataset(name, root))
    };
    let inventory = state
        .inspection
        .select(&zfs_tools::engine::InspectRequest::new(
            datasets.clone(),
            snapshots,
        )?)?;
    relationships.retain(|name, _| intersects(name));
    let boot_environments: Vec<String> = crate::boot_environment::roots(state)
        .into_iter()
        .filter(|dataset| selected(&dataset.name))
        .map(|dataset| dataset.name.clone())
        .collect();
    let boot_refusals: BTreeMap<_, _> = boot_environments
        .iter()
        .filter_map(|name| {
            crate::boot_environment::admit(state, name)
                .err()
                .map(|error| (name.clone(), error.to_string()))
        })
        .collect();
    // A pool's one operation record excludes other writers on that pool, so
    // it remains relevant even when the selected tree is not its data target.
    let pools: BTreeSet<_> = inventory
        .pools
        .iter()
        .map(|pool| pool.name.clone())
        .collect();
    operations
        .operations
        .retain(|operation| pools.contains(operation.pool.as_str()));
    operations
        .orphans
        .retain(|orphan| intersects(&orphan.dataset));
    let properties = if datasets.is_empty() {
        None
    } else {
        let properties = state
            .dataset_properties
            .iter()
            .filter(|(name, _)| selected(name))
            .map(|(name, values)| (name.clone(), values.clone()))
            .collect();
        validate_properties(&inventory, &properties)?;
        Some(properties)
    };
    let mut attention: Vec<_> = boot_refusals
        .iter()
        .map(|(name, reason)| format!("{name}: boot candidate blocked: {reason}"))
        .collect();
    let defaults: Vec<_> = state
        .inspection
        .pools
        .iter()
        .filter_map(|pool| pool.bootfs.as_deref())
        .collect();
    if defaults.len() > 1 && defaults.iter().any(|name| intersects(name)) {
        attention.push(format!(
            "more than one boot default: {}",
            defaults.join(", ")
        ));
    }
    attention.extend(
        crate::mounting::owned_automounts(state)
            .into_iter()
            .filter(|(_, name)| selected(name))
            .map(|(root, name)| {
                if root == name {
                    format!("boot environment {root} has canmount=on")
                } else {
                    format!("{name} has canmount=on inside boot environment {root}")
                }
            }),
    );
    let child_datasets = children(state, &relationships, &selected);
    attention.extend(child_datasets.iter().map(Children::attention));
    attention.extend(
        stale_anchors(state)
            .into_iter()
            .filter(|(owner, _)| selected(owner))
            .map(|(_, item)| item),
    );
    let mut seen = BTreeSet::new();
    for (name, relation) in &relationships {
        let peer = relation.peer.as_deref().unwrap_or("?");
        let key = pair_key(name, peer);
        if !seen.insert(key) {
            continue;
        }
        if relation.peer.as_ref().is_some_and(|peer| {
            !state
                .inspection
                .datasets
                .iter()
                .any(|dataset| &dataset.name == peer)
        }) {
            attention.push(format!("{name}: pair peer {peer} is gone"));
        } else if !relation.blockers.is_empty() {
            attention.push(format!("{name}: {}", relation.blockers.join("; ")));
        } else if !matches!(pair_progress(relation), "level" | "snapshots level") {
            attention.push(format!(
                "{}: {}",
                pair_direction(name, relation),
                pair_progress(relation)
            ));
        }
        if !relation.clones.is_empty() {
            attention.push(format!(
                "{}: the working copy has clones ({}); syncs go on, but `primary` refuses \
                 until they are dropped",
                pair_direction(name, relation),
                relation.clones.join(", ")
            ));
        }
        if !relation.pending_deletions.is_empty() {
            let copy = if relation.role == Some(zfs_tools::engine::management::Role::Secondary) {
                name.as_str()
            } else {
                peer
            };
            let count = relation.pending_deletions.len();
            attention.push(format!(
                "{}: {count} {} only on {copy} {} review for deletion (the working copy no \
                 longer has {}); review with {}",
                pair_direction(name, relation),
                if count == 1 { "snapshot" } else { "snapshots" },
                if count == 1 { "awaits" } else { "await" },
                if count == 1 { "it" } else { "them" },
                crate::pairs::prune::review_command(copy)
            ));
        }
    }
    let space_differences: Vec<_> = pair_space(state)
        .into_iter()
        .filter(|d| intersects(&d.working_copy) || intersects(&d.copy))
        .collect();
    attention.extend(space_differences.iter().map(|d| {
        format!(
            "{} -> {}: {}; {}",
            d.working_copy,
            d.copy,
            d.describe(),
            d.outcome()
        )
    }));
    Ok(Status {
        schema_version: 1,
        inventory,
        running_root,
        properties,
        devices: None,
        relationships,
        operations,
        esps: None,
        disks: None,
        boot_environments,
        blocked: boot_refusals.keys().cloned().collect(),
        kernels: if datasets.is_empty() {
            BTreeMap::new()
        } else {
            // Explicit selection may inspect assets, but a role/identity
            // refusal must never be bypassed by mounting that candidate.
            boot_refusals
                .into_iter()
                .map(|(name, error)| {
                    (
                        name,
                        KernelInventory {
                            kernels: vec![],
                            error: Some(error),
                        },
                    )
                })
                .collect()
        },
        attention,
        space_differences,
        child_datasets,
    })
}

/// Every mutual pair's space differences, from its working copy to its
/// fenced one: the transfer's own rule (`transfer::props::unheld_space`).
fn pair_space(
    state: &zfs_tools::engine::state::NativeState,
) -> Vec<crate::transfer::props::SpaceDifference> {
    crate::pairs::pair_roots(state)
        .iter()
        .filter_map(|name| crate::pairs::local_record(state, name).ok().flatten())
        .filter(|record| {
            record.role == zfs_tools::engine::management::Role::Primary
                && crate::pairs::peer_status(state, record) == crate::pairs::PeerStatus::Mutual
        })
        .filter_map(|record| {
            crate::transfer::props::space_differences(
                state,
                &record.endpoint.name,
                &record.peer.name,
            )
        })
        .flatten()
        .collect()
}

/// The selected datasets below each boot environment and each paired leaf,
/// whatever their `canmount`. A dataset below two such parents (a paired
/// boot environment counts once) is listed with each, naming it.
fn children(
    state: &zfs_tools::engine::state::NativeState,
    relationships: &BTreeMap<String, Relationship>,
    selected: &impl Fn(&str) -> bool,
) -> Vec<Children> {
    let roots: BTreeSet<&str> = crate::mounting::boot_environment_roots(state)
        .into_iter()
        .collect();
    let parents: BTreeSet<&str> = roots
        .iter()
        .copied()
        .chain(relationships.keys().map(String::as_str))
        .collect();
    parents
        .into_iter()
        .filter_map(|parent| {
            let children: Vec<String> = state
                .inspection
                .datasets
                .iter()
                .filter(|d| {
                    d.name != parent
                        && crate::history::contains_dataset(parent, &d.name)
                        && selected(&d.name)
                })
                .map(|d| d.name.clone())
                .collect();
            (!children.is_empty()).then(|| Children {
                parent: parent.into(),
                boot_environment: roots.contains(parent),
                paired_with: relationships
                    .get(parent)
                    .map(|r| r.peer.clone().unwrap_or_else(|| "?".into())),
                children,
            })
        })
        .collect()
}

fn requested_kernel_roots(status: &Status) -> Vec<String> {
    if status.inventory.requested_datasets.is_empty() {
        vec![]
    } else {
        status.boot_environments.clone()
    }
}
fn add_kernels(status: &mut Status, mut inspect: impl FnMut(&str) -> KernelInventory) {
    for name in requested_kernel_roots(status) {
        if !status.kernels.contains_key(&name) {
            status.kernels.insert(name.clone(), inspect(&name));
        }
    }
}
fn kernel_inventory_at(root: &Path) -> io::Result<Vec<Kernel>> {
    crate::menu::inventory::kernel_choices(root)
        .map_err(io::Error::other)
        .map(|choices| {
            choices
                .into_iter()
                .map(|choice| {
                    let filename = choice
                        .kernel
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let name = filename
                        .strip_prefix("vmlinuz-")
                        .unwrap_or(&filename)
                        .to_owned();
                    Kernel {
                        name,
                        kernel: choice.kernel,
                        initrd: choice.initrd,
                        default: choice.default,
                    }
                })
                .collect()
        })
}
fn inspect_kernels(dataset: &str) -> KernelInventory {
    match crate::hostid::readonly_view(dataset, kernel_inventory_at) {
        Ok(kernels) => KernelInventory {
            kernels,
            error: None,
        },
        Err(error) => KernelInventory {
            kernels: vec![],
            error: Some(error.to_string()),
        },
    }
}

fn loader_attention(esps: &[Esp]) -> Vec<String> {
    esps.iter()
        .flat_map(|esp| {
            esp.loaders.iter().filter_map(|loader| {
                if loader.stale {
                    Some(crate::esp::stale_note(&esp.path, &loader.path))
                } else {
                    (loader.owner == Some(crate::esp::LoaderOwner::Zboot)
                        && loader.matches_installed == Some(false))
                    .then(|| {
                        format!(
                            "ESP {} loader {} differs from installed zboot.efi",
                            esp.path, loader.path
                        )
                    })
                }
            })
        })
        .collect()
}
fn pair_key(name: &str, peer: &str) -> (String, String) {
    if name < peer {
        (name.into(), peer.into())
    } else {
        (peer.into(), name.into())
    }
}
fn pair_direction(name: &str, relation: &Relationship) -> String {
    let peer = relation.peer.as_deref().unwrap_or("?");
    if relation.role == Some(zfs_tools::engine::management::Role::Secondary) {
        format!("{peer} -> {name}")
    } else {
        format!("{name} -> {peer}")
    }
}
fn pair_progress(relation: &Relationship) -> &'static str {
    if !relation.blockers.is_empty() {
        return "diverged or unavailable";
    }
    match (relation.role, relation.history.as_deref()) {
        (_, Some("equal")) => "level",
        // The copy has every snapshot; only the working copy's unsnapshotted
        // changes (always there on a running system) are not on it yet.
        (Some(zfs_tools::engine::management::Role::Primary), Some("local ahead"))
        | (Some(zfs_tools::engine::management::Role::Secondary), Some("peer ahead"))
            if relation.snapshots_level =>
        {
            "snapshots level"
        }
        (Some(zfs_tools::engine::management::Role::Primary), Some("local ahead"))
        | (Some(zfs_tools::engine::management::Role::Secondary), Some("peer ahead")) => {
            "secondary behind"
        }
        (_, Some("local ahead" | "peer ahead")) => "diverged (secondary ahead)",
        _ => "history unavailable",
    }
}
/// A boot environment's pair role and progress, from its own side:
/// `primary of B, B behind`, `secondary of A, behind`, `... level`.
fn pair_annotation(relation: &Relationship) -> Vec<String> {
    use zfs_tools::engine::management::Role;
    let peer = esc(relation.peer.as_deref().unwrap_or("?"));
    let progress = match (relation.role, pair_progress(relation)) {
        (Some(Role::Primary), "secondary behind") => format!("{peer} behind"),
        (Some(Role::Secondary), "secondary behind") => "behind".into(),
        (_, progress) => progress.into(),
    };
    match relation.role {
        Some(Role::Primary) => vec![format!("primary of {peer}"), progress],
        Some(Role::Secondary) => vec![format!("secondary of {peer}"), progress],
        None => vec![progress],
    }
}

impl Status {
    #[cfg(test)]
    pub fn render_short(&self) -> String {
        self.render_short_numbered(None)
    }

    pub(crate) fn render_short_numbered(&self, numbers: Option<&Numbering>) -> String {
        let mut out = String::new();
        if !self.boot_environments.is_empty() {
            out.push_str("Boot environments\n");
            for name in &self.boot_environments {
                let dataset = self
                    .inventory
                    .datasets
                    .iter()
                    .find(|dataset| &dataset.name == name)
                    .unwrap();
                let mut annotations = Vec::new();
                if self.running_root.as_ref() == Some(name) {
                    annotations.push("running".into());
                }
                if self
                    .inventory
                    .pools
                    .iter()
                    .any(|pool| pool.bootfs.as_ref() == Some(name))
                {
                    annotations.push("default".into());
                }
                if let Some(relation) = self.relationships.get(name) {
                    annotations.extend(pair_annotation(relation));
                }
                if let Some(origin) = &dataset.origin {
                    annotations.push(format!("clone of {}", esc(origin)));
                }
                annotations.push(self.kernel_evidence(name).into());
                let label = numbers.map_or_else(String::new, |numbers| {
                    numbers.prefix(name, &dataset.identity)
                });
                let _ = writeln!(out, "  {}{}  {}", label, esc(name), annotations.join(", "));
            }
        }
        let mut pairs = Vec::new();
        let mut seen = BTreeSet::new();
        for (name, relation) in &self.relationships {
            let peer = relation.peer.as_deref().unwrap_or("?");
            if self
                .boot_environments
                .iter()
                .any(|be| name == be || peer == be)
            {
                continue;
            }
            if seen.insert(pair_key(name, peer)) {
                pairs.push(format!(
                    "  {}  {}",
                    esc(&pair_direction(name, relation)),
                    pair_progress(relation)
                ));
            }
        }
        if !pairs.is_empty() {
            out.push_str("Pairs\n");
            for pair in pairs {
                let _ = writeln!(out, "{pair}");
            }
        }
        if !self.operations.operations.is_empty() || !self.operations.orphans.is_empty() {
            out.push_str("Interrupted\n");
            for operation in &self.operations.operations {
                let id = operation.id.as_deref().unwrap_or("unreadable");
                let next = if operation.id.is_some() {
                    format!("zboot resume {id}")
                } else {
                    "inspect the unreadable operation record".into()
                };
                let _ = writeln!(
                    out,
                    "  {} {} on {} after step {}  {}",
                    esc(operation.kind.as_deref().unwrap_or("unknown")),
                    esc(id),
                    esc(&operation.pool),
                    esc(operation.step.as_deref().unwrap_or("?")),
                    esc(&next)
                );
            }
            for orphan in &self.operations.orphans {
                let _ = writeln!(out, "  {}", esc(&orphan.describe()));
            }
        }
        self.render_attention(&mut out);
        if out.is_empty() {
            out.push_str(
                "No boot environments, pairs, interrupted operations or attention items.\n",
            );
        }
        // Explicit detail requests may extend the short four-block summary.
        self.render_devices(&mut out);
        self.render_kernels(&mut out);
        out
    }
    fn kernel_evidence(&self, name: &str) -> &'static str {
        if self.blocked.contains(name) {
            return "boot blocked (see Attention)";
        }
        match self.kernels.get(name) {
            Some(inventory) if inventory.error.is_some() => {
                "candidate, kernel inspection unavailable"
            }
            Some(inventory) if !inventory.kernels.is_empty() => "kernel pairs verified",
            _ => "candidate, kernels unprobed",
        }
    }

    fn render_attention(&self, out: &mut String) {
        if !self.attention.is_empty() {
            out.push_str("Attention\n");
            for attention in &self.attention {
                let _ = writeln!(out, "  {}", esc(attention));
            }
        }
    }
    fn render_kernels(&self, out: &mut String) {
        for (dataset, inventory) in &self.kernels {
            let _ = writeln!(out, "Kernels for {}", esc(dataset));
            for kernel in &inventory.kernels {
                let _ = writeln!(
                    out,
                    "  {}  {} + {}{}",
                    esc(&kernel.name),
                    esc(&kernel.kernel.to_string_lossy()),
                    esc(&kernel.initrd.to_string_lossy()),
                    if kernel.default { "  default" } else { "" }
                );
            }
            if let Some(error) = &inventory.error {
                let _ = writeln!(out, "  unavailable: {}", esc(error));
            }
        }
    }
    fn render_devices(&self, out: &mut String) {
        if let Some(disks) = &self.disks {
            out.push_str("Disks\n");
            for disk in disks {
                let _ = writeln!(
                    out,
                    "  {}  {}  model {}  serial {}  {}",
                    esc(&disk.path),
                    crate::device::size(disk.bytes),
                    esc(disk.model.as_deref().unwrap_or("-")),
                    esc(disk.serial.as_deref().unwrap_or("-")),
                    esc(disk
                        .method
                        .as_deref()
                        .or(disk.refused.as_deref())
                        .unwrap_or("erase method unavailable"))
                );
            }
        }
        if let Some(devices) = &self.devices {
            for block in blocks(devices) {
                let uses: Vec<_> = block["mountpoints"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .collect();
                if !uses.is_empty() {
                    let _ = writeln!(
                        out,
                        "  {} mounted at {}",
                        esc(text(block, "path").unwrap_or("?")),
                        esc(&uses.join(", "))
                    );
                }
            }
        }
        for esp in self.esps.iter().flatten() {
            let _ = writeln!(out, "ESP {}", esc(&esp.path));
            for loader in &esp.loaders {
                let owner = match loader.owner {
                    Some(crate::esp::LoaderOwner::Zboot) => "zboot",
                    Some(crate::esp::LoaderOwner::Other) => "other system",
                    None => "absent or unreadable",
                };
                let compared = match loader.matches_installed {
                    _ if loader.stale => "stale, no longer refreshed",
                    Some(true) => "matches installed zboot.efi",
                    Some(false) => "differs from installed zboot.efi",
                    None => "",
                };
                let _ = writeln!(out, "  {}  {}  {}", esc(&loader.path), owner, compared);
                if let Some(error) = &loader.error {
                    let _ = writeln!(out, "    {}", esc(error));
                }
            }
            if let Some(error) = &esp.error {
                let _ = writeln!(out, "  unavailable: {}", esc(error));
            }
            if let Some(error) = &esp.comparison_error {
                let _ = writeln!(
                    out,
                    "  installed loader comparison unavailable: {}",
                    esc(error)
                );
            }
        }
    }
    fn render_details(&self, out: &mut String) {
        self.render_attention(out);
        self.render_devices(out);
        self.render_kernels(out);
    }
}

/// The `lsblk` columns `--devices` reports.
pub const DEVICE_COLUMNS: &str =
    "NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,FSTYPE,MOUNTPOINTS,PTUUID,PARTUUID,PARTTYPE,RM";
use crate::deploy::layout::ESP_TYPE;

/// Every block device in an `lsblk --json` tree, children included.
fn blocks(devices: &serde_json::Value) -> Vec<&serde_json::Value> {
    fn walk<'a>(value: &'a serde_json::Value, out: &mut Vec<&'a serde_json::Value>) {
        for block in value.as_array().into_iter().flatten() {
            out.push(block);
            walk(&block["children"], out);
        }
    }
    let mut out = Vec::new();
    walk(&devices["blockdevices"], &mut out);
    out
}

fn text<'a>(block: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    block[key].as_str().filter(|value| !value.is_empty())
}

/// The ESP partition paths in an `lsblk` tree.
pub fn esp_paths(devices: &serde_json::Value) -> Vec<String> {
    let mut paths: Vec<String> = blocks(devices)
        .into_iter()
        .filter(|block| text(block, "type") == Some("part"))
        .filter(|block| text(block, "parttype").is_some_and(|t| t.eq_ignore_ascii_case(ESP_TYPE)))
        .filter_map(|block| text(block, "path").map(str::to_owned))
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

#[derive(Debug, Serialize)]
pub struct Relationship {
    pub role: Option<zfs_tools::engine::management::Role>,
    pub peer: Option<String>,
    pub history: Option<String>,
    pub blockers: Vec<String>,
    /// Snapshots only on the pair's fenced copy, older than the anchor: the
    /// working copy no longer has them. `sync` deletes them after review.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending_deletions: Vec<String>,
    /// Clones of the working copy's snapshots, such as a `fork` of a boot
    /// environment. Syncs go on; `primary` refuses until they are dropped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clones: Vec<String>,
    /// Both sides have the same newest snapshot, so `local ahead` or `peer
    /// ahead` in `history` is only that side's unsnapshotted changes.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub snapshots_level: bool,
}

pub fn relationships(
    state: &zfs_tools::engine::state::NativeState,
) -> BTreeMap<String, Relationship> {
    relationships_with(state, &mut crate::observation::NativeHistory)
}
pub(crate) fn relationships_with(
    state: &zfs_tools::engine::state::NativeState,
    history: &mut impl crate::observation::HistoryBackend,
) -> BTreeMap<String, Relationship> {
    let mut result = BTreeMap::new();
    for (name, properties) in &state.dataset_properties {
        let Some(property) = properties
            .get(zfs_tools::engine::management::PAIR_PROPERTY)
            .filter(|p| p.source == "local")
        else {
            continue;
        };
        let mut relation = Relationship {
            role: None,
            peer: None,
            history: None,
            blockers: vec![],
            pending_deletions: vec![],
            clones: vec![],
            snapshots_level: false,
        };
        let observed = (|| -> Result<(), Box<dyn std::error::Error>> {
            let record = zfs_tools::engine::management::PairRecord::parse(&property.value)?;
            relation.role = Some(record.role);
            relation.peer = Some(record.peer.name.clone());
            zfs_tools::engine::management::ownership(state, name)?;
            let left = crate::observation::tree(state, name, &mut *history)?;
            let right = crate::observation::tree(state, &record.peer.name, &mut *history)?;
            let admission = crate::history::admit_pair(&left, &right)?;
            let (copy, pending, copy_side, working_clones) = match record.role {
                zfs_tools::engine::management::Role::Secondary => (
                    name.as_str(),
                    &admission.only_left,
                    crate::history::Side::Left,
                    &admission.right_clones,
                ),
                zfs_tools::engine::management::Role::Primary => (
                    record.peer.name.as_str(),
                    &admission.only_right,
                    crate::history::Side::Right,
                    &admission.left_clones,
                ),
            };
            // A clone on the fenced copy stops every sync into it.
            admission.refuse_receiver_clones(copy_side, copy)?;
            relation.clones = working_clones.clone();
            relation.pending_deletions = state
                .inspection
                .snapshots
                .iter()
                .flatten()
                .filter(|s| {
                    pending.contains(&s.identity.guid)
                        && s.name
                            .split_once('@')
                            .is_some_and(|(owner, _)| owner == copy)
                })
                .map(|s| s.name.clone())
                .collect();
            relation.history = Some(
                match admission.ahead {
                    None => "equal",
                    Some(crate::history::Side::Left) => "local ahead",
                    Some(crate::history::Side::Right) => "peer ahead",
                }
                .into(),
            );
            relation.snapshots_level = admission.ahead.is_some() && admission.snapshots_level;
            Ok(())
        })();
        if let Err(error) = observed {
            relation.blockers.push(error.to_string());
        }
        result.insert(name.clone(), relation);
    }
    result
}

/// Anchor holds of an earlier pair on a dataset that is now in another one:
/// `unpair --release-anchors` releases only the current pair's, so these
/// would stay forever. Keyed by the dataset that owns the snapshot.
fn stale_anchors(state: &zfs_tools::engine::state::NativeState) -> Vec<(String, String)> {
    let mut items = Vec::new();
    for snapshot in state.inspection.snapshots.iter().flatten() {
        let Some((owner, _)) = snapshot.name.split_once('@') else {
            continue;
        };
        let Some(record) = state
            .dataset_properties
            .get(owner)
            .and_then(|p| p.get(zfs_tools::engine::management::PAIR_PROPERTY))
            .filter(|p| p.source == "local")
            .and_then(|p| zfs_tools::engine::management::PairRecord::parse(&p.value).ok())
        else {
            continue;
        };
        for tag in &snapshot.holds {
            if let Some(id) = tag.strip_prefix("zboot:anchor:")
                && id != record.pair_id
            {
                items.push((
                    owner.to_owned(),
                    format!(
                        "{} keeps the anchor hold of earlier pair {} (it is now in pair {}); \
                         `zfs release {} {}` frees it",
                        esc(&snapshot.name),
                        esc(id),
                        esc(&record.pair_id),
                        esc(tag),
                        esc(&snapshot.name)
                    ),
                ));
            }
        }
    }
    items
}

/// A property zboot itself writes, which the text view of a selected
/// dataset lists.
fn zboot_record(name: &str) -> bool {
    name.starts_with("zboot:") || name.starts_with("org.zfs-tools:")
}

/// The ZFS dataset mounted at `/` in this thread's mount namespace, if any.
pub fn running_root() -> io::Result<Option<String>> {
    running_zfs_root(&mountinfo::current()?)
}

/// Only the root's own source must be UTF-8: it names the running dataset.
fn running_zfs_root(mounts: &[Mount]) -> io::Result<Option<String>> {
    let mut roots = mounts
        .iter()
        .filter(|mount| mount.mount_point == Path::new("/") && mount.filesystem == "zfs");
    match (roots.next(), roots.next()) {
        (None, _) => Ok(None),
        (Some(root), None) => root
            .source
            .to_str()
            .map(|name| Some(name.to_owned()))
            .ok_or_else(|| io::Error::other("the running ZFS root's source is not UTF-8")),
        (Some(_), Some(_)) => Err(io::Error::other("ambiguous stacked ZFS root mounts")),
    }
}

/// Refuse to mount `dataset` where anything, ZFS or not (such as the RAM
/// Menu's `/var`), is already mounted: `zfs mount` would cover it.
pub(crate) fn unoccupied(dataset: &str) -> Result<(), zfs_tools::engine::Error> {
    let refuse = |detail: String| zfs_tools::engine::Error::Refused(detail);
    let args = ["get", "-H", "-o", "value", "mountpoint", dataset].map(String::from);
    let mountpoint = zfs_tools::engine::native::run("zfs", &args)?;
    let mountpoint = mountpoint.trim_end_matches('\n');
    // `..` through a missing directory resolves only once `zfs mount` has
    // made it (`/missing/../var` is `/var`): such a path is never mounted on.
    if std::path::Path::new(mountpoint)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(refuse(format!(
            "{dataset}'s mountpoint {mountpoint} has a `..` component; it was not mounted"
        )));
    }
    // The kernel mounts on the resolved path: compare that, so `/var/` or a
    // symlink to `/var` is the same place. Without `..`, a missing path is
    // made as new directories, which hold no mount.
    let target = match std::fs::canonicalize(mountpoint) {
        Ok(target) => target,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(refuse(format!("{mountpoint}: {e}"))),
    };
    if mounted_at(
        &mountinfo::current().map_err(|e| refuse(format!("mountinfo: {e}")))?,
        &target,
    ) {
        return Err(refuse(format!(
            "{mountpoint} is already a mount point; {dataset} was not mounted over it"
        )));
    }
    Ok(())
}

/// Whether anything, ZFS or not, is mounted at `path`.
fn mounted_at(mounts: &[Mount], path: &Path) -> bool {
    mounts.iter().any(|mount| mount.mount_point == path)
}

impl Status {
    #[cfg(test)]
    pub fn render(&self) -> String {
        self.render_numbered(None)
    }

    pub(crate) fn render_numbered(&self, numbers: Option<&Numbering>) -> String {
        let mut out = String::from("Imported ZFS storage (sequential observation)\n");
        if self.inventory.pools.is_empty() {
            out.push_str("No imported pools.\n");
        }
        for pool in &self.inventory.pools {
            let _ = writeln!(
                out,
                "{}  {}  {} bytes free  guid={}",
                esc(&pool.name),
                esc(&pool.health),
                pool.free_bytes,
                pool.guid
            );
            for ds in self
                .inventory
                .datasets
                .iter()
                .filter(|d| pool_of(&d.name) == pool.name)
            {
                let depth = ds.name.matches('/').count() + 1;
                let mut annotations = Vec::new();
                if self.running_root.as_ref() == Some(&ds.name) {
                    annotations.push("running root".to_owned());
                }
                if pool.bootfs.as_ref() == Some(&ds.name) {
                    annotations.push("boot default".to_owned());
                }
                if self.boot_environments.contains(&ds.name) {
                    annotations.push(self.kernel_evidence(&ds.name).into());
                }
                annotations.push(if ds.readonly { "readonly" } else { "writable" }.into());
                if ds.mounted == Some(true) {
                    annotations.push(format!(
                        "mounted {}",
                        esc(ds.mountpoint.as_deref().unwrap_or("?"))
                    ));
                }
                if let Some((owner, relation)) = self
                    .relationships
                    .iter()
                    .filter(|(owner, _)| crate::history::contains_dataset(owner, &ds.name))
                    .max_by_key(|(owner, _)| owner.len())
                {
                    if owner == &ds.name {
                        if let Some(role) = relation.role {
                            annotations.push(format!(
                                "{} → {}",
                                if role == zfs_tools::engine::management::Role::Primary {
                                    "primary"
                                } else {
                                    "secondary"
                                },
                                esc(relation.peer.as_deref().unwrap_or("?"))
                            ));
                        }
                        if let Some(direction) = &relation.history {
                            annotations.push(direction.clone());
                        }
                        annotations.extend(
                            relation
                                .blockers
                                .iter()
                                .map(|b| format!("BLOCKED {}", esc(b))),
                        );
                    } else if !relation.blockers.is_empty() {
                        annotations.push(format!("BLOCKED by {}", esc(owner)));
                    }
                }
                if let Some(id) = &ds.pending {
                    annotations.push(format!("BLOCKED pending={}", esc(id)));
                }
                if let Some(id) = &ds.staging {
                    annotations.push(format!("BLOCKED staging={}", esc(id)));
                }
                if let Some(origin) = &ds.origin {
                    annotations.push(format!("clone of {}", esc(origin)));
                }
                let _ = writeln!(
                    out,
                    "{}{}{}  [{}]",
                    "  ".repeat(depth),
                    numbers.map_or_else(String::new, |numbers| numbers
                        .prefix(&ds.name, &ds.identity)),
                    esc(&ds.name),
                    annotations.join(", ")
                );
                if let Some(snaps) = &self.inventory.snapshots {
                    let mut snaps: Vec<_> = snaps
                        .iter()
                        .filter(|s| {
                            s.name
                                .split_once('@')
                                .is_some_and(|(name, _)| name == ds.name)
                        })
                        .collect();
                    snaps.sort_by_key(|s| s.identity.createtxg);
                    for snap in snaps {
                        let _ = writeln!(
                            out,
                            "{}@{}  guid={} holds={} clones={}{}",
                            "  ".repeat(depth + 1),
                            esc(snap.name.split_once('@').unwrap().1),
                            snap.guid,
                            snap.holds.len(),
                            snap.clones.len(),
                            if snap.defer_destroy {
                                " deferred-delete"
                            } else {
                                ""
                            }
                        );
                    }
                }
                if let Some(props) = self.properties.as_ref().and_then(|p| p.get(&ds.name)) {
                    // zboot's own records; `--json` carries every property.
                    for (name, prop) in props.iter().filter(|(name, _)| zboot_record(name)) {
                        let _ = writeln!(
                            out,
                            "{}{}={} ({})",
                            "  ".repeat(depth + 1),
                            esc(name),
                            esc(&prop.value),
                            esc(&prop.source)
                        );
                    }
                }
            }
        }
        if self.operations.operations.is_empty() && self.operations.orphans.is_empty() {
            out.push_str("No interrupted operations.\n");
        }
        for operation in &self.operations.operations {
            let _ = writeln!(
                out,
                "Interrupted {} {} on pool {} after step {}{}; continue with zboot resume {}",
                esc(operation.kind.as_deref().unwrap_or("unreadable")),
                esc(operation.id.as_deref().unwrap_or("-")),
                esc(&operation.pool),
                esc(operation.step.as_deref().unwrap_or("-")),
                operation
                    .detail
                    .as_deref()
                    .map(|d| format!(" ({})", esc(d)))
                    .unwrap_or_default(),
                esc(operation.id.as_deref().unwrap_or("ID"))
            );
        }
        for orphan in &self.operations.orphans {
            let _ = writeln!(out, "{}", esc(&capitalized(&orphan.describe())));
        }
        self.render_details(&mut out);
        out
    }
}

/// TEXT with its first letter in upper case, as a sentence of its own.
pub(crate) fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Tie expanded property rows to this inventory before presenting one report.
pub fn validate_properties(
    inventory: &Inspection,
    properties: &zfs_tools::engine::native::PropertyInventory,
) -> Result<(), String> {
    let expected: BTreeMap<_, _> = inventory
        .datasets
        .iter()
        .map(|d| (&d.name, d.guid.to_string()))
        .collect();
    if expected.len() != properties.len() {
        return Err("property inventory scope changed".into());
    }
    for (name, guid) in expected {
        if properties
            .get(name)
            .and_then(|p| p.get("guid"))
            .map(|p| &p.value)
            != Some(&guid)
        {
            return Err(format!(
                "{}: dataset changed during property query",
                esc(name)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> crate::tree::fake::Fake {
        let mut fake = crate::tree::fake::Fake::new();
        for name in [
            "a/ROOT",
            "b/ROOT",
            "a/ROOT/one",
            "a/ROOT/one/var",
            "a/ROOT/two",
            "a/home",
            "b/home",
            "b/ROOT/other",
        ] {
            fake.create(name);
            fake.set(name, "canmount", "noauto");
        }
        fake.set("a/ROOT/one", "mountpoint", "/");
        fake.set("a/ROOT/two", "mountpoint", "/");
        fake.set("b/ROOT/other", "mountpoint", "/");
        fake.set("a/ROOT/one/var", "canmount", "on");
        fake.pools.get_mut("a").unwrap().bootfs = Some("a/ROOT/one".into());
        fake.pools.get_mut("b").unwrap().bootfs = Some("b/ROOT/other".into());
        fake
    }
    fn status_with(
        state: &zfs_tools::engine::state::NativeState,
        selected: Vec<String>,
        relations: BTreeMap<String, Relationship>,
    ) -> Status {
        from_state(
            state,
            selected,
            false,
            Some("a/ROOT/one".into()),
            crate::restore::Listing {
                operations: vec![crate::restore::Listed {
                    pool: "a".into(),
                    id: Some("op-1".into()),
                    kind: Some("sync".into()),
                    step: Some("1".into()),
                    detail: None,
                }],
                orphans: vec![],
            },
            relations,
        )
        .unwrap()
    }
    fn relation(
        role: zfs_tools::engine::management::Role,
        peer: &str,
        history: &str,
    ) -> Relationship {
        Relationship {
            pending_deletions: vec![],
            clones: vec![],
            snapshots_level: false,
            role: Some(role),
            peer: Some(peer.into()),
            history: Some(history.into()),
            blockers: vec![],
        }
    }

    #[test]
    fn short_status_uses_four_ordered_blocks_and_keeps_plain_reads_mount_free() {
        use crate::tree::Backend;
        use zfs_tools::engine::management::Role;
        let state = fixture().observe().unwrap();
        let relations = BTreeMap::from([
            (
                "a/home".into(),
                relation(Role::Primary, "b/home", "local ahead"),
            ),
            (
                "b/home".into(),
                relation(Role::Secondary, "a/home", "peer ahead"),
            ),
        ]);
        let mut status = status_with(&state, vec![], relations);
        add_kernels(&mut status, |_| {
            panic!("plain status must not inspect a filesystem")
        });
        let text = status.render_short();
        let positions: Vec<_> = [
            "Boot environments\n",
            "Pairs\n",
            "Interrupted\n",
            "Attention\n",
        ]
        .map(|title| text.find(title).unwrap())
        .into_iter()
        .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(text.contains("a/ROOT/one  running, default"));
        assert!(text.contains("candidate, kernels unprobed"));
        assert!(status.render().contains("candidate, kernels unprobed"));
        assert_eq!(text.matches("a/home -> b/home").count(), 2); // pair row and attention
        assert!(text.contains("zboot resume op-1"));
        assert!(text.contains("a/ROOT/one/var has canmount=on"));
        assert!(text.contains("more than one boot default"));
        assert!(!text.contains("Imported ZFS storage"));
        assert!(status.render().contains("Imported ZFS storage"));
        assert!(
            status
                .inventory
                .datasets
                .iter()
                .any(|dataset| dataset.name == "a/home")
        );
        let json = serde_json::to_value(&status).unwrap();
        assert!(json["attention"].as_array().unwrap().len() >= 3);
        assert!(json.get("readiness").is_none());
    }

    #[test]
    fn status_keeps_fenced_root_hazards_and_refuses_their_kernel_probe() {
        use crate::tree::Backend;
        let mut fake = fixture();
        fake.set("a/ROOT/one", "zboot:pending", "unfinished");
        let state = fake.observe().unwrap();
        let mut status = status_with(&state, vec!["a/ROOT/one".into()], BTreeMap::new());
        assert_eq!(status.boot_environments, ["a/ROOT/one"]);
        add_kernels(&mut status, |_| panic!("a fenced root must not be mounted"));
        let text = status.render_short();
        assert!(
            text.lines().any(|line| line.starts_with("  a/ROOT/one  ")
                && line.ends_with("boot blocked (see Attention)")),
            "{text}"
        );
        assert!(
            status
                .attention
                .iter()
                .any(|item| item.contains("boot candidate blocked") && item.contains("pending"))
        );
        assert!(
            status
                .attention
                .iter()
                .any(|item| item.contains("a/ROOT/one/var has canmount=on"))
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["boot_environments"], serde_json::json!(["a/ROOT/one"]));
        assert!(
            json["kernels"]["a/ROOT/one"]["error"]
                .as_str()
                .unwrap()
                .contains("pending")
        );
        assert_eq!(fake.writes, 0);
    }

    #[test]
    fn status_reports_unsafe_defaults_but_excludes_ordinary_restore_workspaces() {
        use crate::tree::Backend;
        let mut fake = fixture();
        let workspace = "a/zboot-restore-1111111111114111";
        fake.create(workspace);
        fake.set(workspace, "mountpoint", "/");
        let state = fake.observe().unwrap();
        let status = status_with(&state, vec![], BTreeMap::new());
        assert!(
            !status
                .boot_environments
                .iter()
                .any(|name| name == workspace)
        );
        fake.pools.get_mut("a").unwrap().bootfs = Some(workspace.into());
        let state = fake.observe().unwrap();
        let mut status = status_with(&state, vec![], BTreeMap::new());
        add_kernels(&mut status, |_| {
            panic!("plain status mounts nothing, even for unsafe defaults")
        });
        assert!(
            status
                .boot_environments
                .iter()
                .any(|name| name == workspace)
        );
        assert!(
            status
                .attention
                .iter()
                .any(|item| item.contains("workspace cannot boot"))
        );
        assert!(
            status
                .render_short()
                .contains("candidate, kernels unprobed")
        );
    }

    #[test]
    fn menu_numbering_prefixes_only_matching_native_dataset_identities() {
        use crate::tree::Backend;
        let state = fixture().observe().unwrap();
        let identity = |name: &str| {
            state
                .inspection
                .datasets
                .iter()
                .find(|dataset| dataset.name == name)
                .unwrap()
                .identity
                .clone()
        };
        let mut numbers = Numbering {
            boot: BTreeMap::from([("a/ROOT/one".into(), ("1".into(), identity("a/ROOT/one")))]),
        };
        let status = status_with(&state, vec![], BTreeMap::new());
        let short = status.render_short_numbered(Some(&numbers));
        assert!(short.contains("  1: a/ROOT/one  running, default"));
        // Attention, child datasets included, carries names and no numbers:
        // only the rows above bind a number to a native identity.
        let attention = |text: &str| text[text.find("Attention\n").unwrap()..].to_owned();
        assert!(attention(&short).contains("boot environment a/ROOT/one has child dataset"));
        assert_eq!(attention(&short), attention(&status.render_short()));
        assert!(!attention(&short).contains("1: "));
        let full = status.render_numbered(Some(&numbers));
        assert!(full.contains("1: a/ROOT/one  ["));
        assert!(full.contains("  a/home  ["));
        numbers.boot.get_mut("a/ROOT/one").unwrap().1.guid = zfs_tools::engine::Guid::new(99999);
        assert!(!status.render_short_numbered(Some(&numbers)).contains("1: "));
        assert!(!status.render_numbered(Some(&numbers)).contains("1: "));
        assert_eq!(status.render_short_numbered(None), status.render_short());
        assert_eq!(status.render_numbered(None), status.render());
    }

    #[test]
    fn explicit_selection_limits_inventory_records_attention_and_kernel_views() {
        use crate::tree::Backend;
        let state = fixture().observe().unwrap();
        let mut status = status_with(&state, vec!["a/ROOT/one".into()], BTreeMap::new());
        let mut inspected = Vec::new();
        add_kernels(&mut status, |name| {
            inspected.push(name.to_owned());
            KernelInventory {
                kernels: vec![],
                error: Some("locked BE".into()),
            }
        });
        assert_eq!(inspected, ["a/ROOT/one"]);
        assert_eq!(status.inventory.datasets.len(), 2);
        assert_eq!(status.properties.as_ref().unwrap().len(), 2);
        assert!(
            status
                .boot_environments
                .iter()
                .all(|name| name.starts_with("a/ROOT/one"))
        );
        assert!(status.render().contains("unavailable: locked BE"));
        let mut child = status_with(&state, vec!["a/ROOT/one/var".into()], BTreeMap::new());
        add_kernels(&mut child, |_| {
            panic!("selecting an ordinary child does not request its ancestor's filesystem")
        });
        assert!(child.kernels.is_empty());
    }

    #[test]
    fn empty_short_status_omits_empty_blocks() {
        use crate::tree::Backend;
        let state = crate::tree::fake::Fake::new().observe().unwrap();
        let status = from_state(
            &state,
            vec![],
            false,
            None,
            crate::restore::Listing {
                operations: vec![],
                orphans: vec![],
            },
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(status.render_short().lines().count(), 1);
        assert!(!status.render_short().contains("\nAttention"));
    }

    #[test]
    fn missing_peers_and_secondary_ahead_are_attention_not_duplicate_pairs() {
        use crate::tree::Backend;
        use zfs_tools::engine::management::Role;
        let state = fixture().observe().unwrap();
        let status = status_with(
            &state,
            vec![],
            BTreeMap::from([
                (
                    "a/home".into(),
                    relation(Role::Primary, "gone/home", "equal"),
                ),
                (
                    "b/home".into(),
                    relation(Role::Secondary, "a/home", "local ahead"),
                ),
            ]),
        );
        assert!(
            status
                .attention
                .iter()
                .any(|item| item.contains("gone/home is gone"))
        );
        assert!(
            status
                .attention
                .iter()
                .any(|item| item.contains("secondary ahead"))
        );
        assert_eq!(
            pair_progress(&relation(Role::Secondary, "a/home", "peer ahead")),
            "secondary behind"
        );
    }

    #[test]
    fn a_boot_environment_line_states_its_pair_progress_from_its_own_side() {
        use zfs_tools::engine::management::Role;
        for (role, peer, history, expected) in [
            (
                Role::Primary,
                "b/BE",
                "local ahead",
                "primary of b/BE, b/BE behind",
            ),
            (
                Role::Secondary,
                "a/BE",
                "peer ahead",
                "secondary of a/BE, behind",
            ),
            (Role::Primary, "b/BE", "equal", "primary of b/BE, level"),
            (
                Role::Secondary,
                "a/BE",
                "local ahead",
                "secondary of a/BE, diverged (secondary ahead)",
            ),
        ] {
            assert_eq!(
                pair_annotation(&relation(role, peer, history)).join(", "),
                expected
            );
        }
    }

    #[test]
    fn an_earlier_pairs_anchor_hold_is_attention_with_its_release() {
        use crate::tree::Backend;
        let mut fake = fixture();
        mutual_home(&mut fake, true);
        fake.snap("a/home@old");
        fake.snapshots
            .get_mut("a/home@old")
            .unwrap()
            .holds
            .insert("zboot:anchor:22222222-2222-4222-8222-222222222222".into());
        let state = fake.observe().unwrap();
        let status = status_with(&state, vec![], BTreeMap::new());
        let text = status.attention.join("\n");
        assert!(
            text.contains(
                "a/home@old keeps the anchor hold of earlier pair \
                 22222222-2222-4222-8222-222222222222 (it is now in pair \
                 11111111-1111-4111-8111-111111111111); `zfs release \
                 zboot:anchor:22222222-2222-4222-8222-222222222222 a/home@old` frees it"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_working_copys_clones_are_attention_naming_primary() {
        let mut fake = fixture();
        mutual_home(&mut fake, true);
        use crate::tree::Backend;
        let state = fake.observe().unwrap();
        let mut working = relation(
            zfs_tools::engine::management::Role::Primary,
            "b/home",
            "equal",
        );
        working.clones = vec!["a/home-fork".into()];
        let status = status_with(
            &state,
            vec![],
            BTreeMap::from([("a/home".to_owned(), working)]),
        );
        let text = status.attention.join("\n");
        assert!(
            text.contains("the working copy has clones (a/home-fork)")
                && text.contains("`primary` refuses"),
            "{text}"
        );
    }

    #[test]
    fn pending_deletions_are_attention_with_the_review_command() {
        use crate::tree::Backend;
        use zfs_tools::engine::management::Role;
        let state = fixture().observe().unwrap();
        for (name, role, peer) in [
            ("a/home", Role::Primary, "b/home"),
            ("b/home", Role::Secondary, "a/home"),
        ] {
            let mut pending = relation(role, peer, "equal");
            pending.pending_deletions = vec!["b/home@old1".into(), "b/home@old2".into()];
            let status = status_with(&state, vec![], BTreeMap::from([(name.into(), pending)]));
            let items: Vec<_> = status
                .attention
                .iter()
                .filter(|item| item.contains("await review"))
                .collect();
            assert_eq!(items.len(), 1, "{:?}", status.attention);
            assert!(
                items[0].starts_with("a/home -> b/home: 2 snapshots only on b/home await review")
                    && items[0].contains("`zboot sync b/home` on a terminal"),
                "{}",
                items[0]
            );
            // Pending deletions are routine: a level pair has nothing else.
            assert!(!status.attention.iter().any(|item| item.contains("behind")));
        }
    }

    #[test]
    fn selected_kernel_names_are_versions_with_resolved_paths_and_pointer_default() {
        use std::os::unix::fs::symlink;
        let scratch = crate::factory::tests::Scratch::new();
        let root = &scratch.0;
        std::fs::create_dir(root.join("boot")).unwrap();
        for version in ["1.2-test", "2.0-test"] {
            std::fs::write(root.join(format!("boot/vmlinuz-{version}")), b"kernel").unwrap();
            std::fs::write(root.join(format!("boot/initrd.img-{version}")), b"initrd").unwrap();
        }
        symlink("boot/vmlinuz-1.2-test", root.join("vmlinuz")).unwrap();
        symlink("boot/initrd.img-1.2-test", root.join("initrd.img")).unwrap();
        let kernels = kernel_inventory_at(root).unwrap();
        assert_eq!(kernels.len(), 2);
        assert_eq!(
            kernels.iter().find(|kernel| kernel.default).unwrap().name,
            "1.2-test"
        );
        assert!(kernels.iter().any(|kernel| kernel.name == "2.0-test"
            && kernel.kernel == Path::new("boot/vmlinuz-2.0-test")));
        std::fs::remove_file(root.join("boot/initrd.img-2.0-test")).unwrap();
        assert_eq!(kernel_inventory_at(root).unwrap().len(), 1);
    }

    #[test]
    fn selected_running_default_be_includes_versioned_kernel_inventory() {
        use crate::tree::Backend;
        use std::os::unix::fs::symlink;
        let scratch = crate::factory::tests::Scratch::new();
        let root = &scratch.0;
        std::fs::create_dir(root.join("boot")).unwrap();
        std::fs::write(root.join("boot/vmlinuz-test-version"), b"kernel").unwrap();
        std::fs::write(root.join("boot/initrd.img-test-version"), b"initrd").unwrap();
        symlink("boot/vmlinuz-test-version", root.join("vmlinuz")).unwrap();
        symlink("boot/initrd.img-test-version", root.join("initrd.img")).unwrap();
        let state = fixture().observe().unwrap();
        let mut status = status_with(&state, vec!["a/ROOT/one".into()], BTreeMap::new());
        add_kernels(&mut status, |dataset| {
            assert_eq!(dataset, "a/ROOT/one");
            KernelInventory {
                kernels: kernel_inventory_at(root).unwrap(),
                error: None,
            }
        });
        assert!(
            status
                .render_short()
                .contains("a/ROOT/one  running, default")
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["running_root"], "a/ROOT/one");
        assert_eq!(
            json["kernels"]["a/ROOT/one"]["kernels"][0]["name"],
            "test-version"
        );
        assert_eq!(json["kernels"]["a/ROOT/one"]["kernels"][0]["default"], true);
        assert!(json["kernels"]["a/ROOT/one"].get("error").is_none());
        assert_eq!(json["inventory"]["pools"][0]["bootfs"], "a/ROOT/one");
    }

    #[test]
    fn loader_attention_requires_a_differing_owned_loader() {
        let loader = |path: &str, owner, compared| crate::esp::Loader {
            path: path.into(),
            identity: None,
            owner,
            matches_installed: compared,
            error: None,
            stale: false,
        };
        let esps = vec![Esp {
            path: "/dev/test1".into(),
            target: None,
            error: None,
            comparison_error: None,
            loaders: vec![
                loader(
                    "EFI/zboot/zboot.efi",
                    Some(crate::esp::LoaderOwner::Zboot),
                    Some(true),
                ),
                loader(
                    "EFI/BOOT/BOOTX64.EFI",
                    Some(crate::esp::LoaderOwner::Zboot),
                    Some(false),
                ),
                loader(
                    "EFI/BOOT/BOOTX64.EFI",
                    Some(crate::esp::LoaderOwner::Other),
                    None,
                ),
            ],
        }];
        let attention = loader_attention(&esps);
        assert_eq!(
            attention,
            ["ESP /dev/test1 loader EFI/BOOT/BOOTX64.EFI differs from installed zboot.efi"]
        );
    }

    #[test]
    fn a_stale_zboot_loader_is_attention_naming_the_firmware_fix() {
        let esps = vec![Esp {
            path: "/dev/test1".into(),
            target: None,
            error: None,
            comparison_error: None,
            loaders: vec![crate::esp::Loader {
                path: "EFI/zboot/zboot-recovery.efi".into(),
                identity: None,
                owner: Some(crate::esp::LoaderOwner::Zboot),
                matches_installed: None,
                error: None,
                stale: true,
            }],
        }];
        assert_eq!(
            loader_attention(&esps),
            [
                "ESP /dev/test1: EFI/zboot/zboot-recovery.efi is a stale zboot loader; \
                 zboot no longer refreshes it. Point the firmware boot entry at \
                 EFI/zboot/zboot.efi (efibootmgr), then remove EFI/zboot/zboot-recovery.efi."
            ]
        );
    }

    #[test]
    fn the_shipped_efi_is_lib_zboot_beside_the_binary_directory_only() {
        let scratch = crate::factory::tests::Scratch::new();
        let executable = scratch.0.join("usr/bin/zboot");
        std::fs::create_dir_all(scratch.0.join("usr/bin")).unwrap();
        // A loader beside the binary is not the shipped one.
        std::fs::write(scratch.0.join("usr/bin/zboot.efi"), b"beside").unwrap();
        let error = shipped_efi_at(&executable).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(
            error.to_string().contains("usr/lib/zboot/zboot.efi"),
            "{error}"
        );
        let packaged = scratch.0.join("usr/lib/zboot/zboot.efi");
        std::fs::create_dir_all(packaged.parent().unwrap()).unwrap();
        std::fs::write(&packaged, b"packaged").unwrap();
        assert_eq!(shipped_efi_at(&executable).unwrap(), packaged);
    }

    #[test]
    fn every_child_of_a_boot_environment_or_paired_leaf_is_attention_with_what_it_means() {
        use crate::tree::Backend;
        use zfs_tools::engine::management::Role;
        let mut fake = fixture();
        // An ordinary child, not canmount=on, and a child of a paired leaf.
        fake.create("a/ROOT/two/srv");
        fake.set("a/ROOT/two/srv", "canmount", "noauto");
        fake.create("a/home/sub");
        let state = fake.observe().unwrap();
        let pair = || {
            BTreeMap::from([
                ("a/home".into(), relation(Role::Primary, "b/home", "equal")),
                (
                    "b/home".into(),
                    relation(Role::Secondary, "a/home", "equal"),
                ),
            ])
        };
        let status = status_with(&state, vec![], pair());
        for item in [
            "a/ROOT/one/var has canmount=on inside boot environment a/ROOT/one",
            "boot environment a/ROOT/one has child dataset a/ROOT/one/var: fork and pair refuse \
             a boot environment with children",
            "boot environment a/ROOT/two has child dataset a/ROOT/two/srv: fork and pair refuse \
             a boot environment with children",
            "paired dataset a/home has child dataset a/home/sub: a sync does not copy it, and \
             a primary switch refuses while either side has one",
        ] {
            assert!(
                status.attention.iter().any(|a| a == item),
                "{item}\n{:#?}",
                status.attention
            );
        }
        // The canmount=on child appears twice, each time naming its boot
        // environment: once for the automount hazard, once as a child.
        let var: Vec<_> = status
            .attention
            .iter()
            .filter(|item| item.contains("a/ROOT/one/var"))
            .collect();
        assert_eq!(var.len(), 2);
        assert!(
            var.iter()
                .all(|item| item.contains("boot environment a/ROOT/one"))
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(
            json["child_datasets"],
            serde_json::json!([
                {"parent": "a/ROOT/one", "boot_environment": true, "children": ["a/ROOT/one/var"]},
                {"parent": "a/ROOT/two", "boot_environment": true, "children": ["a/ROOT/two/srv"]},
                {"parent": "a/home", "boot_environment": false, "paired_with": "b/home",
                 "children": ["a/home/sub"]},
            ])
        );

        // A paired boot environment's child has both meanings, in one item.
        let paired_be = BTreeMap::from([(
            "a/ROOT/one".into(),
            relation(Role::Primary, "b/ROOT/other", "equal"),
        )]);
        let status = status_with(&state, vec![], paired_be);
        assert!(status.attention.iter().any(|item| item
            == "paired boot environment a/ROOT/one has child dataset a/ROOT/one/var: fork \
                refuses a boot environment with children, a sync does not copy it, and a \
                primary switch refuses while either side has one"));

        // A selection lists the children it selects, under their parents.
        let status = status_with(&state, vec!["a/home/sub".into()], pair());
        assert_eq!(status.child_datasets.len(), 1);
        assert_eq!(status.child_datasets[0].parent, "a/home");
        let status = status_with(&state, vec!["a/ROOT/two".into()], pair());
        assert_eq!(status.child_datasets.len(), 1);
        assert_eq!(status.child_datasets[0].children, ["a/ROOT/two/srv"]);
    }

    /// A mutual pair recorded on the fixture's `a/home` (working) and
    /// `b/home` (fenced).
    fn mutual_home(fake: &mut crate::tree::fake::Fake, reciprocated: bool) {
        use zfs_tools::engine::management::{Endpoint, PAIR_PROPERTY, PairRecord, Role};
        let endpoint = |name: &str| Endpoint {
            name: name.into(),
            identity: fake.identity(name),
        };
        let record = PairRecord {
            schema_version: 1,
            pair_id: "11111111-1111-4111-8111-111111111111".into(),
            endpoint: endpoint("a/home"),
            peer: endpoint("b/home"),
            role: Role::Primary,
        };
        fake.set("a/home", PAIR_PROPERTY, &record.encode().unwrap());
        if reciprocated {
            fake.set(
                "b/home",
                PAIR_PROPERTY,
                &record.counterpart().encode().unwrap(),
            );
        }
    }

    #[test]
    fn a_mutual_pairs_unheld_space_limits_are_attention_and_structured_json() {
        use crate::tree::Backend;
        let mut fake = fixture();
        mutual_home(&mut fake, true);
        fake.set("a/home", "quota", "107374182400");
        fake.set("b/home", "reservation", "1024");
        let state = fake.observe().unwrap();
        let status = status_with(&state, vec![], BTreeMap::new());
        let items: Vec<_> = status
            .attention
            .iter()
            .filter(|item| item.starts_with("a/home -> b/home: ") && item.contains(" on b/home; "))
            .collect();
        assert_eq!(
            items,
            [
                "a/home -> b/home: quota 100G on a/home, none on b/home; a sync applies it when \
                 b/home can take it",
                // The fenced side alone holds this one: say that a sync ends it.
                "a/home -> b/home: reservation none on a/home, 1K on b/home; the next sync \
                 removes it from b/home",
            ]
        );
        assert_eq!(
            serde_json::to_value(&status).unwrap()["space_differences"],
            serde_json::json!([
                {"working_copy": "a/home", "copy": "b/home", "key": "quota",
                 "working_value": "107374182400", "copy_value": null},
                {"working_copy": "a/home", "copy": "b/home", "key": "reservation",
                 "working_value": null, "copy_value": "1024", "copy_source": "local"},
            ])
        );
        // The same comparison the transfer and `primary` use.
        assert_eq!(
            status.space_differences,
            crate::transfer::props::space_differences(&state, "a/home", "b/home").unwrap()
        );
        // Either side selects the pair; an unrelated selection does not.
        let selected = |name: &str| {
            status_with(&state, vec![name.into()], BTreeMap::new())
                .space_differences
                .len()
        };
        assert_eq!(selected("b/home"), 2);
        assert_eq!(selected("a/ROOT/one"), 0);
        // A peer that does not name this side is gone, not a copy.
        let mut fake = fixture();
        mutual_home(&mut fake, false);
        fake.set("a/home", "quota", "107374182400");
        let state = fake.observe().unwrap();
        let status = status_with(&state, vec![], BTreeMap::new());
        assert!(status.space_differences.is_empty());
        assert!(
            !status
                .attention
                .iter()
                .any(|item| item.contains("can take it"))
        );
    }

    #[test]
    fn any_mount_at_a_path_occupies_it() {
        let mounts = mountinfo::table(
            "22 1 0:21 / / rw - zfs rpool/ROOT/be rw\n\
             23 22 0:22 / /var rw - tmpfs tmpfs rw\n\
             24 22 0:23 / /srv\\040data rw - zfs rpool/srv rw\n",
        )
        .unwrap();
        assert!(mounted_at(&mounts, Path::new("/var")));
        assert!(mounted_at(&mounts, Path::new("/srv data")));
        assert!(!mounted_at(&mounts, Path::new("/home")));
        assert!(mountinfo::table("22 1 0:21 /").is_err());
        assert!(mountinfo::table("22 1 0:21 / /var rw tmpfs tmpfs rw").is_err());
    }

    fn root_of(text: &str) -> io::Result<Option<String>> {
        running_zfs_root(&mountinfo::table(text)?)
    }

    #[test]
    fn root_uses_filesystem_source_and_decodes_mount_escapes() {
        assert_eq!(
            root_of("31 1 0:2 / / rw - zfs tank/ROOT/my\\040root rw\n").unwrap(),
            Some("tank/ROOT/my root".into())
        );
        assert_eq!(
            root_of("31 1 0:2 / / rw - overlay overlay rw\n").unwrap(),
            None
        );
    }
    #[test]
    fn ambiguity_and_malformed_mounts_are_not_a_guessed_default() {
        let row = "31 1 0:2 / / rw - zfs tank/root rw\n";
        assert!(root_of(&format!("{row}{}", row.replace("31 1", "32 31"))).is_err());
        assert!(root_of("bad line").is_err());
        assert!(root_of(&row.replace("tank/root", "tank/\\999")).is_err());
        // Only the root's source must name a dataset in UTF-8.
        let mut text = row.as_bytes().to_vec();
        text.extend_from_slice(b"32 31 0:3 / /srv/\xff rw - zfs tank/\xfe rw\n");
        let mounts = mountinfo::table(&text).unwrap();
        assert_eq!(running_zfs_root(&mounts).unwrap(), Some("tank/root".into()));
        let root = b"31 1 0:2 / / rw - zfs tank/\xff rw\n";
        assert!(running_zfs_root(&mountinfo::table(root).unwrap()).is_err());
    }
}
