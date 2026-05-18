//! `zboot status` — read-only summary: pools, BE forest (origin lineage),
//! bound datasets, orphans.
//!
//! Pipeline: spawn `zfs(8)` / `zpool(8)` → parse via `zboot-core` → build
//! `Forest` → render. The renderer is split out (`render_human`) so cargo
//! unit tests cover formatting independently of any subprocess.
//!
//! ## Tree rendering style
//!
//! ASCII connectors `├── `, `└── `, `│   `, `    ` — readable on any
//! terminal, no Unicode dependency, no color. Indentation depth follows
//! origin lineage; siblings sort by name within a parent.
//!
//! ## Orphan flagging
//!
//! Datasets whose `zboot:attached-to` list contains zero extant BEs are
//! "orphans". Surfaced as a dedicated `Orphans:` section in the human
//! output (prefix `[!] `).

use std::io::Write;

use anyhow::{Context, Result};

use crate::sub;
use clap::Args;

use zboot_core::{
    BootEnvironment, BoundKey, BoundList, Canmount, Forest, Mountpoint, Pool, PoolRole, Property,
    SnapshotRef, parse_zfs_get, parse_zpool_list,
};

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Don't auto-import `zboot:role=root` pools that are importable
    /// from local disks. Default behavior is to readonly-import them
    /// so the BE forest view is complete. Use this flag for scripted
    /// / CI contexts where you want strictly stable behavior.
    #[arg(long)]
    pub no_import: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: &StatusArgs, out: &mut impl Write) -> Result<()> {
    if !args.no_import {
        // Surface any `zboot:role=root` pools that exist on local disks
        // but aren't imported yet — otherwise their BEs are invisible
        // and the forest is misleading.
        let _ = crate::pools::ensure_zboot_root_pools_imported(out);
    }
    let snapshot = collect_state()?;
    render_human(&snapshot, out)
}

// ---------------------------------------------------------------------------
// State snapshot — what `status` knows about the system after I/O.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct StateSnapshot {
    pub pools: Vec<Pool>,
    pub forest: Forest,
    /// All datasets carrying `zboot:attached-to`. Includes both live-bound
    /// (some entry references an extant BE) and orphans.
    pub bound_datasets: Vec<BoundDataset>,
}

#[derive(Debug, Clone)]
pub struct BoundDataset {
    pub dataset: String,
    pub bound_to: BoundList,
}

// ---------------------------------------------------------------------------
// I/O — spawn `zfs` / `zpool`, parse, assemble StateSnapshot.
// ---------------------------------------------------------------------------

/// Properties we need to pull from `zfs get` for *all* datasets in one call.
const ZFS_PROPS: &str = "origin,mountpoint,canmount,zboot:be,zboot:attached-to,zboot:created-by";

/// Properties we need at the pool level.
const POOL_PROPS: &str = "zboot:role";

fn collect_state() -> Result<StateSnapshot> {
    let pools_text = sub::cmd_capture("zpool", &["list", "-Hp", "-o", "name,bootfs,guid"])?;
    let mut pools = parse_zpool_list(&pools_text).context("parsing `zpool list`")?;

    if !pools.is_empty() {
        let pool_names: Vec<&str> = pools.iter().map(|p| p.name.as_str()).collect();
        let mut args: Vec<&str> = vec!["get", "-Hp", "-o", "name,property,value", POOL_PROPS];
        args.extend(pool_names.iter().copied());
        let role_text = sub::cmd_capture("zpool", &args)?;
        let role_props = parse_zfs_get(&role_text).context("parsing `zpool get zboot:role`")?;
        annotate_pool_roles(&mut pools, &role_props);
    }

    let datasets_text = sub::cmd_capture("zfs", &["list", "-Hp", "-o", "name", "-t", "filesystem"])?;
    let datasets: Vec<String> = datasets_text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let zfs_props = if datasets.is_empty() {
        Vec::new()
    } else {
        let mut args: Vec<&str> = vec!["get", "-Hp", "-o", "name,property,value", ZFS_PROPS];
        args.extend(datasets.iter().map(String::as_str));
        let text = sub::cmd_capture("zfs", &args)?;
        parse_zfs_get(&text).context("parsing `zfs get` for datasets")?
    };

    let (bes, bound) = bes_and_bound_from_props(&datasets, &zfs_props);
    let forest = Forest::from_origins(bes);

    Ok(StateSnapshot {
        pools,
        forest,
        bound_datasets: bound,
    })
}

fn annotate_pool_roles(pools: &mut [Pool], props: &[(String, Property)]) {
    for (name, prop) in props {
        if let Property::ZbootRole(role) = prop
            && let Some(p) = pools.iter_mut().find(|p| &p.name == name)
        {
            p.role = Some(*role);
        }
    }
}

/// Extract the BE list and the bound-dataset list from a flat property bag.
///
/// Datasets with `zboot:be=true` become BEs; their other props (`origin`,
/// `mountpoint`, `canmount`, `zboot:created-by`) are folded in from the
/// same bag. Datasets with `zboot:attached-to` set become bound datasets.
fn bes_and_bound_from_props(
    datasets: &[String],
    props: &[(String, Property)],
) -> (Vec<BootEnvironment>, Vec<BoundDataset>) {
    use std::collections::HashMap;

    #[derive(Default)]
    struct Acc {
        is_be: bool,
        origin: Option<SnapshotRef>,
        mountpoint: Option<Mountpoint>,
        canmount: Option<Canmount>,
        created_by: Option<String>,
        bound_to: Option<BoundList>,
    }

    let mut by_ds: HashMap<&str, Acc> = datasets
        .iter()
        .map(|d| (d.as_str(), Acc::default()))
        .collect();

    for (name, prop) in props {
        let Some(acc) = by_ds.get_mut(name.as_str()) else {
            continue;
        };
        match prop {
            Property::ZbootBe(b) => acc.is_be = *b,
            Property::Origin(o) => acc.origin.clone_from(o),
            Property::Mountpoint(m) => acc.mountpoint = Some(m.clone()),
            Property::Canmount(c) => acc.canmount = Some(*c),
            Property::ZbootCreatedBy(s) => acc.created_by = Some(s.clone()),
            Property::ZbootAttachedTo(bl) => acc.bound_to = Some(bl.clone()),
            _ => {}
        }
    }

    let mut bes = Vec::new();
    let mut bound = Vec::new();

    // Iterate `datasets` (not the HashMap) so output order is deterministic
    // — `zfs list` already sorts by name, and we want `status` output to
    // match for golden-string tests.
    for ds in datasets {
        let Some(acc) = by_ds.get(ds.as_str()) else {
            continue;
        };
        if acc.is_be {
            let (pool, name) = split_dataset_pool_and_name(ds);
            // `BootEnvironment` is `#[non_exhaustive]`; use the
            // builder + field-set pattern rather than a struct literal.
            let mut new_be = BootEnvironment::new(pool, name);
            new_be.dataset.clone_from(ds);
            new_be.origin.clone_from(&acc.origin);
            new_be.created_by.clone_from(&acc.created_by);
            new_be.mountpoint.clone_from(&acc.mountpoint);
            new_be.canmount = acc.canmount;
            bes.push(new_be);
        }
        if let Some(bl) = &acc.bound_to
            && !bl.is_empty()
        {
            bound.push(BoundDataset {
                dataset: ds.clone(),
                bound_to: bl.clone(),
            });
        }
    }

    (bes, bound)
}

/// Split `pool/some/path/leaf` into `(pool, leaf)`.
///
/// ZFS dataset names always start with the pool name and use `/` as a
/// separator. The "leaf" is the last component; the pool is the first.
fn split_dataset_pool_and_name(dataset: &str) -> (&str, &str) {
    let pool = dataset.split('/').next().unwrap_or(dataset);
    let name = dataset.rsplit('/').next().unwrap_or(dataset);
    (pool, name)
}

// ---------------------------------------------------------------------------
// Human renderer
// ---------------------------------------------------------------------------

pub fn render_human(snapshot: &StateSnapshot, out: &mut impl Write) -> Result<()> {
    render_booted(out);
    render_pools(snapshot, out)?;
    render_forest(snapshot, out)?;
    render_orphans(snapshot, out)?;
    Ok(())
}

/// Best-effort: print the currently-running root from /proc/self/mounts.
/// Falls back to silence if unavailable (e.g., non-Linux build host
/// running tests). The point of this line is to tell the operator
/// "you are here" — distinct from any `bootfs` pointer in the pools
/// section below.
fn render_booted(out: &mut impl Write) {
    if let Ok(ds) = crate::zfs_ops::discover_booted_dataset() {
        let _ = writeln!(out, "Booted: {ds}");
    }
}

fn render_pools(snapshot: &StateSnapshot, out: &mut impl Write) -> Result<()> {
    writeln!(out, "Pools:")?;
    if snapshot.pools.is_empty() {
        writeln!(out, "  (none)")?;
        return Ok(());
    }
    for p in &snapshot.pools {
        let role = p.role.map_or("-", role_label);
        let bootfs = p.bootfs.as_deref().unwrap_or("-");
        writeln!(out, "  {}  role={}  bootfs={}", p.name, role, bootfs)?;
    }
    Ok(())
}

fn render_forest(snapshot: &StateSnapshot, out: &mut impl Write) -> Result<()> {
    writeln!(out)?;
    writeln!(out, "Boot environments:")?;
    if snapshot.forest.is_empty() {
        writeln!(out, "  (none)")?;
        return Ok(());
    }

    // Group by pool for stable output. Within a pool: render each root
    // BE and recurse via `children_of`.
    let mut pools: Vec<&str> = snapshot
        .forest
        .bes
        .iter()
        .map(|b| b.pool.as_str())
        .collect();
    pools.sort_unstable();
    pools.dedup();

    for pool in pools {
        writeln!(out, "  pool {pool}:")?;
        // Roots restricted to this pool.
        let mut roots: Vec<&BootEnvironment> = snapshot
            .forest
            .roots()
            .into_iter()
            .filter(|be| be.pool == pool)
            .collect();
        roots.sort_by(|a, b| a.name.cmp(&b.name));

        let last_idx = roots.len().saturating_sub(1);
        for (i, root) in roots.iter().enumerate() {
            let is_last = i == last_idx;
            render_be_node(snapshot, root, "    ", is_last, out)?;
        }
    }

    Ok(())
}

fn render_be_node(
    snapshot: &StateSnapshot,
    be: &BootEnvironment,
    prefix: &str,
    is_last: bool,
    out: &mut impl Write,
) -> Result<()> {
    let connector = if is_last { "└── " } else { "├── " };
    let active_marker = active_marker_for(snapshot, be);
    let rw_marker = rw_marker_for(&be.dataset);
    let primary_marker = primary_marker_for(&be.dataset);
    writeln!(
        out,
        "{prefix}{connector}{active_marker}{}{rw_marker}{primary_marker}",
        be.name
    )?;

    let child_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });

    // dataset path + origin (origin shown indented under the BE).
    writeln!(out, "{child_prefix}    dataset: {}", be.dataset)?;
    if let Some(origin) = &be.origin {
        writeln!(out, "{child_prefix}    origin:  {}", origin.render())?;
    }
    if let Some(line) = render_mirror_line(&be.dataset) {
        writeln!(out, "{child_prefix}    mirror:  {line}")?;
    }
    if let Some(mp) = &be.mountpoint {
        writeln!(
            out,
            "{child_prefix}    mountpoint: {}",
            render_mountpoint(mp)
        )?;
    }
    if let Some(cm) = be.canmount {
        writeln!(out, "{child_prefix}    canmount: {}", render_canmount(cm))?;
    }

    // Bound datasets attached to this BE.
    let key = BoundKey::new(be.pool.clone(), be.name.clone());
    let bound_for: Vec<&BoundDataset> = snapshot
        .bound_datasets
        .iter()
        .filter(|bd| bd.bound_to.contains(&key))
        .collect();
    if !bound_for.is_empty() {
        writeln!(out, "{child_prefix}    bound:")?;
        for bd in bound_for {
            let shared_with: Vec<String> = bd
                .bound_to
                .0
                .iter()
                .filter(|k| *k != &key)
                .map(BoundKey::render)
                .collect();
            let suffix = if shared_with.is_empty() {
                String::new()
            } else {
                format!(" (shared with {})", shared_with.join(", "))
            };
            writeln!(out, "{child_prefix}      - {}{}", bd.dataset, suffix)?;
        }
    }

    // Children (BEs whose origin's dataset == be.dataset).
    let mut children = snapshot.forest.children_of(&be.dataset);
    children.sort_by(|a, b| a.name.cmp(&b.name));
    let last_idx = children.len().saturating_sub(1);
    for (i, child) in children.iter().enumerate() {
        let child_is_last = i == last_idx;
        render_be_node(snapshot, child, &child_prefix, child_is_last, out)?;
    }
    Ok(())
}

fn render_orphans(snapshot: &StateSnapshot, out: &mut impl Write) -> Result<()> {
    let extant_be_keys: Vec<BoundKey> = snapshot
        .forest
        .bes
        .iter()
        .map(|be| BoundKey::new(be.pool.clone(), be.name.clone()))
        .collect();
    let orphans: Vec<&BoundDataset> = snapshot
        .bound_datasets
        .iter()
        .filter(|bd| !bd.bound_to.0.iter().any(|k| extant_be_keys.contains(k)))
        .collect();

    if orphans.is_empty() {
        return Ok(());
    }

    writeln!(out)?;
    writeln!(out, "Orphans:")?;
    writeln!(
        out,
        "  (datasets whose `zboot:attached-to` references no extant BE — \
         remove with `zfs destroy` if no longer needed)"
    )?;
    for bd in orphans {
        let stale: Vec<String> = bd.bound_to.0.iter().map(BoundKey::render).collect();
        writeln!(out, "  [!] {} (stale: {})", bd.dataset, stale.join(","))?;
    }
    Ok(())
}

fn active_marker_for(snapshot: &StateSnapshot, be: &BootEnvironment) -> &'static str {
    let active = snapshot
        .pools
        .iter()
        .find(|p| p.name == be.pool)
        .and_then(|p| p.bootfs.as_deref())
        == Some(be.dataset.as_str());
    if active { "* " } else { "  " }
}

/// `[primary]` / `[mirror]` after `[rw]/[ro]`, reflecting `zboot:primary`.
/// Unpaired BEs (no `zboot:mirror`) show neither marker. Best-effort
/// — shells out, returns "" on failure.
fn primary_marker_for(dataset: &str) -> &'static str {
    // Show marker only when there's a paired peer; otherwise the
    // primary/mirror distinction is moot.
    let paired = crate::zfs_ops::read_pair_pointer(dataset)
        .ok()
        .flatten()
        .is_some();
    if !paired {
        return "";
    }
    match crate::zfs_ops::dataset_property(dataset, "zboot:primary")
        .ok()
        .as_deref()
    {
        Some("on") => " [primary]",
        Some("off") => " [mirror]",
        _ => "",
    }
}

/// `[rw]` / `[ro]` after the BE name, reflecting the native `readonly`
/// property. Shell-outs to `zfs get`; returns "" on any failure so
/// status display is robust against unimported pools or missing
/// datasets.
fn rw_marker_for(dataset: &str) -> &'static str {
    match crate::zfs_ops::dataset_property(dataset, "readonly")
        .ok()
        .as_deref()
    {
        Some("on") => " [ro]",
        Some("off") => " [rw]",
        _ => "",
    }
}

/// The `mirror: <peer> [marker]` line for a BE. Returns `None` if the
/// BE is unpaired (skip the line entirely; renders cleaner than `-`).
/// Shell-outs at render time — paired BEs are a handful, so the cost
/// is bounded.
fn render_mirror_line(dataset: &str) -> Option<String> {
    let peer = crate::zfs_ops::read_pair_pointer(dataset).ok().flatten()?;
    let peer_ds = peer.render();

    let local_guids = crate::zfs_ops::snapshot_guid_set(dataset).unwrap_or_default();
    let peer_exists = crate::zfs_ops::dataset_exists(&peer_ds).unwrap_or(false);
    let peer_guids = if peer_exists {
        Some(crate::zfs_ops::snapshot_guid_set(&peer_ds).unwrap_or_default())
    } else {
        // Distinguish "dataset gone (target-missing)" from "pool not
        // imported": `dataset_exists` returns Ok(false) for both, so
        // probe for the pool's presence to disambiguate.
        let peer_pool = peer.pool.as_str();
        let pool_present = crate::zfs_ops::pool_property(peer_pool, "name").is_ok();
        if pool_present { Some(std::collections::BTreeSet::new()) } else { None }
    };

    let status = zboot_core::PairStatus::from_guids(&local_guids, peer_guids.as_ref(), peer_exists);
    let dirty = crate::zfs_ops::dirty_bytes_since_latest(dataset);
    Some(format!("{peer_ds} {}", status.render(dirty)))
}

fn render_mountpoint(m: &Mountpoint) -> String {
    match m {
        Mountpoint::None => "none".into(),
        Mountpoint::Legacy => "legacy".into(),
        Mountpoint::Path(p) => p.clone(),
        // `Mountpoint` is `#[non_exhaustive]`; a future variant degrades
        // gracefully here rather than crashing `status`.
        _ => "?".into(),
    }
}

fn render_canmount(c: Canmount) -> &'static str {
    match c {
        Canmount::On => "on",
        Canmount::Off => "off",
        Canmount::Noauto => "noauto",
        _ => "?",
    }
}

fn role_label(role: PoolRole) -> &'static str {
    match role {
        PoolRole::Root => "root",
        _ => "?",
    }
}

// ===========================================================================
// Tests — human renderer only; pure-data, no I/O.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(name: &str, role: Option<PoolRole>, bootfs: Option<&str>) -> Pool {
        let mut p = Pool::new(name);
        p.role = role;
        p.bootfs = bootfs.map(str::to_owned);
        p.guid = Some(123_456_789);
        p
    }

    fn be(pool: &str, name: &str, origin: Option<&str>) -> BootEnvironment {
        let mut b = BootEnvironment::new(pool, name);
        b.origin = origin.and_then(SnapshotRef::parse);
        b
    }

    fn bound(dataset: &str, bound_to: &str) -> BoundDataset {
        BoundDataset {
            dataset: dataset.into(),
            bound_to: BoundList::parse(bound_to).unwrap(),
        }
    }

    fn render_string(snapshot: &StateSnapshot) -> String {
        let mut buf = Vec::new();
        render_human(snapshot, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    // --- empty case ---------------------------------------------------------

    #[test]
    fn empty_snapshot_renders_pools_and_bes_sections() {
        let s = render_string(&StateSnapshot::default());
        assert!(s.contains("Pools:\n  (none)"), "got: {s}");
        assert!(s.contains("Boot environments:\n  (none)"), "got: {s}");
        assert!(
            !s.contains("Orphans:"),
            "no orphans section when empty: {s}"
        );
    }

    // --- fresh: one pool, one BE, no orphans --------------------------------

    fn fresh_snapshot() -> StateSnapshot {
        StateSnapshot {
            pools: vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))],
            forest: Forest::from_origins(vec![be("rpool", "be1", None)]),
            bound_datasets: vec![],
        }
    }

    #[test]
    fn fresh_renders_active_marker() {
        let s = render_string(&fresh_snapshot());
        assert!(s.contains("role=root"), "{s}");
        assert!(s.contains("bootfs=rpool/ROOT/be1"), "{s}");
        // Active BE marker.
        assert!(s.contains("* be1") || s.contains("*be1"), "{s}");
        assert!(s.contains("dataset: rpool/ROOT/be1"), "{s}");
    }

    // --- forked: BE1 + BE2 (cloned) -----------------------------------------

    fn forked_snapshot() -> StateSnapshot {
        StateSnapshot {
            pools: vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))],
            forest: Forest::from_origins(vec![
                be("rpool", "be1", None),
                be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
            ]),
            bound_datasets: vec![],
        }
    }

    #[test]
    fn forked_origin_shown_in_human_output() {
        let s = render_string(&forked_snapshot());
        assert!(
            s.contains("origin:  rpool/ROOT/be1@snap1"),
            "expected origin under be2, got:\n{s}"
        );
    }

    #[test]
    fn forked_human_uses_tree_connectors() {
        let s = render_string(&forked_snapshot());
        // BE2 is a child of BE1 — should appear nested via connector.
        assert!(
            s.contains("├── ") || s.contains("└── "),
            "expected tree connector chars, got:\n{s}"
        );
    }

    // --- bound: /home bound to BE1 only -------------------------------------

    fn bound_snapshot() -> StateSnapshot {
        StateSnapshot {
            pools: vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))],
            forest: Forest::from_origins(vec![be("rpool", "be1", None)]),
            bound_datasets: vec![bound("rpool/home", "rpool:be1")],
        }
    }

    #[test]
    fn bound_human_lists_bound_dataset_under_be() {
        let s = render_string(&bound_snapshot());
        assert!(s.contains("bound:"), "{s}");
        assert!(s.contains("- rpool/home"), "{s}");
        assert!(!s.contains("Orphans:"), "{s}");
    }

    // --- shared-bound: /home bound to BE1+BE2 -------------------------------

    fn shared_bound_snapshot() -> StateSnapshot {
        StateSnapshot {
            pools: vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))],
            forest: Forest::from_origins(vec![
                be("rpool", "be1", None),
                be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
            ]),
            bound_datasets: vec![bound("rpool/home", "rpool:be1,rpool:be2")],
        }
    }

    #[test]
    fn shared_bound_human_marks_share() {
        let s = render_string(&shared_bound_snapshot());
        assert!(
            s.contains("shared with"),
            "expected `shared with` annotation, got:\n{s}"
        );
    }

    // --- orphan -------------------------------------------------------------

    #[test]
    fn orphan_surfaces_when_all_bound_to_keys_stale() {
        // /home was bound to be-gone, which no longer exists.
        let snapshot = StateSnapshot {
            pools: vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))],
            forest: Forest::from_origins(vec![be("rpool", "be1", None)]),
            bound_datasets: vec![bound("rpool/home", "rpool:be-gone")],
        };
        let s = render_string(&snapshot);
        assert!(s.contains("Orphans:"), "{s}");
        assert!(s.contains("[!] rpool/home"), "{s}");
    }

    #[test]
    fn dataset_with_one_live_one_dead_key_is_not_an_orphan() {
        let snapshot = StateSnapshot {
            pools: vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))],
            forest: Forest::from_origins(vec![be("rpool", "be1", None)]),
            bound_datasets: vec![bound("rpool/home", "rpool:be1,rpool:dead")],
        };
        let s = render_string(&snapshot);
        assert!(!s.contains("Orphans:"), "{s}");
    }

    // --- multi-pool ---------------------------------------------------------

    #[test]
    fn multi_pool_lists_both_pools_with_role_root() {
        let snapshot = StateSnapshot {
            pools: vec![
                pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1")),
                pool("rpool2", Some(PoolRole::Root), None),
            ],
            forest: Forest::from_origins(vec![be("rpool", "be1", None), be("rpool2", "be1", None)]),
            bound_datasets: vec![],
        };
        let s = render_string(&snapshot);
        assert!(s.contains("rpool"), "{s}");
        assert!(s.contains("rpool2"), "{s}");
        assert!(s.contains("pool rpool:"), "{s}");
        assert!(s.contains("pool rpool2:"), "{s}");
    }

    // --- helpers ------------------------------------------------------------

    #[test]
    fn split_dataset_pool_and_name_basic() {
        assert_eq!(split_dataset_pool_and_name("rpool"), ("rpool", "rpool"));
        assert_eq!(
            split_dataset_pool_and_name("rpool/ROOT/be1"),
            ("rpool", "be1")
        );
        assert_eq!(split_dataset_pool_and_name("rpool/home"), ("rpool", "home"));
    }
}
