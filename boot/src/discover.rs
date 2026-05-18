//! Discovery — read-only enumeration of every pool tagged
//! `zboot:role=root` and the BE datasets inside.
//!
//! All pools are imported read-only by `preinit` before this runs;
//! the property-reading half here doesn't mutate state — `zpool get`,
//! `zfs get`, and `zfs list` cover everything we need.
//!
//! ## Parser strategy
//!
//! Reuses `zboot-core` parsers (`parse_zpool_list`, `parse_zfs_get`)
//! for totality + tab-grammar awareness. Assembled in three waves:
//!
//! 1. `zpool list -Hp -o name,bootfs,guid` → `Vec<Pool>`.
//! 2. `zpool get -Hp -o name,property,value zboot:role …` → annotate role.
//! 3. For each root pool: `zfs list -Hp -r -o name -t filesystem <pool>`
//!    plus `zfs get -Hp -o name,property,value origin,zboot:be,zboot:attached-to,
//!    zboot:bound-mountpoint,zboot:created-by …` → `Vec<BeRecord>`.
//!
//! Restricting wave 3 to root pools keeps boot-time work bounded to
//! `O(root pools)` and avoids reading content datasets the bootloader
//! has no business looking at.
//!
//! Cargo unit tests drive `assemble` against pre-recorded `zfs`/`zpool`
//! text — the I/O wrapper is a thin shell, easy to swap in tests.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};

use zboot_core::{
    BootEnvironment, BoundKey, BoundList, Forest, Pool, PoolRole, Property, SnapshotRef,
    parse_zfs_get, parse_zpool_list,
};

// ---------------------------------------------------------------------------
// Internal data model
// ---------------------------------------------------------------------------
//
// Names retain the `Json` / `V1` suffix from when these doubled as a
// JSON envelope (the `zboot-boot discover` verb has been dropped). They
// are pure Rust data now — the menu's only consumer.

/// Top-level discovery payload — pools + their BEs with kernels.
#[derive(Debug, Clone)]
pub struct DiscoverV1 {
    pub pools: Vec<PoolJson>,
    pub bes: Vec<BeJson>,
}

#[derive(Debug, Clone)]
pub struct PoolJson {
    pub name: String,
    /// `"root"` (since we filter to root-role pools); kept as a field so the
    /// shape is forward-compatible if we widen later.
    pub role: String,
    pub bootfs: Option<String>,
    pub guid: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BeJson {
    pub pool: String,
    /// Full dataset path, e.g. `rpool/ROOT/be1`.
    pub dataset: String,
    /// Last component, e.g. `be1`.
    pub name: String,
    /// `dataset@name` of the clone parent, or null if a root BE.
    pub origin: Option<String>,
    /// True when this BE's dataset == its pool's `bootfs` — the canonical
    /// "this is what reboot would land on" marker per DESIGN.md.
    pub active: bool,
    /// True when the dataset has `readonly=on` — the mirror safety rail.
    /// Surfaced in the boot menu so the operator can tell at a glance
    /// "this BE is a mirror replica" before selecting it.
    pub readonly: bool,
    /// Bound-list as `pool:be` strings — included so the menu can show
    /// "BE2 shares /home with BE1" without an extra round trip. Empty list
    /// for unbound BE datasets (the common case for a fresh BE).
    pub bound_to: Vec<String>,
    /// Kernels discovered in `<be>/boot/`. Empty if the BE could not be
    /// mounted r/o for inspection.
    pub kernels: Vec<KernelEntry>,
    /// Where the BE was mounted r/o for kernel enumeration. Reused by
    /// `kexec::plan` so it doesn't have to mount again. `None` if mount
    /// failed.
    pub mount_root: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KernelEntry {
    /// `vmlinuz`, `vmlinuz-6.13.0-amd64`, etc. — basename only.
    pub vmlinuz: String,
    /// Matching `initrd.img` / `initrd.img-...` for this kernel.
    pub initrd: Option<String>,
    /// True if `<be>/boot/vmlinuz` symlink targets this entry.
    pub default: bool,
}

// ---------------------------------------------------------------------------
// Collection entry point
// ---------------------------------------------------------------------------

/// Bridge to the menu's `(Forest, active_set)` model.
pub fn collect_forest() -> Result<(Forest, Vec<String>)> {
    let payload = collect()?;
    Ok(forest_from_payload(&payload))
}

/// Full discover payload (kernels + mount roots) for the menu.
pub fn collect_for_menu() -> Result<DiscoverV1> {
    collect()
}

/// Pure projection from `DiscoverV1` into the menu's data model. Split
/// out so unit tests can drive it against synthesized payloads without
/// shelling out to `zfs`/`zpool`.
fn forest_from_payload(payload: &DiscoverV1) -> (Forest, Vec<String>) {
    let bes: Vec<BootEnvironment> = payload
        .bes
        .iter()
        .map(|b| {
            let mut be = BootEnvironment::new(&b.pool, &b.name);
            // Honour the dataset path emitted by discover even if it
            // doesn't match the canonical `pool/ROOT/name` shape — the
            // bootloader's job is to render what's actually on disk,
            // not to enforce naming conventions.
            be.dataset.clone_from(&b.dataset);
            be.origin = b.origin.as_deref().and_then(SnapshotRef::parse);
            be
        })
        .collect();

    // Active set = every BE flagged active in the discover payload.
    // Equivalent to "every pool's bootfs that points at a known BE",
    // but using the pre-computed flag avoids re-deriving it here.
    let active: Vec<String> = payload
        .bes
        .iter()
        .filter(|b| b.active)
        .map(|b| b.dataset.clone())
        .collect();

    (Forest::from_origins(bes), active)
}

// ---------------------------------------------------------------------------
// Collection — spawn `zpool` / `zfs`, then assemble.
// ---------------------------------------------------------------------------

/// Properties pulled per dataset to classify BEs and gather origin / bound-list.
/// Kept in a single `zfs get` call for cheapness — multi-prop multi-dataset
/// queries are one TXG-walk inside ZFS.
const ZFS_PROPS: &str =
    "origin,zboot:be,zboot:attached-to,zboot:bound-mountpoint,zboot:created-by,readonly";

fn collect() -> Result<DiscoverV1> {
    // Wave 1: enumerate every pool we can see.
    let pools_text = run_cmd("zpool", &["list", "-Hp", "-o", "name,bootfs,guid"])?;
    let mut pools = parse_zpool_list(&pools_text).context("parsing `zpool list`")?;

    // Wave 2: annotate `zboot:role` so we can filter to root pools.
    if !pools.is_empty() {
        let pool_names: Vec<&str> = pools.iter().map(|p| p.name.as_str()).collect();
        let mut args: Vec<&str> = vec!["get", "-Hp", "-o", "name,property,value", "zboot:role"];
        args.extend(pool_names.iter().copied());
        let role_text = run_cmd("zpool", &args)?;
        let role_props = parse_zfs_get(&role_text).context("parsing `zpool get zboot:role`")?;
        annotate_pool_roles(&mut pools, &role_props);
    }

    // Filter to root-role pools — boot-menu is only interested in pools that
    // can actually host a BE.
    let root_pools: Vec<Pool> = pools
        .into_iter()
        .filter(|p| matches!(p.role, Some(PoolRole::Root)))
        .collect();

    // Wave 3: for each root pool, enumerate filesystem datasets + their props.
    let mut be_records: Vec<BeRecord> = Vec::new();
    for pool in &root_pools {
        let datasets = list_filesystems_in(&pool.name)?;
        if datasets.is_empty() {
            continue;
        }
        let mut args: Vec<&str> = vec!["get", "-Hp", "-o", "name,property,value", ZFS_PROPS];
        args.extend(datasets.iter().map(String::as_str));
        let props_text = run_cmd("zfs", &args)?;
        let props = parse_zfs_get(&props_text)
            .with_context(|| format!("parsing `zfs get` for {}", pool.name))?;
        be_records.extend(extract_bes(&pool.name, &datasets, &props));
    }

    let mut payload = assemble(&root_pools, &be_records);
    populate_be_kernels(&mut payload);
    Ok(payload)
}

/// Mount each BE r/o (PID-1 only) and enumerate its `/boot/vmlinuz*` so
/// the menu can render a per-BE kernel tree. On dev-host (non-PID-1)
/// this is a no-op — the bootloader stage is the only place mounting
/// makes sense, and the menu's fake-data fallback already covers UX
/// iteration there.
fn populate_be_kernels(payload: &mut DiscoverV1) {
    if nix::unistd::getpid().as_raw() != 1 {
        return;
    }
    for be in &mut payload.bes {
        match ensure_be_mounted_ro(&be.dataset, &be.name) {
            Ok(mount) => {
                let boot_dir = mount.join("boot");
                be.kernels = enumerate_kernels(&boot_dir);
                be.mount_root = mount.to_str().map(str::to_owned);
            }
            Err(e) => {
                eprintln!(
                    "zboot-boot/discover: mount {} for kernel enum failed: {e:#}",
                    be.dataset,
                );
            }
        }
    }
}

/// Mount `dataset` read-only at `/zboot/be-mount/<name>` if it isn't
/// already. Idempotent: a second call with the same arguments returns
/// the existing mountpoint without re-mounting (detected by checking
/// `<mountpoint>/boot` exists as a directory).
fn ensure_be_mounted_ro(dataset: &str, name: &str) -> Result<PathBuf> {
    let target = PathBuf::from(format!("/zboot/be-mount/{name}"));
    if target.join("boot").is_dir() {
        return Ok(target);
    }
    std::fs::create_dir_all(&target).with_context(|| format!("mkdir {}", target.display()))?;
    let target_str = target.to_str().context("non-utf8 mount path")?;
    let status = Command::new("/bin/mount")
        .args(["-t", "zfs", "-o", "ro,zfsutil", dataset, target_str])
        .status()
        .context("spawn mount")?;
    if !status.success() {
        anyhow::bail!(
            "mount {} -> {}: rc={:?}",
            dataset,
            target.display(),
            status.code(),
        );
    }
    Ok(target)
}

/// List `vmlinuz*` files in `boot_dir`, pair each with its initrd, and
/// flag the entry pointed at by the `vmlinuz` symlink as `default`.
///
/// "vmlinuz files" here means anything whose filename starts with
/// `vmlinuz`: `vmlinuz` (symlink), `vmlinuz-X.Y.Z` (regular), and the
/// debian `vmlinuz.old` previous-kernel pointer. Companion files
/// (`.sig`, `.dpkg-old`, etc.) are filtered out by `kexec.rs`'s same
/// rule for consistency.
///
/// Initrd pairing is filename-driven:
/// - `vmlinuz`            → `initrd.img`
/// - `vmlinuz.old`        → `initrd.img.old`
/// - `vmlinuz-<ver>`      → `initrd.img-<ver>`
///
/// `default` flag: read `<boot_dir>/vmlinuz` symlink target; the entry
/// whose filename equals the basename of that target is the default.
/// If there's no symlink (or read fails), no entry is flagged default
/// here — the kexec path still falls through to the `vmlinuz` entry by
/// filename.
pub fn enumerate_kernels(boot_dir: &Path) -> Vec<KernelEntry> {
    // Skip-list keeps dpkg leftovers (`.sig`, `.dpkg-old`, etc.) from
    // surfacing as bootable kernels.
    const BAD_EXTS: &[&str] = &[".sig", ".bak", ".dpkg-old", ".dpkg-new"];

    let Ok(entries) = std::fs::read_dir(boot_dir) else {
        return Vec::new();
    };

    let mut filenames: Vec<String> = Vec::new();
    for ent in entries.flatten() {
        let name = ent.file_name();
        let Some(s) = name.to_str() else { continue };
        if !s.starts_with("vmlinuz") {
            continue;
        }
        if BAD_EXTS.iter().any(|e| s.ends_with(e)) {
            continue;
        }
        filenames.push(s.to_owned());
    }
    // Stable order: `vmlinuz`, then `vmlinuz.old`, then `vmlinuz-*`
    // sorted descending so the newest version appears first when both
    // the symlink and a versioned file are present.
    filenames.sort_by_key(|name| kernel_sort_key(name));

    // Resolve the symlink target's basename so we can flag `default`.
    let default_basename: Option<String> = std::fs::read_link(boot_dir.join("vmlinuz"))
        .ok()
        .and_then(|p| p.file_name().and_then(|s| s.to_str().map(str::to_owned)));

    filenames
        .into_iter()
        .map(|vmlinuz| {
            let initrd = pair_initrd(boot_dir, &vmlinuz);
            // The default annotation belongs on the file the symlink
            // *points at* (e.g. `vmlinuz-6.13.0`), not on the symlink
            // itself. Falls back to the `vmlinuz` symlink when no target
            // can be resolved (fresh tempdir, missing read_link).
            let default = match default_basename.as_deref() {
                Some(target) => vmlinuz == target,
                None => vmlinuz == "vmlinuz",
            };
            KernelEntry {
                vmlinuz,
                initrd,
                default,
            }
        })
        .collect()
}

/// Map a vmlinuz filename to its initrd filename, returning `Some` only
/// if the paired file actually exists under `boot_dir`.
fn pair_initrd(boot_dir: &Path, vmlinuz: &str) -> Option<String> {
    let candidate = if vmlinuz == "vmlinuz" {
        "initrd.img".to_owned()
    } else if vmlinuz == "vmlinuz.old" {
        "initrd.img.old".to_owned()
    } else if let Some(suffix) = vmlinuz.strip_prefix("vmlinuz-") {
        format!("initrd.img-{suffix}")
    } else {
        return None;
    };
    if boot_dir.join(&candidate).exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Sort key for kernel filenames: `vmlinuz` first (key 0), then
/// `vmlinuz.old` (key 1), then `vmlinuz-<ver>` (key 2 + reverse-sorted
/// suffix so newest version is first within that group).
fn kernel_sort_key(filename: &str) -> (u8, std::cmp::Reverse<String>) {
    if filename == "vmlinuz" {
        (0, std::cmp::Reverse(String::new()))
    } else if filename == "vmlinuz.old" {
        (1, std::cmp::Reverse(String::new()))
    } else if let Some(suffix) = filename.strip_prefix("vmlinuz-") {
        (2, std::cmp::Reverse(suffix.to_owned()))
    } else {
        (3, std::cmp::Reverse(filename.to_owned()))
    }
}

/// `zfs list -Hp -r -o name -t filesystem <pool>` — flat list of every
/// filesystem dataset (no snapshots, no volumes) under `pool`.
fn list_filesystems_in(pool: &str) -> Result<Vec<String>> {
    let text = run_cmd(
        "zfs",
        &["list", "-Hp", "-r", "-o", "name", "-t", "filesystem", pool],
    )?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

fn run_cmd(prog: &str, args: &[&str]) -> Result<String> {
    // PID 1 starts with no PATH from the kernel cmdline. `Command::new`
    // does program lookup against the *parent's* env (not the env we'd
    // set via `.env()` — that's the child's only). And the workspace
    // lint forbids `unsafe`, so we can't `set_var("PATH", ...)`.
    //
    // Resolve to an absolute path explicitly. The build pipeline
    // (`boot/build.sh` + `boot/lddtree.sh`) stages binaries at
    // `/usr/sbin/<prog>` and symlinks them at `/sbin/<prog>`; check both
    // for resilience.
    let resolved = resolve_bin(prog).with_context(|| format!("locating `{prog}` in the initrd"))?;
    let out = Command::new(&resolved)
        .args(args)
        .output()
        .with_context(|| format!("spawning `{} {}`", resolved.display(), args.join(" ")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return Err(anyhow!(
            "`{} {}` exited rc={:?}: {}",
            prog,
            args.join(" "),
            out.status.code(),
            stderr.trim()
        ));
    }
    String::from_utf8(out.stdout).with_context(|| format!("non-utf8 output from `{prog}`"))
}

/// Resolve a bare program name (`zpool`, `zfs`, …) to its absolute path
/// inside the initrd. Bypasses PATH lookup so we don't depend on PID 1
/// having a sane environment.
fn resolve_bin(prog: &str) -> Result<std::path::PathBuf> {
    for cand in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        let p = std::path::Path::new(cand).join(prog);
        if p.exists() {
            return Ok(p);
        }
    }
    Err(anyhow!(
        "`{prog}` not found in /usr/sbin, /sbin, /usr/bin, or /bin"
    ))
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

// ---------------------------------------------------------------------------
// Pure-data assembly — unit-tested below.
// ---------------------------------------------------------------------------

/// Per-dataset extract of the props relevant to a BE record. Dataset is *not*
/// guaranteed to be a BE here — caller filters by `is_be`.
#[derive(Debug, Clone)]
struct BeRecord {
    pool: String,
    dataset: String,
    is_be: bool,
    origin: Option<String>,
    bound_to: BoundList,
    readonly: bool,
}

/// Walk a flat `(name, prop)` bag and emit one `BeRecord` per dataset. The
/// caller pre-filtered datasets to a single pool, so we tag every record with
/// that pool name.
fn extract_bes(pool: &str, datasets: &[String], props: &[(String, Property)]) -> Vec<BeRecord> {
    use std::collections::HashMap;

    #[derive(Default)]
    struct Acc {
        is_be: bool,
        origin: Option<String>,
        bound_to: BoundList,
        readonly: bool,
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
            Property::Origin(o) => acc.origin = o.as_ref().map(zboot_core::SnapshotRef::render),
            Property::ZbootAttachedTo(bl) => acc.bound_to = bl.clone(),
            // `readonly` is a native ZFS prop; the core parser surfaces it
            // via `Property::Other`. Value is "on" / "off"; anything else
            // (unset, "-") falls through as `false`.
            Property::Other { name: prop_name, value } if prop_name == "readonly" => {
                acc.readonly = value == "on";
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    // Iterate `datasets` (not the HashMap) so output order is deterministic
    // — matches `zfs list -r` ordering, which is sorted.
    for ds in datasets {
        let Some(acc) = by_ds.remove(ds.as_str()) else {
            continue;
        };
        out.push(BeRecord {
            pool: pool.to_owned(),
            dataset: ds.clone(),
            is_be: acc.is_be,
            origin: acc.origin,
            bound_to: acc.bound_to,
            readonly: acc.readonly,
        });
    }
    out
}

/// Project pools + records into the JSON envelope. Pure function — easy to
/// drive from cargo tests over recorded fixture text.
fn assemble(pools: &[Pool], records: &[BeRecord]) -> DiscoverV1 {
    let pools_json: Vec<PoolJson> = pools
        .iter()
        .map(|p| PoolJson {
            name: p.name.clone(),
            role: role_label(p.role).to_owned(),
            bootfs: p.bootfs.clone(),
            guid: p.guid,
        })
        .collect();

    let mut bes = Vec::new();
    for rec in records.iter().filter(|r| r.is_be) {
        // Active marker keys off this pool's bootfs property.
        let active = pools
            .iter()
            .find(|p| p.name == rec.pool)
            .and_then(|p| p.bootfs.as_deref())
            == Some(rec.dataset.as_str());

        let name = rec
            .dataset
            .rsplit('/')
            .next()
            .unwrap_or(&rec.dataset)
            .to_owned();

        bes.push(BeJson {
            pool: rec.pool.clone(),
            dataset: rec.dataset.clone(),
            name,
            origin: rec.origin.clone(),
            active,
            readonly: rec.readonly,
            bound_to: rec.bound_to.0.iter().map(BoundKey::render).collect(),
            kernels: Vec::new(),
            mount_root: None,
        });
    }

    DiscoverV1 {
        pools: pools_json,
        bes,
    }
}

fn role_label(role: Option<PoolRole>) -> &'static str {
    match role {
        Some(PoolRole::Root) => "root",
        // Filter upstream means we shouldn't hit this branch; surface
        // "?" rather than panic if a future variant slips through.
        _ => "?",
    }
}

// ===========================================================================
// Tests — pure data over recorded `zfs`/`zpool` output.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zboot_core::parse_zpool_list;

    fn pool(name: &str, role: Option<PoolRole>, bootfs: Option<&str>) -> Pool {
        let mut p = Pool::new(name);
        p.role = role;
        p.bootfs = bootfs.map(str::to_owned);
        p.guid = Some(42);
        p
    }

    // --- empty payload ------------------------------------------------------

    #[test]
    fn empty_payload_has_no_pools_or_bes() {
        let v1 = assemble(&[], &[]);
        assert!(v1.pools.is_empty());
        assert!(v1.bes.is_empty());
    }

    // --- annotate_pool_roles ------------------------------------------------

    #[test]
    fn annotate_pool_roles_sets_root() {
        let mut pools = vec![pool("rpool", None, None), pool("dpool", None, None)];
        let role_text = "rpool\tzboot:role\troot\n";
        let props = parse_zfs_get(role_text).unwrap();
        annotate_pool_roles(&mut pools, &props);
        assert_eq!(pools[0].role, Some(PoolRole::Root));
        assert_eq!(pools[1].role, None);
    }

    // --- extract_bes --------------------------------------------------------

    #[test]
    fn extract_bes_marks_be_dataset() {
        let datasets = vec![
            "rpool".to_owned(),
            "rpool/ROOT".to_owned(),
            "rpool/ROOT/be1".to_owned(),
        ];
        let text = "\
rpool/ROOT/be1\tzboot:be\ttrue
rpool/ROOT/be1\torigin\t-
rpool/ROOT/be1\tzboot:attached-to\t-
";
        let props = parse_zfs_get(text).unwrap();
        let recs = extract_bes("rpool", &datasets, &props);
        assert_eq!(recs.len(), 3);
        let be1 = recs.iter().find(|r| r.dataset == "rpool/ROOT/be1").unwrap();
        assert!(be1.is_be);
        assert_eq!(be1.origin, None);
        assert!(be1.bound_to.is_empty());
        // Container datasets remain not-BE.
        assert!(!recs.iter().find(|r| r.dataset == "rpool").unwrap().is_be);
    }

    #[test]
    fn extract_bes_captures_origin_and_bound_to() {
        let datasets = vec!["rpool/ROOT/be2".to_owned()];
        let text = "\
rpool/ROOT/be2\tzboot:be\ttrue
rpool/ROOT/be2\torigin\trpool/ROOT/be1@snap1
rpool/ROOT/be2\tzboot:attached-to\trpool:be1,rpool:be2
";
        let props = parse_zfs_get(text).unwrap();
        let recs = extract_bes("rpool", &datasets, &props);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert!(r.is_be);
        assert_eq!(r.origin.as_deref(), Some("rpool/ROOT/be1@snap1"));
        assert_eq!(r.bound_to.len(), 2);
    }

    // --- assemble: single BE ----------------------------------------------

    #[test]
    fn assemble_state_fresh_shape() {
        let pools = vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))];
        let records = vec![BeRecord {
            pool: "rpool".into(),
            dataset: "rpool/ROOT/be1".into(),
            is_be: true,
            origin: None,
            bound_to: BoundList::new(),
            readonly: false,
        }];
        let v1 = assemble(&pools, &records);
        assert_eq!(v1.pools.len(), 1);
        assert_eq!(v1.pools[0].role, "root");
        assert_eq!(v1.pools[0].bootfs.as_deref(), Some("rpool/ROOT/be1"));
        assert_eq!(v1.bes.len(), 1);
        assert!(v1.bes[0].active);
        assert!(v1.bes[0].origin.is_none());
        assert_eq!(v1.bes[0].name, "be1");
        assert!(v1.bes[0].bound_to.is_empty());
    }

    // --- assemble: two BEs with origin (clone of be1@snap1) ---------------

    #[test]
    fn assemble_state_forked_shape() {
        let pools = vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))];
        let records = vec![
            BeRecord {
                pool: "rpool".into(),
                dataset: "rpool/ROOT/be1".into(),
                is_be: true,
                origin: None,
                bound_to: BoundList::new(),
                readonly: false,
            },
            BeRecord {
                pool: "rpool".into(),
                dataset: "rpool/ROOT/be2".into(),
                is_be: true,
                origin: Some("rpool/ROOT/be1@snap1".into()),
                bound_to: BoundList::new(),
                readonly: false,
            },
        ];
        let v1 = assemble(&pools, &records);
        assert_eq!(v1.bes.len(), 2);
        let be1 = v1.bes.iter().find(|b| b.name == "be1").unwrap();
        let be2 = v1.bes.iter().find(|b| b.name == "be2").unwrap();
        assert!(be1.active);
        assert!(!be2.active);
        assert_eq!(be1.origin, None);
        assert_eq!(be2.origin.as_deref(), Some("rpool/ROOT/be1@snap1"));
    }

    // --- assemble: two pools, each role=root --------------------------------

    #[test]
    fn assemble_multi_slot_lists_both_pools() {
        let pools = vec![
            pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1")),
            pool("rpool2", Some(PoolRole::Root), Some("rpool2/ROOT/be1")),
        ];
        let records = vec![
            BeRecord {
                pool: "rpool".into(),
                dataset: "rpool/ROOT/be1".into(),
                is_be: true,
                origin: None,
                bound_to: BoundList::new(),
                readonly: false,
            },
            BeRecord {
                pool: "rpool2".into(),
                dataset: "rpool2/ROOT/be1".into(),
                is_be: true,
                origin: None,
                bound_to: BoundList::new(),
                readonly: false,
            },
        ];
        let v1 = assemble(&pools, &records);
        assert_eq!(v1.pools.len(), 2);
        assert!(v1.pools.iter().all(|p| p.role == "root"));
        assert_eq!(v1.bes.len(), 2);
        // Both BEs are active — each is its own pool's bootfs.
        assert!(v1.bes.iter().all(|b| b.active));
    }

    // --- assemble: drops non-BE rows ---------------------------------------

    #[test]
    fn assemble_skips_non_be_records() {
        let pools = vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))];
        let records = vec![
            BeRecord {
                pool: "rpool".into(),
                dataset: "rpool".into(),
                is_be: false,
                origin: None,
                bound_to: BoundList::new(),
                readonly: false,
            },
            BeRecord {
                pool: "rpool".into(),
                dataset: "rpool/ROOT".into(),
                is_be: false,
                origin: None,
                bound_to: BoundList::new(),
                readonly: false,
            },
            BeRecord {
                pool: "rpool".into(),
                dataset: "rpool/ROOT/be1".into(),
                is_be: true,
                origin: None,
                bound_to: BoundList::new(),
                readonly: false,
            },
        ];
        let v1 = assemble(&pools, &records);
        assert_eq!(v1.bes.len(), 1);
        assert_eq!(v1.bes[0].dataset, "rpool/ROOT/be1");
    }

    // --- assemble: bound_to surfaces in JSON ------------------------------

    #[test]
    fn assemble_bound_to_round_trip() {
        let pools = vec![pool("rpool", Some(PoolRole::Root), Some("rpool/ROOT/be1"))];
        let bound = BoundList::parse("rpool:be1,rpool:be2").unwrap();
        let records = vec![BeRecord {
            pool: "rpool".into(),
            dataset: "rpool/ROOT/be1".into(),
            is_be: true,
            origin: None,
            bound_to: bound,
            readonly: false,
        }];
        let v1 = assemble(&pools, &records);
        assert_eq!(v1.bes[0].bound_to, vec!["rpool:be1", "rpool:be2"]);
    }

    // --- end-to-end: parse zpool list + zfs get → assemble -----------------

    #[test]
    fn end_to_end_state_fresh_recorded_text() {
        // Recorded `zpool list -Hp -o name,bootfs,guid`:
        let pool_text = "rpool\trpool/ROOT/be1\t12345\n";
        let mut pools = parse_zpool_list(pool_text).unwrap();

        // Recorded `zpool get -Hp -o name,property,value zboot:role rpool`:
        let role_text = "rpool\tzboot:role\troot\n";
        let role_props = parse_zfs_get(role_text).unwrap();
        annotate_pool_roles(&mut pools, &role_props);

        // Recorded `zfs list -Hp -r -o name -t filesystem rpool`:
        let datasets = vec![
            "rpool".to_owned(),
            "rpool/ROOT".to_owned(),
            "rpool/ROOT/be1".to_owned(),
        ];
        // Recorded `zfs get -Hp -o name,property,value origin,zboot:be,zboot:attached-to,zboot:bound-mountpoint,zboot:created-by rpool rpool/ROOT rpool/ROOT/be1`:
        let zfs_text = "\
rpool/ROOT/be1\torigin\t-
rpool/ROOT/be1\tzboot:be\ttrue
rpool/ROOT/be1\tzboot:attached-to\t-
";
        let props = parse_zfs_get(zfs_text).unwrap();
        let records = extract_bes("rpool", &datasets, &props);

        let v1 = assemble(&pools, &records);
        assert_eq!(v1.pools.len(), 1);
        assert_eq!(v1.pools[0].role, "root");
        assert_eq!(v1.bes.len(), 1);
        assert!(v1.bes[0].active);
        assert!(v1.bes[0].origin.is_none());
    }

    // --- forest_from_payload: discover → menu bridge -----------------------

    #[test]
    fn forest_from_payload_state_fresh() {
        // One pool, one active BE, no origin.
        let payload = DiscoverV1 {
            pools: vec![PoolJson {
                name: "rpool".into(),
                role: "root".into(),
                bootfs: Some("rpool/ROOT/be1".into()),
                guid: Some(42),
            }],
            bes: vec![BeJson {
                pool: "rpool".into(),
                dataset: "rpool/ROOT/be1".into(),
                name: "be1".into(),
                origin: None,
                active: true,
                bound_to: vec![],
                readonly: false,
                kernels: Vec::new(),
                mount_root: None,
            }],
        };
        let (forest, active) = forest_from_payload(&payload);
        assert_eq!(forest.bes.len(), 1);
        assert_eq!(forest.bes[0].pool, "rpool");
        assert_eq!(forest.bes[0].name, "be1");
        assert_eq!(forest.bes[0].dataset, "rpool/ROOT/be1");
        assert!(forest.bes[0].origin.is_none());
        assert_eq!(active, vec!["rpool/ROOT/be1".to_owned()]);
    }

    #[test]
    fn forest_from_payload_carries_origin_lineage() {
        let payload = DiscoverV1 {
            pools: vec![PoolJson {
                name: "rpool".into(),
                role: "root".into(),
                bootfs: Some("rpool/ROOT/be1".into()),
                guid: None,
            }],
            bes: vec![
                BeJson {
                    pool: "rpool".into(),
                    dataset: "rpool/ROOT/be1".into(),
                    name: "be1".into(),
                    origin: None,
                    active: true,
                    bound_to: vec![],
                    readonly: false,
                    kernels: Vec::new(),
                    mount_root: None,
                },
                BeJson {
                    pool: "rpool".into(),
                    dataset: "rpool/ROOT/be2".into(),
                    name: "be2".into(),
                    origin: Some("rpool/ROOT/be1@snap1".into()),
                    active: false,
                    bound_to: vec![],
                    readonly: false,
                    kernels: Vec::new(),
                    mount_root: None,
                },
            ],
        };
        let (forest, active) = forest_from_payload(&payload);
        let be2 = forest
            .bes
            .iter()
            .find(|b| b.name == "be2")
            .expect("be2 in forest");
        assert_eq!(
            be2.origin.as_ref().map(SnapshotRef::render).as_deref(),
            Some("rpool/ROOT/be1@snap1")
        );
        assert_eq!(active, vec!["rpool/ROOT/be1".to_owned()]);
    }

    #[test]
    fn forest_from_payload_multi_slot_keeps_both_actives() {
        let payload = DiscoverV1 {
            pools: vec![
                PoolJson {
                    name: "rpool".into(),
                    role: "root".into(),
                    bootfs: Some("rpool/ROOT/be1".into()),
                    guid: None,
                },
                PoolJson {
                    name: "rpool2".into(),
                    role: "root".into(),
                    bootfs: Some("rpool2/ROOT/be1".into()),
                    guid: None,
                },
            ],
            bes: vec![
                BeJson {
                    pool: "rpool".into(),
                    dataset: "rpool/ROOT/be1".into(),
                    name: "be1".into(),
                    origin: None,
                    active: true,
                    bound_to: vec![],
                    readonly: false,
                    kernels: Vec::new(),
                    mount_root: None,
                },
                BeJson {
                    pool: "rpool2".into(),
                    dataset: "rpool2/ROOT/be1".into(),
                    name: "be1".into(),
                    origin: None,
                    active: true,
                    bound_to: vec![],
                    readonly: false,
                    kernels: Vec::new(),
                    mount_root: None,
                },
            ],
        };
        let (forest, mut active) = forest_from_payload(&payload);
        assert_eq!(forest.bes.len(), 2);
        active.sort();
        assert_eq!(
            active,
            vec!["rpool/ROOT/be1".to_owned(), "rpool2/ROOT/be1".to_owned()]
        );
    }

    #[test]
    fn forest_from_payload_empty_yields_empty_forest() {
        let payload = DiscoverV1 {
            pools: vec![],
            bes: vec![],
        };
        let (forest, active) = forest_from_payload(&payload);
        assert!(forest.bes.is_empty());
        assert!(active.is_empty());
    }

    // --- enumerate_kernels --------------------------------------------------

    fn tempdir_for(slug: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zboot-discover-{slug}-{pid}-{nanos}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(p: &std::path::Path) {
        std::fs::write(p, b"").unwrap();
    }

    #[test]
    fn enumerate_kernels_handles_symlink_versioned_and_old() {
        use std::os::unix::fs::symlink;

        let dir = tempdir_for("enum_basic");
        // Versioned kernels + matching initrds.
        touch(&dir.join("vmlinuz-6.13.0"));
        touch(&dir.join("initrd.img-6.13.0"));
        touch(&dir.join("vmlinuz-6.12.86"));
        touch(&dir.join("initrd.img-6.12.86"));
        // Symlinks `vmlinuz` -> `vmlinuz-6.13.0`, `vmlinuz.old` ->
        // `vmlinuz-6.12.86` (debian's previous-kernel pointer).
        symlink("vmlinuz-6.13.0", dir.join("vmlinuz")).unwrap();
        symlink("initrd.img-6.13.0", dir.join("initrd.img")).unwrap();
        symlink("vmlinuz-6.12.86", dir.join("vmlinuz.old")).unwrap();
        symlink("initrd.img-6.12.86", dir.join("initrd.img.old")).unwrap();

        let entries = enumerate_kernels(&dir);
        let names: Vec<&str> = entries.iter().map(|e| e.vmlinuz.as_str()).collect();
        // Order: vmlinuz, vmlinuz.old, then versioned (newest first).
        assert_eq!(
            names,
            vec![
                "vmlinuz",
                "vmlinuz.old",
                "vmlinuz-6.13.0",
                "vmlinuz-6.12.86"
            ],
        );

        // `default` flag follows symlink target — `vmlinuz` -> 6.13.0.
        let by_name = |n: &str| entries.iter().find(|e| e.vmlinuz == n).unwrap();
        assert!(by_name("vmlinuz-6.13.0").default);
        assert!(!by_name("vmlinuz").default);
        assert!(!by_name("vmlinuz.old").default);

        assert_eq!(by_name("vmlinuz").initrd.as_deref(), Some("initrd.img"));
        assert_eq!(
            by_name("vmlinuz.old").initrd.as_deref(),
            Some("initrd.img.old"),
        );
        assert_eq!(
            by_name("vmlinuz-6.13.0").initrd.as_deref(),
            Some("initrd.img-6.13.0"),
        );
    }

    #[test]
    fn enumerate_kernels_filters_companion_files() {
        let dir = tempdir_for("enum_companions");
        touch(&dir.join("vmlinuz-6.13.0"));
        touch(&dir.join("initrd.img-6.13.0"));
        // Companion files (post-dpkg leftovers + sig file) — must not
        // surface as bootable kernels.
        touch(&dir.join("vmlinuz-6.13.0.sig"));
        touch(&dir.join("vmlinuz-6.12.0.dpkg-old"));

        let entries = enumerate_kernels(&dir);
        let names: Vec<&str> = entries.iter().map(|e| e.vmlinuz.as_str()).collect();
        assert_eq!(names, vec!["vmlinuz-6.13.0"]);
    }

    #[test]
    fn enumerate_kernels_initrd_pair_missing_yields_none() {
        let dir = tempdir_for("enum_no_initrd");
        // Kernel exists; initrd does not.
        touch(&dir.join("vmlinuz-6.13.0"));
        let entries = enumerate_kernels(&dir);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].initrd.is_none());
        assert!(!entries[0].default);
    }

    #[test]
    fn enumerate_kernels_no_symlink_no_default() {
        // No `vmlinuz` symlink at all (rare but legal) — nothing is the
        // default, callers fall back to `vmlinuz` by filename.
        let dir = tempdir_for("enum_no_symlink");
        touch(&dir.join("vmlinuz-6.13.0"));
        touch(&dir.join("initrd.img-6.13.0"));
        let entries = enumerate_kernels(&dir);
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].default);
    }

    #[test]
    fn enumerate_kernels_empty_dir_yields_empty() {
        let dir = tempdir_for("enum_empty");
        assert!(enumerate_kernels(&dir).is_empty());
    }

    #[test]
    fn enumerate_kernels_missing_dir_yields_empty() {
        // Same shape as "BE has no /boot dir" — hand back an empty
        // vec, not a panic.
        let dir = tempdir_for("enum_missing_parent");
        let nope = dir.join("does-not-exist");
        assert!(enumerate_kernels(&nope).is_empty());
    }
}
