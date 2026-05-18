//! `zboot fork` — clone a snapshot into a new BE.
//!
//! Pipeline:
//!
//! 1. Parse + validate args (`NAME`, `--from <snapshot-ref>`).
//! 2. Probe ZFS state via `zfs get -Hp` over all datasets.
//! 3. Refuse cleanly on:
//!    - target BE name already exists at `<pool>/ROOT/<NAME>`,
//!    - source snapshot's origin BE has been **dropped** (orphaned-origin),
//!      with an error pointing at `zfs promote`.
//! 4. `zfs clone -o canmount=noauto -o mountpoint=/ <from> <pool>/ROOT/<NAME>`.
//! 5. Tag new BE: `zboot:be=true`.
//! 6. Append new BE to every `zboot:attached-to` list that references the
//!    source BE — sharing is the default per DESIGN.md "Binding mechanism".
//!
//! ## Decisive defaults (documented in code per CLAUDE.md)
//!
//! - **Target pool = source snapshot's pool.** `zboot fork` doesn't take a
//!   pool argument; the new BE lives in the same pool as `--from`. Cross-pool
//!   forks are out of scope for MVP.
//! - **Path convention `<pool>/ROOT/<NAME>`** matches the project-wide
//!   creation default. Discovery is property-driven; we still default
//!   creation to this path for convention.
//! - **Source BE detection.** We treat the *snapshot's dataset* as the source
//!   BE. If that dataset doesn't carry `zboot:be=true` we still proceed
//!   (e.g. forking a non-BE clone-source is a useful escape hatch — the
//!   `zboot:attached-to` propagation step is then a no-op).
//! - **Orphaned-origin detection.** We walk the snapshot's dataset and its
//!   `origin` chain. If any non-root ancestor's dataset is *not present*
//!   in `zfs list`, the fork refuses with the `zfs promote` hint. Two
//!   concrete shapes are caught:
//!   - `--from <ds>@snap` where `<ds>` itself was destroyed (snapshot
//!     can't even be addressed; ZFS fails earlier, but we surface the
//!     same hint).
//!   - `--from <live-ds>@snap` where `<live-ds>`'s `origin` chain
//!     contains a destroyed parent.
//! - **`bound-to` updates use `zfs set zboot:attached-to=<new-list>`.** We
//!   write the rendered comma-separated list back. Idempotent via
//!   `BoundList::append`: re-running the fork after a partial completion
//!   is safe.
//! - **No transaction.** If clone succeeds but a `zfs set` fails, the
//!   user sees a partial state; re-running with the same args completes
//!   it (clone fails second time → user runs `zboot drop` to retry from
//!   scratch, or deletes the half-clone manually). This matches the
//!   "Operations idempotent; retry is recovery" principle in DESIGN.md.

use std::io::Write;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;

use zboot_core::{BoundKey, BoundList, Property, SnapshotRef, parse_zfs_get};

use crate::sub;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct ForkArgs {
    /// Target BE name. Created at `<pool>/ROOT/<NAME>`.
    pub name: String,
    /// Source snapshot. Two forms accepted:
    /// - `<dataset>@<snap>` — fully qualified (any BE).
    /// - `<snap>` — bare leaf name; resolved against the active BE's
    ///   dataset (the typical case after `zboot snapshot`).
    #[arg(long)]
    pub from: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: &ForkArgs, w: &mut impl Write) -> Result<()> {
    let snap = resolve_from(&args.from)?;

    if args.name.is_empty() {
        bail!("fork: NAME must be non-empty");
    }
    if args.name.contains('/') || args.name.contains('@') {
        bail!(
            "fork: NAME must be a bare BE name (no `/` or `@`); got {:?}",
            args.name
        );
    }

    let plan = ForkPlan::resolve(&snap, &args.name)?;
    plan.execute(w)
}

// ---------------------------------------------------------------------------
// Plan — pure-data resolution + side-effecting executor.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ForkPlan {
    /// Source snapshot ref (`<src_dataset>@<snap>`).
    source_snap: SnapshotRef,
    /// New BE dataset path: `<pool>/ROOT/<name>`.
    target_dataset: String,
    /// Source BE's `pool:name` key — the value to look for in `bound-to` lists.
    source_key: BoundKey,
    /// New BE's `pool:name` key — the value we'll append.
    target_key: BoundKey,
    /// Datasets whose `zboot:attached-to` references the source BE; we'll
    /// append `target_key` to each.
    bound_datasets_to_extend: Vec<(String, BoundList)>,
}

impl ForkPlan {
    fn resolve(snap: &SnapshotRef, target_name: &str) -> Result<Self> {
        let pool = pool_of(&snap.dataset);
        let target_dataset = format!("{pool}/ROOT/{target_name}");

        // --- target name collision check -----------------------------------
        if dataset_exists(&target_dataset)? {
            bail!(
                "fork: target dataset already exists: {target_dataset}\n\
                 hint: pick a different NAME, or `zboot drop {target_name}` first"
            );
        }

        // --- collect dataset-level state ----------------------------------
        let datasets = list_datasets()?;
        let props_text = zfs_get_props(&datasets, "origin,zboot:be,zboot:attached-to")?;
        let props = parse_zfs_get(&props_text).context("parsing `zfs get` output")?;

        // --- orphaned-origin guard -----------------------------------------
        //
        // Walk the snapshot's dataset and its origin chain. If we encounter
        // a dataset whose `origin` points at a snapshot-of-a-now-gone
        // dataset, refuse with the `zfs promote` hint.
        check_origin_lineage(&snap.dataset, &datasets, &props)?;

        // --- determine source BE name (last path component) ---------------
        //
        // Per DESIGN.md the BE "name" is the last path component
        // (`rpool/ROOT/be1` -> `be1`). The pool comes from the dataset prefix.
        let source_be_name = last_component(&snap.dataset).to_owned();
        let source_key = BoundKey::new(pool.to_owned(), source_be_name);
        let target_key = BoundKey::new(pool.to_owned(), target_name.to_owned());

        // --- find every bound dataset that references the source BE -------
        let mut bound_datasets_to_extend: Vec<(String, BoundList)> = Vec::new();
        for (ds_name, prop) in &props {
            if let Property::ZbootAttachedTo(list) = prop
                && list.contains(&source_key)
            {
                bound_datasets_to_extend.push((ds_name.clone(), list.clone()));
            }
        }
        // Stable ordering for predictable execution + test-friendliness.
        bound_datasets_to_extend.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(Self {
            source_snap: snap.clone(),
            target_dataset,
            source_key,
            target_key,
            bound_datasets_to_extend,
        })
    }

    fn execute(&self, w: &mut impl Write) -> Result<()> {
        // --- 1. zfs clone --------------------------------------------------
        let clone_args = [
            "clone",
            "-o",
            "canmount=noauto",
            "-o",
            "mountpoint=/",
            &self.source_snap.render(),
            &self.target_dataset,
        ];
        sub::zfs_capture(&clone_args)
            .with_context(|| format!("`zfs clone` to {} failed", self.target_dataset))?;

        // --- 2. zboot:be=true on the new BE -------------------------------
        sub::zfs_capture(&["set", "zboot:be=true", &self.target_dataset])
            .with_context(|| format!("`zfs set zboot:be=true {}` failed", self.target_dataset))?;

        // --- 2a. Clear inherited zboot:mirror on the new BE ---------------
        //
        // `zfs clone` carries the source dataset's locally-set user
        // properties through. If the source BE was paired, the clone
        // would inherit a stale `zboot:mirror` pointer at the source's
        // peer — but pair pointers are single-slot, so two BEs can't
        // legitimately point at the same peer. Drop the pointer
        // explicitly. See DESIGN.md § Replication invariants, "Pair
        // bookkeeping on lifecycle verbs."
        let _ = crate::zfs_ops::clear_pair_pointer(&self.target_dataset);

        writeln!(
            w,
            "Created {} (cloned from {}); zboot:be=true",
            self.target_dataset,
            self.source_snap.render()
        )
        .context("write")?;

        // --- 3. propagate bound-to (sharing default) ----------------------
        if self.bound_datasets_to_extend.is_empty() {
            writeln!(
                w,
                "No bound datasets reference {} — new BE has no shared state.",
                self.source_key.render()
            )
            .context("write")?;
        } else {
            writeln!(
                w,
                "Sharing {} bound dataset(s) with {}:",
                self.bound_datasets_to_extend.len(),
                self.source_key.render()
            )
            .context("write")?;
        }
        for (ds_name, list) in &self.bound_datasets_to_extend {
            let mut new_list = list.clone();
            new_list.append(self.target_key.clone()); // idempotent
            let rendered = new_list.render();
            sub::zfs_capture(&["set", &format!("zboot:attached-to={rendered}"), ds_name])
                .with_context(|| format!("updating zboot:attached-to on {ds_name}"))?;
            writeln!(w, "  {ds_name} -> {rendered}").context("write")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ZFS shell-out helpers
// ---------------------------------------------------------------------------

/// `zfs list -Hp -o name -t filesystem` → vec of dataset paths.
fn list_datasets() -> Result<Vec<String>> {
    let text = sub::zfs_capture(&["list", "-Hp", "-o", "name", "-t", "filesystem"])?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

/// `zfs get -Hp -o name,property,value <props> <ds>...` over the supplied list.
/// Returns empty string if `datasets` is empty (zfs would error otherwise).
fn zfs_get_props(datasets: &[String], props: &str) -> Result<String> {
    if datasets.is_empty() {
        return Ok(String::new());
    }
    let mut argv: Vec<&str> = vec!["get", "-Hp", "-o", "name,property,value", props];
    argv.extend(datasets.iter().map(String::as_str));
    sub::zfs_capture(&argv)
}

/// `true` if the given dataset name is in `zfs list -t filesystem`.
fn dataset_exists(dataset: &str) -> Result<bool> {
    let out = Command::new("zfs")
        .args(["list", "-Hp", "-o", "name", dataset])
        .output()
        .with_context(|| format!("spawning `zfs list {dataset}`"))?;
    // ZFS returns rc=1 when the dataset isn't found. Distinguishing
    // "not found" from "real error" via stderr text would be brittle;
    // the simpler convention: rc==0 → exists; anything else → assume
    // not present. Production paths that need finer-grained errors can
    // re-query.
    Ok(out.status.success())
}

// ---------------------------------------------------------------------------
// Orphaned-origin guard
// ---------------------------------------------------------------------------

/// Walk the dataset's `origin` chain; refuse if any ancestor dataset is
/// no longer present in `datasets`. Error message points at `zfs promote`
/// as the workaround.
///
/// Two shapes are caught:
///
/// * `start_dataset` itself is absent — the snapshot can't be cloned.
/// * `start_dataset` exists, but its `origin`'s parent dataset has been
///   destroyed (the classic "drop the BE that another BE was cloned
///   from, without promoting first" failure mode).
fn check_origin_lineage(
    start_dataset: &str,
    datasets: &[String],
    props: &[(String, Property)],
) -> Result<()> {
    if !datasets.iter().any(|d| d == start_dataset) {
        return Err(orphaned_origin_error(start_dataset, start_dataset));
    }

    // Map dataset -> Option<origin SnapshotRef>.
    let mut current = start_dataset.to_owned();
    let mut visited: Vec<String> = Vec::new();
    loop {
        if visited.iter().any(|v| v == &current) {
            // Defensive: shouldn't happen with real ZFS lineage, but
            // we don't want to spin forever on malformed property output.
            break;
        }
        visited.push(current.clone());

        let origin = props.iter().find_map(|(name, prop)| {
            if name == &current
                && let Property::Origin(maybe) = prop
            {
                return Some(maybe.clone());
            }
            None
        });

        let Some(Some(parent_snap)) = origin else {
            // No origin — root dataset; lineage is fine.
            return Ok(());
        };

        // Origin's dataset must be live. If not, the parent BE was dropped
        // without promoting and we can't safely fork through it.
        if !datasets.iter().any(|d| d == &parent_snap.dataset) {
            return Err(orphaned_origin_error(start_dataset, &parent_snap.dataset));
        }
        current = parent_snap.dataset;
    }
    Ok(())
}

fn orphaned_origin_error(start: &str, missing: &str) -> anyhow::Error {
    anyhow!(
        "fork: source snapshot's origin lineage is broken — dataset {missing:?} \
         (an ancestor of {start:?}) is no longer present.\n\
         hint: the parent BE was dropped without promoting its dependent \
         clone first. Run `zfs promote <surviving-clone>` on the chain that \
         still exists, then retry the fork."
    )
}

// ---------------------------------------------------------------------------
// Pure helpers (testable)
// ---------------------------------------------------------------------------

fn pool_of(dataset: &str) -> &str {
    dataset.split('/').next().unwrap_or(dataset)
}

fn last_component(dataset: &str) -> &str {
    dataset.rsplit('/').next().unwrap_or(dataset)
}

/// Parse a `--from` argument:
/// - contains `@` → treated as fully qualified `<dataset>@<snap>`.
/// - bare leaf → resolved against the active BE's dataset (the
///   typical case: you just ran `zboot snapshot` and want to fork
///   from the snap that just landed on your active BE).
fn resolve_from(from: &str) -> Result<SnapshotRef> {
    if from.contains('@') {
        return SnapshotRef::parse(from)
            .ok_or_else(|| anyhow!("--from {from:?} is not a valid `<dataset>@<snap>` ref"));
    }
    if from.is_empty() {
        bail!("--from must not be empty");
    }
    let active = active_be_dataset()?;
    Ok(SnapshotRef {
        dataset: active,
        name: from.to_owned(),
    })
}

/// Read the active BE's dataset from the first root-role pool's `bootfs`.
fn active_be_dataset() -> Result<String> {
    let out = std::process::Command::new("zpool")
        .args(["list", "-Hp", "-o", "name,bootfs"])
        .output()
        .context("spawn `zpool list`")?;
    if !out.status.success() {
        bail!(
            "`zpool list` rc={:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim(),
        );
    }
    let text = String::from_utf8(out.stdout).context("non-utf8 zpool output")?;
    for line in text.lines() {
        let mut parts = line.split('\t');
        let _name = parts.next();
        let bootfs = parts.next().unwrap_or("-").trim();
        if !bootfs.is_empty() && bootfs != "-" {
            return Ok(bootfs.to_owned());
        }
    }
    bail!(
        "can't resolve bare snapshot name: no pool has `bootfs` set. \
         Pass the fully-qualified `--from <dataset>@<snap>` instead."
    )
}

// ===========================================================================
// Tests — pure data only. ZFS-touching paths are exercised by
// `scripts/lifecycle.sh`.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_props(items: &[(&str, &str, &str)]) -> Vec<(String, Property)> {
        items
            .iter()
            .map(|(name, prop, value)| {
                (
                    (*name).to_owned(),
                    zboot_core::parse_property(prop, value).expect("test fixture parse"),
                )
            })
            .collect()
    }

    // --- pool_of / last_component ------------------------------------------

    #[test]
    fn pool_of_basic() {
        assert_eq!(pool_of("rpool/ROOT/be1"), "rpool");
        assert_eq!(pool_of("rpool"), "rpool");
        assert_eq!(pool_of(""), "");
    }

    #[test]
    fn last_component_basic() {
        assert_eq!(last_component("rpool/ROOT/be1"), "be1");
        assert_eq!(last_component("rpool/home"), "home");
        assert_eq!(last_component("rpool"), "rpool");
    }

    #[test]
    fn resolve_from_qualified_passes_through() {
        let r = resolve_from("rpool/ROOT/be1@snap1").unwrap();
        assert_eq!(r.dataset, "rpool/ROOT/be1");
        assert_eq!(r.name, "snap1");
    }

    #[test]
    fn resolve_from_rejects_empty() {
        assert!(resolve_from("").is_err());
    }

    // Bare-name resolution shells out to `zpool list`; the live path
    // is exercised by the e2e shell scripts. Here we only cover the
    // qualified form and the empty case to keep tests hermetic.

    // --- check_origin_lineage ----------------------------------------------

    #[test]
    fn lineage_ok_when_dataset_is_root() {
        let datasets = vec!["rpool/ROOT/be1".to_owned()];
        let props = make_props(&[("rpool/ROOT/be1", "origin", "-")]);
        assert!(check_origin_lineage("rpool/ROOT/be1", &datasets, &props).is_ok());
    }

    #[test]
    fn lineage_ok_when_parent_present() {
        let datasets = vec!["rpool/ROOT/be1".to_owned(), "rpool/ROOT/be2".to_owned()];
        let props = make_props(&[
            ("rpool/ROOT/be1", "origin", "-"),
            ("rpool/ROOT/be2", "origin", "rpool/ROOT/be1@snap1"),
        ]);
        assert!(check_origin_lineage("rpool/ROOT/be2", &datasets, &props).is_ok());
    }

    #[test]
    fn lineage_refuses_when_start_dataset_missing() {
        let datasets: Vec<String> = vec![];
        let props: Vec<(String, Property)> = vec![];
        let err = check_origin_lineage("rpool/ROOT/ghost", &datasets, &props).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("zfs promote"), "{msg}");
        assert!(msg.contains("ghost"), "{msg}");
    }

    #[test]
    fn lineage_refuses_when_origin_dataset_dropped() {
        // be2 cloned from be1; be1 has been destroyed (not in datasets).
        let datasets = vec!["rpool/ROOT/be2".to_owned()];
        let props = make_props(&[("rpool/ROOT/be2", "origin", "rpool/ROOT/be1@snap1")]);
        let err = check_origin_lineage("rpool/ROOT/be2", &datasets, &props).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("zfs promote"), "expected hint, got: {msg}");
        assert!(msg.contains("rpool/ROOT/be1"), "{msg}");
    }

    #[test]
    fn lineage_refuses_on_deeper_chain() {
        // be3 cloned from be2; be2 cloned from be1; be1 destroyed.
        let datasets = vec!["rpool/ROOT/be2".to_owned(), "rpool/ROOT/be3".to_owned()];
        let props = make_props(&[
            ("rpool/ROOT/be2", "origin", "rpool/ROOT/be1@snap1"),
            ("rpool/ROOT/be3", "origin", "rpool/ROOT/be2@snap1"),
        ]);
        let err = check_origin_lineage("rpool/ROOT/be3", &datasets, &props).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("zfs promote"), "{msg}");
        assert!(msg.contains("rpool/ROOT/be1"), "{msg}");
    }

    // --- ForkArgs validation (via run, but stubbing ZFS would be heavy;
    //     just exercise the early-return arg validation here) ---------------

    #[test]
    fn run_rejects_malformed_from() {
        // `dataset@` has `@` but an empty snap name — rejected by
        // SnapshotRef::parse early, before any zpool/zfs subprocess
        // (which keeps this test runnable in CI without ZFS installed).
        // A bare name without `@` is now a valid shorthand resolved
        // against the active BE; not a malformed form.
        let args = ForkArgs {
            name: "be2".into(),
            from: "rpool/ROOT/be1@".into(),
        };
        let mut buf: Vec<u8> = Vec::new();
        let err = run(&args, &mut buf).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--from"), "{msg}");
    }

    #[test]
    fn run_rejects_empty_name() {
        let args = ForkArgs {
            name: String::new(),
            from: "rpool/ROOT/be1@snap1".into(),
        };
        let mut buf: Vec<u8> = Vec::new();
        let err = run(&args, &mut buf).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("non-empty"), "{msg}");
    }

    #[test]
    fn run_rejects_name_with_slash() {
        let args = ForkArgs {
            name: "ROOT/be2".into(),
            from: "rpool/ROOT/be1@snap1".into(),
        };
        let mut buf: Vec<u8> = Vec::new();
        let err = run(&args, &mut buf).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bare BE name"), "{msg}");
    }

    #[test]
    fn run_rejects_name_with_at() {
        let args = ForkArgs {
            name: "be2@bad".into(),
            from: "rpool/ROOT/be1@snap1".into(),
        };
        let mut buf: Vec<u8> = Vec::new();
        let err = run(&args, &mut buf).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bare BE name"), "{msg}");
    }
}
