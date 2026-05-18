//! `zboot drop` — destroy a BE; auto-promote dependent clones first;
//! remove from bound-to lists; surface (but don't destroy) orphans.
//!
//! ## Semantics (per DESIGN.md "Binding mechanism" + "Security principles")
//!
//! 1. **Refuse on active BE.** Dropping the BE the system is currently
//!    booted into (or the next-boot target via `bootfs`) is unsafe.
//!    Non-zero exit; helpful error message.
//! 2. **Typed-target confirmation.** No `--yes` flag in MVP. The user
//!    must echo the BE's full dataset path (`<pool>/ROOT/<NAME>`) on
//!    stdin. The exact required string is printed in the error message
//!    so scripts can `echo … | zboot drop NAME`.
//! 3. **Auto-promote dependent clones.** Before destroying BE2, any BE3
//!    whose ZFS `origin` lies under `BE2/...@...` must be promoted so
//!    that the clone history moves off BE2. Done transitively until no
//!    clone in the forest still points back at the target.
//! 4. **Remove from bound-to lists.** Walk all datasets carrying
//!    `zboot:attached-to`; if `<pool>:<NAME>` appears, remove it. If the
//!    list becomes empty, the dataset becomes an "orphan" — surfaced
//!    on stdout (and subsequently in `zboot status`). zboot does **not**
//!    `zfs destroy` orphan datasets; that's the user's call.
//!
//! ## Confirmation string choice
//!
//! `<pool>/ROOT/<NAME>` (the canonical BE dataset path) is verbose but
//! unambiguous: it carries the pool, so scripts can't accidentally
//! drop a same-named BE on a different pool. DESIGN.md leaves the
//! exact form to the implementer; this module documents the choice
//! and the error message includes the exact string.
//!
//! ## Testability
//!
//! `run()`'s signature is locked (`&DropArgs, &mut impl Write`). The
//! interactive read uses `std::io::stdin()` by default. The internal
//! `confirm_with` helper takes any `BufRead`, so unit tests can drive
//! it deterministically without touching a tty. Integration tests pipe
//! a string into the binary's stdin.
//!
//! All ZFS-touching code paths are deferred to small free functions
//! (`run_zfs`, `discover_*`, `promote_dependent_clones`, `destroy_be`,
//! `purge_be_from_bound_lists`) so that the orchestration in
//! `run_inner` is a thin sequence of named steps.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;

use zboot_core::{BoundKey, BoundList, SnapshotRef, parse_zfs_get};

use crate::sub;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct DropArgs {
    /// Target BE. Two forms:
    /// 1. bare name (`be1`) — single-pool deployments
    /// 2. fully-qualified dataset (`rpool2/ROOT/be1`) — required when a bare
    ///    name is ambiguous across multiple `zboot:role=root` pools.
    pub name: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: &DropArgs, mut w: &mut dyn Write) -> Result<()> {
    let stdin = std::io::stdin();
    let mut locked = stdin.lock();
    // See rollback.rs::run — `&mut w` lets us pass through to the
    // `impl Write`-bound helper without churning the test surface.
    run_inner(args, &RealZfs, &mut locked, &mut w)
}

/// Internal entry point, parameterized over the ZFS access trait + a
/// generic stdin reader. All tests target this.
fn run_inner<Z: Zfs, R: BufRead, W: Write>(
    args: &DropArgs,
    zfs: &Z,
    stdin: &mut R,
    out: &mut W,
) -> Result<()> {
    // 1) Locate the target BE. We need its dataset (for the confirmation
    //    string and destroy step) and its pool (for bound-to-key purge).
    let target = locate_target_be(zfs, &args.name)?;

    // 2) Refuse on active BE. Two flavors of "active":
    //    (a) `bootfs` of any root pool points at this dataset — it's
    //        the next-boot target.
    //    (b) the dataset is the live `/` mount — it's the currently-
    //        running root. `zfs destroy -r` on this fails with
    //        "cannot unmount '/': pool or dataset is busy" anyway,
    //        but the error is cryptic. Surface it cleanly.
    if is_active(zfs, &target.dataset)? {
        bail!(
            "drop: refusing — `{name}` is the active BE (bootfs points here). \
             Switch to a different BE first, then drop this one.\n\
             Active dataset: {ds}",
            name = args.name,
            ds = target.dataset,
        );
    }
    if is_live_root(&target.dataset) {
        bail!(
            "drop: refusing — `{name}` is mounted as the live `/` (currently running root). \
             Reboot into a different BE first, then drop this one.\n\
             Live-root dataset: {ds}",
            name = args.name,
            ds = target.dataset,
        );
    }

    // 3) Typed-target confirmation. The exact required string is the
    //    full dataset path. We print the prompt+expected to *stderr*
    //    via the error path on mismatch; on the success path we read
    //    stdin and silently proceed. The error message includes the
    //    exact string verbatim so scripts can `echo` it.
    let expected = target.dataset.as_str();
    confirm_with(stdin, expected).with_context(|| {
        format!(
            "drop: confirmation required. To proceed, the exact dataset \
             path must be supplied on stdin.\n\
             Required confirmation string: {expected}\n\
             Example (scripted): echo {expected} | zboot drop {name}",
            name = args.name,
        )
    })?;

    // 4) Auto-promote any clone whose origin sits under the target BE,
    //    transitively. After this loop, no extant dataset still has
    //    `origin = <target>@*`, so `zfs destroy` won't fail on
    //    "filesystem has dependent clones".
    let promoted = promote_dependent_clones(zfs, &target.dataset)?;
    for ds in &promoted {
        writeln!(out, "promoted: {ds}")?;
    }

    // 5) Destroy the BE. `-r` to drop snapshots that lived on the BE
    //    itself; auto-promote above moved any user-visible history off.
    destroy_be(zfs, &target.dataset)?;
    writeln!(out, "destroyed: {}", target.dataset)?;

    // 6a) Clear `zboot:mirror` on any peer that was pointing back at
    //     this BE (the mutual-pair case in DESIGN.md § Replication
    //     invariants). One-to-many tracking pointers from other "many"
    //     sides also dangle — surfaced as `[target missing]` in status;
    //     left to the user's `unpair`.
    let _ = clear_incoming_mirror_pointers(&target.dataset, out);

    // 6) Walk all `zboot:attached-to`-bearing datasets; drop the
    //    `<pool>:<NAME>` entry. Empty list → orphan; surfaced here,
    //    not destroyed. Use the dataset's LEAF as the BE name —
    //    args.name may be a full dataset path when the user
    //    disambiguated via fully-qualified form.
    let be_name = dataset_leaf(&target.dataset).to_owned();
    let key = BoundKey::new(target.pool.clone(), be_name);
    let orphans = purge_be_from_bound_lists(zfs, &key)?;
    for ds in &orphans {
        writeln!(
            out,
            "orphaned: {ds} (no live binding remains; remove with `zfs destroy {ds}` if no longer needed)",
        )?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Confirmation
// ---------------------------------------------------------------------------

/// Read one line from `stdin` and compare to `expected` after trimming
/// the trailing newline (and surrounding whitespace, defensively).
/// Returns `Err` on mismatch *or* read failure.
fn confirm_with<R: BufRead>(stdin: &mut R, expected: &str) -> Result<()> {
    let mut line = String::new();
    let read = stdin
        .read_line(&mut line)
        .context("failed to read confirmation from stdin")?;
    if read == 0 {
        // EOF without a line.
        bail!("no confirmation input");
    }
    let got = line.trim();
    if got != expected {
        bail!("confirmation mismatch (got {got:?}, expected {expected:?})");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ZFS access trait — keeps the orchestration testable.
// ---------------------------------------------------------------------------

/// Minimal abstraction over the ZFS subprocess surface drop needs. Lets
/// unit tests stub each call. Production impl is `RealZfs`.
trait Zfs {
    /// `zfs list -Hp -t filesystem -o name,zboot:be,origin,zboot:attached-to`
    /// (or equivalent multi-property form). Returns one row per dataset.
    fn list_datasets(&self) -> Result<Vec<DatasetRow>>;

    /// `zpool list -Hp -o name,bootfs`.
    fn list_pools(&self) -> Result<Vec<PoolRow>>;

    /// `zfs promote <dataset>` — moves clone history.
    fn promote(&self, dataset: &str) -> Result<()>;

    /// `zfs destroy -r <dataset>` — recursive (snapshots, no children
    /// expected on a BE dataset by DESIGN convention).
    fn destroy(&self, dataset: &str) -> Result<()>;

    /// `zfs set zboot:attached-to=<value> <dataset>` — write the bound list.
    fn set_bound_to(&self, dataset: &str, value: &str) -> Result<()>;

    /// `zfs inherit zboot:attached-to <dataset>` — clear when value would
    /// be empty. (Setting to empty string is awkward; inherit is clean.)
    fn unset_bound_to(&self, dataset: &str) -> Result<()>;
}

#[derive(Debug, Clone)]
struct DatasetRow {
    name: String,
    is_be: bool,
    /// `dataset@snap` if the dataset was created via `zfs clone`.
    origin: Option<SnapshotRef>,
    bound_to: Option<BoundList>,
}

#[derive(Debug, Clone)]
struct PoolRow {
    #[allow(dead_code)] // surfaced for future error messages
    name: String,
    bootfs: Option<String>,
}

// ---------------------------------------------------------------------------
// Production ZFS impl.
// ---------------------------------------------------------------------------

struct RealZfs;

impl Zfs for RealZfs {
    fn list_datasets(&self) -> Result<Vec<DatasetRow>> {
        // Use `zfs list` to enumerate filesystems; then `zfs get` for
        // the property bag. Two calls keep parsing simple — the `get`
        // output already has dataset/property/value rows that core's
        // parse_zfs_get understands.
        let names_text =
            sub::zfs_capture(&["list", "-Hp", "-o", "name", "-t", "filesystem"]).context("zfs list")?;
        let datasets: Vec<String> = names_text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        if datasets.is_empty() {
            return Ok(Vec::new());
        }

        let mut args: Vec<&str> = vec![
            "get",
            "-Hp",
            "-o",
            "name,property,value",
            "zboot:be,origin,zboot:attached-to",
        ];
        args.extend(datasets.iter().map(String::as_str));
        let props_text = sub::zfs_capture(&args).context("zfs get for drop")?;
        let props = parse_zfs_get(&props_text).context("parsing zfs get")?;

        let mut rows: Vec<DatasetRow> = datasets
            .iter()
            .map(|d| DatasetRow {
                name: d.clone(),
                is_be: false,
                origin: None,
                bound_to: None,
            })
            .collect();

        for (name, prop) in props {
            let Some(row) = rows.iter_mut().find(|r| r.name == name) else {
                continue;
            };
            match prop {
                zboot_core::Property::ZbootBe(b) => row.is_be = b,
                zboot_core::Property::Origin(o) => row.origin = o,
                zboot_core::Property::ZbootAttachedTo(bl) => row.bound_to = Some(bl),
                _ => {}
            }
        }

        Ok(rows)
    }

    fn list_pools(&self) -> Result<Vec<PoolRow>> {
        let text = sub::zpool_capture(&["list", "-Hp", "-o", "name,bootfs"])?;
        let mut pools = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut cols = line.split('\t');
            let name = cols.next().unwrap_or_default().to_owned();
            let bootfs_raw = cols.next().unwrap_or("-").to_owned();
            let bootfs = if bootfs_raw == "-" || bootfs_raw.is_empty() {
                None
            } else {
                Some(bootfs_raw)
            };
            pools.push(PoolRow { name, bootfs });
        }
        Ok(pools)
    }

    fn promote(&self, dataset: &str) -> Result<()> {
        sub::zfs(&["promote", dataset]).with_context(|| format!("zfs promote {dataset}"))?;
        Ok(())
    }

    fn destroy(&self, dataset: &str) -> Result<()> {
        sub::zfs(&["destroy", "-r", dataset])
            .with_context(|| format!("zfs destroy -r {dataset}"))?;
        Ok(())
    }

    fn set_bound_to(&self, dataset: &str, value: &str) -> Result<()> {
        let arg = format!("zboot:attached-to={value}");
        sub::zfs(&["set", &arg, dataset])
            .with_context(|| format!("zfs set zboot:attached-to on {dataset}"))?;
        Ok(())
    }

    fn unset_bound_to(&self, dataset: &str) -> Result<()> {
        sub::zfs(&["inherit", "zboot:attached-to", dataset])
            .with_context(|| format!("zfs inherit zboot:attached-to on {dataset}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Step helpers — small, individually testable.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TargetBe {
    pool: String,
    dataset: String,
}

/// Find the target BE. Accepts:
///
/// - **fully-qualified dataset** (`rpool/ROOT/be1`): direct match.
/// - **bare name** (`be1`): matches across all root-role pools; refuses
///   to guess when the name is ambiguous (operator must pass the full
///   dataset path).
fn locate_target_be<Z: Zfs>(zfs: &Z, name: &str) -> Result<TargetBe> {
    let rows = zfs.list_datasets()?;
    if name.contains('/') {
        // Fully-qualified: exact-match on dataset name, must be a BE.
        let row = rows
            .iter()
            .find(|r| r.is_be && r.name == name)
            .ok_or_else(|| anyhow::anyhow!("drop: no BE matching dataset {name:?}"))?;
        return Ok(TargetBe {
            pool: dataset_pool(&row.name).to_owned(),
            dataset: row.name.clone(),
        });
    }

    let matches: Vec<&DatasetRow> = rows
        .iter()
        .filter(|r| r.is_be && dataset_leaf(&r.name) == name)
        .collect();
    match matches.len() {
        0 => bail!("drop: no BE named {name:?} found (looked for `*/ROOT/{name}`)"),
        1 => {
            let row = matches[0];
            Ok(TargetBe {
                pool: dataset_pool(&row.name).to_owned(),
                dataset: row.name.clone(),
            })
        }
        _ => {
            let datasets: Vec<&str> = matches.iter().map(|r| r.name.as_str()).collect();
            bail!(
                "drop: multiple BEs named {name:?} across pools: {}. \
                 Disambiguate by passing the full dataset path.",
                datasets.join(", "),
            )
        }
    }
}

/// True iff any pool's `bootfs` equals `dataset`.
fn is_active<Z: Zfs>(zfs: &Z, dataset: &str) -> Result<bool> {
    let pools = zfs.list_pools()?;
    Ok(pools.iter().any(|p| p.bootfs.as_deref() == Some(dataset)))
}

/// True iff `dataset` is the source of the live `/` mount.
/// Reads /proc/self/mounts directly; falling back to `false` on read
/// failure is correct because the worst case is that we let the
/// downstream `zfs destroy` produce its own "dataset is busy" error.
fn is_live_root(dataset: &str) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return false;
    };
    for line in mounts.lines() {
        // Format: "<source> <target> <fstype> <opts> <freq> <pass>"
        let mut parts = line.split_whitespace();
        let source = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        if target == "/" && source == dataset {
            return true;
        }
    }
    false
}

/// Promote any dataset whose `origin` references `target` (transitively
/// through promotion chains). Returns the datasets we promoted, in
/// order, for surfacing on stdout.
///
/// Why a loop: each `zfs promote` can leave another clone behind (the
/// snapshot transferred to the promoted dataset). The DESIGN
/// "auto-promote dependent clones" guarantee is "no clone of `target`
/// remains by destroy-time". We re-list datasets after each promote
/// and stop when no row's origin still points at `target`.
fn promote_dependent_clones<Z: Zfs>(zfs: &Z, target_dataset: &str) -> Result<Vec<String>> {
    let mut promoted: Vec<String> = Vec::new();
    // Bound the loop defensively: `zfs promote` only moves snapshots
    // *to* the promoted dataset, so the number of iterations is bounded
    // by the depth of the clone chain anchored at `target`. A safety
    // bound prevents infinite loops if some pathological state slips
    // through (e.g. the impl's view of "origin" disagrees with ZFS).
    for _ in 0..256 {
        let rows = zfs.list_datasets()?;
        let candidate = rows
            .iter()
            .find(|r| {
                r.origin
                    .as_ref()
                    .is_some_and(|o| o.dataset == target_dataset)
            })
            .map(|r| r.name.clone());
        match candidate {
            Some(ds) => {
                zfs.promote(&ds)?;
                promoted.push(ds);
            }
            None => return Ok(promoted),
        }
    }
    Err(anyhow!(
        "promote loop did not converge for {target_dataset}; aborting"
    ))
}

fn destroy_be<Z: Zfs>(zfs: &Z, dataset: &str) -> Result<()> {
    zfs.destroy(dataset)
}

/// Walk every dataset's `zboot:attached-to`; drop `key` if present. Return
/// the list of datasets whose binding list became empty (orphans).
fn purge_be_from_bound_lists<Z: Zfs>(zfs: &Z, key: &BoundKey) -> Result<Vec<String>> {
    let rows = zfs.list_datasets()?;
    let mut orphans = Vec::new();
    for row in rows {
        let Some(mut list) = row.bound_to else {
            continue;
        };
        if !list.contains(key) {
            continue;
        }
        list.remove(key);
        if list.is_empty() {
            // Empty list — orphan. Inherit the property to clear it
            // cleanly (setting it to "" reads back as "-" anyway, but
            // inherit avoids the empty-string round-trip surprise).
            zfs.unset_bound_to(&row.name)?;
            orphans.push(row.name);
        } else {
            zfs.set_bound_to(&row.name, &list.render())?;
        }
    }
    Ok(orphans)
}

// ---------------------------------------------------------------------------
// Path utilities (mirror cmd::status's split helpers, narrower form).
// ---------------------------------------------------------------------------

/// `rpool/ROOT/be1` → `"rpool"`.
fn dataset_pool(d: &str) -> &str {
    d.split('/').next().unwrap_or(d)
}

/// `rpool/ROOT/be1` → `"be1"`.
fn dataset_leaf(d: &str) -> &str {
    d.rsplit('/').next().unwrap_or(d)
}

/// Walk all imported root pools, find any dataset whose `zboot:mirror`
/// equals the dropped dataset's canonical pointer form, and inherit
/// (clear) that property. Best-effort: shell-out failures emit a note
/// but don't abort the drop. Mirrors the rename verb's incoming-pointer
/// rewrite logic.
fn clear_incoming_mirror_pointers<W: Write>(dropped_dataset: &str, out: &mut W) -> Result<()> {
    let Some(target_pointer) = zboot_core::PairPointer::parse_dataset(dropped_dataset) else {
        return Ok(());
    };
    let target_render = target_pointer.render();

    let Ok(pools) = sub::zpool_capture(&["list", "-Hp", "-o", "name"]) else {
        return Ok(());
    };
    for pool in pools.lines() {
        if crate::zfs_ops::pool_property(pool, "zboot:role")
            .ok()
            .as_deref()
            != Some("root")
        {
            continue;
        }
        let Ok(text) = sub::zfs_capture(&[
            "get", "-Hp", "-r", "-t", "filesystem", "-o", "name,value", "zboot:mirror", pool,
        ]) else {
            continue;
        };
        for line in text.lines() {
            let mut parts = line.split('\t');
            let name = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            if value == target_render {
                let _ = crate::zfs_ops::clear_pair_pointer(name);
                writeln!(out, "cleared zboot:mirror on {name} (was pointing at dropped {dropped_dataset})").ok();
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Tests — pure-data, no I/O. All ZFS calls go through `FakeZfs`.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;

    // --- in-memory FakeZfs -------------------------------------------------

    #[derive(Default)]
    struct FakeZfs {
        datasets: RefCell<Vec<DatasetRow>>,
        pools: RefCell<Vec<PoolRow>>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeZfs {
        fn add_pool(&self, name: &str, bootfs: Option<&str>) {
            self.pools.borrow_mut().push(PoolRow {
                name: name.into(),
                bootfs: bootfs.map(str::to_owned),
            });
        }

        fn add_be(&self, dataset: &str, origin: Option<&str>) {
            self.datasets.borrow_mut().push(DatasetRow {
                name: dataset.into(),
                is_be: true,
                origin: origin.and_then(SnapshotRef::parse),
                bound_to: None,
            });
        }

        fn add_bound(&self, dataset: &str, bound_to: &str) {
            self.datasets.borrow_mut().push(DatasetRow {
                name: dataset.into(),
                is_be: false,
                origin: None,
                bound_to: Some(BoundList::parse(bound_to).unwrap()),
            });
        }
    }

    impl Zfs for FakeZfs {
        fn list_datasets(&self) -> Result<Vec<DatasetRow>> {
            Ok(self.datasets.borrow().clone())
        }
        fn list_pools(&self) -> Result<Vec<PoolRow>> {
            Ok(self.pools.borrow().clone())
        }
        fn promote(&self, dataset: &str) -> Result<()> {
            self.calls.borrow_mut().push(format!("promote {dataset}"));
            // Simulate `zfs promote`: the promoted dataset's origin
            // becomes None, and any clones that previously hung off the
            // promoted dataset's siblings... we approximate by walking
            // the rows and rewriting origins so that whichever dataset
            // *was* the source-of-history (i.e. the dataset whose
            // snapshot the promoted one was cloned from) now has its
            // origin set to a snapshot of the promoted dataset (or
            // None if it had no further parents).
            //
            // For test purposes we model the simplest meaningful case:
            // - The promoted dataset's origin becomes None.
            // - Any other dataset whose origin's dataset == the
            //   promoted dataset's *former* origin's dataset gets
            //   rewritten to point at the promoted dataset.
            // This is enough to break the "still clone of target"
            // condition the loop checks.
            let mut datasets = self.datasets.borrow_mut();
            let promoted_idx = datasets
                .iter()
                .position(|r| r.name == dataset)
                .ok_or_else(|| anyhow!("promote target {dataset} missing in fake"))?;
            let former_origin_ds = datasets[promoted_idx]
                .origin
                .as_ref()
                .map(|o| o.dataset.clone());
            datasets[promoted_idx].origin = None;
            if let Some(former) = former_origin_ds {
                // Rewrite the former origin BE's origin? No — the
                // semantics we need: the former parent (e.g. BE2) now
                // descends from the promoted (e.g. BE3). We model this
                // by giving the former-parent an origin pointing at
                // the promoted dataset. This is enough to make
                // promote_dependent_clones converge.
                if let Some(parent) = datasets.iter_mut().find(|r| r.name == former) {
                    parent.origin = SnapshotRef::parse(&format!("{dataset}@promoted-snap"));
                }
            }
            Ok(())
        }
        fn destroy(&self, dataset: &str) -> Result<()> {
            self.calls.borrow_mut().push(format!("destroy {dataset}"));
            self.datasets.borrow_mut().retain(|r| r.name != dataset);
            Ok(())
        }
        fn set_bound_to(&self, dataset: &str, value: &str) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("set bound-to={value} {dataset}"));
            if let Some(row) = self
                .datasets
                .borrow_mut()
                .iter_mut()
                .find(|r| r.name == dataset)
            {
                row.bound_to = Some(BoundList::parse(value).unwrap());
            }
            Ok(())
        }
        fn unset_bound_to(&self, dataset: &str) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("unset bound-to {dataset}"));
            if let Some(row) = self
                .datasets
                .borrow_mut()
                .iter_mut()
                .find(|r| r.name == dataset)
            {
                row.bound_to = None;
            }
            Ok(())
        }
    }

    fn drop_args(name: &str) -> DropArgs {
        DropArgs {
            name: name.to_owned(),
        }
    }

    // --- confirm_with -------------------------------------------------------

    #[test]
    fn confirm_with_exact_match_succeeds() {
        let mut input = Cursor::new(b"rpool/ROOT/BE2\n".to_vec());
        confirm_with(&mut input, "rpool/ROOT/BE2").unwrap();
    }

    #[test]
    fn confirm_with_trailing_whitespace_ok() {
        let mut input = Cursor::new(b"rpool/ROOT/BE2  \n".to_vec());
        confirm_with(&mut input, "rpool/ROOT/BE2").unwrap();
    }

    #[test]
    fn confirm_with_mismatch_fails() {
        let mut input = Cursor::new(b"BE2\n".to_vec());
        let err = confirm_with(&mut input, "rpool/ROOT/BE2").unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn confirm_with_eof_fails() {
        let mut input = Cursor::new(b"".to_vec());
        let err = confirm_with(&mut input, "rpool/ROOT/BE2").unwrap_err();
        assert!(err.to_string().contains("no confirmation"));
    }

    // --- locate_target_be ---------------------------------------------------

    #[test]
    fn locate_finds_unique_be() {
        let z = FakeZfs::default();
        z.add_be("rpool/ROOT/BE1", None);
        z.add_be("rpool/ROOT/BE2", Some("rpool/ROOT/BE1@snap1"));
        let t = locate_target_be(&z, "BE2").unwrap();
        assert_eq!(t.dataset, "rpool/ROOT/BE2");
        assert_eq!(t.pool, "rpool");
    }

    #[test]
    fn locate_errors_when_missing() {
        let z = FakeZfs::default();
        z.add_be("rpool/ROOT/BE1", None);
        let err = locate_target_be(&z, "ghost").unwrap_err();
        assert!(err.to_string().contains("no BE named"));
    }

    #[test]
    fn locate_errors_when_ambiguous() {
        let z = FakeZfs::default();
        z.add_be("rpool/ROOT/BE1", None);
        z.add_be("rpool2/ROOT/BE1", None);
        let err = locate_target_be(&z, "BE1").unwrap_err();
        assert!(err.to_string().contains("multiple BEs"));
        assert!(
            err.to_string().contains("full dataset path"),
            "error should mention full dataset path: {err}"
        );
    }

    #[test]
    fn locate_accepts_fully_qualified_dataset() {
        let z = FakeZfs::default();
        z.add_be("rpool/ROOT/BE1", None);
        z.add_be("rpool2/ROOT/BE1", None);
        let t = locate_target_be(&z, "rpool2/ROOT/BE1").unwrap();
        assert_eq!(t.dataset, "rpool2/ROOT/BE1");
        assert_eq!(t.pool, "rpool2");
    }

    #[test]
    fn locate_errors_on_unknown_fully_qualified() {
        let z = FakeZfs::default();
        z.add_be("rpool/ROOT/BE1", None);
        let err = locate_target_be(&z, "rpool/ROOT/ghost").unwrap_err();
        assert!(err.to_string().contains("no BE matching dataset"));
    }

    // --- is_active ----------------------------------------------------------

    #[test]
    fn is_active_when_bootfs_matches() {
        let z = FakeZfs::default();
        z.add_pool("rpool", Some("rpool/ROOT/BE1"));
        assert!(is_active(&z, "rpool/ROOT/BE1").unwrap());
        assert!(!is_active(&z, "rpool/ROOT/BE2").unwrap());
    }

    #[test]
    fn is_active_false_when_no_bootfs() {
        let z = FakeZfs::default();
        z.add_pool("rpool", None);
        assert!(!is_active(&z, "rpool/ROOT/BE1").unwrap());
    }

    // --- promote_dependent_clones ------------------------------------------

    #[test]
    fn promote_clears_one_dependent() {
        let z = FakeZfs::default();
        z.add_be("rpool/ROOT/BE1", None);
        z.add_be("rpool/ROOT/BE2", Some("rpool/ROOT/BE1@snap1"));
        let promoted = promote_dependent_clones(&z, "rpool/ROOT/BE1").unwrap();
        assert_eq!(promoted, vec!["rpool/ROOT/BE2"]);
        // After promote, no clone hangs off BE1.
        let rows = z.list_datasets().unwrap();
        assert!(!rows.iter().any(|r| {
            r.origin
                .as_ref()
                .is_some_and(|o| o.dataset == "rpool/ROOT/BE1")
        }));
    }

    #[test]
    fn promote_noop_when_no_clones() {
        let z = FakeZfs::default();
        z.add_be("rpool/ROOT/BE1", None);
        let promoted = promote_dependent_clones(&z, "rpool/ROOT/BE1").unwrap();
        assert!(promoted.is_empty());
    }

    // --- purge_be_from_bound_lists -----------------------------------------

    #[test]
    fn purge_removes_key_from_shared_list() {
        let z = FakeZfs::default();
        z.add_bound("rpool/home", "rpool:BE1,rpool:BE2");
        let key = BoundKey::new("rpool", "BE2");
        let orphans = purge_be_from_bound_lists(&z, &key).unwrap();
        assert!(orphans.is_empty());
        // /home now binds only to BE1.
        let rows = z.list_datasets().unwrap();
        let home = rows.iter().find(|r| r.name == "rpool/home").unwrap();
        assert_eq!(home.bound_to.as_ref().unwrap().render(), "rpool:BE1");
    }

    #[test]
    fn purge_orphans_dataset_when_last_key_removed() {
        let z = FakeZfs::default();
        z.add_bound("rpool/home", "rpool:BE3");
        let key = BoundKey::new("rpool", "BE3");
        let orphans = purge_be_from_bound_lists(&z, &key).unwrap();
        assert_eq!(orphans, vec!["rpool/home"]);
        let rows = z.list_datasets().unwrap();
        let home = rows.iter().find(|r| r.name == "rpool/home").unwrap();
        assert!(home.bound_to.is_none());
    }

    #[test]
    fn purge_skips_unrelated_lists() {
        let z = FakeZfs::default();
        z.add_bound("rpool/home", "rpool:BE1");
        let key = BoundKey::new("rpool", "BE2");
        let orphans = purge_be_from_bound_lists(&z, &key).unwrap();
        assert!(orphans.is_empty());
        let rows = z.list_datasets().unwrap();
        let home = rows.iter().find(|r| r.name == "rpool/home").unwrap();
        // Untouched.
        assert_eq!(home.bound_to.as_ref().unwrap().render(), "rpool:BE1");
    }

    // --- run_inner end-to-end (against FakeZfs) ----------------------------

    #[test]
    fn run_inner_drops_non_active_be_with_correct_confirmation() {
        let z = FakeZfs::default();
        z.add_pool("rpool", Some("rpool/ROOT/BE1"));
        z.add_be("rpool/ROOT/BE1", None);
        z.add_be("rpool/ROOT/BE2", Some("rpool/ROOT/BE1@snap1"));
        z.add_bound("rpool/home", "rpool:BE1,rpool:BE2");

        let mut stdin = Cursor::new(b"rpool/ROOT/BE2\n".to_vec());
        let mut out = Vec::new();
        run_inner(&drop_args("BE2"), &z, &mut stdin, &mut out).unwrap();

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("destroyed: rpool/ROOT/BE2"), "{stdout}");
        // No orphan — /home still binds to BE1.
        assert!(!stdout.contains("orphaned:"), "{stdout}");

        // BE2 gone from datasets; /home still bound to BE1.
        let rows = z.list_datasets().unwrap();
        assert!(rows.iter().all(|r| r.name != "rpool/ROOT/BE2"));
        let home = rows.iter().find(|r| r.name == "rpool/home").unwrap();
        assert_eq!(home.bound_to.as_ref().unwrap().render(), "rpool:BE1");
    }

    #[test]
    fn run_inner_refuses_active_be() {
        let z = FakeZfs::default();
        z.add_pool("rpool", Some("rpool/ROOT/BE1"));
        z.add_be("rpool/ROOT/BE1", None);

        let mut stdin = Cursor::new(b"rpool/ROOT/BE1\n".to_vec());
        let mut out = Vec::new();
        let err = run_inner(&drop_args("BE1"), &z, &mut stdin, &mut out).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("active BE"), "got: {msg}");
        // Datasets untouched.
        let rows = z.list_datasets().unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn run_inner_refuses_on_confirmation_mismatch() {
        let z = FakeZfs::default();
        z.add_pool("rpool", Some("rpool/ROOT/BE1"));
        z.add_be("rpool/ROOT/BE1", None);
        z.add_be("rpool/ROOT/BE2", None);

        let mut stdin = Cursor::new(b"BE2\n".to_vec());
        let mut out = Vec::new();
        let err = run_inner(&drop_args("BE2"), &z, &mut stdin, &mut out).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("rpool/ROOT/BE2"), "got: {msg}");
        // BE2 untouched.
        let rows = z.list_datasets().unwrap();
        assert!(rows.iter().any(|r| r.name == "rpool/ROOT/BE2"));
    }

    #[test]
    fn run_inner_surfaces_orphan_when_last_binding_removed() {
        let z = FakeZfs::default();
        z.add_pool("rpool", Some("rpool/ROOT/BE1"));
        z.add_be("rpool/ROOT/BE1", None);
        z.add_be("rpool/ROOT/BE3", None);
        z.add_bound("rpool/home3", "rpool:BE3");

        let mut stdin = Cursor::new(b"rpool/ROOT/BE3\n".to_vec());
        let mut out = Vec::new();
        run_inner(&drop_args("BE3"), &z, &mut stdin, &mut out).unwrap();

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("orphaned: rpool/home3"), "{stdout}");
        // Orphan dataset itself is NOT destroyed — only its property
        // was cleared.
        let rows = z.list_datasets().unwrap();
        assert!(rows.iter().any(|r| r.name == "rpool/home3"));
    }

    #[test]
    fn run_inner_promotes_dependent_clone_before_destroy() {
        // BE1 → BE2 → BE3 chain. Drop BE2 must promote BE3.
        let z = FakeZfs::default();
        z.add_pool("rpool", Some("rpool/ROOT/BE1"));
        z.add_be("rpool/ROOT/BE1", None);
        z.add_be("rpool/ROOT/BE2", Some("rpool/ROOT/BE1@snap1"));
        z.add_be("rpool/ROOT/BE3", Some("rpool/ROOT/BE2@snap2"));

        let mut stdin = Cursor::new(b"rpool/ROOT/BE2\n".to_vec());
        let mut out = Vec::new();
        run_inner(&drop_args("BE2"), &z, &mut stdin, &mut out).unwrap();

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("promoted: rpool/ROOT/BE3"), "{stdout}");
        assert!(stdout.contains("destroyed: rpool/ROOT/BE2"), "{stdout}");

        let calls = z.calls.borrow();
        // promote must precede destroy in the call order.
        let promote_idx = calls
            .iter()
            .position(|c| c.starts_with("promote "))
            .unwrap();
        let destroy_idx = calls
            .iter()
            .position(|c| c.starts_with("destroy "))
            .unwrap();
        assert!(promote_idx < destroy_idx, "calls: {calls:?}");
    }

    // --- path utilities -----------------------------------------------------

    #[test]
    fn dataset_pool_and_leaf_basic() {
        assert_eq!(dataset_pool("rpool/ROOT/BE1"), "rpool");
        assert_eq!(dataset_leaf("rpool/ROOT/BE1"), "BE1");
        assert_eq!(dataset_pool("rpool"), "rpool");
        assert_eq!(dataset_leaf("rpool"), "rpool");
    }
}
