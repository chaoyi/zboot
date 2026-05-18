//! `zboot default` — set the next-boot BE for a pool. Two effects:
//!
//! 1. Set `bootfs=<dataset>` on the BE's pool — canonical "what boots
//!    next" marker.
//! 2. Toggle `canmount` on every dataset carrying `zboot:attached-to`:
//!    - new active BE in the attached-to list → `canmount=on`
//!    - else                                  → `canmount=off`
//!
//! `mountpoint` is left alone (user controls it via `zfs create -o
//! mountpoint=…`). Idempotent: re-running with the already-active BE
//! is a no-op (we read state first and skip writes that would not
//! change anything).

use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;

use zboot_core::{
    BoundKey, BoundList, Canmount, PoolRole, Property, parse_zfs_get, parse_zpool_list,
};

use crate::sub::{self, Runner, SystemRunner};
#[cfg(test)]
use crate::sub::RunOutput;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct DefaultArgs {
    /// Target BE. Bare name (`be2`) for single-pool deployments; for
    /// multi-pool, pass the fully-qualified dataset path
    /// (`rpool2/ROOT/be2`) — bare names refuse on ambiguity.
    /// Matched against `zboot:be=true` datasets.
    pub name: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: &DefaultArgs, w: &mut impl Write) -> Result<()> {
    run_with_runner(args, w, &mut SystemRunner)
}

// ---------------------------------------------------------------------------
// Internals — split from `run` for unit testing without subprocess.
// ---------------------------------------------------------------------------

fn run_with_runner(args: &DefaultArgs, w: &mut impl Write, r: &mut dyn Runner) -> Result<()> {
    let pools = list_root_pools(r)?;
    if pools.is_empty() {
        bail!(
            "no root-role pool found (no pool tagged `zboot:role=root`); \
             nothing to set"
        );
    }

    let bes = list_bes(r, &pools)?;
    let target = resolve_target_be(&bes, &args.name)?.clone();

    // Warn if target is the mirror side of a pair (zboot:primary=off).
    // `default` only sets bootfs; it doesn't touch `zboot:primary` or
    // peer's state. If the operator wants the full failover gesture
    // (flip primary + readonly on both sides), they should use `primary`
    // instead. Helps catch the typo where you mean to fail over but
    // type `default`.
    if let Ok(primary_val) = crate::zfs_ops::dataset_property(&target.dataset, "zboot:primary") {
        if primary_val == "off" {
            // Only warn if paired (primary=off with no mirror is meaningless).
            let paired = crate::zfs_ops::read_pair_pointer(&target.dataset)
                .ok()
                .flatten()
                .is_some();
            if paired {
                writeln!(
                    w,
                    "  warning: {} is the mirror side of a pair (zboot:primary=off).\n  \
                     `default` only sets bootfs; it does not flip primary or readonly. \
                     Did you mean `primary {}`?",
                    target.dataset, target.dataset,
                )
                .ok();
            }
        }
    }

    // `zpool set bootfs=...` requires the target pool to be imported
    // read-write. `status`'s auto-import scan brings secondary
    // `zboot:role=root` pools in read-only; promote before mutating.
    // Idempotent — no-op when already R/W. Guarded against tests by
    // the `is_pool_imported` returning false when no real ZFS state
    // is present (FakeRunner in unit tests).
    //
    // Same guard wraps the readonly check below: if the pool isn't
    // imported on this host, there's no live property to inspect, and
    // the FakeRunner in tests doesn't expect a `zfs get readonly`.
    if crate::pools::is_pool_imported(&target.pool).unwrap_or(false) {
        crate::pools::ensure_pool_imported_rw(&target.pool)
            .context("default: target pool must be imported R/W to set bootfs")?;

        // `mirror` sets `readonly=on` on the dest BE as a safety rail so
        // accidental writes can't fork it from its source. Booting into
        // such a BE leaves the rootfs read-only at the ZFS layer — systemd's
        // remount-rw fails. Switching the BE to active is the explicit
        // "I'm committing to this slot" signal — clear `readonly=off` so
        // the resulting boot behaves like any other primary slot.
        // Idempotent: skipped when already `off`.
        if target_be_readonly_on(r, &target.dataset)? {
            writeln!(
                w,
                "default: clearing readonly on {} (was a mirror dest)",
                target.dataset
            )
            .ok();
            zfs_set(r, &target.dataset, "readonly", "off")?;
        }
    }

    // ----- bootfs ------------------------------------------------------------
    let target_pool = pools
        .iter()
        .find(|p| p.name == target.pool)
        .ok_or_else(|| {
            anyhow!(
                "internal: target BE {:?} references unknown pool {:?}",
                target.name,
                target.pool
            )
        })?;

    let already_active = target_pool.bootfs.as_deref() == Some(target.dataset.as_str());

    // Write order matters: clear losers FIRST, set the winner LAST.
    // If interrupted mid-write, zero pools have bootfs (recoverable:
    // re-run `default <name>`) instead of two (ambiguous boot — the
    // bootloader picks one alphabetically and the user has no idea
    // which).
    //
    // Cross-pool single-active invariant: if any OTHER root pool has
    // a `bootfs` set, clear it. zboot-boot's menu picks the first
    // `is_active` BE alphabetically across all pools, so leaving
    // stale bootfs on a sibling pool means `default` on a different
    // pool appears to do nothing — the boot still goes to the sibling.
    // `zpool set bootfs=` empty is rejected by some ZFS versions;
    // a bare `-` is universally accepted as "unset".
    //
    // Capture the previously-active BE datasets *before* clearing so we
    // can flip them to `readonly=on` after. The active BE is the only
    // writable one; everything else (including the BE that just lost
    // active status) becomes a read-only replica. Prevents the operator
    // from accidentally diverging the inactive side by manual mount+write.
    let mut ex_active_bes: Vec<String> = Vec::new();
    for p in &pools {
        if let Some(bootfs) = &p.bootfs
            && bootfs.as_str() != target.dataset.as_str()
        {
            ex_active_bes.push(bootfs.clone());
        }
    }

    for p in &pools {
        if p.name == target.pool {
            continue;
        }
        if p.bootfs.is_some() {
            writeln!(
                w,
                "default: clearing bootfs on pool {} (was {})",
                p.name,
                p.bootfs.as_deref().unwrap_or("-")
            )
            .ok();
            zpool_set(r, &p.name, "bootfs", "")
                .or_else(|_| zpool_set(r, &p.name, "bootfs", "-"))?;
        }
    }

    // Symmetric primary/mirror invariant: flip every ex-active BE to
    // `readonly=on`. Combined with the `readonly=off` set on the new
    // target below, exactly one BE across all root pools is writable —
    // the active one. Inactive BEs become physical read-only replicas;
    // recovery work (mount + edit) requires explicit `zfs set
    // readonly=off` opt-in.
    //
    // Gated on `is_pool_imported` per the ex-active's pool: if the
    // inactive pool is currently imported R/O (auto-import scan), the
    // property write would fail. We don't promote inactive pools just
    // to set readonly. The dest will pick up readonly=on the next time
    // it's R/W-imported. Also keeps unit tests clean (FakeRunner skips
    // the readonly writes when `is_pool_imported` returns false).
    //
    // **Live-root caveat**: ZFS's `readonly` property triggers an
    // immediate remount regardless of `-u` (the `-u` flag only skips
    // remount for `mountpoint`/`sharenfs`/`sharesmb`). If the ex-active
    // is currently mounted (the typical case — operator runs `default`
    // from within the BE they're abandoning), setting `readonly=on`
    // would remount that filesystem read-only — including `/` if it's
    // the live root. We skip mounted datasets and rely on mirror's
    // divergence-refusal as the reactive backstop. Inactive non-live
    // datasets still get the proactive readonly=on.
    for ds in &ex_active_bes {
        let ex_pool = ds.split('/').next().unwrap_or("");
        if !crate::pools::is_pool_imported(ex_pool).unwrap_or(false) {
            continue;
        }
        if is_dataset_mounted(ds) {
            writeln!(
                w,
                "default: ex-active {ds} is currently mounted — skipping readonly=on \
                 to avoid breaking the live mount. Reboot to leave it unmounted, then \
                 manually `zfs set readonly=on {ds}` if you want the proactive rail. \
                 Divergence is still caught reactively by `mirror`'s refuse-on-divergence.",
            )
            .ok();
            continue;
        }
        writeln!(w, "default: marking ex-active {ds} readonly=on").ok();
        let _ = zfs_set(r, ds, "readonly", "on");
    }

    if already_active {
        writeln!(
            w,
            "default: {:?} is already active on pool {} — nothing to do",
            target.name, target.pool
        )
        .context("writing status line")?;
    } else {
        writeln!(
            w,
            "default: setting bootfs={} on pool {}",
            target.dataset, target.pool
        )
        .context("writing status line")?;
        zpool_set(r, &target.pool, "bootfs", &target.dataset)?;
    }

    // ----- attached datasets -------------------------------------------------
    //
    // Toggle `canmount` based on whether the new active BE is in the
    // dataset's `zboot:attached-to` list. We leave `mountpoint` alone so
    // `zfs get mountpoint /home` always reflects what the user set
    // (this avoids needing a `zboot:bound-mountpoint` cache property).
    //
    // - Active in bound-to → `canmount=on`  (auto-mount at next zfs.target)
    // - Inactive           → `canmount=off` (unmount + can't remount)
    let bound = list_bound_datasets(r, &pools)?;
    let target_key = BoundKey::new(target.pool.clone(), target.name.clone());

    for bd in &bound {
        let in_target = bd.bound_to.contains(&target_key);
        let desired = if in_target {
            Canmount::On
        } else {
            Canmount::Off
        };
        if bd.canmount == Some(desired) {
            continue;
        }
        let label = if in_target {
            "in target"
        } else {
            "not in target"
        };
        writeln!(
            w,
            "default: {} canmount -> {} ({label})",
            bd.dataset,
            desired.render(),
        )
        .ok();
        zfs_set(r, &bd.dataset, "canmount", desired.render())?;
    }

    Ok(())
}


/// Read the dataset's `readonly` property; `true` iff it's currently `on`.
/// Missing/unparseable values are treated as `off` (the safe default —
/// we'd rather skip a redundant `zfs set` than fail the whole `default`).
fn target_be_readonly_on(r: &mut dyn Runner, dataset: &str) -> Result<bool> {
    let out = sub::capture(r, "zfs", &["get", "-Hp", "-o", "value", "readonly", dataset])
        .with_context(|| format!("read readonly on {dataset}"))?;
    Ok(out.trim() == "on")
}

/// Resolve a target BE. Accepts:
/// - **fully-qualified dataset** (`rpool2/ROOT/be2`): exact match on `dataset`.
/// - **bare name** (`be2`): matches by `name` across pools; `pool_filter`
///   (when set) narrows to that pool; without filter, refuses to guess
///   when the name is ambiguous.
fn resolve_target_be<'a>(bes: &'a [BeInfo], name_or_path: &str) -> Result<&'a BeInfo> {
    if name_or_path.contains('/') {
        return bes
            .iter()
            .find(|be| be.dataset == name_or_path)
            .ok_or_else(|| anyhow!("no boot environment matching dataset {name_or_path:?}"));
    }
    let matches: Vec<&BeInfo> = bes.iter().filter(|be| be.name == name_or_path).collect();
    match matches.len() {
        0 => {
            let known: Vec<String> = bes.iter().map(|b| b.dataset.clone()).collect();
            Err(anyhow!(
                "no boot environment named {:?} (known: {})",
                name_or_path,
                if known.is_empty() { "<none>".to_owned() } else { known.join(", ") }
            ))
        }
        1 => Ok(matches[0]),
        _ => {
            let dsets: Vec<&str> = matches.iter().map(|b| b.dataset.as_str()).collect();
            Err(anyhow!(
                "ambiguous: BE {:?} exists in multiple pools: {}. \
                 Disambiguate by passing the full dataset path.",
                name_or_path,
                dsets.join(", ")
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery — minimal slice of state needed by default.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PoolInfo {
    name: String,
    bootfs: Option<String>,
}

#[derive(Debug, Clone)]
struct BeInfo {
    pool: String,
    dataset: String,
    name: String,
}

#[derive(Debug, Clone)]
struct BoundDsInfo {
    dataset: String,
    bound_to: BoundList,
    /// Current `canmount` — used for idempotency (skip `zfs set` when
    /// the property already has the desired value).
    canmount: Option<Canmount>,
}

fn list_root_pools(r: &mut dyn Runner) -> Result<Vec<PoolInfo>> {
    let pl = sub::capture(r, "zpool", &["list", "-Hp", "-o", "name,bootfs,guid"])?;
    let pools = parse_zpool_list(&pl).context("parsing `zpool list`")?;
    if pools.is_empty() {
        return Ok(Vec::new());
    }

    let names: Vec<&str> = pools.iter().map(|p| p.name.as_str()).collect();
    let mut args: Vec<&str> = vec!["get", "-Hp", "-o", "name,property,value", "zboot:role"];
    args.extend(names.iter().copied());
    let role_text = sub::capture(r, "zpool", &args)?;
    let role_props = parse_zfs_get(&role_text).context("parsing `zpool get zboot:role`")?;

    let mut roots: Vec<PoolInfo> = Vec::new();
    for p in &pools {
        let role = role_props
            .iter()
            .find(|(n, prop)| n == &p.name && matches!(prop, Property::ZbootRole(_)))
            .map(|(_, prop)| prop);
        if matches!(role, Some(Property::ZbootRole(PoolRole::Root))) {
            roots.push(PoolInfo {
                name: p.name.clone(),
                bootfs: p.bootfs.clone(),
            });
        }
    }
    Ok(roots)
}

fn list_bes(r: &mut dyn Runner, pools: &[PoolInfo]) -> Result<Vec<BeInfo>> {
    if pools.is_empty() {
        return Ok(Vec::new());
    }

    // `zfs get -Hpr -o name,property,value zboot:be <pool>...` — recursive
    // across each root pool, surfaces every dataset whose `zboot:be` is set
    // (including inherited values, but only datasets with their own
    // `zboot:be=true` setting are BEs).
    let mut args: Vec<&str> = vec!["get", "-Hpr", "-o", "name,property,value", "zboot:be"];
    let names: Vec<&str> = pools.iter().map(|p| p.name.as_str()).collect();
    args.extend(names.iter().copied());
    let text = sub::capture(r, "zfs", &args)?;
    let props = parse_zfs_get(&text).context("parsing `zfs get zboot:be`")?;

    let mut bes = Vec::new();
    for (ds, prop) in &props {
        if let Property::ZbootBe(true) = prop {
            let (pool, name) = split_dataset_pool_and_name(ds);
            // Only count BEs whose pool is one of the root-role pools we're
            // operating against — defends against stray `zboot:be=true` on
            // a non-root pool.
            if pools.iter().any(|p| p.name == pool) {
                bes.push(BeInfo {
                    pool: pool.to_owned(),
                    dataset: ds.clone(),
                    name: name.to_owned(),
                });
            }
        }
    }
    Ok(bes)
}

#[derive(Default)]
struct BoundDsAcc {
    bound_to: Option<BoundList>,
    canmount: Option<Canmount>,
}

fn list_bound_datasets(r: &mut dyn Runner, pools: &[PoolInfo]) -> Result<Vec<BoundDsInfo>> {
    use std::collections::BTreeMap;

    if pools.is_empty() {
        return Ok(Vec::new());
    }

    // One fetch: bound-to + current canmount (for idempotency).
    let mut args: Vec<&str> = vec![
        "get",
        "-Hpr",
        "-o",
        "name,property,value",
        "zboot:attached-to,canmount",
    ];
    let names: Vec<&str> = pools.iter().map(|p| p.name.as_str()).collect();
    args.extend(names.iter().copied());
    let text = sub::capture(r, "zfs", &args)?;
    let props = parse_zfs_get(&text).context("parsing `zfs get` for bound datasets")?;

    let mut by_ds: BTreeMap<String, BoundDsAcc> = BTreeMap::new();
    for (ds, prop) in &props {
        let acc = by_ds.entry(ds.clone()).or_default();
        match prop {
            Property::ZbootAttachedTo(bl) => acc.bound_to = Some(bl.clone()),
            Property::Canmount(c) => acc.canmount = Some(*c),
            _ => {}
        }
    }

    let mut out = Vec::new();
    for (ds, acc) in by_ds {
        if let Some(bl) = acc.bound_to {
            out.push(BoundDsInfo {
                dataset: ds,
                bound_to: bl,
                canmount: acc.canmount,
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Mutating ZFS calls.
// ---------------------------------------------------------------------------

fn zpool_set(r: &mut dyn Runner, pool: &str, prop: &str, value: &str) -> Result<()> {
    let assignment = format!("{prop}={value}");
    let out = r
        .run("zpool", &["set", &assignment, pool])
        .with_context(|| format!("running `zpool set {assignment} {pool}`"))?;
    if out.rc != 0 {
        bail!(
            "`zpool set {assignment} {pool}` failed rc={}: {}",
            out.rc,
            out.stderr.trim()
        );
    }
    Ok(())
}

fn zfs_set(r: &mut dyn Runner, dataset: &str, prop: &str, value: &str) -> Result<()> {
    let assignment = format!("{prop}={value}");
    let out = r
        .run("zfs", &["set", &assignment, dataset])
        .with_context(|| format!("running `zfs set {assignment} {dataset}`"))?;
    if out.rc != 0 {
        bail!(
            "`zfs set {assignment} {dataset}` failed rc={}: {}",
            out.rc,
            out.stderr.trim()
        );
    }
    Ok(())
}

/// Check whether the dataset is currently mounted anywhere. ZFS's
/// `readonly` property triggers an unconditional remount when set,
/// even with `-u` — so we use this to skip `readonly=on` writes that
/// would brick a live mount (e.g. the live root when running `default`
/// from within the BE being abandoned).
fn is_dataset_mounted(dataset: &str) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return false;
    };
    for line in mounts.lines() {
        if line.split_whitespace().next() == Some(dataset) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn split_dataset_pool_and_name(dataset: &str) -> (&str, &str) {
    let pool = dataset.split('/').next().unwrap_or(dataset);
    let name = dataset.rsplit('/').next().unwrap_or(dataset);
    (pool, name)
}

// ===========================================================================
// Tests — pure-data exercises of the planning loop with a fake Runner.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Recorded transcript runner.
    ///
    /// `expectations` is a queue of `(prog, args, output)` tuples. Each call
    /// to `run` pops the front entry and asserts the prog/args match. Tests
    /// assert at the end that the queue is drained.
    #[derive(Default)]
    struct FakeRunner {
        expectations: VecDeque<(String, Vec<String>, RunOutput)>,
        observed: Vec<(String, Vec<String>)>,
    }

    impl FakeRunner {
        fn expect(&mut self, prog: &str, args: &[&str], rc: i32, stdout: &str, stderr: &str) {
            self.expectations.push_back((
                prog.to_owned(),
                args.iter().map(|s| (*s).to_owned()).collect(),
                RunOutput {
                    rc,
                    stdout: stdout.to_owned(),
                    stderr: stderr.to_owned(),
                },
            ));
        }
    }

    impl Runner for FakeRunner {
        fn run(&mut self, prog: &str, args: &[&str]) -> Result<RunOutput> {
            let observed_args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
            self.observed.push((prog.to_owned(), observed_args.clone()));
            let (eprog, eargs, out) = self
                .expectations
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected call: {prog} {observed_args:?}"));
            assert_eq!(
                prog, eprog,
                "prog mismatch (observed args: {observed_args:?})"
            );
            assert_eq!(eargs, observed_args, "args mismatch for {prog}");
            Ok(out)
        }
    }

    fn zpool_list_text() -> &'static str {
        "rpool\trpool/ROOT/BE1\t111\n"
    }

    fn zpool_list_two_pools() -> &'static str {
        "rpool\trpool/ROOT/BE1\t111\nrpool2\trpool2/ROOT/BE1\t222\n"
    }

    /// rpool active (bootfs=BE1); rpool2 has no bootfs set.
    fn zpool_list_two_pools_one_active() -> &'static str {
        "rpool\trpool/ROOT/BE1\t111\nrpool2\t-\t222\n"
    }

    // ------------------------------------------------------------------
    // Helpers — typical fixed transcript prefix shared by most tests.
    // ------------------------------------------------------------------

    fn expect_discovery_single_pool(r: &mut FakeRunner, zboot_be_text: &str, bound_text: &str) {
        r.expect(
            "zpool",
            &["list", "-Hp", "-o", "name,bootfs,guid"],
            0,
            zpool_list_text(),
            "",
        );
        r.expect(
            "zpool",
            &[
                "get",
                "-Hp",
                "-o",
                "name,property,value",
                "zboot:role",
                "rpool",
            ],
            0,
            "rpool\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:be",
                "rpool",
            ],
            0,
            zboot_be_text,
            "",
        );
        // After bootfs decision, list_bound_datasets is called.
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:attached-to,canmount",
                "rpool",
            ],
            0,
            bound_text,
            "",
        );
    }

    // ------------------------------------------------------------------
    // Test cases
    // ------------------------------------------------------------------

    #[test]
    fn default_unknown_be_errors_without_writing() {
        let mut r = FakeRunner::default();
        r.expect(
            "zpool",
            &["list", "-Hp", "-o", "name,bootfs,guid"],
            0,
            zpool_list_text(),
            "",
        );
        r.expect(
            "zpool",
            &[
                "get",
                "-Hp",
                "-o",
                "name,property,value",
                "zboot:role",
                "rpool",
            ],
            0,
            "rpool\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:be",
                "rpool",
            ],
            0,
            "rpool/ROOT/BE1\tzboot:be\ttrue\n",
            "",
        );
        let mut buf = Vec::new();
        let res = run_with_runner(
            &DefaultArgs {
                name: "ghost".into(),
            },
            &mut buf,
            &mut r,
        );
        let err = res.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("ghost"), "{msg}");
        // No `zpool set` / `zfs set` calls expected.
        assert!(r.expectations.is_empty(), "queue should be drained");
        assert!(
            !r.observed
                .iter()
                .any(|(p, a)| p == "zpool" && a.first().is_some_and(|x| x == "set")),
            "must not call zpool set on error: {:?}",
            r.observed
        );
    }

    #[test]
    fn default_idempotent_on_active_be() {
        let mut r = FakeRunner::default();
        expect_discovery_single_pool(
            &mut r,
            "rpool/ROOT/BE1\tzboot:be\ttrue\n",
            "", // no bound datasets
        );
        // No `zpool set bootfs=` because BE1 is already active.
        // No `zfs set` calls because no bound datasets.
        let mut buf = Vec::new();
        run_with_runner(&DefaultArgs { name: "BE1".into() }, &mut buf, &mut r).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("already active"), "{out}");
        assert!(
            !r.observed
                .iter()
                .any(|(p, a)| p == "zpool" && a.first().is_some_and(|x| x == "set")),
            "no zpool set on idempotent path: {:?}",
            r.observed
        );
        assert!(r.expectations.is_empty(), "queue should be drained");
    }

    #[test]
    fn default_sets_bootfs_when_changing_be() {
        let mut r = FakeRunner::default();
        // Pool says active=BE1, two BEs exist; we'll switch to BE2.
        r.expect(
            "zpool",
            &["list", "-Hp", "-o", "name,bootfs,guid"],
            0,
            zpool_list_text(),
            "",
        );
        r.expect(
            "zpool",
            &[
                "get",
                "-Hp",
                "-o",
                "name,property,value",
                "zboot:role",
                "rpool",
            ],
            0,
            "rpool\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:be",
                "rpool",
            ],
            0,
            "rpool/ROOT/BE1\tzboot:be\ttrue\nrpool/ROOT/BE2\tzboot:be\ttrue\n",
            "",
        );
        // bootfs change first.
        r.expect(
            "zpool",
            &["set", "bootfs=rpool/ROOT/BE2", "rpool"],
            0,
            "",
            "",
        );
        // Then bound-dataset listing (empty in this test).
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:attached-to,canmount",
                "rpool",
            ],
            0,
            "",
            "",
        );
        let mut buf = Vec::new();
        run_with_runner(&DefaultArgs { name: "BE2".into() }, &mut buf, &mut r).unwrap();
        assert!(r.expectations.is_empty(), "queue should be drained");
    }

    #[test]
    fn default_unbinds_dataset_bound_to_other_be_only() {
        let mut r = FakeRunner::default();
        r.expect(
            "zpool",
            &["list", "-Hp", "-o", "name,bootfs,guid"],
            0,
            zpool_list_text(),
            "",
        );
        r.expect(
            "zpool",
            &[
                "get",
                "-Hp",
                "-o",
                "name,property,value",
                "zboot:role",
                "rpool",
            ],
            0,
            "rpool\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:be",
                "rpool",
            ],
            0,
            "rpool/ROOT/BE1\tzboot:be\ttrue\nrpool/ROOT/BE2\tzboot:be\ttrue\n",
            "",
        );
        r.expect(
            "zpool",
            &["set", "bootfs=rpool/ROOT/BE2", "rpool"],
            0,
            "",
            "",
        );
        // /home is bound only to BE1; switching to BE2 must set its
        // canmount=off (active BE not in bound-to list).
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:attached-to,canmount",
                "rpool",
            ],
            0,
            "rpool/home\tzboot:attached-to\trpool:BE1\n\
             rpool/home\tcanmount\ton\n",
            "",
        );
        r.expect("zfs", &["set", "canmount=off", "rpool/home"], 0, "", "");

        let mut buf = Vec::new();
        run_with_runner(&DefaultArgs { name: "BE2".into() }, &mut buf, &mut r).unwrap();
        assert!(r.expectations.is_empty(), "queue should be drained");
    }

    #[test]
    fn default_remounts_dataset_bound_to_target() {
        let mut r = FakeRunner::default();
        r.expect(
            "zpool",
            &["list", "-Hp", "-o", "name,bootfs,guid"],
            0,
            zpool_list_text(),
            "",
        );
        r.expect(
            "zpool",
            &[
                "get",
                "-Hp",
                "-o",
                "name,property,value",
                "zboot:role",
                "rpool",
            ],
            0,
            "rpool\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:be",
                "rpool",
            ],
            0,
            "rpool/ROOT/BE1\tzboot:be\ttrue\nrpool/ROOT/BE2\tzboot:be\ttrue\n",
            "",
        );
        r.expect(
            "zpool",
            &["set", "bootfs=rpool/ROOT/BE2", "rpool"],
            0,
            "",
            "",
        );
        // /home is bound to BE1+BE2; switching from BE1 to BE2 keeps mount.
        // Current mountpoint shows `none` to verify we *do* set it.
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:attached-to,canmount",
                "rpool",
            ],
            0,
            "rpool/home\tzboot:attached-to\trpool:BE1,rpool:BE2\n\
             rpool/home\tcanmount\toff\n",
            "",
        );
        r.expect("zfs", &["set", "canmount=on", "rpool/home"], 0, "", "");

        let mut buf = Vec::new();
        run_with_runner(&DefaultArgs { name: "BE2".into() }, &mut buf, &mut r).unwrap();
        assert!(r.expectations.is_empty(), "queue should be drained");
    }

    #[test]
    fn default_skips_zfs_set_when_mountpoint_already_correct() {
        let mut r = FakeRunner::default();
        r.expect(
            "zpool",
            &["list", "-Hp", "-o", "name,bootfs,guid"],
            0,
            zpool_list_text(),
            "",
        );
        r.expect(
            "zpool",
            &[
                "get",
                "-Hp",
                "-o",
                "name,property,value",
                "zboot:role",
                "rpool",
            ],
            0,
            "rpool\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:be",
                "rpool",
            ],
            0,
            "rpool/ROOT/BE1\tzboot:be\ttrue\n",
            "",
        );
        // Already-active BE; idempotent path. canmount=on already
        // matches "BE1 in bound-to" → no `zfs set` call needed.
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:attached-to,canmount",
                "rpool",
            ],
            0,
            "rpool/home\tzboot:attached-to\trpool:BE1\n\
             rpool/home\tcanmount\ton\n",
            "",
        );

        let mut buf = Vec::new();
        run_with_runner(&DefaultArgs { name: "BE1".into() }, &mut buf, &mut r).unwrap();
        assert!(r.expectations.is_empty(), "queue should be drained");
    }

    #[test]
    fn default_finds_be_in_second_root_pool() {
        let mut r = FakeRunner::default();
        r.expect(
            "zpool",
            &["list", "-Hp", "-o", "name,bootfs,guid"],
            0,
            zpool_list_two_pools(),
            "",
        );
        r.expect(
            "zpool",
            &[
                "get",
                "-Hp",
                "-o",
                "name,property,value",
                "zboot:role",
                "rpool",
                "rpool2",
            ],
            0,
            "rpool\tzboot:role\troot\nrpool2\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:be",
                "rpool",
                "rpool2",
            ],
            0,
            "rpool/ROOT/BE1\tzboot:be\ttrue\nrpool2/ROOT/BE1\tzboot:be\ttrue\n",
            "",
        );
        // Both pools have a BE named "BE1"; disambiguate by passing the
        // full dataset path. Target is rpool's BE1 (already-active there),
        // so bootfs on rpool isn't reset. BUT rpool2 has a stale bootfs
        // from the fixture, which the cross-pool single-active invariant
        // clears.
        r.expect(
            "zpool",
            &["set", "bootfs=", "rpool2"],
            0,
            "",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:attached-to,canmount",
                "rpool",
                "rpool2",
            ],
            0,
            "",
            "",
        );

        let mut buf = Vec::new();
        run_with_runner(
            &DefaultArgs { name: "rpool/ROOT/BE1".into() },
            &mut buf,
            &mut r,
        )
        .unwrap();
        assert!(r.expectations.is_empty(), "queue should be drained");
    }

    #[test]
    fn default_refuses_ambiguous_be_name_across_pools() {
        let mut r = FakeRunner::default();
        r.expect("zpool", &["list", "-Hp", "-o", "name,bootfs,guid"], 0, zpool_list_two_pools(), "");
        r.expect(
            "zpool",
            &["get", "-Hp", "-o", "name,property,value", "zboot:role", "rpool", "rpool2"],
            0,
            "rpool\tzboot:role\troot\nrpool2\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &["get", "-Hpr", "-o", "name,property,value", "zboot:be", "rpool", "rpool2"],
            0,
            "rpool/ROOT/BE1\tzboot:be\ttrue\nrpool2/ROOT/BE1\tzboot:be\ttrue\n",
            "",
        );
        let mut buf = Vec::new();
        let err = run_with_runner(
            &DefaultArgs { name: "BE1".into() },
            &mut buf,
            &mut r,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("ambiguous"), "{msg}");
        assert!(msg.contains("full dataset path"), "{msg}");
    }

    /// Crash-safety: when `default` switches the active pool, the
    /// loser's bootfs MUST be cleared before the winner's bootfs is
    /// set. A mid-crash with the opposite order would leave two pools
    /// with bootfs set — bootloader picks one alphabetically and the
    /// user has no idea which.
    #[test]
    fn default_clears_losing_pool_before_setting_winner() {
        let mut r = FakeRunner::default();
        // rpool is active (bootfs=rpool/ROOT/BE1); rpool2 has BE2 we'll switch to.
        r.expect(
            "zpool",
            &["list", "-Hp", "-o", "name,bootfs,guid"],
            0,
            zpool_list_two_pools_one_active(),
            "",
        );
        r.expect(
            "zpool",
            &[
                "get",
                "-Hp",
                "-o",
                "name,property,value",
                "zboot:role",
                "rpool",
                "rpool2",
            ],
            0,
            "rpool\tzboot:role\troot\nrpool2\tzboot:role\troot\n",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:be",
                "rpool",
                "rpool2",
            ],
            0,
            "rpool/ROOT/BE1\tzboot:be\ttrue\nrpool2/ROOT/BE2\tzboot:be\ttrue\n",
            "",
        );
        // ORDER MATTERS — the FakeRunner enforces it via FIFO dequeue.
        // (1) Clear rpool first (it's the loser).
        r.expect("zpool", &["set", "bootfs=", "rpool"], 0, "", "");
        // (2) THEN set rpool2 (the winner).
        r.expect(
            "zpool",
            &["set", "bootfs=rpool2/ROOT/BE2", "rpool2"],
            0,
            "",
            "",
        );
        r.expect(
            "zfs",
            &[
                "get",
                "-Hpr",
                "-o",
                "name,property,value",
                "zboot:attached-to,canmount",
                "rpool",
                "rpool2",
            ],
            0,
            "",
            "",
        );

        let mut buf = Vec::new();
        run_with_runner(&DefaultArgs { name: "BE2".into() }, &mut buf, &mut r).unwrap();
        assert!(r.expectations.is_empty(), "queue should be drained");

        // Belt-and-suspenders: also cross-check the recorded sequence.
        let order: Vec<String> = r
            .observed
            .iter()
            .filter_map(|(prog, args)| {
                if prog == "zpool" && args.first().map(String::as_str) == Some("set") {
                    Some(args.join(" "))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(order.len(), 2, "expected 2 zpool set calls, got {order:?}");
        assert!(
            order[0].contains("bootfs= rpool"),
            "first zpool set must clear the loser; got {:?}",
            order[0]
        );
        assert!(
            order[1].contains("bootfs=rpool2/ROOT/BE2 rpool2"),
            "second zpool set must set the winner; got {:?}",
            order[1]
        );
    }

    #[test]
    fn split_dataset_pool_and_name_basic() {
        assert_eq!(
            split_dataset_pool_and_name("rpool/ROOT/BE1"),
            ("rpool", "BE1")
        );
        assert_eq!(split_dataset_pool_and_name("rpool/home"), ("rpool", "home"));
    }

    // -- readonly-clearing helper -------------------------------------------

    #[test]
    fn target_be_readonly_on_detects_on() {
        let mut r = FakeRunner::default();
        r.expect(
            "zfs",
            &[
                "get",
                "-Hp",
                "-o",
                "value",
                "readonly",
                "rpool2/ROOT/be2",
            ],
            0,
            "on\n",
            "",
        );
        assert!(target_be_readonly_on(&mut r, "rpool2/ROOT/be2").unwrap());
    }

    #[test]
    fn target_be_readonly_on_returns_false_when_off() {
        let mut r = FakeRunner::default();
        r.expect(
            "zfs",
            &[
                "get",
                "-Hp",
                "-o",
                "value",
                "readonly",
                "rpool/ROOT/BE1",
            ],
            0,
            "off\n",
            "",
        );
        assert!(!target_be_readonly_on(&mut r, "rpool/ROOT/BE1").unwrap());
    }

    #[test]
    fn target_be_readonly_on_returns_false_when_unparseable() {
        let mut r = FakeRunner::default();
        r.expect(
            "zfs",
            &["get", "-Hp", "-o", "value", "readonly", "rpool/ROOT/BE1"],
            0,
            "-\n", // unset / inherited
            "",
        );
        assert!(!target_be_readonly_on(&mut r, "rpool/ROOT/BE1").unwrap());
    }
}
