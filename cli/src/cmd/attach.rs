//! `zboot attach` — attach a dataset to one or more BEs. Writes
//! `zboot:attached-to` and toggles `canmount` based on whether the pool's
//! active BE is in the list. The dataset's `mountpoint` is left alone
//! (user controls that via `zfs set mountpoint=…`).
//!
//! Two modes:
//!
//! ```text
//! zboot attach <DATASET>                                   # show
//! zboot attach <DATASET> --to BE1[,BE2,…]                  # set list
//! ```
//!
//! `<BE>` entries follow `pool:name` (e.g. `rpool:be1`).
//!
//! To clear: `zboot detach <DATASET>` — leaves `canmount`/`mountpoint`
//! as-is, only inherits the `zboot:attached-to` property. To remove
//! one BE from a multi-BE list, re-run `attach --to` with a smaller list.

use std::io::Write;

use anyhow::{Context, Result, bail};
use clap::Args;

use zboot_core::{BoundKey, BoundList};

use crate::sub;

#[derive(Debug, Args)]
pub struct AttachArgs {
    /// Target dataset (e.g. `rpool/home`).
    pub dataset: String,

    /// New `bound-to` list (comma-separated `pool:be` entries). Without
    /// this, `attach <DATASET>` just prints the dataset's current
    /// `zboot:attached-to` state. To clear, use `zboot detach <DATASET>`.
    #[arg(long)]
    pub to: Option<String>,
}

pub fn run(args: &AttachArgs, w: &mut impl Write) -> Result<()> {
    match &args.to {
        Some(list) => run_set(&args.dataset, list, w),
        None => run_show(&args.dataset, w),
    }
}

#[derive(Debug, clap::Args)]
pub struct DetachArgs {
    /// Target dataset to detach from any BE bindings.
    pub dataset: String,
}

/// `zboot detach <DATASET>` — sugar for `zboot attach <DATASET> --clear`.
pub fn detach(args: &DetachArgs, w: &mut impl Write) -> Result<()> {
    run_clear(&args.dataset, w)
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

fn run_show(dataset: &str, w: &mut impl Write) -> Result<()> {
    let bound_to = read_prop(dataset, "zboot:attached-to")?;
    let canmount = read_prop(dataset, "canmount")?;
    let mp_live = read_prop(dataset, "mountpoint")?;
    writeln!(w, "{dataset}").ok();
    writeln!(w, "  zboot:attached-to : {}", or_dash(&bound_to)).ok();
    writeln!(w, "  canmount       : {}", or_dash(&canmount)).ok();
    writeln!(w, "  mountpoint     : {}", or_dash(&mp_live)).ok();
    Ok(())
}

fn or_dash(s: &str) -> &str {
    if is_unset(s) { "(unset)" } else { s }
}

// ---------------------------------------------------------------------------
// clear
// ---------------------------------------------------------------------------

fn run_clear(dataset: &str, w: &mut impl Write) -> Result<()> {
    writeln!(w, "attach: clearing zboot:attached-to on {dataset}").ok();
    sub::zfs(&["inherit", "zboot:attached-to", dataset])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// set
// ---------------------------------------------------------------------------

fn run_set(dataset: &str, list_str: &str, w: &mut impl Write) -> Result<()> {
    let new_list =
        BoundList::parse(list_str).with_context(|| format!("parsing --to {list_str:?}"))?;

    // Validate each `pool:be` resolves to an actual BE before writing the
    // property — silently accepting a typo'd BE name leaves a dataset
    // permanently `canmount=off` on every active BE and produces an
    // orphan-style entry that surfaces only via `status`. Reject early
    // with a hint listing the known BEs in the named pool.
    ensure_bes_exist(&new_list)?;

    let pool = pool_of(dataset);
    let active = active_be(pool)?;
    let active_in_list = new_list.0.contains(&active);
    let desired_canmount = if active_in_list { "on" } else { "off" };

    writeln!(w, "attach: {dataset}").ok();
    writeln!(w, "  zboot:attached-to := {}", new_list.render()).ok();
    writeln!(
        w,
        "  canmount       := {desired_canmount} (active={})",
        active.render(),
    )
    .ok();

    sub::zfs(&[
        "set",
        &format!("zboot:attached-to={}", new_list.render()),
        dataset,
    ])?;
    sub::zfs(&["set", &format!("canmount={desired_canmount}"), dataset])?;
    Ok(())
}

/// Refuse the operation if any `pool:be` entry in the list doesn't point
/// at an existing dataset with `zboot:be=true`. Cross-pool: each entry's
/// pool prefix selects which pool to look in.
///
/// Single batched `zfs get` over `<pool>/ROOT/<be>` paths — one
/// subprocess per attach, not one per entry.
fn ensure_bes_exist(list: &BoundList) -> Result<()> {
    use std::collections::HashSet;
    let datasets: Vec<String> = list
        .0
        .iter()
        .map(|k| format!("{}/ROOT/{}", k.pool, k.be))
        .collect();
    let mut args: Vec<&str> = vec!["get", "-Hp", "-o", "name,value", "zboot:be"];
    let ds_refs: Vec<&str> = datasets.iter().map(String::as_str).collect();
    args.extend(ds_refs.iter().copied());

    // `zfs get <missing-dataset>` exits non-zero with "dataset does not
    // exist" — capture and parse the stderr for which entries are missing.
    let output = std::process::Command::new("zfs")
        .args(&args)
        .output()
        .context("spawn zfs get for attach validation")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Datasets that emitted a `zboot:be=true` row.
    let mut have_be: HashSet<&str> = HashSet::new();
    for line in stdout.lines() {
        let mut cols = line.split('\t');
        let (Some(name), Some(value)) = (cols.next(), cols.next()) else {
            continue;
        };
        if value.trim() == "true" {
            have_be.insert(name);
        }
    }

    let mut missing = Vec::new();
    for (k, ds) in list.0.iter().zip(datasets.iter()) {
        if !have_be.contains(ds.as_str()) {
            missing.push(k.render());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let hint = if stderr.contains("does not exist") {
        "(some datasets don't exist; check the pool prefix)"
    } else {
        "(datasets exist but lack `zboot:be=true` — they aren't BEs)"
    };
    bail!(
        "attach: unknown BE(s) in --to list: {} {hint}. \
         Run `zboot status` to see the BE catalog.",
        missing.join(", ")
    );
}

fn pool_of(dataset: &str) -> &str {
    dataset.split('/').next().unwrap_or(dataset)
}

fn is_unset(s: &str) -> bool {
    s.is_empty() || s == "-"
}

/// Read the pool's `bootfs` and split into pool + BE name.
fn active_be(pool: &str) -> Result<BoundKey> {
    let bootfs = sub::zpool_capture(&["get", "-Hp", "-o", "value", "bootfs", pool])?
        .trim()
        .to_owned();
    if bootfs.is_empty() || bootfs == "-" {
        bail!("pool {pool} has no bootfs set");
    }
    let be = bootfs
        .rsplit('/')
        .next()
        .with_context(|| format!("can't parse BE name from bootfs={bootfs:?}"))?;
    Ok(BoundKey::new(pool, be))
}

fn read_prop(dataset: &str, prop: &str) -> Result<String> {
    sub::zfs_capture(&["get", "-Hp", "-o", "value", prop, dataset]).map(|s| s.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_of_first_component() {
        assert_eq!(pool_of("rpool/home"), "rpool");
        assert_eq!(pool_of("rpool/ROOT/be1"), "rpool");
        assert_eq!(pool_of("rpool"), "rpool");
    }

    #[test]
    fn or_dash_handles_unset_forms() {
        assert_eq!(or_dash(""), "(unset)");
        assert_eq!(or_dash("-"), "(unset)");
        assert_eq!(or_dash("/home"), "/home");
    }
}
