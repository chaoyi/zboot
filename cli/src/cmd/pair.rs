//! `zboot pair` / `zboot unpair` — metadata-only verbs that flip the
//! `zboot:mirror` property without sending bytes.
//!
//! Pair semantics are asymmetric (see DESIGN.md § Replication
//! invariants): `pair a b` always sets `zboot:mirror` on `a` (refuses
//! if `a` already has one — use `unpair` first), and additionally sets
//! it on `b` IF `b` has none (mutual). If `b` already points elsewhere
//! — the canonical "one" in a one-to-many topology — its pointer is
//! left alone; `a` becomes a tracking-only "many" side.

use std::collections::BTreeSet;
use std::io::Write;

use anyhow::{Result, anyhow, bail};
use clap::Args;

use crate::zfs_ops;
use zboot_core::{PairPointer, is_replication_anchor};

#[derive(Debug, Args)]
pub struct PairArgs {
    /// First BE (full dataset path).
    pub a: String,
    /// Second BE (full dataset path).
    pub b: String,
    /// Skip the GUID-set compatibility check. Use only when you know
    /// the two sides are actually peers (initialized from the same
    /// source, identical snapshot history).
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct UnpairArgs {
    /// BE whose `zboot:mirror` to clear (full dataset path).
    pub be: String,
}

pub fn run_pair(args: &PairArgs, w: &mut impl Write) -> Result<()> {
    if args.a == args.b {
        bail!("can't pair a BE with itself");
    }
    let a_pool = pool_of(&args.a)?;
    let b_pool = pool_of(&args.b)?;
    if a_pool == b_pool {
        bail!("pair must be cross-pool (got {a_pool} for both sides)");
    }
    for ds in [&args.a, &args.b] {
        if !zfs_ops::dataset_exists(ds)? {
            bail!("dataset {ds} does not exist");
        }
    }
    if zfs_ops::read_pair_pointer(&args.a)?.is_some() {
        bail!("{} already has a pair; clear with `unpair` first", args.a);
    }

    if !args.force {
        verify_compatible(&args.a, &args.b)?;
    }

    let a_peer = PairPointer::parse_dataset(&args.b)
        .ok_or_else(|| anyhow!("{} not in canonical `<pool>/ROOT/<be>` form", args.b))?;
    let b_peer = PairPointer::parse_dataset(&args.a)
        .ok_or_else(|| anyhow!("{} not in canonical `<pool>/ROOT/<be>` form", args.a))?;

    let b_was_paired = zfs_ops::read_pair_pointer(&args.b)?.is_some();
    zfs_ops::write_pair_pointer(&args.a, &a_peer)?;
    if !b_was_paired {
        zfs_ops::write_pair_pointer(&args.b, &b_peer)?;
        // Convention: first arg is primary, second is mirror.
        zfs_ops::set_property_tolerant(&args.a, "zboot:primary", "on")?;
        zfs_ops::set_property_tolerant(&args.b, "zboot:primary", "off")?;
        writeln!(w, "  paired {} \u{2194} {} (mutual; {} is primary)", args.a, args.b, args.a).ok();
    } else {
        // Asymmetric: a is tracking-only mirror of b; b's primary state untouched.
        zfs_ops::set_property_tolerant(&args.a, "zboot:primary", "off")?;
        writeln!(
            w,
            "  paired {} \u{2192} {} (asymmetric — {} already has a pair; {} is tracking-only)",
            args.a, args.b, args.b, args.a
        )
        .ok();
    }
    Ok(())
}

pub fn run_unpair(args: &UnpairArgs, w: &mut impl Write) -> Result<()> {
    let pointer = zfs_ops::read_pair_pointer(&args.be)?.ok_or_else(|| {
        anyhow!(
            "{} has no zboot:mirror; nothing to unpair",
            args.be
        )
    })?;
    zfs_ops::clear_pair_pointer(&args.be)?;
    // Clear primary marker on the local side too (the pair is gone, the
    // marker has no referent).
    let _ = zfs_ops::inherit_property_tolerant(&args.be, "zboot:primary");
    writeln!(w, "  cleared zboot:mirror + zboot:primary on {}", args.be).ok();

    // If the peer was pointing back at us (mutual case), clear the
    // peer's pointer too. If the peer was pointing elsewhere (we were
    // tracking-only), leave it.
    let peer_ds = pointer.render();
    if zfs_ops::dataset_exists(&peer_ds).unwrap_or(false) {
        match zfs_ops::read_pair_pointer(&peer_ds)? {
            Some(peer_pointer) => {
                let we_are_peer = PairPointer::parse_dataset(&args.be)
                    .map(|p| p == peer_pointer)
                    .unwrap_or(false);
                if we_are_peer {
                    zfs_ops::clear_pair_pointer(&peer_ds)?;
                    let _ = zfs_ops::inherit_property_tolerant(&peer_ds, "zboot:primary");
                    writeln!(w, "  cleared zboot:mirror + zboot:primary on {peer_ds} (mutual)").ok();
                } else {
                    writeln!(
                        w,
                        "  left {peer_ds} alone (its pair points at {}, not at {})",
                        peer_pointer.render(),
                        args.be,
                    )
                    .ok();
                }
            }
            None => {
                writeln!(w, "  {peer_ds} had no pair pointer; nothing to clear there").ok();
            }
        }
    } else {
        writeln!(w, "  peer {peer_ds} not reachable; left as-is").ok();
    }
    Ok(())
}

fn pool_of(ds: &str) -> Result<String> {
    ds.split('/')
        .next()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("bad dataset {ds}"))
}

/// Compatibility: the GUID sets on the two sides should be one-a-subset-
/// of-the-other (modulo equality). Replication anchors excluded.
fn verify_compatible(a: &str, b: &str) -> Result<()> {
    let a_set: BTreeSet<String> = zfs_ops::list_snapshots_with_guids(a)
        .unwrap_or_default()
        .into_iter()
        .filter(|(n, _)| !is_replication_anchor(n))
        .map(|(_, g)| g)
        .collect();
    let b_set: BTreeSet<String> = zfs_ops::list_snapshots_with_guids(b)
        .unwrap_or_default()
        .into_iter()
        .filter(|(n, _)| !is_replication_anchor(n))
        .map(|(_, g)| g)
        .collect();
    let a_only: BTreeSet<&String> = a_set.difference(&b_set).collect();
    let b_only: BTreeSet<&String> = b_set.difference(&a_set).collect();
    if a_only.is_empty() || b_only.is_empty() {
        return Ok(());
    }
    bail!(
        "refuses: GUID sets diverged ({a} has {ao} snaps {b} doesn't; {b} has {bo} snaps \
         {a} doesn't). Pairing now would create immediate divergence. \
         Use --force to skip, but you'll need `push --force` or `pull --force` next.",
        ao = a_only.len(),
        bo = b_only.len(),
    )
}
