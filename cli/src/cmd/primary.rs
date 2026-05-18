//! `zboot primary` — promote a BE to be the primary side of its mutual pair.
//!
//! Operation: flip `zboot:primary` and `readonly` on both sides of the
//! mutual pair, and move bootfs to follow if the demoted side was the
//! bootfs target on its pool. Metadata-only — no `zfs send/recv`. No
//! `--force` flag needed (every step is additive or a property write).
//!
//! Requires a mutual pair. Asymmetric tracking pointers (`Mirror[BE] =
//! peer` but `Mirror[peer]` points elsewhere) get a warning and proceed
//! on the local side only — peer's primary state is left alone.
//!
//! Live-root case: if peer is mounted at /, the `readonly=on` flip on
//! peer is skipped (ZFS won't honor it while mounted at /); the next
//! reboot unmounts peer, and a subsequent `push BE` from new-primary
//! to peer settles peer's readonly automatically (push sets readonly=on
//! on its receive side).

use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;

use crate::zfs_ops;
use zboot_core::PairPointer;

#[derive(Debug, Args)]
pub struct PrimaryArgs {
    /// BE to promote. Bare name (resolved against the booted pool — the
    /// pool whose dataset is currently mounted at `/`) or fully-qualified
    /// dataset path. Use the full path to disambiguate across pools.
    pub be: String,
}

pub fn run(args: &PrimaryArgs, w: &mut impl Write) -> Result<()> {
    let be_dataset = crate::be_arg::resolve_be_dataset(&args.be)?;
    if !zfs_ops::dataset_exists(&be_dataset)? {
        bail!("BE {be_dataset} does not exist");
    }

    let peer = zfs_ops::read_pair_pointer(&be_dataset)?.ok_or_else(|| {
        anyhow!(
            "{be_dataset} has no zboot:mirror peer; primary operates on mutual pairs only. \
             Run `pair {be_dataset} <peer>` first, or use `default {be_dataset}` if you \
             just want to change bootfs."
        )
    })?;
    let peer_ds = peer.render();

    // Verify mutual pair.
    let peer_back = if zfs_ops::dataset_exists(&peer_ds).unwrap_or(false) {
        zfs_ops::read_pair_pointer(&peer_ds)?
    } else {
        None
    };
    let be_pointer = PairPointer::parse_dataset(&be_dataset)
        .ok_or_else(|| anyhow!("{be_dataset} not in canonical form"))?;
    let mutual = peer_back.as_ref() == Some(&be_pointer);
    if !mutual {
        writeln!(
            w,
            "  warning: {peer_ds} doesn't point back at {be_dataset} (asymmetric pair). \
             Continuing on the local side only — peer's state untouched."
        )
        .ok();
    }

    // Idempotency: already primary?
    let cur_primary = read_primary_flag(&be_dataset)?;
    if cur_primary {
        writeln!(w, "  {be_dataset} is already zboot:primary=on — no-op.").ok();
        return Ok(());
    }

    writeln!(w, "  primary {be_dataset} (peer: {peer_ds})").ok();

    // Mutual case: snapshot peer if it's mounted at / (live-root failover
    // captures pre-flip state for the operator's restore reference). Skip
    // when peer isn't mounted — no stranded writes to worry about.
    if mutual && zfs_ops::is_mounted(&peer_ds) {
        let snap_name = format!("pre-primary-{}", zfs_ops::fresh_anchor_name().trim_start_matches("mirror-"));
        zfs_ops::take_snapshot(&peer_ds, &snap_name)
            .context("snapshot peer before primary flip (live-root case)")?;
        writeln!(
            w,
            "    pre-primary snapshot: {peer_ds}@{snap_name} (peer is mounted at /)"
        )
        .ok();
    }

    // Flip Primary marker on BE side.
    set_primary_flag(&be_dataset, true)?;
    // Flip Primary marker on peer side IF mutual (asymmetric: leave peer alone).
    if mutual {
        set_primary_flag(&peer_ds, false)?;
    }

    // Flip readonly on BE (now primary, must be writable).
    zfs_ops::set_readonly_tolerant(&be_dataset, "off")
        .context("clearing readonly on new primary")?;

    // Flip readonly on peer (now mirror), best-effort. Skip if mounted at /.
    if mutual {
        if zfs_ops::is_mounted(&peer_ds) {
            writeln!(
                w,
                "    skipped readonly=on on {peer_ds} (mounted at /; next reboot + `push {be_dataset_short}` settles)",
                be_dataset_short = be_dataset.rsplit('/').next().unwrap_or(&be_dataset),
            )
            .ok();
        } else {
            zfs_ops::set_readonly_tolerant(&peer_ds, "on")
                .context("setting readonly=on on demoted peer")?;
        }
    }

    // Bootfs follow.
    let be_pool = be_dataset.split('/').next().unwrap_or("");
    let peer_pool = peer.pool.as_str();
    let peer_was_bootfs = zfs_ops::pool_bootfs(peer_pool)
        .ok()
        .flatten()
        .as_deref()
        == Some(&peer_ds);
    if peer_was_bootfs {
        // Clear peer's pool bootfs, set BE's pool bootfs.
        crate::sub::cmd("zpool", &["set", "bootfs=", peer_pool])
            .with_context(|| format!("clearing bootfs on {peer_pool}"))?;
        writeln!(w, "    bootfs[{peer_pool}] cleared").ok();
    }
    let be_is_bootfs = zfs_ops::pool_bootfs(be_pool)
        .ok()
        .flatten()
        .as_deref()
        == Some(&be_dataset);
    if !be_is_bootfs {
        crate::sub::cmd("zpool", &["set", &format!("bootfs={be_dataset}"), be_pool])
            .with_context(|| format!("setting bootfs on {be_pool}"))?;
        writeln!(w, "    bootfs[{be_pool}] = {be_dataset}").ok();
    }

    if mutual && zfs_ops::is_mounted(&peer_ds) {
        let be_short = be_dataset.rsplit('/').next().unwrap_or(&be_dataset);
        writeln!(w).ok();
        writeln!(w, "  Next steps to complete failover:").ok();
        writeln!(w, "    reboot                       # land on {be_dataset}").ok();
        writeln!(w, "    push {be_short} --force            # settles peer's readonly=on").ok();
        writeln!(w).ok();
        writeln!(w, "  Note: pre-primary snapshot on {peer_ds} captures pre-failover").ok();
        writeln!(w, "  state. `push --force` wipes it; to preserve, first pull it").ok();
        writeln!(w, "  out: `pull {peer_ds}@pre-primary-... --name failover-archive`").ok();
    }
    Ok(())
}

fn read_primary_flag(ds: &str) -> Result<bool> {
    let val = zfs_ops::dataset_property(ds, "zboot:primary")?;
    Ok(val == "on")
}

fn set_primary_flag(ds: &str, on: bool) -> Result<()> {
    let value = if on { "on" } else { "off" };
    zfs_ops::set_property_tolerant(ds, "zboot:primary", value)
}
