//! `zboot mirror` — bulk replication driven by `zboot:primary` markers.
//!
//! Walks every BE with `zboot:primary=on` across imported root pools.
//! For each, push to its canonical Mirror peer plus every asymmetric
//! incoming tracker (other BEs whose `zboot:mirror` points back at this
//! primary). Single command syncs the full topology in canonical
//! direction.
//!
//! `--force` lifts divergence-refusal on each per-pair push; each
//! truncate requires typed confirmation (matches push --force).
//!
//! Status output per pair:
//! - "synced" when push succeeded.
//! - "no-op" when already in sync.
//! - "refused" when divergent and no --force.
//! - "skipped" when dest is unreachable or other operational issue.

use std::io::Write;

use anyhow::{Context, Result};
use clap::Args;

use crate::zfs_ops;
use zboot_core::PairPointer;

#[derive(Debug, Args)]
pub struct MirrorArgs {
    /// Lift divergence-refusal; truncate divergent dest snapshots on each
    /// per-pair push. Each truncate requires typed confirmation.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: &MirrorArgs, w: &mut impl Write) -> Result<()> {
    let primaries = list_primary_bes()?;
    if primaries.is_empty() {
        writeln!(
            w,
            "mirror: no BEs with zboot:primary=on found across imported root pools."
        )
        .ok();
        return Ok(());
    }

    writeln!(w, "=== mirror: walking {} primary BE(s) ===", primaries.len()).ok();
    let mut synced = 0usize;
    let mut noop = 0usize;
    let mut refused = 0usize;
    let mut skipped = 0usize;

    for primary in &primaries {
        let targets = list_outgoing_targets(primary)?;
        if targets.is_empty() {
            writeln!(
                w,
                "  {primary}: no peers (Mirror unset and no incoming trackers); skip"
            )
            .ok();
            skipped += 1;
            continue;
        }
        for target in targets {
            writeln!(w, "  {primary} \u{2192} {target}").ok();
            match push_one_pair(primary, &target, args.force, w) {
                Ok(PushOutcome::Synced) => synced += 1,
                Ok(PushOutcome::NoOp) => noop += 1,
                Ok(PushOutcome::Refused) => refused += 1,
                Err(e) => {
                    writeln!(w, "    skipped: {e}").ok();
                    skipped += 1;
                }
            }
        }
    }

    writeln!(w).ok();
    writeln!(
        w,
        "=== mirror summary: synced={synced} no-op={noop} refused={refused} skipped={skipped} ==="
    )
    .ok();
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PushOutcome {
    Synced,
    NoOp,
    Refused,
}

/// All BEs with zboot:primary=on, across imported root pools.
fn list_primary_bes() -> Result<Vec<String>> {
    let pools = crate::sub::zpool_capture(&["list", "-Hp", "-o", "name"])?;
    let mut primaries = Vec::new();
    for pool in pools.lines() {
        if zfs_ops::pool_property(pool, "zboot:role")
            .ok()
            .as_deref()
            != Some("root")
        {
            continue;
        }
        let out = crate::sub::zfs_capture(&[
            "get", "-Hp", "-r", "-t", "filesystem", "-o", "name,value", "zboot:primary", pool,
        ])?;
        for line in out.lines() {
            let mut parts = line.split('\t');
            let name = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            if value == "on" {
                primaries.push(name.to_owned());
            }
        }
    }
    primaries.sort();
    Ok(primaries)
}

/// Targets to push to FROM `primary`: its Mirror peer (if any) plus all
/// asymmetric incoming trackers (BEs whose Mirror = primary, regardless
/// of whether primary points back).
fn list_outgoing_targets(primary: &str) -> Result<Vec<String>> {
    let mut targets = Vec::new();
    let primary_pair = PairPointer::parse_dataset(primary);
    let primary_render = primary_pair.as_ref().map(|p| p.render()).unwrap_or_default();

    // Canonical peer from Mirror[primary]. Dangling pointer (target
    // missing) is silently dropped from the push list; status already
    // surfaces it as `[target missing]`. We don't auto-bootstrap a new
    // dataset at the dangling path (that's the orphan-create footgun
    // push.rs explicitly refuses against).
    if let Some(peer) = zfs_ops::read_pair_pointer(primary)? {
        let peer_ds = peer.render();
        if zfs_ops::dataset_exists(&peer_ds).unwrap_or(false) {
            targets.push(peer_ds);
        }
    }

    // Asymmetric incoming trackers.
    let pools = crate::sub::zpool_capture(&["list", "-Hp", "-o", "name"])?;
    for pool in pools.lines() {
        if zfs_ops::pool_property(pool, "zboot:role")
            .ok()
            .as_deref()
            != Some("root")
        {
            continue;
        }
        let out = crate::sub::zfs_capture(&[
            "get", "-Hp", "-r", "-t", "filesystem", "-o", "name,value", "zboot:mirror", pool,
        ])?;
        for line in out.lines() {
            let mut parts = line.split('\t');
            let name = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            if value == primary_render && name != primary && !targets.iter().any(|t| t == name) {
                targets.push(name.to_owned());
            }
        }
    }
    targets.sort();
    Ok(targets)
}

/// Push from `src` to `dst` directly without going through `cmd::push::run`.
/// Lets mirror handle the per-pair `--force` accounting and outcome
/// reporting without re-implementing CLI argument parsing.
fn push_one_pair(src: &str, dst: &str, force: bool, w: &mut impl Write) -> Result<PushOutcome> {
    let dest_exists = zfs_ops::dataset_exists(dst).unwrap_or(false);

    // Refuse if dest is mounted+rw.
    if dest_exists
        && zfs_ops::is_mounted(dst)
        && zfs_ops::dataset_property(dst, "readonly").unwrap_or_default() != "on"
    {
        anyhow::bail!("dest {dst} is mounted+rw");
    }

    // Compute divergent dest snapshots.
    if dest_exists {
        let dst_extras = zfs_ops::snapshots_only_on_right(src, dst)?;
        if !dst_extras.is_empty() {
            if !force {
                writeln!(
                    w,
                    "    refused: divergent ({} dest-only snapshots; pass --force to truncate)",
                    dst_extras.len()
                )
                .ok();
                return Ok(PushOutcome::Refused);
            }
            zfs_ops::confirm_destructive_truncate(
                &format!("mirror --force will destroy these snapshots on {dst}"),
                dst,
                &dst_extras,
            )?;
        }
    }

    // Fresh anchor + send/recv.
    let anchor = format!("{src}@{}", zfs_ops::fresh_anchor_name());
    zfs_ops::take_snapshot(src, anchor.split_once('@').unwrap().1)
        .context("snapshot source")?;

    if !dest_exists {
        let dst_pool = dst.split('/').next().unwrap_or_default();
        zfs_ops::ensure_root_container(dst_pool)?;
    }

    let dest_mounted_ro = dest_exists
        && zfs_ops::is_mounted(dst)
        && zfs_ops::dataset_property(dst, "readonly").unwrap_or_default() == "on";
    let was_readonly = if dest_exists && !dest_mounted_ro {
        let val = zfs_ops::dataset_property(dst, "readonly")?;
        if val == "on" {
            zfs_ops::set_readonly_tolerant(dst, "off")?;
            true
        } else {
            false
        }
    } else {
        false
    };

    let prev = if dest_exists {
        zfs_ops::previous_anchor_on_dest(src, dst)?
    } else {
        None
    };
    let send_result = if let Some(p) = &prev {
        if p == &anchor {
            // Nothing new to send.
            zfs_ops::prune_old_anchors(src, &anchor);
            let dst_anchor = format!("{dst}@{}", anchor.split_once('@').unwrap().1);
            zfs_ops::prune_old_anchors(dst, &dst_anchor);
            return Ok(PushOutcome::NoOp);
        }
        zfs_ops::send_recv_incremental(p, &anchor, dst)
    } else {
        zfs_ops::send_recv_full(&anchor, dst)
    };
    if let Err(e) = send_result {
        if was_readonly {
            let _ = zfs_ops::set_readonly_tolerant(dst, "on");
        }
        return Err(e);
    }

    zfs_ops::set_be_contract(dst)?;
    zfs_ops::set_readonly_tolerant(dst, "on")?;

    zfs_ops::prune_old_anchors(src, &anchor);
    let dst_anchor = format!("{dst}@{}", anchor.split_once('@').unwrap().1);
    zfs_ops::prune_old_anchors(dst, &dst_anchor);

    Ok(PushOutcome::Synced)
}
