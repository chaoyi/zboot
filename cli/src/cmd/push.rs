//! `zboot push` — send a BE's snapshot stream to its paired peer (or
//! `--to <pool>` to bootstrap a new pair).
//!
//! Wire-level: `zfs send -R [-I <prev>] <src>@mirror-<ts> | zfs receive
//! -F -u <dst>`. Default form requires a paired peer (`zboot:mirror`
//! set); refuses on divergence. `--force` is `zfs receive -F` against
//! the dest. Bounded form (`<be>@<snap>`) sends only up to the named
//! snapshot, refusing if dest is past it (rewind case) unless `--force`
//! is given, in which case `zfs rollback -r` truncates dest to the
//! bound.

use std::io::Write;

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::zfs_ops;
use zboot_core::PairPointer;

#[derive(Debug, Args)]
pub struct PushArgs {
    /// Source BE — bare name (resolved against the booted pool — the
    /// pool whose dataset is mounted at `/`) or fully-qualified dataset
    /// path (`rpool/ROOT/be1`). Optional `@<snap>` suffix bounds the
    /// push to that snapshot ("checkpoint-only" mode): `push be1@known-good`
    /// sends up to `be1@known-good`, leaving newer WIP snapshots local.
    /// The snapshot must be a descendant of the last successful anchor
    /// on dest; rewinds require `--force`. Omit BE entirely to push the
    /// currently-running BE.
    pub be: Option<String>,

    /// Bootstrap: push to `<pool>` (same name; sets pair pointers on
    /// both sides) or `<pool>/ROOT/<other-name>` (ad-hoc, unpaired).
    /// Required if the source has no paired peer. Note: bounded
    /// (`@<snap>`) bootstrap is always treated as ad-hoc — pinning a
    /// snapshot for replication-on-arrival doesn't fit the mutual-pair
    /// model.
    #[arg(long)]
    pub to: Option<String>,

    /// Overwrite divergent dest snapshots, or rewind dest when the
    /// bounded form names an older snapshot than dest currently sits at.
    /// Divergence → `zfs receive -F` (destroys dest-only snapshots not
    /// in the stream). Rewind → `zfs rollback -r <dest>@<bound>`
    /// (destroys dest snapshots after the bound). Either path requires
    /// typing the dest dataset name on stdin to confirm.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: &PushArgs, w: &mut impl Write) -> Result<()> {
    let be_arg_owned = match &args.be {
        Some(s) => s.clone(),
        None => zfs_ops::discover_booted_dataset()
            .context("no BE given; can't determine the running BE from /proc/self/mounts")?,
    };
    let (be_arg, bounded_snap) = crate::be_arg::split_be_snap(&be_arg_owned);
    let src_dataset = crate::be_arg::resolve_be_dataset(&be_arg)?;
    let src_pool = src_dataset
        .split('/')
        .next()
        .ok_or_else(|| anyhow::anyhow!("bad source dataset {src_dataset}"))?
        .to_owned();
    if !zfs_ops::dataset_exists(&src_dataset)? {
        bail!("source BE {src_dataset} does not exist");
    }
    zfs_ops::require_role_root(&src_pool)
        .with_context(|| format!("source pool {src_pool}"))?;

    // Warn (don't refuse) if source has zboot:primary=off.  Pushing from
    // the mirror side reverses canonical direction — legit but unusual.
    if let Ok(val) = zfs_ops::dataset_property(&src_dataset, "zboot:primary") {
        if val == "off" {
            writeln!(
                w,
                "  warning: {src_dataset} has zboot:primary=off (mirror side).\n  \
                 Pushing from the mirror side reverses canonical direction. \
                 Did you mean `primary {src_dataset}` first?"
            )
            .ok();
        }
    }

    if let Some(snap) = &bounded_snap {
        let full = format!("{src_dataset}@{snap}");
        if !zfs_ops::snapshot_exists(&full)? {
            bail!("source snapshot {full} does not exist");
        }
    }

    // Three modes, distinguished by --to and the existing pair pointer.
    let (dest_dataset, mut paired_mode) = match &args.to {
        None => {
            // Default: use the paired peer.
            let peer = zfs_ops::read_pair_pointer(&src_dataset)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "{src_dataset} has no zboot:mirror peer; supply --to <pool> to bootstrap, \
                     or --to <pool>/ROOT/<name> for an ad-hoc copy"
                )
            })?;
            let peer_ds = peer.render();
            // Refuse if the pair pointer is dangling: status already
            // flags this as `[target missing]`, and silently bootstrapping
            // a new dataset at the dangling path would create an orphan
            // (operator probably intended to fix the pointer or unpair).
            if !zfs_ops::dataset_exists(&peer_ds)? {
                bail!(
                    "{src_dataset}'s zboot:mirror points at {peer_ds}, but that dataset \
                     doesn't exist. The pair pointer is dangling (status shows it as \
                     `[target missing]`). Either:\n    \
                     zboot unpair {src_dataset}                  # clear the stale pointer\n    \
                     zboot push {src_dataset} --to <pool>        # bootstrap a fresh peer"
                );
            }
            (peer_ds, PairedMode::Existing)
        }
        Some(spec) => {
            let (dst, mode) = parse_to_target(&src_dataset, spec)?;
            // Same-pool push: warn, don't refuse. It works (full-copy send/
            // receive into a new dataset on the same pool) but is wasteful
            // when `fork` (clone, no copy) would do. The exception is when
            // the operator wants an *independent* in-pool copy (no clone
            // dep) — exactly the preserve-divergent-state workflow. Let
            // them through; just point at the cheaper primitive.
            let dst_pool = dst
                .split('/')
                .next()
                .ok_or_else(|| anyhow::anyhow!("bad dest dataset {dst}"))?;
            if dst_pool == src_pool {
                writeln!(
                    w,
                    "  warning: same-pool push will full-copy data into {dst}. \
                     If you want a cheaper clone, use `zboot fork` instead. \
                     Proceeding (full-copy creates an independent dataset, \
                     no clone dependency)."
                )
                .ok();
            }
            zfs_ops::require_role_root(dst_pool)
                .with_context(|| format!("dest pool {dst_pool}"))?;
            (dst, mode)
        }
    };

    // Bounded bootstrap is always ad-hoc: pinning a specific snapshot
    // for "this checkpoint only" is the unpaired idiom. Stamping a
    // mutual pair pointer at it would suggest "this is the canonical
    // peer", which it isn't.
    if bounded_snap.is_some() && matches!(paired_mode, PairedMode::BootstrapPaired) {
        paired_mode = PairedMode::AdHocUnpaired;
    }

    push_one(
        &src_dataset,
        &dest_dataset,
        paired_mode,
        bounded_snap.as_deref(),
        args.force,
        w,
    )
}

#[derive(Debug, Clone, Copy)]
enum PairedMode {
    /// Pair pointer already exists (default `push <BE>`). No pointer
    /// writes; just bytes.
    Existing,
    /// Bootstrap a paired peer (`push --to <pool>`, same-name). Writes
    /// `zboot:mirror` on the source; if the dest's pointer is currently
    /// unset, also writes it (making the typical case mutual).
    BootstrapPaired,
    /// Ad-hoc copy (`push --to <pool>/ROOT/<other>`). No pointer writes
    /// on either side.
    AdHocUnpaired,
}

fn push_one(
    src: &str,
    dest: &str,
    mode: PairedMode,
    bounded_snap: Option<&str>,
    force: bool,
    w: &mut impl Write,
) -> Result<()> {
    match bounded_snap {
        Some(snap) => writeln!(w, "  push {src}@{snap} \u{2192} {dest}").ok(),
        None => writeln!(w, "  push {src} \u{2192} {dest}").ok(),
    };

    // Refuse to push INTO a mounted+rw destination. ZFS receive into a
    // mounted-rw dataset (especially mounted at /) corrupts the running
    // kernel via cache divergence (kernel caches stale blocks, receive
    // writes new blocks underneath). Mounted+ro is OK — kernel doesn't
    // dirty pages, ZFS invalidates ARC on receive. Unmounted is OK.
    let dest_exists = zfs_ops::dataset_exists(dest).unwrap_or(false);
    if dest_exists && zfs_ops::is_mounted(dest) {
        let ro = zfs_ops::dataset_property(dest, "readonly").unwrap_or_default();
        if ro != "on" {
            bail!(
                "dest {dest} is mounted+rw; refuses (would corrupt kernel cache). \
                 Either unmount, or set readonly=on on dest first."
            );
        }
    }

    // Divergence check: refuses unless --force. Under normal use, the
    // mirror side (readonly=on) is a strict subset of the primary's
    // snapshots — push only adds, never removes. If dest has any GUIDs
    // source doesn't, something wrote to the dest out-of-band (or via
    // dest-side ops outside the replication flow); the refusal surfaces
    // that so the operator decides instead of losing data silently.
    if dest_exists {
        let dest_extras = zfs_ops::snapshots_only_on_right(src, dest)?;
        if !dest_extras.is_empty() {
            if !force {
                bail_on_divergence(src, dest, &dest_extras)?;
            }
            zfs_ops::confirm_destructive_truncate(
                &format!(
                    "push --force will run: zfs receive -F (destroys dest-only snapshots on {dest})"
                ),
                dest,
                &dest_extras,
            )?;
        }
    }

    // Bounded rewind check: if the user names a snapshot older than the
    // one dest is currently at (via matching GUIDs), this push is a
    // *rewind*, not a fast-forward. Refuses unless --force. With --force,
    // the operation is `zfs rollback -r <dest>@<bound>` — no send, just
    // a destructive truncation. Matches `git push --force` semantics for
    // rewinding a remote ref.
    let rewind_only = if let Some(snap_name) = &bounded_snap {
        if dest_exists {
            let to_destroy = zfs_ops::dest_snapshots_after_bound(src, dest, snap_name)?;
            if !to_destroy.is_empty() {
                let dest_bound = format!("{dest}@{snap_name}");
                if !force {
                    bail_on_rewind(src, dest, snap_name, &to_destroy)?;
                }
                zfs_ops::confirm_destructive_truncate(
                    &format!(
                        "push --force will run: zfs rollback -r {dest_bound} \
                         (rewinds dest, destroying snapshots taken after the bound)"
                    ),
                    dest,
                    &to_destroy,
                )?;
                Some(dest_bound)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Anchor selection: bounded form uses the user-named snapshot
    // (must exist locally; validated up the call chain). Default form
    // mints a fresh `@mirror-<utc-ns>`. The bounded anchor doubles as
    // the replication anchor — pruning will keep only the latest such,
    // so the user's named snapshot stays around exactly as long as the
    // next push (or anchor prune) lets it.
    // Skip anchor creation in the rewind path (rollback uses the existing
    // user-named bound; no fresh anchor needed).
    let anchor = if rewind_only.is_some() {
        // Use the bound directly; this is only used downstream for prune.
        format!("{src}@{}", bounded_snap.as_ref().unwrap())
    } else {
        match &bounded_snap {
            Some(snap) => format!("{src}@{snap}"),
            None => {
                let fresh = format!("{src}@{}", zfs_ops::fresh_anchor_name());
                zfs_ops::take_snapshot(src, fresh.split_once('@').unwrap().1)
                    .context("snapshot source")?;
                fresh
            }
        }
    };

    // Ensure dest pool's ROOT container exists for the first-time case.
    if !dest_exists {
        let dst_pool = dest.split('/').next().unwrap_or_default();
        zfs_ops::ensure_root_container(dst_pool)?;
    }

    // Clear dest readonly briefly so receive (or rollback) can mutate
    // the dataset. Special-case: when dest is mounted-ro, leave
    // readonly=on to keep the kernel's mount in ro state during the
    // operation (no dirty page cache). `zfs receive -F` and `zfs rollback`
    // both write at the dataset layer and work through the readonly
    // property — verified by ZFS source.
    let dest_mounted_ro = dest_exists
        && zfs_ops::is_mounted(dest)
        && zfs_ops::dataset_property(dest, "readonly").unwrap_or_default() == "on";
    let was_readonly = if dest_exists && !dest_mounted_ro {
        let val = zfs_ops::dataset_property(dest, "readonly")?;
        if val == "on" {
            zfs_ops::set_readonly_tolerant(dest, "off")?;
            true
        } else {
            false
        }
    } else {
        false
    };

    let result = if let Some(dest_bound) = &rewind_only {
        // Rewind path: rollback only, no send.
        zfs_ops::zfs_rollback_recursive(dest_bound)
    } else {
        let prev = if dest_exists {
            zfs_ops::previous_anchor_on_dest(src, dest)?
        } else {
            None
        };
        if let Some(p) = &prev {
            zfs_ops::send_recv_incremental(p, &anchor, dest)
        } else if zfs_ops::dataset_is_clone(src).unwrap_or(false) {
            // Bootstrap of a clone source: `zfs send -R` would carry the
            // clone-origin GUID, and the receiver requires that GUID to
            // exist locally — which fails when the dest pool doesn't
            // share the origin's lineage. Use `zfs send -p` instead:
            // sends just the anchor's data + user properties, no clone
            // pointer. Dest gets a standalone dataset.
            //
            // Side effect: earlier own snapshots of the clone (anything
            // before the anchor) are NOT replicated. Warn the operator
            // if there are any so they know what's being left behind.
            warn_lost_intermediate_snapshots(src, &anchor, w);
            zfs_ops::send_recv_full_standalone(&anchor, dest)
        } else {
            zfs_ops::send_recv_full(&anchor, dest)
        }
    };
    if let Err(e) = result {
        // Best-effort restore readonly even on failure.
        if was_readonly {
            let _ = zfs_ops::set_readonly_tolerant(dest, "on");
        }
        return Err(e);
    }

    // Dest BE contract: noauto, mountpoint=/, zboot:be=true.
    zfs_ops::set_be_contract(dest)?;
    // Replication safety rail.
    zfs_ops::set_readonly_tolerant(dest, "on")?;

    // Pair pointer writes — see PairedMode docstrings. Skip entirely in
    // the rewind path: rewind doesn't establish or change pair
    // relationships, it only truncates dest snapshots.
    if rewind_only.is_none() {
        match mode {
            PairedMode::Existing => {}
            PairedMode::BootstrapPaired => {
                let src_pair = parse_pair_from_ds(dest)?;
                let dest_pair = parse_pair_from_ds(src)?;
                zfs_ops::write_pair_pointer(src, &src_pair)?;
                // Source becomes primary on bootstrap.
                let _ = zfs_ops::set_property_tolerant(src, "zboot:primary", "on");
                // Dest's pointer only gets written if it was unset (the
                // typical-mutual case). If the dest already has a pair, leave
                // it — we're a tracking-only "many" side.
                if zfs_ops::read_pair_pointer(dest)?.is_none() {
                    zfs_ops::write_pair_pointer(dest, &dest_pair)?;
                    let _ = zfs_ops::set_property_tolerant(dest, "zboot:primary", "off");
                } else {
                    // Asymmetric: dest is the tracking-only side from src's POV.
                    // Source becomes primary, but we don't touch dest's existing primary.
                    let _ = zfs_ops::set_property_tolerant(src, "zboot:primary", "on");
                }
            }
            PairedMode::AdHocUnpaired => {
                // `zfs send -R` carries the source's `zboot:mirror` user
                // property through to the dest. For an ad-hoc copy that's
                // wrong — the dest isn't paired to source's peer, it isn't
                // paired at all. Clear the inherited pointer.
                let _ = zfs_ops::clear_pair_pointer(dest);
            }
        }
    }

    // Prune anchors on both sides — keep only the new one. (Skip in the
    // rewind path: the bound is operator-named, not a `mirror-*` anchor,
    // and rollback already destroyed everything after it.)
    if rewind_only.is_none() {
        zfs_ops::prune_old_anchors(src, &anchor);
        let dest_anchor = format!("{dest}@{}", anchor.split_once('@').unwrap().1);
        zfs_ops::prune_old_anchors(dest, &dest_anchor);
    }

    match &rewind_only {
        Some(dest_bound) => writeln!(w, "    rewound to {dest_bound} (dest readonly)").ok(),
        None => writeln!(w, "    pushed (dest readonly)").ok(),
    };
    Ok(())
}

fn bail_on_divergence(src: &str, dest: &str, dest_extras: &[String]) -> Result<()> {
    let preview = zfs_ops::format_snapshot_preview(dest_extras);
    let dest_pool = dest.split('/').next().unwrap_or("<pool>");
    bail!(
        "refuses: divergent dest {dest} (has {n} snapshot(s) source {src} does not).\n  \
         Why: a regular push only adds snapshots — it can't decide whether to keep\n  \
         or destroy dest-only ones. Refusing so you pick: force-overwrite, pull\n  \
         instead, or preserve dest's lineage as a separate BE first.\n  \
         dest-only:\n      {preview}\n  \
         resolve with:\n    \
         push --force         will run: zfs receive -F (destroys dest-only above)\n    \
         pull --force         will run: zfs receive -F on this side (accepts peer)\n    \
         preserve + re-bootstrap (if you want dest's lineage kept somewhere):\n                         \
         zboot fork <name> --from {dest}@<snap>     # clone of dest@<snap>\n                         \
         zfs promote {dest_pool}/ROOT/<name>        # snapshots move to <name>\n                         \
         zboot drop {dest}                          # dest is now an empty clone\n                         \
         zboot push --to {dest_pool}                # re-bootstrap pair on fresh dest",
        n = dest_extras.len(),
    )
}

fn bail_on_rewind(
    src: &str,
    dest: &str,
    bound: &str,
    dest_after_bound: &[String],
) -> Result<()> {
    let preview = zfs_ops::format_snapshot_preview(dest_after_bound);
    let dest_pool = dest.split('/').next().unwrap_or("<pool>");
    bail!(
        "refuses: bounded push to {dest} but dest is past the bound {src}@{bound}.\n  \
         Why: dest has {n} snapshot(s) taken after the bound on source. A regular\n  \
         push can't go backwards (zfs send -I requires forward time). This is a\n  \
         *rewind*, not a fast-forward — matches git's non-fast-forward refusal.\n  \
         dest-after-bound:\n      {preview}\n  \
         resolve with:\n    \
         push --force         will run: zfs rollback -r {dest}@{bound}\n                         destroys the {n} snapshot(s) above on dest\n    \
         (omit @{bound})      push to dest's latest, no rewind\n    \
         preserve + re-bootstrap (if you want dest's newer lineage kept):\n                         \
         zboot fork <name> --from {dest}@<snap>     # clone of dest@<snap>\n                         \
         zfs promote {dest_pool}/ROOT/<name>        # snapshots move to <name>\n                         \
         zboot drop {dest}                          # dest is now an empty clone\n                         \
         zboot push --to {dest_pool}                # re-bootstrap pair on fresh dest",
        n = dest_after_bound.len(),
    )
}

/// Parse `--to` argument: either `<pool>` (same name as source →
/// bootstrap-paired) or `<pool>/ROOT/<other-name>` (ad-hoc unpaired).
fn parse_to_target(src_dataset: &str, spec: &str) -> Result<(String, PairedMode)> {
    if spec.contains('/') {
        // Full path. Must start with `<pool>/ROOT/<name>`.
        if zboot_core::PairPointer::parse_dataset(spec).is_none() {
            bail!(
                "--to {spec:?}: expected `<pool>` (same name as source) or \
                 `<pool>/ROOT/<other-name>` (full path)"
            );
        }
        Ok((spec.to_owned(), PairedMode::AdHocUnpaired))
    } else {
        // Bare pool name → same-name target.
        let src_name = src_dataset
            .rsplit('/')
            .next()
            .ok_or_else(|| anyhow::anyhow!("bad source dataset {src_dataset}"))?;
        Ok((format!("{spec}/ROOT/{src_name}"), PairedMode::BootstrapPaired))
    }
}

fn parse_pair_from_ds(ds: &str) -> Result<PairPointer> {
    PairPointer::parse_dataset(ds).ok_or_else(|| {
        anyhow::anyhow!("dataset {ds:?} doesn't fit the canonical `<pool>/ROOT/<be>` form")
    })
}

/// For bootstrap-of-clone via `zfs send -p`: warn the operator about any
/// non-anchor own snapshots that won't make it to dest. The anchor snap
/// itself transfers; everything else under the source dataset stays
/// local. `@mirror-*` anchors are excluded from the warning (pruning
/// lag, not operator-meaningful state).
fn warn_lost_intermediate_snapshots<W: std::io::Write>(src: &str, anchor: &str, w: &mut W) {
    let Ok(snaps) = zfs_ops::list_snapshots_with_guids(src) else {
        return;
    };
    let lost: Vec<&str> = snaps
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|n| !zboot_core::is_replication_anchor(
            n.rsplit_once('@').map(|(_, s)| s).unwrap_or(n)
        ))
        .filter(|n| *n != anchor)
        .collect();
    if lost.is_empty() {
        return;
    }
    writeln!(
        w,
        "  warning: source is a clone; bootstrap uses `zfs send -p` and won't \
         transfer these own snapshots to dest:"
    )
    .ok();
    for s in lost.iter().take(5) {
        writeln!(w, "    {s}").ok();
    }
    if lost.len() > 5 {
        writeln!(w, "    ... ({} more)", lost.len() - 5).ok();
    }
    writeln!(
        w,
        "  Only the anchor's data state transfers. If you want any of these \
         on dest, run `zboot push <BE>@<snap>` individually for each before \
         (or after) the bootstrap."
    )
    .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_to_pool_only_is_bootstrap_paired() {
        let (dst, mode) = parse_to_target("rpool/ROOT/be1", "rpool2").unwrap();
        assert_eq!(dst, "rpool2/ROOT/be1");
        assert!(matches!(mode, PairedMode::BootstrapPaired));
    }

    #[test]
    fn parse_to_full_path_is_adhoc() {
        let (dst, mode) = parse_to_target("rpool/ROOT/be1", "rpool2/ROOT/snapshot-feb").unwrap();
        assert_eq!(dst, "rpool2/ROOT/snapshot-feb");
        assert!(matches!(mode, PairedMode::AdHocUnpaired));
    }

    #[test]
    fn parse_to_bad_path_rejected() {
        assert!(parse_to_target("rpool/ROOT/be1", "rpool2/ZOO/be1").is_err());
        assert!(parse_to_target("rpool/ROOT/be1", "rpool2/ROOT/").is_err());
    }

}
