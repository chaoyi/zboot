//! `zboot pull` — receive from a peer into a local BE.
//!
//! Mirror of `push`: defaults to the paired peer; `--name <new>`
//! bootstraps a fresh local BE pulled from a remote dataset; refuses
//! on divergence (`--force` = `zfs receive -F`); refuses on bounded
//! rewind (`--force` = `zfs rollback -r <local>@<bound>`); refuses if
//! the local target is the active BE (can't write live root) — use the
//! `pull --name <new>` + `default` + reboot + `drop` + `rename` recipe.

use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;

use crate::zfs_ops;
use zboot_core::PairPointer;

#[derive(Debug, Args)]
pub struct PullArgs {
    /// With `--name`: SOURCE on the remote pool (full dataset path,
    /// optionally `@<snap>` for a bounded historical pull). Without
    /// `--name`: local BE to pull into. Bare or full path; `@<snap>`
    /// suffix names a remote snapshot to bound the pull at. Omit
    /// entirely (no `--name`) to pull into the active BE.
    pub be: Option<String>,

    /// Initial pull: create a new local BE with this name, sourced
    /// from `<be>` (which must be a full remote dataset path).
    /// Bounded form (`<remote>@<snap> --name <local>`) creates an
    /// immortal historical reference copy, unpaired by convention.
    #[arg(long)]
    pub name: Option<String>,

    /// Overwrite local divergent snapshots, or rewind local when the
    /// bounded form names a remote snapshot older than local's current
    /// position. Divergence → `zfs receive -F`. Rewind →
    /// `zfs rollback -r <local>@<bound>`. Either path requires typing
    /// the local dataset name on stdin to confirm.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: &PullArgs, w: &mut impl Write) -> Result<()> {
    let be_arg_owned = match &args.be {
        Some(s) => s.clone(),
        None => {
            if args.name.is_some() {
                bail!("`--name` requires the source BE path as a positional argument");
            }
            zfs_ops::discover_booted_dataset()
                .context("no BE given; can't determine the running BE from /proc/self/mounts")?
        }
    };
    let (be_arg, bounded_snap) = crate::be_arg::split_be_snap(&be_arg_owned);
    match &args.name {
        Some(new_name) => pull_initial(&be_arg, bounded_snap.as_deref(), new_name, args.force, w),
        None => pull_incremental(&be_arg, bounded_snap.as_deref(), args.force, w),
    }
}

/// Initial pull: `--be` is the remote source dataset (optionally
/// `@<snap>`); `--name` is the local target name. Creates a paired BE
/// on the local active pool. Bounded form pins the local BE to the
/// named snapshot and leaves it unpaired (immortal historical copy).
fn pull_initial(
    remote_src: &str,
    bounded_snap: Option<&str>,
    local_name: &str,
    force: bool,
    w: &mut impl Write,
) -> Result<()> {
    if !remote_src.contains('/') {
        bail!(
            "--name is for initial pull; `--be` must be the FULL remote dataset path \
             (e.g. rpool2/ROOT/be1), got bare name {remote_src:?}"
        );
    }
    if !zfs_ops::dataset_exists(remote_src)? {
        bail!("remote source {remote_src} does not exist");
    }
    if let Some(snap) = bounded_snap {
        let full = format!("{remote_src}@{snap}");
        if !zfs_ops::snapshot_exists(&full)? {
            bail!("remote snapshot {full} does not exist");
        }
    }
    let remote_pool = remote_src
        .split('/')
        .next()
        .ok_or_else(|| anyhow!("bad remote dataset {remote_src}"))?;
    zfs_ops::require_role_root(remote_pool)
        .with_context(|| format!("remote pool {remote_pool}"))?;

    let local_pool = zfs_ops::discover_booted_pool()?;
    if local_pool == remote_pool {
        // Same-pool pull: warn, don't refuse. Mirrors the push side.
        writeln!(
            w,
            "  warning: same-pool pull will full-copy data into the new BE. \
             If you want a cheaper clone, use `zboot fork` instead. \
             Proceeding (full-copy creates an independent dataset, no clone dependency)."
        )
        .ok();
    }
    zfs_ops::require_role_root(&local_pool)?;
    let local_dataset = format!("{local_pool}/ROOT/{local_name}");
    if zfs_ops::dataset_exists(&local_dataset).unwrap_or(false) {
        bail!(
            "local BE {local_dataset} already exists; pick a different --name or drop the old one"
        );
    }

    match bounded_snap {
        Some(snap) => writeln!(w, "  pull {remote_src}@{snap} \u{2192} {local_dataset} (initial bounded)").ok(),
        None => writeln!(w, "  pull {remote_src} \u{2192} {local_dataset} (initial)").ok(),
    };
    zfs_ops::ensure_root_container(&local_pool)?;
    receive_into(remote_src, &local_dataset, bounded_snap, force, /*existed=*/ false, w)?;

    // Pair pointers — only for the unbounded (canonical) form. Bounded
    // initial pull is a historical reference copy; pinning a pair to
    // a frozen snapshot would suggest live-tracking, which it isn't.
    if bounded_snap.is_none() {
        let local_peer = PairPointer::parse_dataset(remote_src)
            .ok_or_else(|| anyhow!("can't parse remote source {remote_src}"))?;
        let remote_peer = PairPointer::parse_dataset(&local_dataset)
            .ok_or_else(|| anyhow!("can't parse local dataset {local_dataset}"))?;
        zfs_ops::write_pair_pointer(&local_dataset, &local_peer)?;
        // pull --name: local is the new mirror dest; mark primary=off.
        let _ = zfs_ops::set_property_tolerant(&local_dataset, "zboot:primary", "off");
        // Remote: only set Mirror pointer if it was unset. Do NOT touch
        // remote's zboot:primary — remote might already be a mirror of
        // something else, and forcing primary=on would be a lie. Operator
        // runs `primary <remote>` separately if they want that.
        if zfs_ops::read_pair_pointer(remote_src)?.is_none() {
            zfs_ops::write_pair_pointer(remote_src, &remote_peer)?;
        }
    } else {
        // Bounded historical reference copy: `zfs send -R` carries the
        // remote's `zboot:mirror` through; explicitly clear so the
        // pinned-snapshot BE is unpaired by convention.
        let _ = zfs_ops::clear_pair_pointer(&local_dataset);
    }
    Ok(())
}

/// Incremental pull into a paired local BE.
fn pull_incremental(
    local_arg: &str,
    bounded_snap: Option<&str>,
    force: bool,
    w: &mut impl Write,
) -> Result<()> {
    let local_dataset = crate::be_arg::resolve_be_dataset(local_arg)?;
    if !zfs_ops::dataset_exists(&local_dataset)? {
        bail!("local BE {local_dataset} does not exist");
    }

    // Refuse to receive into a mounted+rw filesystem — the kernel caches
    // stale blocks while ZFS rewrites them underneath. Mirrors push's
    // check (push.rs::push_one). The live root is always mounted+rw, so
    // this also covers the "pulling into the active BE" case, but with
    // the right rationale: kernel-cache corruption, not bootfs identity.
    if zfs_ops::is_mounted(&local_dataset) {
        let ro = zfs_ops::dataset_property(&local_dataset, "readonly").unwrap_or_default();
        if ro != "on" {
            let leaf = local_dataset.rsplit('/').next().unwrap_or(&local_dataset);
            bail!(
                "local {local_dataset} is mounted+rw; refuses (would corrupt kernel cache).\n  \
                 If this is the active BE, the recipe is:\n    \
                 zboot pull --name <fresh> <remote>\n    \
                 zboot default <fresh>\n    \
                 reboot\n    \
                 zboot drop {leaf}\n    \
                 zboot rename <fresh> {leaf}\n  \
                 Otherwise: unmount, or set readonly=on on local first."
            );
        }
    }

    let peer = zfs_ops::read_pair_pointer(&local_dataset)?.ok_or_else(|| {
        anyhow!(
            "{local_dataset} has no zboot:mirror peer; use `pull --name <new> <remote>` \
             to do an initial pull"
        )
    })?;
    let remote_src = peer.render();
    if !zfs_ops::dataset_exists(&remote_src)? {
        bail!("paired remote {remote_src} not reachable (pool not imported or destroyed)");
    }
    if let Some(snap) = bounded_snap {
        let full = format!("{remote_src}@{snap}");
        if !zfs_ops::snapshot_exists(&full)? {
            bail!("remote snapshot {full} does not exist on paired peer");
        }
    }

    match bounded_snap {
        Some(snap) => writeln!(w, "  pull {remote_src}@{snap} \u{2192} {local_dataset}").ok(),
        None => writeln!(w, "  pull {remote_src} \u{2192} {local_dataset}").ok(),
    };
    receive_into(&remote_src, &local_dataset, bounded_snap, force, /*existed=*/ true, w)
}

/// Common receive path used by both initial and incremental pull.
/// `existed` indicates whether the local dataset is being overwritten
/// (incremental) or freshly created (initial).
fn receive_into(
    remote_src: &str,
    local_dataset: &str,
    bounded_snap: Option<&str>,
    force: bool,
    existed: bool,
    w: &mut impl Write,
) -> Result<()> {
    // Divergence check: local snapshots that aren't on remote get
    // wiped by `receive -F`. Without --force, refuse. With --force,
    // require typed confirmation.
    if existed {
        let local_extras = zfs_ops::snapshots_only_on_right(remote_src, local_dataset)?;
        if !local_extras.is_empty() {
            if !force {
                bail_on_pull_divergence(remote_src, local_dataset, &local_extras)?;
            }
            // --force + truncate: require typed confirmation.
            zfs_ops::confirm_destructive_truncate(
                &format!(
                    "pull --force will run: zfs receive -F (destroys local-only snapshots on {local_dataset})"
                ),
                local_dataset,
                &local_extras,
            )?;
        }
    }

    // Bounded rewind check (mirror of push): if the user names a remote
    // snapshot older than local's current position, refuse unless --force.
    // With --force, `zfs rollback -r <local>@<bound>` truncates local back
    // to the bound. No receive needed.
    let rewind_only = if let Some(snap_name) = bounded_snap {
        if existed {
            let to_destroy =
                zfs_ops::dest_snapshots_after_bound(remote_src, local_dataset, snap_name)?;
            if !to_destroy.is_empty() {
                let local_bound = format!("{local_dataset}@{snap_name}");
                if !force {
                    bail_on_pull_rewind(remote_src, local_dataset, snap_name, &to_destroy)?;
                }
                zfs_ops::confirm_destructive_truncate(
                    &format!(
                        "pull --force will run: zfs rollback -r {local_bound} \
                         (rewinds local, destroying snapshots taken after the bound)"
                    ),
                    local_dataset,
                    &to_destroy,
                )?;
                Some(local_bound)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Anchor: bounded form uses the user-named remote snapshot; default
    // mints a fresh `@mirror-<utc-ns>` on the remote. Rewind path uses
    // the bound directly; no fresh anchor.
    let anchor = if rewind_only.is_some() {
        format!("{remote_src}@{}", bounded_snap.unwrap())
    } else {
        match bounded_snap {
            Some(snap) => format!("{remote_src}@{snap}"),
            None => {
                let fresh = format!("{remote_src}@{}", zfs_ops::fresh_anchor_name());
                zfs_ops::take_snapshot(remote_src, fresh.split_once('@').unwrap().1)
                    .context("snapshot remote")?;
                fresh
            }
        }
    };

    // Clear local readonly briefly to receive or rollback (incremental case).
    let was_readonly = if existed {
        let val = zfs_ops::dataset_property(local_dataset, "readonly")?;
        if val == "on" {
            zfs_ops::set_readonly_tolerant(local_dataset, "off")?;
            true
        } else {
            false
        }
    } else {
        false
    };

    let result = if let Some(local_bound) = &rewind_only {
        zfs_ops::zfs_rollback_recursive(local_bound)
    } else {
        let prev = if existed {
            zfs_ops::previous_anchor_on_dest(remote_src, local_dataset)?
        } else {
            None
        };
        if let Some(p) = &prev {
            zfs_ops::send_recv_incremental(p, &anchor, local_dataset)
        } else {
            zfs_ops::send_recv_full(&anchor, local_dataset)
        }
    };
    if let Err(e) = result {
        if was_readonly {
            let _ = zfs_ops::set_readonly_tolerant(local_dataset, "on");
        }
        return Err(e);
    }

    zfs_ops::set_be_contract(local_dataset)?;
    zfs_ops::set_readonly_tolerant(local_dataset, "on")?;

    // Skip anchor pruning on the rewind path: the bound is operator-named,
    // and rollback already destroyed everything after it on local.
    if rewind_only.is_none() {
        zfs_ops::prune_old_anchors(remote_src, &anchor);
        let local_anchor = format!(
            "{local_dataset}@{}",
            anchor.split_once('@').unwrap().1
        );
        zfs_ops::prune_old_anchors(local_dataset, &local_anchor);
    }

    match &rewind_only {
        Some(local_bound) => writeln!(w, "    rewound to {local_bound} (local readonly)").ok(),
        None => writeln!(w, "    pulled (local readonly)").ok(),
    };
    Ok(())
}

fn bail_on_pull_divergence(
    remote_src: &str,
    local: &str,
    local_extras: &[String],
) -> Result<()> {
    let preview = zfs_ops::format_snapshot_preview(local_extras);
    let local_pool = local.split('/').next().unwrap_or("<pool>");
    let local_leaf = local.rsplit('/').next().unwrap_or("<name>");
    bail!(
        "refuses: local {local} has {n} snapshot(s) remote {remote_src} does not.\n  \
         Why: a regular pull only adds snapshots from remote — it can't decide\n  \
         whether to keep or destroy local-only ones. Refusing so you pick:\n  \
         force-overwrite local, push the other way, or preserve local's lineage\n  \
         as a separate BE first.\n  \
         local-only:\n      {preview}\n  \
         resolve with:\n    \
         push --force         will run: zfs receive -F on remote (keeps this side)\n    \
         pull --force         will run: zfs receive -F (destroys local-only above)\n    \
         preserve + re-bootstrap (if you want local's lineage kept somewhere):\n                         \
         zboot fork <name> --from {local}@<snap>     # clone of local@<snap>\n                         \
         zfs promote {local_pool}/ROOT/<name>        # snapshots move to <name>\n                         \
         zboot drop {local}                          # local is now an empty clone\n                         \
         zboot pull --name {local_leaf} {remote_src} # re-bootstrap from remote",
        n = local_extras.len(),
    )
}

fn bail_on_pull_rewind(
    remote_src: &str,
    local: &str,
    bound: &str,
    local_after_bound: &[String],
) -> Result<()> {
    let preview = zfs_ops::format_snapshot_preview(local_after_bound);
    let local_pool = local.split('/').next().unwrap_or("<pool>");
    let local_leaf = local.rsplit('/').next().unwrap_or("<name>");
    bail!(
        "refuses: bounded pull into {local} but local is past the bound {remote_src}@{bound}.\n  \
         Why: local has {n} snapshot(s) taken after the bound on remote. A regular pull\n  \
         can't go backwards (zfs send -I requires forward time). This is a *rewind*,\n  \
         not a fast-forward — matches git's non-fast-forward refusal.\n  \
         local-after-bound:\n      {preview}\n  \
         resolve with:\n    \
         pull --force         will run: zfs rollback -r {local}@{bound}\n                         destroys the {n} snapshot(s) above on local\n    \
         (omit @{bound})      pull remote's latest, no rewind\n    \
         preserve + re-bootstrap (if you want local's newer lineage kept):\n                         \
         zboot fork <name> --from {local}@<snap>     # clone of local@<snap>\n                         \
         zfs promote {local_pool}/ROOT/<name>        # snapshots move to <name>\n                         \
         zboot drop {local}                          # local is now an empty clone\n                         \
         zboot pull --name {local_leaf} {remote_src} # re-bootstrap from remote",
        n = local_after_bound.len(),
    )
}
