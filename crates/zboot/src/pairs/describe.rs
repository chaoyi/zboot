//! Plain-text reviews of the pair verbs' plans and follow-ups, shared by the
//! command line and the Menu.
use super::{
    PairResult, PrimaryMode, PrimaryPlan, PrimaryResult, Released, SyncEntry, SyncPlan, UnpairPlan,
    UnpairResult,
    prune::{Pending, review_command},
};
use crate::pairs::plan::PairPlan;
use zfs_tools::engine::escape_display as esc;

fn snapshots(count: usize) -> String {
    format!(
        "{count} {}",
        if count == 1 { "snapshot" } else { "snapshots" }
    )
}
/// Bytes in binary units, as `zfs list` shows them.
fn space(bytes: u64) -> String {
    let mut value = bytes as f64;
    for unit in ["B", "K", "M", "G", "T"] {
        if value < 1024.0 || unit == "T" {
            return if unit == "B" {
                format!("{bytes}B")
            } else {
                format!("{value:.1}{unit}")
            };
        }
        value /= 1024.0;
    }
    unreachable!()
}
/// A snapshot's creation time, in UTC.
fn created(epoch: i64) -> String {
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(epoch.max(0) as u64);
    crate::tree::snapshot_name("", at)
        .trim_start_matches('-')
        .to_owned()
}
/// The pending deletions of one pair, one line each.
fn pending(p: &Pending, source: &str) -> String {
    let copy = esc(&p.copy.name);
    let source = esc(source);
    let mut out = format!(
        "  {} only on {copy}; {source} no longer has {}:\n",
        snapshots(p.snapshots.len()),
        if p.snapshots.len() == 1 { "it" } else { "them" }
    );
    for s in &p.snapshots {
        out += &format!(
            "    {}  created {}  frees {}{}\n",
            esc(&s.snapshot.name),
            created(s.creation_epoch_seconds),
            space(s.used_bytes),
            if s.collides {
                format!("  (its name arrives from {source}: kept, it stops this pair)")
            } else {
                String::new()
            }
        );
    }
    if p.snapshots.len() > 1 {
        out += &format!(
            "  Together they free at least {}.\n",
            space(p.snapshots.iter().map(|s| s.used_bytes).sum())
        );
    }
    out
}

/// What `sync` does before it starts: each pair, the snapshots only its copy
/// keeps, and how to delete them.
pub fn sync_plan(plan: &SyncPlan, token: &str) -> String {
    let mut out = String::new();
    for entry in &plan.entries {
        let creates = entry.admitted.as_ref().is_some_and(|admission| {
            matches!(
                admission.destination,
                crate::transfer::Destination::Absent { .. }
            )
        });
        out += &format!(
            "Sync {} -> {}{}\n",
            esc(&entry.source),
            esc(&entry.destination),
            match &entry.error {
                Some(error) => format!(" ({})", esc(error)),
                None if creates => format!(
                    ": creates {} and pairs the two, with {} as the working copy",
                    esc(&entry.destination),
                    esc(&entry.source)
                ),
                None => String::new(),
            }
        );
        if let Some(p) = &entry.pending {
            out += &pending(p, &entry.source);
        }
    }
    if let Some(summary) = plan.summary() {
        out += &format!(
            "After deletion these snapshots exist nowhere. Type the summary ({}) on a terminal, \
             or pass --confirm with this token, to delete them before the transfer; otherwise \
             they are kept and the transfer runs.\n",
            esc(&summary)
        );
    }
    out += &format!("Token {token}\n");
    out
}

/// What `pair` does.
pub fn pair(plan: &PairPlan) -> String {
    let (primary, receiver) = match plan.primary {
        crate::history::Side::Left => (&plan.left, &plan.right),
        crate::history::Side::Right => (&plan.right, &plan.left),
    };
    let mut out = format!(
        "Pair {} (primary) with {}.\n{} becomes read-only and unmounted.\n",
        zfs_tools::engine::escape_display(&primary.endpoint.name),
        zfs_tools::engine::escape_display(&receiver.endpoint.name),
        zfs_tools::engine::escape_display(&receiver.endpoint.name),
    );
    for (a, b) in &plan.anchors {
        out += &format!(
            "  hold common snapshot {} = {}\n",
            zfs_tools::engine::escape_display(&a.name),
            zfs_tools::engine::escape_display(&b.name)
        );
    }
    out
}

/// What `unpair` changes, and what the operator states or releases.
pub fn unpair(plan: &UnpairPlan) -> String {
    let name = zfs_tools::engine::escape_display(&plan.dataset.name);
    let mut out = String::new();
    match (&plan.record, plan.one_sided) {
        (Some(r), false) => {
            out += &format!(
                "Unpair {name} and {}: both pair records are removed. Data, mounts, read-only \
                 settings and anchor holds stay.\n",
                zfs_tools::engine::escape_display(&r.peer.name)
            )
        }
        (Some(_), true) => out += &format!("Unpair {name} one-sided.\n"),
        (None, _) => out += &format!("{name} is not paired.\n"),
    }
    if let Some(statement) = &plan.statement {
        out += &format!("{}\n", zfs_tools::engine::escape_display(statement));
    }
    if let Some(points) = &plan.release {
        out += "Release these anchor holds; the snapshots become deletable:\n";
        for p in points {
            out += &format!(
                "  {} {}{}{}\n",
                p.tag,
                zfs_tools::engine::escape_display(&p.point.name),
                if p.deferred_destroy {
                    " (marked for deferred destroy: it is destroyed with its last hold)"
                } else {
                    ""
                },
                if p.clones.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (clones: {})",
                        zfs_tools::engine::escape_display(&p.clones.join(", "))
                    )
                }
            );
        }
    }
    out
}

/// What `primary` does, and what it loses.
pub fn primary(plan: &PrimaryPlan) -> String {
    let name = zfs_tools::engine::escape_display(&plan.target.name);
    let peer = plan
        .peer
        .as_ref()
        .map(|p| zfs_tools::engine::escape_display(&p.name))
        .unwrap_or_default();
    let mut out = match plan.mode {
        PrimaryMode::AlreadyPrimary => format!("{name} is already the primary.\n"),
        PrimaryMode::Standalone => format!("{name} is not paired; activate it.\n"),
        PrimaryMode::CatchUp => format!(
            "Fence {peer}, transfer its last changes to {name}, then make {name} the primary. \
             Nothing is lost.\n"
        ),
        PrimaryMode::Takeover => format!(
            "Make {name} the primary. {peer} is rolled back to the last snapshot it shares with \
             {name}; this LOSES on {peer}:\n"
        ),
        PrimaryMode::DeadPeer => format!("Make {name} the primary without its peer {peer}.\n"),
    };
    if !plan.unreviewed.is_empty() {
        out += &format!(
            "{peer} deleted these and they exist only on {name}; after the switch {name}'s own \
             retention may delete them, and then they exist nowhere:\n"
        );
        for s in &plan.unreviewed {
            out += &format!(
                "  snapshot {}\n",
                zfs_tools::engine::escape_display(&s.name)
            );
        }
    }
    if let Some(loss) = &plan.loss {
        for s in &loss.snapshots {
            out += &format!(
                "  snapshot {}\n",
                zfs_tools::engine::escape_display(&s.name)
            );
        }
        for d in &loss.unsnapshotted {
            out += &format!(
                "  changes in {} since its last snapshot\n",
                zfs_tools::engine::escape_display(d)
            );
        }
    }
    if let Some(statement) = &plan.statement {
        out += &format!("{}\n", zfs_tools::engine::escape_display(statement));
    }
    for a in plan.activation.iter().filter(|a| a.changes) {
        out += &format!(
            "  activate {}{}\n",
            zfs_tools::engine::escape_display(&a.dataset.name),
            if a.mounts { " and mount it" } else { "" }
        );
    }
    if let Some(h) = &plan.boot_default {
        out += &format!(
            "  boot default of pool {} becomes {}\n",
            zfs_tools::engine::escape_display(&h.pool),
            zfs_tools::engine::escape_display(&h.dataset)
        );
        if let Some(stale) = &h.clears {
            out += &format!(
                "  clear the stale boot default {} of pool {}\n",
                zfs_tools::engine::escape_display(&stale.dataset),
                zfs_tools::engine::escape_display(&stale.pool)
            );
        }
    }
    // For review only: they lose nothing, and the token does not bind them.
    if !plan.space_differences.is_empty() {
        out += &match plan.mode {
            PrimaryMode::CatchUp => format!(
                "Space limits differ. The catch-up applies {peer}'s where {name} can take them, \
                 and the next sync gives {peer} whatever {name} then holds:\n"
            ),
            PrimaryMode::Takeover => format!(
                "Space limits differ. {name} keeps its own, and the next sync gives them to \
                 {peer}:\n"
            ),
            _ => format!(
                "Space limits differ. A sync applies {name}'s when {peer} can take them, and \
                 removes from {peer} a limit {name} does not set:\n"
            ),
        };
        for difference in &plan.space_differences {
            out += &format!("  {}\n", esc(&difference.describe()));
        }
    }
    out
}

/// What `pair` did.
pub fn paired(result: &PairResult) -> String {
    let o = &result.outcome;
    let (primary, secondary) = match o.primary {
        crate::history::Side::Left => (&o.left.name, &o.right.name),
        crate::history::Side::Right => (&o.right.name, &o.left.name),
    };
    if o.already_paired {
        return format!(
            "{} and {} are already paired (pair {}).\n",
            zfs_tools::engine::escape_display(&o.left.name),
            zfs_tools::engine::escape_display(&o.right.name),
            o.operation_id
        );
    }
    format!(
        "Paired {} (primary) with {} (read-only secondary); pair {}.\n",
        zfs_tools::engine::escape_display(primary),
        zfs_tools::engine::escape_display(secondary),
        o.operation_id,
    )
}

/// What `unpair` did.
pub fn unpaired(result: &UnpairResult) -> String {
    let mut out = String::new();
    if let Some(peer) = &result.peer {
        out += &format!(
            "Unpaired {}{}.\n",
            zfs_tools::engine::escape_display(&result.dataset.name),
            if result.one_sided {
                format!(
                    " (only here; {} was not changed)",
                    zfs_tools::engine::escape_display(&peer.name)
                )
            } else {
                format!(" and {}", zfs_tools::engine::escape_display(&peer.name))
            }
        );
    }
    if let Some(tag) = &result.retained_anchor_tag {
        out += &format!(
            "Anchor holds {tag} stay; `unpair {} --release-anchors` releases them.\n",
            zfs_tools::engine::escape_display(&result.dataset.name)
        );
    }
    for r in &result.released {
        out += &format!(
            "Released {} on {}{}.\n",
            r.tag,
            zfs_tools::engine::escape_display(&r.snapshot),
            match r.state {
                Released::HoldRemoved => "",
                Released::NotHeld => " (was not held)",
                Released::Destroyed => " (destroyed: it was marked for deferred destroy)",
            }
        );
    }
    out
}

/// What `sync` did, one pair per entry.
pub fn synced(entries: &[SyncEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        let (src, dst) = (
            zfs_tools::engine::escape_display(&entry.source),
            zfs_tools::engine::escape_display(&entry.destination),
        );
        match (&entry.result, &entry.error) {
            (Some(r), _) => {
                out += &format!(
                    "Synced {src} -> {dst}: {}.\n",
                    match r.transfer.status {
                        crate::transfer::TransferStatus::Complete => "complete",
                        crate::transfer::TransferStatus::AlreadyComplete => "already up to date",
                    }
                );
                if let Some(pair) = &r.bootstrapped {
                    out += &format!("Created {dst} and paired it with {src} (pair {pair}).\n");
                }
                for renamed in &r.renamed {
                    out += &format!(
                        "Renamed {} to {}, its name on {src}.\n",
                        esc(&renamed.from),
                        esc(&renamed.to)
                    );
                }
                for deleted in &r.deleted {
                    out += &format!(
                        "Deleted {}: it existed only on {dst}.\n",
                        esc(&deleted.name)
                    );
                }
                for kept in &r.kept {
                    out += &format!("Kept {}: {}.\n", esc(&kept.snapshot), esc(&kept.reason));
                }
                if !r.boundaries.deleted.is_empty() {
                    out += &format!(
                        "Deleted {} of zboot's older boundary snapshots on {src} and {dst}.\n",
                        r.boundaries.deleted.len()
                    );
                }
                for kept in &r.boundaries.kept {
                    out += &format!(
                        "Kept boundary snapshot {}: {}.\n",
                        esc(&kept.snapshot),
                        esc(&kept.reason)
                    );
                }
                if let Some(p) = &r.pending {
                    out += &format!(
                        "{} only on {dst} {} review for deletion; {src} no longer has {}. \
                         Review with {}.\n",
                        snapshots(p.snapshots.len()),
                        if p.snapshots.len() == 1 {
                            "awaits"
                        } else {
                            "await"
                        },
                        if p.snapshots.len() == 1 { "it" } else { "them" },
                        esc(&review_command(&p.copy.name))
                    );
                }
                for key in &r.transfer.unapplied {
                    out += &format!(
                        "NOT applied: {dst} does not hold {src}'s {key} and keeps its own; \
                         check its space and sync again.\n",
                        key = zfs_tools::engine::escape_display(key)
                    );
                }
                for child in &r.transfer.unmirrored {
                    out += &format!(
                        "NOT mirrored: {} is inside the pair; a pair joins leaf datasets, so move it out or remove it.\n",
                        zfs_tools::engine::escape_display(child)
                    );
                }
            }
            (None, Some(error)) => {
                out += &format!(
                    "NOT synced {src} -> {dst}: {}\n",
                    zfs_tools::engine::escape_display(error)
                )
            }
            (None, None) => {}
        }
    }
    out
}

/// What `primary` did.
pub fn switched(result: &PrimaryResult) -> String {
    let name = zfs_tools::engine::escape_display(&result.target.name);
    let mut out = match &result.former_primary {
        Some(former) => format!(
            "{name} is the primary; {} is its read-only secondary.\n",
            zfs_tools::engine::escape_display(&former.name)
        ),
        None if result.already_primary => format!("{name} is already the primary.\n"),
        None => format!("{name} is active.\n"),
    };
    if let Some(moved) = &result.boot_default {
        out += &if moved.complete {
            "Boot default moved.\n".to_string()
        } else {
            format!(
                "Boot default NOT moved: {}\n",
                zfs_tools::engine::escape_display(
                    moved.detail.as_deref().unwrap_or("unknown result")
                )
            )
        };
    }
    out
}
