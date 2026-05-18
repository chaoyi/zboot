//! Replication primitives — pair pointers, status markers, dirty-byte
//! rendering. Pure data; no I/O. Mirrors the state catalog in
//! `DESIGN.md § Replication invariants`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PairPointer — the value of a `zboot:mirror` property.
// ---------------------------------------------------------------------------

/// Identifies a paired BE on another pool. Stored on disk as the value
/// of `zboot:mirror` (form: `<pool>/ROOT/<be>`).
///
/// Pair pointers are single-slot (each BE has at most one) and may be
/// asymmetric: in one-to-many topologies the "many" sides all point at
/// the canonical source, while the source points back at only one of
/// them. Mutuality is the typical case, not an invariant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PairPointer {
    pub pool: String,
    pub be: String,
}

impl PairPointer {
    pub fn new(pool: impl Into<String>, be: impl Into<String>) -> Self {
        Self {
            pool: pool.into(),
            be: be.into(),
        }
    }

    /// Parse the canonical `<pool>/ROOT/<be>` form. Returns `None` for
    /// `-` / empty (= unpaired) or any other shape; callers distinguish
    /// "unpaired" from "malformed" by inspecting the raw input.
    pub fn parse_dataset(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed == "-" {
            return None;
        }
        let (pool, rest) = trimmed.split_once('/')?;
        let rest = rest.strip_prefix("ROOT/")?;
        if pool.is_empty() || rest.is_empty() || rest.contains('/') {
            return None;
        }
        Some(Self {
            pool: pool.to_owned(),
            be: rest.to_owned(),
        })
    }

    /// Render to the on-disk form (`<pool>/ROOT/<be>`).
    pub fn render(&self) -> String {
        format!("{}/ROOT/{}", self.pool, self.be)
    }
}

// ---------------------------------------------------------------------------
// PairStatus — what `status` prints for the mirror row.
// ---------------------------------------------------------------------------

/// Computed at status-render time from local + peer snapshot GUID sets.
/// `dirty_bytes` is orthogonal to ahead/behind — both can be present
/// simultaneously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairStatus {
    /// Snapshot GUID sets match.
    InSync,
    /// Local has `n` snapshots peer doesn't.
    Ahead(usize),
    /// Peer has `n` snapshots local doesn't.
    Behind(usize),
    /// Both sides have unique snapshots; `--force` needed to resolve.
    Diverged { ahead: usize, behind: usize },
    /// Peer pointer references a dataset that doesn't exist (peer pool
    /// is imported but the dataset is gone).
    TargetMissing,
    /// Peer's pool isn't currently imported; can't compute.
    PoolNotImported,
    /// Peer exists but its `Mirror` doesn't point back (or points
    /// elsewhere). Informational — legitimate for tracking pointers
    /// in one-to-many topologies; flagged so the user knows.
    Asymmetric,
}

impl PairStatus {
    /// Compute the snapshot-set markers given local and peer GUID sets.
    /// Pass `None` for `peer_guids` if the peer pool isn't imported.
    /// `peer_exists` should be `false` if the peer pool IS imported but
    /// the dataset is gone (target-missing).
    pub fn from_guids(
        local_guids: &BTreeSet<String>,
        peer_guids: Option<&BTreeSet<String>>,
        peer_exists: bool,
    ) -> Self {
        let Some(peer) = peer_guids else {
            return Self::PoolNotImported;
        };
        if !peer_exists {
            return Self::TargetMissing;
        }
        let ahead = local_guids.difference(peer).count();
        let behind = peer.difference(local_guids).count();
        match (ahead, behind) {
            (0, 0) => Self::InSync,
            (n, 0) => Self::Ahead(n),
            (0, n) => Self::Behind(n),
            (a, b) => Self::Diverged {
                ahead: a,
                behind: b,
            },
        }
    }

    /// Render the bracketed status marker for the `mirror:` line.
    /// `dirty_bytes` is overlaid as `, dirty <bytes>` on every state
    /// except the explicit error states.
    pub fn render(&self, dirty_bytes: Option<u64>) -> String {
        let body = match self {
            Self::InSync => "in sync".to_owned(),
            Self::Ahead(n) => format!("\u{2191}{n}"),
            Self::Behind(n) => format!("\u{2193}{n}"),
            Self::Diverged { ahead, behind } => {
                format!("\u{2191}{ahead} \u{2193}{behind} diverged")
            }
            Self::TargetMissing => return "[target missing]".to_owned(),
            Self::PoolNotImported => return "[pool not imported]".to_owned(),
            Self::Asymmetric => "asymmetric".to_owned(),
        };
        match dirty_bytes {
            Some(bytes) if bytes > 0 => format!("[{body}, dirty {}]", human_bytes(bytes)),
            _ => format!("[{body}]"),
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot anchor naming — `@mirror-<utc-ns>` (legacy + new).
// ---------------------------------------------------------------------------

/// True iff `snap_name` looks like a replication anchor managed by
/// push/pull/mirror. These are excluded from divergence calculations
/// (pruning lag isn't divergence) and from ahead/behind counts.
///
/// Accepts both forms:
/// - `<dataset>@mirror-<utc-ns>` — full path
/// - `mirror-<utc-ns>` — just the snapshot name after `@`
pub fn is_replication_anchor(snap_or_name: &str) -> bool {
    let name = snap_or_name.rsplit_once('@').map_or(snap_or_name, |(_, n)| n);
    name.starts_with("mirror-")
}

// ---------------------------------------------------------------------------
// Human-readable byte sizes — for status's `dirty <bytes>` field.
// ---------------------------------------------------------------------------

/// Format a byte count as a short human-readable string (`12.4 MiB`,
/// `248 KiB`, `4.0 KiB`). Single decimal place; binary units (1024).
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- PairPointer --------------------------------------------------------

    #[test]
    fn pair_pointer_parses_canonical() {
        let p = PairPointer::parse_dataset("rpool2/ROOT/be1").unwrap();
        assert_eq!(p.pool, "rpool2");
        assert_eq!(p.be, "be1");
    }

    #[test]
    fn pair_pointer_round_trip() {
        let s = "rpool2/ROOT/be1";
        assert_eq!(PairPointer::parse_dataset(s).unwrap().render(), s);
    }

    #[test]
    fn pair_pointer_empty_and_dash() {
        assert!(PairPointer::parse_dataset("").is_none());
        assert!(PairPointer::parse_dataset("-").is_none());
        assert!(PairPointer::parse_dataset("   ").is_none());
    }

    #[test]
    fn pair_pointer_rejects_non_root() {
        assert!(PairPointer::parse_dataset("rpool/home").is_none());
        assert!(PairPointer::parse_dataset("rpool/ROOT/be1/sub").is_none());
        assert!(PairPointer::parse_dataset("rpool2/ROOT/").is_none());
        assert!(PairPointer::parse_dataset("just-a-name").is_none());
    }

    // --- PairStatus.from_guids ---------------------------------------------

    fn s(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn in_sync_when_sets_match() {
        assert_eq!(
            PairStatus::from_guids(&s(&["g1", "g2"]), Some(&s(&["g1", "g2"])), true),
            PairStatus::InSync
        );
    }

    #[test]
    fn ahead_when_local_extra() {
        assert_eq!(
            PairStatus::from_guids(&s(&["g1", "g2", "g3"]), Some(&s(&["g1"])), true),
            PairStatus::Ahead(2)
        );
    }

    #[test]
    fn behind_when_peer_extra() {
        assert_eq!(
            PairStatus::from_guids(&s(&["g1"]), Some(&s(&["g1", "g2"])), true),
            PairStatus::Behind(1)
        );
    }

    #[test]
    fn diverged_when_both_unique() {
        assert_eq!(
            PairStatus::from_guids(&s(&["g1", "g2"]), Some(&s(&["g1", "g3"])), true),
            PairStatus::Diverged {
                ahead: 1,
                behind: 1
            }
        );
    }

    #[test]
    fn pool_not_imported_when_peer_guids_none() {
        assert_eq!(
            PairStatus::from_guids(&s(&["g1"]), None, false),
            PairStatus::PoolNotImported
        );
    }

    #[test]
    fn target_missing_when_pool_imported_but_dataset_gone() {
        assert_eq!(
            PairStatus::from_guids(&s(&["g1"]), Some(&s(&[])), false),
            PairStatus::TargetMissing
        );
    }

    // --- PairStatus.render --------------------------------------------------

    #[test]
    fn render_in_sync_clean() {
        assert_eq!(PairStatus::InSync.render(None), "[in sync]");
        assert_eq!(PairStatus::InSync.render(Some(0)), "[in sync]");
    }

    #[test]
    fn render_in_sync_dirty() {
        assert_eq!(
            PairStatus::InSync.render(Some(13_000_000)),
            "[in sync, dirty 12.4 MiB]"
        );
    }

    #[test]
    fn render_ahead_dirty() {
        assert_eq!(
            PairStatus::Ahead(3).render(Some(254_000)),
            "[\u{2191}3, dirty 248.0 KiB]"
        );
    }

    #[test]
    fn render_diverged() {
        let s = PairStatus::Diverged {
            ahead: 3,
            behind: 2,
        }
        .render(None);
        assert_eq!(s, "[\u{2191}3 \u{2193}2 diverged]");
    }

    #[test]
    fn render_target_missing_ignores_dirty() {
        assert_eq!(
            PairStatus::TargetMissing.render(Some(99)),
            "[target missing]"
        );
    }

    #[test]
    fn render_pool_not_imported() {
        assert_eq!(
            PairStatus::PoolNotImported.render(None),
            "[pool not imported]"
        );
    }

    // --- is_replication_anchor ----------------------------------------------

    #[test]
    fn anchor_detection_full_path() {
        assert!(is_replication_anchor("rpool/ROOT/be1@mirror-1234567890"));
        assert!(!is_replication_anchor("rpool/ROOT/be1@pre-experiment"));
    }

    #[test]
    fn anchor_detection_name_only() {
        assert!(is_replication_anchor("mirror-1"));
        assert!(!is_replication_anchor("pre-experiment"));
    }

    // --- human_bytes --------------------------------------------------------

    #[test]
    fn bytes_under_kib_show_b() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1023), "1023 B");
    }

    #[test]
    fn bytes_at_unit_boundaries() {
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn bytes_round_to_decimal() {
        assert_eq!(human_bytes(13_000_000), "12.4 MiB");
        assert_eq!(human_bytes(254_000), "248.0 KiB");
    }
}
