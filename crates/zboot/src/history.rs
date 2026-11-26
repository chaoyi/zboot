//! Pure admission over authoritative observations; these values are not consent.
//! Snapshot GUIDs establish shared points. A local incarnation still has to be
//! revalidated by the executor before it changes any native object.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use zfs_tools::engine::Guid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Filesystem,
    Volume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Head {
    Clean,
    Changed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Encryption {
    Plain,
    /// Native raw ancestry, never inferred from encryption-root names or keys alone.
    Raw {
        cipher: String,
        ivsets: BTreeMap<Guid, Guid>,
    },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub kind: Kind,
    /// Oldest to newest in this dataset's native ancestry order.
    pub snapshots: Vec<Guid>,
    pub head: Head,
    pub encryption: Encryption,
    pub origin: Option<String>,
    /// Includes dependents outside the selected tree.
    pub clone_dependents: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub root: String,
    /// Empty relative path denotes the root itself.
    pub nodes: BTreeMap<String, Node>,
    pub peer: Option<String>,
    pub pending: bool,
    pub staging: bool,
    /// Unknown external dependency closure cannot establish admissibility.
    pub dependencies_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Admission {
    /// None means either side may be chosen primary.
    pub ahead: Option<Side>,
    /// The newest common snapshot of the two leaves.
    pub anchor: Guid,
    /// Snapshots older than the anchor that only one side retains, oldest
    /// first. On a pair's fenced copy these are pending deletions.
    pub only_left: Vec<Guid>,
    pub only_right: Vec<Guid>,
    /// Child datasets under either leaf, relative to its root. A pair joins
    /// leaves: children are never compared or copied, only reported.
    pub children: Vec<String>,
    /// Clones of each leaf's snapshots (a `fork` of a boot environment).
    /// Only a side that sends may have them: a receive or a rollback on the
    /// other side could need to destroy their origin. Callers that know the
    /// direction refuse them on the receiving side.
    pub left_clones: Vec<String>,
    pub right_clones: Vec<String>,
    /// Both leaves have the same newest snapshot; `ahead`, if set, is only
    /// unsnapshotted changes on that side (a running system, say).
    pub snapshots_level: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Rejection {
    #[error("invalid tree: {0}")]
    Invalid(String),
    #[error("overlapping dataset scopes cannot be paired")]
    Overlap,
    #[error("{0}: unresolved operation or archive staging")]
    Pending(String),
    #[error("{0}: existing peer is not the requested endpoint")]
    OtherPeer(String),
    #[error("{0} is itself a clone, or its clones could not all be listed; promote it first")]
    Clone(String),
    #[error(
        "{dataset} has clones of its snapshots ({}); a copy that receives cannot have them: drop them first",
        clones.join(", ")
    )]
    Clones {
        dataset: String,
        clones: Vec<String>,
    },
    #[error("{0}: dataset types differ")]
    Kind(String),
    #[error("{0}: no shared retained history")]
    NoHistory(String),
    #[error("{0}: common snapshots are in a different order, or both sides have newer snapshots")]
    History(String),
    #[error("{0}: receiving head has unreviewed changes, or both heads changed")]
    Dirty(String),
    #[error("{0}: head changes were not observed")]
    UnknownHead(String),
    #[error("{0}: raw encryption ancestry is incompatible or not proven")]
    Encryption(String),
}

pub use zfs_tools::engine::contains_dataset;

/// The leaf itself; its children are only reported.
fn leaf(tree: &Tree) -> Result<&Node, Rejection> {
    zfs_tools::engine::validate_dataset_name(&tree.root)
        .map_err(|e| Rejection::Invalid(e.to_string()))?;
    let node = tree
        .nodes
        .get("")
        .ok_or_else(|| Rejection::Invalid(format!("{}: root missing", tree.root)))?;
    if tree.pending || tree.staging {
        return Err(Rejection::Pending(tree.root.clone()));
    }
    // Clones of the leaf's own snapshots are reported in the admission; the
    // caller refuses them where the leaf receives.
    if !tree.dependencies_complete || node.origin.is_some() {
        return Err(Rejection::Clone(tree.root.clone()));
    }
    let mut seen = BTreeSet::new();
    if node
        .snapshots
        .iter()
        .any(|s| s.get() == 0 || !seen.insert(*s))
    {
        return Err(Rejection::Invalid(format!(
            "{}: duplicate or zero snapshot GUID",
            tree.root
        )));
    }
    if matches!(node.encryption, Encryption::Unknown) {
        return Err(Rejection::Encryption(tree.root.clone()));
    }
    if node.head == Head::Unknown {
        return Err(Rejection::UnknownHead(tree.root.clone()));
    }
    Ok(node)
}

fn encryption(left: &Node, right: &Node, common: &[Guid], name: &str) -> Result<(), Rejection> {
    match (&left.encryption, &right.encryption) {
        (Encryption::Plain, Encryption::Plain) => Ok(()),
        (
            Encryption::Raw {
                cipher: a,
                ivsets: x,
            },
            Encryption::Raw {
                cipher: b,
                ivsets: y,
            },
        ) if a == b
            && common.iter().all(|s| {
                x.get(s)
                    .is_some_and(|iv| iv.get() != 0 && Some(iv) == y.get(s))
            }) =>
        {
            Ok(())
        }
        _ => Err(Rejection::Encryption(name.into())),
    }
}

/// Validate a pair of leaves for pairing, syncing or switching. They need a
/// common snapshot, their common snapshots in the same order, and newer
/// snapshots on at most one side. Older snapshots may differ: one side may
/// have pruned what the other still keeps.
pub fn admit_pair(left: &Tree, right: &Tree) -> Result<Admission, Rejection> {
    let a = leaf(left)?;
    let b = leaf(right)?;
    if contains_dataset(&left.root, &right.root) || contains_dataset(&right.root, &left.root) {
        return Err(Rejection::Overlap);
    }
    for (tree, other) in [(left, right), (right, left)] {
        if tree.peer.as_ref().is_some_and(|peer| peer != &other.root) {
            return Err(Rejection::OtherPeer(tree.root.clone()));
        }
    }
    // A one-sided existing pointer is not an established mutual relationship.
    if left.peer.is_some() != right.peer.is_some() {
        return Err(Rejection::Invalid(
            "partial pair publication requires reconciliation".into(),
        ));
    }
    let name = &left.root;
    if a.kind != b.kind {
        return Err(Rejection::Kind(name.clone()));
    }
    let in_right: BTreeSet<_> = b.snapshots.iter().collect();
    let in_left: BTreeSet<_> = a.snapshots.iter().collect();
    let common: Vec<Guid> = a
        .snapshots
        .iter()
        .filter(|s| in_right.contains(s))
        .copied()
        .collect();
    let Some(&anchor) = common.last() else {
        return Err(Rejection::NoHistory(name.clone()));
    };
    let common_right: Vec<Guid> = b
        .snapshots
        .iter()
        .filter(|s| in_left.contains(s))
        .copied()
        .collect();
    if common != common_right {
        return Err(Rejection::History(name.clone()));
    }
    encryption(a, b, &common, name)?;
    let split = |snapshots: &[Guid]| {
        let at = snapshots.iter().position(|s| *s == anchor).unwrap();
        (snapshots[..at].to_vec(), snapshots[at + 1..].to_vec())
    };
    let (before_a, after_a) = split(&a.snapshots);
    let (before_b, after_b) = split(&b.snapshots);
    let direction = match (after_a.is_empty(), after_b.is_empty()) {
        (false, false) => return Err(Rejection::History(name.clone())),
        (false, true) => Some(Side::Left),
        (true, false) => Some(Side::Right),
        (true, true) => None,
    };
    let ahead = match (direction, a.head, b.head) {
        (Some(Side::Left), _, Head::Changed)
        | (Some(Side::Right), Head::Changed, _)
        | (None, Head::Changed, Head::Changed) => return Err(Rejection::Dirty(name.clone())),
        (Some(side), _, _) => Some(side),
        (None, Head::Changed, Head::Clean) => Some(Side::Left),
        (None, Head::Clean, Head::Changed) => Some(Side::Right),
        _ => None,
    };
    let mut children: BTreeSet<String> = BTreeSet::new();
    for tree in [left, right] {
        children.extend(tree.nodes.keys().filter(|k| !k.is_empty()).cloned());
    }
    Ok(Admission {
        ahead,
        anchor,
        only_left: before_a
            .into_iter()
            .filter(|s| !in_right.contains(s))
            .collect(),
        only_right: before_b
            .into_iter()
            .filter(|s| !in_left.contains(s))
            .collect(),
        children: children.into_iter().collect(),
        left_clones: a.clone_dependents.clone(),
        right_clones: b.clone_dependents.clone(),
        snapshots_level: direction.is_none(),
    })
}

impl Admission {
    /// Refuse clones on the side that receives: `Side::Right` for a transfer
    /// from left to right.
    pub fn refuse_receiver_clones(&self, receiver: Side, name: &str) -> Result<(), Rejection> {
        let clones = match receiver {
            Side::Left => &self.left_clones,
            Side::Right => &self.right_clones,
        };
        if clones.is_empty() {
            Ok(())
        } else {
            Err(Rejection::Clones {
                dataset: name.into(),
                clones: clones.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(ids: &[u64]) -> Node {
        Node {
            kind: Kind::Filesystem,
            snapshots: ids.iter().copied().map(Guid::new).collect(),
            head: Head::Clean,
            encryption: Encryption::Plain,
            origin: None,
            clone_dependents: vec![],
        }
    }
    fn tree(root: &str, ids: &[u64]) -> Tree {
        Tree {
            root: root.into(),
            nodes: BTreeMap::from([(String::new(), node(ids))]),
            peer: None,
            pending: false,
            staging: false,
            dependencies_complete: true,
        }
    }
    #[test]
    fn strict_prefix_and_symmetry() {
        for len in 1..=8 {
            let ids: Vec<_> = (1..=len).collect();
            let a = tree("a/root", &ids);
            for prefix in 1..=len {
                let b = tree("b/root", &ids[..prefix as usize]);
                let ab = admit_pair(&a, &b).unwrap();
                let ba = admit_pair(&b, &a).unwrap();
                assert_eq!(
                    ab.ahead,
                    if prefix == len {
                        None
                    } else {
                        Some(Side::Left)
                    }
                );
                assert_eq!(
                    ba.ahead,
                    if prefix == len {
                        None
                    } else {
                        Some(Side::Right)
                    }
                );
                assert_eq!(ab.anchor, ba.anchor);
            }
        }
    }
    #[test]
    fn pruned_older_snapshots_are_reported_not_refused() {
        let ab = admit_pair(&tree("a/r", &[1, 2, 3, 4]), &tree("b/r", &[1, 3])).unwrap();
        assert_eq!(ab.ahead, Some(Side::Left));
        assert_eq!(ab.anchor, Guid::new(3));
        assert_eq!(ab.only_left, vec![Guid::new(2)]);
        assert!(ab.only_right.is_empty());
        // The working copy pruned 1 and 2; the copy still has them.
        let pruned = admit_pair(&tree("a/r", &[3, 4]), &tree("b/r", &[1, 2, 3])).unwrap();
        assert_eq!(pruned.ahead, Some(Side::Left));
        assert_eq!(pruned.only_right, vec![Guid::new(1), Guid::new(2)]);
        assert!(pruned.only_left.is_empty());
        let level = admit_pair(&tree("a/r", &[2, 3]), &tree("b/r", &[1, 3])).unwrap();
        assert_eq!(level.ahead, None);
        assert_eq!(
            (level.only_left, level.only_right),
            (vec![Guid::new(2)], vec![Guid::new(1)])
        );
    }
    #[test]
    fn diverged_or_reordered_histories_refuse() {
        for (a, b) in [
            (&[1, 2][..], &[1, 3][..]),
            (&[1, 2, 3][..], &[1, 3, 2][..]),
            (&[1, 2, 4][..], &[1, 3][..]),
        ] {
            assert!(
                matches!(
                    admit_pair(&tree("a/r", a), &tree("b/r", b)),
                    Err(Rejection::History(_))
                ),
                "{a:?} {b:?}"
            );
        }
        assert!(matches!(
            admit_pair(&tree("a/r", &[1, 2]), &tree("b/r", &[3, 4])),
            Err(Rejection::NoHistory(_))
        ));
    }
    #[test]
    fn children_are_reported_and_never_compared() {
        let mut a = tree("a/r", &[1, 2]);
        let mut b = tree("b/r", &[1]);
        a.nodes.insert("new".into(), node(&[]));
        b.nodes.insert("other".into(), node(&[8]));
        let admitted = admit_pair(&a, &b).unwrap();
        assert_eq!(admitted.children, vec!["new", "other"]);
        assert_eq!(admitted.ahead, Some(Side::Left));
        // A child's clone or unknown state does not affect the leaf.
        a.nodes.get_mut("new").unwrap().origin = Some("x@y".into());
        a.nodes.get_mut("new").unwrap().head = Head::Unknown;
        assert!(admit_pair(&a, &b).is_ok());
    }
    #[test]
    fn dirty_receiver_is_not_pair_metadata_repair() {
        let a = tree("a/r", &[1, 2]);
        let mut b = tree("b/r", &[1]);
        b.nodes.get_mut("").unwrap().head = Head::Changed;
        assert!(matches!(admit_pair(&a, &b), Err(Rejection::Dirty(_))));
    }
    #[test]
    fn equal_history_dirty_source_selects_direction() {
        let mut a = tree("a/r", &[1]);
        let b = tree("b/r", &[1]);
        a.nodes.get_mut("").unwrap().head = Head::Changed;
        assert_eq!(admit_pair(&a, &b).unwrap().ahead, Some(Side::Left));
    }
    #[test]
    fn raw_ancestry_needs_every_common_ivset() {
        let mut a = tree("a/r", &[1, 2]);
        let mut b = tree("b/r", &[1]);
        a.nodes.get_mut("").unwrap().encryption = Encryption::Raw {
            cipher: "aes-256-gcm".into(),
            ivsets: BTreeMap::from([(Guid::new(1), Guid::new(99))]),
        };
        b.nodes.get_mut("").unwrap().encryption = Encryption::Raw {
            cipher: "aes-256-gcm".into(),
            ivsets: BTreeMap::new(),
        };
        assert!(matches!(admit_pair(&a, &b), Err(Rejection::Encryption(_))));
        b.nodes.get_mut("").unwrap().encryption = a.nodes[""].encryption.clone();
        assert!(admit_pair(&a, &b).is_ok());
    }
    #[test]
    fn third_peer_clone_and_unknown_closure_refuse() {
        let a = tree("a/r", &[1]);
        let mut b = tree("b/r", &[1]);
        b.peer = Some("c/r".into());
        assert!(matches!(admit_pair(&a, &b), Err(Rejection::OtherPeer(_))));
        b.peer = None;
        b.nodes
            .get_mut("")
            .unwrap()
            .clone_dependents
            .push("outside/clone".into());
        // Clones of a leaf's snapshots are reported, and refused only where
        // that leaf receives.
        let admission = admit_pair(&a, &b).unwrap();
        assert_eq!(admission.right_clones, vec!["outside/clone".to_owned()]);
        assert!(admission.left_clones.is_empty());
        assert!(admission.refuse_receiver_clones(Side::Left, "a/r").is_ok());
        assert!(matches!(
            admission.refuse_receiver_clones(Side::Right, "b/r"),
            Err(Rejection::Clones { .. })
        ));
        b.nodes.get_mut("").unwrap().clone_dependents.clear();
        // A leaf that is itself a clone is still refused.
        b.nodes.get_mut("").unwrap().origin = Some("b/base@s".into());
        assert!(matches!(admit_pair(&a, &b), Err(Rejection::Clone(_))));
        b.nodes.get_mut("").unwrap().origin = None;
        b.dependencies_complete = false;
        assert!(matches!(admit_pair(&a, &b), Err(Rejection::Clone(_))));
    }
    #[test]
    fn no_history_partial_pair_and_overlap_refuse() {
        assert!(matches!(
            admit_pair(&tree("a/r", &[]), &tree("b/r", &[])),
            Err(Rejection::NoHistory(_))
        ));
        let mut a = tree("a/r", &[1]);
        let b = tree("b/r", &[1]);
        a.peer = Some(b.root.clone());
        assert!(matches!(admit_pair(&a, &b), Err(Rejection::Invalid(_))));
        assert_eq!(
            admit_pair(&tree("a/r", &[1]), &tree("a/r/child", &[1])),
            Err(Rejection::Overlap)
        );
        assert!(admit_pair(&tree("a/r", &[1]), &tree("a/root", &[1])).is_ok());
    }
}
