//! Core data types: pools, BEs, snapshots, bound lists, properties, forest,
//! atomic-set. All public types use `#[non_exhaustive]` where extension is
//! plausible; the small/stable ones (`BoundKey`, `SnapshotRef`) don't, so
//! external crates can construct them directly without `new()` ceremony.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Pools
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Pool {
    pub name: String,
    /// Set from `zboot:role`; `None` if pool isn't tagged.
    pub role: Option<PoolRole>,
    /// Native `bootfs`; `None` if unset.
    pub bootfs: Option<String>,
    pub guid: Option<u64>,
}

impl Pool {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            role: None,
            bootfs: None,
            guid: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "lowercase")]
pub enum PoolRole {
    Root,
}

// ---------------------------------------------------------------------------
// Boot environments
// ---------------------------------------------------------------------------

/// A boot environment — a ZFS dataset tagged `zboot:be=true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BootEnvironment {
    pub pool: String,
    /// Full dataset path, e.g. `rpool/ROOT/be1`.
    pub dataset: String,
    /// Last component, e.g. `be1`.
    pub name: String,
    /// Native `origin` (clone parent). `None` for root BEs.
    pub origin: Option<SnapshotRef>,
    pub created_by: Option<String>,
    pub mountpoint: Option<Mountpoint>,
    pub canmount: Option<Canmount>,
}

impl BootEnvironment {
    pub fn new(pool: impl Into<String>, name: impl Into<String>) -> Self {
        let pool = pool.into();
        let name = name.into();
        let dataset = format!("{pool}/ROOT/{name}");
        Self {
            pool,
            dataset,
            name,
            origin: None,
            created_by: None,
            mountpoint: None,
            canmount: None,
        }
    }

    #[must_use]
    pub fn with_origin(mut self, origin: SnapshotRef) -> Self {
        self.origin = Some(origin);
        self
    }
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/// `dataset@name`. Stable shape; not `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub dataset: String,
    pub name: String,
}

impl SnapshotRef {
    /// Parse `dataset@name`. `None` if `@` absent or either side empty.
    pub fn parse(s: &str) -> Option<Self> {
        let (ds, name) = s.split_once('@')?;
        if ds.is_empty() || name.is_empty() {
            return None;
        }
        Some(Self {
            dataset: ds.to_owned(),
            name: name.to_owned(),
        })
    }

    pub fn render(&self) -> String {
        format!("{}@{}", self.dataset, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Snapshot {
    pub dataset: String,
    pub name: String,
    /// `zboot:set` UUID — set only for atomic snapshots involving multiple datasets.
    /// Singleton snapshots leave this `None`; provenance lives in `created_by`.
    pub set: Option<String>,
    pub created_by: Option<String>,
}

impl Snapshot {
    pub fn new(dataset: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            dataset: dataset.into(),
            name: name.into(),
            set: None,
            created_by: None,
        }
    }

    pub fn as_ref(&self) -> SnapshotRef {
        SnapshotRef {
            dataset: self.dataset.clone(),
            name: self.name.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Mount-related primitives
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "lowercase")]
pub enum Canmount {
    On,
    Off,
    Noauto,
}

impl Canmount {
    /// ZFS-property-string form (`on`, `off`, `noauto`).
    pub fn render(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Noauto => "noauto",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "lowercase")]
pub enum Mountpoint {
    None,
    Legacy,
    Path(String),
}

// ---------------------------------------------------------------------------
// Bound lists
// ---------------------------------------------------------------------------

/// `pool:be` reference inside a `zboot:attached-to` list. Stable shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundKey {
    pub pool: String,
    pub be: String,
}

impl BoundKey {
    pub fn new(pool: impl Into<String>, be: impl Into<String>) -> Self {
        Self {
            pool: pool.into(),
            be: be.into(),
        }
    }

    pub fn render(&self) -> String {
        format!("{}:{}", self.pool, self.be)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BoundList(pub Vec<BoundKey>);

impl BoundList {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn parse(s: &str) -> Result<Self, crate::ParseError> {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed == "-" {
            return Ok(Self::new());
        }
        let mut entries = Vec::new();
        for part in trimmed.split(',') {
            let part = part.trim();
            let (pool, be) = part
                .split_once(':')
                .ok_or_else(|| crate::ParseError::BoundList(part.to_owned()))?;
            if pool.is_empty() || be.is_empty() {
                return Err(crate::ParseError::BoundList(part.to_owned()));
            }
            entries.push(BoundKey::new(pool, be));
        }
        Ok(Self(entries))
    }

    pub fn render(&self) -> String {
        self.0
            .iter()
            .map(BoundKey::render)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Idempotent: appending an existing key is a no-op.
    pub fn append(&mut self, key: BoundKey) {
        if !self.0.iter().any(|k| k == &key) {
            self.0.push(key);
        }
    }

    /// Returns `true` if removed.
    pub fn remove(&mut self, key: &BoundKey) -> bool {
        let prev = self.0.len();
        self.0.retain(|k| k != key);
        prev != self.0.len()
    }

    pub fn contains(&self, key: &BoundKey) -> bool {
        self.0.iter().any(|k| k == key)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

// ---------------------------------------------------------------------------
// Property
// ---------------------------------------------------------------------------

/// A ZFS property zboot interprets.
///
/// Native ZFS props get named variants; the `zboot:*` namespace gets named variants;
/// anything else falls into `Other`. Adding a new variant is non-breaking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Property {
    Bootfs(Option<String>),
    Mountpoint(Mountpoint),
    Canmount(Canmount),
    Origin(Option<SnapshotRef>),
    Cachefile(Option<String>),

    ZbootRole(PoolRole),
    ZbootBe(bool),
    ZbootAttachedTo(BoundList),
    ZbootSet(String),
    ZbootCreatedBy(String),

    Other { name: String, value: String },
}

impl Property {
    pub fn name(&self) -> &str {
        match self {
            Self::Bootfs(_) => "bootfs",
            Self::Mountpoint(_) => "mountpoint",
            Self::Canmount(_) => "canmount",
            Self::Origin(_) => "origin",
            Self::Cachefile(_) => "cachefile",
            Self::ZbootRole(_) => "zboot:role",
            Self::ZbootBe(_) => "zboot:be",
            Self::ZbootAttachedTo(_) => "zboot:attached-to",
            Self::ZbootSet(_) => "zboot:set",
            Self::ZbootCreatedBy(_) => "zboot:created-by",
            Self::Other { name, .. } => name,
        }
    }
}

// ---------------------------------------------------------------------------
// Forest — flat list of BEs with origin-based lineage queries.
// ---------------------------------------------------------------------------

/// The forest is *flat*. Tree-shaped views are built on demand
/// by walking the `origin` field of each BE. ZFS already carries the lineage
/// authoritatively in `origin`; we don't duplicate it as pointers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Forest {
    pub bes: Vec<BootEnvironment>,
}

impl Forest {
    pub fn from_origins(bes: Vec<BootEnvironment>) -> Self {
        Self { bes }
    }

    pub fn len(&self) -> usize {
        self.bes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bes.is_empty()
    }

    /// Find by full dataset path (e.g. `rpool/ROOT/be1`).
    pub fn find_by_dataset(&self, dataset: &str) -> Option<&BootEnvironment> {
        self.bes.iter().find(|be| be.dataset == dataset)
    }

    /// BEs whose origin is `None`, or whose origin's dataset isn't itself in
    /// the forest.
    pub fn roots(&self) -> Vec<&BootEnvironment> {
        let by_ds = self.dataset_index();
        self.bes
            .iter()
            .filter(|be| match &be.origin {
                None => true,
                Some(snap) => !by_ds.contains_key(snap.dataset.as_str()),
            })
            .collect()
    }

    /// All BEs that descend (directly or transitively) from `ancestor_dataset`.
    /// The ancestor itself is not included.
    pub fn descendants_of(&self, ancestor_dataset: &str) -> Vec<&BootEnvironment> {
        let by_ds = self.dataset_index();
        self.bes
            .iter()
            .filter(|be| {
                let mut current = be.origin.as_ref();
                while let Some(snap) = current {
                    if snap.dataset == ancestor_dataset {
                        return true;
                    }
                    match by_ds.get(snap.dataset.as_str()) {
                        Some(parent) => current = parent.origin.as_ref(),
                        None => return false,
                    }
                }
                false
            })
            .collect()
    }

    /// Direct children: BEs whose origin's dataset == `dataset`.
    pub fn children_of(&self, dataset: &str) -> Vec<&BootEnvironment> {
        self.bes
            .iter()
            .filter(|be| be.origin.as_ref().is_some_and(|s| s.dataset == dataset))
            .collect()
    }

    fn dataset_index(&self) -> HashMap<&str, &BootEnvironment> {
        self.bes
            .iter()
            .map(|be| (be.dataset.as_str(), be))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AtomicSet — snapshots taken in one zboot operation share a `zboot:set` UUID.
// Singleton operations (BE only, no bound datasets) don't set the UUID; only
// multi-dataset atomic ops do.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AtomicSet {
    pub uuid: String,
    pub members: Vec<SnapshotRef>,
    pub created_by: Option<String>,
}

impl AtomicSet {
    /// Group snapshots by `zboot:set` UUID. Snapshots without a `set` are
    /// dropped — they aren't part of any zboot atomic-set (singletons live
    /// outside this grouping).
    pub fn from_snapshots(snaps: &[Snapshot]) -> Vec<Self> {
        let mut by_set: HashMap<String, AtomicSet> = HashMap::new();
        for snap in snaps {
            let Some(uuid) = snap.set.as_ref() else {
                continue;
            };
            let entry = by_set.entry(uuid.clone()).or_insert_with(|| AtomicSet {
                uuid: uuid.clone(),
                members: Vec::new(),
                created_by: snap.created_by.clone(),
            });
            entry.members.push(snap.as_ref());
            if entry.created_by.is_none() {
                entry.created_by.clone_from(&snap.created_by);
            }
        }
        let mut sets: Vec<AtomicSet> = by_set.into_values().collect();
        sets.sort_by(|a, b| a.uuid.cmp(&b.uuid));
        sets
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn be(pool: &str, name: &str, origin: Option<&str>) -> BootEnvironment {
        let mut be = BootEnvironment::new(pool, name);
        be.origin = origin.and_then(SnapshotRef::parse);
        be
    }

    // --- BoundList ----------------------------------------------------------

    #[test]
    fn bound_list_empty() {
        assert_eq!(BoundList::parse("").unwrap().len(), 0);
        assert_eq!(BoundList::parse("-").unwrap().len(), 0);
        assert_eq!(BoundList::parse("   ").unwrap().len(), 0);
    }

    #[test]
    fn bound_list_single() {
        let bl = BoundList::parse("rpool:be1").unwrap();
        assert_eq!(bl.0, vec![BoundKey::new("rpool", "be1")]);
    }

    #[test]
    fn bound_list_multi() {
        let bl = BoundList::parse("rpool:be1,rpool2:be2,rpool:be3").unwrap();
        assert_eq!(bl.len(), 3);
    }

    #[test]
    fn bound_list_round_trip() {
        let s = "rpool:be1,rpool2:be2";
        assert_eq!(BoundList::parse(s).unwrap().render(), s);
    }

    #[test]
    fn bound_list_malformed_no_colon() {
        assert!(matches!(
            BoundList::parse("rpoolbe1"),
            Err(crate::ParseError::BoundList(_))
        ));
    }

    #[test]
    fn bound_list_malformed_empty_pool() {
        assert!(matches!(
            BoundList::parse(":be1"),
            Err(crate::ParseError::BoundList(_))
        ));
    }

    #[test]
    fn bound_list_append_idempotent() {
        let mut bl = BoundList::parse("rpool:be1").unwrap();
        let k = BoundKey::new("rpool", "be1");
        bl.append(k.clone());
        bl.append(k);
        assert_eq!(bl.len(), 1);
    }

    #[test]
    fn bound_list_append_distinct() {
        let mut bl = BoundList::parse("rpool:be1").unwrap();
        bl.append(BoundKey::new("rpool", "be2"));
        assert_eq!(bl.len(), 2);
    }

    #[test]
    fn bound_list_remove() {
        let mut bl = BoundList::parse("rpool:be1,rpool:be2").unwrap();
        assert!(bl.remove(&BoundKey::new("rpool", "be1")));
        assert_eq!(bl.render(), "rpool:be2");
    }

    #[test]
    fn bound_list_remove_missing() {
        let mut bl = BoundList::parse("rpool:be1").unwrap();
        assert!(!bl.remove(&BoundKey::new("rpool", "ghost")));
        assert_eq!(bl.len(), 1);
    }

    // --- SnapshotRef --------------------------------------------------------

    #[test]
    fn snapshot_ref_parse() {
        let r = SnapshotRef::parse("rpool/ROOT/be1@snap1").unwrap();
        assert_eq!(r.dataset, "rpool/ROOT/be1");
        assert_eq!(r.name, "snap1");
    }

    #[test]
    fn snapshot_ref_round_trip() {
        let s = "rpool/ROOT/be1@snap1";
        assert_eq!(SnapshotRef::parse(s).unwrap().render(), s);
    }

    #[test]
    fn snapshot_ref_malformed() {
        assert!(SnapshotRef::parse("rpool/ROOT/be1").is_none());
        assert!(SnapshotRef::parse("@snap1").is_none());
        assert!(SnapshotRef::parse("rpool@").is_none());
    }

    // --- Forest -------------------------------------------------------------

    #[test]
    fn empty_forest() {
        let f = Forest::default();
        assert!(f.is_empty());
        assert_eq!(f.roots().len(), 0);
    }

    #[test]
    fn single_be_is_a_root() {
        let f = Forest::from_origins(vec![be("rpool", "be1", None)]);
        assert_eq!(f.roots().len(), 1);
        assert_eq!(f.roots()[0].name, "be1");
    }

    #[test]
    fn clone_chain_has_one_root() {
        let f = Forest::from_origins(vec![
            be("rpool", "be1", None),
            be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
            be("rpool", "be3", Some("rpool/ROOT/be2@snap1")),
        ]);
        assert_eq!(f.roots().len(), 1);
        assert_eq!(f.roots()[0].name, "be1");
    }

    #[test]
    fn external_origin_is_a_root() {
        let f = Forest::from_origins(vec![be("rpool", "be1", Some("dpool/foreign@x"))]);
        assert_eq!(f.roots().len(), 1);
    }

    #[test]
    fn descendants_walks_chain() {
        let f = Forest::from_origins(vec![
            be("rpool", "be1", None),
            be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
            be("rpool", "be3", Some("rpool/ROOT/be2@snap1")),
            be("rpool", "be4", None),
        ]);
        let descendants = f.descendants_of("rpool/ROOT/be1");
        let names: Vec<_> = descendants.iter().map(|be| be.name.as_str()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"be2"));
        assert!(names.contains(&"be3"));
    }

    #[test]
    fn descendants_excludes_ancestor_self() {
        let f = Forest::from_origins(vec![
            be("rpool", "be1", None),
            be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
        ]);
        let descendants = f.descendants_of("rpool/ROOT/be1");
        assert_eq!(descendants.len(), 1);
        assert_eq!(descendants[0].name, "be2");
    }

    #[test]
    fn descendants_of_missing_dataset_is_empty() {
        let f = Forest::from_origins(vec![be("rpool", "be1", None)]);
        assert_eq!(f.descendants_of("rpool/ROOT/ghost").len(), 0);
    }

    #[test]
    fn children_direct_only() {
        let f = Forest::from_origins(vec![
            be("rpool", "be1", None),
            be("rpool", "be2", Some("rpool/ROOT/be1@snap1")),
            be("rpool", "be3", Some("rpool/ROOT/be2@snap1")),
        ]);
        let children = f.children_of("rpool/ROOT/be1");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "be2");
    }

    #[test]
    fn find_by_dataset() {
        let f = Forest::from_origins(vec![be("rpool", "be1", None), be("rpool2", "be1", None)]);
        let found = f.find_by_dataset("rpool2/ROOT/be1").unwrap();
        assert_eq!(found.pool, "rpool2");
        assert!(f.find_by_dataset("nope").is_none());
    }

    #[test]
    fn cross_pool_origins() {
        // Phase-1 mirror: rpool2's BE cloned from rpool's BE.
        let f = Forest::from_origins(vec![
            be("rpool", "be1", None),
            be("rpool2", "mirror", Some("rpool/ROOT/be1@snap1")),
        ]);
        let descendants = f.descendants_of("rpool/ROOT/be1");
        assert_eq!(descendants.len(), 1);
        assert_eq!(descendants[0].pool, "rpool2");
    }

    // --- AtomicSet ----------------------------------------------------------

    #[test]
    fn atomic_set_groups_by_uuid() {
        let snaps = vec![
            Snapshot {
                dataset: "rpool/ROOT/be1".into(),
                name: "snap1".into(),
                set: Some("uuid-a".into()),
                created_by: Some("snapshot".into()),
            },
            Snapshot {
                dataset: "rpool/home".into(),
                name: "snap1".into(),
                set: Some("uuid-a".into()),
                created_by: Some("snapshot".into()),
            },
            Snapshot {
                dataset: "rpool/ROOT/be2".into(),
                name: "snap1".into(),
                set: Some("uuid-b".into()),
                created_by: Some("snapshot".into()),
            },
        ];
        let sets = AtomicSet::from_snapshots(&snaps);
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0].uuid, "uuid-a");
        assert_eq!(sets[0].members.len(), 2);
        assert_eq!(sets[1].uuid, "uuid-b");
        assert_eq!(sets[1].members.len(), 1);
    }

    #[test]
    fn atomic_set_drops_singletons_without_uuid() {
        // Snapshots without a `set` value (e.g. BE-only snapshot, no bound
        // datasets) are not atomic-set members.
        let snaps = vec![Snapshot::new("rpool/ROOT/be1", "snap1")];
        assert!(AtomicSet::from_snapshots(&snaps).is_empty());
    }
}
