//! Convert native, identity-bound observations into the pure history contract.
//! A zero written-byte observation describes the synced objset at that instant;
//! it is not application quiescence. Pair/receive executors fence the receiver
//! and synchronize its pool before relying on this evidence.
use crate::history::{self, Encryption, Head, Kind, Node, Tree};
use std::collections::BTreeMap;
use zfs_tools::engine::{
    Dataset, Error, SnapshotRef,
    management::{self, PairRecord},
    pool_of,
    state::NativeState,
};

pub trait HistoryBackend {
    fn written(&mut self, dataset: &Dataset, base: &SnapshotRef) -> Result<u64, Error>;
    fn ivset(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Guid, Error>;
}
pub struct NativeHistory;
impl HistoryBackend for NativeHistory {
    fn written(&mut self, dataset: &Dataset, base: &SnapshotRef) -> Result<u64, Error> {
        Ok(zfs_tools::engine::observe_written_since(dataset, base)?.referenced_new_bytes)
    }
    fn ivset(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Guid, Error> {
        Ok(zfs_tools::engine::observe_snapshot_ivset(point)?.ivset_guid)
    }
}

pub fn tree(
    state: &NativeState,
    root: &str,
    backend: &mut impl HistoryBackend,
) -> Result<Tree, Error> {
    zfs_tools::engine::validate_dataset_name(root)?;
    if !state.inspection.requested_datasets.is_empty() {
        return Err(refuse(
            "history requires complete supported imported inventory",
        ));
    }
    let snapshots = state
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| refuse("history observation omitted snapshots"))?;
    let root_dataset = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == root)
        .ok_or_else(|| Error::MissingScope(root.into()))?;
    let pool_name = pool_of(root);
    let pool = state
        .inspection
        .pools
        .iter()
        .find(|pool| pool.name == pool_name)
        .ok_or_else(|| refuse("history pool was not observed"))?;
    let pool_props = state
        .pool_properties
        .get(pool_name)
        .ok_or_else(|| refuse("complete history pool properties were not observed"))?;
    if pool.guid != root_dataset.identity.pool_guid
        || pool_props
            .get("guid")
            .map(|property| property.value.as_str())
            != Some(pool.guid.to_string().as_str())
    {
        return Err(refuse("history pool identity changed during observation"));
    }
    if pool_props.keys().any(|key| management::managed_key(key)) {
        return Err(refuse("unsupported native pool management properties"));
    }
    let root_props = management::bound_properties(state, root)?;
    management::validate_supported_properties(root_props, root)?;
    let record = root_props
        .get(management::PAIR_PROPERTY)
        .map(|property| {
            let record = PairRecord::parse(&property.value)?;
            if property.source != "local"
                || record.endpoint.name != root
                || record.endpoint.identity != root_dataset.identity
            {
                return Err(refuse("pair scope does not own its native root"));
            }
            Ok(record)
        })
        .transpose()?;
    let mut parent = root.rsplit_once('/').map(|(parent, _)| parent);
    while let Some(name) = parent {
        let props = management::bound_properties(state, name)?;
        management::validate_supported_properties(props, name)?;
        if props.contains_key(management::PAIR_PROPERTY) {
            return Err(refuse(
                "pair endpoint overlaps an ancestor's management scope",
            ));
        }
        parent = name.rsplit_once('/').map(|(parent, _)| parent);
    }
    let mut nodes = BTreeMap::new();
    for dataset in state
        .inspection
        .datasets
        .iter()
        .filter(|d| history::contains_dataset(root, &d.name))
    {
        let props = management::bound_properties(state, &dataset.name)?;
        management::validate_supported_properties(props, &dataset.name)?;
        match (record.as_ref(), props.get(management::PAIR_PROPERTY)) {
            (None, None) => {}
            (Some(expected), Some(property)) => {
                let source = if dataset.name == root {
                    "local".into()
                } else {
                    format!("inherited from {root}")
                };
                if property.source != source || PairRecord::parse(&property.value)? != *expected {
                    return Err(refuse("nested, received or inconsistent pair ownership"));
                }
            }
            _ => return Err(refuse("partial or overlapping pair publication")),
        }
        let mut history: Vec<_> = snapshots
            .iter()
            .filter(|s| {
                s.name
                    .split_once('@')
                    .is_some_and(|(name, _)| name == dataset.name)
            })
            .collect();
        history.sort_by_key(|s| s.identity.createtxg);
        if history
            .windows(2)
            .any(|w| w[0].identity.createtxg >= w[1].identity.createtxg)
        {
            return Err(refuse("ambiguous native snapshot ancestry order"));
        }
        if history.iter().any(|snapshot| snapshot.defer_destroy) {
            return Err(refuse(
                "retained history contains a snapshot pending deferred destruction",
            ));
        }
        let head = match history.last() {
            None => Head::Changed,
            Some(snapshot) => {
                if backend.written(dataset, &snapshot.point())? == 0 {
                    Head::Clean
                } else {
                    Head::Changed
                }
            }
        };
        let encryption = if dataset.encryption == zfs_tools::engine::Encryption::Off {
            Encryption::Plain
        } else {
            let mut ivsets = BTreeMap::new();
            for snapshot in &history {
                ivsets.insert(snapshot.guid, backend.ivset(&snapshot.point())?);
            }
            Encryption::Raw {
                cipher: format!("{:?}", dataset.encryption),
                ivsets,
            }
        };
        let clone_dependents = history
            .iter()
            .flat_map(|s| s.clones.iter().cloned())
            .collect();
        let relative = dataset
            .name
            .strip_prefix(root)
            .unwrap()
            .strip_prefix('/')
            .unwrap_or("");
        nodes.insert(
            relative.into(),
            Node {
                kind: match &dataset.kind {
                    zfs_tools::engine::DatasetKind::Filesystem => Kind::Filesystem,
                    zfs_tools::engine::DatasetKind::Volume => Kind::Volume,
                },
                snapshots: history.iter().map(|s| s.guid).collect(),
                head,
                encryption,
                origin: dataset.origin.clone(),
                clone_dependents,
            },
        );
    }
    Ok(Tree {
        root: root.into(),
        nodes,
        peer: record.map(|r| r.peer.name),
        pending: false,
        staging: false,
        dependencies_complete: true,
    })
}

fn refuse(detail: impl Into<String>) -> Error {
    Error::Inconsistent(detail.into())
}
