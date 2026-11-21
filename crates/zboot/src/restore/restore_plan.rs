//! Identity-bound choices for whole-disk recovery. These values describe intent;
//! they never grant disk-loss consent or replace native transfer admission.
use crate::{history::contains_dataset, selection};
use serde::{Deserialize, Serialize};
use zfs_tools::engine::{Error, SnapshotRef, management::Endpoint, state::NativeState};

fn refuse(message: impl Into<String>) -> Error {
    Error::Refused(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceArgument {
    pub dataset: String,
    pub snapshot: Option<String>,
}

impl SourceArgument {
    pub fn parse(value: &str) -> Result<Self, Error> {
        let (dataset, snapshot) = match value.split_once('@') {
            Some((dataset, suffix)) => {
                zfs_tools::engine::validate_snapshot_name(value)?;
                (dataset, Some(suffix.to_owned()))
            }
            None => {
                zfs_tools::engine::validate_dataset_name(value)?;
                (value, None)
            }
        };
        Ok(Self {
            dataset: dataset.into(),
            snapshot,
        })
    }
}

/// All members and snapshot identities are retained, so a later refresh cannot
/// silently change a numbered selection or substitute a same-name checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub root: Endpoint,
    pub boundary: SnapshotRef,
    pub members: Vec<Endpoint>,
    pub points: Vec<SnapshotRef>,
}

impl Source {
    pub fn observe(state: &NativeState, argument: &SourceArgument) -> Result<Self, Error> {
        if crate::handoff::is_guided_restore_workspace_dataset(&argument.dataset) {
            return Err(refuse(
                "guided restore workspace cannot be a restore source",
            ));
        }
        if !crate::menu::inventory::candidates(state)
            .iter()
            .any(|c| c.dataset == argument.dataset)
        {
            return Err(refuse(
                "restore source must be an observed boot environment",
            ));
        }
        let snapshots = state
            .inspection
            .snapshots
            .as_ref()
            .ok_or_else(|| refuse("restore selection requires snapshot inventory"))?;
        let members = state
            .inspection
            .datasets
            .iter()
            .filter(|d| contains_dataset(&argument.dataset, &d.name))
            .map(|d| Endpoint {
                name: d.name.clone(),
                identity: d.identity.clone(),
            })
            .collect::<Vec<_>>();
        let points = snapshots.iter().map(|s| s.point()).collect::<Vec<_>>();
        Self::select(argument, members, &points)
    }

    fn select(
        argument: &SourceArgument,
        mut members: Vec<Endpoint>,
        points: &[SnapshotRef],
    ) -> Result<Self, Error> {
        members.sort_by(|a, b| a.name.cmp(&b.name));
        let root = members
            .iter()
            .find(|m| m.name == argument.dataset)
            .ok_or_else(|| refuse("restore source disappeared"))?
            .clone();
        if members.windows(2).any(|m| m[0].name == m[1].name)
            || members.iter().any(|m| {
                !contains_dataset(&root.name, &m.name)
                    || m.identity.pool_guid != root.identity.pool_guid
            })
        {
            return Err(refuse("restore source member inventory is inconsistent"));
        }
        let mut boundaries = points
            .iter()
            .filter(|p| {
                p.name.split_once('@').is_some_and(|(name, suffix)| {
                    name == root.name
                        && argument
                            .snapshot
                            .as_deref()
                            .is_none_or(|requested| suffix == requested)
                })
            })
            .collect::<Vec<_>>();
        boundaries.sort_by_key(|point| std::cmp::Reverse(point.identity.createtxg));
        for boundary in boundaries {
            let suffix = boundary.name.split_once('@').unwrap().1;
            let mut chosen = Vec::new();
            for member in &members {
                let name = format!("{}@{suffix}", member.name);
                let matches = points.iter().filter(|p| p.name == name).collect::<Vec<_>>();
                if matches.len() != 1 {
                    break;
                }
                let point = matches[0];
                if point.dataset_guid != member.identity.guid
                    || point.identity.pool_guid != member.identity.pool_guid
                {
                    return Err(refuse("restore checkpoint belongs to a replaced dataset"));
                }
                chosen.push(point.clone());
            }
            if chosen.len() == members.len() {
                return Ok(Self {
                    root,
                    boundary: boundary.clone(),
                    members,
                    points: chosen,
                });
            }
        }
        Err(refuse(match &argument.snapshot {
            Some(_) => "selected checkpoint is missing or not recursively complete",
            None => "boot environment has no complete recursive snapshot",
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub source_be: String,
    pub restored_be: String,
    /// Independent source roots on the target disk, restored to these exact
    /// same names. Parent choices include descendants.
    pub preserve: Vec<String>,
}

impl Mapping {
    pub fn new(source_be: &str, target_pool: &str, preserve: &[String]) -> Result<Self, Error> {
        zfs_tools::engine::validate_dataset_name(source_be)?;
        zfs_tools::engine::validate_dataset_name(target_pool)?;
        if target_pool.contains('/') {
            return Err(refuse("target must name one pool"));
        }
        let (_, relative) = source_be
            .split_once('/')
            .ok_or_else(|| refuse("restore source must be pool/ROOT/BE"))?;
        if relative
            .strip_prefix("ROOT/")
            .is_none_or(|s| s.is_empty() || s.contains('/'))
        {
            return Err(refuse("restore source must be pool/ROOT/BE"));
        }
        let restored_be = format!("{target_pool}/{relative}");
        let preserve = selection::normalize_roots(preserve).map_err(|e| refuse(e.to_string()))?;
        for root in &preserve {
            if root == target_pool || !contains_dataset(target_pool, root) {
                return Err(refuse(
                    "preserved datasets must belong to the selected target pool; pool roots are layout, not datasets to replace",
                ));
            }
        }
        Ok(Self {
            source_be: source_be.into(),
            restored_be,
            preserve,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zfs_tools::engine::{
        DatasetIdentity, Guid, InspectRequest, ObjsetId, SnapshotIdentity, Txg, native,
    };
    fn member(name: &str, guid: u64) -> Endpoint {
        Endpoint {
            name: name.into(),
            identity: DatasetIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(guid),
                createtxg: Txg::new(1),
                objsetid: ObjsetId::new(guid),
            },
        }
    }
    fn point(m: &Endpoint, suffix: &str, guid: u64, txg: u64) -> SnapshotRef {
        SnapshotRef {
            name: format!("{}@{suffix}", m.name),
            dataset_guid: m.identity.guid,
            identity: SnapshotIdentity {
                pool_guid: m.identity.pool_guid,
                guid: Guid::new(guid),
                createtxg: Txg::new(txg),
                objsetid: ObjsetId::new(guid),
            },
        }
    }
    #[test]
    fn latest_means_latest_complete_tree_not_latest_root_only() {
        let root = member("b/ROOT/be", 2);
        let child = member("b/ROOT/be/home", 3);
        let points = vec![
            point(&root, "old", 20, 10),
            point(&child, "old", 21, 11),
            point(&root, "partial", 22, 30),
        ];
        let chosen = Source::select(
            &SourceArgument::parse("b/ROOT/be").unwrap(),
            vec![root, child],
            &points,
        )
        .unwrap();
        assert_eq!(chosen.boundary.name, "b/ROOT/be@old");
        assert_eq!(chosen.points.len(), 2);
    }
    #[test]
    fn explicit_missing_child_never_falls_back_to_another_checkpoint() {
        let root = member("b/ROOT/be", 2);
        let child = member("b/ROOT/be/home", 3);
        let points = vec![
            point(&root, "old", 20, 10),
            point(&child, "old", 21, 11),
            point(&root, "partial", 22, 30),
        ];
        assert!(
            Source::select(
                &SourceArgument::parse("b/ROOT/be@partial").unwrap(),
                vec![root, child],
                &points
            )
            .is_err()
        );
    }
    #[test]
    fn same_name_snapshot_of_replaced_dataset_refuses() {
        let root = member("b/ROOT/be", 2);
        let mut p = point(&root, "saved", 20, 10);
        p.dataset_guid = Guid::new(99);
        assert!(
            Source::select(
                &SourceArgument::parse("b/ROOT/be@saved").unwrap(),
                vec![root],
                &[p]
            )
            .is_err()
        );
    }
    #[test]
    fn malformed_source_arguments_refuse() {
        for arg in ["", "-x", "b/ROOT/be@", "b/ROOT/be@one@two"] {
            assert!(SourceArgument::parse(arg).is_err(), "{arg}");
        }
    }
    #[test]
    fn refused_default_workspace_cannot_be_selected_as_restore_source() {
        let work = "b/zboot-restore-0123456789abcdef";
        let staged = format!("{work}/ROOT/be1");
        let rows = [
            ("b".to_owned(), "none"),
            (work.to_owned(), "none"),
            (format!("{work}/ROOT"), "none"),
            (staged.clone(), "/"),
        ]
        .iter()
        .enumerate()
        .map(|(index, (name, mount))| {
            let id = index + 1;
            format!("{name}\tfilesystem\t{id}\t0\t1000\t0\t{mount}\t-\t{}\t{}\tno\toff\ton\t-\toff\t-\t-\t-\t-\n", id + 10, id + 20)
        })
        .collect::<String>();
        let pool = format!("b\t100\t1000\t0\t1000\tONLINE\t{staged}\n");
        let inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    pool.clone()
                } else {
                    rows.clone()
                })
            },
        )
        .unwrap();
        let state = NativeState {
            inspection,
            dataset_properties: std::collections::BTreeMap::new(),
            pool_properties: std::collections::BTreeMap::new(),
        };

        assert!(
            crate::menu::inventory::candidates(&state)
                .iter()
                .any(|candidate| {
                    candidate.dataset == staged && candidate.default && candidate.refusal.is_some()
                })
        );
        let argument = SourceArgument::parse(&staged).unwrap();
        assert!(
            Source::observe(&state, &argument)
                .unwrap_err()
                .to_string()
                .contains("guided restore workspace cannot be a restore source")
        );
    }
    #[test]
    fn mapping_keeps_original_names_and_normalizes_nested_choices() {
        let map = Mapping::new(
            "b/ROOT/be",
            "a",
            &[
                "a/home/child".into(),
                "a/home".into(),
                "a/ROOT/be/var".into(),
            ],
        )
        .unwrap();
        assert_eq!(map.restored_be, "a/ROOT/be");
        assert_eq!(map.preserve, vec!["a/ROOT/be/var", "a/home"]);
    }
    #[test]
    fn unrelated_pool_and_pool_root_cannot_be_preserved() {
        for stash in ["a", "another/home", "a2/home"] {
            assert!(Mapping::new("b/ROOT/be", "a", &[stash.into()]).is_err());
        }
    }
    #[test]
    fn restore_requires_be_shape_and_single_pool_name() {
        for source in ["b", "b/home", "b/ROOT/be/child"] {
            assert!(Mapping::new(source, "a", &[]).is_err());
        }
        assert!(Mapping::new("b/ROOT/be", "a/other", &[]).is_err());
    }
}
