//! Identity-bound choices for whole-disk recovery. These values describe intent;
//! they never grant disk-loss consent or replace native transfer admission.
use crate::{history::contains_dataset, selection};
use serde::{Deserialize, Serialize};
use zfs_tools::engine::Error;

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
    use zfs_tools::engine::{InspectRequest, native, state::NativeState};
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
        // restore::plan refuses that candidate, and its name is no POOL/ROOT/BE.
        assert!(Mapping::new(&staged, "a", &[]).is_err());
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
