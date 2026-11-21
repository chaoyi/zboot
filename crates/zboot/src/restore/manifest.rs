//! The manifest: what restore records of every dataset it copies before A is
//! erased, and how a copy is made to match it. Streams carry no properties,
//! so a staged copy holds none of its source's; once A is erased this record,
//! in the receipt on B, is the only one (docs/DESIGN.md, "Guided restore"
//! and "Copied properties" under "How a transfer runs").
//!
//! The copied set is a pair transfer's (`transfer::bound_property_evidence`):
//! every effective-value property and every other copied key the source sets,
//! never placement, zboot's records or encryption, which restore handles
//! itself. Its write-time, stream-fixed and space keys are the transfer's
//! (`transfer::props`). For each key the copy gets one desired state: a local
//! value where the source set one, otherwise inherit, unless the copy's own
//! inheritance gives another value; then the source's value is set locally.
use super::{DatasetView, View, backend::within, refuse};
use crate::{
    menu::Result,
    transfer::props::{Change, SPACE, STREAM, WRITE_TIME, no_limit},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zfs_tools::engine::native::NativeProperty;

/// How the source had a copied property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Class {
    /// Set on the source, locally or received: local on the copy.
    Local,
    Inherited,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Copied {
    pub value: String,
    pub class: Class,
}

/// An encrypted dataset's key, as the source had it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Keys {
    /// Its encryption root, relative to the tree root (`""` is the root).
    pub root: String,
    /// The root's key format and location.
    pub keyformat: String,
    pub keylocation: String,
}

fn user(key: &str) -> bool {
    key.contains(':')
        && !zfs_tools::engine::management::managed_key(key)
        && !key.starts_with("org.zfs-tools:")
}

/// The copied properties of `member` with their class.
pub(super) fn capture(member: &DatasetView) -> BTreeMap<String, Copied> {
    let native: BTreeMap<String, NativeProperty> = member
        .properties
        .iter()
        .map(|(key, p)| {
            (
                key.clone(),
                NativeProperty {
                    value: p.value.clone(),
                    source: p.source.clone(),
                },
            )
        })
        .collect();
    crate::transfer::bound_property_evidence(&native)
        .into_keys()
        .filter(|key| {
            !zfs_tools::engine::management::managed_key(key) && !key.starts_with("org.zfs-tools:")
        })
        .filter_map(|key| {
            let property = member.property(&key)?;
            let class = match property.source.as_str() {
                "local" | "received" => Class::Local,
                source if source.starts_with("inherited from ") => Class::Inherited,
                "default" => Class::Default,
                _ if STREAM.contains(&key.as_str()) => Class::Default,
                _ => return None,
            };
            Some((
                key,
                Copied {
                    value: property.value.clone(),
                    class,
                },
            ))
        })
        .collect()
}

/// `member`'s key in its tree `root`; `None` for a plaintext dataset.
pub(super) fn keys(view: &View, root: &str, member: &DatasetView) -> Result<Option<Keys>> {
    if !member.encrypted {
        return Ok(None);
    }
    let encryption_root = member
        .encryption_root
        .as_deref()
        .filter(|r| within(root, r))
        .ok_or_else(|| {
            refuse(format!(
                "{} is encrypted under a root outside {root}",
                member.name
            ))
        })?;
    let dataset = view
        .dataset(encryption_root)
        .ok_or_else(|| refuse(format!("encryption root {encryption_root} disappeared")))?;
    Ok(Some(Keys {
        root: encryption_root[root.len()..]
            .trim_start_matches('/')
            .to_owned(),
        keyformat: dataset.value("keyformat").unwrap_or("-").to_owned(),
        keylocation: dataset.value("keylocation").unwrap_or("-").to_owned(),
    }))
}

/// `receive -o` values for a new copy: an inactive `canmount` for a
/// filesystem and every write-time key at the source's value.
pub(super) fn creation(
    volume: bool,
    properties: &BTreeMap<String, Copied>,
) -> Vec<(String, String)> {
    let mut values = Vec::new();
    if !volume {
        values.push(("canmount".into(), "off".into()));
    }
    for key in WRITE_TIME {
        if let Some(copied) = properties.get(*key) {
            values.push(((*key).into(), copied.value.clone()));
        }
    }
    values
}

/// A write-time key whose effective value on `copy` differs from the
/// source's: blocks already received there were written another way.
pub(super) fn write_time_differs(
    properties: &BTreeMap<String, Copied>,
    copy: &DatasetView,
) -> Option<&'static str> {
    WRITE_TIME.iter().copied().find(|key| {
        properties
            .get(*key)
            .is_some_and(|copied| copy.value(key) != Some(copied.value.as_str()))
    })
}

/// The changes that give `copy` the desired state of every copied key. A key
/// inherited from here may still give another value; [`materialize`] then
/// sets it after a fresh read.
pub(super) fn changes(properties: &BTreeMap<String, Copied>, copy: &DatasetView) -> Vec<Change> {
    let mut out = Vec::new();
    for (key, copied) in properties {
        if STREAM.contains(&key.as_str()) {
            continue;
        }
        let current = copy.property(key);
        if copied.class == Class::Local {
            if !current.is_some_and(|p| p.local() && p.value == copied.value) {
                out.push((key.clone(), Some(copied.value.clone())));
            }
        } else if SPACE.contains(&key.as_str()) {
            // No limit on the source; these keys do not inherit.
            if current.is_some_and(|p| !no_limit(&p.value)) {
                out.push((key.clone(), Some(copied.value.clone())));
            }
        } else if current.is_some_and(|p| p.local() || p.received()) {
            out.push((key.clone(), None));
        }
    }
    for (key, property) in &copy.properties {
        if user(key) && !properties.contains_key(key) && (property.local() || property.received()) {
            out.push((key.clone(), None));
        }
    }
    out
}

/// Keys the source inherited or had by default whose effective value on
/// `copy` differs: set local to the source's value.
pub(super) fn materialize(
    properties: &BTreeMap<String, Copied>,
    copy: &DatasetView,
) -> Vec<Change> {
    properties
        .iter()
        .filter(|(key, copied)| {
            copied.class != Class::Local
                && !STREAM.contains(&key.as_str())
                && !SPACE.contains(&key.as_str())
                && copy.value(key) != Some(copied.value.as_str())
        })
        .map(|(key, copied)| (key.clone(), Some(copied.value.clone())))
        .collect()
}

/// `copy` holds the source's stream-carried and write-time values.
pub(super) fn verify_data(properties: &BTreeMap<String, Copied>, copy: &DatasetView) -> Result<()> {
    for key in STREAM.iter().chain(WRITE_TIME) {
        if let Some(copied) = properties.get(*key)
            && copy.value(key) != Some(copied.value.as_str())
        {
            return Err(refuse(format!(
                "{}'s {key} is not its source's {}",
                copy.name, copied.value
            )));
        }
    }
    Ok(())
}

/// `copy` holds the desired state of every copied key, and no user property
/// its source did not have. Space limits it could not take are returned for
/// attention instead.
pub(super) fn verify(
    properties: &BTreeMap<String, Copied>,
    copy: &DatasetView,
) -> Result<Vec<String>> {
    verify_data(properties, copy)?;
    let mut attention = Vec::new();
    for (key, copied) in properties {
        if STREAM.contains(&key.as_str()) {
            continue;
        }
        let current = copy.property(key);
        let held = current.is_some_and(|p| {
            p.value == copied.value && (copied.class != Class::Local || p.local())
        }) || (SPACE.contains(&key.as_str())
            && copied.class != Class::Local
            && current.is_none_or(|p| no_limit(&p.value)));
        if held {
            continue;
        }
        if SPACE.contains(&key.as_str()) {
            attention.push(key.clone());
        } else {
            return Err(refuse(format!(
                "{} does not hold its source's {key}={}",
                copy.name, copied.value
            )));
        }
    }
    if let Some((key, _)) = copy
        .properties
        .iter()
        .find(|(key, p)| user(key) && !properties.contains_key(*key) && (p.local() || p.received()))
    {
        return Err(refuse(format!(
            "{} sets {key}, which its source does not",
            copy.name
        )));
    }
    Ok(attention)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restore::Property;

    fn dataset(properties: &[(&str, &str, &str)]) -> DatasetView {
        DatasetView {
            name: "p/copy".into(),
            identity: zfs_tools::engine::DatasetIdentity {
                pool_guid: zfs_tools::engine::Guid::new(1),
                guid: zfs_tools::engine::Guid::new(2),
                createtxg: zfs_tools::engine::Txg::new(3),
                objsetid: zfs_tools::engine::ObjsetId::new(4),
            },
            volume: false,
            used: 0,
            available: 0,
            mounted: false,
            origin: None,
            encrypted: false,
            encryption_root: None,
            resume_token: false,
            properties: properties
                .iter()
                .map(|(key, value, source)| {
                    (
                        (*key).into(),
                        Property {
                            value: (*value).into(),
                            source: (*source).into(),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn the_manifest_keeps_copied_keys_with_their_class_and_never_placement_records_or_keys() {
        let source = dataset(&[
            ("compression", "zstd", "local"),
            ("atime", "off", "inherited from p"),
            ("checksum", "on", "default"),
            ("quota", "100", "local"),
            ("refquota", "0", "default"),
            ("org.example:x", "1", "received"),
            ("mountpoint", "/srv", "local"),
            ("canmount", "noauto", "local"),
            ("keylocation", "prompt", "local"),
            ("zboot:pair", "{}", "local"),
            ("org.zfs-tools:receive-inert-init", "1:2", "local"),
            ("written", "0", "-"),
        ]);
        let captured = capture(&source);
        let classes: Vec<_> = captured
            .iter()
            .map(|(key, copied)| (key.as_str(), copied.class))
            .collect();
        assert_eq!(
            classes,
            [
                ("atime", Class::Inherited),
                ("checksum", Class::Default),
                ("compression", Class::Local),
                ("org.example:x", Class::Local),
                ("quota", Class::Local),
            ]
        );
        assert_eq!(
            creation(false, &captured),
            [
                ("canmount".to_string(), "off".to_string()),
                ("checksum".into(), "on".into()),
                ("compression".into(), "zstd".into()),
            ]
        );
    }

    #[test]
    fn a_copy_takes_local_values_inherits_the_rest_and_materializes_a_different_inheritance() {
        let source = dataset(&[
            ("compression", "zstd", "local"),
            ("atime", "off", "inherited from p"),
            ("checksum", "on", "default"),
            ("quota", "100", "local"),
            ("org.example:x", "1", "received"),
        ]);
        let manifest = capture(&source);
        // A new copy: write-time keys local from creation, nothing else.
        let copy = dataset(&[
            ("compression", "zstd", "local"),
            ("checksum", "on", "local"),
            ("atime", "on", "default"),
            ("org.example:stray", "y", "local"),
        ]);
        assert_eq!(
            changes(&manifest, &copy),
            [
                ("checksum".to_string(), None),
                ("org.example:x".into(), Some("1".into())),
                ("quota".into(), Some("100".into())),
                ("org.example:stray".into(), None),
            ]
        );
        assert_eq!(
            materialize(&manifest, &copy),
            [("atime".to_string(), Some("off".to_string()))]
        );
        assert!(verify(&manifest, &copy).is_err());
        let done = dataset(&[
            ("compression", "zstd", "local"),
            ("checksum", "on", "default"),
            ("atime", "off", "local"),
            ("org.example:x", "1", "local"),
            ("quota", "50", "local"),
        ]);
        assert_eq!(verify(&manifest, &done).unwrap(), ["quota"]);
        let received = dataset(&[
            ("compression", "zstd", "received"),
            ("checksum", "on", "default"),
            ("atime", "off", "local"),
            ("org.example:x", "1", "local"),
            ("quota", "100", "local"),
        ]);
        assert!(verify(&manifest, &received).is_err());
    }

    #[test]
    fn a_write_time_value_that_differs_is_found_before_more_data() {
        let manifest = capture(&dataset(&[("copies", "2", "local")]));
        assert_eq!(
            write_time_differs(&manifest, &dataset(&[("copies", "1", "default")])),
            Some("copies")
        );
        assert_eq!(
            write_time_differs(&manifest, &dataset(&[("copies", "2", "local")])),
            None
        );
    }
}
