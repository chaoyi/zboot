//! Placement retained before a receive temporarily makes a tree inert.
//!
//! The engines record these values before mutation. Receive-time exclusions
//! are not a safety boundary: OpenZFS can ignore property-setting errors.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zfs_tools::engine::{Error, native::NativeProperty};

pub const PLACEMENT_KEYS: &[&str] = &["mountpoint", "readonly", "canmount", "volmode"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedProperty {
    pub value: String,
    pub source: String,
    pub received: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivePlacement {
    pub mountpoint: Option<SavedProperty>,
    pub readonly: SavedProperty,
    pub canmount: Option<SavedProperty>,
    pub volmode: SavedProperty,
}

impl ReceivePlacement {
    pub fn capture(
        volume: bool,
        properties: &BTreeMap<String, NativeProperty>,
        received: &BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        let get = |key: &str| {
            let property = properties
                .get(key)
                .ok_or_else(|| Error::Inconsistent(format!("receive placement lacks {key}")))?;
            if property.value.is_empty() || property.source.is_empty() {
                return Err(Error::Inconsistent(format!(
                    "receive placement has incomplete {key}"
                )));
            }
            Ok(SavedProperty {
                value: property.value.clone(),
                source: property.source.clone(),
                received: received.get(key).cloned(),
            })
        };
        Ok(Self {
            mountpoint: if volume {
                None
            } else {
                Some(get("mountpoint")?)
            },
            readonly: get("readonly")?,
            canmount: if volume { None } else { Some(get("canmount")?) },
            volmode: get("volmode")?,
        })
    }
}

/// New copies cannot reproduce an external ancestor or a received layer.
/// Materialize their intended root values, but retain live inheritance inside
/// the copied tree whenever the final parent produces that same value. A
/// default descendant follows the copied parent too, even when that parent
/// needed a local value to isolate it from its new external ancestry. Old
/// restore receipts can identify the same relation as recovered inheritance.
pub fn new_member_property(
    key: &str,
    saved: &SavedProperty,
    intended: &str,
    target: &str,
    parent: Option<(&str, &SavedProperty)>,
) -> SavedProperty {
    let local = SavedProperty {
        value: intended.into(),
        source: "local".into(),
        received: None,
    };
    if key == "canmount"
        || !(saved.source == "default"
            || saved.source.starts_with("inherited from ")
            || saved.source == "recovered inheritance")
    {
        return local;
    }
    let Some((parent_name, parent)) = parent else {
        return local;
    };
    let Some((actual_parent, leaf)) = target.rsplit_once('/') else {
        return local;
    };
    if actual_parent != parent_name {
        return local;
    }
    let inherited = if key == "mountpoint" && parent.value.starts_with('/') {
        format!("{}/{leaf}", parent.value.trim_end_matches('/'))
    } else {
        parent.value.clone()
    };
    if inherited != intended {
        return local;
    }
    let source = match parent.source.as_str() {
        "local" | "received" => format!("inherited from {parent_name}"),
        "default" => "default".into(),
        source if source.starts_with("inherited from ") => source.into(),
        _ => return local,
    };
    SavedProperty { source, ..local }
}

/// Undo libzfs's mountpoint display transform, including `zfs get -p`
/// and its received column: a pool imported with an altroot shows every
/// mountpoint under it. The persistent value omits it.
pub fn mountpoint_without_altroot(value: &str, altroot: Option<&str>) -> Result<String, Error> {
    let Some(root) = altroot.filter(|root| !matches!(*root, "" | "-" | "/")) else {
        return Ok(value.into());
    };
    if !root.starts_with('/') || root.chars().any(char::is_control) {
        return Err(Error::Inconsistent("invalid bound receive altroot".into()));
    }
    if !value.starts_with('/') {
        return Ok(value.into());
    }
    match value.strip_prefix(root) {
        Some("") => Ok("/".into()),
        Some(relative) if relative.starts_with('/') => Ok(relative.into()),
        _ => Err(Error::Inconsistent(
            "mountpoint does not have its bound pool altroot".into(),
        )),
    }
}

/// How zboot holds a dataset it is not exposing: the local values that
/// establish it, and the one check of it.
///
/// At rest a dormant copy is read-only and never mounts by itself; its
/// mountpoint stays, and only a volume needs `volmode=none`, so the live host
/// has no device for it. Staged data is inert: no mountpoint and no device,
/// for a filesystem too, since a volume created beneath it must have no device
/// from its first txg (`engine::stream::quiesce`). Publication drops a new
/// filesystem's `volmode` again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    AtRest,
    /// PARENT: what is received into or beneath it inherits these values, so
    /// they must be its own local ones; a member below needs only inherit
    /// them.
    Inert {
        parent: bool,
    },
}
impl Posture {
    /// The local values that establish the posture, in the order they are set.
    pub fn properties(self, volume: bool) -> &'static [(&'static str, &'static str)] {
        match (self, volume) {
            (Self::AtRest, false) => &[("readonly", "on"), ("canmount", "noauto")],
            (_, true) => &[("readonly", "on"), ("volmode", "none")],
            (Self::Inert { .. }, false) => &[
                ("readonly", "on"),
                ("volmode", "none"),
                ("mountpoint", "none"),
                ("canmount", "off"),
            ],
        }
    }
    /// Whether a dataset holds the posture: it is unmounted and has each
    /// value, a parent's set locally. PROPERTY gives a key's value and whether
    /// it is local. At rest `canmount=off` holds too. An inert `canmount` is
    /// free: with no mountpoint nothing mounts, and a received copy takes its
    /// final inactive `noauto` there.
    pub fn holds<'a>(
        self,
        volume: bool,
        mounted: bool,
        mut property: impl FnMut(&str) -> Option<(&'a str, bool)>,
    ) -> bool {
        let local = self == Self::Inert { parent: true };
        !mounted
            && self
                .properties(volume)
                .iter()
                .all(|(key, value)| match (self, *key) {
                    (Self::Inert { .. }, "canmount") => true,
                    (Self::AtRest, "canmount") => {
                        matches!(property(key), Some(("noauto" | "off", _)))
                    }
                    _ => property(key).is_some_and(|(v, own)| v == *value && (own || !local)),
                })
    }
}

/// The values an inert dataset is created with, for `zfs create -o`.
pub fn inert_properties(volume: bool) -> Vec<(String, String)> {
    Posture::Inert { parent: true }
        .properties(volume)
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_displayed_mountpoint_loses_exactly_its_altroot() {
        for root in [None, Some("-"), Some("/")] {
            for value in ["/", "/var", "none", "legacy"] {
                assert_eq!(mountpoint_without_altroot(value, root).unwrap(), value);
            }
        }
        for (shown, value) in [("/mnt/source", "/"), ("/mnt/source/var", "/var")] {
            assert_eq!(
                mountpoint_without_altroot(shown, Some("/mnt/source")).unwrap(),
                value
            );
        }
        assert!(mountpoint_without_altroot("/mnt/source-other/var", Some("/mnt/source")).is_err());
        assert_eq!(
            mountpoint_without_altroot("/mnt/source/mnt/source/var", Some("/mnt/source")).unwrap(),
            "/mnt/source/var"
        );
        assert_eq!(
            mountpoint_without_altroot("none", Some("/mnt/source")).unwrap(),
            "none"
        );
        assert_eq!(
            mountpoint_without_altroot("legacy", Some("/mnt/source")).unwrap(),
            "legacy"
        );
    }

    #[test]
    fn new_members_retain_only_compatible_internal_inheritance() {
        let saved = |value: &str, source: &str| SavedProperty {
            value: value.into(),
            source: source.into(),
            received: Some("hidden original layer".into()),
        };
        let root = new_member_property(
            "mountpoint",
            &saved("/home", "inherited from old"),
            "/home",
            "new/home",
            None,
        );
        assert_eq!(root.source, "local");
        assert_eq!(root.received, None);
        for source in [
            "default",
            "inherited from old",
            "inherited from old/home",
            "recovered inheritance",
        ] {
            let child = new_member_property(
                "mountpoint",
                &saved("/home/alice", source),
                "/home/alice",
                "new/home/alice",
                Some(("new/home", &root)),
            );
            assert_eq!(child.source, "inherited from new/home");
            let grandchild = new_member_property(
                "mountpoint",
                &saved("/home/alice/data", source),
                "/home/alice/data",
                "new/home/alice/data",
                Some(("new/home/alice", &child)),
            );
            assert_eq!(grandchild.source, "inherited from new/home");
            assert_eq!(grandchild.received, None);
        }
        for source in ["local", "received", "unknown"] {
            assert_eq!(
                new_member_property(
                    "mountpoint",
                    &saved("/home/alice", source),
                    "/home/alice",
                    "new/home/alice",
                    Some(("new/home", &root)),
                )
                .source,
                "local"
            );
        }
        let canonical = saved("/", "local");
        assert_eq!(
            new_member_property(
                "mountpoint",
                &saved("/old/var", "inherited from old/be"),
                "/old/var",
                "new/be/var",
                Some(("new/be", &canonical)),
            )
            .source,
            "local",
            "canonical boot placement must win over inheritance"
        );
        for key in ["readonly", "volmode"] {
            let root = saved("on", "local");
            assert_eq!(
                new_member_property(
                    key,
                    &saved("on", "default"),
                    "on",
                    "new/root/child",
                    Some(("new/root", &root)),
                )
                .source,
                "inherited from new/root"
            );
            assert_eq!(
                new_member_property(
                    key,
                    &saved("off", "default"),
                    "off",
                    "new/root/child",
                    Some(("new/root", &root)),
                )
                .source,
                "local"
            );
        }
        assert_eq!(
            new_member_property(
                "canmount",
                &saved("on", "default"),
                "on",
                "new/root/child",
                Some(("new/root", &saved("on", "local"))),
            )
            .source,
            "local"
        );
    }

    #[test]
    fn every_parent_must_supply_inert_mountpoint_and_device_policy() {
        let mut values = BTreeMap::from([
            ("readonly", ("on", true)),
            ("mountpoint", ("none", true)),
            ("volmode", ("none", true)),
            ("canmount", ("on", true)),
        ]);
        let member = Posture::Inert { parent: false };
        let parent = Posture::Inert { parent: true };
        let holds = |posture: Posture, volume, mounted, values: &BTreeMap<_, _>| {
            posture.holds(volume, mounted, |key| values.get(key).copied())
        };
        assert!(holds(member, false, false, &values));
        assert!(holds(parent, false, false, &values));
        values.insert("volmode", ("none", false));
        assert!(holds(member, false, false, &values));
        assert!(!holds(parent, false, false, &values), "inherited authority");
        values.insert("volmode", ("none", true));
        values.insert("mountpoint", ("/var", true));
        assert!(!holds(member, false, false, &values));
        assert!(holds(member, true, false, &values));
        values.insert("volmode", ("dev", true));
        assert!(!holds(member, true, false, &values));
        values.insert("volmode", ("none", true));
        assert!(!holds(member, true, true, &values));
        values.insert("readonly", ("off", true));
        assert!(!holds(member, true, false, &values));
    }

    #[test]
    fn at_rest_only_a_volume_needs_volmode_none() {
        let mut values = BTreeMap::from([
            ("readonly", ("on", true)),
            ("volmode", ("default", false)),
            ("canmount", ("noauto", true)),
        ]);
        let holds = |volume, mounted, values: &BTreeMap<_, _>| {
            Posture::AtRest.holds(volume, mounted, |key| values.get(key).copied())
        };
        assert!(holds(false, false, &values));
        assert!(!holds(false, true, &values));
        assert!(!holds(true, false, &values));
        values.insert("volmode", ("none", true));
        assert!(holds(true, false, &values));
        values.insert("canmount", ("off", true));
        assert!(holds(false, false, &values));
        values.insert("canmount", ("on", true));
        assert!(!holds(false, false, &values));
        assert!(holds(true, false, &values), "a volume has no canmount");
        assert_eq!(
            Posture::AtRest.properties(false),
            [("readonly", "on"), ("canmount", "noauto")]
        );
        assert!(
            inert_properties(false).contains(&("volmode".into(), "none".into())),
            "a staged filesystem is a parent"
        );
    }

    #[test]
    fn a_receipt_retains_local_inherited_and_received_evidence() {
        let properties = BTreeMap::from([
            (
                "mountpoint".into(),
                NativeProperty {
                    value: "/var".into(),
                    source: "local".into(),
                },
            ),
            (
                "readonly".into(),
                NativeProperty {
                    value: "off".into(),
                    source: "default".into(),
                },
            ),
            (
                "canmount".into(),
                NativeProperty {
                    value: "noauto".into(),
                    source: "local".into(),
                },
            ),
            (
                "volmode".into(),
                NativeProperty {
                    value: "dev".into(),
                    source: "inherited from tank".into(),
                },
            ),
        ]);
        let received = BTreeMap::from([("mountpoint".into(), "/old".into())]);
        let placement = ReceivePlacement::capture(false, &properties, &received).unwrap();
        assert_eq!(
            placement.mountpoint.as_ref().unwrap().received.as_deref(),
            Some("/old")
        );
        assert_eq!(placement.volmode.source, "inherited from tank");
        let encoded = serde_json::to_string(&placement).unwrap();
        assert_eq!(
            serde_json::from_str::<ReceivePlacement>(&encoded).unwrap(),
            placement
        );
        let volume = ReceivePlacement::capture(true, &properties, &received).unwrap();
        assert!(volume.mountpoint.is_none() && volume.canmount.is_none());
        assert!(ReceivePlacement::capture(false, &BTreeMap::new(), &received).is_err());
    }
}
