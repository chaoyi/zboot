//! Parsers for `zfs(8)` / `zpool(8)` text output.
//!
//! All parsers expect tab-separated, machine-friendly output produced by `-Hp`
//! flags. The parsers are total over their input grammar; ambiguity returns
//! [`ParseError`].

use crate::types::{
    BoundList, Canmount, Mountpoint, Pool, PoolRole, Property, Snapshot, SnapshotRef,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("malformed line: {0:?}")]
    Line(String),
    #[error("malformed bound-to entry: {0:?}")]
    BoundList(String),
    #[error("malformed snapshot ref (expected `dataset@name`): {0:?}")]
    SnapshotRef(String),
    #[error("invalid value for {prop}: {value:?}")]
    Value { prop: &'static str, value: String },
}

/// Parse output of `zfs get -Hp -o name,property,value <prop>...`.
///
/// Each non-empty line is `name<TAB>property<TAB>value`. Trailing whitespace
/// is permitted; blank lines are skipped. Returns one tuple per non-blank line.
pub fn parse_zfs_get(text: &str) -> Result<Vec<(String, Property)>, ParseError> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 3 {
            return Err(ParseError::Line(line.to_owned()));
        }
        let name = parts[0];
        let prop_name = parts[1];
        let value = parts[2].trim_end_matches('\r');
        let prop = parse_property(prop_name, value)?;
        out.push((name.to_owned(), prop));
    }
    Ok(out)
}

/// Parse a single property name + value into a typed [`Property`].
///
/// Unknown property names produce [`Property::Other`] (escape hatch); they're
/// not errors. Known property names with malformed values return [`ParseError`].
pub fn parse_property(name: &str, value: &str) -> Result<Property, ParseError> {
    Ok(match name {
        "bootfs" => Property::Bootfs(parse_optional_string(value)),
        "mountpoint" => Property::Mountpoint(parse_mountpoint(value)),
        // `-` means "not applicable" (e.g. snapshots have no canmount); fall
        // through to Property::Other so consumers can skip those rows.
        "canmount" if value == "-" => Property::Other {
            name: name.to_owned(),
            value: value.to_owned(),
        },
        "canmount" => Property::Canmount(parse_canmount(value)?),
        "origin" => Property::Origin(parse_optional_snapshot_ref(value)?),
        "cachefile" => Property::Cachefile(parse_optional_string(value)),
        "zboot:role" => Property::ZbootRole(parse_pool_role(value)?),
        "zboot:be" => Property::ZbootBe(parse_bool(value)?),
        // `-` means inherited/unset — distinct from "explicitly set to empty
        // list". Without this, every BE root (which never has `attached-to`)
        // would look like a dataset "bound to nothing" and `default` would
        // try to set `canmount=off` on the active BE root, failing with
        // "cannot unmount '/'".
        "zboot:attached-to" if value == "-" => Property::Other {
            name: name.to_owned(),
            value: value.to_owned(),
        },
        "zboot:attached-to" => Property::ZbootAttachedTo(BoundList::parse(value)?),
        "zboot:set" => Property::ZbootSet(value.to_owned()),
        "zboot:created-by" => Property::ZbootCreatedBy(value.to_owned()),
        _ => Property::Other {
            name: name.to_owned(),
            value: value.to_owned(),
        },
    })
}

fn parse_optional_string(s: &str) -> Option<String> {
    match s {
        "-" | "" | "none" => None,
        other => Some(other.to_owned()),
    }
}

fn parse_optional_snapshot_ref(s: &str) -> Result<Option<SnapshotRef>, ParseError> {
    match s {
        "-" | "" => Ok(None),
        other => SnapshotRef::parse(other)
            .map(Some)
            .ok_or_else(|| ParseError::SnapshotRef(other.to_owned())),
    }
}

fn parse_mountpoint(s: &str) -> Mountpoint {
    match s {
        "none" => Mountpoint::None,
        "legacy" => Mountpoint::Legacy,
        other => Mountpoint::Path(other.to_owned()),
    }
}

fn parse_canmount(s: &str) -> Result<Canmount, ParseError> {
    Ok(match s {
        "on" => Canmount::On,
        "off" => Canmount::Off,
        "noauto" => Canmount::Noauto,
        other => {
            return Err(ParseError::Value {
                prop: "canmount",
                value: other.to_owned(),
            });
        }
    })
}

fn parse_pool_role(s: &str) -> Result<PoolRole, ParseError> {
    Ok(match s {
        "root" => PoolRole::Root,
        other => {
            return Err(ParseError::Value {
                prop: "zboot:role",
                value: other.to_owned(),
            });
        }
    })
}

fn parse_bool(s: &str) -> Result<bool, ParseError> {
    Ok(match s {
        "true" | "on" | "yes" => true,
        "false" | "off" | "no" | "-" | "" => false,
        other => {
            return Err(ParseError::Value {
                prop: "zboot:be",
                value: other.to_owned(),
            });
        }
    })
}

/// Parse output of `zpool list -Hp -o name,bootfs,guid`.
///
/// `bootfs` of `-` becomes `None`. `guid` is parsed as `u64`; non-numeric is
/// `None` (some `zpool list` builds emit `-` for guid in unusual states).
pub fn parse_zpool_list(text: &str) -> Result<Vec<Pool>, ParseError> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        let name = parts
            .first()
            .ok_or_else(|| ParseError::Line(line.to_owned()))?;
        if name.is_empty() {
            return Err(ParseError::Line(line.to_owned()));
        }
        let bootfs = parts.get(1).and_then(|s| parse_optional_string(s));
        let guid = parts.get(2).and_then(|s| s.parse::<u64>().ok());
        out.push(Pool {
            name: (*name).to_owned(),
            role: None,
            bootfs,
            guid,
        });
    }
    Ok(out)
}

/// Parse output of `zfs list -Hp -t snapshot -o name`.
///
/// `set` and `created_by` are left `None`; those come from a separate
/// `zfs get -Hp -o name,property,value zboot:set,zboot:created-by` query
/// that the caller can join via [`parse_zfs_get`].
pub fn parse_zfs_list_snapshots(text: &str) -> Result<Vec<Snapshot>, ParseError> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let full = line.trim();
        let r = SnapshotRef::parse(full).ok_or_else(|| ParseError::SnapshotRef(full.to_owned()))?;
        let mut snap = Snapshot::new(r.dataset, r.name);
        snap.set = None;
        snap.created_by = None;
        out.push(snap);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BoundKey, Canmount, Mountpoint, PoolRole, SnapshotRef};

    // --- parse_property -----------------------------------------------------

    #[test]
    fn property_bootfs_set() {
        let p = parse_property("bootfs", "rpool/ROOT/be1").unwrap();
        assert_eq!(p, Property::Bootfs(Some("rpool/ROOT/be1".into())));
    }

    #[test]
    fn property_bootfs_dash_is_none() {
        assert_eq!(
            parse_property("bootfs", "-").unwrap(),
            Property::Bootfs(None)
        );
    }

    #[test]
    fn property_mountpoint_path() {
        assert_eq!(
            parse_property("mountpoint", "/").unwrap(),
            Property::Mountpoint(Mountpoint::Path("/".into()))
        );
    }

    #[test]
    fn property_mountpoint_none() {
        assert_eq!(
            parse_property("mountpoint", "none").unwrap(),
            Property::Mountpoint(Mountpoint::None)
        );
    }

    #[test]
    fn property_mountpoint_legacy() {
        assert_eq!(
            parse_property("mountpoint", "legacy").unwrap(),
            Property::Mountpoint(Mountpoint::Legacy)
        );
    }

    #[test]
    fn property_canmount_noauto() {
        assert_eq!(
            parse_property("canmount", "noauto").unwrap(),
            Property::Canmount(Canmount::Noauto)
        );
    }

    #[test]
    fn property_canmount_garbage_errors() {
        assert!(matches!(
            parse_property("canmount", "wat"),
            Err(ParseError::Value {
                prop: "canmount",
                ..
            })
        ));
    }

    #[test]
    fn property_origin_set() {
        let p = parse_property("origin", "rpool/ROOT/be1@snap1").unwrap();
        assert_eq!(
            p,
            Property::Origin(Some(SnapshotRef {
                dataset: "rpool/ROOT/be1".into(),
                name: "snap1".into(),
            }))
        );
    }

    #[test]
    fn property_origin_none() {
        assert_eq!(
            parse_property("origin", "-").unwrap(),
            Property::Origin(None)
        );
    }

    #[test]
    fn property_origin_malformed() {
        assert!(matches!(
            parse_property("origin", "no_at_sign"),
            Err(ParseError::SnapshotRef(_))
        ));
    }

    #[test]
    fn property_zboot_role_root() {
        assert_eq!(
            parse_property("zboot:role", "root").unwrap(),
            Property::ZbootRole(PoolRole::Root)
        );
    }

    #[test]
    fn property_zboot_role_invalid() {
        assert!(matches!(
            parse_property("zboot:role", "primary"),
            Err(ParseError::Value {
                prop: "zboot:role",
                ..
            })
        ));
    }

    #[test]
    fn property_zboot_be_true() {
        assert_eq!(
            parse_property("zboot:be", "true").unwrap(),
            Property::ZbootBe(true)
        );
    }

    #[test]
    fn property_zboot_be_dash_is_false() {
        assert_eq!(
            parse_property("zboot:be", "-").unwrap(),
            Property::ZbootBe(false)
        );
    }

    #[test]
    fn property_zboot_bound_to() {
        let p = parse_property("zboot:attached-to", "rpool:be1,rpool:be2").unwrap();
        match p {
            Property::ZbootAttachedTo(bl) => {
                assert_eq!(
                    bl.0,
                    vec![BoundKey::new("rpool", "be1"), BoundKey::new("rpool", "be2")]
                );
            }
            other => panic!("expected ZbootAttachedTo, got {other:?}"),
        }
    }

    #[test]
    fn property_unknown_falls_to_other() {
        assert_eq!(
            parse_property("custom:thing", "hello").unwrap(),
            Property::Other {
                name: "custom:thing".into(),
                value: "hello".into(),
            }
        );
    }

    #[test]
    fn property_name_round_trip() {
        let cases = [
            ("bootfs", parse_property("bootfs", "-").unwrap()),
            ("mountpoint", parse_property("mountpoint", "none").unwrap()),
            ("zboot:role", parse_property("zboot:role", "root").unwrap()),
            ("zboot:be", parse_property("zboot:be", "true").unwrap()),
        ];
        for (expected_name, prop) in cases {
            assert_eq!(prop.name(), expected_name);
        }
    }

    // --- parse_zfs_get ------------------------------------------------------

    #[test]
    fn parse_zfs_get_basic() {
        let text = "rpool\tbootfs\trpool/ROOT/be1\nrpool\tzboot:role\troot\n";
        let parsed = parse_zfs_get(text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "rpool");
        assert!(matches!(parsed[0].1, Property::Bootfs(Some(ref s)) if s == "rpool/ROOT/be1"));
        assert!(matches!(parsed[1].1, Property::ZbootRole(PoolRole::Root)));
    }

    #[test]
    fn parse_zfs_get_skips_blank_lines() {
        let text = "\nrpool\tbootfs\t-\n\n\nrpool\tcanmount\toff\n";
        let parsed = parse_zfs_get(text).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_zfs_get_malformed_line() {
        assert!(matches!(
            parse_zfs_get("rpool\tbootfs\n"),
            Err(ParseError::Line(_))
        ));
    }

    #[test]
    fn parse_zfs_get_value_with_tab_safe() {
        // splitn(3) keeps the value column even if it itself contains tabs.
        // Properties don't typically have tab-bearing values, but be safe.
        let text = "rpool\tcustom:weird\tvalue\twith\ttabs\n";
        let parsed = parse_zfs_get(text).unwrap();
        assert_eq!(parsed.len(), 1);
        match &parsed[0].1 {
            Property::Other { value, .. } => assert_eq!(value, "value\twith\ttabs"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    // --- parse_zpool_list ---------------------------------------------------

    #[test]
    fn parse_zpool_list_basic() {
        let text = "rpool\trpool/ROOT/be1\t12345678\nrpool2\t-\t87654321\n";
        let pools = parse_zpool_list(text).unwrap();
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].name, "rpool");
        assert_eq!(pools[0].bootfs, Some("rpool/ROOT/be1".into()));
        assert_eq!(pools[0].guid, Some(12_345_678));
        assert_eq!(pools[1].bootfs, None);
    }

    #[test]
    fn parse_zpool_list_name_only() {
        let pools = parse_zpool_list("dpool\n").unwrap();
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].name, "dpool");
        assert_eq!(pools[0].bootfs, None);
        assert_eq!(pools[0].guid, None);
    }

    // --- parse_zfs_list_snapshots ------------------------------------------

    #[test]
    fn parse_zfs_list_snapshots_basic() {
        let text = "rpool/ROOT/be1@snap1\nrpool/ROOT/be1@snap2\nrpool/home@snap1\n";
        let snaps = parse_zfs_list_snapshots(text).unwrap();
        assert_eq!(snaps.len(), 3);
        assert_eq!(snaps[0].dataset, "rpool/ROOT/be1");
        assert_eq!(snaps[0].name, "snap1");
    }

    #[test]
    fn parse_zfs_list_snapshots_malformed() {
        assert!(matches!(
            parse_zfs_list_snapshots("not_a_snapshot\n"),
            Err(ParseError::SnapshotRef(_))
        ));
    }
}
