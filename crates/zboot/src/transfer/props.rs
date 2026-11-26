//! Which properties a copy takes from its source, and when.
//!
//! The stream carries none. zboot copies what `send -p` would have carried:
//! every property the source sets locally or received, except placement,
//! zboot's own records, encryption, and what the stream itself fixes. For
//! each key it computes one desired state on the copy, a local value or
//! inherit, and makes the copy match it (docs/DESIGN.md, "Copied properties"
//! under "How a transfer runs"). Restore's manifest classifies keys with the
//! same tables.
use super::{Member, fidelity_property, property_evidence};
use crate::placement::PLACEMENT_KEYS;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use zfs_tools::engine::{Error, management, native::NativeProperty, state::NativeState};

/// Space limits: they can refuse a receive, and they do not inherit.
pub(crate) const SPACE: &[&str] = &[
    "quota",
    "refquota",
    "reservation",
    "refreservation",
    "filesystem_limit",
    "snapshot_limit",
];
/// Properties that decide how received blocks are written. A new copy takes
/// them at creation, so they govern its first blocks; setting one after data
/// never changes blocks already written.
pub(crate) const WRITE_TIME: &[&str] = &[
    "copies",
    "checksum",
    "compression",
    "recordsize",
    "dnodesize",
    "dedup",
    "special_small_blocks",
    "redundant_metadata",
];
/// Fixed at creation or carried by the stream: verified, never set.
pub(crate) const STREAM: &[&str] = &[
    "casesensitivity",
    "normalization",
    "utf8only",
    "volblocksize",
    "volsize",
];

pub(super) fn space(key: &str) -> bool {
    SPACE.contains(&key)
}
pub(super) fn write_time(key: &str) -> bool {
    WRITE_TIME.contains(&key)
}

/// A property the copy takes from its source.
pub(super) fn copied(key: &str) -> bool {
    !PLACEMENT_KEYS.contains(&key)
        && !management::managed_key(key)
        && !STREAM.contains(&key)
        && !matches!(
            key,
            // Encryption: the receive and zboot's key handling own these.
            "encryption"
                | "keyformat"
                | "keylocation"
                | "pbkdf2iters"
                | "pbkdf2salt"
                | "encryptionroot"
                | "keystatus"
        )
}

/// The source set it: a local or received value, which the copy holds local.
fn explicit(property: &NativeProperty) -> bool {
    matches!(property.source.as_str(), "local" | "received")
}

/// The copied keys SOURCE sets: frozen by the plan, with their values'
/// digests in the member's property evidence.
pub(super) fn frozen_local(properties: &BTreeMap<String, NativeProperty>) -> BTreeSet<String> {
    properties
        .iter()
        .filter(|(key, property)| copied(key) && explicit(property))
        .map(|(key, _)| key.clone())
        .collect()
}

/// When a change is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum When {
    /// Before data: everything except a space limit that tightens.
    BeforeData,
    /// After data: everything, including tightened space limits.
    AfterData,
}

/// One change on the copy: `Some(value)` sets it local, `None` inherits.
pub(crate) type Change = (String, Option<String>);

/// A space value that sets no limit.
pub(crate) fn no_limit(value: &str) -> bool {
    matches!(value, "none" | "0" | "")
}
/// A value just set reads back as WANTED. `zfs get -p` prints a space key
/// that sets no limit as `0`, also right after `zfs set KEY=none`.
pub(super) fn reads_back(key: &str, wanted: &str, held: &str) -> bool {
    held == wanted || (space(key) && no_limit(wanted) && no_limit(held))
}
/// The limit a space value sets; one that does not parse sets none.
fn limit(value: &str) -> Option<u64> {
    if no_limit(value) {
        None
    } else {
        value.parse().ok()
    }
}

/// Changing a space key from CURRENT to DESIRED cannot refuse a receive that
/// the current value allows.
pub(super) fn loosens(key: &str, current: Option<&str>, desired: &str) -> bool {
    let current = current.and_then(limit);
    let desired = limit(desired);
    if matches!(key, "reservation" | "refreservation") {
        desired.unwrap_or(0) <= current.unwrap_or(0)
    } else {
        match (current, desired) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(current), Some(desired)) => desired >= current,
        }
    }
}

fn source_value<'a>(
    frozen: &Member,
    source: &'a BTreeMap<String, NativeProperty>,
    key: &str,
) -> Result<&'a NativeProperty, Error> {
    source
        .get(key)
        .filter(|p| frozen.properties.get(key) == Some(&property_evidence(key, &p.value)))
        .ok_or_else(|| {
            super::refuse(format!(
                "the source's {key} changed since this transfer was planned; run it again"
            ))
        })
}

/// The changes that give COPY the desired state of every copied key, from
/// the live SOURCE properties, checked against the FROZEN plan member.
/// Inheriting is decided here; a key whose inherited value then differs from
/// the source's is materialized by [`materialize`] after a fresh read.
pub(super) fn changes(
    frozen: &Member,
    source: &BTreeMap<String, NativeProperty>,
    copy: &BTreeMap<String, NativeProperty>,
    when: When,
) -> Result<Vec<Change>, Error> {
    let keys: BTreeSet<&String> = frozen
        .local
        .iter()
        .chain(copy.iter().filter(|(_, p)| explicit(p)).map(|(k, _)| k))
        .filter(|key| copied(key))
        .collect();
    let mut out = Vec::new();
    for key in keys {
        let current = copy.get(key);
        if frozen.local.contains(key) {
            let value = &source_value(frozen, source, key)?.value;
            if current.is_some_and(|p| p.source == "local" && p.value == *value) {
                continue;
            }
            if space(key)
                && when == When::BeforeData
                && !loosens(key, current.map(|p| p.value.as_str()), value)
            {
                continue;
            }
            out.push((key.clone(), Some(value.clone())));
        } else if space(key) {
            // Not set on the source: no limit. These keys do not inherit.
            if current.is_some_and(|p| limit(&p.value).is_some()) {
                out.push((key.clone(), Some("none".into())));
            }
        } else if current.is_some_and(explicit) {
            out.push((key.clone(), None));
        }
    }
    Ok(out)
}

/// Keys the source inherits or has by default whose effective value on COPY
/// differs: set local to the source's value.
pub(super) fn materialize(
    frozen: &Member,
    source: &BTreeMap<String, NativeProperty>,
    copy: &BTreeMap<String, NativeProperty>,
) -> Result<Vec<Change>, Error> {
    let mut out = Vec::new();
    for (key, expected) in &frozen.properties {
        if !fidelity_property(key) || !copied(key) || frozen.local.contains(key) {
            continue;
        }
        if copy
            .get(key)
            .is_some_and(|p| property_evidence(key, &p.value) == *expected)
        {
            continue;
        }
        let value = &source_value(frozen, source, key)?.value;
        out.push((key.clone(), Some(value.clone())));
    }
    Ok(out)
}

/// The copy holds the desired state: every key the source sets is local with
/// its value, and no other copied key is set on the copy. Space limits are
/// not checked here: one the copy cannot take is no failure, and
/// [`unheld_space`] reports it.
pub(super) fn verify(
    frozen: &Member,
    copy: &BTreeMap<String, NativeProperty>,
) -> Result<(), Error> {
    for key in frozen.local.iter().filter(|key| !space(key)) {
        let held = copy.get(key).is_some_and(|p| {
            p.source == "local"
                && frozen.properties.get(key) == Some(&property_evidence(key, &p.value))
        });
        if !held {
            return Err(super::refuse(format!(
                "the copy does not hold the source's {key}"
            )));
        }
    }
    for (key, property) in copy {
        if !copied(key) || space(key) || frozen.local.contains(key) || !explicit(property) {
            continue;
        }
        if !(fidelity_property(key)
            && property.source == "local"
            && frozen.properties.get(key) == Some(&property_evidence(key, &property.value)))
        {
            // A materialized key is local with the source's effective value.
            return Err(super::refuse(format!(
                "the copy sets {key}, which its source does not"
            )));
        }
    }
    Ok(())
}

/// The space keys COPY does not hold as WORKING sets them, by the desired
/// state a transfer gives a copy: the working copy's explicit (local or
/// received) limit, held as a local value, or no limit when the working copy
/// sets none. A value that sets no limit (`none`, `0`, or `-` where the key
/// does not apply) is no limit on either side, whatever its source. Each
/// entry is the key, the limit wanted and the limit held. `status`, the
/// `primary` plan and a finished transfer all report through this one rule.
pub(crate) fn unheld_space<'a>(
    working: &'a BTreeMap<String, NativeProperty>,
    copy: &'a BTreeMap<String, NativeProperty>,
) -> Vec<(&'static str, Option<&'a str>, Option<&'a NativeProperty>)> {
    SPACE
        .iter()
        .filter_map(|&key| {
            let wanted = working
                .get(key)
                .filter(|p| explicit(p) && limit(&p.value).is_some())
                .map(|p| p.value.as_str());
            let held = copy.get(key).filter(|p| limit(&p.value).is_some());
            let holds = match (wanted, held) {
                (None, None) => true,
                (Some(wanted), Some(held)) => held.source == "local" && held.value == wanted,
                _ => false,
            };
            (!holds).then_some((key, wanted, held))
        })
        .collect()
}

/// One space limit a pair's copy does not hold as its working copy sets it
/// ([`unheld_space`]). A sync applies the working copy's value when the copy
/// can take it. Values are as `zfs get -p` shows them; `None` is no limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpaceDifference {
    pub working_copy: String,
    pub copy: String,
    pub key: String,
    pub working_value: Option<String>,
    pub copy_value: Option<String>,
    /// Where the copy's limit comes from (`local`, `received`); absent when
    /// it holds none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copy_source: Option<String>,
}
impl SpaceDifference {
    /// `quota 100G on rpool/home, none on bpool/home`, names unescaped.
    pub(crate) fn describe(&self) -> String {
        let source = self
            .copy_source
            .as_deref()
            .filter(|source| *source != "local")
            .map(|source| format!(" ({source})"))
            .unwrap_or_default();
        format!(
            "{} {} on {}, {}{source} on {}",
            self.key,
            shown(&self.key, self.working_value.as_deref()),
            self.working_copy,
            shown(&self.key, self.copy_value.as_deref()),
            self.copy
        )
    }
    /// What the next sync does about it. Where the working copy sets no
    /// limit, that is the removal of the copy's: the last place it is kept.
    pub(crate) fn outcome(&self) -> String {
        if self.working_value.is_none() {
            format!("the next sync removes it from {}", self.copy)
        } else {
            format!("a sync applies it when {} can take it", self.copy)
        }
    }
}

/// The space limits COPY does not hold as WORKING sets them, from the
/// properties in STATE; `None` when either side's were not observed.
pub(crate) fn space_differences(
    state: &NativeState,
    working: &str,
    copy: &str,
) -> Option<Vec<SpaceDifference>> {
    let wanted = state.dataset_properties.get(working)?;
    let held = state.dataset_properties.get(copy)?;
    Some(
        unheld_space(wanted, held)
            .into_iter()
            .map(|(key, value, held)| SpaceDifference {
                working_copy: working.into(),
                copy: copy.into(),
                key: key.into(),
                working_value: value.map(str::to_owned),
                copy_value: held.map(|p| p.value.clone()),
                copy_source: held.map(|p| p.source.clone()),
            })
            .collect(),
    )
}

/// A space value for reading: a byte limit in the largest binary unit that
/// holds it exactly (`100G`), else in bytes (`1536001B`); a count as it is.
fn shown(key: &str, value: Option<&str>) -> String {
    let Some(value) = value else {
        return "none".into();
    };
    match value.parse::<u64>() {
        Ok(bytes) if !key.ends_with("_limit") => [("T", 40), ("G", 30), ("M", 20), ("K", 10)]
            .into_iter()
            .find(|(_, shift)| bytes >> shift > 0 && bytes % (1 << shift) == 0)
            .map_or_else(
                || format!("{bytes}B"),
                |(unit, shift)| format!("{}{unit}", bytes >> shift),
            ),
        _ => value.into(),
    }
}

/// Values a new copy takes at creation (`zfs receive -o`), so write-time
/// settings govern its first blocks: every key the source sets except space
/// limits, and every write-time key at the source's effective value.
pub(super) fn creation(
    frozen: &Member,
    source: &BTreeMap<String, NativeProperty>,
) -> Result<Vec<(String, String)>, Error> {
    let mut out = BTreeMap::new();
    for key in &frozen.local {
        if !space(key) {
            out.insert(
                key.clone(),
                source_value(frozen, source, key)?.value.clone(),
            );
        }
    }
    for key in frozen.properties.keys() {
        if write_time(key) && !out.contains_key(key) {
            out.insert(
                key.clone(),
                source_value(frozen, source, key)?.value.clone(),
            );
        }
    }
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prop(value: &str, source: &str) -> NativeProperty {
        NativeProperty {
            value: value.into(),
            source: source.into(),
        }
    }
    fn member(source: &BTreeMap<String, NativeProperty>) -> Member {
        let mut member = crate::transfer::tests::frozen_member();
        member.properties = super::super::bound_property_evidence(source);
        member.local = frozen_local(source);
        member
    }

    #[test]
    fn placement_records_encryption_and_stream_keys_are_never_copied() {
        for key in [
            "mountpoint",
            "canmount",
            "readonly",
            "volmode",
            "zboot:pair",
            "zboot:placement",
            "keylocation",
            "encryption",
            "volsize",
            "casesensitivity",
        ] {
            assert!(!copied(key), "{key}");
        }
        for key in [
            "compression",
            "copies",
            "checksum",
            "quota",
            "zsnap:policy",
            "org.example:x",
        ] {
            assert!(copied(key), "{key}");
        }
        assert!(space("refquota") && !space("copies"));
    }

    #[test]
    fn a_cleared_limit_reads_back_as_zero_and_nothing_else_is_loose() {
        for key in ["quota", "refquota", "reservation", "refreservation"] {
            assert!(reads_back(key, "none", "0"), "{key}");
            assert!(reads_back(key, "none", "none"), "{key}");
            assert!(!reads_back(key, "none", "1073741824"), "{key}");
            assert!(!reads_back(key, "1073741824", "0"), "{key}");
            assert!(reads_back(key, "1073741824", "1073741824"), "{key}");
        }
        assert!(reads_back("filesystem_limit", "none", "none"));
        // Only space keys have a second spelling of "no limit".
        assert!(!reads_back("compression", "none", "0"));
    }
    #[test]
    fn a_limit_loosens_upward_and_a_reservation_downward() {
        assert!(loosens("quota", Some("100"), "200"));
        assert!(loosens("quota", Some("100"), "none"));
        assert!(!loosens("quota", Some("100"), "50"));
        assert!(!loosens("quota", None, "50"));
        assert!(loosens("refreservation", Some("100"), "50"));
        assert!(loosens("refreservation", Some("100"), "none"));
        assert!(!loosens("reservation", None, "50"));
    }

    #[test]
    fn the_desired_state_sets_local_values_inherits_the_rest_and_never_inherits_limits() {
        let source = BTreeMap::from([
            ("compression".into(), prop("zstd", "local")),
            ("zsnap:policy".into(), prop("daily", "received")),
            ("quota".into(), prop("200", "local")),
            ("refquota".into(), prop("50", "local")),
            ("atime".into(), prop("off", "inherited from a")),
            ("mountpoint".into(), prop("/srv", "local")),
        ]);
        let copy = BTreeMap::from([
            ("compression".into(), prop("lz4", "received")),
            ("quota".into(), prop("100", "local")),
            ("refquota".into(), prop("100", "local")),
            ("reservation".into(), prop("10", "local")),
            ("atime".into(), prop("on", "local")),
            ("org.example:stale".into(), prop("x", "received")),
            ("mountpoint".into(), prop("none", "local")),
        ]);
        let frozen = member(&source);
        let before = changes(&frozen, &source, &copy, When::BeforeData).unwrap();
        assert_eq!(
            before,
            [
                ("atime".into(), None),
                ("compression".into(), Some("zstd".into())),
                ("org.example:stale".into(), None),
                ("quota".into(), Some("200".into())),
                ("reservation".into(), Some("none".into())),
                ("zsnap:policy".into(), Some("daily".into())),
            ]
        );
        let after = changes(&frozen, &source, &copy, When::AfterData).unwrap();
        assert!(after.contains(&("refquota".into(), Some("50".into()))));
        // The copy then inherits atime=on from its own parent: materialize.
        let copy = BTreeMap::from([("atime".into(), prop("on", "default"))]);
        assert_eq!(
            materialize(&frozen, &source, &copy).unwrap(),
            [("atime".into(), Some("off".into()))]
        );
    }

    #[test]
    fn a_source_value_changed_since_the_plan_refuses() {
        let source = BTreeMap::from([("compression".into(), prop("zstd", "local"))]);
        let frozen = member(&source);
        let changed = BTreeMap::from([("compression".into(), prop("lz4", "local"))]);
        let error = changes(&frozen, &changed, &BTreeMap::new(), When::BeforeData).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed since this transfer was planned")
        );
    }

    #[test]
    fn verification_leaves_limits_to_the_space_rule_and_refuses_any_other_difference() {
        let source = BTreeMap::from([
            ("compression".into(), prop("zstd", "local")),
            ("refquota".into(), prop("50", "local")),
        ]);
        let frozen = member(&source);
        let good = BTreeMap::from([
            ("compression".into(), prop("zstd", "local")),
            ("refquota".into(), prop("100", "local")),
            ("quota".into(), prop("7", "local")),
        ]);
        verify(&frozen, &good).unwrap();
        let keys: Vec<_> = unheld_space(&source, &good)
            .into_iter()
            .map(|(key, ..)| key)
            .collect();
        assert_eq!(keys, ["quota", "refquota"]);
        let received = BTreeMap::from([("compression".into(), prop("zstd", "received"))]);
        assert!(verify(&frozen, &received).is_err());
        let extra = BTreeMap::from([
            ("compression".into(), prop("zstd", "local")),
            ("org.example:x".into(), prop("1", "local")),
        ]);
        assert!(verify(&frozen, &extra).is_err());
    }

    /// The rule: the working copy's explicit limit, held locally, or no
    /// limit on both sides, whatever value or source says so.
    #[test]
    fn a_copy_holds_the_working_copys_explicit_limit_locally_or_no_limit() {
        let working = BTreeMap::from([
            ("quota".into(), prop("107374182400", "local")),
            ("refquota".into(), prop("50", "received")),
            ("reservation".into(), prop("0", "local")),
            ("refreservation".into(), prop("1536001", "default")),
            ("snapshot_limit".into(), prop("none", "default")),
            ("filesystem_limit".into(), prop("-", "-")),
        ]);
        let copy = BTreeMap::from([
            ("quota".into(), prop("0", "default")),
            ("refquota".into(), prop("50", "local")),
            ("reservation".into(), prop("none", "default")),
            ("refreservation".into(), prop("none", "default")),
            ("snapshot_limit".into(), prop("12", "received")),
            ("filesystem_limit".into(), prop("-", "-")),
        ]);
        let unheld = unheld_space(&working, &copy);
        let found: Vec<_> = unheld
            .iter()
            .map(|(key, wanted, held)| (*key, *wanted, held.map(|p| p.value.as_str())))
            .collect();
        // A refreservation the working copy only inherits or defaults to is
        // not its own: the copy should hold none, and does.
        assert_eq!(
            found,
            [
                ("quota", Some("107374182400"), None),
                ("snapshot_limit", None, Some("12")),
            ]
        );
        // The working copy's value held as a received one is not held.
        let received = BTreeMap::from([("quota".into(), prop("107374182400", "received"))]);
        assert_eq!(unheld_space(&working, &received)[0].0, "quota");
        assert_eq!(unheld_space(&working, &received)[1].0, "refquota");
    }

    #[test]
    fn a_difference_reads_in_exact_units_with_a_non_local_source_named() {
        let difference = |key: &str, working: Option<&str>, copy: Option<&str>, source| {
            SpaceDifference {
                working_copy: "a/home".into(),
                copy: "b/home".into(),
                key: key.into(),
                working_value: working.map(Into::into),
                copy_value: copy.map(Into::into),
                copy_source: copy.map(|_| String::from(source)),
            }
            .describe()
        };
        assert_eq!(
            difference("quota", Some("107374182400"), None, ""),
            "quota 100G on a/home, none on b/home"
        );
        assert_eq!(
            difference("refreservation", None, Some("1536001"), "local"),
            "refreservation none on a/home, 1536001B on b/home"
        );
        assert_eq!(
            difference("refquota", Some("1024"), Some("1024"), "received"),
            "refquota 1K on a/home, 1K (received) on b/home"
        );
        assert_eq!(
            difference("snapshot_limit", Some("1024"), None, ""),
            "snapshot_limit 1024 on a/home, none on b/home"
        );
    }

    #[test]
    fn a_new_copy_is_created_with_write_time_values_but_no_limits() {
        let source = BTreeMap::from([
            ("org.example:x".into(), prop("1", "local")),
            ("quota".into(), prop("200", "local")),
            ("copies".into(), prop("2", "inherited from a")),
            ("compression".into(), prop("on", "default")),
        ]);
        let frozen = member(&source);
        assert_eq!(
            creation(&frozen, &source).unwrap(),
            [
                ("compression".into(), "on".into()),
                ("copies".into(), "2".into()),
                ("org.example:x".into(), "1".into()),
            ]
        );
    }
}
