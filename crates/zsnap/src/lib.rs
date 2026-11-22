//! Restic-style snapshot retention.
//!
//! One timestamped stream per dataset (`<ds>@zsnap_<UTC-stamp>`). A policy is a
//! take `frequency` (snapshot on change, at most this often) + a `keep` policy
//! (restic `forget`: a union of `within` / `last` / `hourly..yearly N`). The GFS
//! pyramid is derived at prune time by bucketing the stream. Semantics follow
//! restic's `ApplyPolicy`: `within` is relative to the latest snapshot, rules
//! are ORed, and each period keeps the newest snapshot per bucket (plus the
//! oldest while a count remains). One safety extension preserves the checkpoint
//! before a long gap until a complete new `within` window exists.
//!
//! Retention planning performs no filesystem, clock, lock, or ZFS operations. The
//! caller supplies observations and time. Configuration parsing and assignment
//! interpretation also perform no effects. The `properties` and `transport`
//! modules observe and change native policy assignments through private engine safety
//! checks; their callers own writer coordination. A retention decision alone is
//! not authorization to delete a snapshot.
#![cfg_attr(test, allow(clippy::disallowed_methods, reason = "test fixtures"))]

mod config;
pub(crate) mod properties;
mod selection;
pub(crate) mod transport;
pub use config::{Assignment, Config, DEFAULT_POLICIES, POLICY_PROPERTY};
pub use selection::{SnapshotNameCollision, capture_names, dataset_plan};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Timelike, Utc};
use std::collections::BTreeMap;

const STAMP: &str = "%Y-%m-%d-%H%M%S";

// ── durations ─────────────────────────────────────────────────────────────────
pub fn parse_duration(s: &str) -> Result<i64> {
    let s = s.trim();
    let split = s.char_indices().next_back().map_or(0, |(i, _)| i);
    let (num, unit) = s.split_at(split);
    let n: i64 = num
        .parse()
        .with_context(|| format!("bad duration {s:?} — use e.g. 30s, 5m, 1h, 7d"))?;
    if n <= 0 {
        bail!("duration must be positive: {s:?}");
    }
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => bail!("bad duration unit in {s:?}"),
    };
    let seconds = n
        .checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("duration is too large: {s:?}"))?;
    if Duration::try_seconds(seconds).is_none() {
        bail!("duration is too large: {s:?}");
    }
    Ok(seconds)
}

pub fn canon_duration(secs: i64) -> String {
    for (unit, size) in [("w", 604800), ("d", 86400), ("h", 3600), ("m", 60)] {
        if secs % size == 0 {
            return format!("{}{}", secs / size, unit);
        }
    }
    format!("{secs}s")
}

// ── snapshot naming (the safety boundary) ─────────────────────────────────────
pub(crate) fn snap_suffix(now: DateTime<Utc>) -> String {
    format!("zsnap_{}", now.format(STAMP))
}

pub fn snap_name(dataset: &str, now: DateTime<Utc>) -> String {
    format!("{dataset}@{}", snap_suffix(now))
}

pub fn snap_time(name: &str) -> Option<DateTime<Utc>> {
    let (dataset, stamp) = name.split_once("@zsnap_")?;
    zfs_tools::engine::validate_dataset_name(dataset).ok()?;
    let time = NaiveDateTime::parse_from_str(stamp, STAMP).ok()?.and_utc();
    (time.format(STAMP).to_string() == stamp).then_some(time)
}

pub(crate) fn owned_snap_time(name: &str, dataset: &str) -> Option<DateTime<Utc>> {
    (name.split_once('@').map(|(ds, _)| ds) == Some(dataset))
        .then(|| snap_time(name))
        .flatten()
}

pub(crate) fn is_disabled_policy(value: &str) -> bool {
    matches!(value.trim(), "" | "-" | "none")
}

#[cfg(test)]
fn is_zsnap(name: &str) -> bool {
    snap_time(name).is_some()
}

// ── policy ────────────────────────────────────────────────────────────────────
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keep {
    pub last: Option<i64>,
    pub within: Option<i64>, // seconds
    pub hourly: Option<i64>,
    pub daily: Option<i64>,
    pub weekly: Option<i64>,
    pub monthly: Option<i64>,
    pub yearly: Option<i64>,
}

impl Keep {
    pub fn is_empty(&self) -> bool {
        self.within.is_none()
            && self
                .counted_rules()
                .iter()
                .all(|(_, count)| count.is_none())
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(n) = self.last {
            parts.push(format!("last={n}"));
        }
        if let Some(w) = self.within {
            parts.push(format!("within={}", canon_duration(w)));
        }
        for (rule, v) in self
            .counted_rules()
            .into_iter()
            .filter(|(rule, _)| !matches!(rule, CountRule::Last))
        {
            if let Some(n) = v {
                parts.push(format!("{}={n}", rule.label()));
            }
        }
        if parts.is_empty() {
            "(nothing)".into()
        } else {
            parts.join(" ")
        }
    }

    // This order is also the public order of counted keep reasons.
    fn counted_rules(&self) -> [(CountRule, Option<i64>); 6] {
        [
            (CountRule::Last, self.last),
            (CountRule::Hourly, self.hourly),
            (CountRule::Daily, self.daily),
            (CountRule::Weekly, self.weekly),
            (CountRule::Monthly, self.monthly),
            (CountRule::Yearly, self.yearly),
        ]
    }

    fn validate_policy(&self, policy: &str) -> Result<()> {
        self.validate_within()?;
        if self.is_empty() {
            bail!("policy {policy:?} must define at least one keep rule");
        }
        for (rule, value) in self.counted_rules() {
            if value.is_some_and(|n| n <= 0) {
                let rule = rule.label();
                bail!("policy {policy:?} keep.{rule} must be positive");
            }
        }
        Ok(())
    }

    /// One-off prune overrides are deliberately more permissive than policies:
    /// `--last 0` is the explicit, confirmed way to remove the owned stream.
    pub fn validate_prune_override(&self) -> Result<()> {
        self.validate_within()?;
        if self.is_empty() {
            bail!("prune requires a keep rule (use last=0 explicitly to keep nothing)");
        }
        if self.last.is_some_and(|n| n < 0) {
            bail!("--last must be non-negative");
        }
        for (rule, value) in self
            .counted_rules()
            .into_iter()
            .filter(|(rule, _)| !matches!(rule, CountRule::Last))
        {
            if value.is_some_and(|n| n <= 0) {
                let rule = rule.label();
                bail!("--{rule} must be positive (only --last 0 means keep nothing)");
            }
        }
        Ok(())
    }

    fn validate_within(&self) -> Result<()> {
        if self
            .within
            .is_some_and(|n| n <= 0 || Duration::try_seconds(n).is_none())
        {
            bail!("within must be a positive, representable duration");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub frequency: i64, // seconds
    pub keep: Keep,
}

mod raw {
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Deserialize, Default)]
    #[serde(deny_unknown_fields)]
    pub struct Keep {
        pub last: Option<i64>,
        pub within: Option<String>,
        pub hourly: Option<i64>,
        pub daily: Option<i64>,
        pub weekly: Option<i64>,
        pub monthly: Option<i64>,
        pub yearly: Option<i64>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Policy {
        pub frequency: String,
        #[serde(default)]
        pub keep: Keep,
    }
    #[derive(Deserialize, Default)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        #[serde(default)]
        pub policy: BTreeMap<String, Policy>,
    }
}

/// Parse and validate policy definitions without reading files or merging defaults.
pub fn parse_policies(text: &str) -> Result<BTreeMap<String, Policy>> {
    let raw: raw::Config = toml::from_str(text).context("parse config")?;
    let mut out = BTreeMap::new();
    for (name, p) in raw.policy {
        if name.trim() != name || is_disabled_policy(&name) || name.chars().any(char::is_control) {
            bail!(
                "policy name must be nonempty, unpadded, contain no controls and not a disabled value"
            );
        }
        let keep = Keep {
            last: p.keep.last,
            within: p.keep.within.as_deref().map(parse_duration).transpose()?,
            hourly: p.keep.hourly,
            daily: p.keep.daily,
            weekly: p.keep.weekly,
            monthly: p.keep.monthly,
            yearly: p.keep.yearly,
        };
        keep.validate_policy(&name)?;
        out.insert(
            name,
            Policy {
                frequency: parse_duration(&p.frequency)
                    .with_context(|| format!("policy frequency {0:?}", p.frequency))?,
                keep,
            },
        );
    }
    Ok(out)
}

// ── forget (restic ApplyPolicy) ───────────────────────────────────────────────
#[derive(Clone, Copy)]
enum CountRule {
    Last,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

impl CountRule {
    fn label(self) -> &'static str {
        match self {
            Self::Last => "last",
            Self::Hourly => "hourly",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Yearly => "yearly",
        }
    }

    fn bucket(self, t: DateTime<Utc>, nr: usize) -> i64 {
        match self {
            Self::Last => nr as i64, // a unique number per snapshot
            Self::Hourly => {
                t.year() as i64 * 1_000_000
                    + t.month() as i64 * 10_000
                    + t.day() as i64 * 100
                    + t.hour() as i64
            }
            Self::Daily => t.year() as i64 * 10_000 + t.month() as i64 * 100 + t.day() as i64,
            Self::Weekly => {
                let w = t.iso_week();
                w.year() as i64 * 100 + w.week() as i64
            }
            Self::Monthly => t.year() as i64 * 100 + t.month() as i64,
            Self::Yearly => t.year() as i64,
        }
    }
}

struct RuleState {
    rule: CountRule,
    remaining: i64,
    last_bucket: Option<i64>,
}

/// One snapshot's fate + WHY (restic's KeepReason). `reasons` lists the rules that
/// keep it ("within", "daily", …); empty `reasons` ⇒ removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub name: String,
    pub reasons: Vec<&'static str>,
}

impl Decision {
    pub fn kept(&self) -> bool {
        !self.reasons.is_empty()
    }
}

/// Evaluate every snapshot against the keep policy (restic `ApplyPolicy`), newest
/// first, recording which rule(s) keep each one. A snapshot survives if ANY rule
/// keeps it (union). Callers must supply only snapshots from the owned stream;
/// this planner does not authorize deletion or check native ZFS guards.
/// Equal timestamps use ascending names as a deterministic tie breaker. This
/// low-level function accepts prevalidated inputs; frontends use `dataset_plan`.
pub fn plan(snaps: &[(String, DateTime<Utc>)], keep: &Keep, now: DateTime<Utc>) -> Vec<Decision> {
    let mut ordered: Vec<&(String, DateTime<Utc>)> = snaps.iter().collect();
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if ordered.is_empty() {
        return Vec::new();
    }
    // Descending timestamps make all points at or before now one suffix.
    let eligible = &ordered[ordered.partition_point(|s| s.1 > now)..];
    let latest = eligible.first().map(|s| s.1).unwrap_or(ordered[0].1);
    let within_cut = keep.within.map(|w| {
        Duration::try_seconds(w)
            .and_then(|duration| latest.checked_sub_signed(duration))
            .unwrap_or(DateTime::<Utc>::MIN_UTC)
    });

    // A long scheduler/change gap is the moment the last pre-gap checkpoint is
    // most valuable. Keep the older edge of the newest such gap until snapshots
    // on the new side span a complete `within` window. This adds at most one
    // checkpoint and is derived from the stream, so it needs no mutable state.
    let gap_anchor = keep.within.and_then(|window| {
        let latest = eligible.first()?.1;
        let mut segment_start = latest;
        for pair in eligible.windows(2) {
            let newer = pair[0].1;
            let older = pair[1].1;
            if (newer - older).num_seconds() > window {
                return ((latest - segment_start).num_seconds() < window)
                    .then_some(pair[1].0.as_str());
            }
            segment_start = older;
        }
        None
    });

    let mut rules = keep.counted_rules().map(|(rule, count)| RuleState {
        rule,
        remaining: count.unwrap_or(0),
        last_bucket: None,
    });
    let n = ordered.len();
    let mut out = Vec::with_capacity(n);
    for (nr, (name, t)) in ordered.iter().enumerate() {
        let mut reasons: Vec<&'static str> = Vec::new();
        if within_cut.is_some_and(|c| *t > c) {
            reasons.push("within");
        }
        if gap_anchor.is_some_and(|anchor| name.as_str() == anchor) {
            reasons.push("gap");
        }
        for state in &mut rules {
            if state.remaining <= 0 {
                continue;
            }
            let val = state.rule.bucket(*t, nr);
            if state.last_bucket != Some(val) || nr == n - 1 {
                reasons.push(state.rule.label());
                state.last_bucket = Some(val);
                state.remaining -= 1;
            }
        }
        out.push(Decision {
            name: (*name).clone(),
            reasons,
        });
    }
    out
}

/// Retention candidates (those `plan` keeps for no reason), for unit tests.
#[cfg(test)]
fn forget(snaps: &[(String, DateTime<Utc>)], keep: &Keep, now: DateTime<Utc>) -> Vec<String> {
    plan(snaps, keep, now)
        .into_iter()
        .filter(|d| !d.kept())
        .map(|d| d.name)
        .collect()
}

/// Whether the snapshot frequency permits a take at `now`.
///
/// No prior snapshot is immediately due. When this returns true for an existing
/// snapshot, the caller must still read its change counter and skip a take when
/// that counter is zero. Keeping that read separate preserves the timer's lazy
/// query behavior: a snapshot that is too recent requires no backend read.
pub fn snapshot_due(
    newest: Option<DateTime<Utc>>,
    frequency: i64,
    now: DateTime<Utc>,
) -> Result<bool> {
    if frequency <= 0 {
        bail!("policy frequency must be positive");
    }
    let frequency = Duration::try_seconds(frequency)
        .ok_or_else(|| anyhow::anyhow!("policy frequency is out of range"))?;
    let Some(newest) = newest else {
        return Ok(true);
    };
    Ok(now - newest >= frequency)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(stamp: &str) -> DateTime<Utc> {
        NaiveDateTime::parse_from_str(stamp, STAMP)
            .unwrap()
            .and_utc()
    }
    fn nm(ds: &str, stamp: &str) -> String {
        format!("{ds}@zsnap_{stamp}")
    }
    fn pair(ds: &str, stamp: &str) -> (String, DateTime<Utc>) {
        (nm(ds, stamp), t(stamp))
    }
    fn now() -> DateTime<Utc> {
        t("2026-06-19-120000")
    }

    #[test]
    fn durations_and_naming() {
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert!(parse_duration("-5m").is_err());
        assert!(parse_duration("0m").is_err());
        assert!(parse_duration(&format!("{}w", i64::MAX)).is_err());
        assert!(
            forget(
                &[pair("p", "2026-06-19-120000")],
                &Keep {
                    within: Some(i64::MAX),
                    ..Default::default()
                },
                now()
            )
            .is_empty()
        );
        let name = snap_name("tank/x", now());
        assert_eq!(name, "tank/x@zsnap_2026-06-19-120000");
        assert!(is_zsnap(&name) && snap_time(&name) == Some(now()));
        assert!(!is_zsnap("tank/x@zfs-auto-snap_daily-2025") && !is_zsnap("tank/x@manual"));
    }

    #[test]
    fn config_rejects_fail_open_retention() {
        for bad in [
            r#"[policy.bad]
frequency = "5m"
"#,
            r#"[policy.bad]
frequency = "5m"
keep = { daliy = 14 }
"#,
            r#"[policy.bad]
frequency = "5m"
keep = { daily = 0 }
"#,
            r#"[policy.bad]
frequency = "0m"
keep = { daily = 1 }
"#,
        ] {
            assert!(
                parse_policies(bad).is_err(),
                "accepted unsafe config:\n{bad}"
            );
        }
        assert!(
            parse_policies(
                r#"[policy.good]
frequency = "5m"
keep = { within = "2h", daily = 14 }
"#
            )
            .is_ok()
        );
    }

    #[test]
    fn only_explicit_last_zero_is_a_valid_destructive_override() {
        Keep {
            last: Some(0),
            ..Default::default()
        }
        .validate_prune_override()
        .unwrap();
        assert!(
            Keep {
                last: Some(-1),
                ..Default::default()
            }
            .validate_prune_override()
            .is_err()
        );
        assert!(
            Keep {
                daily: Some(0),
                ..Default::default()
            }
            .validate_prune_override()
            .is_err()
        );
    }

    #[test]
    fn forget_keep_within() {
        let snaps = vec![
            pair("p", "2026-06-19-114000"),
            pair("p", "2026-06-19-112000"),
            pair("p", "2026-06-19-110000"),
            pair("p", "2026-06-18-120000"),
        ];
        let v = forget(
            &snaps,
            &Keep {
                within: Some(parse_duration("30m").unwrap()),
                ..Default::default()
            },
            now(),
        );
        assert_eq!(
            v,
            vec![nm("p", "2026-06-19-110000"), nm("p", "2026-06-18-120000")]
        );
    }

    #[test]
    fn forget_within_relative_to_latest_not_now() {
        // newest snapshot is 2h old; within 30m keeps a window around it (10:00), not around now
        let snaps = vec![
            pair("p", "2026-06-19-100000"),
            pair("p", "2026-06-19-094000"),
            pair("p", "2026-06-19-092000"),
            pair("p", "2026-06-19-080000"),
        ];
        let v = forget(
            &snaps,
            &Keep {
                within: Some(parse_duration("30m").unwrap()),
                ..Default::default()
            },
            now(),
        );
        assert_eq!(
            v,
            vec![nm("p", "2026-06-19-092000"), nm("p", "2026-06-19-080000")]
        );
    }

    #[test]
    fn within_keeps_a_pre_gap_anchor_until_the_new_window_is_full() {
        let keep = Keep {
            within: Some(parse_duration("30m").unwrap()),
            ..Default::default()
        };
        let old = pair("p", "2026-06-19-080000");

        let partial = vec![
            old.clone(),
            pair("p", "2026-06-19-112000"),
            pair("p", "2026-06-19-113500"),
        ];
        assert!(
            !forget(&partial, &keep, now()).contains(&old.0),
            "the last pre-gap checkpoint must survive while the new window is partial"
        );
        let old_decision = plan(&partial, &keep, now())
            .into_iter()
            .find(|d| d.name == old.0)
            .unwrap();
        assert_eq!(old_decision.reasons, vec!["gap"]);

        let full = vec![
            old.clone(),
            pair("p", "2026-06-19-112000"),
            pair("p", "2026-06-19-113500"),
            pair("p", "2026-06-19-115000"),
        ];
        assert!(forget(&full, &keep, now()).contains(&old.0));
    }

    #[test]
    fn forget_keep_daily_newest_per_snapshot_day() {
        let snaps = vec![
            pair("p", "2026-06-19-090000"),
            pair("p", "2026-06-19-080000"), // older same day → out
            pair("p", "2026-06-18-100000"),
            pair("p", "2026-06-17-100000"), // 3rd snapshot-day → beyond daily=2
        ];
        let mut v = forget(
            &snaps,
            &Keep {
                daily: Some(2),
                ..Default::default()
            },
            now(),
        );
        v.sort();
        assert_eq!(
            v,
            vec![nm("p", "2026-06-17-100000"), nm("p", "2026-06-19-080000")]
        );
    }

    #[test]
    fn forget_keeps_oldest_in_bucket_while_count_remains() {
        let snaps = vec![
            pair("p", "2026-06-19-100000"),
            pair("p", "2026-06-19-090000"),
            pair("p", "2026-06-19-080000"),
        ];
        assert_eq!(
            forget(
                &snaps,
                &Keep {
                    daily: Some(5),
                    ..Default::default()
                },
                now()
            ),
            vec![nm("p", "2026-06-19-090000")]
        );
    }

    #[test]
    fn forget_rules_unioned() {
        let snaps = vec![
            pair("p", "2026-06-19-115500"),
            pair("p", "2026-06-15-100000"),
        ];
        assert!(
            forget(
                &snaps,
                &Keep {
                    within: Some(parse_duration("30m").unwrap()),
                    daily: Some(7),
                    ..Default::default()
                },
                now()
            )
            .is_empty()
        );
    }

    #[test]
    fn due_matches_frequency_boundary_and_missing_snapshot() {
        let latest = now();
        assert!(snapshot_due(None, 900, latest).unwrap());
        assert!(snapshot_due(None, i64::MAX, latest).is_err());
        assert!(!snapshot_due(Some(latest), 900, latest).unwrap());
        assert!(!snapshot_due(Some(latest), 900, latest + Duration::seconds(899)).unwrap());
        assert!(snapshot_due(Some(latest), 900, latest + Duration::seconds(900)).unwrap());
        assert!(!snapshot_due(Some(latest), 900, latest - Duration::seconds(1)).unwrap());
        assert!(snapshot_due(Some(latest), i64::MAX, latest).is_err());
    }

    #[test]
    fn name_parser_rejects_foreign_and_partial_names() {
        for name in [
            "tank/x@manual",
            "tank/x@syncoid_2026-06-19-120000",
            "tank/x@zsnap_2026-06-19-120000-suffix",
            "tank/x@zsnap_2026-02-30-120000",
            "tank/x@zsnap_",
        ] {
            assert!(!is_zsnap(name), "accepted {name}");
        }
    }
}

mod reader_cgroup;
mod reader_process;
mod reader_store;
mod reader_task;
mod reader_view;

mod application;
mod cli;
mod status;

/// The zsnap command. Use the composable `zfs_tools` API for work inside a
/// caller-owned writer session instead of nesting this command.
pub fn run<I, T>(args: I) -> std::process::ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    use clap::Parser;
    let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    if args.get(1).is_some_and(|value| value == "__protect-child") {
        let result = args
            .get(2)
            .and_then(|value| value.to_str())
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| std::io::Error::other("missing private reader channel"))
            .and_then(reader_process::child_entry);
        if let Err(error) = result {
            eprintln!(
                "zsnap reader child: {}",
                zfs_tools::engine::escape_display(&error.to_string())
            );
        }
        return std::process::ExitCode::FAILURE;
    }
    let command = cli::Cli::parse_from(args).command;
    let command = match command {
        cli::Command::Protect(options) => {
            return std::process::ExitCode::from(reader_task::protect(options));
        }
        cli::Command::Recover(options) => {
            return std::process::ExitCode::from(reader_task::recover(options));
        }
        command => command,
    };
    let _writer = if command.locks_at_entry() {
        match zfs_tools::engine::lock::for_command("zsnap", command.name()) {
            Ok(lock) => Some(lock),
            Err(error) => {
                eprintln!("zsnap: {error}");
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    match application::execute(command) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "zsnap: {}",
                zfs_tools::engine::escape_display(&format!("{error:#}"))
            );
            if error.is::<application::Unconfirmed>() {
                std::process::ExitCode::from(3)
            } else {
                std::process::ExitCode::FAILURE
            }
        }
    }
}
