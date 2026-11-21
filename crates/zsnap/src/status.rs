use crate::{
    Config, POLICY_PROPERTY, canon_duration, dataset_plan, is_disabled_policy, owned_snap_time,
};
use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use std::fmt::Write;
use zfs_tools::engine::{Inspection, escape_display, native::PropertyInventory};

pub fn render(
    inspection: &Inspection,
    properties: &PropertyInventory,
    config: &Config,
    dataset: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String> {
    let snapshots = inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| anyhow!("snapshot history was not observed"))?;
    if let Some(dataset) = dataset {
        zfs_tools::engine::validate_dataset_name(dataset)?;
        if !inspection.datasets.iter().any(|d| d.name == dataset) {
            bail!("dataset was not observed: {}", escape_display(dataset));
        }
        let names: Vec<_> = snapshots
            .iter()
            .filter(|s| s.name.split_once('@').map(|(ds, _)| ds) == Some(dataset))
            .map(|s| s.name.clone())
            .collect();
        let assignment = assignment(properties, dataset)?;
        let mut output = String::new();
        let policy = assignment.and_then(|name| config.policies.get(name));
        match (assignment, policy) {
            (Some(name), Some(policy)) => writeln!(
                output,
                "{} — policy '{}': every {}; keep {}",
                escape_display(dataset),
                escape_display(name),
                canon_duration(policy.frequency),
                policy.keep.describe()
            )?,
            (Some(name), None) => writeln!(
                output,
                "{} — unknown policy '{}'",
                escape_display(dataset),
                escape_display(name)
            )?,
            _ => writeln!(
                output,
                "{} — no active snapshot policy",
                escape_display(dataset)
            )?,
        }
        if let Some(policy) = policy {
            let decisions = dataset_plan(dataset, &names, &policy.keep, now)?;
            if decisions.is_empty() {
                writeln!(output, "  (no owned snapshots)")?;
            }
            for decision in decisions {
                let why = if decision.kept() {
                    decision.reasons.join(", ")
                } else {
                    "retention candidate".into()
                };
                writeln!(output, "  {}  {why}", escape_display(&decision.name))?;
            }
        } else {
            for name in names
                .iter()
                .filter(|name| owned_snap_time(name, dataset).is_some())
            {
                writeln!(
                    output,
                    "  {}  (no retention decision)",
                    escape_display(name)
                )?;
            }
        }
        return Ok(output);
    }
    let mut output = String::new();
    let mut datasets: Vec<_> = inspection.datasets.iter().collect();
    datasets.sort_by(|a, b| a.name.cmp(&b.name));
    for dataset in datasets {
        let Some(name) = assignment(properties, &dataset.name)? else {
            continue;
        };
        let mut times: Vec<_> = snapshots
            .iter()
            .filter_map(|s| owned_snap_time(&s.name, &dataset.name))
            .collect();
        times.sort();
        let newest = times
            .last()
            .map_or_else(|| "-".into(), |time| time.to_rfc3339());
        let policy = config.policies.get(name);
        writeln!(
            output,
            "{}  policy={}{}  snapshots={}  newest={}",
            escape_display(&dataset.name),
            escape_display(name),
            if policy.is_none() { "?" } else { "" },
            times.len(),
            newest
        )?;
    }
    if output.is_empty() {
        output.push_str("no datasets carry an active zsnap:policy\n");
    }
    Ok(output)
}

pub fn assignment<'a>(properties: &'a PropertyInventory, dataset: &str) -> Result<Option<&'a str>> {
    let properties = properties.get(dataset).ok_or_else(|| {
        anyhow!(
            "dataset properties were not observed: {}",
            escape_display(dataset)
        )
    })?;
    let value = properties
        .get(POLICY_PROPERTY)
        .map_or("-", |p| p.value.trim());
    Ok((!is_disabled_policy(value)).then_some(value))
}

pub fn render_diagnostics(report: &crate::transport::PolicyStatusReport) -> Result<String> {
    let mut output = String::new();
    for row in &report.datasets {
        let age = |seconds: Option<i64>| {
            seconds.map_or_else(
                || "-".into(),
                |s| {
                    if s < 0 {
                        format!("in {}s", s.unsigned_abs())
                    } else if s >= 86400 {
                        format!("{}d", s / 86400)
                    } else if s >= 3600 {
                        format!("{}h", s / 3600)
                    } else if s >= 60 {
                        format!("{}m", s / 60)
                    } else {
                        format!("{s}s")
                    }
                },
            )
        };
        writeln!(
            output,
            "{}  policy={} snapshots={} oldest={} newest={} usedbysnapshots={} status={}",
            escape_display(&row.expected.dataset),
            escape_display(
                row.expected
                    .policy
                    .as_ref()
                    .map_or("-", |p| p.value.as_str())
            ),
            row.snapshots,
            age(row.oldest_age_seconds),
            age(row.newest_age_seconds),
            row.used_by_snapshots_bytes
                .map_or_else(|| "unknown".into(), |b| b.to_string()),
            row.diagnostic
        )?;
        // A read-only or fenced row's blocker is the snapshot admission
        // refusal the legend already explains; repeating it on every
        // read-only dataset is noise.
        let plain = matches!(row.diagnostic.as_str(), "read_only" | "fenced");
        for error in [
            row.expected.blocker.as_deref().filter(|_| !plain),
            row.accounting_error.as_deref(),
            row.diagnostic_error.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            writeln!(output, "  {}", escape_display(error))?;
        }
    }
    writeln!(output, "Policies (frequency; retention):")?;
    for (name, policy) in &report.policies {
        writeln!(
            output,
            "  {}: every {}; keep {}",
            escape_display(name),
            canon_duration(policy.frequency),
            policy.keep.describe()
        )?;
    }
    writeln!(
        output,
        "Legend: changed_and_overdue = older than twice the frequency with new writes; unchanged = due without new writes; no_snapshots = first capture needed; read_only = read-only dataset, snapshots are taken on a writable working copy; fenced = fenced pair copy, follows its working copy through `zboot sync`; blocked = role/pending/authority admission refused; unknown = accounting/query unavailable."
    )?;
    Ok(output)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zfs_tools::engine::native::NativeProperty;

    pub(crate) fn fixture() -> (Inspection, PropertyInventory) {
        let inspection = zfs_tools::engine::native::inspect_with(&zfs_tools::engine::InspectRequest::new(vec![], true).unwrap(), |program, args| {
            Ok(if program == "zpool" {
                "tank\t1\t1000\t100\t900\tONLINE\t-\n".into()
            } else if args[0] == "holds" {
                String::new()
            } else if args.iter().any(|a| a == "filesystem,volume") {
                "tank\tfilesystem\t1\t0\t900\t0\t/tank\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\t-\t-\ntank/data\tfilesystem\t2\t0\t900\t0\t/tank/data\t-\t5\t7\tno\toff\ton\t-\toff\t-\t-\t-\t-\n".into()
            } else {
                "tank/data@zsnap_2026-06-19-120000\t3\t1781870400\t0\t0\t10\t8\t0\toff\t-\ntank/data@manual\t4\t1781870400\t0\t0\t11\t9\t0\toff\t-\n".into()
            })
        }).unwrap();
        let properties = BTreeMap::from([
            ("tank".into(), BTreeMap::new()),
            (
                "tank/data".into(),
                BTreeMap::from([(
                    POLICY_PROPERTY.into(),
                    NativeProperty {
                        value: "guard".into(),
                        source: "local".into(),
                    },
                )]),
            ),
        ]);
        (inspection, properties)
    }

    #[test]
    fn summary_and_detail_scope_only_owned_snapshots() {
        let (inspection, properties) = fixture();
        let config = Config::from_override(None).unwrap();
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let summary = render(&inspection, &properties, &config, None, now).unwrap();
        assert!(summary.contains("tank/data  policy=guard  snapshots=1"));
        let detail = render(&inspection, &properties, &config, Some("tank/data"), now).unwrap();
        assert!(detail.contains("within"));
        assert!(!detail.contains("manual"));
        assert!(render(&inspection, &properties, &config, Some("tank/missing"), now).is_err());
    }

    #[test]
    fn unknown_or_missing_assignments_never_invent_retention() {
        let (inspection, mut properties) = fixture();
        properties
            .get_mut("tank/data")
            .unwrap()
            .get_mut(POLICY_PROPERTY)
            .unwrap()
            .value = "unknown\u{202e}".into();
        let output = render(
            &inspection,
            &properties,
            &Config::from_override(None).unwrap(),
            Some("tank/data"),
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .unwrap();
        assert!(output.contains("unknown policy"));
        assert!(!output.contains('\u{202e}'));
        assert!(!output.contains("retention candidate"));
        properties.remove("tank/data");
        assert!(assignment(&properties, "tank/data").is_err());
    }
}
