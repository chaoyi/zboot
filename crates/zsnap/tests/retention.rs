use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;
use std::collections::BTreeSet;
use zsnap::{Keep, Policy, forget, parse_duration, plan, snap_name, snap_time, snapshot_due};

fn t(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .unwrap()
        .with_timezone(&Utc)
}

fn snapshots(times: &[&str]) -> Vec<(String, DateTime<Utc>)> {
    times
        .iter()
        .map(|text| {
            let time = t(text);
            (snap_name("pool/data", time), time)
        })
        .collect()
}

#[test]
fn reasons_preserve_within_gap_and_counted_rule_order() {
    let snaps = snapshots(&["2026-06-19T12:00:00Z", "2025-05-18T11:00:00Z"]);
    let keep = Keep {
        within: Some(1800),
        last: Some(2),
        hourly: Some(2),
        daily: Some(2),
        weekly: Some(2),
        monthly: Some(2),
        yearly: Some(2),
    };
    let decisions = plan(&snaps, &keep, snaps[0].1);
    assert_eq!(
        decisions[0].reasons,
        [
            "within", "last", "hourly", "daily", "weekly", "monthly", "yearly"
        ]
    );
    assert_eq!(
        decisions[1].reasons,
        [
            "gap", "last", "hourly", "daily", "weekly", "monthly", "yearly"
        ]
    );
}

#[test]
fn counted_rules_exhaust_independently_and_only_oldest_gets_same_bucket_fallback() {
    let latest = t("2026-06-19T12:00:00Z");
    // The low-level planner permits same-time points with distinct names.
    let snaps = vec![
        ("point-b".to_owned(), latest),
        ("point-oldest".to_owned(), latest - Duration::hours(3)),
        ("point-a".to_owned(), latest),
        ("point-middle".to_owned(), latest - Duration::hours(2)),
        ("point-hour".to_owned(), latest - Duration::hours(1)),
    ];
    let keep = Keep {
        last: Some(2),
        hourly: Some(2),
        daily: Some(2),
        weekly: Some(1),
        monthly: Some(1),
        yearly: Some(1),
        ..Default::default()
    };
    let decisions = plan(&snaps, &keep, latest);
    let actual: Vec<_> = decisions
        .iter()
        .map(|d| (d.name.as_str(), d.reasons.as_slice()))
        .collect();
    assert_eq!(
        actual,
        vec![
            (
                "point-a",
                &["last", "hourly", "daily", "weekly", "monthly", "yearly"][..]
            ),
            ("point-b", &["last"][..]),
            ("point-hour", &["hourly"][..]),
            ("point-middle", &[][..]),
            ("point-oldest", &["daily"][..]),
        ]
    );

    // Reaching the oldest point does not revive an exhausted rule.
    let exhausted = Keep {
        daily: Some(1),
        ..keep
    };
    assert!(
        plan(&snaps, &exhausted, latest)
            .last()
            .unwrap()
            .reasons
            .is_empty()
    );
}

#[test]
fn keep_and_policy_preserve_public_json_fields_and_description_order() {
    let policy = Policy {
        frequency: 300,
        keep: Keep {
            last: Some(2),
            within: Some(1800),
            hourly: Some(3),
            daily: Some(4),
            weekly: Some(5),
            monthly: Some(6),
            yearly: Some(7),
        },
    };
    let wire = serde_json::json!({
        "frequency": 300,
        "keep": {
            "last": 2, "within": 1800, "hourly": 3, "daily": 4,
            "weekly": 5, "monthly": 6, "yearly": 7
        }
    });
    assert_eq!(serde_json::to_value(&policy).unwrap(), wire);
    assert_eq!(serde_json::from_value::<Policy>(wire).unwrap(), policy);
    assert_eq!(
        policy.keep.describe(),
        "last=2 within=30m hourly=3 daily=4 weekly=5 monthly=6 yearly=7"
    );

    let empty = Keep::default();
    assert_eq!(
        serde_json::to_value(&empty).unwrap(),
        serde_json::json!({
            "last": null, "within": null, "hourly": null, "daily": null,
            "weekly": null, "monthly": null, "yearly": null
        })
    );
    assert_eq!(empty.describe(), "(nothing)");
}

#[test]
fn calendar_buckets_cross_iso_year_leap_day_and_month_boundaries() {
    let cases = [
        (
            Keep {
                weekly: Some(2),
                ..Default::default()
            },
            vec![
                "2021-01-04T12:00:00Z", // ISO 2021 week 1
                "2021-01-03T12:00:00Z", // ISO 2020 week 53
                "2020-12-31T12:00:00Z", // same ISO week
                "2020-12-27T12:00:00Z", // week 52
            ],
        ),
        (
            Keep {
                monthly: Some(2),
                ..Default::default()
            },
            vec![
                "2024-03-01T00:00:00Z",
                "2024-02-29T23:59:59Z",
                "2024-02-01T00:00:00Z",
                "2024-01-31T23:59:59Z",
            ],
        ),
        (
            Keep {
                yearly: Some(2),
                ..Default::default()
            },
            vec![
                "2025-01-01T00:00:00Z",
                "2024-12-31T23:59:59Z",
                "2024-02-29T00:00:00Z",
                "2023-12-31T23:59:59Z",
            ],
        ),
        (
            Keep {
                daily: Some(2),
                ..Default::default()
            },
            vec![
                "2024-03-01T00:00:00Z",
                "2024-02-29T23:59:59Z",
                "2024-02-29T00:00:00Z",
                "2024-02-28T23:59:59Z",
            ],
        ),
        (
            Keep {
                hourly: Some(2),
                ..Default::default()
            },
            vec![
                "2024-03-01T00:00:00Z",
                "2024-02-29T23:59:59Z",
                "2024-02-29T23:00:00Z",
                "2024-02-29T22:59:59Z",
            ],
        ),
    ];
    for (keep, times) in cases {
        let snaps = snapshots(&times);
        assert_eq!(
            forget(&snaps, &keep, snaps[0].1),
            vec![snaps[2].0.clone(), snaps[3].0.clone()]
        );
    }
}

#[test]
fn within_cutoff_is_exclusive_and_future_does_not_move_eligible_window() {
    let snaps = snapshots(&[
        "2026-06-20T12:00:00Z", // future timestamp is retained by within
        "2026-06-19T12:00:00Z",
        "2026-06-19T11:30:01Z",
        "2026-06-19T11:30:00Z", // exact cutoff
        "2026-06-19T11:29:59Z",
    ]);
    let keep = Keep {
        within: Some(1800),
        ..Default::default()
    };
    assert_eq!(
        forget(&snaps, &keep, snaps[1].1),
        vec![snaps[3].0.clone(), snaps[4].0.clone()]
    );
}

#[test]
fn all_future_history_uses_newest_cutoff_without_gap_and_consumes_count_rules() {
    let now = t("2026-06-19T12:00:00Z");
    let snaps = snapshots(&[
        "2026-06-20T12:00:00Z",
        "2026-06-20T11:45:00Z",
        "2026-06-20T11:30:00Z", // exact cutoff relative to the newest future point
        "2026-06-20T08:00:00Z", // a long gap between ineligible future points
    ]);
    let keep = Keep {
        within: Some(1800),
        last: Some(1),
        ..Default::default()
    };
    let decisions = plan(&snaps, &keep, now);
    let reasons: Vec<_> = decisions.iter().map(|d| d.reasons.as_slice()).collect();
    assert_eq!(
        reasons,
        vec![&["within", "last"][..], &["within"][..], &[][..], &[][..]]
    );
}

#[test]
fn future_injection_preserves_eligible_within_reasons_and_gap_anchor_state() {
    let now = t("2026-06-19T12:00:00Z");
    let keep = Keep {
        within: Some(1800),
        ..Default::default()
    };
    for (times, expected) in [
        (
            vec![
                "2026-06-19T12:00:00Z", // exactly now remains eligible
                "2026-06-19T11:45:00Z",
                "2026-06-19T08:00:00Z",
            ],
            vec![&["within"][..], &["within"][..], &["gap"][..]],
        ),
        (
            vec![
                "2026-06-19T12:00:00Z",
                "2026-06-19T11:45:00Z",
                "2026-06-19T11:30:00Z", // complete window releases the anchor
                "2026-06-19T08:00:00Z",
            ],
            vec![&["within"][..], &["within"][..], &[][..], &[][..]],
        ),
    ] {
        let eligible = snapshots(&times);
        let baseline = plan(&eligible, &keep, now);
        assert_eq!(
            baseline
                .iter()
                .map(|d| d.reasons.as_slice())
                .collect::<Vec<_>>(),
            expected
        );

        for future_times in [
            vec!["2026-06-19T12:15:00Z", "2026-06-19T12:30:00Z"],
            vec!["2026-06-20T12:00:00Z", "2026-06-21T12:00:00Z"],
        ] {
            let future = snapshots(&future_times);
            let mut injected = eligible.clone();
            injected.extend(future.clone());
            let decisions = plan(&injected, &keep, now);
            let eligible_decisions: Vec<_> = decisions
                .iter()
                .filter(|d| eligible.iter().any(|s| s.0 == d.name))
                .cloned()
                .collect();
            assert_eq!(eligible_decisions, baseline);
            for decision in decisions
                .iter()
                .filter(|d| future.iter().any(|s| s.0 == d.name))
            {
                assert_eq!(decision.reasons, ["within"]);
            }
        }
    }
}

#[test]
fn exact_gap_window_and_future_due_boundaries() {
    let snaps = snapshots(&["2026-06-19T12:00:00Z", "2026-06-19T11:30:00Z"]);
    let keep = Keep {
        within: Some(1800),
        ..Default::default()
    };
    // Exactly one window is not a long gap.
    assert_eq!(forget(&snaps, &keep, snaps[0].1), vec![snaps[1].0.clone()]);
    for bad in [0, -1, i64::MAX] {
        assert!(snapshot_due(None, bad, snaps[0].1).is_err());
    }
    assert!(!snapshot_due(Some(snaps[0].1), 60, snaps[0].1 - Duration::seconds(1)).unwrap());
}

#[test]
fn malformed_namespace_and_noncanonical_stamp_are_not_owned() {
    for name in [
        "@zsnap_2026-06-19-120000",
        "p@foreign@zsnap_2026-06-19-120000",
        "p//a@zsnap_2026-06-19-120000",
        "p@zsnap_2026-6-19-120000",
        "p@zsnap_2026-06-19-120000 ",
    ] {
        assert_eq!(snap_time(name), None, "{name}");
    }
    for duration in ["", "💾", "1💾", "0m", "9223372036854775807d"] {
        assert!(parse_duration(duration).is_err());
    }
}

proptest! {
    #[test]
    fn last_cardinality_and_permutation_invariance(
        offsets in prop::collection::vec(0i64..1_000_000, 0..120),
        count in 0i64..140,
    ) {
        let origin = t("2026-01-01T00:00:00Z");
        // Distinct names permit same-time inputs, testing deterministic ties.
        let snaps: Vec<_> = offsets.iter().enumerate().map(|(i, &seconds)|
            (format!("point-{i:03}"), origin + Duration::seconds(seconds))).collect();
        let keep = Keep { last: Some(count), ..Default::default() };
        let decisions = plan(&snaps, &keep, origin + Duration::days(100));
        prop_assert_eq!(decisions.iter().filter(|d| d.kept()).count(), snaps.len().min(count as usize));
        let mut reversed = snaps.clone();
        reversed.reverse();
        prop_assert_eq!(&decisions, &plan(&reversed, &keep, origin + Duration::days(100)));
        let decided: BTreeSet<_> = decisions.iter().map(|d| &d.name).collect();
        prop_assert_eq!(decided.len(), snaps.len());
    }

    #[test]
    fn combined_rules_preserve_each_individual_rule(
        offsets in prop::collection::btree_set(0i64..20_000_000, 0..100),
        last in 1i64..20,
        daily in 1i64..20,
    ) {
        let origin = t("2024-01-01T00:00:00Z");
        let snaps: Vec<_> = offsets.iter().map(|&offset| {
            let time = origin + Duration::seconds(offset);
            (snap_name("p/a", time), time)
        }).collect();
        let now = origin + Duration::days(365);
        let merged = plan(&snaps, &Keep { last: Some(last), daily: Some(daily), ..Default::default() }, now);
        let merged_kept: BTreeSet<_> = merged.iter().filter(|d| d.kept()).map(|d| &d.name).collect();
        for keep in [Keep { last: Some(last), ..Default::default() }, Keep { daily: Some(daily), ..Default::default() }] {
            for decision in plan(&snaps, &keep, now).into_iter().filter(|d| d.kept()) {
                prop_assert!(merged_kept.contains(&decision.name));
            }
        }
    }

    #[test]
    fn duration_input_never_panics(input in ".*") {
        let _ = parse_duration(&input);
    }
}
