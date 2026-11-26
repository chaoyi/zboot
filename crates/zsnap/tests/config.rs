use zsnap::{Keep, parse_policies};

#[test]
fn counted_rule_validation_preserves_policy_and_prune_distinction() {
    for rule in ["last", "hourly", "daily", "weekly", "monthly", "yearly"] {
        for count in [-1, 0, 1] {
            let keep: Keep = serde_json::from_value(serde_json::json!({rule: count})).unwrap();
            assert!(!keep.is_empty(), "{rule}={count} is an explicit rule");
            assert_eq!(keep.describe(), format!("{rule}={count}"));

            let policies = parse_policies(&format!(
                "[policy.example]\nfrequency = '1m'\nkeep = {{ {rule} = {count} }}"
            ));
            if count > 0 {
                assert_eq!(policies.unwrap()["example"].keep, keep);
            } else {
                assert_eq!(
                    policies.unwrap_err().to_string(),
                    format!("policy \"example\" keep.{rule} must be positive")
                );
            }

            let prune = keep.validate_prune_override();
            if count > 0 || (rule == "last" && count == 0) {
                prune.unwrap();
            } else {
                let expected = if rule == "last" {
                    "--last must be non-negative".to_owned()
                } else {
                    format!("--{rule} must be positive (only --last 0 means keep nothing)")
                };
                assert_eq!(prune.unwrap_err().to_string(), expected);
            }
        }
    }
    assert!(Keep::default().is_empty());
    assert!(
        !Keep {
            within: Some(60),
            ..Default::default()
        }
        .is_empty()
    );
}

#[test]
fn validation_preserves_error_precedence() {
    let keep = Keep {
        within: Some(0),
        last: Some(-1),
        daily: Some(0),
        ..Default::default()
    };
    assert_eq!(
        keep.validate_prune_override().unwrap_err().to_string(),
        "within must be a positive, representable duration"
    );
    assert_eq!(
        Keep {
            within: None,
            ..keep
        }
        .validate_prune_override()
        .unwrap_err()
        .to_string(),
        "--last must be non-negative"
    );
    // Keep validation precedes frequency parsing, even when both are invalid.
    let error =
        parse_policies("[policy.example]\nfrequency = '0s'\nkeep = { last = 0, daily = 0 }")
            .unwrap_err();
    assert_eq!(
        error.to_string(),
        "policy \"example\" keep.last must be positive"
    );
}
