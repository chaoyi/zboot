use super::run::{Incomplete, applied_operation, consent_to, dialogue, json_response, lossless};

pub(super) fn rollback_command(
    target: String,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::tree::rollback;
    let Some((plan, token)) = consent_to(
        dry_run,
        confirm,
        json,
        || Ok(rollback::plan(&target)?),
        rollback::consent,
        rollback::describe,
        rollback::typed,
    )?
    else {
        return Ok(());
    };
    let outcome = rollback::execute(&plan, &token, &mut dialogue(json))?;
    if !json {
        println!(
            "Rolled back {} to @{}; destroyed {} newer snapshot(s).",
            zfs_tools::engine::escape_display(&outcome.root.name),
            zfs_tools::engine::escape_display(&outcome.snapshot),
            outcome.destroyed.len()
        );
    }
    let id = outcome.operation_id.clone();
    applied_operation(json, Some(token), Some(&id), outcome.complete, outcome)
}
pub(super) fn drop_command(
    targets: Vec<String>,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::tree::discard;
    let Some((plan, token)) = consent_to(
        dry_run,
        confirm,
        json,
        || Ok(discard::plan(&targets)?),
        discard::consent,
        discard::describe,
        discard::typed,
    )?
    else {
        return Ok(());
    };
    let outcome = discard::execute(&plan, &token, &mut dialogue(json))?;
    if !json {
        println!(
            "Dropped {}; destroyed {} dataset(s) and snapshot(s).",
            plan.summary,
            outcome.destroyed.len()
        );
    }
    let id = outcome.operation_id.clone();
    applied_operation(json, Some(token), Some(&id), outcome.complete, outcome)
}
pub(super) fn rename_command(
    source: String,
    destination: String,
    dry_run: bool,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::tree::rename;
    let Some(plan) = lossless(
        dry_run,
        json,
        || Ok(rename::plan(&source, &destination)?),
        rename::describe,
    )?
    else {
        return Ok(());
    };
    let outcome = rename::execute(&plan, &mut dialogue(json))?;
    if !json {
        println!(
            "Renamed {} to {}.",
            zfs_tools::engine::escape_display(&source),
            zfs_tools::engine::escape_display(&destination)
        );
    }
    let id = outcome.operation_id.clone();
    applied_operation(json, None, Some(&id), outcome.complete, outcome)
}
pub(super) fn fork_command(
    source: String,
    destination: String,
    dry_run: bool,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::tree::fork;
    let Some(plan) = lossless(
        dry_run,
        json,
        || {
            Ok(if source.contains('@') {
                fork::plan(&source, &destination)?
            } else {
                fork::plan_running(&source, &destination)?
            })
        },
        fork::describe,
    )?
    else {
        return Ok(());
    };
    let outcome = fork::execute(&plan, &mut dialogue(json))?;
    if !json {
        println!(
            "Forked {} as {}.",
            zfs_tools::engine::escape_display(&outcome.source_snapshot),
            zfs_tools::engine::escape_display(&destination)
        );
    }
    let id = outcome.operation_id.clone();
    applied_operation(json, None, Some(&id), outcome.complete, outcome)
}
fn default_snapshot_name(now: std::time::SystemTime) -> String {
    crate::tree::snapshot_name("zboot", now)
}

pub(super) fn default(
    dataset: Option<String>,
    dry_run: bool,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(dataset) = dataset else {
        let state = zfs_tools::engine::state::observe()?;
        let defaults: Vec<_> = state
            .pool_properties
            .values()
            .filter_map(|properties| properties.get("bootfs"))
            .filter(|property| !property.value.is_empty() && property.value != "-")
            .map(|property| property.value.clone())
            .collect();
        if json {
            return json_response(crate::consent::Envelope::new(
                crate::consent::Outcome::Applied,
                None,
                defaults,
            ));
        }
        match defaults.as_slice() {
            [] => println!("No boot default."),
            [dataset] => println!("{}", zfs_tools::engine::escape_display(dataset)),
            _ => {
                println!("More than one boot default.");
                for dataset in defaults {
                    println!("  {}", zfs_tools::engine::escape_display(&dataset));
                }
            }
        }
        return Ok(());
    };
    let Some(plan) = lossless(
        dry_run,
        json,
        || Ok(crate::boot_support::default::plan(&dataset)?),
        |_| {
            format!(
                "Select {} as the host boot default.\n",
                zfs_tools::engine::escape_display(&dataset)
            )
        },
    )?
    else {
        return Ok(());
    };
    let result = crate::boot_support::default::execute(&plan)?;
    if !json {
        println!(
            "Default selection {} {}.",
            zfs_tools::engine::escape_display(&dataset),
            if result.complete {
                "verified"
            } else {
                "incomplete"
            }
        );
        if let Some(detail) = &result.detail {
            println!("{}", zfs_tools::engine::escape_display(detail));
        }
    }
    applied_operation(json, None, None, result.complete, result)
}

pub(super) fn cmdline(
    dataset: String,
    set: Option<String>,
    clear: bool,
    dry_run: bool,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(value) = set.or(clear.then(String::new)) {
        let Some(plan) = lossless(
            dry_run,
            json,
            || Ok(crate::boot_support::cmdline_plan(&dataset, &value)?),
            |_| {
                format!(
                    "Set kernel additions for {} to {:?}.\n",
                    zfs_tools::engine::escape_display(&dataset),
                    zfs_tools::engine::escape_display(&value)
                )
            },
        )?
        else {
            return Ok(());
        };
        let result = crate::boot_support::apply_cmdline(&plan)?;
        if !json {
            println!(
                "Kernel argument update for {} {}.",
                zfs_tools::engine::escape_display(&dataset),
                if result.complete {
                    "verified"
                } else {
                    "incomplete"
                }
            );
            if let Some(detail) = &result.detail {
                println!("{}", zfs_tools::engine::escape_display(detail));
            }
        }
        applied_operation(json, None, None, result.complete, result)
    } else {
        let result = crate::boot_support::saved_cmdline(&dataset)?;
        if json {
            json_response(crate::consent::Envelope::new(
                crate::consent::Outcome::Applied,
                None,
                result,
            ))
        } else {
            println!(
                "{}",
                zfs_tools::engine::escape_display(
                    result
                        .as_ref()
                        .map_or("", |property| property.value.as_str())
                )
            );
            Ok(())
        }
    }
}

pub(super) fn chroot(
    dataset: String,
    command: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let code = crate::maintenance::chroot(&dataset, &command)?;
    if code != 0 {
        return Err(Box::new(crate::maintenance::CommandExit(code)));
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(super) struct SnapshotGroup {
    name: Option<String>,
    scope: zfs_tools::engine::operation::SnapshotScope,
}
pub(super) fn snapshot_plan(
    state: &zfs_tools::engine::state::NativeState,
    targets: &[String],
) -> Result<Vec<SnapshotGroup>, zfs_tools::engine::Error> {
    let mut groups = std::collections::BTreeMap::<Option<String>, Vec<String>>::new();
    for target in targets {
        let (dataset, name) = match target.split_once('@') {
            Some((dataset, name)) => (dataset, Some(name.to_owned())),
            None => (target.as_str(), None),
        };
        groups.entry(name).or_default().push(dataset.to_owned());
    }
    groups
        .into_iter()
        .map(|(name, roots)| {
            let scope = zfs_tools::engine::operation::SnapshotScope::plan(
                &state.inspection,
                &state.dataset_properties,
                &state.pool_properties,
                &roots,
            )?;
            if let Some(name) = &name {
                zfs_tools::engine::validate_snapshot_name(&format!("validation/point@{name}"))?;
                if scope.datasets().iter().any(|dataset| {
                    state
                        .inspection
                        .snapshots
                        .as_ref()
                        .is_some_and(|snapshots| {
                            snapshots
                                .iter()
                                .any(|snapshot| snapshot.name == format!("{}@{name}", dataset.name))
                        })
                }) {
                    return Err(zfs_tools::engine::Error::Refused(format!(
                        "capture name already exists in the selected scope: @{name}"
                    )));
                }
            }
            Ok(SnapshotGroup { name, scope })
        })
        .collect()
}

pub(super) fn snapshot(
    datasets: Vec<String>,
    dry_run: bool,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(groups) = lossless(
        dry_run,
        json,
        || {
            Ok(snapshot_plan(
                &zfs_tools::engine::state::observe()?,
                &datasets,
            )?)
        },
        |groups| {
            let mut text = String::new();
            for group in groups {
                text.push_str(&format!(
                    "Capture {} as {}.\n",
                    group.scope.roots().join(", "),
                    group.name.as_deref().unwrap_or("a generated snapshot name")
                ));
            }
            text
        },
    )?
    else {
        return Ok(());
    };
    let generated = default_snapshot_name(std::time::SystemTime::now());
    let mut outcomes = Vec::new();
    for group in groups {
        let name = group.name.as_deref().unwrap_or(&generated);
        let id = uuid::Uuid::new_v4().to_string();
        let outcome = match zfs_tools::engine::capture::capture_prepared(&group.scope, name, &id) {
            Ok(outcome) => outcome,
            Err(error) => {
                if json && !outcomes.is_empty() {
                    json_response(crate::consent::Envelope::new(
                        crate::consent::Outcome::Partial,
                        None,
                        &outcomes,
                    ))?;
                }
                return Err(error.into());
            }
        };
        let complete = outcome.status() == zfs_tools::CaptureStatus::Complete;
        if !json {
            for point in outcome.points() {
                println!(
                    "Captured {}  guid={}",
                    zfs_tools::engine::escape_display(&point.name),
                    point.identity.guid
                );
            }
            for name in outcome.missing() {
                println!("Unverified {}", zfs_tools::engine::escape_display(name));
            }
        }
        let detail = outcome.detail().map(str::to_owned);
        outcomes.push(outcome);
        if !complete {
            if json {
                json_response(crate::consent::Envelope::new(
                    crate::consent::Outcome::Partial,
                    None,
                    &outcomes,
                ))?;
            }
            return Err(Incomplete(format!(
                "capture {id} needs inspection. {}",
                detail
                    .as_deref()
                    .unwrap_or("one or more points are missing")
            ))
            .into());
        }
    }
    if json {
        json_response(crate::consent::Envelope::new(
            crate::consent::Outcome::Applied,
            None,
            outcomes,
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_groups_bind_explicit_names_and_generate_nothing_in_preview() {
        let mut fake = crate::tree::fake::Fake::new();
        fake.create("a/data");
        fake.create("a/data/child");
        fake.create("a/other");
        let state = crate::tree::Backend::observe(&mut fake).unwrap();
        let targets = vec!["a/data@before".into(), "a/other@after".into()];
        let first = snapshot_plan(&state, &targets).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].name.as_deref(), Some("after"));
        assert_eq!(first[1].scope.datasets().len(), 2);
        let generated = snapshot_plan(&state, &["a/data".into()]).unwrap();
        assert!(generated[0].name.is_none());
        assert_eq!(
            generated,
            snapshot_plan(&state, &["a/data".into()]).unwrap()
        );
        assert_eq!(fake.writes, 0);
        fake.snap("a/data@before");
        let state = crate::tree::Backend::observe(&mut fake).unwrap();
        assert!(snapshot_plan(&state, &targets).is_err());
    }

    #[test]
    fn default_snapshot_names_are_utc_and_sort_in_time_order() {
        let at = |seconds| std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
        assert_eq!(default_snapshot_name(at(0)), "zboot-19700101T000000Z");
        assert_eq!(
            default_snapshot_name(at(951_782_400)),
            "zboot-20000229T000000Z"
        );
        assert_eq!(
            default_snapshot_name(at(1_794_123_045)),
            "zboot-20261108T073045Z"
        );
        assert!(
            default_snapshot_name(at(1_794_123_045)) < default_snapshot_name(at(1_794_123_046))
        );
    }
}
