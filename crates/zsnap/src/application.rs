use crate::{
    Config, Keep, SnapshotNameCollision, capture_names, dataset_plan, owned_snap_time,
    properties::{self, PolicyChange, PolicyRequest, PolicyStatus},
    snap_name, snap_suffix, snapshot_due,
};
use crate::{
    cli::{Command, load_config},
    status,
};
use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use std::io::{self, Write};
use zfs_tools::engine::{
    SnapshotRef,
    capture::{self, CaptureRequest, NativeCapture},
    delete::{self, NativeDelete, RetentionDeletePlan, RetentionSelection},
    operation::SnapshotScope,
    state::{self, NativeState},
};
use zfs_tools::{CaptureOutcome, CaptureStatus, DeleteOutcome, DeletePointStatus, DeleteStatus};

pub fn execute(command: Command) -> Result<()> {
    match command {
        Command::Protect(_) | Command::Recover(_) => {
            bail!("reader tasks own their complete writer and process lifetime")
        }
        Command::Status {
            dataset,
            config,
            json,
        } => {
            let config = load_config(config.as_deref())?;
            let state = state::observe()?;
            let now = now();
            let report =
                crate::transport::observe_status(&state, &config, dataset.as_deref(), now)?;
            if json {
                println!("{}", serde_json::to_string(&report)?);
                return Ok(());
            }
            if dataset.is_some() {
                print!(
                    "{}",
                    status::render(
                        &state.inspection,
                        &state.dataset_properties,
                        &config,
                        dataset.as_deref(),
                        now
                    )?
                );
            }
            print!("{}", status::render_diagnostics(&report)?);
        }
        Command::Snap { datasets, dry_run } => snap(&datasets, dry_run)?,
        Command::Assign {
            dataset,
            policy,
            request_json,
            config,
            dry_run,
        } => {
            let config = load_config(config.as_deref())?;
            let assignment = config.assignment(&policy)?;
            let value = match assignment {
                crate::Assignment::Disabled => "none".into(),
                crate::Assignment::Policy(name) => name,
            };
            if let Some(path) = request_json {
                return machine_assignment(
                    &path,
                    &config,
                    &dataset,
                    crate::transport::PolicyChange::Set(value),
                );
            }
            change_assignment(
                PolicyRequest {
                    dataset,
                    change: PolicyChange::Set(value),
                },
                dry_run,
            )?;
        }
        Command::Unassign {
            dataset,
            dry_run,
            request_json,
        } => {
            if let Some(path) = request_json {
                return machine_assignment(
                    &path,
                    &Config::from_override(None)?,
                    &dataset,
                    crate::transport::PolicyChange::Inherit,
                );
            }
            change_assignment(
                PolicyRequest {
                    dataset,
                    change: PolicyChange::Inherit,
                },
                dry_run,
            )?;
        }
        Command::Prune {
            dataset,
            config,
            yes,
            dry_run,
            keep,
        } => {
            let config = load_config(config.as_deref())?;
            prune(
                dataset.as_deref(),
                &config,
                keep.policy()?.as_ref(),
                yes,
                dry_run,
            )?;
        }
        Command::Run { config, dry_run } => run(&load_config(config.as_deref())?, dry_run)?,
    }
    Ok(())
}

fn now() -> DateTime<Utc> {
    std::time::SystemTime::now().into()
}

fn snapshot_names(state: &NativeState) -> Result<Vec<String>> {
    Ok(state
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| anyhow!("snapshot history was not observed"))?
        .iter()
        .map(|s| s.name.clone())
        .collect())
}

fn exact_scope(state: &NativeState, datasets: &[String]) -> Result<()> {
    SnapshotScope::plan_exact(
        &state.inspection,
        &state.dataset_properties,
        &state.pool_properties,
        datasets,
    )?;
    Ok(())
}

fn snap(datasets: &[String], dry_run: bool) -> Result<()> {
    if dry_run {
        let state = state::observe()?;
        exact_scope(&state, datasets)?;
        for name in capture_names(datasets, &snapshot_names(&state)?, now())? {
            println!("DRY capture {}", zfs_tools::engine::escape_display(&name));
        }
        return Ok(());
    }
    // Only pre-effect name collisions are retried. Native failures or uncertain
    // outcomes are never retried, even if a later name would be available.
    for attempt in 0..3 {
        let state = state::observe()?;
        let now = now();
        match capture_names(datasets, &snapshot_names(&state)?, now) {
            Ok(_) => return take(datasets, now),
            Err(error)
                if error.downcast_ref::<SnapshotNameCollision>().is_some() && attempt < 2 =>
            {
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("each final attempt returns")
}

fn take(datasets: &[String], now: DateTime<Utc>) -> Result<()> {
    let outcome = capture::capture_with(
        &CaptureRequest {
            roots: datasets.to_vec(),
            name: snap_suffix(now),
            recursive: false,
        },
        &mut NativeCapture,
    )?;
    write_capture(&outcome, &mut io::stdout().lock())
}

fn write_capture(outcome: &CaptureOutcome, output: &mut impl Write) -> Result<()> {
    let status = outcome.status();
    if status != CaptureStatus::Complete {
        bail!(
            "capture {} is {:?}; observed {}; missing [{}]; {}",
            outcome.operation_id(),
            status,
            serde_json::to_string(outcome.points())?,
            outcome.missing().join(", "),
            outcome.detail().unwrap_or("re-observe before continuing")
        );
    }
    // `snap` consumers require one exact native name per line, and must not
    // mistake a partial capture for a successfully verified atomic set.
    for point in outcome.points() {
        writeln!(output, "{}", point.name)?;
    }
    Ok(())
}

fn change_assignment(request: PolicyRequest, dry_run: bool) -> Result<()> {
    if dry_run {
        let preview = properties::preview_policy(&state::observe()?, &request)?;
        match preview.change {
            PolicyChange::Set(value) => println!(
                "DRY {}: local zsnap:policy = {}",
                zfs_tools::engine::escape_display(&preview.dataset.name),
                zfs_tools::engine::escape_display(&value)
            ),
            PolicyChange::Inherit => println!(
                "DRY {}: clear local zsnap:policy; an ancestor policy may become effective",
                zfs_tools::engine::escape_display(&preview.dataset.name)
            ),
        }
        return Ok(());
    }
    let outcome = properties::change_policy(&request)?;
    if outcome.status != PolicyStatus::Complete {
        bail!(
            "assignment outcome uncertain: {}",
            outcome
                .detail
                .as_deref()
                .unwrap_or("re-observe before continuing")
        );
    }
    let effective = outcome
        .effective
        .ok_or_else(|| anyhow!("assignment verification was not returned"))?;
    println!(
        "{}: zsnap:policy = {} ({})",
        zfs_tools::engine::escape_display(&request.dataset),
        zfs_tools::engine::escape_display(effective.value.as_deref().unwrap_or("-")),
        zfs_tools::engine::escape_display(effective.source.as_deref().unwrap_or("unset"))
    );
    Ok(())
}

fn selected_policies(
    state: &NativeState,
    config: &Config,
    dataset: Option<&str>,
    override_keep: Option<&Keep>,
) -> Result<Vec<(String, String, Keep)>> {
    if let Some(dataset) = dataset {
        zfs_tools::engine::validate_dataset_name(dataset)?;
        if !state.inspection.datasets.iter().any(|d| d.name == dataset) {
            bail!("dataset was not observed: {dataset}");
        }
        let assigned = status::assignment(&state.dataset_properties, dataset)?;
        let keep = match override_keep {
            Some(keep) => keep.clone(),
            None => {
                let assigned = assigned.ok_or_else(|| {
                    anyhow!("{dataset} has no active policy; supply a retention override")
                })?;
                config
                    .policies
                    .get(assigned)
                    .ok_or_else(|| anyhow!("unknown policy {assigned:?} on {dataset}"))?
                    .keep
                    .clone()
            }
        };
        return Ok(vec![(
            dataset.into(),
            assigned.unwrap_or("explicit override").into(),
            keep,
        )]);
    }
    let mut selected = Vec::new();
    for dataset in &state.inspection.datasets {
        let Some(assigned) = status::assignment(&state.dataset_properties, &dataset.name)? else {
            continue;
        };
        let keep = match override_keep {
            Some(keep) => keep.clone(),
            None => config
                .policies
                .get(assigned)
                .ok_or_else(|| anyhow!("unknown policy {assigned:?} on {}", dataset.name))?
                .keep
                .clone(),
        };
        selected.push((dataset.name.clone(), assigned.into(), keep));
    }
    selected.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(selected)
}

fn candidates(
    state: &NativeState,
    dataset: &str,
    keep: &Keep,
    now: DateTime<Utc>,
    proposed_capture: Option<&str>,
) -> Result<Vec<SnapshotRef>> {
    let snapshots = state
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| anyhow!("snapshot history was not observed"))?;
    let mut by_name = std::collections::HashMap::new();
    let mut names = Vec::new();
    for snapshot in snapshots {
        if snapshot.name.split_once('@').map(|(ds, _)| ds) == Some(dataset) {
            names.push(snapshot.name.clone());
            by_name.entry(snapshot.name.as_str()).or_insert(snapshot);
        }
    }
    if let Some(name) = proposed_capture {
        names.push(name.to_owned());
    }
    let decisions = dataset_plan(dataset, &names, keep, now)?;
    decisions
        .into_iter()
        .filter(|decision| !decision.kept())
        .map(|decision| {
            by_name
                .get(decision.name.as_str())
                .map(|s| s.point())
                .ok_or_else(|| {
                    anyhow!(
                        "retention selected a point that was not observed: {}",
                        decision.name
                    )
                })
        })
        .collect()
}

/// Prune previewed without `-y` and without a terminal to ask: nothing
/// changed. Exit status 3, as for zboot's unconfirmed loss verbs, so a
/// script never mistakes a preview for a deletion.
#[derive(Debug)]
pub struct Unconfirmed {
    count: usize,
}
impl std::fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "not confirmed; nothing changed: no terminal to ask, pass -y to destroy these {} exact snapshot(s)",
            self.count
        )
    }
}
impl std::error::Error for Unconfirmed {}

/// Ask on the terminal, never on a script's stdin: without a terminal on both
/// stdin and stderr, refuse with [`Unconfirmed`] instead of reading.
fn confirm(count: usize) -> Result<bool> {
    use std::io::IsTerminal;
    let interactive = io::stdin().is_terminal() && io::stderr().is_terminal();
    confirm_with(
        count,
        interactive,
        &mut io::stdin().lock(),
        &mut io::stderr(),
    )
}

fn confirm_with(
    count: usize,
    interactive: bool,
    input: &mut impl io::BufRead,
    prompt: &mut impl Write,
) -> Result<bool> {
    if !interactive {
        return Err(Unconfirmed { count }.into());
    }
    write!(prompt, "Destroy {count} exact snapshot(s)? [y/N] ")?;
    prompt.flush()?;
    let mut reply = String::new();
    input.read_line(&mut reply)?;
    Ok(matches!(reply.trim(), "y" | "Y" | "yes"))
}

/// What retention deletes on DATASET as of NOW. The same state, policy and
/// NOW give an equal plan, so two plans compare what was decided.
fn retention_plan(
    state: &NativeState,
    dataset: &str,
    policy: &str,
    keep: &Keep,
    now: DateTime<Utc>,
    proposed_capture: Option<&str>,
) -> Result<RetentionDeletePlan> {
    let points = candidates(state, dataset, keep, now, proposed_capture)?;
    let selection = RetentionSelection::new(
        dataset.to_owned(),
        format!("assignment={policy:?};keep={}", keep.describe()),
        now.timestamp(),
        points,
    )?;
    Ok(delete::plan_retention_from_state(&selection, state)?)
}

/// [`retention_plan`], naming on stderr each point it leaves out.
fn retention_preview(
    state: &NativeState,
    dataset: &str,
    policy: &str,
    keep: &Keep,
    now: DateTime<Utc>,
    proposed_capture: Option<&str>,
) -> Result<RetentionDeletePlan> {
    let plan = retention_plan(state, dataset, policy, keep, now, proposed_capture)?;
    for skip in plan.skipped() {
        eprintln!(
            "{}: skipped ({})",
            zfs_tools::engine::escape_display(&skip.point.name),
            zfs_tools::engine::escape_display(&skip.reason)
        );
    }
    Ok(plan)
}

fn prune(
    dataset: Option<&str>,
    config: &Config,
    override_keep: Option<&Keep>,
    yes: bool,
    dry_run: bool,
) -> Result<()> {
    let now = now();
    // Every selected dataset's plan, from one fresh observation.
    let plan_all = |preview: bool| -> Result<Vec<RetentionDeletePlan>> {
        let state = state::observe()?;
        let plan = if preview {
            retention_preview
        } else {
            retention_plan
        };
        selected_policies(&state, config, dataset, override_keep)?
            .iter()
            .map(|(dataset, policy, keep)| plan(&state, dataset, policy, keep, now, None))
            .collect()
    };
    let plans = plan_all(true)?;
    let count: usize = plans
        .iter()
        .filter_map(|p| p.plan())
        .map(|p| p.points().len())
        .sum();
    if count == 0 {
        println!("nothing to prune");
        return Ok(());
    }
    for plan in plans.iter().filter_map(|p| p.plan()) {
        for point in plan.points() {
            println!(
                "{}{}",
                if dry_run { "DRY prune " } else { "  " },
                zfs_tools::engine::escape_display(&point.name)
            );
        }
    }
    if dry_run {
        return Ok(());
    }
    let _writer = if yes {
        None // taken at entry (`Command::locks_at_entry`)
    } else {
        if !confirm(count)? {
            bail!("prune cancelled; no snapshots were deleted");
        }
        // The prompt held no writer lock, so another writer may have run: a
        // rollback, a new assignment, a timer's prune. Each exact deletion
        // revalidates its own points, not what retention keeps, so plan again
        // under the lock and go on only if the decision is the same. This
        // compares; it enrols nothing the operator did not see.
        let writer = zfs_tools::engine::lock::for_command("zsnap", "prune")
            .map_err(|error| anyhow!("{error}"))?;
        if plan_all(false)? != plans {
            bail!(
                "the snapshots or the policy changed while prune waited for the answer; \
                 no snapshots were deleted, run it again"
            );
        }
        writer
    };
    for plan in plans.iter().filter_map(|p| p.plan()) {
        // Confirmation binds these immutable exact candidates. Replanning after
        // consent could silently enroll a newly unheld or newly eligible point.
        let outcome =
            delete::execute_snapshot_delete_with(plan, plan.loss_token(), &mut NativeDelete)?;
        report_delete(outcome)?;
    }
    Ok(())
}

fn report_delete(outcome: DeleteOutcome) -> Result<()> {
    for point in outcome.points() {
        let status = point.status();
        if status == DeletePointStatus::AbsentAfterCommand {
            println!(
                "absent after prune {}",
                zfs_tools::engine::escape_display(&point.point().name)
            );
        } else {
            eprintln!(
                "{}: {:?}{}",
                zfs_tools::engine::escape_display(&point.point().name),
                status,
                point.detail().map_or(String::new(), |message| format!(
                    " ({})",
                    zfs_tools::engine::escape_display(message)
                ))
            );
        }
        if let Some(error) = point.command_error() {
            eprintln!(
                "{}: native reply error: {}",
                zfs_tools::engine::escape_display(&point.point().name),
                zfs_tools::engine::escape_display(error)
            );
        }
    }
    let status = outcome.status();
    if status != DeleteStatus::Complete {
        bail!("prune outcome is {status:?}; re-observe before continuing");
    }
    Ok(())
}

fn run(config: &Config, dry_run: bool) -> Result<()> {
    let initial = state::observe()?;
    let now = now();
    let mut datasets: Vec<_> = initial
        .inspection
        .datasets
        .iter()
        .map(|d| d.name.clone())
        .collect();
    datasets.sort();
    let mut failures = 0;
    for dataset in datasets {
        let result = (|| -> Result<()> {
            let Some(assignment) = status::assignment(&initial.dataset_properties, &dataset)?
            else {
                return Ok(());
            };
            // A fenced pair copy carries its working copy's policy, dormant
            // until it becomes the working copy: its snapshots follow sync.
            if matches!(
                zfs_tools::engine::management::ownership(&initial, &dataset),
                Ok(zfs_tools::engine::management::Ownership::Secondary { .. })
            ) {
                println!(
                    "{}: policy {} is dormant on this fenced pair copy",
                    zfs_tools::engine::escape_display(&dataset),
                    zfs_tools::engine::escape_display(assignment)
                );
                return Ok(());
            }
            let policy = config
                .policies
                .get(assignment)
                .ok_or_else(|| anyhow!("unknown policy {assignment:?}"))?;
            run_one(&dataset, assignment, policy, now, dry_run)
        })();
        if let Err(error) = result {
            failures += 1;
            eprintln!(
                "{}: {}",
                zfs_tools::engine::escape_display(&dataset),
                zfs_tools::engine::escape_display(&format!("{error:#}"))
            );
        }
    }
    if failures > 0 {
        bail!("{failures} dataset(s) failed");
    }
    Ok(())
}

fn run_one(
    dataset: &str,
    assignment: &str,
    policy: &crate::Policy,
    now: DateTime<Utc>,
    dry_run: bool,
) -> Result<()> {
    let before = state::observe()?;
    if status::assignment(&before.dataset_properties, dataset)? != Some(assignment) {
        bail!("policy assignment changed since discovery");
    }
    exact_scope(&before, &[dataset.to_owned()])?;
    let observed_dataset = before
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == dataset)
        .ok_or_else(|| anyhow!("dataset was not observed"))?;
    let newest = before
        .inspection
        .snapshots
        .as_ref()
        .ok_or_else(|| anyhow!("snapshot history was not observed"))?
        .iter()
        .filter_map(|snapshot| {
            owned_snap_time(&snapshot.name, dataset).map(|time| (snapshot, time))
        })
        .max_by_key(|(_, time)| *time);
    let should_take = should_capture(
        newest.as_ref().map(|(_, time)| *time),
        policy.frequency,
        now,
        || {
            let snapshot = newest.unwrap().0;
            Ok(
                zfs_tools::engine::observe_written_since(observed_dataset, &snapshot.point())?
                    .referenced_new_bytes,
            )
        },
    )?;
    let proposed = should_take.then(|| snap_name(dataset, now));
    let after = if should_take && !dry_run {
        take(&[dataset.to_owned()], now)?;
        state::observe()?
    } else {
        before
    };
    if let Some(name) = &proposed
        && dry_run
    {
        println!("DRY capture {}", zfs_tools::engine::escape_display(name));
    }
    if status::assignment(&after.dataset_properties, dataset)? != Some(assignment) {
        bail!("policy assignment changed before pruning");
    }
    let plan = retention_preview(
        &after,
        dataset,
        assignment,
        &policy.keep,
        now,
        if dry_run { proposed.as_deref() } else { None },
    )?;
    if dry_run {
        if let Some(plan) = plan.plan() {
            for point in plan.points() {
                println!(
                    "DRY prune {}",
                    zfs_tools::engine::escape_display(&point.name)
                );
            }
        }
    } else {
        report_delete(delete::execute_retention_with(&plan, &mut NativeDelete)?)?;
    }
    Ok(())
}

/// The written-byte metric is a scheduling heuristic, not clean-head evidence.
/// Keep it lazy: a recent snapshot or empty history needs no native metric read.
fn should_capture(
    newest: Option<DateTime<Utc>>,
    frequency: i64,
    now: DateTime<Utc>,
    written: impl FnOnce() -> Result<u64>,
) -> Result<bool> {
    if !snapshot_due(newest, frequency, now)? {
        return Ok(false);
    }
    match newest {
        None => Ok(true),
        Some(_) => Ok(written()? > 0),
    }
}

fn machine_assignment(
    path: &std::path::Path,
    config: &Config,
    dataset: &str,
    change: crate::transport::PolicyChange,
) -> Result<()> {
    use std::io::Read;
    let mut bytes = Vec::new();
    let reader: Box<dyn Read> = if path == std::path::Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    reader.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        bail!("policy request exceeds 4 MiB");
    }
    let request: crate::transport::PolicyRequest = serde_json::from_slice(&bytes)?;
    if request.expected.dataset != dataset || request.change != change {
        bail!("request dataset/change differs from command");
    }
    let result = crate::transport::apply_policy(config, &request)?;
    println!("{}", serde_json::to_string(&result)?);
    if result.outcome.status != PolicyStatus::Complete {
        bail!("policy outcome uncertain; re-observe before continuing");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_stdout_is_a_complete_lossless_name_set_or_empty_on_failure() {
        let points: Vec<_> = ["tank/a space", r"tank/b\slash"]
            .into_iter()
            .enumerate()
            .map(|(index, dataset)| {
                let point = SnapshotRef {
                    name: format!("{dataset}@zsnap_2026-09-08-120000"),
                    dataset_guid: zfs_tools::engine::Guid::new(10 + index as u64),
                    identity: zfs_tools::engine::SnapshotIdentity {
                        pool_guid: zfs_tools::engine::Guid::new(1),
                        guid: zfs_tools::engine::Guid::new(20 + index as u64),
                        createtxg: zfs_tools::engine::Txg::new(30),
                        objsetid: zfs_tools::engine::ObjsetId::new(40 + index as u64),
                    },
                };
                zfs_tools::engine::validate_snapshot_name(&point.name).unwrap();
                point
            })
            .collect();
        let outcome = CaptureOutcome::from_parts(
            "capture-operation".into(),
            CaptureStatus::Complete,
            points.clone(),
            vec![],
            None,
        );
        let mut output = Vec::new();
        write_capture(&outcome, &mut output).unwrap();
        assert_eq!(
            output,
            b"tank/a space@zsnap_2026-09-08-120000\ntank/b\\slash@zsnap_2026-09-08-120000\n"
        );
        let mut points = points;
        let missing = points.pop().unwrap().name;
        for status in [CaptureStatus::Partial, CaptureStatus::Uncertain] {
            let outcome = CaptureOutcome::from_parts(
                "capture-operation".into(),
                status,
                points.clone(),
                vec![missing.clone()],
                Some("native capture reply failed".into()),
            );
            output.clear();
            let error = write_capture(&outcome, &mut output)
                .unwrap_err()
                .to_string();
            assert!(
                output.is_empty(),
                "incomplete capture emitted successful names"
            );
            assert!(error.contains(outcome.operation_id()));
            assert!(error.contains(&format!("{status:?}")));
            assert!(error.contains(&serde_json::to_string(outcome.points()).unwrap()));
            assert!(error.contains(&missing));
            assert!(error.contains(outcome.detail().unwrap()));
        }
    }

    #[test]
    fn timer_frequency_is_lazy_and_metric_failure_is_not_no_change() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        assert!(
            should_capture(None, 900, now, || panic!(
                "empty history queried written bytes"
            ))
            .unwrap()
        );
        assert!(
            !should_capture(Some(now), 900, now, || panic!(
                "recent history queried written bytes"
            ))
            .unwrap()
        );
        let old = now - chrono::Duration::seconds(900);
        assert!(!should_capture(Some(old), 900, now, || Ok(0)).unwrap());
        assert!(should_capture(Some(old), 900, now, || Ok(1)).unwrap());
        assert!(should_capture(Some(old), 900, now, || bail!("query failed")).is_err());
    }

    fn fixture() -> NativeState {
        let (inspection, dataset_properties) = crate::status::tests::fixture();
        NativeState {
            inspection,
            dataset_properties,
            pool_properties: Default::default(),
        }
    }

    #[test]
    fn candidates_bind_owned_exact_incarnations_and_preview_post_capture() {
        let state = fixture();
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let keep_none = Keep {
            last: Some(0),
            ..Default::default()
        };
        let points = candidates(&state, "tank/data", &keep_none, now, None).unwrap();
        assert_eq!(points.len(), 1);
        assert!(points[0].name.contains("@zsnap_"));
        assert_eq!(points[0].identity.guid.get(), 3);
        assert_eq!(points[0].dataset_guid.get(), 2);
        let keep = Keep {
            last: Some(1),
            ..Default::default()
        };
        assert!(
            candidates(&state, "tank/data", &keep, now, None)
                .unwrap()
                .is_empty()
        );
        let proposed = snap_name("tank/data", now);
        assert_eq!(
            candidates(&state, "tank/data", &keep, now, Some(&proposed)).unwrap(),
            points
        );
    }

    #[test]
    fn absent_unknown_and_explicit_override_policy_resolution() {
        let mut state = fixture();
        let config = Config::from_override(None).unwrap();
        let selected = selected_policies(&state, &config, None, None).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, "tank/data");
        state
            .dataset_properties
            .get_mut("tank/data")
            .unwrap()
            .get_mut(crate::POLICY_PROPERTY)
            .unwrap()
            .value = "missing".into();
        assert!(selected_policies(&state, &config, None, None).is_err());
        let override_keep = Keep {
            last: Some(0),
            ..Default::default()
        };
        let overridden =
            selected_policies(&state, &config, Some("tank/data"), Some(&override_keep)).unwrap();
        assert_eq!(overridden[0].2.last, Some(0));
        assert!(selected_policies(&state, &config, Some("tank"), None).is_err());
        assert!(
            selected_policies(&state, &config, Some("tank/missing"), Some(&override_keep)).is_err()
        );
    }

    #[test]
    fn prune_never_reads_a_scripts_stdin_for_consent() {
        // Without a terminal the answer is never read, even a "y".
        let mut input = io::Cursor::new(b"y\n".to_vec());
        let mut prompt = Vec::new();
        let error = confirm_with(2, false, &mut input, &mut prompt).unwrap_err();
        assert!(error.is::<Unconfirmed>());
        assert_eq!(
            error.to_string(),
            "not confirmed; nothing changed: no terminal to ask, pass -y to destroy these 2 exact snapshot(s)"
        );
        assert_eq!(input.position(), 0);
        assert!(prompt.is_empty());
        // On a terminal the operator answers the prompt.
        for (reply, accepted) in [
            ("y\n", true),
            ("yes\n", true),
            ("\n", false),
            ("n\n", false),
        ] {
            let mut input = io::Cursor::new(reply.as_bytes().to_vec());
            let mut prompt = Vec::new();
            assert_eq!(
                confirm_with(2, true, &mut input, &mut prompt).unwrap(),
                accepted
            );
            assert_eq!(prompt, b"Destroy 2 exact snapshot(s)? [y/N] ");
        }
    }
}
