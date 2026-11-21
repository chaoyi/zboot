//! `pair`, `unpair`, `sync` and `primary` on the command line. Each runs
//! directly unless its plan can lose data or rests on the operator's word
//! (†): a takeover, a one-sided unpair or released anchors. Those print the
//! plan and take the typed target or `--confirm TOKEN`. `sync` runs either
//! way; only its pending deletions wait for the typed summary or the token.
use super::run::{
    applied_operation, consent_to, dialogue, json_response, review, writer_for, writer_for_replan,
};
use crate::{
    consent::{self, Envelope, Outcome, Typed},
    pairs::{self, PrimaryPlan, SyncTarget, UnpairPlan},
};
use std::{error::Error, io::Write};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

/// Shared confirmation flags for pair verbs.
pub(super) struct ConsentFlags {
    pub dry_run: bool,
    pub confirm: Option<String>,
    pub json: bool,
}

/// The envelope (or human summary) of a verb that ran. A verb whose effects
/// stand but whose follow-up (the boot default) failed is `partial`
/// and exits 4.
fn report(
    json: bool,
    token: Option<String>,
    operation: Option<String>,
    complete: bool,
    result: impl serde::Serialize,
    human: String,
) -> Result {
    if !json {
        print!("{human}");
    }
    applied_operation(json, token, operation.as_deref(), complete, result)
}
/// Go on with `planned` directly, or through typed consent when it is † or
/// the operator asked for a preview or passed a token. Either way the writer
/// lock is taken only now, after the plan (and any answer); the engine plans
/// again under it and refuses a changed plan.
pub(super) fn consent<P: serde::Serialize>(
    planned: P,
    dagger: bool,
    flags: ConsentFlags,
    plan: impl Fn() -> Result<P>,
    token: impl Fn(&P) -> std::io::Result<String>,
    describe: impl Fn(&P, &str) -> String,
    target: impl Fn(&P) -> Typed,
) -> Result<Option<(P, String)>> {
    if dagger || flags.dry_run || flags.confirm.is_some() {
        return consent_to(
            flags.dry_run,
            flags.confirm,
            flags.json,
            plan,
            token,
            describe,
            target,
        );
    }
    let token = token(&planned)?;
    writer_for(&planned)?;
    Ok(Some((planned, token)))
}
fn dataset_target(name: &str) -> Typed {
    Typed {
        what: "the dataset name",
        text: name.into(),
    }
}

pub(super) fn pair(
    left: String,
    right: String,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result {
    let request = crate::pairs::plan::PairRequest {
        left,
        right,
        primary: Some(crate::history::Side::Left),
    };
    let Some((plan, token)) = review(
        dry_run,
        confirm,
        json,
        // The plan's own refusal says when to swap PRIMARY and SECONDARY.
        || crate::pairs::plan::plan(&request).map_err(Into::into),
        consent::token,
        |plan, token| format!("{}Token {token}\n", pairs::describe::pair(plan)),
    )?
    else {
        return Ok(());
    };
    let result = pairs::pair_prepared(&plan)?;
    let o = &result.outcome;
    let human = pairs::describe::paired(&result);
    let operation = (!o.already_paired).then(|| o.operation_id.clone());
    report(json, Some(token), operation, true, &result, human)
}
pub(super) fn unpair(
    dataset: String,
    release_anchors: bool,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result {
    let plan_now = || -> Result<UnpairPlan> { Ok(pairs::unpair_plan(&dataset, release_anchors)?) };
    let first = plan_now()?;
    let dagger = first.confirms();
    let Some((plan, token)) = consent(
        first,
        dagger,
        ConsentFlags {
            dry_run,
            confirm,
            json,
        },
        plan_now,
        consent::token,
        |p, token| format!("{}Token {token}\n", pairs::describe::unpair(p)),
        |p| dataset_target(&p.dataset.name),
    )?
    else {
        return Ok(());
    };
    let result = pairs::unpair(&plan)?;
    let human = pairs::describe::unpaired(&result);
    report(
        json,
        Some(token),
        result.operation_id.clone(),
        true,
        &result,
        human,
    )
}
pub(super) fn sync(
    source: Option<String>,
    destination: Option<String>,
    all: bool,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result {
    let target = match (source, destination, all) {
        (_, _, true) => SyncTarget::All,
        (Some(source), Some(destination), false) => SyncTarget::Between {
            source,
            destination,
        },
        (Some(dataset), None, false) => SyncTarget::Pair(dataset),
        (None, _, false) => return Err("name a pair root, SRC DEST, or --all".into()),
    };
    let plan_now = || -> Result<pairs::SyncPlan> { Ok(pairs::sync_plan(&target)?) };
    let planned = plan_now()?;
    let shown = planned.token()?;
    if let Some(given) = confirm.as_deref() {
        consent::unchanged(given, &shown)?;
    }
    if dry_run {
        if json {
            json_response(Envelope::new(Outcome::Preview, Some(shown), &planned))?;
        } else {
            print!("{}", pairs::describe::sync_plan(&planned, &shown));
            println!("Dry run; nothing changed.");
        }
        return Ok(());
    }
    // The transfer runs in every case. The pending deletions go only with
    // the token, or with the summary typed on a terminal; with neither (a
    // timer) they are kept and reported.
    let delete = match (&confirm, planned.summary()) {
        (Some(_), _) => true,
        (None, Some(summary))
            if consent::Mode::select(false, None) == consent::Mode::Interactive =>
        {
            let mut out = dialogue(json);
            write!(out, "{}", pairs::describe::sync_plan(&planned, &shown))?;
            out.flush()?;
            let mut input =
                std::io::BufReader::with_capacity(1, std::fs::File::open("/proc/self/fd/0")?);
            consent::optional(
                &Typed {
                    what: "the summary",
                    text: summary,
                },
                "delete them before the transfer",
                "keep them (the transfer runs either way)",
                &mut input,
                &mut std::io::stderr(),
            )?
        }
        _ => false,
    };
    writer_for_replan(&planned, &plan_now, delete)?;
    let fresh = plan_now()?;
    let token = fresh.token()?;
    if delete {
        consent::unchanged(&shown, &token)?;
    }
    report_synced(&target, pairs::sync_prepared(&fresh, delete)?, token, json)
}

pub(super) fn report_synced(
    target: &SyncTarget,
    entries: Vec<pairs::SyncEntry>,
    token: String,
    json: bool,
) -> Result {
    let human = pairs::describe::synced(&entries);
    if *target == SyncTarget::All {
        // A child inside a pair is a layout problem that needs action: the
        // run reports it as unfinished, although the leaves were synced.
        let complete = entries.iter().all(|e| {
            e.result
                .as_ref()
                .is_some_and(|r| r.transfer.unmirrored.is_empty())
        });
        return report(
            json,
            Some(token),
            None,
            complete,
            pairs::SyncAll {
                pairs: entries,
                complete,
            },
            human,
        );
    }
    let result = entries
        .into_iter()
        .next()
        .and_then(|e| e.result)
        .ok_or("sync returned no result")?;
    let id = result.transfer.operation_id.clone();
    report(json, Some(token), Some(id), true, &result, human)
}

pub(super) fn primary(
    dataset: String,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result {
    let plan_now = || -> Result<PrimaryPlan> { Ok(pairs::primary_plan(&dataset)?) };
    let first = plan_now()?;
    let dagger = first.confirms();
    let Some((plan, token)) = consent(
        first,
        dagger,
        ConsentFlags {
            dry_run,
            confirm,
            json,
        },
        plan_now,
        PrimaryPlan::token,
        |p, token| format!("{}Token {token}\n", pairs::describe::primary(p)),
        |p| dataset_target(p.typed_target()),
    )?
    else {
        return Ok(());
    };
    let result = pairs::primary(&plan)?;
    let complete = result.complete();
    let human = pairs::describe::switched(&result);
    report(
        json,
        Some(token),
        result.operation_id.clone(),
        complete,
        &result,
        human,
    )
}
