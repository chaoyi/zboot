//! `pair`, `unpair`, `sync` and `primary` on the command line. `pair` loses
//! nothing and takes no token. The others run directly unless their plan can
//! lose data or rests on the operator's word (†): a takeover, a one-sided
//! unpair or released anchors. Those print the plan and take the typed target
//! or `--confirm TOKEN`. `sync` runs either way; only its pending deletions
//! wait for the typed summary or the token.
use super::{
    grammar::Consent,
    run::{
        Invocation, applied_operation, consent_to, dialogue, json_response, lossless, writer_for,
        writer_for_replan,
    },
};
use crate::{
    consent::{self, Envelope, Outcome, Typed},
    pairs::{self, PrimaryPlan, SyncTarget, UnpairPlan},
};
use std::{error::Error, io::Write};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

/// The envelope (or human summary) of a verb that ran. A verb whose effects
/// stand but whose follow-up (the boot default) failed is `partial`
/// and exits 4.
fn report(
    inv: &mut Invocation,
    token: Option<String>,
    operation: Option<String>,
    complete: bool,
    result: impl serde::Serialize,
    human: String,
) -> Result {
    if !inv.json {
        print!("{human}");
    }
    applied_operation(inv, token, operation.as_deref(), complete, result)
}
/// Go on with `planned` directly, or through typed consent when it is † or
/// the operator asked for a preview or passed a token. Either way the writer
/// lock is taken only now, after the plan (and any answer); the engine plans
/// again under it and refuses a changed plan.
#[allow(clippy::too_many_arguments)]
pub(super) fn consent<P: serde::Serialize>(
    planned: P,
    dagger: bool,
    consent: Consent,
    inv: &mut Invocation,
    plan: impl Fn() -> Result<P>,
    token: impl Fn(&P) -> std::io::Result<String>,
    describe: impl Fn(&P, &str) -> String,
    target: impl Fn(&P) -> Typed,
) -> Result<Option<(P, String)>> {
    if dagger || consent.dry_run || consent.confirm.is_some() {
        return consent_to(inv, consent, plan, token, describe, target);
    }
    let token = token(&planned)?;
    writer_for(inv, &planned)?;
    Ok(Some((planned, token)))
}
fn dataset_target(name: &str) -> Typed {
    Typed {
        what: "the dataset name",
        text: name.into(),
    }
}

pub(super) fn pair(left: String, right: String, dry_run: bool, inv: &mut Invocation) -> Result {
    let request = crate::pairs::plan::PairRequest {
        left,
        right,
        primary: Some(crate::history::Side::Left),
    };
    let Some(plan) = lossless(
        inv,
        dry_run,
        // The plan's own refusal says when to swap PRIMARY and SECONDARY.
        || crate::pairs::plan::plan(&request).map_err(Into::into),
        pairs::describe::pair,
    )?
    else {
        return Ok(());
    };
    let result = pairs::pair_prepared(&plan)?;
    let o = &result.outcome;
    let human = pairs::describe::paired(&result);
    let operation = (!o.already_paired).then(|| o.operation_id.clone());
    report(inv, None, operation, true, &result, human)
}
pub(super) fn unpair(
    dataset: String,
    release_anchors: bool,
    flags: Consent,
    inv: &mut Invocation,
) -> Result {
    let plan_now = || -> Result<UnpairPlan> { Ok(pairs::unpair_plan(&dataset, release_anchors)?) };
    let first = plan_now()?;
    let dagger = first.confirms();
    let Some((plan, token)) = consent(
        first,
        dagger,
        flags,
        inv,
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
        inv,
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
    consent: Consent,
    inv: &mut Invocation,
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
    if let Some(given) = consent.confirm.as_deref() {
        consent::unchanged(given, &shown)?;
    }
    if consent.dry_run {
        if inv.json {
            json_response(inv, Envelope::new(Outcome::Preview, Some(shown), &planned))?;
        } else {
            print!("{}", pairs::describe::sync_plan(&planned, &shown));
            println!("Dry run; nothing changed.");
        }
        return Ok(());
    }
    // The transfer runs in every case. The pending deletions go only with
    // the token, or with the summary typed on a terminal; with neither (a
    // timer) they are kept and reported.
    let delete = match (&consent.confirm, planned.summary()) {
        (Some(_), _) => true,
        (None, Some(summary))
            if consent::Mode::select(false, None) == consent::Mode::Interactive =>
        {
            let mut out = dialogue(inv.json);
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
    writer_for_replan(inv, &planned, &plan_now, delete)?;
    let fresh = plan_now()?;
    let token = fresh.token()?;
    if delete {
        consent::unchanged(&shown, &token)?;
    }
    report_synced(&target, pairs::sync_prepared(&fresh, delete)?, token, inv)
}

pub(super) fn report_synced(
    target: &SyncTarget,
    entries: Vec<pairs::SyncEntry>,
    token: String,
    inv: &mut Invocation,
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
            inv,
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
    report(inv, Some(token), Some(id), true, &result, human)
}

pub(super) fn primary(dataset: String, flags: Consent, inv: &mut Invocation) -> Result {
    let plan_now = || -> Result<PrimaryPlan> { Ok(pairs::primary_plan(&dataset)?) };
    let first = plan_now()?;
    let dagger = first.confirms();
    let Some((plan, token)) = consent(
        first,
        dagger,
        flags,
        inv,
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
        inv,
        Some(token),
        result.operation_id.clone(),
        complete,
        &result,
        human,
    )
}
