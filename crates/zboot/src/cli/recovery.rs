//! Command-line restore and interrupted-operation recovery.
use super::{
    grammar::Consent,
    run::{
        Invocation, applied, applied_operation, consent_to, dialogue, json_response, writer_for,
    },
};

pub(super) fn restore_backend() -> crate::restore::Native {
    crate::restore::Native::new()
}

fn restore_plan(
    request: &crate::restore::Request,
    id: &str,
) -> Result<crate::restore::Plan, Box<dyn std::error::Error>> {
    Ok(crate::restore::plan(&mut restore_backend(), request, id)?)
}

fn resume_plan(id: &str) -> Result<crate::restore::ResumePlan, Box<dyn std::error::Error>> {
    Ok(crate::restore::resume_plan(&mut restore_backend(), id)?)
}

fn cleanup_restore<T>(
    backend: &mut crate::restore::Native,
    result: crate::menu::Result<T>,
) -> Result<T, Box<dyn std::error::Error>> {
    if super::access::Env::detect() == super::access::Env::Uki
        && let Err(cleanup) = backend.cleanup_imported_target()
    {
        return Err(format!(
            "{}. Restore target cleanup failed. {cleanup}",
            result
                .err()
                .map_or_else(|| "The restore completed".into(), |error| error.to_string())
        )
        .into());
    }
    result.map_err(Into::into)
}

fn print_completed(
    inv: &mut Invocation,
    token: Option<String>,
    done: &crate::restore::Completed,
) -> Result<(), Box<dyn std::error::Error>> {
    if inv.json {
        let mut envelope =
            crate::consent::Envelope::new(crate::consent::Outcome::Applied, token, done);
        envelope.operation = Some(done.id.clone());
        return json_response(inv, envelope);
    }
    println!(
        "Restored {} on pool {}; it is the boot default.",
        zfs_tools::engine::escape_display(&done.be),
        zfs_tools::engine::escape_display(&done.pool)
    );
    for note in &done.notes {
        println!("  {}", zfs_tools::engine::escape_display(note));
    }
    Ok(())
}

pub(super) fn restore(
    request: crate::restore::Request,
    consent: Consent,
    inv: &mut Invocation,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::restore;
    let id = restore::new_id();
    let Some((plan, token)) = consent_to(
        inv,
        consent,
        || restore_plan(&request, &id),
        |plan| Ok(plan.token.clone()),
        |plan, _| restore::render(plan),
        |plan| plan.typed(),
    )?
    else {
        return Ok(());
    };
    let mut dialogue = dialogue(inv.json);
    zfs_tools::engine::effect::operation_hint(&id);
    let mut backend = restore_backend();
    let result = restore::Run::start(&mut backend, &plan, &mut dialogue);
    match cleanup_restore(&mut backend, result) {
        Ok(done) => print_completed(inv, Some(token), &done),
        Err(error) => Err(format!("{error}. Restore {id} stopped").into()),
    }
}

fn selected_operation(
    listing: &crate::restore::Listing,
    verb: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if listing.operations.is_empty() && listing.orphans.is_empty() {
        return Err(format!("no interrupted operation to {verb}; inspect zboot status").into());
    }
    if let [operation] = listing.operations.as_slice()
        && listing.orphans.is_empty()
        && let Some(id) = &operation.id
    {
        return Ok(id.clone());
    }
    let mut message = format!("choose an operation with zboot {verb} ID; inspect zboot status");
    for operation in &listing.operations {
        message.push_str(&format!(
            "\n  {} on pool {} ({})",
            zfs_tools::engine::escape_display(
                operation.id.as_deref().unwrap_or("unreadable record")
            ),
            zfs_tools::engine::escape_display(&operation.pool),
            zfs_tools::engine::escape_display(operation.kind.as_deref().unwrap_or("unreadable")),
        ));
    }
    for orphan in &listing.orphans {
        message.push_str(&format!(
            "\n  {}",
            zfs_tools::engine::escape_display(&orphan.describe())
        ));
    }
    Err(message.into())
}

/// The engine that continues a one-record operation of `kind`: the pairs
/// engine for pair verbs, the tree engine for tree verbs, and the default
/// engine for a cross-pool `default`. Restore records have none.
fn resume_engine(kind: &str) -> Option<ResumeEngine> {
    if crate::pairs::KINDS.contains(&kind) {
        Some(crate::pairs::resume_outcome)
    } else if crate::tree::KINDS.contains(&kind) {
        Some(crate::tree::resume_outcome)
    } else if kind == crate::boot_support::default::KIND {
        Some(crate::boot_support::default::resume_outcome)
    } else {
        None
    }
}
type ResumeEngine = fn(
    zfs_tools::engine::intent::Intent<serde_json::Value>,
    bool,
    &mut dyn std::io::Write,
) -> Result<crate::pairs::ResumeOutcome, zfs_tools::engine::Error>;

/// The record is the complete token, in the UKI as on a host.
fn one_record_token(
    record: &zfs_tools::engine::intent::Intent<serde_json::Value>,
) -> std::io::Result<String> {
    crate::consent::token(&(&record.id, &record.kind, record.step, &record.state))
}

/// A pair, tree or default record: its engine continues it without new
/// consent; abandoning it, which destroys nothing, is typed against the
/// operation id like a restore's. An engine that reports its follow-up
/// incomplete leaves the record resumable, and the command fails.
fn resume_one(
    record: zfs_tools::engine::intent::Intent<serde_json::Value>,
    abandon: bool,
    consent: Consent,
    inv: &mut Invocation,
    engine: ResumeEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = record.id.clone();
    let kind = record.kind.clone();
    let shown = one_record_token;
    let reread =
        || -> Result<zfs_tools::engine::intent::Intent<serde_json::Value>, Box<dyn std::error::Error>> {
            let record = crate::restore::record(&mut restore_backend(), &id)?
                .ok_or_else(|| format!("operation {id} is no longer recorded"))?
                .1;
            if record.kind != kind {
                return Err(format!("operation {id} changed kind; nothing was done").into());
            }
            Ok(record)
        };
    let verb = if abandon { "Abandon" } else { "Continue" };
    let Some((record, token)) = (if abandon {
        consent_to(
            inv,
            consent,
            reread,
            shown,
            |record, token| {
                format!(
                    "{verb} {} {} after step {}: nothing is destroyed.\n  Token: {token}\n",
                    zfs_tools::engine::escape_display(&record.kind),
                    zfs_tools::engine::escape_display(&record.id),
                    record.step
                )
            },
            |record| crate::consent::Typed {
                what: "the operation id",
                text: record.id.clone(),
            },
        )?
    } else if consent.dry_run {
        let record = reread()?;
        let token = shown(&record)?;
        if inv.json {
            json_response(
                inv,
                crate::consent::Envelope::new(
                    crate::consent::Outcome::Preview,
                    Some(token),
                    &record,
                ),
            )?;
        } else {
            println!(
                "{verb} {} {} after step {}; dry run, nothing changed.",
                zfs_tools::engine::escape_display(&record.kind),
                zfs_tools::engine::escape_display(&record.id),
                record.step
            );
        }
        None
    } else {
        // A token is checked before the lock, whose pool reopen is an effect,
        // and the record again under it.
        let record = reread()?;
        let token = shown(&record)?;
        continue_token(&id, consent.confirm.as_deref(), Some(&token))?;
        writer_for(inv, &record)?;
        let fresh = reread()?;
        crate::consent::unchanged(&token, &shown(&fresh)?)?;
        Some((fresh, token))
    }) else {
        return Ok(());
    };
    if record.kind != kind {
        return Err(format!("operation {id} changed kind; nothing was done").into());
    }
    let mut dialogue = dialogue(inv.json);
    zfs_tools::engine::effect::operation_hint(&id);
    let outcome = engine(record, abandon, &mut dialogue)?;
    applied_operation(
        inv,
        Some(token),
        Some(&id),
        outcome.complete,
        &outcome.result,
    )?;
    if !inv.json {
        println!(
            "{} operation {}.",
            if abandon { "Abandoned" } else { "Continued" },
            zfs_tools::engine::escape_display(&id)
        );
    }
    Ok(())
}

/// `resume ID --confirm TOKEN` where continuing needs no consent: the token
/// is still checked against the record's preview (`shown`), and refused when
/// the preview has none, so a stale or meaningless token is never ignored.
fn continue_token(
    id: &str,
    confirm: Option<&str>,
    shown: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match (confirm, shown) {
        (None, _) => Ok(()),
        (Some(confirm), Some(shown)) if confirm == shown => Ok(()),
        (Some(_), Some(_)) => Err(std::io::Error::from(crate::consent::Stale).into()),
        (Some(_), None) => Err(format!(
            "operation {id} has no erase ahead, so --confirm names nothing. Resume it without --confirm"
        ).into()),
    }
}

pub(super) fn resume(
    id: Option<String>,
    abandon: bool,
    consent: Consent,
    inv: &mut Invocation,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::restore;
    use std::io::Write;
    let id = match id {
        Some(id) => id,
        None => selected_operation(
            &restore::list(&mut restore_backend())?,
            if abandon { "abandon" } else { "resume" },
        )?,
    };
    zfs_tools::engine::effect::operation_hint(&id);
    // Dispatch by the record's kind; restore records and unknown ids go to
    // the restore engine, which refuses unknown ids and other kinds.
    if let Some((_, record)) = restore::record(&mut restore_backend(), &id)?
        && let Some(engine) = resume_engine(&record.kind)
    {
        return resume_one(record, abandon, consent, inv, engine);
    }
    if abandon {
        let Some((preview, token)) = consent_to(
            inv,
            consent,
            || Ok(restore::abandon_plan(&mut restore_backend(), &id)?),
            |preview| Ok(preview.token.clone()),
            |preview, token| {
                format!(
                    "Abandon restore {id} after step {}: nothing is destroyed; {}.\n  Token: {token}\n",
                    preview.step,
                    if preview.releases {
                        "redundant staging stays in place; restore holds on deferred snapshots stay, and ordinary holds are released"
                    } else {
                        "staging may be the only complete copy of the kept data, so its holds stay; ordinary source holds are released and deferred snapshots stay held"
                    }
                )
            },
            |_| crate::consent::Typed {
                what: "the operation id",
                text: id.clone(),
            },
        )?
        else {
            return Ok(());
        };
        debug_assert_eq!(preview.id, id);
        let abandoned = restore::abandon(&mut restore_backend(), &id)?;
        if inv.json {
            return applied(inv, Some(token), &abandoned);
        }
        println!("Abandoned restore {id}. Left in place:");
        for left in &abandoned.left {
            println!("  {}", zfs_tools::engine::escape_display(left));
        }
        return Ok(());
    }
    let plan = resume_plan(&id)?;
    let plan = if plan.typed().is_some() {
        // An erase of A is ahead or was interrupted: a fresh typed answer.
        let Some((plan, _)) = consent_to(
            inv,
            consent,
            || resume_plan(&id),
            |plan| {
                plan.token.clone().ok_or_else(|| {
                    std::io::Error::other(
                        "the restore no longer has an erase ahead; run resume again",
                    )
                })
            },
            |plan, token| {
                let Some(review) = &plan.erase else {
                    return String::new();
                };
                format!(
                    "Restore {id}: last completed step {}\n  Continuing ERASES {} serial {} wwn {} ({} partitions) and recreates pool {}.\n  Token: {token}\n",
                    plan.step,
                    zfs_tools::engine::escape_display(&review.identity.path),
                    zfs_tools::engine::escape_display(
                        review.identity.serial.as_deref().unwrap_or("-")
                    ),
                    zfs_tools::engine::escape_display(
                        review.identity.wwn.as_deref().unwrap_or("-")
                    ),
                    review.partitions.len(),
                    zfs_tools::engine::escape_display(&plan.state.pool)
                )
            },
            |plan| plan.typed().expect("an erase is ahead"),
        )?
        else {
            return Ok(());
        };
        plan
    } else {
        continue_token(&id, consent.confirm.as_deref(), None)?;
        let mut dialogue = dialogue(inv.json);
        writeln!(dialogue, "Restore {id}: last completed step {}", plan.step)?;
        if consent.dry_run {
            writeln!(dialogue, "Dry run; nothing changed.")?;
            if inv.json {
                json_response(
                    inv,
                    crate::consent::Envelope::new(crate::consent::Outcome::Preview, None, &plan),
                )?;
            }
            return Ok(());
        }
        writer_for(inv, &plan)?;
        let fresh = resume_plan(&id)?;
        if fresh.token.is_some() {
            return Err(
                "an erase of the target disk is now ahead; run resume again to confirm it".into(),
            );
        }
        fresh
    };
    let mut dialogue = dialogue(inv.json);
    let mut backend = restore_backend();
    let result = restore::Run::resume(&mut backend, &id, plan.erase_layout()?, &mut dialogue);
    let done = cleanup_restore(&mut backend, result)?;
    print_completed(inv, plan.token, &done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omission_selects_one_operation_and_lists_ambiguous_records() {
        let mut listing = crate::restore::Listing {
            operations: vec![],
            orphans: vec![],
        };
        assert!(
            selected_operation(&listing, "resume")
                .unwrap_err()
                .to_string()
                .contains("no interrupted")
        );
        let operation = crate::restore::Listed {
            pool: "rpool".into(),
            id: Some("first".into()),
            kind: Some("fork".into()),
            step: Some("1".into()),
            detail: None,
        };
        listing.operations.push(operation.clone());
        assert_eq!(selected_operation(&listing, "resume").unwrap(), "first");
        listing.operations.push(crate::restore::Listed {
            id: Some("second".into()),
            ..operation
        });
        let message = selected_operation(&listing, "abandon")
            .unwrap_err()
            .to_string();
        assert!(message.contains("zboot abandon ID"));
        assert!(message.contains("first") && message.contains("second"));
        listing.operations.truncate(1);
        listing.orphans.push(crate::restore::Orphan {
            dataset: "rpool/data".into(),
            attachment: "orphan:plan".into(),
            pool: "rpool".into(),
            record: crate::restore::PoolRecord::Nothing,
        });
        assert!(selected_operation(&listing, "resume").is_err());
        listing.orphans.clear();
        listing.operations[0].id = None;
        assert!(selected_operation(&listing, "resume").is_err());
    }

    #[test]
    fn a_one_record_token_is_the_record_in_the_uki_as_on_a_host() {
        let record = zfs_tools::engine::intent::Intent::new(
            "11111111-1111-4111-8111-111111111111",
            "sync",
            serde_json::json!({
                "source": "a/data", "destination": "b/data", "bootstrap": true,
            }),
        );
        assert_eq!(
            one_record_token(&record).unwrap(),
            crate::consent::token(&(&record.id, &record.kind, record.step, &record.state,))
                .unwrap()
        );
    }

    #[test]
    fn a_continue_token_is_checked_never_ignored() {
        assert!(continue_token("op", None, Some("t1")).is_ok());
        assert!(continue_token("op", None, None).is_ok());
        assert!(continue_token("op", Some("t1"), Some("t1")).is_ok());
        let stale = continue_token("op", Some("t0"), Some("t1")).unwrap_err();
        assert!(crate::consent::is_stale(stale.as_ref()), "{stale}");
        let meaningless = continue_token("op", Some("t1"), None).unwrap_err();
        assert!(
            meaningless.to_string().contains("names nothing"),
            "{meaningless}"
        );
    }

    #[test]
    fn resume_dispatches_every_one_record_kind_to_a_typed_engine() {
        for kind in crate::pairs::KINDS
            .iter()
            .chain(crate::tree::KINDS.iter())
            .chain([&crate::boot_support::default::KIND])
        {
            assert!(resume_engine(kind).is_some(), "{kind}");
        }
        assert!(resume_engine(crate::restore::KIND).is_none());
    }
}
