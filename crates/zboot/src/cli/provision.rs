//! Provisioning command glue.
use super::{
    grammar::Consent,
    run::{Invocation, applied, applied_operation, consent_to, json_response, lossless},
};
use std::error::Error;

#[derive(serde::Serialize)]
struct WipePlan {
    #[serde(flatten)]
    review: crate::device::DiskReview,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<crate::device::DiskScope>,
}

impl WipePlan {
    fn token(&self) -> std::io::Result<String> {
        let ordinary = crate::device::wipe_consent(&self.review)?;
        match &self.scope {
            Some(scope) => crate::consent::token(&(ordinary, scope)),
            None => Ok(ordinary),
        }
    }
}

fn disk_scope(
    inv: &mut Invocation,
    disk: &str,
) -> Result<Option<crate::device::DiskScope>, Box<dyn std::error::Error>> {
    if super::access::Env::detect() == super::access::Env::Host {
        return Ok(None);
    }
    let scope = crate::device::DiskScope::plan(disk)?;
    super::run::include_disk_scope(inv, &scope)?;
    Ok(Some(scope))
}

fn disk_typed(identity: &crate::device::DiskIdentity) -> crate::consent::Typed {
    crate::consent::disk_target(identity.serial.as_deref(), identity.wwn.as_deref())
}

pub(super) fn wipe(
    disk: String,
    consent: Consent,
    inv: &mut Invocation,
) -> Result<(), Box<dyn std::error::Error>> {
    let scope = disk_scope(inv, &disk)?;
    let Some((plan, token)) = consent_to(
        inv,
        consent,
        || {
            let review = match &scope {
                Some(scope) => scope.review()?,
                None => crate::device::plan(&disk)?,
            };
            Ok(WipePlan {
                review,
                scope: scope.clone(),
            })
        },
        WipePlan::token,
        |plan, token| {
            let mut text = crate::device::describe_wipe(&plan.review, token);
            if let Some(scope) = &plan.scope {
                text.push_str(&scope.describe());
            }
            text
        },
        |plan| disk_typed(&plan.review.identity),
    )?
    else {
        return Ok(());
    };
    let outcome = crate::device::wipe(&plan.review, &plan.review.loss_token)?;
    if !inv.json {
        println!(
            "{}: {}.",
            zfs_tools::engine::escape_display(&outcome.identity.path),
            zfs_tools::engine::escape_display(&outcome.report)
        );
    }
    applied_operation(inv, Some(token), None, outcome.complete, outcome)
}

pub(super) fn deploy(
    args: crate::deploy::command::Args,
    consent: Consent,
    inv: &mut Invocation,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::deploy::command;
    require_root(consent.dry_run, "deploy")?;
    let command::Target::Disk { disk } = &args.target else {
        return deploy_image(args, consent.dry_run, inv);
    };
    let scope = disk_scope(inv, disk)?;
    let Some((plan, token)) = consent_to(
        inv,
        consent,
        || {
            Ok(match &scope {
                Some(scope) => command::plan_scoped(&args, scope)?,
                None => command::plan_with(&args, &mut command::Native)?,
            })
        },
        command::consent,
        command::describe,
        command::typed,
    )?
    else {
        return Ok(());
    };
    let done = command::apply_with(&plan, &mut command::Native)?;
    if !inv.json {
        println!(
            "Deployed pool {}{} on {}; it is exported.",
            zfs_tools::engine::escape_display(&done.outcome.pool.name),
            done.outcome
                .dataset
                .as_ref()
                .map(|be| format!(" with BE {}", zfs_tools::engine::escape_display(&be.name)))
                .unwrap_or_default(),
            zfs_tools::engine::escape_display(&done.outcome.disk.path)
        );
    }
    applied(inv, Some(token), done)
}

/// Every deploy changes disks or pools, mounts filesystems and
/// reads raw devices. Say so, rather than fail at whichever step first lacks
/// the privilege. A preview changes nothing and plans as far as it can.
fn require_root(dry_run: bool, verb: &str) -> Result<(), Box<dyn Error>> {
    if !dry_run && !rustix::process::geteuid().is_root() {
        return Err(std::io::Error::other(format!(
            "{verb} needs root: it changes disks or pools, creates datasets, and mounts them"
        ))
        .into());
    }
    Ok(())
}

pub(super) fn deploy_into(
    request: crate::deploy::into::Request,
    dry_run: bool,
    inv: &mut Invocation,
) -> Result<(), Box<dyn Error>> {
    use crate::deploy::into;
    require_root(dry_run, "deploy into")?;
    let Some(plan) = lossless(
        inv,
        dry_run,
        || {
            crate::deploy::require_on_path(&["zfs", "zpool", "zdb"], "deployment")?;
            Ok(into::plan_with(&request, &mut into::Native)?)
        },
        into::describe,
    )?
    else {
        return Ok(());
    };
    let outcome = into::apply_with(&plan, &mut into::Native)?;
    if !inv.json {
        println!(
            "Deployed {}. Boot defaults remain unchanged.",
            zfs_tools::engine::escape_display(&outcome.dataset.name)
        );
    }
    applied(inv, None, outcome)
}

/// A new image file loses nothing, so it needs no typing and no token. It is
/// planned under the same writer boundary as a disk deploy, before the
/// exclusive create or the loop attachment.
fn deploy_image(
    args: crate::deploy::command::Args,
    dry_run: bool,
    inv: &mut Invocation,
) -> Result<(), Box<dyn Error>> {
    use crate::deploy::image;
    let Some(plan) = lossless(
        inv,
        dry_run,
        || Ok(image::plan_with(&args, &mut image::Native)?),
        image::describe,
    )?
    else {
        return Ok(());
    };
    let done = image::apply_with(&plan, &mut image::Native)?;
    if !inv.json {
        println!(
            "Deployed image {} ({}); pool exported and loop detached.",
            zfs_tools::engine::escape_display(&done.image.display().to_string()),
            crate::device::size(done.bytes)
        );
    }
    applied(inv, None, done)
}

pub(super) fn esp(
    partitions: Vec<String>,
    efi: &std::path::Path,
    consent: Consent,
    inv: &mut Invocation,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = || -> Result<crate::esp::RefreshPlan, Box<dyn std::error::Error>> {
        Ok(crate::esp::refresh_plan(&partitions, efi)?)
    };
    // A refresh loses nothing and runs at once. A plan that replaces another
    // system's file asks; a preview or a token takes the same path, so a
    // script can bind either kind to what it previewed.
    let initial = plan()?;
    let selected = if initial.needs_confirmation() || consent.dry_run || consent.confirm.is_some() {
        consent_to(
            inv,
            consent,
            plan,
            crate::esp::refresh_consent,
            crate::esp::describe_refresh,
            |plan: &crate::esp::RefreshPlan| {
                let typed = crate::esp::refresh_typed(plan);
                match plan.targets.as_slice() {
                    [target]
                        if !typed.text.is_empty()
                            && crate::device::typed_identity_is_shared(
                                &target.review.target.disk,
                                &typed.text,
                            ) =>
                    {
                        crate::consent::Typed {
                            what: "the disk",
                            text: String::new(),
                        }
                    }
                    _ => typed,
                }
            },
        )?
    } else {
        lossless(
            inv,
            false,
            || {
                let fresh = plan()?;
                if fresh.needs_confirmation() {
                    return Err("ESP ownership changed and now needs typed confirmation".into());
                }
                Ok(fresh)
            },
            |_| String::new(),
        )?
        .map(|plan| crate::esp::refresh_consent(&plan).map(|token| (plan, token)))
        .transpose()?
    };
    let Some((plan, token)) = selected else {
        return Ok(());
    };
    let outcome = crate::esp::refresh_apply(&plan, &token)?;
    if !inv.json {
        println!(
            "Refreshed {} ESPs. {}",
            outcome.partitions.len(),
            outcome.partitions.join(", ")
        );
        for kept in &outcome.left_in_place {
            println!(
                "{}: {} is another system's; left in place.",
                zfs_tools::engine::escape_display(&kept.partition),
                zfs_tools::engine::escape_display(&kept.path)
            );
        }
        for stale in &outcome.stale_loaders {
            println!(
                "{}",
                zfs_tools::engine::escape_display(&crate::esp::stale_note(
                    &stale.partition,
                    &stale.path
                ))
            );
        }
        if let Some(note) = crate::esp::loader_note(&plan) {
            println!("{note}");
        }
    }
    applied(inv, Some(token), outcome)
}

pub(super) fn factory(
    request: crate::factory::Request,
    inv: &mut Invocation,
) -> Result<(), Box<dyn std::error::Error>> {
    let outcome = crate::factory::build(&request)?;
    if inv.json {
        json_response(
            inv,
            crate::consent::Envelope::new(crate::consent::Outcome::Applied, None, &outcome),
        )?;
    } else {
        println!(
            "wrote {} ({}, {} packages, kernel {}) in {} s\n  sha256 {}\n  packages {}",
            outcome.tar.display(),
            crate::device::size(outcome.bytes),
            outcome.packages,
            outcome.kernels.join(" "),
            outcome.seconds,
            outcome.sha256,
            outcome.packages_file.display()
        );
    }
    Ok(())
}
