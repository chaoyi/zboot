//! Provisioning command glue.
use super::run::{applied, applied_operation, consent_to, json_response};
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

fn disk_scope(disk: &str) -> Result<Option<crate::device::DiskScope>, Box<dyn std::error::Error>> {
    if super::access::Env::detect() == super::access::Env::Host {
        return Ok(None);
    }
    let scope = crate::device::DiskScope::plan(disk)?;
    super::run::include_disk_scope(&scope)?;
    Ok(Some(scope))
}

fn disk_typed(identity: &crate::device::DiskIdentity) -> crate::consent::Typed {
    crate::consent::disk_target(identity.serial.as_deref(), identity.wwn.as_deref())
}

pub(super) fn wipe(
    disk: String,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let scope = disk_scope(&disk)?;
    let Some((plan, token)) = consent_to(
        dry_run,
        confirm,
        json,
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
    if !json {
        println!(
            "{}: {}.",
            zfs_tools::engine::escape_display(&outcome.identity.path),
            zfs_tools::engine::escape_display(&outcome.report)
        );
    }
    applied_operation(json, Some(token), None, outcome.complete, outcome)
}

pub(super) fn deploy(
    args: crate::deploy::command::Args,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::deploy::command;
    // Every form changes disks or pools, mounts filesystems and reads raw
    // devices. Say so, rather than fail at whichever step first lacks the
    // privilege. A preview changes nothing and plans as far as it can.
    if !dry_run && !rustix::process::geteuid().is_root() {
        return Err(std::io::Error::other(
            "deploy needs root: it changes disks, creates pools and datasets, and mounts them",
        )
        .into());
    }
    if matches!(&args.target, command::Target::Into { .. }) {
        return deploy_into(args, dry_run, confirm, json);
    }
    let command::Target::Disk { disk } = &args.target else {
        return deploy_image(args, dry_run, confirm, json);
    };
    let scope = disk_scope(disk)?;
    let Some((plan, token)) = consent_to(
        dry_run,
        confirm,
        json,
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
    if !json {
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
    applied(json, token, done)
}

fn deploy_into(
    args: crate::deploy::command::Args,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    use crate::deploy::into;
    let request = into::Request::from_args(&args)?;
    let Some((plan, token)) = super::run::review(
        dry_run,
        confirm,
        json,
        || {
            crate::deploy::require_on_path(&["zfs", "zpool", "zdb"], "deployment")?;
            Ok(into::plan_with(&request, &mut into::Native)?)
        },
        into::consent,
        into::describe,
    )?
    else {
        return Ok(());
    };
    let outcome = into::apply_with(&plan, &mut into::Native)?;
    if !json {
        println!(
            "Deployed {}. Boot defaults remain unchanged.",
            zfs_tools::engine::escape_display(&outcome.dataset.name)
        );
    }
    applied(json, token, outcome)
}

fn deploy_image(
    args: crate::deploy::command::Args,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    use crate::{consent, deploy::image};
    use std::io::Write;
    let mut plan = image::plan_with(&args, &mut image::Native)?;
    let token = image::consent(&plan)?;
    if let Some(given) = confirm {
        consent::unchanged(&given, &token)?;
    }
    if json {
        eprint!("{}", image::describe(&plan, &token));
    } else {
        print!("{}", image::describe(&plan, &token));
        crate::output::stdout().flush()?;
    }
    if dry_run {
        if json {
            json_response(consent::Envelope::new(
                consent::Outcome::Preview,
                Some(token),
                &plan,
            ))?;
        }
        return Ok(());
    }
    // No typing is required to create a new file. Replan under the same writer
    // boundary as disk deployment before exclusive create or loop attachment.
    super::run::writer_for(&plan)?;
    let fresh = image::plan_with(&args, &mut image::Native)?;
    consent::unchanged(&token, &image::consent(&fresh)?)?;
    plan = fresh;
    let done = image::apply_with(&plan, &mut image::Native)?;
    if !json {
        println!(
            "Deployed image {} ({}); pool exported and loop detached.",
            zfs_tools::engine::escape_display(&done.image.display().to_string()),
            crate::device::size(done.bytes)
        );
    }
    applied(json, token, done)
}

pub(super) fn esp(
    partitions: Vec<String>,
    efi: &std::path::Path,
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = || -> Result<crate::esp::RefreshPlan, Box<dyn std::error::Error>> {
        Ok(crate::esp::refresh_plan(&partitions, efi)?)
    };
    let initial = plan()?;
    let selected = if initial.needs_confirmation() {
        consent_to(
            dry_run,
            confirm,
            json,
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
        super::run::review(
            dry_run,
            confirm,
            json,
            || {
                let fresh = plan()?;
                if fresh.needs_confirmation() {
                    return Err("ESP ownership changed and now needs typed confirmation".into());
                }
                Ok(fresh)
            },
            crate::esp::refresh_consent,
            crate::esp::describe_refresh,
        )?
    };
    let Some((plan, token)) = selected else {
        return Ok(());
    };
    let outcome = crate::esp::refresh_apply(&plan, &token)?;
    if !json {
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
        if let Some(note) = crate::esp::loader_note(&plan) {
            println!("{note}");
        }
    }
    applied(json, token, outcome)
}

pub(super) fn factory(
    request: crate::factory::Request,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let outcome = crate::factory::build(&request)?;
    if json {
        json_response(crate::consent::Envelope::new(
            crate::consent::Outcome::Applied,
            None,
            &outcome,
        ))?;
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
