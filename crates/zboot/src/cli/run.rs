use super::{
    access::{Access, Bindings, Env},
    grammar::{Cli, Verb},
    names, pairs, provision, recovery, status, trees,
};
use crate::consent::{Envelope, Outcome};

thread_local! {
    static RESPONSE: std::cell::RefCell<Option<serde_json::Value>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug)]
pub(super) struct Incomplete(pub(super) String);

impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Incomplete {}

/// A † verb's consent: print the plan, then take `--confirm TOKEN` or, on a
/// terminal, the typed target, after which the verb plans again and goes on
/// only if the token is unchanged. Returns the plan to apply and its token, or
/// `None` after a `--dry-run` preview; anything unconfirmed is exit status 3.
/// With `--json`, stdout carries only the envelope and dialogue goes to stderr.
///
/// The plan, the preview and the prompt run without the writer lock. A verb
/// that defers it ([`LockAt::AfterConsent`]) takes it after the answer and
/// before the plan is made again, so a `--confirm` plan is also made again
/// under the lock; a dry run or an unconfirmed exit never takes it.
pub(super) fn consent_to<P: serde::Serialize>(
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
    plan: impl Fn() -> Result<P, Box<dyn std::error::Error>>,
    token: impl Fn(&P) -> std::io::Result<String>,
    describe: impl Fn(&P, &str) -> String,
    target: impl Fn(&P) -> crate::consent::Typed,
) -> Result<Option<(P, String)>, Box<dyn std::error::Error>> {
    use crate::consent::{self, Decision, Envelope, Mode, Outcome};
    use std::io::Write;
    let planned = plan()?;
    let shown = token(&planned)?;
    let mode = Mode::select(dry_run, confirm);
    if let Mode::Token(given) = &mode {
        consent::unchanged(given, &shown)?;
    }
    let mut dialogue = self::dialogue(json);
    write!(dialogue, "{}", describe(&planned, &shown))?;
    dialogue.flush()?;
    let mut input: Box<dyn std::io::BufRead> = match &mode {
        Mode::Interactive => Box::new(std::io::BufReader::with_capacity(
            1,
            std::fs::File::open("/proc/self/fd/0")?,
        )),
        _ => Box::new(std::io::empty()),
    };
    let decision = consent::decide(
        &mode,
        &shown,
        &target(&planned),
        &mut input,
        &mut std::io::stderr(),
    )?;
    match decision {
        Decision::DryRun | Decision::Unconfirmed => {
            if json {
                json_response(Envelope::new(Outcome::Preview, Some(shown), &planned))?;
            }
            if decision == Decision::Unconfirmed {
                return Err(consent::Unconfirmed.into());
            }
            Ok(None)
        }
        Decision::Proceed { replan } => {
            let locked = writer_for_replan(&planned, &plan, true)?;
            if !replan && !locked {
                return Ok(Some((planned, shown)));
            }
            let fresh = plan()?;
            consent::unchanged(&shown, &token(&fresh)?)?;
            Ok(Some((fresh, shown)))
        }
    }
}

/// Preview a lossless change or bind execution to an earlier preview.
/// Explicit confirmation checks the plan again under the writer lock.
/// Ordinary execution uses the fresh locked plan and its token.
pub(super) fn review<P: serde::Serialize>(
    dry_run: bool,
    confirm: Option<String>,
    json: bool,
    plan: impl Fn() -> Result<P, Box<dyn std::error::Error>>,
    token: impl Fn(&P) -> std::io::Result<String>,
    describe: impl Fn(&P, &str) -> String,
) -> Result<Option<(P, String)>, Box<dyn std::error::Error>> {
    use std::io::Write;
    let planned = plan()?;
    let shown = token(&planned)?;
    if let Some(given) = confirm.as_deref() {
        crate::consent::unchanged(given, &shown)?;
    }
    if dry_run {
        if json {
            json_response(Envelope::new(Outcome::Preview, Some(shown), &planned))?;
        } else {
            write!(dialogue(false), "{}", describe(&planned, &shown))?;
            println!("Dry run; nothing changed.");
        }
        return Ok(None);
    }
    writer_for_replan(&planned, &plan, confirm.is_some())?;
    let fresh = plan()?;
    let fresh_token = token(&fresh)?;
    if confirm.is_some() {
        crate::consent::unchanged(&shown, &fresh_token)?;
    }
    Ok(Some((fresh, fresh_token)))
}

/// When a command takes the writer lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockAt {
    /// Never: it changes no pool, or runs for a session (the Menu, a chroot
    /// shell) and so must not hold the lock.
    Never,
    /// A † verb: after the operator's answer (`consent_to`), or, on its paths
    /// that need no answer, right before its engine plans again and acts. Its
    /// preview, `--dry-run` and prompt run without the lock.
    AfterConsent,
}

type TakeLock =
    fn(
        &str,
    )
        -> Result<Option<zfs_tools::engine::lock::WriterLock>, zfs_tools::engine::lock::LockError>;

/// The deferred writer lock of this process.
enum Writer {
    /// Not deferred: taken at entry, or never.
    NotDeferred,
    Deferred {
        purpose: String,
        take: TakeLock,
    },
    Held(#[allow(dead_code)] Option<zfs_tools::engine::lock::WriterLock>),
}
thread_local! {
    static WRITER: std::cell::RefCell<Writer> = const { std::cell::RefCell::new(Writer::NotDeferred) };
    static ACCESS: std::cell::RefCell<Access> = const { std::cell::RefCell::new(Access::new()) };
    static DISK_SCOPE: std::cell::RefCell<Option<crate::device::DiskScope>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn defer_writer(purpose: String, take: TakeLock) {
    WRITER.set(Writer::Deferred { purpose, take });
}

/// Take the deferred writer lock now, once; it is then held until the
/// process ends. Under it, before any effect, the menu's displayed identities
/// are checked again, a reviewed disk scope is exported and, in the UKI, the
/// pools `plan` names are reopened writable. Returns whether this call took
/// the lock. A no-op for a command that took the lock at entry or takes none.
pub(super) fn writer_for(plan: &impl serde::Serialize) -> Result<bool, Box<dyn std::error::Error>> {
    let locked = lock()?;
    if locked {
        ACCESS.with_borrow_mut(|access| access.open(plan))?;
    }
    Ok(locked)
}

/// [`writer_for`] for a verb that plans again under the lock and executes
/// that plan. In the UKI it is first made again on the read-only pools: one
/// that now names a pool the reviewed plan did not would write a pool that
/// stays read-only, so it is refused before any pool reopens. That is a stale
/// plan when it was `confirmed`, otherwise a refusal to run the verb again.
pub(super) fn writer_for_replan<P: serde::Serialize>(
    planned: &P,
    plan: &dyn Fn() -> Result<P, Box<dyn std::error::Error>>,
    confirmed: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let locked = lock()?;
    if locked {
        if ACCESS.with_borrow(Access::reopens_plan) {
            let added = super::access::unreviewed_pools(planned, &plan()?)?;
            if let Some(refusal) = replan_refusal(&added, confirmed) {
                return Err(refusal);
            }
        }
        ACCESS.with_borrow_mut(|access| access.open(planned))?;
    }
    Ok(locked)
}

fn replan_refusal(added: &[String], confirmed: bool) -> Option<Box<dyn std::error::Error>> {
    if added.is_empty() {
        None
    } else if confirmed {
        Some(std::io::Error::from(crate::consent::Stale).into())
    } else {
        Some(
            format!(
                "the plan changed before the writer lock: it now also writes pool {}. Run the command again",
                zfs_tools::engine::escape_display(&added.join(", "))
            )
            .into(),
        )
    }
}

/// Take the deferred writer lock; under it, check the menu's displayed
/// identities again and export a reviewed disk scope.
fn lock() -> Result<bool, Box<dyn std::error::Error>> {
    let locked = WRITER.with_borrow_mut(|writer| -> Result<bool, Box<dyn std::error::Error>> {
        let Writer::Deferred { purpose, take } = writer else {
            return Ok(false);
        };
        *writer = Writer::Held(crate::menu::after_imports(|| {
            take(purpose).map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
        })?);
        Ok(true)
    })?;
    if locked {
        ACCESS.with_borrow(Access::check)?;
        DISK_SCOPE.with_borrow(|scope| -> Result<(), Box<dyn std::error::Error>> {
            if let Some(scope) = scope {
                scope.export()?;
            }
            Ok(())
        })?;
    }
    Ok(locked)
}

pub(super) fn include_disk_scope(
    scope: &crate::device::DiskScope,
) -> Result<(), Box<dyn std::error::Error>> {
    DISK_SCOPE.with_borrow_mut(|selected| {
        if selected.as_ref().is_some_and(|selected| selected != scope) {
            return Err("the reviewed disk export scope changed".into());
        }
        *selected = Some(scope.clone());
        Ok(())
    })
}

/// A panic unwinds past the ordinary close. Return the pools to read-only
/// here, while the writer lock is still held.
struct CloseOnPanic;
impl Drop for CloseOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Err(error) = close_access()
        {
            eprintln!(
                "zboot: pool cleanup failed: {}. Inspect zboot status before booting",
                zfs_tools::engine::escape_display(&error.to_string())
            );
        }
    }
}

fn close_access() -> Result<(), Box<dyn std::error::Error>> {
    Ok(ACCESS.with_borrow_mut(Access::close)?)
}

pub(super) fn applied(
    json: bool,
    token: String,
    outcome: impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        json_response(crate::consent::Envelope::new(
            crate::consent::Outcome::Applied,
            Some(token),
            outcome,
        ))?;
    }
    Ok(())
}

pub(super) fn dialogue(json: bool) -> Box<dyn std::io::Write> {
    // With --json, stdout carries only JSON; the dialogue goes to stderr.
    if json {
        Box::new(crate::output::stderr())
    } else {
        Box::new(crate::output::stdout())
    }
}

pub(super) fn json_response<T: serde::Serialize>(
    value: Envelope<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    RESPONSE.set(Some(serde_json::to_value(value)?));
    Ok(())
}

/// The envelope of a recorded operation: `partial`, and a failure naming
/// `zboot resume`, when its follow-up is incomplete and its record remains.
pub(super) fn applied_operation(
    json: bool,
    token: Option<String>,
    operation: Option<&str>,
    complete: bool,
    outcome: impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        let mut envelope = crate::consent::Envelope::new(
            if complete {
                crate::consent::Outcome::Applied
            } else {
                crate::consent::Outcome::Partial
            },
            token,
            outcome,
        );
        envelope.operation = operation.map(str::to_owned);
        json_response(envelope)?;
    }
    if !complete {
        if let Some(operation) = operation {
            zfs_tools::engine::effect::operation_hint(operation);
        }
        return Err(Incomplete("operation follow-up is incomplete".into()).into());
    }
    Ok(())
}
fn execute(
    cli: Cli,
    numbers: Option<&crate::status::Numbering>,
    listed_boot: Option<crate::handoff::HandoffRequest>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Verb::Restore {
            source,
            disk,
            keep,
            pool,
            esp,
            swap,
            dry_run,
            confirm,
            json,
        } => recovery::restore(recovery::RestoreArgs {
            request: crate::restore::Request {
                source: source.ok_or("restore source is missing")?,
                disk: disk.ok_or("restore disk is missing")?,
                keep,
                pool,
                esp_bytes: esp,
                swap_bytes: swap,
            },
            dry_run,
            confirm,
            json,
        })?,
        Verb::Resume {
            id,
            dry_run,
            confirm,
            json,
        } => recovery::resume(id, false, dry_run, confirm, json)?,
        Verb::Abandon {
            id,
            dry_run,
            confirm,
            json,
        } => recovery::resume(id, true, dry_run, confirm, json)?,
        Verb::Deploy {
            disk,
            image,
            into,
            size,
            portable,
            efi,
            tar,
            overlay,
            be,
            empty: _,
            pool,
            hostid,
            hostname,
            esp,
            esp_partition,
            swap,
            dry_run,
            confirm,
            json,
        } => provision::deploy(
            crate::deploy::command::Args {
                target: match (disk, image, into.clone()) {
                    (Some(disk), None, None) => crate::deploy::command::Target::Disk { disk },
                    (None, Some(file), None) => {
                        crate::deploy::command::Target::Image { file, size }
                    }
                    (None, None, Some(pool)) => crate::deploy::command::Target::Into { pool },
                    _ => return Err("deploy needs exactly one target".into()),
                },
                portable,
                efi: if into.is_some() {
                    std::path::PathBuf::new()
                } else {
                    efi.map(Ok).unwrap_or_else(crate::status::shipped_efi)?
                },
                factory: tar,
                overlay,
                be,
                pool,
                hostid,
                hostname,
                esp,
                esp_partition,
                swap,
            },
            dry_run,
            confirm,
            json,
        )?,
        Verb::FactoryFinish { root, stage } => crate::factory::finish_stage(&root, &stage)?,
        Verb::Factory {
            output,
            suite,
            mirror,
            snapshot,
            packages,
            zfs_from_suite,
            json,
            ..
        } => provision::factory(
            crate::factory::Request {
                output,
                mirror: mirror.unwrap_or_else(|| crate::factory::DEFAULT_MIRROR.into()),
                suite,
                snapshot,
                packages,
                zfs_from_suite,
            },
            json,
        )?,
        Verb::Esp {
            partitions,
            efi,
            dry_run,
            confirm,
            json,
        } => provision::esp(
            partitions,
            &efi.map(Ok).unwrap_or_else(crate::status::shipped_efi)?,
            dry_run,
            confirm,
            json,
        )?,
        Verb::Trace { cmdline, json } => status::trace(cmdline, json)?,
        Verb::Rename {
            source,
            destination,
            dry_run,
            confirm,
            json,
        } => trees::rename_command(source, destination, dry_run, confirm, json)?,
        Verb::Rollback {
            target,
            dry_run,
            confirm,
            json,
        } => trees::rollback_command(target, dry_run, confirm, json)?,
        Verb::Primary {
            dataset,
            dry_run,
            confirm,
            json,
        } => pairs::primary(dataset, dry_run, confirm, json)?,
        Verb::Chroot { dataset, command } => trees::chroot(dataset, command)?,
        Verb::Wipe {
            disk,
            dry_run,
            confirm,
            json,
        } => provision::wipe(disk.ok_or("wipe disk is missing")?, dry_run, confirm, json)?,
        Verb::Sync {
            source,
            destination,
            all,
            dry_run,
            confirm,
            json,
        } => pairs::sync(source, destination, all, dry_run, confirm, json)?,
        Verb::Default {
            dataset,
            dry_run,
            confirm,
            json,
        } => trees::default(dataset, dry_run, confirm, json)?,
        Verb::Cmdline {
            dataset,
            set,
            clear,
            dry_run,
            confirm,
            json,
        } => trees::cmdline(
            dataset.ok_or("no running boot environment")?,
            set,
            clear,
            dry_run,
            confirm,
            json,
        )?,
        Verb::Fork {
            snapshot,
            destination,
            dry_run,
            confirm,
            json,
        } => trees::fork_command(
            snapshot.ok_or("no running boot environment")?,
            destination,
            dry_run,
            confirm,
            json,
        )?,
        Verb::Drop {
            targets,
            dry_run,
            confirm,
            json,
        } => trees::drop_command(targets, dry_run, confirm, json)?,
        Verb::Boot {
            tar: Some(tar),
            overlay,
            ..
        } => crate::menu::ram_boot::boot(&tar, &overlay)?,
        Verb::Boot {
            dataset, kernel, ..
        } => crate::menu::boot(dataset, kernel, listed_boot)?,
        Verb::Reboot {
            key,
            esp,
            dry_run,
            confirm,
            json,
            ..
        } => {
            if let Some((planned, token)) = review(
                dry_run,
                confirm,
                json,
                || Ok(crate::reboot::plan(key.as_deref(), esp.as_deref())?),
                crate::reboot::consent,
                crate::reboot::describe,
            )? {
                crate::reboot::apply(&planned, &token)?;
                if !json {
                    println!(
                        "Menu request written to {}; rebooting.",
                        zfs_tools::engine::escape_display(&planned.target.partition.path)
                    );
                }
                applied(json, token, &planned)?;
            }
        }
        Verb::Menu { no_autoboot } => crate::menu::start(no_autoboot)?,
        Verb::Unpair {
            dataset,
            release_anchors,
            dry_run,
            confirm,
            json,
        } => pairs::unpair(dataset, release_anchors, dry_run, confirm, json)?,
        Verb::Pair {
            left,
            right,
            dry_run,
            confirm,
            json,
        } => pairs::pair(left, right, dry_run, confirm, json)?,
        Verb::Snapshot {
            datasets,
            dry_run,
            confirm,
            json,
        } => trees::snapshot(datasets, dry_run, confirm, json)?,
        Verb::Status {
            datasets,
            snapshots,
            all,
            devices,
            json,
        } => status::status(datasets, snapshots, all, devices, json, numbers)?,
    }
    Ok(())
}
/// When `command` takes the writer lock: never for a read-only or session
/// command, otherwise after its answer or right before it acts.
fn lock_at(command: &Verb) -> LockAt {
    match command {
        Verb::Status { .. }
        | Verb::Trace { .. }
        | Verb::Chroot { .. }
        | Verb::Boot { .. }
        | Verb::Menu { .. }
        | Verb::Factory { .. }
        | Verb::FactoryFinish { .. }
        | Verb::Default { dataset: None, .. }
        | Verb::Cmdline {
            set: None,
            clear: false,
            ..
        } => LockAt::Never,
        _ => LockAt::AfterConsent,
    }
}

fn wants_json(command: &Verb) -> bool {
    match command {
        Verb::Reboot { json, .. }
        | Verb::Boot { json, .. }
        | Verb::Restore { json, .. }
        | Verb::Resume { json, .. }
        | Verb::Abandon { json, .. }
        | Verb::Deploy { json, .. }
        | Verb::Factory { json, .. }
        | Verb::Trace { json, .. }
        | Verb::Rename { json, .. }
        | Verb::Rollback { json, .. }
        | Verb::Primary { json, .. }
        | Verb::Wipe { json, .. }
        | Verb::Sync { json, .. }
        | Verb::Default { json, .. }
        | Verb::Cmdline { json, .. }
        | Verb::Fork { json, .. }
        | Verb::Drop { json, .. }
        | Verb::Unpair { json, .. }
        | Verb::Pair { json, .. }
        | Verb::Status { json, .. }
        | Verb::Snapshot { json, .. }
        | Verb::Esp { json, .. } => *json,
        Verb::Chroot { .. } | Verb::Menu { .. } | Verb::FactoryFinish { .. } => false,
    }
}

fn verb_name(command: &Verb) -> &'static str {
    match command {
        Verb::Restore { .. } => "restore",
        Verb::Resume { .. } => "resume",
        Verb::Abandon { .. } => "abandon",
        Verb::Deploy { .. } => "deploy",
        Verb::Factory { .. } => "factory",
        Verb::FactoryFinish { .. } => "factory-finish",
        Verb::Esp { .. } => "esp",
        Verb::Trace { .. } => "trace",
        Verb::Rename { .. } => "rename",
        Verb::Rollback { .. } => "rollback",
        Verb::Primary { .. } => "primary",
        Verb::Chroot { .. } => "chroot",
        Verb::Wipe { .. } => "wipe",
        Verb::Sync { .. } => "sync",
        Verb::Default { .. } => "default",
        Verb::Cmdline { .. } => "cmdline",
        Verb::Fork { .. } => "fork",
        Verb::Drop { .. } => "drop",
        Verb::Reboot { .. } => "reboot --menu",
        Verb::Boot { .. } => "boot",
        Verb::Menu { .. } => "menu",
        Verb::Unpair { .. } => "unpair",
        Verb::Pair { .. } => "pair",
        Verb::Status { .. } => "status",
        Verb::Snapshot { .. } => "snapshot",
    }
}

fn recorded_operations() -> Vec<String> {
    let hints = zfs_tools::engine::effect::operation_hints();
    if hints.is_empty() {
        return Vec::new();
    }
    zfs_tools::engine::intent::find(&mut zfs_tools::engine::intent::Native)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, found)| match found {
            zfs_tools::engine::intent::Found::Record(record) if hints.contains(&record.id) => {
                Some(record.id)
            }
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn finish(
    result: Result<(), Box<dyn std::error::Error>>,
    json: bool,
    retry: &str,
) -> i32 {
    use std::io::Write;
    let mut response = RESPONSE.take();
    let reported_partial = response
        .as_ref()
        .is_some_and(|value| value["mode"] == "partial");
    let (code, mode) = match &result {
        Err(error) => {
            if let Some(exit) = error.downcast_ref::<crate::maintenance::CommandExit>() {
                eprintln!(
                    "zboot: {}",
                    zfs_tools::engine::escape_display(&error.to_string())
                );
                return exit.0;
            }
            if reported_partial || error.is::<Incomplete>() || zfs_tools::engine::effect::any() {
                (4, Outcome::Partial)
            } else if crate::consent::is_stale(error.as_ref()) {
                (3, Outcome::Refused)
            } else if error.is::<crate::consent::Unconfirmed>() {
                (3, Outcome::Preview)
            } else {
                (1, Outcome::Refused)
            }
        }
        Ok(()) if reported_partial => (4, Outcome::Partial),
        Ok(())
            if response
                .as_ref()
                .is_some_and(|value| value["mode"] == "preview") =>
        {
            (0, Outcome::Preview)
        }
        Ok(()) => (0, Outcome::Applied),
    };
    let stale = result
        .as_ref()
        .err()
        .is_some_and(|error| crate::consent::is_stale(error.as_ref()));
    let mut message = result
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            if code == 4 {
                "operation follow-up is incomplete".into()
            } else {
                String::new()
            }
        });
    let operations = if code == 4 {
        recorded_operations()
    } else {
        Vec::new()
    };
    if code == 4 {
        let guidance = if operations.is_empty() {
            if retry == "factory" {
                "Inspect the published files and choose a fresh TAR path before running zboot factory again.".into()
            } else {
                format!("Run zboot {retry} again after reviewing its current inputs and plan.")
            }
        } else {
            operations
                .iter()
                .map(|id| format!("zboot resume {id}"))
                .collect::<Vec<_>>()
                .join(", then ")
        };
        message.push_str(". ");
        message.push_str(&guidance);
    }
    if !message.is_empty() {
        // The library's errors escape their text in `Display` already; a
        // second pass would print their line breaks and backslashes as
        // `\\u{a}` and `\\\\`.
        let escaped = result.as_ref().err().is_some_and(|error| {
            error.is::<zfs_tools::engine::Error>() || error.is::<zfs_tools::Error>()
        });
        if escaped {
            eprintln!("zboot: {message}");
        } else {
            eprintln!("zboot: {}", zfs_tools::engine::escape_display(&message));
        }
    }
    if json {
        if mode == Outcome::Refused
            || response.is_none()
            || (mode == Outcome::Partial
                && response
                    .as_ref()
                    .is_some_and(|value| value["mode"] == "preview"))
        {
            let value = if code == 0 {
                serde_json::Value::Null
            } else {
                serde_json::json!({"reason": if stale { "stale_token" } else { "error" }, "message": message})
            };
            response = Some(serde_json::json!({"schema_version": 1, "result": value}));
        }
        let mut response = response.expect("JSON response is initialized above");
        response["mode"] = serde_json::json!(mode);
        if operations.len() == 1 && response.get("operation").is_none() {
            response["operation"] = serde_json::json!(operations[0]);
        }
        let output = serde_json::to_vec_pretty(&response)
            .map_err(std::io::Error::other)
            .and_then(|mut bytes| {
                bytes.push(b'\n');
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&bytes)?;
                stdout.flush()
            });
        if let Err(error) = output {
            eprintln!(
                "zboot: {}",
                zfs_tools::engine::escape_display(&error.to_string())
            );
            return if zfs_tools::engine::effect::any() || code == 4 {
                4
            } else {
                1
            };
        }
    }
    code
}

/// Resolve the written targets, then supply an omitted one from the running
/// boot environment. A menu line arrives with its targets already resolved.
fn resolve_targets(command: &mut Verb, menu: bool) -> Result<(), Box<dyn std::error::Error>> {
    let omitted = matches!(&*command, Verb::Snapshot { datasets, .. } if datasets.is_empty())
        || matches!(
            &*command,
            Verb::Cmdline { dataset: None, .. } | Verb::Fork { snapshot: None, .. }
        );
    let needs_running = omitted
        || !menu
            && command
                .targets_mut()
                .iter()
                .any(|target| names::needs_running(Some(target.as_str())));
    let running = if needs_running {
        crate::status::running_root()?
    } else {
        None
    };
    if !menu {
        for target in command.targets_mut() {
            *target = names::resolve(Some(target.as_str()), running.as_deref())?;
        }
    }
    match command {
        Verb::Snapshot { datasets, .. } if datasets.is_empty() => {
            datasets.push(names::resolve(None, running.as_deref())?)
        }
        Verb::Cmdline {
            dataset: dataset @ None,
            ..
        }
        | Verb::Fork {
            snapshot: dataset @ None,
            ..
        } => {
            *dataset = Some(names::resolve(None, running.as_deref())?);
        }
        _ => {}
    }
    Ok(())
}

pub fn main<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    run(args, |purpose| {
        zfs_tools::engine::lock::for_command("zboot", purpose)
    })
}

struct InvocationVerbosity {
    previous: bool,
}

impl InvocationVerbosity {
    fn new() -> Self {
        Self {
            previous: zfs_tools::engine::native::set_verbose(false),
        }
    }

    fn apply(&self, flag: bool) {
        zfs_tools::engine::native::set_verbose(self.previous || flag);
    }
}

impl Drop for InvocationVerbosity {
    fn drop(&mut self) {
        zfs_tools::engine::native::set_verbose(self.previous);
    }
}

pub(super) fn run<I, T>(args: I, take: TakeLock) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let verbosity = InvocationVerbosity::new();
    reset_invocation();
    let cli = match Cli::parse_from_args(args) {
        Ok(cli) => cli,
        Err(error) => return usage_exit(error),
    };
    run_parsed(cli, take, None, None, None, &verbosity)
}

fn usage_exit(error: clap::Error) -> i32 {
    let status = error.exit_code();
    match error.print() {
        Ok(()) => status,
        Err(error) => {
            eprintln!(
                "zboot: {}",
                zfs_tools::engine::escape_display(&error.to_string())
            );
            1
        }
    }
}

fn reset_invocation() {
    WRITER.set(Writer::NotDeferred);
    RESPONSE.set(None);
    ACCESS.set(Access::new());
    DISK_SCOPE.set(None);
    zfs_tools::engine::effect::reset();
}

/// Preserve the outer menu session while each parsed line owns its own
/// response, effect accounting, access guard and writer lock.
struct MenuInvocation {
    writer: Option<Writer>,
    response: Option<serde_json::Value>,
    access: Access,
    disk_scope: Option<crate::device::DiskScope>,
    effect: bool,
    hints: Vec<String>,
}

impl MenuInvocation {
    fn new() -> Self {
        Self {
            writer: Some(
                WRITER.with_borrow_mut(|writer| std::mem::replace(writer, Writer::NotDeferred)),
            ),
            response: RESPONSE.take(),
            access: ACCESS.take(),
            disk_scope: DISK_SCOPE.take(),
            effect: zfs_tools::engine::effect::any(),
            hints: zfs_tools::engine::effect::operation_hints(),
        }
    }
}

impl Drop for MenuInvocation {
    fn drop(&mut self) {
        WRITER.set(self.writer.take().unwrap());
        RESPONSE.set(self.response.take());
        ACCESS.set(std::mem::take(&mut self.access));
        DISK_SCOPE.set(self.disk_scope.take());
        zfs_tools::engine::effect::reset();
        if self.effect {
            zfs_tools::engine::effect::mark();
        }
        for id in &self.hints {
            zfs_tools::engine::effect::operation_hint(id);
        }
    }
}

pub(crate) fn run_menu(
    cli: Cli,
    bindings: Bindings,
    numbers: Option<&crate::status::Numbering>,
    listed_boot: Option<crate::handoff::HandoffRequest>,
) -> i32 {
    let _session = MenuInvocation::new();
    let verbosity = InvocationVerbosity::new();
    run_parsed(
        cli,
        |purpose| zfs_tools::engine::lock::for_command("zboot", purpose),
        Some(bindings),
        numbers,
        listed_boot,
        &verbosity,
    )
}

/// Target resolution and picker failures happen before a menu command can
/// enter `run_menu`. Give them the same response and invocation isolation.
/// Parsing here is only for the command's output contract; no target resolves.
pub(crate) fn finish_menu_pre_execution(
    words: &[String],
    error: Box<dyn std::error::Error>,
) -> i32 {
    let _session = MenuInvocation::new();
    let verbosity = InvocationVerbosity::new();
    reset_invocation();
    let shortcut = words.len() == 1 && words[0].as_bytes().first().is_some_and(u8::is_ascii_digit);
    let args = std::iter::once("zboot")
        .chain(shortcut.then_some("boot"))
        .chain(words.iter().map(String::as_str));
    let cli = match Cli::parse_for_menu(args) {
        Ok(cli) => cli,
        Err(error) => return usage_exit(error),
    };
    verbosity.apply(cli.verbose);
    finish(
        Err(error),
        wants_json(&cli.command),
        verb_name(&cli.command),
    )
}

/// `bindings` are a menu line's displayed identities; `None` for a command line.
fn run_parsed(
    mut cli: Cli,
    take: TakeLock,
    bindings: Option<Bindings>,
    numbers: Option<&crate::status::Numbering>,
    listed_boot: Option<crate::handoff::HandoffRequest>,
    verbosity: &InvocationVerbosity,
) -> i32 {
    reset_invocation();
    if let Err(error) = cli.validate_complete() {
        return usage_exit(error);
    }
    verbosity.apply(cli.verbose);
    let json = wants_json(&cli.command);
    let verb = verb_name(&cli.command);
    let _close = CloseOnPanic;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let environment = Env::detect();
        environment.admit(&cli.command)?;
        let menu = bindings.is_some();
        // Boot imports read-only in menu::boot itself, for a menu line and a
        // command line alike; importing here as well ran discovery twice.
        if environment == Env::Uki
            && !menu
            && (lock_at(&cli.command) == LockAt::AfterConsent
                || matches!(&cli.command, Verb::Chroot { .. }))
            && !matches!(
                &cli.command,
                Verb::Wipe { .. } | Verb::Deploy { into: None, .. }
            )
        {
            crate::menu::import_readonly_for_action()?;
        }
        resolve_targets(&mut cli.command, menu)?;
        ACCESS.set(Access::of(
            environment,
            &cli.command,
            bindings.unwrap_or_default(),
        ));
        ACCESS.with_borrow(Access::check)?;
        match lock_at(&cli.command) {
            LockAt::Never => {}
            LockAt::AfterConsent => defer_writer(verb.into(), take),
        }
        if let Verb::Chroot { dataset, .. } = &cli.command {
            ACCESS.with_borrow_mut(|access| access.open_chroot(dataset))?;
        }
        execute(cli, numbers, listed_boot)
    })();
    let result = match (result, close_access()) {
        (result, Ok(())) => result,
        (result, Err(cleanup)) => Err(format!(
            "{}. Pool cleanup failed. {cleanup}. Inspect zboot status before booting",
            result
                .err()
                .map_or_else(|| "The command completed".into(), |error| error.to_string())
        )
        .into()),
    };
    let code = finish(result, json, verb);
    WRITER.set(Writer::NotDeferred);
    code
}

#[cfg(test)]
pub(super) fn writer_is_held_for_test() -> bool {
    WRITER.with_borrow(|writer| matches!(writer, Writer::Held(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_session_and_read_only_commands_skip_the_writer_lock() {
        let parse = |args: &[&str]| {
            Cli::parse_from_args(std::iter::once("zboot").chain(args.iter().copied()))
                .unwrap()
                .command
        };
        for args in [
            &["status"][..],
            &["trace"],
            &["menu"],
            &["chroot", "rpool/ROOT/a"],
            &["default"],
            &["cmdline", "rpool/ROOT/a"],
        ] {
            assert_eq!(lock_at(&parse(args)), LockAt::Never, "{args:?}");
        }
        for args in [
            &["snapshot"][..],
            &["default", "rpool/ROOT/a"],
            &["fork", "rpool/x@s", "rpool/y"],
            &["pair", "a/x", "b/x"],
            &["cmdline", "rpool/ROOT/a", "--set", "quiet"],
            &["cmdline", "rpool/ROOT/a", "--clear"],
            &["sync", "a/x"],
            &["reboot", "--menu"],
        ] {
            assert_eq!(lock_at(&parse(args)), LockAt::AfterConsent, "{args:?}");
        }
        for args in [
            &["drop", "rpool/x"][..],
            &["rollback", "rpool/x@s", "--dry-run"],
            &["rename", "rpool/x", "tank/x"],
            &["rename", "rpool/x", "rpool/y"],
            &["primary", "a/x"],
            &["unpair", "a/x", "--release-anchors"],
            &["wipe", "/dev/sdz"],
            &["abandon", "id"],
            &["restore", "rpool/ROOT/a", "/dev/sdz"],
        ] {
            assert_eq!(lock_at(&parse(args)), LockAt::AfterConsent, "{args:?}");
        }
    }

    /// `consent_to` for a verb that defers its lock, with a fake lock taker:
    /// returns the plan calls, each with whether the lock was held then.
    fn consented(dry_run: bool, confirm: Option<&str>) -> (bool, Vec<bool>) {
        defer_writer("drop".into(), |_| Ok(None));
        let calls = std::cell::RefCell::new(Vec::new());
        let held = || WRITER.with_borrow(|w| matches!(w, Writer::Held(_)));
        let result = consent_to(
            dry_run,
            confirm.map(String::from),
            true,
            || {
                calls.borrow_mut().push(held());
                Ok("the plan")
            },
            |_| Ok("sha256:token".to_string()),
            |_, _| String::new(),
            |_| crate::consent::Typed {
                what: "the target",
                text: "x".into(),
            },
        );
        let proceeded = matches!(result, Ok(Some(_)));
        let calls = calls.into_inner();
        assert_eq!(
            held(),
            proceeded,
            "the lock is held exactly when consent proceeds"
        );
        WRITER.set(Writer::NotDeferred);
        (proceeded, calls)
    }

    #[test]
    fn a_deferred_writer_lock_is_taken_after_consent_and_before_the_replan() {
        // A dry run and a stale token take no lock.
        assert_eq!(consented(true, None), (false, vec![false]));
        assert_eq!(consented(false, Some("sha256:other")), (false, vec![false]));
        // A matching token: plan, lock, plan again under it.
        assert_eq!(
            consented(false, Some("sha256:token")),
            (true, vec![false, true])
        );
        // A lock taken at entry (or none) is not taken again.
        WRITER.set(Writer::NotDeferred);
        assert!(!writer_for(&()).unwrap());
    }

    #[test]
    fn lossless_previews_take_no_lock_and_confirmed_reviews_recheck_under_it() {
        let token = crate::consent::token(&7u8).unwrap();
        for (dry_run, given, expected) in [
            (true, None, vec![false]),
            (false, Some("stale".to_owned()), vec![false]),
            (false, Some(token), vec![false, true]),
        ] {
            defer_writer("snapshot".into(), |_| Ok(None));
            let calls = std::cell::RefCell::new(Vec::new());
            let result = review(
                dry_run,
                given,
                true,
                || {
                    calls
                        .borrow_mut()
                        .push(WRITER.with_borrow(|writer| matches!(writer, Writer::Held(_))));
                    Ok(7u8)
                },
                crate::consent::token,
                |_, _| String::new(),
            );
            assert_eq!(*calls.borrow(), expected);
            if expected.len() == 2 {
                assert!(matches!(result, Ok(Some(_))));
            }
            WRITER.set(Writer::NotDeferred);
            RESPONSE.set(None);
        }
    }

    #[test]
    fn a_replan_naming_an_unreviewed_pool_refuses_as_stale_or_to_run_again() {
        assert!(replan_refusal(&[], true).is_none());
        for (confirmed, code) in [(true, 3), (false, 1)] {
            zfs_tools::engine::effect::reset();
            RESPONSE.set(None);
            let refusal = replan_refusal(&["bpool".into()], confirmed).unwrap();
            assert_eq!(crate::consent::is_stale(refusal.as_ref()), confirmed);
            assert_eq!(finish(Err(refusal), false, "sync"), code);
        }
    }

    #[test]
    fn the_library_entry_point_parses_its_supplied_arguments_and_returns_status() {
        assert_eq!(main(["zboot", "unknown-verb"]), 2);
        assert_eq!(main(["zboot", "--version"]), 0);
    }

    #[test]
    fn a_library_cli_invocation_clears_previous_deferred_writer_state() {
        defer_writer("previous invocation".into(), |_| {
            panic!("previous writer must be cleared")
        });
        assert_eq!(main(["zboot", "--version"]), 0);
        assert!(WRITER.with_borrow(|writer| matches!(writer, Writer::NotDeferred)));
    }

    #[test]
    fn successive_menu_commands_restore_the_session_and_clear_their_effects() {
        reset_invocation();
        let outer_response = serde_json::json!({"session": "outer"});
        RESPONSE.set(Some(outer_response.clone()));
        defer_writer("outer session".into(), |_| Ok(None));
        zfs_tools::engine::effect::operation_hint("outer operation");
        for previous_effect in [false, true] {
            if previous_effect {
                zfs_tools::engine::effect::mark();
            }
            {
                let _session = MenuInvocation::new();
                reset_invocation();
                assert!(!zfs_tools::engine::effect::any());
                assert!(zfs_tools::engine::effect::operation_hints().is_empty());
                assert!(RESPONSE.with_borrow(Option::is_none));
                defer_writer("inner command".into(), |_| Ok(None));
                assert!(writer_for(&()).unwrap());
                zfs_tools::engine::effect::mark();
                zfs_tools::engine::effect::operation_hint("inner operation");
                RESPONSE.set(Some(serde_json::json!({"command": "inner"})));
            }
            assert_eq!(zfs_tools::engine::effect::any(), previous_effect);
            assert_eq!(
                zfs_tools::engine::effect::operation_hints(),
                vec!["outer operation"]
            );
            assert_eq!(
                RESPONSE.with_borrow(Clone::clone),
                Some(outer_response.clone())
            );
            assert!(WRITER.with_borrow(|writer| matches!(
                writer,
                Writer::Deferred { purpose, .. } if purpose == "outer session"
            )));
        }
        reset_invocation();
    }
}
