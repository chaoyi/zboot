use super::{
    access::{Access, Bindings, Env},
    grammar::{Cli, Consent, DeployInto, Verb},
    names, pairs, provision, recovery, status, trees,
};
use crate::consent::{Envelope, Outcome};

#[derive(Debug)]
pub(super) struct Incomplete(pub(super) String);

impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Incomplete {}

/// One command's state: whether it prints JSON, the envelope it reports, its
/// writer lock, its pool access and its reviewed disk scope. A menu line is
/// an invocation of its own beside the menu's.
pub(super) struct Invocation {
    pub(super) json: bool,
    response: Option<serde_json::Value>,
    writer: Writer,
    access: Access,
    disk_scope: Option<crate::device::DiskScope>,
}

impl Invocation {
    pub(super) fn new(json: bool) -> Self {
        Self {
            json,
            response: None,
            writer: Writer::NotDeferred,
            access: Access::new(),
            disk_scope: None,
        }
    }

    pub(super) fn defer_writer(&mut self, purpose: String, take: TakeLock) {
        self.writer = Writer::Deferred { purpose, take };
    }

    #[cfg(test)]
    pub(super) fn writer_held(&self) -> bool {
        matches!(self.writer, Writer::Held(_))
    }

    /// Exit status and output of this invocation's `result`.
    pub(super) fn finish(
        mut self,
        result: Result<(), Box<dyn std::error::Error>>,
        retry: &str,
    ) -> i32 {
        finish(result, self.response.take(), self.json, retry)
    }
}

/// A panic unwinds past the ordinary close. Return the pools to read-only
/// here: the drop body runs before any field drops, so the writer lock is
/// still held.
impl Drop for Invocation {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Err(error) = self.access.close()
        {
            eprintln!(
                "zboot: pool cleanup failed: {}. Inspect zboot status before booting",
                zfs_tools::engine::escape_display(&error.to_string())
            );
        }
    }
}

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
    inv: &mut Invocation,
    consent: Consent,
    plan: impl Fn() -> Result<P, Box<dyn std::error::Error>>,
    token: impl Fn(&P) -> std::io::Result<String>,
    describe: impl Fn(&P, &str) -> String,
    target: impl Fn(&P) -> crate::consent::Typed,
) -> Result<Option<(P, String)>, Box<dyn std::error::Error>> {
    use crate::consent::{self, Decision, Envelope, Mode, Outcome};
    use std::io::Write;
    let planned = plan()?;
    let shown = token(&planned)?;
    let mode = Mode::select(consent.dry_run, consent.confirm);
    if let Mode::Token(given) = &mode {
        consent::unchanged(given, &shown)?;
    }
    let mut dialogue = self::dialogue(inv.json);
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
            if inv.json {
                json_response(inv, Envelope::new(Outcome::Preview, Some(shown), &planned))?;
            }
            if decision == Decision::Unconfirmed {
                return Err(consent::Unconfirmed.into());
            }
            Ok(None)
        }
        Decision::Proceed { replan } => {
            let locked = writer_for_replan(inv, &planned, &plan, true)?;
            if !replan && !locked {
                return Ok(Some((planned, shown)));
            }
            let fresh = plan()?;
            consent::unchanged(&shown, &token(&fresh)?)?;
            Ok(Some((fresh, shown)))
        }
    }
}

/// A change that loses nothing, so it takes no `--confirm` and has no token.
/// `--dry-run` plans and previews without the writer lock. Otherwise the plan
/// is made once, under the lock, and returned to apply. In the UKI the pools
/// that plan names are then reopened writable and it is made again on them;
/// one that now names another pool is refused, to be run again.
pub(super) fn lossless<P: serde::Serialize>(
    inv: &mut Invocation,
    dry_run: bool,
    plan: impl Fn() -> Result<P, Box<dyn std::error::Error>>,
    describe: impl Fn(&P) -> String,
) -> Result<Option<P>, Box<dyn std::error::Error>> {
    use std::io::Write;
    if dry_run {
        let planned = plan()?;
        if inv.json {
            json_response(inv, Envelope::new(Outcome::Preview, None, &planned))?;
        } else {
            write!(dialogue(false), "{}", describe(&planned))?;
            println!("Dry run; nothing changed.");
        }
        return Ok(None);
    }
    let locked = lock(inv)?;
    let planned = plan()?;
    if !locked || !inv.access.reopens_plan() {
        return Ok(Some(planned));
    }
    inv.access.open(&planned)?;
    let fresh = plan()?;
    let added = super::access::unreviewed_pools(&planned, &fresh)?;
    if let Some(refusal) = replan_refusal(&added, false) {
        return Err(refusal);
    }
    Ok(Some(fresh))
}

/// When a command takes the writer lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockAt {
    /// Never: it changes no pool, or runs for a session (the Menu, a chroot
    /// shell) and so must not hold the lock.
    Never,
    /// A changing verb: after the operator's answer (`consent_to`), or, on
    /// its paths that need no answer, right before it plans under the lock
    /// (`lossless`) or its engine plans again and acts. Its preview,
    /// `--dry-run` and prompt run without the lock.
    AfterConsent,
}

/// Takes the writer lock; `Ok(None)` stands for one in tests, which take none.
type TakeLock =
    fn(
        &str,
    )
        -> Result<Option<zfs_tools::engine::lock::WriterLock>, zfs_tools::engine::lock::LockError>;

/// An invocation's deferred writer lock.
enum Writer {
    /// Not deferred: the command takes none.
    NotDeferred,
    Deferred {
        purpose: String,
        take: TakeLock,
    },
    Held(#[allow(dead_code)] Option<zfs_tools::engine::lock::WriterLock>),
}

/// Take the deferred writer lock now, once; it is then held until the
/// invocation ends. Under it, before any effect, the menu's displayed
/// identities are checked again, a reviewed disk scope is exported and, in
/// the UKI, the pools `plan` names are reopened writable. Returns whether this
/// call took the lock. A no-op for a command that takes none.
pub(super) fn writer_for(
    inv: &mut Invocation,
    plan: &impl serde::Serialize,
) -> Result<bool, Box<dyn std::error::Error>> {
    let locked = lock(inv)?;
    if locked {
        inv.access.open(plan)?;
    }
    Ok(locked)
}

/// [`writer_for`] for a verb that plans again under the lock and executes
/// that plan. In the UKI it is first made again on the read-only pools: one
/// that now names a pool the reviewed plan did not would write a pool that
/// stays read-only, so it is refused before any pool reopens. That is a stale
/// plan when it was `confirmed`, otherwise a refusal to run the verb again.
pub(super) fn writer_for_replan<P: serde::Serialize>(
    inv: &mut Invocation,
    planned: &P,
    plan: &dyn Fn() -> Result<P, Box<dyn std::error::Error>>,
    confirmed: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let locked = lock(inv)?;
    if locked {
        if inv.access.reopens_plan() {
            let added = super::access::unreviewed_pools(planned, &plan()?)?;
            if let Some(refusal) = replan_refusal(&added, confirmed) {
                return Err(refusal);
            }
        }
        inv.access.open(planned)?;
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
                "the plan changed: it now also writes pool {}. Run the command again",
                zfs_tools::engine::escape_display(&added.join(", "))
            )
            .into(),
        )
    }
}

/// Take the deferred writer lock; under it, check the menu's displayed
/// identities again and export a reviewed disk scope.
fn lock(inv: &mut Invocation) -> Result<bool, Box<dyn std::error::Error>> {
    let Writer::Deferred { purpose, take } = &inv.writer else {
        return Ok(false);
    };
    inv.writer = Writer::Held(crate::menu::after_imports(|| {
        take(purpose).map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
    })?);
    inv.access.check()?;
    if let Some(scope) = &inv.disk_scope {
        scope.export()?;
    }
    Ok(true)
}

pub(super) fn include_disk_scope(
    inv: &mut Invocation,
    scope: &crate::device::DiskScope,
) -> Result<(), Box<dyn std::error::Error>> {
    if inv
        .disk_scope
        .as_ref()
        .is_some_and(|selected| selected != scope)
    {
        return Err("the reviewed disk export scope changed".into());
    }
    inv.disk_scope = Some(scope.clone());
    Ok(())
}

pub(super) fn applied(
    inv: &mut Invocation,
    token: Option<String>,
    outcome: impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    if inv.json {
        json_response(
            inv,
            crate::consent::Envelope::new(crate::consent::Outcome::Applied, token, outcome),
        )?;
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
    inv: &mut Invocation,
    value: Envelope<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    inv.response = Some(serde_json::to_value(value)?);
    Ok(())
}

/// The envelope of a recorded operation: `partial`, and a failure naming
/// `zboot resume`, when its follow-up is incomplete and its record remains.
pub(super) fn applied_operation(
    inv: &mut Invocation,
    token: Option<String>,
    operation: Option<&str>,
    complete: bool,
    outcome: impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    if inv.json {
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
        json_response(inv, envelope)?;
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
    inv: &mut Invocation,
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
            consent,
        } => recovery::restore(
            crate::restore::Request {
                source,
                disk,
                keep,
                pool,
                esp_bytes: esp,
                swap_bytes: swap,
            },
            consent,
            inv,
        )?,
        Verb::Resume { id, consent } => recovery::resume(id, false, consent, inv)?,
        Verb::Abandon { id, consent } => recovery::resume(id, true, consent, inv)?,
        Verb::Deploy {
            into: Some(DeployInto::Into(into)),
            ..
        } => {
            let into = *into;
            provision::deploy_into(
                crate::deploy::into::Request {
                    pool: into.pool,
                    be: into
                        .be
                        .unwrap_or_else(|| crate::deploy::command::DEFAULT_BE.into()),
                    tar: into.tar,
                    overlays: into.overlay,
                    hostname: into.hostname,
                },
                into.dry_run,
                inv,
            )?
        }
        Verb::Deploy {
            into: None,
            disk,
            image,
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
            consent,
        } => provision::deploy(
            crate::deploy::command::Args {
                target: match (disk, image) {
                    (Some(disk), None) => crate::deploy::command::Target::Disk { disk },
                    (None, Some(file)) => crate::deploy::command::Target::Image { file },
                    _ => return Err("deploy needs exactly one target".into()),
                },
                portable,
                efi: efi.map(Ok).unwrap_or_else(crate::status::shipped_efi)?,
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
            consent,
            inv,
        )?,
        Verb::FactoryFinish { root, stage } => crate::factory::finish_stage(&root, &stage)?,
        Verb::Factory {
            output,
            suite,
            mirror,
            snapshot,
            packages,
        } => provision::factory(
            crate::factory::Request {
                output,
                mirror: mirror.unwrap_or_else(|| crate::factory::DEFAULT_MIRROR.into()),
                suite,
                snapshot,
                packages,
            },
            inv,
        )?,
        Verb::Esp {
            partitions,
            efi,
            consent,
        } => provision::esp(
            partitions,
            &efi.map(Ok).unwrap_or_else(crate::status::shipped_efi)?,
            consent,
            inv,
        )?,
        Verb::Rename {
            source,
            destination,
            dry_run,
        } => trees::rename_command(source, destination, dry_run, inv)?,
        Verb::Rollback { target, consent } => trees::rollback_command(target, consent, inv)?,
        Verb::Primary { dataset, consent } => pairs::primary(dataset, consent, inv)?,
        Verb::Chroot { dataset, command } => trees::chroot(dataset, command)?,
        Verb::Wipe { disk, consent } => provision::wipe(disk, consent, inv)?,
        Verb::Sync {
            source,
            destination,
            all,
            consent,
        } => pairs::sync(source, destination, all, consent, inv)?,
        Verb::Default { dataset, dry_run } => trees::default(dataset, dry_run, inv)?,
        Verb::Cmdline {
            dataset,
            set,
            clear,
            dry_run,
        } => trees::cmdline(
            dataset.ok_or("no running boot environment")?,
            set,
            clear,
            dry_run,
            inv,
        )?,
        Verb::Fork {
            snapshot,
            destination,
            dry_run,
        } => trees::fork_command(
            snapshot.ok_or("no running boot environment")?,
            destination,
            dry_run,
            inv,
        )?,
        Verb::Drop { targets, consent } => trees::drop_command(targets, consent, inv)?,
        Verb::Boot {
            tar: Some(tar),
            overlay,
            ..
        } => crate::menu::ram_boot::boot(&tar, &overlay)?,
        Verb::Boot {
            dataset, kernel, ..
        } => crate::menu::boot(dataset, kernel, listed_boot)?,
        Verb::Reboot {
            key, esp, dry_run, ..
        } => {
            if let Some(planned) = lossless(
                inv,
                dry_run,
                || Ok(crate::reboot::plan(key.as_deref(), esp.as_deref())?),
                crate::reboot::describe,
            )? {
                crate::reboot::apply(&planned)?;
                if !inv.json {
                    println!(
                        "Menu request written to {}; rebooting.",
                        zfs_tools::engine::escape_display(&planned.target.partition.path)
                    );
                }
                applied(inv, None, &planned)?;
            }
        }
        Verb::Menu { no_autoboot } => crate::menu::start(no_autoboot)?,
        Verb::Unpair {
            dataset,
            release_anchors,
            consent,
        } => pairs::unpair(dataset, release_anchors, consent, inv)?,
        Verb::Pair {
            left,
            right,
            dry_run,
        } => pairs::pair(left, right, dry_run, inv)?,
        Verb::Snapshot { datasets, dry_run } => trees::snapshot(datasets, dry_run, inv)?,
        Verb::Status {
            datasets,
            snapshots,
            all,
            devices,
        } => status::status(datasets, snapshots, all, devices, inv, numbers)?,
    }
    Ok(())
}
/// When `command` takes the writer lock: never for a read-only or session
/// command, otherwise after its answer or right before it acts.
fn lock_at(command: &Verb) -> LockAt {
    match command {
        Verb::Status { .. }
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

fn verb_name(command: &Verb) -> &'static str {
    match command {
        Verb::Restore { .. } => "restore",
        Verb::Resume { .. } => "resume",
        Verb::Abandon { .. } => "abandon",
        Verb::Deploy { into: Some(_), .. } => "deploy into",
        Verb::Deploy { .. } => "deploy",
        Verb::Factory { .. } => "factory",
        Verb::FactoryFinish { .. } => "factory-finish",
        Verb::Esp { .. } => "esp",
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

/// The exit status and output of a command's `result` and the envelope it
/// reported, if any.
pub(crate) fn finish(
    result: Result<(), Box<dyn std::error::Error>>,
    mut response: Option<serde_json::Value>,
    json: bool,
    retry: &str,
) -> i32 {
    use std::io::Write;
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
        zfs_tools::engine::lock::for_command("zboot", purpose).map(Some)
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
    zfs_tools::engine::effect::reset();
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

/// The library's effect accounting is per process. Each menu line counts its
/// own; the menu session's is restored after it.
struct MenuEffects {
    effect: bool,
    hints: Vec<String>,
}

impl MenuEffects {
    fn new() -> Self {
        let session = Self {
            effect: zfs_tools::engine::effect::any(),
            hints: zfs_tools::engine::effect::operation_hints(),
        };
        zfs_tools::engine::effect::reset();
        session
    }
}

impl Drop for MenuEffects {
    fn drop(&mut self) {
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
    let _session = MenuEffects::new();
    let verbosity = InvocationVerbosity::new();
    run_parsed(
        cli,
        |purpose| zfs_tools::engine::lock::for_command("zboot", purpose).map(Some),
        Some(bindings),
        numbers,
        listed_boot,
        &verbosity,
    )
}

/// Target resolution failures happen before a menu command can
/// enter `run_menu`. Give them the same response and effect isolation.
/// Parsing here is only for the command's output contract; no target resolves.
pub(crate) fn finish_menu_pre_execution(
    words: &[String],
    error: Box<dyn std::error::Error>,
) -> i32 {
    let _session = MenuEffects::new();
    let verbosity = InvocationVerbosity::new();
    let shortcut = words.len() == 1 && words[0].as_bytes().first().is_some_and(u8::is_ascii_digit);
    let args = std::iter::once("zboot")
        .chain(shortcut.then_some("boot"))
        .chain(words.iter().map(String::as_str));
    let cli = match Cli::parse_from_args(args) {
        Ok(cli) => cli,
        Err(error) => return usage_exit(error),
    };
    verbosity.apply(cli.verbose);
    finish(Err(error), None, cli.json, verb_name(&cli.command))
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
    zfs_tools::engine::effect::reset();
    verbosity.apply(cli.verbose);
    let verb = verb_name(&cli.command);
    let mut inv = Invocation::new(cli.json);
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
        inv.access = Access::of(environment, &cli.command, bindings.unwrap_or_default());
        inv.access.check()?;
        match lock_at(&cli.command) {
            LockAt::Never => {}
            LockAt::AfterConsent => inv.defer_writer(verb.into(), take),
        }
        if let Verb::Chroot { dataset, .. } = &cli.command {
            inv.access.open_chroot(dataset)?;
        }
        execute(&mut inv, cli, numbers, listed_boot)
    })();
    let result = match (result, inv.access.close()) {
        (result, Ok(())) => result,
        (result, Err(cleanup)) => Err(format!(
            "{}. Pool cleanup failed. {cleanup}. Inspect zboot status before booting",
            result
                .err()
                .map_or_else(|| "The command completed".into(), |error| error.to_string())
        )
        .into()),
    };
    // The writer lock goes with the invocation, after its output.
    inv.finish(result, verb)
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

    thread_local! {
        static TAKEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// A fake lock taker that records that it ran.
    fn take(
        _: &str,
    ) -> Result<Option<zfs_tools::engine::lock::WriterLock>, zfs_tools::engine::lock::LockError>
    {
        TAKEN.set(true);
        Ok(None)
    }

    /// `consent_to` for a verb that defers its lock, with a fake lock taker:
    /// returns the plan calls, each with whether the lock was held then.
    fn consented(dry_run: bool, confirm: Option<&str>) -> (bool, Vec<bool>) {
        TAKEN.set(false);
        let mut inv = Invocation::new(true);
        inv.defer_writer("drop".into(), take);
        let calls = std::cell::RefCell::new(Vec::new());
        let result = consent_to(
            &mut inv,
            Consent {
                dry_run,
                confirm: confirm.map(String::from),
            },
            || {
                calls.borrow_mut().push(TAKEN.get());
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
            matches!(inv.writer, Writer::Held(_)),
            proceeded,
            "the lock is held exactly when consent proceeds"
        );
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
        // A command that takes no lock does not take one here.
        assert!(!writer_for(&mut Invocation::new(false), &()).unwrap());
    }

    #[test]
    fn a_lossless_preview_takes_no_lock_and_a_change_plans_once_under_it() {
        for (dry_run, expected) in [(true, vec![false]), (false, vec![true])] {
            TAKEN.set(false);
            let mut inv = Invocation::new(true);
            inv.defer_writer("snapshot".into(), take);
            let calls = std::cell::RefCell::new(Vec::new());
            let result = lossless(
                &mut inv,
                dry_run,
                || {
                    calls.borrow_mut().push(TAKEN.get());
                    Ok(7u8)
                },
                |_| String::new(),
            );
            assert_eq!(*calls.borrow(), expected);
            assert_eq!(result.unwrap(), (!dry_run).then_some(7u8));
            let preview = inv.response.take();
            assert_eq!(preview.is_some(), dry_run);
            assert!(preview.is_none_or(|value| value.get("token").is_none()));
        }
    }

    #[test]
    fn a_replan_naming_an_unreviewed_pool_refuses_as_stale_or_to_run_again() {
        assert!(replan_refusal(&[], true).is_none());
        for (confirmed, code) in [(true, 3), (false, 1)] {
            zfs_tools::engine::effect::reset();
            let refusal = replan_refusal(&["bpool".into()], confirmed).unwrap();
            assert_eq!(crate::consent::is_stale(refusal.as_ref()), confirmed);
            assert_eq!(finish(Err(refusal), None, false, "sync"), code);
        }
    }

    #[test]
    fn the_library_entry_point_parses_its_supplied_arguments_and_returns_status() {
        assert_eq!(main(["zboot", "unknown-verb"]), 2);
        assert_eq!(main(["zboot", "--version"]), 0);
    }

    #[test]
    fn successive_menu_commands_restore_the_session_and_clear_their_effects() {
        zfs_tools::engine::effect::reset();
        zfs_tools::engine::effect::operation_hint("outer operation");
        for previous_effect in [false, true] {
            if previous_effect {
                zfs_tools::engine::effect::mark();
            }
            {
                let _session = MenuEffects::new();
                assert!(!zfs_tools::engine::effect::any());
                assert!(zfs_tools::engine::effect::operation_hints().is_empty());
                zfs_tools::engine::effect::mark();
                zfs_tools::engine::effect::operation_hint("inner operation");
            }
            assert_eq!(zfs_tools::engine::effect::any(), previous_effect);
            assert_eq!(
                zfs_tools::engine::effect::operation_hints(),
                vec!["outer operation"]
            );
        }
        zfs_tools::engine::effect::reset();
    }
}
