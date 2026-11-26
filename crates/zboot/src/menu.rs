//! The standalone RAM recovery menu: its console loop, commands and the shared
//! recovery error. Boot construction and the kexec handoff ([`crate::handoff`])
//! share the application safety rules.

mod console;
mod discovery;
mod host_words;
pub(crate) mod hostid_adopt;
pub(crate) mod inventory;
mod menu_connect;
mod menu_view;
pub mod pool_access;
pub(crate) mod ram_boot;
mod screen;
pub(crate) mod select;

use crate::handoff::{
    HandoffRequest, discovery_imports_allowed, handoff, handoff_automatic, prove_ram,
    readonly_pools,
};
use inventory::{MenuInventory, boot_entries, menu_inventory, render_menu};
use screen::{Screen, Update, View};
use select::{
    AccessHold, CountdownOutcome, TerminalMode, auto_boot_request, boot_request, boot_shortcut,
    countdown_refusal, input_ready, listed_boot_request, parsed_menu_command, poll_remote_access,
    report_countdown_refusal, run_countdown_with,
};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use zfs_tools::engine::{
    Error as NativeError,
    state::{self, NativeState},
};

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("{0}")]
    Refused(String),
    #[error(transparent)]
    Native(#[from] NativeError),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{program} failed: {detail}")]
    Command { program: String, detail: String },
    #[error("{operation}: {source}")]
    Context {
        operation: &'static str,
        #[source]
        source: Box<RecoveryError>,
    },
    #[error("{activity} failed ({primary}); {operation} failed: {cleanup}")]
    Cleanup {
        activity: &'static str,
        #[source]
        primary: Box<RecoveryError>,
        operation: &'static str,
        cleanup: Box<RecoveryError>,
    },
}
pub type Result<T> = std::result::Result<T, RecoveryError>;
pub(crate) fn refuse(message: impl Into<String>) -> RecoveryError {
    RecoveryError::Refused(message.into())
}
pub(crate) fn at(operation: &'static str, source: RecoveryError) -> RecoveryError {
    RecoveryError::Context {
        operation,
        source: Box::new(source),
    }
}

pub(crate) fn cleanup_error(
    result: Result<()>,
    operation: &'static str,
    cleanup: RecoveryError,
) -> RecoveryError {
    cleanup_error_for("handoff", result, operation, cleanup)
}

fn cleanup_error_for(
    activity: &'static str,
    result: Result<()>,
    operation: &'static str,
    cleanup: RecoveryError,
) -> RecoveryError {
    match result {
        Err(primary) => RecoveryError::Cleanup {
            activity,
            primary: Box::new(primary),
            operation,
            cleanup: Box::new(cleanup),
        },
        Ok(()) => at(operation, cleanup),
    }
}

fn menu_ready_line() -> String {
    format!(
        "ZBOOT_MENU_READY version={} source_sha256_prefix={}",
        env!("CARGO_PKG_VERSION"),
        crate::build_identity::SOURCE_SHA256_PREFIX
    )
}

fn connect_available() -> bool {
    menu_connect::available()
}

fn menu_shortcuts(can_connect: bool) -> &'static str {
    if can_connect {
        "Boot: N or N.M | Enter: redraw | status: machine state | connect: SSH | help"
    } else {
        "Boot: N or N.M | Enter: redraw | status: machine state | help"
    }
}

pub(crate) fn import_readonly() -> Result<()> {
    import_readonly_with_policy(false)
}

/// A shell/SSH storage action uses only its selected pools. If another pool is
/// already writable, do not discover/import more pools or change host identity.
/// The common CLI still admits every pool it reopens, under its writer lock.
pub(crate) fn import_readonly_for_action() -> Result<()> {
    import_readonly_with_policy(true)
}

fn import_readonly_with_policy(allow_existing_writable: bool) -> Result<()> {
    prove_ram()?;
    let observed = state::observe()?;
    if !discovery_imports_allowed(&observed, allow_existing_writable)? {
        let writable = observed
            .inspection
            .pools
            .iter()
            .filter(|pool| observed.pool_properties[&pool.name]["readonly"].value == "off")
            .map(|pool| zfs_tools::engine::escape_display(&pool.name))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("menu discovery skipped while pools {writable} are imported writable");
        return Ok(());
    }
    discovery::start()?;
    discovery::wait()?;
    readonly_pools(&state::observe()?)
}

/// Join in-flight imports before a foreground command acquires the writer.
/// The closure runs while local discovery scheduling remains excluded.
pub(crate) fn after_imports<T, E: From<RecoveryError>>(
    action: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    discovery::barrier(action)
}

/// Boot the request a menu line built from its displayed table, or else a
/// freshly inspected BE with its discovered kernel/initrd pair.
pub(crate) fn boot(
    dataset: Option<String>,
    kernel: Option<String>,
    listed: Option<HandoffRequest>,
) -> Result<()> {
    prove_ram()?;
    import_readonly()?;
    let request = match listed {
        Some(request) => request,
        None => {
            let named = dataset.clone();
            boot_request(dataset, kernel, || {
                boot_entries(&state::observe()?, named.as_deref())
            })?
        }
    };
    handoff(&request)
}

// Read exactly one line without buffering bytes that belong to a subsequently
// spawned maintenance shell. StdinLock's shared buffer can otherwise consume
// pasted shell input before the shell inherits the terminal descriptor.
fn console_line(input: &mut impl Read) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    let mut byte = [0];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if line.len() >= 65536 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "menu input exceeds 64 KiB",
                    ));
                }
                line.push(byte[0]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Interrupted operations, as `status` lists them; `resume` continues one.
fn print_operations() -> Result<()> {
    let listing = crate::restore::list(&mut crate::restore::Native::new())?;
    for operation in &listing.operations {
        println!(
            "Interrupted {} {} on pool {} after step {}; continue with resume",
            zfs_tools::engine::escape_display(operation.kind.as_deref().unwrap_or("unreadable")),
            zfs_tools::engine::escape_display(operation.id.as_deref().unwrap_or("-")),
            zfs_tools::engine::escape_display(&operation.pool),
            zfs_tools::engine::escape_display(operation.step.as_deref().unwrap_or("-")),
        );
    }
    for orphan in &listing.orphans {
        println!(
            "{}",
            zfs_tools::engine::escape_display(&crate::status::capitalized(&orphan.describe()))
        );
    }
    Ok(())
}

fn shutdown_from_menu(restart: bool) -> Result<()> {
    prove_ram()?;
    let _writer = after_imports(|| {
        zfs_tools::engine::lock::for_command("zboot", "menu shutdown")
            .map_err(|error| refuse(error.to_string()))
    })?;
    for (program, arguments) in [
        ("/bin/sync", vec![]),
        ("/sbin/zpool", vec!["export", "-a"]),
        (
            "/bin/busybox",
            vec![if restart { "reboot" } else { "poweroff" }, "-f"],
        ),
    ] {
        let mut mutates = false;
        if program == "/sbin/zpool" {
            let observed = state::observe()?;
            for pool in &observed.inspection.pools {
                match observed
                    .pool_properties
                    .get(&pool.name)
                    .and_then(|properties| properties.get("readonly"))
                    .map(|property| property.value.as_str())
                {
                    Some("off") => mutates = true,
                    Some("on") => {}
                    _ => {
                        return Err(refuse(format!(
                            "pool readonly property was not observed before export: {}",
                            pool.name
                        )));
                    }
                }
            }
        }
        let mut child =
            zfs_tools::engine::native::announced(Command::new(program).args(arguments)).spawn()?;
        if mutates {
            zfs_tools::engine::effect::mark();
        }
        let status = child.wait()?;
        if !status.success() {
            return Err(refuse(format!(
                "{program} returned {status}; reboot stopped"
            )));
        }
    }
    Err(refuse("reboot returned without restarting"))
}

/// The BE labels the menu displayed, each bound to the incarnation it showed.
fn numbering(entries: &[menu_view::MenuEntry]) -> crate::status::Numbering {
    crate::status::Numbering {
        boot: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                (
                    entry.candidate.dataset.clone(),
                    ((index + 1).to_string(), entry.candidate.identity.clone()),
                )
            })
            .collect(),
    }
}

fn menu_prompt(output: &mut impl Write, shown: &mut bool) -> io::Result<()> {
    if !*shown {
        write!(output, "zboot> ")?;
        output.flush()?;
        *shown = true;
    }
    Ok(())
}

fn menu_ready_to_announce(
    progress: &discovery::Progress,
    inventory: &MenuInventory,
    entering_countdown: Option<&HandoffRequest>,
) -> bool {
    !inventory.retry_needed() && (progress.settled() || entering_countdown.is_some())
}

fn announce_menu_ready(
    announced: &mut bool,
    prompt_shown: &mut bool,
    output: &mut impl Write,
) -> io::Result<()> {
    if !*announced {
        if *prompt_shown {
            writeln!(output)?;
        }
        writeln!(output, "{}", menu_ready_line())?;
        *prompt_shown = false;
        *announced = true;
    }
    Ok(())
}

fn view(inventory: &MenuInventory) -> View {
    View {
        entries: inventory.entries.clone(),
        pairs: inventory.pairs.clone(),
        adoption: hostid_adopt::adopted()
            .map(|adoption| hostid_adopt::banner(&adoption))
            .unwrap_or_default(),
    }
}

/// The full listing, recorded as shown. Its first line is a fresh one.
fn list_menu(
    screen: &mut Screen,
    inventory: &MenuInventory,
    prompt_shown: &mut bool,
) -> Result<()> {
    render_menu(inventory)?;
    println!("{}", menu_shortcuts(connect_available()));
    screen.listing(view(inventory), discovery::progress().findings());
    *prompt_shown = false;
    Ok(())
}

/// Discovery lines, on a fresh line when the prompt is showing.
fn print_findings(
    lines: &[String],
    prompt_shown: &mut bool,
    output: &mut impl Write,
) -> io::Result<()> {
    if *prompt_shown {
        writeln!(output)?;
    }
    for line in lines {
        writeln!(output, "{line}")?;
    }
    *prompt_shown = false;
    Ok(())
}

/// The live SSH session's lines, repeated so they stay the console's last.
fn print_ssh_lines(lines: &[String], output: &mut impl Write) -> io::Result<()> {
    for line in lines {
        writeln!(output, "{line}")?;
    }
    Ok(())
}

/// Held for the life of the UKI's menu. A second `menu`, typed at the prompt,
/// in the shell or over SSH, finds it taken and is refused.
const MENU_LOCK: &str = "/run/zboot-menu.lock";

fn menu_lock(path: &Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |_| refuse("the menu is already running; menu is what the UKI runs at start-up"),
    )?;
    Ok(file)
}

pub(crate) fn start(no_autoboot: bool) -> Result<()> {
    prove_ram()?;
    let _menu = menu_lock(Path::new(MENU_LOCK))?;
    let result = run_menu(no_autoboot);
    match menu_connect::stop() {
        Ok(()) => result,
        Err(cleanup) => Err(cleanup_error_for("menu", result, "stop SSH", cleanup)),
    }
}

fn run_menu(no_autoboot: bool) -> Result<()> {
    // ESP consumption completes its deletion, sync and unmount before this
    // function can activate networking or start the discovery coordinator.
    let mut access_hold = if let Err(error) = menu_connect::recover() {
        eprintln!(
            "menu SSH cleanup: {}",
            zfs_tools::engine::escape_display(&error.to_string())
        );
        AccessHold::CleanupFailed
    } else {
        match crate::remote_access::consume_startup() {
            Ok(Some(keys)) => {
                let hold = AccessHold::waiting(Instant::now());
                if !keys.is_empty()
                    && let Err(error) = menu_connect::start_keys(&keys)
                {
                    eprintln!(
                        "menu SSH: {}",
                        zfs_tools::engine::escape_display(&error.to_string())
                    );
                }
                hold
            }
            Ok(None) => AccessHold::Inactive,
            Err(error) => {
                eprintln!(
                    "menu access request: {}",
                    zfs_tools::engine::escape_display(&error.to_string())
                );
                AccessHold::Inactive
            }
        }
    };
    if access_hold.watches_console() {
        println!(
            "Remote-access wait lasts ten minutes. A console key or successful SSH login holds the menu."
        );
    }
    // A previous maintenance shell may deliberately have reopened archive
    // storage writable. Keep the console available after a menu restart;
    // import_readonly still refuses to import or reconfigure that state.
    if let Err(error) = discovery::start() {
        eprintln!(
            "menu import: {}",
            zfs_tools::engine::escape_display(&error.to_string())
        );
    }
    if let Err(error) = print_operations() {
        eprintln!(
            "menu operation discovery: {}",
            zfs_tools::engine::escape_display(&error.to_string())
        );
    }
    if no_autoboot {
        println!(
            "Select N for a boot environment or N.M for a kernel. Automatic default boot is disabled; type help for menu commands."
        );
    } else {
        println!(
            "Select N for a boot environment or N.M for a kernel. The [once] target or, otherwise, the unique bootable [default] boots after 5 seconds; press any key to pause. Type help for menu commands."
        );
    }
    let mut input = std::fs::File::open("/proc/self/fd/0")?;
    let input_fd = input.try_clone()?;
    let mut import_revision = discovery::progress().revision();
    let mut inventory = MenuInventory::default();
    inventory.refresh_with(menu_inventory);
    // The first listing waits for discovery to settle (screen.rs); the
    // countdown below still starts on its own readiness, listing first.
    let mut screen = Screen::new(Instant::now());
    let mut ready_announced = false;
    let mut countdown_reason_checked = false;
    let mut last_countdown_reason = None;
    let mut autoboot_consumed = no_autoboot;
    let mut prompt_shown = false;
    let mut displayed_access = access_hold;
    loop {
        if poll_remote_access(&mut access_hold) {
            prompt_shown = false;
        }
        let access_released = access_hold.released(displayed_access);
        if access_released {
            // SSH may have repaired the default, assets or mounting policy.
            // Re-evaluate the ordinary gates after an automatic access window.
            autoboot_consumed = no_autoboot;
            countdown_reason_checked = false;
        }
        displayed_access = access_hold;
        let progress = discovery::progress();
        // SSH lines go last after anything this pass prints.
        let mut printed = false;
        if access_released || inventory.retry_needed() || progress.revision() != import_revision {
            let revision_changed = progress.revision() != import_revision;
            let previous_error = inventory.error.clone();
            let refreshed = inventory.refresh_with(menu_inventory);
            if refreshed {
                countdown_reason_checked = false;
            }
            if revision_changed {
                screen.changed(Instant::now());
            }
            if refreshed || revision_changed {
                match screen.update(&view(&inventory), progress.findings()) {
                    Update::Nothing => {}
                    Update::Lines(lines) => {
                        print_findings(&lines, &mut prompt_shown, &mut io::stdout())?;
                        printed = true;
                    }
                    Update::Listing => {
                        list_menu(&mut screen, &inventory, &mut prompt_shown)?;
                        printed = true;
                    }
                }
            }
            if inventory.error != previous_error {
                prompt_shown = false;
            }
            import_revision = progress.revision();
        }
        if screen.due(
            Instant::now(),
            progress.settled() && !inventory.retry_needed(),
        ) {
            list_menu(&mut screen, &inventory, &mut prompt_shown)?;
            printed = true;
        }
        if screen.listed()
            && !ready_announced
            && menu_ready_to_announce(&progress, &inventory, None)
        {
            if let Some(error) = progress.error() {
                eprintln!("menu import: {}", zfs_tools::engine::escape_display(error));
            }
            announce_menu_ready(&mut ready_announced, &mut prompt_shown, &mut io::stdout())?;
            printed = true;
        }
        if printed {
            print_ssh_lines(&menu_connect::banner(), &mut io::stdout())?;
        }
        let check_countdown_refusal = |observed: &NativeState,
                                       last_reason: &mut Option<String>,
                                       prompt_shown: &mut bool,
                                       autoboot_consumed: &mut bool|
         -> Result<bool> {
            let reason = countdown_refusal(observed, hostid_adopt::countdown_refusal());
            if report_countdown_refusal(reason.as_deref(), last_reason, &mut io::stdout())? {
                *prompt_shown = false;
            }
            if reason.is_some() {
                *autoboot_consumed = true;
                return Ok(true);
            }
            Ok(false)
        };
        if !countdown_reason_checked
            && !access_hold.blocks_countdown()
            && progress.local_ready
            && let Some(observed) = inventory.countdown_state()
        {
            check_countdown_refusal(
                observed,
                &mut last_countdown_reason,
                &mut prompt_shown,
                &mut autoboot_consumed,
            )?;
            countdown_reason_checked = true;
        }
        if !autoboot_consumed
            && !access_hold.blocks_countdown()
            && progress.countdown_ready()
            && let Some(observed) = inventory.countdown_state()
            && !check_countdown_refusal(
                observed,
                &mut last_countdown_reason,
                &mut prompt_shown,
                &mut autoboot_consumed,
            )?
            && let Some(request) = auto_boot_request(&inventory.entries)
        {
            if !screen.listed() {
                list_menu(&mut screen, &inventory, &mut prompt_shown)?;
            }
            if menu_ready_to_announce(&progress, &inventory, Some(&request)) {
                announce_menu_ready(&mut ready_announced, &mut prompt_shown, &mut io::stdout())?;
            }
            print_ssh_lines(&menu_connect::banner(), &mut io::stdout())?;
            autoboot_consumed = true;
            let mut retry_inventory = false;
            let countdown =
                run_countdown_with(&mut input, input_fd.as_fd(), &request.dataset, || {
                    let progress = discovery::progress();
                    if progress.revision() != import_revision {
                        import_revision = progress.revision();
                        if !inventory.refresh_with(menu_inventory) {
                            retry_inventory = true;
                            return Ok(false);
                        }
                        if inventory.countdown_state().is_none_or(|observed| {
                            countdown_refusal(observed, hostid_adopt::countdown_refusal()).is_some()
                        }) {
                            return Ok(false);
                        }
                    }
                    Ok(auto_boot_request(&inventory.entries).as_ref() == Some(&request))
                });
            if retry_inventory {
                autoboot_consumed = no_autoboot;
                countdown_reason_checked = false;
            }
            let discovery_may_have_superseded = matches!(
                countdown,
                Ok(CountdownOutcome::Changed | CountdownOutcome::TimedOut)
            );
            match countdown {
                Ok(CountdownOutcome::TimedOut) => {
                    if let Err(error) = handoff_automatic(&request) {
                        inventory.refresh_with(menu_inventory);
                        eprintln!(
                            "menu auto-boot: {}",
                            zfs_tools::engine::escape_display(&error.to_string())
                        );
                    }
                }
                Ok(
                    CountdownOutcome::Paused
                    | CountdownOutcome::Changed
                    | CountdownOutcome::Unavailable,
                ) => {}
                Err(error) => eprintln!(
                    "menu auto-boot disabled: {}",
                    zfs_tools::engine::escape_display(&error.to_string())
                ),
            }
            list_menu(&mut screen, &inventory, &mut prompt_shown)?;
            print_ssh_lines(&menu_connect::banner(), &mut io::stdout())?;
            // A removable one-shot disk can arrive during the ordinary default's
            // countdown or the import barrier. Give its own target a full window.
            if discovery_may_have_superseded
                && request.selection == crate::handoff::PairSelection::PoolDefault
                && inventory.countdown_state().is_some()
                && auto_boot_request(&inventory.entries)
                    .is_some_and(|new| new.selection == crate::handoff::PairSelection::Once)
            {
                autoboot_consumed = false;
                countdown_reason_checked = false;
                continue;
            }
        }
        // No prompt before the first listing: it would precede the menu.
        if screen.listed() {
            menu_prompt(&mut io::stdout(), &mut prompt_shown)?;
        }
        let mut terminal = if access_hold.watches_console() {
            TerminalMode::enter(input_fd.as_fd())?
        } else {
            None
        };
        while !input_ready(input_fd.as_fd(), Duration::from_millis(200))? {
            if poll_remote_access(&mut access_hold) {
                prompt_shown = false;
                break;
            }
            if discovery::progress().revision() != import_revision || inventory.retry_needed() {
                break;
            }
            if screen.due(Instant::now(), false) {
                break;
            }
        }
        if input_ready(input_fd.as_fd(), Duration::ZERO)?
            && let Some(mode) = terminal.as_mut()
        {
            let mut pause = [0];
            input.read_exact(&mut pause)?;
            mode.discard_pause_input()?;
            mode.restore()?;
            access_hold.console_key();
            autoboot_consumed = true;
            println!("\rMenu held by the console.");
            prompt_shown = false;
            continue;
        }
        drop(terminal);
        if !input_ready(input_fd.as_fd(), Duration::ZERO)? {
            continue;
        }
        access_hold.console_key();
        autoboot_consumed = true;
        prompt_shown = false;
        let Some(line) = console_line(&mut input)? else {
            return Err(refuse("menu console closed"));
        };
        let mut words = match console::parse_line(&line) {
            Ok(words) => words,
            Err(error) => {
                eprintln!("menu: {error}");
                continue;
            }
        };
        if words.first().is_some_and(|word| word == "zboot") {
            words.remove(0);
        }
        if words.first().is_some_and(|word| word == "ls") {
            words[0] = "status".into();
        }
        let borrowed = words.iter().map(String::as_str).collect::<Vec<_>>();
        let mut pre_execution = false;
        // Enter, list, rescan and a completed command show the full listing.
        let mut relist = false;
        let result = (|| -> Result<()> {
            match borrowed.as_slice() {
                [] | ["list"] => {
                    relist = true;
                    return Ok(());
                }
                ["help"] => {
                    return Ok(console::render_help(
                        &mut io::stdout(),
                        connect_available(),
                    )?);
                }
                ["help", command] => {
                    return match crate::cli::grammar::Cli::parse_from_args([
                        "zboot", command, "--help",
                    ]) {
                        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
                            print!("{error}");
                            Ok(())
                        }
                        Err(error) => Err(refuse(error.to_string())),
                        Ok(_) => Ok(()),
                    };
                }
                ["connect"] | ["connect", "--new"] => {
                    prove_ram()?;
                    if !connect_available() {
                        return Err(refuse("connect is unavailable in this UKI"));
                    }
                    return menu_connect::connect(borrowed.len() == 2);
                }
                ["rescan"] => {
                    discovery::start()?;
                    inventory.refresh_with(menu_inventory);
                    relist = true;
                    return Ok(());
                }
                ["shell"] => {
                    prove_ram()?;
                    println!("Local RAM shell. Exit returns to the menu.");
                    let status = zfs_tools::engine::native::announced(
                        Command::new("/bin/sh")
                            .arg("-i")
                            .env("PS1", "zboot-shell# "),
                    )
                    .status()?;
                    println!("Maintenance shell returned ({status}).");
                    return Ok(());
                }
                ["reboot"] => return shutdown_from_menu(true),
                ["poweroff"] => return shutdown_from_menu(false),
                _ => {}
            }
            pre_execution = true;
            // Numbers resolve against the displayed tables only; the command
            // checks their identities at entry and under its lock.
            let (cli, bindings, shortcut) = if words.len() == 1
                && words[0].as_bytes().first().is_some_and(u8::is_ascii_digit)
            {
                let (cli, bindings, request) = boot_shortcut(&words[0], &inventory.entries)?;
                (cli, bindings, Some(request))
            } else {
                let (cli, bindings) = parsed_menu_command(&words, &inventory.entries)?;
                (cli, bindings, None)
            };
            let bindings = crate::cli::access::Bindings { datasets: bindings };
            let listing = matches!(cli.command, crate::cli::grammar::Verb::Status { .. });
            let armed_boot = matches!(
                cli.command,
                crate::cli::grammar::Verb::Boot { tar: None, .. }
            ) && inventory.entries.iter().any(|entry| entry.candidate.once);
            let numbers = numbering(&inventory.entries);
            let listed_boot = match shortcut {
                Some(request) => Some(request),
                None => listed_boot_request(&cli, &inventory.entries)?,
            };
            pre_execution = false;
            let code = crate::cli::run_menu(cli, bindings, Some(&numbers), listed_boot);
            // Export or execution can fail after the one-shot mark was consumed.
            if (code == 0 && !listing) || armed_boot {
                inventory.refresh_with(menu_inventory);
                relist = true;
            }
            Ok(())
        })();
        if relist {
            list_menu(&mut screen, &inventory, &mut prompt_shown)?;
            print_ssh_lines(&menu_connect::banner(), &mut io::stdout())?;
        }
        if let Err(error) = result {
            if pre_execution {
                crate::cli::finish_menu_pre_execution(&words, Box::new(error));
            } else {
                eprintln!(
                    "menu: {}",
                    zfs_tools::engine::escape_display(&error.to_string())
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::handoff::tests::{fixture, fixture_with_be_guid};
    use crate::menu::inventory::MenuInventory;
    use crate::menu::inventory::tests::{displayed_be, menu_entry, menu_kernel};
    use crate::menu::select::{auto_boot_request, boot_shortcut, parsed_menu_command};

    #[test]
    fn menu_shortcuts_show_connect_only_when_ssh_is_available() {
        assert!(menu_shortcuts(true).contains("connect"));
        assert!(!menu_shortcuts(false).contains("connect"));
    }

    #[test]
    fn status_numbers_are_the_displayed_boot_entries() {
        let prior = fixture_with_be_guid(true, 10);
        let entry = displayed_be(&prior);
        let numbers = numbering(std::slice::from_ref(&entry));
        assert_eq!(
            numbers.boot.get(&entry.candidate.dataset),
            Some(&("1".to_owned(), entry.candidate.identity.clone()))
        );
        assert_eq!(numbers.boot.len(), 1);
    }

    #[test]
    fn inventory_retries_do_not_repeat_an_already_displayed_prompt() {
        let mut output = Vec::new();
        let mut shown = false;
        for _ in 0..32 {
            menu_prompt(&mut output, &mut shown).unwrap();
        }
        assert_eq!(output, b"zboot> ");
        shown = false;
        menu_prompt(&mut output, &mut shown).unwrap();
        assert_eq!(output, b"zboot> zboot> ");
    }

    #[test]
    #[allow(unsafe_code)]
    fn pre_execution_menu_failures_use_one_isolated_cli_envelope() {
        use std::{fs, os::fd::AsRawFd, process::Command};
        const CASE: &str = "ZBOOT_MENU_PRE_EXECUTION_CASE";
        const OUTPUT: &str = "ZBOOT_MENU_PRE_EXECUTION_OUTPUT";
        const SELF: &str = "menu::tests::pre_execution_menu_failures_use_one_isolated_cli_envelope";
        if let Ok(case) = std::env::var(CASE) {
            let output = fs::File::create_new(std::env::var_os(OUTPUT).unwrap()).unwrap();
            io::stdout().flush().unwrap();
            // Redirect only this fresh child after the test harness prologue.
            assert_eq!(
                unsafe { libc::dup2(output.as_raw_fd(), libc::STDOUT_FILENO) },
                libc::STDOUT_FILENO
            );
            assert!(!zfs_tools::engine::effect::any());
            zfs_tools::engine::effect::mark();
            zfs_tools::engine::effect::operation_hint("outer-menu-operation");
            let words = match case.as_str() {
                "short" => vec!["drop", "short", "--json"],
                "number" => vec!["drop", "1", "--json"],
                "syntax" => vec!["drop", "tank/ROOT/be", "--unknown", "--json"],
                "shortcut" => vec!["99"],
                _ => panic!("unknown menu error case"),
            }
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
            let observed = fixture(true);
            let error: Box<dyn std::error::Error> = match case.as_str() {
                "shortcut" => Box::new(boot_shortcut(&words[0], &[]).unwrap_err()),
                "number" => {
                    let entry = displayed_be(&observed);
                    let replaced =
                        fixture_with_be_guid(true, entry.candidate.identity.guid.get() + 1);
                    let (_, datasets) = parsed_menu_command(&words, &[entry]).unwrap();
                    Box::new(
                        crate::cli::access::Bindings { datasets }
                            .check_state(&replaced)
                            .unwrap_err(),
                    )
                }
                _ => Box::new(parsed_menu_command(&words, &[]).unwrap_err()),
            };
            let code = crate::cli::finish_menu_pre_execution(&words, error);
            assert!(
                zfs_tools::engine::effect::any(),
                "outer menu effect must be restored"
            );
            assert_eq!(
                zfs_tools::engine::effect::operation_hints(),
                ["outer-menu-operation"]
            );
            std::process::exit(code);
        }
        for (case, expected, mode) in [
            ("short", 1, Some("refused")),
            ("number", 1, Some("refused")),
            ("syntax", 2, None),
            ("shortcut", 1, None),
        ] {
            let scratch = crate::factory::tests::Scratch::new();
            let output = scratch.0.join("stdout");
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", SELF, "--nocapture"])
                .env(CASE, case)
                .env(OUTPUT, &output)
                .output()
                .unwrap();
            assert_eq!(
                child.status.code(),
                Some(expected),
                "{case}: {}",
                String::from_utf8_lossy(&child.stderr)
            );
            let bytes = fs::read(output).unwrap();
            if let Some(mode) = mode {
                let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(envelope["schema_version"], 1);
                assert_eq!(envelope["mode"], mode);
                assert!(envelope.get("result").is_some());
                if case == "number" {
                    assert!(
                        envelope["result"]["message"]
                            .as_str()
                            .unwrap()
                            .contains("changed since it was displayed")
                    );
                }
            } else {
                assert!(bytes.is_empty(), "{case} must not emit JSON");
            }
        }
    }

    #[test]
    fn a_discovery_line_starts_a_fresh_line_and_the_ssh_lines_follow_it() {
        let mut output = Vec::new();
        let mut shown = false;
        menu_prompt(&mut output, &mut shown).unwrap();
        print_findings(
            &["found pool data on /dev/vdb".into()],
            &mut shown,
            &mut output,
        )
        .unwrap();
        print_ssh_lines(
            &["Menu SSH enabled".into(), "Host key words: 1 a".into()],
            &mut output,
        )
        .unwrap();
        assert!(!shown, "the prompt returns below the SSH lines");
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "zboot> \nfound pool data on /dev/vdb\nMenu SSH enabled\nHost key words: 1 a\n"
        );
    }

    #[test]
    fn partial_console_confirmation_at_eof_is_cancelled() {
        assert_eq!(console_line(&mut io::Cursor::new(b"tank")).unwrap(), None);
        assert_eq!(
            console_line(&mut io::Cursor::new(b"tank\n")).unwrap(),
            Some("tank".into())
        );
    }

    #[test]
    fn oversized_console_input_is_rejected() {
        let mut input = io::Cursor::new(vec![b'x'; 65537]);
        assert_eq!(
            console_line(&mut input).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn menu_line_leaves_pasted_shell_input_for_the_child() {
        let mut input = io::Cursor::new(b"shell\nprintf 'from-shell\\n'\nexit\n");
        assert_eq!(console_line(&mut input).unwrap().as_deref(), Some("shell"));
        let mut remaining = String::new();
        input.read_to_string(&mut remaining).unwrap();
        assert_eq!(remaining, "printf 'from-shell\\n'\nexit\n");
        assert_eq!(console_line(&mut input).unwrap(), None);
    }

    #[test]
    fn the_ready_line_names_the_version_and_the_source() {
        let ready = menu_ready_line();
        assert!(ready.starts_with(concat!(
            "ZBOOT_MENU_READY version=",
            env!("CARGO_PKG_VERSION"),
            " "
        )));
        assert!(ready.ends_with(&format!(
            " source_sha256_prefix={}",
            crate::build_identity::SOURCE_SHA256_PREFIX
        )));
    }
    #[test]
    fn a_second_menu_is_refused_while_the_first_runs() {
        let path =
            std::env::temp_dir().join(format!("zboot-menu-lock-test-{}", uuid::Uuid::new_v4()));
        let first = menu_lock(&path).unwrap();
        let error = menu_lock(&path).unwrap_err().to_string();
        assert!(error.contains("already running"), "{error}");
        drop(first);
        menu_lock(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn local_prefix_readiness_announces_only_when_an_eligible_countdown_starts() {
        let mut progress = discovery::Progress::default();
        assert!(!progress.countdown_ready());
        progress.local_ready = true;
        assert!(progress.countdown_ready());
        assert!(!progress.settled());
        let mut inventory = MenuInventory::default();
        assert!(inventory.refresh_with(|| Ok((fixture(true), Vec::new()))));
        assert!(!menu_ready_to_announce(&progress, &inventory, None));

        inventory.entries = vec![menu_entry(
            "tank/ROOT/be",
            true,
            None,
            vec![menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true)],
            None,
        )];
        let request = auto_boot_request(&inventory.entries).unwrap();
        // Disabled automatic boot, a hold and policy refusals never enter the
        // countdown branch, even when a default is displayed.
        assert!(!menu_ready_to_announce(&progress, &inventory, None));
        assert!(menu_ready_to_announce(
            &progress,
            &inventory,
            Some(&request)
        ));
        inventory.error = Some("inventory needs another observation".into());
        assert!(!menu_ready_to_announce(
            &progress,
            &inventory,
            Some(&request)
        ));
    }

    #[test]
    fn readiness_is_announced_once_on_a_physical_line_before_countdown_output() {
        let mut output = Vec::new();
        let mut shown = false;
        let mut announced = false;
        menu_prompt(&mut output, &mut shown).unwrap();
        announce_menu_ready(&mut announced, &mut shown, &mut output).unwrap();
        writeln!(output, "Countdown starts").unwrap();
        announce_menu_ready(&mut announced, &mut shown, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.matches("ZBOOT_MENU_READY").count(), 1);
        assert!(text.starts_with("zboot> \nZBOOT_MENU_READY"));
        assert!(text.find("ZBOOT_MENU_READY").unwrap() < text.find("Countdown starts").unwrap());
        assert!(!shown);
    }
}
