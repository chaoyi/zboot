//! Menu selectors, the automatic-boot countdown and the remote-access hold.
use super::{Result, at, console, hostid_adopt, menu_connect, menu_view, refuse};
use crate::handoff::{HandoffRequest, PairSelection};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    termios::{
        InputModes, LocalModes, OptionalActions, QueueSelector, SpecialCodeIndex, Termios, isatty,
        tcflush, tcgetattr, tcsetattr,
    },
};
use std::io::{self, Read, Write};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};
use zfs_tools::engine::{DatasetIdentity, state::NativeState};

/// Build the only request that is safe to start without an operator command.
/// A marked pool default must be unique, eligible, and expose one explicit
/// default pair.  In particular, the menu never guesses a pair for a timed
/// boot when the displayed inventory is ambiguous.
pub(super) fn auto_boot_request(entries: &[menu_view::MenuEntry]) -> Option<HandoffRequest> {
    let mut defaults = entries.iter().filter(|entry| entry.candidate.default);
    let entry = defaults.next()?;
    if defaults.next().is_some()
        || entry.candidate.refusal.is_some()
        || entry.asset_refusal.is_some()
    {
        return None;
    }

    let mut kernels = entry.kernels.iter().filter(|kernel| kernel.default);
    let kernel = kernels.next()?;
    if kernels.next().is_some() {
        return None;
    }
    Some(HandoffRequest {
        selection: PairSelection::PoolDefault,
        expected_assets: kernel.assets.clone(),
        dataset: entry.candidate.dataset.clone(),
        kernel: Some(kernel.kernel.clone()),
        initrd: Some(kernel.initrd.clone()),
        expected_identity: Some(entry.candidate.identity.clone()),
    })
}

/// Why the menu does not count down. An adopted identity disables OpenZFS's
/// second-writer refusal, so the countdown runs only when adoption found
/// every pool member local and no hibernation image (`hazard`). And it never
/// runs while a boot environment has a `canmount=on` descendant: the operator
/// decides which one boots and fixes the child there.
pub(crate) fn countdown_refusal(state: &NativeState, hazard: Option<String>) -> Option<String> {
    hazard.or_else(|| crate::mounting::refusal(state, None))
}

/// Preserve the last semantic warning across unrelated import revisions.
/// A resolved refusal clears its identity so a later recurrence is reported.
pub(super) fn report_countdown_refusal(
    reason: Option<&str>,
    reported: &mut Option<String>,
    output: &mut impl Write,
) -> io::Result<bool> {
    if reported.as_deref() == reason {
        return Ok(false);
    }
    if let Some(reason) = reason {
        writeln!(output, "{}", hostid_adopt::countdown_line(reason))?;
        *reported = Some(reason.to_owned());
        Ok(true)
    } else {
        *reported = None;
        Ok(false)
    }
}

/// Bare `boot` makes exactly the request the timed default boot would make.
fn bare_boot_request(entries: &[menu_view::MenuEntry]) -> Result<HandoffRequest> {
    auto_boot_request(entries).ok_or_else(|| {
        refuse("no unique eligible default with one default kernel pair; use boot N or N.M")
    })
}

const AUTOBOOT_SECONDS: u64 = 5;

pub(super) struct TerminalMode {
    fd: OwnedFd,
    saved: Termios,
    restored: bool,
}

impl TerminalMode {
    pub(super) fn enter(fd: BorrowedFd<'_>) -> io::Result<Option<Self>> {
        // Pipes and redirected stdin remain fully usable for scripted menu
        // clients, but must never receive a timed boot they cannot pause.
        if !isatty(fd) {
            return Ok(None);
        }

        let owned = fd.try_clone_to_owned()?;
        let saved = tcgetattr(&owned).map_err(io::Error::from)?;
        let mut raw = saved.clone();
        raw.input_modes.remove(InputModes::IXON | InputModes::IXOFF);
        raw.local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO | LocalModes::ISIG | LocalModes::IEXTEN);
        raw.special_codes[SpecialCodeIndex::VMIN] = 0;
        raw.special_codes[SpecialCodeIndex::VTIME] = 0;

        let mut mode = Self {
            fd: owned,
            saved,
            restored: false,
        };
        if let Err(error) = tcsetattr(&mode.fd, OptionalActions::Now, &raw) {
            let error = io::Error::from(error);
            let _ = mode.restore();
            return Err(error);
        }
        Ok(Some(mode))
    }

    pub(super) fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        tcsetattr(&self.fd, OptionalActions::Now, &self.saved).map_err(io::Error::from)?;
        self.restored = true;
        Ok(())
    }

    pub(super) fn discard_pause_input(&self) -> io::Result<()> {
        // An arrow/function key may deliver several bytes. None of the pause
        // keystroke should become a prefix of the next menu command.
        tcflush(&self.fd, QueueSelector::IFlush).map_err(io::Error::from)?;
        Ok(())
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        if !self.restored {
            let _ = tcsetattr(&self.fd, OptionalActions::Now, &self.saved);
        }
    }
}

pub(super) fn input_ready(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        let remaining = match deadline {
            Some(until) => until.saturating_duration_since(Instant::now()),
            None => timeout,
        };
        let ts = Timespec::try_from(remaining).unwrap_or(Timespec {
            tv_sec: i64::MAX,
            tv_nsec: 0,
        });
        let mut descriptors = [PollFd::new(&fd, PollFlags::IN)];
        match poll(&mut descriptors, Some(&ts)) {
            Ok(0) => return Ok(false),
            Ok(_) => {
                return Ok(descriptors[0]
                    .revents()
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR));
            }
            Err(Errno::INTR) => {
                if !timeout.is_zero() && deadline.is_some_and(|until| Instant::now() >= until) {
                    return Ok(false);
                }
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

fn consume_one(input: &mut impl Read) -> io::Result<()> {
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CountdownOutcome {
    Unavailable,
    Paused,
    TimedOut,
}

/// Give a real terminal five one-second chances to pause the one permitted
/// default handoff.  The terminal guard is released before either returning a
/// pause or allowing the caller to run handoff/menu commands.
#[cfg(test)]
fn run_countdown(
    input: &mut impl Read,
    fd: BorrowedFd<'_>,
    dataset: &str,
) -> Result<CountdownOutcome> {
    run_countdown_with(input, fd, dataset, || Ok(true))
}

pub(super) fn run_countdown_with(
    input: &mut impl Read,
    fd: BorrowedFd<'_>,
    dataset: &str,
    mut still_valid: impl FnMut() -> Result<bool>,
) -> Result<CountdownOutcome> {
    let Some(mut terminal) = TerminalMode::enter(fd)? else {
        return Ok(CountdownOutcome::Unavailable);
    };
    let escaped_dataset = zfs_tools::engine::escape_display(dataset);
    let result = (|| {
        let mut stdout = io::stdout();
        for remaining in (1..=AUTOBOOT_SECONDS).rev() {
            if !still_valid()? {
                terminal.restore()?;
                writeln!(
                    stdout,
                    "\rAuto-boot cancelled because pool discovery changed the default.    "
                )?;
                return Ok(CountdownOutcome::Paused);
            }
            write!(
                stdout,
                "\rAuto-booting {} in {remaining}s; press any key to pause.   ",
                escaped_dataset
            )?;
            stdout.flush()?;
            if input_ready(fd, Duration::from_secs(1))? {
                consume_one(input)?;
                terminal.discard_pause_input()?;
                terminal.restore()?;
                writeln!(
                    stdout,
                    "\rAuto-boot paused; select N/N.M or type a menu command.          "
                )?;
                stdout.flush()?;
                return Ok(CountdownOutcome::Paused);
            }
        }
        if !still_valid()? {
            terminal.restore()?;
            writeln!(
                stdout,
                "\rAuto-boot cancelled because pool discovery changed the default.    "
            )?;
            return Ok(CountdownOutcome::Paused);
        }
        terminal.restore()?;
        writeln!(
            stdout,
            "\rAuto-booting {} now.                                             ",
            escaped_dataset
        )?;
        stdout.flush()?;
        Ok(CountdownOutcome::TimedOut)
    })();
    if result.is_err() {
        let _ = terminal.restore();
    }
    result
}

/// A command-line `boot`: the request from a fresh discovery of every BE.
pub(super) fn boot_request(
    dataset: Option<String>,
    kernel: Option<String>,
    discover: impl FnOnce() -> Result<Vec<menu_view::MenuEntry>>,
) -> Result<HandoffRequest> {
    select_boot_request(&discover()?, dataset.as_deref(), kernel.as_deref())
}

fn select_boot_request(
    entries: &[menu_view::MenuEntry],
    dataset: Option<&str>,
    kernel: Option<&str>,
) -> Result<HandoffRequest> {
    let pool_default = dataset.is_none();
    if pool_default && kernel.is_none() {
        return bare_boot_request(entries);
    }
    let (index, entry) = if let Some(dataset) = dataset {
        entries
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.candidate.dataset == dataset)
            .ok_or_else(|| refuse("boot environment is not listed"))?
    } else {
        let defaults: Vec<_> = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.candidate.default)
            .collect();
        let [selected] = defaults.as_slice() else {
            return Err(refuse("no unique pool boot default; choose an explicit BE"));
        };
        *selected
    };
    let dataset = &entry.candidate.dataset;
    if let Some(reason) = &entry.candidate.refusal {
        return Err(refuse(format!(
            "boot environment {dataset} is blocked: {reason}"
        )));
    }
    if let Some(reason) = &entry.asset_refusal {
        return Err(refuse(format!(
            "boot environment {dataset} assets are blocked: {reason}"
        )));
    }
    let selector = match kernel {
        None => (index + 1).to_string(),
        Some(name) => {
            let matching: Vec<_> = entry
                .kernels
                .iter()
                .enumerate()
                .filter(|(_, choice)| kernel_name(choice) == name)
                .map(|(index, _)| index + 1)
                .collect();
            let [number] = matching.as_slice() else {
                return Err(refuse(format!(
                    "kernel name {} must match exactly one listed kernel of {dataset}; \
                     boot {dataset} takes its default pair",
                    zfs_tools::engine::escape_display(name)
                )));
            };
            format!("{}.{}", index + 1, number)
        }
    };
    let mut request = menu_view::select(entries, &selector)?;
    if pool_default {
        request.selection = PairSelection::PoolDefaultKernel;
    }
    Ok(request)
}

fn kernel_name(choice: &menu_view::KernelChoice) -> String {
    let filename = choice
        .kernel
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    filename
        .strip_prefix("vmlinuz-")
        .unwrap_or(&filename)
        .to_owned()
}

/// A maintenance selection may name a blocked BE: repairing that BE is the
/// point. It binds the identity that was displayed.
fn resolve_be_selector(
    value: &str,
    entries: &[menu_view::MenuEntry],
) -> Result<Option<(String, DatasetIdentity)>> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let index = value
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| refuse("invalid BE number; use ls to inspect the menu"))?;
    let selected = entries
        .get(index)
        .ok_or_else(|| refuse("unknown BE number; use ls to inspect the menu"))?;
    Ok(Some((
        selected.candidate.dataset.clone(),
        selected.candidate.identity.clone(),
    )))
}

/// A target's name and, for a displayed number, the identity it showed.
fn resolve_console_target(
    target: &str,
    entries: &[menu_view::MenuEntry],
    datasets: &console::DatasetMenu,
) -> Result<(String, Option<DatasetIdentity>)> {
    if let Some((dataset, identity)) = resolve_be_selector(target, entries)? {
        return Ok((dataset, Some(identity)));
    }
    if target.strip_prefix('d').is_some_and(|number| {
        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        let (dataset, identity) = datasets
            .resolve(target)
            .map_err(|error| refuse(error.to_string()))?;
        return Ok((dataset, Some(identity)));
    }
    if !target.contains('/') {
        return Err(refuse(
            "menu targets require a displayed number or full dataset name",
        ));
    }
    Ok((crate::cli::names::resolve(Some(target), None)?, None))
}

type DisplayedBindings = Vec<(String, DatasetIdentity)>;
type ParsedCommand = (crate::cli::grammar::Cli, DisplayedBindings);

/// Resolve only the grammar's target fields, through the displayed tables.
/// Option values and a chroot tail remain the exact tokens supplied by the
/// console tokenizer.
pub(super) fn parsed_menu_command(
    words: &[String],
    entries: &[menu_view::MenuEntry],
    datasets: &console::DatasetMenu,
) -> Result<ParsedCommand> {
    use crate::cli::grammar::Cli;
    let mut cli =
        Cli::parse_for_menu(std::iter::once("zboot").chain(words.iter().map(String::as_str)))
            .map_err(|error| refuse(error.to_string()))?;
    let mut bindings = Vec::new();
    for target in cli.command.targets_mut() {
        let (dataset, snapshot) = target
            .split_once('@')
            .map_or((target.as_str(), None), |(dataset, snapshot)| {
                (dataset, Some(snapshot))
            });
        let (resolved, identity) = resolve_console_target(dataset, entries, datasets)?;
        if let Some(identity) = identity {
            bindings.push((resolved.clone(), identity));
        }
        *target = match snapshot {
            Some(snapshot) => {
                let value = format!("{resolved}@{snapshot}");
                zfs_tools::engine::validate_snapshot_name(&value)?;
                value
            }
            None => resolved,
        };
    }
    Ok((cli, bindings))
}

/// `N` and `N.M` name a displayed entry and pair: the request is built here,
/// once, from the displayed table and goes to the handoff as it is.
pub(super) fn boot_shortcut(
    value: &str,
    entries: &[menu_view::MenuEntry],
) -> Result<(crate::cli::grammar::Cli, DisplayedBindings, HandoffRequest)> {
    let request = menu_view::select(entries, value)
        .map_err(|error| at("run rescan to update the displayed boot selection", error))?;
    let cli = crate::cli::grammar::Cli {
        verbose: false,
        command: crate::cli::grammar::Verb::Boot {
            dataset: Some(request.dataset.clone()),
            kernel: None,
            tar: None,
            overlay: Vec::new(),
            json: false,
        },
    };
    let bindings = vec![(
        request.dataset.clone(),
        request
            .expected_identity
            .clone()
            .expect("menu selection binds identity"),
    )];
    Ok((cli, bindings, request))
}

pub(super) fn listed_boot_request(
    cli: &crate::cli::grammar::Cli,
    entries: &[menu_view::MenuEntry],
) -> Result<Option<HandoffRequest>> {
    let crate::cli::grammar::Verb::Boot {
        dataset,
        kernel,
        tar: None,
        ..
    } = &cli.command
    else {
        return Ok(None);
    };
    // A displayed refusal remains authoritative until the operator rescans.
    // An explicit name outside that display may take the ordinary discovery path.
    if dataset.as_ref().is_some_and(|dataset| {
        !entries
            .iter()
            .any(|entry| &entry.candidate.dataset == dataset)
    }) {
        return Ok(None);
    }
    select_boot_request(entries, dataset.as_deref(), kernel.as_deref())
        .map(Some)
        .map_err(|error| at("run rescan to update the displayed boot selection", error))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AccessHold {
    Inactive,
    Waiting(Instant),
    Authenticated,
    Held,
    CleanupFailed,
}

impl AccessHold {
    pub(super) fn waiting(now: Instant) -> Self {
        Self::Waiting(now + Duration::from_secs(600))
    }

    pub(super) fn watches_console(self) -> bool {
        matches!(self, Self::Waiting(_) | Self::Authenticated)
    }

    pub(super) fn blocks_countdown(self) -> bool {
        self != Self::Inactive
    }

    pub(super) fn released(self, previous: Self) -> bool {
        previous.watches_console() && self == Self::Inactive
    }

    pub(super) fn console_key(&mut self) {
        if *self != Self::CleanupFailed {
            *self = Self::Held;
        }
    }

    fn event(&mut self, event: menu_connect::Event) {
        if !self.watches_console() {
            return;
        }
        *self = match event {
            menu_connect::Event::Authenticated => Self::Authenticated,
            menu_connect::Event::SessionEnded | menu_connect::Event::Stopped
                if *self == Self::Authenticated =>
            {
                Self::Inactive
            }
            _ => *self,
        };
    }

    fn expire(&mut self, now: Instant) -> bool {
        if matches!(*self, Self::Waiting(deadline) if now >= deadline) {
            *self = Self::Inactive;
            true
        } else {
            false
        }
    }
}

pub(super) fn poll_remote_access(hold: &mut AccessHold) -> bool {
    let before = *hold;
    match menu_connect::poll() {
        Ok(events) => {
            for event in events {
                if matches!(*hold, AccessHold::Waiting(_)) && event == menu_connect::Event::Stopped
                {
                    println!(
                        "SSH access stopped. The remote-access wait continues until its ten-minute deadline."
                    );
                }
                hold.event(event);
            }
        }
        Err(error) => {
            let cleanup_failed = matches!(&error, menu_connect::PollError::Cleanup(_));
            if cleanup_failed && before == AccessHold::CleanupFailed {
                return false;
            }
            eprintln!(
                "menu SSH: {}",
                zfs_tools::engine::escape_display(&error.to_string())
            );
            if cleanup_failed {
                *hold = AccessHold::CleanupFailed;
            } else {
                hold.event(menu_connect::Event::Stopped);
            }
            if let Err(error) = menu_connect::stop() {
                eprintln!(
                    "menu SSH cleanup: {}",
                    zfs_tools::engine::escape_display(&error.to_string())
                );
                *hold = AccessHold::CleanupFailed;
            }
        }
    }
    let expired = hold.expire(Instant::now());
    if before.watches_console() && *hold == AccessHold::Inactive {
        match menu_connect::stop() {
            Ok(()) => {
                if expired {
                    println!(
                        "Remote-access wait ended. Automatic boot follows the ordinary menu conditions."
                    );
                } else {
                    println!(
                        "Automatic SSH session ended. Automatic boot follows the ordinary menu conditions."
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "menu SSH cleanup: {}",
                    zfs_tools::engine::escape_display(&error.to_string())
                );
                *hold = AccessHold::CleanupFailed;
            }
        }
    }
    before != *hold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handoff::tests::{
        Fake, Scratch, fixture, fixture_with_be_guid, fixture_with_extra_bes, two_bes, two_bes_on,
    };
    use crate::handoff::{
        Action, AssetHashes, HandoffRequest, PairSelection, handoff_with, validate_native_default,
    };
    use crate::menu::inventory::tests::{displayed_be, menu_entry, menu_kernel};
    use crate::menu::inventory::{candidates, kernel_choices, stable_entries};
    use crate::menu::{Result, console, console_line, menu_connect, menu_view, refuse};
    use std::os::fd::{AsFd, AsRawFd};
    use std::path::{Path, PathBuf};

    use zfs_tools::engine::{
        InspectRequest,
        native::{self},
    };

    #[test]
    fn an_empty_request_holds_for_the_complete_ten_minutes() {
        let start = Instant::now();
        let mut hold = AccessHold::waiting(start);
        assert!(hold.blocks_countdown());
        assert!(!hold.expire(start + Duration::from_secs(599)));
        assert!(hold.blocks_countdown());
        assert!(hold.expire(start + Duration::from_secs(600)));
        assert!(!hold.blocks_countdown());
    }

    #[test]
    fn a_console_key_holds_the_menu_for_good() {
        let start = Instant::now();
        let mut hold = AccessHold::waiting(start);
        hold.console_key();
        hold.event(menu_connect::Event::Authenticated);
        hold.event(menu_connect::Event::SessionEnded);
        hold.event(menu_connect::Event::Stopped);
        assert!(!hold.expire(start + Duration::from_secs(3600)));
        assert!(hold.blocks_countdown());
    }

    #[test]
    fn failed_ssh_cleanup_keeps_the_countdown_disabled_after_console_input() {
        let mut hold = AccessHold::CleanupFailed;
        hold.console_key();
        hold.event(menu_connect::Event::Stopped);
        assert!(!hold.expire(Instant::now() + Duration::from_secs(3600)));
        assert_eq!(hold, AccessHold::CleanupFailed);
        assert!(hold.blocks_countdown());
    }

    #[test]
    fn ending_remote_access_rechecks_a_changed_default_and_kernel_choice() {
        let mut hold = AccessHold::waiting(Instant::now());
        hold.event(menu_connect::Event::Authenticated);
        let previous = hold;
        hold.event(menu_connect::Event::SessionEnded);
        assert!(hold.released(previous));
        let old = menu_entry(
            "tank/ROOT/be",
            false,
            None,
            vec![menu_kernel("boot/vmlinuz-old", "boot/initrd.img-old", true)],
            None,
        );
        assert!(auto_boot_request(std::slice::from_ref(&old)).is_none());
        let mut current = old.clone();
        current.candidate.default = true;
        current.kernels = vec![menu_kernel("boot/vmlinuz-new", "boot/initrd.img-new", true)];
        let entries = stable_entries(&[old], vec![current]);
        let request = auto_boot_request(&entries).unwrap();
        assert_eq!(
            request.kernel.as_deref(),
            Some(Path::new("boot/vmlinuz-new"))
        );
        hold.console_key();
        assert!(!AccessHold::Inactive.released(hold));
        assert!(!AccessHold::Inactive.released(AccessHold::CleanupFailed));
    }

    #[test]
    fn a_successful_login_holds_until_the_last_automatic_session_ends() {
        let start = Instant::now();
        let mut hold = AccessHold::waiting(start);
        hold.event(menu_connect::Event::Authenticated);
        assert!(!hold.expire(start + Duration::from_secs(3600)));
        assert!(hold.blocks_countdown());
        hold.event(menu_connect::Event::SessionEnded);
        assert!(!hold.blocks_countdown());
    }

    #[test]
    fn a_stopped_listener_preserves_the_unauthenticated_ten_minute_wait() {
        let start = Instant::now();
        let mut hold = AccessHold::waiting(start);
        let waiting = hold;
        hold.event(menu_connect::Event::Stopped);
        hold.event(menu_connect::Event::SessionEnded);
        assert_eq!(hold, waiting);
        assert!(!hold.expire(start + Duration::from_secs(60)));
        assert!(!hold.expire(start + Duration::from_secs(599)));
        assert!(hold.expire(start + Duration::from_secs(600)));
        assert!(!hold.blocks_countdown());
    }

    #[test]
    fn authentication_and_console_holds_do_not_request_a_release_refresh() {
        let waiting = AccessHold::waiting(Instant::now());
        let mut authenticated = waiting;
        authenticated.event(menu_connect::Event::Authenticated);
        assert!(!authenticated.released(waiting));
        let mut console = authenticated;
        console.console_key();
        assert!(!console.released(authenticated));
        authenticated.event(menu_connect::Event::Stopped);
        assert!(authenticated.released(AccessHold::Authenticated));
    }

    #[test]
    fn after_the_wait_the_ordinary_countdown_runs_with_all_its_conditions() {
        let start = Instant::now();
        let mut hold = AccessHold::waiting(start);
        assert!(hold.expire(start + Duration::from_secs(600)));
        assert!(!hold.blocks_countdown());
        assert!(countdown_refusal(&two_bes(false), None).is_none());
        assert_eq!(
            countdown_refusal(&two_bes(false), Some("hibernation".into())).as_deref(),
            Some("hibernation")
        );
    }

    #[test]
    fn maintenance_number_binds_identity_but_allows_a_blocked_be() {
        let state = fixture(true);
        let mut entry = menu_entry("tank/ROOT/be", false, Some("repair needed"), vec![], None);
        entry.candidate.identity = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == "tank/ROOT/be")
            .unwrap()
            .identity
            .clone();
        let bound = resolve_be_selector("1", &[entry.clone()]).unwrap().unwrap();
        assert_eq!(
            bound,
            ("tank/ROOT/be".into(), entry.candidate.identity.clone())
        );
        let bindings = |bound| crate::cli::access::Bindings {
            datasets: vec![bound],
            ..Default::default()
        };
        bindings(bound).check_state(&state).unwrap();
        entry.candidate.identity.guid = zfs_tools::engine::Guid::new(99999);
        let stale = resolve_be_selector("1", &[entry]).unwrap().unwrap();
        assert!(
            bindings(stale)
                .check_state(&state)
                .unwrap_err()
                .to_string()
                .contains("changed since it was displayed")
        );
        assert!(resolve_be_selector("0", &[]).is_err());
        assert!(resolve_be_selector("2", &[]).is_err());
        assert_eq!(resolve_be_selector("tank/ROOT/be", &[]).unwrap(), None);
    }

    #[test]
    fn a_menu_line_and_a_command_line_parse_to_the_same_command() {
        use crate::cli::grammar::Cli;
        let words = console::parse_line("cmdline tank/ROOT/be --set 'loglevel=4 quiet'").unwrap();
        let (menu, bindings) =
            parsed_menu_command(&words, &[], &console::DatasetMenu::default()).unwrap();
        let cli = Cli::parse_from_args([
            "zboot",
            "cmdline",
            "tank/ROOT/be",
            "--set",
            "loglevel=4 quiet",
        ])
        .unwrap();
        assert_eq!(menu, cli);
        assert!(bindings.is_empty());
    }

    #[test]
    fn a_stale_number_is_refused() {
        let displayed = fixture(true);
        let entry = displayed_be(&displayed);
        let datasets = console::DatasetMenu::from_state(&displayed);
        let words = ["drop", "1"].map(String::from);
        let replaced = fixture_with_be_guid(true, entry.candidate.identity.guid.get() + 1);
        let (_, datasets) = parsed_menu_command(&words, &[entry], &datasets).unwrap();
        let bindings = crate::cli::access::Bindings {
            datasets,
            ..Default::default()
        };
        bindings.check_state(&displayed).unwrap();
        let error = bindings.check_state(&replaced).unwrap_err().to_string();
        assert!(error.contains("changed since it was displayed"), "{error}");
    }

    #[test]
    fn a_number_inside_a_quoted_value_is_left_alone() {
        use crate::cli::grammar::Verb;
        let observed = fixture(true);
        let entries = [displayed_be(&observed)];
        let datasets = console::DatasetMenu::from_state(&observed);
        let words = console::parse_line("cmdline 1 --set 'd2 root=2'").unwrap();
        let (cli, bindings) = parsed_menu_command(&words, &entries, &datasets).unwrap();
        match cli.command {
            Verb::Cmdline { dataset, set, .. } => {
                assert_eq!(dataset.as_deref(), Some("tank/ROOT/be"));
                assert_eq!(set.as_deref(), Some("d2 root=2"));
            }
            _ => panic!("cmdline"),
        }
        assert_eq!(
            bindings,
            [("tank/ROOT/be".into(), entries[0].candidate.identity.clone())]
        );
        let words = console::parse_line("chroot 1 -- printf d2 2").unwrap();
        let (cli, _) = parsed_menu_command(&words, &entries, &datasets).unwrap();
        match cli.command {
            Verb::Chroot { dataset, command } => {
                assert_eq!(dataset, "tank/ROOT/be");
                assert_eq!(command, ["printf", "d2", "2"]);
            }
            _ => panic!("chroot"),
        }
    }

    #[test]
    fn a_short_name_is_refused_in_the_menu() {
        let words = ["drop", "be"].map(String::from);
        let error = parsed_menu_command(&words, &[], &console::DatasetMenu::default())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("full dataset name"), "{error}");
    }

    #[test]
    fn dataset_number_cannot_be_shadowed_by_a_pool_name() {
        let mut state = fixture(true);
        let rows = [("d2", "none", 1), ("tank", "none", 2)];
        let output = rows.iter().map(|(name,mount,id)| format!("{name}\tfilesystem\t{id}\t0\t1000\t0\t{mount}\t-\t{}\t{}\tno\toff\ton\t-\toff\t-\t-\t-\t-\n",id+10,id+20)).collect::<String>();
        state.inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    "d2\t200\t1000\t0\t1000\tONLINE\t-\ntank\t100\t1000\t0\t1000\tONLINE\t-\n"
                        .into()
                } else {
                    output.clone()
                })
            },
        )
        .unwrap();
        let menu = console::DatasetMenu::from_state(&state);
        assert_eq!(resolve_console_target("d2", &[], &menu).unwrap().0, "tank");
    }

    #[test]
    fn auto_boot_requires_one_eligible_default_and_one_default_pair() {
        let entries = vec![
            menu_entry(
                "tank/ROOT/stable",
                true,
                None,
                vec![menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true)],
                None,
            ),
            menu_entry(
                "tank/ROOT/old",
                false,
                None,
                vec![menu_kernel("boot/vmlinuz-0", "boot/initrd.img-0", false)],
                None,
            ),
        ];
        assert_eq!(
            auto_boot_request(&entries),
            Some(HandoffRequest {
                selection: PairSelection::PoolDefault,
                expected_assets: None,
                dataset: "tank/ROOT/stable".into(),
                kernel: Some("boot/vmlinuz-1".into()),
                initrd: Some("boot/initrd.img-1".into()),
                expected_identity: Some(DatasetIdentity {
                    pool_guid: zfs_tools::engine::Guid::new(1),
                    guid: zfs_tools::engine::Guid::new(2),
                    createtxg: zfs_tools::engine::Txg::new(3),
                    objsetid: zfs_tools::engine::ObjsetId::new(4),
                }),
            })
        );

        let blocked = menu_entry(
            "tank/ROOT/stable",
            true,
            Some("blocked"),
            vec![menu_kernel("vmlinuz", "initrd.img", true)],
            None,
        );
        assert_eq!(
            bare_boot_request(&entries).unwrap(),
            auto_boot_request(&entries).unwrap()
        );
        assert!(
            bare_boot_request(std::slice::from_ref(&blocked))
                .unwrap_err()
                .to_string()
                .contains("use boot N or N.M")
        );
        assert!(bare_boot_request(&[entries[0].clone(), entries[0].clone()]).is_err());
        assert!(auto_boot_request(&[blocked]).is_none());
        assert!(auto_boot_request(&[entries[0].clone(), entries[0].clone()]).is_none());
        assert!(
            auto_boot_request(&[menu_entry(
                "tank/ROOT/stable",
                true,
                None,
                vec![
                    menu_kernel("vmlinuz-a", "initrd-a", true),
                    menu_kernel("vmlinuz-b", "initrd-b", true),
                ],
                None,
            )])
            .is_none()
        );
        assert!(
            auto_boot_request(&[menu_entry(
                "tank/ROOT/stable",
                true,
                None,
                vec![menu_kernel("vmlinuz", "initrd.img", false)],
                None,
            )])
            .is_none()
        );
        assert!(
            auto_boot_request(&[menu_entry(
                "tank/ROOT/stable",
                true,
                None,
                vec![menu_kernel("vmlinuz", "initrd.img", true)],
                Some("asset refusal"),
            )])
            .is_none()
        );
        assert!(
            auto_boot_request(&[menu_entry(
                "tank/ROOT/stable",
                false,
                None,
                vec![menu_kernel("vmlinuz", "initrd.img", true)],
                None,
            )])
            .is_none()
        );
    }

    #[test]
    #[allow(unsafe_code)]
    fn countdown_pauses_on_a_bare_key_and_restores_terminal_mode() {
        use std::os::fd::FromRawFd;

        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { std::fs::File::from_raw_fd(master) };
        let mut input = unsafe { std::fs::File::from_raw_fd(slave) };

        let mut before = std::mem::MaybeUninit::<libc::termios>::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(input.as_raw_fd(), before.as_mut_ptr()) },
            0
        );
        let before = unsafe { before.assume_init() };
        master.write_all(b"\x1b[A").unwrap();
        let started = std::time::Instant::now();
        let input_fd = input.try_clone().unwrap();
        let outcome = run_countdown(&mut input, input_fd.as_fd(), "tank/ROOT/stable").unwrap();
        assert_eq!(outcome, CountdownOutcome::Paused);
        assert!(started.elapsed() < Duration::from_secs(1));

        let mut after = std::mem::MaybeUninit::<libc::termios>::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(input.as_raw_fd(), after.as_mut_ptr()) },
            0
        );
        let after = unsafe { after.assume_init() };
        assert_eq!(after.c_iflag, before.c_iflag);
        assert_eq!(after.c_lflag, before.c_lflag);
        assert_eq!(after.c_oflag, before.c_oflag);
        assert_eq!(after.c_cflag, before.c_cflag);
        assert_eq!(after.c_cc, before.c_cc);
        master.write_all(b"1\n").unwrap();
        assert_eq!(console_line(&mut input).unwrap().as_deref(), Some("1"));
    }

    #[test]
    fn a_parsed_menu_boot_retains_its_listed_assets_across_fresh_discovery() {
        let state = fixture(true);
        let mut entry = displayed_be(&state);
        entry.kernels = vec![menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true)];
        entry.kernels[0].assets = Some(AssetHashes {
            kernel_sha256: "a".repeat(64),
            initrd_sha256: "b".repeat(64),
        });
        entry.asset_refusal = None;
        let entries = vec![entry];
        let words = vec!["boot".into(), "1".into(), "--kernel".into(), "1".into()];
        let (cli, _) =
            parsed_menu_command(&words, &entries, &console::DatasetMenu::default()).unwrap();
        // The displayed request goes to the handoff as it is: nothing probes
        // every BE again.
        let request = listed_boot_request(&cli, &entries).unwrap().unwrap();
        let mut backend = Fake::new();
        assert!(
            handoff_with(&request, &mut backend)
                .unwrap_err()
                .to_string()
                .contains("kexec returned")
        );
        assert_eq!(
            backend
                .actions
                .iter()
                .filter(|action| matches!(action, Action::MountReadonly { .. }))
                .count(),
            1
        );
        let mut backend = Fake::new();
        backend.drift = true;
        assert!(handoff_with(&request, &mut backend).is_err());
    }

    fn parsed_bound_boot(
        line: &str,
        entries: &[menu_view::MenuEntry],
        discover: impl FnOnce() -> Result<Vec<menu_view::MenuEntry>>,
    ) -> Result<HandoffRequest> {
        let words = console::parse_line(line).map_err(|error| refuse(error.to_string()))?;
        let (cli, _) = parsed_menu_command(&words, entries, &console::DatasetMenu::default())?;
        cli.validate_complete()
            .map_err(|error| refuse(error.to_string()))?;
        let listed = listed_boot_request(&cli, entries)?;
        let crate::cli::grammar::Verb::Boot {
            dataset, kernel, ..
        } = cli.command
        else {
            panic!("the normal parser must return Boot");
        };
        // As `menu::boot`: a displayed request, else a fresh discovery.
        match listed {
            Some(request) => Ok(request),
            None => boot_request(dataset, kernel, discover),
        }
    }

    fn bound_boot_entries(state: &NativeState) -> Vec<menu_view::MenuEntry> {
        candidates(state)
            .into_iter()
            .map(|candidate| {
                let mut kernels = vec![
                    menu_kernel("boot/vmlinuz-2", "boot/initrd.img-2", true),
                    menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", false),
                ];
                for kernel in &mut kernels {
                    kernel.assets = Some(AssetHashes {
                        kernel_sha256: "a".repeat(64),
                        initrd_sha256: "b".repeat(64),
                    });
                }
                menu_view::MenuEntry {
                    candidate,
                    kernels,
                    asset_refusal: None,
                }
            })
            .collect()
    }

    #[test]
    fn numbers_boot_their_displayed_pair_when_two_kernels_share_a_name() {
        let state = two_bes(false);
        let mut entries = bound_boot_entries(&state);
        for entry in &mut entries {
            entry.kernels[1].kernel = "boot/vmlinuz-2".into();
        }
        let number = entries
            .iter()
            .position(|entry| entry.candidate.dataset == "tank/ROOT/be")
            .unwrap()
            + 1;
        let (cli, bindings, request) = boot_shortcut(&number.to_string(), &entries).unwrap();
        match cli.command {
            crate::cli::grammar::Verb::Boot {
                dataset, kernel, ..
            } => {
                assert_eq!(dataset.as_deref(), Some("tank/ROOT/be"));
                assert_eq!(kernel, None);
            }
            _ => panic!("boot"),
        }
        assert_eq!(
            bindings,
            [(
                "tank/ROOT/be".to_owned(),
                request.expected_identity.clone().unwrap()
            )]
        );
        assert_eq!(request.selection, PairSelection::DefaultPair);
        assert_eq!(
            request.initrd.as_deref(),
            Some(Path::new("boot/initrd.img-2"))
        );
        // `N.M` is the displayed pair itself, not its version name.
        let (_, _, request) = boot_shortcut(&format!("{number}.2"), &entries).unwrap();
        assert_eq!(request.selection, PairSelection::Explicit);
        assert_eq!(request.kernel.as_deref(), Some(Path::new("boot/vmlinuz-2")));
        assert_eq!(
            request.initrd.as_deref(),
            Some(Path::new("boot/initrd.img-1"))
        );
    }

    #[test]
    fn parsed_bare_and_named_default_boots_keep_their_displayed_bindings() {
        let state = two_bes(false);
        let entries = bound_boot_entries(&state);
        for (line, kernel, mode) in [
            ("boot", "2", PairSelection::PoolDefault),
            ("boot --kernel 1", "1", PairSelection::PoolDefaultKernel),
        ] {
            let request = parsed_bound_boot(line, &entries, || {
                panic!("a valid displayed binding must skip all-BE discovery")
            })
            .unwrap();
            assert_eq!(request.selection, mode);
            assert_eq!(request.dataset, "tank/ROOT/be");
            assert_eq!(
                request.kernel,
                Some(PathBuf::from(format!("boot/vmlinuz-{kernel}")))
            );
            validate_native_default(&state, &request).unwrap();
            let discoveries = std::cell::Cell::new(0);
            let standalone = boot_request(
                None,
                (mode == PairSelection::PoolDefaultKernel).then(|| kernel.into()),
                || {
                    discoveries.set(discoveries.get() + 1);
                    Ok(entries.clone())
                },
            )
            .unwrap();
            assert_eq!(discoveries.get(), 1);
            assert_eq!(standalone, request);
            let mut backend = Fake::new();
            backend.state = state.clone();
            let error = handoff_with(&request, &mut backend).unwrap_err();
            assert!(error.to_string().contains("kexec returned"), "{error}");
            assert_eq!(
                backend
                    .actions
                    .iter()
                    .filter(|action| matches!(action, Action::MountReadonly { .. }))
                    .count(),
                1
            );
            let mut backend = Fake::new();
            backend.state = state.clone();
            backend.state.inspection.pools[0].bootfs = Some("tank/ROOT/b".into());
            assert!(
                handoff_with(&request, &mut backend)
                    .unwrap_err()
                    .to_string()
                    .contains("native boot default changed")
            );
            assert!(backend.actions.is_empty());
            let mut changed_assets = request;
            changed_assets
                .expected_assets
                .as_mut()
                .unwrap()
                .kernel_sha256 = "c".repeat(64);
            let mut backend = Fake::new();
            backend.state = state.clone();
            let error = handoff_with(&changed_assets, &mut backend).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("assets changed since the listing"),
                "{error}"
            );
            assert!(
                backend
                    .actions
                    .iter()
                    .all(|action| !matches!(action, Action::Load { .. }))
            );
        }
        let mut explicit_only = entries;
        for entry in &mut explicit_only {
            for kernel in &mut entry.kernels {
                kernel.default = false;
            }
        }
        assert!(parsed_bound_boot("boot", &explicit_only, || panic!("no fallback")).is_err());
        let named = parsed_bound_boot("boot --kernel 1", &explicit_only, || {
            panic!("a named version uses its displayed pair")
        })
        .unwrap();
        assert_eq!(named.selection, PairSelection::PoolDefaultKernel);
    }

    #[test]
    fn parsed_default_boots_refuse_ambiguous_or_blocked_displays_before_discovery() {
        let state = two_bes(false);
        let entries = bound_boot_entries(&state);
        for fault in [
            "missing default",
            "multiple defaults",
            "role refusal",
            "asset refusal",
        ] {
            let mut broken = entries.clone();
            match fault {
                "missing default" => {
                    for entry in &mut broken {
                        entry.candidate.default = false;
                    }
                }
                "multiple defaults" => {
                    for entry in &mut broken {
                        entry.candidate.default = true;
                    }
                }
                "role refusal" => {
                    broken
                        .iter_mut()
                        .find(|entry| entry.candidate.default)
                        .unwrap()
                        .candidate
                        .refusal = Some("pending repair".into())
                }
                "asset refusal" => {
                    broken
                        .iter_mut()
                        .find(|entry| entry.candidate.default)
                        .unwrap()
                        .asset_refusal = Some("missing initrd".into())
                }
                _ => unreachable!(),
            }
            for line in ["boot", "boot --kernel 1"] {
                let error = parsed_bound_boot(line, &broken, || {
                    panic!("a displayed refusal must keep its binding")
                })
                .unwrap_err();
                assert!(error.to_string().contains("run rescan"), "{fault}: {error}");
                let kernel = (line != "boot").then(|| "1".into());
                assert!(boot_request(None, kernel, || Ok(broken.clone())).is_err());
            }
        }
        for fault in ["missing version", "ambiguous version"] {
            let mut broken = entries.clone();
            let entry = broken
                .iter_mut()
                .find(|entry| entry.candidate.default)
                .unwrap();
            if fault == "missing version" {
                entry.kernels.retain(|kernel| kernel_name(kernel) != "1");
            } else {
                entry.kernels.push(entry.kernels[1].clone());
            }
            let error = parsed_bound_boot("boot --kernel 1", &broken, || {
                panic!("a kernel name refusal must not rediscover")
            })
            .unwrap_err();
            assert!(
                error.to_string().contains("exactly one listed kernel"),
                "{error}"
            );
            assert!(error.to_string().contains("run rescan"), "{error}");
        }
    }

    #[test]
    fn repaired_displayed_boot_refusals_require_rescan_and_preserve_explicit_versions() {
        let state = two_bes(false);
        let fresh = bound_boot_entries(&state);
        let mut stale = fresh.clone();
        stale
            .iter_mut()
            .find(|entry| entry.candidate.dataset == "tank/ROOT/be")
            .unwrap()
            .candidate
            .refusal = Some("previous pending state".into());
        for line in [
            "boot",
            "boot --kernel 1",
            "boot tank/ROOT/be",
            "boot 2 --kernel 1",
        ] {
            let error = parsed_bound_boot(line, &stale, || {
                panic!("repair must be acknowledged by a refreshed display")
            })
            .unwrap_err();
            assert!(error.to_string().contains("run rescan"), "{line}: {error}");
        }
        let error = boot_shortcut("2", &stale).unwrap_err();
        assert!(error.to_string().contains("run rescan"), "{error}");
        let request = parsed_bound_boot("boot --kernel 1", &fresh, || {
            panic!("the refreshed binding must remain sufficient")
        })
        .unwrap();
        let scratch = Scratch::new();
        std::fs::create_dir(scratch.0.join("boot")).unwrap();
        for version in ["1", "2"] {
            std::fs::write(scratch.0.join(format!("boot/vmlinuz-{version}")), "kernel").unwrap();
            std::fs::write(
                scratch.0.join(format!("boot/initrd.img-{version}")),
                "initrd",
            )
            .unwrap();
        }
        std::os::unix::fs::symlink("boot/vmlinuz-2", scratch.0.join("vmlinuz")).unwrap();
        std::os::unix::fs::symlink("boot/initrd.img-2", scratch.0.join("initrd.img")).unwrap();
        let mut backend = Fake::new();
        backend.state = state;
        backend.asset_root = Some(scratch.0.clone());
        let error = handoff_with(&request, &mut backend).unwrap_err();
        assert!(error.to_string().contains("kexec returned"), "{error}");
        assert_eq!(
            backend
                .actions
                .iter()
                .filter(|action| matches!(action, Action::MountReadonly { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn a_received_copy_is_listed_but_never_counted_down() {
        let entries = vec![menu_entry(
            "tank/ROOT/received",
            false,
            None,
            vec![menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true)],
            None,
        )];
        assert_eq!(auto_boot_request(&entries), None);
        assert!(bare_boot_request(&entries).is_err());
        assert!(menu_view::select(&entries, "1").is_ok());
    }

    #[test]
    #[allow(unsafe_code)]
    fn a_default_arriving_during_the_countdown_cancels_it() {
        use std::os::fd::FromRawFd;
        let first = menu_entry(
            "tank/ROOT/one",
            true,
            None,
            vec![menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true)],
            None,
        );
        let mut entries = vec![first.clone()];
        let armed = auto_boot_request(&entries).unwrap();
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: openpty initializes both descriptors and each is owned once.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let _master = unsafe { std::fs::File::from_raw_fd(master) };
        let mut input = unsafe { std::fs::File::from_raw_fd(slave) };
        let fd = input.try_clone().unwrap();
        let started = std::time::Instant::now();
        let mut second = first;
        second.candidate.dataset = "late/ROOT/two".into();
        let outcome = run_countdown_with(&mut input, fd.as_fd(), &armed.dataset, || {
            entries.push(second.clone());
            Ok(auto_boot_request(&entries).as_ref() == Some(&armed))
        })
        .unwrap();
        assert_eq!(outcome, CountdownOutcome::Paused);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_canmount_on_dataset_stops_the_countdown() {
        for hazard in ["tank/ROOT/be", "tank/ROOT/be/var", "tank/ROOT/b/var"] {
            let state = two_bes_on(&[hazard]);
            let reason = countdown_refusal(&state, None).expect("the countdown stops");
            assert!(reason.contains(hazard), "{reason}");
        }
        assert_eq!(countdown_refusal(&two_bes(false), None), None);
    }

    #[test]
    fn countdown_refusal_output_tracks_reason_changes_and_recurrence() {
        let mut reported = None;
        let mut output = Vec::new();
        assert!(
            report_countdown_refusal(Some("unsafe child"), &mut reported, &mut output).unwrap()
        );
        let first = output.clone();
        assert!(
            !report_countdown_refusal(Some("unsafe child"), &mut reported, &mut output).unwrap()
        );
        assert_eq!(output, first);
        assert!(
            report_countdown_refusal(Some("hibernation image"), &mut reported, &mut output)
                .unwrap()
        );
        let changed = output.clone();
        assert!(!report_countdown_refusal(None, &mut reported, &mut output).unwrap());
        assert_eq!(output, changed);
        assert_eq!(reported, None);
        assert!(
            report_countdown_refusal(Some("unsafe child"), &mut reported, &mut output).unwrap()
        );
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert_eq!(text.matches("unsafe child").count(), 2);
        assert_eq!(text.matches("hibernation image").count(), 1);
    }
    #[test]
    fn default_pair_handoff_checks_the_pointer_inside_its_only_mount() {
        let scratch = Scratch::new();
        std::fs::create_dir(scratch.0.join("boot")).unwrap();
        for version in ["1", "2"] {
            std::fs::write(scratch.0.join(format!("boot/vmlinuz-{version}")), "kernel").unwrap();
            std::fs::write(
                scratch.0.join(format!("boot/initrd.img-{version}")),
                "initrd",
            )
            .unwrap();
        }
        let point = |version: &str| {
            for (link, target) in [("vmlinuz", "vmlinuz"), ("initrd.img", "initrd.img")] {
                let path = scratch.0.join(link);
                if path.symlink_metadata().is_ok() {
                    std::fs::remove_file(&path).unwrap();
                }
                std::os::unix::fs::symlink(format!("boot/{target}-{version}"), path).unwrap();
            }
        };
        point("1");
        let mut entry = displayed_be(&fixture(true));
        entry.kernels = kernel_choices(&scratch.0).unwrap();
        entry.asset_refusal = None;
        let mut request = menu_view::select(&[entry], "1").unwrap();
        request.expected_assets = Some(AssetHashes {
            kernel_sha256: "a".repeat(64),
            initrd_sha256: "b".repeat(64),
        });
        point("2");
        for selection in [
            PairSelection::DefaultPair,
            PairSelection::PoolDefault,
            PairSelection::Explicit,
        ] {
            let mut request = request.clone();
            request.selection = selection;
            let mut backend = Fake::new();
            if selection == PairSelection::PoolDefault {
                backend.state.inspection.pools[0].bootfs = Some(request.dataset.clone());
            }
            backend.asset_root = Some(scratch.0.clone());
            let error = handoff_with(&request, &mut backend).unwrap_err();
            if selection == PairSelection::Explicit {
                assert!(error.to_string().contains("kexec returned"), "{error}");
                assert!(
                    backend
                        .actions
                        .iter()
                        .any(|action| matches!(action, Action::Load { .. }))
                );
            } else {
                assert!(
                    error
                        .to_string()
                        .contains("default kernel/initrd pair changed"),
                    "{error}"
                );
                assert!(matches!(
                    backend.actions.as_slice(),
                    [Action::MountReadonly { .. }, Action::Unmount { .. }]
                ));
            }
        }
        // The selected kernel can remain intact while its default alias escapes.
        std::fs::remove_file(scratch.0.join("vmlinuz")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", scratch.0.join("vmlinuz")).unwrap();
        let mut backend = Fake::new();
        backend.asset_root = Some(scratch.0.clone());
        let error = handoff_with(&request, &mut backend).unwrap_err();
        assert!(error.to_string().contains("symlink escapes"), "{error}");
        assert!(
            backend
                .actions
                .iter()
                .all(|action| !matches!(action, Action::Load { .. }))
        );
    }

    #[test]
    fn a_bound_pool_default_rechecks_native_defaults_without_reprobing_assets() {
        let mut backend = Fake::new();
        backend.state = fixture_with_extra_bes(&["tank/ROOT/b".into()], "tank/ROOT/be");
        let mut entry = displayed_be(&backend.state);
        entry.candidate.default = true;
        let mut kernel = menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true);
        kernel.assets = Some(AssetHashes {
            kernel_sha256: "a".repeat(64),
            initrd_sha256: "b".repeat(64),
        });
        entry.kernels = vec![kernel];
        entry.asset_refusal = None;
        // A bound bare boot goes to the handoff without repeating asset discovery.
        let request = auto_boot_request(&[entry]).unwrap();
        validate_native_default(&backend.state, &request).unwrap();
        let mut second = backend.state.inspection.pools[0].clone();
        second.name = "late".into();
        second.guid = zfs_tools::engine::Guid::new(200);
        second.bootfs = Some("late/root".into());
        backend.state.inspection.pools.push(second);
        assert!(validate_native_default(&backend.state, &request).is_err());
        backend.state.inspection.pools.pop();
        backend.state.inspection.pools[0].bootfs = Some("tank/ROOT/b".into());
        let error = handoff_with(&request, &mut backend).unwrap_err();
        assert!(
            error.to_string().contains("native boot default changed"),
            "{error}"
        );
        assert!(backend.actions.is_empty());
    }
}
