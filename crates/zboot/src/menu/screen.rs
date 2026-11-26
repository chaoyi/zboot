//! What the menu console prints, and when. Append-only, with no cursor control,
//! so serial consoles and transcripts read the same as a screen.
//!
//! The first listing waits until pool discovery has finished, has been quiet
//! for [`QUIET`], or [`CAP`] has passed since the menu started. After it, a
//! discovery event prints one line; the full listing returns only when the
//! operator asks for it or the inventory (numbered BEs, kernels, pairs, adopted
//! identity) changed. The caller prints the SSH lines after each of these, so
//! they stay at the bottom of a console without scrollback.

use super::menu_view::MenuEntry;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

pub(super) const QUIET: Duration = Duration::from_secs(1);
pub(super) const CAP: Duration = Duration::from_secs(3);

/// The displayed entries, pair relationships and adoption banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct View {
    pub(super) entries: Vec<MenuEntry>,
    pub(super) pairs: Vec<String>,
    pub(super) adoption: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Update {
    Nothing,
    /// Discovery lines not printed before, oldest first.
    Lines(Vec<String>),
    /// The selectable view changed: print the whole listing.
    Listing,
}

pub(super) struct Screen {
    start: Instant,
    last_change: Instant,
    shown: Option<View>,
    reported: BTreeSet<String>,
}

impl Screen {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            start: now,
            last_change: now,
            shown: None,
            reported: BTreeSet::new(),
        }
    }

    pub(super) fn listed(&self) -> bool {
        self.shown.is_some()
    }

    /// Discovery progress moved.
    pub(super) fn changed(&mut self, now: Instant) {
        self.last_change = now;
    }

    /// Whether the held first listing is due. `finished`: discovery ended
    /// and the inventory reflects it, so no further event is expected.
    pub(super) fn due(&self, now: Instant, finished: bool) -> bool {
        !self.listed()
            && (finished
                || now.saturating_duration_since(self.last_change) >= QUIET
                || now.saturating_duration_since(self.start) >= CAP)
    }

    /// Record a full listing of `view`, which includes every finding so far.
    pub(super) fn listing(&mut self, view: View, findings: Vec<String>) {
        self.shown = Some(view);
        self.reported.extend(findings);
    }

    /// After the first listing, what a refreshed inventory should print.
    pub(super) fn update(&mut self, view: &View, findings: Vec<String>) -> Update {
        let Some(shown) = &self.shown else {
            return Update::Nothing;
        };
        if shown != view {
            return Update::Listing;
        }
        let fresh: Vec<String> = findings
            .into_iter()
            .filter(|line| !self.reported.contains(line))
            .collect();
        if fresh.is_empty() {
            Update::Nothing
        } else {
            self.reported.extend(fresh.iter().cloned());
            Update::Lines(fresh)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::menu::inventory::tests::{menu_entry, menu_kernel};

    fn view(datasets: &[&str]) -> View {
        View {
            entries: datasets
                .iter()
                .map(|dataset| {
                    menu_entry(
                        dataset,
                        false,
                        None,
                        vec![menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true)],
                        None,
                    )
                })
                .collect(),
            pairs: Vec::new(),
            adoption: Vec::new(),
        }
    }

    #[test]
    fn the_first_listing_waits_for_quiet_discovery_up_to_the_cap() {
        let start = Instant::now();
        let mut screen = Screen::new(start);
        assert!(!screen.due(start, false));
        assert!(screen.due(start, true), "finished discovery lists at once");
        // Events every half second keep the hold until the cap.
        for step in 1..6 {
            let now = start + Duration::from_millis(500 * step);
            screen.changed(now);
            assert!(!screen.due(now, false), "{step}");
        }
        assert!(screen.due(start + CAP, false));
        // Quiet for one second after the last event also ends the hold.
        let mut screen = Screen::new(start);
        screen.changed(start + Duration::from_millis(300));
        assert!(!screen.due(start + Duration::from_millis(1299), false));
        assert!(screen.due(start + Duration::from_millis(1300), false));
        screen.listing(view(&[]), Vec::new());
        assert!(!screen.due(start + CAP, true), "listed once");
    }

    #[test]
    fn after_the_listing_a_pool_event_prints_one_line_once() {
        let mut screen = Screen::new(Instant::now());
        assert_eq!(screen.update(&view(&[]), vec!["x".into()]), Update::Nothing);
        screen.listing(
            view(&["rpool/ROOT/a"]),
            vec!["found pool rpool on /dev/a".into()],
        );
        let same = view(&["rpool/ROOT/a"]);
        assert_eq!(
            screen.update(&same, vec!["found pool rpool on /dev/a".into()]),
            Update::Nothing
        );
        let findings = vec![
            "found pool rpool on /dev/a".to_owned(),
            "found pool data on /dev/b".to_owned(),
        ];
        assert_eq!(
            screen.update(&same, findings.clone()),
            Update::Lines(vec!["found pool data on /dev/b".into()])
        );
        assert_eq!(screen.update(&same, findings), Update::Nothing);
    }

    #[test]
    fn a_selection_change_reprints_the_listing() {
        let mut screen = Screen::new(Instant::now());
        screen.listing(view(&["rpool/ROOT/a"]), Vec::new());
        let grown = view(&["rpool/ROOT/a", "spool/ROOT/b"]);
        assert_eq!(screen.update(&grown, Vec::new()), Update::Listing);
        let mut paired = view(&["rpool/ROOT/a"]);
        paired.pairs.push("a/data -> b/data".into());
        assert_eq!(screen.update(&paired, Vec::new()), Update::Listing);
        let mut adopted = view(&["rpool/ROOT/a"]);
        adopted.adoption = vec!["Hostid 1 adopted".into()];
        assert_eq!(screen.update(&adopted, Vec::new()), Update::Listing);
        screen.listing(grown.clone(), Vec::new());
        assert_eq!(screen.update(&grown, Vec::new()), Update::Nothing);
    }
}
