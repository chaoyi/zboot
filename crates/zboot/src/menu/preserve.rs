//! Pure UI state for choosing datasets to preserve during recovery.
//!
//! The caller owns inventory discovery, input reading, and every native
//! action.  This module only keeps the displayed rows and their observed
//! identities together while the operator makes a selection.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};

use zfs_tools::engine::DatasetIdentity;

/// One immutable row in the preservation inventory.
///
/// The row number is its position in the vector supplied to
/// [`PreservationChooser::new`], so callers can keep the displayed numbering
/// stable until they deliberately redraw the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservationRow {
    pub dataset: String,
    pub identity: DatasetIdentity,
}

impl PreservationRow {
    /// Build a row without querying native state.
    pub fn new(dataset: impl Into<String>, identity: DatasetIdentity) -> Self {
        Self {
            dataset: dataset.into(),
            identity,
        }
    }
}

/// Errors found while constructing a preservation inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    InvalidDatasetName(String),
    DuplicateDatasetName(String),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDatasetName(dataset) => write!(
                formatter,
                "invalid preservation dataset name: {}",
                zfs_tools::engine::escape_display(dataset)
            ),
            Self::DuplicateDatasetName(dataset) => write!(
                formatter,
                "duplicate preservation dataset row: {}",
                zfs_tools::engine::escape_display(dataset)
            ),
        }
    }
}

impl std::error::Error for ModelError {}

/// A fully parsed preservation prompt command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionCommand {
    /// Toggle the listed one-based row numbers in the order supplied.
    Toggle(Vec<usize>),
    All,
    None,
    Done,
    Cancel,
}

/// Result after applying one valid command to a chooser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptResult {
    /// Keep the chooser open and render it again.
    Continue,
    /// Finish with normalized, non-overlapping dataset roots.
    Done(Vec<PreservationRow>),
    /// Stop without producing a preservation plan.
    Cancel,
}

/// Errors from parsing a preservation prompt line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    UnknownCommand(String),
    MixedCommand,
    InvalidRow(String),
    RowOutOfRange { row: usize, row_count: usize },
    DuplicateRow(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("enter row numbers or all/none/done/cancel"),
            Self::UnknownCommand(command) => write!(
                formatter,
                "unknown preservation command: {}",
                zfs_tools::engine::escape_display(command)
            ),
            Self::MixedCommand => {
                formatter.write_str("all, none, done, and cancel must be entered by themselves")
            }
            Self::InvalidRow(row) => write!(
                formatter,
                "invalid preservation row: {}",
                zfs_tools::engine::escape_display(row)
            ),
            Self::RowOutOfRange { row, row_count } => {
                write!(
                    formatter,
                    "preservation row {row} is outside 1..={row_count}"
                )
            }
            Self::DuplicateRow(row) => write!(formatter, "preservation row {row} was repeated"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse one preservation prompt line.
///
/// Numeric input is deliberately a small grammar: one or more positive
/// decimal row numbers separated by whitespace.  The command words must be
/// the whole line.  There is no shell evaluation and no partial result: every
/// token is checked before a [`SelectionCommand`] is returned.
pub fn parse_line(line: &str, row_count: usize) -> Result<SelectionCommand, ParseError> {
    let tokens: Vec<_> = line.split_whitespace().collect();
    let Some(first) = tokens.first().copied() else {
        return Err(ParseError::Empty);
    };

    match first {
        "all" => return command_alone(&tokens, SelectionCommand::All),
        "none" => return command_alone(&tokens, SelectionCommand::None),
        "done" => return command_alone(&tokens, SelectionCommand::Done),
        "cancel" => return command_alone(&tokens, SelectionCommand::Cancel),
        _ => {}
    }

    if !first.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        return Err(ParseError::UnknownCommand(first.to_owned()));
    }

    let mut rows = Vec::with_capacity(tokens.len());
    let mut seen = HashSet::with_capacity(tokens.len());
    for token in tokens {
        let row = parse_row(token)?;
        if row == 0 || row > row_count {
            return Err(ParseError::RowOutOfRange { row, row_count });
        }
        if !seen.insert(row) {
            return Err(ParseError::DuplicateRow(row));
        }
        rows.push(row);
    }
    Ok(SelectionCommand::Toggle(rows))
}

fn command_alone(
    tokens: &[&str],
    command: SelectionCommand,
) -> Result<SelectionCommand, ParseError> {
    if tokens.len() == 1 {
        Ok(command)
    } else {
        Err(ParseError::MixedCommand)
    }
}

fn parse_row(token: &str) -> Result<usize, ParseError> {
    if token.is_empty()
        || !token.bytes().all(|byte| byte.is_ascii_digit())
        || (token.len() > 1 && token.starts_with('0'))
    {
        return Err(ParseError::InvalidRow(token.to_owned()));
    }
    token
        .parse()
        .map_err(|_| ParseError::InvalidRow(token.to_owned()))
}

/// The immutable inventory and its current checkbox state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservationChooser {
    rows: Vec<PreservationRow>,
    selected: Vec<bool>,
}

impl PreservationChooser {
    /// Create a chooser from the exact rows that will be displayed.
    pub fn new(rows: Vec<PreservationRow>) -> Result<Self, ModelError> {
        let mut names = HashSet::with_capacity(rows.len());
        for row in &rows {
            if zfs_tools::engine::validate_dataset_name(&row.dataset).is_err() {
                return Err(ModelError::InvalidDatasetName(row.dataset.clone()));
            }
            if !names.insert(row.dataset.clone()) {
                return Err(ModelError::DuplicateDatasetName(row.dataset.clone()));
            }
        }
        let selected = vec![false; rows.len()];
        Ok(Self { rows, selected })
    }

    /// Return whether a one-based row is currently selected.
    #[cfg(test)]
    pub fn is_selected(&self, row: usize) -> Option<bool> {
        row.checked_sub(1)
            .and_then(|index| self.selected.get(index).copied())
    }

    /// Render a numbered checkbox list.  The caller supplies the prompt and
    /// reads the next line; EOF is therefore intentionally outside this API.
    pub fn render(&self, writer: &mut impl Write) -> io::Result<()> {
        writeln!(
            writer,
            "Preserve datasets (numbers toggle; all/none/done/cancel):"
        )?;
        if self.rows.is_empty() {
            writeln!(writer, "  (no datasets observed)")?;
            return Ok(());
        }
        for (index, row) in self.rows.iter().enumerate() {
            let marker = if self.selected[index] { 'x' } else { ' ' };
            let indent = "  ".repeat(row.dataset.matches('/').count());
            writeln!(
                writer,
                "  [{marker}] {}: {indent}{} (guid={})",
                index + 1,
                zfs_tools::engine::escape_display(&row.dataset),
                row.identity.guid,
            )?;
        }
        Ok(())
    }

    /// Parse and apply one line.  Parsing and command validation happen before
    /// any checkbox changes, so an invalid whole line is atomic.
    pub fn apply_line(&mut self, line: &str) -> Result<PromptResult, ParseError> {
        let command = parse_line(line, self.rows.len())?;
        self.apply(command)
    }

    /// Apply a previously parsed command.  This repeats validation so callers
    /// constructing [`SelectionCommand`] values directly retain the same
    /// atomicity guarantee as [`Self::apply_line`].
    pub fn apply(&mut self, command: SelectionCommand) -> Result<PromptResult, ParseError> {
        match command {
            SelectionCommand::Toggle(rows) => {
                validate_rows(&rows, self.rows.len())?;
                for row in rows {
                    self.toggle(row - 1);
                }
                Ok(PromptResult::Continue)
            }
            SelectionCommand::All => {
                self.selected.fill(true);
                Ok(PromptResult::Continue)
            }
            SelectionCommand::None => {
                self.selected.fill(false);
                Ok(PromptResult::Continue)
            }
            SelectionCommand::Done => Ok(PromptResult::Done(self.normalized())),
            SelectionCommand::Cancel => Ok(PromptResult::Cancel),
        }
    }

    /// Return every selected row, including rows covered by a selected root.
    #[cfg(test)]
    pub fn selected_rows(&self) -> Vec<PreservationRow> {
        self.rows
            .iter()
            .zip(&self.selected)
            .filter(|(_, selected)| **selected)
            .map(|(row, _)| row.clone())
            .collect()
    }

    /// Return selected rows with descendants covered by a selected ancestor
    /// removed.  The original displayed order is retained.
    pub fn normalized(&self) -> Vec<PreservationRow> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(index, row)| {
                self.selected[*index]
                    && !self.rows.iter().enumerate().any(|(ancestor, candidate)| {
                        ancestor != *index
                            && self.selected[ancestor]
                            && is_ancestor(&candidate.dataset, &row.dataset)
                    })
            })
            .map(|(_, row)| row.clone())
            .collect()
    }

    fn toggle(&mut self, index: usize) {
        if self.selected[index] {
            let has_selected_ancestor =
                self.rows.iter().enumerate().any(|(ancestor, candidate)| {
                    ancestor != index
                        && self.selected[ancestor]
                        && is_ancestor(&candidate.dataset, &self.rows[index].dataset)
                });
            if has_selected_ancestor {
                // A child selected through a checked ancestor is made
                // independently editable: clear the ancestor and this child,
                // while retaining the other descendants.
                for (ancestor, candidate) in self.rows.iter().enumerate() {
                    if self.selected[ancestor]
                        && is_ancestor(&candidate.dataset, &self.rows[index].dataset)
                    {
                        self.selected[ancestor] = false;
                    }
                }
                self.selected[index] = false;
            } else {
                // Toggling an independently selected parent off clears its
                // represented subtree as one intuitive operation.
                let parent = self.rows[index].dataset.clone();
                for (descendant, row) in self.rows.iter().enumerate() {
                    if is_ancestor(&parent, &row.dataset) {
                        self.selected[descendant] = false;
                    }
                }
            }
        } else {
            // Selecting a parent selects every represented descendant, even
            // when the inventory is not sorted parent-first.
            let parent = self.rows[index].dataset.clone();
            for (descendant, row) in self.rows.iter().enumerate() {
                if is_ancestor(&parent, &row.dataset) {
                    self.selected[descendant] = true;
                }
            }
        }
    }
}

fn validate_rows(rows: &[usize], row_count: usize) -> Result<(), ParseError> {
    let mut seen = HashSet::with_capacity(rows.len());
    for &row in rows {
        if row == 0 || row > row_count {
            return Err(ParseError::RowOutOfRange { row, row_count });
        }
        if !seen.insert(row) {
            return Err(ParseError::DuplicateRow(row));
        }
    }
    Ok(())
}

fn is_ancestor(parent: &str, child: &str) -> bool {
    child == parent
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zfs_tools::engine::{Guid, ObjsetId, Txg};

    fn identity(value: u64) -> DatasetIdentity {
        DatasetIdentity {
            pool_guid: Guid::new(10),
            guid: Guid::new(value),
            createtxg: Txg::new(value + 100),
            objsetid: ObjsetId::new(value + 200),
        }
    }

    fn row(name: &str, value: u64) -> PreservationRow {
        PreservationRow::new(name, identity(value))
    }

    fn chooser() -> PreservationChooser {
        PreservationChooser::new(vec![
            row("tank", 1),
            row("tank/ROOT", 2),
            row("tank/ROOT/a", 3),
            row("tank/ROOT/b", 4),
            row("tank/other", 5),
            row("tank2", 6),
        ])
        .unwrap()
    }

    #[test]
    fn starts_empty_and_renders_stable_numbered_rows() {
        let chooser = chooser();
        assert!(chooser.selected_rows().is_empty());
        assert_eq!(chooser.is_selected(1), Some(false));
        assert_eq!(chooser.is_selected(99), None);

        let mut output = Vec::new();
        chooser.render(&mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("[ ] 1: tank"));
        assert!(output.contains("[ ] 3:     tank/ROOT/a"));
        assert!(output.contains("guid=3"));
    }

    #[test]
    fn parser_accepts_toggles_and_standalone_commands() {
        assert_eq!(
            parse_line(" 2   4 ", 4),
            Ok(SelectionCommand::Toggle(vec![2, 4]))
        );
        assert_eq!(parse_line("all", 4), Ok(SelectionCommand::All));
        assert_eq!(parse_line("none", 4), Ok(SelectionCommand::None));
        assert_eq!(parse_line("done", 4), Ok(SelectionCommand::Done));
        assert_eq!(parse_line("cancel", 4), Ok(SelectionCommand::Cancel));
        assert_eq!(
            parse_line("2 4", 4),
            Ok(SelectionCommand::Toggle(vec![2, 4]))
        );
    }

    #[test]
    fn invalid_whole_line_does_not_mutate_selection() {
        let mut chooser = chooser();
        chooser.apply_line("1").unwrap();
        let before = chooser.selected_rows();

        assert!(chooser.apply_line("2 99").is_err());
        assert_eq!(chooser.selected_rows(), before);
        assert!(chooser.apply_line("2 2").is_err());
        assert_eq!(chooser.selected_rows(), before);
        assert!(chooser.apply_line("all 2").is_err());
        assert_eq!(chooser.selected_rows(), before);
        assert!(chooser.apply_line("2,nope").is_err());
        assert_eq!(chooser.selected_rows(), before);
    }

    #[test]
    fn parent_selection_and_child_unselection_have_independent_roots() {
        let mut chooser = chooser();
        chooser.apply_line("1").unwrap();
        assert_eq!(chooser.normalized(), vec![row("tank", 1)]);

        // Row 2 is selected through row 1.  Toggling it off clears the
        // selected ancestor and row 2, preserving the other descendants as
        // independently selected roots.
        chooser.apply_line("2").unwrap();
        assert_eq!(
            chooser.normalized(),
            vec![
                row("tank/ROOT/a", 3),
                row("tank/ROOT/b", 4),
                row("tank/other", 5)
            ]
        );

        chooser.apply_line("none").unwrap();
        chooser.apply_line("2").unwrap();
        assert_eq!(chooser.normalized(), vec![row("tank/ROOT", 2)]);
        chooser.apply_line("2").unwrap();
        assert!(chooser.normalized().is_empty());
    }

    #[test]
    fn normalized_selection_is_nonoverlapping_even_when_rows_are_unsorted() {
        let mut chooser = PreservationChooser::new(vec![
            row("tank/ROOT/a", 1),
            row("tank", 2),
            row("tank/ROOT", 3),
        ])
        .unwrap();
        chooser.apply_line("all").unwrap();
        assert_eq!(chooser.normalized(), vec![row("tank", 2)]);

        chooser.apply_line("none").unwrap();
        chooser.apply_line("1").unwrap();
        chooser.apply_line("3").unwrap();
        assert_eq!(chooser.normalized(), vec![row("tank/ROOT", 3)]);
    }

    #[test]
    fn all_none_done_and_cancel_do_not_rearm_or_mutate_unexpectedly() {
        let mut chooser = chooser();
        assert_eq!(chooser.apply_line("all"), Ok(PromptResult::Continue));
        assert_eq!(chooser.normalized(), vec![row("tank", 1), row("tank2", 6)]);
        assert_eq!(
            chooser.apply_line("done"),
            Ok(PromptResult::Done(vec![row("tank", 1), row("tank2", 6)]))
        );
        assert_eq!(chooser.normalized(), vec![row("tank", 1), row("tank2", 6)]);
        assert_eq!(chooser.apply_line("cancel"), Ok(PromptResult::Cancel));
        assert_eq!(chooser.normalized(), vec![row("tank", 1), row("tank2", 6)]);
        chooser.apply_line("none").unwrap();
        assert!(chooser.normalized().is_empty());
        assert_eq!(
            chooser.apply_line("done"),
            Ok(PromptResult::Done(Vec::new()))
        );
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert_eq!(parse_line("", 2), Err(ParseError::Empty));
        assert_eq!(
            parse_line("unknown", 2),
            Err(ParseError::UnknownCommand("unknown".into()))
        );
        assert_eq!(parse_line("done now", 2), Err(ParseError::MixedCommand));
        assert_eq!(
            parse_line("0", 2),
            Err(ParseError::RowOutOfRange {
                row: 0,
                row_count: 2
            })
        );
        assert_eq!(
            parse_line("01", 2),
            Err(ParseError::InvalidRow("01".into()))
        );
        assert_eq!(
            parse_line("1,2", 2),
            Err(ParseError::InvalidRow("1,2".into()))
        );
        assert!(parse_line("２", 2).is_err());
        assert_eq!(
            parse_line("3", 2),
            Err(ParseError::RowOutOfRange {
                row: 3,
                row_count: 2
            })
        );
    }

    #[test]
    fn constructor_rejects_invalid_or_duplicate_names() {
        assert!(matches!(
            PreservationChooser::new(vec![row("", 1)]),
            Err(ModelError::InvalidDatasetName(_))
        ));
        assert!(matches!(
            PreservationChooser::new(vec![row("tank", 1), row("tank", 2)]),
            Err(ModelError::DuplicateDatasetName(name)) if name == "tank"
        ));
    }
}
