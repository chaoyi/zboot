//! Pure parsing and dataset presentation for the interactive menu console.
//!
//! This module deliberately does not dispatch commands or run a shell.  The
//! menu loop passes [`parse_line`] results to the shared command grammar,
//! while ordinary dataset numbers remain bound to the native identities that
//! were displayed to the operator.

use std::cmp::Ordering;
use std::fmt;
use std::io::Write;

use zfs_tools::engine::{DatasetIdentity, DatasetKind, state::NativeState};

/// Errors from the small shell-like tokenizer used by the menu prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A quote was opened but no matching quote occurred on this line.
    UnterminatedQuote { quote: char },
    /// A backslash at the end of a line has no character to escape.
    TrailingEscape,
    /// A raw line break or other control character cannot be passed as one
    /// menu command.  Escaped data is still tokenized literally.
    ControlCharacter(char),
}

fn forbidden_control(character: char) -> bool {
    character.is_control() && character != '\t'
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnterminatedQuote { quote } => {
                write!(formatter, "unterminated {quote} quote")
            }
            Self::TrailingEscape => formatter.write_str("trailing backslash in command"),
            Self::ControlCharacter(character) => write!(
                formatter,
                "control character U+{:04X} is not allowed in a menu command",
                *character as u32
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Tokenize one menu prompt line without invoking a shell.
///
/// Single and double quotes group whitespace.  A backslash quotes the next
/// character outside single quotes, including another quote or a Unicode
/// character.  Adjacent quoted and unquoted fragments form one token, as in a
/// shell.  The resulting strings are data for the caller; this function never
/// evaluates substitutions, redirections, pipelines, or command separators.
pub fn parse_line(line: &str) -> Result<Vec<String>, ParseError> {
    #[derive(Clone, Copy)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut quote = Quote::None;
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut started = false;
    let mut characters = line.chars();

    while let Some(character) = characters.next() {
        match quote {
            Quote::Single => {
                if character == '\'' {
                    quote = Quote::None;
                } else if forbidden_control(character) {
                    return Err(ParseError::ControlCharacter(character));
                } else {
                    token.push(character);
                }
            }
            Quote::Double => match character {
                '"' => quote = Quote::None,
                '\\' => {
                    let Some(next) = characters.next() else {
                        return Err(ParseError::TrailingEscape);
                    };
                    if forbidden_control(next) {
                        return Err(ParseError::ControlCharacter(next));
                    }
                    token.push(next);
                }
                _ => {
                    if forbidden_control(character) {
                        return Err(ParseError::ControlCharacter(character));
                    }
                    token.push(character);
                }
            },
            Quote::None => match character {
                '\'' => {
                    quote = Quote::Single;
                    started = true;
                }
                '"' => {
                    quote = Quote::Double;
                    started = true;
                }
                '\\' => {
                    let Some(next) = characters.next() else {
                        return Err(ParseError::TrailingEscape);
                    };
                    if forbidden_control(next) {
                        return Err(ParseError::ControlCharacter(next));
                    }
                    token.push(next);
                    started = true;
                }
                character if character.is_whitespace() => {
                    if forbidden_control(character) {
                        return Err(ParseError::ControlCharacter(character));
                    }
                    if started {
                        tokens.push(std::mem::take(&mut token));
                        started = false;
                    }
                }
                _ => {
                    if forbidden_control(character) {
                        return Err(ParseError::ControlCharacter(character));
                    }
                    token.push(character);
                    started = true;
                }
            },
        }
    }

    match quote {
        Quote::None => {
            if started {
                tokens.push(token);
            }
            Ok(tokens)
        }
        Quote::Single => Err(ParseError::UnterminatedQuote { quote: '\'' }),
        Quote::Double => Err(ParseError::UnterminatedQuote { quote: '"' }),
    }
}

/// Render the prompt's command grammar.  The boot `N`/`N.M` references are
/// intentionally separate from this ordinary dataset `dN` inventory.
pub fn render_help(writer: &mut impl Write, can_connect: bool) -> std::io::Result<()> {
    crate::cli::help::command().write_long_help(writer)?;
    writeln!(
        writer,
        "\nMenu targets use BE number N, dataset dN, or a full name."
    )?;
    writeln!(
        writer,
        "Menu-only commands: N | N.M | rescan | ls | shell | reboot | poweroff | help"
    )?;
    if can_connect {
        writeln!(
            writer,
            "connect starts the prepared network and SSH session."
        )?;
    }
    writeln!(
        writer,
        "restore, wipe, resume and abandon open a picker for omitted operands."
    )?;
    writeln!(writer, "Use help COMMAND for a command's options.")?;
    writeln!(
        writer,
        "rescan refreshes BE numbers. Full text status refreshes dN selections. Quoting preserves option values."
    )?;
    Ok(())
}

/// One immutable row from a complete native dataset observation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DatasetRow {
    selector: String,
    dataset: String,
    identity: DatasetIdentity,
    kind: DatasetKind,
    mountpoint: Option<String>,
    readonly: bool,
}

/// Immutable, numbered ordinary-dataset inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatasetMenu {
    rows: Vec<DatasetRow>,
}

impl DatasetMenu {
    /// Sort by native name and then every identity component before assigning
    /// selectors.  This makes numbering deterministic even if a backend ever
    /// returns duplicate names while a replacement dataset is being observed.
    pub fn from_state(state: &NativeState) -> Self {
        let mut rows: Vec<_> = state
            .inspection
            .datasets
            .iter()
            .map(|dataset| DatasetRow {
                selector: String::new(),
                dataset: dataset.name.clone(),
                identity: dataset.identity.clone(),
                kind: dataset.kind.clone(),
                mountpoint: dataset.mountpoint.clone(),
                readonly: dataset.readonly.to_owned(),
            })
            .collect();
        rows.sort_by(|left, right| {
            left.dataset
                .cmp(&right.dataset)
                .then_with(|| identity_order(&left.identity, &right.identity))
        });
        for (index, row) in rows.iter_mut().enumerate() {
            row.selector = format!("d{}", index + 1);
        }
        Self { rows }
    }

    /// Render the stable ordinary-dataset numbering.  The identity is shown
    /// in abbreviated form so an operator can distinguish a replacement while
    /// the complete identity remains attached to the row for selection.
    pub fn render(&self, writer: &mut impl Write) -> std::io::Result<()> {
        if self.rows.is_empty() {
            writeln!(writer, "No imported datasets observed.")?;
            return Ok(());
        }
        for row in &self.rows {
            let kind = match &row.kind {
                DatasetKind::Filesystem => "filesystem",
                DatasetKind::Volume => "volume",
            };
            let mountpoint = row
                .mountpoint
                .as_deref()
                .map(zfs_tools::engine::escape_display)
                .unwrap_or_else(|| "-".into());
            let access = if row.readonly { "ro" } else { "rw" };
            writeln!(
                writer,
                "{}: {}  [{} {}] mount={} guid={}",
                row.selector,
                zfs_tools::engine::escape_display(&row.dataset),
                kind,
                access,
                mountpoint,
                row.identity.guid
            )?;
        }
        Ok(())
    }

    pub(super) fn numbered(&self) -> impl Iterator<Item = (&str, &str, &DatasetIdentity)> {
        self.rows
            .iter()
            .map(|row| (row.selector.as_str(), row.dataset.as_str(), &row.identity))
    }

    /// Resolve an ordinary `dN` selector to the dataset and identity it
    /// displayed. The command checks that identity against native state.
    fn select(&self, selector: &str) -> Result<(String, DatasetIdentity), SelectionError> {
        let index = parse_dataset_selector(selector)?;
        let row = self
            .rows
            .get(index)
            .ok_or_else(|| SelectionError::UnknownSelector(selector.into()))?;
        Ok((row.dataset.clone(), row.identity.clone()))
    }

    /// Resolve either a stable `dN` selector or a displayed dataset name.
    pub fn resolve(&self, selector: &str) -> Result<(String, DatasetIdentity), SelectionError> {
        let selector =
            if selector.starts_with('d') && selector[1..].bytes().all(|b| b.is_ascii_digit()) {
                selector
            } else {
                let row = self
                    .rows
                    .iter()
                    .find(|row| row.dataset == selector)
                    .ok_or_else(|| SelectionError::UnknownSelector(selector.into()))?;
                &row.selector
            };
        self.select(selector)
    }
}

/// Parse an ordinary dataset selector and return its zero-based row index.
fn parse_dataset_selector(selector: &str) -> Result<usize, SelectionError> {
    let Some(number) = selector.strip_prefix('d') else {
        return Err(SelectionError::InvalidSelector(selector.into()));
    };
    if number.is_empty()
        || (number.len() > 1 && number.starts_with('0'))
        || !number.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SelectionError::InvalidSelector(selector.into()));
    }
    let number = number
        .parse::<usize>()
        .map_err(|_| SelectionError::InvalidSelector(selector.into()))?;
    number
        .checked_sub(1)
        .ok_or_else(|| SelectionError::InvalidSelector(selector.into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionError {
    InvalidSelector(String),
    UnknownSelector(String),
}

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSelector(selector) => {
                write!(
                    formatter,
                    "invalid dataset selector: {}",
                    zfs_tools::engine::escape_display(selector)
                )
            }
            Self::UnknownSelector(selector) => {
                write!(
                    formatter,
                    "unknown dataset selector: {}",
                    zfs_tools::engine::escape_display(selector)
                )
            }
        }
    }
}

impl std::error::Error for SelectionError {}

fn identity_order(left: &DatasetIdentity, right: &DatasetIdentity) -> Ordering {
    left.pool_guid
        .cmp(&right.pool_guid)
        .then_with(|| left.guid.cmp(&right.guid))
        .then_with(|| left.createtxg.cmp(&right.createtxg))
        .then_with(|| left.objsetid.cmp(&right.objsetid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use zfs_tools::engine::{InspectRequest, native};

    #[test]
    fn help_describes_connect_according_to_runtime_capability() {
        let mut available = Vec::new();
        render_help(&mut available, true).unwrap();
        let available = String::from_utf8(available).unwrap();
        assert!(available.contains("connect starts"));
        assert!(available.contains("help COMMAND"));
        let mut grammar = crate::cli::help::command();
        for (command, option) in [("boot", "--kernel"), ("menu", "--no-autoboot")] {
            assert!(
                grammar
                    .find_subcommand_mut(command)
                    .unwrap()
                    .render_long_help()
                    .to_string()
                    .contains(option)
            );
        }
        assert!(!available.contains("R starts"));
        let mut unavailable = Vec::new();
        render_help(&mut unavailable, false).unwrap();
        let unavailable = String::from_utf8(unavailable).unwrap();
        assert!(!unavailable.contains("connect starts"));
        assert!(unavailable.contains("restore, wipe, resume and abandon"));
    }

    #[test]
    fn parse_line_supports_shell_like_unicode_quotes_without_evaluation() {
        assert_eq!(
            parse_line(r#"zboot cmdline d1 --set 'console=ttyS0 quiet' "π path" plain\ value ''"#)
                .unwrap(),
            vec![
                "zboot",
                "cmdline",
                "d1",
                "--set",
                "console=ttyS0 quiet",
                "π path",
                "plain value",
                "",
            ]
        );
        assert_eq!(
            parse_line(r#"zboot '$(touch /tmp/nope)'"#).unwrap()[1],
            "$(touch /tmp/nope)"
        );
        assert_eq!(
            parse_line(r#"cmdline d1 --set "a'b\\c""#).unwrap()[3],
            "a'b\\c"
        );
    }

    #[test]
    fn parse_line_rejects_unterminated_quotes_trailing_escape_and_controls() {
        assert_eq!(
            parse_line("zboot 'unterminated").unwrap_err(),
            ParseError::UnterminatedQuote { quote: '\'' }
        );
        assert_eq!(
            parse_line("zboot \"unterminated").unwrap_err(),
            ParseError::UnterminatedQuote { quote: '"' }
        );
        assert_eq!(
            parse_line("zboot trailing\\").unwrap_err(),
            ParseError::TrailingEscape
        );
        assert!(matches!(
            parse_line("zboot\nreboot"),
            Err(ParseError::ControlCharacter('\n'))
        ));
    }

    #[test]
    fn inventory_numbers_are_stable_and_bind_dataset_identity() {
        let old = fixture(&[("tank/z", 2), ("tank/a", 1)]);
        let inventory = DatasetMenu::from_state(&old);
        assert_eq!(
            inventory
                .rows
                .iter()
                .map(|row| (row.selector.as_str(), row.dataset.as_str()))
                .collect::<Vec<_>>(),
            vec![("d1", "tank"), ("d2", "tank/a"), ("d3", "tank/z")]
        );
        let (selected, identity) = inventory.select("d2").unwrap();
        assert_eq!(selected, "tank/a");
        assert_eq!(identity.guid, zfs_tools::engine::Guid::new(1));
        assert_eq!(
            inventory.resolve("tank/a").unwrap(),
            ("tank/a".into(), identity)
        );
    }

    #[test]
    fn dataset_selection_errors_are_fail_closed() {
        let state = fixture(&[("tank/a", 1)]);
        let inventory = DatasetMenu::from_state(&state);
        for selector in ["", "1", "D1", "d", "d0", "d01", "d-1", "d1.1"] {
            assert!(matches!(
                inventory.select(selector),
                Err(SelectionError::InvalidSelector(_))
            ));
        }
        assert!(matches!(
            inventory.select("d3"),
            Err(SelectionError::UnknownSelector(_))
        ));
    }

    #[test]
    fn inventory_rendering_escapes_names_and_shows_identity_hint() {
        let state = fixture(&[("tank/\u{202e}a", 1)]);
        let mut output = Cursor::new(Vec::new());
        let inventory = DatasetMenu::from_state(&state);
        inventory.render(&mut output).unwrap();
        let output = String::from_utf8(output.into_inner()).unwrap();
        assert_eq!(inventory.rows.len(), 2);
        assert!(output.contains("d2: tank/\\u{202e}a"));
        assert!(output.contains("guid=1"));
    }

    fn fixture(datasets: &[(&str, u64)]) -> NativeState {
        let mut rows =
            "tank\tfilesystem\t900\t0\t1000\t0\t/\t-\t910\t920\tno\toff\ton\t-\toff\t-\t-\t-\t-\n"
                .to_string();
        rows.push_str(
            &datasets
            .iter()
            .map(|(name, id)| {
                format!(
                    "{name}\tfilesystem\t{id}\t0\t1000\t0\t/\t-\t{}\t{}\tno\toff\ton\t-\toff\t-\t-\t-\t-\n",
                    id + 10,
                    id + 20
                )
            })
            .collect::<String>(),
        );
        let inspection = native::inspect_with(
            &InspectRequest::new(vec![], false).unwrap(),
            |program, _| {
                Ok(if program == "zpool" {
                    "tank\t100\t1000\t0\t1000\tONLINE\t-\n".into()
                } else {
                    rows.clone()
                })
            },
        )
        .unwrap();
        NativeState {
            inspection,
            dataset_properties: BTreeMap::new(),
            pool_properties: BTreeMap::new(),
        }
    }
}
