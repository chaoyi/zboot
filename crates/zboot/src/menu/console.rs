//! Pure parsing and help for the interactive menu console.
//!
//! This module deliberately does not dispatch commands or run a shell.  The
//! menu loop passes [`parse_line`] results to the shared command grammar.

use std::fmt;
use std::io::Write;

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

/// Render the prompt's command grammar and the menu's own commands.
pub fn render_help(writer: &mut impl Write, can_connect: bool) -> std::io::Result<()> {
    crate::cli::help::command().write_long_help(writer)?;
    writeln!(
        writer,
        "\nMenu targets use BE number N or a full dataset name."
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
    writeln!(writer, "Use help COMMAND for a command's options.")?;
    writeln!(
        writer,
        "rescan refreshes BE numbers. Quoting preserves option values."
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn parse_line_supports_shell_like_unicode_quotes_without_evaluation() {
        assert_eq!(
            parse_line(r#"zboot cmdline 1 --set 'console=ttyS0 quiet' "π path" plain\ value ''"#)
                .unwrap(),
            vec![
                "zboot",
                "cmdline",
                "1",
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
            parse_line(r#"cmdline 1 --set "a'b\\c""#).unwrap()[3],
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
}
