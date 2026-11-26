//! Confirmation for destructive verbs, without request or review files.
//!
//! A verb plans, prints its plan with a short consent token, and changes
//! nothing unless confirmed. Interactively the operator types the target (a
//! disk serial or dataset name); the verb then plans again and proceeds only if
//! the consent is unchanged. Scripts pass `--confirm TOKEN` from an earlier
//! preview; the plan made on that command line must yield the same token.
//!
//! The token hashes only what the operator consents to: native identities,
//! loss scope and artifact digests. Callers exclude operation ids, timestamps
//! and free-space figures and recheck those as preconditions instead.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, IsTerminal, Write};

/// 128 bits of SHA-256, as 32 lowercase hex digits.
pub fn token(consent: &impl Serialize) -> io::Result<String> {
    let bytes = serde_json::to_vec(consent).map_err(io::Error::other)?;
    let digest = Sha256::digest(&bytes);
    Ok(digest[..16].iter().map(|b| format!("{b:02x}")).collect())
}

/// How the operator asked a destructive verb to proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `--dry-run`: print the plan only, successfully.
    DryRun,
    /// Proceed if the fresh plan's token equals this one.
    Token(String),
    /// Ask for the typed target on the terminal.
    Interactive,
    /// No terminal and no token: print the plan only, as not confirmed.
    Unattended,
}

impl Mode {
    /// `--dry-run` always previews; `--confirm` proceeds by token; otherwise
    /// a terminal is asked and anything else previews, never waiting. The
    /// dialogue uses stdin and stderr, so stdout may be piped (`--json`).
    pub fn select(dry_run: bool, confirm: Option<String>) -> Self {
        match (dry_run, confirm) {
            (true, _) => Self::DryRun,
            (false, Some(token)) => Self::Token(token),
            (false, None) if io::stdin().is_terminal() && io::stderr().is_terminal() => {
                Self::Interactive
            }
            (false, None) => Self::Unattended,
        }
    }
}

/// The decision after showing a plan.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// `--dry-run`: nothing changed, as asked.
    DryRun,
    /// Nothing changed because consent was not given; the verb ends with
    /// [`Unconfirmed`].
    Unconfirmed,
    /// Proceed; for interactive consent the caller must plan again and call
    /// [`unchanged`] before acting.
    Proceed { replan: bool },
}

/// A loss-capable verb previewed without `--dry-run`, or its typed answer did
/// not match. Exit status 3, so a preview never looks like success.
#[derive(Debug)]
pub struct Unconfirmed;
impl std::fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not confirmed; nothing changed")
    }
}
impl std::error::Error for Unconfirmed {}

#[derive(Debug)]
pub struct Stale;

impl std::fmt::Display for Stale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the plan changed. Preview it again before confirming")
    }
}
impl std::error::Error for Stale {}

impl From<Stale> for io::Error {
    fn from(error: Stale) -> Self {
        Self::new(io::ErrorKind::PermissionDenied, error)
    }
}

pub fn is_stale(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error.is::<Stale>() {
            return true;
        }
        if let Some(inner) = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            error = inner;
        } else if let Some(inner) = error.source() {
            error = inner;
        } else {
            return false;
        }
    }
}

/// What the operator types to confirm: a description and the exact text,
/// empty when the target has no stable name (then only `--confirm` works).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Typed {
    pub what: &'static str,
    pub text: String,
}

/// A whole disk is confirmed by its serial, else its WWN. Device review
/// already refuses disks with neither and duplicated identities.
pub fn disk_target(serial: Option<&str>, wwn: Option<&str>) -> Typed {
    match (
        serial.filter(|s| !s.is_empty()),
        wwn.filter(|w| !w.is_empty()),
    ) {
        (Some(serial), _) => Typed {
            what: "the disk serial",
            text: serial.to_owned(),
        },
        (None, Some(wwn)) => Typed {
            what: "the disk WWN",
            text: wwn.to_owned(),
        },
        (None, None) => Typed {
            what: "the disk",
            text: String::new(),
        },
    }
}

/// Decide from `mode` for a plan whose token is `planned` and whose typed
/// target is `target`. Prompts and notes go to `dialogue`.
pub fn decide(
    mode: &Mode,
    planned: &str,
    target: &Typed,
    input: &mut impl BufRead,
    dialogue: &mut impl Write,
) -> io::Result<Decision> {
    match mode {
        Mode::DryRun => {
            writeln!(dialogue, "Dry run; nothing changed.")?;
            Ok(Decision::DryRun)
        }
        Mode::Unattended => {
            writeln!(
                dialogue,
                "Nothing changed. To proceed, rerun on a terminal, or add --confirm {planned}."
            )?;
            Ok(Decision::Unconfirmed)
        }
        Mode::Token(given) if given == planned => Ok(Decision::Proceed { replan: false }),
        Mode::Token(_) => Err(Stale.into()),
        Mode::Interactive => {
            if target.text.is_empty() {
                writeln!(
                    dialogue,
                    "{} has no stable name to type; nothing changed. Rerun with --confirm {planned}.",
                    target.what
                )?;
                return Ok(Decision::Unconfirmed);
            }
            write!(
                dialogue,
                "Type {} ({}) to proceed, anything else cancels: ",
                target.what, target.text
            )?;
            dialogue.flush()?;
            let mut line = String::new();
            input.read_line(&mut line)?;
            if !line.ends_with('\n') || line.trim_end_matches(['\n', '\r']) != target.text {
                writeln!(dialogue, "Cancelled; nothing changed.")?;
                return Ok(Decision::Unconfirmed);
            }
            Ok(Decision::Proceed { replan: true })
        }
    }
}

/// A loss offered inside work that runs either way, such as the pending
/// deletions of `sync`: typing the target exactly accepts it; Enter, or any
/// other answer, declines it and the verb goes on without it.
pub fn optional(
    target: &Typed,
    accept: &str,
    decline: &str,
    input: &mut impl BufRead,
    dialogue: &mut impl Write,
) -> io::Result<bool> {
    write!(
        dialogue,
        "Type {} ({}) to {accept}, or press Enter to {decline}: ",
        target.what, target.text
    )?;
    dialogue.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    let answer = line.trim_end_matches(['\n', '\r']);
    if line.ends_with('\n') && answer == target.text {
        return Ok(true);
    }
    if !answer.is_empty() {
        writeln!(dialogue, "That is not {}; declined.", target.text)?;
    }
    Ok(false)
}

/// After an interactive answer, the fresh plan must match the one shown.
pub fn unchanged(shown: &str, fresh: &str) -> io::Result<()> {
    if shown != fresh {
        return Err(Stale.into());
    }
    Ok(())
}

/// How a `--json` run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Preview,
    Applied,
    Partial,
    Refused,
}

/// The one JSON object a converted verb prints on stdout with `--json`.
#[derive(Debug, Serialize)]
pub struct Envelope<T: Serialize> {
    pub schema_version: u32,
    pub mode: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub result: T,
}

impl<T: Serialize> Envelope<T> {
    pub fn new(mode: Outcome, token: Option<String>, result: T) -> Self {
        Self {
            schema_version: 1,
            mode,
            operation: None,
            token,
            result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(mode: Mode, typed: &str) -> (io::Result<Decision>, String) {
        let mut output = Vec::new();
        let decision = decide(
            &mode,
            "00112233445566778899aabbccddeeff",
            &disk_target(Some("SERIAL1"), Some("0x5000")),
            &mut typed.as_bytes(),
            &mut output,
        );
        (decision, String::from_utf8(output).unwrap())
    }

    #[test]
    fn token_is_128_bits_of_the_canonical_consent() {
        let a = token(&("disk", 1u64)).unwrap();
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(a, token(&("disk", 1u64)).unwrap());
        assert_ne!(a, token(&("disk", 2u64)).unwrap());
    }

    #[test]
    fn only_dry_run_previews_successfully() {
        let (decision, text) = run(Mode::DryRun, "");
        assert_eq!(decision.unwrap(), Decision::DryRun);
        assert!(text.contains("Dry run"));
        let (decision, text) = run(Mode::Unattended, "");
        assert_eq!(decision.unwrap(), Decision::Unconfirmed);
        assert!(text.contains("--confirm 00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn token_must_match_the_fresh_plan() {
        let (decision, _) = run(Mode::Token("00112233445566778899aabbccddeeff".into()), "");
        assert_eq!(decision.unwrap(), Decision::Proceed { replan: false });
        let (decision, _) = run(Mode::Token("ffff".into()), "");
        assert!(decision.unwrap_err().to_string().contains("plan changed"));
    }

    #[test]
    fn interactive_needs_the_exact_target_then_a_replan() {
        for answer in ["SERIAL1\n", "SERIAL1\r\n"] {
            let (decision, text) = run(Mode::Interactive, answer);
            assert_eq!(decision.unwrap(), Decision::Proceed { replan: true });
            assert!(text.contains("the disk serial (SERIAL1)"));
        }
        for wrong in [
            "serial1\n",
            "SERIAL1 \n",
            "0x5000\n",
            "\n",
            "",
            "SERIAL1",
            "SERIAL1\r",
        ] {
            let (decision, text) = run(Mode::Interactive, wrong);
            assert_eq!(decision.unwrap(), Decision::Unconfirmed, "{wrong:?}");
            assert!(text.contains("Cancelled"));
        }
        assert!(unchanged("a", "a").is_ok());
        assert!(unchanged("a", "b").is_err());
    }

    #[test]
    fn a_disk_without_serial_is_typed_by_wwn_and_without_either_only_by_token() {
        assert_eq!(disk_target(None, Some("0x5000")).text, "0x5000");
        assert_eq!(disk_target(Some(""), Some("0x5000")).what, "the disk WWN");
        let none = disk_target(None, None);
        let mut output = Vec::new();
        let decision = decide(
            &Mode::Interactive,
            "aa",
            &none,
            &mut "anything\n".as_bytes(),
            &mut output,
        );
        assert_eq!(decision.unwrap(), Decision::Unconfirmed);
        assert!(String::from_utf8(output).unwrap().contains("--confirm aa"));
    }

    #[test]
    fn an_optional_loss_needs_the_exact_target_and_anything_else_declines() {
        let target = Typed {
            what: "the summary",
            text: "3 snapshots on b/data".into(),
        };
        let ask = |typed: &str| {
            let mut output = Vec::new();
            let accepted = optional(
                &target,
                "delete them",
                "keep them",
                &mut typed.as_bytes(),
                &mut output,
            )
            .unwrap();
            (accepted, String::from_utf8(output).unwrap())
        };
        for answer in ["3 snapshots on b/data\n", "3 snapshots on b/data\r\n"] {
            let (accepted, text) = ask(answer);
            assert!(accepted, "{answer:?}");
            assert!(text.contains("Type the summary (3 snapshots on b/data) to delete them"));
            assert!(text.contains("press Enter to keep them"));
        }
        for answer in ["\n", "", "3 snapshots on b/data", "3 snapshots\n", "yes\n"] {
            let (accepted, text) = ask(answer);
            assert!(!accepted, "{answer:?}");
            assert_eq!(
                text.contains("declined"),
                !answer.trim().is_empty(),
                "{answer:?}"
            );
        }
    }

    #[test]
    fn envelope_is_versioned_and_names_its_mode() {
        let value =
            serde_json::to_value(Envelope::new(Outcome::Preview, Some("aa".into()), 1)).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"schema_version": 1, "mode": "preview", "token": "aa", "result": 1})
        );
    }
}
