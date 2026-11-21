use crate::{Config, Keep, parse_duration};
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Change-aware ZFS snapshots and tiered retention through the shared ZFS executor.
#[derive(Debug, Parser)]
// A bare `about` printed the zfs-tools package description while this code
// lived in that package; the literal keeps the published help unchanged.
#[command(
    name = "zsnap",
    version,
    about = "ZFS snapshots, retention and protected snapshot readers"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Supervise a complete protected filesystem reader with verified cleanup.
    Protect(super::reader_task::ProtectOptions),
    /// Inspect and recover an interrupted, authenticated protected reader job.
    Recover(super::reader_task::RecoverOptions),
    /// Capture due changed datasets and prune their assigned snapshot streams.
    Run {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Capture one exact snapshot set, independent of policy frequency.
    Snap {
        #[arg(required = true, num_args = 1..)]
        datasets: Vec<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Preview retention candidates and confirm exact deletion; --last 0 keeps none.
    Prune {
        dataset: Option<String>,
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
        #[command(flatten)]
        keep: KeepArgs,
    },
    /// Show assigned policies and owned snapshots, with keep reasons for one dataset.
    Status {
        #[arg(long)]
        json: bool,
        dataset: Option<String>,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Set a local policy assignment; 'none' disables inherited snapshot policy.
    Assign {
        /// Versioned expected-state request file, or - for stdin; emits JSON.
        #[arg(long, conflicts_with = "dry_run")]
        request_json: Option<PathBuf>,
        dataset: String,
        policy: String,
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the local assignment, revealing any inherited ancestor policy.
    Unassign {
        #[arg(long, conflicts_with = "dry_run")]
        request_json: Option<PathBuf>,
        dataset: String,
        #[arg(long)]
        dry_run: bool,
    },
}

impl Command {
    /// Whether this invocation takes the shared writer lock at entry: it can
    /// change snapshots or properties and asks nothing first. A `prune`
    /// without `-y` takes the lock itself, after its answer, so that a prompt
    /// never holds it.
    pub fn locks_at_entry(&self) -> bool {
        match self {
            Self::Protect(_) | Self::Recover(_) => false,
            Self::Run { dry_run, .. }
            | Self::Snap { dry_run, .. }
            | Self::Assign { dry_run, .. }
            | Self::Unassign { dry_run, .. } => !dry_run,
            Self::Prune { dry_run, yes, .. } => !dry_run && *yes,
            Self::Status { .. } => false,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Protect(_) => "protect",
            Self::Recover(_) => "recover",
            Self::Run { .. } => "run",
            Self::Snap { .. } => "snap",
            Self::Prune { .. } => "prune",
            Self::Status { .. } => "status",
            Self::Assign { .. } => "assign",
            Self::Unassign { .. } => "unassign",
        }
    }
}

#[derive(Debug, Default, Args)]
pub struct KeepArgs {
    #[arg(long)]
    pub within: Option<String>,
    #[arg(long)]
    pub last: Option<i64>,
    #[arg(long)]
    pub hourly: Option<i64>,
    #[arg(long)]
    pub daily: Option<i64>,
    #[arg(long)]
    pub weekly: Option<i64>,
    #[arg(long)]
    pub monthly: Option<i64>,
    #[arg(long)]
    pub yearly: Option<i64>,
}

impl KeepArgs {
    pub fn policy(&self) -> Result<Option<Keep>> {
        let keep = Keep {
            within: self.within.as_deref().map(parse_duration).transpose()?,
            last: self.last,
            hourly: self.hourly,
            daily: self.daily,
            weekly: self.weekly,
            monthly: self.monthly,
            yearly: self.yearly,
        };
        if keep.is_empty() {
            return Ok(None);
        }
        keep.validate_prune_override()?;
        Ok(Some(keep))
    }
}

pub fn load_config(explicit: Option<&Path>) -> Result<Config> {
    load_config_from(
        explicit,
        std::env::var_os("ZSNAP_CONFIG").as_deref(),
        Path::new("/etc/zsnap/zsnap.toml"),
    )
}

fn load_config_from(
    explicit: Option<&Path>,
    environment: Option<&OsStr>,
    default: &Path,
) -> Result<Config> {
    let chosen = explicit.or_else(|| environment.map(Path::new));
    let path = chosen.unwrap_or(default);
    match std::fs::read_to_string(path) {
        Ok(text) => Config::from_override(Some(&text)),
        Err(error) if chosen.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
            Config::from_override(None)
        }
        Err(error) => Err(error).with_context(|| format!("read policy config {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_unasked_effect_takes_the_writer_lock_at_entry_and_previews_do_not() {
        let command = |args: &[&str]| Cli::try_parse_from(args).unwrap().command;
        for args in [
            &["zsnap", "run"][..],
            &["zsnap", "snap", "tank/a"],
            &["zsnap", "prune", "tank/a", "-y"],
            &["zsnap", "assign", "tank/a", "guard"],
            &["zsnap", "unassign", "tank/a"],
        ] {
            assert!(command(args).locks_at_entry(), "{args:?}");
            let mut preview = args.to_vec();
            preview.push("--dry-run");
            assert!(!command(&preview).locks_at_entry(), "{preview:?}");
        }
        assert!(!command(&["zsnap", "status"]).locks_at_entry());
        // A prune that asks holds no lock while it waits for the answer.
        assert!(!command(&["zsnap", "prune", "tank/a"]).locks_at_entry());
    }

    #[test]
    fn conventional_verbs_and_retention_overrides_parse() {
        for args in [
            vec!["zsnap", "run", "--dry-run"],
            vec!["zsnap", "snap", "tank/a", "tank/b"],
            vec!["zsnap", "prune", "tank/a", "--last", "0", "-y"],
            vec!["zsnap", "status", "tank/a", "--config", "/example"],
            vec!["zsnap", "assign", "tank/a", "guard"],
            vec!["zsnap", "unassign", "tank/a"],
            vec!["zsnap", "status", "--json"],
            vec!["zsnap", "assign", "tank/a", "guard", "--request-json", "-"],
            vec![
                "zsnap",
                "unassign",
                "tank/a",
                "--request-json",
                "request.json",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        for args in [
            vec!["zsnap", "snap"],
            vec!["zsnap", "overview"],
            vec![
                "zsnap",
                "assign",
                "tank/a",
                "guard",
                "--request-json",
                "-",
                "--dry-run",
            ],
            vec!["zsnap", "prune", "--daliy", "4"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn explicit_zero_is_retained_but_invalid_override_refuses() {
        assert!(KeepArgs::default().policy().unwrap().is_none());
        assert_eq!(
            KeepArgs {
                last: Some(0),
                ..Default::default()
            }
            .policy()
            .unwrap()
            .unwrap()
            .last,
            Some(0)
        );
        for args in [
            KeepArgs {
                daily: Some(0),
                ..Default::default()
            },
            KeepArgs {
                last: Some(-1),
                ..Default::default()
            },
            KeepArgs {
                within: Some("0m".into()),
                ..Default::default()
            },
        ] {
            assert!(args.policy().is_err());
        }
    }

    #[test]
    fn only_absent_default_uses_builtins() {
        let missing =
            Path::new("/nonexistent/zsnap-config-test-81069d32-75dd-4cb2-a159-27d1970e64af");
        assert!(load_config_from(None, None, missing).is_ok());
        assert!(load_config_from(Some(missing), None, missing).is_err());
        assert!(load_config_from(None, Some(missing.as_os_str()), missing).is_err());
    }
}
