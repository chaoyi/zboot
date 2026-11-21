//! Root help follows the job groups in docs/CLI.md using the grammar's descriptions.
use super::grammar::Cli;
use clap::CommandFactory;
use std::fmt::Write;

pub(crate) fn command() -> clap::Command {
    let command = Cli::command().disable_help_subcommand(true);
    let groups: &[(&str, &[&str])] = &[
        ("Look", &["status", "trace"]),
        (
            "Boot environments and trees",
            &[
                "snapshot", "fork", "default", "cmdline", "chroot", "rename", "rollback", "drop",
            ],
        ),
        ("Pairs", &["pair", "sync", "primary", "unpair"]),
        ("Install", &["factory", "deploy", "esp", "wipe"]),
        ("Recover", &["restore", "resume", "abandon"]),
        ("Menu", &["reboot", "boot", "menu"]),
    ];
    let mut grouped = String::new();
    for (heading, verbs) in groups {
        let _ = writeln!(grouped, "{heading}:");
        for verb in *verbs {
            let subcommand = command
                .find_subcommand(verb)
                .expect("help group has a verb");
            let about = subcommand
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            let _ = writeln!(grouped, "  {verb:<10} {}", about.replace('\n', " "));
        }
        grouped.push('\n');
    }
    command
        .help_template(
            "{about-with-newline}\n{usage-heading} {usage}\n\n{after-help}\nOptions:\n{options}",
        )
        .after_help(grouped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_help_groups_the_current_cli_md_verbs() {
        let help = command().render_help().to_string();
        let mut previous = 0;
        for heading in [
            "Look:",
            "Boot environments and trees:",
            "Pairs:",
            "Install:",
            "Recover:",
            "Menu:",
        ] {
            let offset = help
                .find(heading)
                .unwrap_or_else(|| panic!("missing {heading}: {help}"));
            assert!(offset >= previous, "{help}");
            previous = offset;
        }
        assert!(
            help.contains("rename")
                && help.contains("abandon")
                && help.contains("boot")
                && help.contains("menu"),
            "{help}"
        );
        assert!(!help.contains("factory-finish"), "{help}");
        assert!(
            !help.contains("legacy recovery") && !help.contains("  recovery"),
            "{help}"
        );
        assert!(
            help.contains("--help") && help.contains("--version"),
            "{help}"
        );
        let error = Cli::parse_from_args(["zboot", "--help"]).err().unwrap();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("Boot environments and trees:"));
    }
}
