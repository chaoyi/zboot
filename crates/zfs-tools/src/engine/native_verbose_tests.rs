use super::{announce, announced, run, set_verbose, verbose};
use std::process::{Command, Output};

const CASE: &str = "ZFS_TOOLS_NATIVE_VERBOSE_TEST_CASE";
const CHILD: &str = "engine::native::verbose_tests::verbose_child";
const JSON: &str = r#"{"ok":true}"#;
const JSON_ANNOUNCEMENT: &str = "+ /usr/bin/printf %s {\"ok\":true}\n";

fn child_command(case: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD, "--nocapture"])
        .env(CASE, case)
        .env_remove("ZBOOT_VERBOSE");
    command
}

fn checked_output(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "child failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("+ "),
        "diagnostics reached stdout"
    );
    output
}

fn captured_json_is_unchanged() {
    let output = run("/usr/bin/printf", &["%s".into(), JSON.into()]).unwrap();
    assert_eq!(output, JSON);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).unwrap()["ok"],
        true
    );
}

#[test]
fn verbosity_is_opt_in_and_preserves_captured_json() {
    for env in [None, Some("0"), Some("true"), Some("01")] {
        let mut command = child_command("quiet");
        if let Some(value) = env {
            command.env("ZBOOT_VERBOSE", value);
        }
        let output = checked_output(&mut command);
        assert!(
            output.stderr.is_empty(),
            "unexpected diagnostic for {env:?}"
        );
    }
    for case in ["flag", "environment"] {
        let mut command = child_command(case);
        if case == "environment" {
            command.env("ZBOOT_VERBOSE", "1");
        }
        let output = checked_output(&mut command);
        assert_eq!(String::from_utf8(output.stderr).unwrap(), JSON_ANNOUNCEMENT);
    }
}

#[test]
fn announcement_escapes_program_arguments_and_terminal_controls() {
    let output = checked_output(&mut child_command("escaped"));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "+ p\\u{a}rog one\\u{9}two \\u{1b}[31m back\\\\slash \\u{202e}\n"
    );
}

#[test]
fn announced_propagates_verbose_after_environment_clear_to_a_nested_process() {
    let output = checked_output(&mut child_command("env-clear"));
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.starts_with("+ "));
    assert!(
        diagnostic.contains(" --exact engine::native::verbose_tests::verbose_child --nocapture\n")
    );
    assert!(diagnostic.ends_with(JSON_ANNOUNCEMENT));
    assert_eq!(diagnostic.lines().count(), 2);
}

// Each scenario runs in its own process: no test changes the environment or
// verbosity of another test in this binary.
#[test]
fn verbose_child() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    assert!(!set_verbose(false));
    match case.as_str() {
        "quiet" => {
            assert!(!verbose());
            captured_json_is_unchanged();
        }
        "flag" => {
            assert!(!verbose());
            assert!(!set_verbose(true));
            assert!(set_verbose(true));
            assert!(set_verbose(false));
            assert!(!verbose());
            assert!(!set_verbose(true));
            captured_json_is_unchanged();
            assert!(set_verbose(false));
        }
        "environment" | "nested-environment" => {
            assert_eq!(std::env::var("ZBOOT_VERBOSE").unwrap(), "1");
            assert!(verbose());
            assert!(!set_verbose(false));
            assert!(verbose());
            captured_json_is_unchanged();
        }
        "escaped" => {
            set_verbose(true);
            let mut command = Command::new("p\nrog");
            command.args(["one\ttwo", "\u{1b}[31m", r"back\slash", "\u{202e}"]);
            announce(&command);
        }
        "env-clear" => {
            assert!(!set_verbose(true));
            let mut command = child_command("nested-environment");
            command.env_clear().env(CASE, "nested-environment");
            let output = announced(&mut command).output().unwrap();
            assert!(output.status.success(), "{output:?}");
            assert_eq!(String::from_utf8_lossy(&output.stderr), JSON_ANNOUNCEMENT);
            assert!(!String::from_utf8_lossy(&output.stdout).contains("+ "));
            eprint!("{}", String::from_utf8(output.stderr).unwrap());
        }
        _ => panic!("unknown verbose test case: {case}"),
    }
}
