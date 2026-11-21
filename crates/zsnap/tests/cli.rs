#![allow(clippy::disallowed_methods, reason = "test fixtures")]
use std::process::Command;

#[test]
fn executable_help_exposes_conventional_verbs_without_native_io() {
    let output = Command::new(env!("CARGO_BIN_EXE_zsnap"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for verb in ["run", "snap", "prune", "status", "assign", "unassign"] {
        assert!(
            help.lines()
                .any(|line| line.trim_start().starts_with(&format!("{verb} "))),
            "missing {verb}: {help}"
        );
        let output = Command::new(env!("CARGO_BIN_EXE_zsnap"))
            .args([verb, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{verb}");
    }
    assert!(!help.contains("overview"));
}

#[test]
fn malformed_commands_fail_before_any_native_observation() {
    for args in [
        vec!["snap"],
        vec!["overview"],
        vec!["prune", "--daliy", "2"],
        vec!["assign", "tank/data"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_zsnap"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn explicit_missing_config_fails_before_storage_queries() {
    let output = Command::new(env!("CARGO_BIN_EXE_zsnap"))
        .args([
            "status",
            "--config",
            "/nonexistent/zsnap-test-missing-9fdb20fd-944f-4ca0-b20a-6931f75bdf07",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("read policy config"));
    assert!(!error.contains("zfs query"));
}

#[test]
fn machine_request_mismatch_refuses_before_native_execution() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_zsnap"))
        .args(["assign", "tank/data", "guard", "--request-json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let written = child.stdin.take().unwrap().write_all(br#"{"schema_version":1,"expected":{"dataset":"tank/other","identity":{"pool_guid":"1","guid":"2","createtxg":"3","objsetid":"4"},"policy":null,"local_value":null,"inherited_policy":null,"authority":{},"blocker":null},"change":{"set":"guard"}}"#);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    // On a fresh unprivileged host the writer-lock refusal can close stdin
    // before the parent writes. Reap the child and still check that exact
    // refusal below; other input errors must not become a passing test.
    if let Err(error) = written {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(
            stderr.contains("root must initialize the readable writer lock"),
            "request pipe closed for an unexpected reason: {stderr}"
        );
    }
    // A writer that is not root must join the precreated writer lock; on a
    // host without it the command refuses on the lock instead, still before
    // any native execution.
    use std::os::unix::fs::MetadataExt;
    let root = std::fs::metadata("/proc/self").unwrap().uid() == 0;
    let refusal = if root || std::path::Path::new("/run/zfs-tools/writer.lock").exists() {
        "request dataset/change differs from command"
    } else {
        "root must initialize the readable writer lock"
    };
    assert!(stderr.contains(refusal), "{stderr}");
    assert!(!stderr.contains("zfs query"), "{stderr}");
}
