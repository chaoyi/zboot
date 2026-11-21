use super::run::{Incomplete, consent_to, defer_writer, finish, json_response, review, run};
use crate::consent::{Envelope, Outcome, Typed};
use std::{fs, io::Write, os::unix::fs::PermissionsExt, process::Command};

const CASE: &str = "ZBOOT_CLI_OUTPUT_CASE";
const ROOT: &str = "ZBOOT_CLI_OUTPUT_ROOT";
const ARGS: &str = "ZBOOT_CLI_OUTPUT_ARGS";
const RECORD: &str = "ZBOOT_CLI_OUTPUT_RECORD";
const ID: &str = "00112233445566778899aabbccddeeff";
const TOKEN: &str = "ffeeddccbbaa99887766554433221100";

thread_local! {
    static ADMISSION_ORDER: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn admission_event(event: &'static str) {
    ADMISSION_ORDER.with_borrow_mut(|events| events.push(event));
}

fn refuse_admission_lock(
    _: &str,
) -> Result<Option<zfs_tools::engine::lock::WriterLock>, zfs_tools::engine::lock::LockError> {
    admission_event("lock refused");
    Err(zfs_tools::engine::lock::LockError::Busy {
        holder: "another test writer".into(),
    })
}

fn typed_input_lock(
    _: &str,
) -> Result<Option<zfs_tools::engine::lock::WriterLock>, zfs_tools::engine::lock::LockError> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use std::io::Read;
    assert_eq!(ADMISSION_ORDER.with_borrow(Clone::clone), ["plan"]);
    let stdin = std::io::stdin();
    let mut ready = [PollFd::new(&stdin, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    assert_eq!(poll(&mut ready, Some(&timeout)).unwrap(), 1);
    let mut fence = [0; 11];
    fs::File::open("/proc/self/fd/0")
        .unwrap()
        .read_exact(&mut fence)
        .unwrap();
    // This line follows TARGET in the same PTY write. It can be next only
    // after consent consumed the complete typed answer without reading ahead.
    assert_eq!(&fence, b"lock fence\n");
    admission_event("typed answer consumed");
    admission_event("lock");
    Ok(None)
}

struct CaseResult {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
    changed: bool,
    child_verbose: bool,
}

impl CaseResult {
    fn envelope(&self, code: i32, mode: &str) -> serde_json::Value {
        assert_eq!(self.code, code, "{}", self.stderr);
        let value: serde_json::Value = serde_json::from_slice(&self.stdout).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["mode"], mode);
        assert!(value.get("result").is_some());
        value
    }
}

fn case(name: &str, args: &[&str]) -> CaseResult {
    case_with_verbose_environment(name, args, None)
}

fn case_with_verbose_environment(name: &str, args: &[&str], verbose: Option<&str>) -> CaseResult {
    let root = crate::factory::tests::Scratch::new();
    let bin = root.0.join("bin");
    fs::create_dir(&bin).unwrap();
    let shim = r#"#!/bin/sh
if [ "$ZBOOT_VERBOSE" = 1 ]; then
    printf '%s' "$ZBOOT_VERBOSE" > "$ZBOOT_CLI_OUTPUT_ROOT/verbose-child"
fi
if [ -n "$ZBOOT_CLI_OUTPUT_RECORD" ]; then
    case "$0" in
        */zpool) printf 'testpool\n' ;;
        */zfs) printf '%s\tlocal\n' "$ZBOOT_CLI_OUTPUT_RECORD" ;;
        *) exit 1 ;;
    esac
else
    printf 'test observation refusal\n' >&2
    exit 1
fi
"#;
    for program in ["zfs", "zpool", "lsblk"] {
        let path = bin.join(program);
        fs::write(&path, shim).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(root.0.join("exists"), b"existing output").unwrap();
    let args = args
        .iter()
        .map(|arg| {
            arg.strip_prefix("ROOT/").map_or_else(
                || (*arg).to_owned(),
                |relative| root.0.join(relative).to_string_lossy().into_owned(),
            )
        })
        .collect::<Vec<_>>();
    let record = zfs_tools::engine::intent::Intent::new(ID, "sync", serde_json::json!({}));
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "cli::output_tests::a_refusal_with_json_prints_one_refused_envelope",
            "--nocapture",
        ])
        .env(CASE, name)
        .env(ROOT, &root.0)
        .env(ARGS, serde_json::to_string(&args).unwrap())
        .env(
            RECORD,
            if name.starts_with("resume_") {
                serde_json::to_string(&record).unwrap()
            } else {
                String::new()
            },
        )
        .env("PATH", &bin)
        .env_remove("ZBOOT_VERBOSE");
    if let Some(value) = verbose {
        command.env("ZBOOT_VERBOSE", value);
    }
    let output = command.output().unwrap();
    assert!(output.status.code().is_some(), "{output:?}");
    let stdout = fs::read(root.0.join("stdout")).unwrap();
    CaseResult {
        code: output.status.code().unwrap(),
        stdout,
        stderr: String::from_utf8(output.stderr).unwrap(),
        changed: root.0.join("changed").exists(),
        child_verbose: root.0.join("verbose-child").exists(),
    }
}

#[allow(unsafe_code)]
fn child(name: &str) -> ! {
    use std::os::fd::AsRawFd;
    let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
    let output = fs::File::create_new(root.join("stdout")).unwrap();
    std::io::stdout().flush().unwrap();
    // Each child redirects its own stdout after the test harness prologue.
    assert_eq!(
        unsafe { libc::dup2(output.as_raw_fd(), libc::STDOUT_FILENO) },
        libc::STDOUT_FILENO
    );
    zfs_tools::engine::effect::reset();
    let args: Vec<String> = serde_json::from_str(&std::env::var(ARGS).unwrap()).unwrap();
    let code = match name {
        "run" => run(args, |_| Ok(None)),
        "closed_stdin" => {
            assert_eq!(unsafe { libc::close(libc::STDIN_FILENO) }, 0);
            for dry_run in [true, false] {
                defer_writer("test confirmation".into(), |_| Ok(None));
                let result = consent_to(
                    dry_run,
                    (!dry_run).then(|| TOKEN.into()),
                    true,
                    || Ok(7u8),
                    |_| Ok(TOKEN.into()),
                    |_, _| String::new(),
                    |_| Typed {
                        what: "the test target",
                        text: "target".into(),
                    },
                )
                .unwrap();
                assert_eq!(result.is_some(), !dry_run);
            }
            json_response(Envelope::new(Outcome::Applied, None, ())).unwrap();
            finish(Ok(()), true, "test")
        }
        "typed_input" => {
            use std::io::{Read, Write};
            use std::os::fd::{FromRawFd, OwnedFd};
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
            let mut master = unsafe { fs::File::from_raw_fd(master) };
            let slave = unsafe { OwnedFd::from_raw_fd(slave) };
            for fd in [libc::STDIN_FILENO, libc::STDERR_FILENO] {
                assert_eq!(unsafe { libc::dup2(slave.as_raw_fd(), fd) }, fd);
            }
            master
                .write_all(b"target\nlock fence\nnext command\n")
                .unwrap();
            ADMISSION_ORDER.set(Vec::new());
            defer_writer("test typed answer".into(), typed_input_lock);
            let selected = consent_to(
                false,
                None,
                true,
                || {
                    if ADMISSION_ORDER.with_borrow(Vec::is_empty) {
                        assert!(!super::run::writer_is_held_for_test());
                        admission_event("plan");
                    } else {
                        assert!(super::run::writer_is_held_for_test());
                        admission_event("replan");
                    }
                    assert!(!zfs_tools::engine::effect::any());
                    Ok(7u8)
                },
                |_| Ok(TOKEN.into()),
                |_, _| String::new(),
                |_| Typed {
                    what: "the test target",
                    text: "target".into(),
                },
            )
            .unwrap();
            assert!(selected.is_some());
            assert!(super::run::writer_is_held_for_test());
            assert_eq!(
                ADMISSION_ORDER.with_borrow(Clone::clone),
                ["plan", "typed answer consumed", "lock", "replan"]
            );
            assert!(!zfs_tools::engine::effect::any());
            let mut ready = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut ready, 1, 1000) }, 1);
            let mut remaining = [0; 13];
            fs::File::open("/proc/self/fd/0")
                .unwrap()
                .read_exact(&mut remaining)
                .unwrap();
            assert_eq!(&remaining, b"next command\n");
            finish(Ok(()), true, "test")
        }
        "writer_admission" => {
            // Exercise the shared consent/review -> writer gate. No pools are
            // selected here: native pool reopening/cleanup has separate backend tests.
            for lossless in [false, true] {
                for (dry_run, confirm, expected) in [
                    (true, None, vec!["plan"]),
                    (false, Some("stale".to_owned()), vec!["plan"]),
                    (false, Some(TOKEN.to_owned()), vec!["plan", "lock refused"]),
                ] {
                    ADMISSION_ORDER.set(Vec::new());
                    zfs_tools::engine::effect::reset();
                    defer_writer("test direct mutation".into(), refuse_admission_lock);
                    let plan = || {
                        admission_event("plan");
                        assert!(!super::run::writer_is_held_for_test());
                        Ok(7u8)
                    };
                    let selected = if lossless {
                        review(
                            dry_run,
                            confirm.clone(),
                            true,
                            plan,
                            |_| Ok(TOKEN.into()),
                            |_, _| String::new(),
                        )
                    } else {
                        consent_to(
                            dry_run,
                            confirm.clone(),
                            true,
                            plan,
                            |_| Ok(TOKEN.into()),
                            |_, _| String::new(),
                            |_| Typed {
                                what: "the test target",
                                text: "target".into(),
                            },
                        )
                    };
                    let result = selected.and_then(|selected| {
                        if selected.is_some() {
                            admission_event("action");
                            zfs_tools::engine::native::run_mutating(
                                "/bin/sh",
                                &[
                                    "-c".into(),
                                    "printf changed > \"$ZBOOT_CLI_OUTPUT_ROOT/changed\"".into(),
                                ],
                            )?;
                        }
                        Ok(())
                    });
                    if dry_run {
                        result.unwrap();
                    } else if confirm.as_deref() == Some("stale") {
                        let error = result.unwrap_err();
                        assert!(crate::consent::is_stale(error.as_ref()), "{error}");
                    } else {
                        let error = result.unwrap_err();
                        assert!(
                            error
                                .downcast_ref::<zfs_tools::engine::lock::LockError>()
                                .is_some(),
                            "{error}"
                        );
                    }
                    assert_eq!(ADMISSION_ORDER.with_borrow(Clone::clone), expected);
                    assert!(!super::run::writer_is_held_for_test());
                    assert!(!zfs_tools::engine::effect::any());
                    assert!(!root.join("changed").exists());
                }
            }
            json_response(Envelope::new(Outcome::Applied, None, ())).unwrap();
            finish(Ok(()), true, "test")
        }
        "verbose_successive" => {
            assert!(!zfs_tools::engine::native::set_verbose(false));
            assert_eq!(run(["zboot", "status", "-v", "--json"], |_| Ok(None)), 1);
            assert!(!zfs_tools::engine::native::set_verbose(false));
            eprintln!("FIRST_VERBOSE_INVOCATION_ENDED");
            let code = run(["zboot", "status", "--json"], |_| Ok(None));
            assert!(!zfs_tools::engine::native::set_verbose(false));
            code
        }
        "verbose_nested" => {
            assert!(!zfs_tools::engine::native::set_verbose(true));
            let code = run(["zboot", "status", "--json"], |_| Ok(None));
            assert!(zfs_tools::engine::native::set_verbose(false));
            code
        }
        "verbose_help" | "verbose_usage" => {
            assert!(!zfs_tools::engine::native::set_verbose(false));
            let args = if name == "verbose_help" {
                ["zboot", "-v", "--help"]
            } else {
                ["zboot", "-v", "--unsupported-flag"]
            };
            let code = run(args, |_| Ok(None));
            assert!(!zfs_tools::engine::native::set_verbose(true));
            assert_eq!(run(args, |_| Ok(None)), code);
            assert!(zfs_tools::engine::native::set_verbose(false));
            code
        }
        "trace_success" => {
            let trace = crate::trace::Trace {
                schema_version: 1,
                kernel_sha256: None,
                initrd_sha256: None,
                omitted_events: 0,
                events: vec![crate::trace::Event {
                    stage: crate::trace::Stage::ImportReadonly,
                    complete: true,
                    elapsed_ms: 1,
                }],
            };
            let cmdline = root.join("cmdline");
            fs::write(
                &cmdline,
                format!("zboot.trace={}\n", trace.token(1024).unwrap().unwrap()),
            )
            .unwrap();
            run(
                vec![
                    "zboot".into(),
                    "trace".into(),
                    "--cmdline".into(),
                    cmdline.to_string_lossy().into_owned(),
                    "--json".into(),
                ],
                |_| Ok(None),
            )
        }
        "lock" => run(args, |_| {
            Err(zfs_tools::engine::lock::LockError::Io(
                "test lock refusal".into(),
            ))
        }),
        "stale" | "unconfirmed" => {
            let result = consent_to(
                false,
                (name == "stale").then(|| "old token".into()),
                true,
                || Ok(7u8),
                |_| Ok(TOKEN.into()),
                |_, token| format!("Plan token {token}\n"),
                |_| Typed {
                    what: "the target",
                    text: "target".into(),
                },
            );
            finish(result.map(|_| ()), true, "fork")
        }
        "stale_replan" | "stale_after_effect" => {
            defer_writer(
                "fork".into(),
                if name == "stale_after_effect" {
                    |_| {
                        // Model the writable UKI import before the locked replan.
                        zfs_tools::engine::effect::mark();
                        Ok(None)
                    }
                } else {
                    |_| Ok(None)
                },
            );
            let calls = std::cell::Cell::new(0u8);
            let result = consent_to(
                false,
                Some("planned-1".into()),
                true,
                || {
                    let value = calls.get() + 1;
                    calls.set(value);
                    Ok(value)
                },
                |value| Ok(format!("planned-{value}")),
                |_, token| format!("Plan token {token}\n"),
                |_| Typed {
                    what: "the target",
                    text: "target".into(),
                },
            );
            finish(result.map(|_| ()), true, "fork")
        }
        "matching_after_delay" => {
            let preview = crate::consent::token(&7u8).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
            defer_writer("pair".into(), |_| Ok(None));
            let result = consent_to(
                false,
                Some(preview),
                true,
                || Ok(7u8),
                crate::consent::token,
                |_, token| format!("Plan token {token}\n"),
                |_| Typed {
                    what: "the target",
                    text: "target".into(),
                },
            );
            assert!(matches!(result, Ok(Some(_))));
            finish(result.map(|_| ()), true, "pair")
        }
        "nonloss_stale" => {
            let result = super::pairs::consent(
                7u8,
                false,
                super::pairs::ConsentFlags {
                    dry_run: false,
                    confirm: Some("old token".into()),
                    json: true,
                },
                || Ok(7u8),
                crate::consent::token,
                |_, token| format!("Plan token {token}\n"),
                |_| Typed {
                    what: "the target",
                    text: "target".into(),
                },
            );
            finish(result.map(|_| ()), true, "primary")
        }
        "review_changed" | "review_confirm_changed" | "review_dry_run" => {
            defer_writer("snapshot".into(), |_| {
                let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
                fs::write(root.join("review-lock"), b"held").unwrap();
                Ok(None)
            });
            let dry_run = name == "review_dry_run";
            let calls = std::cell::Cell::new(0);
            let result = review(
                dry_run,
                (name == "review_confirm_changed").then(|| crate::consent::token(&1u8).unwrap()),
                true,
                || {
                    calls.set(calls.get() + 1);
                    Ok(if root.join("review-lock").exists() {
                        2u8
                    } else {
                        1u8
                    })
                },
                crate::consent::token,
                |_, _| String::new(),
            );
            assert_eq!(calls.get(), if dry_run { 1 } else { 2 });
            assert_eq!(root.join("review-lock").exists(), !dry_run);
            assert!(!zfs_tools::engine::effect::any());
            let result = result.and_then(|planned| {
                if let Some((plan, token)) = planned {
                    assert_eq!(name, "review_changed");
                    assert_eq!(plan, 2);
                    assert_eq!(token, crate::consent::token(&2u8).unwrap());
                    fs::write(root.join("changed"), b"applied fresh locked plan")?;
                    json_response(Envelope::new(Outcome::Applied, Some(token), plan))?;
                }
                Ok(())
            });
            finish(result, true, "snapshot")
        }
        "sync_all_admissions_failed" => {
            let entries = vec![crate::pairs::SyncEntry {
                source: "testpool/data".into(),
                destination: "peer/data".into(),
                result: None,
                error: Some("receiver admission refused".into()),
            }];
            let result = super::pairs::report_synced(
                &crate::pairs::SyncTarget::All,
                entries,
                "frozen-token".into(),
                true,
            );
            assert!(!zfs_tools::engine::effect::any());
            finish(result, true, "sync")
        }
        "partial" => {
            json_response(Envelope::new(
                Outcome::Partial,
                None,
                serde_json::json!({"complete":false}),
            ))
            .unwrap();
            finish(
                Err(Incomplete("incomplete result".into()).into()),
                true,
                "sync",
            )
        }
        "effect" | "resume_effect" | "record_removed" => {
            if name != "effect" {
                zfs_tools::engine::effect::operation_hint(ID);
            }
            let result = zfs_tools::engine::native::run_mutating(
                "/bin/sh",
                &[
                    "-c".into(),
                    "printf changed > \"$1\"; exit 9".into(),
                    "effect-test".into(),
                    root.join("changed").to_string_lossy().into_owned(),
                ],
            );
            finish(
                result
                    .map(drop)
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>),
                true,
                "sync",
            )
        }
        "resume_admission" => {
            zfs_tools::engine::effect::operation_hint(ID);
            assert!(!zfs_tools::engine::effect::any());
            finish(Err("resume admission refused".into()), true, "resume")
        }
        "chroot" => {
            zfs_tools::engine::effect::mark();
            finish(
                Err(crate::maintenance::CommandExit(23).into()),
                false,
                "chroot",
            )
        }
        _ => panic!("unknown child case {name}"),
    };
    std::process::exit(code)
}

#[test]
fn tree_actions_open_access_only_after_the_typed_answer() {
    // Real PTY consent and common writer state, with the pool access set empty.
    case("typed_input", &[]).envelope(0, "applied");
}

#[test]
fn direct_mutations_require_their_writer_lock_before_native_effects() {
    let result = case("writer_admission", &[]);
    result.envelope(0, "applied");
    assert!(!result.changed);
}

#[test]
fn preview_and_token_confirmation_work_with_closed_stdin() {
    case("closed_stdin", &[]).envelope(0, "applied");
}

#[test]
fn an_ordinary_lossless_review_adopts_the_fresh_locked_plan_and_token() {
    let result = case("review_changed", &[]);
    let value = result.envelope(0, "applied");
    assert_eq!(value["result"], 2);
    assert_eq!(value["token"], crate::consent::token(&2u8).unwrap());
    assert!(result.changed);
}

#[test]
fn a_confirmed_lossless_review_refuses_a_locked_plan_change_without_a_new_token() {
    let result = case("review_confirm_changed", &[]);
    let value = result.envelope(3, "refused");
    assert_eq!(value["result"]["reason"], "stale_token");
    assert!(value.get("token").is_none());
    assert!(
        !result
            .stderr
            .contains(&crate::consent::token(&2u8).unwrap())
    );
    assert!(!result.changed);
}

#[test]
fn a_lossless_dry_run_keeps_the_unlocked_preview_without_acting() {
    let result = case("review_dry_run", &[]);
    let value = result.envelope(0, "preview");
    assert_eq!(value["result"], 1);
    assert_eq!(value["token"], crate::consent::token(&1u8).unwrap());
    assert!(!result.changed);
}

#[test]
fn verbose_diagnostics_keep_json_on_stdout_and_commands_on_stderr() {
    let quiet = case("run", &["zboot", "status", "--json"]);
    quiet.envelope(1, "refused");
    assert!(!quiet.stderr.lines().any(|line| line.starts_with("+ ")));
    assert!(!quiet.child_verbose);

    for result in [
        case("run", &["zboot", "status", "--json", "-v"]),
        case_with_verbose_environment("run", &["zboot", "status", "--json"], Some("1")),
    ] {
        result.envelope(1, "refused");
        assert!(result.child_verbose);
        assert!(
            result
                .stderr
                .lines()
                .any(|line| line.starts_with("+ zpool "))
        );
    }
    let disabled = case_with_verbose_environment("run", &["zboot", "status", "--json"], Some("0"));
    disabled.envelope(1, "refused");
    assert!(!disabled.stderr.lines().any(|line| line.starts_with("+ ")));
    assert!(!disabled.child_verbose);
}

#[test]
fn successive_invocations_restore_verbosity_and_nested_calls_inherit_it() {
    let result = case("verbose_successive", &[]);
    assert_eq!(result.code, 1, "{}", result.stderr);
    let objects = serde_json::Deserializer::from_slice(&result.stdout)
        .into_iter::<serde_json::Value>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(objects.len(), 2);
    assert!(objects.iter().all(|value| value["mode"] == "refused"));
    let (first, second) = result
        .stderr
        .split_once("FIRST_VERBOSE_INVOCATION_ENDED")
        .unwrap();
    assert!(first.lines().any(|line| line.starts_with("+ zpool ")));
    assert!(!second.lines().any(|line| line.starts_with("+ ")));

    let nested = case("verbose_nested", &[]);
    nested.envelope(1, "refused");
    assert!(
        nested
            .stderr
            .lines()
            .any(|line| line.starts_with("+ zpool "))
    );
    assert_eq!(case("verbose_help", &[]).code, 0);
    assert_eq!(case("verbose_usage", &[]).code, 2);
}

#[test]
fn sync_all_with_only_failed_admissions_is_partial_without_a_new_effect() {
    let value = case("sync_all_admissions_failed", &[]).envelope(4, "partial");
    assert_eq!(value["result"]["complete"], false);
    assert_eq!(
        value["result"]["pairs"][0]["result"],
        serde_json::Value::Null
    );
}

#[test]
fn a_refusal_with_json_prints_one_refused_envelope() {
    if let Ok(name) = std::env::var(CASE) {
        child(&name);
    }
    let result = case(
        "run",
        &["zboot", "trace", "--cmdline", "ROOT/missing", "--json"],
    );
    let value = result.envelope(1, "refused");
    assert_eq!(value["result"]["reason"], "error");
    case("lock", &["zboot", "snapshot", "testpool/data", "--json"]).envelope(1, "refused");
}

#[test]
fn every_json_output_is_the_envelope() {
    for args in [
        vec!["trace", "--cmdline", "ROOT/missing"],
        vec!["status"],
        vec!["snapshot", "testpool/data"],
        vec!["fork", "testpool/data@s", "testpool/copy"],
        vec!["default", "testpool/ROOT/be"],
        vec!["cmdline", "testpool/ROOT/be"],
        vec!["rename", "testpool/data", "testpool/new"],
        vec!["rollback", "testpool/data@s"],
        vec!["drop", "testpool/data"],
        vec!["pair", "testpool/data", "otherpool/data"],
        vec!["sync", "testpool/data"],
        vec!["primary", "testpool/data"],
        vec!["unpair", "testpool/data"],
        vec!["wipe", "/dev/test-disk"],
        vec!["restore", "testpool/ROOT/be@s", "/dev/test-disk"],
        vec!["resume", ID],
        vec!["factory", "ROOT/exists"],
        vec![
            "deploy",
            "/dev/test-disk",
            "--empty",
            "--efi",
            "ROOT/missing",
        ],
        vec!["esp", "/dev/test-partition", "--efi", "ROOT/missing"],
    ] {
        let args = std::iter::once("zboot")
            .chain(args)
            .chain(["--json"])
            .collect::<Vec<_>>();
        case("run", &args).envelope(1, "refused");
    }
    let value = case("trace_success", &[]).envelope(0, "applied");
    assert_eq!(value["result"]["events"][0]["stage"], "import_readonly");
}

#[test]
fn a_stale_token_is_refused_without_a_new_token() {
    let result = case("stale", &[]);
    let value = result.envelope(3, "refused");
    assert_eq!(value["result"]["reason"], "stale_token");
    assert!(value.get("token").is_none());
    assert!(!String::from_utf8(result.stdout).unwrap().contains(TOKEN));
    assert!(!result.stderr.contains(TOKEN));
    let result = case("unconfirmed", &[]);
    assert_eq!(result.envelope(3, "preview")["token"], TOKEN);
    let result = case("stale_replan", &[]);
    assert_eq!(
        result.envelope(3, "refused")["result"]["reason"],
        "stale_token"
    );
    assert!(!result.stderr.contains("planned-2"));
}

#[test]
fn a_token_previewed_earlier_still_confirms_after_a_delay() {
    case("matching_after_delay", &[]).envelope(0, "applied");
}

#[test]
fn a_stale_locked_plan_after_the_first_effect_returns_partial_without_a_new_token() {
    let result = case("stale_after_effect", &[]);
    let value = result.envelope(4, "partial");
    assert_eq!(value["result"]["reason"], "stale_token");
    assert!(value.get("token").is_none());
    assert!(!result.stderr.contains("planned-2"));
}

#[test]
fn a_verb_without_loss_still_checks_a_token_it_is_given() {
    let result = case("nonloss_stale", &[]);
    assert_eq!(
        result.envelope(3, "refused")["result"]["reason"],
        "stale_token"
    );
    assert!(!result.stderr.contains("Plan token"));
}

#[test]
fn partial_exits_4_from_the_first_durable_effect() {
    case("partial", &[]).envelope(4, "partial");
    let result = case("effect", &[]);
    result.envelope(4, "partial");
    assert!(result.changed);
    let result = case("record_removed", &[]);
    let value = result.envelope(4, "partial");
    assert!(value.get("operation").is_none());
    assert!(!result.stderr.contains("zboot resume"));
}

#[test]
fn resume_admission_refusal_has_no_effect() {
    let result = case("resume_admission", &[]);
    let value = result.envelope(1, "refused");
    assert!(value.get("operation").is_none());
    assert!(!result.changed);
}

#[test]
fn resume_mutation_before_checkpoint_is_partial() {
    let result = case("resume_effect", &[]);
    assert_eq!(result.envelope(4, "partial")["operation"], ID);
    assert!(result.changed);
    assert!(result.stderr.contains(&format!("zboot resume {ID}")));
}

#[test]
fn usage_errors_emit_no_json_and_chroot_keeps_its_status() {
    let result = case("run", &["zboot", "unknown-verb", "--json"]);
    assert_eq!(result.code, 2);
    assert!(result.stdout.is_empty());
    let result = case("chroot", &[]);
    assert_eq!(result.code, 23);
    assert!(result.stdout.is_empty());
}
