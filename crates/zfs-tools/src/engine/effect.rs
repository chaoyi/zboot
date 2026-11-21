//! Effects and recovery guidance accumulated by this command invocation.
//! Call `reset` at the invocation boundary before admitting any work.
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "internal")]
use std::{collections::BTreeSet, sync::Mutex};

static EFFECT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "internal")]
static HINTS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Record an actual write or a dispatched native mutation with an uncertain outcome.
pub fn mark() {
    EFFECT.store(true, Ordering::SeqCst);
}

/// Whether this invocation has performed or dispatched a mutation.
#[cfg(feature = "internal")]
pub fn any() -> bool {
    EFFECT.load(Ordering::SeqCst)
}

/// Start a new invocation, clearing its effect flag and guidance-only IDs.
#[cfg(feature = "internal")]
pub fn reset() {
    EFFECT.store(false, Ordering::SeqCst);
    HINTS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
}

/// Remember an operation ID for later verified recovery guidance.
/// A hint carries no authority and does not itself record an effect.
#[cfg(feature = "internal")]
pub fn operation_hint(id: &str) {
    if !id.is_empty() {
        HINTS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(id.into());
    }
}

/// Deterministically ordered guidance candidates, requiring native revalidation.
#[cfg(feature = "internal")]
pub fn operation_hints() -> Vec<String> {
    HINTS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .cloned()
        .collect()
}

#[cfg(test)]
#[cfg(feature = "internal")]
mod tests {
    use super::*;
    use crate::engine::{intent, native};
    use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

    const CASE: &str = "ZFS_TOOLS_EFFECT_CASE";
    const STATE: &str = "ZFS_TOOLS_EFFECT_STATE";
    const ID: &str = "00112233445566778899aabbccddeeff";

    // Each assertion about invocation state runs in its own process. Native
    // writer routes execute this fixed test shim instead of an installed zfs.
    #[test]
    fn native_writers_keep_effects_invocation_local() {
        if let Ok(case) = std::env::var(CASE) {
            child_case(&case);
            return;
        }
        let root = std::env::temp_dir().join(format!("zfs-tools-effect-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let shim = root.join("zfs");
        fs::write(
            &shim,
            r#"#!/bin/sh
case "$1" in
get)
    if [ -f "$ZFS_TOOLS_EFFECT_STATE" ]; then
        [ "$ZFS_TOOLS_EFFECT_CASE" = readback_failure ] && exit 7
        printf '%s\tlocal\n' "$(cat "$ZFS_TOOLS_EFFECT_STATE")"
    else
        printf '%s\t-\n' '-'
    fi
    ;;
set)
    case "$2" in
        zboot:operation=*) printf '%s' "${2#*=}" > "$ZFS_TOOLS_EFFECT_STATE" ;;
        *) exit 2 ;;
    esac
    [ "$ZFS_TOOLS_EFFECT_CASE" = lost_reply ] && exit 9
    ;;
inherit) rm -f "$ZFS_TOOLS_EFFECT_STATE" ;;
*) exit 2 ;;
esac
exit 0
"#,
        )
        .unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).unwrap();
        let path = std::env::join_paths(
            std::iter::once(root.clone())
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        let mut failures = Vec::new();
        for case in [
            "hints",
            "read",
            "spawn_failure",
            "native_failure",
            "invalid_stdout",
            "begin",
            "advance",
            "remove",
            "noop",
            "lost_reply",
            "readback_failure",
        ] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine::effect::tests::native_writers_keep_effects_invocation_local",
                    "--nocapture",
                ])
                .env(CASE, case)
                .env(STATE, root.join(format!("{case}.state")))
                .env("PATH", &path)
                .output()
                .unwrap();
            if !output.status.success() {
                failures.push(format!(
                    "{case}: {}\n{}\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        fs::remove_dir_all(&root).unwrap();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    fn child_case(case: &str) {
        use intent::Backend;
        assert!(!any());
        assert!(operation_hints().is_empty());
        let state = std::env::var_os(STATE).unwrap();
        let state = Path::new(&state);
        let record = intent::Intent::new(ID, "effect-test", 0);
        let seed = || fs::write(state, intent::encode(&record).unwrap()).unwrap();
        match case {
            "hints" => {
                operation_hint("second");
                operation_hint("first");
                operation_hint("second");
                assert_eq!(operation_hints(), ["first", "second"]);
                assert!(!any());
                mark();
                assert!(any());
                reset();
                assert!(!any());
                assert!(operation_hints().is_empty());
            }
            "read" => {
                assert_eq!(intent::Native.read("tank").unwrap(), None);
                assert!(!any());
                assert!(operation_hints().is_empty());
            }
            "spawn_failure" => {
                assert!(native::run_mutating("/zfs-tools-effect-missing-executable", &[]).is_err());
                assert!(!any());
            }
            "native_failure" => {
                let args = [
                    "-c".into(),
                    "printf changed > \"$ZFS_TOOLS_EFFECT_STATE\"; exit 9".into(),
                ];
                assert!(native::run_mutating("/bin/sh", &args).is_err());
                assert_eq!(fs::read_to_string(state).unwrap(), "changed");
                assert!(any());
            }
            "invalid_stdout" => {
                let args = ["-c".into(), "printf '\\377'".into()];
                assert!(native::run_mutating("/bin/sh", &args).is_err());
                assert!(any());
            }
            "begin" | "lost_reply" => {
                intent::begin(&mut intent::Native, "tank", &record).unwrap();
                assert!(any());
                assert_eq!(operation_hints(), [ID]);
                assert_eq!(
                    intent::Native.read("tank").unwrap(),
                    Some(intent::encode(&record).unwrap())
                );
            }
            "advance" => {
                seed();
                let mut next = record.clone();
                next.step = 1;
                intent::advance(&mut intent::Native, "tank", &record, &next).unwrap();
                assert!(any());
                assert_eq!(operation_hints(), [ID]);
                assert_eq!(
                    intent::Native.read("tank").unwrap(),
                    Some(intent::encode(&next).unwrap())
                );
            }
            "remove" => {
                seed();
                intent::finish(&mut intent::Native, "tank", &record).unwrap();
                assert!(any());
                assert_eq!(operation_hints(), [ID]);
                assert_eq!(intent::Native.read("tank").unwrap(), None);
            }
            "noop" => {
                intent::Native.remove("tank").unwrap();
                seed();
                intent::advance(&mut intent::Native, "tank", &record, &record).unwrap();
                intent::Native
                    .write("tank", &intent::encode(&record).unwrap())
                    .unwrap();
                assert!(intent::begin(&mut intent::Native, "tank", &record).is_err());
                assert!(!any());
                assert!(operation_hints().is_empty());
            }
            "readback_failure" => {
                assert!(intent::begin(&mut intent::Native, "tank", &record).is_err());
                assert_eq!(
                    fs::read_to_string(state).unwrap(),
                    intent::encode(&record).unwrap()
                );
                assert!(any());
                assert_eq!(operation_hints(), [ID]);
            }
            _ => panic!("unknown effect child case {case}"),
        }
    }
}
