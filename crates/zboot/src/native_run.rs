//! Bounded execution of fixed native programs: device observation, wipe's
//! NVMe and signature probes, restore's key relink helper, hostid adoption,
//! the loop module for `deploy --image`, and `lsinitramfs` in a portable root.
use std::{
    io::Read,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use zfs_tools::engine::Error;
fn refuse(detail: impl Into<String>) -> Error {
    Error::Refused(detail.into())
}
fn error(e: impl std::fmt::Display) -> Error {
    refuse(e.to_string())
}
/// Bounded output from one fixed native program. Callers that need to accept
/// a documented nonzero status use this status-preserving seam; ordinary
/// readers use [`run`].
pub struct NativeOutput {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
/// Fixed native programs only; both output streams and elapsed execution are
/// bounded. There is no shell and no process detached from its owned group.
pub fn run(program: &str, args: &[String], limit: usize, seconds: u64) -> Result<String, Error> {
    let output = run_status(program, args, limit, seconds)?;
    if !output.status.success() {
        return Err(refuse(format!(
            "{program} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout).map_err(error)
}

/// Run one fixed native reader while preserving its exit status and both
/// bounded output streams. No shell or detached process is involved.
pub fn run_status(
    program: &str,
    args: &[String],
    limit: usize,
    seconds: u64,
) -> Result<NativeOutput, Error> {
    run_status_with(program, args, limit, seconds, false)
}

/// Run a fixed mutator. A successfully spawned child may change durable state
/// even when its exit, output or subsequent observation reports failure.
pub fn run_status_mutating(
    program: &str,
    args: &[String],
    limit: usize,
    seconds: u64,
) -> Result<NativeOutput, Error> {
    run_status_with(program, args, limit, seconds, true)
}

fn run_status_with(
    program: &str,
    args: &[String],
    limit: usize,
    seconds: u64,
    mutating: bool,
) -> Result<NativeOutput, Error> {
    if ![
        "zdb",
        "zpool",
        "zfs",
        "lsblk",
        "blkid",
        "nvme",
        "/sbin/zboot-probe-signatures",
        "/sbin/zboot-change-key",
        "/sbin/modprobe",
        "chroot",
    ]
    .contains(&program)
    {
        return Err(refuse("unsupported native program"));
    }
    if !fixed_args(program, args) {
        return Err(refuse(format!(
            "{program} is restricted to its fixed argument profile"
        )));
    }
    let mut child = zfs_tools::engine::native::announced(
        Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0),
    )
    .spawn()
    .map_err(error)?;
    if mutating {
        zfs_tools::engine::effect::mark();
    }
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).map_err(error)?);
    let (tx, rx) = mpsc::channel();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| refuse("child stdout missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| refuse("child stderr missing"))?;
    let readers = [
        (true, Box::new(stdout) as Box<dyn Read + Send>, limit),
        (false, Box::new(stderr) as Box<dyn Read + Send>, 64 * 1024),
    ]
    .into_iter()
    .map(|(out, pipe, cap)| {
        let tx = tx.clone();
        thread::spawn(move || {
            let mut data = Vec::new();
            let result = pipe
                .take(cap as u64 + 1)
                .read_to_end(&mut data)
                .map(|_| data)
                .and_then(|data| {
                    if data.len() > cap {
                        Err(std::io::Error::other("native output exceeds bound"))
                    } else {
                        Ok(data)
                    }
                });
            let _ = tx.send((out, result));
        })
    })
    .collect::<Vec<_>>();
    drop(tx);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let result = (|| -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), Error> {
        let mut output = None;
        let mut errors = None;
        while output.is_none() || errors.is_none() {
            if Instant::now() >= deadline {
                return Err(refuse("native command timed out"));
            }
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok((true, value)) => output = Some(value.map_err(error)?),
                Ok((false, value)) => errors = Some(value.map_err(error)?),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(e) => return Err(error(e)),
            }
        }
        loop {
            if let Some(status) = child.try_wait().map_err(error)? {
                return Ok((status, output.unwrap(), errors.unwrap()));
            }
            if Instant::now() >= deadline {
                return Err(refuse("native command timed out"));
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    if result.is_err() {
        // Child has not been reaped on this branch, so its numeric identity
        // cannot have been recycled into another process group.
        let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
        let _ = child.wait();
    }
    for reader in readers {
        reader
            .join()
            .map_err(|_| refuse("native reader panicked"))?;
    }
    let (status, stdout, stderr) = result?;
    Ok(NativeOutput {
        status,
        stdout,
        stderr,
    })
}
fn fixed_args(program: &str, args: &[String]) -> bool {
    let valid_path = |value: &str| {
        value.starts_with("/dev/")
            && !value.chars().any(char::is_control)
            && !value.split('/').any(|part| part == "." || part == "..")
    };
    match program {
        "/sbin/zboot-probe-signatures" => {
            args.len() == 2 && args[0] == "--" && valid_path(&args[1])
        }
        // A pool's child, never a pool root, snapshot or bookmark.
        "/sbin/zboot-change-key" => match args {
            [check] => check == "--check",
            [verb, dataset] => {
                (verb == "inherit" || verb == "new-key")
                    && dataset.contains('/')
                    && zfs_tools::engine::validate_dataset_name(dataset).is_ok()
            }
            _ => false,
        },
        // The admin queries wipe reads, and the one Sanitize it submits.
        "nvme" => match args {
            [verb, device, rest @ ..] if valid_path(device) => match verb.as_str() {
                "id-ctrl" | "list-ns" | "id-ns" | "sanitize-log" => {
                    rest.last()
                        .is_some_and(|last| last == "--output-format=json")
                        && rest[..rest.len() - 1].iter().all(|option| {
                            option == "--all"
                                || option
                                    .strip_prefix("--namespace-id=")
                                    .is_some_and(|n| n.parse::<u32>().is_ok())
                        })
                }
                "sanitize" => {
                    matches!(rest, [action] if action == "--sanact=2" || action == "--sanact=4")
                }
                _ => false,
            },
            _ => false,
        },
        _ => true,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn words(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn probes_and_nvme_accept_only_their_fixed_profiles() {
        let probe = "/sbin/zboot-probe-signatures";
        assert!(fixed_args(probe, &words(&["--", "/dev/vdb"])));
        for args in [
            words(&["/dev/vdb"]),
            words(&["--", "/tmp/file"]),
            words(&["--", "/dev/../tmp/file"]),
            words(&["--", "/dev/vdb", "extra"]),
            words(&["--", "/dev/vdb\n"]),
        ] {
            assert!(!fixed_args(probe, &args));
        }
        let helper = "/sbin/zboot-change-key";
        for args in [
            words(&["--check"]),
            words(&["inherit", "rpool/secret/inner"]),
            words(&["new-key", "rpool/secret"]),
        ] {
            assert!(fixed_args(helper, &args), "{args:?}");
        }
        for args in [
            words(&[]),
            words(&["--check", "rpool/a"]),
            words(&["inherit", "rpool"]),
            words(&["inherit", "rpool/a@snap"]),
            words(&["inherit", "rpool/a#mark"]),
            words(&["inherit", "rpool/a\n"]),
            words(&["rewrap", "rpool/a"]),
            words(&["inherit", "rpool/a", "extra"]),
        ] {
            assert!(!fixed_args(helper, &args), "{args:?}");
        }
        for args in [
            words(&["id-ctrl", "/dev/nvme0", "--output-format=json"]),
            words(&["list-ns", "/dev/nvme0", "--output-format=json"]),
            words(&["list-ns", "/dev/nvme0", "--all", "--output-format=json"]),
            words(&[
                "id-ns",
                "/dev/nvme0",
                "--namespace-id=1",
                "--output-format=json",
            ]),
            words(&["sanitize-log", "/dev/nvme0", "--output-format=json"]),
            words(&["sanitize", "/dev/nvme0", "--sanact=4"]),
            words(&["sanitize", "/dev/nvme0", "--sanact=2"]),
        ] {
            assert!(fixed_args("nvme", &args), "{args:?}");
        }
        for args in [
            words(&["id-ctrl", "/dev/nvme0"]),
            words(&["format", "/dev/nvme0n1", "--output-format=json"]),
            words(&["sanitize", "/dev/nvme0", "--sanact=3"]),
            words(&["sanitize", "/dev/nvme0", "--sanact=1"]),
            words(&["sanitize", "/dev/nvme0", "--sanact=4", "--ause"]),
            words(&["list-ns", "/tmp/x", "--output-format=json"]),
            words(&["list-ns", "/dev/nvme0", "--csi=2", "--output-format=json"]),
            words(&["list-ctrl", "/dev/nvme0", "--output-format=json"]),
        ] {
            assert!(!fixed_args("nvme", &args), "{args:?}");
        }
    }
}
