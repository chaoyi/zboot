//! Owned native replication pipeline: the host's own `zfs send -w | zfs
//! receive`, one dataset per stream. No force receive, resumable partial-state
//! deletion, shell interpolation, or uncontrolled stderr buffering. Application
//! executors supply the frozen scope, fencing and durable intent before calling.
mod quiesce;
use crate::engine::{Error, SnapshotRef, management::Endpoint, native};
pub use quiesce::{quiesce_inert, volume_unavailable};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    process::{Child, Command, Stdio},
    thread,
};

/// A receiver's environment: nothing inherited, so no loader or C library
/// variable reaches the host's own `zfs`.
fn clean_environment(command: &mut Command) -> &mut Command {
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
}

/// ENDPOINT is still the bound incarnation.
fn require_endpoint(endpoint: &Endpoint) -> Result<(), Error> {
    crate::engine::validate_dataset_name(&endpoint.name)?;
    let inspection = crate::engine::inspect(&crate::engine::InspectRequest::new(
        vec![endpoint.name.clone()],
        false,
    )?)?;
    if inspection
        .datasets
        .iter()
        .any(|dataset| dataset.name == endpoint.name && dataset.identity == endpoint.identity)
    {
        Ok(())
    } else {
        Err(refuse("receive destination incarnation changed"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamOutcome {
    pub sender_success: bool,
    pub receiver_success: bool,
    pub sender_status: String,
    pub receiver_status: String,
    pub sender_stderr: String,
    pub receiver_stderr: String,
    pub output_truncated: bool,
}
impl StreamOutcome {
    pub fn complete(&self) -> bool {
        self.sender_success && self.receiver_success
    }
}
/// One raw stream of one dataset into Debian's own `zfs receive`, with no
/// properties: without `-R` or `-p` libzfs passes no received property list,
/// and without `-o`/`-x` no local one, so the receive changes no property of
/// an existing dataset (`zfs_ioc_recv_impl`). A new dataset takes `create` as
/// local values before its data; its fences come from the staging container
/// it is created in, not from these setters. Never forced, never resumable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafStream {
    pub source: Endpoint,
    /// The destination's newest snapshot; `None` sends `boundary` in full.
    pub base: Option<SnapshotRef>,
    pub boundary: SnapshotRef,
    pub destination: String,
    /// `-o` values for a new dataset; empty for an existing one.
    pub create: Vec<(String, String)>,
}

pub fn leaf_arguments(stream: &LeafStream) -> Result<(Vec<String>, Vec<String>), Error> {
    crate::engine::validate_dataset_name(&stream.source.name)?;
    crate::engine::validate_dataset_name(&stream.destination)?;
    crate::engine::validate_snapshot_name(&stream.boundary.name)?;
    if crate::engine::contains_dataset(&stream.source.name, &stream.destination)
        || crate::engine::contains_dataset(&stream.destination, &stream.source.name)
    {
        return Err(refuse("stream endpoints overlap"));
    }
    let own = |point: &SnapshotRef| {
        point.name.split_once('@').map(|(name, _)| name) == Some(stream.source.name.as_str())
            && point.dataset_guid == stream.source.identity.guid
            && point.identity.pool_guid == stream.source.identity.pool_guid
    };
    if !own(&stream.boundary) {
        return Err(refuse(
            "stream boundary does not belong to the bound source",
        ));
    }
    let mut send = vec!["send".into(), "-w".into()];
    if let Some(base) = &stream.base {
        crate::engine::validate_snapshot_name(&base.name)?;
        if !own(base) || base.identity.createtxg >= stream.boundary.identity.createtxg {
            return Err(refuse("stream base is not an older point on this source"));
        }
        if !stream.create.is_empty() {
            return Err(refuse("an incremental stream creates no dataset"));
        }
        send.extend(["-I".into(), base.name.clone()]);
    }
    send.push(stream.boundary.name.clone());
    let mut receive: Vec<String> = vec!["receive".into(), "-u".into()];
    for (key, value) in &stream.create {
        let key_ok = !key.is_empty()
            && key.len() <= 255
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '.'));
        if !key_ok
            || crate::engine::management::managed_key(key)
            || matches!(
                key.as_str(),
                "mountpoint"
                    | "readonly"
                    | "volmode"
                    | "encryption"
                    | "keyformat"
                    | "keylocation"
                    | "pbkdf2iters"
                    | "volsize"
                    | "volblocksize"
            )
            || value.is_empty()
            || value.chars().any(char::is_control)
            || stream
                .create
                .iter()
                .filter(|(other, _)| other == key)
                .count()
                != 1
        {
            return Err(refuse(format!("invalid creation property {key}")));
        }
        receive.extend(["-o".into(), format!("{key}={value}")]);
    }
    receive.push(stream.destination.clone());
    Ok((send, receive))
}

/// Run one leaf stream after checking that the source and its points are
/// still the bound incarnations. Both ends are the host's own `zfs`.
pub fn leaf_replicate(stream: &LeafStream) -> Result<StreamOutcome, Error> {
    let (send, receive) = leaf_arguments(stream)?;
    let inspection = crate::engine::inspect(&crate::engine::InspectRequest::new(
        vec![stream.source.name.clone()],
        false,
    )?)?;
    if inspection
        .datasets
        .iter()
        .find(|d| d.name == stream.source.name)
        .is_none_or(|d| d.identity != stream.source.identity)
    {
        return Err(refuse("stream source incarnation changed"));
    }
    for point in stream.base.iter().chain(std::iter::once(&stream.boundary)) {
        let current = native::resolve_with(point, &mut native::run)?;
        if current.point() != *point {
            return Err(refuse("stream snapshot identity or name changed"));
        }
    }
    pipeline("zfs", &send, "zfs", &receive)
}

struct OwnedChild(Option<Child>);
impl OwnedChild {
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }
    fn wait(&mut self) -> Result<std::process::ExitStatus, Error> {
        let result = self.child().wait().map_err(|e| refuse(e.to_string()))?;
        self.0 = None;
        Ok(result)
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn drain(mut reader: impl Read + Send + 'static) -> thread::JoinHandle<(String, bool)> {
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut truncated = false;
        let mut buffer = [0; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let remaining = (64 * 1024usize).saturating_sub(output.len());
                    output.extend_from_slice(&buffer[..n.min(remaining)]);
                    truncated |= n > remaining;
                }
                Err(error) => {
                    output.extend_from_slice(
                        format!("\n[diagnostic read failed: {error}]").as_bytes(),
                    );
                    break;
                }
            }
        }
        (String::from_utf8_lossy(&output).into_owned(), truncated)
    })
}
fn join(handle: thread::JoinHandle<(String, bool)>) -> Result<(String, bool), Error> {
    handle
        .join()
        .map_err(|_| refuse("stream diagnostic reader failed"))
}
fn pipeline(
    sender_program: &str,
    send: &[String],
    receiver_program: &str,
    receive: &[String],
) -> Result<StreamOutcome, Error> {
    let mut sender_command = Command::new(sender_program);
    sender_command
        .args(send)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let sender = native::announced(&mut sender_command)
        .spawn()
        .map_err(|e| refuse(format!("native sender {e}")))?;
    let mut sender = OwnedChild(Some(sender));
    let pipe = sender.child().stdout.take().unwrap();
    let sender_stderr = drain(sender.child().stderr.take().unwrap());
    let mut receiver_command = Command::new(receiver_program);
    clean_environment(&mut receiver_command)
        .args(receive)
        .stdin(Stdio::from(pipe))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let receiver = match native::announced(&mut receiver_command).spawn() {
        Ok(child) => child,
        Err(error) => {
            drop(sender);
            let _ = join(sender_stderr);
            return Err(refuse(format!("native receiver {error}")));
        }
    };
    crate::engine::effect::mark();
    let mut receiver = OwnedChild(Some(receiver));
    let receiver_stderr = drain(receiver.child().stderr.take().unwrap());
    let receiver_status = receiver.wait()?;
    // The receive end has closed its pipe. A failed receiver cannot leave an
    // indefinitely running sender that still owns source resources.
    if !receiver_status.success() {
        let _ = sender.child().kill();
    }
    let sender_status = sender.wait()?;
    let (sender_stderr, a) = join(sender_stderr)?;
    let (receiver_stderr, b) = join(receiver_stderr)?;
    Ok(StreamOutcome {
        sender_success: sender_status.success(),
        receiver_success: receiver_status.success(),
        sender_status: sender_status.to_string(),
        receiver_status: receiver_status.to_string(),
        sender_stderr,
        receiver_stderr,
        output_truncated: a || b,
    })
}
fn refuse(detail: impl Into<String>) -> Error {
    Error::Inconsistent(detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{DatasetIdentity, Guid, ObjsetId, SnapshotIdentity, Txg};

    fn leaf() -> LeafStream {
        let identity = DatasetIdentity {
            pool_guid: Guid::new(1),
            guid: Guid::new(2),
            createtxg: Txg::new(3),
            objsetid: ObjsetId::new(4),
        };
        LeafStream {
            source: Endpoint {
                name: "a/data".into(),
                identity,
            },
            base: None,
            boundary: SnapshotRef {
                name: "a/data@two".into(),
                dataset_guid: Guid::new(2),
                identity: SnapshotIdentity {
                    pool_guid: Guid::new(1),
                    guid: Guid::new(9),
                    createtxg: Txg::new(20),
                    objsetid: ObjsetId::new(30),
                },
            },
            destination: "b/zboot-receive-x/root".into(),
            create: vec![
                ("canmount".into(), "noauto".into()),
                ("copies".into(), "2".into()),
            ],
        }
    }
    #[test]
    fn a_leaf_stream_carries_no_properties_and_is_never_forced() {
        let full = leaf();
        let (send, receive) = leaf_arguments(&full).unwrap();
        assert_eq!(send, ["send", "-w", "a/data@two"]);
        assert_eq!(
            receive,
            [
                "receive",
                "-u",
                "-o",
                "canmount=noauto",
                "-o",
                "copies=2",
                "b/zboot-receive-x/root"
            ]
        );
        for argv in [&send, &receive] {
            assert!(
                !argv
                    .iter()
                    .any(|a| matches!(a.as_str(), "-R" | "-p" | "-F" | "-s" | "-x" | "-d" | "-e"))
            );
        }
        let mut incremental = leaf();
        incremental.create.clear();
        let mut base = incremental.boundary.clone();
        base.name = "a/data@one".into();
        base.identity.createtxg = Txg::new(10);
        base.identity.guid = Guid::new(8);
        incremental.base = Some(base);
        let (send, receive) = leaf_arguments(&incremental).unwrap();
        assert_eq!(send, ["send", "-w", "-I", "a/data@one", "a/data@two"]);
        assert_eq!(receive, ["receive", "-u", "b/zboot-receive-x/root"]);
    }
    #[test]
    fn a_leaf_stream_refuses_unsafe_creation_values_and_foreign_points() {
        for bad in 0..7 {
            let mut s = leaf();
            match bad {
                0 => s.create.push(("readonly".into(), "off".into())),
                1 => s.create.push(("zboot:pair".into(), "x".into())),
                2 => s.create.push(("keylocation".into(), "file:///k".into())),
                3 => s.create.push(("copies".into(), "1".into())),
                4 => s.destination = "a/data/child".into(),
                5 => s.boundary.dataset_guid = Guid::new(99),
                _ => {
                    let mut base = s.boundary.clone();
                    base.name = "a/data@one".into();
                    base.identity.createtxg = Txg::new(10);
                    s.base = Some(base);
                }
            }
            assert!(leaf_arguments(&s).is_err(), "{bad}");
        }
    }
    #[test]
    fn owned_pipeline_requires_both_statuses() {
        let result = pipeline("/usr/bin/printf", &["payload".into()], "/usr/bin/cat", &[]).unwrap();
        assert!(result.complete());
        let result = pipeline("/usr/bin/yes", &[], "/usr/bin/false", &[]).unwrap();
        assert!(!result.complete());
        assert!(!result.receiver_success);
    }
    #[test]
    fn receiver_spawn_failure_reaps_unbounded_sender() {
        assert!(pipeline("/usr/bin/yes", &[], "/no/such/receiver", &[]).is_err());
    }
}
