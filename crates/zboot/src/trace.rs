//! Bounded, versioned handoff evidence carried across kexec in the kernel
//! command line. Only stage timings and public asset hashes enter this channel.
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, fmt::Write as _, time::Instant};

pub const KEY: &str = "zboot.trace=";
const PREFIX: &str = "v1.";
const MAX_EVENTS: usize = 64;
const FIXED_BYTES: usize = 67;
const EVENT_BYTES: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Stage {
    // Each value is the stage's byte in the v1 wire; 2, 4 and 5 are unassigned.
    ImportReadonly = 1,
    MountReadonly = 3,
    Unmount = 6,
    Export = 7,
    #[serde(rename = "stage_assets")]
    Assets = 8,
    LoadKernel = 9,
    ExecuteKernel = 10,
    ListBootEnvironments = 11,
}
impl Stage {
    fn decode(byte: u8) -> Result<Self, String> {
        Ok(match byte {
            1 => Self::ImportReadonly,
            3 => Self::MountReadonly,
            6 => Self::Unmount,
            7 => Self::Export,
            8 => Self::Assets,
            9 => Self::LoadKernel,
            10 => Self::ExecuteKernel,
            11 => Self::ListBootEnvironments,
            _ => return Err("unsupported handoff trace stage".into()),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub stage: Stage,
    pub complete: bool,
    pub elapsed_ms: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    pub schema_version: u32,
    pub kernel_sha256: Option<String>,
    pub initrd_sha256: Option<String>,
    pub omitted_events: u8,
    pub events: Vec<Event>,
}
use zfs_tools::engine::attachment::hex;
fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid canonical trace hex".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| {
            let digit = |v: u8| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
            Ok(digit(b[0]) * 16 + digit(b[1]))
        })
        .collect()
}
impl Trace {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.events.len() > MAX_EVENTS
            || self.kernel_sha256.is_some() != self.initrd_sha256.is_some()
            || self
                .events
                .windows(2)
                .any(|e| e[0].elapsed_ms > e[1].elapsed_ms)
        {
            return Err("invalid handoff trace shape or chronology".into());
        }
        for digest in [&self.kernel_sha256, &self.initrd_sha256]
            .into_iter()
            .flatten()
        {
            if digest.len() != 64 {
                return Err("invalid trace asset digest".into());
            }
            unhex(digest)?;
        }
        Ok(())
    }
    pub fn token(&self, budget: usize) -> Result<Option<String>, String> {
        self.validate()?;
        let bytes_budget = budget.saturating_sub(PREFIX.len()) / 2;
        if bytes_budget < FIXED_BYTES + EVENT_BYTES || self.events.is_empty() {
            return Ok(None);
        }
        let retained = self
            .events
            .len()
            .min((bytes_budget - FIXED_BYTES) / EVENT_BYTES);
        let removed = self.events.len() - retained;
        let mut bytes = vec![
            retained as u8,
            self.omitted_events.saturating_add(removed as u8),
            u8::from(self.kernel_sha256.is_some()),
        ];
        for digest in [&self.kernel_sha256, &self.initrd_sha256] {
            bytes.extend(if let Some(value) = digest {
                unhex(value)?
            } else {
                vec![0; 32]
            });
        }
        for event in &self.events[removed..] {
            bytes.extend([event.stage as u8, u8::from(event.complete)]);
            bytes.extend(event.elapsed_ms.to_be_bytes());
        }
        Ok(Some(format!("{PREFIX}{}", hex(&bytes))))
    }
    pub fn from_cmdline(cmdline: &str) -> Result<Option<Self>, String> {
        let values: Vec<_> = cmdline
            .split_ascii_whitespace()
            .filter_map(|w| w.strip_prefix(KEY))
            .collect();
        if values.is_empty() {
            return Ok(None);
        }
        if values.len() != 1 {
            return Err("duplicate handoff trace arguments".into());
        }
        let token = values[0]
            .strip_prefix(PREFIX)
            .ok_or("unsupported handoff trace version")?;
        if token.len() > 2 * (FIXED_BYTES + EVENT_BYTES * MAX_EVENTS) {
            return Err("handoff trace exceeds supported bound".into());
        }
        let bytes = unhex(token)?;
        if bytes.len() < FIXED_BYTES
            || bytes[0] == 0
            || bytes[0] as usize > MAX_EVENTS
            || bytes.len() != FIXED_BYTES + EVENT_BYTES * bytes[0] as usize
            || bytes[2] > 1
        {
            return Err("invalid handoff trace wire shape".into());
        }
        if bytes[2] == 0 && bytes[3..67].iter().any(|b| *b != 0) {
            return Err("unexpected absent trace hashes".into());
        }
        let mut events = Vec::new();
        for event in bytes[FIXED_BYTES..].as_chunks::<EVENT_BYTES>().0 {
            if event[1] > 1 {
                return Err("invalid handoff trace completion flag".into());
            }
            events.push(Event {
                stage: Stage::decode(event[0])?,
                complete: event[1] == 1,
                elapsed_ms: u32::from_be_bytes(event[2..6].try_into().unwrap()),
            });
        }
        let trace = Self {
            schema_version: 1,
            kernel_sha256: (bytes[2] == 1).then(|| hex(&bytes[3..35])),
            initrd_sha256: (bytes[2] == 1).then(|| hex(&bytes[35..67])),
            omitted_events: bytes[1],
            events,
        };
        trace.validate()?;
        Ok(Some(trace))
    }
    pub fn attach(&self, cmdline: &str) -> Result<String, String> {
        if cmdline.split_ascii_whitespace().any(|w| w.starts_with(KEY)) {
            return Err("handoff command line already has a trace".into());
        }
        let budget = 2047usize.saturating_sub(cmdline.len() + 1 + KEY.len());
        Ok(match self.token(budget)? {
            Some(token) => format!("{cmdline} {KEY}{token}"),
            None => cmdline.into(),
        })
    }
    pub fn render(&self) -> String {
        let mut out = String::new();
        if let Some(digest) = &self.kernel_sha256 {
            let _ = writeln!(out, "Kernel SHA256: {digest}");
        }
        if let Some(digest) = &self.initrd_sha256 {
            let _ = writeln!(out, "Initrd SHA256: {digest}");
        }
        if self.omitted_events > 0 {
            let _ = writeln!(
                out,
                "{} earlier events omitted to fit the command line.",
                self.omitted_events
            );
        }
        for event in &self.events {
            let _ = writeln!(
                out,
                "+{:>8.3}s {:?} {}",
                event.elapsed_ms as f64 / 1000.0,
                event.stage,
                if event.complete { "complete" } else { "begin" }
            );
        }
        out.push_str("Carried trace ends at kernel loading; later export and execution are not recorded here.\n");
        out
    }
}
pub(crate) struct Recorder {
    start: Instant,
    elapsed_offset_ms: u32,
    events: VecDeque<Event>,
    omitted: u8,
    hashes: Option<(String, String)>,
}
impl Recorder {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            elapsed_offset_ms: 0,
            events: VecDeque::new(),
            omitted: 0,
            hashes: None,
        }
    }
    /// Seed a fresh recorder with completed listing work, then time handoff
    /// work from a new instant. Elapsed values accumulate active stages only;
    /// the interval spent waiting for a menu choice is deliberately absent.
    pub fn with_listing(mut self, elapsed_ms: u32) -> Self {
        self.start = Instant::now();
        self.elapsed_offset_ms = elapsed_ms;
        self.events = VecDeque::from([
            Event {
                stage: Stage::ListBootEnvironments,
                complete: false,
                elapsed_ms: 0,
            },
            Event {
                stage: Stage::ListBootEnvironments,
                complete: true,
                elapsed_ms,
            },
        ]);
        self.omitted = 0;
        self
    }

    pub fn mark(&mut self, stage: Stage, complete: bool) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
            self.omitted = self.omitted.saturating_add(1);
        }
        self.events.push_back(Event {
            stage,
            complete,
            elapsed_ms: self
                .elapsed_offset_ms
                .saturating_add(self.start.elapsed().as_millis().min(u32::MAX as u128) as u32),
        });
    }
    pub fn assets(&mut self, kernel: &str, initrd: &str) {
        self.hashes = Some((kernel.into(), initrd.into()));
    }
    pub fn snapshot(&self) -> Trace {
        Trace {
            schema_version: 1,
            kernel_sha256: self.hashes.as_ref().map(|h| h.0.clone()),
            initrd_sha256: self.hashes.as_ref().map(|h| h.1.clone()),
            omitted_events: self.omitted,
            events: self.events.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Trace {
        Trace {
            schema_version: 1,
            kernel_sha256: Some("ab".repeat(32)),
            initrd_sha256: Some("cd".repeat(32)),
            omitted_events: 0,
            events: (0..64)
                .map(|i| Event {
                    stage: Stage::Assets,
                    complete: i % 2 == 1,
                    elapsed_ms: i * 100,
                })
                .collect(),
        }
    }
    #[test]
    fn listing_stage_roundtrips_and_offsets_later_active_work() {
        let mut recorder = Recorder::new().with_listing(275);
        assert_eq!(
            recorder.snapshot().events,
            [
                Event {
                    stage: Stage::ListBootEnvironments,
                    complete: false,
                    elapsed_ms: 0
                },
                Event {
                    stage: Stage::ListBootEnvironments,
                    complete: true,
                    elapsed_ms: 275
                },
            ]
        );
        recorder.mark(Stage::MountReadonly, false);
        recorder.mark(Stage::MountReadonly, true);
        let trace = recorder.snapshot();
        assert!(
            trace.events[2..]
                .iter()
                .all(|event| event.elapsed_ms >= 275)
        );
        assert!(
            trace
                .events
                .windows(2)
                .all(|events| events[0].elapsed_ms <= events[1].elapsed_ms)
        );
        let cmdline = trace.attach("root=ZFS=tank/BE/linux ro").unwrap();
        assert_eq!(Trace::from_cmdline(&cmdline).unwrap(), Some(trace));
        let bytes = unhex(cmdline.split(PREFIX).nth(1).unwrap()).unwrap();
        assert_eq!(bytes[FIXED_BYTES], 11);

        let mut saturated = Recorder::new().with_listing(u32::MAX);
        saturated.mark(Stage::Assets, true);
        let trace = saturated.snapshot();
        assert_eq!(trace.events[2].elapsed_ms, u32::MAX);
        trace.validate().unwrap();
    }

    #[test]
    fn a_bare_v1_import_stage_decodes_and_new_recorders_start_without_an_offset() {
        // A v1 wire: one completed stage 1 import at 12ms, no hashes.
        let mut bytes = vec![1, 0, 0];
        bytes.extend([0; 64]);
        bytes.extend([1, 1]);
        bytes.extend(12u32.to_be_bytes());
        let trace = Trace::from_cmdline(&format!("{KEY}{PREFIX}{}", hex(&bytes)))
            .unwrap()
            .unwrap();
        assert_eq!(
            trace.events,
            [Event {
                stage: Stage::ImportReadonly,
                complete: true,
                elapsed_ms: 12
            }]
        );
        let recorder = Recorder::new();
        assert_eq!(recorder.elapsed_offset_ms, 0);
        assert!(recorder.snapshot().events.is_empty());
    }

    #[test]
    fn real_cmdline_roundtrip_and_compaction_preserve_latest_chronology() {
        let trace = fixture();
        let cmd = trace.attach("root=ZFS=tank/BE/linux ro").unwrap();
        assert_eq!(Trace::from_cmdline(&cmd).unwrap(), Some(trace.clone()));
        let token = trace
            .token(PREFIX.len() + 2 * (FIXED_BYTES + 3 * EVENT_BYTES))
            .unwrap()
            .unwrap();
        let restored = Trace::from_cmdline(&format!("{KEY}{token}"))
            .unwrap()
            .unwrap();
        assert_eq!(restored.events, trace.events[61..]);
        assert_eq!(restored.omitted_events, 61);
        assert_eq!(trace.attach(&"x".repeat(2000)).unwrap(), "x".repeat(2000));
    }
    #[test]
    fn unknown_truncated_duplicate_and_excessive_payloads_refuse() {
        let token = fixture().token(1500).unwrap().unwrap();
        for value in [
            format!("{KEY}v2.00"),
            format!("{KEY}{token} {KEY}{token}"),
            format!("{KEY}{}", &token[..token.len() - 2]),
            format!("{KEY}v1.{}", "00".repeat(1000)),
            format!("{KEY}v1.gg"),
        ] {
            assert!(Trace::from_cmdline(&value).is_err());
        }
        assert!(
            Trace::from_cmdline("root=ZFS=tank/root ro")
                .unwrap()
                .is_none()
        );
        let mut bad = fixture();
        bad.events[1].elapsed_ms = u32::MAX;
        assert!(bad.token(1500).is_err());
        assert!(fixture().attach(&format!("{KEY}{token}")).is_err());
    }
}
