//! Shared native ZFS observations, operations and safety checks.
//! Application crates own workflows and user interfaces. Shared admission binds
//! dataset and snapshot identities and recognizes boot/pair metadata so every
//! writer respects the same guards. Callers coordinate multi-step writes through
//! the host writer lock; sequential native observations are not atomic.
pub mod attachment;
pub(crate) mod bounded;
pub mod capture;
pub mod delete;
pub(crate) mod dispatch;
pub mod effect;
pub mod hold;
pub mod intent;
pub mod lock;
pub mod management;
pub mod mountinfo;
pub mod mutation;
pub mod native;
pub mod operation;
pub(crate) mod protection;
pub mod state;
pub mod stream;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Validate a dataset selector before passing it as a native argv operand.
/// Spaces are preserved; snapshots, bookmarks and option-like components are not accepted.
pub fn validate_dataset_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '@' | '#'))
        || name
            .split('/')
            .any(|part| part.is_empty() || part.starts_with('-') || matches!(part, "." | ".."))
    {
        return Err(Error::InvalidScope(name.into()));
    }
    Ok(())
}

/// Validate a pool name before passing it as a native argv operand.
pub fn validate_pool_name(name: &str) -> Result<(), Error> {
    validate_dataset_name(name)?;
    if name.contains('/') {
        return Err(Error::InvalidScope(name.into()));
    }
    Ok(())
}

/// Whether `value` is a lowercase hyphenated canonical RFC 4122 UUID v4.
pub fn is_canonical_uuid_v4(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| {
        id.to_string() == value
            && id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
    })
}

/// Whether dataset NAME is ROOT or lies below it.
pub fn contains_dataset(root: &str, name: &str) -> bool {
    name == root
        || name
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}

/// The pool that holds `dataset`: its first path component.
pub fn pool_of(dataset: &str) -> &str {
    dataset.split('/').next().unwrap_or(dataset)
}

/// The external origin that destroying `dataset`, a member of the tree at
/// `root`, would destroy with it: a snapshot outside that tree marked for
/// deferred destruction whose only clone is `dataset`. OpenZFS completes a
/// deferred destroy when the last clone goes, so `zboot drop` and the
/// library's guarded destroy both refuse such a dataset.
pub fn deferred_origin<'a>(
    dataset: &'a Dataset,
    root: &str,
    snapshots: &[Snapshot],
) -> Option<&'a str> {
    let origin = dataset.origin.as_deref()?;
    let parent = origin.split('@').next().unwrap_or_default();
    (!contains_dataset(root, parent)
        && snapshots
            .iter()
            .find(|s| s.name == origin)
            .is_some_and(|s| s.defer_destroy && s.clones.len() == 1))
    .then_some(origin)
}

/// Escape terminal controls and Unicode direction controls without losing data.
pub fn escape_display(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_control()
            || matches!(
                c,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
        {
            out.extend(c.escape_unicode());
        } else if c == '\\' {
            out.push_str("\\\\");
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectRequest {
    datasets: Vec<String>,
    snapshots: bool,
}
impl InspectRequest {
    pub fn new(datasets: Vec<String>, snapshots: bool) -> Result<Self, Error> {
        for dataset in &datasets {
            validate_dataset_name(dataset)?;
        }
        let mut unique = datasets;
        unique.sort();
        unique.dedup();
        Ok(Self {
            datasets: unique,
            snapshots,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetKind {
    Filesystem,
    Volume,
}

macro_rules! observation {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
        pub struct $name { $(pub $field: $ty),* }
    }
}
observation!(Pool {
    name: String,
    guid: Guid,
    size_bytes: u64,
    allocated_bytes: u64,
    free_bytes: u64,
    health: String,
    bootfs: Option<String>
});
/// Native local dataset incarnation; send/receive reconstruction changes this identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetIdentity {
    pub pool_guid: Guid,
    pub guid: Guid,
    pub createtxg: Txg,
    pub objsetid: ObjsetId,
}
impl DatasetIdentity {
    pub(crate) fn is_complete(&self) -> bool {
        self.pool_guid.get() != 0
            && self.guid.get() != 0
            && self.createtxg.get() != 0
            && self.objsetid.get() != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanMount {
    On,
    Off,
    NoAuto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encryption {
    Off,
    Aes128Ccm,
    Aes192Ccm,
    Aes256Ccm,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Unencrypted,
    Available,
    Unavailable,
}

observation!(Dataset {
    name: String, kind: DatasetKind, guid: Guid, identity: DatasetIdentity,
    used_bytes: u64, available_bytes: u64, referenced_bytes: u64,
    mountpoint: Option<String>, volume_size_bytes: Option<u64>,
    mounted: Option<bool>, readonly: bool, canmount: Option<CanMount>,
    origin: Option<String>, encryption: Encryption, keystatus: KeyStatus,
    encryptionroot: Option<String>,
    staging: Option<String>, pending: Option<String>
});
observation!(Snapshot {
    name: String,
    guid: Guid,
    dataset_guid: Guid,
    identity: SnapshotIdentity,
    userrefs: u64,
    defer_destroy: bool,
    clones: Vec<String>,
    holds: Vec<String>,
    creation_epoch_seconds: i64,
    used_bytes: u64,
    referenced_bytes: u64
});
observation!(Inspection {
    schema_version: u32,
    imported_only: bool,
    non_atomic: bool,
    recursive: bool,
    requested_datasets: Vec<String>,
    pools: Vec<Pool>,
    datasets: Vec<Dataset>,
    snapshots: Option<Vec<Snapshot>>,
});

impl Inspection {
    /// Select a presentation scope from an already complete native observation.
    /// This cannot turn a partial inventory into complete mutation evidence.
    pub fn select(&self, request: &InspectRequest) -> Result<Self, Error> {
        if !self.requested_datasets.is_empty() {
            return Err(Error::Inconsistent(
                "selection requires complete imported inventory".into(),
            ));
        }
        for name in &request.datasets {
            if !self.datasets.iter().any(|d| &d.name == name) {
                return Err(Error::MissingScope(name.clone()));
            }
        }
        let selected = |name: &str| {
            request.datasets.is_empty()
                || request
                    .datasets
                    .iter()
                    .any(|root| contains_dataset(root, name))
        };
        let mut result = self.clone();
        result.requested_datasets = request.datasets.clone();
        result.datasets.retain(|d| selected(&d.name));
        result.pools.retain(|p| {
            result
                .datasets
                .iter()
                .any(|d| d.identity.pool_guid == p.guid)
        });
        if request.snapshots {
            if self.snapshots.is_none() {
                return Err(Error::Inconsistent(
                    "snapshot history was not observed".into(),
                ));
            }
            result.snapshots.as_mut().unwrap().retain(|s| {
                s.name
                    .split_once('@')
                    .is_some_and(|(name, _)| selected(name))
            });
        } else {
            result.snapshots = None;
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidScope(String),
    Command {
        program: &'static str,
        args: Vec<String>,
        detail: String,
    },
    Parse {
        subject: &'static str,
        detail: String,
    },
    MissingScope(String),
    NotFound(String),
    Inconsistent(String),
    /// An application's own refusal, shown as its message alone.
    Refused(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidScope(name) => format!("invalid dataset selector: {name}"),
            Self::Command {
                program, detail, ..
            } => format!("{program} query failed: {detail}"),
            Self::Parse { subject, detail } => format!("invalid {subject} query output: {detail}"),
            Self::NotFound(name) => format!("snapshot was not observed: {name}"),
            Self::MissingScope(name) => format!("requested dataset was not observed: {name}"),
            Self::Inconsistent(detail) => format!("inconsistent ZFS observation: {detail}"),
            Self::Refused(detail) => detail.clone(),
        };
        f.write_str(&escape_display(&message))
    }
}
impl std::error::Error for Error {}

/// Inspect already-imported pools and datasets using native read-only commands.
/// Empty imported inventory succeeds only for an unscoped request. Snapshot
/// history is `None` when not requested and `Some([])` when observed empty.
pub fn inspect(request: &InspectRequest) -> Result<Inspection, Error> {
    native::inspect_with(request, native::run)
}

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);
        impl $name {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }
            pub const fn get(self) -> u64 {
                self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0.to_string())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                if value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(serde::de::Error::custom(
                        "expected canonical decimal identifier string",
                    ));
                }
                value
                    .parse::<u64>()
                    .map(Self)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
identifier!(Guid);
identifier!(Txg);
identifier!(ObjsetId);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIdentity {
    pub pool_guid: Guid,
    pub guid: Guid,
    pub createtxg: Txg,
    pub objsetid: ObjsetId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRef {
    pub name: String,
    pub dataset_guid: Guid,
    pub identity: SnapshotIdentity,
}
impl SnapshotRef {
    pub(crate) fn is_complete(&self) -> bool {
        self.dataset_guid.get() != 0
            && self.identity.pool_guid.get() != 0
            && self.identity.guid.get() != 0
            && self.identity.createtxg.get() != 0
            && self.identity.objsetid.get() != 0
    }
}
impl Snapshot {
    pub fn point(&self) -> SnapshotRef {
        SnapshotRef {
            name: self.name.clone(),
            dataset_guid: self.dataset_guid,
            identity: self.identity.clone(),
        }
    }
}
pub fn validate_snapshot_name(name: &str) -> Result<(), Error> {
    let (dataset, suffix) = name
        .split_once('@')
        .ok_or_else(|| Error::InvalidScope(name.into()))?;
    validate_dataset_name(dataset)?;
    if suffix.is_empty()
        || suffix.starts_with('-')
        || suffix.contains(['@', '#', '/'])
        || suffix.chars().any(char::is_control)
    {
        return Err(Error::InvalidScope(name.into()));
    }
    Ok(())
}
/// Observe one current snapshot. A failed native query is never reported as absence.
pub fn observe_snapshot(name: &str) -> Result<Snapshot, Error> {
    native::observe_with(name, &mut native::run)
}

/// An explicitly queried encrypted snapshot IV-set identity. This observation
/// alone does not establish topology, cipher, or complete raw-receive admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotIvset {
    pub point: SnapshotRef,
    pub ivset_guid: Guid,
}

/// Referenced space newly written since an exact snapshot. This is a native
/// accounting metric, not proof of an unchanged head or writer quiescence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrittenSince {
    pub dataset_name: String,
    pub dataset_identity: DatasetIdentity,
    pub base: SnapshotRef,
    pub referenced_new_bytes: u64,
}

/// Opt into the backend's hidden `ivsetguid` property. Unsupported, missing or
/// zero observations refuse; ordinary inventory does not require this capability.
pub fn observe_snapshot_ivset(point: &SnapshotRef) -> Result<SnapshotIvset, Error> {
    native::observe_ivset_with(point, native::run)
}

pub fn observe_written_since(dataset: &Dataset, base: &SnapshotRef) -> Result<WrittenSince, Error> {
    native::observe_written_since_with(dataset, base, native::run)
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn a_refusal_shows_its_message_alone_and_an_inconsistency_names_itself() {
        assert_eq!(
            Error::Refused("selected disk is in use".into()).to_string(),
            "selected disk is in use"
        );
        assert_eq!(
            Error::Inconsistent("lost reply".into()).to_string(),
            "inconsistent ZFS observation: lost reply"
        );
    }
}
