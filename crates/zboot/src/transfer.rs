//! Directional, snapshot-bound replication. Source heads may keep changing;
//! receiver mutation is fenced and preceded by durable, identity-bound intent.
//! An interrupted native stream is never repaired using force or destruction.
//!
//! A transfer runs inside its caller's operation and keeps its progress in
//! that operation's intent record ([`Record`]), a bootstrap's nested pair
//! phases included. The frozen plan, too large for the record, is a
//! write-once [attachment] on the record's holder, a leaf of the transfer on
//! the record's own pool; a bootstrap's nested pair plan is a second one.
//! The record names each from the advance that commits it until `Released`
//! or `Abandoned`, and only then are its chunks removed.
use crate::{
    history::{self, Side},
    observation::{self, HistoryBackend},
    pairs::plan::{self, PairBackend},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zfs_tools::engine::{
    DatasetIdentity, Error, Guid, ObjsetId, SnapshotRef, Txg,
    attachment::{self, Attachment, AttachmentBackend, Key, NativeAttachment},
    capture::{self, CaptureBackend, CaptureRequest},
    intent,
    management::{self, Endpoint, MountMode, Ownership, PairRecord, Placement, Role},
    mutation::{PropertyKey, PropertyValue},
    native::NativeProperty,
    pool_of,
    state::NativeState,
    stream::{self, LeafStream, StreamOutcome},
};
mod boot_policy;
pub(crate) mod props;
mod receive;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    pub source: String,
    pub destination: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub bound: plan::Member,
    pub kind: history::Kind,
    pub mounted: bool,
    pub encryption: history::Encryption,
    pub encryption_root: Option<String>,
    pub properties: BTreeMap<String, String>,
    /// The copied keys this dataset sets (local or received); their digests
    /// are in `properties`. A copy holds each of them local.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub local: BTreeSet<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub endpoint: Endpoint,
    pub members: BTreeMap<String, Member>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Destination {
    Existing { tree: Tree },
    Absent { name: String, parent: Endpoint },
}
impl Destination {
    fn name(&self) -> &str {
        match self {
            Self::Existing { tree } => &tree.endpoint.name,
            Self::Absent { name, .. } => name,
        }
    }
    fn existing(&self) -> Option<&Tree> {
        match self {
            Self::Existing { tree } => Some(tree),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferPlan {
    pub schema_version: u32,
    pub source: Tree,
    pub destination: Destination,
    pub boundary: SnapshotRef,
    pub base: Option<SnapshotRef>,
    pub source_pair: Option<PairRecord>,
    pub bootstrap_pair_id: Option<String>,
}
/// A transfer's phases, in order. Each is recorded once the effects before
/// it were verified from native state. `Released` and `Abandoned` are ends:
/// the record names no attachment from them on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The plan attachment is named: the commit.
    Prepared,
    Protected,
    Fenced,
    /// The copy is verified and adopted; a bootstrap names its pair plan.
    Received,
    Activating,
    /// Activated and its receive retired; holds and markers go next.
    Complete,
    /// Complete with nothing left to read: the attachments are removed.
    Released,
    /// Abandoned before Received: the attachments are removed.
    Abandoned,
}
/// What a transfer's caller records for it, in its intent record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProgress {
    pub phase: Phase,
    /// The frozen plan and receive session, named while the phase is
    /// before `Released`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<Attachment>,
    /// A bootstrap's nested pair plan, named from `Received` to `Released`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair: Option<Attachment>,
    /// The last phase a bootstrap's nested pair recorded, from `Activating`
    /// to `Released`. From its `Prepared` on, the pair's pending markers on
    /// either leaf are this transfer's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_phase: Option<plan::Phase>,
    #[serde(default)]
    pub receive: receive::Receive,
    /// The adopted copy, from `Received`; at `Released` only so that its
    /// staging marker can be removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<Received>,
    /// At `Abandoned`, the partial new copy, or its receive container, that
    /// the abandon left fenced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<Endpoint>,
}
impl TransferProgress {
    /// An end, which names nothing.
    fn ended(phase: Phase) -> Self {
        Self {
            phase,
            plan: None,
            pair: None,
            pair_phase: None,
            receive: receive::Receive::default(),
            received: None,
            left: None,
        }
    }
}
/// The copy a transfer adopted: its root and the name-free identity digest
/// of the tree it received ([`identity_digest`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Received {
    pub endpoint: Endpoint,
    pub digest: String,
}
/// The payload of the `plan` attachment, frozen at the commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frozen {
    plan: TransferPlan,
    receive: receive::Session,
}
const PLAN: &str = "plan";
const PAIR: &str = "pair";

/// The intent record of the operation a transfer runs in, which holds the
/// transfer's progress. Its holder is a leaf of the transfer on the record's
/// own pool, so the record write naming an attachment there needs no `zpool
/// sync` first: a `zfs set` returns once its transaction group is on disk,
/// and a pool commits them in order.
pub(crate) trait Record {
    /// The operation's id, which is also the transfer's.
    fn id(&self) -> &str;
    /// The pool whose root holds the record.
    fn pool(&self) -> &str;
    /// Where the transfer's attachments go.
    fn holder(&self) -> &Endpoint;
    fn transfer(&self) -> Option<&TransferProgress>;
    /// One record write replacing the transfer's progress, the operation's
    /// own step unchanged; a lost reply is judged by reading back.
    fn advance(
        &mut self,
        backend: &mut impl intent::Backend,
        transfer: TransferProgress,
    ) -> Result<(), Error>;
}

/// A transfer as its engine works on it: the payloads its record names, read
/// back, and the progress the record holds. `received` is the copy as last
/// verified from native state; it is never recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransferOperation {
    pub plan: TransferPlan,
    pub receive: receive::Session,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_plan: Option<plan::PairPlan>,
    pub progress: TransferProgress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received: Option<Tree>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Complete,
    AlreadyComplete,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransferOutcome {
    pub operation_id: String,
    pub source: Endpoint,
    pub destination: Option<Endpoint>,
    pub status: TransferStatus,
    pub pair_id: Option<String>,
    /// Result evidence only: the operation as it completed.
    pub completed_operation: Option<TransferOperation>,
    /// The fresh capture performed by this invocation, if one was necessary.
    pub capture: Option<TransferCapture>,
    /// Child datasets under either leaf. A pair joins leaves: these were not
    /// copied, and `sync --all` reports them as unfinished.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unmirrored: Vec<String>,
    /// Space limits the copy does not hold as the source sets them when the
    /// transfer ends (`props::unheld_space`): one it could not take keeps its
    /// own value. Never a reason to fail the sync.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unapplied: Vec<String>,
}

/// How an encryption root's key is wrapped. Two roots whose wrapping is equal
/// open each other's raw-received datasets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapping {
    pub keyformat: String,
    pub keylocation: String,
    pub pbkdf2iters: String,
    pub pbkdf2salt: String,
}

/// Datasets below either leaf of a transfer, which no stream copies.
pub fn unmirrored(state: &NativeState, source: &str, destination: &str) -> Vec<String> {
    state
        .inspection
        .datasets
        .iter()
        .filter(|d| {
            [source, destination]
                .iter()
                .any(|root| history::contains_dataset(root, &d.name) && d.name != *root)
        })
        .map(|d| d.name.clone())
        .collect()
}

/// An exact successful capture performed by this transfer invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferCapture {
    pub operation_id: String,
    pub points: Vec<SnapshotRef>,
}

/// Every effect is typed and runs beneath the same caller-owned writer guard.
pub trait TransferBackend: PairBackend + CaptureBackend + intent::Backend {
    /// The identity-bound chunk properties of this transfer's attachments.
    fn attachments(&mut self) -> impl AttachmentBackend;
    /// Set one copied property on TARGET local (`Some`) or inherit it
    /// (`None`). TARGET carries this operation's ownership markers.
    fn copy_property(
        &mut self,
        target: &Endpoint,
        key: &str,
        value: Option<&str>,
        operation_id: &str,
    ) -> Result<(), Error>;
    fn create_inert_container(
        &mut self,
        _parent: &Endpoint,
        _name: &str,
        _id: &str,
    ) -> Result<(), Error> {
        Err(refuse("backend cannot create an inert receive container"))
    }
    fn rename_received(
        &mut self,
        _source: &Endpoint,
        _parent: &Endpoint,
        _destination: &str,
    ) -> Result<(), Error> {
        Err(refuse("backend cannot rename an identity-bound receive"))
    }
    /// Give a new copy, still read-only and `canmount=noauto`, the
    /// mountpoint SAVED names, as a local value or inherited, and read it back.
    fn publish_mountpoint(
        &mut self,
        _endpoint: &Endpoint,
        _saved: &crate::placement::SavedProperty,
    ) -> Result<(), Error> {
        Err(refuse("backend cannot publish a receive mountpoint"))
    }
    fn quiesce_receive_scope(&mut self, _endpoint: &Endpoint, _id: &str) -> Result<(), Error> {
        Err(refuse("backend cannot prove receive device quiescence"))
    }
    fn volume_unavailable(&mut self, _endpoint: &Endpoint) -> Result<bool, Error> {
        Err(refuse("backend cannot verify volume device removal"))
    }
    fn destroy_empty_container(&mut self, _endpoint: &Endpoint, _id: &str) -> Result<(), Error> {
        Err(refuse("backend cannot retire an empty receive container"))
    }
    /// One property-free raw stream into the host's own `zfs receive`.
    fn stream(&mut self, stream: &LeafStream) -> Result<StreamOutcome, Error>;
    /// How ROOT's key is wrapped, read natively.
    fn wrapping(&mut self, root: &Endpoint) -> Result<Wrapping, Error>;
    /// `zfs load-key -n -L LOCATION ROOT` succeeds: the key at LOCATION opens
    /// ROOT. Loads nothing.
    fn key_opens(&mut self, root: &Endpoint, location: &str) -> Result<bool, Error>;
    /// Set a new copy's `keylocation` to its source root's.
    fn set_keylocation(&mut self, target: &Endpoint, location: &str, id: &str)
    -> Result<(), Error>;
    fn release_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error>;
    fn mount(&mut self, endpoint: &Endpoint) -> Result<(), Error>;
    /// Rename the snapshot POINT, re-observed as exactly that incarnation, to
    /// `DATASET@NAME` (NAME is the bare snapshot name). Its GUID, holds and
    /// data stay; the new name must read back with the same identity.
    fn rename_snapshot(&mut self, point: &SnapshotRef, name: &str) -> Result<(), Error>;
    /// Destroy exactly POINT, re-observed by name and identity first. Never
    /// recursive or deferred; refused while it is held, has a clone or is
    /// marked for deferred destruction. Done once its name no longer resolves.
    fn destroy_snapshot(&mut self, point: &SnapshotRef) -> Result<(), Error>;
}
#[derive(Default)]
pub struct NativeTransfer {}
impl NativeTransfer {
    pub fn new() -> Self {
        Self {}
    }
    /// Native mountpoints read back as they are set only on a pool imported
    /// without an altroot; the observation must include the pool's altroot.
    fn without_altroot(&mut self, ep: &Endpoint) -> Result<(), Error> {
        let state = PairBackend::observe(self)?;
        if endpoint(&state, &ep.name)? != *ep {
            return Err(refuse("receive placement endpoint changed"));
        }
        let pool = pool_of(&ep.name);
        if state
            .pool_properties
            .get(pool)
            .is_none_or(|p| !p.contains_key("altroot"))
        {
            return Err(refuse("receive placement omitted pool altroot evidence"));
        }
        refuse_altroot(&state, &ep.name)
    }
    fn set_mountpoint(&mut self, ep: &Endpoint, value: &PropertyValue) -> Result<(), Error> {
        let encoded = value.encode(ep)?;
        self.without_altroot(ep)?;
        self.properties(ep)?;
        let result = zfs_tools::engine::native::run_mutating(
            "zfs",
            &[
                "set".into(),
                "-u".into(),
                format!("mountpoint={encoded}"),
                ep.name.clone(),
            ],
        );
        let properties = self.properties(ep)?;
        self.without_altroot(ep)?;
        if properties
            .get("mountpoint")
            .is_some_and(|p| p.source == "local" && p.value == encoded)
        {
            Ok(())
        } else {
            Err(result
                .err()
                .unwrap_or_else(|| refuse("persistent mountpoint publication was not verified")))
        }
    }
}
impl HistoryBackend for NativeTransfer {
    fn written(
        &mut self,
        dataset: &zfs_tools::engine::Dataset,
        point: &SnapshotRef,
    ) -> Result<u64, Error> {
        plan::NativePair::new().written(dataset, point)
    }
    fn ivset(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Guid, Error> {
        plan::NativePair::new().ivset(point)
    }
}
impl PairBackend for NativeTransfer {
    fn observe(&mut self) -> Result<NativeState, Error> {
        plan::NativePair::new().observe()
    }
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<BTreeMap<String, NativeProperty>, Error> {
        plan::NativePair::new().properties(endpoint)
    }
    fn sync(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        plan::NativePair::new().sync(endpoint)
    }
    fn set_property(&mut self, endpoint: &Endpoint, value: &PropertyValue) -> Result<(), Error> {
        if matches!(value, PropertyValue::Mountpoint(_)) {
            self.set_mountpoint(endpoint, value)
        } else {
            plan::NativePair::new().set_property(endpoint, value)
        }
    }
    fn inherit_property(
        &mut self,
        endpoint: &Endpoint,
        key: PropertyKey,
        expected: &str,
    ) -> Result<Option<NativeProperty>, Error> {
        plan::NativePair::new().inherit_property(endpoint, key, expected)
    }
    fn observe_point(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Snapshot, Error> {
        plan::NativePair::new().observe_point(point)
    }
    fn unmount(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        plan::NativePair::new().unmount(endpoint)
    }
    fn add_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
        plan::NativePair::new().add_hold(point, tag)
    }
    fn running_root(&mut self) -> Result<Option<String>, Error> {
        plan::NativePair::new().running_root()
    }
}
impl CaptureBackend for NativeTransfer {
    fn observe(&mut self) -> Result<NativeState, Error> {
        PairBackend::observe(self)
    }
    fn snapshot(&mut self, names: &[String], operation_id: &str) -> Result<(), Error> {
        capture::NativeCapture.snapshot(names, operation_id)
    }
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error> {
        capture::NativeCapture.capture_marker(point)
    }
}
impl TransferBackend for NativeTransfer {
    fn attachments(&mut self) -> impl AttachmentBackend {
        NativeAttachment
    }
    fn create_inert_container(
        &mut self,
        parent: &Endpoint,
        name: &str,
        id: &str,
    ) -> Result<(), Error> {
        valid_id(id)?;
        zfs_tools::engine::validate_dataset_name(name)?;
        let state = PairBackend::observe(self)?;
        if endpoint(&state, &parent.name)? != *parent
            || name.rsplit_once('/').map(|p| p.0) != Some(parent.name.as_str())
            || state.inspection.datasets.iter().any(|d| d.name == name)
        {
            return Err(refuse("receive container parent or empty name changed"));
        }
        let mut args = vec!["create".into(), "-o".into(), "encryption=off".into()];
        for (key, value) in crate::placement::inert_properties(false)
            .into_iter()
            .chain([
                (management::PENDING_PROPERTY.into(), id.into()),
                (management::STAGING_PROPERTY.into(), id.into()),
            ])
        {
            args.extend(["-o".into(), format!("{key}={value}")]);
        }
        args.push(name.into());
        zfs_tools::engine::native::run_mutating("zfs", &args).map(drop)
    }
    fn rename_received(
        &mut self,
        source: &Endpoint,
        parent: &Endpoint,
        destination: &str,
    ) -> Result<(), Error> {
        zfs_tools::engine::validate_dataset_name(destination)?;
        let state = PairBackend::observe(self)?;
        if endpoint(&state, &source.name)? != *source
            || endpoint(&state, &parent.name)? != *parent
            || parent.identity.pool_guid != source.identity.pool_guid
            || destination.rsplit_once('/').map(|p| p.0) != Some(parent.name.as_str())
            || state
                .inspection
                .datasets
                .iter()
                .any(|d| d.name == destination)
        {
            return Err(refuse("receive rename endpoint or final parent changed"));
        }
        // `-u` keeps a filesystem unmounted; OpenZFS refuses it for a volume,
        // which has nothing to mount (zfs_main.c, zfs_do_rename).
        let volume = state
            .inspection
            .datasets
            .iter()
            .any(|d| d.name == source.name && d.kind == zfs_tools::engine::DatasetKind::Volume);
        let mut args = vec!["rename".to_string()];
        if !volume {
            args.push("-u".into());
        }
        args.extend([source.name.clone(), destination.into()]);
        let result = zfs_tools::engine::native::run_mutating("zfs", &args);
        let after = PairBackend::observe(self)?;
        if endpoint(&after, destination).is_ok_and(|ep| ep.identity == source.identity)
            && !after
                .inspection
                .datasets
                .iter()
                .any(|d| d.name == source.name)
        {
            Ok(())
        } else {
            Err(result
                .err()
                .unwrap_or_else(|| refuse("receive rename was not verified")))
        }
    }
    fn publish_mountpoint(
        &mut self,
        endpoint: &Endpoint,
        saved: &crate::placement::SavedProperty,
    ) -> Result<(), Error> {
        if !(saved.source == "local"
            || saved.source == "default"
            || saved.source.starts_with("inherited from "))
        {
            return Err(refuse("invalid frozen mountpoint source"));
        }
        let value = PropertyValue::Mountpoint(saved.value.clone());
        value.encode(endpoint)?;
        let before = self.properties(endpoint)?;
        self.without_altroot(endpoint)?;
        if before
            .get("mountpoint")
            .is_some_and(|p| p.value == saved.value && p.source == saved.source)
        {
            return Ok(());
        }
        if before.get("readonly").is_none_or(|p| p.value != "on")
            || before.get("canmount").is_none_or(|p| p.value != "noauto")
        {
            return Err(refuse(
                "mountpoint restoration requires a verified inactive receive role",
            ));
        }
        if saved.source == "local" {
            self.set_property(endpoint, &value)?;
        } else {
            zfs_tools::engine::mutation::NativeMutation::new()
                .inherit_native(endpoint, PropertyKey::Mountpoint)?;
        }
        let after = self.properties(endpoint)?;
        self.without_altroot(endpoint)?;
        if after
            .get("mountpoint")
            .is_none_or(|p| p.value != saved.value || p.source != saved.source)
        {
            return Err(refuse(
                "native receive mountpoint value/source restoration differs from receipt",
            ));
        }
        Ok(())
    }
    fn quiesce_receive_scope(&mut self, endpoint: &Endpoint, id: &str) -> Result<(), Error> {
        stream::quiesce_inert(endpoint, id)
    }
    fn volume_unavailable(&mut self, endpoint: &Endpoint) -> Result<bool, Error> {
        stream::volume_unavailable(endpoint)
    }
    fn destroy_empty_container(&mut self, endpoint: &Endpoint, id: &str) -> Result<(), Error> {
        let state = PairBackend::observe(self)?;
        if crate::transfer::endpoint(&state, &endpoint.name)? != *endpoint {
            return Err(refuse("receive container was replaced before retirement"));
        }
        let props = self.properties(endpoint)?;
        if [management::PENDING_PROPERTY, management::STAGING_PROPERTY]
            .iter()
            .any(|key| {
                props
                    .get(*key)
                    .is_none_or(|p| p.source != "local" || p.value != id)
            })
            || state.inspection.datasets.iter().any(|d| {
                history::contains_dataset(&endpoint.name, &d.name) && d.name != endpoint.name
            })
            || state
                .inspection
                .snapshots
                .as_ref()
                .unwrap()
                .iter()
                .any(|p| {
                    p.name
                        .split_once('@')
                        .is_some_and(|(owner, _)| owner == endpoint.name)
                })
        {
            return Err(refuse(
                "receive container is not the exact owned empty workspace",
            ));
        }
        let result = zfs_tools::engine::native::run_mutating(
            "zfs",
            &["destroy".into(), endpoint.name.clone()],
        );
        if PairBackend::observe(self)?
            .inspection
            .datasets
            .iter()
            .any(|d| d.name == endpoint.name)
        {
            Err(result
                .err()
                .unwrap_or_else(|| refuse("empty receive container still exists")))
        } else {
            Ok(())
        }
    }
    fn copy_property(
        &mut self,
        target: &Endpoint,
        key: &str,
        value: Option<&str>,
        id: &str,
    ) -> Result<(), Error> {
        valid_id(id)?;
        if !props::copied(key) || (value.is_none() && props::space(key)) {
            return Err(refuse(format!("{key} is not a copied property")));
        }
        let before = self.properties(target)?;
        for marker in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
            if before.get(marker).is_none_or(|p| p.value != id) {
                return Err(refuse("copy lacks this operation's ownership markers"));
            }
        }
        let args = match value {
            Some(value) => vec!["set".into(), format!("{key}={value}"), target.name.clone()],
            None => vec!["inherit".into(), key.into(), target.name.clone()],
        };
        zfs_tools::engine::native::run_mutating("zfs", &args)
            .map_err(|error| refuse(format!("cannot set {key} on {}: {error}", target.name)))?;
        let after = self.properties(target)?;
        let held = after.get(key);
        let done = match value {
            Some(value) => {
                held.is_some_and(|p| p.source == "local" && props::reads_back(key, value, &p.value))
            }
            None => held.is_none_or(|p| !matches!(p.source.as_str(), "local" | "received")),
        };
        if !done {
            return Err(refuse(format!(
                "{key} on {} did not read back",
                target.name
            )));
        }
        Ok(())
    }
    fn mount(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.properties(endpoint)?;
        crate::status::unoccupied(&endpoint.name)?;
        zfs_tools::engine::native::run_mutating("zfs", &["mount".into(), endpoint.name.clone()])
            .map(|_| ())
    }
    fn stream(&mut self, request: &LeafStream) -> Result<StreamOutcome, Error> {
        stream::leaf_replicate(request)
    }
    fn wrapping(&mut self, root: &Endpoint) -> Result<Wrapping, Error> {
        self.properties(root)?;
        // pbkdf2salt is hidden from `zfs get all`; it is read by name.
        let text = zfs_tools::engine::native::run(
            "zfs",
            &[
                "get".into(),
                "-H".into(),
                "-p".into(),
                "-o".into(),
                "property,value".into(),
                "keyformat,keylocation,pbkdf2iters,pbkdf2salt".into(),
                root.name.clone(),
            ],
        )?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('\t') {
                values.insert(key.to_string(), value.to_string());
            }
        }
        let mut take = |key: &str| {
            values
                .remove(key)
                .ok_or_else(|| refuse(format!("{key} of {} was not reported", root.name)))
        };
        Ok(Wrapping {
            keyformat: take("keyformat")?,
            keylocation: take("keylocation")?,
            pbkdf2iters: take("pbkdf2iters")?,
            pbkdf2salt: take("pbkdf2salt")?,
        })
    }
    fn key_opens(&mut self, root: &Endpoint, location: &str) -> Result<bool, Error> {
        self.properties(root)?;
        // Checks the key and loads nothing; works with the key loaded and on
        // a read-only pool.
        if !location.starts_with("file:///") || location.chars().any(char::is_control) {
            return Err(refuse(format!("{location} is not a file:// key location")));
        }
        let args = ["load-key", "-n", "-L", location, &root.name].map(String::from);
        Ok(zfs_tools::engine::native::run("zfs", &args).is_ok())
    }
    fn set_keylocation(
        &mut self,
        target: &Endpoint,
        location: &str,
        id: &str,
    ) -> Result<(), Error> {
        valid_id(id)?;
        if location.chars().any(char::is_control) {
            return Err(refuse("invalid key location"));
        }
        let before = self.properties(target)?;
        if before
            .get(management::PENDING_PROPERTY)
            .is_none_or(|p| p.value != id)
        {
            return Err(refuse("copy lacks this operation's ownership markers"));
        }
        zfs_tools::engine::native::run_mutating(
            "zfs",
            &[
                "set".into(),
                format!("keylocation={location}"),
                target.name.clone(),
            ],
        )?;
        if self
            .properties(target)?
            .get("keylocation")
            .is_none_or(|p| p.value != location || p.source != "local")
        {
            return Err(refuse("keylocation did not read back"));
        }
        Ok(())
    }
    fn release_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
        let current = self.observe_point(point)?;
        if current.point() != *point || current.defer_destroy {
            return Err(refuse("temporary hold target changed or is deferred"));
        }
        zfs_tools::engine::native::run_mutating(
            "zfs",
            &["release".into(), tag.into(), point.name.clone()],
        )
        .map(|_| ())
    }
    fn rename_snapshot(&mut self, point: &SnapshotRef, name: &str) -> Result<(), Error> {
        let (dataset, _) = point
            .name
            .split_once('@')
            .ok_or_else(|| refuse("a snapshot rename needs a snapshot"))?;
        let renamed = format!("{dataset}@{name}");
        zfs_tools::engine::validate_snapshot_name(&renamed)?;
        self.observe_point(point)?;
        // A snapshot rename is a DSL operation: allowed on a read-only copy.
        let result = zfs_tools::engine::native::run_mutating(
            "zfs",
            &["rename".into(), point.name.clone(), renamed.clone()],
        );
        let after = SnapshotRef {
            name: renamed,
            ..point.clone()
        };
        match self.observe_point(&after) {
            Ok(_) => Ok(()),
            Err(error) => Err(result.err().unwrap_or(error)),
        }
    }
    fn destroy_snapshot(&mut self, point: &SnapshotRef) -> Result<(), Error> {
        zfs_tools::engine::validate_snapshot_name(&point.name)?;
        let current = self.observe_point(point)?;
        if current.userrefs != 0
            || !current.holds.is_empty()
            || !current.clones.is_empty()
            || current.defer_destroy
        {
            return Err(refuse(format!(
                "{} is held, has a clone or is marked for deferred destruction",
                point.name
            )));
        }
        // One exact snapshot: no -r, -R or -d. Allowed on a read-only copy.
        let result =
            zfs_tools::engine::native::run_mutating("zfs", &["destroy".into(), point.name.clone()]);
        match zfs_tools::engine::observe_snapshot(&point.name) {
            Err(Error::NotFound(_)) => Ok(()),
            Ok(_) => Err(result
                .err()
                .unwrap_or_else(|| refuse(format!("{} still exists after destroy", point.name)))),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Admission {
    pub source: Tree,
    pub destination: Destination,
    pub source_owner: Ownership,
    pub destination_owner: Ownership,
}

pub fn admission_with(
    request: &TransferRequest,
    backend: &mut impl TransferBackend,
) -> Result<Admission, Error> {
    let state = PairBackend::observe(backend)?;
    let admission = preflight(&state, request, backend)?;
    refuse_running(request, backend)?;
    // A read-only source is sent from its newest snapshot and never captured
    // anew (`transfer_with_id`), so it needs one before any operation begins.
    let readonly = state
        .inspection
        .datasets
        .iter()
        .any(|dataset| dataset.name == request.source && dataset.readonly);
    if readonly
        && admission
            .source
            .members
            .get("")
            .is_none_or(|member| member.bound.snapshots.is_empty())
    {
        return Err(refuse(format!(
            "{} is read-only and has no snapshot to send; snapshot it or make it writable",
            request.source
        )));
    }
    Ok(admission)
}

/// Admission only: the checks `transfer_with_id` makes before its first effect.
pub fn admit_with(
    request: &TransferRequest,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    admission_with(request, backend).map(drop)
}
/// Transfer REQUEST under RECORD, which its caller wrote before any effect
/// and which records no transfer yet, so an interruption is found again by
/// that record's id.
pub(crate) fn transfer_with_id(
    request: &TransferRequest,
    record: &mut impl Record,
    backend: &mut impl TransferBackend,
) -> Result<TransferOutcome, Error> {
    let id = record.id().to_owned();
    valid_id(&id)?;
    let before = PairBackend::observe(backend)?;
    preflight(&before, request, backend)?;
    refuse_running(request, backend)?;
    // A pair joins leaf datasets: only the source itself is captured.
    let readonly = before
        .inspection
        .datasets
        .iter()
        .find(|dataset| dataset.name == request.source)
        .is_some_and(|dataset| dataset.readonly);
    let fresh_capture = if !readonly {
        let name = format!("zboot_transfer_{}", uuid::Uuid::new_v4().simple());
        let captured = capture::capture_with(
            &CaptureRequest {
                roots: vec![request.source.clone()],
                name,
                recursive: false,
            },
            backend,
        )?;
        let status = captured.status();
        if status != zfs_tools::CaptureStatus::Complete
            || !captured.missing().is_empty()
            || captured.detail().is_some()
        {
            return Err(refuse(format!(
                "source capture {} requires reconciliation: {:?}",
                captured.operation_id(),
                status
            )));
        }
        Some(TransferCapture {
            operation_id: captured.operation_id().to_owned(),
            points: captured.points().to_vec(),
        })
    } else {
        None
    };
    let state = PairBackend::observe(backend)?;
    let plan = plan_with(&state, request, &id, backend)?;
    let result: Result<TransferOutcome, Error> = (|| {
        let mut outcome = begin(record, plan, backend)?;
        outcome.capture = fresh_capture;
        Ok(outcome)
    })();
    result.map_err(|error| {
        zfs_tools::engine::effect::operation_hint(&id);
        refuse(format!(
            "transfer operation {id} on {} needs reconciliation: {error}",
            request.source
        ))
    })
}

/// Execute an already captured boundary under RECORD, as `transfer_with_id`.
/// The complete supplied plan is reobserved before the transfer is recorded.
pub(crate) fn apply_with_id(
    plan: &TransferPlan,
    record: &mut impl Record,
    backend: &mut impl TransferBackend,
) -> Result<TransferOutcome, Error> {
    let id = record.id().to_owned();
    valid_id(&id)?;
    validate_plan(plan)?;
    let state = PairBackend::observe(backend)?;
    if plan_with(&state, &request(plan), &id, backend)? != *plan {
        return Err(refuse("predeclared transfer plan changed before execution"));
    }
    refuse_running(&request(plan), backend)?;
    begin(record, plan.clone(), backend).map_err(|error| {
        zfs_tools::engine::effect::operation_hint(&id);
        refuse(format!(
            "transfer operation {id} on {} needs reconciliation: {error}",
            plan.source.endpoint.name
        ))
    })
}
/// Record PLAN in RECORD, which names no transfer yet: the commit.
/// The frozen plan and receive session are written as an attachment on the
/// record's holder while the record names nothing, then one record write
/// names it. A cut before that write leaves chunks nothing names, which
/// [`discard`] removes.
fn commit(
    record: &mut impl Record,
    plan: TransferPlan,
    backend: &mut impl TransferBackend,
) -> Result<TransferOperation, Error> {
    let id = record.id().to_owned();
    if record.transfer().is_some() {
        return Err(refuse(format!("operation {id} already records a transfer")));
    }
    validate_plan(&plan)?;
    let receive = receive::capture(&plan, &id, backend)?;
    let frozen = Frozen { plan, receive };
    let named = write_attachment(record, PLAN, &frozen, backend)?;
    let operation = TransferOperation {
        plan: frozen.plan,
        receive: frozen.receive,
        pair_plan: None,
        progress: TransferProgress {
            plan: Some(named),
            ..TransferProgress::ended(Phase::Prepared)
        },
        received: None,
    };
    save(record, &operation, backend)?;
    Ok(operation)
}
fn begin(
    record: &mut impl Record,
    plan: TransferPlan,
    backend: &mut impl TransferBackend,
) -> Result<TransferOutcome, Error> {
    let mut operation = commit(record, plan, backend)?;
    execute(record, &mut operation, backend)
}

/// The transfer RECORD names, its frozen payloads read back. A named payload
/// that does not read back refuses: it is never discarded unread.
fn load(
    record: &impl Record,
    backend: &mut impl TransferBackend,
) -> Result<TransferOperation, Error> {
    let id = record.id();
    valid_id(id)?;
    let progress = record
        .transfer()
        .cloned()
        .ok_or_else(|| refuse(format!("operation {id} records no transfer")))?;
    let named = progress.plan.as_ref().ok_or_else(|| {
        refuse(format!(
            "transfer {id} has ended ({:?}); it names no plan",
            progress.phase
        ))
    })?;
    let frozen: Frozen = read_attachment(record, PLAN, named, backend)?;
    let pair_plan = progress
        .pair
        .as_ref()
        .map(|named| read_attachment(record, PAIR, named, backend))
        .transpose()?;
    let operation = TransferOperation {
        plan: frozen.plan,
        receive: frozen.receive,
        pair_plan,
        progress,
        received: None,
    };
    validate(&operation, id)?;
    Ok(operation)
}

/// Abandon RECORD's transfer between SOURCE and DESTINATION before it
/// adopted its received data (its Received phase), so one stuck pair never
/// holds its pool's operation slot. An existing copy stays fenced with the
/// snapshots it received, a valid prefix of the source's history that the
/// next sync continues from; the anchors are unchanged. A new copy stays in
/// its fenced receive container, whose name is returned. Holds, markers and
/// attachments of the transfer are removed; the caller then clears its
/// record. A transfer recorded as ended, or not recorded, only loses the
/// attachment chunks its record does not name.
pub(crate) fn abandon_between_with(
    source: &str,
    destination: &str,
    record: &mut impl Record,
    backend: &mut impl TransferBackend,
) -> Result<Option<String>, Error> {
    let id = record.id().to_owned();
    valid_id(&id)?;
    if record.transfer().is_none_or(|t| t.phase >= Phase::Released) {
        discard(record, backend)?;
        return Ok(None);
    }
    let operation = load(record, backend)?;
    let state = PairBackend::observe(backend)?;
    if operation.plan.source.endpoint.name != source
        || operation.plan.destination.name() != destination
    {
        return Err(refuse(
            "transfer recovery intent and requested endpoints disagree; nothing abandoned",
        ));
    }
    if operation.progress.phase >= Phase::Received {
        return Err(refuse(verified(&state, &operation, &id, backend)?));
    }
    let left = receive::abandon(&operation, &id, backend)?;
    let tag = format!("zboot:transfer:{id}");
    for point in &operation.plan.source.members[""].bound.snapshots {
        if backend.observe_point(point).is_ok() {
            release_exact(point, &tag, backend)?;
        }
    }
    let mut marked = vec![(&operation.plan.source.endpoint, vec![PropertyKey::Pending])];
    if let Some(target) = operation.plan.destination.existing() {
        marked.push((
            &target.endpoint,
            vec![PropertyKey::Pending, PropertyKey::Staging],
        ));
    }
    for (endpoint, keys) in marked {
        for key in keys {
            if backend
                .properties(endpoint)?
                .get(key.native())
                .is_some_and(|p| p.value == id && p.source == "local")
            {
                backend.inherit_property(endpoint, key, &id)?;
            }
        }
    }
    let state = PairBackend::observe(backend)?;
    let abandoned = TransferProgress {
        left: left.as_ref().and_then(|name| endpoint(&state, name).ok()),
        ..TransferProgress::ended(Phase::Abandoned)
    };
    end(record, abandoned, backend)?;
    Ok(left)
}
/// Why transfer ID, past its Received phase, is not abandoned. While its copy
/// is still the one it received, under its staging marker (removed only once
/// the record is released), it is resumed. A copy gone, replaced or
/// released from it by hand leaves nothing to resume: the refusal names the
/// commands that end the transfer on the source alone, never touching the
/// copy or the pair's anchors (docs/RECOVERY.md).
fn verified(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<String, Error> {
    let copy = &operation
        .progress
        .received
        .as_ref()
        .ok_or_else(|| refuse("verified transfer intent lacks its copy"))?
        .endpoint;
    let source = &operation.plan.source.endpoint.name;
    let steps = source_only_steps(state, operation, id);
    let pool = pool_of(&copy.name);
    if !state.inspection.pools.iter().any(|p| p.name == pool) {
        return Ok(format!(
            "transfer {id} already verified its data; import pool {pool} of {} to resume it, \
             or, if pool {pool} is lost for good, end it on {source} alone: {steps}",
            copy.name
        ));
    }
    if let Some(moved) = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.identity == copy.identity && d.name != copy.name)
    {
        return Ok(format!(
            "transfer {id} already verified its data, but {} is now {}: rename it back to \
             resume it; nothing was changed",
            copy.name, moved.name
        ));
    }
    let current = endpoint(state, &copy.name).ok().as_ref() == Some(copy);
    if current
        && backend
            .properties(copy)?
            .get(management::STAGING_PROPERTY)
            .is_some_and(|p| p.source == "local" && p.value == id)
    {
        return Ok(format!(
            "transfer {id} already verified its data; resume it to finish"
        ));
    }
    // Its last step releases the copy, just after the record is released.
    if current && operation.progress.phase == Phase::Complete {
        return Ok(format!(
            "transfer {id} already verified its data; resume it to finish, or, if {} was \
             released from it by hand, end it on {source} alone: {steps}",
            copy.name
        ));
    }
    Ok(format!(
        "transfer {id} already verified its data, but {} is no longer the copy it \
         received; nothing was changed. To end it on {source} alone: {steps}",
        copy.name
    ))
}
/// The commands that end transfer ID on its source alone, each run only if
/// the one before succeeded: release its holds there, remove its marker and
/// its attachments there, and last its record, while that still names ID.
fn source_only_steps(state: &NativeState, operation: &TransferOperation, id: &str) -> String {
    let source = &operation.plan.source.endpoint.name;
    let tag = format!("zboot:transfer:{id}");
    let held: Vec<&str> = state
        .inspection
        .snapshots
        .iter()
        .flatten()
        .filter(|s| {
            s.name.split_once('@').map(|(owner, _)| owner) == Some(source.as_str())
                && s.holds.contains(&tag)
        })
        .map(|s| s.name.as_str())
        .collect();
    let ids: Vec<&str> = std::iter::once(id)
        .chain(operation.plan.bootstrap_pair_id.as_deref())
        .collect();
    let pending = state
        .dataset_properties
        .get(source)
        .and_then(|props| props.get(management::PENDING_PROPERTY))
        .is_some_and(|p| p.source == "local" && ids.contains(&p.value.as_str()));
    crate::recipe::source_only(source, pool_of(source), &tag, &held, pending, id)
}
/// Continue RECORD's transfer between SOURCE and DESTINATION. One already
/// `Released` only loses the rest of its attachments.
pub(crate) fn resume_between_with(
    source: &str,
    destination: &str,
    record: &mut impl Record,
    backend: &mut impl TransferBackend,
) -> Result<TransferOutcome, Error> {
    let id = record.id().to_owned();
    valid_id(&id)?;
    let state = PairBackend::observe(backend)?;
    let source_endpoint = endpoint(&state, source)?;
    let destination_endpoint = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == destination)
        .map(|d| Endpoint {
            name: destination.into(),
            identity: d.identity.clone(),
        });
    match record.transfer().map(|t| t.phase) {
        None => return Err(refuse(format!("operation {id} records no transfer"))),
        Some(Phase::Abandoned) => {
            return Err(refuse(format!(
                "transfer {id} was abandoned; abandon its operation to finish"
            )));
        }
        // Its record names nothing more; a cut while its chunks were
        // removed leaves them to remove.
        Some(Phase::Released) => {
            discard(record, backend)?;
            return Ok(TransferOutcome {
                operation_id: id,
                source: source_endpoint,
                destination: destination_endpoint,
                status: TransferStatus::AlreadyComplete,
                pair_id: None,
                completed_operation: None,
                capture: None,
                unmirrored: Vec::new(),
                unapplied: Vec::new(),
            });
        }
        Some(_) => {}
    }
    let mut operation = load(record, backend)?;
    if operation.plan.source.endpoint != source_endpoint
        || operation.plan.destination.name() != destination
    {
        return Err(refuse(
            "transfer recovery intent and requested endpoints disagree",
        ));
    }
    execute(record, &mut operation, backend).map_err(|error| {
        zfs_tools::engine::effect::operation_hint(&id);
        refuse(format!(
            "transfer operation {id} needs reconciliation: {error}"
        ))
    })
}
/// Remove every chunk of RECORD's attachments that it does not name: a write
/// cut before the record named it, or what a removal after `Released` or
/// `Abandoned` left. A holder that is no longer at its name took its chunks
/// with it; one renamed is renamed back first.
pub(crate) fn discard(
    record: &impl Record,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let id = record.id();
    if record
        .transfer()
        .is_some_and(|t| t.plan.is_some() || t.pair.is_some())
    {
        return Err(refuse(format!(
            "transfer {id} names its attachments; they are read, never discarded"
        )));
    }
    release_copy(record, backend)?;
    let holder = record.holder();
    let state = PairBackend::observe(backend)?;
    if endpoint(&state, &holder.name).ok().as_ref() != Some(holder) {
        if let Some(moved) = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.identity == holder.identity)
        {
            return Err(refuse(format!(
                "{} is now {}, and holds operation {id}'s attachments: rename it back; \
                 nothing was changed",
                holder.name, moved.name
            )));
        }
        return Ok(());
    }
    // The record names neither: only chunks it never named, or what a
    // removal after its end left, are here.
    for slot in [PLAN, PAIR] {
        attachment::remove(&mut backend.attachments(), holder, &key(id, slot)?, None)?;
    }
    Ok(())
}
/// At `Released`, remove the staging marker the copy still carries, which
/// kept every other command off it until then. A copy no longer at its name
/// in its imported pool took the marker with it; one renamed is renamed back
/// first, and one whose pool is not imported is imported, as only the record
/// remembers its marker.
fn release_copy(record: &impl Record, backend: &mut impl TransferBackend) -> Result<(), Error> {
    let Some(copy) = record
        .transfer()
        .filter(|t| t.phase == Phase::Released)
        .and_then(|t| t.received.as_ref())
        .map(|r| &r.endpoint)
    else {
        return Ok(());
    };
    let id = record.id();
    let state = PairBackend::observe(backend)?;
    if endpoint(&state, &copy.name).ok().as_ref() != Some(copy) {
        if let Some(moved) = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.identity == copy.identity)
        {
            return Err(refuse(format!(
                "{} is now {}, and still carries transfer {id}'s staging marker: rename it \
                 back; nothing was changed",
                copy.name, moved.name
            )));
        }
        let pool = pool_of(&copy.name);
        if !state
            .inspection
            .pools
            .iter()
            .any(|p| p.guid == copy.identity.pool_guid)
        {
            return Err(refuse(format!(
                "transfer {id} is released, but pool {pool} of {} is not imported and the \
                 copy may still carry its staging marker: import pool {pool} to finish; \
                 nothing was changed. If pool {pool} is lost for good, end it by hand: {}; \
                 should pool {pool} ever return, run `{}`",
                copy.name,
                released_steps(record),
                crate::recipe::inherit(management::STAGING_PROPERTY, &copy.name)
            )));
        }
        return Ok(());
    }
    let staged = |backend: &mut _| -> Result<bool, Error> {
        Ok(PairBackend::properties(backend, copy)?
            .get(management::STAGING_PROPERTY)
            .is_some_and(|p| p.source == "local" && p.value == id))
    };
    if staged(backend)? {
        let revealed = backend.inherit_property(copy, PropertyKey::Staging, id)?;
        if staged(backend)? {
            return Err(refuse("owned transfer marker remains after cleanup"));
        }
        if revealed.is_some() {
            return Err(refuse("cleanup revealed a different inherited operation"));
        }
    }
    Ok(())
}
/// The commands that end RECORD's released transfer by hand, each run only if
/// the one before succeeded: remove its attachments from its holder, and
/// last its record, while that still names it.
fn released_steps(record: &impl Record) -> String {
    crate::recipe::released(&record.holder().name, record.pool(), record.id())
}
/// Advance RECORD's transfer to ENDED, an end that names neither attachment,
/// then remove both: no path reads them once the record stops naming them.
fn end(
    record: &mut impl Record,
    ended: TransferProgress,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    if record.transfer() != Some(&ended) {
        record.advance(backend, ended)?;
    }
    discard(record, backend)
}
fn key(id: &str, slot: &str) -> Result<Key, Error> {
    Key::new(id, slot)
}
/// Write SLOT of RECORD's operation on its holder while the record names
/// nothing under it: leftovers of an earlier cut write are discarded or
/// adopted. A slot the record names is only ever read back ([`load`]),
/// never written again from a recomputed payload.
fn write_attachment<T: Serialize + serde::de::DeserializeOwned + PartialEq>(
    record: &impl Record,
    slot: &str,
    payload: &T,
    backend: &mut impl TransferBackend,
) -> Result<Attachment, Error> {
    let named = record.transfer().and_then(|t| match slot {
        PLAN => t.plan.as_ref(),
        _ => t.pair.as_ref(),
    });
    if named.is_some() {
        return Err(refuse(format!(
            "transfer {} already names its {slot} attachment; it is read, never rewritten",
            record.id()
        )));
    }
    // The record write that names it is what makes it durable.
    if pool_of(&record.holder().name) != record.pool() {
        return Err(refuse(format!(
            "transfer {}'s attachments would not be on its record's pool {}",
            record.id(),
            record.pool()
        )));
    }
    attachment::write(
        &mut backend.attachments(),
        record.holder(),
        &key(record.id(), slot)?,
        payload,
        named,
    )
}
/// The payload RECORD names as SLOT on its holder.
fn read_attachment<T: serde::de::DeserializeOwned>(
    record: &impl Record,
    slot: &str,
    named: &Attachment,
    backend: &mut impl TransferBackend,
) -> Result<T, Error> {
    let holder = record.holder();
    if attachment_endpoint(named) != holder {
        return Err(refuse(format!(
            "transfer {}'s {slot} attachment is named on {}, not its holder {}",
            record.id(),
            attachment_endpoint(named).name,
            holder.name
        )));
    }
    attachment::read(&mut backend.attachments(), &key(record.id(), slot)?, named).map_err(|error| {
        refuse(format!(
            "transfer {}'s {slot} attachment does not read back from {}: {error}; \
                 nothing was changed",
            record.id(),
            holder.name
        ))
    })
}
/// Where a named attachment's chunks are.
fn attachment_endpoint(named: &Attachment) -> &Endpoint {
    named.endpoint()
}
/// The pair id a bootstrap's nested pair takes, derived from the operation's
/// id like every record of it, so the operation alone finds them all.
pub(crate) fn bootstrap_pair_id(id: &str) -> String {
    let hash = Sha256::digest(format!("zboot bootstrap pair {id}"));
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    uuid::Uuid::from_bytes(bytes).to_string()
}
/// The widest progress a transfer under ID into DESTINATION, its attachments
/// on HOLDER, can record: every optional field present at its longest, with
/// the largest identities. A caller encodes its record with it before its
/// first effect, so no later advance can outgrow the record.
pub(crate) fn widest(
    id: &str,
    holder: &str,
    destination: &str,
    bootstrap: bool,
) -> Result<TransferProgress, Error> {
    let identity = DatasetIdentity {
        pool_guid: Guid::new(u64::MAX),
        guid: Guid::new(u64::MAX),
        createtxg: Txg::new(u64::MAX),
        objsetid: ObjsetId::new(u64::MAX),
    };
    let at = |name: &str| Endpoint {
        name: name.into(),
        identity: identity.clone(),
    };
    let digest = "f".repeat(64);
    Ok(TransferProgress {
        phase: Phase::Activating,
        plan: Some(Attachment::widest(&key(id, PLAN)?, at(holder))),
        pair: bootstrap
            .then(|| Ok::<_, Error>(Attachment::widest(&key(id, PAIR)?, at(holder))))
            .transpose()?,
        pair_phase: bootstrap.then_some(plan::Phase::Published),
        receive: receive::Receive {
            container: bootstrap.then(|| at(&receive::container_name(pool_of(destination), id))),
            step: receive::Step::Verified,
            stage: Some(digest.clone()),
        },
        received: Some(Received {
            endpoint: at(destination),
            digest,
        }),
        // Only an abandoned transfer, which names nothing else, records it.
        left: None,
    })
}

fn preflight(
    state: &NativeState,
    request: &TransferRequest,
    backend: &mut impl TransferBackend,
) -> Result<Admission, Error> {
    zfs_tools::engine::validate_dataset_name(&request.source)?;
    zfs_tools::engine::validate_dataset_name(&request.destination)?;
    // A read-only source still sends; both pools must be free of an altroot.
    for name in [&request.source, &request.destination] {
        let pool = zfs_tools::engine::pool_of(name);
        if state
            .pool_properties
            .get(pool)
            .and_then(|p| p.get("altroot"))
            .is_some_and(|p| !matches!(p.value.as_str(), "-" | ""))
        {
            return Err(refuse(format!(
                "pool {pool} is imported with an altroot (zpool import -R); zboot writes \
                 nothing there: export it and import it again without -R"
            )));
        }
    }
    destination_outside_boot_environment(state, &request.destination)?;
    if history::contains_dataset(&request.source, &request.destination)
        || history::contains_dataset(&request.destination, &request.source)
    {
        return Err(refuse("transfer scopes overlap"));
    }
    let source = observation::tree(state, &request.source, backend)?;
    // Clones of the source's snapshots (a fork) stay on the sending side and
    // do not affect the copy. A source that is itself a clone is refused: its
    // copy would need the origin's history.
    if source
        .nodes
        .get("")
        .is_some_and(|node| node.origin.is_some())
    {
        return Err(refuse(format!(
            "{} is a clone; promote it first (`zfs promote {}`), or copy its origin",
            request.source, request.source
        )));
    }
    let source_role = management::ownership(state, &request.source)?;
    // A sync copies a pair's working copy into its fenced secondary, never
    // the other way: switching which copy works is `primary`.
    if let Ownership::Secondary { record } = &source_role {
        let (source, peer) = (
            zfs_tools::engine::escape_display(&request.source),
            zfs_tools::engine::escape_display(&record.peer.name),
        );
        return Err(refuse(format!(
            "{source} is the secondary of {peer}; sync copies only a pair's primary into its \
             secondary. To make {source} the working copy, run `zboot primary {source}`"
        )));
    }
    let target = if state
        .inspection
        .datasets
        .iter()
        .any(|d| d.name == request.destination)
    {
        let destination = observation::tree(state, &request.destination, backend)?;
        let admission = history::admit_pair(&source, &destination)
            .map_err(|error| refuse(error.to_string()))?;
        admission
            .refuse_receiver_clones(Side::Right, &request.destination)
            .map_err(|error| refuse(error.to_string()))?;
        if admission.ahead == Some(Side::Right)
            || destination
                .nodes
                .get("")
                .is_some_and(|node| node.head != history::Head::Clean)
        {
            return Err(refuse("destination is ahead or has unsnapshotted changes"));
        }
        let destination_role = management::ownership(state, &request.destination)?;
        match (source_role, destination_role) {
            // A copy into an existing dataset is a pair's sync; pairing two
            // existing datasets is `pair`, which checks them both first.
            (Ownership::Unpaired, Ownership::Unpaired) => {
                return Err(refuse(format!(
                    "{} already exists and is not paired with {}; pair them first, \
                     or sync into a name that does not exist yet",
                    request.destination, request.source
                )));
            }
            (Ownership::Primary { record: a }, Ownership::Secondary { record: b })
                if a.endpoint.name == request.source
                    && b.endpoint.name == request.destination
                    && a.counterpart() == b => {}
            _ => {
                return Err(refuse(
                    "transfer endpoints do not have compatible mutual ownership",
                ));
            }
        }
        Some(bind_observed(
            state,
            &request.destination,
            destination,
            End::Receiver,
        )?)
    } else {
        if source_role != Ownership::Unpaired {
            return Err(refuse("bootstrap requires an unpaired source"));
        }
        let children: Vec<String> = source
            .nodes
            .keys()
            .filter(|k| !k.is_empty())
            .cloned()
            .collect();
        plan::refuse_children(&request.source, &request.destination, &children)?;
        let parent = request
            .destination
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .ok_or_else(|| refuse("bootstrap cannot create a pool root"))?;
        endpoint(state, parent)?;
        if management::ownership(state, parent)? != Ownership::Unpaired {
            return Err(refuse("bootstrap parent belongs to a managed pair"));
        }
        validate_parent(state, parent)?;
        if state
            .inspection
            .datasets
            .iter()
            .any(|d| history::contains_dataset(&request.destination, &d.name))
        {
            return Err(refuse("bootstrap destination scope is occupied"));
        }
        None
    };
    let source = bind_observed(state, &request.source, source, End::Sender)?;
    boot_policy::validate_publication(&source, target.as_ref(), &request.destination)?;
    if let Some(target) = &target {
        prove_wrapping_of(&source.members[""], &target.members[""], backend)?;
    }
    let destination_owner = if target.is_some() {
        management::ownership(state, &request.destination)?
    } else {
        Ownership::Unpaired
    };
    let destination = match target {
        Some(tree) => Destination::Existing { tree },
        None => Destination::Absent {
            name: request.destination.clone(),
            parent: endpoint(state, request.destination.rsplit_once('/').unwrap().0)?,
        },
    };
    Ok(Admission {
        source,
        destination,
        source_owner: management::ownership(state, &request.source)?,
        destination_owner,
    })
}

/// The plan of a transfer under operation ID, frozen from STATE.
pub fn plan_with(
    state: &NativeState,
    request: &TransferRequest,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<TransferPlan, Error> {
    preflight(state, request, backend)?;
    let source = bind(state, &request.source, backend, End::Sender)?;
    let root = source
        .members
        .get("")
        .ok_or_else(|| refuse("source root missing"))?;
    let boundary = root
        .bound
        .snapshots
        .last()
        .cloned()
        .ok_or_else(|| refuse("read-only source has no retained boundary"))?;
    let boundary_suffix = suffix(&boundary)?;
    if source.members.values().any(|member| {
        member.bound.snapshots.last().is_none_or(|point| {
            point.name.rsplit_once('@').map(|(_, s)| s) != Some(boundary_suffix)
        })
    }) {
        return Err(refuse("source lacks a complete latest snapshot boundary"));
    }
    let destination = if state
        .inspection
        .datasets
        .iter()
        .any(|d| d.name == request.destination)
    {
        Destination::Existing {
            tree: bind(state, &request.destination, backend, End::Receiver)?,
        }
    } else {
        Destination::Absent {
            name: request.destination.clone(),
            parent: endpoint(state, request.destination.rsplit_once('/').unwrap().0)?,
        }
    };
    let base = if let Some(target) = destination.existing() {
        let last = target.members[""]
            .bound
            .snapshots
            .last()
            .ok_or_else(|| refuse("existing destination root has no shared base"))?;
        let source_base = root
            .bound
            .snapshots
            .iter()
            .find(|point| point.identity.guid == last.identity.guid)
            .cloned()
            .ok_or_else(|| refuse("destination boundary is not retained by source"))?;
        let base_suffix = suffix(&source_base)?;
        for (relative, member) in &target.members {
            let source_member = &source.members[relative];
            let target_last = member
                .bound
                .snapshots
                .last()
                .ok_or_else(|| refuse("destination child lacks a common boundary"))?;
            if source_member
                .bound
                .snapshots
                .iter()
                .find(|point| suffix(point).ok() == Some(base_suffix))
                .is_none_or(|point| point.identity.guid != target_last.identity.guid)
            {
                return Err(refuse(
                    "incremental base is not a complete boundary; per-dataset recovery required",
                ));
            }
        }
        Some(source_base)
    } else {
        None
    };
    let source_pair = match management::ownership(state, &request.source)? {
        Ownership::Unpaired => None,
        Ownership::Primary { record } | Ownership::Secondary { record } => Some(record),
    };
    let bootstrap_pair_id = destination
        .existing()
        .is_none()
        .then(|| bootstrap_pair_id(id));
    let plan = TransferPlan {
        schema_version: 2,
        source,
        destination,
        boundary,
        base,
        source_pair,
        bootstrap_pair_id,
    };
    validate_plan(&plan)?;
    Ok(plan)
}

fn destination_outside_boot_environment(state: &NativeState, name: &str) -> Result<(), Error> {
    crate::mounting::require_outside_boot_environment(state, name)
}
fn verify_receive_destinations(
    state: &NativeState,
    operation: &TransferOperation,
) -> Result<(), Error> {
    destination_outside_boot_environment(state, operation.plan.destination.name())?;
    if let Some(container) = &operation.receive.container {
        destination_outside_boot_environment(state, &container.name)?;
    }
    Ok(())
}

fn validate_parent(state: &NativeState, parent: &str) -> Result<(), Error> {
    let bound = endpoint(state, parent)?;
    if management::ownership(state, parent)? != Ownership::Unpaired {
        return Err(refuse("bootstrap parent belongs to a managed scope"));
    }
    let pool = pool_of(parent);
    let props = state
        .pool_properties
        .get(pool)
        .ok_or_else(|| refuse("bootstrap parent pool properties are incomplete"))?;
    if props.get("guid").map(|p| p.value.as_str())
        != Some(bound.identity.pool_guid.to_string().as_str())
        || props.keys().any(|key| management::managed_key(key))
    {
        return Err(refuse(
            "bootstrap parent pool identity or management properties changed",
        ));
    }
    Ok(())
}

/// Admission refuses a pool imported with an altroot, so every tree a transfer
/// freezes was bound without one and its mountpoints are the persistent
/// values. A pool imported again with `-R` since then refuses: nothing is
/// bound or written there.
fn refuse_altroot(state: &NativeState, name: &str) -> Result<(), Error> {
    let pool = pool_of(name);
    if state
        .pool_properties
        .get(pool)
        .and_then(|p| p.get("altroot"))
        .is_some_and(|p| !matches!(p.value.as_str(), "" | "-" | "/"))
    {
        return Err(refuse(format!(
            "pool {pool} is imported with an altroot (zpool import -R); zboot writes \
             nothing there: export it and import it again without -R"
        )));
    }
    Ok(())
}

/// Which end of a transfer a bound tree is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// Sends; clones of its snapshots stay with it.
    Sender,
    /// Receives, and may be rolled back to its base: clones of its snapshots
    /// would block that, or be lost with them.
    Receiver,
}

/// The bound tree of `root` as a transfer sees it, including unpaired receives.
pub fn bind(
    state: &NativeState,
    root: &str,
    backend: &mut impl HistoryBackend,
    end: End,
) -> Result<Tree, Error> {
    let observed = observation::tree(state, root, backend)?;
    bind_observed(state, root, observed, end)
}

fn bind_observed(
    state: &NativeState,
    root: &str,
    observed: history::Tree,
    end: End,
) -> Result<Tree, Error> {
    refuse_altroot(state, root)?;
    let endpoint = endpoint(state, root)?;
    let mut members = BTreeMap::new();
    // A transfer copies one leaf; children are reported, never bound.
    for (relative, node) in observed.nodes.into_iter().filter(|(r, _)| r.is_empty()) {
        if node.origin.is_some() {
            return Err(refuse(format!("{root} became a clone")));
        }
        if end == End::Receiver && !node.clone_dependents.is_empty() {
            return Err(refuse(format!(
                "{root} receives but has clones of its snapshots ({}); drop them first",
                node.clone_dependents.join(", ")
            )));
        }
        let name = mapped(root, &relative);
        let dataset = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == name)
            .ok_or_else(|| refuse("observed tree member disappeared"))?;
        let props = management::bound_properties(state, &name)?;
        let placement = props
            .get(management::PLACEMENT_PROPERTY)
            .filter(|p| p.source == "local")
            .map(|p| Placement::parse(&p.value))
            .transpose()?
            .unwrap_or_else(|| Placement::observed(dataset, props));
        let mut snapshots: Vec<_> = state
            .inspection
            .snapshots
            .as_ref()
            .unwrap()
            .iter()
            .filter(|s| {
                s.name
                    .split_once('@')
                    .is_some_and(|(owner, _)| owner == name)
            })
            .map(|s| s.point())
            .collect();
        snapshots.sort_by_key(|s| s.identity.createtxg);
        let properties = bound_property_evidence(props);
        let local = props::frozen_local(props);
        members.insert(
            relative,
            Member {
                bound: plan::Member {
                    endpoint: Endpoint {
                        name,
                        identity: dataset.identity.clone(),
                    },
                    placement,
                    mountpoint: dataset.mountpoint.clone(),
                    snapshots,
                },
                kind: node.kind,
                mounted: dataset.mounted == Some(true),
                encryption: node.encryption,
                encryption_root: dataset.encryptionroot.clone(),
                properties,
                local,
            },
        );
    }
    Ok(Tree { endpoint, members })
}
/// The exact effective property evidence stored by `bind`. Source and peer
/// revalidation must use the same projection, including explicit boot policy.
pub(crate) fn bound_property_evidence(
    properties: &BTreeMap<String, NativeProperty>,
) -> BTreeMap<String, String> {
    properties
        .iter()
        .filter(|(key, property)| {
            fidelity_property(key)
                || ((boot_policy::key(key) || props::copied(key))
                    && matches!(property.source.as_str(), "local" | "received"))
        })
        .map(|(key, property)| (key.clone(), property_evidence(key, &property.value)))
        .collect()
}

pub fn fidelity_property(key: &str) -> bool {
    (!management::managed_key(key) && key.contains(':'))
        || matches!(
            key,
            "compression"
                | "checksum"
                | "recordsize"
                | "volblocksize"
                | "volsize"
                | "acltype"
                | "aclinherit"
                | "aclmode"
                | "xattr"
                | "casesensitivity"
                | "normalization"
                | "utf8only"
                | "dnodesize"
                | "dedup"
                | "copies"
                | "atime"
                | "relatime"
                | "devices"
                | "exec"
                | "setuid"
                | "snapdir"
                | "sync"
                | "logbias"
                | "special_small_blocks"
                | "redundant_metadata"
        )
}
/// Public operation records and attachments retain fidelity evidence, never
/// raw user-property values. zboot copies values from the source itself, never
/// through a record.
pub fn property_evidence(key: &str, value: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"zboot-property-v1\0");
    hash.update((key.len() as u64).to_be_bytes());
    hash.update(key.as_bytes());
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
    format!("sha256:{:x}", hash.finalize())
}
pub(crate) fn valid_property_evidence(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn endpoint(state: &NativeState, name: &str) -> Result<Endpoint, Error> {
    state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == name)
        .map(|d| Endpoint {
            name: name.into(),
            identity: d.identity.clone(),
        })
        .ok_or_else(|| refuse(format!("dataset was not observed: {name}")))
}
fn mapped(root: &str, relative: &str) -> String {
    if relative.is_empty() {
        root.into()
    } else {
        format!("{root}/{relative}")
    }
}
fn suffix(point: &SnapshotRef) -> Result<&str, Error> {
    point
        .name
        .rsplit_once('@')
        .map(|(_, suffix)| suffix)
        .ok_or_else(|| refuse("snapshot has no suffix"))
}
fn valid_id(id: &str) -> Result<(), Error> {
    if !zfs_tools::engine::is_canonical_uuid_v4(id) {
        return Err(refuse("operation ID must be canonical UUIDv4"));
    }
    Ok(())
}
fn refuse(detail: impl Into<String>) -> Error {
    Error::Refused(detail.into())
}

fn validate_tree(tree: &Tree) -> Result<(), Error> {
    zfs_tools::engine::validate_dataset_name(&tree.endpoint.name)?;
    if tree
        .members
        .get("")
        .is_none_or(|member| member.bound.endpoint != tree.endpoint)
    {
        return Err(refuse("frozen tree root missing"));
    }
    let mut ids = BTreeSet::new();
    for (relative, member) in &tree.members {
        let bound = &member.bound;
        let identity = &bound.endpoint.identity;
        if bound.endpoint.name != mapped(&tree.endpoint.name, relative)
            || relative.starts_with('/')
            || (!relative.is_empty()
                && !tree.members.contains_key(
                    relative
                        .rsplit_once('/')
                        .map(|(parent, _)| parent)
                        .unwrap_or(""),
                ))
            || !ids.insert(identity.guid)
            || identity.pool_guid != tree.endpoint.identity.pool_guid
            || [
                identity.pool_guid.get(),
                identity.guid.get(),
                identity.createtxg.get(),
                identity.objsetid.get(),
            ]
            .contains(&0)
            || bound.placement.identity != *identity
        {
            return Err(refuse("invalid frozen tree membership or identity"));
        }
        zfs_tools::engine::validate_dataset_name(&bound.endpoint.name)?;
        Placement::parse(&bound.placement.encode()?)?;
        if bound.placement.canmount.is_some() != (member.kind == history::Kind::Filesystem) {
            return Err(refuse("placement type differs from frozen dataset"));
        }
        let mut names = BTreeSet::new();
        let mut guids = BTreeSet::new();
        let mut txg = None;
        for point in &bound.snapshots {
            zfs_tools::engine::validate_snapshot_name(&point.name)?;
            if point.name.split_once('@').map(|(name, _)| name)
                != Some(bound.endpoint.name.as_str())
                || point.dataset_guid != identity.guid
                || point.identity.pool_guid != identity.pool_guid
                || [
                    point.identity.guid.get(),
                    point.identity.createtxg.get(),
                    point.identity.objsetid.get(),
                ]
                .contains(&0)
                || !names.insert(&point.name)
                || !guids.insert(point.identity.guid)
                || txg.is_some_and(|txg| txg >= point.identity.createtxg)
            {
                return Err(refuse("invalid frozen snapshot ancestry"));
            }
            txg = Some(point.identity.createtxg);
        }
        match &member.encryption {
            history::Encryption::Plain if member.encryption_root.is_none() => {}
            history::Encryption::Raw { cipher, ivsets }
                if !cipher.is_empty()
                    && member.encryption_root.is_some()
                    && ivsets.len() == guids.len()
                    && guids
                        .iter()
                        .all(|guid| ivsets.get(guid).is_some_and(|iv| iv.get() != 0)) => {}
            _ => return Err(refuse("frozen encryption evidence is incomplete")),
        }
        if member.properties.iter().any(|(key, value)| {
            !(fidelity_property(key) || props::copied(key) || boot_policy::key(key))
                || !valid_property_evidence(value)
        }) || member
            .local
            .iter()
            .any(|key| !props::copied(key) || !member.properties.contains_key(key))
        {
            return Err(refuse("unsupported frozen transfer property"));
        }
    }
    Ok(())
}
fn validate_plan(plan: &TransferPlan) -> Result<(), Error> {
    if plan.schema_version != 2 {
        return Err(refuse("unsupported transfer schema"));
    }
    validate_tree(&plan.source)?;
    boot_policy::validate_publication(
        &plan.source,
        plan.destination.existing(),
        plan.destination.name(),
    )?;
    for (relative, member) in &plan.source.members {
        if plan
            .destination
            .existing()
            .is_some_and(|t| t.members.contains_key(relative))
            || (!boot_policy::root(member)
                && !member.properties.keys().any(|key| boot_policy::key(key)))
        {
            continue;
        }
        if member.bound.mountpoint.as_deref() != Some("/")
            || member.bound.placement.canmount != Some(MountMode::NoAuto)
        {
            return Err(refuse(
                "bootstrap root policy requires an inactive-placement source root",
            ));
        }
    }
    zfs_tools::engine::validate_dataset_name(plan.destination.name())?;
    if history::contains_dataset(&plan.source.endpoint.name, plan.destination.name())
        || history::contains_dataset(plan.destination.name(), &plan.source.endpoint.name)
    {
        return Err(refuse("transfer scopes overlap"));
    }
    let boundary_suffix = suffix(&plan.boundary)?;
    if plan.source.members[""].bound.snapshots.last() != Some(&plan.boundary)
        || plan.source.members.values().any(|member| {
            member
                .bound
                .snapshots
                .last()
                .is_none_or(|point| suffix(point).ok() != Some(boundary_suffix))
        })
    {
        return Err(refuse("frozen boundary is incomplete"));
    }
    if let Some(record) = &plan.source_pair {
        record.validate()?;
        if record.endpoint != plan.source.endpoint || record.peer.name != plan.destination.name() {
            return Err(refuse("frozen transfer pair scope differs"));
        }
        if record.role != Role::Primary {
            return Err(refuse(
                "a transfer from a pair's secondary is not supported; use `zboot primary`",
            ));
        }
    }
    match &plan.destination {
        Destination::Absent { name, parent } => {
            if name.rsplit_once('/').map(|(owner, _)| owner) != Some(parent.name.as_str())
                || plan.source_pair.is_some()
                || plan.base.is_some()
            {
                return Err(refuse("invalid bootstrap parent or ownership"));
            }
            if [
                parent.identity.pool_guid.get(),
                parent.identity.guid.get(),
                parent.identity.createtxg.get(),
                parent.identity.objsetid.get(),
            ]
            .contains(&0)
            {
                return Err(refuse("bootstrap parent has invalid identity"));
            }
            valid_id(
                plan.bootstrap_pair_id
                    .as_deref()
                    .ok_or_else(|| refuse("bootstrap lacks predeclared pair intent"))?,
            )?;
        }
        Destination::Existing { tree } => {
            validate_tree(tree)?;
            if plan.bootstrap_pair_id.is_some() {
                return Err(refuse("existing destination cannot bootstrap a new pair"));
            }
            let base = plan
                .base
                .as_ref()
                .ok_or_else(|| refuse("existing destination lacks frozen incremental base"))?;
            if !plan.source.members[""].bound.snapshots.contains(base) {
                return Err(refuse("incremental base is not in source history"));
            }
            for (relative, target) in &tree.members {
                let source = plan
                    .source
                    .members
                    .get(relative)
                    .ok_or_else(|| refuse("destination has an unmatched descendant"))?;
                if target.kind != source.kind {
                    return Err(refuse("destination dataset type differs"));
                }
                validate_existing_history(&source.bound.snapshots, &target.bound.snapshots, base)?;
                verify_encryption(
                    &source.encryption,
                    &target.encryption,
                    &target.bound.snapshots,
                )?;
            }
            if base == &plan.boundary && plan.source.members.len() != tree.members.len() {
                return Err(refuse("new descendants require a newer boundary"));
            }
        }
    }
    Ok(())
}
fn verify_encryption(
    source: &history::Encryption,
    target: &history::Encryption,
    points: &[SnapshotRef],
) -> Result<(), Error> {
    match (source, target) {
        (history::Encryption::Plain, history::Encryption::Plain) => Ok(()),
        (
            history::Encryption::Raw {
                cipher: a,
                ivsets: x,
            },
            history::Encryption::Raw {
                cipher: b,
                ivsets: y,
            },
        ) if a == b
            && points
                .iter()
                .filter(|point| x.contains_key(&point.identity.guid))
                .all(|point| {
                    x.get(&point.identity.guid)
                        .is_some_and(|iv| iv.get() != 0 && Some(iv) == y.get(&point.identity.guid))
                }) =>
        {
            Ok(())
        }
        _ => Err(refuse("raw encryption ancestry differs")),
    }
}
/// A snapshot's identity in a pair's history: its GUID and name suffix.
fn history_of(points: &[SnapshotRef]) -> Result<Vec<(zfs_tools::engine::Guid, String)>, Error> {
    points
        .iter()
        .map(|point| Ok((point.identity.guid, suffix(point)?.to_owned())))
        .collect()
}
/// The copy's snapshots once this transfer is complete: for an existing copy
/// its own frozen snapshots, then exactly the source's after the base; for a
/// new copy all of the source's. Older snapshots only one side keeps stay.
fn expected_history(
    plan: &TransferPlan,
    relative: &str,
) -> Result<Vec<(zfs_tools::engine::Guid, String)>, Error> {
    let source = &plan
        .source
        .members
        .get(relative)
        .ok_or_else(|| refuse("frozen source member missing"))?
        .bound
        .snapshots;
    let Some(tree) = plan.destination.existing() else {
        return history_of(source);
    };
    let target = &tree
        .members
        .get(relative)
        .ok_or_else(|| refuse("frozen destination member missing"))?
        .bound
        .snapshots;
    let base = plan
        .base
        .as_ref()
        .ok_or_else(|| refuse("existing destination lacks frozen incremental base"))?;
    let at = source
        .iter()
        .position(|point| point.identity.guid == base.identity.guid)
        .ok_or_else(|| refuse("incremental base is not in source history"))?;
    let mut expected = history_of(target)?;
    expected.extend(history_of(&source[at + 1..])?);
    Ok(expected)
}
/// An existing copy can receive from this source: its newest snapshot is the
/// base, every snapshot it shares with the source has the source's name (the
/// sync renames them first), and the shared ones are in the same order.
fn validate_existing_history(
    source: &[SnapshotRef],
    target: &[SnapshotRef],
    base: &SnapshotRef,
) -> Result<(), Error> {
    if target.last().map(|p| p.identity.guid) != Some(base.identity.guid) {
        return Err(refuse(
            "incremental base is not the destination's newest snapshot",
        ));
    }
    let names: BTreeMap<_, _> = source
        .iter()
        .map(|point| (point.identity.guid, suffix(point)))
        .collect();
    let mut last = None;
    for point in target {
        let Some(name) = names.get(&point.identity.guid) else {
            continue;
        };
        let at = source
            .iter()
            .position(|p| p.identity.guid == point.identity.guid)
            .unwrap();
        if name.as_ref().ok() != suffix(point).ok().as_ref() || last.is_some_and(|l| l >= at) {
            return Err(refuse(
                "destination shares snapshots under other names or in another order",
            ));
        }
        last = Some(at);
    }
    Ok(())
}
/// Whether OPERATION is a well-formed active transfer of operation ID: its
/// plan, its named attachments and its progress agree with one another.
fn validate(operation: &TransferOperation, id: &str) -> Result<(), Error> {
    let plan = &operation.plan;
    validate_plan(plan)?;
    if plan
        .bootstrap_pair_id
        .as_ref()
        .is_some_and(|pair| *pair != bootstrap_pair_id(id))
    {
        return Err(refuse(
            "bootstrap pair id is not the one its operation derives",
        ));
    }
    let progress = &operation.progress;
    let holder = progress
        .plan
        .as_ref()
        .map(attachment_endpoint)
        .ok_or_else(|| refuse("an active transfer names its plan"))?;
    if progress.phase >= Phase::Released || progress.left.is_some() {
        return Err(refuse("an ended transfer names no plan"));
    }
    if *holder != plan.source.endpoint
        && Some(holder) != plan.destination.existing().map(|tree| &tree.endpoint)
    {
        return Err(refuse("transfer attachments are not on a leaf of it"));
    }
    let adopted = progress.phase >= Phase::Received;
    if progress.received.is_some() != adopted {
        return Err(refuse("adopted destination does not match transfer phase"));
    }
    if let Some(received) = &progress.received
        && (received.endpoint.name != plan.destination.name() || !valid_digest(&received.digest))
    {
        return Err(refuse("adopted destination differs from immutable scope"));
    }
    let paired = adopted && plan.bootstrap_pair_id.is_some();
    if progress.pair.is_some() != paired || operation.pair_plan.is_some() != paired {
        return Err(refuse("nested pair plan does not match transfer phase"));
    }
    if let (Some(pair), Some(named), Some(received)) =
        (&operation.pair_plan, &progress.pair, &progress.received)
    {
        pair.validate()?;
        if attachment_endpoint(named) != holder
            || pair.left != bound_tree(&plan.source)
            || pair.right.endpoint != received.endpoint
        {
            return Err(refuse("nested pair plan differs from verified transfer"));
        }
    }
    let published = progress.pair_phase == Some(plan::Phase::Published);
    if (progress.pair_phase.is_some()
        && (plan.bootstrap_pair_id.is_none() || progress.phase < Phase::Activating))
        || (progress.phase == Phase::Complete && plan.bootstrap_pair_id.is_some() && !published)
    {
        return Err(refuse("nested pair phase does not match transfer phase"));
    }
    receive::validate(&operation.receive, &progress.receive, plan, id)?;
    let retired = progress.receive.step == receive::Step::Retired;
    if (progress.phase == Phase::Complete && !retired)
        || (progress.phase < Phase::Activating && retired)
    {
        return Err(refuse("receive retirement does not match transfer phase"));
    }
    Ok(())
}
/// Record OPERATION's progress after the effects before it were verified:
/// one record write, none when it is already recorded.
fn save(
    record: &mut impl Record,
    operation: &TransferOperation,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    validate(operation, record.id())?;
    if record.transfer() != Some(&operation.progress) {
        record.advance(backend, operation.progress.clone())?;
    }
    Ok(())
}

/// STATE without this transfer's own control metadata: its attachments
/// ([`mask_attachments`]) and its markers on either leaf.
fn clean_parent_state(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
) -> Result<NativeState, Error> {
    let mut clean = state.clone();
    mask_attachments(&mut clean, state, operation, id)?;
    let nested = operation.progress.pair_phase.is_some();
    for root in [
        &operation.plan.source.endpoint.name,
        &operation.plan.destination.name().to_owned(),
    ] {
        for (name, props) in clean
            .dataset_properties
            .iter_mut()
            .filter(|(name, _)| history::contains_dataset(root, name))
        {
            let keys: Vec<_> = props.keys().cloned().collect();
            for key in keys {
                let property = &props[&key];
                if matches!(
                    key.as_str(),
                    management::PENDING_PROPERTY | management::STAGING_PROPERTY
                ) {
                    if property.value != id {
                        if key == management::PENDING_PROPERTY
                            && nested
                            && operation.plan.bootstrap_pair_id.as_deref()
                                == Some(property.value.as_str())
                        {
                            continue;
                        }
                        return Err(refuse(
                            "foreign pending or staging operation occupies transfer scope",
                        ));
                    }
                    let valid_source = property.source == "local"
                        || property
                            .source
                            .strip_prefix("inherited from ")
                            .is_some_and(|owner| {
                                history::contains_dataset(root, owner)
                                    && history::contains_dataset(owner, name)
                            });
                    if !valid_source {
                        return Err(refuse("transfer marker has an external or received source"));
                    }
                    props.remove(&key);
                }
            }
        }
    }
    Ok(clean)
}
/// Set aside this transfer's attachment chunks, as admission would refuse
/// them: on the holder each is local and the plan's first chunk is there,
/// and below it each is inherited from it with the holder's value. Any
/// other chunk of this operation's keys is drift.
fn mask_attachments(
    clean: &mut NativeState,
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
) -> Result<(), Error> {
    let holder = operation
        .progress
        .plan
        .as_ref()
        .map(attachment_endpoint)
        .ok_or_else(|| refuse("an ended transfer names no plan"))?;
    let keys = [key(id, PLAN)?, key(id, PAIR)?];
    let ours = |property: &str| keys.iter().any(|key| property.starts_with(key.prefix()));
    let Some(root) = state.dataset_properties.get(&holder.name) else {
        return Ok(());
    };
    if root
        .get(&format!("{}0000", keys[0].prefix()))
        .is_none_or(|p| p.source != "local")
    {
        return Err(refuse(format!(
            "transfer {id}'s plan attachment disappeared from {}",
            holder.name
        )));
    }
    let inherited = format!("inherited from {}", holder.name);
    for (name, props) in &mut clean.dataset_properties {
        let expected = if *name == holder.name {
            "local"
        } else {
            inherited.as_str()
        };
        let chunks: Vec<_> = props.keys().filter(|k| ours(k)).cloned().collect();
        for chunk in chunks {
            if !history::contains_dataset(&holder.name, name)
                || props[&chunk].source != expected
                || root
                    .get(&chunk)
                    .is_none_or(|p| p.value != props[&chunk].value)
            {
                return Err(refuse(format!(
                    "transfer {id}'s attachment drifted on {name}: {chunk}"
                )));
            }
            props.remove(&chunk);
        }
    }
    Ok(())
}
fn verify_source(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let clean = clean_state(state, operation, id)?;
    let mut current = bind(
        &clean,
        &operation.plan.source.endpoint.name,
        backend,
        End::Sender,
    )?;
    if current.endpoint != operation.plan.source.endpoint
        || current
            .members
            .keys()
            .ne(operation.plan.source.members.keys())
    {
        return Err(refuse(
            "source dataset is no longer the one this transfer was planned for",
        ));
    }
    for (relative, expected) in &operation.plan.source.members {
        let actual = current.members.get_mut(relative).unwrap();
        let boundary = expected.bound.snapshots.last().unwrap();
        actual
            .bound
            .snapshots
            .retain(|point| point.identity.createtxg <= boundary.identity.createtxg);
        if let history::Encryption::Raw { ivsets, .. } = &mut actual.encryption {
            ivsets.retain(|guid, _| {
                actual
                    .bound
                    .snapshots
                    .iter()
                    .any(|point| point.identity.guid == *guid)
            });
        }
        if actual.bound != expected.bound
            || actual.kind != expected.kind
            || actual.encryption != expected.encryption
            || actual.encryption_root != expected.encryption_root
            || actual.properties != expected.properties
        {
            // Name the dataset and what differs: after the data is verified
            // an abandon is refused, so putting it back is the only way on.
            let mut changed = Vec::new();
            if actual.bound.endpoint != expected.bound.endpoint {
                changed.push("its identity".to_owned());
            }
            if actual.bound.snapshots != expected.bound.snapshots {
                changed.push("its snapshots".to_owned());
            }
            if actual.bound.placement != expected.bound.placement {
                changed.push("its readonly, canmount or volmode".to_owned());
            }
            if actual.bound.mountpoint != expected.bound.mountpoint {
                changed.push("its mountpoint".to_owned());
            }
            if actual.kind != expected.kind {
                changed.push("its kind".to_owned());
            }
            if actual.encryption != expected.encryption
                || actual.encryption_root != expected.encryption_root
            {
                changed.push("its encryption".to_owned());
            }
            changed.extend(
                expected
                    .properties
                    .keys()
                    .chain(actual.properties.keys())
                    .filter(|key| expected.properties.get(*key) != actual.properties.get(*key))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|key| zfs_tools::engine::escape_display(key)),
            );
            let name = if relative.is_empty() {
                operation.plan.source.endpoint.name.clone()
            } else {
                format!("{}/{relative}", operation.plan.source.endpoint.name)
            };
            return Err(refuse(format!(
                "frozen source boundary, properties or identity changed: {} ({}); set it back \
                 as it was when the transfer was planned, then run it again (`zboot resume` if \
                 it was interrupted)",
                zfs_tools::engine::escape_display(&name),
                changed.join(", ")
            )));
        }
        if operation
            .plan
            .destination
            .existing()
            .is_none_or(|t| !t.members.contains_key(relative))
            && boot_policy::root(expected)
        {
            let props = backend.properties(&expected.bound.endpoint)?;
            crate::handoff::compose_cmdline(
                &expected.bound.endpoint.name,
                props.get("zboot:cmdline").map_or("", |p| p.value.as_str()),
            )
            .map_err(|e| refuse(e.to_string()))?;
        }
    }
    let props = management::bound_properties(&clean, &operation.plan.source.endpoint.name)?;
    let actual = props
        .get(management::PAIR_PROPERTY)
        .map(|p| PairRecord::parse(&p.value))
        .transpose()?;
    let expected = operation.plan.source_pair.clone();
    if actual != expected {
        let permitted = operation
            .plan
            .bootstrap_pair_id
            .as_ref()
            .zip(operation.pair_plan.as_ref())
            .is_some_and(|(pair_id, plan)| {
                actual.as_ref() == Some(&nested_pair_record(plan, pair_id))
            });
        if !permitted {
            return Err(refuse("source ownership changed during transfer"));
        }
    }
    Ok(())
}
fn refuse_running(request: &TransferRequest, backend: &mut impl PairBackend) -> Result<(), Error> {
    if backend
        .running_root()?
        .is_some_and(|root| history::contains_dataset(&request.destination, &root))
    {
        return Err(refuse(
            "running receiving root requires recovery before fencing",
        ));
    }
    Ok(())
}
fn request(plan: &TransferPlan) -> TransferRequest {
    TransferRequest {
        source: plan.source.endpoint.name.clone(),
        destination: plan.destination.name().into(),
    }
}
fn verify_fenced(state: &NativeState, tree: &Tree) -> Result<(), Error> {
    for member in tree.members.values() {
        let dataset = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == member.bound.endpoint.name)
            .ok_or_else(|| refuse("receiver member disappeared"))?;
        if dataset.identity != member.bound.endpoint.identity
            || !crate::pairs::at_rest(state, dataset)
        {
            return Err(refuse("receiver is not fully fenced"));
        }
    }
    Ok(())
}
/// Fence every member at rest with its placement saved, children first so a
/// parent unmount never hides a mounted child.
fn fence(tree: &Tree, backend: &mut impl TransferBackend) -> Result<(), Error> {
    for member in tree.members.values().rev() {
        crate::pairs::fence(
            backend,
            &member.bound.endpoint,
            Some(&member.bound.placement),
            crate::placement::Posture::AtRest,
        )?;
    }
    backend.sync(&tree.endpoint)?;
    verify_fenced(&PairBackend::observe(backend)?, tree)
}
fn protect(
    point: &SnapshotRef,
    tag: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let before = backend.observe_point(point)?;
    if before.point() != *point || before.defer_destroy {
        return Err(refuse("protected snapshot changed or is deferred"));
    }
    if before.holds.iter().any(|held| held == tag) {
        return Ok(());
    }
    let error = backend.add_hold(point, tag).err();
    let after = backend.observe_point(point)?;
    if after.point() != *point || !after.holds.iter().any(|held| held == tag) {
        return Err(error.unwrap_or_else(|| refuse("snapshot hold was not verified")));
    }
    Ok(())
}
fn verify_holds(
    plan: &TransferPlan,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let tag = format!("zboot:transfer:{id}");
    for point in plan
        .source
        .members
        .values()
        .flat_map(|member| &member.bound.snapshots)
    {
        let snapshot = backend.observe_point(point)?;
        if snapshot.point() != *point
            || snapshot.defer_destroy
            || !snapshot.holds.iter().any(|held| held == &tag)
        {
            return Err(refuse("temporary source protection changed"));
        }
    }
    Ok(())
}
fn verify_original_target(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    match &operation.plan.destination {
        Destination::Absent { name, parent } => {
            if endpoint(state, &parent.name)? != *parent
                || state
                    .inspection
                    .datasets
                    .iter()
                    .any(|d| history::contains_dataset(name, &d.name))
            {
                return Err(refuse(
                    "bootstrap destination is occupied or its parent changed",
                ));
            }
            let clean = clean_state(state, operation, id)?;
            validate_parent(&clean, &parent.name)?;
        }
        Destination::Existing { tree } => {
            let clean = clean_state(state, operation, id)?;
            let actual = bind(&clean, &tree.endpoint.name, backend, End::Receiver)?;
            if actual.endpoint != tree.endpoint || actual.members.keys().ne(tree.members.keys()) {
                return Err(refuse("destination changed before the stream"));
            }
            for (relative, expected) in &tree.members {
                let got = &actual.members[relative];
                let mut bound = got.bound.clone();
                // A retry after a cut keeps what an earlier attempt committed:
                // the frozen snapshots, then a prefix of the source's new ones.
                let frozen = expected.bound.snapshots.len();
                let wanted = expected_history(&operation.plan, relative)?;
                let progress = history_of(&bound.snapshots)?;
                if !bound.snapshots.starts_with(&expected.bound.snapshots)
                    || !wanted.starts_with(&progress)
                {
                    return Err(refuse(
                        "destination history is not its frozen snapshots plus this transfer's",
                    ));
                }
                bound.snapshots.truncate(frozen);
                // Snapshots this transfer appended bring their own IV sets, and
                // its copy of properties before data changed copied keys: only
                // what was frozen is compared here, the rest after the stream.
                let frozen_guids: BTreeSet<_> = expected
                    .bound
                    .snapshots
                    .iter()
                    .map(|p| p.identity.guid)
                    .collect();
                let encryption = match &got.encryption {
                    history::Encryption::Raw { cipher, ivsets } => history::Encryption::Raw {
                        cipher: cipher.clone(),
                        ivsets: ivsets
                            .iter()
                            .filter(|(guid, _)| frozen_guids.contains(guid))
                            .map(|(guid, ivset)| (*guid, *ivset))
                            .collect(),
                    },
                    other => other.clone(),
                };
                let uncopied = |properties: &BTreeMap<String, String>| -> BTreeMap<String, String> {
                    properties
                        .iter()
                        .filter(|(key, _)| !props::copied(key) && !fidelity_property(key))
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect()
                };
                if bound != expected.bound
                    || got.kind != expected.kind
                    || encryption != expected.encryption
                    || got.encryption_root != expected.encryption_root
                    || uncopied(&got.properties) != uncopied(&expected.properties)
                {
                    return Err(refuse(
                        "destination changed since approved incremental base",
                    ));
                }
                let dataset = clean
                    .inspection
                    .datasets
                    .iter()
                    .find(|d| d.name == got.bound.endpoint.name)
                    .unwrap();
                if backend.written(dataset, got.bound.snapshots.last().unwrap())? != 0 {
                    return Err(refuse("receiving head changed after fencing"));
                }
            }
            verify_existing_pair(&clean, &operation.plan)?;
        }
    }
    Ok(())
}
fn verify_existing_pair(state: &NativeState, plan: &TransferPlan) -> Result<(), Error> {
    for (root, expected) in [
        (&plan.source.endpoint.name, plan.source_pair.clone()),
        (
            &plan.destination.name().to_owned(),
            plan.source_pair.as_ref().map(|r| r.counterpart()),
        ),
    ] {
        let props = management::bound_properties(state, root)?;
        let actual = props
            .get(management::PAIR_PROPERTY)
            .map(|p| PairRecord::parse(&p.value))
            .transpose()?;
        if actual != expected {
            return Err(refuse("existing transfer ownership changed"));
        }
    }
    Ok(())
}
/// A selected raw subtree becomes a new encryption root when its original
/// encryption root lies above the selected source. Native raw-key receive
/// initializes that root locally; compound hierarchy fixup excludes top_zfs.
/// Use the actual receiving root before publication, then the final name.
/// The encryption root a copy has after a raw receive. A new copy is its own
/// root; an existing one keeps the root it had (`dsl_crypto_recv_raw_key_sync`).
fn expected_encryption_root(plan: &TransferPlan, receiving: &str) -> Option<String> {
    let source = &plan.source.members[""];
    source.encryption_root.as_ref()?;
    match plan.destination.existing() {
        Some(tree) => tree.members[""].encryption_root.clone(),
        None => Some(receiving.into()),
    }
}
/// Before any stream into an existing copy that takes its key from a root on
/// its own side: that root's wrapping must provably equal the sender root's,
/// or the received data opens with neither key. A copy that is its own root
/// takes the sender's wrapping and is always consistent.
fn prove_wrapping(
    operation: &TransferOperation,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let Some(existing) = operation.plan.destination.existing() else {
        return Ok(());
    };
    prove_wrapping_of(
        &operation.plan.source.members[""],
        &existing.members[""],
        backend,
    )
}
/// The proof for SOURCE sending into the existing COPY. Admission runs it
/// too, so a sync it refuses records nothing.
fn prove_wrapping_of(
    source: &Member,
    copy: &Member,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let Some(receiving) = copy.encryption_root.as_deref() else {
        return Ok(());
    };
    if receiving == copy.bound.endpoint.name {
        return Ok(());
    }
    let sender = source
        .encryption_root
        .as_deref()
        .ok_or_else(|| refuse("an encrypted copy of a plain source"))?;
    let state = PairBackend::observe(backend)?;
    let (sender_root, receiving_root) = (endpoint(&state, sender)?, endpoint(&state, receiving)?);
    let (sent, held) = (
        backend.wrapping(&sender_root)?,
        backend.wrapping(&receiving_root)?,
    );
    let name = &copy.bound.endpoint.name;
    let refusal = |why: &str| {
        refuse(format!(
            "{name} takes its key from {receiving}, and {why}; after this sync {name} \
             would open with neither key. Make {name} its own encryption root first \
             (zfs change-key {name}); sync then gives it {sender}'s key"
        ))
    };
    if sent.keyformat != held.keyformat {
        return Err(refusal(&format!("{sender} uses a different key format")));
    }
    if sent.keyformat == "passphrase" {
        if sent.pbkdf2salt != held.pbkdf2salt || sent.pbkdf2iters != held.pbkdf2iters {
            return Err(refusal(&format!(
                "{sender}'s passphrase wrapping differs (its key was changed)"
            )));
        }
        return Ok(());
    }
    let location = &sent.keylocation;
    if !location.starts_with("file:///") || held.keylocation != *location {
        return Err(refusal(&format!(
            "{sender}'s key is not a key file both roots name, so zboot cannot prove they match"
        )));
    }
    if !backend.key_opens(&sender_root, location)?
        || !backend.key_opens(&receiving_root, location)?
    {
        return Err(refusal(&format!(
            "{location} does not open both {sender} and {receiving}"
        )));
    }
    Ok(())
}
/// A new copy is its own encryption root with `keylocation=prompt`: give it
/// the location of its source's root, so it opens the same way.
fn give_keylocation(
    operation: &TransferOperation,
    destination: &str,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    if operation.plan.destination.existing().is_some() {
        return Ok(());
    }
    let Some(sender) = operation.plan.source.members[""].encryption_root.as_deref() else {
        return Ok(());
    };
    let state = PairBackend::observe(backend)?;
    let location = backend.wrapping(&endpoint(&state, sender)?)?.keylocation;
    let target = endpoint(&state, destination)?;
    if location != "prompt"
        && backend
            .properties(&target)?
            .get("keylocation")
            .is_none_or(|p| p.value != location)
    {
        backend.set_keylocation(&target, &location, id)?;
    }
    Ok(())
}

fn verify_received(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<Tree, Error> {
    verify_received_mode(state, operation, id, backend, true)
}
fn reconcile_external(
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    reconcile_external_mode(operation, id, backend, false)
}
fn reconcile_external_mode(
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
    inert: bool,
) -> Result<(), Error> {
    let state = PairBackend::observe(backend)?;
    verify_received_mode(&state, operation, id, backend, false)?;
    // Limits the copy could not take stay visible to `status` and `primary`,
    // which compare the pair's live values; they never wedge the pair.
    copy_properties(
        operation,
        operation.plan.destination.name(),
        props::When::AfterData,
        id,
        backend,
    )?;
    give_keylocation(operation, operation.plan.destination.name(), id, backend)?;
    verify_source(&PairBackend::observe(backend)?, operation, id, backend)?;
    boot_policy::reconcile(operation, id, backend, inert)?;
    verify_received_mode_inner(
        &PairBackend::observe(backend)?,
        operation,
        id,
        backend,
        true,
        inert,
    )?;
    Ok(())
}
fn verify_received_mode(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
    check_properties: bool,
) -> Result<Tree, Error> {
    verify_received_mode_inner(state, operation, id, backend, check_properties, false)
}
fn verify_received_mode_inner(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
    check_properties: bool,
    inert: bool,
) -> Result<Tree, Error> {
    let plan = &operation.plan;
    let adopted = operation.progress.received.as_ref();
    let clean = clean_state(state, operation, id)?;
    let mut target = bind(&clean, plan.destination.name(), backend, End::Receiver)?;
    if target.members.keys().ne(plan.source.members.keys()) {
        return Err(refuse(
            "received subtree membership is incomplete or unexpected",
        ));
    }
    // An adopted copy is the one its recorded digest names (below).
    if let Some(adopted) = adopted
        && (target.endpoint != adopted.endpoint || identity_digest(&target)? != adopted.digest)
    {
        return Err(refuse(
            "the adopted copy's incarnations or snapshots changed",
        ));
    }
    for (relative, source) in &plan.source.members {
        let received = target.members.get_mut(relative).unwrap();
        let initial = plan
            .destination
            .existing()
            .and_then(|tree| tree.members.get(relative));
        if let Some(expected) = initial {
            if received.bound.endpoint != expected.bound.endpoint {
                return Err(refuse("received dataset replaced a bound incarnation"));
            }
        } else if adopted.is_none() {
            let props = management::bound_properties(state, &received.bound.endpoint.name)?;
            for key in [management::PENDING_PROPERTY, management::STAGING_PROPERTY] {
                let marker = props
                    .get(key)
                    .ok_or_else(|| refuse("new received member lacks operation adoption marker"))?;
                if marker.value != id
                    || !(marker.source == "local"
                        || marker
                            .source
                            .strip_prefix("inherited from ")
                            .is_some_and(|owner| {
                                history::contains_dataset(plan.destination.name(), owner)
                                    && history::contains_dataset(
                                        owner,
                                        &received.bound.endpoint.name,
                                    )
                            }))
                {
                    return Err(refuse("new received member is not owned by this stream"));
                }
            }
        }
        if received.kind != source.kind
            || history_of(&received.bound.snapshots)? != expected_history(plan, relative)?
        {
            return Err(refuse(format!(
                "received snapshot GUID ancestry differs: {relative}"
            )));
        }
        if let Some(initial) = initial
            && !received
                .bound
                .snapshots
                .starts_with(&initial.bound.snapshots)
        {
            return Err(refuse("receive changed a retained snapshot incarnation"));
        }
        verify_encryption(
            &source.encryption,
            &received.encryption,
            &received.bound.snapshots,
        )?;
        if received.encryption_root != expected_encryption_root(plan, plan.destination.name()) {
            return Err(refuse("received encryption hierarchy differs from source"));
        }
        if check_properties
            && received
                .properties
                .iter()
                .filter(|(k, _)| fidelity_property(k))
                .ne(source
                    .properties
                    .iter()
                    .filter(|(k, _)| fidelity_property(k)))
        {
            let different: BTreeSet<_> = received
                .properties
                .keys()
                .chain(source.properties.keys())
                .filter(|key| received.properties.get(*key) != source.properties.get(*key))
                .collect();
            return Err(refuse(format!(
                "received data properties differ from frozen source at {relative:?}: {different:?}"
            )));
        }
        if check_properties {
            props::verify(source, &backend.properties(&received.bound.endpoint)?)?;
            boot_policy::verify(state, operation, relative, received, inert)?;
        }
        let dataset = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == received.bound.endpoint.name)
            .unwrap();
        if inert {
            let props = backend.properties(&received.bound.endpoint)?;
            if !receive::receiving(plan.destination.existing().is_some()).holds(
                received.kind == history::Kind::Volume,
                received.mounted,
                |key| {
                    props
                        .get(key)
                        .map(|p| (p.value.as_str(), p.source == "local"))
                },
            ) || (received.kind == history::Kind::Filesystem
                && props
                    .get("canmount")
                    .is_none_or(|property| property.value != "noauto"))
            {
                return Err(refuse(
                    "received role or placement escaped before full verification",
                ));
            }
        }
        if operation.progress.phase < Phase::Activating
            && backend.written(dataset, received.bound.snapshots.last().unwrap())? != 0
        {
            return Err(refuse("received head does not match captured boundary"));
        }
        if operation.progress.phase < Phase::Activating
            && (!dataset.readonly || dataset.mounted == Some(true))
        {
            return Err(refuse("received data is not readonly and unmounted"));
        }
        let intended = initial
            .map(|member| &member.bound.placement)
            .unwrap_or(&source.bound.placement);
        received.bound.placement = Placement {
            identity: received.bound.endpoint.identity.clone(),
            ..intended.clone()
        };
        received.mounted = initial.is_some_and(|member| member.mounted);
    }
    Ok(target)
}
/// A tree as the pair executor binds it.
fn bound_tree(tree: &Tree) -> plan::BoundTree {
    plan::BoundTree {
        endpoint: tree.endpoint.clone(),
        members: tree
            .members
            .values()
            .map(|member| member.bound.clone())
            .collect(),
    }
}
/// A copy's name-free identity: its root's incarnation and, per member, its
/// relative name, its incarnation and its snapshots by suffix and
/// incarnation. A rename keeps it; a replaced member or a snapshot added,
/// removed or replaced changes it. Placement, mounts, holds and properties
/// are not in it.
fn identity_digest(tree: &Tree) -> Result<String, Error> {
    let members = tree
        .members
        .iter()
        .map(|(relative, member)| {
            let snapshots = member
                .bound
                .snapshots
                .iter()
                .map(|point| Ok((suffix(point)?, point.dataset_guid, &point.identity)))
                .collect::<Result<Vec<_>, Error>>()?;
            Ok((relative, &member.bound.endpoint.identity, snapshots))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let bytes = serde_json::to_vec(&(
        "zboot-received-identity-v1",
        &tree.endpoint.identity,
        members,
    ))
    .map_err(|e| refuse(e.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bootstrap_pair_plan(plan: &TransferPlan, target: &Tree) -> Result<plan::PairPlan, Error> {
    let bound = bound_tree;
    let anchors = plan
        .source
        .members
        .iter()
        .map(|(relative, source)| {
            Ok((
                source
                    .bound
                    .snapshots
                    .last()
                    .ok_or_else(|| refuse("bootstrap source boundary missing"))?
                    .clone(),
                target.members[relative]
                    .bound
                    .snapshots
                    .last()
                    .ok_or_else(|| refuse("bootstrap target boundary missing"))?
                    .clone(),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let pair = plan::PairPlan {
        schema_version: 1,
        left: bound(&plan.source),
        right: bound(target),
        primary: Side::Left,
        anchors,
        existing_pair: None,
    };
    pair.validate()?;
    Ok(pair)
}
fn nested_pair_record(plan: &plan::PairPlan, id: &str) -> PairRecord {
    PairRecord {
        schema_version: 1,
        pair_id: id.into(),
        endpoint: plan.left.endpoint.clone(),
        peer: plan.right.endpoint.clone(),
        role: Role::Primary,
    }
}

fn clean_state(
    state: &NativeState,
    operation: &TransferOperation,
    id: &str,
) -> Result<NativeState, Error> {
    let mut clean = clean_parent_state(state, operation, id)?;
    let Some(pair_id) = &operation.plan.bootstrap_pair_id else {
        return Ok(clean);
    };
    if operation.progress.pair_phase.is_none() {
        return Ok(clean);
    }
    for root in [
        &operation.plan.source.endpoint.name,
        &operation.plan.destination.name().to_owned(),
    ] {
        for (name, props) in clean
            .dataset_properties
            .iter_mut()
            .filter(|(name, _)| history::contains_dataset(root, name))
        {
            let keys: Vec<_> = props.keys().cloned().collect();
            for key in keys {
                let p = &props[&key];
                let source = if name == root {
                    "local".into()
                } else {
                    format!("inherited from {root}")
                };
                if key == management::PENDING_PROPERTY && p.value == *pair_id {
                    if p.source != source {
                        return Err(refuse("nested pair pending source changed"));
                    }
                    props.remove(&key);
                }
            }
        }
    }
    Ok(clean)
}
/// A bootstrap's nested pair as the pair executor sees it: native state
/// without this transfer's own control metadata, and the transfer's record,
/// which keeps the pair's phases.
struct NestedPair<'a, B, R> {
    backend: &'a mut B,
    record: &'a mut R,
    operation: &'a mut TransferOperation,
    id: &'a str,
}
impl<B: TransferBackend, R: Record> NestedPair<'_, B, R> {
    /// Record that the nested pair reached PHASE: one advance of the
    /// transfer's record, none for a phase it already records.
    fn reached(&mut self, phase: plan::Phase) -> Result<(), Error> {
        if self.operation.progress.pair_phase < Some(phase) {
            self.operation.progress.pair_phase = Some(phase);
            save(self.record, self.operation, self.backend)?;
        }
        Ok(())
    }
}
impl<B: TransferBackend, R> HistoryBackend for NestedPair<'_, B, R> {
    fn written(
        &mut self,
        dataset: &zfs_tools::engine::Dataset,
        point: &SnapshotRef,
    ) -> Result<u64, Error> {
        self.backend.written(dataset, point)
    }
    fn ivset(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Guid, Error> {
        self.backend.ivset(point)
    }
}
impl<B: TransferBackend, R> PairBackend for NestedPair<'_, B, R> {
    fn observe(&mut self) -> Result<NativeState, Error> {
        clean_parent_state(
            &PairBackend::observe(self.backend)?,
            self.operation,
            self.id,
        )
    }
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<BTreeMap<String, NativeProperty>, Error> {
        self.backend.properties(endpoint)
    }
    fn sync(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.backend.sync(endpoint)
    }
    fn set_property(&mut self, endpoint: &Endpoint, value: &PropertyValue) -> Result<(), Error> {
        self.backend.set_property(endpoint, value)
    }
    fn inherit_property(
        &mut self,
        endpoint: &Endpoint,
        key: PropertyKey,
        expected: &str,
    ) -> Result<Option<NativeProperty>, Error> {
        self.backend.inherit_property(endpoint, key, expected)
    }
    fn observe_point(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Snapshot, Error> {
        self.backend.observe_point(point)
    }
    fn unmount(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.backend.unmount(endpoint)
    }
    fn add_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
        self.backend.add_hold(point, tag)
    }
    fn running_root(&mut self) -> Result<Option<String>, Error> {
        self.backend.running_root()
    }
}
/// Remove this transfer's pending markers when activation begins or, with
/// STAGING, the receiver's staging marker at its end: the staging marker keeps
/// every other command off the receiver until the record is released.
fn clear_markers(
    operation: &TransferOperation,
    id: &str,
    backend: &mut impl TransferBackend,
    staging: bool,
) -> Result<(), Error> {
    let target = operation
        .received
        .as_ref()
        .ok_or_else(|| refuse("cannot clear markers before verified adoption"))?;
    let markers = if staging {
        vec![(target, vec![PropertyKey::Staging])]
    } else {
        vec![
            (&operation.plan.source, vec![PropertyKey::Pending]),
            (target, vec![PropertyKey::Pending]),
        ]
    };
    for (tree, keys) in markers {
        for member in tree.members.values().rev() {
            for key in &keys {
                let props = backend.properties(&member.bound.endpoint)?;
                if let Some(p) = props.get(key.native()) {
                    if p.value != id {
                        if *key == PropertyKey::Pending
                            && operation.plan.bootstrap_pair_id.as_deref() == Some(p.value.as_str())
                        {
                            let expected = if member.bound.endpoint == tree.endpoint {
                                "local".into()
                            } else {
                                format!("inherited from {}", tree.endpoint.name)
                            };
                            if p.source == expected && operation.progress.pair_phase.is_some() {
                                continue;
                            }
                        }
                        return Err(refuse("cleanup encountered a different operation marker"));
                    }
                    if p.source == "local" {
                        let revealed =
                            backend.inherit_property(&member.bound.endpoint, *key, id)?;
                        if revealed.as_ref().is_some_and(|p| p.value != id) {
                            return Err(refuse("cleanup revealed a different inherited operation"));
                        }
                    }
                }
            }
        }
        for member in tree.members.values() {
            let props = backend.properties(&member.bound.endpoint)?;
            for key in &keys {
                if props.get(key.native()).is_some_and(|p| p.value == id) {
                    return Err(refuse("owned transfer marker remains after cleanup"));
                }
            }
        }
    }
    Ok(())
}
fn release_exact(
    point: &SnapshotRef,
    tag: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let before = backend.observe_point(point)?;
    if before.point() != *point {
        return Err(refuse("hold cleanup snapshot incarnation changed"));
    }
    if !before.holds.iter().any(|held| held == tag) {
        return Ok(());
    }
    if before.defer_destroy {
        return Err(refuse(
            "hold cleanup would complete deferred deletion; protection retained",
        ));
    }
    let error = backend.release_hold(point, tag).err();
    let after = backend.observe_point(point)?;
    if after.point() != *point || after.holds.iter().any(|held| held == tag) {
        return Err(error.unwrap_or_else(|| refuse("temporary hold release was not verified")));
    }
    Ok(())
}
fn rotate_anchors(
    operation: &TransferOperation,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let Some(record) = &operation.plan.source_pair else {
        return Ok(());
    };
    let tag = format!("zboot:anchor:{}", record.pair_id);
    let target = operation.received.as_ref().unwrap();
    let mut newest = BTreeSet::new();
    for (relative, source) in &operation.plan.source.members {
        for point in [
            source.bound.snapshots.last().unwrap(),
            target.members[relative].bound.snapshots.last().unwrap(),
        ] {
            protect(point, &tag, backend)?;
            newest.insert(point.name.clone());
        }
    }
    // All newer anchors are verified before any old common protection can end.
    for point in operation
        .plan
        .source
        .members
        .values()
        .chain(target.members.values())
        .flat_map(|member| &member.bound.snapshots)
        .filter(|point| !newest.contains(&point.name))
    {
        let current = backend.observe_point(point)?;
        if !current.defer_destroy && current.holds.iter().any(|held| held == &tag) {
            release_exact(point, &tag, backend)?;
        }
    }
    Ok(())
}
/// Which end of a native stream failed, how, and its last error line, in
/// words: `zfs receive exited with exit status: 1 (cannot receive incremental
/// stream: out of space); zfs send ended with signal: 9 (SIGKILL)`.
fn stream_failure(outcome: &zfs_tools::engine::stream::StreamOutcome) -> String {
    let last = |stderr: &str| {
        stderr
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(|line| format!(" ({})", line.trim()))
            .unwrap_or_default()
    };
    let mut parts = Vec::new();
    if !outcome.receiver_success {
        parts.push(format!(
            "zfs receive exited with {}{}",
            outcome.receiver_status,
            last(&outcome.receiver_stderr)
        ));
    }
    if !outcome.sender_success {
        parts.push(format!(
            "zfs send ended with {}{}",
            outcome.sender_status,
            last(&outcome.sender_stderr)
        ));
    }
    if parts.is_empty() {
        parts.push("the stream did not complete".into());
    }
    if outcome.output_truncated {
        parts.push("their output was cut short".into());
    }
    parts.join("; ")
}

#[cfg(test)]
#[test]
fn a_failed_stream_is_described_in_words() {
    let outcome = zfs_tools::engine::stream::StreamOutcome {
        sender_success: false,
        receiver_success: false,
        sender_status: "signal: 9 (SIGKILL)".into(),
        receiver_status: "exit status: 1".into(),
        sender_stderr: String::new(),
        receiver_stderr: "cannot receive incremental stream: out of space\n".into(),
        output_truncated: false,
    };
    assert_eq!(
        stream_failure(&outcome),
        "zfs receive exited with exit status: 1 (cannot receive incremental stream: out of \
         space); zfs send ended with signal: 9 (SIGKILL)"
    );
}

/// Send what the destination lacks, decided from native state: a full stream
/// of the source's first snapshot when the destination does not exist yet,
/// then one incremental from its newest snapshot to the boundary. A retry
/// recomputes both; OpenZFS discards a receive that a crash cut.
fn run_streams(
    operation: &TransferOperation,
    destination: &str,
    backend: &mut impl TransferBackend,
) -> Result<(), Error> {
    let source = &operation.plan.source.members[""];
    let points = &source.bound.snapshots;
    let run = |stream: LeafStream, backend: &mut _| -> Result<(), Error> {
        let outcome = TransferBackend::stream(backend, &stream)?;
        if outcome.complete() {
            Ok(())
        } else {
            Err(refuse(format!(
                "native stream failed: {}",
                stream_failure(&outcome)
            )))
        }
    };
    let state = PairBackend::observe(backend)?;
    let exists = state
        .inspection
        .datasets
        .iter()
        .any(|d| d.name == destination);
    if exists && operation.plan.destination.existing().is_none() {
        // A new copy continued after a cut: its blocks so far were written
        // with the values it was created with, and the rest must be too.
        let want = props::creation(source, &backend.properties(&source.bound.endpoint)?)?;
        let have = backend.properties(&endpoint(&state, destination)?)?;
        for (key, value) in want.iter().filter(|(key, _)| props::write_time(key)) {
            let held = have.get(key).map(|p| p.value.as_str()).unwrap_or("");
            if held != value {
                return Err(refuse(format!(
                    "the new copy {destination} has {key}={held}, not the {value} it was \
                     created with, so its blocks would mix both; abandon this sync and sync \
                     again"
                )));
            }
        }
    }
    if !exists {
        if operation.plan.destination.existing().is_some() {
            return Err(refuse("existing destination disappeared before its stream"));
        }
        let first = points
            .first()
            .ok_or_else(|| refuse("source has no snapshot to send"))?;
        let create = creation_properties(operation, backend)?;
        run(
            LeafStream {
                source: source.bound.endpoint.clone(),
                base: None,
                boundary: first.clone(),
                destination: destination.into(),
                create,
            },
            backend,
        )?;
    }
    let have = copy_snapshots(&PairBackend::observe(backend)?, destination);
    let newest = have
        .last()
        .ok_or_else(|| refuse("destination has no snapshot after its stream"))?;
    let at = points
        .iter()
        .position(|p| p.identity.guid == newest.identity.guid)
        .ok_or_else(|| {
            refuse("destination's newest snapshot is not in the frozen source history")
        })?;
    if at + 1 < points.len() {
        run(
            LeafStream {
                source: source.bound.endpoint.clone(),
                base: Some(points[at].clone()),
                boundary: operation.plan.boundary.clone(),
                destination: destination.into(),
                create: vec![],
            },
            backend,
        )?;
    }
    Ok(())
}
/// Local values a new copy takes at creation: an inactive `canmount` and
/// every copied property the source sets, so write-time settings govern its
/// first blocks. Space limits wait until after data.
fn creation_properties(
    operation: &TransferOperation,
    backend: &mut impl TransferBackend,
) -> Result<Vec<(String, String)>, Error> {
    let source = &operation.plan.source.members[""];
    let mut values = Vec::new();
    if source.kind == history::Kind::Filesystem {
        values.push(("canmount".into(), "noauto".into()));
    }
    values.extend(props::creation(
        source,
        &backend.properties(&source.bound.endpoint)?,
    )?);
    Ok(values)
}
/// Give the copy its source's copied properties: before data on an existing
/// copy, so write-time keys govern the received blocks, and after data on
/// every copy, with space limits that tighten. Returns the space limits the
/// copy could not take, for attention.
fn copy_properties(
    operation: &TransferOperation,
    destination: &str,
    when: props::When,
    id: &str,
    backend: &mut impl TransferBackend,
) -> Result<Vec<String>, Error> {
    let frozen = &operation.plan.source.members[""];
    let state = PairBackend::observe(backend)?;
    let target = endpoint(&state, destination)?;
    let source = backend.properties(&frozen.bound.endpoint)?;
    let copy = backend.properties(&target)?;
    let changes = props::changes(frozen, &source, &copy, when)?;
    if when == props::When::BeforeData
        && let Some(existing) = operation.plan.destination.existing()
        && let Some((key, _)) = changes.iter().find(|(key, _)| props::write_time(key))
        && history_of(&copy_snapshots(&state, destination))?
            != history_of(&existing.members[""].bound.snapshots)?
    {
        return Err(refuse(format!(
            "{destination} received data of this transfer while its {key} differed from \
             the source's; those blocks keep the old setting. Copy the dataset again"
        )));
    }
    let mut failed = Vec::new();
    for (key, value) in &changes {
        match backend.copy_property(&target, key, value.as_deref(), id) {
            Ok(()) => {}
            Err(_) if when == props::When::AfterData && props::space(key) => {
                failed.push(key.clone());
            }
            Err(error) => return Err(error),
        }
    }
    let copy = backend.properties(&target)?;
    for (key, value) in props::materialize(frozen, &source, &copy)? {
        backend.copy_property(&target, &key, value.as_deref(), id)?;
    }
    let now = backend.properties(&frozen.bound.endpoint)?;
    if props::changes(frozen, &now, &BTreeMap::new(), props::When::AfterData).is_err() {
        return Err(refuse(
            "the source's properties changed during this transfer; run it again",
        ));
    }
    Ok(failed)
}
fn copy_snapshots(state: &NativeState, dataset: &str) -> Vec<SnapshotRef> {
    let mut found: Vec<_> = state
        .inspection
        .snapshots
        .as_ref()
        .unwrap()
        .iter()
        .filter(|s| s.name.split_once('@').map(|(n, _)| n) == Some(dataset))
        .map(|s| s.point())
        .collect();
    found.sort_by_key(|p| p.identity.createtxg);
    found
}
fn execute(
    record: &mut impl Record,
    operation: &mut TransferOperation,
    backend: &mut impl TransferBackend,
) -> Result<TransferOutcome, Error> {
    let id = record.id().to_owned();
    let id = id.as_str();
    valid_id(id)?;
    validate(operation, id)?;
    let state = PairBackend::observe(backend)?;
    // The receiver keeps its recorded identity, checked before any effect.
    if let Some(receiver) = operation
        .plan
        .destination
        .existing()
        .map(|tree| &tree.endpoint)
        .or(operation.progress.received.as_ref().map(|r| &r.endpoint))
        && endpoint(&state, &receiver.name).ok().as_ref() != Some(receiver)
    {
        let pool = pool_of(&receiver.name);
        if !state.inspection.pools.iter().any(|p| p.name == pool) {
            return Err(refuse(format!(
                "pool {pool} of the destination {} is not imported; import it to continue",
                receiver.name
            )));
        }
        return Err(refuse(
            "transfer destination no longer has its recorded identity",
        ));
    }
    if operation.progress.phase != Phase::Complete {
        verify_receive_destinations(&state, operation)?;
    }
    if operation.progress.phase < Phase::Activating {
        refuse_running(&request(&operation.plan), backend)?;
    }
    verify_source(&PairBackend::observe(backend)?, operation, id, backend)?;
    if operation.progress.phase < Phase::Received {
        backend.set_property(
            &operation.plan.source.endpoint,
            &PropertyValue::Pending(id.into()),
        )?;
        if let Some(target) = operation.plan.destination.existing() {
            backend.set_property(&target.endpoint, &PropertyValue::Pending(id.into()))?;
            backend.set_property(&target.endpoint, &PropertyValue::Staging(id.into()))?;
        }
        let tag = format!("zboot:transfer:{id}");
        for point in operation
            .plan
            .source
            .members
            .values()
            .flat_map(|member| &member.bound.snapshots)
        {
            protect(point, &tag, backend)?;
        }
        backend.sync(&operation.plan.source.endpoint)?;
        if operation.progress.phase < Phase::Protected {
            operation.progress.phase = Phase::Protected;
            save(record, operation, backend)?;
        }
        let receive_destination = receive::prepare(record, operation, id, backend)?;
        let finished = receive::finish(record, operation, id, backend, false)?;
        if finished {
            reconcile_external(operation, id, backend)?;
        }
        // Native GUID completeness alone cannot prove post-ioctl snapshot
        // metadata. Only the durable compound-completion/adoption checkpoint
        // permits these complete-result fast paths.
        if finished && operation.progress.phase >= Phase::Fenced {
            let probe = PairBackend::observe(backend)?;
            if verify_received_mode(&probe, operation, id, backend, false).is_ok() {
                reconcile_external(operation, id, backend)?;
            }
        }
        let before = PairBackend::observe(backend)?;
        let complete = if finished {
            verify_received(&before, operation, id, backend).ok()
        } else {
            None
        };
        let received = if let Some(received) = complete {
            received
        } else {
            // receive::prepare fenced an existing destination, and an adopted
            // one was fenced before adoption; verify_fenced below rechecks it.
            verify_original_target(&before, operation, id, backend)?;
            if operation.progress.phase < Phase::Fenced {
                operation.progress.phase = Phase::Fenced;
                save(record, operation, backend)?;
            }
            let current = PairBackend::observe(backend)?;
            verify_source(&current, operation, id, backend)?;
            verify_original_target(&current, operation, id, backend)?;
            verify_holds(&operation.plan, id, backend)?;
            if let Some(target) = operation.plan.destination.existing() {
                verify_fenced(&current, target)?;
                boot_policy::preserve_existing(operation, id, backend)?;
                copy_properties(
                    operation,
                    &target.endpoint.name,
                    props::When::BeforeData,
                    id,
                    backend,
                )?;
                prove_wrapping(operation, backend)?;
            }
            if operation.plan.base.as_ref() == Some(&operation.plan.boundary) {
                verify_received(&PairBackend::observe(backend)?, operation, id, backend)?
            } else {
                let stream_result = run_streams(operation, &receive_destination, backend);
                let finished =
                    receive::finish(record, operation, id, backend, true).map_err(|error| {
                        let stream = match &stream_result {
                            Ok(()) => "native stream completed".to_owned(),
                            Err(error) => error.to_string(),
                        };
                        refuse(format!("{stream}; destination remains fenced: {error}"))
                    })?;
                stream_result?;
                if !finished {
                    return Err(refuse(
                        "native stream did not produce the complete fenced copy",
                    ));
                }
                let after = PairBackend::observe(backend)?;
                let destination = endpoint(&after, operation.plan.destination.name())?;
                backend.sync(&destination)?;
                let synced = PairBackend::observe(backend)?;
                verify_source(&synced, operation, id, backend)?;
                reconcile_external(operation, id, backend)?;
                let synced = PairBackend::observe(backend)?;
                verify_received(&synced, operation, id, backend).map_err(|error| {
                    refuse(format!(
                        "destination remains fenced for reconciliation: {error}"
                    ))
                })?
            }
        };
        operation.progress.received = Some(Received {
            endpoint: received.endpoint.clone(),
            digest: identity_digest(&received)?,
        });
        if operation.plan.bootstrap_pair_id.is_some() {
            // Written while the record names no pair plan, just before the
            // advance that names it; from then on it is read, never
            // recomputed, as a key the record names is never rewritten.
            let pair = bootstrap_pair_plan(&operation.plan, &received)?;
            operation.progress.pair = Some(write_attachment(record, PAIR, &pair, backend)?);
            operation.pair_plan = Some(pair);
        }
        operation.received = Some(received);
        operation.progress.phase = Phase::Received;
        save(record, operation, backend)?;
    }
    if operation.progress.phase == Phase::Received {
        operation.received = Some(verify_received(
            &PairBackend::observe(backend)?,
            operation,
            id,
            backend,
        )?);
        fence(operation.received.as_ref().unwrap(), backend)?;
        operation.progress.phase = Phase::Activating;
        // Activation intent is durable before nested pair publication or enabling writes.
        save(record, operation, backend)?;
    }
    if operation.progress.phase == Phase::Activating {
        verify_source(&PairBackend::observe(backend)?, operation, id, backend)?;
        operation.received = Some(verify_received(
            &PairBackend::observe(backend)?,
            operation,
            id,
            backend,
        )?);
        verify_holds(&operation.plan, id, backend)?;
        clear_markers(operation, id, backend, false)?;
        if let Some(pair_id) = operation.plan.bootstrap_pair_id.clone() {
            let pair_plan = operation.pair_plan.clone().unwrap();
            let recorded = operation.progress.pair_phase;
            let mut nested = NestedPair {
                backend,
                record,
                operation,
                id,
            };
            plan::apply_with_id(
                &pair_plan,
                &pair_id,
                recorded,
                &mut nested,
                &mut |nested: &mut NestedPair<_, _>, phase| nested.reached(phase),
            )?;
        } else {
            let clean = clean_state(&PairBackend::observe(backend)?, operation, id)?;
            verify_existing_pair(&clean, &operation.plan)?;
            rotate_anchors(operation, backend)?;
            // The secondary stays fenced with what it received.
            verify_fenced(
                &PairBackend::observe(backend)?,
                operation.received.as_ref().unwrap(),
            )?;
        }
        receive::retire(record, operation, id, backend)?;
        operation.progress.phase = Phase::Complete;
        save(record, operation, backend)?;
    }
    let state = PairBackend::observe(backend)?;
    verify_source(&state, operation, id, backend)?;
    operation.received = Some(verify_received(&state, operation, id, backend)?);
    let clean = clean_state(&state, operation, id)?;
    management::ownership(&clean, &operation.plan.source.endpoint.name)?;
    management::ownership(&clean, operation.plan.destination.name())?;
    let tag = format!("zboot:transfer:{id}");
    for point in operation
        .plan
        .source
        .members
        .values()
        .flat_map(|member| &member.bound.snapshots)
    {
        release_exact(point, &tag, backend)?;
    }
    // Released names no attachment and verifies nothing more: a cut during
    // the removal leaves only chunks nothing names. The copy keeps this
    // transfer's staging marker until it is recorded, so no other command
    // acts on the copy while the record still verifies it.
    let released = TransferProgress {
        received: operation.progress.received.clone(),
        ..TransferProgress::ended(Phase::Released)
    };
    if record.transfer() != Some(&released) {
        record.advance(backend, released.clone())?;
    }
    clear_markers(operation, id, backend, true)?;
    discard(record, backend)?;
    // The operation as recorded now: its plan named no more.
    operation.progress = released;
    let copy = &operation.received.as_ref().unwrap().endpoint;
    let held = backend.properties(copy)?;
    props::verify(&operation.plan.source.members[""], &held)?;
    // The limits the copy does not hold now, by the rule `status` and the
    // `primary` plan use, so the three agree.
    let wanted = backend.properties(&operation.plan.source.endpoint)?;
    let unapplied = props::unheld_space(&wanted, &held)
        .into_iter()
        .map(|(key, ..)| key.to_owned())
        .collect();
    Ok(TransferOutcome {
        unapplied,
        operation_id: id.into(),
        source: operation.plan.source.endpoint.clone(),
        destination: Some(copy.clone()),
        status: TransferStatus::Complete,
        completed_operation: Some(operation.clone()),
        capture: None,
        unmirrored: unmirrored(
            &state,
            &operation.plan.source.endpoint.name,
            operation.plan.destination.name(),
        ),
        pair_id: operation.plan.bootstrap_pair_id.clone().or_else(|| {
            operation
                .plan
                .source_pair
                .as_ref()
                .map(|record| record.pair_id.clone())
        }),
    })
}

#[cfg(test)]
pub(crate) mod tests;
