use super::*;
use crate::pairs::{Journal, Recorded, Transferring};
const ID: &str = "11111111-1111-4111-8111-111111111111";
const PAIR_ID: &str = "22222222-2222-4222-8222-222222222222";

#[test]
fn transfer_fake_enforces_the_native_attachment_namespace() {
    let mut fake = Fake::new(false);
    let ep = endpoint(&fake.native.state().unwrap(), "a/data").unwrap();
    for key in ["mountpoint", "zboot:cmdline"] {
        assert!(
            fake.attachments()
                .set(&ep, &[(key.into(), "1".into())])
                .unwrap_err()
                .to_string()
                .contains("outside attachment namespace")
        );
    }
    let chunk = format!("{}0000", key(ID, PLAN).unwrap().prefix());
    fake.attachments()
        .set(&ep, &[(chunk, "00".into())])
        .unwrap();
}

#[test]
fn typed_mountpoint_set_never_runs_a_native_mount_changelist() {
    for noauto in [false, true] {
        let mut fake = Fake::new(false);
        let ep = endpoint(&fake.native.state().unwrap(), "b/data").unwrap();
        fake.native.mounted.remove(&ep.name);
        fake.set_property(&ep, &PropertyValue::Readonly(true))
            .unwrap();
        if noauto {
            fake.set_property(&ep, &PropertyValue::Canmount(MountMode::NoAuto))
                .unwrap();
        }
        fake.set_property(&ep, &PropertyValue::Mountpoint("/".into()))
            .unwrap();
        let state = fake.native.state().unwrap();
        let received = state
            .inspection
            .datasets
            .iter()
            .find(|d| d.name == ep.name)
            .unwrap();
        assert!(received.readonly);
        assert_eq!(received.mounted, Some(false));
    }
}

fn boot_fixture(bootstrap: bool) -> Fake {
    let mut fake = Fake::new(bootstrap);
    for name in if bootstrap {
        vec!["a/data"]
    } else {
        vec!["a/data", "b/data"]
    } {
        let ep = fake
            .native
            .members
            .iter()
            .find(|m| m.endpoint.name == name)
            .unwrap()
            .endpoint
            .clone();
        fake.native
            .set(
                &ep,
                &[
                    ("mountpoint".into(), "/".into()),
                    ("canmount".into(), "noauto".into()),
                ],
            )
            .unwrap();
        if name == "b/data" {
            fake.native
                .mounted
                .retain(|name| !history::contains_dataset("b/data", name));
            fake.native
                .properties
                .get_mut(name)
                .unwrap()
                .get_mut("mountpoint")
                .unwrap()
                .source = "received".into();
        }
    }
    fake
}

#[test]
fn boot_peer_survives_bootstrap_incremental_transfer() {
    let mut fake = Fake::new(true);
    let source = fake
        .native
        .members
        .iter()
        .find(|m| m.endpoint.name == "a/data")
        .unwrap()
        .endpoint
        .clone();
    fake.native
        .set(
            &source,
            &[
                ("mountpoint".into(), "/".into()),
                ("canmount".into(), "noauto".into()),
                ("zboot:cmdline".into(), "console=ttyS0".into()),
            ],
        )
        .unwrap();
    let request = TransferRequest {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    transfer_with(&request, &mut fake).unwrap();
    let state = fake.native.state().unwrap();
    let peer = endpoint(&state, "b/data").unwrap();
    let props = fake.properties(&peer).unwrap();
    assert_eq!(
        props["mountpoint"],
        NativeProperty {
            value: "/".into(),
            source: "local".into()
        }
    );
    // The peer's explicit boot policy wins over later source policy changes.
    fake.native
        .set(&peer, &[("zboot:cmdline".into(), "console=ttyS1".into())])
        .unwrap();
    // A peer whose mountpoint is received, as `zfs receive` of a stream with
    // properties leaves it.
    fake.native
        .properties
        .get_mut("b/data")
        .unwrap()
        .get_mut("mountpoint")
        .unwrap()
        .source = "received".into();
    transfer_with(&request, &mut fake).unwrap();
    // An existing copy's mountpoint is never touched by a receive: a property-
    // free stream cannot clear it, and changing it would remount children.
    assert_eq!(
        fake.properties(&peer).unwrap()["mountpoint"].source,
        "received"
    );
    assert_eq!(
        fake.properties(&peer).unwrap()["zboot:cmdline"].value,
        "console=ttyS1"
    );
}

#[test]
fn a_changed_destination_boot_policy_refuses_before_any_stream() {
    let mut fake = boot_fixture(false);
    let plan = fake.prepare();
    let peer = plan.destination.existing().unwrap().endpoint.clone();
    fake.native
        .set(&peer, &[("zboot:cmdline".into(), "console=ttyS2".into())])
        .unwrap();
    assert!(fake.run(plan).is_err());
    assert_eq!(fake.streams, 0);
    assert_eq!(
        fake.properties(&peer).unwrap()["zboot:cmdline"].value,
        "console=ttyS2"
    );
}

#[derive(Clone)]
pub(crate) struct Fake {
    pub(crate) native: plan::tests::Fake,
    pub(crate) primary_mode: bool,
    markers: BTreeMap<String, String>,
    pub(crate) streams: usize,
    partial_stream: bool,
    partial_member_snapshots: Option<usize>,
    snapshot_properties: BTreeMap<String, BTreeMap<String, String>>,
    observed_streams: Vec<LeafStream>,
    /// Every copied-property change, in order.
    copied_properties: Vec<(String, Option<String>)>,
    /// Keys whose native set fails, as a quota below usage does.
    refuse_copied: BTreeSet<String>,
    /// Key wrapping per encryption root; absent roots use `Fake::wrapped`.
    wrappings: BTreeMap<String, Wrapping>,
    /// (root, location) pairs where `load-key -n -L location` succeeds.
    key_files: BTreeSet<(String, String)>,
    first_stream_effect: Option<usize>,
    volume_nodes: BTreeSet<String>,
    keep_volume_node: bool,
    received_layers: BTreeMap<String, BTreeMap<String, String>>,
    altroots: BTreeMap<String, String>,
    inherit_routes: Vec<(usize, String, PropertyKey, bool)>,
    cmdline_setters: usize,
    /// Snapshot renames, (old name, new name), in order.
    pub(crate) renamed: Vec<(String, String)>,
    /// Destroyed snapshots, in order.
    pub(crate) destroyed: Vec<String>,
    /// Attachment and record writes, each with the effect number it took.
    pub(crate) writes: Vec<(usize, Write)>,
}
/// A write the commit points of a transfer are made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Write {
    /// Chunks set on a dataset: their slot and count.
    Chunks(String, usize),
    /// One chunk removed: its slot.
    Removed(String),
    /// A record written: its transfer's phase, if it records one.
    Record(Option<Phase>),
    /// A record cleared.
    Cleared,
}
impl Fake {
    /// The leaf fixture: `a/data` is the working copy. With `bootstrap` the
    /// destination is absent; otherwise `b/data` is its fenced pair peer, one
    /// snapshot behind, holding the shared anchor.
    pub(crate) fn new(bootstrap: bool) -> Self {
        let mut fake = Self::unpaired(bootstrap);
        if !bootstrap {
            fake.pair("a/data", "b/data");
        }
        fake
    }
    /// Pair SOURCE (working) with DESTINATION (fenced), as `pair` leaves them.
    pub(crate) fn pair(&mut self, source: &str, destination: &str) {
        let state = self.native.state().unwrap();
        let record = PairRecord {
            schema_version: 1,
            pair_id: PAIR_ID.into(),
            endpoint: endpoint(&state, source).unwrap(),
            peer: endpoint(&state, destination).unwrap(),
            role: Role::Primary,
        };
        for pair in [record.clone(), record.counterpart()] {
            self.native
                .set(
                    &pair.endpoint,
                    &[(management::PAIR_PROPERTY.into(), pair.encode().unwrap())],
                )
                .unwrap();
        }
        let member = self
            .native
            .members
            .iter()
            .find(|m| m.endpoint.name == destination)
            .cloned()
            .unwrap();
        let mut fences = vec![
            PropertyValue::Placement(member.placement.clone()),
            PropertyValue::Readonly(true),
        ];
        if member.placement.canmount.is_some() {
            fences.push(PropertyValue::Canmount(MountMode::NoAuto));
        }
        for value in fences {
            self.set_property(&member.endpoint, &value).unwrap();
        }
        self.native.mounted.remove(destination);
        let tag = format!("zboot:anchor:{PAIR_ID}");
        for name in [source, destination] {
            let anchor = self
                .native
                .members
                .iter()
                .find(|m| m.endpoint.name == name)
                .and_then(|m| m.snapshots.last())
                .map(|p| p.name.clone())
                .unwrap();
            self.native
                .holds
                .entry(anchor)
                .or_default()
                .insert(tag.clone());
        }
        self.native.effects = 0;
    }
    /// The leaf fixture with volumes in place of filesystems.
    pub(crate) fn volumes(bootstrap: bool) -> Self {
        let mut fake = Self::unpaired(bootstrap);
        for member in &mut fake.native.members {
            member.placement.canmount = None;
            member.mountpoint = None;
        }
        fake.native.mounted.clear();
        if !bootstrap {
            fake.pair("a/data", "b/data");
        }
        fake
    }
    /// A passphrase wrapping with SALT.
    pub(crate) fn wrapped(salt: &str) -> Wrapping {
        Wrapping {
            keyformat: "passphrase".into(),
            keylocation: "prompt".into(),
            pbkdf2iters: "350000".into(),
            pbkdf2salt: salt.into(),
        }
    }
    pub(crate) fn unpaired(bootstrap: bool) -> Self {
        let mut native = plan::tests::Fake::new();
        if bootstrap {
            native
                .members
                .retain(|m| !history::contains_dataset("b/data", &m.endpoint.name));
            native
                .mounted
                .retain(|name| !history::contains_dataset("b/data", name));
        }
        Self {
            native,
            primary_mode: false,
            markers: BTreeMap::new(),
            streams: 0,
            partial_stream: false,
            partial_member_snapshots: None,
            snapshot_properties: BTreeMap::new(),
            observed_streams: vec![],
            copied_properties: vec![],
            refuse_copied: BTreeSet::new(),
            wrappings: BTreeMap::new(),
            key_files: BTreeSet::new(),
            first_stream_effect: None,
            volume_nodes: BTreeSet::new(),
            keep_volume_node: false,
            received_layers: BTreeMap::new(),
            altroots: BTreeMap::new(),
            inherit_routes: vec![],
            cmdline_setters: 0,
            renamed: vec![],
            destroyed: vec![],
            writes: vec![],
        }
    }
    fn prepare(&mut self) -> TransferPlan {
        CaptureBackend::snapshot(self, &["a/data@next".into()], ID).unwrap();
        self.native.effects = 0;
        plan_with(
            &PairBackend::observe(self).unwrap(),
            &TransferRequest {
                source: "a/data".into(),
                destination: "b/data".into(),
            },
            ID,
            self,
        )
        .unwrap()
    }
    /// Begin this test's record of operation ID on a/data's pool, as a sync
    /// does before its transfer.
    pub(crate) fn record(&mut self) -> Result<Journal<Standalone>, Error> {
        let holder = endpoint(&self.native.state()?, "a/data")?;
        Journal::begin(
            self,
            ID,
            "transfer",
            Standalone {
                holder,
                transfer: None,
            },
        )
    }
    /// The record as a new process reads it, if one survived.
    pub(crate) fn recorded(&mut self) -> Option<Journal<Standalone>> {
        let value = intent::Backend::read(self, "a").unwrap()?;
        Some(Journal::decode(serde_json::from_str(&value).unwrap()).unwrap())
    }
    /// Record PLAN and run it, as a caller does; the record is left at
    /// `Released`, where only the caller's own tail remains.
    fn run(&mut self, plan: TransferPlan) -> Result<TransferOutcome, Error> {
        let mut record = self.record()?;
        begin(&mut record, plan, self)
    }
    /// The attachment chunk properties on every dataset.
    pub(crate) fn chunks(&self) -> Vec<(String, String)> {
        self.native
            .properties
            .iter()
            .flat_map(|(name, props)| {
                props
                    .keys()
                    .filter(|key| key.starts_with(attachment::PREFIX))
                    .map(move |key| (name.clone(), key.clone()))
            })
            .collect()
    }
}
/// A transfer test's own record: one per run, on the source's pool, with
/// the transfer alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Standalone {
    holder: Endpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transfer: Option<TransferProgress>,
}
impl Recorded for Standalone {
    fn pool(&self) -> String {
        pool_of(&self.holder.name).into()
    }
}
impl Transferring for Standalone {
    fn holder(&self) -> &Endpoint {
        &self.holder
    }
    fn transfer(&self) -> Option<&TransferProgress> {
        self.transfer.as_ref()
    }
    fn set_transfer(&mut self, transfer: Option<TransferProgress>) {
        self.transfer = transfer;
    }
}
/// Transfer REQUEST under a new record, then clear it, as a sync does:
/// admitted before the record is written.
fn transfer_with(request: &TransferRequest, fake: &mut Fake) -> Result<TransferOutcome, Error> {
    admit_with(request, fake)?;
    let mut record = fake.record()?;
    let outcome = transfer_with_id(request, &mut record, fake)?;
    record.finish(fake)?;
    Ok(outcome)
}
/// The attachment chunks of the transfer's own keys on one dataset, as
/// the native backend sees them.
pub(crate) struct Chunks<'a>(&'a mut Fake);
impl AttachmentBackend for Chunks<'_> {
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<BTreeMap<String, NativeProperty>, Error> {
        PairBackend::properties(self.0, endpoint)
    }
    fn set(&mut self, endpoint: &Endpoint, values: &[(String, String)]) -> Result<(), Error> {
        attachment::validate_set(values)?;
        let slot = values[0].0.split(':').nth(3).unwrap_or_default().to_owned();
        let result = self.0.native.set(endpoint, values);
        self.0
            .writes
            .push((self.0.native.effects, Write::Chunks(slot, values.len())));
        result
    }
    fn inherit(&mut self, endpoint: &Endpoint, property: &str) -> Result<(), Error> {
        if !property.starts_with(attachment::PREFIX) {
            return Err(refuse("property outside attachment namespace"));
        }
        let slot = property.split(':').nth(3).unwrap_or_default().to_owned();
        let result = self.0.native.inherit(endpoint, property);
        self.0
            .writes
            .push((self.0.native.effects, Write::Removed(slot)));
        result
    }
}
impl intent::Backend for Fake {
    fn pools(&mut self) -> Result<Vec<String>, Error> {
        self.native.alive()?;
        Ok(self
            .native
            .members
            .iter()
            .filter(|m| !m.endpoint.name.contains('/'))
            .map(|m| m.endpoint.name.clone())
            .collect())
    }
    fn read(&mut self, pool: &str) -> Result<Option<String>, Error> {
        self.native.alive()?;
        Ok(self
            .native
            .properties
            .get(pool)
            .and_then(|p| p.get(intent::PROPERTY))
            .filter(|p| p.source == "local")
            .map(|p| p.value.clone()))
    }
    fn write(&mut self, pool: &str, value: &str) -> Result<(), Error> {
        self.native.before()?;
        self.native
            .properties
            .entry(pool.into())
            .or_default()
            .insert(
                intent::PROPERTY.into(),
                NativeProperty {
                    value: value.into(),
                    source: "local".into(),
                },
            );
        let phase = serde_json::from_str::<serde_json::Value>(value)
            .ok()
            .and_then(|record| record["state"].get("transfer").cloned())
            .and_then(|transfer| serde_json::from_value::<TransferProgress>(transfer).ok())
            .map(|transfer| transfer.phase);
        self.writes
            .push((self.native.effects, Write::Record(phase)));
        self.native.after()
    }
    fn remove(&mut self, pool: &str) -> Result<(), Error> {
        self.native.before()?;
        if let Some(p) = self.native.properties.get_mut(pool) {
            p.remove(intent::PROPERTY);
        }
        self.writes.push((self.native.effects, Write::Cleared));
        self.native.after()
    }
}
impl HistoryBackend for Fake {
    fn written(
        &mut self,
        dataset: &zfs_tools::engine::Dataset,
        point: &SnapshotRef,
    ) -> Result<u64, Error> {
        self.native.written(dataset, point)
    }
    fn ivset(&mut self, point: &SnapshotRef) -> Result<Guid, Error> {
        self.native.ivset(point)
    }
}
impl PairBackend for Fake {
    fn observe(&mut self) -> Result<NativeState, Error> {
        let mut state = self.native.state()?;
        for (pool, altroot) in &self.altroots {
            state.pool_properties.get_mut(pool).unwrap().insert(
                "altroot".into(),
                NativeProperty {
                    value: altroot.clone(),
                    source: "-".into(),
                },
            );
        }
        if self.primary_mode {
            for props in state.pool_properties.values_mut() {
                props.insert(
                    "readonly".into(),
                    NativeProperty {
                        value: "off".into(),
                        source: "local".into(),
                    },
                );
            }
        }
        Ok(state)
    }
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<BTreeMap<String, NativeProperty>, Error> {
        if !self
            .native
            .members
            .iter()
            .any(|member| member.endpoint == *endpoint)
        {
            return Err(refuse("fake native endpoint changed"));
        }
        self.native.properties(endpoint)
    }
    fn sync(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.native.sync(endpoint)
    }
    fn set_property(&mut self, endpoint: &Endpoint, value: &PropertyValue) -> Result<(), Error> {
        // As native (`engine::mutation`): never overwrite another operation's
        // marker; this operation's inherited one becomes local.
        if let PropertyValue::Pending(id) | PropertyValue::Staging(id) = value
            && self
                .native
                .effective(&endpoint.name)
                .get(value.key().native())
                .is_some_and(|p| p.value != *id)
        {
            return Err(refuse(
                "foreign pending or staging operation occupies the endpoint",
            ));
        }
        if value.key() == PropertyKey::Cmdline {
            self.cmdline_setters += 1;
        }
        if let PropertyValue::Pair(record) = value {
            let state = self.native.state()?;
            let receiver = if record.role == Role::Secondary {
                &record.endpoint
            } else {
                &record.peer
            };
            assert!(
                state
                    .inspection
                    .datasets
                    .iter()
                    .filter(|d| history::contains_dataset(&receiver.name, &d.name))
                    .all(|d| d.readonly
                        && d.mounted != Some(true)
                        && (d.kind == zfs_tools::engine::DatasetKind::Volume
                            || d.canmount == Some(zfs_tools::engine::CanMount::NoAuto)))
            );
        }
        let encoded = value.encode(endpoint)?;
        // As native (`NativeTransfer::set_mountpoint`): never under an altroot.
        if value.key() == PropertyKey::Mountpoint {
            refuse_altroot(&PairBackend::observe(self)?, &endpoint.name)?;
        }
        if crate::placement::PLACEMENT_KEYS.contains(&value.key().native())
            && let Some(previous) = self
                .native
                .effective(&endpoint.name)
                .get(value.key().native())
            && previous.source == "received"
        {
            self.received_layers
                .entry(endpoint.name.clone())
                .or_default()
                .entry(value.key().native().into())
                .or_insert(previous.value.clone());
        }
        let result = self
            .native
            .set(endpoint, &[(value.key().native().into(), encoded)]);
        if matches!(value,PropertyValue::Volmode(mode) if mode=="none") && !self.keep_volume_node {
            self.volume_nodes.remove(&endpoint.name);
        }
        result
    }
    fn inherit_property(
        &mut self,
        endpoint: &Endpoint,
        key: PropertyKey,
        expected: &str,
    ) -> Result<Option<NativeProperty>, Error> {
        self.native.inherit_property(endpoint, key, expected)
    }
    fn observe_point(&mut self, point: &SnapshotRef) -> Result<zfs_tools::engine::Snapshot, Error> {
        self.native.observe_point(point)
    }
    fn unmount(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        if self.primary_mode && history::contains_dataset("a/data", &endpoint.name) {
            self.native.before()?;
            self.native.mounted.remove(&endpoint.name);
            self.native.after()
        } else {
            self.native.unmount(endpoint)
        }
    }
    fn add_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
        self.native.add_hold(point, tag)
    }
    fn running_root(&mut self) -> Result<Option<String>, Error> {
        self.native.running_root()
    }
}
impl CaptureBackend for Fake {
    fn observe(&mut self) -> Result<NativeState, Error> {
        self.native.state()
    }
    fn snapshot(&mut self, names: &[String], id: &str) -> Result<(), Error> {
        self.native.before()?;
        let next_guid = self
            .native
            .members
            .iter()
            .flat_map(|m| &m.snapshots)
            .map(|p| p.identity.guid.get())
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(300);
        let next_txg = self
            .native
            .members
            .iter()
            .flat_map(|m| &m.snapshots)
            .map(|p| p.identity.createtxg.get())
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(20);
        for (offset, name) in names.iter().enumerate() {
            let dataset = name.split_once('@').unwrap().0;
            let member = self
                .native
                .members
                .iter_mut()
                .find(|m| m.endpoint.name == dataset)
                .unwrap();
            let mut point = member
                .snapshots
                .last()
                .cloned()
                .unwrap_or_else(|| SnapshotRef {
                    name: name.clone(),
                    dataset_guid: member.endpoint.identity.guid,
                    identity: zfs_tools::engine::SnapshotIdentity {
                        pool_guid: member.endpoint.identity.pool_guid,
                        guid: Guid::new(300 + offset as u64),
                        createtxg: Txg::new(20),
                        objsetid: ObjsetId::new(2000 + offset as u64),
                    },
                });
            point.name = name.clone();
            point.identity.guid = Guid::new(next_guid + offset as u64);
            point.identity.createtxg = Txg::new(next_txg);
            point.identity.objsetid = ObjsetId::new(2000 + next_guid + offset as u64);
            member.snapshots.push(point);
            self.markers.insert(name.clone(), id.into());
            self.native.written.remove(dataset);
        }
        self.native.after()
    }
    fn capture_marker(&mut self, point: &SnapshotRef) -> Result<String, Error> {
        self.native.alive()?;
        self.markers
            .get(&point.name)
            .cloned()
            .ok_or_else(|| refuse("capture marker absent"))
    }
}
impl TransferBackend for Fake {
    fn attachments(&mut self) -> impl AttachmentBackend {
        Chunks(self)
    }
    fn create_inert_container(
        &mut self,
        parent: &Endpoint,
        name: &str,
        id: &str,
    ) -> Result<(), Error> {
        self.native.before()?;
        let state = self.native.state()?;
        if endpoint(&state, &parent.name)? != *parent
            || self.native.members.iter().any(|m| m.endpoint.name == name)
        {
            return Err(refuse("fake receive container occupied"));
        }
        let guid = self
            .native
            .members
            .iter()
            .map(|m| m.endpoint.identity.guid.get())
            .max()
            .unwrap()
            + 1;
        let mut member = plan::tests::member(name, parent.identity.pool_guid.get(), guid, &[]);
        member.endpoint.identity.createtxg = Txg::new(guid + 100);
        member.placement.identity = member.endpoint.identity.clone();
        self.native.members.push(member);
        self.native.properties.insert(
            name.into(),
            crate::placement::inert_properties(false)
                .into_iter()
                .chain([
                    (management::PENDING_PROPERTY.into(), id.into()),
                    (management::STAGING_PROPERTY.into(), id.into()),
                ])
                .map(|(key, value)| {
                    (
                        key,
                        NativeProperty {
                            value,
                            source: "local".into(),
                        },
                    )
                })
                .collect(),
        );
        self.native.properties.get_mut(name).unwrap().insert(
            "encryption".into(),
            NativeProperty {
                value: "off".into(),
                source: "local".into(),
            },
        );
        self.native.mounted.remove(name);
        self.native.after()
    }
    fn rename_received(
        &mut self,
        source: &Endpoint,
        parent: &Endpoint,
        destination: &str,
    ) -> Result<(), Error> {
        self.native.before()?;
        if self
            .native
            .members
            .iter()
            .any(|m| m.endpoint.name == destination)
            || !self.native.members.iter().any(|m| m.endpoint == *source)
            || !self.native.members.iter().any(|m| m.endpoint == *parent)
        {
            return Err(refuse("fake receive rename intruder"));
        }
        for member in self
            .native
            .members
            .iter_mut()
            .filter(|m| history::contains_dataset(&source.name, &m.endpoint.name))
        {
            let old = member.endpoint.name.clone();
            member.endpoint.name = format!("{destination}{}", &old[source.name.len()..]);
            for snapshot in &mut member.snapshots {
                let suffix = snapshot.name.split_once('@').unwrap().1;
                snapshot.name = format!("{}@{suffix}", member.endpoint.name);
            }
            if let Some(properties) = self.native.properties.remove(&old) {
                self.native
                    .properties
                    .insert(member.endpoint.name.clone(), properties);
            }
            for point in &member.snapshots {
                let oldname = format!("{old}@{}", point.name.split_once('@').unwrap().1);
                if let Some(holds) = self.native.holds.remove(&oldname) {
                    self.native.holds.insert(point.name.clone(), holds);
                }
                if let Some(properties) = self.snapshot_properties.remove(&oldname) {
                    self.snapshot_properties
                        .insert(point.name.clone(), properties);
                }
            }
        }
        self.native.after()
    }
    fn received_properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<BTreeMap<String, String>, Error> {
        refuse_altroot(&PairBackend::observe(self)?, &endpoint.name)?;
        let mut received: BTreeMap<_, _> = self
            .properties(endpoint)?
            .into_iter()
            .filter(|(_, property)| property.source == "received")
            .map(|(key, property)| (key, property.value))
            .collect();
        received.extend(
            self.received_layers
                .get(&endpoint.name)
                .cloned()
                .unwrap_or_default(),
        );
        Ok(received)
    }
    fn restore_receive_property(
        &mut self,
        endpoint: &Endpoint,
        key: PropertyKey,
        property: &crate::placement::SavedProperty,
    ) -> Result<(), Error> {
        let received = restore_inherit_received(key, property)?;
        if property.source != "local" && key == PropertyKey::Canmount && !received {
            return Err(refuse("canmount is not inheritable"));
        }
        if self.received_properties(endpoint)?.get(key.native()) != property.received.as_ref() {
            return Err(refuse("fake original received placement changed"));
        }
        self.native.before()?;
        if property.source != "local" {
            self.inherit_routes
                .push((self.native.effects, endpoint.name.clone(), key, received));
        }
        if key == PropertyKey::Mountpoint {
            let props = self.native.effective(&endpoint.name);
            assert_eq!(props["readonly"].value, "on");
            assert_eq!(props["canmount"].value, "noauto");
        }
        if !self.native.members.iter().any(|m| m.endpoint == *endpoint) {
            return Err(refuse("fake receive placement endpoint changed"));
        }
        self.native
            .properties
            .entry(endpoint.name.clone())
            .or_default()
            .insert(
                key.native().into(),
                NativeProperty {
                    value: property.value.clone(),
                    source: property.source.clone(),
                },
            );
        self.native.after()
    }
    fn quiesce_receive_scope(&mut self, endpoint: &Endpoint, _id: &str) -> Result<(), Error> {
        // As native (`engine::stream::quiesce`): the scope must be inert.
        let props = self.native.effective(&endpoint.name);
        let value = |key: &str| props.get(key).map(|p| p.value.as_str());
        let volume = self
            .native
            .members
            .iter()
            .find(|m| m.endpoint.name == endpoint.name)
            .is_some_and(|m| m.placement.canmount.is_none());
        if value("readonly") != Some("on")
            || value("volmode") != Some("none")
            || (!volume
                && (value("mountpoint") != Some("none")
                    || self.native.mounted.contains(&endpoint.name)))
        {
            return Err(refuse(format!(
                "{} is not an inert receive scope",
                endpoint.name
            )));
        }
        self.native.before()?;
        self.native.after()
    }
    fn volume_unavailable(&mut self, endpoint: &Endpoint) -> Result<bool, Error> {
        Ok(!self.volume_nodes.contains(&endpoint.name))
    }
    fn destroy_empty_container(&mut self, endpoint: &Endpoint, id: &str) -> Result<(), Error> {
        self.native.before()?;
        if !self
            .native
            .members
            .iter()
            .any(|m| m.endpoint == *endpoint && m.snapshots.is_empty())
            || self.native.members.iter().any(|m| {
                m.endpoint.name != endpoint.name
                    && history::contains_dataset(&endpoint.name, &m.endpoint.name)
            })
            || [management::PENDING_PROPERTY, management::STAGING_PROPERTY]
                .iter()
                .any(|key| {
                    self.native
                        .effective(&endpoint.name)
                        .get(*key)
                        .is_none_or(|p| p.value != id || p.source != "local")
                })
        {
            return Err(refuse("fake receive container is not owned and empty"));
        }
        self.native.members.retain(|m| m.endpoint != *endpoint);
        self.native.properties.remove(&endpoint.name);
        self.native.after()
    }
    fn copy_property(
        &mut self,
        target: &Endpoint,
        key: &str,
        value: Option<&str>,
        id: &str,
    ) -> Result<(), Error> {
        if !props::copied(key) || (value.is_none() && props::space(key)) {
            return Err(refuse("fake: not a copied property"));
        }
        let effective = self.native.effective(&target.name);
        if [management::PENDING_PROPERTY, management::STAGING_PROPERTY]
            .iter()
            .any(|marker| effective.get(*marker).is_none_or(|p| p.value != id))
        {
            return Err(refuse("fake copy lacks ownership markers"));
        }
        if self.refuse_copied.contains(key) {
            return Err(refuse("fake native set refused"));
        }
        self.native.before()?;
        self.copied_properties
            .push((key.into(), value.map(String::from)));
        let props = self
            .native
            .properties
            .entry(target.name.clone())
            .or_default();
        match value {
            Some(value) => {
                props.insert(
                    key.into(),
                    NativeProperty {
                        value: value.into(),
                        source: "local".into(),
                    },
                );
            }
            None => {
                props.remove(key);
            }
        }
        self.native.after()
    }
    fn wrapping(&mut self, root: &Endpoint) -> Result<Wrapping, Error> {
        self.native.alive()?;
        Ok(self
            .wrappings
            .get(&root.name)
            .cloned()
            .unwrap_or_else(|| Fake::wrapped("1")))
    }
    fn key_opens(&mut self, root: &Endpoint, location: &str) -> Result<bool, Error> {
        self.native.alive()?;
        Ok(self
            .key_files
            .contains(&(root.name.clone(), location.into())))
    }
    fn set_keylocation(
        &mut self,
        target: &Endpoint,
        location: &str,
        id: &str,
    ) -> Result<(), Error> {
        if self
            .native
            .effective(&target.name)
            .get(management::PENDING_PROPERTY)
            .is_none_or(|p| p.value != id)
        {
            return Err(refuse("fake copy lacks ownership markers"));
        }
        self.native.before()?;
        props_insert(
            &mut self.native.properties,
            &target.name,
            "keylocation".into(),
            NativeProperty {
                value: location.into(),
                source: "local".into(),
            },
        );
        self.native.after()
    }
    fn mount(&mut self, endpoint: &Endpoint) -> Result<(), Error> {
        self.native.before()?;
        self.native.mounted.insert(endpoint.name.clone());
        self.native.after()
    }
    fn release_hold(&mut self, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
        self.native.before()?;
        self.native
            .holds
            .entry(point.name.clone())
            .or_default()
            .remove(tag);
        self.native.after()
    }
    fn rename_snapshot(&mut self, point: &SnapshotRef, name: &str) -> Result<(), Error> {
        self.native.observe_point(point)?;
        let dataset = point.name.split_once('@').unwrap().0;
        let renamed = format!("{dataset}@{name}");
        zfs_tools::engine::validate_snapshot_name(&renamed)?;
        if self
            .native
            .members
            .iter()
            .flat_map(|m| &m.snapshots)
            .any(|p| p.name == renamed)
        {
            return Err(refuse("dataset already has a snapshot of that name"));
        }
        self.native.before()?;
        for member in &mut self.native.members {
            for p in &mut member.snapshots {
                if p == point {
                    p.name = renamed.clone();
                }
            }
        }
        // Holds, clones and markers belong to the snapshot, not its name.
        let n = &mut self.native;
        if let Some(holds) = n.holds.remove(&point.name) {
            n.holds.insert(renamed.clone(), holds);
        }
        if let Some(clone) = n.clones.remove(&point.name) {
            n.clones.insert(renamed.clone(), clone);
        }
        if let Some(ivset) = n.ivsets.remove(&point.name) {
            n.ivsets.insert(renamed.clone(), ivset);
        }
        if n.deferred.remove(&point.name) {
            n.deferred.insert(renamed.clone());
        }
        if let Some(marker) = self.markers.remove(&point.name) {
            self.markers.insert(renamed.clone(), marker);
        }
        self.renamed.push((point.name.clone(), renamed));
        self.native.after()
    }
    fn destroy_snapshot(&mut self, point: &SnapshotRef) -> Result<(), Error> {
        let current = self.native.observe_point(point)?;
        if current.userrefs != 0
            || !current.holds.is_empty()
            || !current.clones.is_empty()
            || current.defer_destroy
        {
            return Err(refuse("snapshot is held, cloned or deferred"));
        }
        self.native.before()?;
        for member in &mut self.native.members {
            member.snapshots.retain(|p| p != point);
        }
        self.native.holds.remove(&point.name);
        self.markers.remove(&point.name);
        self.destroyed.push(point.name.clone());
        self.native.after()
    }
    fn stream(&mut self, request: &LeafStream) -> Result<StreamOutcome, Error> {
        self.native.before()?;
        self.first_stream_effect.get_or_insert(self.native.effects);
        stream::leaf_arguments(request)?;
        self.streams += 1;
        self.observed_streams.push(request.clone());
        self.native.state()?; // a cut fake refuses like native observation
        let source = self
            .native
            .members
            .iter()
            .find(|m| m.endpoint.name == request.source.name)
            .cloned()
            .ok_or_else(|| refuse("fake stream source missing"))?;
        let name = request.destination.clone();
        let boundary = source
            .snapshots
            .iter()
            .position(|p| p.identity.guid == request.boundary.identity.guid)
            .ok_or_else(|| refuse("fake send boundary is absent"))?;
        let from = match &request.base {
            None => {
                if self.native.members.iter().any(|m| m.endpoint.name == name) {
                    return Err(refuse("destination exists; a full stream needs -F"));
                }
                let guid = self
                    .native
                    .members
                    .iter()
                    .map(|m| m.endpoint.identity.guid.get())
                    .max()
                    .unwrap_or(99)
                    .max(99)
                    + 1;
                let mut new = plan::tests::member(&name, 2, guid, &[]);
                let txg = self
                    .native
                    .members
                    .iter()
                    .map(|m| m.endpoint.identity.createtxg.get())
                    .max()
                    .unwrap_or(1)
                    + 1;
                new.endpoint.identity.createtxg = Txg::new(txg);
                new.placement.identity.createtxg = Txg::new(txg);
                if source.placement.canmount.is_none() {
                    new.placement.canmount = None;
                    new.mountpoint = None;
                }
                self.native.members.push(new);
                let props = self.native.properties.entry(name.clone()).or_default();
                // canmount is not inherited: a new filesystem has the default
                // unless the receive set it.
                if source.placement.canmount.is_some() {
                    props.insert(
                        "canmount".into(),
                        NativeProperty {
                            value: "on".into(),
                            source: "default".into(),
                        },
                    );
                }
                for (key, value) in &request.create {
                    props.insert(
                        key.clone(),
                        NativeProperty {
                            value: value.clone(),
                            source: "local".into(),
                        },
                    );
                }
                if self.native.encrypted {
                    for (key, value) in [("encryption", "aes-256-gcm"), ("keylocation", "prompt")] {
                        props.insert(
                            key.into(),
                            NativeProperty {
                                value: value.into(),
                                source: "local".into(),
                            },
                        );
                    }
                }
                boundary
            }
            Some(base) => {
                let target = self
                    .native
                    .members
                    .iter()
                    .find(|m| m.endpoint.name == name)
                    .ok_or_else(|| refuse("incremental destination missing"))?;
                if target.snapshots.last().map(|p| p.identity.guid) != Some(base.identity.guid) {
                    return Err(refuse(
                        "destination's newest snapshot is not the stream base",
                    ));
                }
                source
                    .snapshots
                    .iter()
                    .position(|p| p.identity.guid == base.identity.guid)
                    .ok_or_else(|| refuse("fake send base is absent"))?
                    + 1
            }
        };
        let properties = self.native.effective(&name);
        let value = |key: &str| properties.get(key).map(|p| p.value.as_str());
        let volume = source.placement.canmount.is_none();
        let fenced = !self.native.mounted.contains(&name)
            && value("readonly") == Some("on")
            && if volume {
                value("volmode") == Some("none")
            } else {
                matches!(value("canmount"), Some("noauto" | "off"))
            };
        assert!(
            fenced,
            "data began into an unfenced copy {name}: {properties:?}"
        );
        if request.base.is_none() {
            assert!(
                crate::placement::Posture::Inert { parent: false }
                    .holds(volume, false, |key| value(key).map(|v| (v, false))),
                "a new copy began outside its inert container at {name}: {properties:?}"
            );
        }
        let mut failed = false;
        for (committed, point) in source.snapshots[from..=boundary].iter().enumerate() {
            if self.partial_stream && committed >= self.partial_member_snapshots.unwrap_or(0) {
                failed = true;
                break;
            }
            let target = self
                .native
                .members
                .iter_mut()
                .find(|m| m.endpoint.name == name)
                .unwrap();
            let received_name = format!("{name}@{}", suffix(point)?);
            if target.snapshots.iter().any(|p| p.name == received_name) {
                failed = true; // EEXIST: another snapshot has this name
                break;
            }
            let mut received = point.clone();
            received.name = received_name;
            received.dataset_guid = target.endpoint.identity.guid;
            received.identity.pool_guid = target.endpoint.identity.pool_guid;
            received.identity.objsetid = ObjsetId::new(
                5000 + 10000 * target.endpoint.identity.guid.get() + point.identity.guid.get(),
            );
            target.snapshots.push(received);
        }
        self.native.mounted.remove(&name);
        self.native
            .members
            .sort_by(|a, b| a.endpoint.name.cmp(&b.endpoint.name));
        self.native.after()?;
        Ok(StreamOutcome {
            sender_success: !failed,
            receiver_success: !failed,
            sender_status: "0".into(),
            receiver_status: if failed { "1".into() } else { "0".into() },
            sender_stderr: String::new(),
            receiver_stderr: String::new(),
            output_truncated: false,
        })
    }
}
fn props_insert(
    props: &mut zfs_tools::engine::native::PropertyInventory,
    name: &str,
    key: String,
    value: NativeProperty,
) {
    props.entry(name.into()).or_default().insert(key, value);
}
#[test]
fn a_copied_key_set_on_the_copy_follows_the_source_at_the_next_sync() {
    for held in ["local", "received"] {
        let mut fake = Fake::new(false);
        let prop = |value: &str, source: &str| NativeProperty {
            value: value.into(),
            source: source.into(),
        };
        props_insert(
            &mut fake.native.properties,
            "a/data",
            "acltype".into(),
            prop("off", "default"),
        );
        props_insert(
            &mut fake.native.properties,
            "b/data",
            "acltype".into(),
            prop("posix", held),
        );
        props_insert(
            &mut fake.native.properties,
            "a/data",
            "compression".into(),
            prop("zstd", "local"),
        );
        props_insert(
            &mut fake.native.properties,
            "b/data",
            "org.example:old".into(),
            prop("1", held),
        );
        let plan = fake.prepare();
        fake.run(plan).unwrap();
        let copy = fake.native.effective("b/data");
        // The copy's own value is gone; the fake has no native defaults, so
        // the source's effective value is materialized in its place.
        assert_eq!(copy["acltype"].value, "off", "{held}");
        assert_eq!(copy["compression"], prop("zstd", "local"));
        assert!(
            !copy.contains_key("org.example:old"),
            "{held}: removed on the source"
        );
        // Write-time keys change before the first block of the stream.
        let first = fake
            .copied_properties
            .iter()
            .position(|(key, _)| key == "compression")
            .unwrap();
        assert!(fake.first_stream_effect.unwrap() > first);
    }
}

#[test]
fn space_limits_loosen_before_data_tighten_after_and_never_wedge_the_pair() {
    let prop = |value: &str| NativeProperty {
        value: value.into(),
        source: "local".into(),
    };
    let mut fake = Fake::new(false);
    for (key, source, copy) in [("quota", "300", "100"), ("refquota", "50", "100")] {
        props_insert(
            &mut fake.native.properties,
            "a/data",
            key.into(),
            prop(source),
        );
        props_insert(
            &mut fake.native.properties,
            "b/data",
            key.into(),
            prop(copy),
        );
    }
    props_insert(
        &mut fake.native.properties,
        "b/data",
        "reservation".into(),
        prop("10"),
    );
    let plan = fake.prepare();
    let outcome = fake.run(plan).unwrap();
    let order: Vec<_> = fake
        .copied_properties
        .iter()
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(order, ["quota", "reservation", "refquota"]);
    let copy = fake.native.effective("b/data");
    assert_eq!(
        ["quota", "refquota", "reservation"].map(|k| copy[k].value.clone()),
        ["300", "50", "none"]
    );
    assert!(outcome.unapplied.is_empty());

    // A tightened limit the copy cannot take is reported, not a failed sync.
    let mut fake = Fake::new(false);
    props_insert(
        &mut fake.native.properties,
        "a/data",
        "refquota".into(),
        prop("50"),
    );
    fake.refuse_copied.insert("refquota".into());
    let plan = fake.prepare();
    let outcome = fake.run(plan).unwrap();
    assert_eq!(outcome.status, TransferStatus::Complete);
    assert_eq!(outcome.unapplied, ["refquota"]);
    assert!(!fake.native.effective("b/data").contains_key("refquota"));
    // The report agrees with the comparison `status` and `primary` show.
    let state = fake.native.state().unwrap();
    let differences = props::space_differences(&state, "a/data", "b/data").unwrap();
    assert_eq!(
        differences
            .iter()
            .map(|d| d.key.as_str())
            .collect::<Vec<_>>(),
        outcome.unapplied
    );
    assert_eq!(differences[0].working_value.as_deref(), Some("50"));
    assert_eq!(differences[0].copy_value, None);
}

#[test]
fn a_source_property_changed_after_the_plan_refuses_before_data() {
    let mut fake = Fake::new(false);
    let prop = |value: &str| NativeProperty {
        value: value.into(),
        source: "local".into(),
    };
    props_insert(
        &mut fake.native.properties,
        "a/data",
        "copies".into(),
        prop("2"),
    );
    let plan = fake.prepare();
    props_insert(
        &mut fake.native.properties,
        "a/data",
        "copies".into(),
        prop("3"),
    );
    let error = fake.run(plan).unwrap_err().to_string();
    assert!(
        error.contains(
            "frozen source boundary, properties or identity changed: a/data (copies); set it back"
        ),
        "{error}"
    );
    assert_eq!(fake.streams, 0);
    assert!(fake.copied_properties.is_empty());
}

#[test]
fn transfer_plan_keeps_only_property_digests_while_native_stream_preserves_values() {
    let mut fake = Fake::new(true);
    fake.native
        .properties
        .entry("a/data".into())
        .or_default()
        .insert(
            "app:credential".into(),
            NativeProperty {
                value: "test-private-property-sentinel".into(),
                source: "local".into(),
            },
        );
    let plan = fake.prepare();
    assert!(
        !serde_json::to_string(&plan)
            .unwrap()
            .contains("test-private-property-sentinel")
    );
    assert_eq!(
        plan.source.members[""].properties["app:credential"],
        property_evidence("app:credential", "test-private-property-sentinel")
    );
    fake.run(plan).unwrap();
    assert_eq!(
        fake.native.effective("b/data")["app:credential"].value,
        "test-private-property-sentinel"
    );
}

#[test]
fn incremental_transfer_preserves_incarnations_and_keeps_the_peer_fenced() {
    let mut fake = Fake::new(false);
    let plan = fake.prepare();
    let before = plan.destination.existing().unwrap().clone();
    let outcome = fake.run(plan).unwrap();
    assert_eq!(outcome.status, TransferStatus::Complete);
    assert_eq!(fake.streams, 1);
    let stream = &fake.observed_streams[0];
    assert_eq!(stream.base.as_ref().unwrap().name, "a/data@s1");
    assert!(
        stream.create.is_empty(),
        "an existing copy takes nothing at creation"
    );
    let now = endpoint(&fake.native.state().unwrap(), "b/data").unwrap();
    assert_eq!(now, before.members[""].bound.endpoint);
    assert!(!fake.native.mounted.contains("b/data"));
    let props = fake.native.effective("b/data");
    assert_eq!(
        (
            props["readonly"].value.as_str(),
            props["canmount"].value.as_str()
        ),
        ("on", "noauto")
    );
    let tag = format!("zboot:anchor:{PAIR_ID}");
    let anchored: Vec<_> = fake
        .native
        .holds
        .iter()
        .filter(|(_, tags)| tags.contains(&tag))
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        anchored,
        ["a/data@next", "b/data@next"],
        "the anchor moves to the boundary"
    );
    // Released, only the caller's tail is left: a resume completes nothing.
    let mut record = fake.recorded().unwrap();
    assert_released(record.transfer().unwrap(), "incremental");
    let effects = fake.native.effects;
    assert_eq!(
        resume_between_with("a/data", "b/data", &mut record, &mut fake)
            .unwrap()
            .status,
        TransferStatus::AlreadyComplete
    );
    assert_eq!(fake.native.effects, effects);
}
#[test]
fn bootstrap_verified_history_uses_the_pair_executor_and_keeps_secondary_fenced() {
    let mut fake = Fake::new(true);
    let plan = fake.prepare();
    let outcome = fake.run(plan).unwrap();
    let pair = bootstrap_pair_id(ID);
    assert_eq!(outcome.pair_id.as_deref(), Some(pair.as_str()));
    let state = fake.native.state().unwrap();
    assert!(matches!(
        management::ownership(&state, "a/data").unwrap(),
        Ownership::Primary { .. }
    ));
    assert!(matches!(
        management::ownership(&state, "b/data").unwrap(),
        Ownership::Secondary { .. }
    ));
    assert!(fake.native.holds.values().all(|holds| {
        holds
            .iter()
            .all(|tag| tag == &format!("zboot:anchor:{pair}"))
    }));
}

/// A released transfer's record: no attachment and nothing to verify, only
/// the copy whose staging marker it removes.
fn assert_released(progress: &TransferProgress, context: &str) {
    assert_eq!(
        TransferProgress {
            received: None,
            ..progress.clone()
        },
        TransferProgress::ended(Phase::Released),
        "{context}"
    );
    assert_eq!(
        progress.received.as_ref().map(|r| r.endpoint.name.as_str()),
        Some("b/data"),
        "{context}"
    );
}
/// A snapshot of DATASET taken by hand, newer than every other.
fn snapshot_by_hand(fake: &mut Fake, dataset: &str) {
    let member = fake
        .native
        .members
        .iter_mut()
        .find(|m| m.endpoint.name == dataset)
        .unwrap();
    let mut point = member.snapshots.last().unwrap().clone();
    point.name = format!("{dataset}@by-hand");
    point.identity.guid = Guid::new(point.identity.guid.get() + 7000);
    point.identity.createtxg = Txg::new(point.identity.createtxg.get() + 50);
    point.identity.objsetid = ObjsetId::new(point.identity.objsetid.get() + 7000);
    member.snapshots.push(point);
}

/// The copy keeps the transfer's staging marker until the record is
/// released, so no other command acts on it while a recorded state still
/// verifies it; Released verifies nothing, so a snapshot of the copy taken
/// after it never stops a resume from finishing.
#[test]
fn the_copy_stays_staged_until_released_and_a_later_snapshot_never_wedges_a_resume() {
    for bootstrap in [false, true] {
        let mut reference = boot_fixture(bootstrap);
        let plan = reference.prepare();
        reference.run(plan).unwrap();
        let effects = reference.native.effects;
        let (mut complete, mut released) = (0, 0);
        for cut in 1..=effects {
            for after in [false, true] {
                let context = format!("bootstrap={bootstrap} cut={cut} after={after}");
                let mut fake = boot_fixture(bootstrap);
                let plan = fake.prepare();
                fake.native.cut = Some((cut, after));
                assert!(fake.run(plan).is_err(), "{context}");
                fake.native.crashed = false;
                fake.native.cut = None;
                let Some(mut record) = fake.recorded() else {
                    continue;
                };
                let staged = fake
                    .native
                    .properties
                    .get("b/data")
                    .and_then(|p| p.get(management::STAGING_PROPERTY))
                    .is_some_and(|p| p.source == "local" && p.value == ID);
                match record.transfer().map(|t| t.phase) {
                    Some(Phase::Complete) => {
                        complete += 1;
                        assert!(staged, "{context}");
                    }
                    Some(Phase::Released) => {
                        released += 1;
                        snapshot_by_hand(&mut fake, "b/data");
                        let outcome =
                            resume_between_with("a/data", "b/data", &mut record, &mut fake)
                                .unwrap_or_else(|e| panic!("{context}: {e}"));
                        assert_eq!(outcome.status, TransferStatus::AlreadyComplete);
                        assert!(
                            !fake
                                .native
                                .effective("b/data")
                                .contains_key(management::STAGING_PROPERTY),
                            "{context}"
                        );
                        assert_no_records_left(&fake, &context);
                    }
                    _ => {}
                }
            }
        }
        assert!(complete > 0 && released > 0, "{complete} {released}");
    }
}

/// What a finished transfer leaves of its records: nothing. No dataset keeps
/// an attachment chunk or a journal property, nor a marker of the transfer
/// or of a bootstrap's nested pair.
fn assert_no_records_left(fake: &Fake, context: &str) {
    assert_eq!(fake.chunks(), Vec::<(String, String)>::new(), "{context}");
    let ids = [ID.to_owned(), bootstrap_pair_id(ID)];
    for (name, props) in &fake.native.properties {
        for (key, p) in props {
            let marker = matches!(
                key.as_str(),
                management::PENDING_PROPERTY | management::STAGING_PROPERTY
            ) && ids.contains(&p.value);
            assert!(
                !key.starts_with("zboot:journal:") && !marker,
                "{name} keeps {key}: {context}"
            );
        }
    }
}

#[test]
fn every_incremental_and_bootstrap_effect_cut_recovers_without_retransmitting_verified_data() {
    for bootstrap in [false, true] {
        let mut reference = boot_fixture(bootstrap);
        let plan = reference.prepare();
        reference.run(plan.clone()).unwrap();
        assert_no_records_left(&reference, "reference");
        let effects = reference.native.effects;
        let mut recovered = 0;
        for cut in 1..=effects {
            for after in [false, true] {
                let context = format!("bootstrap={bootstrap} cut={cut} after={after}");
                let mut fake = boot_fixture(bootstrap);
                let current_plan = fake.prepare();
                assert_eq!(current_plan, plan);
                fake.native.cut = Some((cut, after));
                assert!(fake.run(current_plan.clone()).is_err(), "{context}");
                fake.native.crashed = false;
                fake.native.cut = None;
                let Some(mut record) = fake.recorded() else {
                    // The record never landed: nothing else did.
                    assert_eq!(fake.streams, 0, "{context}");
                    assert_eq!(fake.native.holds, boot_fixture(bootstrap).native.holds);
                    assert!(fake.chunks().is_empty(), "{context}");
                    continue;
                };
                if record.transfer().is_none() {
                    // Cut before the commit: at most chunks no record names.
                    // The caller discards them and starts the transfer again.
                    assert_eq!(fake.streams, 0, "{context}");
                    assert_eq!(fake.native.holds, boot_fixture(bootstrap).native.holds);
                    discard(&record, &mut fake).unwrap();
                    assert!(fake.chunks().is_empty(), "{context}");
                    begin(&mut record, current_plan, &mut fake)
                        .unwrap_or_else(|error| panic!("{context}: {error}"));
                } else {
                    let streams = fake.streams;
                    resume_between_with("a/data", "b/data", &mut record, &mut fake)
                        .unwrap_or_else(|error| panic!("{context}: {error}"));
                    assert!(fake.streams >= streams);
                }
                assert_eq!(
                    fake.streams, reference.streams,
                    "a resume sends only the snapshots the copy lacks"
                );
                assert_eq!(fake.native.members, reference.native.members);
                assert_eq!(fake.native.holds, reference.native.holds);
                assert_released(fake.recorded().unwrap().transfer().unwrap(), &context);
                assert_no_records_left(&fake, &context);
                for key in ["mountpoint", "zboot:cmdline"] {
                    assert_eq!(
                        fake.native.properties["b/data"].get(key),
                        reference.native.properties["b/data"].get(key)
                    );
                }
                recovered += 1;
            }
        }
        // Every cut but one before the record's own first write recovers.
        assert_eq!(recovered, 2 * effects - 1, "bootstrap={bootstrap}");
        assert!(effects > 30, "{effects}");
    }
}

/// The transfer's own commit points, each cut before and after it lands:
/// the plan's write and the advance that names it, a bootstrap's pair plan
/// and its Received advance, the Released advance and every chunk removal.
/// A cut before a name is recorded leaves chunks nothing names, and only
/// those are discarded; once named, chunks are only read, until Released
/// names nothing and a cut during their removal leaves fewer to remove.
#[test]
fn a_cut_at_each_attachment_commit_point_recovers_to_the_same_end() {
    for bootstrap in [false, true] {
        let mut reference = boot_fixture(bootstrap);
        let plan = reference.prepare();
        reference.writes.clear();
        reference.run(plan).unwrap();
        let writes = reference.writes.clone();
        let at = |wanted: &dyn Fn(&Write) -> bool| -> Vec<usize> {
            writes
                .iter()
                .filter(|(_, write)| wanted(write))
                .map(|(effect, _)| *effect)
                .collect()
        };
        let plan_write = at(&|w| matches!(w, Write::Chunks(slot, _) if slot == PLAN));
        let pair_write = at(&|w| matches!(w, Write::Chunks(slot, _) if slot == PAIR));
        let commit = at(&|w| *w == Write::Record(Some(Phase::Prepared)));
        let received = at(&|w| *w == Write::Record(Some(Phase::Received)));
        let released = at(&|w| *w == Write::Record(Some(Phase::Released)));
        let removed = at(&|w| matches!(w, Write::Removed(_)));
        assert!(!plan_write.is_empty(), "{writes:?}");
        assert_eq!(!pair_write.is_empty(), bootstrap, "{writes:?}");
        assert_eq!((commit.len(), received.len(), released.len()), (1, 1, 1));
        assert!(plan_write.iter().all(|w| *w < commit[0]) && released[0] < removed[0]);
        assert!(pair_write.iter().all(|w| *w < received[0]));
        // The plan and a bootstrap's pair plan are each removed whole.
        let chunks = |slot: &str| {
            writes
                .iter()
                .filter_map(|(_, w)| match w {
                    Write::Chunks(s, n) if s == slot => Some(*n),
                    _ => None,
                })
                .sum::<usize>()
        };
        assert_eq!(removed.len(), chunks(PLAN) + chunks(PAIR));
        let points: Vec<usize> =
            [plan_write, pair_write, commit, received, released, removed].concat();
        for cut in points {
            for after in [false, true] {
                let context = format!("bootstrap={bootstrap} cut={cut} after={after}");
                let mut fake = boot_fixture(bootstrap);
                let plan = fake.prepare();
                fake.native.cut = Some((cut, after));
                assert!(fake.run(plan.clone()).is_err(), "{context}");
                fake.native.crashed = false;
                fake.native.cut = None;
                let mut record = fake.recorded().unwrap();
                let progress = record.transfer().cloned();
                let named: Vec<&str> = progress
                    .iter()
                    .flat_map(|p| {
                        [(PLAN, p.plan.is_some()), (PAIR, p.pair.is_some())]
                            .into_iter()
                            .filter(|(_, named)| *named)
                            .map(|(slot, _)| slot)
                    })
                    .collect();
                // Every named attachment is whole; anything else on the
                // holder is a partial write or what a removal left.
                for slot in &named {
                    let prefix = key(ID, slot).unwrap().prefix().to_owned();
                    let have = fake
                        .chunks()
                        .iter()
                        .filter(|(name, chunk)| name == "a/data" && chunk.starts_with(&prefix))
                        .count();
                    assert_eq!(have, chunks(slot), "{context}: {slot}");
                }
                assert!(
                    fake.chunks().iter().all(|(name, _)| name == "a/data"),
                    "{context}: a chunk off the holder"
                );
                match progress.as_ref().map(|p| p.phase) {
                    None => {
                        discard(&record, &mut fake).unwrap();
                        assert!(fake.chunks().is_empty(), "{context}");
                        begin(&mut record, plan, &mut fake)
                            .unwrap_or_else(|e| panic!("{context}: {e}"));
                    }
                    Some(phase) => {
                        if phase == Phase::Released {
                            assert!(named.is_empty(), "{context}");
                        }
                        let outcome =
                            resume_between_with("a/data", "b/data", &mut record, &mut fake)
                                .unwrap_or_else(|e| panic!("{context}: {e}"));
                        assert_eq!(
                            outcome.status == TransferStatus::AlreadyComplete,
                            phase == Phase::Released,
                            "{context}"
                        );
                    }
                }
                assert_eq!(fake.native.members, reference.native.members, "{context}");
                assert_eq!(fake.native.holds, reference.native.holds, "{context}");
                assert_no_records_left(&fake, &context);
            }
        }
    }
}

/// A bootstrap cut anywhere from its Activating advance to its Complete one,
/// before and after each effect. The phase its record names for the nested
/// pair never runs behind native state: the pair's pending markers only
/// from `Prepared`, its anchor holds only from `Fenced`, a publication only
/// from `Anchored`, and both from `Published`. A resume finishes from that
/// phase, and nothing of the transfer or its pair is left.
#[test]
fn a_bootstrap_cut_in_its_nested_pair_resumes_from_the_phase_its_record_names() {
    use plan::Phase::{Anchored, Fenced, Prepared, Published};
    let pair = bootstrap_pair_id(ID);
    let tag = format!("zboot:anchor:{pair}");
    let mut reference = Fake::new(true);
    let plan = reference.prepare();
    reference.writes.clear();
    reference.run(plan).unwrap();
    let first = |phase: Phase| {
        reference
            .writes
            .iter()
            .find(|(_, write)| *write == Write::Record(Some(phase)))
            .map(|(effect, _)| *effect)
            .unwrap()
    };
    let (activating, complete) = (first(Phase::Activating), first(Phase::Complete));
    let mut seen = BTreeSet::new();
    for cut in activating..=complete {
        for after in [false, true] {
            let context = format!("cut={cut} after={after}");
            let mut fake = Fake::new(true);
            let plan = fake.prepare();
            fake.native.cut = Some((cut, after));
            assert!(fake.run(plan).is_err(), "{context}");
            fake.native.crashed = false;
            fake.native.cut = None;
            let mut record = fake.recorded().unwrap();
            let phase = record.transfer().unwrap().pair_phase;
            let state = fake.native.state().unwrap();
            let leaves = ["a/data", "b/data"];
            let pending = leaves
                .iter()
                .filter(|name| {
                    state.dataset_properties[**name]
                        .get(management::PENDING_PROPERTY)
                        .is_some_and(|p| p.value == pair)
                })
                .count();
            let published = leaves
                .iter()
                .filter(|name| {
                    state.dataset_properties[**name]
                        .get(management::PAIR_PROPERTY)
                        .is_some_and(|p| PairRecord::parse(&p.value).unwrap().pair_id == pair)
                })
                .count();
            let held = fake
                .native
                .holds
                .values()
                .filter(|tags| tags.contains(&tag))
                .count();
            assert!(pending == 0 || phase >= Some(Prepared), "{context}");
            assert!(held == 0 || phase >= Some(Fenced), "{context}");
            assert!(published == 0 || phase >= Some(Anchored), "{context}");
            assert!(phase < Some(Published) || published == 2, "{context}");
            seen.insert((phase, pending, held, published));
            resume_between_with("a/data", "b/data", &mut record, &mut fake)
                .unwrap_or_else(|error| panic!("{context}: {error}"));
            assert_eq!(fake.native.members, reference.native.members, "{context}");
            assert_eq!(fake.native.holds, reference.native.holds, "{context}");
            assert_no_records_left(&fake, &context);
        }
    }
    for case in [
        // Before its commit.
        (None, 0, 0, 0),
        // Between the left and right pending markers.
        (Some(Prepared), 1, 0, 0),
        // While the receiver is fenced.
        (Some(Prepared), 2, 0, 0),
        // Between the anchor holds.
        (Some(Fenced), 2, 1, 0),
        // Half published.
        (Some(Anchored), 2, 2, 1),
        // Between the pending clears.
        (Some(Published), 1, 2, 2),
        // After them, before Complete.
        (Some(Published), 0, 2, 2),
    ] {
        assert!(seen.contains(&case), "{case:?} not among {seen:?}");
    }
}

/// A bootstrap cut once its copy is at its final name, before the record
/// says so, whose destination pool is then imported with an altroot: the
/// abandon cannot read the copy there, so it refuses with nothing changed,
/// rather than report only an empty container and leave the copy marked.
#[test]
fn an_abandon_that_cannot_read_a_renamed_copy_refuses_with_nothing_changed() {
    let mut reference = Fake::new(true);
    let plan = reference.prepare();
    reference.run(plan).unwrap();
    let mut checked = 0;
    for cut in 1..=reference.native.effects {
        for after in [false, true] {
            let mut fake = Fake::new(true);
            let plan = fake.prepare();
            fake.native.cut = Some((cut, after));
            assert!(fake.run(plan).is_err());
            fake.native.crashed = false;
            fake.native.cut = None;
            let Some(mut record) = fake.recorded() else {
                continue;
            };
            let unrecorded = record.transfer().is_some_and(|t| {
                t.phase < Phase::Received && t.receive.step == receive::Step::Adopted
            });
            let renamed = fake
                .native
                .members
                .iter()
                .any(|m| m.endpoint.name == "b/data");
            if !(unrecorded && renamed) {
                continue;
            }
            fake.altroots.insert("b".into(), "/mnt".into());
            let (effects, properties) = (fake.native.effects, fake.native.properties.clone());
            let error = abandon_between_with("a/data", "b/data", &mut record, &mut fake)
                .unwrap_err()
                .to_string();
            assert!(error.contains("altroot"), "{cut} {after}: {error}");
            assert_eq!(fake.native.effects, effects, "{cut} {after}");
            assert_eq!(fake.native.properties, properties, "{cut} {after}");
            checked += 1;
        }
    }
    assert!(checked > 0, "no cut left a renamed copy unrecorded");
}

/// A copy's identity digest is the same at its stage inside the receive
/// container and at its final name, whatever its placement, mounts or
/// properties, and changes with any snapshot added, renamed, or replaced
/// under the same name, and with a replaced dataset.
#[test]
fn the_received_identity_digest_survives_the_rename_and_nothing_else() {
    let mut fake = Fake::new(true);
    let plan = fake.prepare();
    let outcome = fake.run(plan).unwrap();
    let operation = outcome.completed_operation.unwrap();
    let copy = operation.received.clone().unwrap();
    let digest = identity_digest(&copy).unwrap();
    assert_eq!(
        operation
            .progress
            .received
            .as_ref()
            .map(|r| r.digest.as_str()),
        Some(digest.as_str())
    );
    let mut staged = copy.clone();
    staged.endpoint.name = "b/zboot-receive-x/root".into();
    for member in staged.members.values_mut() {
        member.bound.endpoint.name = staged.endpoint.name.clone();
        for point in &mut member.bound.snapshots {
            point.name = format!("{}@{}", staged.endpoint.name, suffix(point).unwrap());
        }
        member.mounted = !member.mounted;
        member.bound.placement.readonly = !member.bound.placement.readonly;
        member.bound.mountpoint = None;
        member.properties.clear();
    }
    assert_eq!(identity_digest(&staged).unwrap(), digest);
    let changed = |change: &dyn Fn(&mut Vec<SnapshotRef>)| {
        let mut tree = copy.clone();
        change(&mut tree.members.get_mut("").unwrap().bound.snapshots);
        identity_digest(&tree).unwrap()
    };
    let added = changed(&|points| {
        let mut point = points.last().unwrap().clone();
        point.name = "b/data@later".into();
        point.identity.guid = Guid::new(point.identity.guid.get() + 1000);
        point.identity.createtxg = Txg::new(point.identity.createtxg.get() + 1);
        points.push(point);
    });
    let pruned = changed(&|points| {
        points.remove(0);
    });
    let renamed = changed(&|points| points[0].name = "b/data@other".into());
    let replaced = changed(&|points| {
        let point = &mut points[0];
        point.identity.guid = Guid::new(point.identity.guid.get() + 1000);
        point.identity.objsetid = ObjsetId::new(point.identity.objsetid.get() + 1000);
    });
    for (what, other) in [
        ("added", added),
        ("pruned", pruned),
        ("renamed", renamed),
        ("replaced", replaced),
    ] {
        assert_ne!(other, digest, "{what}");
    }
    let mut dataset = copy;
    dataset
        .members
        .get_mut("")
        .unwrap()
        .bound
        .endpoint
        .identity
        .objsetid = ObjsetId::new(7);
    assert_ne!(identity_digest(&dataset).unwrap(), digest);
}

#[test]
fn public_transfer_captures_a_writable_leaf_and_reports_a_new_child() {
    let mut fake = Fake::new(false);
    let request = TransferRequest {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    let outcome = transfer_with(&request, &mut fake).unwrap();
    assert_eq!(outcome.status, TransferStatus::Complete);
    assert_eq!(outcome.capture.as_ref().unwrap().points.len(), 1);
    assert_eq!(fake.streams, 1);
    let stream = &fake.observed_streams[0];
    assert!(stream.boundary.name.contains("@zboot_transfer_"));
    assert!(stream.base.is_some() && stream.create.is_empty());
    assert!(outcome.unmirrored.is_empty());

    let mut fake = Fake::new(false);
    let mut new = plan::tests::member("a/data/new", 1, 12, &[400]);
    new.snapshots[0].name = "a/data/new@s1".into();
    fake.native.members.push(new);
    fake.native
        .members
        .sort_by(|a, b| a.endpoint.name.cmp(&b.endpoint.name));
    let outcome = transfer_with(&request, &mut fake).unwrap();
    assert_eq!(outcome.status, TransferStatus::Complete);
    assert_eq!(outcome.unmirrored, ["a/data/new"]);
    assert_eq!(
        outcome.capture.as_ref().unwrap().points.len(),
        1,
        "only the leaf is captured"
    );
    assert!(
        !fake
            .native
            .members
            .iter()
            .any(|m| m.endpoint.name == "b/data/new")
    );

    // A bootstrap refuses instead: the new pair would start incomplete.
    let mut fake = Fake::new(true);
    let mut new = plan::tests::member("a/data/new", 1, 12, &[400]);
    new.snapshots[0].name = "a/data/new@s1".into();
    fake.native.members.push(new);
    let effects = fake.native.effects;
    let error = transfer_with(&request, &mut fake).unwrap_err().to_string();
    assert!(error.contains("a pair joins leaf datasets"), "{error}");
    assert_eq!((fake.native.effects, fake.streams), (effects, 0));
}
#[test]
fn readonly_secondary_push_preserves_ownership_and_rotates_only_managed_anchors() {
    let mut fake = Fake::unpaired(false);
    let state = fake.native.state().unwrap();
    let record = PairRecord {
        schema_version: 1,
        pair_id: PAIR_ID.into(),
        endpoint: endpoint(&state, "a/data").unwrap(),
        peer: endpoint(&state, "b/data").unwrap(),
        role: Role::Secondary,
    };
    for pair in [record.clone(), record.counterpart()] {
        fake.native
            .set(
                &pair.endpoint,
                &[(management::PAIR_PROPERTY.into(), pair.encode().unwrap())],
            )
            .unwrap();
    }
    for member in fake
        .native
        .members
        .clone()
        .into_iter()
        .filter(|m| history::contains_dataset("a/data", &m.endpoint.name))
    {
        fake.set_property(
            &member.endpoint,
            &PropertyValue::Placement(member.placement.clone()),
        )
        .unwrap();
        fake.set_property(&member.endpoint, &PropertyValue::Readonly(true))
            .unwrap();
        fake.set_property(
            &member.endpoint,
            &PropertyValue::Canmount(MountMode::NoAuto),
        )
        .unwrap();
        fake.native.mounted.remove(&member.endpoint.name);
    }
    for member in &mut fake.native.members {
        if history::contains_dataset("b/data", &member.endpoint.name) {
            member.snapshots.pop();
        }
    }
    let tag = format!("zboot:anchor:{PAIR_ID}");
    for member in fake
        .native
        .members
        .iter()
        .filter(|m| m.endpoint.name.contains("/data"))
    {
        fake.native
            .holds
            .entry(member.snapshots[0].name.clone())
            .or_default()
            .extend([tag.clone(), "external-reader".into()]);
    }
    let source_count = fake
        .native
        .members
        .iter()
        .filter(|m| history::contains_dataset("a/data", &m.endpoint.name))
        .map(|m| m.snapshots.len())
        .sum::<usize>();
    let outcome = transfer_with(
        &TransferRequest {
            source: "a/data".into(),
            destination: "b/data".into(),
        },
        &mut fake,
    )
    .unwrap();
    assert_eq!(outcome.pair_id.as_deref(), Some(PAIR_ID));
    assert_eq!(fake.markers.len(), 0);
    assert_eq!(
        source_count,
        fake.native
            .members
            .iter()
            .filter(|m| history::contains_dataset("a/data", &m.endpoint.name))
            .map(|m| m.snapshots.len())
            .sum::<usize>()
    );
    let state = fake.native.state().unwrap();
    assert_eq!(
        management::ownership(&state, "a/data").unwrap(),
        Ownership::Secondary {
            record: record.clone()
        }
    );
    assert_eq!(
        management::ownership(&state, "b/data").unwrap(),
        Ownership::Primary {
            record: record.counterpart()
        }
    );
    for member in fake
        .native
        .members
        .iter()
        .filter(|m| m.endpoint.name.contains("/data"))
    {
        assert!(fake.native.holds[&member.snapshots[0].name].contains("external-reader"));
        assert!(!fake.native.holds[&member.snapshots[0].name].contains(&tag));
        assert!(fake.native.holds[&member.snapshots.last().unwrap().name].contains(&tag));
    }
}
/// A resume reads its record and the plan it names on the source alone, and
/// binds the requested and the recorded destination before any effect; a
/// plan lost from the source is refused.
#[test]
fn transfer_recovery_reads_its_record_and_binds_destination_before_effects() {
    let mut fake = Fake::new(false);
    let (mut record, _) = recorded_operation(&mut fake);
    let prefix = format!("{}{ID}:", attachment::PREFIX);
    assert!(fake.chunks().iter().all(|(name, _)| name == "a/data"));
    let before = fake.native.effects;
    assert!(resume_between_with("a/data", "b/other", &mut record, &mut fake).is_err());
    assert_eq!(fake.native.effects, before);
    // Without the plan the record names, nothing is resumed.
    let mut lost = fake.clone();
    lost.native
        .properties
        .get_mut("a/data")
        .unwrap()
        .retain(|key, _| !key.starts_with(&prefix));
    let effects = lost.native.effects;
    let error = resume_between_with("a/data", "b/data", &mut lost.recorded().unwrap(), &mut lost)
        .unwrap_err()
        .to_string();
    assert!(error.contains("does not read back from a/data"), "{error}");
    assert_eq!(lost.native.effects, effects);
    // The destination's incarnation changed since the plan.
    let mut replaced = fake.clone();
    replaced
        .native
        .members
        .iter_mut()
        .find(|m| m.endpoint.name == "b/data")
        .unwrap()
        .endpoint
        .identity
        .objsetid = ObjsetId::new(999);
    let effects = replaced.native.effects;
    assert!(
        resume_between_with(
            "a/data",
            "b/data",
            &mut replaced.recorded().unwrap(),
            &mut replaced
        )
        .is_err()
    );
    assert_eq!(replaced.native.effects, effects);
    // The destination's pool is not imported.
    let mut exported = fake.clone();
    exported
        .native
        .members
        .retain(|m| !history::contains_dataset("b", &m.endpoint.name));
    let effects = exported.native.effects;
    let error = resume_between_with(
        "a/data",
        "b/data",
        &mut exported.recorded().unwrap(),
        &mut exported,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("pool b of the destination b/data is not imported"),
        "{error}"
    );
    assert_eq!(exported.native.effects, effects);
    resume_between_with("a/data", "b/data", &mut record, &mut fake).unwrap();
}

/// A finished sync or bootstrap leaves nothing of its records on any
/// dataset: a bootstrap's nested pair keeps its phases in the same record.
#[test]
fn a_finished_transfer_leaves_no_attachment_journal_or_marker() {
    for bootstrap in [false, true] {
        let mut fake = Fake::new(bootstrap);
        let plan = fake.prepare();
        fake.run(plan).unwrap();
        assert_no_records_left(&fake, &format!("bootstrap={bootstrap}"));
    }
}

#[test]
fn a_read_only_source_without_a_snapshot_is_refused_at_admission() {
    let request = TransferRequest {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    let mut fake = Fake::new(true);
    let source = fake
        .native
        .members
        .iter()
        .find(|m| m.endpoint.name == "a/data")
        .unwrap()
        .endpoint
        .clone();
    fake.set_property(&source, &PropertyValue::Readonly(true))
        .unwrap();
    for member in &mut fake.native.members {
        if member.endpoint.name == "a/data" {
            member.snapshots.clear();
        }
    }
    let error = admission_with(&request, &mut fake).unwrap_err().to_string();
    assert!(
        error.contains("a/data is read-only and has no snapshot to send"),
        "{error}"
    );
    assert_eq!(fake.streams, 0);
    assert!(fake.markers.is_empty());
}

#[test]
fn equal_readonly_boundary_verifies_without_a_native_stream() {
    let mut fake = Fake::new(false);
    for member in fake
        .native
        .members
        .clone()
        .into_iter()
        .filter(|m| history::contains_dataset("a/data", &m.endpoint.name))
    {
        fake.set_property(&member.endpoint, &PropertyValue::Readonly(true))
            .unwrap();
    }
    transfer_with(
        &TransferRequest {
            source: "a/data".into(),
            destination: "b/data".into(),
        },
        &mut fake,
    )
    .unwrap();
    assert_eq!(fake.streams, 0);
    assert!(fake.markers.is_empty());
}

#[test]
fn diverged_or_dirty_destination_refuses_before_any_effect() {
    let request = TransferRequest {
        source: "a/data".into(),
        destination: "b/data".into(),
    };
    // Start from equal histories on every member so only the destination
    // mutation decides the admission direction.
    let equal = || Fake::new(false);
    for case in ["destination snapshot", "destination written"] {
        let mut fake = equal();
        if case == "destination snapshot" {
            let dest = fake
                .native
                .members
                .iter_mut()
                .find(|m| m.endpoint.name == "b/data")
                .unwrap();
            let mut point = dest.snapshots.last().unwrap().clone();
            point.name = "b/data@s2".into();
            point.identity.guid = Guid::new(102);
            point.identity.createtxg = Txg::new(12);
            point.identity.objsetid = ObjsetId::new(1002);
            dest.snapshots.push(point);
        } else {
            fake.native.written.insert("b/data".into(), 4096);
        }
        let members = fake.native.members.clone();
        let holds = fake.native.holds.clone();
        let error = transfer_with(&request, &mut fake).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("destination is ahead or has unsnapshotted changes"),
            "{case}: {error}"
        );
        assert_eq!(fake.native.effects, 0, "{case}");
        assert_eq!(fake.streams, 0, "{case}");
        assert_eq!(fake.native.members, members, "{case}: no capture was taken");
        assert_eq!(fake.native.holds, holds, "{case}");
    }
}

fn before_first_stream(bootstrap: bool) -> (Fake, TransferPlan) {
    let mut reference = Fake::new(bootstrap);
    let plan = reference.prepare();
    reference.run(plan).unwrap();
    let first = reference.first_stream_effect.unwrap();
    let mut fake = Fake::new(bootstrap);
    let plan = fake.prepare();
    fake.native.cut = Some((first, false));
    assert!(fake.run(plan.clone()).is_err());
    fake.native.crashed = false;
    fake.native.cut = None;
    (fake, plan)
}

#[test]
fn an_unremovable_volume_node_refuses_before_any_stream() {
    let mut fake = Fake::volumes(false);
    fake.volume_nodes.insert("b/data".into());
    fake.keep_volume_node = true;
    let plan = fake.prepare();
    assert!(fake.run(plan).is_err());
    assert_eq!(fake.streams, 0);
    assert!(fake.volume_nodes.contains("b/data"));
    assert_eq!(fake.native.effective("b/data")["readonly"].value, "on");
}

#[test]
fn bootstrap_uses_a_bound_unencrypted_empty_container_and_retires_only_that_container() {
    let mut fake = Fake::new(true);
    let plan = fake.prepare();
    let session = receive::capture(&plan, ID, &mut fake).unwrap();
    let container = session.container.as_ref().unwrap().name.clone();
    let outcome = fake.run(plan).unwrap();
    assert_eq!(
        fake.observed_streams[0].destination,
        format!("{container}/root")
    );
    assert!(
        fake.native
            .members
            .iter()
            .all(|member| member.endpoint.name != container)
    );
    assert_eq!(outcome.destination.unwrap().name, "b/data");
    // The operation as its record ends: released, naming no plan.
    assert_released(&outcome.completed_operation.unwrap().progress, "bootstrap");
}

#[test]
fn a_foreign_receive_container_is_never_adopted_or_destroyed() {
    let mut fake = Fake::new(true);
    let plan = fake.prepare();
    let session = receive::capture(&plan, ID, &mut fake).unwrap();
    let name = session.container.unwrap().name;
    fake.native
        .members
        .push(plan::tests::member(&name, 2, 999, &[]));
    let before = fake.native.members.clone();
    assert!(fake.run(plan).is_err());
    assert_eq!(fake.streams, 0);
    assert_eq!(fake.native.members, before);
}

#[test]
fn a_final_name_intruder_after_receive_is_preserved_and_never_renamed_over() {
    let mut reference = Fake::new(true);
    let plan = reference.prepare();
    reference.run(plan).unwrap();
    let first = reference.first_stream_effect.unwrap();
    let mut fake = Fake::new(true);
    let plan = fake.prepare();
    fake.native.cut = Some((first, true));
    assert!(fake.run(plan).is_err());
    fake.native.crashed = false;
    fake.native.cut = None;
    let mut record = fake.recorded().unwrap();
    let staged: Vec<_> = fake
        .native
        .members
        .iter()
        .filter(|member| member.endpoint.name.starts_with("b/zboot-receive-"))
        .cloned()
        .collect();
    let intruder = plan::tests::member("b/data", 2, 9999, &[]);
    fake.native.members.push(intruder.clone());
    assert!(resume_between_with("a/data", "b/data", &mut record, &mut fake).is_err());
    assert!(fake.native.members.contains(&intruder));
    // The cut lost the reply of a complete stream: the copy in the container
    // already holds the frozen history, so no stream is sent again.
    assert_eq!(fake.streams, 1);
    assert!(resume_between_with("a/data", "b/data", &mut record, &mut fake).is_err());
    assert_eq!(fake.streams, 1);
    assert!(fake.native.members.contains(&intruder));
    for expected in staged {
        let actual = fake
            .native
            .members
            .iter()
            .find(|member| member.endpoint == expected.endpoint)
            .unwrap();
        assert_eq!(actual.snapshots, expected.snapshots);
    }
    assert!(fake.native.members.iter().any(|member| {
        member.endpoint.name.starts_with("b/zboot-receive-")
            && member.endpoint.name.ends_with("/root")
    }));
    assert!(
        fake.native
            .effective("a/data")
            .contains_key(management::PENDING_PROPERTY)
    );
}

#[test]
fn an_existing_volume_loses_its_device_before_the_first_data_stream() {
    let mut fake = Fake::volumes(false);
    fake.volume_nodes.insert("b/data".into());
    let plan = fake.prepare();
    fake.run(plan).unwrap();
    assert_eq!(fake.streams, 1);
    assert!(!fake.volume_nodes.contains("b/data"));
    let volmode = &fake.native.effective("b/data")["volmode"];
    assert_eq!(
        (volmode.value.as_str(), volmode.source.as_str()),
        ("none", "local")
    );
}

#[test]
fn a_bootstrap_volume_is_inert_during_receive_and_fenced_before_pair_publication() {
    let mut fake = Fake::volumes(true);
    let plan = fake.prepare();
    fake.run(plan).unwrap();
    let state = fake.native.state().unwrap();
    let copy = state
        .inspection
        .datasets
        .iter()
        .find(|dataset| dataset.name == "b/data")
        .unwrap();
    assert_eq!(&copy.kind, &zfs_tools::engine::DatasetKind::Volume);
    assert!(copy.readonly);
    let volmode = &fake.native.effective("b/data")["volmode"];
    assert_eq!(
        (volmode.value.as_str(), volmode.source.as_str()),
        ("none", "local")
    );
    assert_ne!(copy.mounted, Some(true));
    // A new copy takes the first snapshot whole, then the rest incrementally.
    assert_eq!(fake.streams, 2);
    assert!(fake.observed_streams[0].base.is_none());
    assert!(
        fake.observed_streams[0]
            .create
            .iter()
            .all(|(key, _)| key != "canmount")
    );
    assert!(fake.observed_streams[1].create.is_empty());
}

/// An operation on the existing pair `a/data` -> `b/data`, recorded with its
/// plan and nothing done yet.
fn recorded_operation(fake: &mut Fake) -> (Journal<Standalone>, TransferOperation) {
    let plan = fake.prepare();
    let mut record = fake.record().unwrap();
    let operation = commit(&mut record, plan, fake).unwrap();
    (record, operation)
}

/// A named attachment that does not read back, a chunk changed or gone,
/// refuses a resume and an abandon before any effect: it is never discarded
/// unread, and the transfer it records is never abandoned around it.
#[test]
fn a_named_attachment_that_does_not_read_back_refuses_before_any_effect() {
    for damage in ["changed", "missing"] {
        let mut fake = Fake::new(false);
        let (mut record, _) = recorded_operation(&mut fake);
        let chunk = format!("{}0000", key(ID, PLAN).unwrap().prefix());
        let props = fake.native.properties.get_mut("a/data").unwrap();
        if damage == "changed" {
            props
                .get_mut(&chunk)
                .unwrap()
                .value
                .replace_range(0..2, "00");
        } else {
            props.remove(&chunk);
        }
        let (effects, properties, holds) = (
            fake.native.effects,
            fake.native.properties.clone(),
            fake.native.holds.clone(),
        );
        for abandon in [false, true] {
            let error = if abandon {
                abandon_between_with("a/data", "b/data", &mut record, &mut fake).unwrap_err()
            } else {
                resume_between_with("a/data", "b/data", &mut record, &mut fake).unwrap_err()
            }
            .to_string();
            assert!(error.contains("does not read back"), "{damage}: {error}");
            assert!(discard(&record, &mut fake).is_err(), "{damage}");
        }
        assert_eq!(fake.native.effects, effects, "{damage}");
        assert_eq!(fake.native.properties, properties, "{damage}");
        assert_eq!(fake.native.holds, holds, "{damage}");
    }
}

/// Chunks no record names are a write cut before its commit, which nothing
/// acted on: an abandon removes them, and so does a transfer that starts.
#[test]
fn an_abandon_discards_attachment_chunks_its_record_does_not_name() {
    let mut fake = Fake::new(false);
    let mut record = fake.record().unwrap();
    let source = endpoint(&fake.native.state().unwrap(), "a/data").unwrap();
    for slot in [PLAN, PAIR] {
        fake.attachments()
            .set(
                &source,
                &[(
                    format!("{}0000", key(ID, slot).unwrap().prefix()),
                    "00".into(),
                )],
            )
            .unwrap();
    }
    assert_eq!(fake.chunks().len(), 2);
    assert_eq!(
        abandon_between_with("a/data", "b/data", &mut record, &mut fake).unwrap(),
        None
    );
    assert!(fake.chunks().is_empty());
    assert!(record.transfer().is_none());
    // Partial chunks of the plan's own key, left between admission and the
    // write, are replaced by its full write.
    let plan = fake.prepare();
    fake.attachments()
        .set(
            &source,
            &[(
                format!("{}0005", key(ID, PLAN).unwrap().prefix()),
                "00".into(),
            )],
        )
        .unwrap();
    begin(&mut record, plan, &mut fake).unwrap();
    assert_no_records_left(&fake, "begun over leftovers");
}

/// An abandon before Received, of a bootstrap or into an existing copy, ends
/// the transfer in its record before its attachments go, through every cut:
/// while the record names the plan its chunks are whole, and the copy stays
/// fenced with the same left-behind name.
#[test]
fn an_abandon_records_its_end_before_removing_the_attachments_through_every_cut() {
    for bootstrap in [true, false] {
        let setup = || {
            let (mut fake, _) = before_first_stream(bootstrap);
            let record = fake.recorded().unwrap();
            assert_eq!(record.transfer().map(|t| t.phase), Some(Phase::Fenced));
            (fake, record)
        };
        let (mut reference, mut record) = setup();
        let whole = reference.chunks().len();
        assert_eq!(whole, named_chunks(&record));
        let base = reference.native.effects;
        let left = abandon_between_with("a/data", "b/data", &mut record, &mut reference).unwrap();
        assert_eq!(left.is_some(), bootstrap);
        // Its end names only what it left, by incarnation.
        let ended = record.transfer().unwrap();
        assert_eq!(
            TransferProgress {
                left: None,
                ..ended.clone()
            },
            TransferProgress::ended(Phase::Abandoned)
        );
        assert_eq!(ended.left.as_ref().map(|e| e.name.clone()), left);
        assert!(reference.chunks().is_empty());
        for cut in base + 1..=reference.native.effects {
            for after in [false, true] {
                let context = format!("bootstrap={bootstrap} cut={cut} after={after}");
                let (mut fake, mut record) = setup();
                fake.native.cut = Some((cut, after));
                assert!(abandon_between_with("a/data", "b/data", &mut record, &mut fake).is_err());
                fake.native.crashed = false;
                fake.native.cut = None;
                let mut record = fake.recorded().unwrap();
                let progress = record.transfer().unwrap().clone();
                if progress.plan.is_some() {
                    assert_eq!(fake.chunks().len(), whole, "{context}");
                } else {
                    assert_eq!(progress.phase, Phase::Abandoned, "{context}");
                }
                let again = abandon_between_with("a/data", "b/data", &mut record, &mut fake)
                    .unwrap_or_else(|e| panic!("{context}: {e}"));
                if progress.plan.is_some() {
                    assert_eq!(again, left, "{context}");
                }
                assert!(fake.chunks().is_empty(), "{context}");
                assert_eq!(fake.native.holds, reference.native.holds);
                assert!(
                    !fake
                        .native
                        .effective("a/data")
                        .contains_key(management::PENDING_PROPERTY)
                );
            }
        }
    }
}
/// How many chunks the plan RECORD names has.
fn named_chunks(record: &Journal<Standalone>) -> usize {
    let named = serde_json::to_value(record.transfer().unwrap().plan.as_ref().unwrap()).unwrap();
    named["chunks"].as_u64().unwrap() as usize
}

/// A holder renamed since keeps its chunks: a discard refuses and names it.
/// One gone took them with it: a discard does nothing.
#[test]
fn a_discard_refuses_a_renamed_holder_and_does_nothing_once_it_is_gone() {
    let mut fake = Fake::new(false);
    let record = fake.record().unwrap();
    let source = endpoint(&fake.native.state().unwrap(), "a/data").unwrap();
    let chunk = format!("{}0000", key(ID, PLAN).unwrap().prefix());
    fake.attachments()
        .set(&source, &[(chunk, "00".into())])
        .unwrap();
    let mut renamed = fake.clone();
    {
        let n = &mut renamed.native;
        let member = n
            .members
            .iter_mut()
            .find(|m| m.endpoint.name == "a/data")
            .unwrap();
        member.endpoint.name = "a/moved".into();
        for point in &mut member.snapshots {
            point.name = point.name.replace("a/data@", "a/moved@");
        }
        let properties = n.properties.remove("a/data").unwrap();
        n.properties.insert("a/moved".into(), properties);
    }
    let effects = renamed.native.effects;
    let error = discard(&record, &mut renamed).unwrap_err().to_string();
    assert!(error.contains("a/data is now a/moved"), "{error}");
    assert!(error.contains("rename it back"), "{error}");
    assert_eq!(renamed.native.effects, effects);
    assert_eq!(renamed.chunks().len(), 1);
    let mut gone = fake;
    gone.native.members.retain(|m| m.endpoint.name != "a/data");
    gone.native.properties.remove("a/data");
    let effects = gone.native.effects;
    discard(&record, &mut gone).unwrap();
    assert_eq!(gone.native.effects, effects);
}

/// The transfer's attachments are set aside only where they belong: on the
/// holder, local and with its first plan chunk, and below it inherited with
/// the holder's value. Anything else is drift and refuses.
#[test]
fn attachment_chunks_off_the_holder_or_changed_below_it_refuse_as_drift() {
    let mut fake = Fake::new(false);
    fake.native
        .members
        .push(plan::tests::member("a/data/child", 1, 12, &[]));
    fake.native
        .members
        .sort_by(|a, b| a.endpoint.name.cmp(&b.endpoint.name));
    let plan = fake.prepare();
    let mut record = fake.record().unwrap();
    let operation = commit(&mut record, plan, &mut fake).unwrap();
    let state = fake.native.state().unwrap();
    let chunk = format!("{}0000", key(ID, PLAN).unwrap().prefix());
    let clean = clean_state(&state, &operation, ID).unwrap();
    for name in ["a/data", "a/data/child"] {
        assert!(
            !clean.dataset_properties[name].contains_key(&chunk),
            "{name}"
        );
    }
    assert_eq!(
        state.dataset_properties["a/data/child"][&chunk].source,
        "inherited from a/data"
    );
    let drift = |change: &dyn Fn(&mut NativeState), why: &str| {
        let mut state = state.clone();
        change(&mut state);
        let error = clean_state(&state, &operation, ID).unwrap_err().to_string();
        assert!(error.contains(why), "{error}");
    };
    let copy = state.dataset_properties["a/data"][&chunk].clone();
    drift(
        &|state| {
            state
                .dataset_properties
                .get_mut("b/data")
                .unwrap()
                .insert(chunk.clone(), copy.clone());
        },
        &format!("attachment drifted on b/data: {chunk}"),
    );
    drift(
        &|state| {
            let child = state.dataset_properties.get_mut("a/data/child").unwrap();
            child.get_mut(&chunk).unwrap().source = "local".into();
        },
        &format!("attachment drifted on a/data/child: {chunk}"),
    );
    drift(
        &|state| {
            let child = state.dataset_properties.get_mut("a/data/child").unwrap();
            child.get_mut(&chunk).unwrap().value = "00".into();
        },
        &format!("attachment drifted on a/data/child: {chunk}"),
    );
    drift(
        &|state| {
            state
                .dataset_properties
                .get_mut("a/data")
                .unwrap()
                .remove(&chunk);
        },
        "plan attachment disappeared from a/data",
    );
}

/// A record naming its plan anywhere but on its holder is refused before
/// anything is read, and a plan whose holder is not a leaf of the transfer
/// is never named.
#[test]
fn a_plan_named_off_the_holder_or_held_off_the_transfer_refuses() {
    let mut fake = Fake::new(false);
    let (mut record, _) = recorded_operation(&mut fake);
    let copy = endpoint(&fake.native.state().unwrap(), "b/data").unwrap();
    let elsewhere = TransferProgress {
        plan: Some(Attachment::widest(&key(ID, PLAN).unwrap(), copy)),
        ..record.transfer().unwrap().clone()
    };
    record.advance(&mut fake, elsewhere).unwrap();
    let effects = fake.native.effects;
    let error = load(&record, &mut fake).unwrap_err().to_string();
    assert!(
        error.contains("is named on b/data, not its holder a/data"),
        "{error}"
    );
    assert_eq!(fake.native.effects, effects);

    let mut fake = Fake::new(false);
    let plan = fake.prepare();
    let root = endpoint(&fake.native.state().unwrap(), "a").unwrap();
    let mut record = Journal::begin(
        &mut fake,
        ID,
        "transfer",
        Standalone {
            holder: root,
            transfer: None,
        },
    )
    .unwrap();
    let error = commit(&mut record, plan, &mut fake)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not on a leaf of it"), "{error}");
    assert!(record.transfer().is_none());
    assert!(fake.recorded().unwrap().transfer().is_none());
}

/// A bootstrap's nested pair plan must be the one its verified copy made, and
/// its pair id the one its operation derives.
#[test]
fn a_nested_pair_plan_or_pair_id_other_than_the_verified_ones_refuses() {
    let mut reference = Fake::new(true);
    let plan = reference.prepare();
    reference.writes.clear();
    reference.run(plan).unwrap();
    let activating = reference
        .writes
        .iter()
        .find(|(_, w)| *w == Write::Record(Some(Phase::Activating)))
        .unwrap()
        .0;
    let mut fake = Fake::new(true);
    let plan = fake.prepare();
    fake.native.cut = Some((activating, true));
    assert!(fake.run(plan).is_err());
    fake.native.crashed = false;
    fake.native.cut = None;
    let operation = load(&fake.recorded().unwrap(), &mut fake).unwrap();
    assert_eq!(operation.progress.phase, Phase::Activating);
    validate(&operation, ID).unwrap();
    let mut other = operation.clone();
    other.pair_plan.as_mut().unwrap().left.members[0].mountpoint = Some("/elsewhere".into());
    let error = validate(&other, ID).unwrap_err().to_string();
    assert!(error.contains("nested pair plan differs"), "{error}");
    let mut other = operation;
    other.plan.bootstrap_pair_id = Some(PAIR_ID.into());
    let error = validate(&other, ID).unwrap_err().to_string();
    assert!(
        error.contains("not the one its operation derives"),
        "{error}"
    );
}

#[test]
fn a_pool_imported_with_an_altroot_since_the_plan_refuses_before_any_stream() {
    for (pool, bootstrap) in [("a", false), ("b", false), ("b", true)] {
        let mut fake = Fake::new(bootstrap);
        let plan = fake.prepare();
        let mut record = fake.record().unwrap();
        let mut operation = commit(&mut record, plan, &mut fake).unwrap();
        fake.altroots.insert(pool.into(), "/changed-import".into());
        let error = execute(&mut record, &mut operation, &mut fake)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("pool {pool} is imported with an altroot")),
            "{error}"
        );
        assert_eq!(fake.streams, 0);
    }
}

fn declare_pool_root_be(fake: &mut Fake) {
    let root = endpoint(&fake.native.state().unwrap(), "b").unwrap();
    fake.native
        .set(
            &root,
            &[
                ("mountpoint".into(), "/".into()),
                ("canmount".into(), "noauto".into()),
            ],
        )
        .unwrap();
}

#[test]
fn receive_destinations_inside_another_be_refuse_before_capture_or_any_effect() {
    for bootstrap in [false, true] {
        let mut fake = Fake::new(bootstrap);
        declare_pool_root_be(&mut fake);
        let effects = fake.native.effects;
        let members = fake.native.members.clone();
        let holds = fake.native.holds.clone();
        let error = transfer_with(
            &TransferRequest {
                source: "a/data".into(),
                destination: "b/data".into(),
            },
            &mut fake,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("inside boot environment b"),
            "{error}"
        );
        assert_eq!(fake.native.effects, effects);
        assert_eq!(fake.native.members, members);
        assert_eq!(fake.native.holds, holds);
        assert_eq!(fake.streams, 0);
    }
}

#[test]
fn a_new_boot_ancestor_on_receive_resume_refuses_without_more_effects() {
    for bootstrap in [false, true] {
        let (mut fake, _) = before_first_stream(bootstrap);
        declare_pool_root_be(&mut fake);
        let effects = fake.native.effects;
        let holds = fake.native.holds.clone();
        let mut record = fake.recorded().unwrap();
        let error = resume_between_with("a/data", "b/data", &mut record, &mut fake).unwrap_err();
        assert!(
            error.to_string().contains("inside boot environment b"),
            "{error}"
        );
        assert_eq!(fake.native.effects, effects);
        assert_eq!(fake.native.holds, holds);
        assert_eq!(fake.streams, 0);
        assert!(
            fake.native
                .effective("a/data")
                .contains_key(management::PENDING_PROPERTY)
        );
    }
}

#[test]
fn a_new_boot_ancestor_after_data_refuses_before_any_publication_effect() {
    for bootstrap in [false, true] {
        let mut reference = Fake::new(bootstrap);
        let plan = reference.prepare();
        reference.run(plan).unwrap();
        let mut fake = Fake::new(bootstrap);
        let plan = fake.prepare();
        fake.native.cut = Some((reference.first_stream_effect.unwrap(), true));
        assert!(fake.run(plan).is_err());
        fake.native.crashed = false;
        fake.native.cut = None;
        let mut record = fake.recorded().unwrap();
        let mut operation = load(&record, &mut fake).unwrap();
        declare_pool_root_be(&mut fake);
        let effects = fake.native.effects;
        let holds = fake.native.holds.clone();
        assert!(
            receive::finish(&mut record, &mut operation, ID, &mut fake, true)
                .unwrap_err()
                .to_string()
                .contains("inside boot environment b")
        );
        assert_eq!(fake.native.effects, effects);
        assert_eq!(fake.native.holds, holds);
        assert_eq!(fake.streams, 1);
        if bootstrap {
            assert!(
                !fake
                    .native
                    .members
                    .iter()
                    .any(|member| member.endpoint.name == "b/data")
            );
        }
    }
}

#[test]
fn receiving_the_existing_be_root_itself_keeps_its_role_and_is_allowed() {
    let mut fake = boot_fixture(false);
    let plan = fake.prepare();
    fake.run(plan).unwrap();
    assert_eq!(fake.native.effective("b/data")["mountpoint"].value, "/");
}

fn declare_source_be(fake: &mut Fake, name: &str) {
    let ep = endpoint(&fake.native.state().unwrap(), name).unwrap();
    fake.native
        .set(
            &ep,
            &[
                ("mountpoint".into(), "/".into()),
                ("canmount".into(), "noauto".into()),
            ],
        )
        .unwrap();
}

#[test]
fn sibling_boot_roots_and_a_selected_be_with_an_outside_ancestor_are_allowed() {
    let mut fake = Fake::new(true);
    fake.native
        .members
        .push(plan::tests::member("a/sibling", 1, 33, &[500, 501]));
    declare_source_be(&mut fake, "a/sibling");
    declare_source_be(&mut fake, "a/data");
    let state = fake.native.state().unwrap();
    plan_with(
        &state,
        &TransferRequest {
            source: "a/data".into(),
            destination: "b/data".into(),
        },
        ID,
        &mut fake,
    )
    .unwrap();
    let mut leaf = plan::tests::member("a/data/leaf", 1, 34, &[502]);
    leaf.snapshots[0].name = "a/data/leaf@s0".into();
    fake.native.members.push(leaf);
    fake.native
        .members
        .sort_by(|a, b| a.endpoint.name.cmp(&b.endpoint.name));
    let state = fake.native.state().unwrap();
    let plan = plan_with(
        &state,
        &TransferRequest {
            source: "a/data/leaf".into(),
            destination: "b/copy".into(),
        },
        ID,
        &mut fake,
    )
    .unwrap();
    assert_eq!(plan.source.members.len(), 1);
    assert_eq!(fake.streams, 0);
}

/// A frozen plan member for property tests.
pub(crate) fn frozen_member() -> Member {
    let mut fake = Fake::new(true);
    fake.prepare().source.members[""].clone()
}

#[test]
fn a_new_encrypted_copy_is_its_own_root_and_takes_its_source_roots_key_location() {
    let mut fake = Fake::new(true);
    fake.native.encrypted = true;
    fake.native.roots.insert("a/data".into(), "a".into());
    fake.wrappings.insert(
        "a".into(),
        Wrapping {
            keylocation: "file:///etc/zfs/a.key".into(),
            ..Fake::wrapped("1")
        },
    );
    let plan = fake.prepare();
    fake.run(plan).unwrap();
    let state = fake.native.state().unwrap();
    let copy = state
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == "b/data")
        .unwrap();
    assert_eq!(copy.encryptionroot.as_deref(), Some("b/data"));
    assert_eq!(
        fake.native.effective("b/data")["keylocation"].value,
        "file:///etc/zfs/a.key"
    );
}

#[test]
fn a_stream_into_a_copy_that_inherits_its_key_needs_provably_equal_wrapping() {
    let encrypted = |held: Wrapping, sent: Wrapping| {
        let mut fake = Fake::new(false);
        fake.native.encrypted = true;
        fake.native.roots.insert("b/data".into(), "b".into());
        fake.wrappings.insert("a/data".into(), sent);
        fake.wrappings.insert("b".into(), held);
        fake
    };
    // The sync back after `primary`: the copy's root was received from the
    // sender's, so their passphrase wrapping is equal.
    let mut fake = encrypted(Fake::wrapped("7"), Fake::wrapped("7"));
    let plan = fake.prepare();
    fake.run(plan).unwrap();
    assert_eq!(fake.streams, 1);

    let keyfile = |location: &str| Wrapping {
        keyformat: "raw".into(),
        keylocation: location.into(),
        ..Fake::wrapped("0")
    };
    let mut fake = encrypted(keyfile("file:///k"), keyfile("file:///k"));
    for root in ["a/data", "b"] {
        fake.key_files.insert((root.into(), "file:///k".into()));
    }
    let plan = fake.prepare();
    fake.run(plan).unwrap();
    assert_eq!(fake.streams, 1);

    for (held, sent, why) in [
        (
            Fake::wrapped("7"),
            Fake::wrapped("8"),
            "its key was changed",
        ),
        (keyfile("prompt"), keyfile("prompt"), "cannot prove"),
        (
            keyfile("file:///k"),
            keyfile("file:///k"),
            "does not open both",
        ),
        (
            Fake::wrapped("7"),
            keyfile("file:///k"),
            "different key format",
        ),
    ] {
        let mut fake = encrypted(held, sent);
        let effects = fake.native.effects;
        let error = transfer_with(
            &TransferRequest {
                source: "a/data".into(),
                destination: "b/data".into(),
            },
            &mut fake,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(why) && error.contains("zfs change-key b/data"),
            "{error}"
        );
        // Refused at admission: no capture, no record, no stream.
        assert_eq!((fake.native.effects, fake.streams), (effects, 0), "{why}");
    }
}

#[test]
fn a_pool_imported_with_an_altroot_is_never_written() {
    for (pool, bootstrap) in [("a", false), ("b", false), ("b", true)] {
        let mut fake = Fake::new(bootstrap);
        fake.altroots = BTreeMap::from([(pool.into(), "/mnt".into())]);
        let effects = fake.native.effects;
        let error = transfer_with(
            &TransferRequest {
                source: "a/data".into(),
                destination: "b/data".into(),
            },
            &mut fake,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(&format!("pool {pool} is imported with an altroot")),
            "{error}"
        );
        assert_eq!((fake.native.effects, fake.streams), (effects, 0));
    }
}
