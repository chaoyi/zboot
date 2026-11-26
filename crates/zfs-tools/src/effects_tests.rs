use super::*;
use crate::engine::{
    CanMount, Dataset, Encryption, Inspection, KeyStatus, ObjsetId, Pool, Snapshot,
    SnapshotIdentity, Txg, lock::LockError, native::PropertyInventory,
};
use crate::{ObservationStop, QueryCleanup};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    rc::Rc,
    time::Instant,
};

fn identity(id: u64) -> DatasetIdentity {
    DatasetIdentity {
        pool_guid: Guid::new(1),
        guid: Guid::new(id),
        createtxg: Txg::new(id + 10),
        objsetid: ObjsetId::new(id + 20),
    }
}
fn dataset(name: &str, id: u64, kind: DatasetKind) -> Dataset {
    let volume = kind == DatasetKind::Volume;
    Dataset {
        name: name.into(),
        kind,
        guid: Guid::new(id),
        identity: identity(id),
        used_bytes: 0,
        available_bytes: 1 << 30,
        referenced_bytes: 0,
        mountpoint: (!volume).then(|| format!("/{name}")),
        volume_size_bytes: volume.then_some(1 << 20),
        mounted: (!volume).then_some(false),
        readonly: false,
        canmount: (!volume).then_some(CanMount::On),
        origin: None,
        encryption: Encryption::Off,
        keystatus: KeyStatus::Unencrypted,
        encryptionroot: None,
        staging: None,
        pending: None,
    }
}
fn snapshot(name: &str, dataset_guid: u64, id: u64) -> Snapshot {
    Snapshot {
        name: name.into(),
        guid: Guid::new(id),
        dataset_guid: Guid::new(dataset_guid),
        identity: SnapshotIdentity {
            pool_guid: Guid::new(1),
            guid: Guid::new(id),
            createtxg: Txg::new(id),
            objsetid: ObjsetId::new(id + 1000),
        },
        userrefs: 0,
        defer_destroy: false,
        clones: vec![],
        holds: vec![],
        creation_epoch_seconds: 1,
        used_bytes: 0,
        referenced_bytes: 0,
    }
}
fn prop(value: impl ToString, source: &str) -> NativeProperty {
    NativeProperty {
        value: value.to_string(),
        source: source.into(),
    }
}
fn identity_properties(id: u64) -> BTreeMap<String, NativeProperty> {
    BTreeMap::from([
        ("guid".into(), prop(id, "-")),
        ("createtxg".into(), prop(id + 10, "-")),
        ("objsetid".into(), prop(id + 20, "-")),
    ])
}

/// tank (1) with tank/vm (2) holding a volume with two snapshots (3), a
/// clone (4) of tank/base@s and an empty volume (7); tank/base (5) is that
/// origin's volume; tank/secure (6) is an encryption root.
fn fixture() -> NativeState {
    let mut datasets = vec![
        dataset("tank", 1, DatasetKind::Filesystem),
        dataset("tank/base", 5, DatasetKind::Volume),
        dataset("tank/secure", 6, DatasetKind::Filesystem),
        dataset("tank/vm", 2, DatasetKind::Filesystem),
        dataset("tank/vm/clone", 4, DatasetKind::Volume),
        dataset("tank/vm/disk", 3, DatasetKind::Volume),
        dataset("tank/vm/empty", 7, DatasetKind::Volume),
    ];
    datasets[4].origin = Some("tank/base@s".into());
    datasets[2].encryption = Encryption::Aes256Gcm;
    datasets[2].keystatus = KeyStatus::Unavailable;
    datasets[2].encryptionroot = Some("tank/secure".into());
    let mut base = snapshot("tank/base@s", 5, 40);
    base.clones = vec!["tank/vm/clone".into()];
    let snapshots = vec![
        base,
        snapshot("tank/vm/disk@a", 3, 50),
        snapshot("tank/vm/disk@b", 3, 60),
    ];
    let dataset_properties = datasets
        .iter()
        .map(|d| {
            let mut properties = identity_properties(d.identity.guid.get());
            if d.name == "tank/secure" {
                properties.insert("keylocation".into(), prop("prompt", "local"));
            }
            (d.name.clone(), properties)
        })
        .collect();
    NativeState {
        inspection: Inspection {
            schema_version: 3,
            imported_only: true,
            non_atomic: true,
            recursive: true,
            requested_datasets: vec![],
            pools: vec![Pool {
                name: "tank".into(),
                guid: Guid::new(1),
                size_bytes: 1 << 30,
                allocated_bytes: 0,
                free_bytes: 1 << 30,
                health: "ONLINE".into(),
                bootfs: None,
            }],
            datasets,
            snapshots: Some(snapshots),
        },
        dataset_properties,
        pool_properties: PropertyInventory::from([(
            "tank".into(),
            BTreeMap::from([
                ("guid".into(), prop(1, "-")),
                ("load_guid".into(), prop(77, "-")),
            ]),
        )]),
    }
}
fn with(change: impl FnOnce(&mut NativeState)) -> NativeState {
    let mut state = fixture();
    change(&mut state);
    state
}

fn target(name: &str) -> DatasetTarget {
    let observed = fixture();
    let d = observed
        .inspection
        .datasets
        .iter()
        .find(|d| d.name == name)
        .unwrap();
    DatasetTarget::new(name, d.identity.clone()).unwrap()
}
fn point(name: &str) -> SnapshotRef {
    fixture()
        .inspection
        .snapshots
        .unwrap()
        .iter()
        .find(|s| s.name == name)
        .unwrap()
        .point()
}
fn pool() -> PoolTarget {
    PoolTarget::new("tank", Guid::new(1)).unwrap()
}
fn assign(key: &str, value: &str) -> PropertyAssignment {
    PropertyAssignment::new(key, value).unwrap()
}
fn device(path: &str) -> DevicePath {
    DevicePath::new(path).unwrap()
}

type Events = Rc<RefCell<Vec<String>>>;

/// Observations in order (the last repeats), a recorded run and its result.
struct Fake {
    states: VecDeque<NativeState>,
    events: Events,
    ran: Ran,
    input: Option<Vec<u8>>,
}
impl Fake {
    fn new(events: &Events, states: Vec<NativeState>) -> Self {
        Self {
            states: states.into(),
            events: events.clone(),
            ran: Ran::Exited {
                code: 0,
                stderr: String::new(),
            },
            input: None,
        }
    }
}
impl Backend for Fake {
    fn observe(&mut self, _: Option<Duration>) -> Result<NativeState, Error> {
        self.events.borrow_mut().push("observe".into());
        Ok(if self.states.len() > 1 {
            self.states.pop_front().unwrap()
        } else {
            self.states.front().unwrap().clone()
        })
    }
    fn run(
        &mut self,
        _: &lock::WriterLock,
        program: &'static str,
        args: &[String],
        input: Option<&[u8]>,
        _: Duration,
    ) -> Ran {
        self.events
            .borrow_mut()
            .push(format!("run {program} {}", args.join(" ")));
        self.input = input.map(<[u8]>::to_vec);
        self.ran.clone()
    }
}

fn lock_path() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zfs-tools-effects-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("writer.lock")
}
fn session_at(path: &Path) -> WriterSession {
    WriterSession {
        held: lock::WriterLock::acquire_at(path, "effects test", Duration::ZERO, |_| {}).unwrap(),
        poisoned: None,
    }
}
fn session() -> WriterSession {
    session_at(&lock_path())
}
fn guard(events: &Events) -> impl FnMut(&GuardCheck<'_>) -> Result<(), Error> + use<> {
    let events = events.clone();
    move |_| {
        events.borrow_mut().push("guard".into());
        Ok(())
    }
}
const SECOND: Duration = Duration::from_secs(1);

/// Admit `targets` on the fixture, dispatch `effect` on `dispatch_state`,
/// and return the result with every event.
fn run(
    targets: &[EffectTarget],
    effect: &Effect<'_>,
    dispatch_state: NativeState,
) -> (Result<EffectReply, Error>, Vec<String>) {
    let events = Events::default();
    let mut session = session();
    let mut fake = Fake::new(&events, vec![fixture(), dispatch_state]);
    let mut scope = session
        .admit_effects_with(targets, guard(&events), None, &mut fake)
        .unwrap();
    let result = scope.dispatch_with(effect, SECOND, &mut fake);
    let events = events.borrow().clone();
    (result, events)
}
fn argv(targets: &[EffectTarget], effect: &Effect<'_>) -> String {
    let (result, events) = run(targets, effect, fixture());
    assert_eq!(result.unwrap(), EffectReply::Succeeded);
    // Admission: guard, observation. Dispatch: guard, fresh observation,
    // admission and binding, guard again, then the spawn.
    assert_eq!(
        events[..5],
        ["guard", "observe", "guard", "observe", "guard"]
    );
    assert_eq!(events.len(), 6, "{events:?}");
    events[5].strip_prefix("run ").unwrap().to_string()
}
fn refused(targets: &[EffectTarget], effect: &Effect<'_>, state: NativeState, why: &str) {
    let (result, events) = run(targets, effect, state);
    let error = result.unwrap_err().to_string();
    assert!(error.contains(why), "{error}");
    assert!(!events.iter().any(|e| e.starts_with("run")), "{events:?}");
}
fn exact(name: &str) -> EffectTarget {
    EffectTarget::dataset(target(name))
}
fn subtree(name: &str) -> EffectTarget {
    EffectTarget::subtree(target(name))
}

#[test]
fn every_shape_has_its_pinned_argv() {
    let vm = target("tank/vm");
    let bound = pool().with_load_guid(Guid::new(77)).unwrap();
    let cases: Vec<(Vec<EffectTarget>, Effect<'_>, &str)> = vec![
        (
            vec![exact("tank/vm")],
            Effect::create_volume(
                &vm,
                "tank/vm/new",
                1 << 20,
                16384,
                &[assign("compression", "zstd")],
            )
            .unwrap(),
            "zfs create -s -V 1048576 -o volblocksize=16384 -o compression=zstd tank/vm/new",
        ),
        (
            vec![exact("tank/vm")],
            Effect::create_filesystem(
                &vm,
                "tank/vm/data",
                &[
                    assign("readonly", "off"),
                    assign("mountpoint", "/srv/data"),
                    assign("canmount", "noauto"),
                ],
            )
            .unwrap(),
            "zfs create -u -o readonly=off -o mountpoint=/srv/data -o canmount=noauto tank/vm/data",
        ),
        (
            vec![exact("tank/base"), exact("tank/vm")],
            Effect::clone_snapshot(&point("tank/base@s"), &vm, "tank/vm/copy").unwrap(),
            "zfs clone -u tank/base@s tank/vm/copy",
        ),
        (
            vec![exact("tank/vm/empty")],
            Effect::destroy(&target("tank/vm/empty")).unwrap(),
            "zfs destroy tank/vm/empty",
        ),
        (
            vec![exact("tank/vm/disk")],
            Effect::rollback(&target("tank/vm/disk"), &point("tank/vm/disk@b")).unwrap(),
            "zfs rollback tank/vm/disk@b",
        ),
        (
            vec![subtree("tank/vm")],
            Effect::set_properties(
                &vm,
                &[
                    assign("mountpoint", "none"),
                    assign("org.fleet:pending", "x"),
                ],
            )
            .unwrap(),
            "zfs set -u mountpoint=none org.fleet:pending=x tank/vm",
        ),
        (
            vec![exact("tank/vm")],
            Effect::set_properties(&vm, &[assign("canmount", "noauto")]).unwrap(),
            "zfs set -u canmount=noauto tank/vm",
        ),
        (
            vec![subtree("tank/vm")],
            Effect::inherit_property(&vm, "mountpoint").unwrap(),
            "zfs inherit mountpoint tank/vm",
        ),
        (
            vec![exact("tank/secure")],
            Effect::unload_key(&target("tank/secure")),
            "zfs unload-key tank/secure",
        ),
        (
            vec![exact("tank/vm")],
            Effect::unmount(&vm),
            "zfs unmount tank/vm",
        ),
        (
            vec![EffectTarget::absent_pool("data").unwrap()],
            Effect::create_pool(
                "data",
                &device("/dev/disk/by-id/nvme-x-part1"),
                &[assign("ashift", "12"), assign("cachefile", "none")],
                &[
                    assign("encryption", "aes-256-gcm"),
                    assign("org.fleet:pending", "id"),
                ],
                None,
            )
            .unwrap(),
            "zpool create -o ashift=12 -o cachefile=none -O encryption=aes-256-gcm -O org.fleet:pending=id data /dev/disk/by-id/nvme-x-part1",
        ),
        (
            vec![EffectTarget::exported_pool(Guid::new(100)).unwrap()],
            Effect::import_pool(Guid::new(100), &device("/dev/nvme0n1p1")).unwrap(),
            "zpool import -N -o cachefile=none -d /dev/nvme0n1p1 100",
        ),
        (
            vec![EffectTarget::exported_pool(Guid::new(100)).unwrap()],
            Effect::import_pool_readonly(Guid::new(100), &device("/dev/nvme0n1p1")).unwrap(),
            "zpool import -N -o readonly=on -o cachefile=none -d /dev/nvme0n1p1 100",
        ),
        (
            vec![EffectTarget::pool(bound.clone())],
            Effect::export_pool(&bound),
            "zpool export tank",
        ),
        (
            vec![EffectTarget::pool(pool())],
            Effect::sync_pool(&pool()),
            "zpool sync tank",
        ),
    ];
    for (targets, effect, expected) in &cases {
        assert_eq!(argv(targets, effect), *expected);
        // The argv a caller compares before any session is the one bound.
        let (program, args) = effect.argv();
        assert_eq!(format!("{program} {}", args.join(" ")), *expected);
    }
    // A read-only import is its own effect: a consent to one is not a
    // consent to the other.
    let leaf = device("/dev/nvme0n1p1");
    assert_ne!(
        Effect::import_pool(Guid::new(100), &leaf).unwrap(),
        Effect::import_pool_readonly(Guid::new(100), &leaf).unwrap()
    );
    assert!(Effect::import_pool_readonly(Guid::new(0), &leaf).is_err());
    refused(
        &[EffectTarget::exported_pool(Guid::new(100)).unwrap()],
        &Effect::import_pool_readonly(Guid::new(101), &leaf).unwrap(),
        fixture(),
        "not admitted as exported",
    );
}

#[test]
fn key_input_reaches_only_the_child_standard_input() {
    let key = b"correct horse\n";
    let effect = Effect::load_key(&target("tank/secure"), key).unwrap();
    let events = Events::default();
    let mut session = session();
    let mut fake = Fake::new(&events, vec![fixture()]);
    let mut scope = session
        .admit_effects_with(&[exact("tank/secure")], guard(&events), None, &mut fake)
        .unwrap();
    assert_eq!(
        scope.dispatch_with(&effect, SECOND, &mut fake).unwrap(),
        EffectReply::Succeeded
    );
    assert_eq!(
        events.borrow().last().unwrap(),
        "run zfs load-key tank/secure"
    );
    assert_eq!(fake.input.as_deref(), Some(&key[..]));
    let pool = Effect::create_pool(
        "data",
        &device("/dev/vdb"),
        &[],
        &[assign("keylocation", "prompt")],
        Some(key),
    )
    .unwrap();
    assert_eq!(pool.input, Some(&key[..]));
    let shown = format!("{pool:?}{effect:?}");
    assert!(
        !shown.contains("horse") && shown.contains("input_bytes: Some(14)"),
        "{shown}"
    );
    assert!(Effect::load_key(&target("tank/secure"), b"").is_err());
    assert!(Effect::load_key(&target("tank/secure"), &[0; 4097]).is_err());
}

#[test]
fn management_keys_are_never_set_or_inherited() {
    for key in ["zboot:pending", "zboot:pair", "org.zfs-tools:x"] {
        let error = PropertyAssignment::new(key, "v").unwrap_err().to_string();
        assert!(error.contains("management state"), "{error}");
        assert!(Effect::inherit_property(&target("tank/vm"), key).is_err());
    }
    for key in ["", "-o", "Mountpoint", "a=b", "a b", "1x"] {
        assert!(PropertyAssignment::new(key, "v").is_err(), "{key}");
    }
    assert!(PropertyAssignment::new("mountpoint", "/a\nb").is_err());
    let twice = [assign("compression", "lz4"), assign("compression", "off")];
    assert!(Effect::set_properties(&target("tank/vm"), &twice).is_err());
    assert!(Effect::set_properties(&target("tank/vm"), &[]).is_err());
    assert!(PropertyAssignment::new("org.fleet:pending", "id").is_ok());
}

#[test]
fn constructors_refuse_operands_outside_their_shape() {
    let vm = target("tank/vm");
    assert!(Effect::create_volume(&vm, "tank/other/x", 4096, 4096, &[]).is_err());
    assert!(Effect::create_volume(&vm, "tank/vm/x/y", 4096, 4096, &[]).is_err());
    assert!(Effect::create_volume(&vm, "tank/vm/x", 0, 4096, &[]).is_err());
    assert!(Effect::create_volume(&vm, "tank/vm/x", 6000, 4096, &[]).is_err());
    assert!(Effect::create_volume(&vm, "tank/vm/x", 6000, 3000, &[]).is_err());
    assert!(
        Effect::create_volume(&vm, "tank/vm/x", 4096, 4096, &[assign("volsize", "1")]).is_err()
    );
    assert!(Effect::destroy(&target("tank")).is_err());
    assert!(Effect::rollback(&target("tank/vm/empty"), &point("tank/vm/disk@b")).is_err());
    for path in [
        "dev/sda",
        "/dev//sda",
        "/dev/../sda",
        "/dev/-f",
        "/dev/sd\na",
        "/",
    ] {
        assert!(DevicePath::new(path).is_err(), "{path}");
    }
    assert!(PoolTarget::new("tank/vm", Guid::new(1)).is_err());
    assert!(PoolTarget::new("tank", Guid::new(0)).is_err());
    assert!(EffectTarget::exported_pool(Guid::new(0)).is_err());
    assert!(Effect::import_pool(Guid::new(0), &device("/dev/vdb")).is_err());
}

#[test]
fn operands_must_be_admitted_targets() {
    let vm = target("tank/vm");
    refused(
        &[exact("tank/vm/empty")],
        &Effect::unmount(&vm),
        fixture(),
        "not an admitted target",
    );
    // A member of an admitted subtree is admitted.
    assert_eq!(
        argv(
            &[subtree("tank/vm")],
            &Effect::destroy(&target("tank/vm/empty")).unwrap()
        ),
        "zfs destroy tank/vm/empty"
    );
    // Another incarnation at an admitted name is not.
    let stale = DatasetTarget::new("tank/vm/empty", identity(99)).unwrap();
    refused(
        &[subtree("tank/vm")],
        &Effect::destroy(&stale).unwrap(),
        fixture(),
        "another incarnation",
    );
    // Pool shapes need their own pool targets.
    refused(
        &[exact("tank/vm")],
        &Effect::sync_pool(&pool()),
        fixture(),
        "not admitted",
    );
    refused(
        &[exact("tank/vm")],
        &Effect::import_pool(Guid::new(100), &device("/dev/vdb")).unwrap(),
        fixture(),
        "not admitted as exported",
    );
    refused(
        &[exact("tank/vm")],
        &Effect::create_pool("data", &device("/dev/vdb"), &[], &[], None).unwrap(),
        fixture(),
        "not admitted as absent",
    );
    // An admission names each target once.
    let events = Events::default();
    let mut session = session();
    let mut fake = Fake::new(&events, vec![fixture()]);
    assert!(
        session
            .admit_effects_with(
                &[exact("tank/vm"), exact("tank/vm")],
                guard(&events),
                None,
                &mut fake,
            )
            .is_err()
    );
    assert!(
        session
            .admit_effects_with(&[], guard(&events), None, &mut fake)
            .is_err()
    );
}

#[test]
fn inheritable_changes_need_the_subtree_admitted() {
    let vm = target("tank/vm");
    for effect in [
        Effect::set_properties(&vm, &[assign("mountpoint", "/x")]).unwrap(),
        Effect::set_properties(
            &vm,
            &[assign("canmount", "off"), assign("org.fleet:x", "1")],
        )
        .unwrap(),
        Effect::inherit_property(&vm, "mountpoint").unwrap(),
        Effect::inherit_property(&vm, "org.fleet:pending").unwrap(),
    ] {
        refused(
            &[exact("tank/vm")],
            &effect,
            fixture(),
            "needs its subtree admitted",
        );
    }
    // A descendant created since the subtree admission refuses dispatch.
    let grown = with(|s| {
        s.inspection
            .datasets
            .push(dataset("tank/vm/late", 30, DatasetKind::Volume));
        s.dataset_properties
            .insert("tank/vm/late".into(), identity_properties(30));
    });
    refused(
        &[subtree("tank/vm")],
        &Effect::inherit_property(&vm, "mountpoint").unwrap(),
        grown,
        "changed since admission",
    );
}

#[test]
fn destroy_refuses_what_a_flagless_destroy_must_not_take() {
    refused(
        &[exact("tank/vm/disk")],
        &Effect::destroy(&target("tank/vm/disk")).unwrap(),
        fixture(),
        "has snapshots",
    );
    refused(
        &[subtree("tank/vm")],
        &Effect::destroy(&target("tank/vm")).unwrap(),
        fixture(),
        "has descendants",
    );
    let boot = with(|s| s.inspection.pools[0].bootfs = Some("tank/vm/empty".into()));
    refused(
        &[exact("tank/vm/empty")],
        &Effect::destroy(&target("tank/vm/empty")).unwrap(),
        boot,
        "boot default",
    );
    // The clone is the only clone of an external origin marked deferred:
    // destroying it would destroy tank/base@s too.
    let deferred = with(|s| s.inspection.snapshots.as_mut().unwrap()[0].defer_destroy = true);
    refused(
        &[exact("tank/vm/clone")],
        &Effect::destroy(&target("tank/vm/clone")).unwrap(),
        deferred,
        "deferred origin tank/base@s",
    );
    // Not deferred, or not the last clone: it is destroyed alone.
    assert_eq!(
        argv(
            &[exact("tank/vm/clone")],
            &Effect::destroy(&target("tank/vm/clone")).unwrap()
        ),
        "zfs destroy tank/vm/clone"
    );
    let shared = with(|s| {
        let origin = &mut s.inspection.snapshots.as_mut().unwrap()[0];
        origin.defer_destroy = true;
        origin.clones.push("tank/other".into());
    });
    let (result, _) = run(
        &[exact("tank/vm/clone")],
        &Effect::destroy(&target("tank/vm/clone")).unwrap(),
        shared,
    );
    assert_eq!(result.unwrap(), EffectReply::Succeeded);
}

#[test]
fn rollback_clone_create_and_key_operands_are_bound_to_the_fresh_observation() {
    let disk = target("tank/vm/disk");
    refused(
        &[exact("tank/vm/disk")],
        &Effect::rollback(&disk, &point("tank/vm/disk@a")).unwrap(),
        fixture(),
        "not the newest snapshot",
    );
    let replaced = with(|s| {
        s.inspection.snapshots.as_mut().unwrap()[2].identity.guid = Guid::new(61);
    });
    refused(
        &[exact("tank/vm/disk")],
        &Effect::rollback(&disk, &point("tank/vm/disk@b")).unwrap(),
        replaced,
        "changed or is gone",
    );
    let vm = target("tank/vm");
    let deferred = with(|s| s.inspection.snapshots.as_mut().unwrap()[0].defer_destroy = true);
    refused(
        &[exact("tank/base"), exact("tank/vm")],
        &Effect::clone_snapshot(&point("tank/base@s"), &vm, "tank/vm/copy").unwrap(),
        deferred,
        "deferred destruction",
    );
    refused(
        &[exact("tank/vm")],
        &Effect::clone_snapshot(&point("tank/base@s"), &vm, "tank/vm/copy").unwrap(),
        fixture(),
        "not an admitted target",
    );
    refused(
        &[exact("tank/base"), exact("tank/vm")],
        &Effect::clone_snapshot(&point("tank/base@s"), &vm, "tank/vm/disk").unwrap(),
        fixture(),
        "already exists",
    );
    refused(
        &[exact("tank/vm")],
        &Effect::create_volume(&vm, "tank/vm/disk", 4096, 4096, &[]).unwrap(),
        fixture(),
        "already exists",
    );
    refused(
        &[exact("tank/vm/disk")],
        &Effect::create_filesystem(&disk, "tank/vm/disk/x", &[]).unwrap(),
        fixture(),
        "is not a Filesystem",
    );
    refused(
        &[exact("tank/vm")],
        &Effect::load_key(&vm, b"k").unwrap(),
        fixture(),
        "not an encryption root",
    );
    let file = with(|s| {
        s.dataset_properties
            .get_mut("tank/secure")
            .unwrap()
            .insert("keylocation".into(), prop("file:///run/key", "local"));
    });
    refused(
        &[exact("tank/secure")],
        &Effect::load_key(&target("tank/secure"), b"k").unwrap(),
        file,
        "does not read its key from a prompt",
    );
    refused(
        &[exact("tank/vm/disk")],
        &Effect::unmount(&disk),
        fixture(),
        "is not a Filesystem",
    );
}

#[test]
fn pool_targets_bind_name_guid_and_import_instance() {
    let events = Events::default();
    let mut session = session();
    let mut fake = Fake::new(&events, vec![fixture()]);
    for (targets, why) in [
        (
            vec![EffectTarget::absent_pool("tank").unwrap()],
            "is imported",
        ),
        (
            vec![EffectTarget::exported_pool(Guid::new(1)).unwrap()],
            "is imported",
        ),
        (
            vec![EffectTarget::pool(
                PoolTarget::new("tank", Guid::new(2)).unwrap(),
            )],
            "admitted GUID",
        ),
        (
            vec![EffectTarget::pool(
                pool().with_load_guid(Guid::new(78)).unwrap(),
            )],
            "import instance",
        ),
    ] {
        let error = session
            .admit_effects_with(&targets, guard(&events), None, &mut fake)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains(why), "{error}");
    }
    // Re-imported between admission and export: load_guid drifted.
    let bound = pool().with_load_guid(Guid::new(77)).unwrap();
    let reimported = with(|s| {
        s.pool_properties
            .get_mut("tank")
            .unwrap()
            .insert("load_guid".into(), prop(78, "-"));
    });
    refused(
        &[EffectTarget::pool(bound.clone())],
        &Effect::export_pool(&bound),
        reimported,
        "import instance",
    );
    let marked = with(|s| {
        s.pool_properties
            .get_mut("tank")
            .unwrap()
            .insert("zboot:x".into(), prop(1, "local"));
    });
    let mut fake = Fake::new(&events, vec![marked]);
    assert!(
        session
            .admit_effects_with(
                &[EffectTarget::pool(pool())],
                guard(&events),
                None,
                &mut fake
            )
            .is_err()
    );
}

#[test]
fn a_target_changed_between_admission_and_spawn_is_refused() {
    // The volume was replaced at its name after admission.
    let replaced = with(|s| {
        let d = s
            .inspection
            .datasets
            .iter_mut()
            .find(|d| d.name == "tank/vm/empty")
            .unwrap();
        d.identity.objsetid = ObjsetId::new(999);
        s.dataset_properties
            .get_mut("tank/vm/empty")
            .unwrap()
            .insert("objsetid".into(), prop(999, "-"));
    });
    let (result, events) = run(
        &[exact("tank/vm/empty")],
        &Effect::destroy(&target("tank/vm/empty")).unwrap(),
        replaced,
    );
    assert!(result.unwrap_err().to_string().contains("tank/vm/empty"));
    // The guard ran before the fresh observation; nothing ran after it.
    assert_eq!(events, ["guard", "observe", "guard", "observe"]);
    // Management state written since admission refuses too.
    let pending = with(|s| {
        s.dataset_properties
            .get_mut("tank/vm/empty")
            .unwrap()
            .insert("zboot:pending".into(), prop(uuid::Uuid::new_v4(), "local"));
    });
    refused(
        &[exact("tank/vm/empty")],
        &Effect::destroy(&target("tank/vm/empty")).unwrap(),
        pending,
        "zboot:pending",
    );
}

#[test]
fn the_guard_runs_before_the_observation_and_again_before_the_spawn() {
    for refuse_at in 1..=3 {
        let events = Events::default();
        let calls = Rc::new(RefCell::new(0));
        let counter = calls.clone();
        let log = events.clone();
        let mut session = session();
        let mut fake = Fake::new(&events, vec![fixture()]);
        let admitted = session.admit_effects_with(
            &[exact("tank/vm")],
            move |_: &GuardCheck<'_>| {
                *counter.borrow_mut() += 1;
                log.borrow_mut().push("guard".into());
                if *counter.borrow() == refuse_at {
                    Err(Error::new("owner withdrew"))
                } else {
                    Ok(())
                }
            },
            None,
            &mut fake,
        );
        let result = match admitted {
            Ok(mut scope) => {
                scope.dispatch_with(&Effect::unmount(&target("tank/vm")), SECOND, &mut fake)
            }
            Err(error) => Err(error),
        };
        assert!(result.unwrap_err().to_string().contains("owner withdrew"));
        let expected: &[&str] = match refuse_at {
            1 => &["guard"],
            2 => &["guard", "observe", "guard"],
            _ => &["guard", "observe", "guard", "observe", "guard"],
        };
        assert_eq!(*events.borrow(), expected);
    }
}

#[test]
fn replies_report_the_command_and_membership_changes_end_the_admission() {
    let events = Events::default();
    let mut session = session();
    let mut fake = Fake::new(&events, vec![fixture()]);
    let mut scope = session
        .admit_effects_with(&[subtree("tank/vm")], guard(&events), None, &mut fake)
        .unwrap();
    let vm = target("tank/vm");
    fake.ran = Ran::Exited {
        code: 1,
        stderr: "cannot unmount: busy".into(),
    };
    assert_eq!(
        scope
            .dispatch_with(&Effect::unmount(&vm), SECOND, &mut fake)
            .unwrap(),
        EffectReply::Failed {
            status: 1,
            stderr: "cannot unmount: busy".into()
        }
    );
    fake.ran = Ran::Uncertain("deadline".into());
    assert_eq!(
        scope
            .dispatch_with(
                &Effect::inherit_property(&vm, "mountpoint").unwrap(),
                SECOND,
                &mut fake
            )
            .unwrap(),
        EffectReply::Uncertain {
            why: "deadline".into()
        }
    );
    // A child that never started changes nothing and keeps the admission.
    fake.ran = Ran::NotStarted("no zfs".into());
    let destroy = Effect::destroy(&target("tank/vm/empty")).unwrap();
    assert!(scope.dispatch_with(&destroy, SECOND, &mut fake).is_err());
    fake.ran = Ran::Exited {
        code: 1,
        stderr: "dataset is busy".into(),
    };
    assert!(matches!(
        scope.dispatch_with(&destroy, SECOND, &mut fake).unwrap(),
        EffectReply::Failed { .. }
    ));
    // Even a failed destroy may have changed membership.
    let before = events.borrow().len();
    let error = scope
        .dispatch_with(&Effect::unmount(&vm), SECOND, &mut fake)
        .unwrap_err()
        .to_string();
    assert!(error.contains("ended when zfs destroy"), "{error}");
    assert_eq!(
        events.borrow().len(),
        before,
        "refused without a guard or observation"
    );
}

#[test]
fn a_zero_deadline_is_refused_before_the_guard() {
    let events = Events::default();
    let mut session = session();
    let mut fake = Fake::new(&events, vec![fixture()]);
    let mut scope = session
        .admit_effects_with(&[exact("tank/vm")], guard(&events), None, &mut fake)
        .unwrap();
    assert!(
        scope
            .dispatch_with(
                &Effect::unmount(&target("tank/vm")),
                Duration::ZERO,
                &mut fake
            )
            .is_err()
    );
    assert_eq!(*events.borrow(), ["guard", "observe"]);
}

#[test]
fn an_unconfirmed_reap_poisons_the_session() {
    let events = Events::default();
    let mut session = session();
    let mut fake = Fake::new(&events, vec![fixture()]);
    let vm = target("tank/vm");
    {
        let mut scope = session
            .admit_effects_with(&[exact("tank/vm")], guard(&events), None, &mut fake)
            .unwrap();
        fake.ran = Ran::Unreaped("zfs exceeded its deadline, but it was not reaped".into());
        match scope
            .dispatch_with(&Effect::unmount(&vm), SECOND, &mut fake)
            .unwrap()
        {
            EffectReply::Uncertain { why } => assert!(why.contains("poisoned"), "{why}"),
            other => panic!("{other:?}"),
        }
        let before = events.borrow().len();
        let error = scope
            .dispatch_with(&Effect::unmount(&vm), SECOND, &mut fake)
            .unwrap_err()
            .to_string();
        assert!(error.contains("poisoned"), "{error}");
        assert_eq!(events.borrow().len(), before);
    }
    let before = events.borrow().len();
    assert!(
        session
            .admit_effects_with(&[exact("tank/vm")], guard(&events), None, &mut fake)
            .is_err()
    );
    assert!(session.admit(&[target("tank/vm")]).is_err());
    assert_eq!(events.borrow().len(), before);
}

/// Runs the session's real custody path with a shell in place of zfs.
struct Shell(String);
impl Backend for Shell {
    fn observe(&mut self, _: Option<Duration>) -> Result<NativeState, Error> {
        Ok(fixture())
    }
    fn run(
        &mut self,
        held: &lock::WriterLock,
        _: &'static str,
        _: &[String],
        input: Option<&[u8]>,
        deadline: Duration,
    ) -> Ran {
        let args = ["-c".into(), self.0.clone()];
        dispatch::run_in_custody(
            held,
            "/bin/sh",
            &args,
            input,
            deadline,
            dispatch::REAP_GRACE,
        )
    }
}
fn busy(path: &Path) -> bool {
    matches!(
        lock::WriterLock::acquire_at(path, "probe", Duration::ZERO, |_| {}),
        Err(LockError::Busy { .. })
    )
}
/// A concurrent test's fork can briefly keep a CLOEXEC copy until its exec.
fn eventually_free(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !busy(path) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn custody_comes_from_the_session_on_another_thread() {
    let path = lock_path();
    let release = path.with_file_name("release");
    let session = session_at(&path);
    let script = format!(
        "(while [ ! -e {} ]; do sleep 0.05; done) >/dev/null 2>&1 &",
        release.display()
    );
    // Acquired here, dispatched from a thread that never held custody.
    let reply = std::thread::spawn(move || {
        let mut session = session;
        let mut shell = Shell(script);
        let mut scope = session
            .admit_effects_with(&[exact("tank/vm")], |_| Ok(()), None, &mut shell)
            .unwrap();
        scope.dispatch_with(
            &Effect::unmount(&target("tank/vm")),
            SECOND * 10,
            &mut shell,
        )
    })
    .join()
    .unwrap();
    assert_eq!(reply.unwrap(), EffectReply::Succeeded);
    // The session is gone; its child's descendant still holds the lock.
    assert!(busy(&path));
    std::fs::write(&release, "").unwrap();
    assert!(eventually_free(&path));
}

#[test]
fn a_deadline_kills_the_group_without_poisoning_a_reaped_session() {
    let path = lock_path();
    let mut session = session_at(&path);
    let mut shell = Shell("sleep 30 >/dev/null 2>&1 & sleep 30".into());
    {
        let mut scope = session
            .admit_effects_with(&[exact("tank/vm")], |_| Ok(()), None, &mut shell)
            .unwrap();
        let reply = scope
            .dispatch_with(
                &Effect::unmount(&target("tank/vm")),
                Duration::from_millis(200),
                &mut shell,
            )
            .unwrap();
        assert!(
            matches!(&reply, EffectReply::Uncertain { why } if why.contains("reaped")),
            "{reply:?}"
        );
    }
    assert!(session.poisoned.is_none());
    drop(session);
    assert!(eventually_free(&path));
}

#[test]
fn a_session_can_move_to_another_thread() {
    fn send<T: Send>() {}
    send::<WriterSession>();
}

fn pair_state() -> NativeState {
    with(|s| {
        s.inspection
            .datasets
            .push(dataset("tank/pa", 10, DatasetKind::Filesystem));
        let mut secondary = dataset("tank/pb", 11, DatasetKind::Filesystem);
        secondary.readonly = true;
        secondary.canmount = Some(CanMount::NoAuto);
        s.inspection.datasets.push(secondary);
        let record = management::PairRecord {
            schema_version: 1,
            pair_id: "29c4aaaa-1111-4111-8111-111111111111".into(),
            endpoint: management::Endpoint {
                name: "tank/pa".into(),
                identity: identity(10),
            },
            peer: management::Endpoint {
                name: "tank/pb".into(),
                identity: identity(11),
            },
            role: management::Role::Primary,
        };
        for (name, id, record) in [
            ("tank/pa", 10, record.clone()),
            ("tank/pb", 11, record.counterpart()),
        ] {
            let mut properties = identity_properties(id);
            properties.insert(
                management::PAIR_PROPERTY.into(),
                prop(serde_json::to_string(&record).unwrap(), "local"),
            );
            s.dataset_properties.insert(name.into(), properties);
        }
    })
}

#[test]
fn management_reports_role_and_unfinished_work_read_only() {
    let s = pair_state();
    assert_eq!(
        management_of(&s, "tank/vm").unwrap().role(),
        &Role::Unpaired
    );
    let primary = management_of(&s, "tank/pa").unwrap();
    match primary.role() {
        Role::Primary { peer } => {
            assert_eq!(peer.name(), "tank/pb");
            assert_eq!(peer.identity(), &identity(11));
        }
        other => panic!("{other:?}"),
    }
    assert!(primary.unfinished().is_empty());
    assert!(matches!(
        management_of(&s, "tank/pb").unwrap().role(),
        Role::Secondary { peer } if peer.name() == "tank/pa"
    ));
    // A pending mark inherited from its parent, and the pool's record.
    let id = "29c4bbbb-1111-4111-8111-111111111111";
    let marked = with(|s| {
        for (name, source) in [
            ("tank/vm", "local"),
            ("tank/vm/disk", "inherited from tank/vm"),
        ] {
            s.dataset_properties
                .get_mut(name)
                .unwrap()
                .insert(management::PENDING_PROPERTY.into(), prop(id, source));
        }
        for (name, source) in [
            ("tank", "local"),
            ("tank/vm", "inherited from tank"),
            ("tank/vm/disk", "inherited from tank"),
        ] {
            s.dataset_properties
                .get_mut(name)
                .unwrap()
                .insert(management::OPERATION_PROPERTY.into(), prop("{}", source));
        }
    });
    let management = management_of(&marked, "tank/vm/disk").unwrap();
    assert_eq!(management.role(), &Role::Unpaired);
    assert_eq!(
        management.unfinished(),
        [
            Unfinished::OperationRecord {
                pool: "tank".into()
            },
            Unfinished::Pending {
                id: id.into(),
                holder: "tank/vm".into()
            }
        ]
    );
    // A key this build does not read is an error, never a role.
    let unknown = with(|s| {
        s.dataset_properties
            .get_mut("tank/vm")
            .unwrap()
            .insert("zboot:unknown".into(), prop(1, "local"));
    });
    assert!(management_of(&unknown, "tank/vm").is_err());
    assert!(management_of(&s, "tank/absent").is_err());
}

#[test]
fn destroy_and_rollback_refuse_paired_datasets() {
    let pa = DatasetTarget::new("tank/pa", identity(10)).unwrap();
    for effect in [
        Effect::destroy(&pa).unwrap(),
        Effect::rollback(
            &pa,
            &SnapshotRef {
                name: "tank/pa@s".into(),
                dataset_guid: Guid::new(10),
                identity: SnapshotIdentity {
                    pool_guid: Guid::new(1),
                    guid: Guid::new(70),
                    createtxg: Txg::new(70),
                    objsetid: ObjsetId::new(1070),
                },
            },
        )
        .unwrap(),
    ] {
        let mut state = pair_state();
        state
            .inspection
            .snapshots
            .as_mut()
            .unwrap()
            .push(snapshot("tank/pa@s", 10, 70));
        if matches!(effect.kind, Kind::Destroy { .. }) {
            state.inspection.snapshots.as_mut().unwrap().pop();
        }
        let events = Events::default();
        let mut session = session();
        let mut fake = Fake::new(&events, vec![state]);
        let mut scope = session
            .admit_effects_with(
                &[EffectTarget::dataset(pa.clone())],
                guard(&events),
                None,
                &mut fake,
            )
            .unwrap();
        let error = scope
            .dispatch_with(&effect, SECOND, &mut fake)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is paired"), "{error}");
        assert!(!events.borrow().iter().any(|e| e.starts_with("run")));
    }
}

fn refused_on(state: NativeState, targets: &[EffectTarget], effect: &Effect<'_>, why: &str) {
    let events = Events::default();
    let mut session = session();
    let mut fake = Fake::new(&events, vec![state]);
    let mut scope = session
        .admit_effects_with(targets, guard(&events), None, &mut fake)
        .unwrap();
    let error = scope
        .dispatch_with(effect, SECOND, &mut fake)
        .unwrap_err()
        .to_string();
    assert!(error.contains(why), "{error}");
    assert!(!events.borrow().iter().any(|e| e.starts_with("run")));
}

#[test]
fn volsize_is_never_set() {
    let error = Effect::set_properties(&target("tank/vm/disk"), &[assign("volsize", "4096")])
        .unwrap_err()
        .to_string();
    assert!(error.contains("truncates"), "{error}");
}

#[test]
fn the_guard_sees_the_admission_then_the_effect_then_its_bound_argv() {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let log = seen.clone();
    let vm = target("tank/vm");
    let unmount = Effect::unmount(&vm);
    let expected = unmount.clone();
    let mut session = session();
    let events = Events::default();
    let mut fake = Fake::new(&events, vec![fixture()]);
    let mut scope = session
        .admit_effects_with(
            &[exact("tank/vm")],
            move |check: &GuardCheck<'_>| {
                log.borrow_mut().push((
                    check.effect().map(|e| e == &expected),
                    check.argv().map(|(p, a)| format!("{p} {}", a.join(" "))),
                ));
                Ok(())
            },
            None,
            &mut fake,
        )
        .unwrap();
    scope.dispatch_with(&unmount, SECOND, &mut fake).unwrap();
    assert_eq!(
        *seen.borrow(),
        [
            (None, None),
            (Some(true), None),
            (Some(true), Some("zfs unmount tank/vm".into()))
        ]
    );
}

#[test]
fn an_operation_record_on_the_pool_refuses_every_shape_there() {
    let recorded = with(|s| {
        for (name, properties) in s.dataset_properties.iter_mut() {
            let source = if name == "tank" {
                "local".to_string()
            } else {
                "inherited from tank".into()
            };
            properties.insert(management::OPERATION_PROPERTY.into(), prop("{}", &source));
        }
    });
    let vm = target("tank/vm");
    for (targets, effect) in [
        (vec![exact("tank/vm")], Effect::unmount(&vm)),
        (
            vec![exact("tank/vm")],
            Effect::set_properties(&vm, &[assign("canmount", "off")]).unwrap(),
        ),
        (
            vec![exact("tank/vm")],
            Effect::create_filesystem(&vm, "tank/vm/new", &[]).unwrap(),
        ),
        (
            vec![exact("tank/vm/empty")],
            Effect::destroy(&target("tank/vm/empty")).unwrap(),
        ),
        (
            vec![exact("tank/secure")],
            Effect::unload_key(&target("tank/secure")),
        ),
        (vec![EffectTarget::pool(pool())], Effect::sync_pool(&pool())),
        (
            vec![EffectTarget::pool(pool())],
            Effect::export_pool(&pool()),
        ),
    ] {
        refused(&targets, &effect, recorded.clone(), "operation record");
    }
}

#[test]
fn every_dataset_shape_refuses_a_pair_member() {
    let pa = DatasetTarget::new("tank/pa", identity(10)).unwrap();
    for effect in [
        Effect::set_properties(&pa, &[assign("canmount", "on")]).unwrap(),
        Effect::unmount(&pa),
        Effect::create_filesystem(&pa, "tank/pa/child", &[]).unwrap(),
    ] {
        refused_on(
            pair_state(),
            &[EffectTarget::dataset(pa.clone())],
            &effect,
            "is paired",
        );
    }
    refused_on(
        pair_state(),
        &[EffectTarget::subtree(pa.clone())],
        &Effect::inherit_property(&pa, "readonly").unwrap(),
        "is paired",
    );
}

/// tank/pa still names tank/vm/empty as its peer: an unpair stopped after
/// clearing tank/vm/empty's own record.
fn half_unpaired() -> NativeState {
    with(|s| {
        s.inspection
            .datasets
            .push(dataset("tank/pa", 10, DatasetKind::Filesystem));
        let record = management::PairRecord {
            schema_version: 1,
            pair_id: "29c4aaaa-1111-4111-8111-111111111111".into(),
            endpoint: management::Endpoint {
                name: "tank/pa".into(),
                identity: identity(10),
            },
            peer: management::Endpoint {
                name: "tank/vm/empty".into(),
                identity: identity(7),
            },
            role: management::Role::Primary,
        };
        let mut properties = identity_properties(10);
        properties.insert(
            management::PAIR_PROPERTY.into(),
            prop(serde_json::to_string(&record).unwrap(), "local"),
        );
        s.dataset_properties.insert("tank/pa".into(), properties);
    })
}

#[test]
fn a_record_naming_the_target_as_its_peer_refuses_and_hides_no_role() {
    let state = half_unpaired();
    refused_on(
        state.clone(),
        &[exact("tank/vm/empty")],
        &Effect::destroy(&target("tank/vm/empty")).unwrap(),
        "names tank/vm/empty as its peer",
    );
    // A subtree change reaches the descendant too.
    refused_on(
        state.clone(),
        &[subtree("tank/vm")],
        &Effect::unmount(&target("tank/vm")),
        "names tank/vm/empty as its peer",
    );
    let error = management_of(&state, "tank/vm/empty")
        .unwrap_err()
        .to_string();
    assert!(error.contains("role is not known"), "{error}");
    // A mutual pair's own peer reference is expected.
    assert!(management_of(&pair_state(), "tank/pb").is_ok());
}

/// Observes through the library's real bounded runner: each observation runs
/// its next shell script as a query, then reports the fixture.
struct Timed {
    scripts: VecDeque<String>,
    within: Vec<Option<Duration>>,
    runs: usize,
}
impl Backend for Timed {
    fn observe(&mut self, within: Option<Duration>) -> Result<NativeState, Error> {
        self.within.push(within);
        let script = self.scripts.pop_front().unwrap_or_else(|| "exit 0".into());
        observe_within(within, |run| {
            let output = run("/bin/sh", &["-c".to_string(), script])?;
            assert_eq!(output, "", "only a complete query reaches the parser");
            Ok(fixture())
        })
    }
    fn run(
        &mut self,
        _: &lock::WriterLock,
        _: &'static str,
        _: &[String],
        _: Option<&[u8]>,
        _: Duration,
    ) -> Ran {
        self.runs += 1;
        Ran::Exited {
            code: 0,
            stderr: String::new(),
        }
    }
}

#[test]
fn a_dispatch_observation_past_its_deadline_kills_its_query_and_starts_no_effect() {
    let pidfile = lock_path().with_file_name("descendant");
    let mut session = session();
    let mut timed = Timed {
        scripts: VecDeque::from([
            "exit 0".to_string(),
            // The leader prints a partial row and exits; its child keeps stdout.
            format!("sleep 30 & echo $! > {}; echo partial", pidfile.display()),
        ]),
        within: vec![],
        runs: 0,
    };
    let within = Duration::from_millis(300);
    let vm = target("tank/vm");
    let mut scope = session
        .admit_effects_with(&[exact("tank/vm")], |_| Ok(()), Some(within), &mut timed)
        .unwrap();
    let started = Instant::now();
    let error = scope
        .dispatch_with(&Effect::unmount(&vm), SECOND, &mut timed)
        .unwrap_err();
    assert!(started.elapsed() < SECOND * 5);
    assert_eq!(
        error.observation_stop(),
        Some(ObservationStop::Deadline(QueryCleanup::LeaderReaped))
    );
    assert_eq!(
        error.to_string(),
        "observation exceeded its 300ms deadline: /bin/sh was still running at the \
         observation's 300ms deadline; SIGKILL was sent to its process group and its leader reaped"
    );
    assert_eq!(
        timed.runs, 0,
        "no effect child after an expired observation"
    );
    let pid: i32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let gone = Instant::now() + SECOND * 5;
    while std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !stat
            .rsplit_once(") ")
            .is_some_and(|(_, s)| s.starts_with('Z'))
    }) {
        assert!(
            Instant::now() < gone,
            "the descendant holding the pipe was killed"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // A read-only query holds no lock: the session stays usable.
    assert_eq!(
        scope
            .dispatch_with(&Effect::unmount(&vm), SECOND, &mut timed)
            .unwrap(),
        EffectReply::Succeeded
    );
    assert_eq!(timed.runs, 1);
    assert_eq!(timed.within, [Some(within); 3]);
}

#[test]
fn observation_deadlines_are_opt_in_and_nonzero() {
    let mut session = session();
    let mut timed = Timed {
        scripts: VecDeque::new(),
        within: vec![],
        runs: 0,
    };
    let vm = target("tank/vm");
    {
        let mut scope = session
            .admit_effects_with(&[exact("tank/vm")], |_| Ok(()), None, &mut timed)
            .unwrap();
        scope
            .dispatch_with(&Effect::unmount(&vm), SECOND, &mut timed)
            .unwrap();
    }
    assert_eq!(timed.within, [None, None]);
    let error = session
        .admit_effects_with(
            &[exact("tank/vm")],
            |_| Ok(()),
            Some(Duration::ZERO),
            &mut timed,
        )
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "an observation deadline must be nonzero");
    assert_eq!(error.observation_stop(), None);
    assert_eq!(timed.within.len(), 2, "refused before observing");
}
