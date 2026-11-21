use super::*;
use crate::device::{DiskIdentity, Partition};
use std::{collections::BTreeMap, collections::VecDeque, fs, path::PathBuf};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("zboot-wipe-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }
    fn write(&self, relative: &str, value: &str) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{value}\n")).unwrap();
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const GIB: u64 = 1 << 30;
const DEV: &str = "/dev/nvme0";
/// The kernel device number of `/dev/nvme0` in the scratch sysfs.
const NODE: &str = "243:0";
/// The captures' scrubbed serial and NQN; the scratch sysfs and the disk's
/// identity carry the same, so they match as a real drive's do.
const SERIAL: &str = "SCRUBBED";

// ---------------------------------------------------------------------------
// Fixtures: nvme-cli output in files (fixtures/README.md).

const P41: &str = "sk-hynix-p41";
const XPG: &str = "xpg-gammix-s11-pro";
const DRIVES: [&str; 2] = [P41, XPG];
const IN_PROGRESS: &str = "synthetic/sanitize-log-crypto-erase-in-progress.json";
const BLOCK_IN_PROGRESS: &str = "synthetic/sanitize-log-block-erase-in-progress.json";
const FAILED: &str = "synthetic/sanitize-log-crypto-erase-failed.json";
const NEVER: &str = "synthetic/sanitize-log-never-sanitized.json";
const TWO_NAMESPACES: &str = "synthetic/list-ns-two-namespaces.json";

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/device/wipe/fixtures")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn of(drive: &str, file: &str) -> String {
    fixture(&format!("{drive}/{file}"))
}

/// A fixture with one JSON value replaced, `at` a JSON pointer.
fn edit(text: &str, at: &str, value: serde_json::Value) -> String {
    let mut json: serde_json::Value = serde_json::from_str(text).unwrap();
    *json.pointer_mut(at).unwrap_or_else(|| panic!("no {at}")) = value;
    json.to_string()
}

/// A sanitize log fixture with `sstat.global_erased` set (the pointer goes
/// through the one device key, whatever it is).
fn erased(log: &str, value: u8) -> String {
    let mut json: serde_json::Value = serde_json::from_str(log).unwrap();
    let device = json.as_object_mut().unwrap().values_mut().next().unwrap();
    device["sstat"]["global_erased"] = value.into();
    json.to_string()
}

fn status(log: &str, value: u8) -> String {
    let mut json: serde_json::Value = serde_json::from_str(log).unwrap();
    let device = json.as_object_mut().unwrap().values_mut().next().unwrap();
    device["sstat"]["status"] = format!("({value}) text").into();
    json.to_string()
}

/// Answers by the joined arguments; `sanitize-log` replies come from a queue
/// (the last one repeats). Records every call.
#[derive(Default)]
struct FakeNvme {
    answers: BTreeMap<String, Result<String, String>>,
    logs: VecDeque<String>,
    submit: Option<Result<(), String>>,
    /// The device number each character device node answers.
    nodes: BTreeMap<String, Result<String, String>>,
    calls: Vec<String>,
    pauses: usize,
}
impl FakeNvme {
    fn answer(mut self, args: &str, reply: Result<String, String>) -> Self {
        self.answers.insert(args.into(), reply);
        self
    }
    fn logs(mut self, logs: &[String]) -> Self {
        self.logs = logs.iter().cloned().collect();
        self
    }
    fn with_node(mut self, path: &str, reply: Result<&str, &str>) -> Self {
        self.nodes
            .insert(path.into(), reply.map(str::to_owned).map_err(str::to_owned));
        self
    }
    /// A captured drive as controller /dev/nvme0, its namespace 1: every
    /// command answers as captured, the two it rejected included.
    fn drive(drive: &str) -> Self {
        FakeNvme::default()
            .with_node(DEV, Ok(NODE))
            .answer("id-ctrl /dev/nvme0", Ok(of(drive, "id-ctrl.json")))
            .answer("list-ns /dev/nvme0", Ok(of(drive, "list-ns.json")))
            .answer(
                "id-ns /dev/nvme0 --namespace-id=1",
                Ok(of(drive, "id-ns.json")),
            )
            .answer(
                "list-ctrl /dev/nvme0",
                Err(of(drive, "list-ctrl.rejected.json")),
            )
            .answer(
                "list-ns /dev/nvme0 --all",
                Err(of(drive, "list-ns-all.rejected.json")),
            )
            .logs(&[of(drive, "sanitize-log.json")])
    }
    /// The drive's id-ctrl with one field changed.
    fn id_ctrl(self, drive: &str, at: &str, value: serde_json::Value) -> Self {
        let text = edit(&of(drive, "id-ctrl.json"), at, value);
        self.answer("id-ctrl /dev/nvme0", Ok(text))
    }
}
impl Nvme for FakeNvme {
    fn query(&mut self, args: &[String]) -> Result<String, Error> {
        let key = args.join(" ");
        self.calls.push(key.clone());
        if args[0] == "sanitize-log" {
            let reply = if self.logs.len() > 1 {
                self.logs.pop_front().unwrap()
            } else {
                self.logs.front().cloned().ok_or_else(|| refuse("no log"))?
            };
            return Ok(reply);
        }
        match self.answers.get(&key) {
            Some(Ok(text)) => Ok(text.clone()),
            Some(Err(stdout)) => Err(refuse(format!("nvme failed (exit status: 1): {stdout}"))),
            None => Err(refuse(format!("unexpected nvme {key}"))),
        }
    }
    fn sanitize(&mut self, controller: &str, action: Action) -> Result<(), Error> {
        self.calls
            .push(format!("sanitize {controller} {}", action.sanact()));
        self.submit.clone().unwrap_or(Ok(())).map_err(refuse)
    }
    fn pause(&mut self) {
        self.pauses += 1;
    }
    fn node(&mut self, path: &str) -> Result<String, Error> {
        match self.nodes.get(path) {
            Some(Ok(number)) => Ok(number.clone()),
            Some(Err(e)) => Err(refuse(e.clone())),
            None => Err(refuse(format!("{path} is not a character device"))),
        }
    }
}

fn cntlid(drive: &str) -> u16 {
    parse_id_ctrl(&of(drive, "id-ctrl.json")).unwrap().cntlid
}

// ---------------------------------------------------------------------------
// The kernel's view: a scratch sysfs.

/// Where the kernel puts the namespace block device.
#[derive(Clone, Copy)]
enum Layout {
    /// Under its controller, `.../nvme/nvme0/nvme0n1`: a single-controller
    /// subsystem on current kernels.
    Controller,
    /// Under `nvme-subsys0/nvme0n1`, the native multipath node.
    Multipath,
}

/// Subsystem `nvme-subsys0` with the controllers given as (name, cntlid,
/// transport), and namespace 1 of the first one as the disk. Returns the
/// disk's sysfs path.
fn kernel(scratch: &Scratch, layout: Layout, controllers: &[(&str, u16, &str)]) -> String {
    let subsys = "class/nvme-subsystem/nvme-subsys0";
    scratch.write(&format!("{subsys}/subsysnqn"), "SCRUBBED");
    for (index, (name, id, transport)) in controllers.iter().enumerate() {
        let dir = format!("devices/pci/{name}/nvme/{name}");
        for (attribute, value) in [
            ("dev", format!("243:{index}").as_str()),
            ("cntlid", id.to_string().as_str()),
            ("serial", &format!("{SERIAL}            ")),
            ("subsysnqn", "SCRUBBED"),
            ("transport", transport),
            ("state", "live"),
        ] {
            scratch.write(&format!("{dir}/{attribute}"), value);
        }
        std::os::unix::fs::symlink(scratch.0.join(&dir), scratch.0.join(subsys).join(name))
            .unwrap();
        // A hidden multipath path device is never a namespace of its own.
        scratch.write(&format!("{dir}/{name}c0n1/nsid"), "1");
    }
    let disk = match layout {
        Layout::Controller => format!("devices/pci/{0}/nvme/{0}/nvme0n1", controllers[0].0),
        Layout::Multipath => format!("{subsys}/nvme0n1"),
    };
    scratch.write(&format!("{disk}/nsid"), "1");
    scratch.0.join(disk).to_string_lossy().into_owned()
}

fn identity(path: &str, number: &str, sysfs: String) -> DiskIdentity {
    DiskIdentity {
        path: path.into(),
        device_number: number.into(),
        sysfs_path: sysfs,
        bytes: GIB,
        logical_sector: 512,
        physical_sector: 512,
        serial: Some("SCRUBBED".into()),
        wwn: Some("eui.SCRUBBED".into()),
        model: Some("SHPP41-2000GM".into()),
    }
}

fn partition(path: &str, number: &str, bytes: u64) -> Partition {
    Partition {
        path: path.into(),
        device_number: number.into(),
        bytes,
        partition_uuid: Some(format!("uuid-{number}")),
        filesystem: Some("zfs_member".into()),
        filesystem_uuid: None,
        filesystem_label: None,
    }
}

fn review_of(identity: DiskIdentity, partitions: Vec<Partition>) -> DiskReview {
    DiskReview {
        schema_version: 2,
        identity,
        partitions,
        filesystem: None,
        partition_table_uuid: Some("table".into()),
        method: Method::Clear {
            reason: ClearReason::NotNvme,
            extents: Vec::new(),
        },
        loss_token: "sha256:test".into(),
    }
}

/// An NVMe disk on a scratch sysfs with one PCIe controller `nvme0` whose
/// id is `id`.
fn nvme_disk(scratch: &Scratch, layout: Layout, id: u16) -> DiskReview {
    let sysfs = kernel(scratch, layout, &[("nvme0", id, "pcie")]);
    review_of(identity("/dev/nvme0n1", "259:0", sysfs), Vec::new())
}

fn sanitize_of(action: Action) -> Method {
    Method::Sanitize {
        action,
        controller: DEV.into(),
        device_number: NODE.into(),
        nsid: 1,
    }
}

// ---------------------------------------------------------------------------
// Selection.

#[test]
fn consumer_drives_without_namespace_management_are_sanitized_by_their_best_action() {
    for (drive, action) in [(P41, Action::BlockErase), (XPG, Action::CryptoErase)] {
        for layout in [Layout::Controller, Layout::Multipath] {
            let scratch = Scratch::new();
            let review = nvme_disk(&scratch, layout, cntlid(drive));
            let mut nvme = FakeNvme::drive(drive);
            let method = select(&review, &scratch.0, &mut nvme).unwrap();
            assert_eq!(method, sanitize_of(action), "{drive}");
            // Neither drive answers list-ctrl or list-ns --all (Invalid
            // Field in Command, as captured); eligibility does not ask them,
            // nor does the plan read the sanitize log.
            assert_eq!(
                nvme.calls,
                [
                    "id-ctrl /dev/nvme0",
                    "list-ns /dev/nvme0",
                    "id-ns /dev/nvme0 --namespace-id=1"
                ],
                "{drive}"
            );
        }
    }
    // What the captures say, so a replaced capture that changes it is noticed.
    let p41 = parse_id_ctrl(&of(P41, "id-ctrl.json")).unwrap();
    assert_eq!(
        (p41.sanicap, p41.cmic, p41.oacs & 8, p41.nn),
        (0x6000_0002, 0, 0, 1)
    );
    let xpg = parse_id_ctrl(&of(XPG, "id-ctrl.json")).unwrap();
    assert_eq!((xpg.sanicap, xpg.cmic, xpg.oacs & 8, xpg.nn), (3, 0, 0, 1));
    for drive in DRIVES {
        for rejected in ["list-ctrl.rejected.json", "list-ns-all.rejected.json"] {
            let text = of(drive, rejected);
            assert!(
                text.contains("Invalid Field in Command"),
                "{drive} {rejected}"
            );
            assert!(parse_ns_list(&text).is_err());
        }
    }
}

#[test]
fn every_other_disk_gets_metadata_clearing_with_its_reason() {
    use ClearReason::*;
    // (what, sysfs controllers, edit of the XPG answers, expected reason)
    type Change = fn(FakeNvme) -> FakeNvme;
    type Controllers = &'static [(&'static str, u16, &'static str)];
    let cases: [(&str, Controllers, Change, ClearReason); 9] = [
        ("fabric", &[("nvme0", 1, "tcp")], |n| n, Fabric),
        (
            "a second controller in the kernel",
            &[("nvme0", 1, "pcie"), ("nvme1", 2, "pcie")],
            |n| n,
            MultipleControllers,
        ),
        (
            "no sanitize",
            &[("nvme0", 1, "pcie")],
            |n| n.id_ctrl(XPG, "/sanicap", serde_json::json!(0x6000_0000_u32)),
            NoSanitize,
        ),
        (
            "overwrite only",
            &[("nvme0", 1, "pcie")],
            |n| n.id_ctrl(XPG, "/sanicap", serde_json::json!(0x6000_0004_u32)),
            OverwriteOnly,
        ),
        (
            "CMIC: multiple controllers possible",
            &[("nvme0", 1, "pcie")],
            |n| n.id_ctrl(XPG, "/cmic", serde_json::json!(2)),
            MultipleControllers,
        ),
        (
            "a second active namespace",
            &[("nvme0", 1, "pcie")],
            |n| n.answer("list-ns /dev/nvme0", Ok(fixture(TWO_NAMESPACES))),
            MultipleNamespaces,
        ),
        (
            "NMIC: the namespace is shareable",
            &[("nvme0", 1, "pcie")],
            |n| {
                let text = edit(&of(XPG, "id-ns.json"), "/nmic", serde_json::json!(1));
                n.answer("id-ns /dev/nvme0 --namespace-id=1", Ok(text))
            },
            MultipleControllers,
        ),
        (
            "NN 4 without namespace management",
            &[("nvme0", 1, "pcie")],
            |n| n.id_ctrl(XPG, "/nn", serde_json::json!(4)),
            MultipleNamespaces,
        ),
        (
            "namespace management, two allocated",
            &[("nvme0", 1, "pcie")],
            |n| {
                n.id_ctrl(XPG, "/oacs", serde_json::json!(22 | 8))
                    .answer("list-ns /dev/nvme0 --all", Ok(fixture(TWO_NAMESPACES)))
            },
            MultipleNamespaces,
        ),
    ];
    for (what, controllers, change, reason) in cases {
        let scratch = Scratch::new();
        let sysfs = kernel(&scratch, Layout::Controller, controllers);
        let review = review_of(identity("/dev/nvme0n1", "259:0", sysfs), Vec::new());
        let mut nvme = change(FakeNvme::drive(XPG));
        let method = select(&review, &scratch.0, &mut nvme).unwrap();
        assert_eq!(
            method,
            Method::Clear {
                reason,
                extents: Vec::new()
            },
            "{what}"
        );
        assert!(!method.describe().contains("sanitize,"), "{what}");
    }
    // The kernel's view alone decides a fabric or a second controller: no
    // query reaches the controller.
    let scratch = Scratch::new();
    let sysfs = kernel(&scratch, Layout::Multipath, &[("nvme0", 1, "rdma")]);
    let review = review_of(identity("/dev/nvme0n1", "259:0", sysfs), Vec::new());
    let mut nvme = FakeNvme::drive(XPG);
    select(&review, &scratch.0, &mut nvme).unwrap();
    assert!(nvme.calls.is_empty());
    // With namespace management, the allocated list must be the disk alone.
    let scratch = Scratch::new();
    let review = nvme_disk(&scratch, Layout::Controller, 1);
    let mut nvme = FakeNvme::drive(XPG)
        .id_ctrl(XPG, "/oacs", serde_json::json!(22 | 8))
        .answer("list-ns /dev/nvme0 --all", Ok(of(XPG, "list-ns.json")));
    assert_eq!(
        select(&review, &scratch.0, &mut nvme).unwrap(),
        sanitize_of(Action::CryptoErase)
    );
    assert_eq!(nvme.calls.last().unwrap(), "list-ns /dev/nvme0 --all");
}

#[test]
fn a_disk_that_is_not_nvme_gets_metadata_clearing_with_its_saved_extents() {
    let scratch = Scratch::new();
    scratch.write("dev/block/252:1/start", "2048");
    scratch.write("dev/block/252:1/size", "131072");
    let review = review_of(
        identity(
            "/dev/vda",
            "252:0",
            "/sys/devices/pci/virtio1/block/vda".into(),
        ),
        vec![partition("/dev/vda1", "252:1", 64 << 20)],
    );
    let mut nvme = FakeNvme::default();
    let method = select(&review, &scratch.0, &mut nvme).unwrap();
    assert_eq!(
        method,
        Method::Clear {
            reason: ClearReason::NotNvme,
            extents: vec![Extent {
                path: "/dev/vda1".into(),
                start: 2048 * 512,
                bytes: 64 << 20
            }]
        }
    );
    assert!(nvme.calls.is_empty(), "no NVMe query for a virtio disk");
    // A kernel extent that disagrees with the partition's size refuses.
    scratch.write("dev/block/252:1/size", "131071");
    assert!(select(&review, &scratch.0, &mut nvme).is_err());
}

#[test]
fn a_failed_or_unreadable_discovery_refuses_and_never_counts_as_unsupported() {
    type Change = fn(FakeNvme) -> FakeNvme;
    let cases: [(&str, Change); 7] = [
        ("id-ctrl rejected", |n| {
            n.answer(
                "id-ctrl /dev/nvme0",
                Err(of(XPG, "list-ctrl.rejected.json")),
            )
        }),
        ("id-ctrl unreadable", |n| {
            n.answer("id-ctrl /dev/nvme0", Ok(of(XPG, "list-ns.json")))
        }),
        ("sanicap out of range", |n| {
            n.id_ctrl(XPG, "/sanicap", serde_json::json!(1_u64 << 32))
        }),
        ("list-ns rejected", |n| {
            n.answer(
                "list-ns /dev/nvme0",
                Err(of(XPG, "list-ns-all.rejected.json")),
            )
        }),
        ("id-ns unreadable", |n| {
            n.answer(
                "id-ns /dev/nvme0 --namespace-id=1",
                Ok(of(XPG, "list-ns.json")),
            )
        }),
        ("another controller id than the kernel's", |n| {
            n.id_ctrl(XPG, "/cntlid", serde_json::json!(7))
        }),
        // A namespace-management drive must answer the allocated list.
        ("list-ns --all rejected with namespace management", |n| {
            n.id_ctrl(XPG, "/oacs", serde_json::json!(22 | 8))
        }),
    ];
    for (what, change) in cases {
        let scratch = Scratch::new();
        let review = nvme_disk(&scratch, Layout::Controller, 1);
        let mut nvme = change(FakeNvme::drive(XPG));
        let error = select(&review, &scratch.0, &mut nvme)
            .map(|m| panic!("{what}: {m:?}"))
            .unwrap_err()
            .to_string();
        if what != "another controller id than the kernel's" {
            assert!(error.contains("NVMe discovery"), "{what}: {error}");
        }
    }
    // A controller the kernel does not show as live, and a namespace in an
    // unrecognized place, refuse too.
    let scratch = Scratch::new();
    let review = nvme_disk(&scratch, Layout::Controller, 1);
    scratch.write("devices/pci/nvme0/nvme/nvme0/state", "resetting");
    assert!(
        select(&review, &scratch.0, &mut FakeNvme::drive(XPG))
            .unwrap_err()
            .to_string()
            .contains("not live")
    );
    let scratch = Scratch::new();
    scratch.write("devices/virtual/block/nvme0n1/nsid", "1");
    let sysfs = scratch.0.join("devices/virtual/block/nvme0n1");
    let review = review_of(
        identity("/dev/nvme0n1", "259:0", sysfs.to_string_lossy().into()),
        Vec::new(),
    );
    assert!(select(&review, &scratch.0, &mut FakeNvme::drive(XPG)).is_err());
}

#[test]
fn nvme_cli_outputs_parse_from_the_captures_and_refuse_anything_else() {
    assert_eq!(
        parse_id_ctrl(&of(P41, "id-ctrl.json")).unwrap(),
        IdCtrl {
            sanicap: 0x6000_0002,
            cntlid: 0,
            cmic: 0,
            oacs: 23,
            nn: 1,
            sn: SERIAL.into(),
            subnqn: Some("SCRUBBED".into())
        }
    );
    // A serial is required; a missing or empty NQN is none.
    let ctrl = of(P41, "id-ctrl.json");
    assert!(parse_id_ctrl(&edit(&ctrl, "/sn", serde_json::json!("   "))).is_err());
    assert_eq!(
        parse_id_ctrl(&edit(&ctrl, "/subnqn", serde_json::json!("")))
            .unwrap()
            .subnqn,
        None
    );
    for drive in DRIVES {
        assert_eq!(parse_ns_list(&of(drive, "list-ns.json")).unwrap(), [1]);
        assert_eq!(parse_id_ns(&of(drive, "id-ns.json")).unwrap(), 0);
    }
    assert_eq!(parse_ns_list(&fixture(TWO_NAMESPACES)).unwrap(), [1, 2]);
    let ctrl = of(XPG, "id-ctrl.json");
    for (at, value) in [
        ("/sanicap", serde_json::json!(-1)),
        ("/cmic", serde_json::json!(256)),
        ("/oacs", serde_json::json!("22")),
        ("/nn", serde_json::Value::Null),
    ] {
        assert!(parse_id_ctrl(&edit(&ctrl, at, value)).is_err(), "{at}");
    }
    for broken in [
        "[]".to_string(),
        "not json".into(),
        edit(
            &of(XPG, "list-ns.json"),
            "/nsid_list/0/nsid",
            serde_json::json!(0),
        ),
        edit(
            &fixture(TWO_NAMESPACES),
            "/nsid_list/1/nsid",
            serde_json::json!(1),
        ),
        edit(
            &of(XPG, "list-ns.json"),
            "/nsid_list/0/nsid",
            serde_json::json!("1"),
        ),
    ] {
        assert!(parse_ns_list(&broken).is_err(), "{broken}");
    }

    let log = |name: &str| parse_sanitize_log(&fixture(name)).unwrap();
    let read = |status, global_erased, cdw10| Log {
        status,
        global_erased,
        cdw10,
    };
    assert_eq!(log("sk-hynix-p41/sanitize-log.json"), read(1, false, 2));
    assert_eq!(
        log("xpg-gammix-s11-pro/sanitize-log.json"),
        read(1, true, 4)
    );
    assert_eq!(log(IN_PROGRESS), read(2, false, 4));
    assert_eq!(log(FAILED), read(3, false, 4));
    assert_eq!(log(NEVER), read(0, false, 0));
    let p41 = of(P41, "sanitize-log.json");
    for broken in [
        "{}".to_string(),
        edit(&p41, "/nvme0/sstat/status", serde_json::json!("Idle")),
        edit(
            &p41,
            "/nvme0/sstat/status",
            serde_json::json!("(9) beyond SSTAT"),
        ),
        edit(&p41, "/nvme0/sstat/global_erased", serde_json::json!(2)),
        edit(&p41, "/nvme0/sstat", serde_json::json!(257)),
        edit(&p41, "/nvme0/cdw10_info", serde_json::json!(-1)),
        format!("{{\"a\": {}, \"b\": {}}}", "{}", "{}"),
    ] {
        assert!(parse_sanitize_log(&broken).is_err(), "{broken}");
    }
}

// ---------------------------------------------------------------------------
// The run.

const TARGET: Target = Target {
    controller: DEV,
    device_number: NODE,
    serial: SERIAL,
};

fn run(nvme: &mut FakeNvme, action: Action) -> Result<Completion, Error> {
    run_sanitize(nvme, &TARGET, action)
}

fn submitted(nvme: &FakeNvme) -> Vec<usize> {
    let calls = nvme.calls.iter().enumerate();
    calls
        .filter(|(_, c)| c.starts_with("sanitize "))
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn a_sanitize_completes_when_seen_running_or_when_the_log_changed() {
    // XPG: the earlier crypto erase's success, this one running, then the
    // same success again: seen running, so it is this run's.
    let xpg = of(XPG, "sanitize-log.json");
    let mut nvme = FakeNvme::drive(XPG).logs(&[xpg.clone(), fixture(IN_PROGRESS), xpg]);
    assert_eq!(
        run(&mut nvme, Action::CryptoErase).unwrap(),
        Completion::Observed
    );
    // The controller is identified again right before the submission.
    assert_eq!(
        nvme.calls,
        [
            "sanitize-log /dev/nvme0",
            "id-ctrl /dev/nvme0",
            "sanitize /dev/nvme0 4",
            "sanitize-log /dev/nvme0",
            "sanitize-log /dev/nvme0"
        ]
    );
    assert_eq!(nvme.pauses, 1);
    // P41: written since its last block erase; this one finishes before the
    // first poll, and the log changed (nothing written since).
    let p41 = of(P41, "sanitize-log.json");
    let mut nvme = FakeNvme::drive(XPG).logs(&[p41.clone(), erased(&p41, 1)]);
    assert_eq!(
        run(&mut nvme, Action::BlockErase).unwrap(),
        Completion::Observed
    );
    assert_eq!(submitted(&nvme), [2]);
    // P41 seen running.
    let mut nvme =
        FakeNvme::drive(XPG).logs(&[p41.clone(), fixture(BLOCK_IN_PROGRESS), erased(&p41, 1)]);
    run(&mut nvme, Action::BlockErase).unwrap();
    // A never-sanitized drive: the first success is this one.
    let mut nvme = FakeNvme::drive(XPG).logs(&[fixture(NEVER), of(XPG, "sanitize-log.json")]);
    run(&mut nvme, Action::CryptoErase).unwrap();
}

#[test]
fn an_earlier_success_in_the_log_is_not_this_runs_completion() {
    // The P41 log reports an earlier successful block erase with data written
    // since (Global Data Erased clear). Unchanged after the submission and
    // never seen running, that success is the earlier one: the outcome is
    // unknown.
    let mut nvme = FakeNvme::drive(XPG).logs(&[of(P41, "sanitize-log.json")]);
    let error = run(&mut nvme, Action::BlockErase).unwrap_err().to_string();
    assert!(
        error.contains("not this run's completion") && error.contains("outcome is unknown"),
        "{error}"
    );
    assert_eq!(submitted(&nvme), [2], "one submission, no retry");
    assert_eq!(
        nvme.calls.len() as u64,
        3 + UNSEEN_POLLS,
        "{:?}",
        nvme.calls
    );
    // The XPG log reports a successful crypto erase with nothing written
    // since (Global Data Erased set). A fast crypto erase can leave exactly
    // that log; the controller states no user data was written since a
    // successful crypto erase, so after the unchanged polls it is accepted,
    // as that and not as an observed completion.
    let mut nvme = FakeNvme::drive(XPG).logs(&[of(XPG, "sanitize-log.json")]);
    assert_eq!(
        run(&mut nvme, Action::CryptoErase).unwrap(),
        Completion::NotWrittenSince
    );
    assert_eq!(submitted(&nvme), [2], "one submission, no retry");
    assert_eq!(
        nvme.calls.len() as u64,
        3 + UNSEEN_POLLS,
        "{:?}",
        nvme.calls
    );
    // A block erase does not finish between polls: the same unchanged log
    // with Global Data Erased set, for a block erase, is an earlier one.
    let mut nvme = FakeNvme::drive(XPG).logs(&[erased(&of(P41, "sanitize-log.json"), 1)]);
    let error = run(&mut nvme, Action::BlockErase).unwrap_err().to_string();
    assert!(error.contains("not this run's completion"), "{error}");
    // A completion of another action is not this one either.
    let mut nvme = FakeNvme::drive(XPG).logs(&[
        fixture(NEVER),
        fixture(BLOCK_IN_PROGRESS),
        of(P41, "sanitize-log.json"),
    ]);
    let error = run(&mut nvme, Action::CryptoErase).unwrap_err().to_string();
    assert!(
        error.contains("no completion of this crypto erase"),
        "{error}"
    );
}

#[test]
fn a_rejected_submission_refuses_and_nothing_follows() {
    let mut nvme = FakeNvme {
        submit: Some(Err("Sanitize Prohibited".into())),
        ..FakeNvme::drive(XPG).logs(&[of(XPG, "sanitize-log.json")])
    };
    let error = run(&mut nvme, Action::CryptoErase).unwrap_err().to_string();
    assert!(
        error.contains("did not accept") && error.contains("does not fall back"),
        "{error}"
    );
    assert_eq!(
        nvme.calls,
        [
            "sanitize-log /dev/nvme0",
            "id-ctrl /dev/nvme0",
            "sanitize /dev/nvme0 4"
        ]
    );
}

#[test]
fn failure_mode_and_unknown_statuses_refuse() {
    // Failure mode before the submission: nothing is submitted.
    for log in [fixture(FAILED), status(&fixture(NEVER), 6)] {
        let mut nvme = FakeNvme::drive(XPG).logs(&[log]);
        let error = run(&mut nvme, Action::CryptoErase).unwrap_err();
        assert!(submitted(&nvme).is_empty(), "{error}");
    }
    let mut nvme = FakeNvme::drive(XPG).logs(&[fixture(FAILED)]);
    let error = run(&mut nvme, Action::CryptoErase).unwrap_err().to_string();
    assert!(
        error.contains("failure mode") && error.contains("exit-failure"),
        "{error}"
    );
    // A failure or an unknown status after the submission.
    let xpg = of(XPG, "sanitize-log.json");
    let mut nvme = FakeNvme::drive(XPG).logs(&[xpg.clone(), fixture(IN_PROGRESS), fixture(FAILED)]);
    let error = run(&mut nvme, Action::CryptoErase).unwrap_err().to_string();
    assert!(
        error.contains("sanitize failed") && error.contains("failure mode"),
        "{error}"
    );
    let mut nvme = FakeNvme::drive(XPG).logs(&[xpg.clone(), status(&xpg, 5)]);
    assert!(
        run(&mut nvme, Action::CryptoErase)
            .unwrap_err()
            .to_string()
            .contains("does not know")
    );
}

#[test]
fn after_power_loss_the_running_sanitize_is_waited_out_before_this_one() {
    let xpg = of(XPG, "sanitize-log.json");
    let running = fixture(IN_PROGRESS);
    let mut nvme = FakeNvme::drive(XPG).logs(&[
        running.clone(),
        running.clone(),
        xpg.clone(),
        running.clone(),
        xpg.clone(),
    ]);
    run(&mut nvme, Action::CryptoErase).unwrap();
    // Watched to its end first, then this wipe's own submission, seen
    // running and complete.
    assert_eq!(submitted(&nvme), [4], "{:?}", nvme.calls);
    assert_eq!(nvme.calls.len(), 7, "{:?}", nvme.calls);
    assert_eq!(nvme.pauses, 3);
    // The earlier operation failing leaves failure mode: nothing is issued.
    let mut nvme = FakeNvme::drive(XPG).logs(&[running.clone(), fixture(FAILED)]);
    assert!(
        run(&mut nvme, Action::CryptoErase)
            .unwrap_err()
            .to_string()
            .contains("failure mode")
    );
    assert!(submitted(&nvme).is_empty());
    // One that never ends is left to the controller after the watch.
    let mut nvme = FakeNvme::drive(XPG).logs(&[running]);
    let error = run(&mut nvme, Action::CryptoErase).unwrap_err().to_string();
    assert!(error.contains("still running"), "{error}");
    assert!(submitted(&nvme).is_empty());
    assert_eq!(nvme.pauses as u64, WATCH_POLLS);
    assert_eq!(WATCH_POLLS * POLL_SECONDS, 12 * 3600);
}

// ---------------------------------------------------------------------------
// Erasing and verifying.

/// An in-memory disk: label regions, effects recorded, native programs
/// acting on the bytes as the real ones would.
struct FakeDisk {
    nvme: FakeNvme,
    bytes: BTreeMap<String, Vec<u8>>,
    /// Offset of each partition within the disk image.
    offsets: BTreeMap<String, u64>,
    disk: String,
    after: DiskReview,
    calls: Vec<String>,
    labelclear_works: bool,
    /// The controller's sanitize changes the bytes (else it only reports).
    sanitize_erases: bool,
}
impl FakeDisk {
    fn image(&mut self, path: &str) -> (&mut Vec<u8>, u64) {
        let offset = self.offsets.get(path).copied().unwrap_or(0);
        (self.bytes.get_mut(&self.disk).unwrap(), offset)
    }
}
impl Nvme for FakeDisk {
    fn query(&mut self, args: &[String]) -> Result<String, Error> {
        self.calls.push(args.join(" "));
        self.nvme.query(args)
    }
    fn sanitize(&mut self, controller: &str, action: Action) -> Result<(), Error> {
        self.calls.push(format!("sanitize {controller}"));
        self.nvme.sanitize(controller, action)?;
        if self.sanitize_erases {
            // Crypto erase: everything reads as noise.
            self.bytes.get_mut(&self.disk).unwrap().fill(0xa5);
        }
        Ok(())
    }
    fn pause(&mut self) {}
    fn node(&mut self, path: &str) -> Result<String, Error> {
        self.nvme.node(path)
    }
}
impl Effects for FakeDisk {
    type Claim = String;
    fn plan(&mut self, path: &str) -> Result<DiskReview, Error> {
        self.calls.push(format!("plan {path}"));
        Ok(self.after.clone())
    }
    fn claim(&mut self, path: &str, _number: &str) -> Result<String, Error> {
        self.calls.push(format!("claim {path}"));
        Ok(path.into())
    }
    fn reread(&mut self, claim: &String) -> Result<(), Error> {
        self.calls.push(format!("reread {claim}"));
        Ok(())
    }
    fn run(&mut self, program: &'static str, args: &[String]) -> Result<(), Error> {
        self.calls.push(format!("{program} {}", args.join(" ")));
        let target = args.last().unwrap().clone();
        let works = self.labelclear_works;
        let size = if target == self.disk {
            None
        } else {
            Some(self.after.identity.bytes)
        };
        let (image, offset) = self.image(&target);
        match program {
            "zpool" if works => {
                let bytes = size.map_or(image.len() as u64, |_| 8 * LABEL);
                let aligned = bytes & !(LABEL - 1);
                for label in [0, LABEL, aligned - 2 * LABEL, aligned - LABEL] {
                    let at = (offset + label) as usize;
                    image[at..at + LABEL as usize].fill(0);
                }
            }
            "sgdisk" => {
                let len = image.len();
                image[512..520].fill(0);
                image[len - 512..len - 504].fill(0);
            }
            _ => {}
        }
        Ok(())
    }
    fn probe(&mut self, path: &str) -> Result<(), Error> {
        self.calls.push(format!("probe {path}"));
        Ok(())
    }
    fn read_at(&mut self, path: &str, offset: u64, buffer: &mut [u8]) -> Result<(), Error> {
        let (image, base) = self.image(path);
        let at = (base + offset) as usize;
        let bytes = image
            .get(at..at + buffer.len())
            .ok_or_else(|| refuse("failed disk read"))?;
        buffer.copy_from_slice(bytes);
        Ok(())
    }
}

const HEADER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn fake_disk(labels_at: &[u64], labelclear_works: bool) -> (FakeDisk, DiskReview) {
    let disk_bytes = 16 * LABEL;
    let mut image = vec![0_u8; disk_bytes as usize];
    image[512..520].copy_from_slice(b"EFI PART");
    let len = image.len();
    image[len - 512..len - 504].copy_from_slice(b"EFI PART");
    for at in labels_at {
        let at = (*at + (16 << 10)) as usize;
        image[at..at + 12].copy_from_slice(&HEADER);
    }
    let mut identity = identity("/dev/vdd", "252:48", "/sys/devices/pci/block/vdd".into());
    identity.bytes = disk_bytes;
    let mut review = review_of(
        identity.clone(),
        vec![partition("/dev/vdd1", "252:49", 8 * LABEL)],
    );
    review.method = Method::Clear {
        reason: ClearReason::NotNvme,
        extents: vec![Extent {
            path: "/dev/vdd1".into(),
            start: 4 * LABEL,
            bytes: 8 * LABEL,
        }],
    };
    let mut after = review_of(identity, Vec::new());
    after.partition_table_uuid = None;
    let fake = FakeDisk {
        nvme: FakeNvme::default(),
        bytes: [("/dev/vdd".to_string(), image)].into(),
        offsets: [("/dev/vdd1".to_string(), 4 * LABEL)].into(),
        disk: "/dev/vdd".into(),
        after,
        calls: Vec::new(),
        labelclear_works,
        sanitize_erases: true,
    };
    (fake, review)
}

#[test]
fn original_label_ranges_remain_observable_after_partition_nodes_disappear() {
    let start = 4 * LABEL;
    let regions = [Extent {
        path: "/dev/vdd1".into(),
        start,
        bytes: 8 * LABEL,
    }];
    for offset in [0, LABEL, 6 * LABEL, 7 * LABEL] {
        let (mut fake, review) = fake_disk(&[start + offset], true);
        fake.offsets.clear();
        assert!(labels_present_with(&review.identity, &regions, &mut fake).unwrap());
        assert!(fake.calls.is_empty(), "the probe must be read-only");
    }
    let (mut fake, review) = fake_disk(&[], true);
    fake.offsets.clear();
    assert!(!labels_present_with(&review.identity, &regions, &mut fake).unwrap());
    assert!(fake.calls.is_empty());
}

#[test]
fn unknown_unreadable_and_unbounded_original_labels_cannot_prove_erasure() {
    let start = 4 * LABEL;
    let regions = [Extent {
        path: "/dev/vdd1".into(),
        start,
        bytes: 8 * LABEL,
    }];
    for offset in [0, LABEL, 6 * LABEL, 7 * LABEL] {
        let (mut fake, review) = fake_disk(&[], true);
        let at = (start + offset + (16 << 10)) as usize;
        fake.bytes.get_mut("/dev/vdd").unwrap()[at..at + 12].fill(0xa5);
        assert!(labels_present_with(&review.identity, &regions, &mut fake).is_err());
    }
    let (mut fake, review) = fake_disk(&[], true);
    fake.bytes
        .get_mut("/dev/vdd")
        .unwrap()
        .truncate((start + LABEL) as usize);
    assert!(labels_present_with(&review.identity, &regions, &mut fake).is_err());
    assert!(labels_present_with(&review.identity, &[], &mut fake).is_err());
    let outside = [Extent {
        path: "/dev/vdd1".into(),
        start: review.identity.bytes,
        bytes: 8 * LABEL,
    }];
    assert!(labels_present_with(&review.identity, &outside, &mut fake).is_err());
    assert!(fake.calls.is_empty());
}

#[test]
fn native_original_label_reads_use_saved_disk_offsets_and_do_not_write() {
    let scratch = Scratch::new();
    let path = scratch.0.join("original-disk.img");
    let start = 4 * LABEL;
    let (fake, mut review) = fake_disk(&[start + 7 * LABEL], true);
    let original = fake.bytes["/dev/vdd"].clone();
    fs::write(&path, &original).unwrap();
    review.identity.path = path.to_str().unwrap().into();
    let regions = [Extent {
        path: "/dev/vanished-partition".into(),
        start,
        bytes: 8 * LABEL,
    }];
    assert!(labels_present_with(&review.identity, &regions, &mut Native).unwrap());
    assert_eq!(fs::read(&path).unwrap(), original);
    let zero = vec![0; original.len()];
    fs::write(&path, &zero).unwrap();
    assert!(!labels_present_with(&review.identity, &regions, &mut Native).unwrap());
    assert_eq!(fs::read(&path).unwrap(), zero);
    fs::write(&path, []).unwrap();
    assert!(labels_present_with(&review.identity, &regions, &mut Native).is_err());
}

#[test]
fn clearing_does_each_partition_then_the_disk_and_verifies_by_probing() {
    // A pool label in the partition (its four labels), none on the disk.
    let part = 4 * LABEL;
    let (mut fake, review) = fake_disk(
        &[part, part + LABEL, part + 6 * LABEL, part + 7 * LABEL],
        true,
    );
    let outcome = execute(&review, &mut fake).unwrap();
    assert!(outcome.complete);
    assert!(outcome.report.contains("not erased"), "{}", outcome.report);
    assert_eq!(
        fake.calls,
        [
            "claim /dev/vdd1",
            "zpool labelclear -f /dev/vdd1",
            "wipefs --all /dev/vdd1",
            "probe /dev/vdd1",
            "claim /dev/vdd",
            "wipefs --all /dev/vdd",
            "sgdisk --zap-all /dev/vdd",
            "claim /dev/vdd",
            "reread /dev/vdd",
            "plan /dev/vdd",
            "probe /dev/vdd",
        ]
    );
    // A label that survives labelclear refuses completion.
    let (mut fake, review) = fake_disk(&[part + 7 * LABEL], false);
    let error = execute(&review, &mut fake).unwrap_err().to_string();
    assert!(error.contains("ZFS label remains on /dev/vdd1"), "{error}");
    assert!(
        !fake
            .calls
            .iter()
            .any(|c| c.contains("/dev/vdd ") || c.ends_with(" /dev/vdd")),
        "{:?}",
        fake.calls
    );
    // A whole-disk label is cleared on the disk.
    let (mut fake, review) = fake_disk(&[0], true);
    execute(&review, &mut fake).unwrap();
    assert!(
        fake.calls
            .contains(&"zpool labelclear -f /dev/vdd".to_string())
    );
    // A disk that still shows a partition after the erase refuses.
    let (mut fake, review) = fake_disk(&[], true);
    fake.after.partitions = review.partitions.clone();
    assert!(
        execute(&review, &mut fake)
            .unwrap_err()
            .to_string()
            .contains("still shows")
    );
    // So does a changed identity.
    let (mut fake, review) = fake_disk(&[], true);
    fake.after.identity.serial = Some("other".into());
    assert!(execute(&review, &mut fake).is_err());
}

/// The captured XPG as the disk, planned by `select`, with its sanitize log
/// queue as given.
fn sanitize_review(scratch: &Scratch, logs: &[String]) -> (FakeDisk, DiskReview) {
    let mut review = nvme_disk(scratch, Layout::Controller, cntlid(XPG));
    review.identity.bytes = 16 * LABEL;
    review.method = select(&review, &scratch.0, &mut FakeNvme::drive(XPG)).unwrap();
    let mut after = review_of(review.identity.clone(), Vec::new());
    after.partition_table_uuid = None;
    let mut image = vec![0_u8; 16 * LABEL as usize];
    image[512..520].copy_from_slice(b"EFI PART");
    let fake = FakeDisk {
        nvme: FakeNvme::drive(XPG).logs(logs),
        bytes: [("/dev/nvme0n1".to_string(), image)].into(),
        offsets: BTreeMap::new(),
        disk: "/dev/nvme0n1".into(),
        after,
        calls: Vec::new(),
        labelclear_works: true,
        sanitize_erases: true,
    };
    (fake, review)
}

#[test]
fn sanitize_holds_the_disk_verifies_it_and_reports_what_the_controller_said() {
    let scratch = Scratch::new();
    let xpg = of(XPG, "sanitize-log.json");
    let logs = [erased(&xpg, 0), fixture(IN_PROGRESS), xpg.clone()];
    let (mut fake, review) = sanitize_review(&scratch, &logs);
    assert_eq!(review.method, sanitize_of(Action::CryptoErase));
    let outcome = execute(&review, &mut fake).unwrap();
    assert!(
        outcome.report.contains("controller reported completion")
            && outcome.report.contains("namespace 1")
            && !outcome.report.contains("erased and verified"),
        "{}",
        outcome.report
    );
    assert_eq!(
        fake.calls,
        [
            "claim /dev/nvme0n1",
            "sanitize-log /dev/nvme0",
            "id-ctrl /dev/nvme0",
            "sanitize /dev/nvme0",
            "sanitize-log /dev/nvme0",
            "sanitize-log /dev/nvme0",
            "reread /dev/nvme0n1",
            "plan /dev/nvme0n1",
            "probe /dev/nvme0n1",
        ]
    );
    // No new sanitize seen, but no data written since the last crypto erase:
    // the report says that, not that the controller reported completion.
    let scratch = Scratch::new();
    let (mut fake, review) = sanitize_review(&scratch, std::slice::from_ref(&xpg));
    let report = execute(&review, &mut fake).unwrap().report;
    assert!(
        report.starts_with("no new sanitize was observed; the controller reports no user data written since its last successful crypto erase")
            && !report.contains("reported completion"),
        "{report}"
    );
    // A GPT header the sanitize left in place refuses completion.
    let scratch = Scratch::new();
    let (mut fake, review) = sanitize_review(&scratch, &logs);
    fake.sanitize_erases = false;
    assert!(
        execute(&review, &mut fake)
            .unwrap_err()
            .to_string()
            .contains("GPT header remains")
    );
    // A refused submission leaves everything else undone: no metadata
    // clearing, no reread, no verification.
    let scratch = Scratch::new();
    let (mut fake, review) = sanitize_review(&scratch, &logs);
    fake.nvme.submit = Some(Err("Access Denied".into()));
    assert!(execute(&review, &mut fake).is_err());
    assert!(
        !fake.calls.iter().any(|c| c.starts_with("wipefs")
            || c.starts_with("zpool")
            || c.starts_with("reread")
            || c.starts_with("plan")),
        "{:?}",
        fake.calls
    );
}

#[test]
fn a_controller_node_that_changed_since_the_plan_gets_no_submission() {
    let xpg = of(XPG, "sanitize-log.json");
    let logs = [erased(&xpg, 0), fixture(IN_PROGRESS), xpg];
    type Change = fn(&mut FakeNvme);
    let cases: [(&str, Change); 3] = [
        ("another device number", |n| {
            n.nodes.insert(DEV.into(), Ok("243:1".into()));
        }),
        ("no longer a character device", |n| {
            n.nodes.remove(DEV);
        }),
        ("another controller's serial", |n| {
            let text = edit(&of(XPG, "id-ctrl.json"), "/sn", serde_json::json!("OTHER"));
            n.answers.insert("id-ctrl /dev/nvme0".into(), Ok(text));
        }),
    ];
    for (what, change) in cases {
        let scratch = Scratch::new();
        let (mut fake, review) = sanitize_review(&scratch, &logs);
        change(&mut fake.nvme);
        let error = execute(&review, &mut fake).unwrap_err().to_string();
        assert!(
            !fake
                .calls
                .iter()
                .any(|c| c.starts_with("sanitize /dev") || c.starts_with("reread")),
            "{what}: {:?}",
            fake.calls
        );
        assert!(error.contains("/dev/nvme0"), "{what}: {error}");
    }
}

#[test]
fn the_planned_controller_must_be_the_reviewed_disks() {
    // (what, change to the scratch sysfs or the answers, accepted)
    type Change = fn(&Scratch, &mut DiskReview, FakeNvme) -> FakeNvme;
    let cases: [(&str, Change, bool); 10] = [
        ("all match", |_, _, n| n, true),
        (
            "a space-padded serial, as nvme-cli prints it",
            |_, _, n| n.id_ctrl(XPG, "/sn", serde_json::json!("SCRUBBED            ")),
            true,
        ),
        (
            "id-ctrl names another serial",
            |_, _, n| n.id_ctrl(XPG, "/sn", serde_json::json!("OTHER")),
            false,
        ),
        (
            "sysfs names another serial than the disk",
            |scratch, _, n| {
                scratch.write("devices/pci/nvme0/nvme/nvme0/serial", "OTHER");
                n.id_ctrl(XPG, "/sn", serde_json::json!("OTHER"))
            },
            false,
        ),
        (
            "the disk has no serial",
            |_, review, n| {
                review.identity.serial = None;
                n
            },
            false,
        ),
        (
            "id-ctrl names another subsystem",
            |_, _, n| {
                n.id_ctrl(
                    XPG,
                    "/subnqn",
                    serde_json::json!("nqn.2014-08.org.nvmexpress:other"),
                )
            },
            false,
        ),
        (
            "id-ctrl names no subsystem while sysfs does",
            |_, _, n| {
                let mut text: serde_json::Value =
                    serde_json::from_str(&of(XPG, "id-ctrl.json")).unwrap();
                text.as_object_mut().unwrap().remove("subnqn");
                n.answer("id-ctrl /dev/nvme0", Ok(text.to_string()))
            },
            false,
        ),
        (
            "sysfs shows no subsystem NQN: the serial binds",
            |scratch, _, n| {
                fs::remove_file(scratch.0.join("devices/pci/nvme0/nvme/nvme0/subsysnqn")).unwrap();
                n.id_ctrl(
                    XPG,
                    "/subnqn",
                    serde_json::json!("nqn.2014-08.org.nvmexpress:other"),
                )
            },
            true,
        ),
        (
            "the kernel's own NQN (IGNORE_DEV_SUBNQN): the serial binds",
            |scratch, _, n| {
                scratch.write(
                    "devices/pci/nvme0/nvme/nvme0/subsysnqn",
                    "nqn.2014.08.org.nvmexpress:1cc11cc1SCRUBBED",
                );
                n
            },
            true,
        ),
        (
            "the node is another device",
            |_, _, n| n.with_node(DEV, Ok("243:9")),
            false,
        ),
    ];
    for (what, change, accepted) in cases {
        let scratch = Scratch::new();
        let mut review = nvme_disk(&scratch, Layout::Controller, cntlid(XPG));
        let mut nvme = change(&scratch, &mut review, FakeNvme::drive(XPG));
        let result = select(&review, &scratch.0, &mut nvme);
        match (result, accepted) {
            (Ok(method), true) => assert_eq!(method, sanitize_of(Action::CryptoErase), "{what}"),
            (Err(_), false) => {}
            (other, _) => panic!("{what}: {other:?}"),
        }
    }
    // The node must be a character device.
    let scratch = Scratch::new();
    let review = nvme_disk(&scratch, Layout::Controller, cntlid(XPG));
    let mut nvme = FakeNvme::drive(XPG);
    nvme.nodes.clear();
    assert!(
        select(&review, &scratch.0, &mut nvme)
            .unwrap_err()
            .to_string()
            .contains("not a character device")
    );
}

#[test]
fn native_nodes_are_character_devices_only() {
    let scratch = Scratch::new();
    assert_eq!(Native.node("/dev/null").unwrap(), "1:3");
    let file = scratch.0.join("regular");
    fs::write(&file, b"").unwrap();
    assert!(Native.node(file.to_str().unwrap()).is_err());
    let link = scratch.0.join("link");
    std::os::unix::fs::symlink("/dev/null", &link).unwrap();
    assert!(Native.node(link.to_str().unwrap()).is_err(), "a symlink");
    assert!(
        Native
            .node(scratch.0.join("absent").to_str().unwrap())
            .is_err()
    );
}

#[test]
fn the_method_serializes_with_its_kind() {
    assert_eq!(
        serde_json::to_value(sanitize_of(Action::CryptoErase)).unwrap(),
        serde_json::json!({
            "kind": "sanitize", "action": "crypto_erase",
            "controller": "/dev/nvme0", "device_number": "243:0", "nsid": 1
        })
    );
    let text = sanitize_of(Action::BlockErase).describe();
    assert!(
        text.contains("block erase")
            && text.contains("cannot be aborted")
            && text.contains("resumes after power loss"),
        "{text}"
    );
    for (wire, reason) in [
        ("overwrite_only", ClearReason::OverwriteOnly),
        ("multiple_controllers", ClearReason::MultipleControllers),
        ("multiple_namespaces", ClearReason::MultipleNamespaces),
    ] {
        let clear = Method::Clear {
            reason,
            extents: vec![],
        };
        assert_eq!(
            serde_json::to_value(&clear).unwrap(),
            serde_json::json!({"kind": "clear", "reason": wire, "extents": []})
        );
        assert!(clear.describe().contains("not erased"));
        assert!(clear.summary().contains(reason.text()));
    }
}

#[test]
fn a_plan_is_refused_when_the_probe_that_verifies_an_erase_is_absent() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let probe = scratch.0.join("zboot-probe-signatures");
    let missing = require_probe(&probe).unwrap_err().to_string();
    assert!(missing.contains("missing or not executable"), "{missing}");
    assert!(missing.contains("none is planned"), "{missing}");
    fs::write(&probe, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(require_probe(&probe).is_err(), "a file nobody can run");
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap();
    require_probe(&probe).unwrap();
    assert!(
        require_probe(&scratch.0).is_err(),
        "a directory is no probe"
    );
}
