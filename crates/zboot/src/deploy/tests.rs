use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("zboot-deploy-tests-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub(super) fn review(root: &Path) -> CoreReview {
    let disk = DiskIdentity {
        path: "/dev/not-a-real-deploy-device".into(),
        device_number: "252:48".into(),
        sysfs_path: "/sys/devices/test/vdd".into(),
        bytes: 8 * 1024 * 1024 * 1024,
        logical_sector: 512,
        physical_sector: 4096,
        serial: Some("owned-disk-D".into()),
        wwn: None,
        model: Some("test".into()),
    };
    let factory = RootTar {
        path: root.join("factory.tar.zst"),
        sha256: "ef".repeat(32),
        bytes: 1,
        zstd: true,
        kernels: vec!["test".into()],
        entries: 1,
        logical_bytes: 0,
    };
    let artifacts = EfiFile {
        efi: root.join("zboot.efi"),
        sha256: "78".repeat(32),
        bytes: 1,
    };
    let selection = request::DeployRequest {
        schema_version: 3,
        disk: disk.path.clone(),
        pool: "newpool".into(),
        hostid: None,
        hostname: None,
        purpose: request::Purpose::Os {
            factory: factory.path.clone(),
            dataset: "newpool/ROOT/os".into(),
        },
        boot: request::Boot::OnTarget {
            esp_bytes: 512 * 1024 * 1024,
        },
        swap: request::Swap::None,
        boot_artifact_directory: artifacts.efi.clone(),
        journal_directory: root.into(),
        overlays: Vec::new(),
        portable: false,
        fresh_image: false,
    };
    let operation_id = layout::derived_uuid(b"fixture", "operation");
    let mut review = CoreReview {
        schema_version: 3,
        hostid: request::requested_hostid(&selection, &operation_id).unwrap(),
        layout: Layout::selected(&disk, Some(512 * 1024 * 1024), None, &operation_id).unwrap(),
        operation_id,
        disk,
        factory: Some(factory),
        overlays: Vec::new(),
        selection,
        external_esp: None,
        artifacts,
        loss_token: String::new(),
    };
    review.loss_token = token(&review).unwrap();
    review
}
fn operation(root: &Path) -> Operation {
    let review = review(root);
    Operation {
        review,
        swap: None,
        esp: None,
        zfs: None,
        pool: None,
        root: None,
        be: None,
        esp_review: None,
        boot_files: BTreeMap::new(),
        final_content: None,
        export_intent: None,
        published: false,
    }
}

#[test]
fn completed_deploy_names_the_firmware_loader() {
    let root = Scratch::new();
    let point: Endpoint = serde_json::from_value(serde_json::json!({
        "name": "newpool",
        "identity": {"pool_guid": "100", "guid": "11", "createtxg": "1", "objsetid": "21"}
    }))
    .unwrap();
    let esp = selected_review(&root.0, true, true)
        .external_esp
        .unwrap()
        .target;
    let mut op = operation(&root.0);
    op.pool = Some(point.clone());
    op.root = Some(point);
    op.esp = Some(esp);
    let result = outcome(op);
    assert_eq!(
        result.firmware_selection,
        "Select EFI/zboot/zboot.efi in firmware; no NVRAM changes were made"
    );
}

fn selected_review(root: &Path, empty: bool, external: bool) -> CoreReview {
    let mut review = review(root);
    review.disk.bytes = 64 * 1024 * 1024 * 1024;
    let mut request = review.selection.clone();
    if empty {
        request.purpose = request::Purpose::EmptyRoot {
            container: "newpool/ROOT".into(),
        };
    }
    if external {
        request.boot = request::Boot::External {
            partition: "/dev/test-external-esp".into(),
            replace_fallback: false,
        };
    }
    request.swap = request::Swap::Create {
        bytes: 32 * 1024 * 1024 * 1024,
    };
    review.selection = request;
    if empty {
        review.factory = None;
    }
    review.layout = Layout::selected(
        &review.disk,
        if external {
            None
        } else {
            Some(512 * 1024 * 1024)
        },
        Some(32 * 1024 * 1024 * 1024),
        &review.operation_id,
    )
    .unwrap();
    if external {
        let mut disk = review.disk.clone();
        disk.path = "/dev/test-external".into();
        disk.device_number = "252:64".into();
        disk.sysfs_path = "/sys/devices/test/external".into();
        let target = PartitionIdentity {
            disk,
            partition: device::Partition {
                path: "/dev/test-external-esp".into(),
                device_number: "252:65".into(),
                bytes: 512 * 1024 * 1024,
                partition_uuid: Some(uuid::Uuid::new_v4().to_string()),
                filesystem: Some("vfat".into()),
                filesystem_uuid: Some("ABCD-1234".into()),
                filesystem_label: None,
            },
            number: 1,
            partition_type: Some(layout::ESP_TYPE.into()),
            readonly: false,
        };
        let mut child = esp::EspReview {
            schema_version: 4,
            target,
            artifacts: review.artifacts.clone(),
            previous: [("EFI/zboot/zboot.efi".into(), None)].into(),
            loss_token: String::new(),
        };
        child.loss_token = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&child).unwrap())
        );
        review.external_esp = Some(child);
    }
    review.loss_token = token(&review).unwrap();
    review
}

#[test]
fn pool_creation_hostid_handoff_restores_rescue_parameter_on_success_and_failure() {
    let scratch = Scratch::new();
    let parameter = scratch.0.join("spl_hostid");
    fs::write(&parameter, "1\n").unwrap();
    let result = create_with_hostid_at(&parameter, &parameter, 2, || {
        assert_eq!(fs::read_to_string(&parameter).unwrap(), "2");
        Ok(42)
    })
    .unwrap();
    assert_eq!(result, 42);
    assert_eq!(fs::read_to_string(&parameter).unwrap(), "1");
    let error = create_with_hostid_at(&parameter, &parameter, 3, || {
        assert_eq!(fs::read_to_string(&parameter).unwrap(), "3");
        Err::<(), _>(refuse("simulated create failure"))
    })
    .unwrap_err();
    assert!(error.to_string().contains("simulated create failure"));
    assert_eq!(fs::read_to_string(&parameter).unwrap(), "1");
    let stale_effective = scratch.0.join("effective_hostid");
    fs::write(&stale_effective, "1").unwrap();
    fs::write(&parameter, "0\n").unwrap();
    create_with_hostid_at(&parameter, &stale_effective, 1, || Ok(())).unwrap();
    assert_eq!(fs::read_to_string(&parameter).unwrap(), "0\n");
    fs::write(&parameter, "1").unwrap();
    let error = create_with_hostid_at(&parameter, &stale_effective, 4, || -> io::Result<()> {
        panic!("unconfirmed hostid must prevent pool creation")
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("did not accept reviewed pool hostid")
    );
    assert_eq!(fs::read_to_string(&parameter).unwrap(), "1");
    fs::write(&parameter, "0x0a1b2c3d\n").unwrap();
    assert_eq!(effective_hostid(&parameter).unwrap(), 0x0a1b2c3d);
}

#[test]
fn a_selection_without_a_hostid_reports_none_and_derives_one() {
    let review = selected_review(
        Path::new("/nonexistent/zboot-pure-deploy-fixture"),
        false,
        false,
    );
    let value = serde_json::to_value(&review.selection).unwrap();
    assert!(value.get("hostid").is_none());
    assert_eq!(review.hostid, hostid(&review.operation_id));
    assert_eq!(token(&review).unwrap(), review.loss_token);
    validate(&review).unwrap();
}
#[test]
fn v2_selected_hostid_binds_paired_os_and_empty_root_reviews_and_consent() {
    let root = Scratch::new();
    let mut os = selected_review(&root.0, false, false);
    let mut empty = selected_review(&root.0, true, false);
    empty.operation_id = layout::derived_uuid(b"paired-empty-root", "operation");
    empty.layout = Layout::selected(
        &empty.disk,
        Some(512 * 1024 * 1024),
        Some(32 * 1024 * 1024 * 1024),
        &empty.operation_id,
    )
    .unwrap();
    assert_ne!(os.operation_id, empty.operation_id);
    for review in [&mut os, &mut empty] {
        review.selection.hostid = Some("0a1b2c3d".into());
        review.hostid = "0a1b2c3d".into();
        review.loss_token = token(review).unwrap();
        validate(review).unwrap();
        assert_eq!(
            serde_json::to_value(&*review).unwrap()["hostid"],
            "0a1b2c3d"
        );
    }
    assert_eq!(os.hostid, empty.hostid);

    let mut changed = os.clone();
    changed.selection.hostid = Some("1a2b3c4d".into());
    changed.hostid = "1a2b3c4d".into();
    assert_ne!(token(&changed).unwrap(), os.loss_token);
    assert!(validate(&changed).is_err());
    // Any neutral Menu deploys any hostid: none is bound to a Menu.
    changed.loss_token = token(&changed).unwrap();
    validate(&changed).unwrap();

    let mut mismatched = os.clone();
    mismatched.hostid = "1a2b3c4d".into();
    mismatched.loss_token = token(&mismatched).unwrap();
    assert!(validate(&mismatched).is_err());

    // A hostname is an OS deploy's, bound into its consent.
    let mut named = os.clone();
    named.selection.hostname = Some("desk".into());
    assert!(validate(&named).is_err());
    named.loss_token = token(&named).unwrap();
    validate(&named).unwrap();
    for bad in ["-desk", "desk-", "de sk", "a..b", ""] {
        let mut broken = os.clone();
        broken.selection.hostname = Some(bad.into());
        broken.loss_token = token(&broken).unwrap();
        assert!(validate(&broken).is_err(), "{bad:?}");
    }
    let mut empty_named = empty;
    empty_named.selection.hostname = Some("desk".into());
    empty_named.loss_token = token(&empty_named).unwrap();
    assert!(validate(&empty_named).is_err());
}
#[test]
fn v2_selected_hostid_rejects_bad_values_before_native_planning() {
    let request = selected_review(
        Path::new("/nonexistent/zboot-pure-deploy-fixture"),
        false,
        false,
    )
    .selection;
    for bad in [
        "00000000",
        "ffffffff",
        "ABCDEF12",
        "abcdef1G",
        "1234567",
        "123456789",
        "1234-678",
        "xyzzy123",
    ] {
        let mut direct = request.clone();
        direct.hostid = Some(bad.into());
        assert!(
            request::plan(&direct)
                .unwrap_err()
                .to_string()
                .contains("deploy hostid"),
            "planned invalid {bad}"
        );
    }
    for good in ["00000001", "fffffffe", "0a1b2c3d"] {
        let mut direct = request.clone();
        direct.hostid = Some(good.into());
        request::validate_request(&direct).unwrap();
    }
}
#[test]
fn a_review_carries_one_loss_token() {
    let root = Scratch::new();
    let review = selected_review(&root.0, false, false);
    validate(&review).unwrap();
    let wire = serde_json::to_string_pretty(&review).unwrap();
    assert_eq!(wire.matches("\"loss_token\"").count(), 1);
}
#[test]
fn new_deploy_requires_explicit_menu_and_the_reviewed_overlays() {
    let original = selected_review(
        Path::new("/nonexistent/zboot-pure-deploy-fixture"),
        false,
        false,
    );
    validate(&original).unwrap();
    let mut invalid_efi = original.clone();
    invalid_efi.artifacts.sha256 = "not a digest".into();
    invalid_efi.loss_token = token(&invalid_efi).unwrap();
    assert!(validate(&invalid_efi).is_err());
    // The selection names a host overlay the review did not read.
    let mut unreviewed = original;
    unreviewed
        .selection
        .overlays
        .push("/etc/zboot/overlay".into());
    unreviewed.loss_token = token(&unreviewed).unwrap();
    assert!(validate(&unreviewed).is_err());
}
#[test]
fn extended_consent_binds_purpose_swap_and_external_preimages() {
    let root = Scratch::new();
    for empty in [false, true] {
        for external in [false, true] {
            let review = selected_review(&root.0, empty, external);
            validate(&review).unwrap();
            assert!(
                apply_core(&review, "wrong")
                    .unwrap_err()
                    .to_string()
                    .contains("consent token does not match")
            );
            for field in 0..5 {
                let mut changed = review.clone();
                match field {
                    0 => {
                        changed.layout.swap.as_mut().unwrap().uuid =
                            uuid::Uuid::new_v4().to_string()
                    }
                    1 => changed.selection.swap = request::Swap::None,
                    2 => {
                        changed.selection.purpose = request::Purpose::EmptyRoot {
                            container: "newpool/elsewhere".into(),
                        }
                    }
                    3 => changed.disk.serial = Some("replacement".into()),
                    _ => {
                        if let Some(esp) = &mut changed.external_esp {
                            *esp.previous.values_mut().next().unwrap() = Some(esp::FileIdentity {
                                sha256: "aa".repeat(32),
                                bytes: 1,
                            });
                        } else {
                            changed.selection.boot = request::Boot::OnTarget {
                                esp_bytes: 1024 * 1024 * 1024,
                            };
                        }
                    }
                }
                assert!(
                    validate(&changed).is_err(),
                    "empty={empty} external={external} field={field}"
                );
                assert_ne!(token(&changed).unwrap(), review.loss_token);
            }
        }
    }
}
#[test]
fn exact_deploy_consent_binds_disk_layout_os_and_boot_artifact_before_native_effects() {
    let root = Scratch::new();
    let review = review(&root.0);
    validate(&review).unwrap();
    let failure = apply_core(&review, "wrong-token").unwrap_err().to_string();
    assert!(
        failure.contains("consent token does not match"),
        "{failure}"
    );
    for case in 0..10 {
        let mut changed = review.clone();
        match case {
            0 => changed.disk.serial = Some("replacement".into()),
            1 => changed.layout.esp_uuid = uuid::Uuid::new_v4().to_string(),
            2 => changed.selection.pool = "other".into(),
            3 => {
                changed.selection.purpose = request::Purpose::Os {
                    factory: changed.factory.as_ref().unwrap().path.clone(),
                    dataset: "newpool/ROOT/other".into(),
                }
            }
            4 => changed.factory.as_mut().unwrap().sha256 = "cd".repeat(32),
            7 => changed.overlays.push(overlay::portable()),
            8 => changed.operation_id = uuid::Uuid::new_v4().to_string(),
            5 => changed.artifacts.sha256 = "ff".repeat(32),
            6 => changed.selection.journal_directory = root.0.join("elsewhere"),
            _ => changed.layout.fat_id = "ABCDEF12".into(),
        }
        assert!(validate(&changed).is_err(), "case {case}");
        assert_ne!(token(&changed).unwrap(), review.loss_token, "case {case}");
    }
}

#[test]
fn the_attempt_directory_must_be_private_canonical_and_ours() {
    let root = Scratch::new();
    assert_eq!(attempt_directory(&root.0).unwrap(), root.0);
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(attempt_directory(&root.0).is_err());
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.0.with_extension("link");
    std::os::unix::fs::symlink(&root.0, &link).unwrap();
    assert!(attempt_directory(&link).is_err());
    fs::remove_file(link).unwrap();
}
#[test]
fn pool_storage_requires_exact_single_direct_partition_without_auxiliary_leaves() {
    let value = serde_json::json!({"output_version":{"command":"zpool status","vers_major":0,"vers_minor":1},"pools":{"newpool":{"vdevs":{"root":{"vdev_type":"root","vdevs":{"disk":{"vdev_type":"disk","path":"/dev/vdd2"}}}}}}});
    assert_eq!(
        single_pool_leaf(&value.to_string(), "newpool").unwrap(),
        "/dev/vdd2"
    );
    for case in 0..4 {
        let mut invalid = value.clone();
        match case {
            0 => {
                invalid["pools"]["newpool"]["spares"] =
                    serde_json::json!({"disk":{"vdev_type":"disk","path":"/dev/vde"}})
            }
            1 => invalid["pools"]["newpool"]["vdevs"]["root"]["vdev_type"] = "mirror".into(),
            2 => invalid["output_version"]["vers_major"] = 1.into(),
            _ => {
                invalid["pools"]["newpool"]["vdevs"]["root"]["vdevs"]["disk"]["vdev_type"] =
                    "file".into()
            }
        }
        assert!(
            single_pool_leaf(&invalid.to_string(), "newpool").is_err(),
            "case {case}"
        );
    }
}

#[test]
fn fresh_pool_admission_accepts_sa_alias_but_refuses_directory_xattrs() {
    let scratch = Scratch::new();
    let op = operation(&scratch.0);
    let name = &op.review.selection.pool;
    let inspection = zfs_tools::engine::native::inspect_with(
        &zfs_tools::engine::InspectRequest::new(vec![], true).unwrap(),
        |program, args| {
            Ok(if program == "zpool" {
                format!("{name}\t100\t1000\t0\t1000\tONLINE\t-\n")
            } else if args.iter().any(|arg| arg == "filesystem,volume") {
                format!("{name}\tfilesystem\t10\t0\t1000\t0\tnone\t-\t2\t10\tno\ton\toff\t-\toff\t-\t-\t-\t{}\n", op.review.operation_id)
            } else {
                String::new()
            })
        },
    ).unwrap();
    let property = |value: &str| native::NativeProperty {
        value: value.into(),
        source: "local".into(),
    };
    let mut state = NativeState {
        inspection,
        dataset_properties: BTreeMap::from([(
            name.clone(),
            BTreeMap::from([
                ("zboot:pending".into(), property(&op.review.operation_id)),
                ("xattr".into(), property("sa")),
                ("acltype".into(), property("posix")),
            ]),
        )]),
        pool_properties: BTreeMap::new(),
    };
    for value in ["sa", "on"] {
        state
            .dataset_properties
            .get_mut(name)
            .unwrap()
            .insert("xattr".into(), property(value));
        observe_member(&op, &state, name, None, false).unwrap();
    }
    // A fresh member carries no zboot property but its pending fence.
    for key in ["zboot:be", "zboot:future-role"] {
        let mut marked = state.clone();
        marked
            .dataset_properties
            .get_mut(name)
            .unwrap()
            .insert(key.into(), property("unknown"));
        assert!(observe_member(&op, &marked, name, None, false).is_err());
    }
    for value in ["dir", "off", "unknown"] {
        state
            .dataset_properties
            .get_mut(name)
            .unwrap()
            .insert("xattr".into(), property(value));
        assert!(
            observe_member(&op, &state, name, None, false).is_err(),
            "accepted {value}"
        );
    }
    state
        .dataset_properties
        .get_mut(name)
        .unwrap()
        .remove("xattr");
    assert!(observe_member(&op, &state, name, None, false).is_err());
}

#[test]
fn fresh_be_admission_uses_native_roles_and_refuses_any_other_zboot_property() {
    let scratch = Scratch::new();
    let op = operation(&scratch.0);
    let be = op.review.selection.dataset();
    let mut fake = crate::tree::fake::Fake::new();
    fake.pool(&op.review.selection.pool, 100);
    fake.create(&format!("{}/ROOT", op.review.selection.pool));
    fake.create(be);
    fake.datasets.get_mut(be).unwrap().mounted = false;
    for (key, value) in [
        ("mountpoint", "/"),
        ("canmount", "noauto"),
        ("readonly", "off"),
        ("xattr", "sa"),
        ("acltype", "posix"),
        ("zboot:pending", &op.review.operation_id),
    ] {
        fake.set(be, key, value);
    }
    let state = fake.state().unwrap();
    observe_member(&op, &state, be, None, false).unwrap();
    for (value, source) in [
        ("1", "local"),
        ("0", "received"),
        ("arbitrary legacy value", "inherited from newpool"),
    ] {
        let mut state = state.clone();
        state.dataset_properties.get_mut(be).unwrap().insert(
            "zboot:be".into(),
            native::NativeProperty {
                value: value.into(),
                source: source.into(),
            },
        );
        assert!(observe_member(&op, &state, be, None, false).is_err());
    }
}

#[test]
fn an_unproven_step_error_retains_the_failed_observation() {
    let detail = gap_detail("pool creation", "native dataset marker is missing").to_string();
    assert!(detail.contains("pool creation result is not proven"));
    assert!(detail.contains("preserve this target"));
    assert!(detail.contains("native dataset marker is missing"));
}
#[test]
fn overlays_apply_in_order_files_then_hook_and_identity_is_enforced_after_all_hooks() {
    struct Steps {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        identity_calls: usize,
    }
    impl Steps {
        fn step(&mut self, name: &'static str) -> io::Result<()> {
            self.calls.push(name);
            if self.fail == Some(name) {
                Err(refuse(name))
            } else {
                Ok(())
            }
        }
    }
    impl Configure for Steps {
        fn overlay_count(&self) -> usize {
            2
        }
        fn rootfs(&mut self, index: usize) -> io::Result<()> {
            self.step(["files1", "files2"][index])
        }
        fn post_install(&mut self, index: usize) -> io::Result<()> {
            self.step(["hook1", "hook2"][index])
        }
        fn enforce_identity(&mut self) -> io::Result<()> {
            let step = ["identity", "enforce"][self.identity_calls];
            self.identity_calls += 1;
            self.step(step)
        }
        fn portable(&mut self) -> io::Result<()> {
            self.step("portable")
        }
        fn verify_portable(&mut self) -> io::Result<()> {
            self.step("verify every initrd")
        }
    }
    let order = [
        "files1",
        "hook1",
        "files2",
        "hook2",
        "identity",
        "portable",
        "enforce",
        "verify every initrd",
    ];
    let mut steps = Steps {
        calls: Vec::new(),
        fail: None,
        identity_calls: 0,
    };
    configure(&mut steps).unwrap();
    assert_eq!(steps.calls, order);
    for (index, failing) in order.iter().enumerate() {
        let mut steps = Steps {
            calls: Vec::new(),
            fail: Some(failing),
            identity_calls: 0,
        };
        assert!(configure(&mut steps).is_err());
        assert_eq!(steps.calls, order[..=index]);
    }
}
#[test]
fn roles_are_set_on_every_member_at_creation_and_never_swept() {
    // The BE is created with its role and nothing else about mounting; the
    // systemd generator's properties are not zboot's.
    let create = be_create("rpool/ROOT/debian", "op");
    assert!(
        !create
            .iter()
            .any(|argument| argument.starts_with("zboot:be=")),
        "{create:?}"
    );
    assert!(create.iter().any(|a| a == "canmount=noauto"), "{create:?}");
    assert!(create.iter().any(|a| a == "mountpoint=/"), "{create:?}");
    assert!(
        !create.iter().any(|a| a.starts_with("org.openzfs.systemd:")),
        "{create:?}"
    );
    assert_eq!(create.last().map(String::as_str), Some("rpool/ROOT/debian"));
    // The pool root and ROOT never mount and stay read-only.
    let has = |argv: &[String], flag: &str, value: &str| {
        argv.windows(2).any(|w| w[0] == flag && w[1] == value)
    };
    let pool = pool_create("rpool", "/dev/disk/by-id/x-part2", "op");
    for value in ["canmount=off", "readonly=on", "mountpoint=none"] {
        assert!(has(&pool, "-O", value), "{pool:?}");
    }
    let root = root_create("rpool", "op");
    for value in ["canmount=off", "readonly=on", "mountpoint=none"] {
        assert!(has(&root, "-o", value), "{root:?}");
    }
    assert_eq!(root.last().map(String::as_str), Some("rpool/ROOT"));
    // Never swept: after creation deploy sets one dataset property, the
    // published BE's `readonly=off`, and inherits only its pending fence.
    assert_eq!(
        be_publish("rpool/ROOT/debian"),
        ["set", "readonly=off", "rpool/ROOT/debian"]
    );
    let source = include_str!("../deploy.rs");
    for role in ["canmount=", "readonly=o"] {
        let quoted = format!("\"{role}");
        let expected = if role == "canmount=" { 3 } else { 4 };
        assert_eq!(source.matches(&quoted).count(), expected, "{role}");
    }
    assert_eq!(source.matches("\"inherit\"").count(), 1);
    assert!(source.contains(r#"&args(&["inherit", "zboot:pending", name])"#));
    assert_eq!(
        source.matches("\"set\"").count(),
        2,
        "be_publish and bootfs"
    );
}

#[test]
fn standalone_efi_review_binds_file_bytes_and_revalidates_without_a_manifest() {
    let scratch = Scratch::new();
    let path = scratch.0.join("standalone.efi");
    crate::loader::tests::uki(&path);
    let loader = EfiFile::inspect(&path).unwrap();
    let mut review = selected_review(&scratch.0, true, false);
    review.artifacts = loader;
    review.selection.boot_artifact_directory = path.clone();
    review.loss_token = token(&review).unwrap();
    validate(&review).unwrap();
    revalidate_inputs(&review).unwrap();
    let wire = serde_json::to_value(&review).unwrap();
    assert_eq!(wire["artifacts"]["efi"], path.to_str().unwrap());
    assert!(wire["artifacts"].get("manifest").is_none());
    let mut bytes = fs::read(&path).unwrap();
    bytes[1024] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(
        revalidate_inputs(&review)
            .unwrap_err()
            .to_string()
            .contains("boot artifact changed")
    );
    assert!(command::Backend::verify_loader(&mut command::Native, &review.artifacts).is_err());
}

// New deployments bind an ordered opt-in list rather than a base layer.
fn new_review(root: &Path, overlays: Vec<overlay::Overlay>, portable: bool) -> CoreReview {
    let mut review = selected_review(root, false, false);
    review.overlays = overlays;
    let request = &mut review.selection;
    request.portable = portable;
    request.swap = request::Swap::None;
    request.overlays = review
        .overlays
        .iter()
        .take(review.overlays.len() - usize::from(portable))
        .map(|o| o.source.clone())
        .collect();
    review.hostid = request::requested_hostid(request, &review.operation_id).unwrap();
    review.layout = Layout::selected(
        &review.disk,
        match request.boot {
            request::Boot::OnTarget { esp_bytes } => Some(esp_bytes),
            request::Boot::External { .. } => None,
        },
        None,
        &review.operation_id,
    )
    .unwrap();
    review.loss_token = token(&review).unwrap();
    review
}
#[test]
fn deploy_applies_no_implicit_base_overlay() {
    let scratch = Scratch::new();
    let review = new_review(&scratch.0, Vec::new(), false);
    validate(&review).unwrap();
    assert!(ordered_overlays(&review).is_empty());
    let native = NativeConfigure {
        op: &Operation {
            review: review.clone(),
            ..operation(&scratch.0)
        },
        root: &scratch.0,
        logs: &scratch.0,
    };
    assert!(native.overlays().is_empty());
}
#[test]
fn reordering_overlays_changes_the_token_including_image_and_into_plans() {
    let scratch = Scratch::new();
    let mut overlays = Vec::new();
    for (name, bytes) in [
        ("first", b"first".as_slice()),
        ("second", b"second".as_slice()),
    ] {
        let directory = scratch.0.join(name);
        fs::create_dir_all(directory.join("rootfs/etc")).unwrap();
        fs::write(directory.join("rootfs/etc/policy"), bytes).unwrap();
        overlays.push(overlay::review(&directory).unwrap());
    }
    let mut review = new_review(&scratch.0, overlays, false);
    validate(&review).unwrap();
    let old = token(&review).unwrap();
    let mut into = super::into::Plan {
        schema_version: 1,
        request: super::into::Request {
            pool: "pool".into(),
            be: "new".into(),
            tar: review.factory.as_ref().unwrap().path.clone(),
            overlays: review.overlays.iter().map(|o| o.source.clone()).collect(),
            hostname: None,
        },
        pool: Endpoint {
            name: "pool".into(),
            identity: zfs_tools::engine::DatasetIdentity {
                pool_guid: zfs_tools::engine::Guid::new(1),
                guid: zfs_tools::engine::Guid::new(2),
                createtxg: zfs_tools::engine::Txg::new(3),
                objsetid: zfs_tools::engine::ObjsetId::new(4),
            },
        },
        container: None,
        hostid: 0x01020304,
        factory: review.factory.clone().unwrap(),
        overlays: review.overlays.clone(),
        defaults: BTreeMap::new(),
    };
    let into_token = super::into::consent(&into).unwrap();
    into.overlays.reverse();
    into.request.overlays.reverse();
    assert_ne!(into_token, super::into::consent(&into).unwrap());
    let mut image_request = review.selection.clone();
    image_request.fresh_image = true;
    image_request.disk.clear();
    image_request.journal_directory.clear();
    let image = super::image::Plan {
        schema_version: 1,
        destination: super::image::Destination {
            path: scratch.0.join("image"),
            parent: scratch.0.clone(),
            parent_device: 1,
            parent_inode: 2,
            parent_owner: 0,
            parent_mode: 0o40700,
        },
        bytes: 8 << 30,
        request: image_request,
        inputs: request::bound_inputs(&review),
    };
    let image_token = super::image::consent(&image).unwrap();
    review.overlays.reverse();
    review.selection.overlays.reverse();
    review.loss_token = token(&review).unwrap();
    validate(&review).unwrap();
    assert_ne!(old, token(&review).unwrap());
    let mut reordered_request = image.request.clone();
    reordered_request.overlays.reverse();
    let reordered = super::image::Plan {
        request: reordered_request,
        inputs: request::bound_inputs(&review),
        ..image
    };
    assert_ne!(image_token, super::image::consent(&reordered).unwrap());
}
#[test]
fn a_changed_overlay_is_refused_before_application() {
    let scratch = Scratch::new();
    let source = scratch.0.join("source");
    fs::create_dir_all(source.join("rootfs/etc")).unwrap();
    fs::write(source.join("rootfs/etc/policy"), b"reviewed").unwrap();
    let review = new_review(&scratch.0, vec![overlay::review(&source).unwrap()], false);
    revalidate_overlays(&review).unwrap();
    fs::write(source.join("rootfs/etc/policy"), b"changed").unwrap();
    assert!(revalidate_overlays(&review).is_err());
    assert!(!scratch.0.join("etc/policy").exists());
}
#[test]
fn a_portable_system_gets_no_identity_no_swap_and_no_default() {
    let scratch = Scratch::new();
    let review = new_review(&scratch.0, vec![overlay::portable()], true);
    validate(&review).unwrap();
    assert_eq!(review.hostid, "00000000");
    assert_eq!(expected_label_hostid(&review).unwrap(), None);
    assert!(review.layout.swap.is_none());
    assert!(!publishes_default(&review));
    assert_eq!(
        ordered_overlays(&review).last().copied(),
        Some(&overlay::portable())
    );
    let changes: [fn(&mut request::DeployRequest); 3] = [
        |r: &mut request::DeployRequest| r.hostid = Some("01020304".into()),
        |r: &mut request::DeployRequest| r.swap = request::Swap::Create { bytes: 1 << 30 },
        |r: &mut request::DeployRequest| {
            r.boot = request::Boot::External {
                partition: "/dev/elsewhere".into(),
                replace_fallback: false,
            }
        },
    ];
    for change in changes {
        let mut bad = review.clone();
        change(&mut bad.selection);
        bad.loss_token = token(&bad).unwrap();
        assert!(validate(&bad).is_err());
    }
}
#[test]
fn a_portable_pool_is_created_under_no_hostid_and_exported() {
    let scratch = Scratch::new();
    let parameter = scratch.0.join("spl_hostid");
    fs::write(&parameter, "123").unwrap();
    let mut effects = Vec::new();
    for effect in ["create", "import", "export"] {
        create_with_hostid_at(&parameter, &parameter, 0, || {
            assert_eq!(effective_hostid(&parameter)?, 0);
            effects.push(effect);
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read_to_string(&parameter).unwrap(), "123");
    }
    assert_eq!(effects, ["create", "import", "export"]);
}
#[test]
fn portable_stops_before_creating_when_the_effective_hostid_is_not_zero() {
    let scratch = Scratch::new();
    let parameter = scratch.0.join("spl_hostid");
    let effective = scratch.0.join("effective");
    fs::write(&parameter, "0").unwrap();
    fs::write(&effective, "123").unwrap();
    let mut created = false;
    assert!(
        create_with_hostid_at(&parameter, &effective, 0, || {
            created = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!created);
    assert_eq!(fs::read_to_string(parameter).unwrap(), "0");
}
