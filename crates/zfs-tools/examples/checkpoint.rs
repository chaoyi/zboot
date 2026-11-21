//! Black-box public SDK consumer for `tests/native-api/run.py`.
//!
//! This intentionally runs only in the disposable test guest. Native commands
//! below create controlled races/protections; all checkpoint operations use
//! only the supported public API, without an injected backend.
#![allow(clippy::disallowed_methods, reason = "guest fixtures")]
use std::{
    cell::Cell,
    os::unix::fs::PermissionsExt,
    process::Command,
    rc::Rc,
    time::{Duration, Instant},
};
use zfs_tools::{
    CanMount, CaptureStatus, DatasetKind, DatasetTarget, DeleteStatus, DevicePath, Effect,
    EffectReply, EffectTarget, Error, Guid, InventoryRequest, ObservationStop, PoolTarget,
    PropertyAssignment, PropertySource, QueryCleanup, Role, Unfinished, WriterSession,
    observe_dataset, observe_inventory, observe_management, observe_management_within,
    observe_snapshot,
};

const VOLUME: &str = "sdkproof/tree/volume";

fn native(args: &[&str]) -> String {
    let result = Command::new("zfs")
        .args(args)
        .output()
        .expect("start native zfs");
    assert!(
        result.status.success(),
        "zfs {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

fn names() -> Vec<String> {
    native(&[
        "list", "-H", "-t", "snapshot", "-o", "name", "-r", "sdkproof",
    ])
    .lines()
    .map(str::to_owned)
    .collect()
}

fn present(name: &str) -> bool {
    names().iter().any(|value| value == name)
}

fn event(case: &str, detail: serde_json::Value) {
    println!(
        "{}",
        serde_json::json!({"case": case, "passed": true, "detail": detail})
    );
}

fn target(name: &str) -> DatasetTarget {
    let observed = observe_dataset(name).expect("observe exact dataset");
    DatasetTarget::new(observed.name(), observed.identity().clone())
        .unwrap()
        .requiring_kind(observed.kind().clone())
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--effect-child") {
        return effect_child();
    }
    if std::env::args().nth(1).as_deref() == Some("--deadline-child") {
        return deadline_child();
    }
    assert_eq!(
        std::env::args().nth(1).as_deref(),
        Some("--isolated-native-proof")
    );
    assert_eq!(
        std::fs::read_to_string("/run/native-sdk-proof").unwrap(),
        "private-vda-only\n"
    );
    assert_eq!(
        native(&["list", "-H", "-t", "volume", "-o", "name", VOLUME]),
        VOLUME
    );
    let expected = target(VOLUME).requiring_kind(DatasetKind::Volume);

    // Read-only inventory: the tree with kinds, mount facts and property
    // sources, and absence proven from successful queries, without a session.
    {
        let request = InventoryRequest::new("sdkproof/tree")
            .unwrap()
            .with_snapshots()
            .with_properties();
        let inventory = observe_inventory(&request).unwrap();
        let names: Vec<_> = inventory.datasets().iter().map(|d| d.name()).collect();
        assert_eq!(
            names,
            ["sdkproof/tree", "sdkproof/tree/child", VOLUME],
            "inventory lists exactly the tree"
        );
        let tree = inventory.dataset("sdkproof/tree").unwrap().unwrap();
        assert_eq!(tree.kind(), &DatasetKind::Filesystem);
        assert_eq!(
            (tree.mountpoint(), tree.mounted(), tree.canmount()),
            (Some("none"), Some(false), Some(CanMount::On))
        );
        let mountpoint = tree.property("mountpoint").unwrap().unwrap();
        assert_eq!(
            mountpoint.source(),
            &PropertySource::Inherited("sdkproof".into())
        );
        let volume = inventory.dataset(VOLUME).unwrap().unwrap();
        assert_eq!(volume.kind(), &DatasetKind::Volume);
        assert_eq!(volume.identity(), expected.identity());
        assert_eq!(volume.mountpoint(), None);
        assert_eq!(
            volume.property("guid").unwrap().unwrap().value(),
            expected.identity().guid.to_string()
        );
        assert!(inventory.snapshots().unwrap().is_empty());
        assert_eq!(inventory.dataset("sdkproof/tree/missing").unwrap(), None);
        assert!(inventory.dataset("sdkproof").is_err(), "outside the root");
        let absent = observe_inventory(&InventoryRequest::new("sdkproof/absent").unwrap()).unwrap();
        assert!(absent.datasets().is_empty());
        assert_eq!(absent.pool_guid(), Some(expected.identity().pool_guid));
        assert_eq!(inventory.pool_guid(), Some(expected.identity().pool_guid));
        let no_pool =
            observe_inventory(&InventoryRequest::new("nopool/vm").unwrap().with_snapshots())
                .unwrap();
        assert!(no_pool.datasets().is_empty() && no_pool.snapshots().unwrap().is_empty());
        assert_eq!(no_pool.pool_guid(), None);
        event(
            "inventory_tree_and_absence",
            serde_json::json!({
                "datasets": names, "volume": volume.identity(),
                "mountpoint_source": format!("{:?}", mountpoint.source()),
            }),
        );
    }
    let mut session = WriterSession::acquire("isolated native SDK checkpoint proof").unwrap();

    // One held session is reused for every operation. Any independently opened
    // nested flock would stall this bounded guest and fail the host runner.
    let point = {
        let mut scope = session.admit(std::slice::from_ref(&expected)).unwrap();
        let capture = scope.capture("checkpoint").unwrap();
        assert_eq!(capture.status(), CaptureStatus::Complete);
        assert_eq!(capture.points().len(), 1);
        assert!(capture.missing().is_empty());
        assert_eq!(names(), [format!("{VOLUME}@checkpoint")]);
        let inventory =
            observe_inventory(&InventoryRequest::new(VOLUME).unwrap().with_snapshots()).unwrap();
        let listed = inventory
            .snapshot(&format!("{VOLUME}@checkpoint"))
            .unwrap()
            .unwrap();
        assert_eq!(listed.point(), &capture.points()[0]);
        assert!(!listed.defer_destroy() && listed.holds().is_empty());
        event(
            "inventory_snapshot_identity",
            serde_json::json!({"point": listed.point()}),
        );
        event(
            "exact_nonrecursive_zvol_capture",
            serde_json::json!({
                "operation_id": capture.operation_id(), "point": capture.points()[0],
                "inventory": names(), "targets": scope.targets().iter().map(|t| t.name()).collect::<Vec<_>>()
            }),
        );
        capture.points()[0].clone()
    };

    // Exact filesystem capture must not silently include either descendant.
    {
        let parent = target("sdkproof/tree");
        let mut scope = session.admit(&[parent]).unwrap();
        let capture = scope.capture("parent-only").unwrap();
        assert_eq!(capture.status(), CaptureStatus::Complete);
        assert_eq!(capture.points().len(), 1);
        assert!(present("sdkproof/tree@parent-only"));
        assert!(!present("sdkproof/tree/child@parent-only"));
        assert!(!present("sdkproof/tree/volume@parent-only"));
        event(
            "exact_filesystem_excludes_descendants",
            serde_json::json!(names()),
        );
    }

    {
        let mut scope = session.admit(std::slice::from_ref(&expected)).unwrap();
        native(&["hold", "sdk-proof:early", &point.name]);
        let refusal = scope
            .review_delete(std::slice::from_ref(&point))
            .err()
            .expect("held review refused");
        assert!(present(&point.name));
        event(
            "native_hold_review_refusal",
            serde_json::json!(refusal.to_string()),
        );
        native(&["release", "sdk-proof:early", &point.name]);
        let review = scope.review_delete(std::slice::from_ref(&point)).unwrap();
        native(&["hold", "sdk-proof:late", &point.name]);
        let refusal = scope
            .apply_delete(&review, review.loss_token())
            .expect_err("late hold refused");
        assert!(present(&point.name));
        event(
            "native_late_hold_apply_refusal",
            serde_json::json!(refusal.to_string()),
        );
        native(&["release", "sdk-proof:late", &point.name]);

        native(&["clone", &point.name, "sdkproof/clone"]);
        let refusal = scope
            .review_delete(std::slice::from_ref(&point))
            .err()
            .expect("clone refused");
        assert!(present(&point.name));
        event(
            "native_clone_refusal",
            serde_json::json!(refusal.to_string()),
        );
        native(&["destroy", "sdkproof/clone"]);

        let review = scope.review_delete(std::slice::from_ref(&point)).unwrap();
        let refusal = scope
            .apply_delete(&review, "wrong-loss-token")
            .expect_err("wrong token refused");
        assert!(present(&point.name));
        event("loss_token_refusal", serde_json::json!(refusal.to_string()));

        // Retaining the same SDK scope/session does not make a review fresh.
        native(&["rename", &point.name, &format!("{VOLUME}@renamed-original")]);
        native(&["snapshot", &point.name]);
        let replacement = observe_snapshot(&point.name).unwrap();
        assert_ne!(replacement.identity, point.identity);
        let refusal = scope
            .apply_delete(&review, review.loss_token())
            .expect_err("reused name refused");
        assert_eq!(observe_snapshot(&point.name).unwrap(), replacement);
        assert!(present(&format!("{VOLUME}@renamed-original")));
        event(
            "stale_snapshot_identity_name_reuse_refusal",
            serde_json::json!({
                "refusal": refusal.to_string(), "reviewed": point, "replacement": replacement
            }),
        );

        let fresh = scope
            .review_delete(std::slice::from_ref(&replacement))
            .unwrap();
        assert_eq!(fresh.points(), vec![replacement.clone()]);
        let outcome = scope.apply_delete(&fresh, fresh.loss_token()).unwrap();
        assert_eq!(outcome.status(), DeleteStatus::Complete);
        assert!(!present(&replacement.name));
        assert!(present(&format!("{VOLUME}@renamed-original")));
        assert!(present("sdkproof/tree@parent-only"));
        event(
            "identity_bound_exact_delete",
            serde_json::json!({
                "status": format!("{:?}", outcome.status()), "inventory": names()
            }),
        );

        // A foreign raw writer can mark a held snapshot for deferred destroy.
        // The SDK must refuse instead of completing that destroy indirectly.
        let deferred = scope.capture("deferred").unwrap().points()[0].clone();
        native(&["hold", "sdk-proof:deferred", &deferred.name]);
        native(&["destroy", "-d", &deferred.name]);
        let refusal = scope
            .review_delete(std::slice::from_ref(&deferred))
            .err()
            .expect("deferred refused");
        assert!(present(&deferred.name));
        assert_eq!(
            native(&["get", "-H", "-o", "value", "defer_destroy", &deferred.name]),
            "on"
        );
        event(
            "native_deferred_refusal",
            serde_json::json!(refusal.to_string()),
        );
        // Deliberately leave the foreign hold for final raw inventory evidence.
    }

    // A late management change by this same writer must invalidate admission.
    {
        let mut scope = session.admit(std::slice::from_ref(&expected)).unwrap();
        native(&["set", "zboot:pending=sdk-proof-foreign", VOLUME]);
        let refusal = scope
            .capture("pending-must-not-exist")
            .expect_err("pending drift refused");
        assert!(!present(&format!("{VOLUME}@pending-must-not-exist")));
        event(
            "same_holder_management_drift_refusal",
            serde_json::json!(refusal.to_string()),
        );
        native(&["inherit", "zboot:pending", VOLUME]);
    }

    // Guard refusal immediately before an effect preserves a known partial
    // outcome with no snapshot. A refusal during readback preserves uncertain
    // evidence; the independent raw inventory can still show the native effect.
    for (deny_at, suffix, expected_status, should_exist) in [
        (3, "guard-before-effect", CaptureStatus::Partial, false),
        (4, "guard-readback", CaptureStatus::Uncertain, true),
    ] {
        let count = Rc::new(Cell::new(0));
        let guard_count = count.clone();
        let mut scope = session
            .admit_guarded(std::slice::from_ref(&expected), move || {
                let next = guard_count.get() + 1;
                guard_count.set(next);
                if next == deny_at {
                    Err(Error::new("test resource owner withdrew authority"))
                } else {
                    Ok(())
                }
            })
            .unwrap();
        let outcome = scope.capture(suffix).unwrap();
        assert_eq!(outcome.status(), expected_status);
        assert_eq!(present(&format!("{VOLUME}@{suffix}")), should_exist);
        assert!(
            outcome
                .detail()
                .unwrap()
                .contains("resource owner withdrew authority")
        );
        event(
            suffix,
            serde_json::json!({
                "status": format!("{:?}", outcome.status()), "guard_calls": count.get(),
                "detail": outcome.detail(), "native_present": should_exist,
                "operation_id": outcome.operation_id(), "missing": outcome.missing()
            }),
        );
    }

    // An obsolete exact dataset identity may not bind a new object at its name.
    native(&["rename", VOLUME, "sdkproof/tree/volume-original"]);
    native(&["create", "-s", "-V", "16M", VOLUME]);
    let replacement = target(VOLUME);
    assert_ne!(replacement.identity(), expected.identity());
    let refusal = session
        .admit(std::slice::from_ref(&expected))
        .err()
        .expect("stale dataset refused");
    assert!(!present(&format!("{VOLUME}@stale-must-not-exist")));
    event(
        "stale_dataset_name_reuse_refusal",
        serde_json::json!({
            "refusal": refusal.to_string(), "old": expected.identity(), "new": replacement.identity()
        }),
    );
    {
        let mut scope = session.admit(&[replacement]).unwrap();
        let capture = scope.capture("replacement-valid").unwrap();
        assert_eq!(capture.status(), CaptureStatus::Complete);
        event(
            "session_reuse_no_nested_lock",
            serde_json::json!({"final_inventory": names()}),
        );
    }
    drop(session);
    effects();
    event(
        "native_sdk_proof_complete",
        serde_json::json!({"public_api_only": true}),
    );
}

const FX: &str = "sdkproof/fx";
const DEADLINE: Duration = Duration::from_secs(120);

fn assign(key: &str, value: &str) -> PropertyAssignment {
    PropertyAssignment::new(key, value).unwrap()
}

fn exists(name: &str) -> bool {
    Command::new("zfs")
        .args(["list", "-H", "-o", "name", name])
        .output()
        .unwrap()
        .status
        .success()
}

fn dispatched(
    session: &mut WriterSession,
    targets: &[EffectTarget],
    effect: &Effect<'_>,
) -> EffectReply {
    let mut scope = session.admit_effects(targets, |_| Ok(())).unwrap();
    scope.dispatch(effect, DEADLINE).unwrap()
}

/// Whether another holder has the host writer lock, without waiting.
fn lock_busy() -> bool {
    let file = std::fs::File::open("/run/zfs-tools/writer.lock").unwrap();
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockShared) {
        Ok(()) => false,
        Err(rustix::io::Errno::WOULDBLOCK) => true,
        Err(error) => panic!("probe writer lock: {error}"),
    }
}

fn wait_for(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < limit, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The child half of the custody case: dispatch one property set whose zfs
/// blocks (the fixture wrapper waits for a release file) and wait for it.
fn effect_child() {
    let fx = target(FX);
    let mut session = WriterSession::acquire("native SDK effect child").unwrap();
    let reply = dispatched(
        &mut session,
        &[EffectTarget::subtree(fx.clone())],
        &Effect::set_properties(&fx, &[assign("org.fleet:held", "1")]).unwrap(),
    );
    // The parent kills this process before the reply arrives.
    panic!("effect child was not killed: {reply:?}");
}

/// Guarded effects through the supported API on the private disk.
fn effects() {
    let mut session = WriterSession::acquire("isolated native SDK effect proof").unwrap();

    // Create, clone, roll back and destroy through the pinned shapes.
    let root = target("sdkproof");
    let reply = dispatched(
        &mut session,
        &[EffectTarget::dataset(root.clone())],
        &Effect::create_filesystem(&root, FX, &[assign("org.fleet:role", "proof")]).unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    let fx = target(FX);
    let volume = format!("{FX}/vol");
    let reply = dispatched(
        &mut session,
        &[EffectTarget::dataset(fx.clone())],
        &Effect::create_volume(
            &fx,
            &volume,
            16 << 20,
            16384,
            &[assign("compression", "lz4")],
        )
        .unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    assert_eq!(
        native(&["get", "-H", "-p", "-o", "value", "volblocksize", &volume]),
        "16384"
    );
    assert_eq!(
        native(&["get", "-H", "-o", "value", "refreservation", &volume]),
        "none"
    );
    let vol = target(&volume).requiring_kind(DatasetKind::Volume);
    let base = {
        let mut scope = session.admit(std::slice::from_ref(&vol)).unwrap();
        scope.capture("base").unwrap().points()[0].clone()
    };
    let copy = format!("{FX}/copy");
    let reply = dispatched(
        &mut session,
        &[
            EffectTarget::dataset(vol.clone()),
            EffectTarget::dataset(fx.clone()),
        ],
        &Effect::clone_snapshot(&base, &fx, &copy).unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    assert_eq!(
        native(&["get", "-H", "-o", "value", "origin", &copy]),
        base.name
    );
    let before = vol.identity().clone();
    let reply = dispatched(
        &mut session,
        &[EffectTarget::dataset(vol.clone())],
        &Effect::rollback(&vol, &base).unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    let after = target(&volume);
    let reply = dispatched(
        &mut session,
        &[EffectTarget::dataset(target(&copy))],
        &Effect::destroy(&target(&copy)).unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    assert!(!exists(&copy));
    event(
        "effects_volume_lifecycle",
        serde_json::json!({
            "volume": volume, "snapshot": base, "rollback_identity_kept": &before == after.identity(),
            "after_rollback": after.identity(),
        }),
    );

    // A target replaced at its name between admission and spawn.
    let swap = format!("{FX}/swap");
    native(&["create", "-s", "-V", "16M", &swap]);
    let admitted = target(&swap);
    {
        let mut scope = session
            .admit_effects(&[EffectTarget::dataset(admitted.clone())], |_| Ok(()))
            .unwrap();
        native(&["rename", &swap, &format!("{swap}-old")]);
        native(&["create", "-s", "-V", "16M", &swap]);
        let refusal = scope
            .dispatch(&Effect::destroy(&admitted).unwrap(), DEADLINE)
            .expect_err("replaced target refused");
        assert!(exists(&swap) && exists(&format!("{swap}-old")));
        event(
            "effects_target_changed_refusal",
            serde_json::json!({"refusal": refusal.to_string(), "admitted": admitted.identity()}),
        );
    }

    // Management keys are refused before any native effect; a Fleet key is
    // set through a subtree admission.
    let refusals = [
        PropertyAssignment::new("zboot:pending", uuid())
            .unwrap_err()
            .to_string(),
        Effect::inherit_property(&fx, "zboot:pending")
            .unwrap_err()
            .to_string(),
        PropertyAssignment::new("org.zfs-tools:x", "1")
            .unwrap_err()
            .to_string(),
    ];
    assert_eq!(
        native(&["get", "-H", "-o", "value", "zboot:pending", FX]),
        "-"
    );
    let narrow = dispatched_err(
        &mut session,
        &[EffectTarget::dataset(fx.clone())],
        &Effect::set_properties(&fx, &[assign("org.fleet:mark", "1")]).unwrap(),
    );
    let reply = dispatched(
        &mut session,
        &[EffectTarget::subtree(fx.clone())],
        &Effect::set_properties(&fx, &[assign("org.fleet:mark", "1")]).unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    assert_eq!(
        native(&["get", "-H", "-o", "value,source", "org.fleet:mark", FX]),
        "1\tlocal"
    );
    event(
        "effects_management_key_refusal",
        serde_json::json!({"refusals": refusals, "exact_admission_refusal": narrow}),
    );

    // Unfinished zboot work refuses: an operation record on the pool, and a
    // pair record elsewhere that still names the target as its peer.
    let mark = Effect::set_properties(&fx, &[assign("org.fleet:mark", "2")]).unwrap();
    native(&["set", "zboot:operation={}", "sdkproof"]);
    let recorded = dispatched_err(&mut session, &[EffectTarget::subtree(fx.clone())], &mark);
    native(&["inherit", "zboot:operation", "sdkproof"]);
    assert!(recorded.contains("operation record"), "{recorded}");
    let holder = format!("{swap}-old");
    let record = serde_json::json!({
        "schema_version": 1, "pair_id": uuid(),
        "endpoint": {"name": holder, "identity": target(&holder).identity()},
        "peer": {"name": swap, "identity": target(&swap).identity()},
        "role": "primary",
    });
    native(&["set", &format!("zboot:pair={record}"), &holder]);
    let swapped = target(&swap);
    let peer = dispatched_err(
        &mut session,
        &[EffectTarget::subtree(swapped.clone())],
        &Effect::set_properties(&swapped, &[assign("org.fleet:mark", "1")]).unwrap(),
    );
    let query = observe_management(&swap).unwrap_err().to_string();
    native(&["inherit", "zboot:pair", &holder]);
    assert!(
        peer.contains("as its peer") && query.contains("role is not known"),
        "{peer} {query}"
    );
    assert_eq!(
        native(&["get", "-H", "-o", "value", "org.fleet:mark", FX]),
        "1"
    );
    event(
        "effects_unfinished_zboot_work_refusal",
        serde_json::json!({"operation_record": recorded, "peer_reference": peer, "query": query}),
    );

    // Destroying the last clone of an origin marked for deferred destruction
    // would destroy that origin: refused, both kept.
    let late = format!("{FX}/late-clone");
    let reply = dispatched(
        &mut session,
        &[
            EffectTarget::dataset(target(&volume)),
            EffectTarget::dataset(fx.clone()),
        ],
        &Effect::clone_snapshot(&observe_snapshot(&base.name).unwrap(), &fx, &late).unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    native(&["destroy", "-d", &base.name]);
    assert_eq!(
        native(&["get", "-H", "-o", "value", "defer_destroy", &base.name]),
        "on"
    );
    let refusal = dispatched_err(
        &mut session,
        &[EffectTarget::dataset(target(&late))],
        &Effect::destroy(&target(&late)).unwrap(),
    );
    assert!(refusal.contains("deferred origin"), "{refusal}");
    assert!(exists(&late) && present(&base.name));
    event(
        "effects_deferred_origin_refusal",
        serde_json::json!({"refusal": refusal, "clone": late, "origin": base.name}),
    );

    // The read-only management query.
    let id = uuid();
    let quiet = observe_management(FX).unwrap();
    native(&["set", &format!("zboot:pending={id}"), FX]);
    let marked = observe_management(&volume).unwrap();
    native(&["inherit", "zboot:pending", FX]);
    assert_eq!(quiet.role(), &Role::Unpaired);
    assert!(quiet.unfinished().is_empty());
    assert_eq!(
        marked.unfinished(),
        [Unfinished::Pending {
            id: id.clone(),
            holder: FX.into()
        }]
    );
    event(
        "effects_management_query",
        serde_json::json!({"unfinished": format!("{:?}", marked.unfinished())}),
    );

    observation_deadlines(&mut session);
    pool_effects(&mut session);
    drop(session);
    custody_after_parent_death();
}

/// A caller-set observation deadline on real ZFS: a generous one changes
/// nothing, and one that expires kills a query whose descendant keeps its
/// pipe open.
fn observation_deadlines(session: &mut WriterSession) {
    const WITHIN: Duration = Duration::from_secs(60);
    let request = InventoryRequest::new("sdkproof").unwrap().with_properties();
    assert_eq!(
        observe_inventory(&request.clone().within(WITHIN)).unwrap(),
        observe_inventory(&request).unwrap()
    );
    assert_eq!(
        observe_management_within(FX, WITHIN).unwrap(),
        observe_management(FX).unwrap()
    );
    let fx = target(FX);
    let reply = {
        let mut scope = session
            .admit_effects_within(&[EffectTarget::subtree(fx.clone())], |_| Ok(()), WITHIN)
            .unwrap();
        scope
            .dispatch(
                &Effect::set_properties(&fx, &[assign("org.fleet:bounded", "1")]).unwrap(),
                DEADLINE,
            )
            .unwrap()
    };
    assert_eq!(reply, EffectReply::Succeeded);
    assert_eq!(
        native(&["get", "-H", "-o", "value", "org.fleet:bounded", FX]),
        "1"
    );

    // A zpool wrapper whose background sleep keeps the real query's stdout
    // open after it exits; the child process observes with a 2 s deadline.
    let real = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|dir| dir.join("zpool"))
        .find(|path| path.is_file())
        .unwrap();
    let bin = std::path::Path::new("/run/deadline-bin");
    std::fs::create_dir_all(bin).unwrap();
    std::fs::write(
        bin.join("zpool"),
        format!(
            "#!/bin/sh\nsleep 600 &\necho $! > /run/deadline-holder\nexec {} \"$@\"\n",
            real.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("zpool"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(bin.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--deadline-child")
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "deadline child: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let detail: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let holder: i32 = std::fs::read_to_string("/run/deadline-holder")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // PID 1 here is a shell that may reap late: a zombie was killed too.
    wait_for(
        "the pipe holder to be killed",
        Duration::from_secs(10),
        || {
            std::fs::read_to_string(format!("/proc/{holder}/stat")).map_or(true, |stat| {
                stat.rsplit_once(") ")
                    .is_some_and(|(_, s)| s.starts_with('Z'))
            })
        },
    );
    event(
        "observation_deadline_real_zfs_and_pipe_holder",
        serde_json::json!({"expired": detail, "holder": holder}),
    );
}

/// The child half of the deadline case: its zpool's descendant keeps the
/// pipe open, so the bounded inventory must expire, kill and reap.
fn deadline_child() {
    let within = Duration::from_secs(2);
    let started = Instant::now();
    let error =
        observe_inventory(&InventoryRequest::new("sdkproof").unwrap().within(within)).unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(
        error.observation_stop(),
        Some(ObservationStop::Deadline(QueryCleanup::LeaderReaped)),
        "{error}"
    );
    assert_eq!(
        error.to_string(),
        "observation exceeded its 2s deadline: zpool was still running at the \
         observation's 2s deadline; SIGKILL was sent to its process group and its leader reaped"
    );
    assert!(
        elapsed >= within && elapsed < Duration::from_secs(20),
        "{elapsed:?}"
    );
    println!(
        "{}",
        serde_json::json!({"error": error.to_string(), "elapsed_ms": elapsed.as_millis()})
    );
}

fn dispatched_err(
    session: &mut WriterSession,
    targets: &[EffectTarget],
    effect: &Effect<'_>,
) -> String {
    let mut scope = session.admit_effects(targets, |_| Ok(())).unwrap();
    scope
        .dispatch(effect, DEADLINE)
        .expect_err("refused")
        .to_string()
}

fn uuid() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .unwrap()
        .trim()
        .to_owned()
}

/// An encrypted file-backed pool: create with the passphrase on standard
/// input, sync, key handling, export bound to its import instance, import
/// from one leaf, and a refused export after the instance changed.
fn pool_effects(session: &mut WriterSession) {
    const POOL: &str = "fxpool";
    let image = "/run/fxpool.img";
    std::fs::File::create(image)
        .unwrap()
        .set_len(128 << 20)
        .unwrap();
    let leaf = DevicePath::new(image).unwrap();
    let passphrase = b"native-sdk-proof-passphrase\n";
    let reply = dispatched(
        session,
        &[EffectTarget::absent_pool(POOL).unwrap()],
        &Effect::create_pool(
            POOL,
            &leaf,
            &[assign("cachefile", "none"), assign("ashift", "12")],
            &[
                assign("encryption", "aes-256-gcm"),
                assign("keyformat", "passphrase"),
                assign("keylocation", "prompt"),
                assign("mountpoint", "none"),
                assign("canmount", "off"),
                assign("org.fleet:pending", "proof"),
            ],
            Some(passphrase),
        )
        .unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    let observed = |name: &str| {
        let inventory =
            observe_inventory(&InventoryRequest::new(name).unwrap().with_pool_properties())
                .unwrap();
        let property = |key: &str| {
            inventory.pool_properties().unwrap()[key]
                .value()
                .parse::<u64>()
                .unwrap()
        };
        PoolTarget::new(name, Guid::new(property("guid")))
            .unwrap()
            .with_load_guid(Guid::new(property("load_guid")))
            .unwrap()
    };
    let pool = observed(POOL);
    let root = target(POOL);
    assert_eq!(
        dispatched(
            session,
            &[EffectTarget::pool(pool.clone())],
            &Effect::sync_pool(&pool)
        ),
        EffectReply::Succeeded
    );
    let rooted = [EffectTarget::subtree(root.clone())];
    let reply = dispatched(
        session,
        &rooted,
        &Effect::inherit_property(&root, "org.fleet:pending").unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    // Not mounted: the command's own failure is reported, not hidden.
    let unmount = dispatched(session, &rooted, &Effect::unmount(&root));
    assert!(matches!(unmount, EffectReply::Failed { .. }), "{unmount:?}");
    assert_eq!(
        dispatched(session, &rooted, &Effect::unload_key(&root)),
        EffectReply::Succeeded
    );
    assert_eq!(
        native(&["get", "-H", "-o", "value", "keystatus", POOL]),
        "unavailable"
    );
    assert_eq!(
        dispatched(
            session,
            &rooted,
            &Effect::load_key(&root, passphrase).unwrap()
        ),
        EffectReply::Succeeded
    );
    assert_eq!(
        native(&["get", "-H", "-o", "value", "keystatus", POOL]),
        "available"
    );
    assert_eq!(
        dispatched(
            session,
            &[EffectTarget::pool(pool.clone())],
            &Effect::export_pool(&pool)
        ),
        EffectReply::Succeeded
    );
    let reply = dispatched(
        session,
        &[EffectTarget::exported_pool(pool.guid()).unwrap()],
        &Effect::import_pool(pool.guid(), &leaf).unwrap(),
    );
    assert_eq!(reply, EffectReply::Succeeded);
    assert_eq!(native(&["get", "-H", "-o", "value", "mounted", POOL]), "no");
    // The earlier import instance no longer admits an export.
    let stale = session
        .admit_effects(&[EffectTarget::pool(pool.clone())], |_| Ok(()))
        .err()
        .expect("stale import instance refused")
        .to_string();
    let current = observed(POOL);
    assert_ne!(current.load_guid(), pool.load_guid());
    assert_eq!(
        dispatched(
            session,
            &[EffectTarget::pool(current.clone())],
            &Effect::export_pool(&current)
        ),
        EffectReply::Succeeded
    );
    event(
        "effects_pool_lifecycle",
        serde_json::json!({
            "guid": pool.guid(), "load_guids": [pool.load_guid(), current.load_guid()],
            "unmount_reply": format!("{unmount:?}"), "stale_export_refusal": stale,
        }),
    );
}

/// The effect child keeps the writer lock after the process that dispatched
/// it is killed, and its effect completes.
fn custody_after_parent_death() {
    let real = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|dir| dir.join("zfs"))
        .find(|path| path.is_file())
        .unwrap();
    let bin = std::path::Path::new("/run/fx-bin");
    std::fs::create_dir_all(bin).unwrap();
    std::fs::write(
        bin.join("zfs"),
        format!(
            "#!/bin/sh\nif [ \"$1\" = set ]; then : > /run/fx-started; \
             while [ ! -e /run/fx-release ]; do sleep 1; done; fi\nexec {} \"$@\"\n",
            real.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("zfs"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(bin.to_path_buf())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    assert!(!lock_busy());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--effect-child")
        .env("PATH", path)
        .spawn()
        .unwrap();
    wait_for("the effect child's zfs", Duration::from_secs(60), || {
        std::path::Path::new("/run/fx-started").exists()
    });
    child.kill().unwrap();
    let status = child.wait().unwrap();
    let held = lock_busy();
    assert!(held, "the zfs child still holds the writer lock");
    assert_eq!(
        native(&["get", "-H", "-o", "value", "org.fleet:held", FX]),
        "-"
    );
    std::fs::write("/run/fx-release", "").unwrap();
    wait_for(
        "the zfs child to release the lock",
        Duration::from_secs(30),
        || !lock_busy(),
    );
    assert_eq!(
        native(&["get", "-H", "-o", "value", "org.fleet:held", FX]),
        "1"
    );
    event(
        "effects_child_holds_lock_after_parent_killed",
        serde_json::json!({"parent_status": status.to_string(), "held_after_kill": held}),
    );
}
