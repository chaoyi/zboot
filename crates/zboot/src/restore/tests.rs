use super::{
    Phase, Request, Run, abandon, abandon_plan,
    fake::{Cut, Fake, HOSTID, ID},
    list, plan, render, resume_plan,
};
use crate::menu::Result;

const GIB: u64 = 1 << 30;

fn request() -> Request {
    Request {
        source: "bpool/ROOT/debian".into(),
        disk: "/dev/fake-a".into(),
        keep: vec!["rpool/home".into(), "rpool/srv".into()],
        ..Request::default()
    }
}

fn staging() -> String {
    format!("bpool/zboot-restore-{ID}")
}

fn rename_workspace(fake: &mut Fake, from: &str, to: &str) {
    let descendants = format!("{from}/");
    let root_snapshots = format!("{from}@");
    for member in &mut fake.datasets {
        if member.name == from || member.name.starts_with(&descendants) {
            member.name = member.name.replacen(from, to, 1);
        }
    }
    for snapshot in &mut fake.snapshots {
        if snapshot.name.starts_with(&descendants) || snapshot.name.starts_with(&root_snapshots) {
            snapshot.name = snapshot.name.replacen(from, to, 1);
        }
    }
}

fn world() -> Fake {
    let mut fake = Fake::world();
    // A root-level inheritable value the kept root must carry over.
    fake.dataset_mut("rpool")
        .local
        .insert("atime".into(), "off".into());
    fake
}

fn start(fake: &mut Fake) -> Result<super::Completed> {
    let plan = plan(fake, &request(), ID)?;
    let mut out = Vec::new();
    Run::start(fake, &plan, &mut out)
}

/// Continue as an operator would: `resume` with a fresh confirmation of A
/// when one is asked for. `Ok(false)` means no record remains.
fn resume(fake: &mut Fake) -> Result<bool> {
    let listing = list(fake)?;
    if listing.operations.is_empty() {
        return Ok(false);
    }
    let plan = resume_plan(fake, ID)?;
    let mut out = Vec::new();
    Run::resume(fake, ID, plan.erase_layout()?, &mut out)?;
    Ok(true)
}

fn baseline() -> (String, usize) {
    let mut fake = world();
    start(&mut fake).unwrap();
    (fake.normalized(), fake.effects.len())
}

fn guid(fake: &Fake, snapshot: &str) -> u64 {
    fake.snapshot_ref(snapshot)
        .unwrap_or_else(|| panic!("no {snapshot}"))
        .guid
}

fn value(fake: &Fake, dataset: &str, key: &str) -> Option<(String, String)> {
    fake.effective(dataset, key)
}

/// No dataset keeps a receipt attachment or a journal once its operation ended.
fn assert_no_chunked_records(fake: &Fake) {
    for dataset in &fake.datasets {
        assert!(
            !dataset.local.keys().any(|key| {
                key.starts_with("zboot:attachment:") || key.starts_with("zboot:journal:")
            }),
            "{} keeps {:?}",
            dataset.name,
            dataset.local.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn restore_rebuilds_a_with_kept_data_and_original_properties() {
    let mut fake = world();
    let daily = guid(&fake, "rpool/home/alice@daily");
    let hourly = guid(&fake, "rpool/home/alice@hourly");
    let plan = plan(&mut fake, &request(), ID).unwrap();
    assert!(fake.effects.is_empty(), "planning changed something");
    let shown = render(&plan);
    assert!(shown.contains("ERASED: all of pool rpool"), "{shown}");
    assert!(shown.contains("serial SERIAL-A"), "{shown}");
    assert!(shown.contains(&plan.token), "{shown}");
    assert_eq!(plan.typed().text, "SERIAL-A");
    assert!(super::intent::encode(&plan.intent()).unwrap().len() < super::intent::LIMIT);

    let mut out = Vec::new();
    let done = Run::start(&mut fake, &plan, &mut out).unwrap();
    assert_eq!(done.be, "rpool/ROOT/debian");
    let rpool = fake.pools.iter().find(|p| p.name == "rpool").unwrap();
    assert!(!rpool.imported, "A is exported at completion");
    let rpool = rpool.guid;
    for p in &mut fake.pools {
        if p.guid == rpool {
            p.imported = true;
        }
    }

    // The BE, as B has it, is A's one boot default.
    let be = "rpool/ROOT/debian";
    assert_eq!(value(&fake, be, "mountpoint").unwrap().0, "/");
    assert_eq!(value(&fake, be, "canmount").unwrap().0, "noauto");
    assert_eq!(value(&fake, be, "readonly").unwrap().0, "off");
    assert!(fake.find("rpool/ROOT/debian/var").is_some());
    let rpool = fake.pools.iter().find(|p| p.name == "rpool").unwrap();
    assert_eq!(rpool.bootfs.as_deref(), Some(be));

    // Kept trees at their names, with A's values and snapshot GUIDs.
    assert_eq!(
        value(&fake, "rpool/home", "mountpoint"),
        Some(("/home".into(), "local".into()))
    );
    assert_eq!(
        value(&fake, "rpool/home", "atime"),
        Some(("off".into(), "local".into()))
    );
    assert_eq!(value(&fake, "rpool/home", "compression").unwrap().0, "zstd");
    assert_eq!(value(&fake, "rpool/home", "canmount").unwrap().0, "on");
    assert_eq!(
        value(&fake, "rpool/home/alice", "mountpoint").unwrap().0,
        "/home/alice"
    );
    assert_eq!(
        value(&fake, "rpool/home/bob", "canmount"),
        Some(("noauto".into(), "local".into()))
    );
    assert_eq!(value(&fake, "rpool/home/bob", "readonly").unwrap().0, "on");
    assert_eq!(value(&fake, "rpool/srv", "mountpoint").unwrap().0, "legacy");
    assert_eq!(guid(&fake, "rpool/home/alice@daily"), daily);
    assert_eq!(guid(&fake, "rpool/home/alice@hourly"), hourly);
    assert_eq!(
        guid(&fake, &format!("rpool/home@zboot-restore-{ID}")),
        guid(&fake, &format!("{}/home@zboot-restore-{ID}", staging()))
    );

    // Staging stays, inert and unmarked; every hold and the record are gone.
    let staging = staging();
    assert_eq!(value(&fake, &staging, "canmount").unwrap().0, "off");
    assert_eq!(value(&fake, &staging, "mountpoint").unwrap().0, "none");
    assert_eq!(value(&fake, &staging, "zboot:staging"), None);
    assert_eq!(
        value(&fake, &format!("{staging}/home/alice"), "mountpoint")
            .unwrap()
            .0,
        "none",
        "staged children never mount"
    );
    assert_eq!(
        value(&fake, &format!("{staging}/home"), "canmount")
            .unwrap()
            .0,
        "off"
    );
    assert!(fake.snapshots.iter().all(|s| s.holds.is_empty()));
    assert_eq!(value(&fake, "bpool", "zboot:operation"), None);
    assert!(
        fake.snapshot_ref(&format!("bpool/ROOT/debian@zboot-restore-{ID}"))
            .is_some()
    );
    assert!(done.notes.iter().any(|n| n.contains("zboot drop")));
    assert_no_chunked_records(&fake);

    // Nothing outside this operation's copies was destroyed, and no transfer
    // asked for more than a raw unforced receive.
    assert!(!fake.effects.iter().any(|e| e.starts_with("destroy")));
}

#[test]
fn restore_installs_the_loader_its_source_ships() {
    let mut fake = world();
    let shipped = fake.loader.clone().unwrap();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    assert_eq!(plan.state.loader, shipped);
    let shown = render(&plan);
    assert!(
        shown.contains(&format!(
            "Loader: bpool/ROOT/debian@zboot-restore-{ID}:/usr/lib/zboot/zboot.efi sha256 {}",
            shipped.sha256
        )),
        "{shown}"
    );
    // The loader is bound into the token.
    fake.loader.as_mut().unwrap().sha256 = "6b".repeat(32);
    assert_ne!(
        super::plan(&mut fake, &request(), ID).unwrap().token,
        plan.token
    );
    fake.loader = Some(shipped);
    // The deploy step gets exactly the planned loader.
    Run::start(&mut fake, &plan, &mut Vec::new()).unwrap();
    assert!(
        fake.effects
            .iter()
            .any(|e| e == "deploy rpool on /dev/fake-a")
    );
}

#[test]
fn a_source_without_a_zboot_loader_is_refused_before_anything_changes() {
    let mut fake = world();
    fake.loader = None;
    let error = plan(&mut fake, &request(), ID).unwrap_err().to_string();
    assert!(error.contains("ships no zboot loader"), "{error}");
    assert!(fake.effects.is_empty(), "{:?}", fake.effects);
}

#[test]
fn a_loader_that_differs_from_the_plan_stops_the_deploy_step() {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    let deploy = fake_effect_index(&plan, "deploy ");
    fake.cut = Some((deploy, Cut::Before));
    assert!(Run::start(&mut fake, &plan, &mut Vec::new()).is_err());
    fake.restart();
    fake.loader.as_mut().unwrap().sha256 = "6b".repeat(32);
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(
        error.contains("ships another zboot loader than planned"),
        "{error}"
    );
    assert!(
        !fake.pools.iter().any(|p| p.name == "rpool"),
        "no pool was made on A"
    );
}

#[test]
fn restored_deploy_shells_release_only_their_temporary_volume_fences() {
    let mut fake = world();
    start(&mut fake).unwrap();
    for pool in &mut fake.pools {
        pool.imported = true;
    }
    for shell in ["rpool", "rpool/ROOT"] {
        assert_eq!(
            value(&fake, shell, "volmode"),
            Some(("default".into(), "default".into()))
        );
        for (key, expected) in [
            ("readonly", "on"),
            ("canmount", "off"),
            ("mountpoint", "none"),
        ] {
            assert_eq!(
                value(&fake, shell, key),
                Some((expected.into(), "local".into()))
            );
        }
        let future = format!("{shell}/future-volume");
        fake.add(&future, &[]);
        fake.dataset_mut(&future).volume = true;
        assert_eq!(
            value(&fake, &future, "volmode"),
            Some(("default".into(), "default".into())),
            "new volumes must not inherit the retired restore fence"
        );
    }
}

#[test]
fn shell_volume_cleanup_is_authorized_and_does_not_overwrite_changed_policy() {
    let mut reference = world();
    start(&mut reference).unwrap();
    let at = reference
        .effects
        .iter()
        .position(|effect| effect == "inherit volmode rpool")
        .unwrap();
    for changed in ["dev", "full", "received", "mounted", "role", "snapshot"] {
        let mut fake = world();
        fake.cut = Some((at, Cut::Before));
        assert!(start(&mut fake).is_err());
        fake.restart();
        let (_, record) = super::record(&mut fake, ID).unwrap().unwrap();
        let state: super::State = serde_json::from_value(record.state).unwrap();
        assert!(state.receive_targets.is_some());
        assert_eq!(
            value(&fake, "rpool/ROOT/debian", "mountpoint").unwrap().0,
            "/"
        );
        // Validate both shells before the first shell inheritance, including
        // the second shell whose fence must not authorize clearing the first.
        let shell = fake.dataset_mut("rpool/ROOT");
        match changed {
            "received" => {
                shell.local.remove("volmode");
                shell.received.insert("volmode".into(), "none".into());
            }
            "mounted" => shell.mounted = true,
            "role" => {
                shell.local.insert("canmount".into(), "noauto".into());
            }
            "snapshot" => fake.snap("rpool/ROOT@foreign", false),
            mode => {
                shell.local.insert("volmode".into(), mode.into());
            }
        }
        let shell_state = |fake: &Fake, name: &str| {
            let shell = fake.dataset_ref(name);
            (
                shell.guid,
                shell.txg,
                shell.local.clone(),
                shell.received.clone(),
                shell.masked.clone(),
                shell.mounted,
            )
        };
        let original_shells = ["rpool", "rpool/ROOT"].map(|name| (name, shell_state(&fake, name)));
        let before = fake.effects.len();
        let error = resume(&mut fake).unwrap_err().to_string();
        assert!(error.contains("shell"), "{changed}: {error}");
        // Member placement inheritance is already authorized and can replay
        // before the separate shell cleanup checks. Only shell effects would
        // violate this refusal; each shell's actual native state stays exact.
        assert!(
            !fake.effects[before..].iter().any(|effect| {
                matches!(
                    effect.as_str(),
                    "inherit volmode rpool" | "inherit volmode rpool/ROOT"
                )
            }),
            "{changed}: cleanup changed a shell after its bounds changed"
        );
        for (name, original) in original_shells {
            assert_eq!(
                shell_state(&fake, name),
                original,
                "{changed}: {name} changed"
            );
        }
        assert_eq!(value(&fake, "rpool", "volmode").unwrap().0, "none");
    }
}

#[test]
fn shell_volume_cleanup_reconciles_each_lost_native_inheritance_reply() {
    let mut reference = world();
    start(&mut reference).unwrap();
    for name in ["rpool", "rpool/ROOT"] {
        let effect = format!("inherit volmode {name}");
        let at = reference.effects.iter().position(|e| e == &effect).unwrap();
        let mut fake = world();
        fake.cut = Some((at, Cut::Lost));
        start(&mut fake).unwrap();
        assert_eq!(fake.normalized(), reference.normalized());
        assert_eq!(fake.effects.iter().filter(|e| *e == &effect).count(), 1);
    }
}

#[test]
fn restored_descendants_follow_final_internal_parents_and_keep_explicit_values() {
    let mut fake = world();
    fake.dataset_mut("rpool/home/alice")
        .local
        .insert("canmount".into(), "noauto".into());
    fake.add("rpool/home/automatic", &[]);
    fake.dataset_mut("rpool")
        .local
        .insert("volmode".into(), "dev".into());
    fake.add(
        "rpool/home/pinned",
        &[("mountpoint", "/pinned"), ("readonly", "off")],
    );
    fake.add("rpool/home/received", &[]);
    fake.dataset_mut("rpool/home/received").received.extend([
        ("mountpoint".into(), "/received".into()),
        ("volmode".into(), "none".into()),
    ]);
    start(&mut fake).unwrap();
    for pool in &mut fake.pools {
        pool.imported = true;
    }
    for (root, child) in [
        ("rpool/home", "rpool/home/alice"),
        ("rpool/ROOT/debian", "rpool/ROOT/debian/var"),
    ] {
        for key in ["mountpoint", "readonly", "volmode"] {
            assert_eq!(
                value(&fake, child, key).unwrap().1,
                format!("inherited from {root}")
            );
        }
    }
    assert_eq!(
        value(&fake, "rpool/home", "volmode"),
        Some(("dev".into(), "local".into())),
        "the copied root isolates its external original ancestor"
    );
    assert_eq!(
        value(&fake, "rpool/home/received", "mountpoint"),
        Some(("/received".into(), "local".into())),
        "a new copy does not invent a received layer"
    );
    assert_eq!(
        value(&fake, "rpool/home/automatic", "mountpoint"),
        Some(("/home/automatic".into(), "local".into())),
        "ordinary inherit mountpoint would mount canmount=on during restore"
    );
    fake.dataset_mut("rpool/home").local.extend([
        ("mountpoint".into(), "/moved".into()),
        ("readonly".into(), "on".into()),
        ("volmode".into(), "full".into()),
    ]);
    assert_eq!(
        value(&fake, "rpool/home/alice", "mountpoint").unwrap().0,
        "/moved/alice"
    );
    assert_eq!(
        value(&fake, "rpool/home/alice", "readonly").unwrap().0,
        "on"
    );
    assert_eq!(
        value(&fake, "rpool/home/automatic", "mountpoint")
            .unwrap()
            .0,
        "/home/automatic"
    );
    assert_eq!(
        value(&fake, "rpool/home/automatic", "readonly").unwrap().0,
        "on"
    );
    assert_eq!(
        value(&fake, "rpool/home/automatic", "volmode").unwrap().0,
        "full"
    );
    assert_eq!(
        value(&fake, "rpool/home/alice", "volmode").unwrap().0,
        "full"
    );
    assert_eq!(
        value(&fake, "rpool/home/pinned", "mountpoint").unwrap().0,
        "/pinned"
    );
    assert_eq!(
        value(&fake, "rpool/home/pinned", "readonly").unwrap().0,
        "off"
    );
    assert_eq!(
        value(&fake, "rpool/home/received", "mountpoint").unwrap().0,
        "/received"
    );
    assert_eq!(
        value(&fake, "rpool/home/received", "volmode").unwrap().0,
        "none"
    );
}

#[test]
fn record_is_written_before_the_first_effect_and_names_no_members() {
    let mut fake = world();
    start(&mut fake).unwrap();
    assert_eq!(fake.effects[0], "record bpool");
    assert_eq!(fake.effects.last().unwrap(), "clear record bpool");
    assert!(
        fake.effects
            .iter()
            .filter(|e| e.starts_with("record"))
            .count()
            >= 12
    );
}

/// Every effect and every record write, cut before, after, or with its reply
/// lost, then resumed (with fresh confirmations where asked) to completion.
#[test]
fn every_cut_resumes_to_the_same_result() {
    let (expected, count) = baseline();
    let mut reference = world();
    start(&mut reference).unwrap();
    for (index, effect) in reference.effects.iter().enumerate().take(count) {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = world();
            let id_plan = plan(&mut fake, &request(), ID).unwrap();
            fake.cut = Some((index, cut));
            let mut out = Vec::new();
            let mut result = Run::start(&mut fake, &id_plan, &mut out).map(|_| ());
            let mut attempts = 0;
            while let Err(error) = result {
                attempts += 1;
                assert!(
                    attempts < 6,
                    "cut {cut:?} at {index} ({effect}) does not converge: {error}",
                );
                fake.restart();
                result = match resume(&mut fake) {
                    Ok(true) => Ok(()),
                    Ok(false) if fake.effects.len() <= 1 => {
                        // Cut before the record existed: nothing happened.
                        start(&mut fake).map(|_| ())
                    }
                    Ok(false) => Ok(()),
                    Err(error) => Err(error),
                };
            }
            assert_eq!(
                fake.normalized(),
                expected,
                "cut {cut:?} at {index} ({effect})"
            );
            for effect in &fake.effects {
                if let Some(target) = effect.strip_prefix("destroy -r ") {
                    assert!(
                        target.starts_with(&format!("{}/", staging()))
                            || target.starts_with("rpool/"),
                        "cut {cut:?} at {index} destroyed {target}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_later_resume_needs_a_fresh_confirmation_to_erase() {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    let erase = fake_effect_index(&plan, "wipe");
    fake.cut = Some((erase, Cut::Before));
    let mut out = Vec::new();
    assert!(Run::start(&mut fake, &plan, &mut out).is_err());
    fake.restart();
    let resumed = resume_plan(&mut fake, ID).unwrap();
    assert_eq!(resumed.step, Phase::Erasing.name());
    assert_eq!(resumed.typed().unwrap().text, "SERIAL-A");
    assert!(resumed.token.is_some());
    let wipes = |fake: &Fake| {
        fake.effects
            .iter()
            .filter(|e| e.starts_with("wipe"))
            .count()
    };
    let attempted = wipes(&fake);
    let error = Run::resume(&mut fake, ID, None, &mut out).unwrap_err();
    assert!(error.to_string().contains("fresh confirmation"), "{error}");
    assert_eq!(
        wipes(&fake),
        attempted,
        "no further erase without confirmation"
    );
    Run::resume(&mut fake, ID, resumed.erase_layout().unwrap(), &mut out).unwrap();
}

fn fake_effect_index(_plan: &super::Plan, prefix: &str) -> usize {
    let mut fake = world();
    start(&mut fake).unwrap();
    fake.effects
        .iter()
        .position(|e| e.starts_with(prefix))
        .unwrap()
}

#[test]
fn enospc_while_staging_leaves_a_unchanged_and_resumes() {
    let (expected, _) = baseline();
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    // Another writer fills B after the plan.
    fake.space_limit = Some(("bpool".into(), 2 * GIB));
    let mut out = Vec::new();
    let error = Run::start(&mut fake, &plan, &mut out)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("out of space") && error.contains("A is unchanged"),
        "{error}"
    );
    assert!(
        !fake
            .effects
            .iter()
            .any(|e| e.starts_with("wipe") || e.starts_with("export"))
    );
    assert!(fake.find("rpool/home/alice").is_some());
    assert_eq!(
        resume_plan(&mut fake, ID).unwrap().step,
        Phase::Quiesced.name()
    );
    fake.space_limit = None;
    assert!(resume(&mut fake).unwrap());
    assert_eq!(fake.normalized(), expected);
}

/// The index of the first stream into exactly `destination`, in a clean run.
fn first_stream_into(destination: &str) -> usize {
    let mut reference = world();
    start(&mut reference).unwrap();
    reference
        .effects
        .iter()
        .position(|effect| {
            effect.starts_with("send ") && effect.ends_with(&format!(" | receive {destination}"))
        })
        .unwrap_or_else(|| panic!("no stream into {destination}"))
}

/// The index of the record write that moves the operation to `phase`, in a
/// clean run.
fn record_reaching(phase: Phase) -> usize {
    let mut reference = world();
    start(&mut reference).unwrap();
    for (index, effect) in reference.effects.iter().enumerate() {
        if effect != "record bpool" {
            continue;
        }
        let mut fake = cut_at(index, Cut::After);
        if super::record(&mut fake, ID)
            .unwrap()
            .is_some_and(|(_, record)| record.step == phase as u32)
        {
            return index;
        }
    }
    panic!("no record reaches {phase:?}")
}

/// A stream whose receiver committed but whose sender failed, or whose reply
/// was lost, leaves a dataset this restore continues from its native
/// snapshots: committed snapshots are never sent again, and an unencrypted
/// copy is never destroyed for it.
#[test]
fn a_committed_stream_whose_outcome_was_lost_is_continued_not_resent() {
    let (expected, _) = baseline();
    for target in [
        format!("{}/home", staging()),
        "rpool/ROOT/debian".into(),
        "rpool/home".into(),
    ] {
        let mut fake = world();
        fake.sender_failure = Some(target.clone());
        let error = start(&mut fake).unwrap_err().to_string();
        assert!(error.contains("sender failed"), "{error}");
        fake.sender_failure = None;
        let old = fake.find(&target).unwrap().guid;
        assert!(resume(&mut fake).unwrap());
        assert_eq!(fake.normalized(), expected, "{target}");
        for pool in &mut fake.pools {
            pool.imported = true;
        }
        assert!(!destroyed(&fake, &target));
        assert_eq!(fake.find(&target).unwrap().guid, old);

        let at = first_stream_into(&target);
        for cut in [Cut::After, Cut::Lost] {
            let mut fake = world();
            fake.cut = Some((at, cut));
            let _ = start(&mut fake);
            fake.restart();
            if super::record(&mut fake, ID).unwrap().is_some() {
                assert!(resume(&mut fake).unwrap());
            }
            assert_eq!(fake.normalized(), expected, "{target} {cut:?}");
            assert!(!fake.effects.iter().any(|e| e.starts_with("destroy")));
            let streams = fake
                .effects
                .iter()
                .filter(|e| *e == &fake.effects[at])
                .count();
            assert_eq!(
                streams, 1,
                "{target} {cut:?}: a committed stream was sent again"
            );
        }
    }
}

/// Rewrite the stored record as an earlier zboot left it: `key` of the state
/// object at `at` taken away, or set to `value`.
fn as_earlier_record(fake: &mut Fake, at: &str, key: &str, value: Option<bool>) {
    let (pool, mut raw) = super::record(fake, ID).unwrap().unwrap();
    let object = raw.state.pointer_mut(at).unwrap().as_object_mut().unwrap();
    match value {
        Some(value) => {
            object.insert(key.into(), value.into());
        }
        None => {
            object.remove(key).unwrap();
        }
    }
    fake.dataset_mut(&pool).local.insert(
        super::intent::PROPERTY.into(),
        super::intent::encode(&raw).unwrap(),
    );
}

#[test]
fn restore_records_from_an_earlier_zboot_are_neither_resumed_nor_abandoned() {
    let (wipe, _, _, _) = paired_erase_effects();
    // Fields this build always writes absent, or fields it never writes.
    let earlier = [
        // Before the receipt became an attachment, records named its
        // journal and carried a per-dataset marker.
        ("", "receive_receipt_id", Some(true)),
        ("", "per_dataset_v1", Some(true)),
        // An earlier receiver's restore marked its records this way.
        ("", "receive_completion_v1", Some(true)),
        ("", "source_identities", None),
        ("", "staged", None),
        ("", "returned", None),
        ("/ended_pairs/0", "role", None),
        ("/ended_pairs/0", "label_extents", Some(true)),
    ];
    let expected = format!(
        "{ID} is a restore record from an earlier zboot; finish or abandon it with the build that started it"
    );
    for (at, key, value) in earlier {
        let old = format!("{at}/{key} {value:?}");
        let mut fake = cut_paired_restore(wipe, Cut::Before);
        as_earlier_record(&mut fake, at, key, value);
        let before = fake.normalized();
        let effects = fake.effects.len();
        for result in [
            resume_plan(&mut fake, ID).map(drop),
            Run::resume(&mut fake, ID, None, &mut Vec::new()).map(drop),
            abandon_plan(&mut fake, ID).map(drop),
            abandon(&mut fake, ID).map(drop),
        ] {
            let error = result.unwrap_err().to_string();
            assert!(error.contains(&expected), "{old}: {error}");
        }
        assert_eq!(fake.effects.len(), effects, "{old}");
        assert_eq!(fake.normalized(), before, "{old}");
        // Status still lists it.
        assert_eq!(list(&mut fake).unwrap().operations.len(), 1, "{old}");
    }
}

#[test]
fn a_failed_staged_receive_is_replaced_never_trusted() {
    let (expected, _) = baseline();
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.corrupt = Some(staging());
    let mut out = Vec::new();
    let error = Run::start(&mut fake, &plan, &mut out)
        .unwrap_err()
        .to_string();
    assert!(error.contains("checksum mismatch"), "{error}");
    assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));
    // Resuming with the fault still present fails the same way.
    assert!(resume(&mut fake).is_err());
    fake.corrupt = None;
    assert!(resume(&mut fake).unwrap());
    assert_eq!(fake.normalized(), expected);
}

#[test]
fn staged_copies_that_differ_from_a_are_refused_before_erasure() {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    // Stop once staging is recorded, then lose one staged snapshot.
    fake.cut = Some((record_reaching(Phase::Staged), Cut::After));
    let mut out = Vec::new();
    assert!(Run::start(&mut fake, &plan, &mut out).is_err());
    fake.restart();
    assert_eq!(
        resume_plan(&mut fake, ID).unwrap().step,
        Phase::Staged.name()
    );
    let name = format!("{}/home/alice@hourly", staging());
    fake.snapshots.retain(|s| s.name != name);
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains("does not match"), "{error}");
    assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));
    assert!(fake.find("rpool/home/alice").is_some());
}

#[test]
fn a_disk_replaced_between_plan_and_erase_is_refused() {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.disks[0].identity.serial = Some("OTHER".into());
    let mut out = Vec::new();
    let error = Run::start(&mut fake, &plan, &mut out)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not the one confirmed"), "{error}");
    assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));
    assert!(
        fake.find("rpool/home/alice").is_some(),
        "A's pool is untouched"
    );
    assert!(resume_plan(&mut fake, ID).is_err());
}

#[test]
fn a_layout_changed_between_plan_and_erase_is_refused() {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    let mut extra = fake.disks[0].partitions[0].clone();
    extra.path = "/dev/fake-ap9".into();
    fake.disks[0].partitions.push(extra);
    let mut out = Vec::new();
    let error = Run::start(&mut fake, &plan, &mut out)
        .unwrap_err()
        .to_string();
    assert!(error.contains("layout changed"), "{error}");
    assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));
}

fn secret_world(format: &str, location: &str) -> (Fake, Request) {
    let mut fake = world();
    fake.add("rpool/secret", &[("mountpoint", "/secret")]);
    fake.encrypt("rpool/secret", format, location);
    fake.add("rpool/secret/inner", &[]);
    fake.inherit_key("rpool/secret/inner");
    fake.add("rpool/secret/inner/deep", &[]);
    fake.inherit_key("rpool/secret/inner/deep");
    fake.snap("rpool/secret@before", true);
    if let Some(path) = location.strip_prefix("file://") {
        fake.keys.insert(path.into(), "key-rpool/secret".into());
    }
    let mut request = request();
    request.keep.push("rpool/secret".into());
    (fake, request)
}

fn assert_secret_restored(fake: &Fake, location: &str) {
    let mut fake = fake.clone();
    for pool in &mut fake.pools {
        pool.imported = true;
    }
    for name in [
        "rpool/secret",
        "rpool/secret/inner",
        "rpool/secret/inner/deep",
    ] {
        let dataset = fake.dataset_ref(name);
        assert_eq!(
            dataset.encryption_root.as_deref(),
            Some("rpool/secret"),
            "{name}"
        );
        assert!(!dataset.unopenable, "{name} opens with no key");
        assert_eq!(
            fake.key_of(name).map(|k| k.material.as_str()),
            Some("key-rpool/secret")
        );
    }
    assert_eq!(
        value(&fake, "rpool/secret", "keylocation"),
        Some((location.into(), "local".into()))
    );
    assert_eq!(
        value(&fake, "rpool/secret", "mountpoint").unwrap().0,
        "/secret"
    );
    // Staging keeps each staged dataset its own root, every one proved.
    let staged = format!("{}/secret/inner", staging());
    assert_eq!(
        fake.dataset_ref(&staged).encryption_root.as_deref(),
        Some(staged.as_str())
    );
}

#[test]
fn encrypted_kept_trees_move_raw_without_keys_and_are_relinked_after_a_proof() {
    for (format, location) in [
        ("passphrase", "prompt"),
        ("raw", "file:///etc/zfs/keys/secret.key"),
    ] {
        let (mut fake, request) = secret_world(format, location);
        let before = guid(&fake, "rpool/secret/inner@before");
        let plan = plan(&mut fake, &request, ID).unwrap();
        let shown = render(&plan);
        assert!(
            shown.contains(&format!(
                "encryption root rpool/secret: keyformat {format}, keylocation {location}"
            )),
            "{shown}"
        );
        let mut out = Vec::new();
        Run::start(&mut fake, &plan, &mut out).unwrap();
        assert_secret_restored(&fake, location);
        // Each relink came after its proof, parents first, on A only.
        let relinks: Vec<_> = fake
            .effects
            .iter()
            .filter(|e| e.starts_with("change-key"))
            .cloned()
            .collect();
        assert_eq!(
            relinks,
            [
                "change-key inherit rpool/secret/inner",
                "change-key inherit rpool/secret/inner/deep",
            ],
            "{format}"
        );
        let mut imported = fake.clone();
        for pool in &mut imported.pools {
            pool.imported = true;
        }
        assert_eq!(guid(&imported, "rpool/secret/inner@before"), before);

        // Every cut converges to the same restore, its relinks included.
        let expected = fake.normalized();
        for (index, effect) in fake.effects.iter().enumerate() {
            for cut in [Cut::Before, Cut::After, Cut::Lost] {
                let (mut cut_fake, request) = secret_world(format, location);
                let plan = super::plan(&mut cut_fake, &request, ID).unwrap();
                cut_fake.cut = Some((index, cut));
                let mut result = Run::start(&mut cut_fake, &plan, &mut Vec::new()).map(drop);
                let mut attempts = 0;
                while result.is_err() {
                    attempts += 1;
                    assert!(attempts < 6, "{format} {cut:?} at {index}: {result:?}");
                    cut_fake.restart();
                    result = match resume(&mut cut_fake) {
                        Ok(false) if cut_fake.effects.len() <= 1 => {
                            Run::start(&mut cut_fake, &plan, &mut Vec::new()).map(drop)
                        }
                        other => other.map(drop),
                    };
                }
                assert_eq!(
                    cut_fake.normalized(),
                    expected,
                    "{format} {cut:?} at {index} ({effect})"
                );
            }
        }
    }
}

/// The index of the first effect starting with `prefix` when `plan` runs
/// on `fake`.
fn effect_in(fake: &Fake, plan: &super::Plan, prefix: &str) -> usize {
    let mut reference = fake.clone();
    Run::start(&mut reference, plan, &mut Vec::new()).unwrap();
    reference
        .effects
        .iter()
        .position(|e| e.starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix}"))
}

/// `plan` run on a copy of `fake` until a cut at `index`, then restarted.
fn stopped_at(fake: &Fake, plan: &super::Plan, index: usize, cut: Cut) -> Fake {
    let mut stopped = fake.clone();
    stopped.cut = Some((index, cut));
    assert!(Run::start(&mut stopped, plan, &mut Vec::new()).is_err());
    stopped.restart();
    stopped
}

/// Nothing after effect `from` destroyed, erased or exported anything.
fn nothing_lost_since(fake: &Fake, from: usize) {
    let lossy = fake.effects[from..]
        .iter()
        .filter(|e| e.starts_with("destroy") || e.starts_with("wipe") || e.starts_with("export"))
        .collect::<Vec<_>>();
    assert!(lossy.is_empty(), "{lossy:?}");
}

/// A key changed on A after its tree was staged completely: the staged copy
/// no longer proves wrapped like A, and restore stops for the operator
/// before anything is erased or discarded. It never stages the tree again,
/// because the new key may live only on A, which the erase destroys. A raw
/// or hex key in a file can be changed back; a passphrase cannot.
#[test]
fn a_key_changed_after_complete_staging_refuses_without_discarding() {
    for at in [Phase::Staged, Phase::Scrubbed] {
        let (fake, request) = secret_world("passphrase", "prompt");
        let plan = plan(&mut fake.clone(), &request, ID).unwrap();
        let mut stopped = stopped_at(
            &fake,
            &plan,
            record_reaching_in(&fake, &plan, at),
            Cut::After,
        );
        // `zfs change-key` with the same passphrase: a new salt.
        stopped
            .dataset_mut("rpool/secret")
            .key
            .as_mut()
            .unwrap()
            .salt = "salt-new".into();
        let before = stopped.effects.len();
        let error = resume(&mut stopped).unwrap_err().to_string();
        assert!(
            error.contains("the key of rpool/secret changed since it was staged")
                && error.contains("wrapped otherwise than rpool/secret")
                && error.contains("cannot be changed back"),
            "{at:?}: {error}"
        );
        nothing_lost_since(&stopped, before);
        assert!(
            stopped
                .find(&format!("{}/secret/inner", staging()))
                .is_some()
        );
        // A is whole: abandoning releases everything and destroys nothing.
        assert!(abandon(&mut stopped, ID).unwrap().released, "{at:?}");
        nothing_lost_since(&stopped, before);
    }

    // A raw key file rotated after staging: refused alike, without any
    // prompt; rotated back, the same staging is erased for and returned.
    let location = "file:///etc/zfs/keys/secret.key";
    let (fake, request) = secret_world("raw", location);
    let plan = plan(&mut fake.clone(), &request, ID).unwrap();
    let scrubbed = record_reaching_in(&fake, &plan, Phase::Scrubbed);
    let mut stopped = stopped_at(&fake, &plan, scrubbed, Cut::After);
    let rotate = |fake: &mut Fake, material: &str| {
        fake.dataset_mut("rpool/secret")
            .key
            .as_mut()
            .unwrap()
            .material = material.into();
        fake.keys
            .insert("/etc/zfs/keys/secret.key".into(), material.into());
    };
    rotate(&mut stopped, "rotated");
    let before = stopped.effects.len();
    let error = resume(&mut stopped).unwrap_err().to_string();
    assert!(
        error.contains("the key of rpool/secret changed since it was staged")
            && !error.contains("cannot be changed back"),
        "{error}"
    );
    nothing_lost_since(&stopped, before);
    rotate(&mut stopped, "key-rpool/secret");
    assert!(resume(&mut stopped).unwrap());
    assert_secret_restored(&stopped, location);
    assert!(
        !stopped.effects[before..]
            .iter()
            .any(|e| e.starts_with(&format!("destroy -r {}", staging()))),
        "staging was discarded"
    );

    // A key file that no longer opens A's own root proves nothing: refused,
    // nothing erased, never prompted.
    let mut stopped = stopped_at(&fake, &plan, scrubbed, Cut::After);
    stopped.keys.remove("/etc/zfs/keys/secret.key");
    let before = stopped.effects.len();
    let error = resume(&mut stopped).unwrap_err().to_string();
    assert!(error.contains("does not open rpool/secret"), "{error}");
    nothing_lost_since(&stopped, before);
}

/// The worst case of a key changed after staging: its new file lives only
/// on A. Before the erase, and before any staging is discarded, every key
/// file the manifest names (a passphrase file too) must still be A's key
/// location and open A's root and its staged copy from here, with nothing
/// of A mounted; otherwise restore stops with A whole.
#[test]
fn a_key_file_moved_onto_a_is_refused_before_the_erase() {
    let location = "file:///etc/zfs/keys/k1";
    let (fake, request) = secret_world("passphrase", location);
    let plan = plan(&mut fake.clone(), &request, ID).unwrap();
    let scrubbed = record_reaching_in(&fake, &plan, Phase::Scrubbed);
    type Change<'a> = (&'a str, &'a dyn Fn(&mut Fake));
    let changes: [Change; 4] = [
        // `zfs change-key -o keylocation=file:///mnt/a-keys/k2` to a file on
        // an unkept dataset of A, unmounted since.
        (
            "the key of rpool/secret changed since it was staged",
            &|f| {
                let root = f.dataset_mut("rpool/secret");
                root.key.as_mut().unwrap().salt = "salt-k2".into();
                root.key.as_mut().unwrap().material = "k2".into();
                root.local
                    .insert("keylocation".into(), "file:///mnt/a-keys/k2".into());
            },
        ),
        // The same key, its location now a file on A.
        (
            "keylocation file:///mnt/a-keys/k1; staged as passphrase, file:///etc/zfs/keys/k1",
            &|f| {
                f.dataset_mut("rpool/secret")
                    .local
                    .insert("keylocation".into(), "file:///mnt/a-keys/k1".into());
            },
        ),
        // The file itself moved onto A.
        (
            "the key file file:///etc/zfs/keys/k1 does not open rpool/secret from here",
            &|f| {
                f.keys.remove("/etc/zfs/keys/k1");
            },
        ),
        // A dataset of A mounted: a file found now may be on it.
        ("rpool/ROOT/debian on the target disk is mounted", &|f| {
            f.dataset_mut("rpool/ROOT/debian").mounted = true;
        }),
    ];
    for (expect, change) in &changes {
        let mut stopped = stopped_at(&fake, &plan, scrubbed, Cut::After);
        change(&mut stopped);
        let before = stopped.effects.len();
        let error = resume(&mut stopped).unwrap_err().to_string();
        assert!(error.contains(expect), "{expect}: {error}");
        nothing_lost_since(&stopped, before);
        assert_eq!(
            resume_plan(&mut stopped, ID).unwrap().step,
            Phase::Scrubbed.name()
        );
    }

    // A resumed erase after A's pool was exported checks the staged copy.
    let export = effect_in(&fake, &plan, "export rpool");
    let mut stopped = stopped_at(&fake, &plan, export, Cut::After);
    stopped.keys.remove("/etc/zfs/keys/k1");
    let before = stopped.effects.len();
    let error = resume(&mut stopped).unwrap_err().to_string();
    assert!(
        error.contains(&format!("does not open {}/secret from here", staging())),
        "{error}"
    );
    nothing_lost_since(&stopped, before);
    stopped
        .keys
        .insert("/etc/zfs/keys/k1".into(), "key-rpool/secret".into());
    assert!(resume(&mut stopped).unwrap());
    assert_secret_restored(&stopped, location);
}

/// Restore relinks returned keys with its helper, a dynamically linked
/// program. A helper that does not work here refuses the plan, and the erase
/// of a recorded restore, before anything is lost; a restore with nothing to
/// relink does not need it.
#[test]
fn an_erase_is_refused_while_the_key_relink_helper_does_not_work() {
    let (fake, request) = secret_world("passphrase", "prompt");
    let mut broken = fake.clone();
    broken.change_key_broken = true;
    let error = plan_error(&mut broken, &request);
    assert!(
        error.contains("zboot-change-key does not work here"),
        "{error}"
    );
    assert!(broken.effects.is_empty());
    let mut plain = world();
    plain.change_key_broken = true;
    start(&mut plain).unwrap();

    let plan = plan(&mut fake.clone(), &request, ID).unwrap();
    for (index, cut, phase) in [
        (
            record_reaching_in(&fake, &plan, Phase::Scrubbed),
            Cut::After,
            Phase::Scrubbed,
        ),
        (effect_in(&fake, &plan, "wipe"), Cut::Before, Phase::Erasing),
    ] {
        let mut stopped = stopped_at(&fake, &plan, index, cut);
        stopped.change_key_broken = true;
        let before = stopped.effects.len();
        let error = resume(&mut stopped).unwrap_err().to_string();
        assert!(
            error.contains("zboot-change-key does not work here")
                && error.contains("nothing was erased"),
            "{phase:?}: {error}"
        );
        assert!(
            !stopped.effects[before..]
                .iter()
                .any(|e| e.starts_with("wipe"))
        );
        assert_eq!(resume_plan(&mut stopped, ID).unwrap().step, phase.name());
        stopped.change_key_broken = false;
        assert!(resume(&mut stopped).unwrap());
        assert_secret_restored(&stopped, "prompt");
    }
}

/// A resume after A's pool was exported, with only the wipe ahead, still
/// verifies staging against the manifest first: it needs no A.
#[test]
fn staging_is_verified_before_the_wipe_after_a_was_exported() {
    let export = first("export rpool");
    let mut fake = cut_at(export, Cut::After);
    assert!(fake.pools.iter().any(|p| p.name == "rpool" && !p.imported));
    fake.dataset_mut(&format!("{}/home/alice", staging()))
        .local
        .insert("compression".into(), "lz4".into());
    let before = fake.effects.len();
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(
        error.contains("home/alice's compression is not its source's zstd"),
        "{error}"
    );
    assert!(!fake.effects[before..].iter().any(|e| e.starts_with("wipe")));
}

/// The index of the record write reaching `phase` when `plan` runs on `fake`.
fn record_reaching_in(fake: &Fake, plan: &super::Plan, phase: Phase) -> usize {
    let mut reference = fake.clone();
    Run::start(&mut reference, plan, &mut Vec::new()).unwrap();
    (0..reference.effects.len())
        .filter(|i| reference.effects[*i] == "record bpool")
        .find(|i| {
            let mut stopped = fake.clone();
            stopped.cut = Some((*i, Cut::After));
            let _ = Run::start(&mut stopped, plan, &mut Vec::new());
            stopped.restart();
            super::record(&mut stopped, ID)
                .unwrap()
                .is_some_and(|(_, r)| r.step == phase as u32)
        })
        .unwrap()
}

/// An encrypted tree is staged in one attempt: a cut in the middle of it
/// leaves part of it in staging, which the next attempt discards under the
/// destruction rule and stages again, so a key changed in between cannot mix
/// wrappings. A part written since is never destroyed, and nothing is
/// discarded while a key file restore needs is not found off A.
#[test]
fn a_partly_staged_encrypted_tree_is_discarded_and_staged_again_in_one_attempt() {
    let (mut fake, request) = secret_world("passphrase", "prompt");
    let plan = plan(&mut fake, &request, ID).unwrap();
    let staged = format!("{}/secret", staging());
    let mut reference = fake.clone();
    Run::start(&mut reference, &plan, &mut Vec::new()).unwrap();
    let inner = reference
        .effects
        .iter()
        .position(|e| e.ends_with(&format!(" | receive {staged}/inner")))
        .unwrap();
    let mut stopped = fake.clone();
    stopped.cut = Some((inner, Cut::Before));
    assert!(Run::start(&mut stopped, &plan, &mut Vec::new()).is_err());
    stopped.restart();
    assert!(stopped.find(&staged).is_some());
    // Between attempts: a new passphrase on A.
    stopped
        .dataset_mut("rpool/secret")
        .key
        .as_mut()
        .unwrap()
        .salt = "salt-new".into();
    let mut fresh = stopped.clone();
    assert!(resume(&mut fresh).unwrap());
    let effects = &fresh.effects[stopped.effects.len()..];
    let discard = effects
        .iter()
        .position(|e| e == &format!("destroy -r {staged}"))
        .expect("the partial encrypted tree is discarded");
    let restaged = effects
        .iter()
        .position(|e| e.ends_with(&format!(" | receive {staged}")))
        .unwrap();
    assert!(discard < restaged);
    let mut imported = fresh.clone();
    for pool in &mut imported.pools {
        pool.imported = true;
    }
    for name in ["rpool/secret", "rpool/secret/inner"] {
        assert_eq!(imported.key_of(name).unwrap().salt, "salt-new", "{name}");
        assert!(!imported.dataset_ref(name).unopenable, "{name}");
    }

    // Written since the cut: the destruction rule refuses, restore stops.
    let mut written = stopped.clone();
    written.dataset_mut(&staged).written = 4096;
    let error = resume(&mut written).unwrap_err().to_string();
    assert!(
        error.contains(&format!("{staged} exists and is not a partial copy")),
        "{error}"
    );
    assert!(!written.effects.iter().any(|e| e.starts_with("destroy")));
    assert!(written.find(&staged).is_some());
    assert!(!written.effects.iter().any(|e| e.starts_with("wipe")));

    // A key in a file: discarded only after the off-A key check passes.
    let location = "file:///etc/zfs/keys/k1";
    let (fake, request) = secret_world("passphrase", location);
    let plan = super::plan(&mut fake.clone(), &request, ID).unwrap();
    let mut reference = fake.clone();
    Run::start(&mut reference, &plan, &mut Vec::new()).unwrap();
    let inner = reference
        .effects
        .iter()
        .position(|e| e.ends_with(&format!(" | receive {staged}/inner")))
        .unwrap();
    let mut stopped = stopped_at(&fake, &plan, inner, Cut::Before);
    stopped.keys.remove("/etc/zfs/keys/k1");
    let before = stopped.effects.len();
    let error = resume(&mut stopped).unwrap_err().to_string();
    assert!(
        error.contains("the key file file:///etc/zfs/keys/k1 does not open rpool/secret from here"),
        "{error}"
    );
    nothing_lost_since(&stopped, before);
    assert!(stopped.find(&staged).is_some());
    stopped
        .keys
        .insert("/etc/zfs/keys/k1".into(), "key-rpool/secret".into());
    assert!(resume(&mut stopped).unwrap());
    assert!(
        stopped.effects[before..]
            .iter()
            .any(|e| e == &format!("destroy -r {staged}"))
    );
    assert_secret_restored(&stopped, location);
}

/// Within one attempt the BE's key changes between two of its streams: the
/// proof before its relink refuses, nothing is relinked, and the next attempt
/// sends the whole encrypted tree again, so A never holds mixed wrappings.
#[test]
fn a_key_changed_between_streams_is_never_relinked() {
    let mut fake = world();
    fake.encrypt("bpool/ROOT/debian", "passphrase", "prompt");
    fake.inherit_key("bpool/ROOT/debian/var");
    fake.before_stream = Some(("rpool/ROOT/debian/var".into(), |f: &mut Fake| {
        f.dataset_mut("bpool/ROOT/debian")
            .key
            .as_mut()
            .unwrap()
            .salt = "salt-new".into();
    }));
    let error = start(&mut fake).unwrap_err().to_string();
    assert!(
        error.contains("wrapped otherwise than rpool/ROOT/debian")
            && error.contains("is not relinked"),
        "{error}"
    );
    assert!(!fake.effects.iter().any(|e| e.starts_with("change-key")));
    assert!(resume(&mut fake).unwrap());
    let discard = fake
        .effects
        .iter()
        .position(|e| e == "destroy -r rpool/ROOT/debian")
        .expect("the mixed tree on A is discarded");
    let relink = fake
        .effects
        .iter()
        .position(|e| e == "change-key inherit rpool/ROOT/debian/var")
        .unwrap();
    assert!(discard < relink);
    for pool in &mut fake.pools {
        pool.imported = true;
    }
    for name in ["rpool/ROOT/debian", "rpool/ROOT/debian/var"] {
        assert_eq!(fake.key_of(name).unwrap().salt, "salt-new", "{name}");
        assert!(!fake.dataset_ref(name).unopenable, "{name}");
    }
}

#[test]
fn a_key_file_must_unlock_from_off_a() {
    let mut fake = world();
    fake.add("rpool/secret", &[]);
    fake.encrypt("rpool/secret", "raw", "file:///etc/zfs/keys/secret.key");
    let mut request = request();
    request.keep.push("rpool/secret".into());
    // Absent here: it may live only on A (an unmounted BE, A's home), which
    // the erase destroys. Refused, not merely noted.
    let error = plan_error(&mut fake, &request);
    assert!(error.contains("does not unlock it"), "{error}");
    // A file at that path that is another root's key is no evidence either.
    fake.keys
        .insert("/etc/zfs/keys/secret.key".into(), "key-rpool/other".into());
    let error = plan_error(&mut fake, &request);
    assert!(error.contains("Incorrect key"), "{error}");
    // The right key, here and off A, is enough.
    fake.keys
        .insert("/etc/zfs/keys/secret.key".into(), "key-rpool/secret".into());
    let planned = plan(&mut fake, &request, ID).unwrap();
    assert!(render(&planned).contains("keylocation file:///etc/zfs/keys/secret.key"));
    // A key file under A's would-be /home, such as on a block-device mount
    // there, is proved the same way.
    fake.dataset_mut("rpool/secret")
        .local
        .insert("keylocation".into(), "file:///home/keys/secret.key".into());
    fake.keys
        .insert("/home/keys/secret.key".into(), "key-rpool/secret".into());
    plan(&mut fake, &request, ID).unwrap();
    // A raw key at a prompt cannot be proved without asking for it.
    fake.dataset_mut("rpool/secret")
        .local
        .insert("keylocation".into(), "prompt".into());
    let error = plan_error(&mut fake, &request);
    assert!(error.contains("entered at a prompt"), "{error}");
    assert!(fake.effects.is_empty());
}

/// The effect index of the first effect starting with `prefix` in a clean run.
fn first(prefix: &str) -> usize {
    fake_effect_index_nth(prefix, 0)
}
fn fake_effect_index_nth(prefix: &str, nth: usize) -> usize {
    let mut fake = world();
    start(&mut fake).unwrap();
    fake.effects
        .iter()
        .enumerate()
        .filter(|(_, e)| e.starts_with(prefix))
        .nth(nth)
        .unwrap_or_else(|| panic!("no {prefix} #{nth}"))
        .0
}
/// Run to the cut, then restart: the process died there.
fn cut_at(index: usize, cut: Cut) -> Fake {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.cut = Some((index, cut));
    let mut out = Vec::new();
    assert!(Run::start(&mut fake, &plan, &mut out).is_err());
    fake.restart();
    fake
}
fn destroyed(fake: &Fake, name: &str) -> bool {
    fake.effects
        .iter()
        .any(|e| e == &format!("destroy -r {name}"))
}

#[test]
fn a_dataset_made_at_a_destination_after_a_cut_is_never_destroyed() {
    // An operator makes a fresh rpool/home with new data on the new pool.
    let mut fake = cut_at(first_stream_into("rpool/home"), Cut::Before);
    fake.add("rpool/home", &[]);
    fake.dataset_mut("rpool/home").written = 1 << 20;
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains("not a partial copy"), "{error}");
    assert!(!destroyed(&fake, "rpool/home"));
    assert!(fake.find("rpool/home").is_some());
    assert_eq!(
        resume_plan(&mut fake, ID).unwrap().step,
        Phase::Erased.name()
    );

    // The same inside staging, before anything on A is erased.
    let staged = format!("{}/srv", staging());
    let mut fake = cut_at(first_stream_into(&staged), Cut::Before);
    fake.add(&staged, &[]);
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains("not a partial copy"), "{error}");
    assert!(!destroyed(&fake, &staged));
    assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));

    // A partial copy of ours written after the cut is no longer ours.
    let (expected, _) = baseline();
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.corrupt = Some("rpool/home/bob".into());
    let mut out = Vec::new();
    assert!(Run::start(&mut fake, &plan, &mut out).is_err());
    fake.corrupt = None;
    assert!(fake.find("rpool/home/alice").is_some(), "a partial copy");
    fake.dataset_mut("rpool/home/alice").written = 4096;
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains("rpool/home/alice exists"), "{error}");
    assert!(!fake.effects.iter().any(|e| e.starts_with("destroy")));
    // Unwritten, the partial copy is ours, continued, and the run converges.
    fake.dataset_mut("rpool/home/alice").written = 0;
    assert!(resume(&mut fake).unwrap());
    assert_eq!(fake.normalized(), expected);
    assert!(!fake.effects.iter().any(|e| e.starts_with("destroy")));
}

#[test]
fn kept_data_changed_after_staging_is_never_erased() {
    let erasing = record_reaching(Phase::Erasing);
    let export = first("export rpool");
    type Change<'a> = (&'a str, &'a dyn Fn(&mut Fake));
    let changes: [Change; 3] = [
        ("gained a snapshot", &|f| {
            f.snap("rpool/home/alice@later", false)
        }),
        ("was written", &|f| {
            f.dataset_mut("rpool/home/bob").written = 512
        }),
        // Natively, creating a child also makes its parent `written`; the
        // new member is still the reason named.
        ("rpool/home/carol gained a snapshot or was created", &|f| {
            f.add("rpool/home/carol", &[]);
            f.dataset_mut("rpool/home").written = 512;
        }),
    ];
    for at in [erasing, export] {
        for (expect, change) in &changes {
            let mut fake = cut_at(at, Cut::Before);
            change(&mut fake);
            let error = resume(&mut fake).unwrap_err().to_string();
            assert!(
                error.contains(expect) && error.contains("nothing was erased"),
                "{expect}: {error}"
            );
            assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));
            assert!(fake.find("rpool/home/alice").is_some());
            // Abandoning destroys nothing; before erasure begins it releases.
            assert_eq!(abandon(&mut fake, ID).unwrap().released, at == erasing);
        }
    }
}

#[test]
fn a_kept_inactive_be_is_configured_without_mounting() {
    let mut fake = world();
    fake.add(
        "rpool/ROOT/old",
        &[("canmount", "noauto"), ("mountpoint", "/")],
    );
    // A kept inactive BE retains its original per-member roles. Give its
    // child the same explicitly safe role expected by this bootable fixture.
    fake.add("rpool/ROOT/old/var", &[("canmount", "noauto")]);
    let mut request = request();
    request.keep.push("rpool/ROOT/old".into());
    let initial = fake.clone();
    let approved = plan(&mut fake, &request, ID).unwrap();
    let mut out = Vec::new();
    Run::start(&mut fake, &approved, &mut out).unwrap();
    let rpool = fake.pools.iter().position(|p| p.name == "rpool").unwrap();
    fake.pools[rpool].imported = true;
    assert_eq!(
        value(&fake, "rpool/ROOT/old", "canmount"),
        Some(("noauto".into(), "local".into()))
    );
    assert_eq!(value(&fake, "rpool/ROOT/old", "mountpoint").unwrap().0, "/");
    let publication = fake
        .effects
        .iter()
        .position(|effect| effect == "set mountpoint=/ rpool/ROOT/old")
        .unwrap();
    let mut stopped = initial;
    let approved = plan(&mut stopped, &request, ID).unwrap();
    stopped.cut = Some((publication, Cut::Before));
    assert!(Run::start(&mut stopped, &approved, &mut Vec::new()).is_err());
    stopped.restart();
    // Native receive already establishes noauto. The proof is the bound
    // all-member role checkpoint before placement, not a redundant setter.
    assert!(active_restore_state(&mut stopped).receive_targets.is_some());
    for name in ["rpool/ROOT/old", "rpool/ROOT/old/var"] {
        assert_eq!(
            value(&stopped, name, "canmount"),
            Some(("noauto".into(), "local".into()))
        );
        assert_eq!(
            value(&stopped, name, "mountpoint"),
            Some(("none".into(), "local".into()))
        );
        assert!(!stopped.dataset_ref(name).mounted);
    }
    assert!(
        fake.datasets
            .iter()
            .all(|d| d.pool != fake.pools[rpool].guid || !d.mounted)
    );
}

/// `endpoint` as a secondary paired with `peer`; with `peer_pool` the peer's
/// pool GUID is replaced (a peer on another pool than the fake's own).
fn pair_record(
    fake: &mut Fake,
    endpoint: &str,
    peer: &str,
    peer_pool: Option<u64>,
) -> zfs_tools::engine::management::PairRecord {
    use zfs_tools::engine::management::{Endpoint, PairRecord, Role};
    let view = super::Backend::view(fake).unwrap();
    let at = |name: &str| Endpoint {
        name: name.into(),
        identity: view.dataset(name).unwrap().identity.clone(),
    };
    let mut peer = at(peer);
    if let Some(guid) = peer_pool {
        peer.identity.pool_guid = zfs_tools::engine::Guid::new(guid);
    }
    PairRecord {
        schema_version: 1,
        pair_id: "0b8f2c1e-3d4a-4b5c-9d6e-7f8091a2b3c4".into(),
        endpoint: at(endpoint),
        peer,
        role: Role::Secondary,
    }
}

/// B's BE is the fenced secondary of A's BE, with an anchor hold on @old.
fn paired_with_a() -> (Fake, Request) {
    use zfs_tools::engine::management::{MountMode, Placement};
    let mut fake = world();
    let b = "bpool/ROOT/debian";
    let record = pair_record(&mut fake, b, "rpool/ROOT/debian", None);
    let identity = super::Backend::view(&mut fake)
        .unwrap()
        .dataset(b)
        .unwrap()
        .identity
        .clone();
    let placement = Placement {
        schema_version: 1,
        identity,
        readonly: false,
        canmount: Some(MountMode::NoAuto),
        volmode: None,
    };
    let d = fake.dataset_mut(b);
    d.local.insert("readonly".into(), "on".into());
    d.local
        .insert("zboot:placement".into(), placement.encode().unwrap());
    d.local
        .insert("zboot:pair".into(), record.encode().unwrap());
    d.mounted = false;
    fake.dataset_mut("rpool/ROOT/debian")
        .local
        .insert("zboot:pair".into(), record.counterpart().encode().unwrap());
    fake.secondaries.insert(b.into());
    let anchor = format!("zboot:anchor:{}", record.pair_id);
    for s in fake
        .snapshots
        .iter_mut()
        .filter(|s| s.name.starts_with("bpool/ROOT/debian") && s.name.ends_with("@old"))
    {
        s.holds.push(anchor.clone());
    }
    fake.running_root = None;
    let mut request = request();
    request.source = format!("{b}@old");
    (fake, request)
}

#[test]
fn after_a_restore_the_source_be_is_unpaired_and_bootable() {
    let b = "bpool/ROOT/debian";
    let (mut fake, request) = paired_with_a();
    let anchor = "zboot:anchor:0b8f2c1e-3d4a-4b5c-9d6e-7f8091a2b3c4";
    let plan = plan(&mut fake, &request, ID).unwrap();
    // The plan states it, and the token binds it.
    let ended = plan
        .state
        .ended_pairs
        .first()
        .cloned()
        .expect("the plan ends B's pair");
    assert_eq!(
        (ended.owner.name.as_str(), ended.peer.name.as_str()),
        (b, "rpool/ROOT/debian")
    );
    let shown = render(&plan);
    assert!(
        shown.contains(&format!("{b}'s pair record is removed")),
        "{shown}"
    );
    assert!(super::intent::encode(&plan.intent()).unwrap().len() < super::intent::LIMIT);

    // The record goes only after A is erased: a run cut before the erase
    // leaves B paired, and abandoning it there ends nothing.
    let mut early = paired_with_a().0;
    let early_plan = super::plan(&mut early, &request, ID).unwrap();
    let mut out = Vec::new();
    let mut reference = paired_with_a().0;
    let reference_plan = super::plan(&mut reference, &request, ID).unwrap();
    let done = Run::start(&mut reference, &reference_plan, &mut out).unwrap();
    let erase = reference
        .effects
        .iter()
        .position(|e| e.contains("wipe") || e.contains("erase"))
        .expect("the run erases A");
    let unpair = reference
        .effects
        .iter()
        .position(|e| e == &format!("inherit zboot:pair {b}"))
        .expect("the run removes B's pair record");
    assert!(
        unpair > erase,
        "the record went before the erase: {:?}",
        reference.effects
    );
    early.cut = Some((erase, Cut::Before));
    assert!(Run::start(&mut early, &early_plan, &mut out).is_err());
    early.restart();
    abandon(&mut early, ID).unwrap();
    assert!(
        value(&early, b, "zboot:pair").is_some(),
        "abandon before the erase ended the pair"
    );

    // After the run: B is unpaired, still fenced, and keeps its anchor holds;
    // with no record left, the Menu's ownership check no longer names a peer.
    for name in [b.to_string(), format!("{b}/var")] {
        assert_eq!(value(&reference, &name, "zboot:pair"), None, "{name}");
    }
    assert_eq!(value(&reference, b, "readonly").unwrap().0, "on");
    assert!(value(&reference, b, "zboot:placement").is_some());
    let old = reference.snapshot_ref(&format!("{b}@old")).unwrap();
    assert!(old.holds.iter().any(|h| h == anchor), "{:?}", old.holds);
    let restored = "rpool/ROOT/debian";
    assert_eq!(value(&reference, restored, "zboot:pair"), None);
    assert!(
        done.notes
            .iter()
            .any(|n| n.contains(&format!("{b} is no longer paired"))),
        "{:?}",
        done.notes
    );
    let listed = super::Backend::view(&mut reference).unwrap();
    let candidate = listed
        .candidates
        .iter()
        .find(|c| c.dataset == b)
        .expect("B's BE is listed");
    assert_eq!(candidate.refusal, None);

    // Every cut converges to the same result, the record removal included.
    let expected = reference.normalized();
    for (index, effect) in reference.effects.iter().enumerate() {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let (mut fake, request) = paired_with_a();
            let plan = super::plan(&mut fake, &request, ID).unwrap();
            fake.cut = Some((index, cut));
            let mut result = Run::start(&mut fake, &plan, &mut out).map(|_| ());
            let mut attempts = 0;
            while let Err(error) = result {
                attempts += 1;
                assert!(
                    attempts < 6,
                    "cut {cut:?} at {index} ({effect}) does not converge: {error}",
                );
                fake.restart();
                result = match resume(&mut fake) {
                    Ok(true) => Ok(()),
                    // Cut before the record existed: nothing happened.
                    Ok(false) if fake.effects.len() <= 1 => {
                        Run::start(&mut fake, &plan, &mut out).map(|_| ())
                    }
                    Ok(false) => Ok(()),
                    Err(error) => Err(error),
                };
            }
            assert_eq!(
                fake.normalized(),
                expected,
                "cut {cut:?} at {index} ({effect})"
            );
        }
    }
}

/// All effects spanning the uncertain erase, including the checkpoint whose
/// lost reply used to leave a dead pair after abandon.
fn paired_erase_effects() -> (usize, usize, usize, usize) {
    let (mut fake, request) = paired_with_a();
    let plan = plan(&mut fake, &request, ID).unwrap();
    Run::start(&mut fake, &plan, &mut Vec::new()).unwrap();
    let wipe = fake
        .effects
        .iter()
        .position(|effect| effect.starts_with("wipe "))
        .unwrap();
    let end = fake
        .effects
        .iter()
        .position(|effect| effect == "inherit zboot:pair bpool/ROOT/debian")
        .unwrap();
    let deploy = fake
        .effects
        .iter()
        .position(|effect| effect.starts_with("deploy "))
        .unwrap();
    let checkpoint = fake
        .effects
        .iter()
        .enumerate()
        .skip(deploy + 1)
        .find(|(_, effect)| effect.starts_with("record "))
        .unwrap()
        .0;
    assert!(wipe < end && end < deploy && deploy < checkpoint);
    (wipe, end, deploy, checkpoint)
}

fn cut_paired_restore(index: usize, cut: Cut) -> Fake {
    let (mut fake, request) = paired_with_a();
    let plan = plan(&mut fake, &request, ID).unwrap();
    fake.cut = Some((index, cut));
    assert!(Run::start(&mut fake, &plan, &mut Vec::new()).is_err());
    fake.restart();
    fake
}

fn assert_pair_anchors_and_placement_stay(fake: &Fake) {
    let b = "bpool/ROOT/debian";
    assert_eq!(value(fake, b, "readonly").unwrap().0, "on");
    assert!(value(fake, b, "zboot:placement").is_some());
    assert!(
        fake.snapshot_ref(&format!("{b}@old"))
            .unwrap()
            .holds
            .iter()
            .any(|hold| hold == "zboot:anchor:0b8f2c1e-3d4a-4b5c-9d6e-7f8091a2b3c4")
    );
}

#[test]
fn abandoning_at_each_erase_effect_ends_only_a_pair_whose_peer_was_erased() {
    let (wipe, _, _, checkpoint) = paired_erase_effects();
    let original_guid = paired_with_a().0.pool_named("rpool").guid;
    for index in wipe..=checkpoint {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let (mut fake, request) = paired_with_a();
            let plan = plan(&mut fake, &request, ID).unwrap();
            fake.cut = Some((index, cut));
            let outcome = Run::start(&mut fake, &plan, &mut Vec::new());
            fake.restart();
            let intact = fake.pools.iter().any(|pool| pool.guid == original_guid);
            // A lost reply may be reconciled in the same run. That is a
            // completed restore, not an interrupted operation to abandon.
            let notes = if outcome.is_err() {
                abandon(&mut fake, ID).unwrap().left
            } else {
                assert!(
                    !intact,
                    "completed despite an intact peer: {cut:?} at {index}"
                );
                Vec::new()
            };
            assert_eq!(
                value(&fake, "bpool/ROOT/debian", "zboot:pair").is_some(),
                intact,
                "cut {cut:?} at effect {index}"
            );
            if intact {
                assert!(
                    !notes
                        .iter()
                        .any(|note| note.contains("is no longer paired"))
                );
            }
            assert_pair_anchors_and_placement_stay(&fake);
            assert!(list(&mut fake).unwrap().operations.is_empty());
        }
    }
}

#[test]
fn abandoning_before_wipe_preserves_the_intact_exported_peers_pair() {
    let (wipe, _, _, _) = paired_erase_effects();
    let mut fake = cut_paired_restore(wipe, Cut::Before);
    assert!(
        fake.pools
            .iter()
            .any(|pool| pool.name == "rpool" && !pool.imported)
    );
    assert!(
        super::Backend::view(&mut fake)
            .unwrap()
            .pool("rpool")
            .is_none()
    );
    abandon(&mut fake, ID).unwrap();
    assert!(value(&fake, "bpool/ROOT/debian", "zboot:pair").is_some());
    assert_pair_anchors_and_placement_stay(&fake);
}

/// Abandoning after the wipe began: an erase whose outcome is unknown keeps
/// the operation and the pair; a pair record that changed since the plan is
/// reported and left as it is, never a reason to keep the operation.
#[test]
fn an_unknown_erase_outcome_keeps_the_operation_and_a_changed_pair_record_is_reported() {
    let (wipe, _, _, _) = paired_erase_effects();
    for changed in ["probe", "disk", "owner", "pair", "endpoint", "role"] {
        let mut fake = cut_paired_restore(wipe, Cut::After);
        match changed {
            "probe" => fake.label_probe_error = true,
            "disk" => fake.disks[0].identity.serial = Some("REPLACED".into()),
            "owner" => fake.dataset_mut("bpool/ROOT/debian").guid += 1,
            "pair" | "endpoint" | "role" => {
                let dataset = fake.dataset_mut("bpool/ROOT/debian");
                let mut record =
                    zfs_tools::engine::management::PairRecord::parse(&dataset.local["zboot:pair"])
                        .unwrap();
                match changed {
                    "pair" => record.pair_id = "9b8f2c1e-3d4a-4b5c-9d6e-7f8091a2b3c4".into(),
                    "endpoint" => {
                        record.endpoint.identity.guid = zfs_tools::engine::Guid::new(99999)
                    }
                    "role" => record.role = zfs_tools::engine::management::Role::Primary,
                    _ => unreachable!(),
                }
                dataset
                    .local
                    .insert("zboot:pair".into(), record.encode().unwrap());
            }
            _ => unreachable!(),
        }
        let before = fake.normalized();
        let pair = value(&fake, "bpool/ROOT/debian", "zboot:pair");
        assert!(pair.is_some(), "{changed}");
        if matches!(changed, "probe" | "disk") {
            // Whether the peer was erased is unknown: everything stays.
            assert!(abandon(&mut fake, ID).is_err(), "{changed}");
            assert_eq!(fake.normalized(), before, "{changed}");
        } else {
            // A record restore may no longer end is reported and left as it
            // is; it never keeps the operation from ending.
            let left = abandon(&mut fake, ID).unwrap().left;
            assert!(
                left.iter().any(|note| note.contains("was left as it is")),
                "{changed}: {left:?}"
            );
            assert!(list(&mut fake).unwrap().operations.is_empty());
        }
        assert_eq!(
            value(&fake, "bpool/ROOT/debian", "zboot:pair"),
            pair,
            "{changed}"
        );
        assert_pair_anchors_and_placement_stay(&fake);
    }
}

#[test]
fn abandoning_an_already_unpaired_source_does_not_claim_the_peer_was_erased() {
    let (wipe, _, _, _) = paired_erase_effects();
    let mut fake = cut_paired_restore(wipe, Cut::Before);
    fake.dataset_mut("bpool/ROOT/debian")
        .local
        .remove("zboot:pair");
    let result = abandon(&mut fake, ID).unwrap();
    assert!(!result.left.iter().any(|note| note.contains("was erased")));
    assert_pair_anchors_and_placement_stay(&fake);
}

#[test]
fn abandoning_after_the_wipe_ends_an_ancestor_owned_pair() {
    let (mut fake, mut request) = paired_with_a();
    let owner = "bpool/ROOT";
    let record = pair_record(&mut fake, owner, "rpool/ROOT", None);
    fake.dataset_mut("bpool/ROOT/debian")
        .local
        .remove("zboot:pair");
    fake.dataset_mut(owner)
        .local
        .insert("zboot:pair".into(), record.encode().unwrap());
    request.source = "bpool/ROOT/debian@old".into();
    let plan = plan(&mut fake, &request, ID).unwrap();
    assert_eq!(plan.state.ended_pairs[0].owner.name, owner);
    // Use the same effect sequence through wipe; changing the owning root
    // does not add an effect before it.
    let (wipe, _, _, _) = paired_erase_effects();
    fake.cut = Some((wipe, Cut::After));
    assert!(Run::start(&mut fake, &plan, &mut Vec::new()).is_err());
    fake.restart();
    abandon(&mut fake, ID).unwrap();
    assert_eq!(value(&fake, owner, "zboot:pair"), None);
    assert_eq!(value(&fake, "bpool/ROOT/debian", "zboot:pair"), None);
    assert_pair_anchors_and_placement_stay(&fake);
}

#[test]
fn a_paired_source_restores_unfenced_and_unpaired() {
    use zfs_tools::engine::management::{MountMode, Placement};
    let mut fake = world();
    // B's BE is a fenced secondary: read-only, `noauto`, values saved.
    for (name, canmount) in [
        ("bpool/ROOT/debian", MountMode::NoAuto),
        ("bpool/ROOT/debian/var", MountMode::On),
    ] {
        let identity = super::Backend::view(&mut fake)
            .unwrap()
            .dataset(name)
            .unwrap()
            .identity
            .clone();
        let placement = Placement {
            schema_version: 1,
            identity,
            readonly: false,
            canmount: Some(canmount),
            volmode: None,
        };
        let d = fake.dataset_mut(name);
        d.local.insert("readonly".into(), "on".into());
        d.local.insert("canmount".into(), "noauto".into());
        d.local
            .insert("zboot:placement".into(), placement.encode().unwrap());
        d.mounted = false;
    }
    fake.secondaries.insert("bpool/ROOT/debian".into());
    // Its peer is on a third pool, not on A: the pair is not ended.
    let record = pair_record(
        &mut fake,
        "bpool/ROOT/debian",
        "rpool/ROOT/debian",
        Some(4242),
    );
    fake.dataset_mut("bpool/ROOT/debian")
        .local
        .insert("zboot:pair".into(), record.encode().unwrap());
    fake.running_root = None;
    let mut request = request();
    request.source = "bpool/ROOT/debian@old".into();
    let plan = plan(&mut fake, &request, ID).unwrap();
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("is paired; the restored BE is unpaired")
                // The peer's pool is not imported: the record stays, and the
                // plan says how to end it.
                && w.contains(
                    "`zboot unpair bpool/ROOT/debian` afterwards removes the record that still names it"
                )),
        "{:?}",
        plan.warnings
    );
    assert!(plan.state.ended_pairs.is_empty());
    let mut out = Vec::new();
    Run::start(&mut fake, &plan, &mut out).unwrap();
    let rpool = fake.pools.iter().position(|p| p.name == "rpool").unwrap();
    fake.pools[rpool].imported = true;
    let be = "rpool/ROOT/debian";
    assert_eq!(value(&fake, be, "readonly").unwrap().0, "off");
    assert_eq!(value(&fake, be, "canmount").unwrap().0, "noauto");
    assert_eq!(
        value(&fake, &format!("{be}/var"), "readonly").unwrap().0,
        "off"
    );
    assert_eq!(
        value(&fake, &format!("{be}/var"), "canmount").unwrap().0,
        "noauto"
    );
    for name in [be.to_string(), format!("{be}/var")] {
        assert_eq!(value(&fake, &name, "zboot:placement"), None, "{name}");
        assert_eq!(value(&fake, &name, "zboot:pair"), None, "{name}");
    }
    assert_eq!(fake.pools[rpool].bootfs.as_deref(), Some(be));

    // A placement record of another incarnation is refused at plan time.
    let mut fake = world();
    let mut placement = Placement {
        schema_version: 1,
        identity: super::Backend::view(&mut fake)
            .unwrap()
            .dataset("bpool/ROOT/debian")
            .unwrap()
            .identity
            .clone(),
        readonly: false,
        canmount: Some(MountMode::NoAuto),
        volmode: None,
    };
    placement.identity.guid = zfs_tools::engine::Guid::new(9999);
    fake.dataset_mut("bpool/ROOT/debian/var")
        .local
        .insert("zboot:placement".into(), placement.encode().unwrap());
    let error = plan_error(
        &mut fake,
        &super::Request {
            source: "bpool/ROOT/debian@old".into(),
            ..request
        },
    );
    assert!(error.contains("another incarnation"), "{error}");
}

#[test]
fn a_default_that_cannot_be_cleared_is_not_reported_as_restored() {
    let (expected, _) = baseline();
    let mut fake = world();
    // A third pool, imported read-only by the Menu, names its own default.
    fake.add_pool("cpool", "259:16", 90 * GIB);
    fake.add("cpool/ROOT", &[]);
    fake.add("cpool/ROOT/x", &[("mountpoint", "/")]);
    let c = fake.pools.iter().position(|p| p.name == "cpool").unwrap();
    fake.pools[c].bootfs = Some("cpool/ROOT/x".into());
    fake.pools[c].readonly = true;
    let error = start(&mut fake).unwrap_err().to_string();
    assert!(error.contains("cpool still names"), "{error}");
    assert_eq!(
        resume_plan(&mut fake, ID).unwrap().step,
        Phase::Configured.name(),
        "the record stays until the default is verified"
    );
    // Erasure rebuilt rpool, so find cpool again.
    let c = fake.pools.iter().position(|p| p.name == "cpool").unwrap();
    fake.pools[c].readonly = false;
    assert!(resume(&mut fake).unwrap());
    assert_eq!(fake.pools[c].bootfs, None);
    fake.pools.remove(c);
    fake.datasets.retain(|d| !d.name.starts_with("cpool"));
    assert_eq!(fake.normalized(), expected);
}

#[test]
fn the_token_binds_every_snapshot_erased_and_the_source_members() {
    let mut fake = world();
    let token = plan(&mut fake, &request(), ID).unwrap().token;
    // A snapshot on an unkept dataset of A widens the loss.
    fake.snap("rpool/ROOT/debian@new", false);
    let wider = plan(&mut fake, &request(), ID).unwrap().token;
    assert_ne!(token, wider);
    // A new member of the source changes what is restored.
    fake.add("bpool/ROOT/debian/srv", &[("canmount", "noauto")]);
    assert_ne!(plan(&mut fake, &request(), ID).unwrap().token, wider);
}

fn plan_error(fake: &mut Fake, request: &Request) -> String {
    let error = plan(fake, request, ID).unwrap_err().to_string();
    assert!(fake.effects.is_empty(), "a refused plan changed something");
    error
}

#[test]
fn plan_refusals_change_nothing() {
    let refused = |change: &dyn Fn(&mut Fake, &mut Request), expect: &str| {
        let mut fake = world();
        let mut request = request();
        change(&mut fake, &mut request);
        let error = plan_error(&mut fake, &request);
        assert!(error.contains(expect), "expected {expect:?}: {error}");
    };
    refused(&|_, r| r.disk = "/dev/fake-b".into(), "on the target disk");
    refused(
        &|f, _| f.dataset_mut("rpool/home/alice").mounted = true,
        "is mounted",
    );
    refused(
        &|f, r| {
            f.running_root = Some("rpool/ROOT/debian".into());
            r.source = "bpool/ROOT/debian@old".into();
        },
        "running system",
    );
    refused(&|_, r| r.source = "rpool/ROOT/debian@x".into(), "");
    refused(
        &|f, _| {
            f.pools
                .iter_mut()
                .find(|p| p.name == "bpool")
                .unwrap()
                .capacity = 6 * GIB
        },
        "staging the kept data needs",
    );
    refused(
        &|f, _| f.disks[0].identity.bytes = 8 * GIB,
        "the target disk can hold",
    );
    refused(
        &|f, _| {
            f.snap("rpool/srv@base", false);
            f.add("rpool/home/clone", &[]);
            f.dataset_mut("rpool/home/clone").origin = Some("rpool/srv@base".into());
        },
        "is a clone of rpool/srv@base",
    );
    refused(
        &|f, _| f.dataset_mut("rpool/home/alice").encryption_root = Some("rpool".into()),
        "encrypted under rpool",
    );
    refused(
        &|_, r| r.keep.push("rpool/ROOT".into()),
        "overlaps the restored BE",
    );
    refused(
        &|_, r| r.keep = vec!["rpool/ROOT/debian".into()],
        "overlaps the restored BE",
    );
    refused(&|_, r| r.keep = vec!["bpool/ROOT".into()], "not in rpool");
    refused(
        &|f, _| {
            f.dataset_mut("rpool/home")
                .local
                .insert("zboot:pair".into(), "x".into());
        },
        "invalid pair",
    );
    refused(
        &|f, _| {
            f.snap("rpool/home/alice@base", false);
            f.add("rpool/home/copy", &[]);
            f.dataset_mut("rpool/home/copy").origin = Some("rpool/home/alice@base".into());
        },
        "would make it an independent copy",
    );
    refused(
        &|f, _| {
            f.add("rpool/home/raw", &[]);
            f.encrypt("rpool/home/raw", "raw", "prompt");
        },
        "is entered at a prompt",
    );
    refused(
        &|f, _| {
            f.add("rpool/home/sealed", &[]);
            f.encrypt("rpool/home/sealed", "passphrase", "prompt");
            f.add("rpool/home/sealed/open", &[]);
        },
        "not encrypted but its parent is",
    );
    refused(
        &|f, _| f.encrypt("bpool", "passphrase", "prompt"),
        "staging would encrypt it with B's key",
    );
    refused(
        &|f, _| {
            f.secondaries.insert("bpool/ROOT/debian".into());
        },
        "paired secondary",
    );
    refused(&|f, _| f.running_root = None, "not the running system");
    // The BE's own hostid is resolved before anything is erased.
    refused(&|f, _| f.hostid = String::new(), "has no /etc/hostid");
    refused(
        &|f, _| f.spl_hostid = "11111111".into(),
        "the running hostid is 11111111",
    );
    refused(
        &|f, _| {
            f.dataset_mut("bpool")
                .local
                .insert(super::intent::PROPERTY.into(), "{}".into());
        },
        "already records an operation",
    );
    refused(
        &|f, _| {
            f.dataset_mut("rpool")
                .local
                .insert(super::intent::PROPERTY.into(), "{}".into());
        },
        "already records an operation",
    );
}

#[test]
fn deploy_geometry_is_checked_before_any_restore_effect() {
    const MIB: u64 = 1024 * 1024;
    // One MiB at each end, a 512 MiB ESP, and exactly deploy's 2 GiB ZFS
    // minimum. Content is deliberately tiny so only geometry can refuse.
    let boundary = 2 * MIB + 512 * MIB + 2 * GIB;
    for (bytes, esp, swap, sector, accepted) in [
        (2 * GIB, 512 * MIB, 0, 512, false),
        (boundary - MIB, 512 * MIB, 0, 512, false),
        (boundary, 512 * MIB, 0, 512, true),
        (boundary, 512 * MIB, 0, 4096, true),
        (boundary, 256 * MIB, 0, 4096, false),
        (boundary, 512 * MIB + 1, 0, 512, false),
        (boundary, 512 * MIB, 1, 512, false),
    ] {
        let mut fake = world();
        for dataset in &mut fake.datasets {
            dataset.used = 0;
        }
        let disk = &mut fake.disks[0];
        disk.identity.bytes = bytes;
        disk.identity.logical_sector = sector;
        disk.partitions.clear();
        disk.table = None;
        let mut request = request();
        request.keep.clear();
        request.esp_bytes = Some(esp);
        request.swap_bytes = Some(swap);
        let before = fake.normalized();
        let result = plan(&mut fake, &request, ID);
        assert_eq!(
            result.is_ok(),
            accepted,
            "{bytes}/{esp}/{swap}/{sector}: {result:?}"
        );
        assert!(fake.effects.is_empty(), "planning attempted a write");
        assert_eq!(fake.normalized(), before, "planning changed native state");
        if !accepted {
            assert!(result.unwrap_err().to_string().contains("partition"));
        }
    }
}

#[test]
fn old_pre_erase_records_revalidate_geometry_before_any_resume_effect() {
    const MIB: u64 = 1024 * 1024;
    let boundary = 2 * MIB + 512 * MIB + 2 * GIB;
    let mut initial = world();
    for dataset in &mut initial.datasets {
        dataset.used = 0;
    }
    initial.disks[0].identity.bytes = boundary;
    initial.disks[0].partitions.clear();
    initial.disks[0].table = None;
    let mut request = request();
    request.keep.clear();
    request.esp_bytes = Some(512 * MIB);
    request.swap_bytes = Some(0);
    let plan = plan(&mut initial, &request, ID).unwrap();
    let mut baseline = initial.clone();
    Run::start(&mut baseline, &plan, &mut Vec::new()).unwrap();
    let wipe = baseline
        .effects
        .iter()
        .position(|e| e.starts_with("wipe "))
        .unwrap();
    let erasing_record = baseline.effects[..wipe]
        .iter()
        .rposition(|e| e == "record bpool")
        .unwrap();
    for (cut, phase) in [(erasing_record, Phase::Scrubbed), (wipe, Phase::Erasing)] {
        let mut stopped = initial.clone();
        stopped.cut = Some((cut, Cut::Before));
        assert!(Run::start(&mut stopped, &plan, &mut Vec::new()).is_err());
        stopped.restart();
        let encoded = stopped.dataset_mut("bpool").local[super::intent::PROPERTY].clone();
        let original: super::Intent = serde_json::from_str(&encoded).unwrap();
        assert_eq!(original.step, phase as u32);
        // Exact boundary geometry continues through the same real fake-engine
        // cuts as a normal interrupted restore.
        let mut valid = stopped.clone();
        let renewed = resume_plan(&mut valid, ID).unwrap();
        Run::resume(
            &mut valid,
            ID,
            renewed.erase_layout().unwrap(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(valid.normalized(), baseline.normalized());
        for (bytes, esp) in [(2 * GIB, 512 * MIB), (boundary, 512 * MIB + 1)] {
            let mut invalid = stopped.clone();
            invalid.disks[0].identity.bytes = bytes;
            let review = super::Backend::disk(&mut invalid, "/dev/fake-a", Some("rpool")).unwrap();
            let mut old = original.clone();
            old.state.disk = super::DiskBinding::of(&review).unwrap();
            old.state.esp_bytes = esp;
            invalid.dataset_mut("bpool").local.insert(
                super::intent::PROPERTY.into(),
                super::intent::encode(&old).unwrap(),
            );
            let before = invalid.normalized();
            let effects = invalid.effects.len();
            assert!(
                resume_plan(&mut invalid, ID)
                    .unwrap_err()
                    .to_string()
                    .contains("partition")
            );
            // Library callers cannot bypass the preview admission with a
            // directly supplied erase layout.
            assert!(
                Run::resume(
                    &mut invalid,
                    ID,
                    Some(old.state.disk.layout.clone()),
                    &mut Vec::new()
                )
                .unwrap_err()
                .to_string()
                .contains("partition")
            );
            assert_eq!(
                invalid.effects.len(),
                effects,
                "{phase:?}: resume wrote something"
            );
            assert_eq!(
                invalid.normalized(),
                before,
                "{phase:?}: resume changed native state"
            );
        }
    }
}

#[test]
fn an_oversized_record_is_refused_before_any_effect() {
    let mut fake = world();
    let mut request = request();
    for index in 0..40 {
        let name = format!("rpool/{}{index:02}", "k".repeat(150));
        fake.add(&name, &[]);
        request.keep.push(name);
    }
    let error = plan_error(&mut fake, &request);
    assert!(error.contains("6000-byte limit"), "{error}");
}

#[test]
fn abandon_before_erasure_releases_and_destroys_nothing() {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.corrupt = Some(format!("{}/srv", staging()));
    let mut out = Vec::new();
    assert!(Run::start(&mut fake, &plan, &mut out).is_err());
    fake.corrupt = None;
    let preview = abandon_plan(&mut fake, ID).unwrap();
    assert!(preview.releases && preview.token.len() == 32);
    let abandoned = abandon(&mut fake, ID).unwrap();
    assert!(abandoned.released);
    assert!(abandoned.left.iter().any(|l| l.contains("zboot drop")));
    assert!(abandoned.left.iter().any(|l| l.contains("stays on A")));
    assert!(fake.snapshots.iter().all(|s| s.holds.is_empty()));
    assert_eq!(value(&fake, "bpool", "zboot:operation"), None);
    assert!(
        !fake
            .effects
            .iter()
            .any(|e| e.starts_with("destroy") || e.starts_with("wipe"))
    );
    assert!(list(&mut fake).unwrap().operations.is_empty());
    assert_no_chunked_records(&fake);
}

#[test]
fn abandon_preserves_deferred_source_and_redundant_staging_even_with_other_protection() {
    let mut stopped = cut_at(first("scrub bpool"), Cut::Before);
    let suffix = super::State::suffix(ID);
    let source = format!("bpool/ROOT/debian@{suffix}");
    let staged = format!("{}/srv@{suffix}", staging());
    let sending = format!("bpool/ROOT/debian/var@{suffix}");
    let cloned = format!("{}/home@daily", staging());
    let ordinary = format!("{}/home/alice@hourly", staging());
    let tag = super::State::tag(ID);
    let send_tag = ".send-1024-1";
    stopped.add("bpool/other-clone", &[]);
    stopped.dataset_mut("bpool/other-clone").origin = Some(cloned.clone());
    let deferred = [&source, &staged, &sending, &cloned];
    for point in deferred {
        let snapshot = stopped
            .snapshots
            .iter_mut()
            .find(|s| &s.name == point)
            .unwrap();
        assert!(snapshot.holds.contains(&tag));
        snapshot.defer_destroy = true;
        if point == &sending {
            snapshot.holds.push(send_tag.into());
        }
    }
    assert!(
        stopped
            .snapshot_ref(&ordinary)
            .unwrap()
            .holds
            .contains(&tag)
    );
    let check = |done: super::Abandoned| {
        assert!(!done.released);
        for point in deferred {
            assert!(
                done.left.iter().any(|line| {
                    line.contains(point) && line.contains(&tag) && line.contains("deferred")
                }),
                "{:?}",
                done.left
            );
        }
        assert!(
            done.left.iter().any(|line| {
                line.contains("redundant staged copy") && line.contains("before using `zboot drop")
            }),
            "{:?}",
            done.left
        );
    };
    let mut baseline = stopped.clone();
    check(abandon(&mut baseline, ID).unwrap());
    assert!(super::record(&mut baseline, ID).unwrap().is_none());
    assert_eq!(value(&baseline, &staging(), "zboot:staging"), None);
    for point in deferred {
        let snapshot = baseline.snapshot_ref(point).unwrap();
        assert_eq!(snapshot.guid, guid(&stopped, point));
        assert!(snapshot.holds.contains(&tag));
    }
    assert_eq!(
        baseline.snapshot_ref(&sending).unwrap().holds,
        [tag.as_str(), send_tag]
    );
    assert!(baseline.snapshot_ref(&ordinary).unwrap().holds.is_empty());
    assert_eq!(
        baseline
            .snapshots
            .iter()
            .filter(|s| s.holds.contains(&tag))
            .count(),
        deferred.len()
    );
    for at in stopped.effects.len()..baseline.effects.len() {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = stopped.clone();
            fake.cut = Some((at, cut));
            if let Ok(done) = abandon(&mut fake, ID) {
                check(done);
            }
            fake.restart();
            if super::record(&mut fake, ID).unwrap().is_some() {
                check(abandon(&mut fake, ID).unwrap());
            }
            assert_eq!(fake.normalized(), baseline.normalized(), "{at} {cut:?}");
        }
    }
    // The sender closing its cleanup descriptor must leave the same snapshot.
    super::Backend::release(&mut baseline, &sending, send_tag).unwrap();
    let snapshot = baseline.snapshot_ref(&sending).unwrap();
    assert_eq!(snapshot.guid, guid(&stopped, &sending));
    assert_eq!(snapshot.holds, [tag.as_str()]);
}

#[test]
fn only_copy_abandon_advises_copying_before_resolving_a_deferred_staging_snapshot() {
    let mut fake = interrupted_only_copy();
    let name = format!("{}/home@daily", staging());
    fake.snapshots
        .iter_mut()
        .find(|s| s.name == name)
        .unwrap()
        .defer_destroy = true;
    let done = abandon(&mut fake, ID).unwrap();
    let tag = super::State::tag(ID);
    let note = done
        .left
        .iter()
        .find(|line| line.contains("only complete copy"))
        .unwrap();
    let copy = note
        .find("Copy the staged data and that metadata elsewhere first")
        .unwrap();
    let resolve = note.find("Resolve the deferred snapshots").unwrap();
    assert!(
        copy < resolve && note.contains(&name) && note.contains(&tag),
        "{note}"
    );
    assert!(fake.snapshot_ref(&name).unwrap().holds.contains(&tag));
}

#[test]
fn abandon_never_releases_the_only_copy() {
    for (prefix, cut) in [
        ("wipe", Cut::After),
        ("deploy", Cut::After),
        ("send bpool/zboot", Cut::Before),
    ] {
        let mut fake = world();
        let plan = plan(&mut fake, &request(), ID).unwrap();
        let index = fake_effect_index(&plan, prefix);
        fake.cut = Some((index, cut));
        let mut out = Vec::new();
        assert!(Run::start(&mut fake, &plan, &mut out).is_err());
        fake.restart();
        assert!(!abandon_plan(&mut fake, ID).unwrap().releases);
        let effects = fake.effects.len();
        let abandoned = abandon(&mut fake, ID).unwrap();
        assert!(!abandoned.released, "{prefix}");
        assert!(
            abandoned
                .left
                .iter()
                .any(|l| l.contains("only complete copy")),
            "{prefix}: {:?}",
            abandoned.left
        );
        let tag = format!("zboot:restore:{ID}");
        let staged = fake
            .snapshot_ref(&format!("{}/home/alice@zboot-restore-{ID}", staging()))
            .unwrap();
        assert!(staged.holds.contains(&tag), "{prefix}");
        // Every staged snapshot, not only the boundary, stays held.
        for older in ["home/alice@daily", "home/alice@hourly", "home@daily"] {
            let name = format!("{}/{older}", staging());
            assert!(
                fake.snapshot_ref(&name).unwrap().holds.contains(&tag),
                "{prefix}: {name}"
            );
        }
        assert!(
            !fake
                .snapshot_ref(&format!("bpool/ROOT/debian@zboot-restore-{ID}"))
                .unwrap()
                .holds
                .contains(&tag)
        );
        assert_eq!(
            value(&fake, &staging(), "zboot:staging").map(|v| v.0),
            Some(ID.to_string())
        );
        // Archive the operation's receipt and remove it, while keeping all
        // staged data held and marked for an independently confirmed drop.
        let receipt_prefix = super::receipt::key(ID).unwrap().prefix().to_owned();
        let archive_prefix = format!("{}{ID}:", super::receipt::ARCHIVE_PREFIX);
        assert!(fake.effects[effects..].iter().all(|effect| {
            effect.starts_with(&format!("release zboot:restore:{ID} bpool/ROOT/debian"))
                || effect.starts_with(&format!("set {archive_prefix}"))
                || effect.starts_with(&format!("inherit {receipt_prefix}"))
                || effect == "clear record bpool"
        }));
        let local = &fake.dataset_ref(&staging()).local;
        assert!(!local.keys().any(|key| key.starts_with(&receipt_prefix)));
        assert!(local.contains_key(&format!("{archive_prefix}manifest")));
        // And the staged copy still refuses destruction.
        assert!(super::Backend::destroy_tree(&mut fake, &staging()).is_err());
    }
}

/// Project the actual abandoned restore's stored identities, local control
/// properties and held snapshots into the tree engine's native-state model.
/// Inherited properties are derived by that model, not fabricated.
fn drop_storage(fake: &Fake) -> crate::tree::fake::Fake {
    use crate::tree::fake::{Ds, Fake as TreeFake, PoolModel, Snap};
    let mut storage = TreeFake::default();
    for pool in fake.pools.iter().filter(|pool| pool.imported) {
        storage.pools.insert(
            pool.name.clone(),
            PoolModel {
                guid: pool.guid,
                bootfs: pool.bootfs.clone(),
            },
        );
        for dataset in fake.datasets.iter().filter(|d| d.pool == pool.guid) {
            storage.datasets.insert(
                dataset.name.clone(),
                Ds {
                    guid: dataset.guid,
                    createtxg: dataset.txg,
                    objsetid: dataset.guid,
                    volume: dataset.volume,
                    origin: dataset.origin.clone(),
                    mounted: dataset.mounted,
                    props: dataset.local.clone(),
                    content: dataset.guid,
                },
            );
        }
        for point in fake.snapshots.iter().filter(|s| s.pool == pool.guid) {
            storage.snapshots.insert(
                point.name.clone(),
                Snap {
                    guid: point.guid,
                    createtxg: point.txg,
                    objsetid: point.txg,
                    holds: point.holds.iter().cloned().collect(),
                    defer: false,
                    content: point.guid,
                },
            );
        }
    }
    storage.next = 1_000_000;
    storage
}

#[test]
fn only_copy_abandon_retires_its_receipt_before_intent_and_admits_explicit_drop_after_every_cut() {
    let mut interrupted = world();
    let plan = plan(&mut interrupted, &request(), ID).unwrap();
    interrupted.cut = Some((fake_effect_index(&plan, "wipe"), Cut::After));
    assert!(Run::start(&mut interrupted, &plan, &mut Vec::new()).is_err());
    interrupted.restart();
    let state = active_restore_state(&mut interrupted);
    let named = state.receipt.clone().unwrap();
    let receipt = super::receipt::read(&mut interrupted, &state, ID).unwrap();
    let targets = [staging()];
    let error = crate::tree::discard::plan_with(&mut drop_storage(&interrupted), &targets)
        .unwrap_err()
        .to_string();
    assert!(error.contains("still recorded"), "{error}");
    let first = interrupted.effects.len();
    let mut baseline = interrupted.clone();
    assert!(!abandon(&mut baseline, ID).unwrap().released);
    let last = baseline.effects.len();
    for at in first..last {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = interrupted.clone();
            fake.cut = Some((at, cut));
            let _ = abandon(&mut fake, ID);
            fake.restart();
            if super::record(&mut fake, ID).unwrap().is_some() {
                assert!(
                    crate::tree::discard::plan_with(&mut drop_storage(&fake), &targets).is_err(),
                    "a still-recorded restore cannot be dropped: {at} {cut:?}"
                );
                assert_eq!(
                    value(&fake, &staging(), "zboot:staging"),
                    Some((ID.into(), "local".into()))
                );
                for point in fake
                    .snapshots
                    .iter()
                    .filter(|point| point.name.starts_with(&format!("{}/", staging())))
                {
                    assert!(point.holds.contains(&super::State::tag(ID)));
                }
                for member in fake.tree(&staging()) {
                    assert!(!member.mounted);
                    for (key, expected) in [
                        ("mountpoint", "none"),
                        ("readonly", "on"),
                        ("canmount", "off"),
                        ("volmode", "none"),
                    ] {
                        let current = value(&fake, &member.name, key).unwrap();
                        assert_eq!(
                            current,
                            (expected.into(), "local".into()),
                            "{} {key}",
                            member.name
                        );
                        assert_eq!(
                            Some(current),
                            value(&interrupted, &member.name, key),
                            "abandon changed inert provenance: {} {key}",
                            member.name
                        );
                    }
                }
                // Until receipt retirement is complete, the original intent
                // still authorizes retrying that exact cleanup.
                abandon(&mut fake, ID).unwrap();
            }
            assert_eq!(fake.normalized(), baseline.normalized(), "{at} {cut:?}");
            // No receipt chunk is left, locally or inherited, and nothing a
            // journal would leave either.
            let view = super::Backend::view(&mut fake).unwrap();
            for member in view.tree(&staging()) {
                assert!(
                    !member.properties.keys().any(|key| {
                        key.starts_with("zboot:attachment:") || key.starts_with("zboot:journal:")
                    }),
                    "{at} {cut:?} {}",
                    member.name
                );
            }
            let owner = super::receipt::endpoint(&view, &state).unwrap();
            assert_eq!(&owner, named.endpoint());
            // Main intent is gone, but the full canonical receipt remains
            // independently recoverable, including every original source and
            // kept member's placement, hidden layer and managed metadata.
            assert!(super::record(&mut fake, ID).unwrap().is_none());
            assert_eq!(
                super::receipt::read_archive(&mut fake, &owner, ID).unwrap(),
                (named.clone(), receipt.clone())
            );
            let mut storage = drop_storage(&fake);
            let staged: std::collections::BTreeSet<_> = storage
                .snapshots
                .keys()
                .filter(|name| name.starts_with(&format!("{}/", staging())))
                .cloned()
                .collect();
            let drop = crate::tree::discard::plan_with(&mut storage, &targets).unwrap();
            assert_eq!(
                drop.releases
                    .iter()
                    .map(|r| r.snapshot.name.clone())
                    .collect::<std::collections::BTreeSet<_>>(),
                staged
            );
            assert!(drop.releases.iter().all(|r| r.tag == super::State::tag(ID)));
            let token = crate::tree::discard::consent(&drop).unwrap();
            let dropped =
                crate::tree::discard::execute_with(&mut storage, &drop, &token, &mut Vec::new())
                    .unwrap();
            assert!(dropped.complete);
            assert!(!storage.datasets.contains_key(&staging()));
            assert!(storage.datasets.contains_key("bpool/ROOT/debian"));
            assert!(storage.snapshots.contains_key("bpool/ROOT/debian@old"));
        }
    }
}

#[test]
fn only_copy_abandon_with_foreign_receipt_or_replaced_owner_keeps_its_intent_and_holds() {
    for replaced_owner in [false, true] {
        let mut fake = world();
        let plan = plan(&mut fake, &request(), ID).unwrap();
        fake.cut = Some((fake_effect_index(&plan, "wipe"), Cut::After));
        assert!(Run::start(&mut fake, &plan, &mut Vec::new()).is_err());
        fake.restart();
        if replaced_owner {
            fake.dataset_mut(&staging()).guid += 100_000;
        } else {
            let prefix = super::receipt::key(ID).unwrap().prefix().to_owned();
            let chunk = fake
                .dataset_mut(&staging())
                .local
                .iter_mut()
                .find(|(key, _)| key.starts_with(&prefix))
                .unwrap()
                .1;
            chunk.push('0');
        }
        let first = fake.effects.len();
        assert!(abandon(&mut fake, ID).is_err());
        assert!(super::record(&mut fake, ID).unwrap().is_some());
        assert_eq!(
            value(&fake, &staging(), "zboot:staging"),
            Some((ID.into(), "local".into()))
        );
        for point in fake
            .snapshots
            .iter()
            .filter(|point| point.name.starts_with(&format!("{}/", staging())))
        {
            assert!(point.holds.contains(&super::State::tag(ID)));
        }
        assert!(
            !fake.effects[first..]
                .iter()
                .any(|effect| effect == "clear record bpool")
        );
    }
}

fn interrupted_only_copy() -> Fake {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.cut = Some((fake_effect_index(&plan, "wipe"), Cut::After));
    assert!(Run::start(&mut fake, &plan, &mut Vec::new()).is_err());
    fake.restart();
    fake
}

#[test]
fn abandon_archive_preflight_does_not_mark_an_effect() {
    const CASE: &str = "ZBOOT_ABANDON_ARCHIVE_PREFLIGHT_CASE";
    if let Ok(case) = std::env::var(CASE) {
        let mut fake = interrupted_only_copy();
        let state = active_restore_state(&mut fake);
        let named = state.receipt.clone().unwrap();
        let receipt = super::receipt::prepare_abandon_archive(&mut fake, &state, ID).unwrap();
        super::receipt::publish_archive(&mut fake, &state, ID, &receipt).unwrap();
        let prefix = format!("{}{ID}:", super::receipt::ARCHIVE_PREFIX);
        match case.as_str() {
            "complete" => {
                assert_eq!(
                    super::receipt::read_archive(&mut fake, named.endpoint(), ID).unwrap(),
                    (named.clone(), receipt.clone())
                );
            }
            "partial" => {
                // A cut before the manifest, the archive's commit.
                let chunk = fake
                    .dataset_ref(&staging())
                    .local
                    .keys()
                    .find(|key| key.starts_with(&prefix) && !key.ends_with(":manifest"))
                    .unwrap()
                    .clone();
                fake.dataset_mut(&staging())
                    .local
                    .retain(|key, _| !key.starts_with(&prefix) || key == &chunk);
            }
            _ => panic!("unknown archive preflight case {case}"),
        }
        let before = fake.normalized();
        let properties = fake.dataset_ref(&staging()).local.clone();
        let intent = super::record(&mut fake, ID).unwrap();
        let effects = fake.effects.len();
        // The fixture represents a prior interrupted operation. Begin this
        // invocation after loading its complete or partial ordinary archive.
        zfs_tools::engine::effect::reset();
        assert!(!zfs_tools::engine::effect::any());
        assert_eq!(
            super::receipt::prepare_abandon_archive(&mut fake, &state, ID).unwrap(),
            receipt
        );
        assert!(
            !zfs_tools::engine::effect::any(),
            "{case} archive preflight marked an effect"
        );
        assert_eq!(fake.effects.len(), effects);
        assert_eq!(fake.normalized(), before);
        assert_eq!(fake.dataset_ref(&staging()).local, properties);
        assert_eq!(super::record(&mut fake, ID).unwrap(), intent);
        let error = super::refuse("a later admission refused the operation");
        let status = crate::cli::finish(Err(Box::new(error)), None, false, "abandon");
        assert!(!zfs_tools::engine::effect::any());
        std::process::exit(status);
    }
    for case in ["complete", "partial"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restore::tests::abandon_archive_preflight_does_not_mark_an_effect",
                "--nocapture",
            ])
            .env(CASE, case)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{case} archive preflight classification failed\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Rewrite the stored record's state in place, as a damaged record would
/// be, in the encoding this zboot writes.
fn rewrite_state(fake: &mut Fake, change: impl FnOnce(&mut serde_json::Value)) {
    let (pool, mut raw) = super::record(fake, ID).unwrap().unwrap();
    change(&mut raw.state);
    let mut record =
        super::Intent::new(raw.id, raw.kind, serde_json::from_value(raw.state).unwrap());
    record.step = raw.step;
    fake.dataset_mut(&pool).local.insert(
        super::intent::PROPERTY.into(),
        super::intent::encode(&record).unwrap(),
    );
}

#[test]
fn only_copy_abandon_rejects_foreign_incomplete_or_noncanonical_archives_before_effects() {
    let original = interrupted_only_copy();
    let state = active_restore_state(&mut original.clone());
    let receipt =
        super::receipt::prepare_abandon_archive(&mut original.clone(), &state, ID).unwrap();
    // The receipt archived and removed: what a cut leaves just before the
    // record is cleared.
    let mut archived = original.clone();
    super::receipt::preserve_abandoned(&mut archived, &state, ID, &receipt).unwrap();
    let prefix = format!("{}{ID}:", super::receipt::ARCHIVE_PREFIX);
    let manifest = format!("{prefix}manifest");
    let chunk = format!("{prefix}0000");
    let attachment = super::receipt::key(ID).unwrap().prefix().to_owned();
    let archive: Vec<_> = archived
        .dataset_ref(&staging())
        .local
        .iter()
        .filter(|(key, _)| key.starts_with(&prefix))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    assert!(archive.iter().any(|(key, _)| *key == chunk));
    assert!(
        !archived
            .dataset_ref(&staging())
            .local
            .keys()
            .any(|key| key.starts_with(&attachment))
    );
    for scenario in [
        "extra",
        "foreign part",
        "corrupt chunk",
        "noncanonical manifest",
        "received",
        "inherited",
        "missing chunk",
        "other archive",
        "partial receipt, partial archive",
        "named digest",
        "unnamed",
        "absent archive",
        "foreign receipt chunk",
        "first receipt chunk left",
    ] {
        let mut fake = if matches!(
            scenario,
            "named digest"
                | "unnamed"
                | "absent archive"
                | "foreign receipt chunk"
                | "first receipt chunk left"
        ) {
            archived.clone()
        } else {
            let mut fake = original.clone();
            fake.dataset_mut(&staging()).local.extend(archive.clone());
            fake
        };
        let local = &mut fake.dataset_mut(&staging()).local;
        match scenario {
            "extra" => {
                local.insert(format!("{prefix}00ff"), "00".into());
            }
            "foreign part" => {
                local.insert(format!("{prefix}header"), "{}".into());
            }
            "corrupt chunk" => local.get_mut(&chunk).unwrap().push('0'),
            "noncanonical manifest" => local.get_mut(&manifest).unwrap().insert(0, ' '),
            "received" => {
                let value = local.remove(&manifest).unwrap();
                fake.dataset_mut(&staging())
                    .received
                    .insert(manifest.clone(), value);
            }
            "inherited" => {
                let value = local.remove(&manifest).unwrap();
                fake.dataset_mut("bpool")
                    .local
                    .insert(manifest.clone(), value);
            }
            "missing chunk" => {
                local.remove(&chunk);
            }
            "other archive" => {
                local.insert(
                    format!(
                        "{}fedcba9876543210:manifest",
                        super::receipt::ARCHIVE_PREFIX
                    ),
                    "{}".into(),
                );
            }
            // A named receipt missing a chunk and an archive without its
            // manifest: no abandon order leaves both.
            "partial receipt, partial archive" => {
                local.remove(&manifest);
                local.remove(&format!("{attachment}0000"));
            }
            // The record's name for the receipt is the authority the
            // archive must match.
            "named digest" => rewrite_state(&mut fake, |state| {
                state["receipt"]["sha256"] = "0".repeat(64).into();
            }),
            "unnamed" => rewrite_state(&mut fake, |state| {
                state.as_object_mut().unwrap().remove("receipt").unwrap();
            }),
            "absent archive" => local.retain(|key, _| !key.starts_with(&prefix)),
            "foreign receipt chunk" => {
                local.insert(format!("{attachment}0000"), "00".into());
            }
            // The receipt's own first chunk, exactly the archive's: no cut
            // of an in-order removal leaves it without the later ones.
            "first receipt chunk left" => {
                let first = local[&chunk].clone();
                local.insert(format!("{attachment}0000"), first);
            }
            _ => unreachable!(),
        }
        let before = fake.normalized();
        let effects = fake.effects.len();
        assert!(abandon(&mut fake, ID).is_err(), "{scenario}");
        assert_eq!(fake.effects.len(), effects, "{scenario}");
        assert_eq!(fake.normalized(), before, "{scenario}");
        assert!(super::record(&mut fake, ID).unwrap().is_some());
    }
    // The archived state itself finishes from its archive.
    let mut fake = archived.clone();
    assert!(!abandon(&mut fake, ID).unwrap().released);
    assert!(super::record(&mut fake, ID).unwrap().is_none());
}

#[test]
fn only_copy_abandon_preserves_renamed_staging_and_refuses_before_effects() {
    let mut fake = interrupted_only_copy();
    let renamed = "bpool/operator-renamed-staging";
    let before = fake.dataset_ref(&staging()).guid;
    rename_workspace(&mut fake, &staging(), renamed);
    let expected = fake.normalized();
    let effects = fake.effects.len();
    let error = abandon(&mut fake, ID).unwrap_err().to_string();
    assert!(
        error.contains("restore staging") && error.contains(renamed),
        "{error}"
    );
    assert_eq!(fake.effects.len(), effects);
    assert_eq!(fake.normalized(), expected);
    assert_eq!(fake.dataset_ref(renamed).guid, before);
    assert!(super::record(&mut fake, ID).unwrap().is_some());
    assert_eq!(
        value(&fake, renamed, "zboot:staging"),
        Some((ID.into(), "local".into()))
    );
}

#[test]
fn redundant_staged_abandon_preserves_a_renamed_workspace_before_any_effect() {
    let mut stopped = cut_at(first("scrub bpool"), Cut::Before);
    assert_eq!(
        super::record(&mut stopped, ID).unwrap().unwrap().1.step,
        Phase::Scrubbing as u32
    );
    assert!(abandon_plan(&mut stopped, ID).unwrap().releases);
    let renamed = "bpool/renamed-redundant-staging";
    let replacement = "bpool/unrelated-redundant-replacement";
    rename_workspace(&mut stopped, &staging(), renamed);
    for occupied in [false, true] {
        let mut fake = stopped.clone();
        if occupied {
            fake.add(&staging(), &[]);
        }
        let before = fake.normalized();
        let effects = fake.effects.len();
        let error = abandon(&mut fake, ID).unwrap_err().to_string();
        assert!(error.contains(renamed), "{occupied}: {error}");
        assert_eq!(fake.effects.len(), effects);
        assert_eq!(fake.normalized(), before);
        assert!(super::record(&mut fake, ID).unwrap().is_some());

        if occupied {
            rename_workspace(&mut fake, &staging(), replacement);
        }
        rename_workspace(&mut fake, renamed, &staging());
        assert!(abandon(&mut fake, ID).unwrap().released);
        assert!(super::record(&mut fake, ID).unwrap().is_none());
        assert_eq!(fake.find(replacement).is_some(), occupied);
    }
}

#[test]
fn restored_but_unconfigured_abandon_preserves_original_member_metadata_and_keeps_staging() {
    let configured_world = || {
        let mut fake = world();
        fake.dataset_mut("rpool/home").local.extend([
            ("mountpoint".into(), "/original-kept".into()),
            ("readonly".into(), "off".into()),
            ("canmount".into(), "on".into()),
            ("volmode".into(), "default".into()),
        ]);
        for (key, value) in [
            ("mountpoint", "/received-alice"),
            ("readonly", "on"),
            ("canmount", "noauto"),
            ("volmode", "none"),
        ] {
            fake.dataset_mut("rpool/home/alice").local.remove(key);
            fake.dataset_mut("rpool/home/alice")
                .received
                .insert(key.into(), value.into());
        }
        fake.dataset_mut("rpool/home/bob")
            .local
            .remove("mountpoint");
        fake.dataset_mut("bpool/ROOT/debian")
            .local
            .insert("zboot:cmdline".into(), "console=ttyS0".into());
        fake
    };
    let mut reference = configured_world();
    start(&mut reference).unwrap();
    let last_receive = reference
        .effects
        .iter()
        .rposition(|effect| effect.starts_with("send "))
        .unwrap();
    // The last tree's checkpoint, then the one that records it Restored.
    let checkpoint = reference
        .effects
        .iter()
        .enumerate()
        .skip(last_receive + 1)
        .filter(|(_, effect)| effect.starts_with("record "))
        .nth(1)
        .unwrap()
        .0;
    let mut fake = configured_world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.cut = Some((checkpoint, Cut::After));
    assert!(Run::start(&mut fake, &plan, &mut Vec::new()).is_err());
    fake.restart();
    let record = super::record(&mut fake, ID).unwrap().unwrap().1;
    assert_eq!(record.step, Phase::Restored as u32);
    let state: super::State = serde_json::from_value(record.state).unwrap();
    let named = state.receipt.clone().unwrap();
    let manifest = super::receipt::read(&mut fake, &state, ID).unwrap();
    let alice = &manifest.kept["home"].members["alice"].placement;
    for saved in [
        alice.mountpoint.as_ref().unwrap(),
        &alice.readonly,
        alice.canmount.as_ref().unwrap(),
        &alice.volmode,
    ] {
        assert_eq!(saved.source, "received");
    }
    assert_eq!(
        manifest.kept["home"].members["bob"]
            .placement
            .mountpoint
            .as_ref()
            .unwrap()
            .source,
        "inherited from rpool/home"
    );
    assert_eq!(
        manifest.source_tree.members[""].managed["zboot:cmdline"],
        "console=ttyS0"
    );
    // A holds the returned trees, but configure has not verified them
    // against the manifest: staging may still be the only good copy.
    assert!(!abandon_plan(&mut fake, ID).unwrap().releases);
    let first = fake.effects.len();
    let interrupted = fake.clone();
    let abandoned = abandon(&mut fake, ID).unwrap();
    assert!(!abandoned.released);
    assert!(
        abandoned
            .left
            .iter()
            .any(|note| note.contains("is the only complete copy of the kept data")),
        "{:?}",
        abandoned.left
    );
    let end = fake.effects.len();
    assert!(!fake.effects[first..].iter().any(
        |effect| effect.starts_with("inherit zboot:staging")
            || effect.starts_with(&format!("release {}", super::State::tag(ID)))
                && effect.contains(&staging())
    ));
    let baseline = fake;
    for at in first..end {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = interrupted.clone();
            fake.cut = Some((at, cut));
            let _ = abandon(&mut fake, ID);
            fake.restart();
            if super::record(&mut fake, ID).unwrap().is_some() {
                assert!(!abandon(&mut fake, ID).unwrap().released, "{at} {cut:?}");
            }
            assert_eq!(fake.normalized(), baseline.normalized(), "{at} {cut:?}");
            assert!(super::record(&mut fake, ID).unwrap().is_none());
            assert_eq!(
                super::receipt::read_archive(&mut fake, named.endpoint(), ID).unwrap(),
                (named.clone(), manifest.clone())
            );
            // The source's holds go; every staged snapshot stays held.
            let tag = super::State::tag(ID);
            for point in &fake.snapshots {
                let staged = point.name.starts_with(&format!("{}/", staging()));
                assert_eq!(point.holds.contains(&tag), staged, "{}", point.name);
            }
            assert_eq!(
                value(&fake, &staging(), "zboot:staging"),
                Some((ID.into(), "local".into()))
            );
        }
    }
}

#[test]
fn abandon_without_staging_marker_never_uses_active_receipts_or_only_copy_archives_as_authority() {
    let original = interrupted_only_copy();
    let state = active_restore_state(&mut original.clone());
    for cleared in [false, true] {
        for marker in ["absent", "wrong-id", "received"] {
            let mut fake = original.clone();
            if cleared {
                let receipt =
                    super::receipt::prepare_abandon_archive(&mut fake, &state, ID).unwrap();
                super::receipt::preserve_abandoned(&mut fake, &state, ID, &receipt).unwrap();
            }
            fake.dataset_mut(&staging()).local.remove("zboot:staging");
            match marker {
                "wrong-id" => {
                    fake.dataset_mut(&staging())
                        .local
                        .insert("zboot:staging".into(), "foreign-restore".into());
                }
                "received" => {
                    fake.dataset_mut(&staging())
                        .received
                        .insert("zboot:staging".into(), ID.into());
                }
                _ => {}
            }
            let before = fake.normalized();
            let effects = fake.effects.len();
            assert!(abandon(&mut fake, ID).is_err(), "{cleared} {marker}");
            assert!(
                super::receipt::prepare_abandon_archive(&mut fake, &state, ID).is_err(),
                "{cleared} {marker}"
            );
            assert_eq!(fake.effects.len(), effects);
            assert_eq!(fake.normalized(), before);
            assert!(super::record(&mut fake, ID).unwrap().is_some());
        }
    }
}

#[test]
fn source_identity_or_snapshot_changes_refuse_before_erase_and_before_receive() {
    let mut reference = world();
    start(&mut reference).unwrap();
    for prefix in ["wipe", "send bpool/ROOT/debian"] {
        let at = reference
            .effects
            .iter()
            .position(|effect| effect.starts_with(prefix))
            .unwrap();
        let mut stopped = world();
        let plan = plan(&mut stopped, &request(), ID).unwrap();
        stopped.cut = Some((at, Cut::Before));
        assert!(Run::start(&mut stopped, &plan, &mut Vec::new()).is_err());
        stopped.restart();
        let erase_layout = resume_plan(&mut stopped, ID)
            .unwrap()
            .erase_layout()
            .unwrap();
        for attack in 0..4 {
            let mut fake = stopped.clone();
            match attack {
                0 => {
                    let original = fake.dataset_ref("bpool/ROOT/debian").clone();
                    fake.dataset_mut("bpool/ROOT/debian").name = "bpool/ROOT/renamed".into();
                    let mut replacement = original;
                    replacement.guid += 10000;
                    fake.datasets.push(replacement);
                }
                1 => {
                    // A replicated child can have the same snapshot GUIDs but
                    // different native dataset identity: digest alone is insufficient.
                    fake.dataset_mut("bpool/ROOT/debian/var").guid += 10000;
                    for point in &mut fake.snapshots {
                        if point.name.starts_with("bpool/ROOT/debian/var@") {
                            point.dataset_guid += 10000;
                        }
                    }
                }
                2 => {
                    fake.snapshots
                        .iter_mut()
                        .find(|s| s.name == format!("bpool/ROOT/debian@zboot-restore-{ID}"))
                        .unwrap()
                        .guid += 10000
                }
                3 => {
                    fake.pools
                        .iter_mut()
                        .find(|p| p.name == "bpool")
                        .unwrap()
                        .guid += 10000
                }
                _ => unreachable!(),
            }
            let effects = fake.effects.len();
            assert!(
                Run::resume(&mut fake, ID, erase_layout.clone(), &mut Vec::new()).is_err(),
                "{prefix} attack {attack}"
            );
            assert!(
                !fake.effects[effects..]
                    .iter()
                    .any(|effect| effect.starts_with("wipe")
                        || effect.starts_with("send bpool/ROOT/debian")),
                "{prefix} attack {attack}: {:?}",
                &fake.effects[effects..]
            );
        }
    }
}

#[test]
fn restore_roles_are_verified_on_every_member_before_placement_is_published() {
    let mut pending = before_publication();
    let state = active_restore_state(&mut pending);
    let original = super::receipt::read(&mut pending, &state, ID).unwrap();
    assert_eq!(
        original.kept["home"].members["bob"]
            .placement
            .canmount
            .as_ref()
            .unwrap()
            .value,
        "noauto"
    );
    let mut fake = world();
    start(&mut fake).unwrap();
    // A is exported at completion; import it again to read it.
    for p in &mut fake.pools {
        if p.name == "rpool" {
            p.imported = true;
        }
    }
    // Every staging member is `canmount=off` locally. Original publication
    // values came from the durable receipt, not the stripped received layer.
    let staging = staging();
    let members: Vec<_> = fake
        .tree(&staging)
        .into_iter()
        .filter(|d| !d.volume)
        .map(|d| d.name.clone())
        .collect();
    assert!(members.len() > 3, "{members:?}");
    for name in &members {
        assert_eq!(
            value(&fake, name, "canmount"),
            Some(("off".into(), "local".into())),
            "{name}"
        );
    }
    assert_eq!(
        fake.find(&format!("{staging}/home/bob"))
            .unwrap()
            .received
            .get("canmount")
            .map(String::as_str),
        None
    );
    // What the restore creates on A takes the roles A had; nothing else is
    // swept.
    assert_eq!(
        value(&fake, "rpool/ROOT/debian", "canmount").unwrap().0,
        "noauto"
    );
    assert_eq!(
        value(&fake, "rpool/ROOT/debian/var", "canmount").unwrap().0,
        "noauto"
    );
    assert_eq!(value(&fake, "rpool/home", "canmount").unwrap().0, "on");
    assert_eq!(
        value(&fake, "rpool/home/alice", "canmount").unwrap().0,
        "on"
    );
    assert_eq!(
        value(&fake, "rpool/home/bob", "canmount").unwrap().0,
        "noauto"
    );
    assert_eq!(
        value(&fake, "bpool/ROOT/debian", "canmount"),
        Some(("noauto".into(), "local".into()))
    );
}

fn active_restore_state(fake: &mut Fake) -> super::State {
    let (_, record) = super::record(fake, ID).unwrap().unwrap();
    serde_json::from_value(record.state).unwrap()
}

#[test]
fn a_failed_role_setter_leaves_received_data_inert_with_its_receipt_on_b() {
    let mut fake = world();
    fake.denied_set = Some(("rpool/home/alice".into(), "canmount".into()));
    let error = start(&mut fake).unwrap_err().to_string();
    assert!(error.contains("setter refused"), "{error}");
    let state = active_restore_state(&mut fake);
    assert!(
        state.receive_targets.is_none(),
        "publication was authorized despite a failed role"
    );
    let record = super::receipt::read(&mut fake, &state, ID).unwrap();
    assert_eq!(
        record.kept["home"].members[""]
            .placement
            .mountpoint
            .as_ref()
            .unwrap()
            .value,
        "/home"
    );
    for member in fake.tree("rpool") {
        assert_eq!(value(&fake, &member.name, "readonly").unwrap().0, "on");
        assert_eq!(value(&fake, &member.name, "volmode").unwrap().0, "none");
        if !member.volume {
            assert_eq!(value(&fake, &member.name, "mountpoint").unwrap().0, "none");
        }
        assert!(!member.mounted);
    }
    fake.denied_set = None;
    resume(&mut fake).unwrap();
    assert!(list(&mut fake).unwrap().operations.is_empty());
}

/// The receipt's chunk writes and the record write that names them, in a
/// clean run.
fn receipt_writes() -> (Vec<usize>, usize) {
    let mut reference = world();
    start(&mut reference).unwrap();
    let set = format!("set {}", super::receipt::key(ID).unwrap().prefix());
    let writes: Vec<_> = reference
        .effects
        .iter()
        .enumerate()
        .filter(|(_, effect)| effect.starts_with(&set))
        .map(|(index, _)| index)
        .collect();
    assert!(writes.len() > 1, "the receipt spans several chunks");
    assert!(writes.windows(2).all(|w| w[1] == w[0] + 1));
    let commit = writes.last().unwrap() + 1;
    assert_eq!(reference.effects[commit], "record bpool");
    (writes, commit)
}

/// The receipt commits at the Quiesced advance that names it. Before that
/// the record names nothing: a resume captures it again from A, which is
/// untouched, and writes over what a cut left, or adopts it when it is
/// exactly the receipt. After that it is never written again.
#[test]
fn the_receipt_commits_at_the_quiesced_advance_that_names_it() {
    let (expected, _) = baseline();
    let (writes, commit) = receipt_writes();
    let last = *writes.last().unwrap();
    let set = format!("set {}", super::receipt::key(ID).unwrap().prefix());
    for at in writes[0]..=commit {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = world();
            let plan = plan(&mut fake, &request(), ID).unwrap();
            fake.cut = Some((at, cut));
            if Run::start(&mut fake, &plan, &mut Vec::new()).is_ok() {
                // A lost reply that applied is judged by reading back.
                assert!(matches!(cut, Cut::Lost) && (at == last || at == commit));
                assert_eq!(fake.normalized(), expected, "{at} {cut:?}");
                continue;
            }
            fake.restart();
            let (_, record) = super::record(&mut fake, ID).unwrap().unwrap();
            assert_eq!(record.step, Phase::Quiesced as u32, "{at} {cut:?}");
            let state: super::State = serde_json::from_value(record.state).unwrap();
            let committed = at == commit && matches!(cut, Cut::After);
            assert_eq!(state.receipt.is_some(), committed, "{at} {cut:?}");
            assert!(state.receipt.is_some() || state.staged == 0);
            // The committed record is no larger than the plan allowed for.
            let stored = fake.dataset_ref("bpool").local[super::intent::PROPERTY].len();
            let widest = super::intent::encode(&plan.state.worst_case(ID).unwrap())
                .unwrap()
                .len();
            assert!(stored <= widest, "{stored} > {widest}");
            let from = fake.effects.len();
            assert!(resume(&mut fake).unwrap(), "{at} {cut:?}");
            assert_eq!(fake.normalized(), expected, "{at} {cut:?}");
            assert_no_chunked_records(&fake);
            let rewritten = fake.effects[from..]
                .iter()
                .filter(|effect| effect.starts_with(&set))
                .count();
            let adopted = at == commit || (at == last && matches!(cut, Cut::After));
            assert_eq!(
                rewritten,
                if adopted { 0 } else { writes.len() },
                "{at} {cut:?}"
            );
        }
    }
}

/// From the commit on, every pass reads the named receipt before any other
/// effect, before the erase and after it, when no capture is possible any
/// more. A receipt that does not read exactly, or a record past the commit
/// that names none, refuses with nothing changed.
#[test]
fn a_named_receipt_that_does_not_read_refuses_before_any_effect_at_every_later_step() {
    let prefix = super::receipt::key(ID).unwrap().prefix().to_owned();
    let first = format!("{prefix}0000");
    let (_, commit) = receipt_writes();
    let mut points = vec![("committed", commit)];
    for phase in [
        Phase::Staged,
        Phase::Verified,
        Phase::Scrubbed,
        Phase::Erasing,
        Phase::Erased,
        Phase::Restored,
    ] {
        points.push((phase.name(), record_reaching(phase)));
    }
    for (step, at) in points {
        let stopped = cut_at(at, Cut::After);
        assert!(active_restore_state(&mut stopped.clone()).receipt.is_some());
        for damage in [
            "missing",
            "extra",
            "inherited",
            "received",
            "corrupt",
            "replaced",
            "unnamed",
        ] {
            if step == "committed" && damage == "unnamed" {
                // Still before staging, so A is untouched: that record is
                // one from before the commit, which captures again.
                continue;
            }
            let mut fake = stopped.clone();
            let staging = staging();
            match damage {
                "missing" => {
                    fake.dataset_mut(&staging).local.remove(&first).unwrap();
                }
                "extra" => {
                    let chunk = fake.dataset_ref(&staging).local[&first].clone();
                    fake.dataset_mut(&staging)
                        .local
                        .insert(format!("{prefix}00ff"), chunk);
                }
                "inherited" => {
                    let chunk = fake.dataset_mut(&staging).local.remove(&first).unwrap();
                    fake.dataset_mut("bpool").local.insert(first.clone(), chunk);
                }
                "received" => {
                    let chunk = fake.dataset_mut(&staging).local.remove(&first).unwrap();
                    fake.dataset_mut(&staging)
                        .received
                        .insert(first.clone(), chunk);
                }
                "corrupt" => {
                    let chunk = fake.dataset_mut(&staging).local.get_mut(&first).unwrap();
                    assert!(!chunk.starts_with("00"));
                    chunk.replace_range(0..2, "00");
                }
                "replaced" => fake.dataset_mut(&staging).guid += 100_000,
                "unnamed" => rewrite_state(&mut fake, |state| {
                    state.as_object_mut().unwrap().remove("receipt").unwrap();
                }),
                _ => unreachable!(),
            }
            let before = fake.normalized();
            let effects = fake.effects.len();
            let error = resume(&mut fake).unwrap_err().to_string();
            assert!(
                error.contains("placement receipt"),
                "{step} {damage}: {error}"
            );
            assert_eq!(fake.effects.len(), effects, "{step} {damage}");
            assert_eq!(fake.normalized(), before, "{step} {damage}");
        }
    }
}

/// Abandon before the commit discards what an interrupted receipt write
/// left; after it, a redundant abandon retires the named receipt. Neither
/// leaves a chunk behind, and every cut of that removal finishes on retry.
#[test]
fn abandon_on_either_side_of_the_receipt_commit_leaves_no_chunk_behind() {
    let (writes, commit) = receipt_writes();
    for (at, cut, named) in [
        (writes[0], Cut::After, false),
        (commit, Cut::Before, false),
        (commit, Cut::After, true),
    ] {
        let stopped = cut_at(at, cut);
        let state = active_restore_state(&mut stopped.clone());
        assert_eq!(state.receipt.is_some(), named);
        let prefix = super::receipt::key(ID).unwrap().prefix().to_owned();
        assert!(
            stopped
                .dataset_ref(&staging())
                .local
                .keys()
                .any(|key| key.starts_with(&prefix))
        );
        let mut baseline = stopped.clone();
        assert!(abandon(&mut baseline, ID).unwrap().released);
        assert_no_chunked_records(&baseline);
        assert_eq!(value(&baseline, &staging(), "zboot:staging"), None);
        for effect in stopped.effects.len()..baseline.effects.len() {
            for cut in [Cut::Before, Cut::After, Cut::Lost] {
                let mut fake = stopped.clone();
                fake.cut = Some((effect, cut));
                let _ = abandon(&mut fake, ID);
                fake.restart();
                if super::record(&mut fake, ID).unwrap().is_some() {
                    abandon(&mut fake, ID).unwrap();
                }
                assert_eq!(
                    fake.normalized(),
                    baseline.normalized(),
                    "{at} {effect} {cut:?}"
                );
            }
        }
    }
}

/// Completion retires the receipt from its recorded staging only: a staging
/// renamed even without its marker is named back before anything is done.
#[test]
fn booted_completion_refuses_a_renamed_unmarked_staging_that_keeps_its_receipt() {
    let mut fake = booted();
    let renamed = "bpool/renamed-unmarked-staging";
    rename_workspace(&mut fake, &staging(), renamed);
    fake.dataset_mut(renamed).local.remove("zboot:staging");
    let before = fake.normalized();
    let effects = fake.effects.len();
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains(renamed), "{error}");
    assert_eq!(fake.effects.len(), effects);
    assert_eq!(fake.normalized(), before);
    rename_workspace(&mut fake, renamed, &staging());
    assert!(resume(&mut fake).unwrap());
    assert!(super::record(&mut fake, ID).unwrap().is_none());
    assert_no_chunked_records(&fake);
}

/// Stopped once the record reached Booted, before completion began.
fn booted() -> Fake {
    let fake = cut_at(record_reaching(Phase::Booted), Cut::After);
    assert!(active_restore_state(&mut fake.clone()).receipt.is_some());
    fake
}

/// A named receipt whose chunks are all there but differ is never discarded
/// by zboot. Its refusal names the chunks; where the receipt is not the only
/// copy of what it records, it also gives the hand removal and the command
/// that then goes on, and following it works. Where it is the only copy it
/// says to leave it. Each refusal changes nothing.
#[test]
fn a_damaged_receipt_names_its_chunks_and_the_recipe_only_where_it_is_not_the_only_copy() {
    let prefix = super::receipt::key(ID).unwrap().prefix().to_owned();
    let chunk = format!("{prefix}0000");
    let corrupt = |fake: &mut Fake| {
        let value = fake.dataset_mut(&staging()).local.get_mut(&chunk).unwrap();
        assert!(!value.starts_with("00"));
        value.replace_range(0..2, "00");
    };
    let by_hand = |fake: &mut Fake| {
        fake.dataset_mut(&staging())
            .local
            .retain(|key, _| !key.starts_with(&prefix));
    };
    let recipe = format!("`{}`", crate::recipe::inherit(&chunk, &staging()));
    type Op = fn(&mut Fake) -> Result<()>;
    let resumed: Op = |fake| resume(fake).map(drop);
    let abandoned: Op = |fake| abandon(fake, ID).map(drop);
    let refuses = |fake: &mut Fake, op: Op, then: Option<&str>| {
        let before = fake.normalized();
        let effects = fake.effects.len();
        let error = op(fake).unwrap_err().to_string();
        assert!(error.contains(&chunk), "{error}");
        match then {
            Some(verb) => assert!(
                error.contains(&recipe) && error.contains(&format!("`zboot {verb} {ID}`")),
                "{error}"
            ),
            // It names the hand procedure, which keeps the chunks first.
            None => assert!(
                !error.contains("zfs inherit")
                    && error.contains("do not remove")
                    && error.contains("zfs get -H -s local all")
                    && error.contains(&format!(
                        "> '/PATH/ON/ANOTHER/DISK/restore-{ID}.properties'"
                    ))
                    && error.contains("copy the kept data")
                    && error.contains("\"Ending a restore by hand\""),
                "{error}"
            ),
        }
        assert_eq!(fake.effects.len(), effects);
        assert_eq!(fake.normalized(), before);
        assert!(super::record(fake, ID).unwrap().is_some());
    };

    // Before the erase, A still has what the receipt records.
    let mut fake = cut_at(first("scrub bpool"), Cut::Before);
    corrupt(&mut fake);
    refuses(&mut fake, resumed, Some("abandon"));
    refuses(&mut fake, abandoned, Some("abandon"));
    by_hand(&mut fake);
    assert!(abandon(&mut fake, ID).unwrap().released);
    assert!(super::record(&mut fake, ID).unwrap().is_none());
    assert_no_chunked_records(&fake);

    // At Booted A has them restored; completion goes on once it is removed.
    let mut fake = booted();
    corrupt(&mut fake);
    refuses(&mut fake, resumed, Some("resume"));
    by_hand(&mut fake);
    assert!(resume(&mut fake).unwrap());
    assert!(super::record(&mut fake, ID).unwrap().is_none());
    assert_no_chunked_records(&fake);

    // From the erase until A is configured it is the only copy.
    let mut fake = interrupted_only_copy();
    corrupt(&mut fake);
    refuses(&mut fake, resumed, None);
    refuses(&mut fake, abandoned, None);
}

/// A cut while an only-copy abandon removes the archived receipt leaves a
/// receipt that does not read: resume says to finish the abandon, and the
/// abandon finishes from the archive.
#[test]
fn a_resume_after_an_interrupted_only_copy_abandon_says_to_abandon_again() {
    let stopped = interrupted_only_copy();
    let mut reference = stopped.clone();
    abandon(&mut reference, ID).unwrap();
    let inherit = format!("inherit {}", super::receipt::key(ID).unwrap().prefix());
    let at = (stopped.effects.len()..reference.effects.len())
        .find(|at| reference.effects[*at].starts_with(&inherit))
        .unwrap();
    let mut fake = stopped.clone();
    fake.cut = Some((at, Cut::After));
    assert!(abandon(&mut fake, ID).is_err());
    fake.restart();
    let effects = fake.effects.len();
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(
        error.contains(&format!("run `zboot abandon {ID}` again")),
        "{error}"
    );
    assert_eq!(fake.effects.len(), effects);
    assert!(!abandon(&mut fake, ID).unwrap().released);
    assert_eq!(fake.normalized(), reference.normalized());
}

/// A record past the commit that names no receipt says what ends it: abandon
/// while staging is not the only copy, the hand procedure while it may be.
#[test]
fn a_record_past_the_commit_naming_no_receipt_says_what_ends_it() {
    let unname = |fake: &mut Fake| {
        rewrite_state(fake, |state| {
            state.as_object_mut().unwrap().remove("receipt").unwrap();
        })
    };
    let mut fake = interrupted_only_copy();
    unname(&mut fake);
    let effects = fake.effects.len();
    for error in [
        resume(&mut fake).unwrap_err().to_string(),
        abandon(&mut fake, ID).unwrap_err().to_string(),
    ] {
        assert!(error.contains("\"Ending a restore by hand\""), "{error}");
        assert!(error.contains("zfs get -H -s local all"), "{error}");
        assert!(
            error.contains(&format!(
                "> '/PATH/ON/ANOTHER/DISK/restore-{ID}.properties'"
            )),
            "{error}"
        );
        assert!(!error.contains("zfs inherit"), "{error}");
        assert!(!error.contains(&format!("`zboot abandon {ID}` ends it")));
    }
    assert_eq!(fake.effects.len(), effects);

    let mut fake = cut_at(first("scrub bpool"), Cut::Before);
    unname(&mut fake);
    let effects = fake.effects.len();
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(
        error.contains(&format!("`zboot abandon {ID}` ends it")),
        "{error}"
    );
    assert_eq!(fake.effects.len(), effects);
    assert!(abandon(&mut fake, ID).unwrap().released);
    assert_no_chunked_records(&fake);
}

/// The index of the second receipt chunk removal after `from` in `reference`.
fn second_receipt_inherit(reference: &Fake, from: usize) -> usize {
    let inherit = format!("inherit {}", super::receipt::key(ID).unwrap().prefix());
    (from..reference.effects.len())
        .filter(|at| reference.effects[*at].starts_with(&inherit))
        .nth(1)
        .unwrap()
}

/// An inherit that reports success without applying stops the receipt's
/// removal there, leaving its last chunks. During an only-copy abandon a
/// retried abandon then finishes from the archive; during completion a
/// retried resume finishes. Both end as an uninterrupted run does.
#[test]
fn a_receipt_removal_whose_inherit_did_not_apply_finishes_on_retry() {
    let prefix = super::receipt::key(ID).unwrap().prefix().to_owned();
    let left = |fake: &Fake| -> Vec<String> {
        fake.dataset_ref(&staging())
            .local
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect()
    };

    let stopped = interrupted_only_copy();
    let all = left(&stopped);
    let mut reference = stopped.clone();
    assert!(!abandon(&mut reference, ID).unwrap().released);
    let mut fake = stopped.clone();
    fake.ignored_inherit = Some(second_receipt_inherit(&reference, stopped.effects.len()));
    let error = abandon(&mut fake, ID).unwrap_err().to_string();
    assert!(error.contains("did not apply"), "{error}");
    assert!(super::record(&mut fake, ID).unwrap().is_some());
    assert_eq!(left(&fake), all[1..], "the receipt's last chunks are left");
    fake.restart();
    assert!(!abandon(&mut fake, ID).unwrap().released);
    assert_eq!(fake.normalized(), reference.normalized());
    assert_no_chunked_records(&fake);

    let stopped = booted();
    let mut reference = stopped.clone();
    assert!(resume(&mut reference).unwrap());
    let mut fake = stopped.clone();
    fake.ignored_inherit = Some(second_receipt_inherit(&reference, stopped.effects.len()));
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(
        error.contains("did not apply") && error.contains(&format!("`zboot resume {ID}` again")),
        "{error}"
    );
    assert_eq!(
        super::record(&mut fake, ID).unwrap().unwrap().1.step,
        Phase::Booted as u32
    );
    assert_eq!(left(&fake), all[1..]);
    fake.restart();
    assert!(resume(&mut fake).unwrap());
    assert_eq!(fake.normalized(), reference.normalized());
    assert_no_chunked_records(&fake);
}

/// An only-copy abandon stopped after archiving the receipt, then resumed
/// instead of retried, completes and notes the inert archive it leaves.
#[test]
fn a_restore_resumed_after_an_abandon_archived_its_receipt_notes_the_archive() {
    let stopped = interrupted_only_copy();
    let mut reference = stopped.clone();
    abandon(&mut reference, ID).unwrap();
    let manifest = format!("set {}{ID}:manifest=", super::receipt::ARCHIVE_PREFIX);
    let at = (stopped.effects.len()..reference.effects.len())
        .find(|at| reference.effects[*at].starts_with(&manifest))
        .unwrap();
    let mut fake = stopped.clone();
    fake.cut = Some((at, Cut::After));
    assert!(abandon(&mut fake, ID).is_err());
    fake.restart();
    let layout = resume_plan(&mut fake, ID).unwrap().erase_layout().unwrap();
    let done = Run::resume(&mut fake, ID, layout, &mut Vec::new()).unwrap();
    assert!(
        done.notes
            .iter()
            .any(|note| note.contains("restore-placement") && note.contains("inert")),
        "{:?}",
        done.notes
    );
    assert_no_chunked_records(&fake);
}

#[test]
fn placement_receipt_is_chunked_and_durable_before_the_target_is_erased() {
    let mut reference = world();
    for n in 0..32 {
        reference.add(
            &format!("rpool/home/member{n}"),
            &[(
                "mountpoint",
                &format!("/home/{}", "long-placement/".repeat(12)),
            )],
        );
    }
    let initial = reference.clone();
    start(&mut reference).unwrap();
    let wipe = reference
        .effects
        .iter()
        .position(|effect| effect.starts_with("wipe "))
        .unwrap();
    let mut fake = initial;
    fake.cut = Some((wipe, Cut::Before));
    assert!(start(&mut fake).is_err());
    fake.restart();
    let state = active_restore_state(&mut fake);
    let receipt = super::receipt::read(&mut fake, &state, ID).unwrap();
    assert!(serde_json::to_vec(&receipt).unwrap().len() > super::intent::LIMIT);
    let stored = fake.dataset_ref("bpool").local[super::intent::PROPERTY].clone();
    assert!(stored.len() < super::intent::LIMIT);
    // Exactly the chunks the record names, on the staging, and nothing a
    // journal would keep.
    let prefix = super::receipt::key(ID).unwrap().prefix().to_owned();
    let local = &fake.dataset_ref(&state.staging).local;
    let chunks = local.keys().filter(|key| key.starts_with(&prefix)).count();
    assert!(chunks > 1);
    // The record names exactly that many.
    assert_eq!(
        serde_json::to_value(&state.receipt).unwrap()["chunks"],
        chunks
    );
    assert!(!local.keys().any(|key| key.starts_with("zboot:journal:")));
    for member in fake.tree(&state.staging) {
        for key in ["mountpoint", "readonly", "volmode"] {
            assert!(
                !member.received.contains_key(key),
                "stripped {key} unexpectedly survived on {}",
                member.name
            );
        }
    }
}

#[test]
fn an_existing_intermediate_parent_with_local_mountpoint_refuses_before_more_data_moves() {
    let mut req = request();
    req.keep = vec!["rpool/home/alice".into(), "rpool/home/bob".into()];
    let mut reference = world();
    let p = plan(&mut reference, &req, ID).unwrap();
    Run::start(&mut reference, &p, &mut Vec::new()).unwrap();
    let at = reference
        .effects
        .iter()
        .position(|effect| effect.starts_with("send rpool/home/alice@"))
        .unwrap();
    let mut fake = world();
    let p = plan(&mut fake, &req, ID).unwrap();
    fake.cut = Some((at, Cut::Before));
    assert!(Run::start(&mut fake, &p, &mut Vec::new()).is_err());
    fake.restart();
    fake.dataset_mut(&format!("{}/home", staging()))
        .local
        .insert("mountpoint".into(), "/unrelated".into());
    let effects = fake.effects.len();
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains("not an inert"), "{error}");
    assert!(
        !fake.effects[effects..]
            .iter()
            .any(|effect| effect.starts_with("send "))
    );
    assert_eq!(
        value(&fake, &format!("{}/home", staging()), "mountpoint")
            .unwrap()
            .0,
        "/unrelated"
    );
}

/// Each dataset is sent on its own, so a clone inside a tree would come back
/// as an independent copy: refused before anything changes.
#[test]
fn an_internal_clone_is_refused_and_every_be_filesystem_comes_back_noauto() {
    let mut fake = world();
    fake.add("bpool/ROOT/debian/clone", &[("canmount", "noauto")]);
    fake.dataset_mut("bpool/ROOT/debian/clone").origin = Some("bpool/ROOT/debian/var@old".into());
    let error = plan_error(&mut fake, &request());
    assert!(
        error.contains("bpool/ROOT/debian/clone in the source BE is a clone"),
        "{error}"
    );
    let mut fake = world();
    fake.snap("rpool/home/alice@base", false);
    fake.add("rpool/home/alice-copy", &[]);
    fake.dataset_mut("rpool/home/alice-copy").origin = Some("rpool/home/alice@base".into());
    let error = plan_error(&mut fake, &request());
    assert!(
        error.contains("rpool/home/alice-copy in a kept tree is a clone"),
        "{error}"
    );

    let mut fake = world();
    start(&mut fake).unwrap();
    for p in &mut fake.pools {
        p.imported = true;
    }
    for member in fake.tree("rpool/ROOT/debian") {
        assert_eq!(value(&fake, &member.name, "canmount").unwrap().0, "noauto");
    }
}

#[test]
fn an_older_be_boundary_missing_a_current_member_is_refused_before_effects() {
    let mut fake = world();
    fake.add("bpool/ROOT/debian/later", &[("canmount", "noauto")]);
    let mut req = request();
    req.source = "bpool/ROOT/debian@old".into();
    let error = plan(&mut fake, &req, ID).unwrap_err().to_string();
    assert!(
        error.contains("not recursive") && error.contains("/later lacks it"),
        "{error}"
    );
    assert!(fake.effects.is_empty());
}

#[test]
fn a_lost_publication_reply_is_reconciled_after_all_roles_were_durably_verified() {
    let mut reference = world();
    start(&mut reference).unwrap();
    let at = reference
        .effects
        .iter()
        .position(|effect| effect == "set mountpoint=/ rpool/ROOT/debian")
        .unwrap();
    let mut fake = world();
    fake.cut = Some((at, Cut::Lost));
    start(&mut fake).unwrap();
    assert!(list(&mut fake).unwrap().operations.is_empty());
    let mut stopped = before_publication();
    assert!(active_restore_state(&mut stopped).receive_targets.is_some());
    for member in stopped.tree("rpool/ROOT/debian") {
        if !member.volume {
            assert_eq!(
                value(&stopped, &member.name, "canmount"),
                Some(("noauto".into(), "local".into()))
            );
            assert_eq!(
                value(&stopped, &member.name, "mountpoint"),
                Some(("none".into(), "local".into()))
            );
        }
        assert!(!member.mounted);
    }
    assert_eq!(
        stopped.effects.last().map(String::as_str),
        Some("set mountpoint=/ rpool/ROOT/debian")
    );
}

fn before_publication() -> Fake {
    let mut reference = world();
    start(&mut reference).unwrap();
    let at = reference
        .effects
        .iter()
        .position(|effect| effect == "set mountpoint=/ rpool/ROOT/debian")
        .unwrap();
    let mut fake = world();
    fake.cut = Some((at, Cut::Before));
    assert!(start(&mut fake).is_err());
    fake.restart();
    fake
}

#[test]
fn unknown_managed_receipt_properties_and_live_management_still_refuse() {
    let mut fake = before_publication();
    let state = active_restore_state(&mut fake);
    let original = super::receipt::read(&mut fake, &state, ID).unwrap();
    for key in ["zboot:future-role", "zboot:be"] {
        let mut receipt = original.clone();
        receipt
            .source_tree
            .members
            .get_mut("")
            .unwrap()
            .managed
            .insert(key.into(), "unknown".into());
        let before = fake.effects.len();
        assert!(
            super::receipt::validate(&receipt, &state, ID)
                .unwrap_err()
                .to_string()
                .contains("unsupported managed property"),
            "{key}"
        );
        assert_eq!(fake.effects.len(), before);
    }

    let mut fake = world();
    fake.dataset_mut("bpool/ROOT/debian/var")
        .local
        .insert("zboot:future-role".into(), "unknown".into());
    assert!(plan_error(&mut fake, &request()).contains("zboot:future-role"));
    assert!(fake.effects.is_empty());
}

#[test]
fn an_empty_container_can_be_prepared_but_no_data_moves_until_its_posture_is_verified() {
    let mut reference = world();
    start(&mut reference).unwrap();
    let at = reference
        .effects
        .iter()
        .position(|effect| effect == &format!("create {}", staging()))
        .unwrap();
    let mut fake = world();
    fake.cut = Some((at, Cut::After));
    assert!(start(&mut fake).is_err());
    fake.restart();
    let name = staging();
    fake.dataset_mut(&name)
        .local
        .insert("volmode".into(), "default".into());
    fake.denied_set = Some((name.clone(), "volmode".into()));
    let before = fake.effects.len();
    assert!(resume(&mut fake).is_err());
    assert!(
        !fake.effects[before..]
            .iter()
            .any(|effect| effect.starts_with("send "))
    );
    fake.denied_set = None;
    resume(&mut fake).unwrap();
}

#[test]
fn a_failed_zvol_publication_drain_prevents_any_new_data_receive() {
    let mut fake = world();
    fake.quiesce_fails = true;
    let error = start(&mut fake).unwrap_err().to_string();
    assert!(error.contains("zvol publication drain failed"), "{error}");
    assert!(
        !fake
            .effects
            .iter()
            .any(|effect| effect.starts_with("send "))
    );
    assert!(!fake.effects.iter().any(|effect| effect.starts_with("wipe")));
    fake.quiesce_fails = false;
    resume(&mut fake).unwrap();
}

#[test]
fn an_export_failure_keeps_the_record_until_required_work_finishes() {
    let expected = baseline().0;
    let mut reference = world();
    start(&mut reference).unwrap();
    let at = reference
        .effects
        .iter()
        .rposition(|effect| effect == "export rpool")
        .unwrap();
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.cut = Some((at, Cut::Before));
    assert!(Run::start(&mut fake, &plan, &mut Vec::new()).is_err());
    fake.restart();
    fake.export_error = true;
    assert!(
        resume(&mut fake)
            .unwrap_err()
            .to_string()
            .contains("export failure")
    );
    assert_eq!(
        list(&mut fake).unwrap().operations[0].step.as_deref(),
        Some(Phase::Booted.name())
    );
    assert!(fake.snapshots.iter().any(|s| !s.holds.is_empty()));
    assert_eq!(value(&fake, &staging(), "zboot:staging").unwrap().0, ID);
    fake.export_error = false;
    resume(&mut fake).unwrap();
    assert_eq!(fake.normalized(), expected);
}

#[test]
fn booted_completion_refuses_renamed_staging_before_effects_and_recovers_after_rename_back() {
    // Completion retires the receipt first, so stop before it begins.
    let mut stopped = booted();
    assert_eq!(
        super::record(&mut stopped, ID).unwrap().unwrap().1.step,
        Phase::Booted as u32
    );
    let renamed = "bpool/renamed-booted-staging";
    rename_workspace(&mut stopped, &staging(), renamed);
    let first = stopped.effects.len();
    for occupied in [false, true] {
        let mut fake = stopped.clone();
        if occupied {
            fake.add(&staging(), &[]);
        }
        let before = fake.normalized();
        let error = resume(&mut fake).unwrap_err().to_string();
        assert!(error.contains(renamed), "{occupied}: {error}");
        assert_eq!(fake.effects.len(), first);
        assert_eq!(fake.normalized(), before);
        assert_eq!(
            super::record(&mut fake, ID).unwrap().unwrap().1.step,
            Phase::Booted as u32
        );
        if occupied {
            let replacement = "bpool/unrelated-booted-replacement";
            rename_workspace(&mut fake, &staging(), replacement);
            rename_workspace(&mut fake, renamed, &staging());
            assert!(resume(&mut fake).unwrap());
            assert!(super::record(&mut fake, ID).unwrap().is_none());
            assert!(fake.find(replacement).is_some());
        }
    }
    assert_eq!(
        value(&stopped, renamed, "zboot:staging"),
        Some((ID.into(), "local".into()))
    );
    assert!(
        stopped
            .dataset_ref(renamed)
            .local
            .keys()
            .any(|key| key.starts_with("zboot:attachment:"))
    );
    assert!(
        stopped
            .snapshots
            .iter()
            .filter(|point| point.name.starts_with(&format!("{renamed}/")))
            .any(|point| point.holds.contains(&super::State::tag(ID)))
    );
    // Return the same native workspace to its recorded path. Completion then
    // remains resumable at every cleanup mutation and lost reply.
    rename_workspace(&mut stopped, renamed, &staging());
    let mut baseline = stopped.clone();
    assert!(resume(&mut baseline).unwrap());
    let end = baseline.effects.len();
    assert!(super::record(&mut baseline, ID).unwrap().is_none());
    for at in first..end {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = stopped.clone();
            fake.cut = Some((at, cut));
            let _ = resume(&mut fake);
            fake.restart();
            if super::record(&mut fake, ID).unwrap().is_some() {
                assert!(resume(&mut fake).unwrap(), "{at} {cut:?}");
            }
            assert_eq!(fake.normalized(), baseline.normalized(), "{at} {cut:?}");
            assert!(super::record(&mut fake, ID).unwrap().is_none());
        }
    }
}

#[test]
fn booted_completion_allows_missing_staging_without_a_matching_marked_workspace() {
    let mut reference = world();
    start(&mut reference).unwrap();
    let at = reference
        .effects
        .iter()
        .rposition(|effect| effect == "export rpool")
        .unwrap();
    let mut fake = world();
    fake.cut = Some((at, Cut::Before));
    assert!(start(&mut fake).is_err());
    fake.restart();
    assert_eq!(
        super::record(&mut fake, ID).unwrap().unwrap().1.step,
        Phase::Booted as u32
    );
    // A is already published and booted; an operator may have removed its
    // redundant B workspace. Missing data alone is not rename authority.
    fake.datasets.retain(|member| {
        member.name != staging() && !member.name.starts_with(&format!("{}/", staging()))
    });
    fake.snapshots.retain(|point| {
        !point.name.starts_with(&format!("{}/", staging()))
            && !point.name.starts_with(&format!("{}@", staging()))
    });
    assert!(resume(&mut fake).unwrap());
    assert!(super::record(&mut fake, ID).unwrap().is_none());
}

#[test]
fn kept_volumes_remain_inert_in_staging_and_recover_local_received_and_inherited_modes() {
    let mut world = world();
    world
        .dataset_mut("rpool")
        .local
        .insert("volmode".into(), "dev".into());
    world.add("rpool/volume", &[]);
    world.dataset_mut("rpool/volume").volume = true;
    for (name, mode) in [
        ("hidden", "none"),
        ("local", "full"),
        ("received", "dev"),
        ("inherited", ""),
    ] {
        let dataset = format!("rpool/home/{name}");
        world.add(&dataset, &[]);
        let volume = world.dataset_mut(&dataset);
        volume.volume = true;
        match name {
            "inherited" => {}
            "received" => {
                volume.received.insert("volmode".into(), mode.into());
            }
            _ => {
                volume.local.insert("volmode".into(), mode.into());
            }
        }
    }
    let mut request = request();
    request.keep.push("rpool/volume".into());
    let plan = plan(&mut world, &request, ID).unwrap();
    let mut baseline = world.clone();
    Run::start(&mut baseline, &plan, &mut Vec::new()).unwrap();
    let expected = baseline.normalized();
    let check = |fake: &Fake| {
        for (relative, mode) in [
            ("volume", "dev"),
            ("home/hidden", "none"),
            ("home/local", "full"),
            ("home/received", "dev"),
            ("home/inherited", "dev"),
        ] {
            assert_eq!(
                value(fake, &format!("{}/{relative}", staging()), "volmode")
                    .unwrap()
                    .0,
                "none"
            );
            let mut imported = fake.clone();
            for pool in &mut imported.pools {
                pool.imported = true;
            }
            assert_eq!(
                value(&imported, &format!("rpool/{relative}"), "volmode")
                    .unwrap()
                    .0,
                mode
            );
            assert_eq!(
                value(&imported, &format!("rpool/{relative}"), "volmode")
                    .unwrap()
                    .1,
                if relative == "home/inherited" {
                    "inherited from rpool/home"
                } else {
                    "local"
                },
            );
        }
    };
    check(&baseline);
    for at in 0..baseline.effects.len() {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = world.clone();
            fake.cut = Some((at, cut));
            let _ = Run::start(&mut fake, &plan, &mut Vec::new());
            fake.restart();
            if !resume(&mut fake).unwrap() && at == 0 && matches!(cut, Cut::Before) {
                Run::start(&mut fake, &plan, &mut Vec::new()).unwrap();
            }
            assert_eq!(fake.normalized(), expected, "{at} {cut:?}");
            check(&fake);
        }
    }
}

#[test]
fn abandon_releases_renamed_source_holds_and_survives_every_cleanup_cut() {
    let mut cut_world = world();
    let plan = plan(&mut cut_world, &request(), ID).unwrap();
    cut_world.cut = Some((fake_effect_index(&plan, "wipe"), Cut::After));
    assert!(Run::start(&mut cut_world, &plan, &mut Vec::new()).is_err());
    cut_world.restart();
    for dataset in &mut cut_world.datasets {
        if dataset.name.starts_with("bpool/ROOT/debian") {
            dataset.name = dataset
                .name
                .replacen("bpool/ROOT/debian", "bpool/ROOT/renamed", 1);
        }
    }
    for snapshot in &mut cut_world.snapshots {
        if snapshot.name.starts_with("bpool/ROOT/debian@") {
            snapshot.name = snapshot
                .name
                .replacen("bpool/ROOT/debian", "bpool/ROOT/renamed", 1);
            snapshot.holds.push("other-reader".into());
        }
    }
    let start = cut_world.effects.len();
    let mut baseline = cut_world.clone();
    abandon(&mut baseline, ID).unwrap();
    let end = baseline.effects.len();
    for at in start..end {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = cut_world.clone();
            fake.cut = Some((at, cut));
            let _ = abandon(&mut fake, ID);
            fake.restart();
            if !list(&mut fake).unwrap().operations.is_empty() {
                abandon(&mut fake, ID).unwrap();
            }
            assert_eq!(fake.normalized(), baseline.normalized(), "{at} {cut:?}");
            for snapshot in &fake.snapshots {
                if snapshot.name.starts_with("bpool/ROOT/renamed@") {
                    assert!(!snapshot.holds.contains(&format!("zboot:restore:{ID}")));
                    assert!(snapshot.holds.contains(&"other-reader".to_owned()));
                }
            }
        }
    }
}

#[test]
fn resume_lists_records_and_orphaned_attachments() {
    use super::{Orphan, PoolRecord};
    const ENDED: &str = "fedcba9876543210";
    const LATER: &str = "abcdef0123456789";
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.corrupt = Some(staging());
    let mut out = Vec::new();
    assert!(Run::start(&mut fake, &plan, &mut out).is_err());
    let chunks = |fake: &mut Fake, dataset: &str, id: &str| {
        for index in 0..2 {
            fake.dataset_mut(dataset).local.insert(
                format!("zboot:attachment:{id}:receipt:{index:04x}"),
                "00".into(),
            );
        }
    };
    // A receipt written before its commit by a restore whose record has
    // since ended, on a dataset no longer its staging, on a pool with no
    // record: nothing names it.
    fake.add_pool("cpool", "259:32", 1 << 30);
    fake.add("cpool/old", &[]);
    chunks(&mut fake, "cpool/old", ENDED);
    // The same on B, whose record is the live restore's: never named by it.
    chunks(&mut fake, "bpool/ROOT", ENDED);
    // A later zboot's restore: its record does not decode here, so its
    // receipt may be the only record of A's properties.
    fake.add_pool("dpool", "259:48", 1 << 30);
    fake.add("dpool/zboot-restore-abcdef0123456789", &[]);
    fake.dataset_mut("dpool").local.insert(
        "zboot:operation".into(),
        format!(r#"{{"schema_version":2,"id":"{LATER}","kind":"restore","step":9,"state":{{}}}}"#),
    );
    chunks(&mut fake, "dpool/zboot-restore-abcdef0123456789", LATER);
    // A live operation's attachment carries the record's id and is not
    // reported.
    fake.dataset_mut("bpool/ROOT")
        .local
        .insert(format!("zboot:attachment:{ID}:receipt:0000"), "00".into());
    let listing = list(&mut fake).unwrap();
    assert_eq!(listing.operations.len(), 2);
    assert_eq!(listing.operations[0].id.as_deref(), Some(ID));
    assert_eq!(
        listing.operations[0].step.as_deref(),
        Some(Phase::Quiesced.name())
    );
    assert_eq!(listing.operations[1].id, None);
    let orphan = |dataset: &str, id: &str, pool: &str, record| Orphan {
        dataset: dataset.into(),
        attachment: format!("{id}:receipt"),
        pool: pool.into(),
        record,
    };
    assert_eq!(
        listing.orphans,
        [
            orphan("bpool/ROOT", ENDED, "bpool", PoolRecord::Other(ID.into())),
            orphan("cpool/old", ENDED, "cpool", PoolRecord::Nothing),
            orphan(
                "dpool/zboot-restore-abcdef0123456789",
                LATER,
                "dpool",
                PoolRecord::Unreadable
            ),
        ]
    );
    // Only the orphan on a pool that records nothing is offered for removal.
    let told: Vec<String> = listing.orphans.iter().map(Orphan::describe).collect();
    assert!(!told[0].contains("zfs inherit"), "{}", told[0]);
    assert!(told[0].contains(&format!("pool bpool records operation {ID}")));
    assert!(told[1].ends_with(&format!(
        "remove it with {}",
        super::orphan_cleanup("cpool/old", &format!("{ENDED}:receipt"))
    )));
    assert_eq!(
        told[2],
        format!(
            "attachment {LATER}:receipt on dpool/zboot-restore-abcdef0123456789 belongs to the \
             unreadable operation record on pool dpool; do not remove it"
        )
    );
    let error = resume_plan(&mut fake, ENDED).unwrap_err().to_string();
    assert!(error.contains("no restore operation"), "{error}");
    assert!(resume_plan(&mut fake, "ffffffffffffffff").is_err());
    // The live record still resolves beside its attachment.
    assert_eq!(resume_plan(&mut fake, ID).unwrap().id, ID);
    let (pool, record) = super::record(&mut fake, ID).unwrap().unwrap();
    assert_eq!(
        (pool.as_str(), record.kind.as_str()),
        ("bpool", super::KIND)
    );
}

#[test]
fn a_reboot_after_erasure_imports_the_new_pool_by_guid() {
    let (expected, _) = baseline();
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    let index = fake_effect_index(&plan, "send bpool/zboot");
    fake.cut = Some((index, Cut::Before));
    let mut out = Vec::new();
    assert!(Run::start(&mut fake, &plan, &mut out).is_err());
    fake.restart();
    for pool in &mut fake.pools {
        pool.imported = pool.name == "bpool";
    }
    assert_eq!(resume_plan(&mut fake, ID).unwrap().token, None);
    assert!(resume(&mut fake).unwrap());
    assert_eq!(fake.normalized(), expected);
}

#[test]
fn a_scrub_with_errors_stops_before_erasure() {
    let mut fake = world();
    fake.scrub_errors = 2;
    let error = start(&mut fake).unwrap_err().to_string();
    assert!(error.contains("found 2 errors"), "{error}");
    assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));
    fake.scrub_errors = 0;
    assert!(resume(&mut fake).unwrap());
}

#[test]
fn an_explicit_snapshot_is_adopted_and_must_be_recursive() {
    let mut fake = world();
    fake.running_root = None;
    let mut request = request();
    request.source = "bpool/ROOT/debian@old".into();
    let plan = plan(&mut fake, &request, ID).unwrap();
    assert!(!plan.state.created);
    let mut out = Vec::new();
    Run::start(&mut fake, &plan, &mut out).unwrap();
    assert!(
        fake.snapshot_ref(&format!("bpool/ROOT/debian@zboot-restore-{ID}"))
            .is_none()
    );
    assert!(
        !fake
            .effects
            .iter()
            .any(|e| e.starts_with("snapshot bpool/"))
    );
    assert!(
        fake.effects
            .iter()
            .any(|e| e == "send bpool/ROOT/debian@old | receive rpool/ROOT/debian")
    );

    let mut fake = world();
    fake.snap("bpool/ROOT/debian@top", false);
    request.source = "bpool/ROOT/debian@top".into();
    let error = plan_error(&mut fake, &request);
    assert!(error.contains("not recursive"), "{error}");
    assert_eq!(HOSTID, fake.hostid);
}

/// Restore's streams are the acceptance pipeline: `send -w` of one snapshot,
/// or `-I` from the copy's newest, into the host's `zfs receive -u`, a new
/// copy taking only an inactive `canmount` and its write-time values.
#[test]
fn stream_argv_is_the_acceptance_pipeline() {
    let mut fake = world();
    fake.dataset_mut("rpool/home")
        .local
        .insert("copies".into(), "2".into());
    start(&mut fake).unwrap();
    let staged = format!("{}/home", staging());
    let streams: Vec<_> = fake
        .effects
        .iter()
        .filter(|e| e.ends_with(&format!(" | receive {staged}")))
        .cloned()
        .collect();
    assert_eq!(
        streams,
        [
            format!("send rpool/home@daily | receive {staged}"),
            format!("send -I rpool/home@daily rpool/home@zboot-restore-{ID} | receive {staged}"),
        ]
    );
    let view = super::Backend::view(&mut fake).unwrap();
    let point = |name: &str| view.snapshot(name).unwrap().point.clone();
    let source = zfs_tools::engine::management::Endpoint {
        name: staged.clone(),
        identity: view.dataset(&staged).unwrap().identity.clone(),
    };
    let full = zfs_tools::engine::stream::LeafStream {
        source: source.clone(),
        base: None,
        boundary: point(&format!("{staged}@daily")),
        destination: "rpool2/home".into(),
        create: super::manifest::creation(
            false,
            &super::manifest::capture(view.dataset(&staged).unwrap()),
        ),
    };
    assert_eq!(
        zfs_tools::engine::stream::leaf_arguments(&full).unwrap(),
        (
            vec!["send".into(), "-w".into(), format!("{staged}@daily")],
            vec![
                "receive".to_string(),
                "-u".into(),
                "-o".into(),
                "canmount=off".into(),
                "-o".into(),
                "copies=2".into(),
                "-o".into(),
                "compression=zstd".into(),
                "rpool2/home".into(),
            ]
        )
    );
    let incremental = zfs_tools::engine::stream::LeafStream {
        base: Some(point(&format!("{staged}@daily"))),
        boundary: point(&format!("{staged}@zboot-restore-{ID}")),
        create: Vec::new(),
        ..full
    };
    assert_eq!(
        zfs_tools::engine::stream::leaf_arguments(&incremental).unwrap(),
        (
            vec![
                "send".into(),
                "-w".into(),
                "-I".into(),
                format!("{staged}@daily"),
                format!("{staged}@zboot-restore-{ID}"),
            ],
            vec!["receive".to_string(), "-u".into(), "rpool2/home".into()]
        )
    );
}

/// Any zboot stick restores any host: a Menu that adopted nothing (hostid
/// zero) still gives A the BE's hostid at every import, the deploy's
/// creation included.
#[test]
fn a_is_imported_under_the_bes_hostid_from_any_menu() {
    let (expected, _) = baseline();
    let mut fake = world();
    fake.spl_hostid = "00000000".into();
    start(&mut fake).unwrap();
    let rpool = fake.pools.iter().find(|p| p.name == "rpool").unwrap();
    assert_eq!(rpool.hostid, HOSTID);
    assert!(fake.effects.iter().any(|e| e.starts_with("import ")));
    // The same A as a run under the BE's own hostid builds.
    assert_eq!(fake.normalized(), expected);
}

/// A late resume can find A already writable: the UKI's pool access reopened
/// it. Under a Menu that adopted nothing that import recorded no hostid, so
/// resume imports A again under the BE's.
#[test]
fn a_resume_reimports_a_writable_a_that_recorded_no_hostid() {
    let erased = record_reaching(Phase::Erased);
    let mut fake = cut_at(erased, Cut::After);
    fake.spl_hostid = "00000000".into();
    let rpool = fake
        .pools
        .iter_mut()
        .find(|p| p.name == "rpool" && p.imported)
        .unwrap();
    rpool.readonly = false;
    rpool.hostid = "00000000".into();
    assert!(resume(&mut fake).unwrap());
    let rpool = fake.pools.iter().find(|p| p.name == "rpool").unwrap();
    assert_eq!(rpool.hostid, HOSTID);
}

/// The identity is carried through resume: a running hostid that changed to
/// another host's refuses before the erase and before any import of A.
#[test]
fn a_resume_under_another_hostid_refuses_before_erasing_or_importing() {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.spl_hostid = "11111111".into();
    let mut out = Vec::new();
    let error = Run::start(&mut fake, &plan, &mut out)
        .unwrap_err()
        .to_string();
    assert!(error.contains("the running hostid is 11111111"), "{error}");
    assert!(fake.effects.is_empty(), "{:?}", fake.effects);

    // Cut once A is created and recorded: the next step imports it.
    let erased = record_reaching(Phase::Erased);
    let mut fake = cut_at(erased, Cut::After);
    let imports = |fake: &Fake| {
        fake.effects
            .iter()
            .filter(|e| e.starts_with("import "))
            .count()
    };
    let before = (fake.effects.len(), imports(&fake));
    fake.spl_hostid = "11111111".into();
    let error = resume_plan(&mut fake, ID).unwrap_err().to_string();
    assert!(error.contains("the running hostid is 11111111"), "{error}");
    let error = Run::resume(&mut fake, ID, None, &mut Vec::new())
        .unwrap_err()
        .to_string();
    assert!(error.contains("the running hostid is 11111111"), "{error}");
    assert_eq!((fake.effects.len(), imports(&fake)), before);
    fake.spl_hostid = HOSTID.into();
    assert_eq!(
        resume_plan(&mut fake, ID).unwrap().step,
        Phase::Erased.name()
    );
    assert!(resume(&mut fake).unwrap());
    let rpool = fake.pools.iter().find(|p| p.name == "rpool").unwrap();
    assert_eq!(rpool.hostid, HOSTID);
}

/// A hibernation image stops the restore before its first write and again
/// before the erase.
#[test]
fn a_hibernation_image_stops_the_restore_before_writing() {
    let mut fake = world();
    let plan = plan(&mut fake, &request(), ID).unwrap();
    fake.hibernation = Some("/dev/fake-c2".into());
    let mut out = Vec::new();
    let error = Run::start(&mut fake, &plan, &mut out)
        .unwrap_err()
        .to_string();
    assert!(error.contains("hibernation image"), "{error}");
    assert!(fake.effects.is_empty(), "{:?}", fake.effects);

    let mut fake = cut_at(fake_effect_index_nth("wipe", 0), Cut::Before);
    let effects = fake.effects.len();
    fake.hibernation = Some("/dev/fake-c2".into());
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains("hibernation image"), "{error}");
    assert_eq!(
        fake.effects.len(),
        effects,
        "{:?}",
        &fake.effects[effects..]
    );
}

#[test]
fn staging_beneath_a_bootable_pool_root_is_refused_before_effects_and_on_resume() {
    for default in [false, true] {
        let mut fake = world();
        if default {
            fake.pools
                .iter_mut()
                .find(|p| p.name == "bpool")
                .unwrap()
                .bootfs = Some("bpool".into());
        } else {
            fake.dataset_mut("bpool")
                .local
                .insert("mountpoint".into(), "/".into());
        }
        let error = plan_error(&mut fake, &request());
        assert!(error.contains("restore staging must be outside"), "{error}");
        assert!(fake.effects.is_empty());
    }
    // The parent can change after preview, or after a durable record exists.
    let mut fake = world();
    let p = plan(&mut fake, &request(), ID).unwrap();
    fake.dataset_mut("bpool")
        .local
        .insert("mountpoint".into(), "/".into());
    let error = Run::start(&mut fake, &p, &mut Vec::new())
        .unwrap_err()
        .to_string();
    assert!(error.contains("restore staging must be outside"), "{error}");
    assert!(fake.effects.is_empty());
    fake.dataset_mut("bpool")
        .local
        .insert("mountpoint".into(), "none".into());
    fake.cut = Some((0, Cut::After));
    assert!(Run::start(&mut fake, &p, &mut Vec::new()).is_err());
    fake.restart();
    fake.dataset_mut("bpool")
        .local
        .insert("mountpoint".into(), "/".into());
    let effects = fake.effects.len();
    let error = Run::resume(&mut fake, ID, None, &mut Vec::new())
        .unwrap_err()
        .to_string();
    assert!(error.contains("restore staging must be outside"), "{error}");
    assert_eq!(fake.effects.len(), effects);
}

#[test]
fn restore_preserves_disabled_be_descendants_from_live_or_fenced_placement() {
    use zfs_tools::engine::management::{MountMode, Placement};
    for fenced in [false, true] {
        let mut fake = world();
        if fenced {
            for (name, mode) in [
                ("bpool/ROOT/debian", MountMode::NoAuto),
                ("bpool/ROOT/debian/var", MountMode::Off),
            ] {
                let identity = super::Backend::view(&mut fake)
                    .unwrap()
                    .dataset(name)
                    .unwrap()
                    .identity
                    .clone();
                let original = Placement {
                    schema_version: 1,
                    identity,
                    readonly: false,
                    canmount: Some(mode),
                    volmode: None,
                };
                let member = fake.dataset_mut(name);
                member
                    .local
                    .insert("zboot:placement".into(), original.encode().unwrap());
                member.local.insert("canmount".into(), "noauto".into());
                member.local.insert("readonly".into(), "on".into());
                member.mounted = false;
            }
            fake.secondaries.insert("bpool/ROOT/debian".into());
            let pair = pair_record(
                &mut fake,
                "bpool/ROOT/debian",
                "rpool/ROOT/debian",
                Some(4242),
            );
            fake.dataset_mut("bpool/ROOT/debian")
                .local
                .insert("zboot:pair".into(), pair.encode().unwrap());
            fake.running_root = None;
        } else {
            fake.dataset_mut("bpool/ROOT/debian/var")
                .local
                .insert("canmount".into(), "off".into());
        }
        let source_before = value(&fake, "bpool/ROOT/debian/var", "canmount");
        let mut request = request();
        request.source = "bpool/ROOT/debian@old".into();
        let planned = plan(&mut fake, &request, ID).unwrap();
        Run::start(&mut fake, &planned, &mut Vec::new()).unwrap();
        for p in &mut fake.pools {
            if p.name == "rpool" {
                p.imported = true;
            }
        }
        assert_eq!(
            value(&fake, "rpool/ROOT/debian", "canmount").unwrap().0,
            "noauto"
        );
        assert_eq!(
            value(&fake, "rpool/ROOT/debian/var", "canmount").unwrap().0,
            "off"
        );
        assert!(!fake.find("rpool/ROOT/debian/var").unwrap().mounted);
        assert_eq!(
            value(&fake, "bpool/ROOT/debian/var", "canmount"),
            source_before
        );
    }
}

#[test]
fn a_source_be_automount_hazard_refuses_before_restore_effects_and_before_resume() {
    for name in ["bpool/ROOT/debian", "bpool/ROOT/debian/var"] {
        let mut fake = world();
        fake.dataset_mut(name)
            .local
            .insert("canmount".into(), "on".into());
        let error = plan_error(&mut fake, &request());
        assert!(
            error.contains(name) && error.contains("before restoring"),
            "{error}"
        );
        assert!(fake.effects.is_empty());
    }
    let mut fake = world();
    let p = plan(&mut fake, &request(), ID).unwrap();
    fake.dataset_mut("bpool/ROOT/debian/var")
        .local
        .insert("canmount".into(), "on".into());
    let error = Run::start(&mut fake, &p, &mut Vec::new())
        .unwrap_err()
        .to_string();
    assert!(error.contains("before restoring"), "{error}");
    assert!(fake.effects.is_empty());
    fake.dataset_mut("bpool/ROOT/debian/var")
        .local
        .insert("canmount".into(), "noauto".into());
    fake.cut = Some((0, Cut::After));
    assert!(Run::start(&mut fake, &p, &mut Vec::new()).is_err());
    fake.restart();
    for name in ["bpool/ROOT/debian", "bpool/ROOT/debian/var"] {
        let mut interrupted = fake.clone();
        interrupted
            .dataset_mut(name)
            .local
            .insert("canmount".into(), "on".into());
        let before = interrupted.normalized();
        let record_before = super::record(&mut interrupted, ID).unwrap();
        let effects = interrupted.effects.len();
        let error = Run::resume(&mut interrupted, ID, None, &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(error.contains("before restoring"), "{error}");
        assert_eq!(interrupted.effects.len(), effects);
        assert_eq!(interrupted.normalized(), before);
        assert_eq!(super::record(&mut interrupted, ID).unwrap(), record_before);
    }
}

/// Give `to` a snapshot `@name` with the same GUID as `from@name`, as a raw
/// copy has it.
fn share_snapshot(fake: &mut Fake, from: &str, to: &str, name: &str) {
    let source = fake
        .snapshot_ref(&format!("{from}@{name}"))
        .unwrap()
        .clone();
    let target = fake.dataset_ref(to).clone();
    fake.snapshots.push(super::fake::FSnapshot {
        name: format!("{to}@{name}"),
        pool: target.pool,
        dataset_guid: target.guid,
        guid: source.guid,
        txg: source.txg + 1,
        holds: Vec::new(),
        defer_destroy: false,
    });
}

const PHOTOS_PAIR: &str = "1b8f2c1e-3d4a-4b5c-9d6e-7f8091a2b3c4";
const MUSIC_PAIR: &str = "2b8f2c1e-3d4a-4b5c-9d6e-7f8091a2b3c4";

/// A's `rpool/data` holds two paired leaves whose peers are on B: `photos`
/// is the fenced copy of B's working `bpool/data/photos`, `music` the working
/// copy of B's fenced `bpool/data/music`. Each pair's anchor is held on both
/// sides.
fn paired_leaves() -> (Fake, Request) {
    use zfs_tools::engine::management::{MountMode, PairRecord, Placement, Role};
    let mut fake = world();
    fake.add(
        "rpool/data",
        &[("canmount", "off"), ("mountpoint", "/data")],
    );
    fake.add(
        "bpool/data",
        &[("canmount", "off"), ("mountpoint", "/data")],
    );
    for leaf in ["photos", "music"] {
        fake.add(&format!("bpool/data/{leaf}"), &[]);
        fake.snap(&format!("bpool/data/{leaf}@anchor"), false);
        fake.add(&format!("rpool/data/{leaf}"), &[]);
        share_snapshot(
            &mut fake,
            &format!("bpool/data/{leaf}"),
            &format!("rpool/data/{leaf}"),
            "anchor",
        );
    }
    let view = super::Backend::view(&mut fake).unwrap();
    let endpoint = |name: &str| zfs_tools::engine::management::Endpoint {
        name: name.into(),
        identity: view.dataset(name).unwrap().identity.clone(),
    };
    for (leaf, id, a_role) in [
        ("photos", PHOTOS_PAIR, Role::Secondary),
        ("music", MUSIC_PAIR, Role::Primary),
    ] {
        let a = format!("rpool/data/{leaf}");
        let b = format!("bpool/data/{leaf}");
        let record = PairRecord {
            schema_version: 1,
            pair_id: id.into(),
            endpoint: endpoint(&a),
            peer: endpoint(&b),
            role: a_role,
        };
        let fenced = if a_role == Role::Secondary { &a } else { &b };
        let placement = Placement {
            schema_version: 1,
            identity: view.dataset(fenced).unwrap().identity.clone(),
            readonly: false,
            canmount: Some(MountMode::On),
            volmode: None,
        };
        fake.dataset_mut(fenced).local.extend([
            ("readonly".into(), "on".into()),
            ("canmount".into(), "noauto".into()),
            ("zboot:placement".into(), placement.encode().unwrap()),
        ]);
        fake.dataset_mut(&a)
            .local
            .insert("zboot:pair".into(), record.encode().unwrap());
        fake.dataset_mut(&b)
            .local
            .insert("zboot:pair".into(), record.counterpart().encode().unwrap());
        for side in [&a, &b] {
            fake.snapshots
                .iter_mut()
                .find(|s| s.name == format!("{side}@anchor"))
                .unwrap()
                .holds
                .push(format!("zboot:anchor:{id}"));
        }
    }
    let mut request = request();
    request.keep.push("rpool/data".into());
    (fake, request)
}

/// Kept trees may hold paired leaves. Each returns as a new incarnation,
/// unpaired, in its former role; the peer's record on B is ended one-sided
/// after the erase, as `unpair` does with a gone peer, its anchor holds
/// kept; and a former fenced copy loses this restore's own snapshot, so the
/// two sides' newest common snapshot is their anchor again.
#[test]
fn paired_kept_leaves_return_unpaired_in_their_role_and_end_their_peers_records() {
    let (mut fake, request) = paired_leaves();
    let plan = plan(&mut fake, &request, ID).unwrap();
    let ended: Vec<_> = plan
        .state
        .ended_pairs
        .iter()
        .map(|e| {
            (
                e.owner.name.as_str(),
                e.peer.name.as_str(),
                e.role,
                e.pair_id.as_str(),
            )
        })
        .collect();
    use zfs_tools::engine::management::Role;
    assert_eq!(
        ended,
        [
            (
                "bpool/data/music",
                "rpool/data/music",
                Role::Secondary,
                MUSIC_PAIR
            ),
            (
                "bpool/data/photos",
                "rpool/data/photos",
                Role::Primary,
                PHOTOS_PAIR
            ),
        ]
    );
    let shown = render(&plan);
    for (peer, member, role) in [
        (
            "bpool/data/photos",
            "rpool/data/photos",
            "fenced, with its saved placement",
        ),
        ("bpool/data/music", "rpool/data/music", "active"),
    ] {
        assert!(
            shown.contains(&format!("{peer} is paired with {member}"))
                && shown.contains(&format!("{member} returns unpaired and {role}")),
            "{shown}"
        );
    }
    assert!(super::intent::encode(&plan.intent()).unwrap().len() < super::intent::LIMIT);
    let mut out = Vec::new();
    let done = Run::start(&mut fake, &plan, &mut out).unwrap();
    let wipe = fake
        .effects
        .iter()
        .position(|e| e.starts_with("wipe "))
        .unwrap();
    for b in ["bpool/data/photos", "bpool/data/music"] {
        let ended = fake
            .effects
            .iter()
            .position(|e| e == &format!("inherit zboot:pair {b}"))
            .unwrap();
        assert!(ended > wipe, "{b}'s record ended before the erase");
        assert_eq!(value(&fake, b, "zboot:pair"), None);
        assert!(
            done.notes
                .iter()
                .any(|n| n.contains(&format!("{b} is no longer paired"))),
            "{:?}",
            done.notes
        );
    }
    for pool in &mut fake.pools {
        pool.imported = true;
    }
    // Both sides keep the anchor held: the peer its own hold, the returned
    // copy the same tag on the snapshot with the anchor's GUID, so a copied
    // retention policy cannot prune what `pair` needs to join them again.
    for (id, side) in [
        (PHOTOS_PAIR, "bpool/data/photos"),
        (MUSIC_PAIR, "bpool/data/music"),
        (PHOTOS_PAIR, "rpool/data/photos"),
        (MUSIC_PAIR, "rpool/data/music"),
    ] {
        assert!(
            fake.snapshot_ref(&format!("{side}@anchor"))
                .unwrap()
                .holds
                .contains(&format!("zboot:anchor:{id}")),
            "{side} lacks its anchor hold"
        );
    }
    let restore_snapshot = format!("zboot-restore-{ID}");
    // The former fenced copy: fenced with its saved placement, rebound to
    // the new incarnation, its newest snapshot the anchor its peer has.
    let photos = "rpool/data/photos";
    assert_eq!(value(&fake, photos, "zboot:pair"), None);
    assert_eq!(
        value(&fake, photos, "readonly"),
        Some(("on".into(), "local".into()))
    );
    assert_eq!(
        value(&fake, photos, "canmount"),
        Some(("noauto".into(), "local".into()))
    );
    let placement = zfs_tools::engine::management::Placement::parse(
        &value(&fake, photos, "zboot:placement").unwrap().0,
    )
    .unwrap();
    assert_eq!(placement.identity.guid.get(), fake.dataset_ref(photos).guid);
    assert!(
        fake.snapshot_ref(&format!("{photos}@{restore_snapshot}"))
            .is_none()
    );
    let newest = fake
        .snapshots
        .iter()
        .filter(|s| s.dataset_guid == fake.dataset_ref(photos).guid)
        .max_by_key(|s| s.txg)
        .unwrap();
    assert_eq!(newest.guid, guid(&fake, "bpool/data/photos@anchor"));
    assert!(
        fake.effects
            .iter()
            .any(|e| e == &format!("destroy {photos}@{restore_snapshot}"))
    );
    // The former working copy: active, unpaired, its restore snapshot kept.
    let music = "rpool/data/music";
    assert_eq!(value(&fake, music, "zboot:pair"), None);
    assert_eq!(value(&fake, music, "readonly").unwrap().0, "off");
    assert_eq!(value(&fake, music, "canmount").unwrap().0, "on");
    assert_eq!(value(&fake, music, "zboot:placement"), None);
    assert!(
        fake.snapshot_ref(&format!("{music}@{restore_snapshot}"))
            .is_some()
    );
    assert_eq!(
        guid(&fake, &format!("{music}@anchor")),
        guid(&fake, "bpool/data/music@anchor")
    );

    // Every cut converges to the same restore, both records ended once.
    let (fresh, request) = paired_leaves();
    let mut reference = fresh.clone();
    let plan = super::plan(&mut reference, &request, ID).unwrap();
    Run::start(&mut reference, &plan, &mut Vec::new()).unwrap();
    let expected = reference.normalized();
    for (index, effect) in reference.effects.iter().enumerate() {
        for cut in [Cut::Before, Cut::After, Cut::Lost] {
            let mut fake = fresh.clone();
            let plan = super::plan(&mut fake, &request, ID).unwrap();
            fake.cut = Some((index, cut));
            let mut result = Run::start(&mut fake, &plan, &mut Vec::new()).map(drop);
            let mut attempts = 0;
            while result.is_err() {
                attempts += 1;
                assert!(attempts < 6, "{cut:?} at {index}: {result:?}");
                fake.restart();
                result = match resume(&mut fake) {
                    Ok(false) if fake.effects.len() <= 1 => {
                        Run::start(&mut fake, &plan, &mut Vec::new()).map(drop)
                    }
                    other => other.map(drop),
                };
            }
            assert_eq!(fake.normalized(), expected, "{cut:?} at {index} ({effect})");
        }
    }
}

/// A peer whose pair record the plan ends must still be there, as planned,
/// when A is erased: before the wipe a gone, replaced or re-paired owner
/// refuses with A whole. After the wipe nothing may stop the restore: such
/// an owner is reported and left as it is, by resume and by abandon alike,
/// and its returned leaf, whose anchor restore cannot find, is reported too.
#[test]
fn a_missing_pair_owner_refuses_before_the_wipe_and_is_reported_after_it() {
    let (fresh, request) = paired_leaves();
    let plan = plan(&mut fresh.clone(), &request, ID).unwrap();
    let wipe = effect_in(&fresh, &plan, "wipe");
    let photos = "bpool/data/photos";
    let remove = |fake: &mut Fake| {
        let guid = fake.dataset_ref(photos).guid;
        fake.datasets.retain(|d| d.name != photos);
        fake.snapshots.retain(|s| s.dataset_guid != guid);
    };
    type Change<'a> = (&'a str, &'a dyn Fn(&mut Fake));
    let changes: [Change; 3] = [
        ("bpool/data/photos is not imported, or was removed", &remove),
        ("bpool/data/photos was replaced", &|f| {
            f.dataset_mut(photos).guid += 1000;
        }),
        (
            "bpool/data/photos's pair record changed since the plan",
            &|f| {
                f.dataset_mut(photos)
                    .local
                    .insert("zboot:pair".into(), "{}".into());
            },
        ),
    ];
    for (expect, change) in &changes {
        let mut stopped = stopped_at(&fresh, &plan, wipe, Cut::Before);
        change(&mut stopped);
        let before = stopped.effects.len();
        let error = resume(&mut stopped).unwrap_err().to_string();
        assert!(
            error.contains(expect) && error.contains("nothing was erased"),
            "{expect}: {error}"
        );
        assert!(
            !stopped.effects[before..]
                .iter()
                .any(|e| e.starts_with("wipe"))
        );
    }

    // After the wipe: reported, and the restore completes.
    let mut erased = stopped_at(&fresh, &plan, wipe, Cut::After);
    remove(&mut erased);
    let mut abandoned = erased.clone();
    let resumed = resume_plan(&mut erased, ID).unwrap();
    let done = Run::resume(
        &mut erased,
        ID,
        resumed.erase_layout().unwrap(),
        &mut Vec::new(),
    )
    .unwrap();
    for expect in [
        "bpool/data/photos is not imported, or was removed, so restore left its pair record as it is",
        "bpool/data/music is no longer paired",
        "rpool/data/photos came back without its pair's anchor",
    ] {
        assert!(
            done.notes.iter().any(|n| n.contains(expect)),
            "{expect}: {:?}",
            done.notes
        );
    }
    assert_eq!(value(&erased, "bpool/data/music", "zboot:pair"), None);
    for pool in &mut erased.pools {
        pool.imported = true;
    }
    assert!(
        erased
            .snapshot_ref("rpool/data/music@anchor")
            .unwrap()
            .holds
            .contains(&format!("zboot:anchor:{MUSIC_PAIR}"))
    );

    // Abandoned there instead: the same.
    let left = abandon(&mut abandoned, ID).unwrap().left;
    assert!(
        left.iter().any(|n| n.contains(
            "bpool/data/photos is not imported, or was removed, so its pair record with rpool/data/photos"
        )) && left.iter().any(|n| n.contains("bpool/data/music is no longer paired")),
        "{left:?}"
    );
    assert_eq!(value(&abandoned, "bpool/data/music", "zboot:pair"), None);
    assert!(list(&mut abandoned).unwrap().operations.is_empty());
}

/// Under the BE rule a dataset made under the source BE after it was
/// snapshotted is not part of it: it is left out and reported, and it never
/// stops a restore, least of all once A is erased.
#[test]
fn a_child_made_under_the_source_be_after_its_snapshot_is_left_out() {
    let (expected, _) = baseline();
    for phase in [Phase::Snapshotted, Phase::Erased] {
        let mut fake = cut_at(record_reaching(phase), Cut::After);
        fake.add("bpool/ROOT/debian/later", &[]);
        let plan = resume_plan(&mut fake, ID).unwrap();
        let mut out = Vec::new();
        let done = Run::resume(&mut fake, ID, plan.erase_layout().unwrap(), &mut out).unwrap();
        assert!(
            done.notes
                .iter()
                .any(|n| n.contains("bpool/ROOT/debian/later appeared under the source BE")),
            "{phase:?}: {:?}",
            done.notes
        );
        let mut imported = fake.clone();
        for pool in &mut imported.pools {
            pool.imported = true;
        }
        assert!(imported.find("rpool/ROOT/debian/later").is_none());
        assert!(imported.find("bpool/ROOT/debian/later").is_some());
        imported
            .datasets
            .retain(|d| d.name != "bpool/ROOT/debian/later");
        for pool in &mut imported.pools {
            pool.imported = pool.name != "rpool";
        }
        assert_eq!(imported.normalized(), expected, "{phase:?}");
    }
    // Before the source is snapshotted, a new member is part of what the
    // plan bound: restore stops there, with A untouched.
    let mut fake = cut_at(0, Cut::After);
    fake.add("bpool/ROOT/debian/early", &[("canmount", "noauto")]);
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains("abandon and plan again"), "{error}");
    assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));
}

/// A new copy that received data while a write-time value differed from its
/// source's (a setter failed) is discarded under the destruction rule and
/// sent again, never fixed by setting the value afterwards; written since,
/// it is never destroyed.
#[test]
fn a_new_copy_written_under_another_write_policy_is_discarded_and_sent_again() {
    let (expected, _) = baseline();
    let staged = format!("{}/home", staging());
    let after = first_stream_into(&staged);
    let mut fake = cut_at(after, Cut::After);
    fake.dataset_mut(&staged)
        .local
        .insert("compression".into(), "lz4".into());
    let before = fake.effects.len();
    assert!(resume(&mut fake).unwrap());
    let effects = &fake.effects[before..];
    let discard = effects
        .iter()
        .position(|e| e == &format!("destroy -r {staged}"))
        .expect("the copy is discarded");
    let sent = effects
        .iter()
        .position(|e| e == &fake.effects[after])
        .expect("and sent again");
    assert!(discard < sent);
    assert_eq!(fake.normalized(), expected);

    let mut fake = cut_at(after, Cut::After);
    fake.dataset_mut(&staged)
        .local
        .insert("compression".into(), "lz4".into());
    fake.dataset_mut(&staged).written = 512;
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(error.contains("not a partial copy"), "{error}");
    assert!(!fake.effects.iter().any(|e| e.starts_with("destroy")));
}

/// The manifest is the only record of the kept datasets' properties once A
/// is erased: restore checks the staged copy against it before the erase and
/// the copy returned to A before publishing anything.
#[test]
fn staged_and_returned_copies_are_verified_against_the_manifest() {
    // Staged: a write-time value no longer the source's.
    let mut fake = cut_at(record_reaching(Phase::Staged), Cut::After);
    fake.dataset_mut(&format!("{}/home/alice", staging()))
        .local
        .insert("compression".into(), "lz4".into());
    let error = resume(&mut fake).unwrap_err().to_string();
    assert!(
        error.contains("home/alice's compression is not its source's zstd"),
        "{error}"
    );
    assert!(!fake.effects.iter().any(|e| e.starts_with("wipe")));

    // Returned: a copied value or a stray user property, before roles.
    for change in ["value", "stray"] {
        let mut fake = cut_at(record_reaching(Phase::Restored), Cut::After);
        let target = fake.dataset_mut("rpool/home");
        match change {
            "value" => target.local.insert("atime".into(), "on".into()),
            _ => target.local.insert("org.example:stray".into(), "1".into()),
        };
        let error = resume(&mut fake).unwrap_err().to_string();
        assert!(
            error.contains("rpool/home does not hold its source's atime=off")
                || error.contains("rpool/home sets org.example:stray"),
            "{change}: {error}"
        );
        assert!(active_restore_state(&mut fake).receive_targets.is_none());
        assert_eq!(
            value(&fake, "rpool/home", "mountpoint"),
            Some(("none".into(), "local".into()))
        );
    }

    // Copied properties arrive as local values, user properties included,
    // and a received value on A comes back local.
    let mut fake = world();
    fake.dataset_mut("rpool/home/alice").received.extend([
        ("org.example:owner".into(), "alice".into()),
        ("copies".into(), "2".into()),
    ]);
    fake.dataset_mut("rpool/srv")
        .local
        .insert("zsnap:policy".into(), "daily".into());
    start(&mut fake).unwrap();
    for pool in &mut fake.pools {
        pool.imported = true;
    }
    assert_eq!(
        value(&fake, "rpool/home/alice", "org.example:owner"),
        Some(("alice".into(), "local".into()))
    );
    assert_eq!(
        value(&fake, "rpool/home/alice", "copies"),
        Some(("2".into(), "local".into()))
    );
    assert_eq!(
        value(&fake, "rpool/srv", "zsnap:policy"),
        Some(("daily".into(), "local".into()))
    );
    assert_eq!(
        value(&fake, "rpool/home/alice", "compression"),
        Some(("zstd".into(), "inherited from rpool/home".into()))
    );
    // Staging carries no user property: no policy acts on it.
    let staged = format!("{}/srv", staging());
    assert_eq!(value(&fake, &staged, "zsnap:policy"), None);
}

/// UKI pool access for a new restore: its plan names B, for the source, and
/// A only when kept trees are snapshotted there; A is otherwise exported for
/// the erase, never reopened.
#[test]
fn a_restore_plan_names_the_pools_it_writes() {
    for keep in [request().keep, vec![]] {
        let mut fake = world();
        let request = Request {
            keep: keep.clone(),
            ..request()
        };
        let plan = plan(&mut fake, &request, ID).unwrap();
        let walked = crate::cli::access::plan_pools(&serde_json::to_value(&plan).unwrap()).pools();
        let pool = |name: &str| {
            let pool = fake
                .pools
                .iter()
                .find(|p| p.name == name && p.imported)
                .unwrap();
            (pool.name.clone(), zfs_tools::engine::Guid::new(pool.guid))
        };
        let mut expected = std::collections::BTreeSet::from([pool("bpool")]);
        if !keep.is_empty() {
            expected.insert(pool("rpool"));
        }
        assert_eq!(walked, expected, "keep {keep:?}");
    }
}

/// A pool on A that also spans another disk is refused by the plan and by a
/// resume before the erase, before anything is staged or erased.
#[test]
fn a_target_pool_spanning_another_disk_is_refused_before_any_effect() {
    let span = |fake: &mut Fake| {
        fake.pools
            .iter_mut()
            .find(|p| p.name == "rpool" && p.imported)
            .unwrap()
            .extra_disks
            .push("259:16".into());
    };
    let mut fake = world();
    span(&mut fake);
    let error = plan(&mut fake, &request(), ID).unwrap_err().to_string();
    assert!(error.contains("spans another disk"), "{error}");
    assert!(fake.effects.is_empty());
    let mut fake = cut_at(record_reaching(Phase::Staged), Cut::After);
    resume_plan(&mut fake, ID).unwrap();
    span(&mut fake);
    let effects = fake.effects.len();
    let error = resume_plan(&mut fake, ID).unwrap_err().to_string();
    assert!(error.contains("spans another disk"), "{error}");
    assert_eq!(fake.effects.len(), effects);
}

/// After the erase a resume takes the replacement only on A alone: matching
/// its recorded name and GUID is not enough.
#[test]
fn a_resume_after_the_erase_refuses_a_replacement_off_the_recorded_disk() {
    let mut fake = cut_at(record_reaching(Phase::Restored), Cut::After);
    resume_plan(&mut fake, ID).unwrap();
    let rpool = fake
        .pools
        .iter_mut()
        .find(|p| p.name == "rpool" && p.imported)
        .unwrap();
    rpool.disk = "259:16".into();
    let error = resume_plan(&mut fake, ID).unwrap_err().to_string();
    assert!(error.contains("not on its recorded target disk"), "{error}");
}

/// The last step clears every other boot default; the plan names those
/// pools, shows them, and so has them reopened in the UKI.
#[test]
fn a_restore_plan_names_and_shows_every_default_it_clears() {
    let mut fake = world();
    fake.add_pool("cpool", "259:16", 10 * GIB);
    for pool in &mut fake.pools {
        if pool.name == "cpool" || pool.name == "bpool" {
            pool.bootfs = Some(format!("{}/ROOT/x", pool.name));
        }
    }
    let plan = plan(&mut fake, &request(), ID).unwrap();
    let names: Vec<_> = plan.state.clears.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["bpool", "cpool"]);
    assert!(render(&plan).contains("Clears the boot default on pool cpool"));
    let walked = crate::cli::access::plan_pools(&serde_json::to_value(&plan).unwrap()).pools();
    assert!(walked.iter().any(|(name, _)| name == "cpool"), "{walked:?}");
}
