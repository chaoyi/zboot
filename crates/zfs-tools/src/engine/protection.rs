//! Identity-bound protection. Native holds do not serialize rename, promotion,
//! unmount, or uncooperating writers. A failed protection never releases holds.
//! Production protect and release verify native identities across observation,
//! admission, effects and verification; injected runners are private test seams.
use crate::engine::*;
use crate::{ReaderReleasePoint, ReaderReleaseReport, ReaderReleaseStatus, ReleasePolicy};

type Runner<'a> = dyn FnMut(&'static str, &[String]) -> Result<String, Error> + 'a;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectionRequest {
    pub(crate) consumer: String,
    pub(crate) points: Vec<SnapshotRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectionLease {
    pub(crate) schema_version: u32,
    pub(crate) consumer: String,
    pub(crate) tag: String,
    pub(crate) points: Vec<SnapshotRef>,
}

/// A fresh acquisition intent, before any native observation or effect.
/// The caller records `intent()` durably before consuming this value. Its
/// points are expected targets, not evidence that protection was acquired.
pub(crate) struct PreparedProtection {
    intent: ProtectionLease,
}

impl PreparedProtection {
    pub(crate) fn prepare(request: &ProtectionRequest) -> Result<Self, ProtectionFailure> {
        validate_consumer(&request.consumer)
            .and_then(|()| validate_points(&request.points))
            .map_err(|message| ProtectionFailure {
                kind: "invalid_request".into(),
                message,
                tag: None,
                partial_lease: None,
                uncertain_names: vec![],
            })?;
        Ok(Self {
            intent: ProtectionLease {
                schema_version: 2,
                consumer: request.consumer.clone(),
                tag: format!(
                    "zctl1:{}:{}",
                    request.consumer,
                    uuid::Uuid::new_v4().simple()
                ),
                points: request.points.clone(),
            },
        })
    }

    pub(crate) fn intent(&self) -> &ProtectionLease {
        &self.intent
    }

    pub(crate) fn execute_with(
        self,
        run: &mut Runner<'_>,
    ) -> Result<ProtectionLease, ProtectionFailure> {
        let intent = self.intent;
        protect_with(
            &ProtectionRequest {
                consumer: intent.consumer,
                points: intent.points,
            },
            intent.tag,
            run,
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtectionFailure {
    pub(crate) kind: String,
    pub(crate) message: String,
    pub(crate) tag: Option<String>,
    pub(crate) partial_lease: Option<Box<ProtectionLease>>,
    pub(crate) uncertain_names: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseFailure {
    pub(crate) kind: String,
    pub(crate) message: String,
    pub(crate) report: ReaderReleaseReport,
}

fn validate_consumer(consumer: &str) -> Result<(), String> {
    if !(1..=20).contains(&consumer.len())
        || !consumer
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("consumer must contain 1–20 ASCII letters, digits, '.', '_' or '-'".into());
    }
    Ok(())
}
fn same_point(a: &SnapshotRef, b: &SnapshotRef) -> bool {
    a.dataset_guid == b.dataset_guid && a.identity == b.identity
}
fn validate_points(points: &[SnapshotRef]) -> Result<(), String> {
    if points.is_empty() {
        return Err("at least one snapshot is required".into());
    }
    for (index, point) in points.iter().enumerate() {
        validate_snapshot_name(&point.name).map_err(|e| e.to_string())?;
        if !point.is_complete() {
            return Err("snapshot identity fields must be nonzero".into());
        }
        if points[..index]
            .iter()
            .any(|other| other.name == point.name || same_point(other, point))
        {
            return Err("duplicate snapshot reference".into());
        }
    }
    Ok(())
}
pub(crate) fn validate_lease(lease: &ProtectionLease) -> Result<(), String> {
    validate_consumer(&lease.consumer)?;
    validate_points(&lease.points)?;
    if lease.schema_version != 2 {
        return Err("unsupported lease schema version".into());
    }
    let prefix = format!("zctl1:{}:", lease.consumer);
    let suffix = lease
        .tag
        .strip_prefix(&prefix)
        .ok_or("lease tag does not match its consumer/protocol")?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("lease tag must contain a canonical UUID".into());
    }
    let id = uuid::Uuid::parse_str(suffix).map_err(|_| "invalid lease UUID")?;
    if id.get_version_num() != 4 || id.get_variant() != uuid::Variant::RFC4122 {
        return Err("lease UUID must be version 4".into());
    }
    Ok(())
}

#[cfg(test)]
fn protect_validated_with(
    request: &ProtectionRequest,
    run: &mut Runner<'_>,
) -> Result<ProtectionLease, ProtectionFailure> {
    PreparedProtection::prepare(request)?.execute_with(run)
}

fn protect_with(
    request: &ProtectionRequest,
    tag: String,
    run: &mut Runner<'_>,
) -> Result<ProtectionLease, ProtectionFailure> {
    let failure = |kind: &str, message: String, started: bool| ProtectionFailure {
        kind: kind.into(),
        message,
        tag: started.then(|| tag.clone()),
        partial_lease: None,
        uncertain_names: vec![],
    };
    validate_consumer(&request.consumer)
        .and_then(|()| validate_points(&request.points))
        .map_err(|e| failure("invalid_request", e, false))?;
    let mut resolved = vec![];
    // Complete admission is required before the first effect.
    for point in &request.points {
        let snapshot = native::resolve_with(point, &mut |p, a| run(p, a))
            .map_err(|e| failure("observation", e.to_string(), false))?;
        native::admit_with(&snapshot, &mut |p, a| run(p, a))
            .map_err(|e| failure("admission", e.to_string(), false))?;
        if snapshot.holds.contains(&tag) {
            return Err(failure(
                "tag_collision",
                "generated tag already exists; ownership cannot be established".into(),
                false,
            ));
        }
        resolved.push(snapshot.point());
    }
    let mut execution_error = None;
    let mut attempted = Vec::new();
    for point in &resolved {
        let current = match native::resolve_with(point, &mut |p, a| run(p, a)) {
            Ok(value) => value,
            Err(error) => {
                execution_error = Some(error.to_string());
                break;
            }
        };
        if current.holds.contains(&tag) {
            execution_error =
                Some("generated tag appeared before acquisition; ownership uncertain".into());
            break;
        }
        if let Err(error) = native::admit_with(&current, &mut |p, a| run(p, a)) {
            execution_error = Some(error.to_string());
            break;
        }
        if let Err(error) = run("zfs", &["hold".into(), tag.clone(), current.name.clone()]) {
            execution_error = Some(error.to_string());
            break;
        }
        attempted.push(current.point());
    }
    let mut verified = vec![];
    let mut uncertain = vec![];
    for point in &resolved {
        match native::resolve_with(point, &mut |p, a| run(p, a)) {
            Ok(snapshot) if snapshot.holds.contains(&tag) => {
                if attempted.iter().any(|p| same_point(p, &snapshot.point())) {
                    verified.push(snapshot.point());
                } else {
                    uncertain.push(snapshot.name.clone());
                }
            }
            Ok(_) => {}
            Err(error) => {
                uncertain.push(point.name.clone());
                if execution_error.is_none() {
                    execution_error = Some(error.to_string());
                }
            }
        }
    }
    let lease = ProtectionLease {
        schema_version: 2,
        consumer: request.consumer.clone(),
        tag: tag.clone(),
        points: verified,
    };
    if lease.points.len() == resolved.len() && uncertain.is_empty() && execution_error.is_none() {
        return Ok(lease);
    }
    Err(ProtectionFailure {
        kind: "incomplete_pin".into(),
        message: execution_error
            .unwrap_or_else(|| "not every requested snapshot has the verified hold".into()),
        tag: Some(tag),
        partial_lease: (!lease.points.is_empty()).then(|| Box::new(lease)),
        uncertain_names: uncertain,
    })
}

pub(crate) fn release_validated_with(
    lease: &ProtectionLease,
    policy: ReleasePolicy,
    run: &mut Runner<'_>,
) -> Result<ReaderReleaseReport, ReleaseFailure> {
    let mut report = ReaderReleaseReport {
        schema_version: 2,
        tag: lease.tag.clone(),
        points: vec![],
    };
    if let Err(message) = validate_lease(lease) {
        return Err(ReleaseFailure {
            kind: "invalid_lease".into(),
            message,
            report,
        });
    }
    if policy == ReleasePolicy::PreserveSnapshots {
        for point in &lease.points {
            let admission = native::resolve_with(point, &mut |p, a| run(p, a))
                .map_err(|error| error.to_string())
                .and_then(|before| preserve_snapshot(lease, point, &before));
            if let Err(message) = admission {
                return Err(ReleaseFailure {
                    kind: "preservation_refused".into(),
                    message,
                    report,
                });
            }
        }
    }
    for point in &lease.points {
        let mut item = ReaderReleasePoint {
            point: point.clone(),
            status: ReaderReleaseStatus::Uncertain,
            released: false,
            exists_after: None,
            possible_deferred_destroy: false,
            message: None,
        };
        let before = match native::resolve_with(point, &mut |p, a| run(p, a)) {
            Ok(value) => value,
            Err(error) => {
                item.status = match error {
                    Error::NotFound(_) => ReaderReleaseStatus::NotFound,
                    Error::Inconsistent(_) => ReaderReleaseStatus::Changed,
                    _ => ReaderReleaseStatus::Uncertain,
                };
                if item.status == ReaderReleaseStatus::NotFound {
                    item.exists_after = Some(false);
                }
                item.message = Some(error.to_string());
                report.points.push(item);
                if policy == ReleasePolicy::PreserveSnapshots {
                    return Err(ReleaseFailure {
                        kind: "preservation_refused".into(),
                        message: "snapshot changed or could not be observed before release".into(),
                        report,
                    });
                }
                continue;
            }
        };
        if policy == ReleasePolicy::PreserveSnapshots
            && let Err(message) = preserve_snapshot(lease, point, &before)
        {
            item.status = ReaderReleaseStatus::Changed;
            item.message = Some(message.clone());
            report.points.push(item);
            return Err(ReleaseFailure {
                kind: "preservation_refused".into(),
                message,
                report,
            });
        }
        item.point = before.point();
        if !before.holds.contains(&lease.tag) {
            item.status = ReaderReleaseStatus::AlreadyReleased;
            item.exists_after = Some(true);
            report.points.push(item);
            continue;
        }
        let effect = run(
            "zfs",
            &["release".into(), lease.tag.clone(), before.name.clone()],
        );
        match native::resolve_with(&before.point(), &mut |p, a| run(p, a)) {
            Ok(after) => {
                item.exists_after = Some(true);
                if !after.holds.contains(&lease.tag) {
                    item.status = ReaderReleaseStatus::Released;
                    item.released = true;
                } else {
                    item.message = Some(effect.err().map_or_else(
                        || "hold still present after release".into(),
                        |e| e.to_string(),
                    ));
                }
            }
            Err(Error::NotFound(_)) => {
                item.exists_after = Some(false);
                if effect.is_ok() {
                    item.status = ReaderReleaseStatus::Released;
                    item.released = true;
                    item.possible_deferred_destroy =
                        before.defer_destroy && before.userrefs == 1 && before.clones.is_empty();
                } else {
                    item.message =
                        Some("snapshot disappeared during release; cause unverified".into());
                }
            }
            Err(error) => {
                item.message = Some(error.to_string());
            }
        }
        let preserved =
            item.status == ReaderReleaseStatus::Released && item.exists_after == Some(true);
        report.points.push(item);
        if policy == ReleasePolicy::PreserveSnapshots && !preserved {
            return Err(ReleaseFailure {
                kind: "preservation_uncertain".into(),
                message: "snapshot preservation was not verified after release".into(),
                report,
            });
        }
    }
    if report.points.iter().any(|p| {
        matches!(
            p.status,
            ReaderReleaseStatus::Changed | ReaderReleaseStatus::Uncertain
        )
    }) {
        Err(ReleaseFailure {
            kind: "incomplete_release".into(),
            message: "some protection could not be safely resolved or verified".into(),
            report,
        })
    } else {
        Ok(report)
    }
}

fn preserve_snapshot(
    lease: &ProtectionLease,
    point: &SnapshotRef,
    before: &Snapshot,
) -> Result<(), String> {
    if before.point() != *point || !before.holds.contains(&lease.tag) || before.defer_destroy {
        return Err(format!(
            "snapshot-preserving release requires the exact held snapshot without deferred destruction: {}",
            point.name
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const TAG: &str = "zctl1:backup:123456781234423492341234567890ab";
    fn point() -> SnapshotRef {
        SnapshotRef {
            name: "tank/data@s".into(),
            dataset_guid: Guid::new(2),
            identity: SnapshotIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(3),
                createtxg: Txg::new(4),
                objsetid: ObjsetId::new(5),
            },
        }
    }
    fn lease() -> ProtectionLease {
        ProtectionLease {
            schema_version: 2,
            consumer: "backup".into(),
            tag: TAG.into(),
            points: vec![point()],
        }
    }
    #[test]
    fn identifiers_are_exact_canonical_decimal_strings() {
        let max = Guid::new(u64::MAX);
        assert_eq!(
            serde_json::to_string(&max).unwrap(),
            "\"18446744073709551615\""
        );
        assert_eq!(
            serde_json::from_str::<Guid>("\"18446744073709551615\"").unwrap(),
            max
        );
        for malformed in [
            "1",
            "null",
            "true",
            "\"\"",
            "\"01\"",
            "\"-1\"",
            "\"+1\"",
            "\"1e3\"",
            "\" 1\"",
            "\"18446744073709551616\"",
        ] {
            assert!(
                serde_json::from_str::<Guid>(malformed).is_err(),
                "{malformed}"
            );
            assert!(serde_json::from_str::<Txg>(malformed).is_err());
            assert!(serde_json::from_str::<ObjsetId>(malformed).is_err());
        }
    }
    #[test]
    fn malformed_receipts_never_reach_native_io() {
        let original = lease();
        assert!(validate_lease(&original).is_ok());
        let mut variants = vec![];
        let mut item = original.clone();
        item.schema_version = 1;
        variants.push(item);
        let mut item = original.clone();
        item.consumer = "other".into();
        variants.push(item);
        let mut item = original.clone();
        item.tag = "rawtag".into();
        variants.push(item);
        let mut item = original.clone();
        item.tag = "zctl1:backup:123456781234123492341234567890ab".into();
        variants.push(item);
        let mut item = original.clone();
        item.points.clear();
        variants.push(item);
        let mut item = original.clone();
        item.points.push(point());
        variants.push(item);
        let mut item = original.clone();
        item.points[0].name = "-tank@s".into();
        variants.push(item);
        let mut item = original.clone();
        item.points[0].identity.objsetid = ObjsetId::new(0);
        variants.push(item);
        for item in variants {
            assert!(
                release_validated_with(&item, ReleasePolicy::EndProtection, &mut |_, _| panic!(
                    "invalid receipt executed native IO"
                ))
                .is_err()
            );
        }
        let mut value = serde_json::to_value(original).unwrap();
        value["arbitrary_tag"] = serde_json::json!("bad");
        assert!(serde_json::from_value::<ProtectionLease>(value).is_err());
    }
    #[test]
    fn invalid_requests_never_reach_native_io() {
        for request in [
            ProtectionRequest {
                consumer: "bad:consumer".into(),
                points: vec![point()],
            },
            ProtectionRequest {
                consumer: "ok".into(),
                points: vec![],
            },
            ProtectionRequest {
                consumer: "ok".into(),
                points: vec![point(), point()],
            },
        ] {
            assert!(
                protect_with(&request, TAG.into(), &mut |_, _| panic!(
                    "invalid request executed IO"
                ))
                .is_err()
            );
        }
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    fn lease() -> ProtectionLease {
        ProtectionLease {
            schema_version: 2,
            consumer: "reader".into(),
            tag: "zctl1:reader:123456781234423492341234567890ab".into(),
            points: vec![SnapshotRef {
                name: "tank@s".into(),
                dataset_guid: Guid::new(2),
                identity: SnapshotIdentity {
                    pool_guid: Guid::new(1),
                    guid: Guid::new(3),
                    createtxg: Txg::new(4),
                    objsetid: ObjsetId::new(5),
                },
            }],
        }
    }

    #[test]
    fn invalid_receipts_and_requests_do_not_query_backend() {
        let mut lease = lease();
        lease.schema_version = 999;
        let failure = release_validated_with(&lease, ReleasePolicy::EndProtection, &mut |_, _| {
            panic!("invalid lease queried backend")
        })
        .unwrap_err();
        assert_eq!(failure.kind, "invalid_lease");
        let request = ProtectionRequest {
            consumer: "invalid:consumer".into(),
            points: lease.points,
        };
        let failure = protect_validated_with(&request, &mut |_, _| {
            panic!("invalid request queried backend")
        })
        .unwrap_err();
        assert_eq!(failure.kind, "invalid_request");
    }
}

#[cfg(test)]
pub(crate) mod semantic_tests {
    use super::*;
    use std::collections::BTreeSet;
    const TAG: &str = "zctl1:backup:123456781234423492341234567890ab";
    #[derive(Clone, Copy, PartialEq)]
    pub(crate) enum Behavior {
        Normal,
        MissingHold,
        SecondFailure,
        FailedWithHold,
        QueryFailure,
        AbaTxg,
        AbaObjset,
        ParentMove,
        ReleaseFailure,
    }
    pub(crate) struct Fixture {
        pub(crate) snapshots: Vec<Snapshot>,
        pub(crate) calls: Vec<Vec<String>>,
        pub(crate) behavior: Behavior,
        pub(crate) effects: usize,
        bootfs: String,
        metadata: Option<String>,
        pool_metadata: Option<String>,
    }
    impl Fixture {
        pub(crate) fn new(count: usize) -> Self {
            Self {
                snapshots: (0..count)
                    .map(|i| Snapshot {
                        name: format!("tank/data@s{i}"),
                        guid: Guid::new(30 + i as u64),
                        dataset_guid: Guid::new(2),
                        identity: SnapshotIdentity {
                            pool_guid: Guid::new(1),
                            guid: Guid::new(30 + i as u64),
                            createtxg: Txg::new(4),
                            objsetid: ObjsetId::new(50 + i as u64),
                        },
                        userrefs: 0,
                        defer_destroy: false,
                        clones: vec![],
                        holds: vec![],
                        creation_epoch_seconds: 1700000000,
                        used_bytes: 0,
                        referenced_bytes: 0,
                    })
                    .collect(),
                calls: vec![],
                behavior: Behavior::Normal,
                effects: 0,
                bootfs: "-".into(),
                metadata: None,
                pool_metadata: None,
            }
        }
        pub(crate) fn request(&self) -> ProtectionRequest {
            ProtectionRequest {
                consumer: "backup".into(),
                points: self.snapshots.iter().map(Snapshot::point).collect(),
            }
        }
        fn held(&mut self) {
            for snapshot in &mut self.snapshots {
                snapshot.holds = vec![TAG.into()];
                snapshot.userrefs = 1;
            }
        }
        fn lease(&self) -> ProtectionLease {
            ProtectionLease {
                schema_version: 2,
                consumer: "backup".into(),
                tag: TAG.into(),
                points: self.request().points,
            }
        }
        fn error(program: &'static str, args: &[String]) -> Error {
            Error::Command {
                program,
                args: args.to_vec(),
                detail: "injected failure".into(),
            }
        }
        pub(crate) fn run(
            &mut self,
            program: &'static str,
            args: &[String],
        ) -> Result<String, Error> {
            self.calls.push(args.to_vec());
            if self.behavior == Behavior::QueryFailure && self.effects > 0 {
                return Err(Self::error(program, args));
            }
            if program == "zpool" && args[0] == "get" {
                assert_eq!(
                    args,
                    &[
                        "get",
                        "-H",
                        "-p",
                        "-o",
                        "name,property,value,source",
                        "all",
                        "tank"
                    ]
                );
                let mut output = "tank\tguid\t1\t-\n".to_string();
                if let Some(property) = &self.pool_metadata {
                    output.push_str(&format!("tank\t{property}\troot\tlocal\n"));
                }
                return Ok(output);
            }
            if program == "zpool" {
                return Ok(format!(
                    "tank\t1\t1000\t100\t900\tONLINE\t{}\n",
                    self.bootfs
                ));
            }
            match args[0].as_str() {
                "list" if args.iter().any(|a| a == "filesystem,volume") => {
                    let guid = self.snapshots.first().map_or(2, |s| s.dataset_guid.get());
                    Ok(format!(
                        "tank\tfilesystem\t1\t0\t900\t0\t/tank\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\t-\t-\ntank/data\tfilesystem\t{guid}\t0\t900\t0\t/tank/data\t-\t5\t6\tno\toff\ton\t-\toff\t-\t-\t-\t-\n"
                    ))
                }
                "list" => Ok(self
                    .snapshots
                    .iter()
                    .map(|s| {
                        format!(
                            "{}\t{}\t{}\t0\t0\t{}\t{}\t{}\t{}\t{}\n",
                            s.name,
                            s.guid,
                            s.creation_epoch_seconds,
                            s.identity.createtxg,
                            s.identity.objsetid,
                            s.holds.len(),
                            if s.defer_destroy { "on" } else { "off" },
                            if s.clones.is_empty() {
                                "-".into()
                            } else {
                                s.clones.join(",")
                            }
                        )
                    })
                    .collect()),
                "holds" => Ok(self
                    .snapshots
                    .iter()
                    .filter(|s| args[2..].contains(&s.name))
                    .flat_map(|s| {
                        s.holds
                            .iter()
                            .map(move |tag| format!("{}\t{tag}\t1700000000\n", s.name))
                    })
                    .collect()),
                "get" => {
                    let mut output = "tank\tguid\t1\t-\ntank\ttype\tfilesystem\t-\ntank/data\tguid\t2\t-\ntank/data\ttype\tfilesystem\t-\n".to_string();
                    if let Some(property) = &self.metadata {
                        output.push_str(&format!("tank\t{property}\tvalue\tlocal\n"));
                    }
                    Ok(output)
                }
                "hold" => {
                    assert_eq!(args.len(), 3, "one target, no recursive hold");
                    self.effects += 1;
                    if self.behavior == Behavior::SecondFailure && self.effects == 2 {
                        return Err(Self::error(program, args));
                    }
                    let s = self
                        .snapshots
                        .iter_mut()
                        .find(|s| s.name == args[2])
                        .unwrap();
                    if self.behavior != Behavior::MissingHold {
                        s.holds.push(args[1].clone());
                        s.userrefs += 1;
                    }
                    match self.behavior {
                        Behavior::AbaTxg => s.identity.createtxg = Txg::new(999),
                        Behavior::AbaObjset => s.identity.objsetid = ObjsetId::new(999),
                        Behavior::ParentMove => s.dataset_guid = Guid::new(999),
                        _ => {}
                    }
                    if self.behavior == Behavior::FailedWithHold {
                        return Err(Self::error(program, args));
                    }
                    Ok(String::new())
                }
                "release" => {
                    assert_eq!(args.len(), 3, "one target, no force/recursive release");
                    self.effects += 1;
                    if self.behavior == Behavior::ReleaseFailure {
                        return Err(Self::error(program, args));
                    }
                    let s = self
                        .snapshots
                        .iter_mut()
                        .find(|s| s.name == args[2])
                        .unwrap();
                    s.holds.retain(|t| t != &args[1]);
                    s.userrefs = s.holds.len() as u64;
                    self.snapshots.retain(|s| {
                        !(s.defer_destroy && s.holds.is_empty() && s.clones.is_empty())
                    });
                    Ok(String::new())
                }
                other => panic!("unexpected command {other}"),
            }
        }
        fn protect(
            &mut self,
            request: &ProtectionRequest,
        ) -> Result<ProtectionLease, ProtectionFailure> {
            protect_with(request, TAG.into(), &mut |p, a| self.run(p, a))
        }
        fn release(
            &mut self,
            lease: &ProtectionLease,
        ) -> Result<ReaderReleaseReport, ReleaseFailure> {
            release_validated_with(lease, ReleasePolicy::EndProtection, &mut |p, a| {
                self.run(p, a)
            })
        }
        pub(crate) fn no_compensation(&self) {
            assert!(
                !self
                    .calls
                    .iter()
                    .any(|args| matches!(args[0].as_str(), "release" | "destroy"))
            );
        }
    }
    #[test]
    fn prepared_intent_preserves_all_exact_targets_before_execution() {
        let mut fixture = Fixture::new(2);
        let mut request = fixture.request();
        let expected = request.clone();
        let prepared = PreparedProtection::prepare(&request).unwrap();
        let second = PreparedProtection::prepare(&request).unwrap();
        assert_ne!(prepared.intent().tag, second.intent().tag);
        validate_lease(prepared.intent()).unwrap();
        let recorded: ProtectionLease =
            serde_json::from_slice(&serde_json::to_vec(prepared.intent()).unwrap()).unwrap();
        request.points.clear();
        assert_eq!(recorded.consumer, expected.consumer);
        assert_eq!(recorded.points, expected.points);
        assert!(fixture.calls.is_empty());
        assert_eq!(fixture.effects, 0);

        let acquired = prepared
            .execute_with(&mut |p, a| fixture.run(p, a))
            .unwrap();
        assert_eq!(acquired, recorded);
        assert_eq!(fixture.effects, 2);
        fixture.no_compensation();
    }

    #[test]
    fn failed_intent_persistence_performs_no_native_work() {
        struct FailedStore;
        impl std::io::Write for FailedStore {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("intent store unavailable"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let fixture = Fixture::new(2);
        let prepared = PreparedProtection::prepare(&fixture.request()).unwrap();
        // A caller whose durable write fails can drop the prepared acquisition
        // without dispatching any native observation or hold.
        assert!(serde_json::to_writer(FailedStore, prepared.intent()).is_err());
        drop(prepared);
        assert!(fixture.calls.is_empty());
        assert_eq!(fixture.effects, 0);
    }

    #[test]
    fn prepared_failed_effect_retains_complete_intent_and_uncertain_protection() {
        let mut fixture = Fixture::new(2);
        fixture.behavior = Behavior::FailedWithHold;
        let prepared = PreparedProtection::prepare(&fixture.request()).unwrap();
        let recorded = prepared.intent().clone();
        let failure = prepared
            .execute_with(&mut |p, a| fixture.run(p, a))
            .unwrap_err();
        assert_eq!(recorded.points.len(), 2);
        assert_eq!(failure.tag, Some(recorded.tag.clone()));
        assert!(failure.partial_lease.is_none());
        assert_eq!(
            failure.uncertain_names,
            vec![recorded.points[0].name.clone()]
        );
        assert_eq!(fixture.snapshots[0].holds, vec![recorded.tag]);
        assert!(fixture.snapshots[1].holds.is_empty());
        fixture.no_compensation();
    }

    #[test]
    fn complete_protection_and_explicit_release_are_verified_single_target_effects() {
        let mut fixture = Fixture::new(2);
        let request = fixture.request();
        let lease = fixture.protect(&request).unwrap();
        assert_eq!(lease.points.len(), 2);
        assert_eq!(fixture.effects, 2);
        let report = fixture.release(&lease).unwrap();
        assert!(
            report
                .points
                .iter()
                .all(|p| p.status == ReaderReleaseStatus::Released
                    && p.released
                    && p.exists_after == Some(true))
        );
        assert!(fixture.snapshots.iter().all(|s| s.holds.is_empty()));
    }
    #[test]
    fn zero_exit_without_hold_is_not_success() {
        let mut fixture = Fixture::new(1);
        fixture.behavior = Behavior::MissingHold;
        let failure = fixture.protect(&fixture.request()).unwrap_err();
        assert!(failure.partial_lease.is_none());
        fixture.no_compensation();
    }
    #[test]
    fn partial_native_failure_retains_verified_protection() {
        let mut fixture = Fixture::new(2);
        fixture.behavior = Behavior::SecondFailure;
        let failure = fixture.protect(&fixture.request()).unwrap_err();
        assert_eq!(failure.partial_lease.unwrap().points.len(), 1);
        assert_eq!(fixture.snapshots[0].holds, vec![TAG]);
        fixture.no_compensation();
    }
    #[test]
    fn failed_effect_with_observed_tag_is_uncertain_not_owned() {
        let mut fixture = Fixture::new(1);
        fixture.behavior = Behavior::FailedWithHold;
        let failure = fixture.protect(&fixture.request()).unwrap_err();
        assert!(failure.partial_lease.is_none());
        assert_eq!(failure.uncertain_names, vec!["tank/data@s0"]);
        assert_eq!(fixture.snapshots[0].holds, vec![TAG]);
        fixture.no_compensation();
    }
    #[test]
    fn failed_postquery_retains_unknown_protection() {
        let mut fixture = Fixture::new(1);
        fixture.behavior = Behavior::QueryFailure;
        let failure = fixture.protect(&fixture.request()).unwrap_err();
        assert_eq!(failure.tag.as_deref(), Some(TAG));
        assert_eq!(failure.uncertain_names.len(), 1);
        assert_eq!(fixture.snapshots[0].holds, vec![TAG]);
        fixture.no_compensation();
    }
    #[test]
    fn aba_and_parent_moves_never_trigger_compensation_or_release() {
        for behavior in [Behavior::AbaTxg, Behavior::AbaObjset, Behavior::ParentMove] {
            let mut fixture = Fixture::new(1);
            fixture.behavior = behavior;
            let before = fixture.lease();
            let failure = fixture.protect(&fixture.request()).unwrap_err();
            assert!(failure.partial_lease.is_none());
            assert_eq!(failure.uncertain_names.len(), 1);
            fixture.no_compensation();
            let failed = fixture.release(&before).unwrap_err();
            assert_eq!(failed.report.points[0].status, ReaderReleaseStatus::Changed);
            fixture.no_compensation();
        }
    }
    #[test]
    fn preexisting_tag_is_never_claimed() {
        let mut fixture = Fixture::new(1);
        fixture.held();
        let failure = fixture.protect(&fixture.request()).unwrap_err();
        assert_eq!(failure.kind, "tag_collision");
        assert_eq!(fixture.effects, 0);
        fixture.no_compensation();
    }
    #[test]
    fn management_roles_and_bootfs_siblings_are_refused_before_effects() {
        for property in [
            "zboot:attached-to",
            "zboot:peer",
            "zboot:paired",
            "zboot:passive",
        ] {
            let mut fixture = Fixture::new(1);
            fixture.metadata = Some(property.into());
            assert!(fixture.protect(&fixture.request()).is_err(), "{property}");
            assert_eq!(fixture.effects, 0);
        }
        for property in ["zboot:role", "zboot:future"] {
            let mut fixture = Fixture::new(1);
            fixture.pool_metadata = Some(property.into());
            assert!(fixture.protect(&fixture.request()).is_err(), "{property}");
            assert_eq!(fixture.effects, 0);
        }
        for bootfs in ["tank", "tank/data", "tank/other"] {
            let mut fixture = Fixture::new(1);
            fixture.bootfs = bootfs.into();
            assert!(fixture.protect(&fixture.request()).is_err(), "{bootfs}");
            assert_eq!(fixture.effects, 0);
        }
        let mut fixture = Fixture::new(1);
        fixture.snapshots[0].defer_destroy = true;
        assert!(fixture.protect(&fixture.request()).is_err());
        assert_eq!(fixture.effects, 0);
    }
    #[test]
    fn a_retired_boot_marker_does_not_require_a_management_adapter() {
        let mut fixture = Fixture::new(1);
        fixture.metadata = Some("zboot:be".into());
        fixture.pool_metadata = Some("zboot:be".into());
        fixture.protect(&fixture.request()).unwrap();
        assert!(fixture.effects > 0);
    }
    #[test]
    fn deferred_release_reports_protection_ended_and_possible_completion() {
        let mut fixture = Fixture::new(1);
        fixture.held();
        fixture.snapshots[0].defer_destroy = true;
        let report = fixture.release(&fixture.lease()).unwrap();
        let point = &report.points[0];
        assert_eq!(point.status, ReaderReleaseStatus::Released);
        assert!(point.released);
        assert_eq!(point.exists_after, Some(false));
        assert!(point.possible_deferred_destroy);
        assert!(!fixture.calls.iter().any(|a| a[0] == "destroy"));
    }
    #[test]
    fn preserving_release_rechecks_whole_lease_after_the_callers_clean_observation() {
        for change in ["deferred", "missing", "foreign-hold", "identity", "query"] {
            let mut fixture = Fixture::new(2);
            fixture.held();
            let lease = fixture.lease();
            assert!(fixture.snapshots.iter().all(|s| !s.defer_destroy));
            // A writer runs after the caller's clean export check but before
            // release performs its own checks. The last point changes, so an
            // effect-by-effect check would already have released the first.
            match change {
                "deferred" => fixture.snapshots[1].defer_destroy = true,
                "missing" => {
                    fixture.snapshots.pop();
                }
                "foreign-hold" => fixture.snapshots[1].holds.clear(),
                "identity" => fixture.snapshots[1].identity.createtxg = Txg::new(999),
                _ => {}
            }
            let failure =
                release_validated_with(&lease, ReleasePolicy::PreserveSnapshots, &mut |p, a| {
                    if change == "query" {
                        Err(Fixture::error(p, a))
                    } else {
                        fixture.run(p, a)
                    }
                })
                .unwrap_err();
            assert_eq!(failure.kind, "preservation_refused", "{change}");
            assert_eq!(fixture.effects, 0, "{change}");
            assert!(fixture.snapshots[0].holds.contains(&TAG.into()), "{change}");
            fixture.no_compensation();
        }
    }
    #[test]
    fn preserving_release_retains_remaining_holds_after_a_release_failure() {
        let mut fixture = Fixture::new(2);
        fixture.held();
        fixture.behavior = Behavior::ReleaseFailure;
        let lease = fixture.lease();
        let failure =
            release_validated_with(&lease, ReleasePolicy::PreserveSnapshots, &mut |p, a| {
                fixture.run(p, a)
            })
            .unwrap_err();
        assert_eq!(failure.kind, "preservation_uncertain");
        assert_eq!(fixture.effects, 1);
        assert!(
            fixture
                .snapshots
                .iter()
                .all(|s| s.holds.contains(&TAG.into()))
        );
    }
    #[test]
    fn missing_and_previously_released_holds_are_not_claimed_as_released() {
        let mut fixture = Fixture::new(1);
        let lease = fixture.lease();
        let report = fixture.release(&lease).unwrap();
        assert_eq!(
            report.points[0].status,
            ReaderReleaseStatus::AlreadyReleased
        );
        // The receipt wire value predates the rename.
        assert_eq!(
            serde_json::to_value(ReaderReleaseStatus::AlreadyReleased).unwrap(),
            "already_unpinned"
        );
        assert!(!report.points[0].released);
        fixture.snapshots.clear();
        let report = fixture.release(&lease).unwrap();
        assert_eq!(report.points[0].status, ReaderReleaseStatus::NotFound);
        assert!(!report.points[0].released);
        assert_eq!(fixture.effects, 0);
    }
    #[test]
    fn failed_release_retains_hold_and_reports_uncertainty() {
        let mut fixture = Fixture::new(1);
        fixture.held();
        fixture.behavior = Behavior::ReleaseFailure;
        let failure = fixture.release(&fixture.lease()).unwrap_err();
        assert_eq!(
            failure.report.points[0].status,
            ReaderReleaseStatus::Uncertain
        );
        assert_eq!(fixture.snapshots[0].holds, vec![TAG]);
    }
    #[test]
    fn successful_protection_receipt_contains_unique_exact_incarnations() {
        let mut fixture = Fixture::new(2);
        let request = fixture.request();
        let receipt = fixture.protect(&request).unwrap();
        let guids: BTreeSet<_> = receipt.points.iter().map(|p| p.identity.guid).collect();
        assert_eq!(guids.len(), 2);
        assert_eq!(receipt.points, request.points);
        assert_eq!(
            serde_json::from_str::<ProtectionLease>(&serde_json::to_string(&receipt).unwrap())
                .unwrap(),
            receipt
        );
    }
}
