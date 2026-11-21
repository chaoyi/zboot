//! Owned protection for snapshot readers. Receipts are recovery data, never
//! proof that a reader has ended. Dropping a protection does not release holds.
use crate::engine::{self, native, protection};
use crate::{Error, SnapshotRef, WriterSession};
use serde::{Deserialize, Serialize};
use std::fmt;

type Runner<'a> = dyn FnMut(&'static str, &[String]) -> Result<String, engine::Error> + 'a;

/// Immutable, validated recovery data for exact local snapshot incarnations.
/// Serialization retains the legacy schema-2 `zctl1` receipt format. A receipt
/// grants neither native permissions nor authority to end a live reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReaderReceipt(protection::ProtectionLease);

impl<'de> Deserialize<'de> for ReaderReceipt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let lease = protection::ProtectionLease::deserialize(deserializer)?;
        protection::validate_lease(&lease).map_err(serde::de::Error::custom)?;
        Ok(Self(lease))
    }
}

impl ReaderReceipt {
    pub fn schema_version(&self) -> u32 {
        self.0.schema_version
    }
    pub fn tag(&self) -> &str {
        &self.0.tag
    }
    pub fn points(&self) -> &[SnapshotRef] {
        &self.0.points
    }
}

/// An acquired reader's owned protection, independent of the acquiring writer
/// session. This handle cannot be cloned or deserialized. Dropping it retains
/// every hold; only an explicit release operation can end protection.
/// ```compile_fail
/// fn duplicate(protection: zfs_tools::ReaderProtection) {
///     let another = protection.clone();
/// }
/// ```
/// ```compile_fail
/// let protection = serde_json::from_str::<zfs_tools::ReaderProtection>("{}");
/// ```
pub struct ReaderProtection {
    outcome: ReaderProtectionOutcome,
}
impl ReaderProtection {
    pub fn receipt(&self) -> &ReaderReceipt {
        &self.outcome.lease
    }
    pub fn outcome(&self) -> &ReaderProtectionOutcome {
        &self.outcome
    }
}

/// Verified acquisition plus the complete intent recorded before the first
/// hold. Resolved snapshot names may differ after a native rename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReaderProtectionOutcome {
    pub intended_receipt: ReaderReceipt,
    pub lease: ReaderReceipt,
}

/// A refused or incomplete acquisition. All partial and uncertain protection
/// remains in place. The intended receipt covers the complete requested scope;
/// `partial_lease` contains only protection verified as acquired by this call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectError {
    pub kind: String,
    pub message: String,
    pub intended_receipt: Option<Box<ReaderReceipt>>,
    pub tag: Option<String>,
    pub partial_lease: Option<Box<ReaderReceipt>>,
    pub uncertain_names: Vec<String>,
}

/// Whether explicitly ending protection may complete native deferred deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePolicy {
    /// End the receipt's protection, potentially completing deferred deletion.
    EndProtection,
    /// Refuse before any release unless the entire exact receipt remains held
    /// and no snapshot is marked for deferred destruction. Stop on uncertainty.
    PreserveSnapshots,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaderReleaseStatus {
    Released,
    #[serde(rename = "already_unpinned")]
    AlreadyReleased,
    NotFound,
    Changed,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReaderReleasePoint {
    pub point: SnapshotRef,
    pub status: ReaderReleaseStatus,
    pub released: bool,
    pub exists_after: Option<bool>,
    /// Consistent with deferred deletion, not proof of its cause.
    pub possible_deferred_destroy: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReaderReleaseReport {
    pub schema_version: u32,
    pub tag: String,
    pub points: Vec<ReaderReleasePoint>,
}

/// The complete release scope and reconciled results. A failed operation can
/// report only a prefix; omitted points remain covered by `receipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReaderReleaseOutcome {
    pub receipt: ReaderReceipt,
    pub report: ReaderReleaseReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndReaderError {
    pub kind: String,
    pub message: String,
    pub outcome: Box<ReaderReleaseOutcome>,
}

macro_rules! display_error {
    ($ty:ty) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&engine::escape_display(&self.message))
            }
        }
        impl std::error::Error for $ty {}
    };
}
display_error!(ProtectError);
display_error!(EndReaderError);

impl WriterSession {
    /// Record the complete intent before observing or holding snapshots. The
    /// persistence callback must return only after the receipt is durable.
    /// Failure retains all protection and recovery data; nothing compensates.
    pub fn protect_reader(
        &mut self,
        points: &[SnapshotRef],
        consumer: &str,
        persist: impl FnOnce(&ReaderReceipt) -> Result<(), Error>,
    ) -> Result<ReaderProtection, ProtectError> {
        self.protect_reader_guarded(points, consumer, persist, || Ok(()))
    }

    /// As `protect_reader`, checking caller lifecycle authority before every
    /// native observation and immediately before each native hold. The guard
    /// can refuse progression; it cannot substitute native evidence or commands.
    pub fn protect_reader_guarded(
        &mut self,
        points: &[SnapshotRef],
        consumer: &str,
        persist: impl FnOnce(&ReaderReceipt) -> Result<(), Error>,
        mut guard: impl FnMut() -> Result<(), Error>,
    ) -> Result<ReaderProtection, ProtectError> {
        self.usable()
            .map_err(|error| protect_refused("writer_custody", error.to_string(), None))?;
        let (prepared, intent) = prepare_and_persist(points, consumer, persist)?;
        self.with_native_writer(|| {
            execute_prepared_with(prepared, &intent, &mut guard, &mut native_run)
        })
        .map_err(|error| protect_refused("writer_custody", error.to_string(), Some(intent)))?
    }

    /// Explicitly end an owned protection after the caller establishes that
    /// all readers and descendants have ended. The guard must keep establishing
    /// that lifecycle authority before native observations and releases. Native
    /// holds do not fence renames, external writers or application activity.
    pub fn end_reader(
        &mut self,
        protection: ReaderProtection,
        policy: ReleasePolicy,
        mut guard: impl FnMut() -> Result<(), Error>,
    ) -> Result<ReaderReleaseOutcome, EndReaderError> {
        let receipt = protection.receipt();
        self.with_native_writer(|| end_with(receipt, policy, &mut guard, &mut native_run))
            .map_err(|error| end_refused("writer_custody", error.to_string(), receipt))?
    }

    /// Revalidate every exact snapshot incarnation, its owned hold and current
    /// native management admission. Returns freshly resolved names for a
    /// supervisor to check before and after mounting a private view and before
    /// starting its reader. Evidence is sequential and is not lifecycle or
    /// future mutation authority. A refusing guard performs no native query.
    pub fn revalidate_reader(
        &mut self,
        receipt: &ReaderReceipt,
        mut guard: impl FnMut() -> Result<(), Error>,
    ) -> Result<Vec<SnapshotRef>, Error> {
        self.with_native_writer(|| revalidate_with(receipt, &mut guard, &mut native_run))?
    }

    /// Explicit receipt-based recovery with fresh native identity/hold checks.
    /// Parsing a receipt does not recover live-reader authority. The caller
    /// must establish that every affected reader and descendant has ended and
    /// retain exclusive lifecycle custody through this operation. Neither the
    /// host writer lock nor absence from a task registry proves reader death.
    /// A supervisor should enforce this with kernel-backed task custody.
    /// Recovery observes the whole receipt before any release, reconciles proven
    /// absence and already-unheld points, and applies the selected release policy
    /// to the remaining owned holds. Changed or uncertain evidence retains them.
    pub fn recover_reader(
        &mut self,
        receipt: &ReaderReceipt,
        policy: ReleasePolicy,
        mut guard: impl FnMut() -> Result<(), Error>,
    ) -> Result<ReaderReleaseOutcome, EndReaderError> {
        self.with_native_writer(|| recover_with(receipt, policy, &mut guard, &mut native_run))
            .map_err(|error| end_refused("writer_custody", error.to_string(), receipt))?
    }
}

fn native_run(program: &'static str, args: &[String]) -> Result<String, engine::Error> {
    if program == "zfs"
        && args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "hold" | "release"))
    {
        native::run_mutating(program, args)
    } else {
        native::run(program, args)
    }
}

fn protect_refused(kind: &str, message: String, intent: Option<ReaderReceipt>) -> ProtectError {
    ProtectError {
        kind: kind.into(),
        message,
        intended_receipt: intent.map(Box::new),
        tag: None,
        partial_lease: None,
        uncertain_names: vec![],
    }
}

fn prepare_and_persist(
    points: &[SnapshotRef],
    consumer: &str,
    persist: impl FnOnce(&ReaderReceipt) -> Result<(), Error>,
) -> Result<(protection::PreparedProtection, ReaderReceipt), ProtectError> {
    let prepared = protection::PreparedProtection::prepare(&protection::ProtectionRequest {
        consumer: consumer.into(),
        points: points.to_vec(),
    })
    .map_err(|error| protect_failure(error, None))?;
    let intent = ReaderReceipt(prepared.intent().clone());
    persist(&intent).map_err(|error| {
        protect_refused(
            "intent_persistence",
            error.to_string(),
            Some(intent.clone()),
        )
    })?;
    Ok((prepared, intent))
}

fn protect_failure(
    error: protection::ProtectionFailure,
    intent: Option<ReaderReceipt>,
) -> ProtectError {
    ProtectError {
        kind: error.kind,
        message: error.message,
        intended_receipt: intent.map(Box::new),
        tag: error.tag,
        partial_lease: error
            .partial_lease
            .map(|lease| Box::new(ReaderReceipt(*lease))),
        uncertain_names: error.uncertain_names,
    }
}

fn execute_prepared_with(
    prepared: protection::PreparedProtection,
    intent: &ReaderReceipt,
    guard: &mut impl FnMut() -> Result<(), Error>,
    run: &mut Runner<'_>,
) -> Result<ReaderProtection, ProtectError> {
    let lease = prepared
        .execute_with(&mut |program, args| guarded_run(guard, run, program, args))
        .map_err(|error| protect_failure(error, Some(intent.clone())))?;
    Ok(ReaderProtection {
        outcome: ReaderProtectionOutcome {
            intended_receipt: intent.clone(),
            lease: ReaderReceipt(lease),
        },
    })
}

fn guarded_run(
    guard: &mut impl FnMut() -> Result<(), Error>,
    run: &mut Runner<'_>,
    program: &'static str,
    args: &[String],
) -> Result<String, engine::Error> {
    guard().map_err(|error| {
        engine::Error::Inconsistent(format!("reader lifecycle guard refused: {error}"))
    })?;
    run(program, args)
}

fn end_refused(kind: &str, message: String, receipt: &ReaderReceipt) -> EndReaderError {
    EndReaderError {
        kind: kind.into(),
        message,
        outcome: Box::new(ReaderReleaseOutcome {
            receipt: receipt.clone(),
            report: ReaderReleaseReport {
                schema_version: 2,
                tag: receipt.tag().into(),
                points: vec![],
            },
        }),
    }
}

fn revalidate_with(
    receipt: &ReaderReceipt,
    guard: &mut impl FnMut() -> Result<(), Error>,
    run: &mut Runner<'_>,
) -> Result<Vec<SnapshotRef>, Error> {
    let mut points = Vec::with_capacity(receipt.points().len());
    for point in receipt.points() {
        let before = native::resolve_with(point, &mut |p, a| guarded_run(guard, run, p, a))?;
        if !before.holds.contains(&receipt.0.tag) {
            return Err(Error::new(format!(
                "reader hold is missing: {}",
                before.name
            )));
        }
        native::admit_with(&before, &mut |p, a| guarded_run(guard, run, p, a))?;
        let current =
            native::resolve_with(&before.point(), &mut |p, a| guarded_run(guard, run, p, a))?;
        if !current.holds.contains(&receipt.0.tag) || current.defer_destroy {
            return Err(Error::new(format!(
                "reader hold is missing or snapshot is pending destruction: {}",
                current.name
            )));
        }
        points.push(current.point());
    }
    Ok(points)
}

fn end_with(
    receipt: &ReaderReceipt,
    policy: ReleasePolicy,
    guard: &mut impl FnMut() -> Result<(), Error>,
    run: &mut Runner<'_>,
) -> Result<ReaderReleaseOutcome, EndReaderError> {
    guard().map_err(|error| end_refused("lifecycle_refused", error.to_string(), receipt))?;
    let result = protection::release_validated_with(&receipt.0, policy, &mut |program, args| {
        guarded_run(guard, run, program, args)
    });
    match result {
        Ok(report) => Ok(ReaderReleaseOutcome {
            receipt: receipt.clone(),
            report,
        }),
        Err(error) => Err(EndReaderError {
            kind: error.kind,
            message: error.message,
            outcome: Box::new(ReaderReleaseOutcome {
                receipt: receipt.clone(),
                report: error.report,
            }),
        }),
    }
}

fn recover_with(
    receipt: &ReaderReceipt,
    policy: ReleasePolicy,
    guard: &mut impl FnMut() -> Result<(), Error>,
    run: &mut Runner<'_>,
) -> Result<ReaderReleaseOutcome, EndReaderError> {
    guard().map_err(|error| end_refused("lifecycle_refused", error.to_string(), receipt))?;
    let mut report = ReaderReleaseReport {
        schema_version: 2,
        tag: receipt.tag().into(),
        points: Vec::with_capacity(receipt.points().len()),
    };
    let mut remaining = receipt.0.clone();
    remaining.points.clear();
    let mut remaining_indices = Vec::new();
    let mut refused = false;
    // Complete observation precedes every effect. An unheld/missing point can
    // be the result of an earlier interrupted release; neither implies a cause.
    for (index, point) in receipt.points().iter().enumerate() {
        let mut item = ReaderReleasePoint {
            point: point.clone(),
            status: ReaderReleaseStatus::Uncertain,
            released: false,
            exists_after: None,
            possible_deferred_destroy: false,
            message: None,
        };
        match native::resolve_with(point, &mut |p, a| guarded_run(guard, run, p, a)) {
            Ok(snapshot) => {
                item.point = snapshot.point();
                item.exists_after = Some(true);
                if snapshot.holds.contains(&receipt.0.tag) {
                    remaining.points.push(snapshot.point());
                    remaining_indices.push(index);
                    item.message =
                        Some("owned hold remains; release has not been attempted".into());
                } else {
                    item.status = ReaderReleaseStatus::AlreadyReleased;
                }
            }
            Err(engine::Error::NotFound(_)) => {
                item.status = ReaderReleaseStatus::NotFound;
                item.exists_after = Some(false);
            }
            Err(error) => {
                if matches!(error, engine::Error::Inconsistent(_)) {
                    item.status = ReaderReleaseStatus::Changed;
                }
                item.message = Some(error.to_string());
                refused = true;
            }
        }
        report.points.push(item);
    }
    let failure = |kind: String, message: String, report: ReaderReleaseReport| EndReaderError {
        kind,
        message,
        outcome: Box::new(ReaderReleaseOutcome {
            receipt: receipt.clone(),
            report,
        }),
    };
    if refused {
        return Err(failure(
            "recovery_refused".into(),
            "complete receipt identities and protection could not be observed".into(),
            report,
        ));
    }
    if remaining.points.is_empty() {
        return Ok(ReaderReleaseOutcome {
            receipt: receipt.clone(),
            report,
        });
    }
    // PreserveSnapshots still performs its complete-subset preflight and each
    // immediate recheck. Recovery does not weaken its deferred-destroy policy.
    let released = protection::release_validated_with(&remaining, policy, &mut |p, a| {
        guarded_run(guard, run, p, a)
    });
    let (released_report, error) = match released {
        Ok(report) => (report, None),
        Err(error) => (error.report, Some((error.kind, error.message))),
    };
    for (index, item) in remaining_indices.into_iter().zip(released_report.points) {
        report.points[index] = item;
    }
    match error {
        Some((kind, message)) => Err(failure(kind, message, report)),
        None => Ok(ReaderReleaseOutcome {
            receipt: receipt.clone(),
            report,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::protection::semantic_tests::{Behavior, Fixture};
    use std::cell::Cell;

    fn acquire(fixture: &mut Fixture) -> ReaderProtection {
        let request = fixture.request();
        let (prepared, intent) =
            prepare_and_persist(&request.points, &request.consumer, |_| Ok(())).unwrap();
        execute_prepared_with(prepared, &intent, &mut || Ok(()), &mut |p, a| {
            fixture.run(p, a)
        })
        .unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn receipt_roundtrips_legacy_wire_format_and_rejects_invalid_identity_or_tag() {
        let fixture = Fixture::new(2);
        let prepared = protection::PreparedProtection::prepare(&fixture.request()).unwrap();
        let receipt = ReaderReceipt(prepared.intent().clone());
        let json = serde_json::to_string(&receipt).unwrap();
        assert_eq!(
            serde_json::from_str::<ReaderReceipt>(&json).unwrap(),
            receipt
        );
        assert_eq!(
            serde_json::to_value(&receipt).unwrap(),
            serde_json::to_value(prepared.intent()).unwrap()
        );
        assert_eq!(receipt.schema_version(), 2);
        let original = serde_json::to_value(&receipt).unwrap();
        let mut invalid = vec![];
        for (key, value) in [
            ("schema_version", serde_json::json!(1)),
            ("consumer", serde_json::json!("other")),
            ("tag", serde_json::json!("foreign-hold")),
            ("points", serde_json::json!([])),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut value_with_change = original.clone();
            value_with_change[key] = value;
            invalid.push(value_with_change);
        }
        for key in ["pool_guid", "guid", "createtxg", "objsetid"] {
            for value in [
                serde_json::json!("0"),
                serde_json::json!("01"),
                serde_json::json!(1),
            ] {
                let mut changed = original.clone();
                changed["points"][0]["identity"][key] = value;
                invalid.push(changed);
            }
        }
        for (key, value) in [
            ("dataset_guid", serde_json::json!("0")),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut changed = original.clone();
            changed["points"][0][key] = value;
            invalid.push(changed);
        }
        let mut wrong_uuid_version = original.clone();
        wrong_uuid_version["tag"] =
            serde_json::json!("zctl1:backup:123456781234123492341234567890ab");
        invalid.push(wrong_uuid_version);
        let mut duplicate = original.clone();
        duplicate["points"][1] = duplicate["points"][0].clone();
        invalid.push(duplicate);
        for value in invalid {
            assert!(serde_json::from_value::<ReaderReceipt>(value).is_err());
        }
    }

    /// Consumers store and compare these bytes; field order, status strings,
    /// explicit nulls and decimal-string identities are all part of the wire.
    #[test]
    fn public_reader_json_bytes_are_pinned() {
        fn json(value: &impl Serialize) -> String {
            serde_json::to_string(value).unwrap()
        }
        let tag = "zctl1:backup:123456781234423492341234567890ab";
        let point = |index: u64| {
            format!(
                r#"{{"name":"tank/data@s{index}","dataset_guid":"2","identity":{{"pool_guid":"1","guid":"{}","createtxg":"4","objsetid":"{}"}}}}"#,
                30 + index,
                50 + index
            )
        };
        let (p0, p1) = (point(0), point(1));
        let receipt_json = format!(
            r#"{{"schema_version":2,"consumer":"backup","tag":"{tag}","points":[{p0},{p1}]}}"#
        );
        let receipt: ReaderReceipt = serde_json::from_str(&receipt_json).unwrap();
        assert_eq!(json(&receipt), receipt_json);
        let partial_json =
            format!(r#"{{"schema_version":2,"consumer":"backup","tag":"{tag}","points":[{p0}]}}"#);
        let partial: ReaderReceipt = serde_json::from_str(&partial_json).unwrap();

        for (policy, wire) in [
            (ReleasePolicy::EndProtection, r#""end_protection""#),
            (ReleasePolicy::PreserveSnapshots, r#""preserve_snapshots""#),
        ] {
            assert_eq!(json(&policy), wire);
        }
        for (status, wire) in [
            (ReaderReleaseStatus::Released, r#""released""#),
            (
                ReaderReleaseStatus::AlreadyReleased,
                r#""already_unpinned""#,
            ),
            (ReaderReleaseStatus::NotFound, r#""not_found""#),
            (ReaderReleaseStatus::Changed, r#""changed""#),
            (ReaderReleaseStatus::Uncertain, r#""uncertain""#),
        ] {
            assert_eq!(json(&status), wire);
        }

        let protected = ReaderProtectionOutcome {
            intended_receipt: receipt.clone(),
            lease: receipt.clone(),
        };
        assert_eq!(
            json(&protected),
            format!(r#"{{"intended_receipt":{receipt_json},"lease":{receipt_json}}}"#)
        );
        let refused = ProtectError {
            kind: "incomplete_pin".into(),
            message: "hold reply \"lost\"".into(),
            intended_receipt: Some(Box::new(receipt.clone())),
            tag: Some(tag.into()),
            partial_lease: Some(Box::new(partial.clone())),
            uncertain_names: vec!["tank/data@s1".into()],
        };
        assert_eq!(
            json(&refused),
            format!(
                r#"{{"kind":"incomplete_pin","message":"hold reply \"lost\"","intended_receipt":{receipt_json},"tag":"{tag}","partial_lease":{partial_json},"uncertain_names":["tank/data@s1"]}}"#
            )
        );
        assert_eq!(
            json(&protect_refused("invalid_request", "bad".into(), None)),
            r#"{"kind":"invalid_request","message":"bad","intended_receipt":null,"tag":null,"partial_lease":null,"uncertain_names":[]}"#
        );

        let released = ReaderReleaseOutcome {
            receipt: receipt.clone(),
            report: ReaderReleaseReport {
                schema_version: 2,
                tag: tag.into(),
                points: vec![
                    ReaderReleasePoint {
                        point: receipt.points()[0].clone(),
                        status: ReaderReleaseStatus::Released,
                        released: true,
                        exists_after: Some(false),
                        possible_deferred_destroy: true,
                        message: None,
                    },
                    ReaderReleasePoint {
                        point: receipt.points()[1].clone(),
                        status: ReaderReleaseStatus::AlreadyReleased,
                        released: false,
                        exists_after: None,
                        possible_deferred_destroy: false,
                        message: Some("owned hold\nremains".into()),
                    },
                ],
            },
        };
        let report_json = format!(
            r#"{{"schema_version":2,"tag":"{tag}","points":[{{"point":{p0},"status":"released","released":true,"exists_after":false,"possible_deferred_destroy":true,"message":null}},{{"point":{p1},"status":"already_unpinned","released":false,"exists_after":null,"possible_deferred_destroy":false,"message":"owned hold\nremains"}}]}}"#
        );
        assert_eq!(json(&released.report), report_json);
        assert_eq!(
            json(&released),
            format!(r#"{{"receipt":{receipt_json},"report":{report_json}}}"#)
        );
        let ended = EndReaderError {
            kind: "incomplete_release".into(),
            message: "some protection could not be safely resolved or verified".into(),
            outcome: Box::new(released),
        };
        assert_eq!(
            json(&ended),
            format!(
                r#"{{"kind":"incomplete_release","message":"some protection could not be safely resolved or verified","outcome":{{"receipt":{receipt_json},"report":{report_json}}}}}"#
            )
        );
        assert_eq!(
            json(&end_refused("writer_custody", "lock lost".into(), &partial)),
            format!(
                r#"{{"kind":"writer_custody","message":"lock lost","outcome":{{"receipt":{partial_json},"report":{{"schema_version":2,"tag":"{tag}","points":[]}}}}}}"#
            )
        );
    }

    /// The same bytes through the engine's release and recovery paths.
    #[test]
    fn executed_reader_json_bytes_are_pinned() {
        let point = |index: u64| {
            format!(
                r#"{{"name":"tank/data@s{index}","dataset_guid":"2","identity":{{"pool_guid":"1","guid":"{}","createtxg":"4","objsetid":"{}"}}}}"#,
                30 + index,
                50 + index
            )
        };
        let (p0, p1) = (point(0), point(1));
        let receipt = format!(
            r#"{{"schema_version":2,"consumer":"backup","tag":"TAG","points":[{p0},{p1}]}}"#
        );
        fn wire(protection: &ReaderProtection, value: &impl Serialize) -> String {
            serde_json::to_string(value)
                .unwrap()
                .replace(protection.receipt().tag(), "TAG")
        }

        let mut fixture = Fixture::new(2);
        let protection = acquire(&mut fixture);
        assert_eq!(
            wire(&protection, protection.outcome()),
            format!(r#"{{"intended_receipt":{receipt},"lease":{receipt}}}"#)
        );
        fixture.snapshots[0].defer_destroy = true;
        let outcome = end_with(
            protection.receipt(),
            ReleasePolicy::EndProtection,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap();
        assert_eq!(
            wire(&protection, &outcome),
            format!(
                r#"{{"receipt":{receipt},"report":{{"schema_version":2,"tag":"TAG","points":[{{"point":{p0},"status":"released","released":true,"exists_after":false,"possible_deferred_destroy":true,"message":null}},{{"point":{p1},"status":"released","released":true,"exists_after":true,"possible_deferred_destroy":false,"message":null}}]}}}}"#
            )
        );

        let mut fixture = Fixture::new(2);
        let protection = acquire(&mut fixture);
        fixture.snapshots[0].holds.clear();
        fixture.snapshots[1].defer_destroy = true;
        let failure = recover_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap_err();
        assert_eq!(
            wire(&protection, &failure),
            format!(
                r#"{{"kind":"preservation_refused","message":"snapshot-preserving release requires the exact held snapshot without deferred destruction: tank/data@s1","outcome":{{"receipt":{receipt},"report":{{"schema_version":2,"tag":"TAG","points":[{{"point":{p0},"status":"already_unpinned","released":false,"exists_after":true,"possible_deferred_destroy":false,"message":null}},{{"point":{p1},"status":"uncertain","released":false,"exists_after":true,"possible_deferred_destroy":false,"message":"owned hold remains; release has not been attempted"}}]}}}}}}"#
            )
        );
    }

    #[test]
    fn persistence_failure_retains_complete_intent_without_native_work() {
        let fixture = Fixture::new(2);
        let request = fixture.request();
        let result = prepare_and_persist(&request.points, &request.consumer, |receipt| {
            assert_eq!(receipt.points(), request.points);
            Err(Error::new("intent store unavailable"))
        });
        let failure = match result {
            Err(failure) => failure,
            Ok(_) => panic!("failed persistence admitted acquisition"),
        };
        assert_eq!(failure.kind, "intent_persistence");
        assert_eq!(failure.intended_receipt.unwrap().points(), request.points);
        assert!(fixture.calls.is_empty());
        assert_eq!(fixture.effects, 0);
    }

    #[test]
    fn successful_protection_runs_only_after_complete_intent_is_recorded() {
        let mut fixture = Fixture::new(2);
        let persisted = Cell::new(false);
        let request = fixture.request();
        let (prepared, intent) =
            prepare_and_persist(&request.points, &request.consumer, |receipt| {
                assert_eq!(receipt.points(), request.points);
                persisted.set(true);
                Ok(())
            })
            .unwrap();
        let protection = execute_prepared_with(prepared, &intent, &mut || Ok(()), &mut |p, a| {
            assert!(persisted.get());
            fixture.run(p, a)
        })
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(protection.receipt(), &intent);
        let outcome = serde_json::to_value(protection.outcome()).unwrap();
        assert_eq!(
            outcome["intended_receipt"]["points"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let holds = fixture
            .snapshots
            .iter()
            .map(|s| s.holds.clone())
            .collect::<Vec<_>>();
        drop(protection);
        assert_eq!(
            fixture
                .snapshots
                .iter()
                .map(|s| s.holds.clone())
                .collect::<Vec<_>>(),
            holds
        );
        fixture.no_compensation();
    }

    #[test]
    fn acquisition_failure_preserves_partial_and_uncertain_receipts() {
        for behavior in [Behavior::SecondFailure, Behavior::FailedWithHold] {
            let mut fixture = Fixture::new(2);
            fixture.behavior = behavior;
            let request = fixture.request();
            let (prepared, intent) =
                prepare_and_persist(&request.points, &request.consumer, |_| Ok(())).unwrap();
            let failure =
                match execute_prepared_with(prepared, &intent, &mut || Ok(()), &mut |p, a| {
                    fixture.run(p, a)
                }) {
                    Err(failure) => failure,
                    Ok(_) => panic!("incomplete acquisition reported success"),
                };
            assert_eq!(failure.intended_receipt.as_deref(), Some(&intent));
            assert_eq!(failure.tag.as_deref(), Some(intent.tag()));
            if behavior == Behavior::SecondFailure {
                assert_eq!(failure.partial_lease.unwrap().points().len(), 1);
                assert!(failure.uncertain_names.is_empty());
            } else {
                assert!(failure.partial_lease.is_none());
                assert_eq!(
                    failure.uncertain_names,
                    vec![request.points[0].name.clone()]
                );
            }
            assert!(
                fixture.snapshots[0]
                    .holds
                    .iter()
                    .any(|tag| tag == intent.tag())
            );
            fixture.no_compensation();
        }
    }

    #[test]
    fn live_reader_guard_refuses_recovery_without_native_work() {
        let mut fixture = Fixture::new(2);
        let protection = acquire(&mut fixture);
        let before = fixture.effects;
        fixture.calls.clear();
        let failure = recover_with(
            protection.receipt(),
            ReleasePolicy::EndProtection,
            &mut || Err(Error::new("reader custody remains live")),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap_err();
        assert_eq!(failure.kind, "lifecycle_refused");
        assert_eq!(&failure.outcome.receipt, protection.receipt());
        assert_eq!(fixture.effects, before);
        assert!(fixture.calls.is_empty());
        assert!(
            fixture
                .snapshots
                .iter()
                .all(|snapshot| !snapshot.holds.is_empty())
        );
    }

    #[test]
    fn revalidation_requires_live_guard_exact_held_points_and_current_admission() {
        let mut fixture = Fixture::new(2);
        let protection = acquire(&mut fixture);
        fixture.calls.clear();
        assert!(
            revalidate_with(
                protection.receipt(),
                &mut || Err(Error::new("custody lost")),
                &mut |p, a| fixture.run(p, a)
            )
            .is_err()
        );
        assert!(fixture.calls.is_empty());
        let observed = revalidate_with(protection.receipt(), &mut || Ok(()), &mut |p, a| {
            fixture.run(p, a)
        })
        .unwrap();
        assert_eq!(observed, protection.receipt().points());
        fixture.snapshots[1].holds.clear();
        assert!(
            revalidate_with(protection.receipt(), &mut || Ok(()), &mut |p, a| fixture
                .run(p, a))
            .is_err()
        );
        fixture.snapshots[1]
            .holds
            .push(protection.receipt().tag().into());
        fixture.snapshots[1].defer_destroy = true;
        assert!(
            revalidate_with(protection.receipt(), &mut || Ok(()), &mut |p, a| fixture
                .run(p, a))
            .is_err()
        );
        fixture.no_compensation();
    }

    #[test]
    fn guard_is_rechecked_immediately_before_release() {
        let mut fixture = Fixture::new(1);
        let protection = acquire(&mut fixture);
        let before = fixture.effects;
        let allowed = Cell::new(true);
        let result = end_with(
            protection.receipt(),
            ReleasePolicy::EndProtection,
            &mut || {
                if allowed.get() {
                    Ok(())
                } else {
                    Err(Error::new("lifecycle custody lost"))
                }
            },
            &mut |p, a| {
                let result = fixture.run(p, a);
                if a[0] == "holds" {
                    allowed.set(false);
                }
                result
            },
        );
        assert!(result.is_err());
        assert_eq!(fixture.effects, before);
        fixture.no_compensation();
    }

    #[test]
    fn preserving_release_refuses_whole_scope_before_effects() {
        let mut fixture = Fixture::new(2);
        let protection = acquire(&mut fixture);
        fixture.snapshots[1].defer_destroy = true;
        let before = fixture.effects;
        let failure = end_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap_err();
        assert_eq!(failure.kind, "preservation_refused");
        assert_eq!(failure.outcome.receipt.points().len(), 2);
        assert!(failure.outcome.report.points.is_empty());
        assert_eq!(fixture.effects, before);
        fixture.no_compensation();
    }

    #[test]
    fn explicit_end_reports_possible_deferred_destroy() {
        let mut fixture = Fixture::new(1);
        let protection = acquire(&mut fixture);
        fixture.snapshots[0].defer_destroy = true;
        let outcome = end_with(
            protection.receipt(),
            ReleasePolicy::EndProtection,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap();
        assert_eq!(outcome.receipt.points().len(), 1);
        assert_eq!(
            outcome.report.points[0].status,
            ReaderReleaseStatus::Released
        );
        assert_eq!(outcome.report.points[0].exists_after, Some(false));
        assert!(outcome.report.points[0].possible_deferred_destroy);
        assert!(!fixture.calls.iter().any(|args| args[0] == "destroy"));
    }

    #[test]
    fn lost_release_reply_is_reconciled_for_both_policies() {
        for policy in [
            ReleasePolicy::EndProtection,
            ReleasePolicy::PreserveSnapshots,
        ] {
            let mut fixture = Fixture::new(2);
            let protection = acquire(&mut fixture);
            let outcome = end_with(protection.receipt(), policy, &mut || Ok(()), &mut |p, a| {
                let result = fixture.run(p, a);
                if a[0] == "release" {
                    Err(engine::Error::Command {
                        program: p,
                        args: a.to_vec(),
                        detail: "reply lost".into(),
                    })
                } else {
                    result
                }
            })
            .unwrap();
            assert_eq!(outcome.report.points.len(), 2);
            assert!(
                outcome
                    .report
                    .points
                    .iter()
                    .all(|point| point.status == ReaderReleaseStatus::Released
                        && point.exists_after == Some(true))
            );
        }
    }

    #[test]
    fn preservation_uncertainty_retains_remaining_holds_and_complete_scope() {
        let mut fixture = Fixture::new(2);
        let protection = acquire(&mut fixture);
        fixture.behavior = Behavior::ReleaseFailure;
        let before = fixture.effects;
        let failure = end_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap_err();
        assert_eq!(failure.kind, "preservation_uncertain");
        assert_eq!(failure.outcome.receipt.points().len(), 2);
        assert_eq!(failure.outcome.report.points.len(), 1);
        assert_eq!(fixture.effects, before + 1);
        assert!(
            fixture
                .snapshots
                .iter()
                .all(|snapshot| !snapshot.holds.is_empty())
        );
    }

    #[test]
    fn recovery_resumes_interrupted_preserving_release_without_releasing_twice() {
        let mut fixture = Fixture::new(3);
        let protection = acquire(&mut fixture);
        let allowed = Cell::new(true);
        // The first release takes effect, then custody is lost before readback.
        // The old operation cannot claim completion or release the next point.
        let interrupted = end_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || {
                if allowed.get() {
                    Ok(())
                } else {
                    Err(Error::new("supervisor interrupted"))
                }
            },
            &mut |p, a| {
                let result = fixture.run(p, a);
                if a[0] == "release" {
                    allowed.set(false);
                }
                result
            },
        )
        .unwrap_err();
        assert_eq!(interrupted.kind, "preservation_uncertain");
        assert!(fixture.snapshots[0].holds.is_empty());
        assert!(
            fixture.snapshots[1..]
                .iter()
                .all(|snapshot| !snapshot.holds.is_empty())
        );
        let before = fixture.effects;
        fixture.calls.clear();
        let recovered = recover_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap();
        assert_eq!(&recovered.receipt, protection.receipt());
        assert_eq!(recovered.report.points.len(), 3);
        assert_eq!(
            recovered.report.points[0].status,
            ReaderReleaseStatus::AlreadyReleased
        );
        // The receipt wire value predates the rename.
        assert_eq!(
            serde_json::to_value(recovered.report.points[0].status).unwrap(),
            "already_unpinned"
        );
        assert!(!recovered.report.points[0].released);
        assert!(
            recovered.report.points[1..]
                .iter()
                .all(|point| point.status == ReaderReleaseStatus::Released)
        );
        assert_eq!(fixture.effects, before + 2);
        let releases = fixture
            .calls
            .iter()
            .filter(|args| args[0] == "release")
            .collect::<Vec<_>>();
        assert_eq!(releases.len(), 2);
        assert!(
            releases
                .iter()
                .all(|args| args[2] != protection.receipt().points()[0].name)
        );
    }

    #[test]
    fn preserving_recovery_reports_proven_absence_without_claiming_a_cause() {
        let mut fixture = Fixture::new(2);
        let protection = acquire(&mut fixture);
        fixture.snapshots.remove(0);
        let before = fixture.effects;
        let recovered = recover_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap();
        let missing = &recovered.report.points[0];
        assert_eq!(missing.status, ReaderReleaseStatus::NotFound);
        assert_eq!(missing.exists_after, Some(false));
        assert!(!missing.released);
        assert!(!missing.possible_deferred_destroy);
        assert_eq!(
            recovered.report.points[1].status,
            ReaderReleaseStatus::Released
        );
        assert_eq!(fixture.effects, before + 1);

        fixture.snapshots.clear();
        let before = fixture.effects;
        let no_holds = recover_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap();
        assert!(
            no_holds
                .report
                .points
                .iter()
                .all(|point| point.status == ReaderReleaseStatus::NotFound)
        );
        assert_eq!(fixture.effects, before);
    }

    #[test]
    fn recovery_observes_the_whole_scope_and_refuses_all_effects_on_drift() {
        for policy in [
            ReleasePolicy::EndProtection,
            ReleasePolicy::PreserveSnapshots,
        ] {
            let mut fixture = Fixture::new(3);
            let protection = acquire(&mut fixture);
            fixture.snapshots[0].holds.clear();
            fixture.snapshots[2].identity.createtxg = crate::Txg::new(999);
            let before = fixture.effects;
            fixture.calls.clear();
            let failure =
                recover_with(protection.receipt(), policy, &mut || Ok(()), &mut |p, a| {
                    fixture.run(p, a)
                })
                .unwrap_err();
            assert_eq!(failure.kind, "recovery_refused");
            assert_eq!(failure.outcome.receipt.points().len(), 3);
            assert_eq!(failure.outcome.report.points.len(), 3);
            assert_eq!(
                failure.outcome.report.points[0].status,
                ReaderReleaseStatus::AlreadyReleased
            );
            assert_eq!(
                failure.outcome.report.points[1].status,
                ReaderReleaseStatus::Uncertain
            );
            assert_eq!(
                failure.outcome.report.points[2].status,
                ReaderReleaseStatus::Changed
            );
            assert_eq!(fixture.effects, before);
            assert!(
                fixture.snapshots[1..]
                    .iter()
                    .all(|snapshot| !snapshot.holds.is_empty())
            );
            fixture.no_compensation();
        }
    }

    #[test]
    fn preserving_recovery_preflights_the_remaining_subset_before_any_release() {
        let mut fixture = Fixture::new(3);
        let protection = acquire(&mut fixture);
        fixture.snapshots[0].holds.clear();
        fixture.snapshots[2].defer_destroy = true;
        let before = fixture.effects;
        fixture.calls.clear();
        let failure = recover_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || Ok(()),
            &mut |p, a| fixture.run(p, a),
        )
        .unwrap_err();
        assert_eq!(failure.kind, "preservation_refused");
        assert_eq!(failure.outcome.report.points.len(), 3);
        assert_eq!(
            failure.outcome.report.points[0].status,
            ReaderReleaseStatus::AlreadyReleased
        );
        assert_eq!(fixture.effects, before);
        assert!(
            fixture.snapshots[1..]
                .iter()
                .all(|snapshot| !snapshot.holds.is_empty())
        );
        fixture.no_compensation();
    }

    #[test]
    fn uncertain_recovery_observation_retains_every_remaining_hold() {
        let mut fixture = Fixture::new(2);
        let protection = acquire(&mut fixture);
        let last_name = protection.receipt().points()[1].name.clone();
        let before = fixture.effects;
        fixture.calls.clear();
        let failure = recover_with(
            protection.receipt(),
            ReleasePolicy::PreserveSnapshots,
            &mut || Ok(()),
            &mut |p, a| {
                if a[0] == "holds" && a.contains(&last_name) {
                    Err(engine::Error::Command {
                        program: p,
                        args: a.to_vec(),
                        detail: "observation unavailable".into(),
                    })
                } else {
                    fixture.run(p, a)
                }
            },
        )
        .unwrap_err();
        assert_eq!(failure.kind, "recovery_refused");
        assert_eq!(failure.outcome.report.points.len(), 2);
        assert_eq!(
            failure.outcome.report.points[1].status,
            ReaderReleaseStatus::Uncertain
        );
        assert_eq!(fixture.effects, before);
        fixture.no_compensation();
    }
}
