//! One operation's durable intent: a single versioned record in the
//! `zboot:operation` user property of the root dataset of the pool that
//! survives the operation. An operation with more than one durable effect
//! writes it before its first effect, advances it as steps complete and clears
//! it on completion; `resume` finds it by listing pool roots.
//!
//! A record is one `zfs set`, which returns only after its transaction group
//! is on disk, so the record itself has no chunks, headers or tombstones.
//! Records name roots, snapshot boundaries and member digests, never member
//! lists, and an encoding over the 6000-byte limit is refused before anything
//! is written. Every write is read back: a write whose reply was lost is
//! recognised by its value. Callers hold the [writer lock](crate::engine::lock)
//! across read, effect and write.
//!
//! This record is the pool's one operation slot and the only entry `resume`
//! takes. A payload too large for it (a transfer's frozen plan, restore's
//! receipt) is a write-once [attachment](crate::engine::attachment) on a
//! dataset of the same pool, which the record names from the write that
//! commits it until no step reads it again; the record is cleared last.
use crate::engine::{Error, native};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub use super::management::OPERATION_PROPERTY as PROPERTY;
/// ZFS refuses a user-property value of this many bytes or more.
const ZFS_VALUE_BYTES: usize = 8192;
/// The largest record, which keeps 2 KiB clear of ZFS's value limit. A
/// restore record with long kept-tree names is the largest.
pub const LIMIT: usize = 6000;
const _: () = assert!(
    LIMIT + 2048 <= ZFS_VALUE_BYTES,
    "a record fits one ZFS user-property value"
);
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent<T> {
    pub schema_version: u32,
    /// The operation id `zboot resume` takes.
    pub id: String,
    /// The verb that owns the record, e.g. `restore`.
    pub kind: String,
    /// The last step known complete; the operation's own numbering.
    pub step: u32,
    pub state: T,
}
impl<T> Intent<T> {
    pub fn new(id: impl Into<String>, kind: impl Into<String>, state: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            id: id.into(),
            kind: kind.into(),
            step: 0,
            state,
        }
    }
}

/// What a pool root holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    Record(Intent<serde_json::Value>),
    /// Present but not a record this version reads; never acted on.
    Unreadable(String),
}

pub trait Backend {
    fn pools(&mut self) -> Result<Vec<String>, Error>;
    /// The locally set value on `pool`'s root, if any.
    fn read(&mut self, pool: &str) -> Result<Option<String>, Error>;
    fn write(&mut self, pool: &str, value: &str) -> Result<(), Error>;
    fn remove(&mut self, pool: &str) -> Result<(), Error>;
}

pub struct Native;
impl Backend for Native {
    fn pools(&mut self) -> Result<Vec<String>, Error> {
        let out = native::run("zpool", &args(&["list", "-H", "-o", "name"]))?;
        Ok(out.lines().map(str::to_string).collect())
    }
    fn read(&mut self, pool: &str) -> Result<Option<String>, Error> {
        validate_pool(pool)?;
        let out = native::run(
            "zfs",
            &args(&["get", "-Hp", "-o", "value,source", PROPERTY, pool]),
        )?;
        let line = out.strip_suffix('\n').unwrap_or(&out);
        let (value, source) = line.rsplit_once('\t').ok_or_else(|| Error::Parse {
            subject: "zfs get",
            detail: format!("{PROPERTY} on {pool}"),
        })?;
        Ok((source == "local").then(|| value.to_string()))
    }
    fn write(&mut self, pool: &str, value: &str) -> Result<(), Error> {
        validate_pool(pool)?;
        if self.read(pool)?.as_deref() == Some(value) {
            return Ok(());
        }
        native::run_mutating(
            "zfs",
            &["set".into(), format!("{PROPERTY}={value}"), pool.into()],
        )
        .map(drop)
    }
    fn remove(&mut self, pool: &str) -> Result<(), Error> {
        validate_pool(pool)?;
        if self.read(pool)?.is_none() {
            return Ok(());
        }
        native::run_mutating("zfs", &args(&["inherit", PROPERTY, pool])).map(drop)
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

fn validate_pool(pool: &str) -> Result<(), Error> {
    crate::engine::validate_dataset_name(pool)?;
    if pool.contains('/') {
        return Err(Error::InvalidScope(pool.to_string()));
    }
    Ok(())
}

fn refuse(detail: String) -> Error {
    Error::Inconsistent(detail)
}

/// The exact stored form, refused before any effect when it is too large.
pub fn encode<T: Serialize>(intent: &Intent<T>) -> Result<String, Error> {
    encode_or(intent, "nothing changed")
}
fn encode_or<T: Serialize>(intent: &Intent<T>, consequence: &str) -> Result<String, Error> {
    let value = serde_json::to_string(intent).map_err(|e| refuse(e.to_string()))?;
    if value.len() > LIMIT {
        return Err(refuse(format!(
            "operation {} record is {} bytes, over the {LIMIT}-byte limit; {consequence}",
            intent.id,
            value.len()
        )));
    }
    Ok(value)
}

/// Record a new operation on `pool`, which must hold none.
pub fn begin<T: Serialize>(
    backend: &mut impl Backend,
    pool: &str,
    intent: &Intent<T>,
) -> Result<(), Error> {
    let value = encode(intent)?;
    if let Some(current) = backend.read(pool)? {
        return Err(refuse(format!(
            "pool {pool} already records an operation ({}); resume or abandon it first",
            describe(&current)
        )));
    }
    replace(backend, pool, None, Some(&value))
}

/// Replace `previous`, which must be what `pool` holds, by `next`.
pub fn advance<T: Serialize>(
    backend: &mut impl Backend,
    pool: &str,
    previous: &Intent<T>,
    next: &Intent<T>,
) -> Result<(), Error> {
    let old = encode(previous)?;
    let new = encode_or(next, "the record keeps its previous step")?;
    expect(backend, pool, &old)?;
    replace(backend, pool, Some(&old), Some(&new))
}

/// Clear `last`, which must be what `pool` holds.
pub fn finish<T: Serialize>(
    backend: &mut impl Backend,
    pool: &str,
    last: &Intent<T>,
) -> Result<(), Error> {
    let old = encode(last)?;
    expect(backend, pool, &old)?;
    replace(backend, pool, Some(&old), None)
}

/// The record on `pool` decoded as `T`, if any.
#[cfg(test)]
pub fn read<T: DeserializeOwned>(
    backend: &mut impl Backend,
    pool: &str,
) -> Result<Option<Intent<T>>, Error> {
    backend
        .read(pool)?
        .map(|value| decode(&value).map_err(|e| refuse(format!("pool {pool}: {e}"))))
        .transpose()
}

/// Every pool root holding a record, in pool order.
pub fn find(backend: &mut impl Backend) -> Result<Vec<(String, Found)>, Error> {
    let mut found = Vec::new();
    for pool in backend.pools()? {
        if let Some(value) = backend.read(&pool)? {
            let entry = match decode(&value) {
                Ok(intent) => Found::Record(intent),
                Err(e) => Found::Unreadable(e),
            };
            found.push((pool, entry));
        }
    }
    Ok(found)
}

/// The one refusal for a `kind` record this zboot did not write. Only records
/// written by this build are resumed or abandoned; delivery requires a host
/// with no open operation (DESIGN, "Consumers and compatibility").
pub fn earlier(kind: &str, id: &str) -> String {
    format!(
        "{id} is a {kind} record from an earlier zboot; finish or abandon it with the build that started it"
    )
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<Intent<T>, String> {
    let version = serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .and_then(|v| v.get("schema_version").and_then(|v| v.as_u64()));
    if version != Some(u64::from(SCHEMA_VERSION)) {
        return Err(format!(
            "operation record has schema version {}, not {SCHEMA_VERSION}",
            version.map_or("none".to_string(), |v| v.to_string())
        ));
    }
    serde_json::from_str(value).map_err(|e| format!("operation record does not decode: {e}"))
}

fn describe(value: &str) -> String {
    match decode::<serde_json::Value>(value) {
        Ok(intent) => format!("{} {}", intent.kind, intent.id),
        Err(e) => e,
    }
}

fn expect(backend: &mut impl Backend, pool: &str, expected: &str) -> Result<(), Error> {
    match backend.read(pool)? {
        Some(current) if current == expected => Ok(()),
        Some(current) => Err(refuse(format!(
            "pool {pool} records a different operation state ({}); nothing changed",
            describe(&current)
        ))),
        None => Err(refuse(format!(
            "pool {pool} no longer records the operation; nothing changed"
        ))),
    }
}

/// One write, judged by reading it back: a lost reply that did apply is
/// success, a failure that left the old value is that failure, and anything
/// else is reported as uncertain rather than guessed at.
fn replace(
    backend: &mut impl Backend,
    pool: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> Result<(), Error> {
    if old == new {
        return Ok(());
    }
    for value in old.into_iter().chain(new) {
        if let Ok(record) = decode::<serde_json::Value>(value) {
            crate::engine::effect::operation_hint(&record.id);
        }
    }
    let result = match new {
        Some(value) => backend.write(pool, value),
        None => backend.remove(pool),
    };
    let after = backend.read(pool)?;
    if after.as_deref() == new {
        return Ok(());
    }
    if after.as_deref() == old {
        return Err(result
            .err()
            .unwrap_or_else(|| refuse(format!("pool {pool} kept its previous operation record"))));
    }
    Err(refuse(format!(
        "pool {pool} operation record is neither the previous nor the new state after a write; \
         inspect it with `zboot status`"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Fake {
        values: BTreeMap<String, String>,
        writes: usize,
        /// Apply the next write but report failure, as a lost reply would.
        lose_reply: bool,
        /// Fail the next write without applying it.
        fail: bool,
        /// Apply something else entirely on the next write.
        garble: bool,
    }
    impl Fake {
        fn mutate(&mut self, pool: &str, value: Option<&str>) -> Result<(), Error> {
            self.writes += 1;
            let error = || Error::Command {
                program: "zfs",
                args: vec![],
                detail: "connection lost".into(),
            };
            if std::mem::take(&mut self.fail) {
                return Err(error());
            }
            if std::mem::take(&mut self.garble) {
                self.values.insert(pool.into(), "{}".into());
                return Ok(());
            }
            match value {
                Some(value) => self.values.insert(pool.into(), value.into()),
                None => self.values.remove(pool),
            };
            if std::mem::take(&mut self.lose_reply) {
                return Err(error());
            }
            Ok(())
        }
    }
    impl Backend for Fake {
        fn pools(&mut self) -> Result<Vec<String>, Error> {
            Ok(vec!["apool".into(), "rpool".into()])
        }
        fn read(&mut self, pool: &str) -> Result<Option<String>, Error> {
            Ok(self.values.get(pool).cloned())
        }
        fn write(&mut self, pool: &str, value: &str) -> Result<(), Error> {
            self.mutate(pool, Some(value))
        }
        fn remove(&mut self, pool: &str) -> Result<(), Error> {
            self.mutate(pool, None)
        }
    }

    fn intent(step: u32) -> Intent<BTreeMap<String, String>> {
        let mut intent = Intent::new("0123456789abcdef", "restore", BTreeMap::new());
        intent.step = step;
        intent
            .state
            .insert("source".into(), "apool/ROOT/be1@zboot-1".into());
        intent
    }

    #[test]
    fn a_record_is_begun_advanced_and_finished_in_one_property() {
        let mut fake = Fake::default();
        begin(&mut fake, "apool", &intent(0)).unwrap();
        advance(&mut fake, "apool", &intent(0), &intent(1)).unwrap();
        assert_eq!(read(&mut fake, "apool").unwrap(), Some(intent(1)));
        let found = find(&mut fake).unwrap();
        assert_eq!(found.len(), 1);
        assert!(matches!(&found[0], (pool, Found::Record(r)) if pool == "apool" && r.step == 1));
        finish(&mut fake, "apool", &intent(1)).unwrap();
        assert!(find(&mut fake).unwrap().is_empty());
    }

    #[test]
    fn an_oversized_record_is_refused_before_any_write() {
        let mut fake = Fake::default();
        let mut big = intent(0);
        big.state.insert("members".into(), "x".repeat(LIMIT));
        let error = begin(&mut fake, "apool", &big).unwrap_err().to_string();
        assert!(error.contains("over the 6000-byte limit"), "{error}");
        assert_eq!(fake.writes, 0);
        assert!(fake.values.is_empty());
    }

    #[test]
    fn a_lost_reply_that_applied_is_success_and_one_that_did_not_is_failure() {
        let mut fake = Fake {
            lose_reply: true,
            ..Fake::default()
        };
        begin(&mut fake, "apool", &intent(0)).unwrap();
        fake.fail = true;
        let error = advance(&mut fake, "apool", &intent(0), &intent(1)).unwrap_err();
        assert!(error.to_string().contains("connection lost"), "{error}");
        assert_eq!(read(&mut fake, "apool").unwrap(), Some(intent(0)));
        fake.lose_reply = true;
        finish(&mut fake, "apool", &intent(0)).unwrap();
        assert!(fake.values.is_empty());
    }

    #[test]
    fn an_unexpected_value_after_a_write_is_uncertain_not_guessed() {
        let mut fake = Fake::default();
        begin(&mut fake, "apool", &intent(0)).unwrap();
        fake.garble = true;
        let error = advance(&mut fake, "apool", &intent(0), &intent(1)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("neither the previous nor the new"),
            "{error}"
        );
    }

    #[test]
    fn a_pool_holds_one_operation_and_stale_state_is_refused() {
        let mut fake = Fake::default();
        begin(&mut fake, "apool", &intent(0)).unwrap();
        let mut other = intent(0);
        other.id = "fedcba9876543210".into();
        let error = begin(&mut fake, "apool", &other).unwrap_err().to_string();
        assert!(
            error.contains("already records an operation (restore 0123456789abcdef)"),
            "{error}"
        );
        let error = advance(&mut fake, "apool", &intent(1), &intent(2))
            .unwrap_err()
            .to_string();
        assert!(error.contains("different operation state"), "{error}");
        finish(&mut fake, "apool", &intent(0)).unwrap();
        let error = finish(&mut fake, "apool", &intent(0))
            .unwrap_err()
            .to_string();
        assert!(error.contains("no longer records"), "{error}");
        assert_eq!(fake.writes, 2);
    }

    #[test]
    fn foreign_versions_are_reported_not_read() {
        let mut fake = Fake::default();
        fake.values.insert(
            "rpool".into(),
            r#"{"schema_version":2,"id":"x","kind":"restore","step":0,"state":{}}"#.into(),
        );
        let found = find(&mut fake).unwrap();
        assert!(matches!(&found[..], [(pool, Found::Unreadable(e))]
            if pool == "rpool" && e.contains("schema version 2")));
        assert!(read::<serde_json::Value>(&mut fake, "rpool").is_err());
        let error = begin(&mut fake, "rpool", &intent(0))
            .unwrap_err()
            .to_string();
        assert!(error.contains("schema version 2"), "{error}");
    }
}
