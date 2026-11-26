//! Tagged native holds on exact snapshots. Each call re-resolves the snapshot
//! by its native identity before acting and judges the outcome by reading the
//! holds back, so a lost reply is neither repeated nor mistaken for failure.
//! Holds keep a snapshot from being destroyed; they do not stop renames,
//! rollbacks of newer history or uncooperating writers. Releasing the last
//! hold of a snapshot already marked for deferred destroy destroys it, which
//! [`Released::Destroyed`] reports. Tags are `zboot:<purpose>[:<id>]`.
use crate::engine::{Error, Snapshot, SnapshotRef, native};

/// A snapshot as resolved now: its current name and tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub name: String,
    pub holds: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    HoldRemoved,
    /// The tag was not held; nothing was done.
    NotHeld,
    /// The snapshot no longer exists, so neither does the hold.
    Destroyed,
}

pub trait Backend {
    /// `None` only when the snapshot is proven absent.
    fn resolve(&mut self, point: &SnapshotRef) -> Result<Option<Seen>, Error>;
    fn hold(&mut self, name: &str, tag: &str) -> Result<(), Error>;
    fn release(&mut self, name: &str, tag: &str) -> Result<(), Error>;
}

pub struct Native;
impl Backend for Native {
    fn resolve(&mut self, point: &SnapshotRef) -> Result<Option<Seen>, Error> {
        match native::resolve_with(point, &mut native::run) {
            Ok(snapshot) => Ok(Some(seen(&snapshot))),
            Err(Error::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn hold(&mut self, name: &str, tag: &str) -> Result<(), Error> {
        native::run_mutating("zfs", &["hold".into(), tag.into(), name.into()]).map(drop)
    }
    fn release(&mut self, name: &str, tag: &str) -> Result<(), Error> {
        native::run_mutating("zfs", &["release".into(), tag.into(), name.into()]).map(drop)
    }
}

fn seen(snapshot: &Snapshot) -> Seen {
    Seen {
        name: snapshot.name.clone(),
        holds: snapshot.holds.clone(),
    }
}

pub fn validate_tag(tag: &str) -> Result<(), Error> {
    let valid = tag.starts_with("zboot:")
        && tag.len() <= 255
        && !tag.chars().any(|c| c.is_control() || c.is_whitespace());
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidScope(format!("hold tag {tag}")))
    }
}

fn gone(point: &SnapshotRef) -> Error {
    Error::NotFound(point.name.clone())
}

/// Hold `point` with `tag`; already holding it is success.
pub fn hold(backend: &mut impl Backend, point: &SnapshotRef, tag: &str) -> Result<(), Error> {
    validate_tag(tag)?;
    let before = backend.resolve(point)?.ok_or_else(|| gone(point))?;
    if before.holds.iter().any(|t| t == tag) {
        return Ok(());
    }
    let result = backend.hold(&before.name, tag);
    match backend.resolve(point)? {
        Some(after) if after.holds.iter().any(|t| t == tag) => Ok(()),
        Some(_) => Err(result.err().unwrap_or_else(|| {
            Error::Inconsistent(format!("hold {tag} did not appear on {}", before.name))
        })),
        None => Err(gone(point)),
    }
}

/// Release `tag` from `point`.
pub fn release(
    backend: &mut impl Backend,
    point: &SnapshotRef,
    tag: &str,
) -> Result<Released, Error> {
    validate_tag(tag)?;
    let Some(before) = backend.resolve(point)? else {
        return Ok(Released::Destroyed);
    };
    if !before.holds.iter().any(|t| t == tag) {
        return Ok(Released::NotHeld);
    }
    let result = backend.release(&before.name, tag);
    match backend.resolve(point)? {
        None => Ok(Released::Destroyed),
        Some(after) if !after.holds.iter().any(|t| t == tag) => Ok(Released::HoldRemoved),
        Some(_) => Err(result.err().unwrap_or_else(|| {
            Error::Inconsistent(format!("hold {tag} is still on {}", before.name))
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Guid, ObjsetId, SnapshotIdentity, Txg};

    #[derive(Default)]
    struct Fake {
        exists: bool,
        holds: Vec<String>,
        deferred: bool,
        calls: Vec<String>,
        lose_reply: bool,
        fail: bool,
        renamed: Option<String>,
    }
    impl Fake {
        fn effect(&mut self, call: String, apply: impl FnOnce(&mut Self)) -> Result<(), Error> {
            self.calls.push(call);
            let error = Error::Command {
                program: "zfs",
                args: vec![],
                detail: "connection lost".into(),
            };
            if std::mem::take(&mut self.fail) {
                return Err(error);
            }
            apply(self);
            if std::mem::take(&mut self.lose_reply) {
                return Err(error);
            }
            Ok(())
        }
    }
    impl Backend for Fake {
        fn resolve(&mut self, point: &SnapshotRef) -> Result<Option<Seen>, Error> {
            Ok(self.exists.then(|| Seen {
                name: self.renamed.clone().unwrap_or_else(|| point.name.clone()),
                holds: self.holds.clone(),
            }))
        }
        fn hold(&mut self, name: &str, tag: &str) -> Result<(), Error> {
            self.effect(format!("hold {tag} {name}"), |s| s.holds.push(tag.into()))
        }
        fn release(&mut self, name: &str, tag: &str) -> Result<(), Error> {
            self.effect(format!("release {tag} {name}"), |s| {
                s.holds.retain(|t| t != tag);
                if s.holds.is_empty() && s.deferred {
                    s.exists = false;
                }
            })
        }
    }

    fn point() -> SnapshotRef {
        SnapshotRef {
            name: "rpool/data@zboot-1".into(),
            dataset_guid: Guid::new(7),
            identity: SnapshotIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(2),
                createtxg: Txg::new(3),
                objsetid: ObjsetId::new(4),
            },
        }
    }
    fn fake() -> Fake {
        Fake {
            exists: true,
            ..Fake::default()
        }
    }
    const TAG: &str = "zboot:anchor";

    #[test]
    fn hold_is_idempotent_and_survives_a_lost_reply() {
        let mut fake = fake();
        fake.lose_reply = true;
        hold(&mut fake, &point(), TAG).unwrap();
        hold(&mut fake, &point(), TAG).unwrap();
        assert_eq!(fake.holds, vec![TAG]);
        assert_eq!(fake.calls.len(), 1);
    }

    #[test]
    fn a_failed_hold_is_reported_and_a_missing_snapshot_is_never_held() {
        let mut fake = fake();
        fake.fail = true;
        let error = hold(&mut fake, &point(), TAG).unwrap_err();
        assert!(error.to_string().contains("connection lost"), "{error}");
        fake.exists = false;
        assert!(matches!(
            hold(&mut fake, &point(), TAG),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn holds_follow_the_snapshot_identity_across_a_rename() {
        let mut fake = fake();
        fake.renamed = Some("rpool/moved@zboot-1".into());
        hold(&mut fake, &point(), TAG).unwrap();
        assert_eq!(fake.calls, vec![format!("hold {TAG} rpool/moved@zboot-1")]);
    }

    #[test]
    fn release_reports_unheld_released_and_deferred_destroy() {
        let mut fake = fake();
        assert_eq!(
            release(&mut fake, &point(), TAG).unwrap(),
            Released::NotHeld
        );
        fake.holds = vec![TAG.into(), "zsnap".into()];
        fake.lose_reply = true;
        assert_eq!(
            release(&mut fake, &point(), TAG).unwrap(),
            Released::HoldRemoved
        );
        fake.holds = vec![TAG.into()];
        fake.deferred = true;
        assert_eq!(
            release(&mut fake, &point(), TAG).unwrap(),
            Released::Destroyed
        );
        assert_eq!(
            release(&mut fake, &point(), TAG).unwrap(),
            Released::Destroyed
        );
        assert!(fake.calls.iter().all(|c| c.starts_with("release")));
    }

    #[test]
    fn tags_are_zboot_namespaced_and_printable() {
        for bad in ["anchor", "zboot:a b", "zboot:a\n", "-zboot"] {
            assert!(validate_tag(bad).is_err(), "{bad:?}");
        }
        validate_tag("zboot:restore:0123456789abcdef").unwrap();
    }
}
