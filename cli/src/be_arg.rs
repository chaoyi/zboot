//! BE-argument parsing shared by every verb that takes a `<BE>` argument.
//!
//! Two operations:
//!
//! - [`split_be_snap`] — strip an optional `@<snap>` tail. Pure string op.
//! - [`resolve_be_dataset`] — qualify a bare BE name with the booted pool
//!   (the pool whose dataset is mounted at `/`). Full paths pass through.
//!
//! Why a dedicated module: push, pull, primary, rename, and rollback all
//! parse BE arguments the same way. Living together here avoids
//! `crate::cmd::push::...` cross-references from sibling verbs and gives
//! the parsing rules a single home.

use anyhow::Result;

use crate::zfs_ops;

/// Split a `be` or `be@snap` argument into the BE portion and an
/// optional snapshot name. The BE portion may itself contain `/`
/// (full dataset path); only the *last* `@` introduces the snapshot.
/// Empty BE or empty snap (`@snap`, `be@`) flow through as a single
/// token with `None` for the snap — the caller's existence checks
/// surface them as clear errors.
pub fn split_be_snap(arg: &str) -> (String, Option<String>) {
    match arg.rsplit_once('@') {
        Some((be, snap)) if !be.is_empty() && !snap.is_empty() => {
            (be.to_owned(), Some(snap.to_owned()))
        }
        _ => (arg.to_owned(), None),
    }
}

/// Resolve a BE argument to a full dataset path. Accepts:
///
/// - **Fully-qualified** (`rpool/ROOT/be1`): returned as-is.
/// - **Bare name** (`be1`): qualified against the *booted* pool — the
///   pool whose dataset is currently mounted at `/`. Matches operator
///   intuition ("be1" = "be1 on this pool"). Differs from `bootfs`
///   between a `default`/`primary` flip and the next reboot.
pub fn resolve_be_dataset(arg: &str) -> Result<String> {
    if arg.contains('/') {
        return Ok(arg.to_owned());
    }
    let booted_pool = zfs_ops::discover_booted_pool()?;
    Ok(format!("{booted_pool}/ROOT/{arg}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_bare() {
        let (be, snap) = split_be_snap("be1");
        assert_eq!(be, "be1");
        assert!(snap.is_none());
    }

    #[test]
    fn split_with_snap() {
        let (be, snap) = split_be_snap("be1@known-good");
        assert_eq!(be, "be1");
        assert_eq!(snap.as_deref(), Some("known-good"));
    }

    #[test]
    fn split_full_path_with_snap() {
        let (be, snap) = split_be_snap("rpool/ROOT/be1@milestone-3");
        assert_eq!(be, "rpool/ROOT/be1");
        assert_eq!(snap.as_deref(), Some("milestone-3"));
    }

    #[test]
    fn split_full_path_without_snap() {
        let (be, snap) = split_be_snap("rpool/ROOT/be1");
        assert_eq!(be, "rpool/ROOT/be1");
        assert!(snap.is_none());
    }

    #[test]
    fn split_empty_components_pass_through() {
        // `@snap` (no BE) and `be@` (no snap) flow through as a single
        // token with no split — caller-side existence checks catch them.
        let (be, snap) = split_be_snap("@snap");
        assert_eq!(be, "@snap");
        assert!(snap.is_none());
        let (be, snap) = split_be_snap("be1@");
        assert_eq!(be, "be1@");
        assert!(snap.is_none());
    }
}
