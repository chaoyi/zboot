//! Native ZFS operations with identity-bound targets and owned writer sessions.
//!
//! Observations, including the read-only [`observe_inventory`] of a dataset
//! tree and [`observe_management`], are sequential evidence, not mutation
//! authority. Mutations use an owned [`WriterSession`] and revalidate their
//! exact scope before effects; an application's own native effects go
//! through [`WriterSession::admit_effects`] and its closed [`Effect`] shapes.
//! Implementation state, native command backends and operation records are
//! private.
//!
//! The hidden `engine` module is public only for this workspace's `zboot` and
//! `zsnap` applications. It is unsupported and unstable: it has no
//! compatibility promise and may change in any release. Other packages use
//! the supported API at the crate root.
#![cfg_attr(test, allow(clippy::disallowed_methods, reason = "test fixtures"))]
mod api;
mod effects;
/// Unsupported, unstable engine internals for `zboot` and `zsnap` only.
#[doc(hidden)]
pub mod engine;
mod inventory;
mod reader;

pub use api::*;
pub use effects::*;
pub use engine::{
    CanMount, DatasetIdentity, DatasetKind, Guid, ObjsetId, SnapshotIdentity, SnapshotRef, Txg,
};
pub use inventory::*;
pub use reader::*;
