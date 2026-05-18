//! `zboot-core` — pure-data primitives for zboot.
//!
//! No I/O. The crate accepts text output from `zfs(8)` / `zpool(8)` and produces
//! typed values. Both `zboot-cli` and `zboot-boot` depend on this crate for the
//! shared data model.
//!
//! See `DESIGN.md` for the boot-environment / forest conceptual model.

pub mod parse;
pub mod replication;
pub mod types;

pub use parse::{
    ParseError, parse_property, parse_zfs_get, parse_zfs_list_snapshots, parse_zpool_list,
};
pub use replication::{PairPointer, PairStatus, human_bytes, is_replication_anchor};
pub use types::{
    AtomicSet, BootEnvironment, BoundKey, BoundList, Canmount, Forest, Mountpoint, Pool, PoolRole,
    Property, Snapshot, SnapshotRef,
};
