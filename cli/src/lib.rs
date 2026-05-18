//! `zboot_cli` — verb implementations exposed as a library.
//!
//! Two consumers:
//! - `zboot` binary (`src/main.rs`) — the operator-facing CLI. Built
//!   with default features → `cmd::{deploy, live, efi}` are present
//!   and bundle `zboot-boot.efi` via `include_bytes!`.
//! - `zboot-boot` (PID 1 in the EFI initrd) — depends on this crate
//!   with `default-features = false` and calls the verb functions
//!   directly from its post-halt shell instead of forking `/sbin/zboot`.
//!   Embed is omitted → the initrd never carries a copy of the EFI
//!   bytes, breaking the size feedback loop.

pub mod be_arg;
pub mod cmd;
pub mod pools;
pub mod sub;
pub mod zfs_ops;
