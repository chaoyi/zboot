//! `zboot-boot` library facade — exposes the menu layout primitives so
//! integration tests in `boot/tests/` can drive `menu::run_with` against
//! synthetic forests without touching the binary's `main`.
//!
//! The crate's primary form is the `zboot-boot` binary (see `main.rs`);
//! this lib target exists purely for testability.

pub mod discover;
pub mod kexec;
pub mod menu;
pub mod preinit;
pub mod shell;
