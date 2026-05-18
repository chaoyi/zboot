//! `zboot` subcommands.  One module per verb; `deploy/` keeps its own
//! submodule layout because the verb is large enough to warrant it.
//!
//! `deploy`, `live`, and `efi` are gated on the `embed-efi` cargo
//! feature — they all consume the bundled `zboot-boot.efi` bytes via
//! `include_bytes!`. The `zboot` userspace binary always has the
//! feature on (default); `zboot-boot` depends on this crate with the
//! feature off, omitting the embed entirely.

pub mod attach;
pub mod chroot;
pub mod cmdline;
pub mod default;
pub mod drop;
pub mod fork;
pub mod factory;
pub mod mirror;
pub mod overlay;
pub mod pair;
pub mod primary;
pub mod pull;
pub mod push;
pub mod rename;
pub mod rollback;
pub mod snapshot;
pub mod status;

#[cfg(feature = "embed-efi")]
pub mod deploy;
#[cfg(feature = "embed-efi")]
pub mod efi;
#[cfg(feature = "embed-efi")]
pub mod esp;
#[cfg(feature = "embed-efi")]
pub mod live;
