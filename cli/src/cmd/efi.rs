//! Shared access to the embedded `zboot-boot.efi` bytes.
//!
//! `cli/build.rs` includes `boot/out/zboot-boot.efi` into the binary at
//! compile time (or an empty placeholder if `bash boot/build.sh` hasn't
//! been run yet).  Both `cmd::deploy` (for ESP install) and `cmd::live`
//! (to seed the PXE-staging tree) need those bytes — owning them here
//! keeps the binary from carrying two copies.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Bytes of `zboot-boot.efi` baked in at compile time.
///
/// Empty when the build couldn't find `boot/out/zboot-boot.efi`
/// (CLI built before `bash boot/build.sh`); callers fall back to
/// filesystem search in that case.
pub(crate) const EMBEDDED_EFI_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/zboot-boot.efi"));

/// Write the embedded bytes to `dest` (atomic replace).  Errors if the
/// embedded copy is empty (CLI was built without the bundle).
pub(crate) fn write_embedded(dest: &Path) -> Result<()> {
    if EMBEDDED_EFI_BYTES.is_empty() {
        bail!(
            "embedded zboot-boot.efi is empty — rebuild with \
             `bash boot/build.sh && cargo build --release`"
        );
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", dest.display()))?;
    }
    let tmp = dest.with_extension("efi.partial");
    std::fs::write(&tmp, EMBEDDED_EFI_BYTES)
        .with_context(|| format!("write embedded zboot-boot.efi to {}", tmp.display()))?;
    std::fs::rename(&tmp, dest)
        .with_context(|| format!("rename {} → {}", tmp.display(), dest.display()))?;
    Ok(())
}

/// Lazily extract the embedded EFI bytes to a fresh `/tmp` path.  Used
/// by `cmd::deploy` when no `ZBOOT_EFI_BUNDLE` override is set and no
/// on-disk copy is found at the standard locations.
pub(crate) fn extract_to_tmp() -> Result<PathBuf> {
    if EMBEDDED_EFI_BYTES.is_empty() {
        bail!("embedded zboot-boot.efi is empty placeholder");
    }
    let path = std::env::temp_dir().join(format!("zboot-boot-{}.efi", std::process::id()));
    std::fs::write(&path, EMBEDDED_EFI_BYTES)
        .with_context(|| format!("write embedded zboot-boot.efi to {}", path.display()))?;
    Ok(path)
}
