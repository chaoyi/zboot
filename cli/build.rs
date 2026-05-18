// build.rs — embed `zboot-boot.efi` into the CLI binary.
//
// At runtime, cmd::deploy::esp::resolve_efi_bundle() writes the embedded
// bytes to /tmp at deploy time and points the install at them, so the
// `zboot` CLI is self-contained — no separate /usr/share/zboot/zboot-boot.efi
// or wget-from-router step required.
//
// The EFI bundle is built by `boot/build.sh` (UKI: kernel + initrd +
// cmdline as PE sections; ~25MB).  Locate it at compile time via either:
//
//   1. ZBOOT_EFI_BUNDLE_BUILD env var — explicit override.
//   2. ../boot/out/zboot-boot.efi — default, the workspace path
//      `boot/build.sh` writes to.
//
// If neither path exists, embed an empty placeholder and emit a
// `cargo:warning=...`.  Runtime behaviour: deploy then falls back to
// the legacy filesystem search (ZBOOT_EFI_BUNDLE / /usr/share/zboot /
// exe-sibling).  Useful in CI / cross-builds where the EFI bundle is
// produced on a different host.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let efi_path = env::var("ZBOOT_EFI_BUNDLE_BUILD")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("cli crate has a parent dir")
                .join("boot/out/zboot-boot.efi")
        });

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let dest = out_dir.join("zboot-boot.efi");

    if efi_path.is_file() {
        fs::copy(&efi_path, &dest).expect("copy zboot-boot.efi to OUT_DIR");
        println!("cargo:rerun-if-changed={}", efi_path.display());
    } else {
        // Empty placeholder so include_bytes!() compiles. Runtime falls back
        // to filesystem lookup (ZBOOT_EFI_BUNDLE / /usr/share/zboot / ...).
        fs::write(&dest, b"").expect("write empty placeholder");
        println!(
            "cargo:warning=zboot-boot.efi not found at {} — embedding empty placeholder. \
             Run `bash boot/build.sh` and re-build the CLI to embed the real bundle. \
             Override the source path via ZBOOT_EFI_BUNDLE_BUILD.",
            efi_path.display(),
        );
    }
    println!("cargo:rerun-if-env-changed=ZBOOT_EFI_BUNDLE_BUILD");
}
