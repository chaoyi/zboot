#!/usr/bin/env python3
"""Build and execute the supported SDK consumer in a disposable native ZFS guest.

Callers may supply CARGO_TARGET_DIR and TMPDIR. Otherwise private staging is
created under TMPDIR (default /var/tmp). Any external build runner must
own this complete process, including QEMU's lifetime.
"""
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "tests"))
import native_proof  # noqa: E402


def fixtures(share, binary):
    shutil.copy2(binary, share / "checkpoint")
    return {}


def main():
    args = native_proof.arguments(__doc__)
    # A consumer cannot silently turn into a private-engine test or application.
    public = (ROOT / "crates/zfs-tools/src/lib.rs").read_text()
    source = (ROOT / "crates/zfs-tools/examples/checkpoint.rs").read_text()
    # The engine is public only as a hidden module for the workspace applications.
    gated = '#[doc(hidden)]\npub mod engine;\n'
    if public.count("pub mod engine") != 1 or gated not in public or "pub use engine::*" in public:
        raise RuntimeError("private engine has become a public escape hatch")
    if "zfs_tools::engine" in source or "zfs_tools::run_" in source:
        raise RuntimeError("native consumer uses private engine or application adapter")
    native_proof.prove(
        args, suite=Path(__file__).resolve().parent, kind="native public SDK proof",
        claim="Current SDK against the UKI's kernel, modules and native userland; no EFI boot, application or writer-cohort qualification",
        crates=("zfs-tools",),
        build=["-p", "zfs-tools", "--no-default-features", "--example", "checkpoint"],
        binary="examples/checkpoint", fixtures=fixtures,
        # The UKI's writers are not part of this experiment.
        stubs=("zboot", "zsnap"), serial="NATIVE-SDK-PRIVATE",
        final_case="native_sdk_proof_complete", enough=lambda count: count == 26)


if __name__ == "__main__":
    main()
