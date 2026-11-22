#!/usr/bin/env python3
"""Build and execute supervised-reader CLI tests in a disposable native ZFS guest.

Callers may supply CARGO_TARGET_DIR and TMPDIR. Otherwise private staging is
created under TMPDIR (default /var/tmp). Any caller-owned execution scope
must cover this complete process, including QEMU's lifetime.
"""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import sysconfig

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "tests"))
import native_proof  # noqa: E402
from native_proof import sha  # noqa: E402


def install_python(fixtures):
    """Isolate host fixtures from the selected runtime's loader and libc."""
    host = fixtures / "host"
    (host / "bin").mkdir(parents=True)
    (host / "lib").mkdir()
    stdlib = Path(sysconfig.get_path("stdlib"))
    shutil.copytree(stdlib, host / "lib" / stdlib.name,
                    ignore=shutil.ignore_patterns("__pycache__", "test", "tests", "site-packages",
                                                  "dist-packages", "idlelib", "tkinter", "ensurepip"))
    interpreter = Path(sys.executable).resolve()
    shutil.copy2(interpreter, host / "bin/python3")
    inputs = {str(interpreter): sha(interpreter)}
    binaries = [interpreter, *(host / "lib" / stdlib.name).rglob("*.so")]
    for binary in binaries:
        result = subprocess.run(["ldd", binary], capture_output=True, text=True, check=True)
        if "not found" in result.stdout:
            raise RuntimeError(f"incomplete host fixture closure: {binary}")
        for name in re.findall(r"(/[^\s()]+)", result.stdout):
            source = Path(name)
            if not source.is_file():
                continue
            digest = sha(source)
            target = host / "lib" / source.name
            if target.exists() and sha(target) != digest:
                raise RuntimeError(f"fixture library basename conflict: {source}")
            if not target.exists():
                shutil.copy2(source, target)
            inputs[str(source)] = digest
    wrapper = fixtures / "python3"
    wrapper.write_text('#!/bin/sh\nexport PYTHONHOME=/fixtures/host\n'
                       'exec /fixtures/host/lib/ld-linux-x86-64.so.2 --inhibit-cache '
                       '--library-path /fixtures/host/lib /fixtures/host/bin/python3 -B "$@"\n')
    wrapper.chmod(0o755)
    inputs.update({str(path.relative_to(fixtures)): sha(path) for path in sorted(host.rglob("*")) if path.is_file()})
    return inputs


def fixtures(share, binary):
    shutil.copy2(binary, share / "zsnap")
    for name in ("cases.py", "reader.py", "fault-zfs.sh"):
        shutil.copy2(Path(__file__).with_name(name), share / name)
    return {"host_fixture_closure": install_python(share)}


def main():
    native_proof.prove(
        native_proof.arguments(__doc__), suite=Path(__file__).resolve().parent,
        kind="native supervised reader CLI proof",
        claim="Current reader CLI against the UKI's kernel, modules and native userland; no EFI boot or writer-cohort qualification",
        crates=("zfs-tools", "zsnap"), build=["-p", "zsnap", "--bin", "zsnap"], binary="zsnap",
        # The UKI's zboot is not part of this experiment.
        fixtures=fixtures, stubs=("zboot",), serial="NATIVE-READERS-PRIVATE",
        final_case="reader_native_proof_complete", enough=lambda count: count >= 9)


if __name__ == "__main__":
    main()
