#!/usr/bin/env python3
"""Build and execute the supported SDK consumer in a disposable native ZFS guest.

Callers may supply CARGO_TARGET_DIR and TMPDIR. Otherwise private staging is
created under TMPDIR (default /var/tmp). Any external build runner must
own this complete process, including QEMU's lifetime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "tests/acceptance"))
from host.uki import boot_payloads, guest_initrd, sha256 as sha  # noqa: E402
from host.vm import accelerator_config, accelerator_args  # noqa: E402


def source_manifest():
    """Bind the complete SDK source, including disabled-feature modules.

    Include workspace resolution/build inputs and this black-box harness. The
    immutable manifest is checked again after build and guest execution so a
    concurrent edit cannot be mislabeled as the source that was exercised.
    """
    # Every file of the crate: `include_str!` inputs are build inputs too.
    paths = {path for path in (ROOT / "crates/zfs-tools").rglob("*") if path.is_file()}
    paths.update((ROOT / "crates").glob("*/Cargo.toml"))
    paths.update(ROOT / name for name in ("Cargo.toml", "Cargo.lock", "build.rs",
                                         "rust-toolchain", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml")
                 if (ROOT / name).is_file())
    paths.update((Path(__file__).resolve(), Path(__file__).with_name("init.sh").resolve()))
    paths.add(ROOT / "tests/acceptance/host/uki.py")
    paths.add(ROOT / "tests/acceptance/host/vm.py")
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uki", type=Path, required=True,
                        help="a zboot UKI whose kernel, modules and native ZFS userland the guest boots")
    parser.add_argument("--evidence", type=Path, required=True, help="new durable evidence directory")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--jobs", type=int, default=int(os.environ.get("CARGO_BUILD_JOBS", "4")))
    args = parser.parse_args()
    if args.timeout <= 0 or not 1 <= args.jobs <= 64:
        parser.error("timeout must be positive and jobs must be between 1 and 64")
    accelerator = accelerator_config()
    uki = args.uki.resolve(strict=True)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    # Refuse to overwrite evidence from another invocation.
    if any(evidence.iterdir()):
        raise RuntimeError(f"evidence directory must be empty: {evidence}")
    # A consumer cannot silently turn into a private-engine test or application.
    public = (ROOT / "crates/zfs-tools/src/lib.rs").read_text()
    source = ROOT / "crates/zfs-tools/examples/checkpoint.rs"
    # Only the unsupported workspace feature, which this build never enables,
    # makes the engine public.
    gated = '#[cfg(feature = "internal")]\n#[doc(hidden)]\npub mod engine;\n'
    if public.count("pub mod engine") != 1 or gated not in public or "pub use engine::*" in public:
        raise RuntimeError("private engine has become a public escape hatch")
    if "zfs_tools::engine" in source.read_text() or "zfs_tools::run_" in source.read_text():
        raise RuntimeError("native consumer uses private engine or application adapter")
    stage = Path(tempfile.mkdtemp(prefix="zfs-native-api-",
                                 dir=os.environ.get("TMPDIR") or "/var/tmp"))
    stage.chmod(0o700)
    started = time.monotonic()
    kernel, initramfs = stage / "vmlinuz", stage / "initrd.img.zst"
    try:
        runtime = boot_payloads(uki, stage / "zboot.efi", kernel, initramfs)
    except BaseException:
        shutil.rmtree(stage)
        raise
    sources = source_manifest()
    source_sums = "".join(f"{digest}  {name}\n" for name, digest in sources.items())
    (evidence / "source-manifest.sha256").write_text(source_sums)
    proof = {"kind": "native public SDK proof", "runtime": runtime,
             "claim": "Current SDK against the UKI's kernel, modules and native userland; no EFI boot, application or writer-cohort qualification",
             "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
             "source_files": sources,
             "source_manifest_sha256": hashlib.sha256(source_sums.encode()).hexdigest(),
             "private_stage": str(stage), "timeout_seconds": args.timeout,
             "accelerator": accelerator}
    process = None
    success = False
    try:
        env = os.environ.copy()
        env.setdefault("CARGO_TARGET_DIR", str(stage / "target"))
        env["CARGO_BUILD_JOBS"] = str(args.jobs)
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C target-feature=+crt-static").strip()
        build = ["cargo", "build", "--offline", "--locked", "-p", "zfs-tools", "--no-default-features",
                 "--example", "checkpoint", "--target", "x86_64-unknown-linux-gnu", "-j", str(args.jobs)]
        proof["build_argv"] = build
        with (evidence / "build.log").open("w") as log:
            subprocess.run(build, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        if source_manifest() != sources:
            raise RuntimeError("candidate source changed during native consumer build")
        binary = Path(env["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-gnu/debug/examples/checkpoint"
        elf = subprocess.check_output(["readelf", "-l", binary], text=True)
        if "INTERP" in elf:
            raise RuntimeError("consumer must be static for the selected runtime")
        proof["consumer_sha256"] = sha(binary)
        (evidence / "consumer-elf.txt").write_text(elf)
        fixtures = stage / "fixtures"
        out = stage / "out"
        fixtures.mkdir()
        out.mkdir()
        shutil.copy2(binary, fixtures / "checkpoint")
        initrd = stage / "initrd"
        # The UKI's writers are not part of this experiment.
        guest_initrd(initramfs, initrd, Path(__file__).with_name("init.sh").read_bytes(), ("zboot", "zsnap"))
        disk = stage / "private.raw"
        with disk.open("xb") as image:
            image.truncate(2 * 1024**3)
        qemu = ["qemu-system-x86_64", *accelerator_args(accelerator),
                "-m", "2048", "-smp", "2", "-nodefaults", "-no-reboot", "-nographic",
                "-serial", "stdio", "-monitor", "none", "-nic", "none",
                "-kernel", str(kernel), "-initrd", str(initrd),
                "-append", "console=ttyS0 panic=-1 rdinit=/init",
                "-drive", f"file={disk},format=raw,if=none,id=private",
                "-device", "virtio-blk-pci,drive=private,serial=NATIVE-SDK-PRIVATE",
                "-fsdev", f"local,id=fixtures,path={fixtures},security_model=none,readonly=on",
                "-device", "virtio-9p-pci,fsdev=fixtures,mount_tag=fixtures",
                "-fsdev", f"local,id=evidence,path={out},security_model=none",
                "-device", "virtio-9p-pci,fsdev=evidence,mount_tag=evidence"]
        proof["qemu_argv"] = qemu
        with (evidence / "serial.log").open("wb") as serial:
            process = subprocess.Popen(qemu, cwd=stage, stdin=subprocess.DEVNULL,
                                       stdout=serial, stderr=subprocess.STDOUT)
            proof["qemu_pid"] = process.pid
            try:
                code = process.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                proof["timed_out"] = True
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                raise RuntimeError("owned guest exceeded its bounded runtime")
        proof["qemu_exit"] = code
        for item in out.iterdir():
            if item.is_file() and not item.is_symlink():
                shutil.copy2(item, evidence / item.name)
        if code != 0 or (out / "status").read_text().strip() != "passed":
            raise RuntimeError("native guest proof failed; inspect retained evidence")
        events = [json.loads(line) for line in (out / "results.jsonl").read_text().splitlines()]
        if len(events) != 26 or events[-1]["case"] != "native_sdk_proof_complete" or not all(e["passed"] for e in events):
            raise RuntimeError("native consumer case set incomplete")
        if source_manifest() != sources:
            raise RuntimeError("candidate source changed during native guest proof")
        proof["passed_cases"] = [event["case"] for event in events]
        success = True
    finally:
        # Exact Child custody: never kill another task's QEMU or use patterns.
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        for item in (stage / "out").glob("*"):
            if item.is_file() and not item.is_symlink() and not (evidence / item.name).exists():
                shutil.copy2(item, evidence / item.name)
        proof["passed"] = success
        proof["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (evidence / "provenance.json").write_text(json.dumps(proof, indent=2) + "\n")
        if success:
            shutil.rmtree(stage)
        else:
            print(f"Failure staging retained at {stage}; owner: native SDK proof runner", flush=True)
    print(f"Native public SDK proof passed: {evidence}", flush=True)


if __name__ == "__main__":
    main()
