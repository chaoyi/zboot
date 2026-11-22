"""The shared host side of the native proofs (tests/native-api, tests/native-readers).

Each suite builds one static consumer from this checkout, boots it with the
UKI's own kernel and initramfs in a disposable KVM guest with one private
disk and two 9P shares, and keeps evidence and provenance. Callers may supply
CARGO_TARGET_DIR and TMPDIR; otherwise private staging is created under TMPDIR
(default /var/tmp). Any external build runner must own the complete process,
including QEMU's lifetime.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "tests/acceptance"))
from host.uki import boot_payloads, guest_initrd, sha256 as sha  # noqa: E402


def arguments(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--uki", type=Path, required=True,
                        help="a zboot UKI whose kernel, modules and native ZFS userland the guest boots")
    parser.add_argument("--evidence", type=Path, required=True, help="new durable evidence directory")
    parser.add_argument("--timeout", type=int, default=300, help="guest runtime bound in seconds (default 300)")
    parser.add_argument("--jobs", type=int, default=os.environ.get("CARGO_BUILD_JOBS", "4"),
                        help="Cargo workers (default: CARGO_BUILD_JOBS or 4)")
    args = parser.parse_args()
    if args.timeout <= 0 or not 1 <= args.jobs <= 64:
        parser.error("timeout must be positive and jobs must be between 1 and 64")
    return args


def source_manifest(suite, crates):
    """Bind the complete source of CRATES, the workspace build inputs and
    this harness. It is checked again after build and guest execution so a
    concurrent edit cannot be mislabeled as the source that was exercised."""
    # Every file of the crates: `include_str!` inputs are build inputs too.
    paths = {path for crate in crates for path in (ROOT / "crates" / crate).rglob("*") if path.is_file()}
    paths.update((ROOT / "crates").glob("*/Cargo.toml"))
    paths.update(ROOT / name for name in ("Cargo.toml", "Cargo.lock", "build.rs",
                                         "rust-toolchain", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml")
                 if (ROOT / name).is_file())
    paths.update(path for path in suite.iterdir() if path.is_file())
    paths.update((Path(__file__).resolve(), ROOT / "tests/acceptance/host/uki.py"))
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}


def stop(process):
    """Exact child custody: never kill another task's QEMU or use patterns."""
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def keep(out, evidence):
    for item in out.glob("*"):
        if item.is_symlink() or (evidence / item.name).exists():
            continue
        if item.is_file():
            shutil.copy2(item, evidence / item.name)
        elif item.is_dir():
            shutil.copytree(item, evidence / item.name, symlinks=True)


def prove(args, *, suite, kind, claim, crates, build, binary, fixtures, stubs, serial,
          final_case, enough):
    """Run one native proof. BUILD is the `cargo build` argv tail, BINARY the
    built file relative to CARGO_TARGET_DIR, FIXTURES(directory, binary) fills
    the read-only share and returns extra provenance, STUBS are the UKI's
    writers replaced by refusing stubs, and the guest's results.jsonl must
    end with FINAL_CASE and hold a count of passed cases for which ENOUGH is
    true."""
    uki = args.uki.resolve(strict=True)
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    # Refuse to overwrite evidence from another invocation.
    if any(evidence.iterdir()):
        raise RuntimeError(f"evidence directory must be empty: {evidence}")
    stage = Path(tempfile.mkdtemp(prefix=f"zfs-{suite.name}-", dir=os.environ.get("TMPDIR") or "/var/tmp"))
    stage.chmod(0o700)
    started = time.monotonic()
    kernel, initramfs = stage / "vmlinuz", stage / "initrd.img.zst"
    try:
        runtime = boot_payloads(uki, stage / "zboot.efi", kernel, initramfs)
    except BaseException:
        shutil.rmtree(stage)
        raise
    sources = source_manifest(suite, crates)
    source_sums = "".join(f"{digest}  {name}\n" for name, digest in sources.items())
    (evidence / "source-manifest.sha256").write_text(source_sums)
    proof = {"kind": kind, "runtime": runtime, "claim": claim,
             "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
             "source_files": sources,
             "source_manifest_sha256": hashlib.sha256(source_sums.encode()).hexdigest(),
             "private_stage": str(stage), "timeout_seconds": args.timeout, "build_jobs": args.jobs}
    process = None
    success = False
    try:
        env = os.environ.copy()
        env.setdefault("CARGO_TARGET_DIR", str(stage / "target"))
        # An inherited native cache must not collect this finite task's
        # intermediates outside the caller-owned complete execution scope.
        env["CARGO_BUILD_BUILD_DIR"] = str(stage / "build")
        proof["build_paths"] = {key: env[key] for key in ("CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR")}
        env["CARGO_BUILD_JOBS"] = str(args.jobs)
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C target-feature=+crt-static").strip()
        argv = ["cargo", "build", "--offline", "--locked", *build,
                "--target", "x86_64-unknown-linux-gnu", "-j", str(args.jobs)]
        proof["build_argv"] = argv
        with (evidence / "build.log").open("w") as log:
            subprocess.run(argv, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        if source_manifest(suite, crates) != sources:
            raise RuntimeError("candidate source changed during native consumer build")
        built = Path(env["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-gnu/debug" / binary
        elf = subprocess.check_output(["readelf", "-l", built], text=True)
        if "INTERP" in elf:
            raise RuntimeError("consumer must be static for the selected runtime")
        proof["consumer_sha256"] = sha(built)
        (evidence / "consumer-elf.txt").write_text(elf)
        share, out = stage / "fixtures", stage / "out"
        share.mkdir()
        out.mkdir()
        proof.update(fixtures(share, built))
        initrd = stage / "initrd"
        guest_initrd(initramfs, initrd, (suite / "init.sh").read_bytes(), stubs)
        disk = stage / "private.raw"
        with disk.open("xb") as image:
            image.truncate(2 * 1024**3)
        qemu = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
                "-m", "2048", "-smp", "2", "-nodefaults", "-no-reboot", "-nographic",
                "-serial", "stdio", "-monitor", "none", "-nic", "none",
                "-kernel", str(kernel), "-initrd", str(initrd),
                "-append", "console=ttyS0 panic=-1 rdinit=/init",
                "-drive", f"file={disk},format=raw,if=none,id=private",
                "-device", f"virtio-blk-pci,drive=private,serial={serial}",
                "-fsdev", f"local,id=fixtures,path={share},security_model=none,readonly=on",
                "-device", "virtio-9p-pci,fsdev=fixtures,mount_tag=fixtures",
                "-fsdev", f"local,id=evidence,path={out},security_model=none",
                "-device", "virtio-9p-pci,fsdev=evidence,mount_tag=evidence"]
        proof["qemu_argv"] = qemu
        with (evidence / "serial.log").open("wb") as console:
            process = subprocess.Popen(qemu, cwd=stage, stdin=subprocess.DEVNULL,
                                       stdout=console, stderr=subprocess.STDOUT)
            proof["qemu_pid"] = process.pid
            try:
                code = process.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                proof["timed_out"] = True
                stop(process)
                raise RuntimeError("owned guest exceeded its bounded runtime")
        proof["qemu_exit"] = code
        keep(out, evidence)
        if code != 0 or (out / "status").read_text().strip() != "passed":
            raise RuntimeError("native guest proof failed; inspect retained evidence")
        events = [json.loads(line) for line in (out / "results.jsonl").read_text().splitlines()]
        if not enough(len(events)) or events[-1]["case"] != final_case or not all(e["passed"] for e in events):
            raise RuntimeError("native consumer case set incomplete")
        if source_manifest(suite, crates) != sources:
            raise RuntimeError("candidate source changed during native guest proof")
        proof["passed_cases"] = [event["case"] for event in events]
        success = True
    finally:
        stop(process)
        keep(stage / "out", evidence)
        proof["passed"] = success
        proof["source_unchanged"] = source_manifest(suite, crates) == sources
        proof["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (evidence / "provenance.json").write_text(json.dumps(proof, indent=2) + "\n")
        if success:
            shutil.rmtree(stage)
        else:
            print(f"Failure staging retained at {stage}; owner: {kind} runner", flush=True)
    print(f"{kind} passed: {evidence}", flush=True)
