#!/fixtures/python3
"""Bounded black-box reader CLI tests; all mutations are inside this guest."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

OUT = Path("/evidence")
CONTROL = Path("/proof/control")
STATE = Path("/proof/state/jobs")
TOOLS = "/usr/bin/zsnap"
OPERATION_TIMEOUT = json.loads(Path("/fixtures/proof-config.json").read_text())["operation_timeout_seconds"]
events = []
owned = []


def failure_diagnostics():
    """Capture live wait state before owned-child cleanup destroys it."""
    processes = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal():
            continue
        state = {}
        for name in ("cmdline", "status", "wchan", "syscall", "stack", "cgroup", "mountinfo"):
            try:
                state[name] = (directory / name).read_text().replace("\x00", " ")
            except OSError as error:
                state[name] = str(error)
        processes[directory.name] = state
    (OUT / "failure-processes.json").write_text(json.dumps(processes, indent=2) + "\n")
    for path in STATE.glob("*/intent.json"):
        (OUT / (path.parent.name + "-failure-record.json")).write_bytes(path.read_bytes())


def wait_budget(seconds):
    """Scale liveness guards only; product timing contracts use fixed values."""
    return seconds * OPERATION_TIMEOUT / 20


def command(args, codes=(0,), timeout=None, **kwargs):
    start = time.monotonic()
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                            timeout=OPERATION_TIMEOUT if timeout is None else timeout, **kwargs)
    with (OUT / "commands.jsonl").open("a") as log:
        log.write(json.dumps({"argv": [str(a) for a in args], "code": result.returncode,
                              "stdout": result.stdout, "stderr": result.stderr,
                              "elapsed": round(time.monotonic() - start, 4)}) + "\n")
    assert result.returncode in codes, (args, result.returncode, result.stdout, result.stderr)
    return result


def event(name, detail):
    value = {"case": name, "passed": True, "detail": detail}
    events.append(value)
    with (OUT / "results.jsonl").open("a") as output:
        output.write(json.dumps(value) + "\n")


def native(*args):
    return command(["zfs", *args]).stdout.strip()


def holds(snapshot):
    return native("holds", "-H", snapshot)


def wait_file(path, process=None, timeout=10):
    start = time.monotonic()
    while time.monotonic() - start < wait_budget(timeout):
        if path.exists() and path.stat().st_size:
            return path
        if process is not None and process.poll() is not None:
            raise AssertionError(f"supervisor exited {process.returncode} before {path}")
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


def read_json(path):
    return json.loads(path.read_text())


def protect(label, mode="wait", snapshot="readerproof/data@first", expected="first-content\n",
            capture=False, end=False):
    result = OUT / (label + "-result.json")
    args = [TOOLS, "protect", snapshot, "--user", "test", "--state-dir", str(STATE),
            "--result", str(result), "--stop-timeout", "1", "--env", "CREDENTIALS_DIRECTORY"]
    if capture:
        args.append("--capture")
    if end:
        args.append("--end-protection")
    args += ["--", "/fixtures/python3", "/fixtures/reader.py", mode, label, expected]
    if label == "basic" and Path("/fixtures/strace").exists():
        args = ["/fixtures/strace", "-f", "-qq", "-o", "/evidence/basic-strace.log",
                "-e", "trace=clone,clone3,execve,execveat,unshare,mount,umount2,openat,openat2,newfstatat,fstat,fstatfs,statx,getdents64,fsync,readlink,readlinkat,write", *args]
    output = (OUT / (label + "-stdout.log")).open("w")
    error = (OUT / (label + "-stderr.log")).open("w")
    env = {**os.environ, "CREDENTIALS_DIRECTORY": "/proof/control/credentials", "PROOF_SHOULD_NOT_LEAK": "not-forwarded"}
    process = subprocess.Popen(args, stdout=output, stderr=error, env=env)
    output.close()
    error.close()
    owned.append(process)
    return process, result


def ready(label, process):
    return read_json(wait_file(CONTROL / (label + ".json"), process))


def finish(label, process, result, codes=(0,)):
    (CONTROL / (label + ".release")).touch()
    assert process.wait(timeout=wait_budget(15)) in codes
    return read_json(result)


def record(job):
    return read_json(STATE / job / "intent.json")


def recovery(job, *options, codes=(0,)):
    result = command([TOOLS, "recover", job, "--state-dir", STATE,
                      "--json", "--stop-timeout", "1", *options], codes=codes)
    return json.loads(result.stdout) if result.stdout.strip() else None


def orphan_stop_release(process, job, snapshots, unrelated=None, release=True):
    process.kill()
    assert process.wait(timeout=5) == -signal.SIGKILL
    preview = recovery(job, "--dry-run")
    assert preview["status"] == "readers_active"
    assert preview["requires_stop"]
    for snapshot in snapshots:
        assert holds(snapshot)
    no_stop = recovery(job, "--confirm", preview["token"], codes=(3,))
    assert no_stop["status"] == "stop_confirmation_required"
    stopped = recovery(job, "--stop", "--confirm", preview["token"], codes=(3,))
    assert stopped["status"] == "stopped_review_required"
    for snapshot in snapshots:
        assert holds(snapshot)
    if unrelated is not None:
        assert unrelated.poll() is None
    next_review = recovery(job, "--dry-run")
    assert next_review["status"] == "preview"
    assert next_review["token"] != preview["token"]
    if not release:
        return {"active": preview, "stop": stopped, "fresh_review": next_review}
    released = recovery(job, "--confirm", next_review["token"])
    assert released["status"] == "complete"
    for snapshot in snapshots:
        assert not holds(snapshot)
    return {"active": preview, "stop": stopped, "fresh_review": next_review,
            "complete": released}


def main():
    assert Path("/sys/fs/cgroup/cgroup.controllers").exists()
    assert Path("/proc/self/cgroup").read_text() == "0::/\n"
    STATE.parent.chmod(0o755)
    process, result = protect("basic", mode="inspect")
    assert process.wait(timeout=wait_budget(20)) == 0
    observed = read_json(CONTROL / "basic.json")
    completed = read_json(result)
    assert completed["status"] == "complete" and completed["cleanup_complete"]
    assert observed["manifest_readonly"] and observed["view_readonly"]
    assert native("get", "-H", "-p", "-o", "value", "guid", "readerproof/data@first") == observed["manifest"]["sources"][0]["snapshot"]["identity"]["guid"]
    assert not holds("readerproof/data@first")
    assert not list(Path("/run/zsnap/view").iterdir())
    event("readonly_exact_view_identity_environment_manifest", {"reader": observed, "result": completed})

    # While readers own native holds, a different task can take the writer lock.
    process, result = protect("nested")
    observed = ready("nested", process)
    assert holds("readerproof/data@first")
    command([TOOLS, "snap", "readerproof/other"], timeout=8)
    live_recovery = command([TOOLS, "recover", observed["manifest"]["job"],
                             "--state-dir", STATE, "--dry-run", "--json"], codes=(1,))
    assert any(word in live_recovery.stderr for word in ("lock", "live", "temporarily unavailable"))
    completed = finish("nested", process, result)
    assert completed["status"] == "complete"
    event("native_hold_live_reader_short_writer_lock", {"reader": observed, "result": completed})

    # Exact capture uses the live parent filesystem, never its child dataset.
    before = set(native("list", "-H", "-r", "-t", "snapshot", "-o", "name", "readerproof").splitlines())
    process, result = protect("capture", mode="inspect", snapshot="readerproof/data",
                              expected="second-content\n", capture=True)
    assert process.wait(timeout=wait_budget(20)) == 0
    completed = read_json(result)
    after = set(native("list", "-H", "-r", "-t", "snapshot", "-o", "name", "readerproof").splitlines())
    new = after - before
    assert len(new) == 1 and next(iter(new)).startswith("readerproof/data@")
    assert completed["status"] == "complete"
    event("capture_exact_nonrecursive_filesystem", {"new_snapshots": sorted(new), "result": completed})

    # Independent namespaces can use exactly the same view pathname/alias.
    first, first_result = protect("isolation-first")
    second, second_result = protect("isolation-second", snapshot="readerproof/data@second", expected="second-content\n")
    one, two = ready("isolation-first", first), ready("isolation-second", second)
    assert one["manifest"]["view_root"] == two["manifest"]["view_root"]
    assert one["mount_namespace"] != two["mount_namespace"]
    assert one["content"] != two["content"]
    assert holds("readerproof/data@first") and holds("readerproof/data@second")
    assert finish("isolation-first", first, first_result)["status"] == "complete"
    assert finish("isolation-second", second, second_result)["status"] == "complete"
    event("simultaneous_same_view_root_isolation", {"first": one, "second": two})

    unrelated_group = Path("/sys/fs/cgroup/unrelated-proof")
    unrelated_group.mkdir()
    unrelated = subprocess.Popen(["/bin/busybox", "sleep", "2147483647"])
    owned.append(unrelated)
    (unrelated_group / "cgroup.procs").write_text(str(unrelated.pid))
    process, result = protect("orphan", mode="descendants")
    observed = ready("orphan", process)
    descendant = read_json(wait_file(CONTROL / "orphan-descendant.json", process))
    job = observed["manifest"]["job"]
    job_record = record(job)
    reader_group = Path(job_record["cgroup"]["parent"]) / job_record["cgroup"]["name"]
    members = (reader_group / "cgroup.procs").read_text().split()
    assert str(descendant["pid"]) in members
    assert descendant["cgroup"] == observed["cgroup"]
    outcome = orphan_stop_release(process, job, ["readerproof/data@first"], unrelated)
    event("owner_sigkill_setsid_doublefork_authenticated_stop_release", {"members": members, "descendant": descendant, "recovery": outcome})

    # A successful first native hold child remains counted even if the frontend
    # dies before the reply. Recovery stops Setup separately from Readers.
    (CONTROL / "fault-mode").write_text("pause-hold")
    process, result = protect("native-orphan")
    reached = CONTROL / "fault-reached"
    start = time.monotonic()
    while not reached.exists() and time.monotonic() - start < wait_budget(10):
        assert process.poll() is None
        time.sleep(0.02)
    assert reached.exists()
    jobs = [p for p in STATE.glob("*/intent.json") if read_json(p)["owner"]["pid"] == process.pid]
    assert len(jobs) == 1
    job_record = read_json(jobs[0])
    setup = Path(job_record["setup_cgroup"]["parent"]) / job_record["setup_cgroup"]["name"]
    native_pid = int((CONTROL / "fault-native-pid").read_text())
    assert str(native_pid) in (setup / "cgroup.procs").read_text().split()
    outcome = orphan_stop_release(process, job_record["id"], ["readerproof/data@first"], unrelated)
    (CONTROL / "fault-mode").unlink()
    event("owner_sigkill_native_hold_child_setup_custody", {"native_pid": native_pid, "recovery": outcome})
    unrelated.terminate()
    unrelated.wait(timeout=5)
    unrelated_group.rmdir()

    # PreserveSnapshots retains a real deferred snapshot and owned hold.
    native("snapshot", "readerproof/data@preserve-deferred")
    process, result = protect("preserve", snapshot="readerproof/data@preserve-deferred", expected="second-content\n")
    observed = ready("preserve", process)
    ended = orphan_stop_release(process, observed["manifest"]["job"],
                                 ["readerproof/data@preserve-deferred"], release=False)
    native("destroy", "-d", "readerproof/data@preserve-deferred")
    assert holds("readerproof/data@preserve-deferred")
    assert native("get", "-H", "-o", "value", "defer_destroy", "readerproof/data@preserve-deferred") == "on"
    preview = recovery(observed["manifest"]["job"], "--dry-run")
    stale = recovery(observed["manifest"]["job"], "--confirm", ended["fresh_review"]["token"], codes=(3,))
    assert stale["status"] == "review_changed"
    retained = recovery(observed["manifest"]["job"], "--confirm", preview["token"], codes=(4,))
    assert retained["status"] == "retained"
    event("preserve_snapshots_refuses_deferred_release", {"stop": ended, "stale_review": stale, "recovery": retained})

    native("snapshot", "readerproof/data@end-deferred")
    process, result = protect("end", snapshot="readerproof/data@end-deferred", expected="second-content\n", end=True)
    end_reader = ready("end", process)
    orphan_stop_release(process, end_reader["manifest"]["job"],
                        ["readerproof/data@end-deferred"], release=False)
    native("destroy", "-d", "readerproof/data@end-deferred")
    assert holds("readerproof/data@end-deferred")
    assert native("get", "-H", "-o", "value", "defer_destroy", "readerproof/data@end-deferred") == "on"
    end_preview = recovery(end_reader["manifest"]["job"], "--dry-run")
    completed = recovery(end_reader["manifest"]["job"], "--confirm", end_preview["token"])
    assert completed["status"] == "complete"
    query = command(["zfs", "list", "-H", "readerproof/data@end-deferred"], codes=(1,))
    assert "does not exist" in query.stderr
    event("explicit_end_protection_allows_deferred_destruction", completed)

    final = native("list", "-H", "-p", "-r", "-t", "filesystem,snapshot", "-o", "name,type,guid,createtxg,objsetid", "readerproof")
    (OUT / "final-inventory.tsv").write_text(final + "\n")
    (OUT / "final-holds.tsv").write_text(holds("readerproof/data@preserve-deferred") + "\n")
    for path in STATE.glob("*/intent.json"):
        (OUT / (path.parent.name + "-record.json")).write_text(path.read_text())
    event("reader_native_proof_complete", {"cases": len(events), "preserved_deferred": True})
    (OUT / "status").write_text("passed\n")


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        try:
            failure_diagnostics()
        except OSError as error:
            print(f"failure diagnostics incomplete: {error}", flush=True)
        raise
    finally:
        # Exact children only. Orphan descendants remain isolated in this guest
        # and are never mistaken for host processes or unrelated job authority.
        for process in owned:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
