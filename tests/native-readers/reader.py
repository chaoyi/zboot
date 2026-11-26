#!/fixtures/python3
"""Unprivileged fixture reader; never imports product implementation modules."""
import errno
import fcntl
import json
import os
from pathlib import Path
import sys
import time


def main():
    mode, label, expected = sys.argv[1:4]
    descriptor = int(os.environ["ZSNAP_MANIFEST_FD"])
    assert fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    try:
        os.write(descriptor, b"corrupt")
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError("manifest descriptor is writable")
    manifest = json.load(os.fdopen(os.dup(descriptor)))
    assert manifest["schema_version"] == 1
    assert manifest["job"] == os.environ["ZSNAP_JOB"]
    source = manifest["sources"][0]
    view = Path(os.environ["ZSNAP_VIEW"]) / source["alias"]
    mounts = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()
              if line.split()[4] == str(view)]
    assert len(mounts) == 1
    mount = mounts[0]
    separator = mount.index("-")
    assert mount[3] == "/" and mount[separator + 1] == "zfs"
    assert mount[separator + 2] == source["snapshot"]["name"]
    assert {"ro", "nosuid", "nodev"} <= set(mount[5].split(","))
    assert (view / "token").read_text() == expected
    try:
        (view / "token").write_text("must not write")
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES)
    else:
        raise AssertionError("snapshot view is writable")
    assert os.getuid() == os.geteuid() == 1000
    assert os.getgid() == os.getegid() == 1000
    assert set(os.getgroups()) == {1000, 1001}
    for key, value in {"HOME": "/home/test", "USER": "test", "LOGNAME": "test"}.items():
        assert os.environ[key] == value
    assert "PROOF_SHOULD_NOT_LEAK" not in os.environ
    assert os.environ.get("CREDENTIALS_DIRECTORY") == "/proof/control/credentials"
    evidence = {"pid": os.getpid(), "ppid": os.getppid(), "uid": os.getuid(),
                "gid": os.getgid(), "groups": os.getgroups(), "environment": dict(os.environ),
                "manifest": manifest, "content": (view / "token").read_text(),
                "cgroup": Path("/proc/self/cgroup").read_text(),
                "mount_namespace": os.readlink("/proc/self/ns/mnt"),
                "snapshot_mount": mount, "view_device": os.stat(view).st_dev,
                "manifest_readonly": True, "view_readonly": True}
    (Path("/proof/control") / (label + ".json")).write_text(json.dumps(evidence))
    if mode == "descendants":
        pid = os.fork()
        if pid == 0:
            os.setsid()
            if os.fork() > 0:
                os._exit(0)
            evidence["pid"] = os.getpid()
            evidence["cgroup"] = Path("/proc/self/cgroup").read_text()
            (Path("/proof/control") / (label + "-descendant.json")).write_text(json.dumps(evidence))
            while True:
                time.sleep(1)
    if mode != "inspect":
        while not (Path("/proof/control") / (label + ".release")).exists():
            time.sleep(0.02)


if __name__ == "__main__":
    main()
