#!/usr/bin/env python3
"""File-only helper tests; linker wrappers simulate devices and libblkid errors."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from _native_helpers import ROOT, build_mock, native_artifacts as _native_artifacts
WRAPPERS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <blkid/blkid.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sed-opal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
static unsigned int opened, closed, acquired, freed;
static int mode(const char *value) { return strcmp(getenv("CASE"), value) == 0; }
static void live_device(int fd) {
    assert(fd == 10 && opened == 1 && closed == 0);
}
static void live_probe(blkid_probe probe) {
    live_device(10);
    assert(probe == (blkid_probe)1 && acquired == 1 && freed == 0);
}
/* Rust's normal process exit runs ELF destructors. Checking balance after the
 * success protocol catches leaked ownership even when the helper returns 0. */
__attribute__((destructor)) static void all_resources_released(void) {
    assert(opened == closed && acquired == freed);
}
static int setup(void) {
    static int call;
    const char *fail = getenv("FAIL_SETUP");
    return fail && ++call == atoi(fail) ? -1 : 0;
}
int __wrap_open(const char *path, int flags, ...) {
    assert(flags == (O_RDONLY | O_CLOEXEC | O_NONBLOCK));
    assert(opened == 0 && closed == 0);
    const char *expected = getenv("EXPECT_PATH");
    assert(strcmp(path, expected ? expected : "/dev/leaf") == 0);
    if (mode("open_error")) {
        errno = EIO; return -1;
    }
    opened++;
    return 10;
}
int __wrap_fstat(int fd, struct stat *st) {
    live_device(fd);
    if (mode("stat_error")) return -1;
    memset(st, 0, sizeof(*st));
    st->st_mode = mode("regular") ? S_IFREG : S_IFBLK;
    st->st_rdev = makedev(8, 1);
    return 0;
}
int __wrap_close(int fd) {
    live_device(fd);
    assert(acquired == freed);
    closed++;
    return mode("close_error") ? -1 : 0;
}
int __wrap_ioctl(int fd, unsigned long request, ...) {
    va_list args;
    live_device(fd);
    live_probe((blkid_probe)1);
    assert(request == IOC_OPAL_GET_STATUS);
    va_start(args, request);
    struct opal_status *status = va_arg(args, struct opal_status *);
    va_end(args);
    if (mode("locked")) {
        status->flags = OPAL_FL_SUPPORTED | OPAL_FL_LOCKED; return 0;
    }
    if (mode("io_error")) { errno = EIO; return -1; }
    if (mode("permission")) { errno = EPERM; return -1; }
    if (mode("invalid_ioctl")) { errno = EINVAL; return -1; }
    if (mode("positive_ioctl")) { errno = ENOTTY; return 1; }
    if (mode("unsupported")) { errno = EOPNOTSUPP; return -1; }
    if (mode("notty")) { errno = ENOTTY; return -1; }
    status->flags = mode("zero_status") ? 0 : OPAL_FL_SUPPORTED; return 0;
}
blkid_probe __wrap_blkid_new_probe(void) {
    live_device(10);
    assert(acquired == 0 && freed == 0);
    if (mode("allocation")) return NULL;
    acquired++;
    return (blkid_probe)1;
}
void __wrap_blkid_free_probe(blkid_probe p) {
    live_probe(p);
    freed++;
}
int __wrap_blkid_probe_set_device(blkid_probe p, int fd, blkid_loff_t off, blkid_loff_t size) {
    live_probe(p);
    live_device(fd);
    assert(off == 0 && size == 0); return setup();
}
int __wrap_blkid_probe_enable_superblocks(blkid_probe p, int v) { live_probe(p); assert(v == 1); return setup(); }
int __wrap_blkid_probe_set_superblocks_flags(blkid_probe p, int v) {
    live_probe(p);
    assert(v == (BLKID_SUBLKS_MAGIC | BLKID_SUBLKS_TYPE | BLKID_SUBLKS_USAGE |
                     BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID | BLKID_SUBLKS_BADCSUM));
    return setup();
}
int __wrap_blkid_probe_enable_partitions(blkid_probe p, int v) { live_probe(p); assert(v == 1); return setup(); }
int __wrap_blkid_probe_set_partitions_flags(blkid_probe p, int v) { live_probe(p); assert(v == 0); return setup(); }
int __wrap_blkid_probe_enable_topology(blkid_probe p, int v) { live_probe(p); assert(v == 0); return setup(); }
int __wrap_blkid_do_safeprobe(blkid_probe p) {
    live_probe(p);
    if (mode("signature")) return 0;
    if (mode("ambiguous")) return -2;
    if (mode("read_error")) { errno = EIO; return -1; }
    if (mode("unexpected")) return 2;
    return 1;
}
'''


def native_artifacts():
    return _native_artifacts("zboot-probe-signatures")


class SignatureProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="zboot-probe-test.",
                                                    dir=os.environ.get("TMPDIR") or "/var/tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        binary, library = native_artifacts()
        cls.real = cls.root / "probe"
        shutil.copyfile(binary, cls.real)
        cls.real.chmod(0o755)
        wrappers = cls.root / "wrappers.c"
        wrappers.write_text(WRAPPERS)
        cls.mock = cls.root / "mock-probe"
        names = ["open", "fstat", "close", "ioctl", "blkid_new_probe", "blkid_free_probe",
                 "blkid_probe_set_device", "blkid_probe_enable_superblocks",
                 "blkid_probe_set_superblocks_flags", "blkid_probe_enable_partitions",
                 "blkid_probe_set_partitions_flags", "blkid_probe_enable_topology",
                 "blkid_do_safeprobe"]
        build_mock(ROOT / "crates/zboot-helpers/src/bin/probe-signatures.rs",
                   cls.mock, wrappers, names, library)

    def run_probe(self, case="none", args=None, real=False,
                  stdout=subprocess.PIPE, preexec_fn=None, **env):
        return subprocess.run([str(self.real if real else self.mock)] +
                              (["--", "/dev/leaf"] if args is None else args),
                              stdout=stdout, stderr=subprocess.PIPE, preexec_fn=preexec_fn,
                              env={**os.environ, "CASE": case, **env}, timeout=5)

    def assert_refusal(self, result):
        # A fixture assertion terminates with a signal, not a valid refusal.
        self.assertGreater(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_exact_absence_protocol_and_unsupported_opal(self):
        for case in ("none", "unsupported", "notty"):
            with self.subTest(case=case):
                result = self.run_probe(case)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"zboot-signatures-v1:none\n")
                self.assertEqual(result.stderr, b"")

    def test_all_nonabsence_and_device_failures_refuse(self):
        for case in ("signature", "ambiguous", "read_error", "unexpected", "open_error",
                     "stat_error", "regular", "close_error", "allocation", "locked",
                     "zero_status", "io_error", "permission", "invalid_ioctl", "positive_ioctl"):
            with self.subTest(case=case):
                self.assert_refusal(self.run_probe(case))

    def test_probe_diagnostics_preserve_distinct_results_and_errno(self):
        for case, code, message in (
                ("signature", 2, b"signature found"),
                ("ambiguous", 3, b"ambiguous signatures"),
                ("read_error", 1, b"probe error result=-1 errno=5")):
            with self.subTest(case=case):
                result = self.run_probe(case)
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"zboot signature probe: " + message + b"\n")

    def test_every_setup_return_is_checked(self):
        for call in range(1, 7):
            with self.subTest(call=call):
                self.assert_refusal(self.run_probe(FAIL_SETUP=str(call)))

    def test_invalid_invocations_refuse_before_device_access(self):
        for args in ([], ["/dev/leaf"], ["--", "/dev/leaf", "extra"], ["-x", "/dev/leaf"],
                     ["--", "/nonexistent/leaf"], ["--", "/dev/"], ["--", "/dev/../leaf"],
                     ["--", "/dev/./leaf"], ["--", "/dev//leaf"], ["--", "/dev/leaf/"],
                     ["--", "/dev/leaf\n"], ["--", "/dev/leaf\x7f"]):
            with self.subTest(args=args):
                self.assert_refusal(self.run_probe(args=args))

    @unittest.skipUnless(Path("/dev/full").exists(), "requires Linux /dev/full")
    def test_failed_protocol_output_refuses(self):
        with open("/dev/full", "wb") as output:
            result = self.run_probe(stdout=output)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"")

    def test_initially_closed_stdout_cannot_report_success(self):
        result = self.run_probe(preexec_fn=lambda: os.close(1))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_broken_protocol_pipe_preserves_inherited_sigpipe(self):
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = self.run_probe(stdout=writer)
        finally:
            os.close(writer)
        self.assertEqual(result.returncode, -signal.SIGPIPE, result.stderr)
        self.assertEqual(result.stderr, b"")

    def test_non_utf8_device_path_reaches_native_open_unchanged(self):
        path = b"/dev/leaf-\xff"
        result = subprocess.run([os.fsencode(self.mock), b"--", path],
                                capture_output=True, timeout=5,
                                env={**os.environb, b"CASE": b"none", b"EXPECT_PATH": path})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"zboot-signatures-v1:none\n")
        self.assertEqual(result.stderr, b"")

    def test_real_helper_uses_dynamic_libblkid(self):
        program = subprocess.run(["readelf", "-l", "-d", str(self.real)], capture_output=True,
                                 text=True, check=True).stdout
        self.assertIn("INTERP", program)
        self.assertIn("Shared library: [libblkid.so.1]", program)

    def test_real_regular_file_and_character_device_refuse(self):
        # /dev/stdin resolves to this regular input; no host block device is opened.
        regular = self.root / "regular"
        regular.write_bytes(b"\0" * 4096)
        with regular.open("rb") as handle:
            result = subprocess.run([str(self.real), "--", "/dev/stdin"], stdin=handle,
                                    capture_output=True, timeout=5)
        self.assert_refusal(result)
        self.assert_refusal(self.run_probe(args=["--", "/dev/null"], real=True))


if __name__ == "__main__":
    unittest.main()
