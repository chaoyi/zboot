#!/usr/bin/env python3
"""File-only helper tests: linker wrappers stand in for libzfs_core, so no
test opens /dev/zfs or names a real dataset."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from _native_helpers import ROOT, build_mock, native_artifacts as _native_artifacts
WRAPPERS = r'''
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int mode(const char *value) { return strcmp(getenv("CASE"), value) == 0; }
static void note(const char *format, const char *name, uint64_t command, int null) {
    FILE *log = fopen(getenv("LOG"), "a");
    if (log == NULL) abort();
    fprintf(log, format, name, (unsigned long long)command, null);
    fclose(log);
}
int __wrap_libzfs_core_init(void) {
    note("init%s%llu%d\n", "", 0, 0);
    return mode("init_error") ? EACCES : 0;
}
void __wrap_libzfs_core_fini(void) { note("fini%s%llu%d\n", "", 0, 0); }
int __wrap_lzc_change_key(const char *name, uint64_t command, void *props,
                          uint8_t *key, unsigned int length) {
    note("change %s %llu %d\n", name, command, props == NULL && key == NULL && length == 0);
    return mode("change_error") ? EBUSY : 0;
}
'''


def native_artifacts():
    return _native_artifacts("zboot-change-key")


class ChangeKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="zboot-change-key-test.",
                                                    dir=os.environ.get("TMPDIR") or "/var/tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        binary, library = native_artifacts()
        cls.real = cls.root / "helper"
        shutil.copyfile(binary, cls.real)
        cls.real.chmod(0o755)
        wrappers = cls.root / "wrappers.c"
        wrappers.write_text(WRAPPERS)
        cls.mock = cls.root / "mock-helper"
        build_mock(ROOT / "crates/zboot-helpers/src/bin/change-key.rs", cls.mock, wrappers,
                   ("libzfs_core_init", "libzfs_core_fini", "lzc_change_key"), library)

    def setUp(self):
        self.log = self.root / f"{self.id()}.log"
        self.log.write_text("")

    def run_helper(self, args, case="ok", real=False, stdout=subprocess.PIPE,
                   preexec_fn=None):
        return subprocess.run([str(self.real if real else self.mock)] + args, stdout=stdout,
                              stderr=subprocess.PIPE, timeout=5, preexec_fn=preexec_fn,
                              env={**os.environ, "CASE": case, "LOG": str(self.log)})

    def calls(self):
        return self.log.read_text().splitlines()

    def test_check_initializes_libzfs_core_and_changes_nothing(self):
        result = self.run_helper(["--check"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"zboot-change-key-v1:ok\n")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(self.calls(), ["init00", "fini00"])

    def test_each_command_is_one_forced_change_without_key_material(self):
        for verb, command in (("inherit", 5), ("new-key", 4)):
            with self.subTest(verb=verb):
                self.log.write_text("")
                result = self.run_helper([verb, "rpool/secret/inner deep"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"zboot-change-key-v1:ok\n")
                self.assertEqual(self.calls(),
                                 ["init00", f"change rpool/secret/inner deep {command} 1", "fini00"])

    def test_failures_report_strerror_and_print_no_protocol_line(self):
        result = self.run_helper(["--check"], case="init_error")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"zboot-change-key: libzfs_core_init: Permission denied\n")
        self.assertEqual(self.calls(), ["init00"])
        self.log.write_text("")
        result = self.run_helper(["inherit", "rpool/a"], case="init_error")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls(), ["init00"], "no change without libzfs_core")
        self.log.write_text("")
        result = self.run_helper(["inherit", "rpool/a"], case="change_error")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr,
                         b"zboot-change-key: lzc_change_key rpool/a: Device or resource busy\n")
        self.assertEqual(self.calls(), ["init00", "change rpool/a 5 1", "fini00"])

    def test_an_unwritable_protocol_line_is_a_failure(self):
        with open("/dev/full", "wb") as full:
            result = self.run_helper(["--check"], stdout=full)
        self.assertEqual(result.returncode, 1)

    def test_initially_closed_stdout_cannot_report_success(self):
        result = self.run_helper(["--check"], preexec_fn=lambda: os.close(1))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_broken_protocol_pipe_preserves_inherited_sigpipe(self):
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = self.run_helper(["--check"], stdout=writer)
        finally:
            os.close(writer)
        self.assertEqual(result.returncode, -signal.SIGPIPE, result.stderr)
        self.assertEqual(result.stderr, b"")

    def test_invalid_invocations_refuse_before_libzfs_core(self):
        for args in ([], ["--help"], ["--check", "extra"], ["inherit"], ["inherit", "rpool"],
                     ["inherit", "rpool/a", "extra"], ["rewrap", "rpool/a"], ["inherit", ""],
                     ["inherit", "/rpool/a"], ["inherit", "rpool/a/"], ["inherit", "rpool//a"],
                     ["inherit", "rpool/./a"], ["inherit", "rpool/../a"], ["inherit", "-rpool/a"],
                     ["inherit", "rpool/a@snap"], ["inherit", "rpool/a#mark"],
                     ["new-key", "rpool/a\n"], ["new-key", "rpool/a\x7f"],
                     ["new-key", "rpool/" + "a" * 250]):
            for real in (False, True):
                with self.subTest(args=args, real=real):
                    result = self.run_helper(args, real=real)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, b"zboot-change-key: expected --check, "
                                     b"or inherit|new-key POOL/DATASET\n")
                    self.assertEqual(self.calls(), [])

    def test_the_real_helper_links_the_hosts_libzfs_core_dynamically(self):
        program = subprocess.run(["readelf", "-l", "-d", str(self.real)], capture_output=True,
                                 text=True, check=True).stdout
        self.assertIn("INTERP", program)
        self.assertIn("Shared library: [libzfs_core.so.3]", program)


if __name__ == "__main__":
    unittest.main()
