"""File-only regressions for acceptance recipes, harness boundaries and shell fixtures."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


class MenuFingerprintTests(unittest.TestCase):
    def test_redraws_must_show_one_distinct_key_for_the_listener(self):
        from host import ssh
        console = SimpleNamespace(case_dir=Path('case'), out=Path('boot-2'))
        key = 'SHA256:' + 'A' * 43
        line = f'Host key fingerprint: {key}\n'
        with patch.object(ssh, 'keyscan') as scan:
            ssh.fingerprint(console, line + line)
            scan.assert_called_once_with(console, Path('case/known-boot-2'), [key], tries=10)
            scan.reset_mock()
            for text in ('', line + 'Host key fingerprint: SHA256:' + 'B' * 43):
                with self.subTest(text=text), self.assertRaises(ssh.ConsoleError):
                    ssh.fingerprint(console, text)
            scan.assert_not_called()


class ResourcePolicyTests(unittest.TestCase):
    def test_guest_memory_defaults_and_explicit_override(self):
        from host.vm import default_memory_mib
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(default_memory_mib('SMOKE'), 2048)
            self.assertEqual(default_memory_mib('OTHER'), 8192)
        with patch.dict(os.environ, {'ZBOOT_VM_MEMORY_MIB': '3072'}):
            self.assertEqual(default_memory_mib('OTHER'), 3072)
        for invalid in ('0', '-1', 'a', '1048577'):
            with patch.dict(os.environ, {'ZBOOT_VM_MEMORY_MIB': invalid}), self.assertRaises(ValueError):
                default_memory_mib('SMOKE')

    def test_selection_cannot_succeed_empty_and_deduplicates_overlapping_names(self):
        import run as acceptance
        module = SimpleNamespace(ID='SMOKE', GROUP='small')
        self.assertEqual(acceptance.select_cases(['SMOKE', 'small'], {'SMOKE': module}), [module])
        for names in ([], ['absent'], ['restore']):
            with self.subTest(names=names), self.assertRaises(RuntimeError):
                acceptance.select_cases(names, {'SMOKE': module})

    def test_selected_prepare_copies_distribution_tools_and_builds_one_initrd(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            out = root / 'out'
            out.mkdir()
            build = {'directory': out}
            for name in ('uki', 'kernel', 'zboot', 'zsnap'):
                build[name] = out / name
                build[name].write_bytes(name.encode())
            record = root / 'build.json'
            record.write_text(json.dumps({'source_oid': 'a' * 40, 'files': {
                path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in out.iterdir()}}))
            prepared = []
            def logged(argv, *_args, **_kwargs):
                prepared.append(argv)
                Path(argv[argv.index('--output') + 1]).write_bytes(b'fixture')
            with patch.object(acceptance, 'STATE', root / 'state'), \
                    patch.object(acceptance, 'clean_at'), \
                    patch.object(acceptance, 'uki_output', return_value=build), \
                    patch.object(acceptance, 'uki_section', side_effect=lambda _p, name: b'kernel' if name == '.linux' else b'initrd'), \
                    patch.object(acceptance, 'HOST_TOOLS', []), \
                    patch.object(acceptance, 'logged', side_effect=logged), \
                    patch.object(acceptance, 'build_tools') as rebuild, \
                    patch.object(acceptance, 'boot_stick') as stick, patch('builtins.print'):
                acceptance.prepare('a' * 40, ['SMOKE'], out, distribution_tools=True, build_record=record)
            rebuild.assert_not_called()
            stick.assert_not_called()
            self.assertEqual(len(prepared), 1)
            session, = (root / 'state/runs').iterdir()
            self.assertEqual((session / 'bin/zboot').read_bytes(), b'zboot')
            self.assertEqual(json.loads((session / 'provenance.json').read_text())['selected_cases'], ['SMOKE'])
            self.assertEqual((session / 'fixtures/e2e-esp-artifacts/zboot-recovery.efi').read_bytes(), b'uki')
            self.assertEqual((session / 'fixtures/initrd.img').read_bytes(), b'fixture')
            self.assertFalse((session / 'fixtures/e2e-factory.tar.zst').exists())
            self.assertFalse((session / 'efi.json').exists())
            with patch.object(acceptance, 'uki_output', return_value=build), \
                    self.assertRaisesRegex(RuntimeError, 'need --factory'):
                acceptance.prepare('a' * 40, ['efi'], out)

    def test_distribution_tools_require_matching_source_and_every_selected_input_hash(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            build = {name: root / name for name in ('uki', 'kernel', 'zboot', 'zsnap')}
            for path in build.values():
                path.write_bytes(path.name.encode())
            record = root / 'build.json'
            files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in build.values()}
            with self.assertRaisesRegex(RuntimeError, 'requires --build-record'):
                acceptance.verify_distribution_record(build, 'a' * 40, None)
            record.write_text(json.dumps({'source_oid': 'a' * 40, 'files': files}))
            self.assertEqual(acceptance.verify_distribution_record(build, 'a' * 40, record), record)
            with self.assertRaisesRegex(RuntimeError, 'not ' + 'b' * 40):
                acceptance.verify_distribution_record(build, 'b' * 40, record)
            build['zsnap'].write_bytes(b'other-source')
            with self.assertRaisesRegex(RuntimeError, 'zsnap: distribution bytes'):
                acceptance.verify_distribution_record(build, 'a' * 40, record)

    def test_a_passed_case_gives_up_its_boot_images_and_keeps_its_evidence(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            case = root / 'cases/SMOKE-20260101T000000Z'
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'kept.raw').write_bytes(b'x' * 8192)
            for boot in ('boot-1', 'boot-2'):
                (case / boot).mkdir(parents=True)
                for name in ('kernel', 'initrd', 'code.fd', 'vars.fd', 'boot.raw', 'case-image-0.raw'):
                    (case / boot / name).write_bytes(b'x' * 8192)
                for name in ('console.log', 'qemu.log', 'test.log', 'launch.json'):
                    (case / boot / name).write_text('evidence')
            (case / 'boot-1/disk-A.raw').write_bytes(b'x' * 65536)
            os.link(case / 'boot-1/disk-A.raw', case / 'boot-2/disk-A.raw')  # carried across a power cut
            (case / 'out').mkdir()
            (case / 'out/verdict.out').write_text('evidence')
            (case / 'out/looks-like.raw').write_text('evidence under another directory')
            (case / 'result.json').write_text('{}')
            (case / 'boot-1/alias.raw').symlink_to(outside / 'kept.raw')
            (case / 'boot-1/nested.raw').mkdir()
            (case / 'boot-9').symlink_to(outside, target_is_directory=True)
            before = sum(p.lstat().st_blocks * 512 for p in {p.lstat().st_ino: p for p in case.rglob('*')
                                                        if p.is_file() and not p.is_symlink()
                                                        and p.parent.name.startswith('boot-')
                                                        and (p.suffix in ('.raw', '.fd') or p.name in ('kernel', 'initrd'))}.values())
            freed = acceptance.discard_boot_bulk(case)
            self.assertEqual(freed, before, 'each image counts once, however many boots link it')
            left = sorted(str(p.relative_to(case)) for p in case.rglob('*') if not p.is_dir() or p.is_symlink())
            self.assertEqual(left, sorted(
                [f'{boot}/{name}' for boot in ('boot-1', 'boot-2')
                 for name in ('console.log', 'qemu.log', 'test.log', 'launch.json')]
                + ['boot-1/alias.raw', 'boot-9', 'out/verdict.out', 'out/looks-like.raw', 'result.json']))
            self.assertTrue((case / 'boot-1/nested.raw').is_dir())
            self.assertEqual((outside / 'kept.raw').read_bytes(), b'x' * 8192)
            self.assertEqual(acceptance.discard_boot_bulk(case), 0)

    def test_run_rejects_missing_selected_fixture_before_a_vm_can_start(self):
        import run as acceptance
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            session = Path(temporary)
            (session / 'source.oid').write_text('a' * 40)
            with patch.object(acceptance.subprocess, 'run'), self.assertRaisesRegex(RuntimeError, 'missing prepared fixture'):
                acceptance.run(session, ['SMOKE'], dev=True)


class RamBootBudgetTests(unittest.TestCase):
    def test_budget_covers_both_unpacking_and_pre_kexec_copies_with_rounding(self):
        from cases.ram_boot import memory_plan
        mib = 1 << 20
        for compressed, logical, kernel in ((128 * mib, 1024 * mib, 16 * mib),
                                             (1024 * mib, 1024 * mib, 16 * mib),
                                             (128 * mib + 1, 1024 * mib, 16 * mib)):
            with self.subTest(compressed=compressed, logical=logical):
                plan = memory_plan(compressed, logical, kernel)
                self.assertLess(plan['short_mib'] * mib, plan['need_bytes'])
                available = plan['positive_mib'] * mib - plan['runtime_headroom_bytes']
                self.assertGreaterEqual(available, compressed + logical + 256 * mib)
                self.assertGreaterEqual(available, 3 * compressed + 2 * kernel)
                self.assertLess(plan['positive_mib'], 8192)
        with self.assertRaisesRegex(RuntimeError, 'root tar is too small'):
            memory_plan(1, 1, 1)

    def test_factory_kernel_size_resolves_the_actual_hardlinked_payload(self):
        from cases.ram_boot import tar_sizes
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            path = Path(temporary) / 'root.tar'
            with tarfile.open(path, 'w') as archive:
                member = tarfile.TarInfo('./payload')
                member.size = 7
                archive.addfile(member, io.BytesIO(b'kernel!'))
                member = tarfile.TarInfo('./boot/vmlinuz-test')
                member.type = tarfile.LNKTYPE
                member.linkname = './payload'
                archive.addfile(member)
            self.assertEqual(tar_sizes(path), (7, 7))

    def test_case_ceiling_refuses_an_oversized_root_instead_of_weakening_negative_leg(self):
        from cases import ram_boot
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            tar = root / 'root.tar'
            tar.write_bytes(b'input')
            run_dir = root / 'case'
            run_dir.mkdir()
            with patch.object(ram_boot, 'root_tar', return_value=tar), \
                    patch.object(ram_boot, 'tar_sizes', return_value=(4 << 30, 16 << 20)), \
                    patch.object(ram_boot, 'keygen', side_effect=lambda p, name: (p / f'{name}.pub').write_bytes(b'public')), \
                    patch.object(ram_boot, 'write_askpass'), \
                    patch.dict(os.environ, {'ZBOOT_VM_MEMORY_MIB': '4096'}), \
                    self.assertRaisesRegex(RuntimeError, 'ceiling is 4096 MiB'):
                ram_boot.prepare(run_dir)
            self.assertFalse((run_dir / 'ram-inputs.json').exists())

    def test_host_reserve_is_checked_for_the_actual_positive_and_short_allocations(self):
        from cases import ram_boot
        from host.case import Boot
        inputs = json.dumps({'positive_mib': 3072, 'short_mib': 1280})
        def contents(path, *_args, **_kwargs):
            return 'MemAvailable: 4194304 kB\n' if str(path) == '/proc/meminfo' else inputs
        with patch.object(Path, 'read_text', autospec=True, side_effect=contents):
            self.assertEqual(ram_boot.memory_mib(Path('case'), Boot(2)), 3072)
            self.assertEqual(ram_boot.memory_mib(Path('case'), Boot(4, extra={'memory': 'short'})), 1280)
        with patch.object(Path, 'read_text', autospec=True, side_effect=lambda p: 'MemAvailable: 3145728 kB\n' if str(p) == '/proc/meminfo' else inputs), \
                self.assertRaisesRegex(RuntimeError, 'host reserve'):
            ram_boot.memory_mib(Path('case'), Boot(2))


class UkiInputTests(unittest.TestCase):
    def test_a_uki_must_match_its_publishers_record(self):
        from host import uki
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR') or '/var/tmp') as directory:
            out = Path(directory) / 'out'
            efi = out / uki.UKI_PATH
            efi.parent.mkdir(parents=True)
            efi.write_bytes(b'not really a UKI')
            digest = hashlib.sha256(efi.read_bytes()).hexdigest()
            (out / 'SHA256SUMS').write_text(f'{"0" * 64}  components.json\n{digest}  {uki.UKI_PATH}\n')
            self.assertEqual(uki.published_digest(efi)[:2], ('sha256', digest))
            stray = Path(directory) / 'zboot.efi'
            stray.write_bytes(efi.read_bytes())
            with self.assertRaisesRegex(RuntimeError, 'no publisher record'):
                uki.published_digest(stray)
            # A copy that differs from the record is refused before any section is read.
            (out / 'SHA256SUMS').write_text(f'{"0" * 64}  {uki.UKI_PATH}\n')
            with self.assertRaisesRegex(RuntimeError, 'differs from its record'):
                uki.boot_payloads(efi, Path(directory) / 'copy.efi', Path(directory) / 'k', Path(directory) / 'i')
            (out / 'SHA256SUMS').write_text(f'{digest}  {uki.UKI_PATH}\n{digest}  {uki.UKI_PATH}\n')
            with self.assertRaisesRegex(RuntimeError, 'exactly one'):
                uki.published_digest(efi)

class InitrdPathTests(unittest.TestCase):
    def test_builder_keeps_runtime_tools_and_routes_zfs_through_the_fault_shim(self):
        import run as acceptance
        from host import uki
        builder = Path(__file__).with_name('build-initrd.sh')
        for product_tool in ('--wipefs', '--nvme', '--mkfs-vfat'):
            self.assertNotIn(product_tool, acceptance.HOST_TOOLS)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            guest = root / 'guest'
            guest.mkdir()
            (guest / 'init.sh').write_text('#!/bin/sh\n')
            runtime_wipefs = b'#!/bin/sh\necho pinned-runtime-wipefs\n'
            for present in (False, True):
                with self.subTest(runtime_wipefs=present):
                    archive = (uki.newc('sbin/wipefs', runtime_wipefs) if present else b'')
                    archive += uki.newc('sbin/zfs', b'#!/bin/sh\n', inode=2)
                    archive += uki.newc('usr/bin', b'', mode=0o040755, inode=3)
                    archive += uki.newc('TRAILER!!!', b'', mode=0, inode=4)
                    base = root / f'base-{present}.zst'
                    subprocess.run(['zstd', '-q', '-o', base], input=archive, check=True)
                    output = root / f'fixture-{present}.zst'
                    result = subprocess.run(['bash', builder, '--base-initrd', base,
                                             '--acceptance', guest, '--fault-tool', 'zfs', '--output', output],
                                            env={**os.environ, 'TMPDIR': str(root)},
                                            capture_output=True, text=True)
                    if not present:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('runtime needs executable /sbin/wipefs', result.stderr)
                        self.assertFalse(output.exists())
                        continue
                    self.assertEqual(result.returncode, 0, result.stderr)
                    tree = root / 'unpacked'
                    tree.mkdir()
                    packed = subprocess.check_output(['zstd', '-dc', output])
                    subprocess.run(['cpio', '-idm', '--quiet'], input=packed, cwd=tree, check=True)
                    self.assertEqual((tree / 'sbin/wipefs').read_bytes(), runtime_wipefs)
                    self.assertFalse((tree / 'usr/bin/wipefs').exists())
                    self.assertEqual((tree / 'usr/bin/zfs').read_text(),
                                     '#!/bin/sh\nexec /acceptance/fault.sh zfs /sbin/zfs "$@"\n')
                    self.assertEqual((tree / 'sbin/zfs').read_bytes(), b'#!/bin/sh\n')
                    digest = hashlib.sha256(runtime_wipefs).hexdigest()
                    self.assertIn(f'{digest}  runtime:/sbin/wipefs',
                                  Path(str(output) + '.provenance').read_text())

    def test_custom_tmpdir_retains_new_path_and_escape_refusals(self):
        builder = Path(__file__).with_name('build-initrd.sh')
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            root = Path(temporary)
            staging = root / 'staging with spaces'
            staging.mkdir()
            outside = root / 'outside'
            outside.mkdir()
            (staging / 'escape').symlink_to(outside, target_is_directory=True)
            missing_base = root / 'missing-base'
            acceptance = root / 'guest'
            acceptance.mkdir()
            (acceptance / 'init.sh').write_text('#!/bin/sh\n')

            def invoke(output, *extra):
                return subprocess.run(['bash', str(builder), '--base-initrd', str(missing_base),
                                       '--acceptance', str(acceptance), '--output', str(output), *extra],
                                      env={**os.environ, 'TMPDIR': str(staging)},
                                      capture_output=True, text=True, check=False)

            # A new path under the selected root reaches input validation;
            # packing never runs because the base input is deliberately absent.
            output = staging / 'new.zst'
            result = invoke(output)
            self.assertIn('not a regular input file:', result.stderr)
            for refused in (outside / 'out.zst', staging / 'escape/out.zst'):
                with self.subTest(output=refused):
                    result = invoke(refused)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('output and provenance must be new files under TMPDIR', result.stderr)
            for existing in (output, Path(str(output) + '.provenance')):
                existing.write_text('keep')
                result = invoke(output)
                self.assertIn('output and provenance must be new files under TMPDIR', result.stderr)
                self.assertEqual(existing.read_text(), 'keep')
                existing.unlink()
            self.assertFalse(output.exists())


class ShutdownFixtureTests(unittest.TestCase):
    def run_case(self, boots, *, timeout=False, stage_1=lambda _console: None):
        from host import case
        waits = []

        class Vm:
            def __init__(self, *_args, **_kwargs):
                self.ssh_port = None
                self.image_paths = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.kill()

            def wait(self, seconds):
                waits.append(seconds)
                if timeout:
                    raise TimeoutError('guest did not power off: test-owned fixture')
                return 0

            def kill(self):
                return -9 if timeout else 0

        class Console:
            def __init__(self, _channel, out, *_args, **_kwargs):
                out.mkdir(parents=True)

        channel = SimpleNamespace(console=object(), until=lambda *_args: ('DONE', 'ok'))
        verdict = Mock()
        module = SimpleNamespace(ID='SHUTDOWN-FIXTURE', SECONDS=600, DISKS={},
                                 BOOTS=boots, stage_1=stage_1, verdict=verdict)
        with tempfile.TemporaryDirectory(prefix='zboot-shutdown-',
                                         dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
            run_dir = Path(temporary) / 'case'
            with patch.object(case, 'Vm', Vm), patch.object(case, 'Channel', return_value=channel), \
                    patch.object(case, 'Console', Console):
                result = case.run(module, run_dir, lambda _boot: {}, lambda _boot: [])
            self.assertEqual(json.loads((run_dir / 'result.json').read_text()), result)
        return result, waits, verdict

    def test_handoff_poweroff_waits_once_with_the_full_shutdown_budget(self):
        from host.case import Boot
        result, waits, verdict = self.run_case([Boot(1, efi=True, target=2, poweroff=True)])
        self.assertTrue(result['pass'], result['failures'])
        self.assertEqual(waits, [300])
        self.assertEqual(result['boots'][0]['target_event'], ['DONE', 'ok'])
        self.assertEqual(result['boots'][0]['exit'], 0)
        verdict.assert_called_once()

    def test_a_dialogue_that_cannot_read_the_menu_is_a_failed_stage_with_its_boot_kept(self):
        from host.case import Boot

        def unreadable(_console):
            raise ValueError('expected one native menu row')

        result, _waits, verdict = self.run_case([Boot(1, efi=True), Boot(3)], stage_1=unreadable)
        self.assertFalse(result['pass'])
        self.assertEqual([boot['event'] for boot in result['boots']], [['DIALOGUE', 'failed']])
        self.assertTrue(any('expected one native menu row' in failure for failure in result['failures']))
        verdict.assert_not_called()

    def test_shutdown_timeouts_preserve_original_failed_results_and_stop_later_boots(self):
        from host.case import Boot
        for boot, seconds in [(Boot(1, efi=True, target=2, poweroff=True), 300),
                              (Boot(1, efi=True, target=2), 60), (Boot(1), 60)]:
            with self.subTest(boot=boot):
                result, waits, verdict = self.run_case([boot, Boot(3)], timeout=True)
                self.assertFalse(result['pass'])
                self.assertEqual(waits, [seconds])
                self.assertEqual(len(result['boots']), 1)
                self.assertIn('guest did not power off', result['boots'][0]['exit'])
                self.assertTrue(any('guest did not power off' in failure
                                    for failure in result['failures']))
                self.assertTrue(any('only 1 of 2 boots ran' in failure
                                    for failure in result['failures']))
                if boot.target:
                    self.assertEqual(result['boots'][0]['target_event'], ['DONE', 'ok'])
                verdict.assert_not_called()


class UsbLoaderFixtureTests(unittest.TestCase):
    def test_only_selected_primary_disk_uses_usb_storage(self):
        from host.vm import disk_device
        self.assertEqual(disk_device('A', ',bootindex=1'),
                         'virtio-blk-pci,drive=diskA,serial=ZFS-E2E-A,bootindex=1')
        self.assertEqual(disk_device('A', ',bootindex=1', primary_bus='usb'),
                         'usb-storage,bus=zt-usb.0,drive=diskA,serial=ZFS-E2E-A,bootindex=1')
        for label in ('B', 'D'):
            self.assertEqual(disk_device(label, primary_bus='usb'), disk_device(label))

    def test_only_selected_primary_disk_uses_nvme_storage(self):
        from host.vm import disk_device
        self.assertEqual(disk_device('A', ',bootindex=1', primary_bus='nvme'),
                         'nvme,drive=diskA,serial=ZFS-E2E-A,bootindex=1')
        for label in ('B', 'D'):
            self.assertEqual(disk_device(label, primary_bus='nvme'), disk_device(label))
        with self.assertRaises(ValueError):
            disk_device('A', primary_bus='unknown')

class ReturnedFixtureTests(unittest.TestCase):
    def test_selected_disk_serial_without_a_newline_and_exact_identity(self):
        source = (Path(__file__).parent / "guest/cases/RESTORE-RETURNED-ERROR-NATIVE.sh").read_text()
        # Extract the actual bounded command body, not a second implementation.
        pattern = re.compile(
            r'''^        must "reset-selected-\$label" sh -e -c '(?P<body>[^']{1,2048})' selected "\$selected" "\$label"$''',
            re.MULTILINE,
        )
        matches = list(pattern.finditer(source))
        self.assertEqual(len(matches), 1, "exact reset-selected command must remain uniquely identifiable")
        original = matches[0]["body"]
        self.assertEqual(original.count("/sys/block/"), 2)
        with tempfile.TemporaryDirectory(prefix="zboot-fixtures-", dir=os.environ.get("TMPDIR", "/var/tmp")) as temporary:
            for index, (primary, fallback, accepted) in enumerate([
                (b"ZFS-E2E-A", None, True),
                (None, b"ZFS-E2E-A", True),
                (b"ZFS-E2E-B", b"ZFS-E2E-A", False),
            ]):
                with self.subTest(primary=primary, fallback=fallback):
                    root = Path(temporary) / str(index)
                    disk = root / "vda"
                    disk.mkdir(parents=True)
                    if primary is not None:
                        (disk / "serial").write_bytes(primary)
                    if fallback is not None:
                        (disk / "device").mkdir()
                        (disk / "device/serial").write_bytes(fallback)
                    body = original.replace("/sys/block/", str(root) + "/")
                    self.assertNotIn("/sys/block/", body)
                    result = subprocess.run(
                        ["sh", "-e", "-c", body, "selected", "/dev/vda", "A"],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        env={"PATH": os.defpath, "LC_ALL": "C"},
                        check=False,
                    )
                    if accepted:
                        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                        self.assertEqual(result.stdout, b"ZFS-E2E-A\t/dev/vda\n")
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, b"")



class FakeNvmeTests(unittest.TestCase):
    """guest/fake-nvme.sh, which WIPE-SANITIZE-NATIVE puts in place of `nvme`,
    run against a regular file standing in for the namespace."""

    FAKE = Path(__file__).parent / "guest/fake-nvme.sh"
    BYTES = 2 << 20

    def shells(self):
        yield "sh", os.defpath
        busybox = shutil.which("busybox")
        if busybox:
            # The guest's busybox: its own sh and applets only.
            with tempfile.TemporaryDirectory(prefix="zboot-fake-nvme-bin-",
                                             dir=os.environ.get("TMPDIR", "/var/tmp")) as bin_dir:
                for applet in ("cat", "dd", "mv", "printf", "sh"):
                    os.symlink(busybox, Path(bin_dir) / applet)
                yield str(Path(bin_dir) / "sh"), bin_dir

    def fake(self, shell, path, state, *args):
        result = subprocess.run([shell, str(self.FAKE), *args], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, check=False,
                                env={"PATH": path, "LC_ALL": "C", "ZT_FAKE_NVME": str(state)})
        return result.returncode, result.stdout, result.stderr

    def setUp_state(self, root, outcome, state):
        disk = root / "namespace"
        disk.write_bytes(b"\xff" * self.BYTES)
        (root / "config").write_text(f"CONTROLLER=/dev/nvme0 NAMESPACE={disk} BYTES={self.BYTES} "
                                     f"CNTLID=7 SERIAL=ZFS-E2E-N SUBNQN=nqn.2019-08.org.qemu:ZFS-E2E-N "
                                     f"RUN_READS=2 OUTCOME={outcome}\n")
        (root / "state").write_text(state + "\n")
        return disk

    def test_answers_as_a_consumer_drive_and_sanitizes_by_zeroing(self):
        for shell, path in self.shells():
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(
                    prefix="zboot-fake-nvme-", dir=os.environ.get("TMPDIR", "/var/tmp")) as temporary:
                root = Path(temporary)
                disk = self.setUp_state(root, "success", "STATUS=1 CDW10=4 ERASED=0 RUNNING=0 ENDS=")
                run = lambda *args: self.fake(shell, path, root, *args)
                status, out, _ = run("id-ctrl", "/dev/nvme0", "--output-format=json")
                self.assertEqual(status, 0)
                ctrl = json.loads(out)
                self.assertEqual({k: ctrl[k] for k in ("sanicap", "cmic", "oacs", "nn", "cntlid", "subnqn")},
                                 {"sanicap": 3, "cmic": 0, "oacs": 22, "nn": 1, "cntlid": 7,
                                  "subnqn": "nqn.2019-08.org.qemu:ZFS-E2E-N"})
                self.assertEqual(ctrl["sn"], "ZFS-E2E-N" + " " * 11, "space-padded like nvme-cli")
                self.assertEqual(json.loads(run("list-ns", "/dev/nvme0", "--output-format=json")[1]),
                                 {"nsid_list": [{"nsid": 1}]})
                status, out, _ = run("id-ns", "/dev/nvme0", "--namespace-id=1", "--output-format=json")
                self.assertEqual((status, json.loads(out)["nmic"], json.loads(out)["nsze"]),
                                 (0, 0, self.BYTES // 512))
                # Rejected like the captured consumer drives.
                for args in (("list-ctrl", "/dev/nvme0", "--output-format=json"),
                             ("list-ns", "/dev/nvme0", "--all", "--output-format=json")):
                    status, out, _ = run(*args)
                    self.assertEqual(status, 1, args)
                    self.assertIn("Invalid Field in Command", json.loads(out)["error"])
                # Anything else, another device included, is an error.
                for args in (("format", "/dev/nvme0"), ("id-ctrl", "/dev/nvme1", "--output-format=json"),
                             ("sanitize", "/dev/nvme0", "--sanact=3")):
                    self.assertEqual(run(*args)[0], 2, args)

                def log():
                    status, out, _ = run("sanitize-log", "/dev/nvme0", "--output-format=json")
                    self.assertEqual(status, 0)
                    (device, value), = json.loads(out).items()
                    self.assertEqual(device, "nvme0")
                    return value["sstat"]["status"][:3], value["sstat"]["global_erased"], value["cdw10_info"]

                self.assertEqual(log(), ("(1)", 0, 4))
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=4")[0], 0)
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=4")[0], 1, "one at a time")
                self.assertEqual([log(), log()], [("(2)", 0, 4)] * 2)
                self.assertEqual(disk.read_bytes(), b"\xff" * self.BYTES, "erased only when it ends")
                self.assertEqual(log(), ("(1)", 1, 4))
                self.assertEqual(disk.read_bytes(), bytes(self.BYTES))
                self.assertEqual(log(), ("(1)", 1, 4))
                record = (root / "calls").read_text().splitlines()
                self.assertIn("sanitize /dev/nvme0 --sanact=4 => exit 0", record)
                self.assertEqual(record[-1], "sanitize-log /dev/nvme0 --output-format=json => status 1")
                self.assertFalse((root / "errors").exists() and (root / "errors").read_text())

    def test_a_running_sanitize_ends_and_a_failure_leaves_the_data(self):
        for shell, path in self.shells():
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(
                    prefix="zboot-fake-nvme-", dir=os.environ.get("TMPDIR", "/var/tmp")) as temporary:
                root = Path(temporary)
                disk = self.setUp_state(root, "failure", "STATUS=1 CDW10=4 ERASED=0 RUNNING=1 ENDS=success")
                run = lambda *args: self.fake(shell, path, root, *args)
                log = lambda: json.loads(run("sanitize-log", "/dev/nvme0", "--output-format=json")[1])[
                    "nvme0"]["sstat"]["status"][:3]
                # Already running (after a power loss): it ends, then a new one may start.
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=4")[0], 1)
                self.assertEqual([log(), log()], ["(2)", "(1)"])
                self.assertEqual(disk.read_bytes(), bytes(self.BYTES))
                disk.write_bytes(b"\xff" * self.BYTES)
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=2")[0], 0)
                self.assertEqual([log(), log(), log()], ["(2)", "(2)", "(3)"])
                self.assertEqual(disk.read_bytes(), b"\xff" * self.BYTES, "a failure erases nothing")
                self.assertEqual(run("sanitize", "/dev/nvme0", "--sanact=4")[0], 1, "failure mode")
                self.assertIn("STATUS=3", (root / "state").read_text())


if __name__ == "__main__":
    unittest.main()
