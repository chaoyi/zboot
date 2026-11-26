#!/usr/bin/env python3
"""zboot VM acceptance: pinned, serial, one disposable QEMU guest at a time.

  run.py list                         list cases (id, group, time bound, boots)
  run.py prepare OID [CASE|GROUP|native...] --uki OUT [--factory TAR]
                                      [--distribution-tools --build-record JSON]
                                      new session: zboot+zsnap at OID, the initrd,
                                      fixtures and the firmware boot stick
  run.py run SESSION CASE|GROUP|native... [--dev]   run cases; PASS/FAIL per case

OUT is what dist/dist.sh wrote: OUT/usr/lib/zboot/zboot.efi, its kernel
OUT/vmlinuz and the static tools under OUT/usr/bin. Direct boots run OUT's
kernel with the UKI's own initramfs (Debian's own OpenZFS) plus the
zboot/zsnap under test. Only `run` launches a VM. Cases
live in cases/*.py (host side: boots and verdict) and guest/cases/ID.sh
(guest side: product commands and native observations). Firmware boots
(Boot(efi=True)) boot the session's UKI from a stick under OVMF;
Boot(efi=True, extra={'from': 'A'}) boots disk A's own ESP with no stick;
Boot(efi=True, network=True, extra={'pxe': True}) boots the UKI through the
firmware's UEFI HTTP boot, with the NIC as the only boot device. Every group
but small gets the fixtures share at /fixtures: the UKI
(/fixtures/e2e-esp-artifacts/zboot-recovery.efi), the `zboot factory` root tar
(/fixtures/e2e-factory.tar.zst), and the acceptance kernel and initrd
(/fixtures/vmlinuz, /fixtures/initrd.img). Environment: ZBOOT_ACCEPTANCE_STATE
(sessions, default $TMPDIR/zboot-acceptance; TMPDIR defaults to /var/tmp),
ZBOOT_ACCEPTANCE_LOCK (default STATE/qemu.lock), ZBOOT_ACCEPTANCE_KEEP_IMAGES=1
(keep a passed case's VM images; a failed case always keeps them).
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from host.uki import sha256, uki_section  # noqa: E402

SOURCE = HERE.parents[1]
STATE = Path(os.environ.get('ZBOOT_ACCEPTANCE_STATE',
                            Path(os.environ.get('TMPDIR', '/var/tmp')) / 'zboot-acceptance')).resolve()
LOCK = Path(os.environ.get('ZBOOT_ACCEPTANCE_LOCK', STATE / 'qemu.lock'))
KEEP_IMAGES = os.environ.get('ZBOOT_ACCEPTANCE_KEEP_IMAGES') == '1'
# What a boot directory holds besides its evidence: disks, sticks and the
# per-boot copies of kernel, initrd and firmware. All of it comes back from
# the session's OID and OUT.
BOOT_BULK = ('*.raw', 'kernel', 'initrd', 'code.fd', 'vars.fd')
OVMF = (Path('/usr/share/OVMF/OVMF_CODE_4M.fd'), Path('/usr/share/OVMF/OVMF_VARS_4M.fd'))
# Test-only host tools the runtime lacks; product tools (nvme, mkfs.vfat,
# wipefs, zfs, ...) are always the runtime's own.
HOST_TOOLS = ['--setfattr', '/usr/bin/setfattr', '--getfattr', '/usr/bin/getfattr',
              '--zvol-id', '/usr/lib/udev/zvol_id', '--fixture-busybox', '/usr/bin/busybox',
              '--jq', '/usr/bin/jq', '--flock', '/usr/bin/flock']
# efi: firmware cases; efi and deploy need prepare --factory.
GROUPS = ('efi', 'small', 'esp', 'deploy', 'restore')
NATIVE = [g for g in GROUPS if g != 'efi']


def cases():
    found = {}
    for path in sorted((HERE / 'cases').glob('*.py')):
        if path.name == '__init__.py':
            continue
        spec = importlib.util.spec_from_file_location(f'cases.{path.stem}', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if module.ID in found:
            raise RuntimeError(f'duplicate case id {module.ID}')
        if module.GROUP not in GROUPS:
            raise RuntimeError(f'{module.ID}: unknown group {module.GROUP}')
        guest = any(not boot.efi for boot in module.BOOTS)
        if guest and not (HERE / 'guest/cases' / f'{module.ID}.sh').is_file():
            raise RuntimeError(f'{module.ID}: no guest/cases/{module.ID}.sh')
        found[module.ID] = module
    return found


def select_cases(names, known=None):
    known = cases() if known is None else known
    selected = {}
    for name in names:
        groups = NATIVE if name == 'native' else [name] if name in GROUPS else None
        if groups:
            matches = [module for module in known.values() if module.GROUP in groups]
        else:
            matches = [known[name]] if name in known else []
        if not matches:
            raise RuntimeError(f'{name}: no matching acceptance cases')
        selected.update((module.ID, module) for module in matches)
    if not selected:
        raise RuntimeError('no acceptance cases selected')
    return list(selected.values())


def verify_distribution_record(build, oid, record_path):
    if record_path is None:
        raise RuntimeError('--distribution-tools requires --build-record JSON binding OUT to its source OID')
    record_path = Path(record_path).resolve()
    record = json.loads(record_path.read_text())
    if record.get('source_oid') != oid:
        raise RuntimeError(f"the build record is of {record.get('source_oid')!r}, not {oid}")
    for name in ('uki', 'kernel', 'zboot', 'zsnap'):
        try:
            relative = build[name].resolve().relative_to(record_path.parent).as_posix()
        except ValueError as error:
            raise RuntimeError(f'{build[name]} is outside the build record root') from error
        if record.get('files', {}).get(relative) != sha256(build[name]):
            raise RuntimeError(f'{name}: distribution bytes do not match the build record')
    return record_path


def git(*args):
    return subprocess.check_output(['git', *args], cwd=SOURCE, text=True, timeout=60).strip()


def clean_at(oid):
    if not re.fullmatch('[0-9a-f]{40}', oid) or git('rev-parse', 'HEAD') != oid or git('status', '--porcelain'):
        raise RuntimeError(f'{SOURCE} must be clean at exactly {oid}')


def logged(argv, log, seconds, *, env=None):
    """Run ARGV in its own process group with output to LOG. The whole group
    is stopped when the leader ends or times out, before any staging goes."""
    with open(log, 'w') as out:
        command = [str(a) for a in argv]
        with subprocess.Popen(command, cwd=SOURCE, stdout=out, stderr=subprocess.STDOUT,
                              env=env, start_new_session=True) as process:
            try:
                status = process.wait(timeout=seconds)
                if status:
                    raise subprocess.CalledProcessError(status, command)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


def build_tools(oid, destination, log):
    """Release zboot and zsnap at OID in DESTINATION, static like the shipped
    tools so each is the guest's /usr/bin binary itself. A caller's
    CARGO_TARGET_DIR is used as given; otherwise the build gets private
    staging, removed afterwards."""
    with tempfile.TemporaryDirectory(prefix='zboot-acceptance-build-',
                                     dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
        environment = {**os.environ, 'RUSTFLAGS': '-C target-feature=+crt-static'}
        if not environment.get('CARGO_TARGET_DIR'):
            environment.update(CARGO_TARGET_DIR=f'{temporary}/target', CARGO_BUILD_BUILD_DIR=f'{temporary}/build')
        logged(['cargo', 'build', '--jobs', os.environ.get('CARGO_BUILD_JOBS', '4'), '--locked', '--release',
                '--target', 'x86_64-unknown-linux-gnu', '-p', 'zboot', '-p', 'zsnap', '--bins'],
               log, 2400, env=environment)
        destination.mkdir(mode=0o700)
        release = Path(environment['CARGO_TARGET_DIR']) / 'x86_64-unknown-linux-gnu/release'
        for name in ('zboot', 'zsnap'):
            shutil.copyfile(release / name, destination / name)
            (destination / name).chmod(0o755)


def uki_output(out):
    """The paths of a dist/dist.sh OUT that a session uses."""
    out = Path(out).resolve()
    found = {'uki': out / 'usr/lib/zboot/zboot.efi', 'kernel': out / 'vmlinuz',
             'zboot': out / 'usr/bin/zboot', 'zsnap': out / 'usr/bin/zsnap'}
    for path in found.values():
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f'{path}: not part of a dist/dist.sh output')
    found['directory'] = out
    return found


def stage_uki(build, directory):
    """DIRECTORY/{vmlinuz,initrd.img.zst,loader/zboot-recovery.efi} from a
    dist/dist.sh output: its kernel, its UKI's own initramfs and the UKI as
    the fixtures share's loader. The UKI must carry exactly that kernel."""
    directory.mkdir(mode=0o700)
    if uki_section(build['uki'], '.linux') != build['kernel'].read_bytes():
        raise RuntimeError(f"{build['uki']}: its .linux is not {build['kernel']}")
    shutil.copyfile(build['kernel'], directory / 'vmlinuz')
    (directory / 'initrd.img.zst').write_bytes(uki_section(build['uki'], '.initrd'))
    (directory / 'loader').mkdir(mode=0o700)
    shutil.copyfile(build['uki'], directory / 'loader/zboot-recovery.efi')
    return directory


def boot_stick(uki, image):
    """A GPT image whose one ESP holds UKI as EFI/BOOT/BOOTX64.EFI, the
    removable-media path firmware boots."""
    mib = 1 << 20
    size = (uki.stat().st_size * 5 // 4 + 128 * mib + mib - 1) // mib * mib
    partition = image.with_suffix('.fat')
    with open(partition, 'xb') as f:
        f.truncate(size)
    subprocess.run(['/usr/bin/mformat', '-i', partition, '-F', '-v', 'ZBOOT', '-N', '5a424f54',
                    '-H', '2048', '-T', str(size // 512), '::'], check=True, timeout=120)
    for directory in ('::EFI', '::EFI/BOOT'):
        subprocess.run(['/usr/bin/mmd', '-i', partition, directory], check=True, timeout=60)
    subprocess.run(['/usr/bin/mcopy', '-i', partition, uki, '::EFI/BOOT/BOOTX64.EFI'],
                   check=True, timeout=600)
    with open(image, 'xb') as f:
        f.truncate(2 * mib + size)
    layout = (f'label: gpt\nlabel-id: 5A424F54-0000-4000-8000-000000000001\nfirst-lba: 2048\n'
              f'start=2048, size={size // 512}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, '
              f'uuid=5A424F54-0000-4000-8000-000000000002, name="zboot"\n')
    subprocess.run(['/usr/sbin/sfdisk', '--quiet', '--no-reread', '--no-tell-kernel', image],
                   input=layout.encode(), check=True, timeout=60)
    with open(partition, 'rb') as source, open(image, 'r+b') as target:
        target.seek(mib)
        shutil.copyfileobj(source, target, 8 << 20)
    partition.unlink()
    readback = image.with_suffix('.readback')
    subprocess.run(['/usr/bin/mcopy', '-i', f'{image}@@{mib}', '::EFI/BOOT/BOOTX64.EFI', readback],
                   check=True, timeout=600)
    if sha256(readback) != sha256(uki):
        raise RuntimeError(f'{image}: the stick does not read back its UKI')
    readback.unlink()
    return image


def prepare(oid, names, out, factory=None, distribution_tools=False, build_record=None):
    """A new session for the selected cases (default: all) from one
    dist/dist.sh OUT: its kernel and UKI, zboot and zsnap at OID, one
    acceptance initrd, the fixtures share and, for firmware boots, a stick."""
    selected = select_cases(names or [*GROUPS])
    if not factory and any(module.GROUP in ('deploy', 'efi') for module in selected):
        raise RuntimeError('the deploy and efi groups need --factory TAR (a `zboot factory` root tar)')
    firmware = any(boot.efi for module in selected for boot in module.BOOTS)
    build = uki_output(out)
    clean_at(oid)
    if distribution_tools:
        build_record = verify_distribution_record(build, oid, build_record)
    STATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    session = STATE / 'runs' / f'{oid[:12]}-{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}'
    session.mkdir(parents=True, mode=0o700)
    (session / 'source.oid').write_text(oid + '\n')
    staged = stage_uki(build, session / 'uki')
    inputs = [build['uki'], build['kernel'],
              *([Path(factory)] if factory else []),
              *[Path(p) for p in HOST_TOOLS[1::2]]]
    (session / 'provenance.json').write_text(json.dumps(
        {'source_oid': oid, 'uki_output': str(build['directory']),
         'selected_cases': [module.ID for module in selected],
         'inputs': {str(p): sha256(p) for p in inputs + ([build['zboot'], build['zsnap']] if distribution_tools else [])}}, indent=2) + '\n')
    if distribution_tools:
        shutil.copyfile(build_record, session / 'build-record.json')
        (session / 'bin').mkdir(mode=0o700)
        for name in ('zboot', 'zsnap'):
            shutil.copy2(build[name], session / 'bin' / name)
    else:
        build_tools(oid, session / 'bin', session / 'build.log')
    (session / 'bin/SHA256SUMS').write_text(''.join(
        f"{sha256(session / 'bin' / name)}  {name}\n" for name in ('zboot', 'zsnap')))
    (session / 'bin/source.oid').write_text(oid + '\n')
    clean_at(oid)
    # Every group routes zfs through the (unarmed: transparent) fault shim.
    logged([HERE / 'build-initrd.sh', '--base-initrd', staged / 'initrd.img.zst', '--acceptance', HERE / 'guest',
            '--zboot', session / 'bin/zboot', '--zsnap', session / 'bin/zsnap', *HOST_TOOLS,
            '--fault-tool', 'zfs', '--output', session / 'initrd.zst'], session / 'prepare-initrd.log', 1800)
    # The read-only share of every group but small: the session's UKI as the
    # loader esp and deploy install and restore's source BEs ship
    # (guest/restore.sh), the factory tar setup stages deploy, and the
    # acceptance kernel and initrd a handoff target BE boots.
    fixtures = session / 'fixtures'
    fixtures.mkdir(mode=0o700)
    (fixtures / 'e2e-esp-artifacts').mkdir(mode=0o700)
    shutil.copyfile(staged / 'loader/zboot-recovery.efi', fixtures / 'e2e-esp-artifacts/zboot-recovery.efi')
    if factory:
        shutil.copyfile(factory, fixtures / 'e2e-factory.tar.zst')
    shutil.copyfile(staged / 'vmlinuz', fixtures / 'vmlinuz')
    os.link(session / 'initrd.zst', fixtures / 'initrd.img')
    if firmware:
        # Firmware boots: the UKI as a stick's EFI/BOOT/BOOTX64.EFI, under
        # OVMF files whose hashes a later run checks.
        stick = boot_stick(staged / 'loader/zboot-recovery.efi', session / 'efi-boot.raw')
        (session / 'efi.json').write_text(json.dumps({
            'uki_sha256': sha256(build['uki']), 'stick': str(stick), 'stick_sha256': sha256(stick),
            'firmware': {str(p): sha256(p) for p in OVMF}}, indent=2) + '\n')
    print(session)


def discard_boot_bulk(run_dir):
    """Remove a passed case's VM images and boot inputs; return the bytes they held.

    Logs, launch records, `result.json` and `out/` stay: they are the case's
    evidence (docs/TESTING.md). Only regular files directly inside a real
    `boot-N` directory go. Boots after a power cut hard-link the previous
    boot's disks, so an image counts once."""
    seen, freed = set(), 0
    for boot in sorted(Path(run_dir).glob('boot-*')):
        if boot.is_symlink() or not boot.is_dir():
            continue
        for pattern in BOOT_BULK:
            for path in boot.glob(pattern):
                status = path.lstat()
                if not stat.S_ISREG(status.st_mode):
                    continue
                if (status.st_dev, status.st_ino) not in seen:
                    seen.add((status.st_dev, status.st_ino))
                    freed += status.st_blocks * 512
                path.unlink()
    return freed


def run(session, names, dev=False):
    """Qualification runs this checkout's runner, cases and guest scripts,
    clean at the session's OID; --dev runs them as they are."""
    from host import case as runner
    session = Path(session).resolve()
    oid = (session / 'source.oid').read_text().strip()
    if not dev:
        clean_at(oid)
    subprocess.run(['sha256sum', '--quiet', '--check', 'SHA256SUMS'], cwd=session / 'bin', check=True)
    selected = select_cases(names)
    if not (session / 'initrd.zst').is_file():
        raise RuntimeError(f'{session}: missing prepared fixture initrd.zst')
    failed = 0
    for module in selected:
        # One case at a time host-wide; batches of different runs interleave.
        with open(LOCK, 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print(f'waiting for {LOCK}: another VM run is active', flush=True)
                fcntl.flock(lock, fcntl.LOCK_EX)

            def boot_for(boot):
                if not boot.efi:
                    return {'kernel': session / 'uki/vmlinuz', 'initrd': session / 'initrd.zst', 'append': ''}
                firmware = efi_record(session)
                if boot.extra.get('case_images'):
                    return {'efi': OVMF}
                if 'from' in boot.extra:  # a stock disk's own ESP
                    label = boot.extra['from']
                    if label not in ('A', 'B', 'D'):
                        raise ValueError('firmware source must be a declared stock disk')
                    spec = {'efi': OVMF, 'boot_disk': label}
                    if 'bus' in boot.extra:  # only A may leave virtio; Vm checks it
                        spec['a_bus'] = boot.extra['bus']
                    return spec
                if boot.extra.get('pxe'):  # the session's UKI from the network
                    uki = session / 'uki/loader/zboot-recovery.efi'
                    if sha256(uki) != firmware['uki_sha256']:
                        raise RuntimeError(f'{uki} changed since prepare')
                    return {'efi': OVMF, 'pxe': uki}
                return {'efi': OVMF, 'disk': Path(firmware['stick'])}

            def shares(_boot, group=module.GROUP):
                found = [('zt-acceptance', HERE / 'guest')]
                return found + ([('zt-fixtures', session / 'fixtures')] if group != 'small' else [])

            (session / 'cases').mkdir(mode=0o700, exist_ok=True)
            run_dir = session / 'cases' / f'{module.ID}-{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}'
            started = time.monotonic()
            try:
                result = runner.run(module, run_dir, boot_for, shares)
            except (OSError, RuntimeError, TimeoutError) as e:
                result = {'id': module.ID, 'pass': False, 'failures': [f'harness: {e!r}']}
                run_dir.mkdir(mode=0o700, exist_ok=True)
                (run_dir / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            result['qualification'] = not dev
            # A passed case needs its images no longer; a failed one keeps
            # everything for diagnosis.
            if result['pass'] and not KEEP_IMAGES:
                result['boot_bulk_removed_bytes'] = discard_boot_bulk(run_dir)
            (run_dir / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            verdict = 'PASS' if result['pass'] else 'FAIL'
            failed += not result['pass']
            print(f"{module.ID} {verdict} {time.monotonic() - started:.1f}s "
                  f"assertions={result.get('assertions', 0)} {run_dir}", flush=True)
            for failure in result['failures']:
                print(f'  - {failure}', flush=True)
    print(f'{len(selected) - failed}/{len(selected)} passed at {oid}' + (' (DEV: working-tree cases)' if dev else ''))
    return 1 if failed else 0


def efi_record(session):
    """The session's firmware-boot record, after checking the OVMF files."""
    if not (session / 'efi.json').is_file():
        raise RuntimeError(f'{session} has no firmware boot stick: prepare it with an efi case selected')
    recorded = json.loads((session / 'efi.json').read_text())
    for path, digest in recorded['firmware'].items():
        if sha256(path) != digest:
            raise RuntimeError(f'{path} changed since prepare')
    return recorded


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    verbs = parser.add_subparsers(dest='verb', required=True)
    verbs.add_parser('list', help='list cases without building or starting VMs')
    p = verbs.add_parser('prepare')
    p.add_argument('oid')
    p.add_argument('cases', nargs='*', metavar='CASE|GROUP|native')
    p.add_argument('--uki', metavar='OUT', required=True, help='what dist/dist.sh OUT wrote')
    p.add_argument('--factory', metavar='TAR', help='`zboot factory` root tar the deploy and efi groups install')
    p.add_argument('--distribution-tools', action='store_true', help='copy OUT tools after checking OUT/SHA256SUMS instead of rebuilding')
    p.add_argument('--build-record', metavar='JSON', help='distribution build record with source_oid and file hashes; required with --distribution-tools')
    r = verbs.add_parser('run')
    r.add_argument('session')
    r.add_argument('cases', nargs='+')
    r.add_argument('--dev', action='store_true', help="run this tree's cases as they are, not a qualification")
    args = parser.parse_args()
    if args.verb == 'list':
        for module in cases().values():
            print(f'{module.ID}\t{module.GROUP}\t{module.SECONDS}s\t{len(module.BOOTS)} boot(s)')
        return 0
    if args.verb == 'prepare':
        return prepare(args.oid, args.cases, args.uki, args.factory, args.distribution_tools, args.build_record)
    return run(args.session, args.cases, args.dev)


if __name__ == '__main__':
    sys.exit(main())
