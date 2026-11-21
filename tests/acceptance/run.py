#!/usr/bin/env python3
"""zboot VM acceptance: pinned, serial, one disposable QEMU guest at a time.

  run.py list                         list cases (id, group, time bound, boots)
  run.py prepare OID [CASE|GROUP|native...] --uki OUT [--factory TAR]
                                      [--build-runner JSON|--distribution-tools --build-record JSON]
                                      [--min-free-gib N]
                                      new session: build zboot+zsnap at OID, initrds
  run.py prepare-efi SESSION NAME=OUT... [--factory TAR]
                                      record verified dist/dist.sh outputs
  run.py run SESSION CASE|GROUP|native... [--dev]   run cases; PASS/FAIL per case

OUT is what dist/dist.sh wrote: OUT/usr/lib/zboot/zboot.efi, its kernel
OUT/vmlinuz and the static tools under OUT/usr/bin. Native groups boot OUT's
kernel with the UKI's own initramfs (Debian's own OpenZFS) plus the
zboot/zsnap under test. Only `run` launches a VM. Cases
live in cases/*.py (host side: boots and verdict) and guest/cases/ID.sh
(guest side: product commands and native observations). Firmware boots
(Boot(efi=True)) boot a recorded build's UKI from a stick under OVMF;
Boot(extra={'build': NAME}) picks it (default `neutral`);
Boot(efi=True, extra={'from': 'A'}) boots disk A's own ESP with no stick;
Boot(efi=True, network=True, extra={'pxe': True}) boots the build's UKI
through the firmware's UEFI HTTP boot, with the NIC as the only boot device. A direct
boot with extra={'setup': NAME} runs that build's kernel, initramfs and
zboot with its UKI and a `zboot factory` root tar on the fixtures share
(/fixtures/e2e-esp-artifacts/zboot-recovery.efi, /fixtures/e2e-factory.tar.zst;
see tests/acceptance/build-initrd.sh). Environment: ZBOOT_ACCEPTANCE_SOURCE (clean checkout, default
this repository), ZBOOT_ACCEPTANCE_STATE (sessions, default
$TMPDIR/zboot-acceptance; TMPDIR defaults to /var/tmp),
ZBOOT_ACCEPTANCE_LOCK (default STATE/qemu.lock), ZBOOT_ACCEPTANCE_KEEP_IMAGES=1
(keep a passed case's VM images; a failed case always keeps them). --build-runner is a JSON
argv prefix, never shell text; by default builds use private temporary staging.
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
from host.uki import sha256, uki_section, verify_product_source  # noqa: E402

SOURCE = Path(os.environ.get('ZBOOT_ACCEPTANCE_SOURCE', HERE.parents[1]))
STATE = Path(os.environ.get('ZBOOT_ACCEPTANCE_STATE',
                            Path(os.environ.get('TMPDIR', '/var/tmp')) / 'zboot-acceptance')).resolve()
LOCK = Path(os.environ.get('ZBOOT_ACCEPTANCE_LOCK', STATE / 'qemu.lock'))
KEEP_IMAGES = os.environ.get('ZBOOT_ACCEPTANCE_KEEP_IMAGES') == '1'
# What a boot directory holds besides its evidence: disks, sticks and the
# per-boot copies of kernel, initrd and firmware. All of it comes back from
# the session's OID and OUT.
BOOT_BULK = ('*.raw', 'kernel', 'initrd', 'code.fd', 'vars.fd')
OVMF = (Path('/usr/share/OVMF/OVMF_CODE_4M.fd'), Path('/usr/share/OVMF/OVMF_VARS_4M.fd'))
HOST_TOOLS = ['--mkfs-vfat', '/usr/sbin/mkfs.fat',
              '--setfattr', '/usr/bin/setfattr', '--getfattr', '/usr/bin/getfattr',
              '--zvol-id', '/usr/lib/udev/zvol_id', '--fixture-busybox', '/usr/bin/busybox',
              '--jq', '/usr/bin/jq', '--nvme', '/usr/sbin/nvme',
              '--flock', '/usr/bin/flock']
# efi: firmware cases, see prepare-efi; deploy also needs prepare --factory.
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


def preparation_budget(build, groups, factory=None):
    # Only known copies: this is a floor, never a prediction of peak storage.
    source_bytes = sum(p.stat().st_size for p in HERE.rglob('*') if p.is_file())
    uki_bytes = build['uki'].stat().st_size
    return (source_bytes + build['kernel'].stat().st_size + uki_bytes
            + len(uki_section(build['uki'], '.initrd'))
            + sum(uki_bytes for group in groups if group in ('esp', 'restore', 'deploy'))
            + (Path(factory).stat().st_size if 'deploy' in groups else 0))


def verify_distribution_record(build, oid, record_path):
    if record_path is None:
        raise RuntimeError('--distribution-tools requires --build-record JSON binding OUT to its source OID')
    record_path = Path(record_path).resolve()
    record = json.loads(record_path.read_text())
    verify_product_source(SOURCE, record.get('source_oid'), oid)
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


def logged(argv, log, seconds, *, env=None, owned_scope=False):
    with open(log, 'w') as out:
        command = [str(a) for a in argv]
        if not owned_scope:
            subprocess.run(command, cwd=SOURCE, stdout=out, stderr=subprocess.STDOUT,
                           timeout=seconds, check=True, env=env)
            return
        # Only our local build's new process group is ours to terminate. Drain
        # it before deleting its staging, including on timeout/interruption.
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


def build_runner(value):
    """Parse a caller-owned argv prefix without introducing a shell."""
    try:
        argv = json.loads(value)
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError('build runner must be a JSON argv array') from error
    if (not isinstance(argv, list) or not argv or
            any(not isinstance(arg, str) or not arg or '\0' in arg for arg in argv)):
        raise argparse.ArgumentTypeError('build runner needs nonempty string argv entries')
    return argv


def run_build(argv, log, seconds, selected_runner=None):
    # A runner owns the complete build and its consumers. Only explicitly
    # published artifacts survive; never borrow another manager's Cargo target.
    if selected_runner is not None:
        logged([*selected_runner, *argv], log, seconds)
        return
    with tempfile.TemporaryDirectory(prefix='zboot-acceptance-build-',
                                     dir=os.environ.get('TMPDIR', '/var/tmp')) as temporary:
        environment = {**os.environ, 'CARGO_TARGET_DIR': str(Path(temporary).resolve() / 'target'),
                       'CARGO_BUILD_BUILD_DIR': str(Path(temporary).resolve() / 'build')}
        Path(environment['CARGO_TARGET_DIR']).mkdir(mode=0o700)
        Path(environment['CARGO_BUILD_BUILD_DIR']).mkdir(mode=0o700)
        logged(argv, log, seconds, env=environment, owned_scope=True)


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


def prepare(oid, groups, out, factory=None, selected_runner=None, min_free_gib=0,
            distribution_tools=False, build_record=None):
    selected = select_cases(groups or ['native'])
    groups = list(dict.fromkeys('small' if module.GROUP == 'efi' else module.GROUP for module in selected))
    if 'small' not in groups and any(boot.efi or 'setup' in boot.extra
                                     for module in selected for boot in module.BOOTS):
        groups.insert(0, 'small')  # prepare-efi stages handoff fixtures from it
    if distribution_tools and selected_runner is not None:
        raise RuntimeError('--distribution-tools and --build-runner are mutually exclusive')
    if 'deploy' in groups and not factory:
        raise RuntimeError('the deploy group needs --factory TAR (a `zboot factory` root tar)')
    build = uki_output(out)
    clean_at(oid)
    STATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    copy_floor = preparation_budget(build, groups, factory)
    free = shutil.disk_usage(STATE).free
    reserve = int(min_free_gib * (1 << 30))
    if free < copy_floor + reserve:
        raise RuntimeError(f'need {copy_floor} known input-copy bytes plus {reserve} requested reserve bytes; '
                           f'only {free} free under {STATE}')
    if distribution_tools:
        build_record = verify_distribution_record(build, oid, build_record)
        subprocess.run(['sha256sum', '--quiet', '--check', 'SHA256SUMS'],
                       cwd=build['directory'], check=True, timeout=600)
    session = STATE / 'runs' / f'{oid[:12]}-{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}'
    session.mkdir(parents=True, mode=0o700)
    (session / 'source.oid').write_text(oid + '\n')
    # Freeze the recipes and guest scripts the session runs with.
    shutil.copytree(HERE, session / 'acceptance', ignore=shutil.ignore_patterns('__pycache__'))
    staged = stage_uki(build, session / 'uki')
    inputs = [build['uki'], build['kernel'],
              *([Path(factory)] if factory else []),
              *[Path(p) for p in HOST_TOOLS[1::2]]]
    tools_source_oid = json.loads(build_record.read_text())['source_oid'] if distribution_tools else oid
    (session / 'provenance.json').write_text(json.dumps(
        {'source_oid': oid, 'producer_source_oid': tools_source_oid, 'uki_output': str(build['directory']),
         'inputs': {str(p): sha256(p) for p in inputs + ([build['zboot'], build['zsnap']] if distribution_tools else [])}}, indent=2) + '\n')
    if distribution_tools:
        shutil.copyfile(build_record, session / 'build-record.json')
        (session / 'bin').mkdir(mode=0o700)
        for name in ('zboot', 'zsnap'):
            shutil.copy2(build[name], session / 'bin' / name)
        (session / 'bin/SHA256SUMS').write_text(''.join(
            f"{sha256(session / 'bin' / name)}  {name}\n" for name in ('zboot', 'zsnap')))
        (session / 'bin/source.oid').write_text(tools_source_oid + '\n')
    else:
        run_build([HERE / 'build.sh', SOURCE, oid, session / 'bin'],
                  session / 'build.log', 2400, selected_runner)
    clean_at(oid)
    for group in groups:
        argv = [session / 'acceptance/build-initrd.sh', '--base-initrd', staged / 'initrd.img.zst',
                '--acceptance', session / 'acceptance/guest',
                '--zboot', session / 'bin/zboot', '--zsnap', session / 'bin/zsnap', *HOST_TOOLS,
                # Every group routes zfs through the (unarmed: transparent) fault shim.
                '--fault-tool', 'zfs',
                '--output', session / f'{group}.zst']
        if group in ('esp', 'restore', 'deploy'):  # only groups with bulk inputs need a share
            argv += ['--fixture-directory', session / f'{group}-fixtures']
        # The session's UKI is the loader esp and deploy install and the
        # one restore's source BEs ship (guest/restore.sh).
        extra = ['--esp-artifacts', staged / 'loader'] if group in ('esp', 'restore') else []
        if group == 'deploy':
            extra = ['--esp-artifacts', staged / 'loader', '--factory-image', Path(factory).resolve()]
        logged(argv + extra, session / f'prepare-{group}.log', 1800)
    (session / 'resources.json').write_text(json.dumps({
        'selected_cases': [module.ID for module in selected], 'prepared_groups': groups,
        'known_input_copy_bytes': copy_floor, 'requested_reserve_bytes': reserve,
        'free_bytes_before': free, 'free_bytes_after': shutil.disk_usage(STATE).free,
        'session_allocated_bytes': sum(p.stat().st_blocks * 512 for p in session.rglob('*') if p.is_file()),
        'distribution_tools': distribution_tools,
        'excludes': ['build staging', 'initrd packing peak', 'later VM disk growth', 'prepare-efi outputs'],
    }, indent=2) + '\n')
    print(session)


def use_frozen_session(session, verb, arguments):
    """Hand the process to the session's recipe before acquiring resources."""
    acceptance = (session / 'acceptance').resolve()
    entrypoint = acceptance / 'run.py'
    if entrypoint.is_symlink():
        raise RuntimeError(f'{entrypoint}: frozen acceptance runner must not be a symlink')
    if not entrypoint.is_file():
        raise RuntimeError(f'{entrypoint}: missing frozen acceptance runner')
    if HERE != acceptance:
        # Exec preserves PID and signal custody while its runner drains owned
        # guests on interruption. A parent subprocess watchdog could kill the
        # runner before that cleanup finishes.
        os.execv(sys.executable, [sys.executable, '-I', '-B', str(entrypoint), verb,
                                str(session), *map(str, arguments)])


def prepare_efi(session, builds, factory=None):
    """Record dist/dist.sh outputs (NAME=OUT): a boot stick of each UKI
    and a setup initrd of its own initramfs, kernel and tools. Setup stages
    deploy `factory`, a `zboot factory` root tar."""
    session = Path(session).resolve()
    use_frozen_session(session, 'prepare-efi',
                       [*builds, *(['--factory', factory] if factory else [])])
    # Direct-kernel stages of efi cases boot the small initrd; a hand-off
    # target BE gets the same kernel and initrd from the `zt-fixtures` share.
    fixtures = session / 'efi-fixtures'
    fixtures.mkdir(mode=0o700, exist_ok=True)
    for source, name in ((session / 'uki/vmlinuz', 'vmlinuz'), (session / 'small.zst', 'initrd.img')):
        shutil.copyfile(source, fixtures / name)
    recorded = {}
    for item in builds:
        name, _, directory = item.partition('=')
        if not re.fullmatch('[a-z0-9-]+', name):
            raise RuntimeError(f'{item}: NAME=OUT with a plain name')
        build = uki_output(directory)
        staged = stage_uki(build, session / f'efi-uki-{name}')
        stick = boot_stick(staged / 'loader/zboot-recovery.efi', session / f'efi-boot-{name}.raw')
        recorded[name] = {'directory': str(staged), 'output': str(build['directory']),
                          'uki_sha256': sha256(build['uki']), 'stick': str(stick),
                          'stick_sha256': sha256(stick)}
        # Setup stages run this build's own kernel, initramfs and zboot/zsnap,
        # with its UKI on the fixtures share, so a deploy in the guest
        # installs what the stick boots.
        logged([session / 'acceptance/build-initrd.sh', '--base-initrd', staged / 'initrd.img.zst',
                '--acceptance', session / 'acceptance/guest',
                '--zboot', build['zboot'], '--zsnap', build['zsnap'],
                *HOST_TOOLS, '--fault-tool', 'zfs', '--output', session / f'efi-setup-{name}.zst',
                '--fixture-directory', session / f'efi-setup-{name}-fixtures',
                '--esp-artifacts', staged / 'loader',
                *(['--factory-image', Path(factory).resolve()] if factory else [])],
               session / f'prepare-efi-setup-{name}.log', 1800)
    efi = session / 'efi.json'
    builds = json.loads(efi.read_text())['builds'] if efi.exists() else {}
    builds.update(recorded)
    firmware = {str(p): sha256(p) for p in OVMF}
    efi.write_text(json.dumps({'builds': builds, 'firmware': firmware}, indent=2) + '\n')
    print(json.dumps(recorded, indent=2))


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
    session = Path(session).resolve()
    if not dev:
        use_frozen_session(session, 'run', names)
    # Qualification runs the session's frozen copy of this file (HERE is then
    # SESSION/acceptance); --dev runs this tree's cases and guest scripts.
    from host import case as runner
    oid = (session / 'source.oid').read_text().strip()
    subprocess.run(['sha256sum', '--quiet', '--check', 'SHA256SUMS'], cwd=session / 'bin', check=True)
    selected = select_cases(names)
    for module in selected:
        fixture = session / ('small.zst' if module.GROUP == 'efi' else f'{module.GROUP}.zst')
        if not fixture.is_file():
            raise RuntimeError(f'{module.ID}: missing prepared fixture {fixture}')
    from host.vm import accelerator_config
    config = accelerator_config()
    if config['experimental']:
        print('EXPERIMENTAL TCG: diagnostic results; not KVM qualification', flush=True)
    failed = 0
    for module in selected:
        # One case at a time host-wide; batches of different runs interleave.
        with open(LOCK, 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print(f'waiting for {LOCK}: another VM run is active', flush=True)
                fcntl.flock(lock, fcntl.LOCK_EX)
            initrd = session / ('small.zst' if module.GROUP == 'efi' else f'{module.GROUP}.zst')
            fixtures = session / f'{module.GROUP}-fixtures'

            def boot_for(boot, initrd=initrd):
                if boot.efi and boot.extra.get('case_images'):
                    efi_build(session, 'neutral')  # retain recorded firmware identity checks
                    return {'efi': OVMF}
                if boot.efi and 'from' in boot.extra:  # a stock disk's own ESP
                    label = boot.extra['from']
                    if label not in ('A', 'B', 'D'):
                        raise ValueError('firmware source must be a declared stock disk')
                    efi_build(session, 'neutral')  # firmware identity check
                    spec = {'efi': OVMF, 'boot_disk': label}
                    if 'bus' in boot.extra:  # only A may leave virtio; Vm checks it
                        spec.update(boot_a=label == 'A', a_bus=boot.extra['bus'])
                    return spec
                if boot.efi and boot.extra.get('pxe'):  # the build's UKI from the network
                    build = efi_build(session, boot.extra.get('build', 'neutral'))
                    uki = Path(build['directory']) / 'loader/zboot-recovery.efi'
                    if sha256(uki) != build['uki_sha256']:
                        raise RuntimeError(f'{uki} changed since prepare-efi')
                    return {'efi': OVMF, 'pxe': uki}
                if boot.efi:
                    build = efi_build(session, boot.extra.get('build', 'neutral'))
                    return {'efi': OVMF, 'disk': Path(build['stick'])}
                if 'setup' in boot.extra:
                    build = efi_build(session, boot.extra['setup'])
                    return {'kernel': Path(build['directory']) / 'vmlinuz', 'append': '',
                            'initrd': session / f"efi-setup-{boot.extra['setup']}.zst"}
                return {'kernel': session / 'uki/vmlinuz', 'initrd': initrd, 'append': ''}

            def shares(boot, fixtures=fixtures):
                if 'setup' in boot.extra:
                    fixtures = session / f"efi-setup-{boot.extra['setup']}-fixtures"
                found = [('zt-acceptance', HERE / 'guest')]
                return found + ([('zt-fixtures', fixtures)] if fixtures.is_dir() else [])

            (session / 'cases').mkdir(mode=0o700, exist_ok=True)
            run_dir = session / 'cases' / f'{module.ID}-{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}'
            started = time.monotonic()
            try:
                result = runner.run(module, run_dir, boot_for, shares)
            except (OSError, RuntimeError, TimeoutError) as e:
                result = {'id': module.ID, 'pass': False, 'failures': [f'harness: {e!r}']}
                run_dir.mkdir(mode=0o700, exist_ok=True)
                (run_dir / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            result['qualification'] = not dev and not config['experimental']
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
    print(f'{len(selected) - failed}/{len(selected)} passed at {oid}' + (' (DEV: working-tree cases)' if dev else '') + (' (EXPERIMENTAL TCG)' if config['experimental'] else ''))
    return 1 if failed else 0


def efi_build(session, name):
    if not (session / 'efi.json').is_file():
        raise RuntimeError(f'{session} has no firmware builds: run prepare-efi SESSION {name}=OUT first')
    recorded = json.loads((session / 'efi.json').read_text())
    for path, digest in recorded['firmware'].items():
        if sha256(path) != digest:
            raise RuntimeError(f'{path} changed since prepare-efi')
    return recorded['builds'][name]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    verbs = parser.add_subparsers(dest='verb', required=True)
    verbs.add_parser('list', help='list cases without building or starting VMs')
    p = verbs.add_parser('prepare')
    p.add_argument('oid')
    p.add_argument('groups', nargs='*', metavar='CASE|GROUP|native')
    p.add_argument('--uki', metavar='OUT', required=True, help='what dist/dist.sh OUT wrote')
    p.add_argument('--build-runner', type=build_runner, metavar='JSON',
                   help='JSON argv prefix owning the build scope; default: private local temporary staging')
    p.add_argument('--build-record', metavar='JSON', help='distribution build record with source_oid and file hashes; required with --distribution-tools')
    p.add_argument('--distribution-tools', action='store_true', help='copy OUT tools after checking OUT/SHA256SUMS instead of rebuilding')
    p.add_argument('--min-free-gib', type=float, default=0, help='requested free-space reserve beyond known input copies (not a total peak estimate)')
    p.add_argument('--factory', metavar='TAR', help='`zboot factory` root tar the deploy group installs')
    e = verbs.add_parser('prepare-efi')
    e.add_argument('session')
    e.add_argument('builds', nargs='+', metavar='NAME=OUT')
    e.add_argument('--factory', metavar='TAR', help='`zboot factory` root tar setup stages deploy')
    r = verbs.add_parser('run')
    r.add_argument('session')
    r.add_argument('cases', nargs='+')
    r.add_argument('--dev', action='store_true', help="run this tree's cases, not the session's frozen copy")
    args = parser.parse_args()
    if args.verb == 'list':
        for module in cases().values():
            print(f'{module.ID}\t{module.GROUP}\t{module.SECONDS}s\t{len(module.BOOTS)} boot(s)')
        return 0
    if args.verb == 'prepare':
        if not 0 <= args.min_free_gib < float('inf'):
            parser.error('--min-free-gib must be finite and nonnegative')
        return prepare(args.oid, args.groups, args.uki, args.factory, args.build_runner,
                       args.min_free_gib, args.distribution_tools, args.build_record)
    if args.verb == 'prepare-efi':
        return prepare_efi(args.session, args.builds, args.factory)
    return run(args.session, args.cases, args.dev)


if __name__ == '__main__':
    sys.exit(main())
