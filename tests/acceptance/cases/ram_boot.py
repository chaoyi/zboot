"""A rescue in RAM from a network-booted UKI: `zboot boot --tar -`.

Setup deploys the session's root tar (`prepare-efi --factory`, the docs/RECOVERY.md
rescue recipe) to A, so the first network boot finds a local pool and
adopts its hostid. In each RAM leg one SSH session, admitted by `connect`'s
one-time password, writes ACCESS (the login key and a login marker) in
the UKI and pipes the same root tar to
`zboot boot --tar - --overlay builtin:rescue --overlay ACCESS`. The RAM
system then shows console and serial autologin, DHCP, DNS, key login with
root locked and password login refused, and imports the local pool. Boot 3
does it again on blank disks, with no pool and no hostid; boot 4 gives the
machine less RAM than the tar needs, and boot --tar refuses before kexec.
"""
import base64
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time

from cases import efi_connect as _connect, pxe_menu as _pxe
from cases.rescue_stick import PACKAGES
from host.case import Boot
from host.console import ConsoleError
from host.vm import default_memory_mib, sha256


ID = 'RAM-BOOT'
GROUP = 'efi'
SECONDS = 4200
DISKS = {'A': 8, 'B': 2, 'D': 2}
BOOTS = [Boot(1, extra={'setup': 'neutral'}),
         Boot(2, efi=True, network=True, extra={'pxe': True}),
         Boot(3, efi=True, network=True, fresh_disks=True, extra={'pxe': True}),
         Boot(4, efi=True, network=True, fresh_disks=True, extra={'pxe': True, 'memory': 'short'})]
POOL = 'e2ea'
PROMPT = 'rescue-root# '
LOGIN = 'ZT_RESCUE_LOGIN tty=/dev/ttyS0 uid=0'
SHORT = 'MiB of available RAM'
PROFILE = r'''terminal=$(tty)
uid=$(id -u)
printf 'tty=%s uid=%s\n' "$terminal" "$uid" > "/run/zt-login-${terminal##*/}"
printf 'ZT_RESCUE_LOGIN tty=%s uid=%s\n' "$terminal" "$uid"
PS1='rescue-root# '
export PS1
'''


def root_tar(run_dir):
    """The host's copy of the root tar the setup stage deploys."""
    return Path(run_dir).parents[1] / 'efi-setup-neutral-fixtures' / 'e2e-factory.tar.zst'


def generate_key(run_dir):
    """ACCESS's login key; only its public half leaves this case."""
    result = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                             '-f', str(run_dir / 'login')], capture_output=True, timeout=30)
    (run_dir / 'keygen.out').write_bytes(result.stdout)
    (run_dir / 'keygen.err').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f'login key generation failed: {result.returncode}')


def memory_plan(tar_bytes, logical_bytes, kernel_bytes):
    """Bound both unpacking and the upload/staged-initrd/kexec copies."""
    mib = 1 << 20
    need = tar_bytes + logical_bytes + 256 * mib
    staging = 3 * tar_bytes + 2 * kernel_bytes
    runtime = 1024 * mib
    positive = max(2048, (max(need, staging) + runtime + mib - 1) // mib)
    short = need // mib - 128
    if short < 1024:
        raise RuntimeError('the root tar is too small for a machine below its RAM need')
    return {'need_bytes': need, 'staging_bytes': staging, 'runtime_headroom_bytes': runtime,
            'positive_mib': positive, 'short_mib': short,
            'formula': 'ceil_MiB(max(tar+logical+256MiB,3*tar+2*kernel)+1024MiB); minimum 2048MiB'}


def tar_sizes(tar):
    with tar.open('rb') as source:
        compressed = source.read(4) == b'\x28\xb5\x2f\xfd'
    logical, members = 0, {}
    with tarfile.open(tar, 'r|zst' if compressed else 'r|') as archive:
        for member in archive:
            name = Path(member.name).as_posix()
            while name.startswith('./'):
                name = name[2:]
            logical += member.size
            members[name] = member
    kernels = [name for name in members if name.startswith('boot/vmlinuz-')]
    if len(kernels) != 1:
        raise RuntimeError(f'RAM-BOOT needs exactly one factory kernel, found {len(kernels)}')
    name = kernels[0]
    for _ in range(4):  # same hardlink-chain bound as product copy_kernel
        member = members.get(name)
        if member is None:
            break
        if member.isfile():
            return logical, member.size
        if not member.islnk():
            break
        name = Path(member.linkname).as_posix()
    raise RuntimeError('RAM-BOOT factory kernel must resolve to a regular member')


def prepare(run_dir):
    generate_key(run_dir)
    _pxe.write_askpass(run_dir)
    # ACCESS, a tar overlay: owners and modes are its own.
    with tarfile.open(run_dir / 'access.tar', 'w', format=tarfile.PAX_FORMAT) as archive:
        for name, mode, data in (('rootfs/root', 0o700, None), ('rootfs/root/.ssh', 0o700, None),
                                 ('rootfs/root/.ssh/authorized_keys', 0o600,
                                  (run_dir / 'login.pub').read_bytes()),
                                 ('rootfs/root/.profile', 0o644, PROFILE.encode())):
            member = tarfile.TarInfo(name)
            member.mode, member.uid, member.gid, member.mtime = mode, 0, 0, 0
            member.uname = member.gname = 'root'
            if data is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    tar = root_tar(run_dir)
    logical, kernel = tar_sizes(tar)
    plan = memory_plan(tar.stat().st_size, logical, kernel)
    # Unlike ordinary fixture defaults, this case's environment value is a
    # ceiling. Enlarging it cannot invalidate the deliberately short machine.
    ceiling = default_memory_mib(ID) if 'ZBOOT_VM_MEMORY_MIB' in os.environ else None
    if ceiling is not None and plan['positive_mib'] > ceiling:
        raise RuntimeError(f"RAM-BOOT needs {plan['positive_mib']} MiB for this factory tar; "
                           f'ZBOOT_VM_MEMORY_MIB ceiling is {ceiling} MiB')
    (run_dir / 'ram-inputs.json').write_text(json.dumps({
        'root_tar': str(tar), 'root_tar_sha256': sha256(tar),
        'root_tar_bytes': tar.stat().st_size, 'logical_bytes': logical,
        'kernel_bytes': kernel, 'ceiling_mib': ceiling, **plan}, indent=2) + '\n')


def memory_mib(run_dir, boot):
    inputs = json.loads((run_dir / 'ram-inputs.json').read_text())
    memory = inputs['short_mib' if boot.extra.get('memory') == 'short' else 'positive_mib']
    # The shared host lock prevents another acceptance guest starting between
    # this check and QEMU's preallocation. Keep 1 GiB available for the host.
    available = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                     if line.startswith('MemAvailable:'))
    if (memory + 1024) * (1 << 20) > available:
        raise RuntimeError(f'RAM-BOOT needs {memory} MiB guest RAM plus 1024 MiB host reserve; '
                           f'host has {available // (1 << 20)} MiB available')
    return memory


def session(console, known, after=''):
    """One UKI SSH session with the root tar on stdin: report, write
    ACCESS, run boot --tar, then AFTER if it returns."""
    access = base64.b64encode((console.case_dir / 'access.tar').read_bytes()).decode()
    body = ('set -e; printf "CMDLINE="; cat /proc/cmdline; '
            '/bin/busybox grep MemAvailable /proc/meminfo; zpool list -H -o name,readonly; '
            f'printf %s {access} | /bin/busybox base64 -d > /run/zt-access.tar; '
            + ('exec ' if not after else 'rc=0; ')
            + 'zboot boot --tar - --overlay builtin:rescue --overlay /run/zt-access.tar'
            + (f' || rc=$?; {after}' if after else ''))
    argv = _connect.ssh_argv(console, known, password=True)
    # A kexec ends the session without a close; keepalives end the client.
    return [argv[0], '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=6', *argv[1:], body]


def ram_boot(console):
    """Upload and boot the tar; return once the RAM system's serial login runs."""
    known, environment = _pxe.connect(console)
    argv = session(console, known)
    output, errors = (console.case_dir / f'upload-{console.out.name}.{kind}' for kind in ('out', 'err'))
    start = console.pos
    with root_tar(console.case_dir).open('rb') as source, output.open('wb') as out, errors.open('wb') as err:
        child = subprocess.Popen(argv, stdin=source, stdout=out, stderr=err, env=environment,
                                 start_new_session=True)
        try:
            console.expect(LOGIN, 1200)
            console.expect(PROMPT, 120)
        finally:
            try:
                child.wait(timeout=60)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
    console._record('ram-boot', 'UKI console from the upload to the RAM system login',
                    console._text(start, console.pos), 0)
    _connect.record(console, 'ram-upload', argv, subprocess.CompletedProcess(
        argv, child.returncode, output.read_text(errors='replace'), errors.read_text(errors='replace')))


def rescue(console, pool):
    """The booted RAM system, driven on its serial console and over SSH."""
    console.must('serial-autologin', 'id -u; tty; cat /run/zt-login-ttyS0')
    console.must('ram-root', 'findmnt -rn -o SOURCE,FSTYPE --target /; uname -r; cat /proc/cmdline; '
                 'test ! -e /etc/hostid')
    console.must('packages', "dpkg-query -W -f '${binary:Package}\\t${Version}\\n'")
    # networkd keeps no lease file; the address DHCP configured is the evidence.
    console.must('dhcp', 'i=0; until hostname -I | tr " " "\\n" | grep -E "^[0-9]+(\\.[0-9]+){3}$"; do '
                 'test "$i" -lt 90 || exit 1; i=$((i+1)); sleep 1; done; '
                 'networkctl status --no-pager', seconds=150)
    # restrict=on: slirp's DHCP offers no router or DNS server, so the lookup
    # is a name resolved answers itself, through resolv.conf and its stub.
    console.must('dns', 'timeout 30 getent ahostsv4 _localdnsstub', seconds=60)
    console.must('ram-fingerprint', 'i=0; until test -s /etc/ssh/ssh_host_ed25519_key.pub; do '
                 'test "$i" -lt 60 || exit 1; i=$((i+1)); sleep 1; done; '
                 'ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ed25519_key.pub', seconds=90)
    native = (console.out / f'{console.n:02d}-ram-fingerprint.out').read_text().split()[1:2]
    scan = ['/usr/bin/ssh-keyscan', '-T', '10', '-t', 'ed25519', '-p', str(console.ssh_port), '127.0.0.1']
    for _ in range(30):  # sshd may start after the login; wait unrecorded
        if subprocess.run(scan, capture_output=True, timeout=30).stdout.strip():
            break
        time.sleep(2)
    found = _connect.command(console, 'ram-keyscan', scan)
    if found.returncode or not found.stdout.strip():
        raise ConsoleError('the RAM system has no SSH listener')
    known = console.case_dir / f'known-ram-{console.out.name}'
    known.write_text(found.stdout)
    checked = _connect.command(console, 'ram-keyscan-fingerprint',
                               ['/usr/bin/ssh-keygen', '-l', '-E', 'sha256', '-f', known])
    if checked.returncode or checked.stdout.split()[1:2] != native:
        raise ConsoleError('the RAM system SSH host key differs from its console fingerprint')
    script = r'''set -e
printf 'KEY_LOGIN_OK\n'
printf 'ROOT_PASSWORD='; awk -F: '$1 == "root" {print $2}' /etc/shadow
for tty in tty1 ttyS0; do
  n=0; while [ ! -f "/run/zt-login-$tty" ] && [ "$n" -lt 30 ]; do sleep 1; n=$((n+1)); done
  printf 'AUTOLOGIN='; cat "/run/zt-login-$tty"
done
journalctl --sync
journalctl -u ssh.service --no-pager -o cat'''
    login = _connect.command(console, 'key-login', _connect.ssh_argv(console, known) + [script], timeout=90)
    if login.returncode:
        raise ConsoleError('the RAM system did not accept the ACCESS key')
    _connect.command(console, 'locked-password', _connect.ssh_argv(console, known, password=True) + ['true'],
                     env=_connect.password_env(console, 'not-a-password'))
    if pool:
        console.must('import-local', f'set -e; zpool list -H -o name {POOL} 2>/dev/null || '
                     f'zpool import -N -o readonly=on -o cachefile=none {POOL}; '
                     f'zpool list -Hp -o name,guid,readonly {POOL}; zpool export {POOL}', seconds=180)
    else:
        console.must('no-pool', 'zpool import 2>&1 || :; test -z "$(zpool list -H -o name)"', seconds=180)


def stage_2(console):
    ram_boot(console)
    rescue(console, True)


def stage_3(console):
    ram_boot(console)
    rescue(console, False)


def stage_4(console):
    known, environment = _pxe.connect(console)
    argv = session(console, known, after='printf "ZT_BOOT_RC=%s\\n" "$rc"; '
                   'printf "UPLOADS="; /bin/busybox ls -A /run/zboot/upload | /bin/busybox wc -l; '
                   '/bin/busybox grep MemAvailable /proc/meminfo')
    start = console.pos
    left = min(900, console.deadline - time.monotonic())
    with root_tar(console.case_dir).open('rb') as source:
        try:
            result = subprocess.run(argv, stdin=source, capture_output=True, text=True,
                                    timeout=left, env=environment, start_new_session=True)
        except subprocess.TimeoutExpired as error:
            raise ConsoleError('boot --tar neither refused nor returned on a short machine') from error
    _connect.record(console, 'short-boot', argv, result)
    console._record('short-console', 'UKI console during the refused boot', console._text(start, None), 0)
    if 'ZT_BOOT_RC=' not in result.stdout:
        raise ConsoleError('the short-RAM session did not report boot --tar')


def ram_leg(ev, check, stage, pool):
    leg = ev.stage(stage)
    label = f'stage{stage}'
    upload = leg.step('ram-upload').out
    check(re.search(r'(?m)^CMDLINE=.*\bzboot\.recovery=1\b', upload) is not None,
          f"{label}: connect's one-time password logs in to the network-booted UKI")
    check(re.search(rf'(?m)^{POOL}\ton$', upload) is not None if pool else
          re.search(rf'(?m)^{POOL}\t', upload) is None, f'{label}: the UKI pools are as the disks hold')
    transcript = leg.step('ram-boot').out
    for line in ('zboot RAM boot: unpacking the root tar', 'zboot RAM boot: applying overlay 000.tar',
                 'zboot RAM boot: applying overlay 001.tar'):
        check.contains(transcript, line, f'{label}: the bootstrap ran')
    check('zboot RAM boot failed' not in transcript, f'{label}: the bootstrap did not fail')
    check.contains(leg.step('serial-autologin').out, 'tty=/dev/ttyS0 uid=0', f'{label}: serial root autologin')
    facts = leg.step('ram-root').out.splitlines()
    check(len(facts) >= 3 and facts[0].split()[1:2] == ['tmpfs'], f'{label}: the root is a tmpfs: {facts[:1]}')
    cmdline = facts[2].split() if len(facts) >= 3 else []
    check(any(word.startswith('console=ttyS0') for word in cmdline), f'{label}: the UKI console is carried')
    check(not any(word.startswith(('zboot.ssh_key=', 'zboot.recovery=', 'ip=')) for word in cmdline),
          f'{label}: no key, UKI marker or network setting is passed: {cmdline}')
    check.equal('spl.spl_hostid=0x0174627a' in cmdline, pool,
                f'{label}: a hostid is passed exactly when the UKI adopted one')
    packages = {line.split('\t', 1)[0].split(':', 1)[0] for line in leg.step('packages').out.splitlines()}
    check(PACKAGES <= packages, f'{label}: the rescue recipe packages run in RAM')
    check(re.search(r'(?m)^10\.0\.2\.\d+$', leg.step('dhcp').out) is not None, f'{label}: DHCP address')
    check.equal(leg.step('dns').rc, 0, f'{label}: application lookup through resolved')
    check(re.search(r'(?m)^127\.0\.0\.53\s', leg.step('dns').out) is not None, f'{label}: the stub answers')
    login = leg.step('key-login').out
    check.contains(login, 'KEY_LOGIN_OK', f'{label}: the ACCESS key logs in')
    check(re.search(r'(?m)^ROOT_PASSWORD=[!*]', login) is not None, f'{label}: root is locked')
    for tty in ('tty1', 'ttyS0'):
        check.contains(login, f'AUTOLOGIN=tty=/dev/{tty} uid=0', f'{label}: {tty} root autologin')
    check.contains(login, 'Accepted publickey for root', f'{label}: sshd records the key login')
    refused = leg.step('locked-password')
    check(refused.rc != 0 and 'Permission denied' in refused.err, f'{label}: password login is refused')
    if pool:
        guid = ev.stage(1).step('pool-guid').out.strip()
        check(re.search(rf'(?m)^{POOL}\t{guid}\t(on|off)$', leg.step('import-local').out) is not None,
              f'{label}: the RAM system imports the local pool')
    else:
        check.equal(leg.step('no-pool').rc, 0, f'{label}: a blank machine has no pool')
    return leg.step('ram-keyscan-fingerprint').out.split()[1:2]


def verdict(ev, check):
    inputs = json.loads((Path(ev.root).parent / 'ram-inputs.json').read_text())
    check(inputs['short_mib'] * (1 << 20) < inputs['need_bytes'],
          'the negative machine is below the product RAM admission requirement')
    for index in (1, 2, 3):
        launch = json.loads((Path(ev.root).parent / f'boot-{index}/launch.json').read_text())
        check.equal(launch['memory_mib'], inputs['positive_mib'],
                    f'boot{index}: actual allocation matches the data-derived positive budget')
    setup = ev.stage(1)
    check.equal(setup.step('deploy').rc, 0, 'the root tar is deployed to A')
    check.equal(setup.step('setup-factory-sha256').out.split()[0], inputs['root_tar_sha256'],
                'the host uploads the tar the setup deployed')
    for index in (2, 3, 4):
        _pxe.network_boot(ev, check, index, f'boot{index}')
    keys = [ram_leg(ev, check, 2, True), ram_leg(ev, check, 3, False)]
    check(keys[0] and keys[1] and keys[0] != keys[1], 'each RAM boot makes its own SSH host key')
    launch = json.loads((Path(ev.root).parent / 'boot-4/launch.json').read_text())
    check.equal(launch['argv'][launch['argv'].index('-m') + 1], str(inputs['short_mib']),
                'the short machine has less RAM than the tar needs')
    short = ev.stage(4).step('short-boot')
    rc = re.search(r'(?m)^ZT_BOOT_RC=(\d+)$', short.out)
    check(rc is not None and rc[1] != '0', 'boot --tar refuses on the short machine')
    check.contains(short.err, SHORT, 'the refusal names the RAM it needs')
    check("Loading the root tar's kernel" not in short.err, 'nothing is loaded into kexec')
    check(re.search(r'(?m)^UPLOADS=\s*0$', short.out) is not None, 'the refused upload is removed')
    check('zboot RAM boot' not in ev.stage(4).step('short-console').out, 'no RAM system starts')
