"""Portable images on different machines, with native labels and real login.
The two constructor hostid routes and every image are private to this case.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from cases.efi_connect import command
from host.case import Boot, Evidence
from host.console import ConsoleError
from host.vm import ImageInput

ID = 'RESCUE-STICK'
GROUP = 'deploy'
SECONDS = 5400
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1, udev=True, extra={'setup': 'neutral'}),
         Boot(2, efi=True, network=True, extra={'case_images': 'parameter'}),
         Boot(3, efi=True, network=True, fresh_disks=True, extra={'case_images': 'parameter'}),
         Boot(4, efi=True, network=True, fresh_disks=True, extra={'case_images': 'file'}),
         Boot(5, efi=True, fresh_disks=True, extra={'case_images': 'copies'})]
ROOT = 'stick/ROOT/rescue'
PROMPT = 'rescue-root# '
PACKAGES = {'openssh-server', 'systemd-resolved', 'ca-certificates', 'curl', 'rsync',
            'less', 'vim-tiny', 'pciutils', 'usbutils', 'smartmontools', 'cryptsetup'}


def prepare(run_dir):
    result = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                             '-f', str(run_dir / 'login')], capture_output=True, timeout=30)
    run_dir.joinpath('keygen.out').write_bytes(result.stdout)
    run_dir.joinpath('keygen.err').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError('rescue fixture key generation failed')
    public = run_dir / 'public'
    public.mkdir(mode=0o700)
    public.joinpath('authorized_keys').write_bytes(run_dir.joinpath('login.pub').read_bytes())
    askpass = run_dir / 'askpass'
    askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$ZT_RESCUE_PASSWORD"\n')
    askpass.chmod(0o700)
    run_dir.joinpath('rescue-inputs.json').write_text(json.dumps({
        'public_key_sha256': hashlib.sha256(public.joinpath('authorized_keys').read_bytes()).hexdigest(),
        'qemu_boots': len(BOOTS), 'factory_recipe_packages': sorted(PACKAGES),
    }, indent=2) + '\n')


def shares(run_dir, _boot):
    return [('zt-rescue-public', run_dir / 'public')]


def images(run_dir, boot):
    kind = boot.extra.get('case_images')
    if not kind:
        return []
    selected = 'parameter' if kind == 'copies' else kind
    step = Evidence(run_dir / 'out').stage(1).step(f'{selected}-image-sha256')
    facts = step.out.split()
    if step.rc or len(facts) != 2 or not re.fullmatch('[0-9a-f]{64}', facts[0]):
        raise RuntimeError('guest did not seal its portable image with a full SHA256')
    relative = f'out/1/portable-{selected}.raw'
    size = int(Evidence(run_dir / 'out').stage(1).step(f'{selected}-image-bytes').out)
    attached = [ImageInput(relative, facts[0], size, 'RESCUE', True)]
    if kind == 'copies':
        # The runner materializes two independent copies, never hard links.
        attached.append(ImageInput(relative, facts[0], size, 'RESCUE-COPY'))
    return attached


def ssh_args(console, known, password=False):
    args = ['/usr/bin/ssh', '-F', '/dev/null', '-p', console.ssh_port,
            '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={known}',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=10',
            '-o', 'ConnectionAttempts=1', '-o', 'LogLevel=ERROR', '-o', 'NumberOfPasswordPrompts=1']
    if password:
        args += ['-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password',
                 '-o', 'KbdInteractiveAuthentication=no', '-o', 'BatchMode=no']
    else:
        args += ['-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-i', console.case_dir / 'login']
    return args + ['root@127.0.0.1']


def running_rescue(console):
    console.menu('boot-rescue', f'boot {ROOT} -v', until=('ZBOOT_HANDOFF_LOAD',))
    start = console.pos
    console.expect('ZT_RESCUE_LOGIN tty=/dev/ttyS0 uid=0', 600)
    console.expect(PROMPT, 60)
    console.must('initial-offline', r"""set -e
for device in /sys/class/net/*; do
  test -e "$device/device" || continue
  printf 'IFACE=%s FLAGS=%s\n' "${device##*/}" "$(cat "$device/flags")"
  test $(( $(cat "$device/flags") & 1 )) -eq 0
done
cat /etc/systemd/network/89-zboot-rescue.network.d/zt-fixture-manual.conf
sha256sum /etc/systemd/network/89-zboot-rescue.network.d/zt-fixture-manual.conf""")
    console.must('resume-default-network', r"""set -e
rm /etc/systemd/network/89-zboot-rescue.network.d/zt-fixture-manual.conf
networkctl reload
for device in /sys/class/net/*; do
  test -e "$device/device" || continue
  networkctl reconfigure "${device##*/}"
done""")
    if 'Rescue IPv4: ' not in console._text(start, console.pos):
        try:
            console.expect('Rescue IPv4: ', 120)
        except ConsoleError:  # say whether DHCP or the announcer failed
            console.shell('banner-diagnosis', 'hostname -I; networkctl --no-pager; '
                          'ps -eo pid,pgid,sid,tty,stat,args')
            raise
    console._record('serial-banner', '', console._text(start, console.pos), 0)
    console.must('serial-autologin', 'id -u; tty; cat /run/zt-login-ttyS0')
    console.must('packages', "dpkg-query -W -f '${binary:Package}\\t${Version}\\n'")
    console.must('binary', 'zboot --version; sha256sum /usr/bin/zboot')
    # The factory installs zboot as a package; record what dpkg reports.
    console.shell('zboot-package', 'dpkg-query -W zboot')
    console.must('network', 'networkctl status --no-pager; resolvectl status --no-pager; cat /etc/resolv.conf; readlink /etc/resolv.conf')
    # restrict=on: slirp's DHCP offers no router or DNS server, so the lookup
    # is a name resolved answers itself, through resolv.conf and its stub.
    console.must('dns', 'timeout 30 getent ahostsv4 _localdnsstub')
    # Real SSH host identity is read from the installed root, then compared
    # independently to the host's loopback-forwarded key exchange.
    console.must('host-fingerprint', 'ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ed25519_key.pub')
    scan = command(console, 'host-keyscan', ['/usr/bin/ssh-keyscan', '-T', '10', '-t', 'ed25519',
                                           '-p', console.ssh_port, '127.0.0.1'])
    if scan.returncode or not scan.stdout.strip():
        raise ConsoleError('the installed rescue SSH listener is absent')
    known = console.case_dir / f'known-{console.out.name}'
    known.write_text(scan.stdout)
    checked = command(console, 'host-keyscan-fingerprint', ['/usr/bin/ssh-keygen', '-l', '-E', 'sha256', '-f', known])
    native = console.out / next(p.name for p in console.out.glob('*-host-fingerprint.out'))
    if checked.returncode or checked.stdout.split()[1:2] != native.read_text().split()[1:2]:
        raise ConsoleError('SSH host key differs from the native console fingerprint')
    script = r'''set -e
printf 'KEY_LOGIN_OK\n'
test ! -e /etc/hostid
printf 'ROOT_PASSWORD='; awk -F: '$1 == "root" {print $2}' /etc/shadow
printf 'ROOT_MOUNT='; findmnt -rn -o SOURCE,FSTYPE,OPTIONS --target /
printf 'LOWER_MOUNT='; findmnt -rn -o SOURCE,FSTYPE,OPTIONS --target /run/zboot-portable/lower
printf 'RAM_MOUNT='; findmnt -rn -o SOURCE,FSTYPE,OPTIONS --target /run/zboot-portable/ram
printf 'POOL_READONLY='; zpool get -H -o value readonly stick
printf 'POOL_BOOTFS='; zpool get -H -o value bootfs stick
printf 'CMDLINE='; cat /proc/cmdline
printf 'RAM_TOKEN\n' > /zt-ram-token
cat /zt-ram-token
test ! -e /run/zboot-portable/lower/zt-ram-token
for tty in tty1 ttyS0; do
  n=0; while [ ! -f "/run/zt-login-$tty" ] && [ "$n" -lt 10 ]; do sleep 1; n=$((n+1)); done
  printf 'AUTOLOGIN='; cat "/run/zt-login-$tty"
done
printf 'PHYSICAL_SCREEN='; dd if=/dev/vcs1 bs=4096 count=1 2>/dev/null
printf '\nLABELS_BEGIN\n'
for disk in /sys/block/vd*; do
  [ "$(cat "$disk/serial" 2>/dev/null)" = ZFS-E2E-RESCUE ] || continue
  for part in /dev/${disk##*/}[0-9]*; do
    [ "$(blkid -p -s TYPE -o value "$part" 2>/dev/null || :)" = zfs_member ] || continue
    zdb -l "$part"
  done
done
printf 'LABELS_END\n'
printf 'INTERNAL_IMPORT='; zpool import -N -o readonly=on internal 2>&1 | tr '\n' ' '; echo
printf 'INTERNAL_POOL='; zpool list -H -o name,readonly internal 2>/dev/null || :
journalctl --sync
journalctl -u ssh.service --no-pager -o cat'''
    logged = command(console, 'key-login', ssh_args(console, known) + [script], timeout=90)
    if logged.returncode:
        raise ConsoleError('the rescue root did not accept its overlay key or failed a native invariant')
    environment = dict(os.environ, SSH_ASKPASS=str(console.case_dir / 'askpass'),
                       SSH_ASKPASS_REQUIRE='force', DISPLAY='zt-rescue:0', ZT_RESCUE_PASSWORD='not-a-password')
    failed = command(console, 'locked-password', ssh_args(console, known, True) + ['true'], env=environment)
    if failed.returncode == 0:
        raise ConsoleError('the locked rescue root accepted a password')


def stage_2(console):
    console.ready()
    console.enter_shell()
    console.must('internal-initial', 'zpool get -Hp -o value guid,readonly internal')
    console.must('export-internal', 'zpool export internal')
    console.leave_shell()
    # One menu runs per UKI; rescan is how it imports the pool again. The
    # import's exact argv (by GUID, never forced) is a unit test in
    # menu/pool_access.rs.
    console.menu('internal-reimport', 'rescan')
    console.enter_shell()
    # rescan starts the imports in the background; wait for this one.
    console.must('internal-reimported', 'i=0; until zpool get -Hp -o value guid,readonly internal '
                 '2> /dev/null; do i=$((i + 1)); [ $i -lt 120 ] || exit 1; sleep 1; done', 180)
    console.leave_shell()
    running_rescue(console)


def stage_3(console):
    console.ready()
    running_rescue(console)


def stage_4(console):
    console.ready()
    running_rescue(console)


def stage_5(console):
    console.ready()
    console.enter_shell()
    console.must('duplicate-devices', 'lsblk -nr -o PATH,MAJ:MIN,SERIAL,PARTUUID')
    console.must('duplicate-imported', 'zpool list -H -o name')
    console.leave_shell()


ESP_TYPE = bytes.fromhex('28732ac11ff8d211ba4b00a0c93ec93b')  # C12A7328-F81F-11D2-BA4B-00A0C93EC93B


def pool_sha256(path):
    """SHA-256 of the image's one GPT partition that is not the ESP."""
    with open(path, 'rb') as f:
        f.seek(512)
        header = f.read(92)
        if header[:8] != b'EFI PART':
            raise ValueError(f'{path}: no GPT')
        start, count, size = struct.unpack_from('<QII', header, 72)
        f.seek(start * 512)
        table = f.read(count * size)
        ranges = []
        for offset in range(0, len(table), size):
            entry = table[offset:offset + size]
            if entry[:16] not in (bytes(16), ESP_TYPE):
                ranges.append(struct.unpack_from('<QQ', entry, 32))
        if len(ranges) != 1:
            raise ValueError(f'{path}: {len(ranges)} non-ESP partitions')
        first, last = ranges[0]
        f.seek(first * 512)
        h, left = hashlib.sha256(), (last - first + 1) * 512
        while left:
            block = f.read(min(left, 8 << 20))
            if not block:
                raise ValueError(f'{path}: short pool partition')
            h.update(block)
            left -= len(block)
        return h.hexdigest()


def labels(check, text, message):
    # zdb -l prints identical labels once, then lists them: `labels = 0 1 2 3`.
    seen = {int(n) for n in re.findall(r'(?m)^LABEL (\d)\s*$', text)}
    for listed in re.findall(r'(?m)^\s*labels = ([\d ]+?)\s*$', text):
        seen |= {int(n) for n in listed.split()}
    for index in range(4):
        check(index in seen, f'{message}: native label{index}')
    check(re.search(r'(?m)^\s*hostid\s*:', text) is None, f'{message}: no recorded hostid')


def verdict(ev, check):
    setup = ev.stage(1)
    hashes = {}
    for kind in ('parameter', 'file'):
        applied = setup.step(f'{kind}-apply')
        check.equal(applied.rc, 0, f'{kind}: actual portable image construction')
        result = applied.json['result']
        check.equal((result.get('loop_detached'), result['outcome'].get('exported'), result['outcome'].get('complete')),
                    (True, True, True), f'{kind}: loop and pool cleanup completed')
        review = result['review']
        check.equal(review['hostid'], '00000000', f'{kind}: reviewed pool identity is hostless')
        check.equal(review['artifacts']['sha256'], setup.step('loader-sha256').out.split()[0],
                    f'{kind}: default shipped-loader lookup selects this fresh family EFI')
        check.equal(review.get('base_overlay'), None, f'{kind}: no implicit base overlay')
        check.equal([item['source'] for item in review['overlays']][::2],
                    ['builtin:rescue', 'builtin-internal:portable'], f'{kind}: user overlays then mandatory portable')
        check.equal(setup.step(f'{kind}-hostid-before').out, setup.step(f'{kind}-hostid-after').out,
                    f'{kind}: caller identity restored')
        check.equal(setup.step(f'{kind}-loop-detached').out.strip(), '', f'{kind}: independent native loop absence')
        labels(check, setup.step(f'{kind}-labels').out, f'{kind} created image')
        check.equal(setup.step(f'{kind}-no-hostid').rc, 0, f'{kind}: root carries no hostid')
        check.equal(setup.step(f'{kind}-bootfs').out.strip(), '-', f'{kind}: portable has no native default')
        partitions = [line.split() for line in setup.step(f'{kind}-partitions').out.splitlines()
                      if len(line.split()) >= 2 and line.split()[1] == 'part']
        check.equal(len(partitions), 2, f'{kind}: native image has only ESP and pool, no swap')
        check(all('0657fd6d-a4ab-43c4-84e5-0933c84b4f4f' not in row for row in partitions),
              f'{kind}: native GPT contains no Linux swap partition')
        hashes[kind] = setup.step(f'{kind}-image-sha256').out.split()[0]
    check.equal(setup.step('parameter-hostid-file').out.strip(), 'absent', 'first route has no /etc/hostid')
    check.equal(setup.step('file-hostid-file').out.strip(), '68245713', 'second route tests real /etc/hostid fallback bytes')
    check.equal(setup.step('file-hostid-before').out.splitlines()[0], '0', 'second route sets kernel parameter0 before fallback')
    fingerprints = []
    for stage in (2, 3, 4):
        observed = ev.stage(stage)
        check.contains(observed.step('ready').out, ROOT, f'stage{stage}: markerless portable BE is listed')
        check('Auto-booting ' not in observed.step('ready').out, f'stage{stage}: no portable countdown')
        facts = observed.step('key-login').out
        check.contains(facts, 'KEY_LOGIN_OK', f'stage{stage}: actual overlay-key SSH authentication')
        binary = re.search(r'(?m)^([0-9a-f]{64})  /usr/bin/zboot$', observed.step('binary').out)
        check(binary is not None and binary[1] == setup.step('source-binary-sha256').out.split()[0],
              f'stage{stage}: installed bytes match the fresh family userspace, not an old tar')
        check(observed.step('zboot-package').rc in (0, 1), f'stage{stage}: actual packaged/unpackaged status is retained')
        check.equal(observed.step('initial-offline').rc, 0, f'stage{stage}: real root console is usable with every link down')
        check.equal(observed.step('resume-default-network').rc, 0, f'stage{stage}: default builtin DHCP resumes after one RAM-only fixture removal')
        banner = observed.step('serial-banner').out
        check(banner.index('ZT_RESCUE_LOGIN') < banner.index('Rescue IPv4:'), f'stage{stage}: serial address banner follows late DHCP without blocking login')
        check.contains(facts, 'ROOT_PASSWORD=*', f'stage{stage}: root remains locked')
        check.contains(facts, 'POOL_READONLY=on', f'stage{stage}: pool is read-only')
        check.contains(facts, 'POOL_BOOTFS=-', f'stage{stage}: no boot default')
        check(re.search(r'ROOT_MOUNT=.*overlay.*\brw\b', facts) is not None, f'stage{stage}: writable overlay root')
        check(re.search(r'LOWER_MOUNT=stick/ROOT/rescue zfs .*\bro\b', facts) is not None, f'stage{stage}: lower root stays read-only')
        check(re.search(r'RAM_MOUNT=.*tmpfs', facts) is not None, f'stage{stage}: RAM upper filesystem')
        for tty in ('tty1', 'ttyS0'):
            check.contains(facts, f'AUTOLOGIN=tty=/dev/{tty} uid=0', f'stage{stage}: actual {tty} root login')
        check.contains(facts, 'Rescue IPv4:', f'stage{stage}: physical screen address banner')
        check(observed.step('locked-password').rc != 0, f'stage{stage}: password authentication refused')
        check.contains(observed.step('locked-password').err, 'Permission denied', f'stage{stage}: refusal is authentication, not transport failure')
        check.equal(observed.step('dns').rc, 0, f'stage{stage}: application lookup through resolved')
        check(re.search(r'(?m)^127\.0\.0\.53\s', observed.step('dns').out) is not None, f'stage{stage}: the stub answers')
        packages = {line.split('\t', 1)[0].split(':', 1)[0] for line in observed.step('packages').out.splitlines()}
        check(PACKAGES <= packages, f'stage{stage}: actual RECOVERY rescue-recipe packages installed')
        check('Accepted publickey for root' in facts, f'stage{stage}: real server authentication journal')
        labels(check, facts.split('LABELS_BEGIN\n', 1)[1].split('LABELS_END', 1)[0], f'stage{stage} booted stick')
        fingerprints.append(observed.step('host-keyscan-fingerprint').out.split()[1])
        if stage == 2:
            check.contains(facts, 'INTERNAL_POOL=internal\ton', 'other-host internal pool imports read-only without force')
        else:
            check('INTERNAL_POOL=internal' not in facts, f'stage{stage}: genuinely fresh machine has no internal pool')
            cmdline = facts.split('CMDLINE=', 1)[1].splitlines()[0].split()
            check(not any(word.startswith('spl.spl_hostid=') for word in cmdline), f'stage{stage}: hostless handoff invents no adopted hostid')
    check(len(set(fingerprints)) == 3, 'factory missing-key generator creates new ephemeral host keys on each RAM boot')
    # The last two words: rescan's background import may print first.
    check.equal(ev.stage(2).step('internal-reimported').out.split()[-2:],
                [setup.step('internal-guid').out.strip(), 'on'],
                'rescan imports the exported internal pool again, read-only')
    duplicated = ev.stage(5)
    check.contains(duplicated.step('ready').out, 'copied vdev identity', 'two independent copied images are visibly refused')
    check.equal(duplicated.step('duplicate-imported').out.strip(), '', 'neither copied pool was imported')
    rows = [line.split() for line in duplicated.step('duplicate-devices').out.splitlines()]
    devices = {row[1] for row in rows if len(row) >= 3 and row[2] in ('ZFS-E2E-RESCUE', 'ZFS-E2E-RESCUE-COPY')}
    check.equal(len(devices), 2, 'copied images are separate native block devices, not aliases')
    # The UKI's stub refreshes loader/random-seed on the ESP it starts from
    # (docs/DESIGN.md, deploy --portable); the pool partition must not change.
    case = Path(ev.root).parent
    sealed = {}
    for index in range(2, len(ev.boots) + 1):
        launch = json.loads((case / f'boot-{index}/launch.json').read_text())
        for fact in launch['case_images']:
            source = fact['source_relative']
            if source not in sealed:
                sealed[source] = pool_sha256(case / source)
            check.equal(pool_sha256(fact['copy']), sealed[source],
                        f'boot{index}: no boot wrote a byte of the pool partition, labels included')
