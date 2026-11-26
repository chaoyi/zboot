"""GUIDED-DIRTY-PORTABLE-MENU: the one neutral Menu over dirty paired pools.

1. setup as GUIDED-RESTORE-EFI-NATIVE, but A's boot probe leaves the OS up.
2. The stick restores A; before exporting, its shell repairs A's ESP with
   `zboot esp PART --efi FILE`, FILE the UKI the stick boots
   (EFI/BOOT/BOOTX64.EFI).
3. A's ESP boots A; once the probe has reopened both pools writable the host
   power-cuts it (cut 1).
4. A's ESP again: its installed Menu (neutral, no hostid) adopts the hostid
   from the dirty pools' labels, admits both read-only, lists both roots and
   boots A a second time; cut 2.
5. The stick: its portable Menu adopts the hostid the same way, imports the
   pools read-only without force and keeps the countdown off on virtio.
"""
import json
import re

from host import guided
from host.case import Boot
from host.console import ConsoleError

ID = 'GUIDED-DIRTY-PORTABLE-MENU'
GROUP = 'efi'
SECONDS = 7200
DISKS = guided.DISKS
BOOTS = [Boot(1), Boot(2, efi=True), Boot(3, efi=True, extra={'from': 'A'}),
         Boot(4, efi=True, extra={'from': 'A'}), Boot(5, efi=True)]

STICK = '/mnt/zfs-e2e/g-stick'
EFI = f'{STICK}/EFI/BOOT/BOOTX64.EFI'
REVIEW, OUTCOME = '/mnt/zfs-e2e/g-esp-repair-review.json', '/mnt/zfs-e2e/g-esp-repair-outcome.json'
ESP = '/mnt/zfs-e2e/g-a-esp'
LOADERS = ('EFI/zboot/zboot.efi', 'EFI/BOOT/BOOTX64.EFI')
HOSTID_BODY = ('h=$(cat /proc/sys/kernel/spl/hostid); /bin/busybox printf \'spl=%08x\\n\' "0x${h#0x}"; '
               'echo "etc=$(/bin/busybox od -An -tx4 /etc/hostid | /bin/busybox tr -d \'[:space:]\')"; '
               'zpool get -H -o name,value readonly e2ea e2eb; '
               'test -s /run/zboot-hostid-adopted && echo adopted=yes')


def install(where):
    return f'/usr/bin/zboot esp /dev/vda1 --efi {EFI} --json {where}'


def shell_json(text):
    return json.loads(text[text.index('{'):text.rindex('}') + 1])


def repair(console):
    console.must('repair-media', 'set -e; test "$(cat /sys/block/vda/serial)" = ZFS-E2E-A; '
                 'test "$(cat /sys/block/vdd/serial)" = ZFS-E2E-C; '
                 f'mkdir -p {STICK}; mount -t vfat -o ro /dev/vdd1 {STICK}; '
                 f'sha256sum {EFI}')
    console.must('repair-pools-before', 'zpool get -H -o name,value readonly e2ea e2eb')
    console.must('repair-native-target', 'lsblk -bnr -o MAJ:MIN,SIZE,PARTUUID,UUID,FSTYPE,PARTTYPE,RO /dev/vda1')
    console.must('repair-preview', f'set -e; {install("--dry-run")} > {REVIEW}; test -s {REVIEW}; cat {REVIEW}')
    try:
        token = shell_json((console.out / f'{console.n:02d}-repair-preview.out').read_text())['token']
    except (ValueError, KeyError) as e:
        raise ConsoleError(f'ESP repair preview: {e!r}') from None
    if not re.fullmatch('[0-9a-f]{32}', str(token)):
        raise ConsoleError(f'ESP repair token {token!r}')
    console.must('repair-pools-after-preview', 'zpool get -H -o name,value readonly e2ea e2eb')
    console.must('repair-apply', f'set -e; {install("--confirm " + token)} > {OUTCOME}; test -s {OUTCOME}; cat {OUTCOME}')
    console.must('repair-pools-after-apply', 'zpool get -H -o name,value readonly e2ea e2eb')
    console.must('repair-esp-mount', f'set -e; mkdir -p {ESP}; mount -t vfat -o ro /dev/vda1 {ESP}')
    console.must('repair-esp', 'sha256sum ' + ' '.join(f'{ESP}/{path}' for path in LOADERS))
    console.must('repair-no-records', f'test ! -e {ESP}/EFI/zboot/operations')
    console.must('repair-esp-mountinfo', 'cat /proc/self/mountinfo')
    console.must('repair-media-close', f'umount {ESP} {STICK}')


def stage_2(console):
    guided.restore(console, repair=repair)


def stage_4(console):
    menu = console.ready('boot-a-ready')
    console.enter_shell()
    console.shell('internal-hostid', HOSTID_BODY)
    console.shell('labels-e2ea', guided.labels_body('e2ea', '/dev/vda2'))
    console.shell('labels-e2eb', guided.labels_body('e2eb', '/dev/vdb1'))
    console.leave_shell()
    guided.select_a(console, menu, 'boot-a')


def stage_5(console):
    console.ready('portable')
    console.enter_shell()
    console.shell('portable-hostid', HOSTID_BODY)
    console.leave_shell()


stage_3 = guided.boot_a


def hostid_facts(text):
    rows = guided.lines(text)
    return ({k: v for k, _, v in (r.partition('=') for r in rows) if k in ('spl', 'etc', 'adopted')},
            [r.split('\t') for r in rows if '\t' in r])


def verdict(ev, check):
    guided.check_setup(ev, check)
    guided.check_restore(ev, 2, check)
    guided.check_restored(ev, 2, check)

    # ESP repair from the UKI the stick boots.
    s = ev.stage(2)
    source_identity = guided.uki(ev, check)
    efi = source_identity['sha256']
    media = dict(line.split()[::-1] for line in guided.lines(s.step('repair-media').out) if len(line.split()) == 2)
    check.equal(media.get(EFI), efi, "the stick boots the session's neutral UKI")
    preview = s.step('repair-preview')
    check.equal(preview.rc, 0, 'ESP batch preview wrote its reviewed plan')
    review = shell_json(preview.out)
    result = review['result']
    check(review.get('mode') == 'preview' and re.fullmatch('[0-9a-f]{32}', str(review.get('token'))) is not None,
          f"preview mode and 32-hex token: {review.get('mode')!r} {review.get('token')!r}")
    expected_source = {'efi': EFI, **source_identity}
    check.equal(result.get('schema_version'), 1, 'batch preview schema')
    check.equal(result.get('efi'), expected_source, 'preview binds the exact standalone UKI file')
    check.equal(result.get('automatic'), False, 'repair names its explicit partition')
    check.equal(result.get('imported_storage'), [], 'explicit repair has no automatic disk-selection dependency')
    targets = result.get('targets', [])
    if not check.equal(len(targets), 1, 'repair previews exactly one ESP'):
        return
    selected = targets[0]
    child = selected['review']
    check.equal(child.get('schema_version'), 4, 'batch target uses the one ESP review schema')
    check.equal(child.get('artifacts'), expected_source, 'target source is the exact selected standalone EFI')
    check.equal(selected.get('foreign_replacements'), [], 'the freshly restored owned loaders need no foreign replacement')
    check.equal(set(child.get('previous', {})), set(LOADERS), 'the repair preserves both current loader paths')
    findings = {finding['path']: finding for finding in selected.get('findings', [])}
    for path in LOADERS:
        check.equal(findings.get(path, {}).get('owned'), True, f'{path} is classified from its native PE identity')
        check.equal(child['previous'].get(path), {'sha256': efi, 'bytes': expected_source['bytes']},
                    f'{path} preimage is the exact restored Menu')
    target = child['target']
    check.equal((target['disk']['path'], target['disk']['serial'], target['partition']['path'], target['number']),
                ('/dev/vda', 'ZFS-E2E-A', '/dev/vda1', 1), 'preview targets A partition 1')
    native = s.step('repair-native-target').out.split()
    expected_native = [target['partition']['device_number'], str(target['partition']['bytes']),
                       target['partition']['partition_uuid'], target['partition']['filesystem_uuid'],
                       'vfat', target['partition_type'], '0']
    # UUID spelling is case-insensitive across blkid and udev-backed lsblk.
    check.equal([field.lower() for field in native], [field.lower() for field in expected_native],
                'the preview binds independent native partition identity and writable block state')
    check('installed_root' not in child, 'neutral repair carries standalone file identity')
    apply = s.step('repair-apply')
    check.equal(apply.rc, 0, 'ESP refresh applies the reviewed batch')
    applied = shell_json(apply.out)
    outcome = applied['result']
    check.equal((applied.get('mode'), applied.get('token'), outcome.get('complete'), outcome.get('efi_sha256')),
                ('applied', review.get('token'), True, efi), 'applied mode, token, complete and exact EFI')
    check.equal(outcome.get('partitions'), [target['partition']['path']], 'applied batch names only the reviewed ESP')
    check('operation' not in applied and 'operation_id' not in outcome, 'ESP batch outcome carries its actual publication fields')
    check.equal(s.step('repair-no-records').rc, 0, 'repair writes no ESP operation record')
    esp = dict(line.split()[::-1] for line in guided.lines(s.step('repair-esp').out) if len(line.split()) == 2)
    for path in LOADERS:
        check.equal(esp.get(f'{ESP}/{path}'), efi, f"A's ESP {path} is the exact selected EFI")
    pool_rows = [['e2ea', 'on'], ['e2eb', 'on']]
    for name in ['repair-pools-before', 'repair-pools-after-preview', 'repair-pools-after-apply']:
        check.equal([row.split('\t') for row in guided.lines(s.step(name).out)], pool_rows,
                    f'{name} preserves read-only pool imports')
    mounts = []
    for line in s.step('repair-esp-mountinfo').out.splitlines():
        left, right = line.split(' - ', 1)
        fields, filesystem = left.split(), right.split()
        if fields[4] == ESP:
            mounts.append((fields, filesystem))
    if check.equal(len(mounts), 1, 'the independent loader proof has one ESP mount'):
        fields, filesystem = mounts[0]
        check.equal(fields[3], '/', 'the independent proof reads the whole ESP')
        check.equal(filesystem[:2], ['vfat', '/dev/vda1'], 'the native proof reads the selected FAT partition')
        check('ro' in fields[5].split(',') and 'rw' not in fields[5].split(','), 'loader verification uses a read-only mount')
    check.equal(s.step('repair-media-close').rc, 0, 'both independent media views close')

    # First installed boot, then cut 1 with both pools writable.
    guided.check_boot_a(ev, 3, check, clean=False)
    check.equal(ev.boots[2].get('killed'), -9, 'cut 1: the running installed OS is SIGKILLed')

    # A's installed Menu over the dirty pools, then the second installed boot and cut 2.
    s = ev.stage(4)
    menu = s.step('boot-a-ready').out
    for root in (guided.ROOT_A, guided.ROOT_B):
        check.equal(len(guided.numbered(menu, root)), 1, f'A Menu lists dirty {root} once in its final listing')
    check.contains(menu, f'Hostid {guided.HOSTID} adopted from the labels of its active pools', 'A Menu adopts the hostid')
    ids, ro = hostid_facts(s.step('internal-hostid').out)
    check.equal((ids.get('spl'), ids.get('etc'), ids.get('adopted')), (guided.HOSTID, guided.HOSTID, 'yes'),
                'A Menu SPL hostid, /etc/hostid and adoption marker')
    check.equal(ro, [['e2ea', 'on'], ['e2eb', 'on']], 'A Menu imported e2ea and e2eb read-only')
    for pool in ('e2ea', 'e2eb'):
        guided.check_labels(s.step(f'labels-{pool}').out, pool, '0', check, 'after cut 1 (dirty)')
    guided.check_boot_a(ev, 4, check, clean=False)
    check.equal(ev.boots[3].get('killed'), -9, 'cut 2: the second installed OS is SIGKILLed')

    # The portable Menu on the stick.
    guided.check_stick(ev, 5, check)
    s = ev.stage(5)
    menu = s.step('portable').out
    for root in (guided.ROOT_A, guided.ROOT_B):
        check.equal(len(guided.numbered(menu, root)), 1, f'portable Menu lists dirty {root} once in its final listing')
    check.contains(menu, f'Hostid {guided.HOSTID} adopted from the labels of its active pools', 'portable Menu adopts the hostid')
    check.contains(menu, 'Automatic boot is off:', 'portable Menu countdown is off')
    ids, ro = hostid_facts(s.step('portable-hostid').out)
    check.equal((ids.get('spl'), ids.get('etc'), ids.get('adopted')), (guided.HOSTID, guided.HOSTID, 'yes'),
                'portable Menu SPL hostid, /etc/hostid and adoption marker')
    check.equal(ro, [['e2ea', 'on'], ['e2eb', 'on']], 'portable Menu imported e2ea and e2eb read-only')
    check.equal(ev.boots[4].get('killed'), -9, 'the portable Menu VM is SIGKILLed and reaped')
