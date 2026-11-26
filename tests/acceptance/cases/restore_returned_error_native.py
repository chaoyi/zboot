"""Returned Run errors reach real CLI cleanup at two native restore boundaries."""
import hashlib
import json
from pathlib import Path
import re

from host.case import Boot
from host import restore as r
from host.identity import unchanged

ID = 'RESTORE-RETURNED-ERROR-NATIVE'
GROUP = 'restore'
SECONDS = 7200
DISKS = {'A': 4, 'B': 4, 'D': 8}
# Each fixture boot runs this build's own kernel, initramfs and tools.
BOOTS = [Boot(1, udev=True, append='zboot.recovery=1'),
         Boot(2, udev=True, append='zboot.recovery=1')]


def active_receipt(check, observation, op, state, what):
    staging, named = state['staging'], state['receipt']
    check.equal(named['endpoint']['name'], staging, f'{what}: the record names its receipt on staging')
    properties = observation.properties(staging)
    prefix = f'zboot:attachment:{op}:receipt:'
    names = sorted(key for key in properties if key.startswith(prefix))
    check.equal(names, [f'{prefix}{index:04x}' for index in range(named['chunks'])],
                f'{what}: staging holds exactly the receipt chunks its record names')
    for name in names:
        check.equal(properties[name]['source'], 'local', f'{what}: receipt chunk {name} remains local')
    check.equal(hashlib.sha256(bytes.fromhex(''.join(properties[name]['value'] for name in names))).hexdigest(),
                named['sha256'], f'{what}: retained receipt bytes match the digest their record names')
    stray = sorted(f'{name} {key}' for name in observation.datasets
                   for key, value in observation.properties(name).items()
                   if key.startswith(('zboot:journal:', 'zboot:attachment:')) and value['source'] == 'local'
                   and not (name == staging and key.startswith(prefix)))
    check.equal(stray, [], f'{what}: no journal and no other attachment is set on any dataset')


def fresh_input_facts(stage, check, boot):
    daemon = stage.step('udev-daemon')
    check.equal(daemon.rc, 0, f'boot {boot}: native udev daemon process exists')
    check(re.search(r'^pid=\d+$', daemon.out, re.M) is not None,
          f'boot {boot}: udev process PID is recorded')
    check.contains(daemon.out, 'systemd-udevd', f'boot {boot}: process is the actual udev daemon')
    check.equal(stage.step('udev-trigger-after-setup').rc, 0, f'boot {boot}: fixture block changes retrigger udev')
    check.equal(stage.step('udev-settle-after-setup').rc, 0, f'boot {boot}: fixture udev queue settled')
    for label, pool in (('A', 'e2ea'), ('B', 'e2eb')):
        signature = stage.step(f'signature-{label}')
        check.equal(signature.rc, 0, f'boot {boot}: {label} filesystem signatures are readable')
        signatures = signature.json['signatures']
        check(bool(signatures) and {row['type'] for row in signatures} == {'zfs_member'},
              f'boot {boot}: new {label}1 contains only native ZFS signatures, no stale FAT')
        info = stage.step(f'udev-info-{label}')
        check.equal(info.rc, 0, f'boot {boot}: {label}1 has udev properties')
        properties = dict(line.split('=', 1) for line in info.out.splitlines() if '=' in line)
        check.equal(properties.get('ID_FS_TYPE'), 'zfs_member', f'boot {boot}: udev sees {label}1 as ZFS')
        guid = stage.step(f'readonly-guid-{pool}').out.strip()
        imported = stage.step(f'readonly-import-{pool}')
        check.equal(imported.argv, ['zpool', 'import', '-N', '-o', 'readonly=on', '-o', 'cachefile=none', guid],
                    f'boot {boot}: {pool} is available through the product default GUID scan')
        check.equal(imported.rc, 0, f'boot {boot}: normal GUID discovery imports {pool}')
    if boot != 2:
        return
    check.equal(stage.step('reset-imported').out, '', 'boot 2 clears signatures with no pool imported')
    for label in ('A', 'B', 'D'):
        selected = stage.step(f'reset-selected-{label}')
        check.equal(selected.rc, 0, f'boot 2: disk {label} serial selection succeeds')
        serial, device = selected.out.strip().split('\t')
        check.equal(serial, f'ZFS-E2E-{label}', f'boot 2: reset is restricted to disk {label}')
        layout = stage.step(f'reset-layout-{label}').json['blockdevices']
        check.equal(len(layout), 1, f'boot 2: exactly one selected disk {label}')
        check.equal(layout[0]['path'], device, f'boot 2: disk {label} layout belongs to selected node')
        check.equal(layout[0]['serial'].strip(), serial, f'boot 2: disk {label} native layout confirms its serial')
        children = layout[0].get('children', [])
        expected = [row['path'] for row in children if row['type'] == 'part']
        check(bool(expected) and len(expected) == len(children), f'boot 2: disk {label} has only direct old partitions')
        partitions = stage.step(f'reset-partitions-{label}').out.splitlines()
        check.equal(sorted(partitions), sorted(expected), f'boot 2: every and only disk {label} partition is cleared')
        for partition in partitions:
            suffix = f'{label}-{Path(partition).name}'
            before = stage.step(f'reset-signatures-before-{suffix}')
            wiped = stage.step(f'reset-clear-{suffix}')
            after = stage.step(f'reset-signatures-after-{suffix}')
            check.equal(before.rc, 0, f'boot 2: retain old signatures on {partition}')
            check(isinstance(before.json['signatures'], list), f'boot 2: bounded old signature inventory for {partition}')
            check.equal(wiped.argv, ['wipefs', '--all', '--force', partition], f'boot 2: wipe only selected old partition {partition}')
            check.equal(wiped.rc, 0, f'boot 2: clear old signatures on {partition}')
            check.equal(after.rc, 0, f'boot 2: read cleared signatures on {partition}')
            check.equal(after.json['signatures'], [], f'boot 2: no old signature remains on {partition}')
        check.equal(stage.step(f'reset-{label}').argv, ['sgdisk', '--zap-all', device],
                    f'boot 2: GPT reset uses the same serial-selected disk {label}')
        check.equal(stage.step(f'reset-probe-{label}').rc, 0, f'boot 2: kernel rereads disk {label}')
        check.equal(stage.step(f'reset-settle-{label}').rc, 0, f'boot 2: reset disk {label} udev queue settled')


def verdict(ev, check):
    operations = []
    source_guids = []
    for boot, fault, mode, phase in ((1, 'returned-import', 'error-after', 7),
                                     (2, 'returned-checkpoint', 'error-before', 8)):
        s = ev.stage(boot)
        what = f'boot {boot} {mode}'
        launch = json.loads((Path(ev.root).parent / f'boot-{boot}/launch.json').read_text())
        cmdline = launch['argv'][launch['argv'].index('-append') + 1].split()
        check.equal([arg for arg in cmdline if arg.startswith('zboot.recovery=')],
                    ['zboot.recovery=1'], f'{what}: real CLI uses the UKI access context')
        check.equal([arg for arg in cmdline if arg.startswith('zt.udev=')], ['zt.udev=1'],
                    f'{what}: direct case uses the product UKI udev startup')
        fresh_input_facts(s, check, boot)
        r.base(s, check)
        r.placed(s, check, 'source')
        token = r.previewed(s.step('restore-preview'), check, f'{what}: restore preview')
        r.loader(s, check)
        before = s.observe('before')
        check.equal(sorted(before.pools), ['e2ea', 'e2eb', 'e2ec'], f'{what}: fresh A/B/C fixture')
        for name in ('e2ea', 'e2eb', 'e2ec'):
            check.equal(before.pools[name]['readonly'], 'on', f'{what}: {name} starts read-only')
        source_guids.append(before.pools['e2eb']['guid'])

        result = s.step('restore-apply')
        check.equal(result.rc, 4, f'{what}: returned error is partial exit 4')
        envelope = result.json
        check.equal(envelope.get('mode'), 'partial', f'{what}: shared finalizer emits partial')
        check(token in result.argv and '--confirm' in result.argv,
              f'{what}: execution consumed the reviewed restore token')
        record = r.record(s.step('stopped-record'))
        op, state = record['id'], record['state']
        operations.append(op)
        check(re.fullmatch('[0-9a-f]{16}', op), f'{what}: active restore has its original ID')
        check.equal(envelope.get('operation'), op, f'{what}: partial output names the active intent')
        check.equal(record['kind'], 'restore', f'{what}: retained intent kind')
        check.equal(record['step'], phase, f'{what}: returned Run error retains its prior checkpoint')
        check.equal(state['old_pool']['guid'], before.pools['e2ea']['guid'], f'{what}: old A GUID is bound')
        check.contains(result.err, f'acceptance injected {mode}: {fault}', f'{what}: real injected error returned')
        check('cleanup failed' not in result.err.lower(), f'{what}: CLI target and pool cleanup succeeded')

        argv = s.cut(fault)
        metadata = s.path / f'cut-{fault}.argv'
        check.equal(Path(str(metadata) + '.mode').read_text().strip(), mode, f'{what}: fault mode')
        check.equal(Path(str(metadata) + '.test-id').read_text().strip(), fault, f'{what}: fault identity')
        check.equal(Path(str(metadata) + '.injected-rc').read_text().strip(), '97', f'{what}: injected status')
        real_rc = Path(str(metadata) + '.real-rc').read_text().strip()
        if boot == 1:
            check.equal(s.step('import-shim-path').out.strip(), '/run/returned-error-bin/zpool',
                        'only boot 1 uses the private zpool boundary wrapper')
            check.equal(argv[:4], ['import', '-N', '-o', 'cachefile=none'], 'fault selects Native::import')
            check.equal(len(argv), 5, 'Native::import exact five-argument boundary')
            check.equal(real_rc, '0', 'real Native import succeeded before its reply became an error')
            replacement = argv[4]
            check(replacement.isdecimal() and int(replacement) > 0, 'real import used a native pool GUID')
            check.equal(state.get('new_pool'), None, 'failed import reply precedes new_pool checkpoint')
        else:
            check.equal(real_rc, 'not-run', 'step-9 checkpoint setter was not dispatched')
            check.equal(len(argv), 3, 'checkpoint fault has exact zfs set argv')
            check.equal([argv[0], argv[-1]], ['set', 'e2eb'], 'checkpoint fault is on B intent')
            check(argv[1].startswith('zboot:operation='), 'checkpoint fault writes the restore intent')
            attempted = json.loads(argv[1].split('=', 1)[1])
            check.equal((attempted['id'], attempted['kind'], attempted['step']), (op, 'restore', 9),
                        'returned fault selects the existing step-9 matcher')
            replacement = state['new_pool']
            check.equal(attempted['state']['new_pool'], replacement, 'new pool was recorded before step 9')
            for name in ('cut-mounts', 'cut-mounts-init'):
                r.nothing_mounted((s.path / name).read_text(), check, f'{what}: checkpoint boundary {name}')
            check.equal(s.step('reset-imported').out, '', 'boot 2 resets disks with no imported pool')
            for label in ('A', 'B', 'D'):
                check.equal(s.step(f'reset-{label}').rc, 0, f'boot 2 resets disposable disk {label}')
                check.equal(s.step(f'reset-probe-{label}').rc, 0, f'boot 2 rereads disposable disk {label}')
        check(replacement != before.pools['e2ea']['guid'], f'{what}: replacement differs from old A')

        after = s.observe('after-error')
        check.equal(sorted(after.pools), ['e2eb', 'e2ec'], f'{what}: replacement exported before CLI returns')
        for pool in ('e2eb', 'e2ec'):
            check.equal(after.pools[pool]['guid'], before.pools[pool]['guid'], f'{what}: {pool} retains its GUID')
            check.equal(after.pools[pool]['readonly'], 'on', f'{what}: {pool} returned read-only')
        check(before.pools['e2ea']['guid'] not in [p['guid'] for p in after.pools.values()],
              f'{what}: old A GUID remains absent after cleanup')
        mount_state = s.step('after-mounted')
        check.equal(mount_state.argv,
                    ['zfs', 'get', '-H', '-r', '-t', 'filesystem', '-o', 'name,value', 'mounted', 'e2eb', 'e2ec'],
                    f'{what}: mount-state query selects native filesystems')
        mounted = [line.split('\t') for line in mount_state.out.splitlines()]
        check(mounted and all(value == 'no' for _, value in mounted), f'{what}: B/C trees remain unmounted')
        r.nothing_mounted((after.path / 'mountinfo').read_text(), check, f'{what}: after returned error')
        native_record = after.properties('e2eb')['zboot:operation']
        check.equal(native_record['source'], 'local', f'{what}: intent remains locally owned')
        check.equal(json.loads(native_record['value']), record, f'{what}: independent native intent matches')
        staging, tag = state['staging'], f'zboot:restore:{op}'
        check(staging in after.datasets, f'{what}: staging remains available')
        check.equal(after.properties(staging)['zboot:staging'], {'value': op, 'source': 'local'},
                    f'{what}: staging retains the operation marker')
        for point in ('e2eb/ROOT/be1@src', 'e2eb/ROOT/be1/var@src',
                      f'{staging}/scratch@zboot-restore-{op}'):
            check((point, tag) in after.holds, f'{what}: protected snapshot {point} retains its hold')
        active_receipt(check, after, op, state, what)
        labels = s.step('target-labels')
        check.equal(labels.rc, 0, f'{what}: exported replacement labels remain readable')
        check.equal(labels.argv[:3], ['zpool', 'import', '-d'], f'{what}: target inspection is list-only')
        check.equal(len(labels.argv), 4, f'{what}: label inspection does not request an import')
        check.equal(re.findall(r'^\s*pool:\s+(\S+)', labels.out, re.M), ['e2ea'], f'{what}: target pool label name')
        check.equal(re.findall(r'^\s*id:\s+(\d+)', labels.out, re.M), [replacement], f'{what}: target label GUID')
        unchanged(check, after, s.observe('after-labels'), f'{what}: label listing preserves exported cleanup state')
    check(operations[0] != operations[1], 'the two independent fixtures have different restore IDs')
    check(source_guids[0] != source_guids[1], 'boot 2 recreated B rather than replaying boot 1')
