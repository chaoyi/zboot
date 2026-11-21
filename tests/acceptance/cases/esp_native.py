"""One reviewed ESP batch rewrites zboot's files directly in EFI/zboot under
their names and the fallback, never adopts a loader elsewhere, and adds the
canonical name only to an ESP without one of zboot's files in EFI/zboot. The two boots
retain mounted-RW cold durability and exercise both imported-pool disks,
untouched rescue media, typed installation and a real late readonly ESP."""
import json

from host.case import Boot
from host.lifecycle import stale_token

ID = 'ESP-NATIVE'
GROUP = 'esp'
SECONDS = 3600
DISKS = {'A': 2, 'B': 2, 'D': 2}
# udev: `status --devices` reads lsblk PARTTYPE.
BOOTS = [Boot(1, cut='esp-published', udev=True), Boot(2, udev=True)]

LOADERS = ('EFI/zboot/zboot-recovery.efi', 'EFI/BOOT/BOOTX64.EFI')
CANONICAL = 'EFI/zboot/zboot.efi'
OUTSIDE = 'EFI/Linux/zboot.efi'
OLD = {'EFI/vendor/loader.efi': 'unrelated-loader-preserved',
       'operator.txt': 'unrelated-root-file-preserved'}


def files(step):
    return dict(line.split('=', 1) for line in step.out.splitlines())


def sums(step):
    return {line.split()[1]: line.split()[0] for line in step.out.splitlines()}


def verdict(ev, check):
    s, cold = ev.stage(1), ev.stage(2)
    uki = s.step('uki-sha256').out.split()[0]
    outside = s.step('outside-owned-sha256').out.split()[0]
    outside_bytes = int(s.step('outside-owned-bytes').out.strip())
    check.equal(outside_bytes, int(s.step('uki-bytes').out.strip()) + 1,
                'outside owned PE differs only by its appended byte')
    check(outside != uki, 'the outside owned PE has a distinct digest')
    partition = s.step('preview').argv[2]
    check(partition.startswith('/dev/vd') and partition.endswith('1'), 'explicit refresh selects the native first ESP partition')
    automatic = s.step('auto-preview').json['result']
    check.equal(automatic.get('automatic'), True, 'omitted partitions select the imported-pool disks')
    auto_targets = automatic['targets']
    check.equal([target['review']['target']['partition']['path'] for target in auto_targets],
                ['/dev/vda1', '/dev/vdb1'], 'the one auto plan selects both imported-pool ESPs')
    check.equal([target['review']['target']['disk']['serial'] for target in auto_targets],
                ['ZFS-E2E-A', 'ZFS-E2E-B'], 'both selected disks retain exact native serials')
    for target in auto_targets:
        check.equal(list(target['review']['previous']), ['EFI/zboot/host.efi'],
                    'auto updates the owned name and preserves the foreign fallback')
        check.equal(target['foreign_replacements'], [], 'auto grants no foreign replacement')
    pairs = []
    for line in s.step('pair-records').out.splitlines():
        name, key, value, provenance = line.split('\t')
        check.equal((key, provenance), ('zboot:pair', 'local'), f'{name}: native pair record is LOCAL')
        pairs.append((name, json.loads(value)))
    check.equal([name for name, _ in pairs], ['e2ea/data', 'e2eb/data'], 'the imported disks carry the real pair')
    if len(pairs) == 2:
        left, right = pairs[0][1], pairs[1][1]
        check.equal((left['role'], right['role']), ('primary', 'secondary'), 'the two disks have their native pair roles')
        check.equal(left['pair_id'], right['pair_id'], 'the pair identity is mutual')
        paired = s.observe('paired')
        for name, record in pairs:
            check.equal(record['endpoint']['identity']['pool_guid'], paired.pools[name.split('/')[0]]['guid'],
                        f'{name}: pair endpoint binds the imported native pool GUID')
            check.equal(record['endpoint']['identity']['guid'], paired.datasets[name]['guid'],
                        f'{name}: pair endpoint binds the native filesystem GUID')
        check.equal(left['peer'], right['endpoint'], 'primary peer binds secondary native identity')
        check.equal(right['peer'], left['endpoint'], 'secondary peer binds primary native identity')
    check.equal(s.step('pair-after').out, s.step('pair-records').out, 'ESP publication preserves exact native pair records')
    late = s.step('auto-late')
    check.equal((late.rc, late.json.get('mode')), (4, 'partial'), 'the second ESP native refusal is partial exit 4')
    check('/dev/vdb1' in late.json['result']['message'], 'partial output names the remaining second ESP')
    transition = dict(line.split('=', 1) for line in (s.path / 'late-transition').read_text().splitlines())
    second = auto_targets[1]['review']['target']['partition']
    check.equal(transition, {'serial': 'ZFS-E2E-B', 'partuuid': second['partition_uuid'],
                             'rdev': second['device_number'], 'before': '0', 'after': '1'},
                'one-shot transition binds native serial, PARTUUID, rdev and readonly pre/post state')
    check.equal((s.path / 'late-fired').read_text(), 'fired', 'only the observed first publication arms the transition')
    check.equal((s.path / 'late-kernel-ro').read_text().strip(), '1', 'kernel reports the selected partition readonly')
    check.equal(s.cut('esp-second-readonly'), ['/bin/busybox', 'blockdev', '--setro', '/dev/vdb1'],
                'fault changes only the second ESP partition')
    check.equal((s.path / 'cut-esp-second-readonly.argv.real-rc').read_text().strip(), '0',
                'the exact native readonly transition succeeded')
    check.equal(s.cut('esp-second-observer'), ['--json', '--tree', '--properties-by', 'blkid',
                '--bytes', '--paths', '--output',
                'PATH,MAJ:MIN,TYPE,SIZE,LOG-SEC,PHY-SEC,RO,SERIAL,WWN,MODEL,FSTYPE,LABEL,UUID,PARTUUID,PARTTYPE,PTUUID,MOUNTPOINTS'],
                'transition occurs at the exact native inventory boundary')
    check.equal(s.step('auto-after-A').out.split()[0], uki, 'first ESP has actual new bytes before late failure')
    check.equal(s.step('auto-after-B').out.split()[0], s.step('auto-before-B').out.split()[0],
                'second ESP retains its old loader after native refusal')
    check.equal(s.step('late-unset').argv, ['busybox', 'blockdev', '--setrw', '/dev/vdb1'],
                'fixture restores only that partition writable')
    finish = s.step('auto-finish').json
    check.equal((s.step('auto-finish').rc, finish.get('mode')), (0, 'applied'), 'ordinary auto refresh needs no confirmation')
    check.equal(finish['result']['partitions'], ['/dev/vda1', '/dev/vdb1'], 'rerun completes both selected disks')
    check.equal(finish['result'].get('left_in_place'),
                [{'partition': p, 'path': 'EFI/BOOT/BOOTX64.EFI'} for p in ('/dev/vda1', '/dev/vdb1')],
                'the result names each foreign fallback it left in place')
    auto_files = s.step('auto-files').out.splitlines()
    check.equal([line.split()[0] for line in auto_files[:2]], [uki, uki], 'both physical ESPs contain the new owned loader')
    check.equal(auto_files[2:], ['foreign-fallback-preserved'] * 2, 'both foreign fallbacks remain untouched')
    check.equal(s.step('auto-skipped').out.split()[0], s.step('esp-before').out.split()[0],
                'the attached rescue ESP stays byte-identical during auto refresh')
    typed = s.step('typed-preview').json
    typed_target = typed['result']['targets'][0]
    check.equal(typed_target['foreign_replacements'], ['EFI/BOOT/BOOTX64.EFI'],
                'an ESP without an owned loader declares the foreign fallback replacement')
    typed_partition = typed_target['review']['target']['partition']['path']
    check.equal((typed_target['review']['target']['disk']['serial'], typed_target['review']['target']['number']),
                ('ZFS-E2E-D', 2), 'typed install selects D partition 2')
    unattended = s.step('unattended')
    check.equal(unattended.rc, 3, 'unattended foreign replacement previews with exit 3')
    check.equal((unattended.json['mode'], unattended.json['token']), ('preview', typed['token']),
                'the loss-capable preview retains its token')
    check.equal(s.step('typed-apply').json['result']['partitions'], [typed_partition],
                'typed install writes only its selected ESP')

    preview = s.step('preview').json
    token = preview['token']
    check.equal((preview['schema_version'], preview['mode']), (1, 'preview'), 'preview envelope')
    check(isinstance(token, str) and token, 'preview carries a token')
    target = preview['result']['targets'][0]
    review = target['review']
    check.equal((review['target']['disk']['serial'], review['target']['number']), ('ZFS-E2E-D', 1),
                'cold refresh is identity-bound to D partition 1')
    check.equal(target['foreign_replacements'], [], "a refresh of zboot's own files replaces nothing foreign")
    # zboot's files directly in EFI/zboot keep their names, no canonical copy
    # is added beside them, and a zboot UKI under EFI/Linux is not adopted
    # (docs/CLI.md esp).
    check.equal(set(review['previous']), set(LOADERS), "the plan writes zboot's existing files only")
    for path in LOADERS:
        check((review['previous'].get(path) or {}).get('bytes', 0) > 0, f'review binds previous bytes at {path}')
    check('legacy_entries' not in target, 'the plan carries no legacy record cleanup')
    wrong = s.step('wrong-token')
    stale_token(check, wrong, 'ESP install with a wrong token', token)
    check.equal(s.step('esp-refused').out.split()[0], s.step('esp-before').out.split()[0],
                'refusals left every ESP byte unchanged')
    check.equal(sums(s.step('refused-sha256')), sums(s.step('seed-sha256')), 'refusal preserves exact seeded loader and unrelated bytes')
    check.equal(files(s.step('refused-files')), OLD, 'refusal preserves unrelated seeded files')

    applied = s.step('apply').json
    check.equal((applied['mode'], applied['token']), ('applied', token), 'applied envelope with the reviewed token')
    result = applied['result']
    check(result['complete'] is True, 'install complete')
    check.equal(result['partitions'], [partition], 'outcome names the refreshed partition')
    check('operation' not in applied and 'operation_id' not in result, 'ESP publication carries no fabricated operation identity')
    check.equal(result['efi_sha256'], uki, 'result names the supplied UKI')

    check.equal(ev.boots[0].get('killed'), -9, 'host power-cuts immediately after successful ESP publication')
    check.equal(s.step('writeback-disabled').out.strip(), '0', 'only guest periodic writeback is disabled before publication')
    check(s.step('writeback-before').out.strip().isdigit(), 'the original guest writeback interval is recorded')
    mounts = []
    for line in s.step('apply-mountinfo').out.splitlines():
        left, right = line.split(' - ', 1)
        fields, filesystem = left.split(), right.split()
        if fields[4] == '/mnt/zfs-e2e/esp':
            mounts.append((fields, filesystem))
    if check.equal(len(mounts), 1, 'the original ESP is mounted once before apply'):
        fields, filesystem = mounts[0]
        check.equal(fields[3], '/', 'the RW host view is the whole ESP')
        check.equal(filesystem[:2], ['vfat', partition], 'the host mount names the native target ESP')
        check('rw' in fields[5].split(',') and 'ro' not in fields[5].split(','),
              'the original ESP remains mounted RW during publication')
    check.equal(cold.step('cold-partition').out, s.step('apply-partition').out,
                'the cold boot sees the same native partition identity')
    check('-o' in cold.step('installed-mount').argv and
          'ro,nosuid,nodev,noexec' in cold.step('installed-mount').argv,
          'cold verification mounts the ESP read-only')
    check.equal(cold.step('cold-legacy-record').out.strip(), 'legacy-record', 'the old operations record is left alone')
    check.equal(cold.step('cold-no-canonical').rc, 0, 'no canonical copy is added beside the existing loader')
    check.equal(cold.step('cold-temporaries').out, '', 'completed publication leaves no staged ESP file')

    status = cold.step('status').json
    check.equal(cold.step('shipped-lookup').out.splitlines(),
                ['/usr/bin/zboot', '/usr/lib/zboot/zboot.efi'],
                'comparison uses the packaged loader ../lib/zboot/zboot.efi of /usr/bin/zboot')
    check.equal(cold.step('shipped-sha256').out.split()[0], uki,
                'the RAM comparison loader matches the known fixture')
    comparison_path = '/usr/lib/zboot/zboot.efi'
    containing = []
    for line in cold.step('shipped-mountinfo').out.splitlines():
        left, right = line.split(' - ', 1)
        mountpoint = left.split()[4]
        if comparison_path == mountpoint or comparison_path.startswith(mountpoint.rstrip('/') + '/'):
            containing.append((len(mountpoint), right.split()[0]))
    check(bool(containing) and max(containing)[1] in ('rootfs', 'ramfs', 'tmpfs'),
          'the comparison loader is supplied inside guest RAM')
    esps = [e for e in status['result']['esps'] if e['path'] == partition]
    if check.equal(len(esps), 1, 'status --devices lists the ESP'):
        check.equal(esps[0].get('target', {}).get('number'), 1, 'status binds the ESP partition identity')
        loaders = {loader['path']: loader for loader in esps[0].get('loaders', [])}
        check.equal(set(loaders), {*LOADERS, CANONICAL},
                    "status lists zboot's directory and both fixed paths, not EFI/Linux or vendor files")
        canonical = loaders.get(CANONICAL, {})
        check.equal((canonical.get('owner'), canonical.get('identity')), (None, None),
                    'status reports the canonical name as empty')
        check.equal((loaders.get('EFI/BOOT/BOOTX64.EFI', {}).get('identity') or {}).get('sha256'), uki,
                    'durable fixed fallback status hash')
        attention = status['result'].get('attention', [])
        for path in LOADERS:
            check(path in loaders, f'status inventories the installed loader {path}')
            if path in loaders:
                check.equal(loaders[path].get('owner'), 'zboot', f'{path} has verified zboot ownership')
                check(loaders[path].get('matches_installed') is True,
                      f'{path} matches the supplied shipped comparison loader')
            check(not any(path in item for item in attention),
                  f'the matching installed loader {path} receives no attention')
        check(not any(OUTSIDE in item or 'EFI/vendor' in item for item in attention),
              'loaders outside zboot\'s paths receive no outdated-zboot attention')
    installed = sums(cold.step('installed-sha256'))
    for path in LOADERS:
        check.equal(installed.get(path), uki, f'cold native readback of {path}')
    check.equal(installed.get(OUTSIDE), outside, 'the zboot UKI under EFI/Linux keeps its bytes')
    check.equal(files(cold.step('installed-files')),
                {k: v for k, v in OLD.items() if k not in LOADERS}, 'unrelated files preserved')
    check.equal(cold.step('mountinfo-after').out, cold.step('mountinfo-before').out, 'cold verification leaks no mount')
