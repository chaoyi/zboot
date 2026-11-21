"""Fresh whole-disk `zboot deploy` of a `zboot factory` root tar and a host
overlay onto D under one reviewed token, read back natively (GPT, readonly
import by guid, @factory/@deployed, overlays, identity, BE contents). The
deployed system then boots and erases spare disk B itself, which needs the
probe the zboot package installs."""
import re

from host.case import Boot
from host import deploy as deploy_proof
from host.lifecycle import prop, source, stale_token

ID = 'DEPLOY-NATIVE'
GROUP = 'deploy'
SECONDS = 3600
DISKS = {'A': 2, 'B': 2, 'D': 8}
BOOTS = [Boot(1, udev=True, extra={'setup': 'neutral'}),
         Boot(2, efi=True, poweroff=True, extra={'from': 'D'})]

def stage_2(console):
    deploy_proof.boot(console, BE)

POOL, BE, VIEW = 'e2ed', 'e2ed/ROOT/os', '/mnt/zfs-e2e/deploy-proof'


def sums(step, prefix):
    return {path[len(prefix):]: digest for digest, path in
            (line.split(None, 1) for line in step.out.splitlines())}


def pool_property(observation, pool, name):
    for line in (observation.path / 'pool-properties').read_text().splitlines():
        fields = line.split('\t')
        if fields[:2] == [pool, name]:
            return fields[2]
    return None


def verdict(ev, check):
    s = ev.stage(1)
    before = s.step('wipe-before').json
    check.equal((before['schema_version'], before['mode']), (1, 'preview'), 'wipe preview envelope')
    check(before['result']['partitions'] == [] and before['result']['partition_table_uuid'] is None,
          'D is bare before deploy')

    small = s.step('esp-32m')
    check.equal(small.rc, 1, f'a 32 MiB ESP is refused (stderr {small.err[-300:]!r})')
    check.contains(small.err, 'unsupported deploy partition geometry', '32 MiB ESP refusal cause')
    preview = s.step('preview')
    check.equal((preview.rc, preview.json['schema_version']), (0, 1), 'preview envelope')
    token = preview.json['token']
    check(isinstance(token, str) and token, 'preview carries a token')
    check(preview.json['mode'] == 'preview' and isinstance(preview.json['result']['deploy']['disk'], dict),
          'preview carries its disk plan')
    planned = preview.json['result']['deploy']
    check('base_overlay' not in planned and 'overlay' not in planned, 'new deploy carries no implicit legacy overlay')
    check.equal([o['form'] for o in planned['overlays']], ['directory'], 'the plan carries the ordered host overlay')
    check(planned['overlays'][0]['post_install'] is not None, 'the host overlay review lists its post-install')
    check([e['path'] for e in planned['overlays'][0]['entries']].count('etc/zboot-e2e/marker') == 1,
          'the host overlay review lists its file')
    check(len(planned['factory']['kernels']) >= 1 and planned['factory']['sha256'],
          'the plan binds the root tar digest and its kernels')
    again = s.step('preview-again')
    check.equal((again.rc, again.json['schema_version'], again.json['token']), (0, 1, token),
                'fresh-process preview returns the same token')
    unattended = s.step('unattended')
    check.equal((unattended.rc, unattended.json['schema_version']), (3, 1), 'unattended deploy exits 3')
    check.equal((unattended.json['mode'], unattended.json['token']), ('preview', token),
                'unattended deploy shows the same preview')
    wrong = s.step('wrong-token')
    stale_token(check, wrong, 'deploy with a wrong token', token)
    check.equal(s.step('wipe-refused').json, before, 'D plan unchanged by the refusals')
    check.equal(s.step('disk-refused').out, s.step('disk-before').out,
                'refusals left the first and last MiB of D unchanged')

    apply = s.step('apply')
    check.equal((apply.rc, apply.json['schema_version']), (0, 1), 'confirmed deploy exits 0')
    applied = apply.json
    check.equal((applied['mode'], applied['token']), ('applied', token), 'applied with the reviewed token')
    review, outcome = applied['result']['review'], applied['result']['outcome']
    check(outcome['complete'] is True, 'outcome complete')
    check(outcome['exported'] is True, 'outcome exported')
    check.equal(outcome['dataset']['name'], BE, 'outcome names the BE')
    status = s.step('inventory-after').json['result']['inventory']
    check(all(p['name'] != POOL for p in status['pools']), 'status: deploy exported its pool')
    check(POOL not in s.observe('after-apply').pools, 'natively: deploy exported its pool')

    table = s.step('gpt').json['partitiontable']
    check.equal(table['label'], 'gpt', 'native GPT label')
    check.equal(len(table['partitions']), 2, 'native GPT has ESP and pool partitions')
    check.equal(table['id'].lower(), review['layout']['disk_uuid'].lower(), 'GPT disk id is the consented one')

    partition = table['partitions'][-1]['node']
    check.equal(table['partitions'][-1]['uuid'].lower(), review['layout']['zfs_uuid'].lower(),
                f'the last GPT partition {partition} is the consented pool partition')
    check.equal(s.step('import').argv[-2:], [partition, outcome['pool']['identity']['pool_guid']],
                'readonly import by guid from the exact partition')

    imported = s.observe('imported')
    identity = outcome['dataset']['identity']
    pool = imported.pools.get(POOL, {})
    check.equal(pool.get('guid'), identity['pool_guid'], 'native pool guid is the deployed one')
    check.equal(pool.get('readonly'), 'on', 'independent import is readonly')
    native = imported.datasets.get(BE, {})
    check.equal((native.get('guid'), native.get('createtxg')), (identity['guid'], identity['createtxg']),
                'native BE guid/createtxg is the deployed one')
    check.equal(imported.properties(BE).get('objsetid', {}).get('value'), identity['objsetid'],
                'native BE objsetid is the deployed one')
    check.equal(pool_property(imported, POOL, 'bootfs'), BE, 'native bootfs selects the BE')
    inventory = s.step('inventory-imported').json['result']['inventory']
    listed = [d for d in inventory['datasets'] if d['name'] == BE]
    check.equal([d['identity'] for d in listed], [identity], 'status: imported BE identity is the deployed one')
    snapshots = sorted(p['name'] for p in inventory.get('snapshots') or [] if p['name'].startswith(BE + '@'))
    check.equal(snapshots, [BE + '@deployed', BE + '@factory'], 'deploy left BE@factory and BE@deployed')

    hostid = review['hostid']
    check.equal(s.step('be-hostid').out.strip(), bytes.fromhex(hostid)[::-1].hex(),
                f'/etc/hostid is the reviewed hostid {hostid} little-endian')
    boot = sums(s.step('boot-files'), VIEW + '/')
    kernels = review['factory']['kernels']
    check(kernels, 'the review names the root tar kernels')
    check.equal(sorted(boot), sorted(f'boot/{name}-{kernel}' for kernel in kernels for name in ('initrd.img', 'vmlinuz')),
                'the BE carries a kernel and an initrd for every reviewed kernel')
    check(all(re.fullmatch('[0-9a-f]{64}', digest) for digest in boot.values()), 'every BE boot file is readable')
    check.equal(s.step('userspace').rc, 0, 'the root carries /usr/bin/{zboot,zsnap}')
    check.equal(s.step('overlay-file').out.split(), ['640', '0', '0'],
                'a directory overlay file is root:root with its mode')
    check.equal(s.step('overlay-marker').out, 'ZFS-E2E-OVERLAY\n', 'the host overlay file arrived')
    check.equal(s.step('hook-env').out.split(), [hostid, POOL, BE], 'post-install got ZBOOT_HOSTID/POOL/BE')
    check.equal(s.step('hook-hostid').out.strip(), 'absent',
                'a new deploy enforces identity after all hooks')
    if s.step('sshd-installed').rc == 0:
        check.contains(s.step('base-unit').out, 'ExecStart=/usr/bin/ssh-keygen -A', 'the SSH factory root carries missing-key generation')
        check.equal(s.step('base-link').out.strip(), '/etc/systemd/system/zboot-ssh-keygen.service',
                    'the SSH factory enables missing-key generation')
    else:
        check(s.step('base-unit').rc != 0 and s.step('base-link').rc != 0, 'the factory omits SSH key generation without sshd')
    check(s.step('policy-rc').rc != 0, 'policy-rc.d does not outlive post-install')
    check.equal(s.step('hook-log').rc, 0, 'the post-install log is kept in the attempt directory')
    # Stock mounting: the BE is noauto at creation, carries no systemd ignore
    # override, and deploy seeds no list cache.
    imported = s.observe('imported')
    check.equal((prop(imported, BE, 'canmount'), source(imported, BE, 'canmount')), ('noauto', 'local'),
                'the BE is canmount=noauto')
    check.equal(prop(imported, BE, 'org.openzfs.systemd:ignore'), '-', 'the BE has no systemd ignore override')
    check.equal(s.step('list-cache').out, '', 'deploy seeds no zfs-list.cache file')
    for name in ('view-umount', 'export'):
        check.equal(s.step(name).rc, 0, f'{name} succeeds')
    check('zboot-deploy-' not in s.step('mountinfo-final').out, 'no private deploy mount leaked')

    deploy_proof.check_boot(ev, check, 2, BE, BE, hostid, erased=True)
