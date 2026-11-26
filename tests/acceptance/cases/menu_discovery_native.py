"""A responsive actual Menu and a writer lock held by a surviving import child."""
import json
import re
from pathlib import Path

from host.case import Boot

ID = 'MENU-DISCOVERY-NATIVE'
GROUP = 'small'
SECONDS = 600
DISKS = {'A': 2, 'B': 2}
BOOTS = [Boot(1, append='zboot.recovery=1')]


def verdict(ev, check):
    s = ev.stage(1)
    launch = json.loads((Path(ev.root).parent / 'boot-1/launch.json').read_text())
    append = launch['argv'][launch['argv'].index('-append') + 1].split()
    check.equal([arg for arg in append if arg.startswith('zboot.recovery=')],
                ['zboot.recovery=1'], 'direct boot explicitly exercises the UKI entry contract')
    created, blocked = s.observe('created'), s.observe('blocked')
    dead, completed = s.observe('parent-dead'), s.observe('completed')
    fast, slow = 'e2efast', 'e2eslow'
    fast_guid, slow_guid = (s.step(f'guid-{pool}').out.strip() for pool in (fast, slow))
    check(fast_guid.isdecimal() and slow_guid.isdecimal() and fast_guid != slow_guid,
          'the two physical fixture pools have distinct native GUIDs')
    check.equal(sorted(created.pools), [fast, slow], 'exactly the two fixture pools were created')
    def disk_paths(value):
        found = []
        if isinstance(value, dict):
            if value.get('vdev_type') == 'disk':
                found.append(value.get('path'))
            for child in value.values():
                found.extend(disk_paths(child))
        elif isinstance(value, list):
            for child in value:
                found.extend(disk_paths(child))
        return found

    for pool in (fast, slow):
        check.equal(disk_paths(s.step(f'topology-{pool}').json),
                    [s.step(f'partition-{pool}').argv[-1] + '1'],
                    f'{pool} has exactly its own physical partition, with no file vdev')
        check.equal(created.properties(f'{pool}/root')['mountpoint']['value'], '/',
                    f'{pool} root has native root shape')
        check.equal(created.properties(f'{pool}/root')['canmount']['value'], 'noauto',
                    f'{pool} root has inactive placement')
    menu, snapshot = s.step('menu'), s.step('snapshot')
    check.equal(menu.argv, ['zboot', 'menu', '--no-autoboot'], 'the real Menu is the background command')
    check.equal(menu.rc, 137, 'only the recorded Menu parent was killed with SIGKILL')
    check.equal(snapshot.argv, ['zboot', 'snapshot', 'e2efast/root@proof', '--json'],
                'the ordinary CLI performs the foreground mutation')
    check.equal(s.step('slow-import-argv').out.splitlines(),
                ['/sbin/zpool', 'import', '-N', '-o', 'readonly=on', '-o', 'cachefile=none', slow_guid],
                'the interposer delays only the exact slow GUID read-only import')
    listing = s.step('listing-before-release').out
    check.contains(listing, 'e2efast/root', 'the fast boot root is listed before release')
    check(any(re.fullmatch(r'[0-9]+: e2efast/root', line) for line in listing.splitlines()),
          'the fast entry has an actual probed kernel/initrd pair')
    check.contains(listing, f'Pool e2eslow guid={slow_guid}  importing',
                   'the same live listing identifies the unfinished import')
    check.contains(listing, 'zboot> ', 'the Menu accepts input while the slow import is gated')
    for label, obs in (('blocked', blocked), ('parent dead', dead)):
        check.equal(sorted(obs.pools), [fast], f'{label}: slow import has not run')
        check.equal(obs.pools[fast]['guid'], fast_guid, f'{label}: fast GUID retained')
        check.equal(obs.pools[fast]['readonly'], 'on', f'{label}: fast pool stays read-only')
        check('e2efast/root@proof' not in obs.datasets, f'{label}: foreground snapshot is absent natively')
        check.equal(obs.properties('e2efast/root')['mounted']['value'], 'no',
                    f'{label}: Menu probe mount was cleaned before parent death')
    writer_inode = s.step('writer-inode-before').out.strip()
    check.equal(s.step('writer-inode-after').out.strip(), writer_inode,
                'parent death does not replace the native writer-lock inode')
    slow_pid, slow_start = s.step('slow-identity').out.splitlines()
    check(slow_pid.isdecimal() and slow_start.isdecimal(), 'slow child custody uses its exact PID and kernel start time')
    for phase in ('before-death', 'after-death'):
        lock = s.step(f'writer-held-{phase}')
        check.equal(lock.rc, 1, f'{phase}: independent nonblocking native flock cannot take the writer')
        check.equal(lock.err, '', f'{phase}: flock failed by contention, not a command error')
        child = s.step(f'slow-{phase}')
        check.equal(child.rc, 0, f'{phase}: the exact slow import PID is alive')
        stat = child.out.splitlines()[0].split()
        check.equal(stat[0], slow_pid, f'{phase}: same recorded slow PID survives')
        check.equal(stat[21], slow_start, f'{phase}: kernel start time excludes PID reuse')
        writer_fds = [part for part in child.out.split('\nFD ')[1:]
                      if part.splitlines()[0].endswith(' /run/zfs-tools/writer.lock')]
        check(bool(writer_fds), f'{phase}: import child retains the exact writer FD')
        check(any(f'ino:\t{writer_inode}\n' in part for part in writer_fds),
              f'{phase}: inherited descriptor refers to the same native writer inode')
        check(any('FLOCK' in part and 'WRITE' in part for part in writer_fds),
              f'{phase}: kernel fdinfo reports an inherited exclusive flock on that FD')
        foreground = s.step(f'foreground-{phase}')
        check.equal(foreground.rc, 0, f'{phase}: the foreground product process is still alive')
        check.contains(foreground.out, 'e2efast/root@proof', f'{phase}: PID belongs to the expected mutation')
    check.contains(s.step('waiting-before-death').out, 'waiting for the ZFS writer lock',
                   'the ordinary mutation reports native writer contention')
    check(' - zfs ' not in s.step('menu-process').out.split('MOUNTS\n', 1)[1],
          'the actual Menu mount namespace has no remaining probe mount before it is killed')
    menu_pid = menu.base.with_suffix('.pid').read_text().strip()
    check.equal(s.step('kill-menu').argv, ['kill', '-KILL', menu_pid], 'the test kills only its recorded Menu PID')
    check.equal(s.step('menu-gone').rc, 0, 'the Menu parent is gone before the inherited-lock probe')
    check.equal(s.step('premature-release').rc, 1, 'the slow import was still gated after Menu death')
    check.equal(s.step('gate-timeout').rc, 1, 'no deadline was converted into a successful import')
    check.equal(s.step('gate-timeout-final').rc, 1, 'the import gate never timed out before real completion')
    check.equal(s.step('writer-initial-free').rc, 0, 'independent flock works before discovery')
    check.equal(s.step('writer-final-free').rc, 0, 'writer releases after import and foreground completion')
    check.equal(snapshot.rc, 0, f'foreground snapshot completes after release: {snapshot.err[-300:]!r}')
    check.equal(snapshot.json.get('mode'), 'applied', 'foreground mutation reports applied')
    check.equal(s.step('slow-child-gone').rc, 0, 'the exact owned import child finished')
    check.equal(s.step('native-before').out.split()[0], s.step('native-after').out.split()[0],
                'the guest native executable was restored byte-for-byte')
    timing = dict(line.split() for line in s.step('timing').out.splitlines())
    started, listed, released = (int(timing[name]) for name in ('started', 'listed', 'released'))
    check(0 <= listed - started < 90000, f'listing arrived while import was held ({listed - started} ms)')
    check(released > listed, 'the slow import was released only after the responsive listing and custody probes')
    check.equal(sorted(completed.pools), [fast, slow], 'both native pools arrive after release')
    for pool, guid in ((fast, fast_guid), (slow, slow_guid)):
        check.equal(completed.pools[pool]['guid'], guid, f'{pool}: final native GUID matches original')
        check.equal(completed.pools[pool]['readonly'], 'on', f'{pool}: foreground action restores read-only access')
        check.equal(completed.properties(f'{pool}/root')['mounted']['value'], 'no',
                    f'{pool}: no probe mount remains')
    proof = s.step('proof-native').out.strip().split('\t')
    check.equal(proof[0], 'e2efast/root@proof', 'native final snapshot has the requested full name')
    check(len(proof) == 2 and proof[1].isdecimal() and int(proof[1]) > 0,
          'native final snapshot has a nonzero GUID')
    check('e2efast/root@proof' in completed.datasets, 'independent final inventory contains the snapshot')
    check.equal(s.observe('cleaned').pools, {}, 'all owned fixture pools were exported at the end')
