"""Pair refusals: same GUID with a different IV set; dirty receiver head."""
from host.case import Boot
from host.lifecycle import placement, preserved, refused

ID = 'PAIR-REFUSALS-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]


def verdict(ev, check):
    s = ev.stage(1)
    sets = {}
    for line in s.step('iv-sets').out.splitlines():
        name, key, value = line.split('\t')
        sets.setdefault(name, {})[key] = value
    source, receiver = sets['e2eb/ivsource@point'], sets['e2ea/ivreceiver@point']
    check.equal(receiver['guid'], source['guid'], 'logical fixture keeps the snapshot GUID')
    check(receiver['ivsetguid'] not in ('-', source['ivsetguid']), f'logical fixture changes the IV set: {sets}')
    before, after = s.observe('iv-before'), s.observe('iv-after')
    check.equal(before.datasets['e2ea/ivreceiver@point']['guid'],
                before.datasets['e2eb/ivsource@point']['guid'], 'native snapshot GUIDs equal')
    refused(check, s.step('iv-pair'), 'raw encryption ancestry is incompatible', 'pair with a different IV set')
    preserved(check, before, after, 'IV refusal')

    check(int(s.step('dirty-written').out) > 0, 'dirty receiver has bytes written since @point')
    before, after = s.observe('dirty-before'), s.observe('dirty-after')
    refused(check, s.step('dirty-pair'), 'initial pair primary must be the containing/ahead copy',
            'pair with a dirty receiver head')
    preserved(check, before, after, 'dirty refusal')
    check.equal(placement(after, 'e2ea/dirtyreceiver'), placement(before, 'e2ea/dirtyreceiver'),
                'dirty refusal keeps readonly/canmount/mountpoint/mounted')
    check.equal(after.mounts.get('/mnt/zfs-e2e/dirty-receiver'), 'e2ea/dirtyreceiver', 'receiver still mounted')
    check.equal(s.step('dirty-read').out, 'receiver changed content', 'receiver content kept (no rollback)')
