"""Framework self-test: product command, native evidence, cut and restart."""
from host.case import Boot

ID = 'SMOKE'
GROUP = 'small'
SECONDS = 600
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1, cut='snapshot-cut'), Boot(2)]


def verdict(ev, check):
    first, second = ev.stage(1), ev.stage(2)
    status = first.step('status')
    check.equal(status.json['schema_version'], 1, 'status envelope schema')
    argv = first.cut('snapshot-cut')
    check.equal(argv[:2], ['snapshot', '-o'], 'cut at the snapshot call')
    check(argv[2].startswith('zboot:capture='), f'snapshot tagged with its capture: {argv}')
    check.equal(argv[3:], ['e2ea@s1', 'e2ea/plain@s1', 'e2ea/plain/child@s1'], 'one atomic call')
    cut = second.observe('after-cut').datasets
    check('e2ea@s1' not in cut, 'the cut snapshot was never taken')
    after = second.step('snapshot')
    check.equal((after.json['schema_version'], after.json['mode']), (1, 'applied'), 'snapshot envelope after restart')
    check('operation' not in after.json, 'snapshot carries no resumable operation')
    check.equal(len(after.json['result']), 1, 'one label group after restart')
    check.equal(after.json['result'][0]['status'], 'complete', 'snapshot after restart')
    datasets = second.observe('after').datasets
    for name in ('e2ea@s2', 'e2ea/plain@s2', 'e2ea/plain/child@s2'):
        check(name in datasets, f'{name} exists natively')
    check.equal(second.observe('after').pools['e2ea']['health'], 'ONLINE', 'pool health')
