"""`zboot chroot`: private writable maintenance chroot of the selected BE, and
the paired-secondary refusal."""
from host.case import Boot

ID = 'MAINTENANCE-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1, udev=True)]


def verdict(ev, check):
    s = ev.stage(1)
    chroot = s.step('chroot')
    check.equal(chroot.argv[:5], ['zboot', 'chroot', 'e2ea/maintenance', '--', '/bin/sh'], 'chroot argv')
    # 90 = the child lacked /proc, /sys, /dev/null or /dev/pts.
    check.equal(chroot.rc, 7, f'child exit status propagated (stderr {chroot.err[-300:]!r})')
    check.equal(s.step('mountinfo-after').out, s.step('mountinfo-before').out,
                'no mount leaked into the invoking namespace')
    check.equal(s.step('token').out, 'MAINTENANCE-WRITE', 'the chroot wrote the selected BE')
    check.equal(s.step('cache').out, 'ORIGINAL-CACHE-BYTES', 'temporary pool cache not persisted')
    check.equal(s.step('inode-after').out, s.step('inode-before').out, 'pool cache inode unchanged')
    run_token = s.step('run-token')
    check(run_token.rc != 0 and 'No such file' in run_token.err,
          f'/run was private: rc {run_token.rc} {run_token.err!r}')
    check.equal(s.step('mounted').out.strip(), 'no', 'e2ea/maintenance unmounted after maintenance')

    replicate = s.step('replicate')
    check(replicate.rc == 0 and 'send=0 receive=0' in replicate.err,
          f'secondary fixture stream: {replicate.err[-300:]!r}')
    pair = s.step('pair').json
    check.equal((pair['schema_version'], pair['mode']), (1, 'applied'), 'pair applied envelope')
    refused = s.step('secondary')
    check(refused.rc != 0, 'chroot of a paired secondary refused')
    check.contains(refused.err, 'secondary', 'secondary refusal cause')
    before, after = s.observe('before-refusal'), s.observe('after-refusal')
    check.equal(after.datasets, before.datasets, 'refusal left datasets unchanged')
    check.equal(after.pools, before.pools, 'refusal left pools unchanged')
    for name in ('e2ea/maintenance', 'e2eb/maintenance'):
        check.equal(after.properties(name), before.properties(name), f'refusal left {name} properties unchanged')
    check.equal(after.mounts, before.mounts, 'refusal left mounts unchanged')
    check(s.step('secondary-ran').rc != 0, 'the refused command never ran on the secondary')
    check.contains(s.step('secondary-root').out, 'etc', 'secondary BE content mounted for the check')
