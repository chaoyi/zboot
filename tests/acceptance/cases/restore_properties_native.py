"""Native OpenZFS facts behind zboot::restore and its fake: staging and
return dataset by dataset through Debian's own `zfs send -w | zfs receive`."""
from host.case import Boot

ID = 'RESTORE-PROPERTIES-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]

SNAP = 'zboot-restore-e2e0e2e0e2e0e2e0'
STAGING = 'e2eb/zboot-restore-e2e0e2e0e2e0e2e0'
PLACEMENT = 'rp-e2e-placement'
WRITE_TIME = {'copies', 'checksum', 'compression', 'recordsize', 'dnodesize', 'dedup',
              'special_small_blocks', 'redundant_metadata'}
# (step prefix, source, destination): restore's copies, parents first.
COPIES = (
    ('stage-rp', 'e2ea/rp', f'{STAGING}/rp'),
    ('stage-rp-child', 'e2ea/rp/child', f'{STAGING}/rp/child'),
    ('stage-rp-secret', 'e2ea/rp-secret', f'{STAGING}/rp-secret'),
    ('stage-rp-inner', 'e2ea/rp-secret/inner', f'{STAGING}/rp-secret/inner'),
    ('return-rp', f'{STAGING}/rp', 'e2ea/rp-back/rp'),
    ('return-rp-child', f'{STAGING}/rp/child', 'e2ea/rp-back/rp/child'),
    ('return-rp-secret', f'{STAGING}/rp-secret', 'e2ea/rp-back/rp-secret'),
    ('return-rp-inner', f'{STAGING}/rp-secret/inner', 'e2ea/rp-back/rp-secret/inner'),
)


def tree(stage, name, check):
    """name -> property -> (value, source, received), and snapshot -> guid."""
    props = {}
    for line in stage.step(f'{name}-props').out.splitlines():
        fields = line.split('\t')
        if check.equal(len(fields), 5, f'{name}: zfs get line has 5 fields ({line!r})'):
            props.setdefault(fields[0], {})[fields[1]] = tuple(fields[2:])
    snaps = {}
    for line in stage.step(f'{name}-snaps').out.splitlines():
        check('\t' in line, f'{name}: zfs list line splits on a tab ({line!r})')
        snap, _, guid = line.partition('\t')
        snaps[snap] = guid
    return props, snaps


def same_snapshots(src, src_root, dst, dst_root):
    """Every snapshot under SRC_ROOT has its GUID at the same name under DST_ROOT."""
    compared = 0
    for name, guid in src.items():
        if not name.startswith(src_root) or name[len(src_root)] not in '/@':
            continue
        if dst.get(dst_root + name[len(src_root):]) != guid:
            return False
        compared += 1
    return compared > 0


def verdict(ev, check):
    s = ev.stage(1)
    for name in ('create-rp', 'create-rp-child', 'create-rp-secret', 'prompt-rp-secret',
                 'create-rp-inner', 'unload-rp-secret', 'early-rp', 'snapshot-rp',
                 'early-rp-secret', 'snapshot-rp-secret', 'create-staging', 'create-back',
                 'zfs-version'):
        check.equal(s.step(name).rc, 0, f'{name} exits 0')
    for prefix, source, destination in COPIES:
        full = s.step(f'{prefix}-full')
        check.equal(full.argv[4], f'-w {source}@early', f'{prefix}: full stream of the first snapshot')
        receive = full.argv[5:]
        check.equal(receive[:4] + receive[-1:], ['receive', '-u', '-o', 'canmount=off', destination],
                    f'{prefix}: a new copy is created inactive')
        options = receive[4:-1]
        check(len(options) % 2 == 0 and all(flag == '-o' for flag in options[::2])
              and {value.split('=')[0] for value in options[1::2]} <= WRITE_TIME,
              f'{prefix}: only write-time values at creation: {options}')
        incremental = s.step(f'{prefix}-incremental')
        check.equal(incremental.argv[4:], [f'-w -I {source}@early {source}@{SNAP}', 'receive', '-u', destination],
                    f'{prefix}: one incremental to the boundary, no property')
        for step in (full, incremental):
            check(step.rc == 0 and 'send=0 receive=0' in step.err,
                  f'{prefix}: stock receive completes: rc {step.rc} {step.err[-300:]!r}')
        check.equal(s.step(f'{prefix}-fence').rc, 0, f'{prefix}: local fences set at once')

    src_plain = tree(s, 'source-plain', check)[1]
    src_secret = tree(s, 'source-secret', check)[1]
    staged, staged_snaps = tree(s, 'staged', check)
    returned, returned_snaps = tree(s, 'returned', check)

    def get(t, name, prop):
        return t[name][prop]

    sp, sc = f'{STAGING}/rp', f'{STAGING}/rp/child'
    ss, si = f'{STAGING}/rp-secret', f'{STAGING}/rp-secret/inner'
    bp, bc = 'e2ea/rp-back/rp', 'e2ea/rp-back/rp/child'
    bs, bi = 'e2ea/rp-back/rp-secret', 'e2ea/rp-back/rp-secret/inner'

    for observed, parent, members in ((staged, STAGING, (sp, sc, ss, si)),
                                      (returned, 'e2ea/rp-back', (bp, bc, bs, bi))):
        for name in (parent, *members):
            for prop, value in (('canmount', 'off'), ('mountpoint', 'none'),
                                ('readonly', 'on'), ('volmode', 'none')):
                check.equal(get(observed, name, prop), (value, 'local', '-'),
                            f'{name}: {prop} is local {value}, with no received layer')
        for name in members:
            # No property travels: nothing received, no user property, no
            # zboot record; the copy's values are its own `-o` ones.
            for prop in ('zboot:placement', 'zfs-e2e:note'):
                check.equal(get(observed, name, prop), ('-', '-', '-'), f'{name}: {prop} not carried')
            for prop, (value, source, received) in observed[name].items():
                check.equal(received, '-', f'{name}: {prop} has no received value')
        for name, top in ((members[2], members[2]), (members[3], members[3])):
            check.equal(get(observed, name, 'encryptionroot')[0], top,
                        f'{name}: a new raw copy is its own encryption root')
            check.equal(get(observed, name, 'keylocation')[:2], ('prompt', 'local'),
                        f'{name}: keylocation local prompt')
            check.equal(get(observed, name, 'keyformat')[0], 'raw', f'{name}: keyformat raw')
            check.equal(get(observed, name, 'keystatus')[0], 'unavailable', f'{name}: no key loaded')
        check.equal(get(observed, members[0], 'compression')[:2], ('zstd', 'local'),
                    f'{members[0]}: the write-time value is local from creation')
        check.equal(get(observed, members[1], 'compression')[:2], ('zstd', 'local'),
                    f'{members[1]}: an inherited write-time value is local from creation too')
    for label, t in (('staged', staged), ('returned', returned)):
        for name in t:
            check(get(t, name, 'mounted')[0] != 'yes', f'{label} {name} unmounted')
            check.equal(get(t, name, 'receive_resume_token')[0], '-', f'{label} {name} receive complete')
    check(same_snapshots(src_plain, 'e2ea/rp', staged_snaps, sp), 'staging keeps rp snapshot guids')
    check(same_snapshots(src_secret, 'e2ea/rp-secret', staged_snaps, ss), 'staging keeps rp-secret snapshot guids')
    check(same_snapshots(staged_snaps, sp, returned_snaps, bp), 'return keeps rp snapshot guids')
    check(same_snapshots(staged_snaps, ss, returned_snaps, bs), 'return keeps rp-secret snapshot guids')

    backup = s.step('backup-flag')
    check.equal(backup.argv[4:], [f'-w -R -b {ss}@{SNAP}', 'receive', '-u', 'e2ea/rp-backup-flag'],
                'backup-flag probe argv')
    check(backup.rc != 0 and 'send=0' in backup.err and 'receive=0' not in backup.err,
          f'send -R -b from a staged encryption root is not received: {backup.err[-300:]!r}')
