"""Native probe for the stock-receive design: Debian's own OpenZFS only.

The claims are documented in docs/DESIGN.md, "Stock receive properties".
Each check names its claim; a failure requires review of the stock pipeline.
"""
from host.case import Boot

ID = 'STOCK-RECEIVE-PROBE'
GROUP = 'small'
SECONDS = 600
DISKS = {'A': 2, 'B': 2}
BOOTS = [Boot(1)]
STAGE = 'e2ea/zboot-receive-probe'


def rows(check, stage, name):
    """property -> (value, source, received) from `zfs get -o property,value,source,received`."""
    step = stage.step(name)
    check.equal(step.rc, 0, f'{name}: property query succeeds')
    out = {}
    for line in step.out.splitlines():
        fields = line.split('\t')
        if check.equal(len(fields), 4, f'{name}: four columns: {line!r}'):
            out[fields[0]] = tuple(fields[1:])
    return out


def local(props):
    return {key: value for key, (value, source, _) in props.items() if source == 'local'}


def received(props):
    return {key: value for key, (_, _, value) in props.items() if value != '-'}


def first_sync_back(check, s):
    before, after = rows(check, s, 'inst-before'), rows(check, s, 'inst-after')
    check.equal(s.step('inst-back').rc, 0, 'P1: property-free incremental into an installer-made dataset succeeds')
    check.equal(local(after), local(before), 'P1: every local value survives the first sync back')
    check.equal(received(after), received(before), 'P1: the received layer is unchanged')
    for key, value in (('compression', 'zstd'), ('zfs-e2e:note', 'keep'), ('canmount', 'noauto'),
                       ('readonly', 'on'), ('mountpoint', '/mnt/sr-inst')):
        check.equal(local(after).get(key), value, f'P1: local {key} kept')
    check.equal(s.step('inst-data').out.strip(), 'two', 'P1: the data arrived')
    ctl_before, ctl_after = rows(check, s, 'ctl-before'), rows(check, s, 'ctl-after')
    check.equal(local(ctl_before).get('zfs-e2e:note'), 'keep', 'control: local user property before')
    if s.step('ctl-back').rc == 0:
        check(local(ctl_after).get('zfs-e2e:note') != 'keep' or local(ctl_after).get('readonly') != 'on',
              f'control: a property-carrying first receive clears local values: {local(ctl_after)}')


def new_members(check, s):
    for name in ('new-one', 'new-two', 'new-three'):
        check.equal(s.step(name).rc, 0, f'P2: {name} receive succeeds')
    one, two, three = (rows(check, s, f'new-{n}-props') for n in ('one', 'two', 'three'))
    for name, props in (('one', one), ('two', two), ('three', three)):
        check.equal(received(props), {}, f'P2: {name} has no received values')
        for key, value in (('readonly', 'on'), ('mountpoint', 'none'), ('volmode', 'none')):
            check.equal(props.get(key, ('', ''))[:2], (value, f'inherited from {STAGE}'),
                        f'P2: {name} inherits {key} from the container')
    check.equal(three.get('canmount', ('',))[0], 'on', 'P2: canmount does not inherit; default on without -o')
    check.equal(local(one).get('canmount'), 'noauto', 'P2: -o canmount=noauto is local')
    check.equal(local(two).get('copies'), '2', 'P2: -o copies=2 is local')
    space = dict(line.split('\t') for line in s.step('new-space').out.splitlines())
    ref1, ref2 = int(space[f'{STAGE}/one']), int(space[f'{STAGE}/two'])
    check(ref2 >= 1.8 * ref1, f'P2: copies=2 governed the received blocks: {ref1} vs {ref2}')
    check.equal(s.step('new-snapprop').out.strip(), '-', 'P2: snapshot user properties are not carried')


def renames(check, s):
    bare, fenced = rows(check, s, 'rename-bare-props'), rows(check, s, 'rename-fenced-props')
    check.equal(bare.get('readonly', ('',))[0], 'off', 'P3: an inherited fence ends at the rename out')
    for key, value in (('readonly', 'on'), ('mountpoint', 'none'), ('canmount', 'noauto')):
        check.equal(local(fenced).get(key), value, f'P3: local {key} survives the rename')
    check(s.step('ren-collide').rc != 0, 'P4: a renamed source snapshot collides without -R')
    guids = dict(line.split('\t') for line in s.step('ren-guids').out.splitlines())
    check.equal(guids['e2eb/rcopy@s2-old'], guids['e2ea/rsrc@s2-old'], 'P4: renamed by GUID')
    check.equal(guids['e2eb/rcopy@s2'], guids['e2ea/rsrc@s2'], 'P4: the new snapshot then arrives')


def encryption(check, s):
    props = {}
    for line in s.step('enc-props').out.splitlines():
        name, key, value, source = line.split('\t')
        props[(name, key)] = (value, source)
    copy = f'{STAGE}/ecopy'
    check.equal(props.get((copy, 'encryptionroot'), ('',))[0], copy, 'P5: a raw copy of an inheriting leaf is its own root')
    check.equal(props.get((copy, 'keylocation')), ('prompt', 'local'), 'P5: with a local keylocation=prompt')
    check.equal(props.get(('e2eb/encrypted/child', 'encryptionroot'), ('',))[0], 'e2eb/encrypted',
                'P5: the source leaf inherits its key')
    check.equal(s.step('enc-proof').rc, 0, 'P5: load-key -n proves the file key')
    check.equal(s.step('enc-proof-status').out.strip(), 'unavailable', 'P5: load-key -n loads nothing')
    check.equal(s.step('enc-back').rc, 0, 'P6: raw incremental back into the inheriting leaf succeeds')
    opened = s.step('enc-back-open')
    check.equal(opened.rc, 0, f'P6: the inheriting leaf still opens with its root key: {opened.err[-300:]}')
    check.contains(opened.out, 'back', 'P6: and has the switched side\'s data')
    back, open2 = s.step('enc2-back'), s.step('enc2-open')
    check(back.rc != 0 or open2.rc != 0,
          f'P7: a key change on the sender cannot pass silently (receive {back.rc}, open {open2.rc})')


def volumes(check, s):
    count = {name: int(s.step(name).out.strip() or 0) for name in
             ('vol-before', 'vol-after-recv', 'vol-after-import', 'vol-at-rest', 'vol-active')}
    base = count['vol-before']
    for name in ('vol-after-recv', 'vol-after-import', 'vol-at-rest'):
        check.equal(count[name], base, f'P8: no zvol device ({name})')
    check.equal(count['vol-active'], base + 1, 'P8: activation adds the device')


def verdict(ev, check):
    s = ev.stage(1)
    check.equal(s.step('container').rc, 0, 'fenced container created')
    first_sync_back(check, s)
    new_members(check, s)
    renames(check, s)
    encryption(check, s)
    volumes(check, s)
