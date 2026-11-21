"""zboot pairs on Debian's own OpenZFS: copied properties, reviewed pruning,
rename by GUID, sync abandon, the wrapping proof and a dormant zvol."""
from host.case import Boot
from host.lifecycle import envelope, holds, identity, no_operation, pair, prop, refused, snapshots, source

ID = 'STOCK-SYNC-NATIVE'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
W, C = 'e2ea/stock', 'e2eb/stock'
VAULT, LEAF, COPY = 'e2ea/vault', 'e2ea/vault/home', 'e2eb/home'
VOL, VCOPY = 'e2ea/stockvol', 'e2eb/stockvol'


def local(check, obs, name, key, value, what):
    check.equal((prop(obs, name, key), source(obs, name, key)), (value, 'local'), f'{what}: {name} {key}')


def fenced(check, obs, name, what):
    for key, value in (('readonly', 'on'), ('canmount', 'noauto')):
        local(check, obs, name, key, value, f'{what}: fenced')
    check.equal(prop(obs, name, 'mounted'), 'no', f'{what}: {name} unmounted')


def inert(check, obs, name, what):
    """Mid-transfer: read-only, unmounted and never mounting by itself."""
    check.equal(prop(obs, name, 'readonly'), 'on', f'{what}: {name} read-only')
    check.equal(prop(obs, name, 'mounted'), 'no', f'{what}: {name} unmounted')
    check(prop(obs, name, 'canmount') in ('off', 'noauto'), f'{what}: {name} canmount is not on')


def mirrored(check, obs, source_name, copy, what):
    """Every snapshot of the working copy is on the copy with its GUID and name."""
    for name in snapshots(obs, source_name + '@'):
        got = obs.datasets.get(copy + name[len(source_name):])
        check.equal(got and got['guid'], obs.datasets[name]['guid'], f'{what}: {name} mirrored on {copy}')


def zsnaps(obs, dataset):
    return snapshots(obs, dataset + '@zsnap_')


def verdict(ev, check):
    s = ev.stage(1)
    pair_id = envelope(check, s.step('pair'), 'applied', 'pair')['result']['operation_id']

    # Copied properties are local on the copy; copies=2 governed its blocks.
    synced = envelope(check, s.step('properties-sync'), 'applied', 'sync with copied properties')['result']
    check.equal(synced.get('pair_id'), pair_id, 'the sync names its pair')
    before, after = s.observe('properties-before'), s.observe('properties-after')
    check.equal(source(before, C, 'copies'), 'default', 'the copy starts with the default copies')
    for key, value in (('copies', '2'), ('e2e:stock', 'working'), ('zsnap:policy', 'e2e'),
                       ('refquota', str(256 << 20))):
        local(check, after, C, key, value, f'copied {key}')
    space = dict(line.split('\t') for line in s.step('copy-space').out.splitlines())
    referenced, logical = int(space.get('referenced', 0)), int(space.get('logicalreferenced', 1))
    check(referenced >= 1.8 * logical,
          f'received blocks were written with copies=2: referenced {referenced}, logical {logical}')
    check.equal(identity(after, C), identity(before, C), 'the sync keeps the copy incarnation')
    fenced(check, after, C, 'after the property sync')
    mirrored(check, after, W, C, 'after the property sync')
    check.equal(pair(after, W)['role'], 'primary', 'the working copy stays primary')
    check.equal(pair(after, C)['role'], 'secondary', 'the copy stays secondary')

    # Pruning: refused on the fenced copy, done on the working copy.
    refused(check, s.step('prune-copy'), f'{C} is read-only', 'zsnap prune on the fenced copy')
    check.contains(s.step('dormant').out, f'{C}: policy e2e is dormant on this fenced pair copy',
                   'the copied policy is dormant on the fenced copy')
    pruned = s.observe('pruned')
    gone = zsnaps(after, W)
    check.equal(len(gone), 1, f'one zsnap snapshot to prune on the working copy: {gone}')
    check.equal(zsnaps(pruned, W), [], 'zsnap prune deleted it on the working copy')
    pending = [C + name[len(W):] for name in gone]
    check.equal(zsnaps(pruned, C), pending, 'the copy still has it')

    preview = envelope(check, s.step('pending-preview'), 'preview', 'sync --dry-run')['result']
    entries = preview.get('entries', [])
    shown = [p['snapshot']['name'] for e in entries for p in (e.get('pending') or {}).get('snapshots', [])]
    check.equal(shown, pending, 'sync --dry-run shows the pending deletion')

    unattended = envelope(check, s.step('unattended'), 'applied', 'unattended sync')['result']
    check('deleted' not in unattended, f"an unattended sync deletes nothing: {unattended.get('deleted')}")
    check.equal([p['snapshot']['name'] for p in (unattended.get('pending') or {}).get('snapshots', [])],
                pending, 'the unattended sync reports the pending deletion')
    kept = s.observe('unattended')
    check.equal(zsnaps(kept, C), pending, 'the unattended sync keeps the snapshot on the copy')
    mirrored(check, kept, W, C, 'after the unattended sync')

    review = envelope(check, s.step('review-preview'), 'preview', 'sync --dry-run for review')
    reviewed = envelope(check, s.step('reviewed'), 'applied', 'sync --confirm')
    check.equal(reviewed.get('token'), review.get('token'), 'sync --confirm applied the reviewed token')
    check.equal([p['name'] for p in reviewed['result'].get('deleted', [])], pending,
                'the reviewed sync deleted exactly the pending deletion')
    deleted = s.observe('reviewed')
    check.equal(zsnaps(deleted, C), [], 'the copy no longer has it')
    check('pending' not in reviewed['result'], 'nothing is pending after the review')
    mirrored(check, deleted, W, C, 'after the reviewed sync')
    # zboot keeps only its newest own boundary, which is the anchor.
    for name in (W, C):
        boundaries = snapshots(deleted, name + '@zboot_transfer_')
        check.equal(len(boundaries), 1, f'one zboot boundary on {name}: {boundaries}')
        for point in boundaries:
            check(f'zboot:anchor:{pair_id}' in holds(deleted, point), f'{point} is the held anchor')

    # A common snapshot renamed on the working copy, by GUID on the copy.
    renamed = envelope(check, s.step('renamed'), 'applied', 'sync after a rename')['result']
    check.equal(renamed.get('renamed'), [{'from': C + '@base', 'to': C + '@base-renamed'}],
                'the copy renames the common snapshot to the working copy name')
    after_rename = s.observe('renamed')
    check(C + '@base' not in after_rename.datasets, 'the old name is gone on the copy')
    check.equal(after_rename.datasets.get(C + '@base-renamed', {}).get('guid'),
                after_rename.datasets.get(W + '@base-renamed', {}).get('guid'), 'the renamed snapshot keeps its GUID')
    mirrored(check, after_rename, W, C, 'after the rename')

    # An interrupted sync, abandoned; the next sync continues.
    interrupted = s.step('interrupted')
    check(interrupted.rc != 0, 'the sync interrupted at its receive fails')
    check.contains(interrupted.err, 'was interrupted', 'the failure names the interrupted sync')
    cut = s.cut('interrupted-receive')
    check.equal(cut[:1], ['receive'], f'the injected failure hit the stock receive: {cut}')
    check.equal(cut[-1:], [C], f'the receive went into the copy: {cut}')
    record = s.step('interrupted-record').out.strip()
    check(record not in ('', '-'), 'the interrupted sync left its operation record')
    stopped = s.observe('interrupted')
    inert(check, stopped, C, 'after the interruption')
    abandon_preview = envelope(check, s.step('abandon-preview'), 'preview', 'abandon preview')
    abandoned_step = s.step('abandon')
    abandoned = envelope(check, abandoned_step, 'applied', 'abandon')
    check.equal(abandoned.get('token'), abandon_preview.get('token'), 'abandon applied the reviewed token')
    check.contains(abandoned_step.err, 'stays fenced with the snapshots it received',
                   'abandon keeps what the copy received')
    left = s.observe('abandoned')
    check.equal(s.step('abandoned-record').out.strip(), '-', 'abandon releases the pool operation slot')
    check.equal(identity(left, C), identity(stopped, C), 'abandon keeps the copy incarnation')
    check.equal(snapshots(left, C + '@'), snapshots(stopped, C + '@'), 'abandon keeps every received snapshot')
    fenced(check, left, C, 'after abandon')
    check(not any(tag.startswith('zboot:transfer:') for point in snapshots(left)
                  for tag in holds(left, point)), 'abandon releases the transfer holds')
    envelope(check, s.step('continued'), 'applied', 'the next sync')
    continued = s.observe('continued')
    mirrored(check, continued, W, C, 'after the next sync')
    fenced(check, continued, C, 'after the next sync')
    no_operation(check, continued, 'after the next sync')

    # The encrypted leaf: bootstrap, primary, sync back, refusal after a key change.
    boot = envelope(check, s.step('bootstrap'), 'applied', 'bootstrap of the encrypted leaf')['result']
    check(isinstance(boot.get('bootstrapped'), str), 'the bootstrap pairs the new copy')
    made = s.observe('bootstrapped')
    check.equal(prop(made, LEAF, 'encryptionroot'), VAULT, f'{LEAF} takes its key from {VAULT}')
    check.equal(prop(made, COPY, 'encryptionroot'), COPY, 'the new copy is its own encryption root')
    local(check, made, COPY, 'keylocation', 'file:///run/stock-pass', "the source root's key location")
    for key, value in (('compression', 'zstd'), ('e2e:installer', 'kept')):
        local(check, made, COPY, key, value, f'copied {key}')
    fenced(check, made, COPY, 'the new copy')
    wrapping = {}
    for line in s.step('wrapping').out.splitlines():
        name, key, value, _ = line.split('\t')
        wrapping.setdefault(name, {})[key] = value
    for key in ('keyformat', 'pbkdf2salt', 'pbkdf2iters'):
        check.equal(wrapping.get(COPY, {}).get(key), wrapping.get(VAULT, {}).get(key),
                    f'the copy is wrapped like {VAULT}: {key}')
    check.equal(wrapping.get(COPY, {}).get('keyformat'), 'passphrase', 'a passphrase wrapping')

    switched = envelope(check, s.step('primary'), 'applied', 'primary to the copy')['result']
    check.equal(switched.get('mode'), 'catch-up', 'primary catches the copy up')
    after_switch = s.observe('switched')
    check.equal(pair(after_switch, COPY)['role'], 'primary', 'the copy is the working copy')
    check.equal(pair(after_switch, LEAF)['role'], 'secondary', 'the original leaf is the fenced copy')
    fenced(check, after_switch, LEAF, 'the original leaf after primary')

    back = envelope(check, s.step('back'), 'applied', 'sync back into the inheriting leaf')['result']
    check.equal(back.get('pair_id'), boot.get('bootstrapped'), 'the sync back uses the same pair')
    synced_back = s.observe('back')
    mirrored(check, synced_back, COPY, LEAF, 'after the sync back')
    check.equal(identity(synced_back, LEAF), identity(made, LEAF), 'the original leaf keeps its incarnation')
    check.equal(prop(synced_back, LEAF, 'encryptionroot'), VAULT, f'the original leaf still takes its key from {VAULT}')
    for key, value in (('compression', 'zstd'), ('e2e:installer', 'kept')):
        local(check, synced_back, LEAF, key, value, f'{key} stays local on the original leaf')

    changed = s.step('changed')
    check(changed.rc != 0, 'the sync after a key change is refused')
    check.contains(changed.err, "passphrase wrapping differs", 'the refusal names the changed wrapping')
    check.contains(changed.err, 'would open with neither key', 'the refusal says why')
    before_change, after_change = s.observe('changed-before'), s.observe('changed-after')
    check.equal({n: after_change.datasets[n]['guid'] for n in snapshots(after_change, LEAF + '@')},
                {n: before_change.datasets[n]['guid'] for n in snapshots(before_change, LEAF + '@')},
                'no data reached the original leaf')
    check.equal(identity(after_change, LEAF), identity(before_change, LEAF), 'the original leaf is untouched')
    inert(check, after_change, LEAF, 'after the refused sync')
    check.equal(s.step('changed-record').out.strip(), '-',
                'the sync was refused at admission and recorded nothing')
    check.equal(s.step('home-keystatus').out.split(), [VAULT, 'available'],
                f'the original leaf opens with the key of {VAULT}')
    check.equal(s.step('home-read').out, 'back', 'the original leaf holds the data of the sync back')

    # A zvol pair: the fenced copy has no device, also after an import.
    vol = envelope(check, s.step('volume-sync'), 'applied', 'zvol bootstrap')['result']
    check(isinstance(vol.get('bootstrapped'), str), 'the zvol copy is paired')
    paired = s.observe('volume-paired')
    local(check, paired, VCOPY, 'volmode', 'none', 'a fenced zvol copy at rest')
    local(check, paired, VCOPY, 'readonly', 'on', 'a fenced zvol copy at rest')
    mirrored(check, paired, VOL, VCOPY, 'zvol bootstrap')
    for step in ('volume-devices', 'volume-devices-imported'):
        devices = [line.split(' ', 1) for line in s.step(step).out.splitlines()]
        check.equal([d[1] for d in devices], [VOL], f'{step}: only the working zvol has a device: {devices}')
        check(all(d[0].startswith('/dev/zd') for d in devices), f'{step}: zvol device paths: {devices}')
    final = s.observe('final')
    local(check, final, VCOPY, 'volmode', 'none', 'the zvol copy after an import')
    no_operation(check, final, 'at the end')
