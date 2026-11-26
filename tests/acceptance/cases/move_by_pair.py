"""Cross-pool move through sync, primary, unpair and drop, leaf by leaf,
including boot policy."""
from host.case import Boot
from host.identity import pool_prop, under
from host.lifecycle import envelope, holds, identity, no_operation, pair, prop, source, snapshots

ID = 'MOVE-BY-PAIR'
GROUP = 'small'
SECONDS = 900
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1)]
# (label, source leaf, destination leaf, boot environment)
MOVES = (
    ('data', 'e2ea/move-pair-data', 'e2eb/move-pair-data', False),
    ('be', 'e2ea/move-pair-be', 'e2eb/move-pair-be', True),
    ('tree-data', 'e2ea/move-pair-tree/data', 'e2eb/move-pair-tree/data', False),
    ('tree-be', 'e2ea/move-pair-tree/be', 'e2eb/move-pair-tree/be', True),
)


def verdict(ev, check):
    stage = ev.stage(1)
    for label, src, dst, boot in MOVES:
        before, synced = stage.observe(f'{label}-before'), stage.observe(f'{label}-synced')
        promoted = stage.observe(f'{label}-promoted')
        unpaired, after = stage.observe(f'{label}-unpaired'), stage.observe(f'{label}-after')
        for verb in ('sync', 'primary', 'unpair', 'drop'):
            envelope(check, stage.step(f'{label}-{verb}'), 'applied', f'{label}: {verb}')
        check.equal(pair(synced, dst)['role'], 'secondary', f'{label}: sync leaves a secondary')
        check.equal(pair(promoted, dst)['role'], 'primary', f'{label}: destination promoted')
        check.equal(pair(promoted, src)['role'], 'secondary', f'{label}: source safely demoted')
        check.equal(identity(synced, src), identity(before, src), f'{label}: source identity')
        check(identity(synced, dst) != identity(before, src), f'{label}: native copy')
        check.equal(identity(after, dst), identity(synced, dst), f'{label}: destination identity')
        for key in ('mountpoint', 'canmount', 'readonly'):
            check.equal(prop(after, dst, key), prop(before, src, key), f'{label}: final {key}')
        check.equal(stage.step(f'{label}-read').out, label, f'{label}: payload')
        for endpoint in (src, dst):
            check.equal(prop(unpaired, endpoint, 'zboot:pair'), '-', f'{label}: unpaired {endpoint}')
        for snapshot in snapshots(synced, src + '@'):
            counterpart = dst + snapshot[len(src):]
            check.equal(synced.datasets[counterpart]['guid'], synced.datasets[snapshot]['guid'],
                        f'{label}: raw snapshot GUID {snapshot}')
            check(not any(tag.startswith('zboot:anchor:') for tag in holds(unpaired, snapshot)),
                  f'{label}: source anchor released {snapshot}')
            check(not any(tag.startswith('zboot:anchor:') for tag in holds(unpaired, counterpart)),
                  f'{label}: destination anchor released {counterpart}')
        check.equal(under(after.datasets, src), [], f'{label}: source retired')
        no_operation(check, after, f'{label}: recipe complete')
        if boot:
            check.equal(prop(after, dst, 'mountpoint'), '/', f'{label}: native root shape carried')
            check.equal(source(after, dst, 'mountpoint'), 'local', f'{label}: root placement materialized locally')
            check.equal(prop(after, dst, 'zboot:cmdline'), f'console=ttyS0 move_pair={label}',
                        f'{label}: kernel additions carried')
            check.equal(source(after, dst, 'zboot:cmdline'), 'local', f'{label}: kernel additions trusted')
            check.equal(pool_prop(after, 'e2eb', 'bootfs'), dst, f'{label}: destination default')
            check.equal(pool_prop(after, 'e2ea', 'bootfs'), '-', f'{label}: old default cleared')
            check.equal(stage.step(f'{label}-kernel').out, 'ZFS-E2E-DISCOVERY-KERNEL',
                        f'{label}: native default retains the discovery kernel companion')
            check.equal(stage.step(f'{label}-initrd').out, 'ZFS-E2E-DISCOVERY-INITRD',
                        f'{label}: native default retains the discovery initrd companion')
    # The tree moved leaf by leaf into the destination's own container.
    envelope(check, stage.step('tree-container-drop'), 'applied', 'tree: drop the emptied source container')
    final = stage.observe('tree-after')
    check.equal(under(final.datasets, 'e2ea/move-pair-tree'), [], 'tree: source container retired')
    check.equal([n for n in under(final.datasets, 'e2eb/move-pair-tree') if '@' not in n],
                ['e2eb/move-pair-tree', 'e2eb/move-pair-tree/be', 'e2eb/move-pair-tree/data'],
                'tree: both leaves live in the destination container')
    no_operation(check, final, 'tree: recipe complete')
