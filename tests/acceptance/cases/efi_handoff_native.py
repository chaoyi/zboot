"""EFI-HANDOFF-NATIVE: OVMF boots the neutral Menu stick twice. First, A (the
default, not booted) has a canmount=on /var child, so the Menu does not count
down, refuses to boot clean B (naming A's child) and still boots A (stage 3). Booted A mounts only its own /var, the way a stock Debian boot
does, and repairs the child to noauto. The second Menu then boots B with its
saved cmdline (stage 5), which mounts only B's /var plus the cross-pool home
tree, read-only. The real root/kernel pair is discovered without a marker,
while a separate real root with an unknown zboot role remains blocked. No
extra boot is needed."""
import re

from host.case import Boot
from host.console import last_listing
from host.lifecycle import prop

ID = 'EFI-HANDOFF-NATIVE'
GROUP = 'efi'
SECONDS = 3600
DISKS = {'A': 2, 'B': 2, 'D': 2}
BOOTS = [Boot(1), Boot(2, efi=True, target=3, extra={'build': 'neutral'}),
         Boot(4, efi=True, target=5, extra={'build': 'neutral'})]

ON_CHILD = 'e2ea/BE/proof/var'
UNKNOWN = 'e2ea/BE/unknown'
UNKNOWN_ROLE = 'zboot:future-discovery'


def menu_number(text, dataset):
    numbers = re.findall(r'(?m)^\s*(\d+): ' + re.escape(dataset) + r'(?:\s|$)', last_listing(text))
    if len(numbers) != 1:
        raise ValueError(f'expected one native menu row for {dataset}, found {numbers}')
    return numbers[0]


def stage_2(console):
    ready = console.ready()
    console.menu('unknown-refused', f'boot {UNKNOWN} -v')
    console.menu('refused', f'boot {menu_number(ready, "e2eb/BE/proof")} -v')
    console.menu('select', f'boot {menu_number(ready, "e2ea/BE/proof")} -v', until=('ZBOOT_HANDOFF_LOAD',))


def stage_4(console):
    ready = console.ready()
    console.menu('select', f'boot {menu_number(ready, "e2eb/BE/proof")} -v', until=('ZBOOT_HANDOFF_LOAD',))


def menu_rows(menu):
    return [f'{n}: {text}' for n, text in re.findall(r'(?m)^\s*(\d+): (\S+.*?)\s*$', last_listing(menu.step('ready').out))]


def dataset_row(menu, dataset):
    prefix = menu_number(menu.step('ready').out, dataset) + ': ' + dataset
    return next(row for row in menu_rows(menu) if row.startswith(prefix))


def target_cmdline(check, target, root, stage):
    args = target.step('cmdline').out.split()
    check.equal([a for a in args if a.startswith('root=')], [f'root=ZFS={root}'], 'one root= for the selected BE')
    check('boot=zfs' in args, f'boot=zfs in {args}')
    check('ro' in args and 'rw' not in args, f'read-only root in {args}')
    check(not any(a.startswith('zboot.recovery=') for a in args), 'no recovery flag in the target cmdline')
    # These hand-made BEs have no /etc/hostid, so the menu adopts no identity
    # and passes none (an adopted one is checked by the deploy cases).
    hostids = [a for a in args if any(k in a for k in ('spl_hostid', 'zfs.force', 'zfs_force', 'zfsforce'))]
    check.equal(hostids, [], 'no spl.spl_hostid or force alias without an adopted identity')
    # The BE's saved zboot:cmdline arrives.
    for arg in ('console=ttyS0,115200', 'zt.case=EFI-HANDOFF-NATIVE', f'zt.stage={stage}'):
        check(arg in args, f'saved cmdline argument {arg} arrives')
    check(not any(a.startswith('zboot.trace=') for a in args), 'the handoff appends no trace record')


def verdict(ev, check):
    setup = ev.stage(1).observe('setup')
    check.equal(prop(setup, UNKNOWN, 'mountpoint'), '/', 'unknown-role clone retains root shape')
    check.equal(prop(setup, UNKNOWN, 'canmount'), 'noauto', 'unknown-role clone creates no automount hazard')
    check.equal(prop(setup, UNKNOWN, UNKNOWN_ROLE), 'fenced', 'unknown role is independently observed')
    check.equal(prop(setup, UNKNOWN, 'origin'), 'e2ea/BE/proof@discovery', 'unknown-role root clones the real boot assets')
    # First Menu: A's canmount=on child blocks B and the countdown, never A.
    menu = ev.stage(2)
    rows = menu_rows(menu)
    check.equal(len(rows), 3, 'first Menu retains two real roots and the refused unknown-role root')
    check.equal(dataset_row(menu, 'e2ea/BE/proof').split(': ', 1)[1],
                'e2ea/BE/proof [default]  eligible', 'marker-free A is eligible with real kernel assets')
    b_row = dataset_row(menu, 'e2eb/BE/proof')
    check('blocked: ' in b_row and ON_CHILD in b_row, f"B is blocked only by A's automount hazard: {b_row}")
    unknown_row = dataset_row(menu, UNKNOWN)
    check('blocked: ' in unknown_row and UNKNOWN_ROLE in unknown_row and '[default]' not in unknown_row,
          f'unknown role stays visibly fenced and is not a default: {unknown_row}')
    ready = menu.step('ready').out
    check('boot/vmlinuz-proof' in ready and 'boot/initrd.img-proof' in ready,
          'marker-free root lists its actual kernel/initrd pair')
    unknown = menu.step('unknown-refused').out
    check(UNKNOWN_ROLE in unknown and 'blocked:' in unknown, f'full-named unknown-role boot refuses its exact role: {unknown}')
    check('ZBOOT_HANDOFF_LOAD' not in unknown, 'unknown-role refusal never loads a kernel')
    off = [line for line in menu.step('ready').out.splitlines() if line.startswith('Automatic boot is off:')]
    check(len(off) == 1 and ON_CHILD in off[0], f'first Menu: the countdown is off, naming {ON_CHILD}: {off}')
    refused = menu.step('refused').out
    check.contains(refused, 'boot environment e2eb/BE/proof is blocked:', 'selecting B is refused')
    check.contains(refused, ON_CHILD, 'the refusal names the canmount=on child')
    check('ZBOOT_HANDOFF_LOAD' not in refused, 'the refused selection loads nothing')
    check.contains(menu.step('select').out, 'ZBOOT_HANDOFF_LOAD', 'the displayed A entry still loads')

    # Booted A mounts its own child; B's noauto child stays unmounted.
    a = ev.stage(3)
    target_cmdline(check, a, 'e2ea/BE/proof', 3)
    check.equal(a.step('var-token').out.strip(), 'ZFS-E2E-VAR-A', 'booted A sees its own /var')
    mounts = a.observe('target').mounts
    check.equal(mounts.get('/selected-root'), 'e2ea/BE/proof', 'A is the root')
    check.equal(mounts.get('/selected-root/var'), ON_CHILD, "A's /var child mounts when A boots")
    check('e2eb/BE/proof/var' not in mounts.values(), f"B's /var child stays unmounted in A: {mounts}")
    check.equal(a.step('repaired').out.split(), ['noauto', 'local'], "A's child repaired to noauto")

    # Second Menu: nothing blocks B now.
    menu = ev.stage(4)
    check.equal(len(menu_rows(menu)), 3, 'second Menu retains the same native root membership')
    for dataset, default in [('e2ea/BE/proof', ' [default]'), ('e2eb/BE/proof', '')]:
        check.equal(dataset_row(menu, dataset).split(': ', 1)[1], f'{dataset}{default}  eligible',
                    f'second Menu: marker-free {dataset} is eligible')
    check(UNKNOWN_ROLE in dataset_row(menu, UNKNOWN) and 'blocked: ' in dataset_row(menu, UNKNOWN),
          'unknown role remains fenced after the unrelated child repair')
    check('canmount=on' not in menu.step('ready').out, 'second Menu reports no canmount=on child')
    check.contains(menu.step('select').out, 'ZBOOT_HANDOFF_LOAD', 'the displayed B entry loads')

    target = ev.stage(5)
    target_cmdline(check, target, 'e2eb/BE/proof', 5)
    check.equal(target.step('token').out.strip(), 'ZFS-E2E-HANDOFF-TOKEN', 'selected root token')
    check.equal(target.step('var-token').out.strip(), 'ZFS-E2E-VAR-B', 'booted B sees its own /var')
    observed = target.observe('target')
    mounts = observed.mounts
    for path, mounted_source in (('/selected-root', 'e2eb/BE/proof'), ('/selected-root/var', 'e2eb/BE/proof/var'),
                         ('/selected-root/home', 'e2ea/home'), ('/selected-root/home/user', 'e2eb/home/user')):
        check.equal(mounts.get(path), mounted_source, f'{path} mounted from {mounted_source}')
    check(ON_CHILD not in mounts.values(), f"A's /var child stays unmounted in B: {mounts}")
    ro = {line.split()[4]: line.split()[5] for line in (observed.path / 'mountinfo').read_text().splitlines()}
    for path in ('/selected-root', '/selected-root/var', '/selected-root/home', '/selected-root/home/user'):
        check(ro.get(path, '').split(',')[0] == 'ro', f'{path} mounted ro')
    check.equal(target.step('base-token').out.strip(), 'ZFS-E2E-HOME-BASE', 'A home token (no shadowing)')
    check.equal(target.step('child-token').out.strip(), 'ZFS-E2E-HOME-CHILD', 'B child token (no shadowing)')
    for pool in ('e2ea', 'e2eb'):
        check.equal(observed.pools.get(pool, {}).get('readonly'), 'on', f'{pool} imported read-only in the target')
