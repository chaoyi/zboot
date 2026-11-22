"""Shared host side of the GUIDED-* cases: Menu dialogues and verdict parts.

Stage 1 (guest/guided.sh) builds the fixture with the `neutral` build's own
kernel, zboot and UKI and a `zboot factory` root tar. Firmware stages then
drive the Menu console of that build's stick or of A's own ESP (the same
UKI, installed by the deploy and again by the restore, from the BE).
Each Menu shell body prints native facts; the verdict judges them here,
never inside the guest.
"""
import hashlib
import json
from pathlib import Path
import re

from host.console import FAILURES, MENU_PROMPT, ConsoleError, last_listing

HOSTID = '0174627a'
DISKS = {'A': 8, 'B': 16, 'D': 2}
ROOT_A, ROOT_B = 'e2ea/ROOT/be1', 'e2eb/ROOT/be1'
# The BE is one dataset; child and disabled are data leaves outside it, kept
# by the restore with scratch.
CHILD_A, SCRATCH_A = 'e2ea/guided-child', 'e2ea/scratch'
DISABLED_A = 'e2ea/guided-disabled'
ROOT_MOUNT = '/mnt/zfs-e2e/guided-a-root'
CHILD_MOUNT = '/mnt/zfs-e2e/guided-a-child'
SCRATCH_MOUNT = '/mnt/zfs-e2e/guided-a-scratch'
DISABLED_MOUNT = '/mnt/zfs-e2e/guided-a-disabled'
BASE = 'ZFS-E2E-GUIDED-BASE'
MUTATED_CHILD = 'ZFS-E2E-GUIDED-MUTATED-CHILD'
KEPT = (SCRATCH_A, CHILD_A, DISABLED_A)
MUTATED_SCRATCH = 'ZFS-E2E-GUIDED-MUTATED-SCRATCH'
UNRELATED = 'ZFS-E2E-GUIDED-UNRELATED-B'
RESTORED = 'Restored e2ea/ROOT/be1 on pool e2ea; it is the boot default.'
ERASE = 'Type the disk serial (ZFS-E2E-A) to proceed, anything else cancels: '
CONTINUE = ERASE
PROBE_OK = '\nZFS_E2E_GUIDED_A_BOOT_OK'
# Line-anchored native recovery diagnostics end a guided dialogue at once;
# `Restore...fail` lines are left to the verdict (`failure_lines`).
GUIDED = FAILURES + ('\nmenu:', '\nzboot:')
CUTS = {'base': '  staged', 'release': '  erased', 'publish': '  properties restored'}
SECONDS = 3600  # one restore or resume, through scrub, on the console

# Restored fixture views mounted read-only in a Menu shell: name -> (dataset, path, file, token)
A_VIEWS = {'a-root': (ROOT_A, '/mnt/zfs-e2e/g-root', 'guided-base-token', BASE),
           'a-child': (CHILD_A, '/mnt/zfs-e2e/g-child', 'guided-child-token', MUTATED_CHILD),
           'a-scratch': (SCRATCH_A, '/mnt/zfs-e2e/g-scratch', 'guided-scratch-token', MUTATED_SCRATCH)}
B_VIEWS = {'b-root': (ROOT_B, '/mnt/zfs-e2e/g-broot', 'guided-base-token', BASE),
           'b-unrelated': ('e2eb/unrelated', '/mnt/zfs-e2e/g-bunrelated', 'token', UNRELATED)}


def mount_body(views):
    paths = ' '.join(path for _, path, _, _ in views.values())
    mounts = '; '.join(f'mount -t zfs -o ro,zfsutil {ds} {path}' for ds, path, _, _ in views.values())
    return f'set -e; mkdir -p {paths}; {mounts}'


def lines(text):
    return text.replace('\r', '').splitlines()


def newest_snapshot(text, dataset):
    """`DATASET@SNAP` for the last (newest) snapshot row under DATASET in a
    `status DATASET --snapshots` report, which lists them by createtxg."""
    found, inside = [], False
    for line in lines(text):
        row = re.match(r'\s*(?:\d+: )?(\S+)  \[', line)
        if row:
            inside = row.group(1) == dataset
        elif inside and (snapshot := re.match(r'\s*@(\S+)  guid=', line)):
            found.append(snapshot.group(1))
    if not found:
        raise ConsoleError(f'status lists no snapshot of {dataset}')
    return f'{dataset}@{found[-1]}'


def operations(text):
    """Rows `restore ID on POOL after step N` of the Menu's short `status`."""
    return re.findall(r'(?m)^\s+restore (\S+) on (\S+) after step ', text.replace('\r', ''))


def eligible_rows(text, dataset):
    rows = []
    for line in lines(last_listing(text)):
        number, sep, entry = line.strip().partition(': ')
        if sep and number.isdigit() and entry in (f'{dataset}  eligible', f'{dataset} [default]  eligible'):
            rows.append(int(number))
    return rows


def numbered(text, dataset):
    """Menu rows `N: DATASET...` (any status)."""
    return [line for line in lines(last_listing(text))
            if re.match(rf'\s*\d+: {re.escape(dataset)}(\s|$)', line)]


def failure_lines(text):
    return [line for line in lines(text) if line.startswith(('menu:', 'zboot:'))
            or (line.startswith('Restore') and 'fail' in line[7:].lower())]


def probe(text):
    # Not line-anchored: the OS console may put terminal noise before the first line.
    return dict(re.findall(r'(?m)ZFS_E2E_PROBE ([\w-]+)=(.*?)\s*$', text.replace('\r', '')))


# --- Menu dialogues (stage functions) ---

def restore(console, cut=None, repair=None):
    """Stick Menu: `restore` B's mirror, from its newest snapshot, onto A,
    keeping A's three data leaves. With a cut, the dialogue ends as soon as
    the Menu prints that phase's progress line and the boot is power-cut
    (host SIGKILL): the stick runs no fault shim, so the cut lands at or
    after the phase, not exactly at it."""
    console.ready()
    source = newest_snapshot(console.menu('source', f'status {ROOT_B} --snapshots', failures=GUIDED), ROOT_B)
    keep = ' '.join(f'--keep {dataset}' for dataset in KEPT)
    console.menu('restore', f'restore {source} /dev/vda {keep}', until=(ERASE,), failures=GUIDED)
    if cut:
        console.menu('consent', 'ZFS-E2E-A', until=('\n' + CUTS[cut],), seconds=SECONDS, failures=GUIDED)
        return
    console.menu('consent', 'ZFS-E2E-A', until=(RESTORED, MENU_PROMPT), seconds=SECONDS, failures=GUIDED)
    verify(console, repair)


def resume(console, consent):
    """A fresh stick boot after a cut: `resume` the one restore `status` lists.
    Before erasure the Menu must ask for consent again; after it, never."""
    console.ready()
    found = operations(console.menu('status', 'status', failures=GUIDED))
    if len(found) != 1:
        raise ConsoleError(f'status listed {found}')
    command = f'resume {found[0][0]}'
    if consent:
        console.menu('resume', command, until=(CONTINUE,), failures=GUIDED)
        console.menu('resume-consent', 'ZFS-E2E-A', until=(RESTORED, MENU_PROMPT), seconds=SECONDS,
                     failures=GUIDED)
    else:
        console.menu('resume', command, until=(RESTORED, MENU_PROMPT), seconds=SECONDS,
                     failures=GUIDED + ('Type the disk serial',))
    verify(console)


def verify(console, repair=None):
    """Menu shell after the restore: native facts of A and B, then export."""
    console.enter_shell()
    console.shell('pools-restored', 'zpool list -H -o name')
    console.shell('b-bootfs', 'zpool get -H -o value bootfs e2eb')
    console.must('import-a', 'zpool import -N -o readonly=on -o cachefile=none -d /dev e2ea')
    console.must('mount-a', mount_body(A_VIEWS))
    console.must('mount-b', mount_body(B_VIEWS))
    for name, (_, path, file, _) in {**A_VIEWS, **B_VIEWS}.items():
        console.shell(f'{name}-token', f'cat {path}/{file}')
    console.shell('b-snapshots', f'zfs list -H -p -t snapshot -o name,guid -r {ROOT_B}')
    console.shell('a-disabled-role', f'zfs get -H -o property,value canmount,mounted,mountpoint {DISABLED_A}')
    console.shell('chunked', "zfs get -H -o name,property -s local,inherited all "
                  "| grep -E '[[:space:]]zboot:(attachment|journal):' || true")
    if repair:
        repair(console)
    views = {**B_VIEWS, **A_VIEWS}
    console.must('cleanup', 'set -e; umount ' + ' '.join(path for _, path, _, _ in views.values())
                 + '; zpool export e2ea; zpool export e2eb; zpool export e2ed')
    console.leave_shell()


def boot_a(console, name='boot-a'):
    """A's own ESP (no stick): its installed Menu boots e2ea/ROOT/be1, whose
    systemd probe reports the booted system and prints its marker."""
    select_a(console, console.ready(f'{name}-ready'), name)


def select_a(console, menu, name):
    """From a ready Menu listing, boot the one eligible A row with -v."""
    rows = eligible_rows(menu, ROOT_A)
    if len(rows) != 1:
        raise ConsoleError(f'A Menu eligible {ROOT_A} rows: {rows}')
    console.menu(name, f'boot {rows[0]} -v', until=('ZBOOT_HANDOFF_LOAD', PROBE_OK), seconds=300,
                 failures=FAILURES + ('ZFS_E2E_GUIDED_A_BOOT_FAILED',))


LABELS = "/bin/busybox grep -E '^LABEL [0-9]|^    (state|name|pool_guid): '"


def labels_body(pool, device):
    return (f'zdb -lll {device} > /run/zt-{pool}-labels || echo zdb-failed; {LABELS} /run/zt-{pool}-labels; '
            f'echo "guid=$(zpool get -H -p -o value guid {pool})"')


def postboot(console):
    """A fresh stick boot after A's clean shutdown. Stock Debian (initramfs-tools)
    does not export pools at shutdown, so the labels stay active; the stick's
    Menu adopts A's hostid, so both still import without force."""
    console.ready()
    console.enter_shell()
    console.shell('serials', 'for d in vda vdb vdd; do echo "$(cat /sys/block/$d/serial)"; done')
    console.shell('menu-readonly', 'zpool get -H -o name,value readonly e2ea e2eb')
    console.shell('labels-e2ea', labels_body('e2ea', '/dev/vda2'))
    console.shell('labels-e2eb', labels_body('e2eb', '/dev/vdb1'))
    console.shell('export', 'set -e; zpool export e2ea; zpool export e2eb')
    console.shell('import', 'set -e; zpool import -N -o readonly=on -o cachefile=none -d /dev e2ea; '
                  'zpool import -N -o readonly=on -o cachefile=none -d /dev e2eb; '
                  'zpool get -H -o name,value readonly e2ea e2eb')
    console.leave_shell()


# --- verdict parts ---

def build(ev, name):
    """The recorded dist/dist.sh output NAME of this run's session (efi.json)."""
    session = Path(ev.root).resolve().parents[2]
    return json.loads((session / 'efi.json').read_text())['builds'][name]


def uki(ev, check, name='neutral'):
    """The file identity of build NAME's UKI as the session staged it for the
    fixtures share, checked against the recorded build output."""
    recorded = build(ev, name)
    path = Path(recorded['directory']) / 'loader/zboot-recovery.efi'
    with path.open('rb') as file:
        digest = hashlib.file_digest(file, 'sha256').hexdigest()
    check.equal(digest, recorded['uki_sha256'], f'the staged {name} UKI is the recorded build output')
    return {'sha256': digest, 'bytes': path.stat().st_size}


def check_stick(ev, n, check, name='neutral'):
    """Boot n attached exactly build NAME's stick image (launch evidence)."""
    launch = json.loads((Path(ev.root).parent / f'boot-{n}/launch.json').read_text())
    check.equal(launch['inputs'].get('boot.raw'), build(ev, name)['stick_sha256'],
                f'boot {n} attached the {name} stick')


def mirror_snapshot(stage):
    rows = [line.split('\t') for line in lines(stage.step('mirror-snapshots').out)]
    return next((row for row in rows if row[0].startswith(ROOT_B + '@')), None)


def check_setup(ev, check):
    s = ev.stage(1)
    check.equal(sorted(s.step('serials').out.split()), ['ZFS-E2E-A', 'ZFS-E2E-B', 'ZFS-E2E-D'],
                'setup sees disks A, B and D, once each')
    check.equal(s.step('wipe-before').json['result']['partitions'], [], 'A starts bare (wipe preview)')
    preview = s.step('deploy-preview').json
    review = preview['result']['deploy']
    hostid = review.get('hostid')
    check(bool(re.fullmatch('[0-9a-f]{8}', str(hostid))) and hostid not in ('00000000', 'ffffffff'),
          f'deploy preview hostid is canonical: {hostid!r}')
    check.equal(hostid, HOSTID, 'deploy preview hostid is the requested one')
    check.equal(review.get('schema_version'), 3, 'ordered deploy review schema')
    check.equal(review['selection']['schema_version'], 3, 'setup selects the current provisioning schema')
    check.equal(review.get('overlays', []), [], 'setup selects its tar without implicit overlays')
    check('base_overlay' not in review and 'overlay' not in review, 'setup preserves the explicit ordered-overlay plan shape')
    check.equal(review['selection']['hostid'], HOSTID, 'deploy review selection hostid')
    # Deploy reviews one EFI file: the session's neutral UKI on the share.
    identity = uki(ev, check)
    check.equal(review['artifacts'], {'efi': '/fixtures/e2e-esp-artifacts/zboot-recovery.efi', **identity},
                "deploy admits the exact standalone neutral UKI file")
    shipped = s.step('loader-sha256').out.split()
    check(shipped[:1] == [identity['sha256']], f'A ships the neutral UKI as its zboot loader: {shipped}')
    factory = review['factory']
    check(str(factory.get('path', '')).endswith('/e2e-factory.tar.zst') and bool(factory.get('kernels')),
          f"deploy admits the factory root tar with a kernel: {factory.get('path')!r}")
    check(bool(preview.get('token')), 'deploy preview carries a token')
    outcome = s.step('deploy-apply').json['result']['outcome']
    check.equal((outcome.get('complete'), outcome.get('exported')), (True, True), 'deploy completed and exported A')
    for name, path in (('root', ROOT_MOUNT), ('child', CHILD_MOUNT), ('scratch', SCRATCH_MOUNT),
                       ('child-again', CHILD_MOUNT), ('scratch-again', SCRATCH_MOUNT)):
        before = s.step(f'{name}-before').out.split()
        check(len(before) == 2 and before[0] == path and before[1] in ('yes', 'no'),
              f'{name}: mountpoint {path} and mounted yes|no before mounting: {before}')
        check.equal(s.step(f'{name}-after').out.strip(), 'yes', f'{name} mounted at its identity-bound path')
    check.equal(s.step('child-role').out.strip(), 'on',
                'the child data leaf mounts by default, outside the BE')
    check.equal(s.step('disabled-role').out.splitlines(), ['off', 'no'],
                'the disabled data leaf starts off and unmounted')
    for name in ('root-publish', 'child-final', 'root-final', 'scratch-final', 'unrelated-final', 'journal-final'):
        check.equal(s.step(f'{name}-unmounted').out.strip(), 'no', f'{name}: unmounted')
    snapshot = mirror_snapshot(s)
    check(snapshot is not None, f'B mirror has a {ROOT_B}@ snapshot')
    if snapshot:
        check(len(snapshot) == 2 and snapshot[1].isdigit(), f'B mirror snapshot guid is decimal: {snapshot}')
        seen = s.observe('setup').datasets.get(snapshot[0], {})
        check.equal(seen.get('guid'), snapshot[1], 'mirror snapshot guid, natively observed')
    check.equal(s.step('mirror-base-token').out, BASE, 'B mirror root token before A is mutated')
    datasets = s.observe('setup').datasets
    for name in (f'{ROOT_A}@guided', f'{CHILD_A}@guided', f'{DISABLED_A}@guided',
                 f'{SCRATCH_A}@guided'):
        check(name in datasets, f'{name} exists natively after setup')
    mirror = dict(line.split('\t') for line in lines(s.step('mirror-snapshots').out))
    expected_mirror = {ROOT_B + name[len(ROOT_A):]: facts['guid']
                       for name, facts in datasets.items()
                       if facts['type'] == 'snapshot' and
                       (name.startswith(ROOT_A + '@') or name.startswith(ROOT_A + '/'))}
    check.equal(mirror, expected_mirror, 'mirror carries the exact BE snapshot GUID set')
    mirror_members = {name for name in datasets
                      if name == ROOT_B or (name.startswith(ROOT_B + '/') and '@' not in name)}
    check.equal(mirror_members, {ROOT_B}, 'the mirrored BE is one dataset')
    for pool in ('e2ea', 'e2eb', 'e2ed'):
        check.equal(s.step(f'export-{pool}').rc, 0, f'setup exports {pool}')


def check_dialogue(stage, names, check):
    for name in names:
        bad = failure_lines(stage.step(name).out)
        check(not bad, f'stage {stage.path.name} {name}: no recovery failure line: {bad}')


def check_restore(ev, n, check, cut=None):
    """The guided restore dialogue of stage n (completed unless cut)."""
    check_stick(ev, n, check)
    s = ev.stage(n)
    source = newest_snapshot(s.step('source').out, ROOT_B)
    check.equal(s.step('restore').argv,
                [f'restore {source} /dev/vda ' + ' '.join(f'--keep {dataset}' for dataset in KEPT)],
                'the restore names the newest mirror snapshot, disk A and the kept leaves')
    review = s.step('restore').out
    check.contains(review, ERASE, 'review asks for the disk serial')
    identity = uki(ev, check)
    for needle, what in ((f'Restore {ROOT_A} (operation ', 'restores the BE'),
                         (f'  Source: {source} (existing snapshot', 'from the B mirror'),
                         ('  Target disk: /dev/vda - serial ZFS-E2E-A', 'onto disk A'),
                         (f'hostid {HOSTID}', "with the BE's hostid"),
                         (f'  Loader: {ROOT_B}@', 'installing the loader the B mirror ships'),
                         (f':/usr/lib/zboot/zboot.efi sha256 {identity["sha256"]} ({identity["bytes"]} bytes)',
                          "that loader is the session's UKI"),
                         *((f'  Kept: {dataset} (1 datasets', f'keeping {dataset}') for dataset in KEPT)):
        check.contains(review, needle, f'review: {what}')
    consent = s.step('consent').out
    if cut:
        check.contains(consent, '\n' + CUTS[cut], f'Menu printed the {cut} phase before the cut')
        check.equal(ev.boots[n - 1].get('killed'), -9, f'stage {n} power-cut while the Menu ran')
    else:
        check.contains(consent, RESTORED, 'restore completes')
        check(consent.rstrip().endswith(MENU_PROMPT.strip()), 'Menu prompt returns after the restore')
    check_dialogue(s, ('source', 'restore', 'consent'), check)


def check_resume(ev, n, check, consent, stick='neutral'):
    check_stick(ev, n, check, stick)
    s = ev.stage(n)
    found = operations(s.step('status').out)
    check.equal(len(found), 1, f'status lists one interrupted restore: {found}')
    check.equal([pool for _, pool in found], ['e2eb'], 'the operation is recorded on surviving B')
    check.equal(s.step('resume').argv, [f'resume {found[0][0]}' if found else 'resume'],
                'resume names the listed operation')
    selected = s.step('resume').out
    if consent:
        check.contains(selected, CONTINUE, 'a resume before erasure asks for consent again')
        done = s.step('resume-consent').out
    else:
        check('Type the disk serial' not in selected, 'a resume after erasure asks no consent')
        done = selected
    check.contains(done, RESTORED, 'the resume completes the restore')
    check(done.rstrip().endswith(MENU_PROMPT.strip()), 'Menu prompt returns after the resume')
    check_dialogue(s, ('status', 'resume') + (('resume-consent',) if consent else ()), check)


def check_restored(ev, n, check):
    """Native facts of the restored fixture, from stage n's Menu shell."""
    s, setup = ev.stage(n), ev.stage(1)
    check('e2ea' not in s.step('pools-restored').out.split(), 'e2ea is not imported after the restore')
    check.equal(s.step('b-bootfs').out.strip(), '-', 'B carries no boot default')
    check.equal(s.step('import-a').rc, 0, 'restored e2ea imports read-only without force')
    for name, (_, _, _, token) in {**A_VIEWS, **B_VIEWS}.items():
        step = s.step(f'{name}-token')
        check.equal((step.rc, step.out.strip()), (0, token), f'{name} token')
    snapshot = mirror_snapshot(setup)
    after = dict(line.split('\t') for line in lines(s.step('b-snapshots').out) if '\t' in line)
    check(snapshot is not None and after.get(snapshot[0]) == snapshot[1],
          f'B mirror snapshot identity unchanged: {snapshot} vs {after}')
    before = dict(line.split('\t') for line in lines(setup.step('mirror-snapshots').out))
    check.equal(after, before, 'restore preserves every mirrored snapshot GUID')
    disabled = dict(line.split('\t') for line in lines(s.step('a-disabled-role').out))
    check.equal(disabled, {'canmount': 'off', 'mounted': 'no', 'mountpoint': DISABLED_MOUNT},
                'restore publishes the kept disabled leaf off and unmounted')
    leftover = s.step('chunked').out
    check('zboot:attachment:' not in leftover and 'zboot:journal:' not in leftover,
          f'the restore left no attachment or journal property on A or B: {leftover.strip()[-300:]!r}')
    check.equal(s.step('cleanup').rc, 0, 'test mounts unmount; e2ea, e2eb and e2ed export')


def check_boot_a(ev, n, check, name='boot-a', clean=True):
    launch = json.loads((Path(ev.root).parent / f'boot-{n}/launch.json').read_text())
    check('boot.raw' not in launch['inputs'] and any('ZFS-E2E-A,bootindex=1' in a for a in launch['argv']),
          f'boot {n} firmware-boots disk A with no stick attached')
    s = ev.stage(n)
    check.equal(len(eligible_rows(s.step(f'{name}-ready').out, ROOT_A)), 1, f'A Menu lists {ROOT_A} eligible once')
    rows = eligible_rows(s.step(f'{name}-ready').out, ROOT_A)
    check(bool(rows) and s.step(name).argv == [f'boot {rows[0]} -v'],
          'A is selected through the shared verbose boot command')
    out = s.step(name).out
    check.contains(out, 'ZBOOT_HANDOFF_LOAD', 'selecting A hands off')
    check.contains(out, PROBE_OK, 'the installed OS probe reports')
    p = probe(out)
    for key, want in (('pid1', 'systemd'), ('efi', 'yes'), ('root-arg', f'root=ZFS={ROOT_A}'),
                      ('root', ROOT_A), ('child', CHILD_A), ('scratch', SCRATCH_A),
                      ('zfs-mount-load-state', 'loaded'),
                      ('root-canmount', 'noauto'), ('child-canmount', 'on'), ('scratch-canmount', 'on'),
                      ('disabled-canmount', 'off'), ('disabled-mounted', 'no'),
                      ('disabled-mountpoint', DISABLED_MOUNT),
                      ('base-token', BASE), ('child-token', MUTATED_CHILD), ('scratch-token', MUTATED_SCRATCH),
                      ('hostid', HOSTID), ('e2ea-readonly', 'off'), ('e2eb-readonly', 'off'),
                      ('b-labels', '1 1 1 1'), ('b-state0', '4'), ('b-name', '4'), ('b-guid', '4')):
        check.equal(p.get(key), want, f'stage {n} installed OS probe {key}')
    check(p.get('zed-cache-hook') in ('vendor', 'not-installed'),
          f"stage {n} has no persistent ZEDlet override: {p.get('zed-cache-hook')!r}")
    check(p.get('zfs-mount-fragment') in ('/usr/lib/systemd/system/zfs-mount.service',
                                         '/lib/systemd/system/zfs-mount.service'),
          f"stage {n} uses the vendor zfs-mount.service: {p.get('zfs-mount-fragment')!r}")
    unit_state = p.get('zfs-mount-unit-file-state', '')
    check(bool(unit_state) and unit_state not in ('masked', 'masked-runtime'),
          f'stage {n} zfs-mount.service is not masked: {unit_state!r}')
    serials = p.get('serials', '').split()
    check(all(f'ZFS-E2E-{x}' in serials for x in 'ABD'), f'installed OS sees A, B and D: {serials}')
    if clean:
        check.equal(ev.boots[n - 1].get('exit'), 0, 'installed A powered off cleanly (QEMU exit 0)')



def check_installed_fork(ev, n, check, name='boot-a'):
    """One-argument fork and a real after-snapshot process cut on installed A.

    FORK-NATIVE separately owns the after-clone QEMU power-cut proof. Here
    the wrapper delegates the actual atomic native snapshot, syncs the pool,
    and kills only its parent zboot before capture verification/checkpoint.
    """
    p = probe(ev.stage(n).step(name).out)
    check.equal(p.get('fork-probe'), 'complete', 'installed fork probe completes')
    check.equal(p.get('status-probe'), 'complete', 'installed selected status probe completes')
    report = json.loads(p.get('status-running-json', '{}'))
    check.equal(report.get('schema_version'), 1, 'selected status uses schema version one')
    check.equal(report.get('mode'), 'applied', 'selected status returns one applied envelope')
    result = report.get('result', {})
    check.equal(result.get('running_root'), ROOT_A, 'status identifies the running root')
    inventory = result.get('inventory', {})
    check.equal(inventory.get('requested_datasets'), [ROOT_A], 'status keeps the explicit selection')
    roots = [dataset for dataset in inventory.get('datasets', []) if dataset.get('name') == ROOT_A]
    check.equal(len(roots), 1, 'selected status includes exactly one running BE root')
    if roots:
        check.equal(roots[0].get('mounted'), True, 'selected BE is already mounted')
        check.equal(roots[0].get('readonly'), False, 'selected BE is writable')
    pools = [pool for pool in inventory.get('pools', []) if pool.get('name') == 'e2ea']
    check.equal(len(pools), 1, 'selected status includes its native pool')
    if pools:
        check.equal(pools[0].get('bootfs'), ROOT_A, 'selected running BE remains the boot default')
    kernels = result.get('kernels', {}).get(ROOT_A, {})
    check.equal(kernels.get('error'), None, 'mounted read-write BE kernel inspection succeeds')
    choices = kernels.get('kernels', [])
    check(bool(choices), 'selected running BE reports nonempty kernel inventory')
    version = p.get('status-running-version')
    check(bool(version), 'the installed probe reports its running kernel version')
    check(any(kernel.get('name') == version and kernel.get('default') is True for kernel in choices),
          'the running VERSION is listed as the default boot kernel')
    check(all(kernel.get('name') and not kernel['name'].startswith('vmlinuz-') for kernel in choices),
          'kernel selectors are VERSION names')
    mount_rows = [line for line in p.get('status-before-mount', '').split(';') if line]
    check.equal(len(mount_rows), 1, 'the installed BE has one original root mount')
    if len(mount_rows) == 1:
        before, filesystem = mount_rows[0].split(' - ', 1)
        fields, native = before.split(), filesystem.split()
        check.equal(fields[3:5], ['/', '/'], 'the original mount is the whole filesystem at root')
        check.equal(native[:2], ['zfs', ROOT_A], 'the original mount names the exact native source')
        check('rw' in fields[5].split(',') and 'ro' not in fields[5].split(','),
              'the original root mount is read-write before status')
    for fact in ('mount', 'native', 'pool', 'boot'):
        before = p.get(f'status-before-{fact}')
        check(bool(before), f'installed status records original {fact}')
        check.equal(p.get(f'status-after-{fact}'), before,
                    f'status preserves original {fact}, including root read-write mode')
    check.equal(p.get('status-esp-probe'), 'complete', 'installed mounted ESP status probe completes and cleans up')
    devices = json.loads(p.get('status-devices-json', '{}'))
    check.equal(devices.get('schema_version'), 1, 'device status uses schema version one')
    check.equal(devices.get('mode'), 'applied', 'device status returns one applied envelope')
    esps = [esp for esp in devices.get('result', {}).get('esps', [])
            if esp.get('path') == p.get('status-esp-device')]
    check.equal(len(esps), 1, 'device status includes the selected mounted A ESP exactly once')
    if len(esps) == 1:
        esp = esps[0]
        check.equal(esp.get('error'), None, 'mounted read-write ESP inspection is available')
        target = esp.get('target') or {}
        check.equal(target.get('partition', {}).get('partition_uuid'), p.get('status-esp-partuuid'),
                    'ESP report binds the original GPT partition UUID')
        check.equal(target.get('partition', {}).get('device_number'), p.get('status-esp-device-number'),
                    'ESP report binds the original native device number')
        check.equal(target.get('disk', {}).get('serial'), 'ZFS-E2E-A', 'the mounted ESP belongs to disk A')
        owned = [loader for loader in esp.get('loaders', []) if loader.get('owner') == 'zboot']
        check(bool(owned), 'mounted A ESP reports owned zboot loader inventory')
        check(all(loader.get('identity', {}).get('sha256') and not loader.get('error') for loader in owned),
              'owned loader files have readable native identities')
    mount_rows = [line for line in p.get('status-esp-before-mount', '').split(';') if line]
    check.equal(len(mount_rows), 1, 'the probe explicitly mounted the whole A ESP once')
    if len(mount_rows) == 1:
        before, filesystem = mount_rows[0].split(' - ', 1)
        fields, native = before.split(), filesystem.split()
        check.equal(fields[2], p.get('status-esp-device-number'), 'mounted ESP has the admitted native device number')
        check.equal(fields[3:5], ['/', '/run/zfs-e2e-status-esp'], 'the probe mounted the whole ESP at its private fixture')
        check.equal(native[0], 'vfat', 'the mounted ESP is a native FAT filesystem')
        check('rw' in fields[5].split(',') and 'ro' not in fields[5].split(','),
              'the original ESP mount is read-write before status')
    for fact in ('mount', 'native', 'files'):
        before = p.get(f'status-esp-before-{fact}')
        check(bool(before), f'installed ESP status records original {fact}')
        check.equal(p.get(f'status-esp-after-{fact}'), before,
                    f'device status preserves original ESP {fact}, including read-write mode')
    check.equal(p.get('fork-running-root'), ROOT_A, 'one-argument fork runs on the actual ZFS root')
    check(p.get('fork-binary') in ('/usr/bin/zboot', '/bin/zboot', '/usr/sbin/zboot', '/sbin/zboot'),
          f"fork uses the installed normal executable: {p.get('fork-binary')!r}")

    wrapper = '/usr/local/libexec/zfs-e2e-fork-capture-cut/zfs'
    check.equal(p.get('fork-wrapper-path'), wrapper, 'the executable capture wrapper is on the installed BE')
    check.equal(p.get('fork-wrapper-preflight-rc'), '0', 'direct absolute wrapper execution succeeds')
    check.equal(p.get('fork-wrapper-entered'), wrapper, 'the wrapper itself records the preflight entry')
    check('zfs-' in p.get('fork-wrapper-preflight-output', ''), 'the wrapper delegates version to native zfs')
    native_zfs = p.get('fork-real-zfs', '')
    check(native_zfs.startswith('/') and native_zfs != wrapper, 'the delegated native zfs is a distinct absolute executable')
    identity = p.get('fork-wrapper-stat', '').split(':')
    check(len(identity) == 5 and identity[:3] == ['0', '0', '700'] and
          all(value.isdigit() and int(value) > 0 for value in identity[3:]),
          'the wrapper has a root-owned private mode and recorded native file identity')
    digest = p.get('fork-wrapper-sha256', '').split()
    check(len(digest) == 2 and re.fullmatch(r'[0-9a-f]{64}', digest[0]) and digest[1] == wrapper,
          'the directly executed wrapper has a recorded content hash')
    mount = p.get('fork-wrapper-mount', '').split()
    if check.equal(len(mount), 4, 'the wrapper filesystem and mount options are recorded'):
        check.equal(mount[:3], ['/', ROOT_A, 'zfs'], 'the wrapper executes from the actual running BE')
        check('rw' in mount[3].split(',') and 'noexec' not in mount[3].split(','),
              'the wrapper filesystem is writable and permits execution')
    check(bool(p.get('fork-control-mount')), 'the separate runtime control mount options are recorded')

    def rows(key):
        return [line.split('\t') for line in p.get(key, '').split(';') if line]

    source_ids = {(name, prop): value for name, prop, value in rows('fork-source-ids')}
    check.equal({name for name, _ in source_ids}, {ROOT_A},
                'capture source is exactly the running BE, one dataset')
    check.equal(rows('fork-source-ids-after'), rows('fork-source-ids'),
                'both forks preserve every source dataset native identity')
    clean = json.loads(p.get('fork-clean-json', '{}'))
    check.equal(clean.get('mode'), 'applied', 'one-argument fork executes directly')
    result = clean.get('result', {})
    check.equal(result.get('complete'), True, 'one-argument fork completes')
    check.equal(result.get('destination', {}).get('name'), 'e2ea/ROOT/try',
                'bare try resolves beside the actual running BE')
    clean_point = result.get('source_snapshot', '')
    check(clean_point.startswith(ROOT_A + '@zboot-'), 'fork reports its generated full source snapshot')
    clean_id = result.get('operation_id')
    check.equal(clean.get('operation'), clean_id, 'fork envelope and result use one UUID')

    record = json.loads(p.get('fork-cut-record', '{}'))
    check.equal(record.get('kind'), 'fork', 'process cut retains one fork intent')
    check.equal(record.get('step'), 0, 'successful native capture precedes the first checkpoint')
    cut_state = record.get('state', {})
    check.equal(cut_state.get('capture'), True, 'the fork makes its own boundary snapshot')
    check('point' not in cut_state, 'cut leaves the captured point uncheckpointed')
    check.equal(cut_state.get('workspace', {}).get('owner'), None, 'capture precedes workspace creation')
    check.equal(cut_state.get('destination'), 'e2ea/ROOT/try-cut', 'second bare destination resolves beside A')
    check.equal(cut_state.get('source', {}).get('name'), ROOT_A, 'cut intent binds the running source')
    for key in ('guid', 'createtxg', 'objsetid'):
        check.equal(str(cut_state.get('source', {}).get('identity', {}).get(key)), source_ids.get((ROOT_A, key)),
                    f'cut intent freezes source native {key}')
    check.equal(str(cut_state.get('source', {}).get('identity', {}).get('pool_guid')), p.get('fork-pool-guid'),
                'cut intent freezes source native pool GUID')
    cut_id, label = record.get('id'), cut_state.get('snapshot', '')
    check(clean_id != cut_id, 'separate forks have separate operation UUIDs')
    check(clean_point != f'{ROOT_A}@{label}', 'separate execution generates another snapshot label')
    check.equal(p.get('fork-cut-rc'), '137', 'wrapper kills the fork process with SIGKILL')
    check.equal(p.get('fork-cut-dest'), 'absent', 'capture cut publishes no clone destination')
    argv = p.get('fork-cut-argv', '').split(';')[:-1]
    check.equal(argv[:3], ['snapshot', '-o', f'zboot:capture={cut_id}'],
                'native cut follows snapshot with the same fork UUID ownership property')
    check.equal(argv[3:], [f'{ROOT_A}@{label}'], 'one explicit native command captures the frozen BE')
    check.equal(len(argv), 4, 'native capture has no recursive or additional arguments')
    check.equal(p.get('fork-cut-holds'), '', 'capture cut occurs before any operation hold')
    resume = json.loads(p.get('fork-resume-json', '{}'))
    check.equal(resume.get('mode'), 'applied', 'ordinary installed resume completes the process-cut fork')
    check.equal(resume.get('result', {}).get('complete', {}).get('complete'), True,
                'resume reports complete fork outcome')

    for prefix, destination, point, operation in (
            ('fork-clean', 'e2ea/ROOT/try', clean_point, clean_id),
            ('fork-resume', 'e2ea/ROOT/try-cut', f'{ROOT_A}@{label}', cut_id)):
        suffix = point.partition('@')[2]
        expected = {f'{ROOT_A}@{suffix}'}
        points = rows(f'{prefix}-points')
        check.equal({row[0] for row in points}, expected, f'{prefix}: generated snapshot set is complete')
        check.equal(len(points), 1, f'{prefix}: exactly one point for the BE')
        check(all(int(row[1]) > 0 and int(row[2]) > 0 for row in points),
              f'{prefix}: native snapshot GUIDs and transaction groups are nonzero')
        point_ids = {(name, key): value for name, key, value in rows(f'{prefix}-point-ids')}
        check.equal(set(point_ids), {(name, key) for name in expected for key in ('guid', 'createtxg', 'objsetid')},
                    f'{prefix}: full native snapshot identity fields are observed')
        check(all(int(value) > 0 for value in point_ids.values()), f'{prefix}: native identity fields are nonzero')
        markers = {name: (value, source) for name, value, source in rows(f'{prefix}-markers')}
        check.equal(markers, {name: (operation, 'local') for name in expected},
                    f'{prefix}: every native snapshot has local same-operation ownership')
        properties = {(name, key): value for name, key, value, source in rows(f'{prefix}-clones')}
        check.equal({name for name, _ in properties}, {destination}, f'{prefix}: the clone is one dataset')
        for key, want in (('origin', f'{ROOT_A}@{suffix}'), ('readonly', 'off'), ('mounted', 'no'),
                          ('canmount', 'noauto')):
            check.equal(properties.get((destination, key)), want, f'{prefix}: {destination} native {key}')
        check.equal(properties.get((destination, 'mountpoint')), '/', f'{prefix}: root placement restored')
        check.equal(p.get(f'{prefix}-root-token'), BASE, f'{prefix}: clone root data')
        check.equal(p.get(f'{prefix}-operation'), '-', f'{prefix}: fork retires its only intent')
        check.equal(p.get(f'{prefix}-holds'), '', f'{prefix}: fork releases its operation holds')
    check.equal(rows('fork-cut-points'), rows('fork-resume-points'),
                'resume reuses every exact native snapshot GUID and createtxg from before the checkpoint')
    check.equal(rows('fork-cut-point-ids'), rows('fork-resume-point-ids'),
                'resume preserves all native snapshot GUID, createtxg and objsetid fields')
    check.equal(rows('fork-cut-markers'), rows('fork-resume-markers'),
                'resume preserves the original local capture ownership markers')


def label_facts(text):
    rows = lines(text)
    return {'labels': [sum(1 for r in rows if re.fullmatch(rf'LABEL {k}\s*', r)) for k in range(4)],
            'states': [r.split(': ', 1)[1] for r in rows if r.startswith('    state: ')],
            'names': [r.split(': ', 1)[1] for r in rows if r.startswith('    name: ')],
            'guids': [r.split(': ', 1)[1] for r in rows if r.startswith('    pool_guid: ')],
            'guid': next((r[5:] for r in rows if r.startswith('guid=')), None)}


def check_labels(text, pool, state, check, what):
    f = label_facts(text)
    check.equal(f['labels'], [1, 1, 1, 1], f'{what}: {pool} LABEL 0-3 once each')
    check.equal(f['states'], [state] * 4, f'{what}: {pool} label states')
    check.equal(f['names'], [f"'{pool}'"] * 4, f'{what}: {pool} label names')
    check(f['guid'] is not None and f['guids'] == [f['guid']] * 4, f"{what}: {pool} label pool_guid {f['guids']} = {f['guid']}")


def check_postboot(ev, n, check, stick='neutral'):
    check_stick(ev, n, check, stick)
    s = ev.stage(n)
    check.equal(s.step('serials').out.split(), ['ZFS-E2E-A', 'ZFS-E2E-B', 'ZFS-E2E-C'], 'vda, vdb, vdd serials')
    ro = [line.split('\t') for line in lines(s.step('menu-readonly').out)]
    check.equal(ro, [['e2ea', 'on'], ['e2eb', 'on']], 'the stick Menu imported e2ea and e2eb read-only')
    for pool in ('e2ea', 'e2eb'):
        # 0 = POOL_STATE_ACTIVE: a clean shutdown of stock Debian leaves its
        # pools imported in the labels (the dracut factory exported them).
        check_labels(s.step(f'labels-{pool}').out, pool, '0', check, 'after A shut down')
    check.equal(s.step('export').rc, 0, 'stick shell exports e2ea and e2eb')
    imp = s.step('import')
    check.equal(imp.rc, 0, 'non-force read-only imports of e2ea and e2eb')
    check.equal([line.split('\t') for line in lines(imp.out)][-2:], [['e2ea', 'on'], ['e2eb', 'on']],
                'both re-imported read-only')
