"""The UKI common `resume` entry completes a restore cut before step 9."""
import json
from pathlib import Path

from host.case import Boot
from host import restore as r

ID = 'RESTORE-MENU-RESUME-NATIVE'
GROUP = 'restore'
SECONDS = 3600
DISKS = {'A': 4, 'B': 4, 'D': 8}
BOOTS = [Boot(1, cut='restore-cut'), Boot(2, append='zboot.recovery=1')]


def verdict(ev, check):
    first, second = ev.stage(1), ev.stage(2)
    for boot, expected in ((1, []), (2, ['zboot.recovery=1'])):
        launch = json.loads((Path(ev.root).parent / f'boot-{boot}/launch.json').read_text())
        cmdline = launch['argv'][launch['argv'].index('-append') + 1].split()
        check.equal([arg for arg in cmdline if arg.startswith('zboot.recovery=')], expected,
                    f'boot {boot} uses its declared backend or UKI entry context')
    r.base(first, check)
    r.placed(first, check, 'source')
    check.equal(first.step('c-readonly').out.strip(), 'on', 'pool C imported read-only')
    r.previewed(first.step('restore-preview'), check, 'restore --dry-run')
    r.loader(first, check)
    op = r.cut(first, check, 9)

    r.hostid(second, check, 2)
    check.equal(sorted(second.observe('before-menu').pools), ['e2ec'], 'only C imported before the Menu')
    for name in ('unrelated-file', 'unrelated-create', 'unrelated-guid',
                 'unrelated-export-created', 'unrelated-import', 'unrelated-status',
                 'unrelated-readonly-before-preview', 'unrelated-readonly-after-preview',
                 'unrelated-export-readonly', 'unrelated-import-writable',
                 'unrelated-before', 'unrelated-before-mounted'):
        check.equal(second.step(name).rc, 0, f'{name}: unrelated RAM file-vdev setup')
    unrelated_guid = second.step('unrelated-guid').out.strip()
    check(unrelated_guid.isdecimal() and int(unrelated_guid) > 0,
          'maintenance pool has a native GUID')
    status = second.step('unrelated-status').json
    leaves = []

    def file_leaves(value):
        if isinstance(value, dict):
            if value.get('vdev_type') == 'file':
                leaves.append(value.get('path'))
            for child in value.values():
                file_leaves(child)
        elif isinstance(value, list):
            for child in value:
                file_leaves(child)

    file_leaves(status)
    check.equal(leaves, ['/run/e2eu.vdev'], 'unrelated pool really uses a RAM file-vdev')
    check.equal(second.step('menu-preview').argv, ['zboot', 'resume', '--dry-run', '--json'],
                'late resume preview uses the ordinary tokenless command')
    preview = r.ok(second.step('menu-preview'), check, 'late resume --dry-run with RO maintenance pool')
    check.equal(preview.get('mode'), 'preview', 'late resume reports a preview')
    check.equal(preview['result'].get('id'), op, 'late resume preview retains the original operation')
    for label in ('before-preview', 'after-preview'):
        facts = second.step(f'unrelated-readonly-{label}')
        properties = dict(line.split('\t') for line in facts.out.splitlines())
        check.equal(properties.get('guid'), unrelated_guid,
                    f'RO maintenance pool {label} retains its GUID')
        check.equal(properties.get('readonly'), 'on',
                    f'RO maintenance pool {label} remains read-only')
    for label in ('before', 'after'):
        facts = second.step(f'unrelated-{label}')
        check.equal(facts.rc, 0, f'maintenance pool {label} resume remains observable')
        properties = dict(line.split('\t') for line in facts.out.splitlines())
        check.equal(properties.get('guid'), unrelated_guid,
                    f'maintenance pool {label} resume retains its GUID')
        check.equal(properties.get('readonly'), 'off',
                    f'unrelated maintenance pool {label} resume remains writable')
        mounted = second.step(f'unrelated-{label}-mounted')
        check.equal(mounted.rc, 0, f'maintenance pool {label} resume mount observation')
        check.equal(mounted.out.strip(), 'no', f'maintenance pool {label} resume stays unmounted')
    check.equal(second.step('unrelated-export').rc, 0, 'export the unrelated maintenance pool')
    absent = second.step('unrelated-absent')
    check.equal(absent.rc, 0, 'observe imported pools after maintenance cleanup')
    check.equal(sorted(absent.out.splitlines()), ['e2eb', 'e2ec'],
                'unrelated maintenance pool exported before existing completion inventories')
    menu = second.step('menu')
    check('menu discovery skipped while pools e2eu are imported writable' in menu.err,
          'common CLI names the maintenance pool that prevents discovery imports')
    check.equal(menu.argv, ['zboot', 'resume', '--json'],
                'late resume uses no erase confirmation token')
    check.equal(menu.rc, 0, f'resume exit (stderr {menu.err[-300:]!r})')
    envelope = menu.json
    check.equal(envelope.get('mode'), 'applied', 'common resume reports an applied result')
    check.equal(envelope.get('operation'), op, 'common resume binds the original cut record')
    check.equal(envelope['result'].get('id'), op, 'completed restore retains its original ID')
    check.equal(envelope['result'].get('be'), 'e2ea/ROOT/be1', 'common resume completes the BE')
    check.equal(envelope['result'].get('pool'), 'e2ea', 'common resume completes the target pool')
    readonly = dict(line.split('\t') for line in second.step('after-readonly').out.splitlines())
    check.equal(readonly.get('e2ec'), 'on', 'C still read-only after the Menu resume')
    check.equal(readonly.get('e2eb'), 'on', 'B read-only after the Menu resume')
    r.completed(second, check, 'done', ('e2ea/scratch',))
    bootfs = dict(line.split('\t') for line in second.step('done-bootfs').out.splitlines())
    check.equal(sorted(bootfs), ['e2eb', 'e2ec'], 'B and C imported after the Menu resume')
