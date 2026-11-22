"""DEPLOY-INTO: `deploy into` adds a bootable sibling, preserves defaults and power-cuts a
second native deployment at its @factory snapshot. A fresh boot observes its
pending role, explicitly Drops it, and retries before an actual UKI handoff."""
import json
import uuid
from pathlib import Path
from host import deploy
from host.case import Boot
from host.lifecycle import prop, source

ID = 'DEPLOY-INTO'
GROUP = 'deploy'
SECONDS = 7200
DISKS = {'A': 2, 'B': 2, 'D': 8}
BOOTS = [Boot(1, cut='INTO-FACTORY', udev=True, extra={'setup': 'neutral'}),
         Boot(2, udev=True, extra={'setup': 'neutral'}),
         Boot(3, efi=True, poweroff=True, extra={'from': 'D'})]
POOL, OLD, BE, HALF = 'e2ed', 'e2ed/ROOT/old', 'e2ed/ROOT/new', 'e2ed/ROOT/interrupted'


def stage_3(console):
    deploy.boot(console, BE)


def verdict(ev, check):
    first, second = ev.stage(1), ev.stage(2)
    preview, again = first.step('preview'), first.step('preview-again')
    check.equal((preview.rc, preview.json['mode']), (0, 'preview'), 'deploy into preview succeeds')
    check('token' not in preview.json, 'deploy into loses nothing and prints no token')
    check.equal(again.json['result'], preview.json['result'], 'deploy into plan is stable across processes')
    plan = preview.json['result']
    check.equal(plan['request']['pool'], POOL, 'plan targets the imported pool')
    check.equal(plan['request']['be'], 'new', 'plan names its new BE')
    check.equal(len(plan['overlays']), 1, 'ordered overlay is bound')
    applied = first.step('apply')
    check.equal((applied.rc, applied.json['mode'], 'token' in applied.json),
                (0, 'applied', False), 'deploy into applies without a token')
    check.equal(applied.json['result']['dataset']['name'], BE, 'deploy into publishes the previewed BE')
    check(applied.json['result']['complete'] is True, 'new BE publication completed')
    check.equal(first.step('defaults-after').out, first.step('defaults-before').out, 'all imported defaults remain fixed')
    check.equal(first.step('disk-after').out, first.step('disk-before').out, 'pool addition preserves the complete GPT layout')
    check.equal(first.step('existing').rc, 1, 'existing BE name refuses before effects')
    successful = first.observe('successful')
    for key, value in [('canmount', 'noauto'), ('mountpoint', '/'), ('readonly', 'off')]:
        check.equal((prop(successful, BE, key), source(successful, BE, key)), (value, 'local'), f'published BE {key}')
    check.equal(prop(successful, BE, 'zboot:pending'), '-', 'completed BE pending marker cleared')
    check.equal(first.cut('INTO-FACTORY'), ['snapshot', HALF + '@factory'], 'actual cut follows the new BE factory snapshot')
    interrupted = second.step('interrupted-native').out.splitlines()
    values = {row.split('\t')[1]: row.split('\t')[2:] for row in interrupted}
    check.equal(values.get('canmount'), ['off', 'local'], 'interrupted BE remains inert')
    check.equal(values.get('mountpoint'), ['none', 'local'], 'interrupted BE has no boot root shape')
    check(values.get('zboot:pending', ['-'])[0] not in ('', '-'), 'interrupted BE retains its pending identity')
    check.equal(values.get('zboot:pending', ['', ''])[1], 'local', 'pending identity remains LOCAL')
    pending = values.get('zboot:pending', [''])[0]
    try:
        identity = uuid.UUID(pending)
        canonical = str(identity) == pending and identity.version == 4
    except ValueError:
        canonical = False
    check(canonical, 'pending fence carries a canonical fresh deployment UUID')
    check.equal(second.step('interrupted-refused').rc, 1, 'existing interrupted name requires explicit Drop')
    status = second.step('interrupted-status').json['result']
    check(HALF not in status['boot_environments'], 'half-made BE is absent from boot candidates')
    check.equal(status['operations']['operations'], [], 'interrupted into creates no resume record')
    check.equal(second.step('drop-apply').rc, 0, 'explicit confirmed Drop removes the interrupted BE')
    check(second.step('absent').rc != 0, 'interrupted name is absent before fresh retry')
    check.equal((second.step('retry').rc, second.step('retry').json['mode']), (0, 'applied'), 'fresh retry completes without a resume record')
    check.equal(second.step('defaults-final').out, first.step('defaults-before').out, 'retry preserves every default')
    final = second.observe('final')
    for dataset in [BE, HALF]:
        check.equal(prop(final, dataset, 'canmount'), 'noauto', f'{dataset} final role')
        check.equal(prop(final, dataset, 'zboot:pending'), '-', f'{dataset} final pending marker')
    names = [line.split('\t')[0] for line in second.step('final-snapshots').out.splitlines()]
    for dataset in [OLD, BE, HALF]:
        for label in ['factory', 'deployed']:
            check(dataset + '@' + label in names, f'{dataset} retains @{label}')
    # Exact launch proves firmware starts D's installed ESP, with no extra stick.
    launch = json.loads((Path(ev.root).parent / 'boot-3/launch.json').read_text())
    check(any('serial=ZFS-E2E-D,bootindex=1' in value for value in launch['argv']), 'actual firmware source is D')
    check('boot.raw' not in launch['inputs'], 'firmware boot uses its installed ESP')
    deploy.check_boot(ev, check, 3, BE, OLD, '0174627a')
