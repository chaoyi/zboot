"""One request from a running Debian boot, one interrupted countdown, then
two unattended firmware handoffs to the fork and the original default."""
import re

from host.case import Boot
from host.console import FAILURES

ID = 'EFI-FORK-ONCE'
GROUP = 'efi'
SECONDS = 1800
DISKS = {'A': 8}
LOCAL = {'from': 'A', 'bus': 'nvme'}
BOOTS = [Boot(1), Boot(2, efi=True, poweroff=True, extra=LOCAL),
         Boot(3, efi=True, extra=LOCAL),
         Boot(4, efi=True, poweroff=True, extra=LOCAL),
         Boot(5, efi=True, poweroff=True, extra=LOCAL)]
SOURCE = 'e2ea/ROOT/proof'
FORK = 'e2ea/ROOT/try'


def unattended(console):
    text = console.expect('ZT_FORK_ONCE_BOOT_OK', 420,
                          failures=FAILURES + ('ZT_FORK_ONCE_FAILED',))
    console._record('boot', '', text, 0)


stage_2 = stage_4 = stage_5 = unattended


def stage_3(console):
    # ready sends a single key at the first countdown and awaits the prompt.
    # Ending this firmware visit here leaves its persistent disks for boot 4.
    console.ready()


def marked(text, dataset, label):
    row = r'(?m)^ *\d+: ' + re.escape(dataset)
    if label == 'once':
        return re.search(row + r'\r?\n  \[once\] Selected for the next boot', text) is not None
    return re.search(row + r' \[default\]\r?$', text) is not None


def verdict(ev, check):
    binary = ev.stage(1).step('binary').out.split()[0]
    original = fork = origin = None
    for stage, expected in ((2, SOURCE), (4, FORK), (5, SOURCE)):
        text = ev.stage(stage).step('boot').out
        fields = dict(re.findall(r'ZT_ONCE (\w+)=([^\r\n]*)', text))
        check.contains(text, f'Auto-booting {expected} in ', f'visit {stage}: named countdown')
        check.equal(fields.get('pid1'), 'systemd', f'visit {stage}: real installed OS')
        check.equal(fields.get('root'), expected, f'visit {stage}: mounted root')
        check.equal(fields.get('default'), SOURCE, f'visit {stage}: persistent bootfs')
        check.equal(fields.get('binary'), binary, f'visit {stage}: matching installed binary')
        check.equal('ZT_ONCE_ARMED' in text, stage == 2, f'visit {stage}: arm only once')
        if stage == 2:
            original, fork, origin = (fields.get(k, '') for k in ('root_guid', 'fork_guid', 'origin'))
            check(original.isdigit() and fork.isdigit() and original != fork, 'distinct native identities')
            check(origin.startswith(SOURCE + '@'), 'ordinary fork uses a snapshot of the default')
        check.equal(fields.get('root_guid'), fork if stage == 4 else original, 'actual root GUID')
        check.equal(fields.get('fork_guid'), fork, 'the fork survives with the original identity')
        check.equal(fields.get('origin'), origin, 'fork origin survives')
        check.equal(marked(text, FORK, 'once'), stage == 4, f'visit {stage}: one-time label')
    paused = ev.stage(3).step('ready').out
    check(marked(paused, SOURCE, 'default'), 'pause shows persistent default')
    check(marked(paused, FORK, 'once'), 'pause shows one-time fork')
    check.contains(paused, f'Auto-booting {FORK} in ', 'paused countdown named the fork')
    check.contains(paused, 'Auto-boot paused;', 'a key paused the one-time countdown')
