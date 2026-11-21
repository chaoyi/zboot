"""Actual firmware-to-installed-root proof for deploy's existing native cases."""
import re
from host.console import FAILURES


def boot(console, dataset):
    console.ready()
    console.menu('boot-deployed', f'boot {dataset} -v',
                 until=('ZBOOT_HANDOFF_LOAD', 'ZFS_E2E_DEPLOY_BOOT_OK'), seconds=600,
                 failures=FAILURES + ('ZFS_E2E_DEPLOY_BOOT_FAILED',))


def check_boot(ev, check, stage, dataset, default, hostid, erased=False):
    text = ev.stage(stage).step('boot-deployed').out
    # systemd asks the console for its terminal name (ESC P + q ... ESC \),
    # which can land at the start of a probe line.
    text = re.sub(r'\x1bP[^\x1b]*\x1b\\', '', text)
    fields = dict(re.findall(r'(?m)^ZFS_E2E_DEPLOY ([a-z0-9-]+)=([^\r\n]*)', text))
    for name, expected in [('pid1', 'systemd'), ('efi', 'yes'), ('root', dataset),
                           ('role', 'noauto'), ('pending', '-'), ('bootfs', default),
                           ('hostid', bytes.fromhex(hostid)[::-1].hex()),
                           # The package installs the probe that verifies an erase.
                           ('probe', 'yes')]:
        check.equal(fields.get(name), expected, f'actual installed boot {name}')
    if erased:
        check.equal(fields.get('wipe'), 'applied', 'the installed system erases a spare disk and verifies it')
    check.contains(text, 'ZFS_E2E_DEPLOY_BOOT_OK', 'actual installed boot completes its native probe')
