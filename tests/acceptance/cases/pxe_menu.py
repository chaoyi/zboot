"""Network boot of the zboot UKI with no disk loader.

Setup deploys the session's root tar to A, removes every EFI executable
from its ESP and installs the probe that runs stage 3. In boot 2 the NIC is
the only boot device: the firmware's UEFI HTTP boot takes the UKI's URL
from DHCP, fetches it and starts it with no arguments, so the UKI runs its
own command line. The menu lists the local BE; `connect` and its one-time
password admit a login, and the menu boots the BE, where stage 3 records
the installed root running.
"""
import json
from pathlib import Path
import re

from cases import efi_connect as _connect
from host.case import Boot
from host.console import ConsoleError

ID = 'PXE-MENU'
GROUP = 'efi'
SECONDS = 1800
DISKS = {'A': 8, 'B': 2, 'D': 2}
BOOTS = [Boot(1, extra={'setup': 'neutral'}),
         Boot(2, efi=True, target=3, network=True, extra={'pxe': True})]
ROOT = 'e2ea/ROOT/proof'
VARIABLE = '/sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
PASSWORD = r'One-time root password: ([23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{12})'


def write_askpass(run_dir):
    """ssh reads the one-time password from this (efi_connect.password_env)."""
    askpass = run_dir / 'askpass'
    askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$ZT_CONNECT_PASSWORD"\n')
    askpass.chmod(0o700)


def prepare(run_dir):
    write_askpass(run_dir)


def connect(console):
    """`connect` in a network-booted UKI: (known_hosts, ssh environment).
    console.ready() first pauses the countdown of a machine with a BE to boot."""
    console.ready()
    enabled = console.menu('connect', 'connect')
    known = _connect.fingerprint(console, enabled)
    passwords = re.findall(PASSWORD, enabled)
    if len(passwords) != 1:
        raise ConsoleError('connect did not print exactly one one-time password')
    return known, _connect.password_env(console, passwords[0])


def stage_2(console):
    known, environment = connect(console)
    body = ('set -e; printf "CMDLINE="; cat /proc/cmdline; '
            '/bin/busybox grep " /sys/firmware/efi/efivars efivarfs " /proc/mounts; '
            f'test ! -e {VARIABLE}; printf "NO_LOADER_PARTITION\\n"')
    login = _connect.command(console, 'password-login',
                             _connect.ssh_argv(console, known, password=True) + [body], env=environment)
    if login.returncode:
        raise ConsoleError('the one-time password did not open an SSH session')
    console.menu('handoff', f'boot {ROOT} -v', until=('ZBOOT_HANDOFF_LOAD',))


def network_boot(ev, check, index, label):
    """The launch and the HTTP server's log of a network boot."""
    directory = Path(ev.root).parent / f'boot-{index}'
    launch = json.loads((directory / 'launch.json').read_text())
    argv = launch['argv']
    devices = [argv[n + 1] for n, arg in enumerate(argv[:-1]) if arg == '-device']
    check.equal([device for device in devices if 'bootindex=' in device],
                ['virtio-net-pci,netdev=zt-net,bootindex=1'], f'{label}: the NIC is the only boot device')
    check(not any('boot.raw' in arg for arg in argv), f'{label}: no stick is attached')
    session = Path(ev.root).parents[2]
    built = json.loads((session / 'efi.json').read_text())['builds']['neutral']['uki_sha256']
    check.equal(launch['inputs'].get('zboot.efi'), built, f'{label}: the server holds the recorded UKI')
    requests = (directory / 'http.log').read_text().splitlines()
    check(bool(requests) and all(line.split()[1:2] == ['/zboot.efi'] for line in requests),
          f'{label}: the firmware asked the server for the UKI only: {requests}')
    size = (directory / 'http/zboot.efi').stat().st_size
    check.contains('\n'.join(requests), f'GET /zboot.efi 200 {size}', f'{label}: the whole UKI was served')


def verdict(ev, check):
    setup = ev.stage(1)
    check.equal(setup.step('deploy').rc, 0, 'the root tar is deployed to A')
    check(setup.step('esp-loaders-before').out.strip() != '', 'deploy installed a disk loader')
    check.equal(setup.step('esp-loaders-after').rc, 0, 'the setup left no EFI executable on the ESP')
    network_boot(ev, check, 2, 'boot2')
    menu = ev.stage(2)
    check.contains(menu.step('ready').out, ROOT, 'the network-booted menu lists the local BE')
    check.contains(menu.step('connect').out, 'One-time root password: ', 'connect prints a password')
    login = menu.step('password-login').out
    check(re.search(r'(?m)^CMDLINE=.*\bzboot\.recovery=1\b', login) is not None,
          'with no loader arguments the UKI runs its own command line')
    check('zboot.ssh_key=' not in login, 'no key came with the network boot')
    check.contains(login, 'NO_LOADER_PARTITION', 'the UKI was not started from a disk partition')
    check.contains(menu.step('ready').out, 'Auto-boot paused', 'a key pauses the countdown')
    check.contains(menu.step('handoff').out, 'ZBOOT_HANDOFF_LOAD', 'the menu loads the BE kernel')
    target = ev.stage(3)
    check.equal(target.step('running-root').out.strip(), ROOT, 'stage3 runs the installed root')
    check.equal(target.step('root-systemd').out.strip(), 'systemd', 'stage3 runs the installed systemd')
    cmdline = target.step('running-cmdline').out
    check('zboot.ssh_key=' not in cmdline and 'zboot.recovery=' not in cmdline,
          'the handoff passes neither the key nor the UKI marker')
    check.contains(cmdline, 'spl.spl_hostid=0x0174627a', 'the BE boots under the adopted hostid')
