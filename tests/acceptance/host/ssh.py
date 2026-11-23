"""Host-side SSH into a guest through its loopback forward (console.ssh_port).

Disposable credentials stay in the case's private run directory; every
command the host runs is recorded as console evidence.
"""
import os
import re
import shlex
import subprocess
import time

from host.console import ConsoleError

# What the menu prints as it starts sshd, and what `connect` adds.
SSH_ENABLED = r'Host key fingerprint: (SHA256:[A-Za-z0-9+/]{43})'
PASSWORD = r'One-time root password: ([23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{12})'


def keygen(run_dir, name):
    """A passphrase-less ed25519 key RUN_DIR/NAME (and NAME.pub)."""
    try:
        result = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                                 '-f', str(run_dir / name)], capture_output=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f'{name} key generation timed out') from error
    (run_dir / f'{name}-keygen.out').write_bytes(result.stdout)
    (run_dir / f'{name}-keygen.err').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f'{name} key generation failed: {result.returncode}')


def write_askpass(run_dir):
    """ssh reads a password from this (password_env)."""
    askpass = run_dir / 'askpass'
    askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$ZT_CONNECT_PASSWORD"\n')
    askpass.chmod(0o700)


def password_env(console, password):
    return dict(os.environ, SSH_ASKPASS=str(console.case_dir / 'askpass'),
                SSH_ASKPASS_REQUIRE='force', DISPLAY='zt-connect:0', ZT_CONNECT_PASSWORD=password)


def record(console, name, argv, result):
    console._record(name, shlex.join([str(arg) for arg in argv]), result.stdout, result.returncode)
    (console.out / f'{console.n:02d}-{name}.err').write_text(result.stderr)
    return result


def command(console, name, argv, *, env=None, timeout=45):
    left = min(timeout, console.deadline - time.monotonic())
    if left <= 0:
        raise TimeoutError(name)
    try:
        result = subprocess.run([str(arg) for arg in argv], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=left,
                                env=env, start_new_session=True)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b''
        errors = error.stderr or b''
        result = subprocess.CompletedProcess(argv, 124,
                    output.decode(errors='replace') if isinstance(output, bytes) else output,
                    errors.decode(errors='replace') if isinstance(errors, bytes) else errors)
        record(console, name, argv, result)
        raise ConsoleError(f'{name}: host SSH command timed out') from error
    return record(console, name, argv, result)


def keyscan(console, known, expected, *, scan_step='host-keyscan', check_step='host-fingerprint',
            tries=0, pause=1):
    """Record one ed25519 scan of the guest's listener into KNOWN and require
    its SHA256 fingerprint to be EXPECTED (`[fingerprint]`). With TRIES, first
    wait (unrecorded) up to TRIES scans, PAUSE seconds apart, for an answer."""
    scan = ['/usr/bin/ssh-keyscan', '-T', '10', '-t', 'ed25519', '-p', str(console.ssh_port), '127.0.0.1']
    for _ in range(tries):
        if subprocess.run(scan, capture_output=True, timeout=30).stdout.strip():
            break
        time.sleep(pause)
    result = command(console, scan_step, scan)
    if result.returncode or not result.stdout.strip():
        raise ConsoleError('SSH listener produced no host key')
    known.write_text(result.stdout)
    actual = command(console, check_step, ['/usr/bin/ssh-keygen', '-l', '-E', 'sha256', '-f', known])
    if actual.returncode or actual.stdout.split()[1:2] != expected:
        raise ConsoleError('SSH host key does not match the console fingerprint')
    return known


def fingerprint(console, ready):
    """Match this boot's advertised key, including any menu redraws, to the listener."""
    hits = sorted(set(re.findall(SSH_ENABLED, ready)))
    if len(hits) != 1:
        raise ConsoleError(f'expected one native host fingerprint, got {hits}')
    # The menu prints the fingerprint as it starts sshd, which may not listen yet.
    return keyscan(console, console.case_dir / f'known-{console.out.name}', hits, tries=10)


def connect(console):
    """`connect` in the menu: (known_hosts, ssh environment) for its one-time
    password. console.ready() first pauses the countdown of a machine with a BE."""
    console.ready()
    enabled = console.menu('connect', 'connect')
    known = fingerprint(console, enabled)
    passwords = re.findall(PASSWORD, enabled)
    if len(passwords) != 1:
        raise ConsoleError('connect did not print exactly one one-time password')
    return known, password_env(console, passwords[0])


def ssh_argv(console, known, *, key='login', password=False):
    args = ['/usr/bin/ssh', '-F', '/dev/null', '-p', str(console.ssh_port),
            '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
            '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={known}',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
            '-o', 'NumberOfPasswordPrompts=1']
    if password:
        args += ['-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password',
                 '-o', 'KbdInteractiveAuthentication=no', '-o', 'BatchMode=no']
    else:
        args += ['-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                 '-o', 'PreferredAuthentications=publickey', '-i', str(console.case_dir / key)]
    return args + ['root@127.0.0.1']
