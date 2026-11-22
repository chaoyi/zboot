"""Real one-boot ESP keys, authentication, timeout and installed-root handoff.
Seven QEMU launches: setup; key login; ordinary boot; full no-auth expiry;
empty request and explicit one-time password; SSH repair and ClientAlive timeout; parent-death custody recovery. No timer is shortened.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import shlex
import socket
import subprocess
import time
import uuid

from host.case import Boot
from host.console import ConsoleError, MENU_PROMPT, READY
from host.ssh import (PASSWORD, command, fingerprint, keygen, password_env, record, ssh_argv,
                      write_askpass)

ID = 'EFI-CONNECT'
GROUP = 'efi'
SECONDS = 4200
DISKS = {'A': 8, 'B': 2, 'D': 2}
# Only local transports permit unattended countdown. The first key-consumption
# leg deliberately stays USB; the held console/custody legs retain virtio.
BOOTS = [Boot(1),
         Boot(2, efi=True, target=3, extra={'from': 'A', 'bus': 'usb'}, network=True),
         Boot(4, efi=True, target=5, extra={'from': 'A', 'bus': 'nvme'}, network=True),
         Boot(6, efi=True, target=7, extra={'from': 'A', 'bus': 'nvme'}, network=True),
         Boot(8, efi=True, extra={'from': 'A'}, network=True),
         Boot(10, efi=True, target=11, poweroff=True, extra={'from': 'A', 'bus': 'nvme'}, network=True),
         Boot(12, efi=True, extra={'from': 'A'}, network=True)]
ROOT = 'e2ea/ROOT/proof'
# An automatic boot is not verbose, so it prints no ZBOOT_HANDOFF_LOAD line.
STARTING = 'Starting the installed system...'
CONSUMED = 'One-boot ESP remote request deleted and synced before networking.'
WAIT_ENDED = 'Remote-access wait ended. Automatic boot follows the ordinary menu conditions.'
RECOVERED = 'Menu SSH: previous owned cgroups closed before startup.'
SESSION_ENDED = 'Automatic SSH session ended. Automatic boot follows the ordinary menu conditions.'
LAST_ENDED = 'Menu SSH: last authenticated session ended; owned cgroup closed.'


def prepare(run_dir):
    """Disposable credentials stay in this private case; only public bytes share."""
    for name in ('login', 'wrong'):
        keygen(run_dir, name)
    public = run_dir / 'public'
    public.mkdir(mode=0o700)
    public.joinpath('authorized_keys').write_bytes(run_dir.joinpath('login.pub').read_bytes())
    write_askpass(run_dir)
    run_dir.joinpath('connect-inputs.json').write_text(json.dumps({
        'public_key_sha256': hashlib.sha256(public.joinpath('authorized_keys').read_bytes()).hexdigest(),
        'qemu_boots': len(BOOTS), 'wait_seconds': 600,
    }, indent=2) + '\n')


def shares(run_dir, _boot):
    return [('zt-connect-key', run_dir / 'public')]


def consumed(console):
    text = console.expect(CONSUMED, 900)
    instant = time.monotonic()
    console._record('consumed', '', text, 0)
    return instant


def pause_remote(console):
    start = console.pos
    console.drain.send(b' ')
    console.expect('Menu held by the console.', 60)
    console.expect(MENU_PROMPT, 60)
    console._record('console-hold', '<one bare space>', console._text(start, console.pos), 0)


def no_banner(console, name):
    """Slirp still accepts the host forward after sshd stops: inspect payload."""
    started = time.monotonic()
    data = b''
    detail = ''
    try:
        with socket.create_connection(('127.0.0.1', console.ssh_port), timeout=2) as connection:
            connection.settimeout(2)
            try:
                data = connection.recv(256)
            except (TimeoutError, ConnectionError, OSError) as error:
                detail = type(error).__name__
    except (ConnectionError, OSError) as error:
        detail = type(error).__name__
    output = json.dumps({'banner': data.decode(errors='replace'), 'detail': detail,
                         'elapsed_seconds': time.monotonic() - started})
    console._record(name, f'TCP 127.0.0.1:{console.ssh_port}; receive only, no authentication', output, 0)
    if data.startswith(b'SSH-'):
        raise ConsoleError(f'{name}: SSH listener is still active')


def key_session(console, known):
    # Keep the first authenticated session alive until the physical-console
    # hold is observed; no race with the session-ended countdown is hidden.
    body = r'''set -e
mkdir -p /run/zt-connect-esp
disk=$(lsblk -dnpo PATH,SERIAL | awk '$2 == "ZFS-E2E-A" {print $1}')
test -b "$disk"
esp=$(lsblk -nrpo PATH,PARTTYPE "$disk" | awk 'tolower($2) == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {print $1}')
test -b "$esp"
printf 'ZT_BOOT_DISK=%s\nZT_BOOT_ESP=%s\n' "$disk" "$esp"
lsblk -dnpo PATH,SERIAL,TRAN "$disk"
mount -t vfat -o ro,nosuid,nodev,noexec "$esp" /run/zt-connect-esp
test ! -e /run/zt-connect-esp/zboot/authorized_keys
printf 'REQUEST_ABSENT\n'
umount /run/zt-connect-esp
cat /run/zboot-connect/sshd_config
printf 'ZT_SSH_HOLD_READY\n'
sleep 120'''
    argv = ssh_argv(console, known) + [body]
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    output = bytearray()
    try:
        deadline = min(console.deadline, time.monotonic() + 45)
        while b'ZT_SSH_HOLD_READY\n' not in output:
            if time.monotonic() >= deadline:
                raise TimeoutError('key-authenticated SSH session did not become ready')
            if select.select([child.stdout], [], [], 1)[0]:
                data = os.read(child.stdout.fileno(), 65536)
                if not data:
                    raise ConsoleError('key-authenticated SSH session ended before its proof')
                output.extend(data)
        pause_remote(console)
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            tail, errors = child.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            tail, errors = child.communicate(timeout=10)
        output.extend(tail)
        record(console, 'key-login', argv, subprocess.CompletedProcess(
            argv, child.returncode, output.decode(errors='replace'), errors.decode(errors='replace')))


def capture_log(console, name):
    # Read the exact native datagrams, not a second parser's summary.
    console.must(name, 'sleep 1; cat /run/zboot-connect/sshd.log')


def stage_2(console):
    consumed(console)
    ready = console.ready()
    known = fingerprint(console, ready)
    key_session(console, known)
    # The supervisor announces the session's end on this console; take it
    # here so it cannot land inside a shell step's output.
    console.expect(LAST_ENDED, 60)
    console.enter_shell()
    console.must('firmware-var', '/bin/busybox od -An -v -tx1 /sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f')
    capture_log(console, 'key-auth-log')
    console.leave_shell()
    console.menu('handoff', f'boot {ROOT} -v', until=('ZBOOT_HANDOFF_LOAD',))


def stage_4(console):
    # Never send a key: this is the following boot's real ordinary countdown.
    start = console.pos
    console.expect(READY, 900)
    no_banner(console, 'ordinary-no-ssh')
    console.expect(STARTING, 120)
    console._record('ordinary-autoboot', '', console._text(start, console.pos), 0)


def stage_6(console):
    started = consumed(console)
    ready = console.ready()  # a remote wait prompts, but sends no input
    known = fingerprint(console, ready)  # unauthenticated connection alone
    failed = command(console, 'failed-key', ssh_argv(console, known, key='wrong') + ['true'])
    if failed.returncode == 0:
        raise ConsoleError('an unlisted key authenticated')
    with socket.create_connection(('127.0.0.1', console.ssh_port), timeout=5) as connection:
        connection.sendall(b'SSH-2.0-ZBOOT-NO-AUTH\r\n')
    console._record('connection-only', 'TCP SSH version exchange, then close without authentication', '', 0)
    before = console.pos
    console.expect(WAIT_ENDED, 700)
    elapsed = time.monotonic() - started
    console._record('full-wait', 'real monotonic wall clock; no guest clock adjustment',
                    json.dumps({'elapsed_seconds': elapsed, 'required_seconds': 600,
                                'delivery_tolerance_seconds': 1}), 0)
    no_banner(console, 'expired-no-ssh')
    console.expect(STARTING, 120)
    console._record('expiry-autoboot', '', console._text(before, console.pos), 0)


def stage_8(console):
    consumed(console)
    console.ready()
    no_banner(console, 'empty-no-ssh')
    pause_remote(console)
    enabled = console.menu('connect', 'connect')
    known = fingerprint(console, enabled)
    passwords = re.findall(PASSWORD, enabled)
    if len(passwords) != 1:
        raise ConsoleError('connect did not print exactly one bounded password')
    environment = password_env(console, passwords[0])
    logged = command(console, 'password-login', ssh_argv(console, known, password=True) + ['printf PASSWORD_LOGIN_OK'], env=environment)
    if logged.returncode or logged.stdout != 'PASSWORD_LOGIN_OK':
        raise ConsoleError('printed one-time password did not authenticate')
    # As in stage 2, take the supervisor's session-end line before the shell.
    console.expect(LAST_ENDED, 60)
    console.enter_shell()
    console.must('password-retired', "awk -F: '$1 == \"root\" { print $2; if ($2 != \"NP\") exit 1 }' /etc/shadow")
    capture_log(console, 'password-auth-log')
    console.leave_shell()
    reused = command(console, 'password-reuse', ssh_argv(console, known, password=True) + ['true'], env=environment)
    if reused.returncode == 0:
        raise ConsoleError('the one-time password authenticated twice')
    console.menu('held-status', 'status')
    # This firmware-only boot intentionally has no shares. Inject only the
    # disposable public bytes already owned by the host fixture, never its key.
    public = console.case_dir.joinpath('public/authorized_keys').read_text()
    console._record('repair-request-input', 'host-owned public key bytes', json.dumps({
        'bytes': len(public.encode()), 'sha256': hashlib.sha256(public.encode()).hexdigest(),
        'fingerprint': 'SHA256:' + base64.b64encode(hashlib.sha256(
            base64.b64decode(public.split()[1], validate=True)).digest()).decode().rstrip('='),
    }), 0)
    console.enter_shell()
    console.must('arm-repair-key', 'set -e; mkdir -p /run/zt-connect-arm; '
        'mount -t vfat -o nosuid,nodev,noexec /dev/vda1 /run/zt-connect-arm; '
        'test -d /run/zt-connect-arm/zboot; printf %s ' +
        shlex.quote(base64.b64encode(public.encode()).decode()) +
        ' | /bin/busybox base64 -d > /run/zt-connect-arm/zboot/authorized_keys; '
        'sha256sum /run/zt-connect-arm/zboot/authorized_keys; '
        '/bin/busybox wc -c < /run/zt-connect-arm/zboot/authorized_keys; '
        'sync /run/zt-connect-arm/zboot/authorized_keys; sync /run/zt-connect-arm/zboot; '
        'umount /run/zt-connect-arm')
    setting = shlex.quote('console=ttyS0,115200 zt.case=EFI-CONNECT zt.stage=11')
    console.must('arm-repair-cmdline', f'set -e; zboot cmdline {ROOT} --set {setting} --dry-run --json > /dev/null; '
        f'zboot cmdline {ROOT} --set {setting} --json')
    console.leave_shell()


def stage_10(console):
    # Never send a console key: this must end through the server's real
    # ClientAlive policy, then refresh the kernel request before autoboot.
    consumed(console)
    start = console.pos
    console.expect(READY, 900)
    console.expect(MENU_PROMPT, 120)
    ready = console._text(start, console.pos)
    console._record('ready', 'passive read only; never pause a countdown', ready, 0)
    known = fingerprint(console, ready)
    argv = ssh_argv(console, known)
    argv[1:1] = ['-N']
    argv[argv.index('LogLevel=ERROR')] = 'LogLevel=DEBUG1'
    debug_path = console.case_dir / 'clientalive-ssh.err'
    child = None
    with debug_path.open('wb') as errors:
        try:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=errors, start_new_session=True)
            deadline = min(console.deadline, time.monotonic() + 45)
            while b'Authenticated to ' not in debug_path.read_bytes():
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise ConsoleError('owned ssh -N did not authenticate before repair')
                time.sleep(0.1)
            # Preserve the ABI and bytes, but change the actual selected paths.
            # Cmdline-only edits do not distinguish an old HandoffRequest.
            repair = r'''set -e
kernel=$(readlink -f /vmlinuz)
initrd=$(readlink -f /initrd.img)
test "$kernel" != /boot/vmlinuz-zt-after-ssh
test "$initrd" != /boot/initrd.img-zt-after-ssh
printf 'ZT_OLD_KERNEL=%s\nZT_OLD_INITRD=%s\n' "$kernel" "$initrd"
sha256sum "$kernel" "$initrd"
cp "$kernel" /boot/vmlinuz-zt-after-ssh
cp "$initrd" /boot/initrd.img-zt-after-ssh
ln -sfn boot/vmlinuz-zt-after-ssh /vmlinuz
ln -sfn boot/initrd.img-zt-after-ssh /initrd.img
sync /boot/vmlinuz-zt-after-ssh /boot/initrd.img-zt-after-ssh /boot /
printf 'ZT_NEW_KERNEL=%s\nZT_NEW_INITRD=%s\n' "$(readlink -f /vmlinuz)" "$(readlink -f /initrd.img)"
sha256sum /boot/vmlinuz-zt-after-ssh /boot/initrd.img-zt-after-ssh'''
            body = (f'set -e; zboot chroot {ROOT} -- /bin/sh -e -c ' + shlex.quote(repair) +
                    '; printf "ZT_REPAIR_APPLIED\\n"; zpool get -H -o value readonly e2ea; '
                    'cat /run/zboot-connect/sshd_config; '
                    'printf "ZT_REPAIR_LOG_BEGIN\\n"; cat /run/zboot-connect/sshd.log')
            result = command(console, 'ssh-kernel-repair', ssh_argv(console, known) + [body], timeout=300)
            if result.returncode:
                raise ConsoleError('actual zboot chroot SSH repair failed')
            # Only this Popen belongs to the fixture. Its socket remains open,
            # but the stopped client cannot answer server keepalive requests.
            child.send_signal(signal.SIGSTOP)
            started = time.monotonic()
            before = console.pos
            console.expect(SESSION_ENDED, 180)
            elapsed = time.monotonic() - started
            console.expect(STARTING, 120)
            text = console._text(before, console.pos)
            console._record('clientalive-autoboot', 'SIGSTOP owned ssh -N; unchanged server ClientAlive policy',
                            text, 0)
            console._record('clientalive-wait', 'real monotonic wall clock',
                            json.dumps({'elapsed_seconds': elapsed, 'client_pid': child.pid,
                                        'signal': 'SIGSTOP', 'interval': 30, 'count_max': 3}), 0)
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()  # SIGKILL also terminates the stopped client.
                child.wait(timeout=10)
                record(console, 'clientalive-client', argv, subprocess.CompletedProcess(
                    argv, child.returncode, '', debug_path.read_text(errors='replace')))


def process_identity(stat):
    pid, rest = stat.split(' (', 1)
    fields = rest.rsplit(') ', 1)[1].split()
    return {'pid': int(pid), 'parent': int(fields[1]), 'group': int(fields[2]),
            'session': int(fields[3]), 'starttime': int(fields[19])}


def stage_12(console):
    consumed(console)
    known = fingerprint(console, console.ready())
    # The inner background shell is reparented after setsid's launcher exits;
    # its cwd keeps this real, disposable RAM mount busy until custody closes.
    detached = ('set -e; cd /run/zt-connect-custody-mount; '
                'printf "%s\\n" "$$" > /run/zt-connect-custody-job; '
                'exec /bin/busybox sleep 2147483647')
    launcher = '/bin/sh -c ' + shlex.quote(detached) + ' </dev/null >/dev/null 2>&1 &'
    body = ('set -e; mkdir -p /run/zt-connect-custody-mount; '
            'mount -t tmpfs -o nosuid,nodev,noexec tmpfs /run/zt-connect-custody-mount; '
            '/bin/busybox setsid /bin/sh -c ' + shlex.quote(launcher) +
            ' </dev/null >/dev/null 2>&1; '
            'i=0; while test ! -s /run/zt-connect-custody-job; do '
            'test "$i" -lt 100; i=$((i+1)); sleep 0.1; done; '
            'job=$(cat /run/zt-connect-custody-job); '
            'printf "ZT_SSH_CGROUP_BEGIN\\n"; cat /proc/$$/cgroup; '
            'printf "ZT_JOB_CGROUP_BEGIN\\n"; cat /proc/$job/cgroup; '
            'printf "ZT_JOB_STAT_BEGIN\\n"; cat /proc/$job/stat; '
            'printf "ZT_JOB_CWD_BEGIN\\n"; /bin/busybox readlink /proc/$job/cwd; '
            'printf "ZT_CUSTODY_HOLD_READY\\n"; exec /bin/busybox sleep 2147483647')
    argv = ssh_argv(console, known) + [body]
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    output = bytearray()
    try:
        deadline = min(console.deadline, time.monotonic() + 45)
        while b'ZT_CUSTODY_HOLD_READY\n' not in output:
            if time.monotonic() >= deadline:
                raise ConsoleError('detached SSH custody fixture did not become ready')
            if select.select([child.stdout], [], [], 1)[0]:
                data = os.read(child.stdout.fileno(), 65536)
                if not data:
                    raise ConsoleError('SSH custody session ended before its proof')
                output.extend(data)
                if len(output) > 65536:
                    raise ConsoleError('SSH custody proof exceeds its bound')
        proof = output.decode()
        ssh_group = proof.split('ZT_SSH_CGROUP_BEGIN\n', 1)[1].split('ZT_JOB_CGROUP_BEGIN\n', 1)[0].strip()
        job_group = proof.split('ZT_JOB_CGROUP_BEGIN\n', 1)[1].split('ZT_JOB_STAT_BEGIN\n', 1)[0].strip()
        match = re.fullmatch(r'0::(/zboot-connect/ssh-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})', ssh_group)
        if match is None or job_group != ssh_group:
            raise ConsoleError('real detached job did not inherit the exact owned SSH cgroup')
        leaf = '/sys/fs/cgroup' + match[1]
        job = process_identity(proof.split('ZT_JOB_STAT_BEGIN\n', 1)[1].splitlines()[0])
        if proof.split('ZT_JOB_CWD_BEGIN\n', 1)[1].splitlines()[0] != '/run/zt-connect-custody-mount':
            raise ConsoleError('detached native job does not hold the actual RAM mount')
        empty = '/sys/fs/cgroup/zboot-connect/ssh-' + str(uuid.uuid4())
        pause_remote(console)
        console.enter_shell()
        console.must('custody-before', 'set -e; printf "ZT_MENU_STAT_BEGIN\\n"; cat /proc/$PPID/stat; '
            'printf "ZT_MENU_EXE_BEGIN\\n"; /bin/busybox readlink /proc/$PPID/exe; '
            'printf "ZT_MENU_ARGV_BEGIN\\n"; /bin/busybox tr "\\000" "\\n" < /proc/$PPID/cmdline; '
            'printf "ZT_CONSOLE_CGROUP_BEGIN\\n"; cat /proc/$$/cgroup; '
            'printf "ZT_INTERFACE_BEGIN\\n"; cat /run/zboot-connect/network-interface')
        before = (console.out / f'{console.n:02d}-custody-before.out').read_text()
        menu = process_identity(before.split('ZT_MENU_STAT_BEGIN\n', 1)[1].splitlines()[0])
        executable = before.split('ZT_MENU_EXE_BEGIN\n', 1)[1].splitlines()[0]
        arguments = before.split('ZT_MENU_ARGV_BEGIN\n', 1)[1].split('ZT_CONSOLE_CGROUP_BEGIN\n', 1)[0].splitlines()
        outside = before.split('ZT_CONSOLE_CGROUP_BEGIN\n', 1)[1].split('ZT_INTERFACE_BEGIN\n', 1)[0].strip()
        interface = before.split('ZT_INTERFACE_BEGIN\n', 1)[1].strip()
        if executable != '/usr/bin/zboot' or arguments != ['/usr/bin/zboot', 'menu']:
            raise ConsoleError('physical shell parent is not this boot\'s exact initial Menu')
        if outside == ssh_group or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
            raise ConsoleError('physical late-join holder is not outside valid SSH custody')
        console._record('custody-identities', 'native /proc stat, cgroup and parent executable evidence',
                        json.dumps({'menu': menu, 'job': job, 'leaf': leaf,
                                    'empty_leaf': empty, 'interface': interface}), 0)
        capture_log(console, 'custody-auth-log')
        # One direct shell line: fd9 belongs to the physical shell outside the
        # leaf and stays open across Menu death. Do not execute a program after
        # trying the stale join; only printf/exec/exit shell builtins remain.
        kill = (f'test "$PPID" = {menu["pid"]} && '
                f'test "$(awk \'{{print $22}}\' /proc/$PPID/stat)" = {menu["starttime"]} && '
                f'test "$(/bin/busybox readlink /proc/$PPID/exe)" = /usr/bin/zboot && '
                f'exec 9>{shlex.quote(leaf + "/cgroup.procs")}; '
                'test "$?" -eq 0 || exit 1; '
                f'mkdir -m 700 {shlex.quote(empty)} || exit 1; '
                f'kill -KILL {menu["pid"]} || exit 1; '
                f'i=0; while test -d {shlex.quote(leaf)} || test -d {shlex.quote(empty)}; do '
                # Split the marker so the echoed command line cannot match it.
                'test "$i" -lt 120 || { printf "ZT_CUSTODY_RECOVERY_%s\\n" TIMEOUT; exit 1; }; '
                'i=$((i+1)); sleep 0.5; done; '
                'set +e; printf 0 >&9; result=$?; printf "ZT_LATE_JOIN_RC=%s\\n" "$result"; exec 9>&-; exit')
        if len(kill) > 2500:
            raise ConsoleError('bounded custody kill line exceeds its console limit')
        start = console.pos
        console.send(kill)
        markers = {
            'recovered': re.escape(RECOVERED.encode()),
            'ready': re.escape(READY.encode()),
            'prompt': re.escape(MENU_PROMPT.encode()),
            # The old shell shares the console with the restarted menu, so
            # its line can follow the menu's prompt.
            'late_join': rb'ZT_LATE_JOIN_RC=\d+\r?\n',
        }
        deadline = min(console.deadline, time.monotonic() + 180)
        while markers:
            end = console.drain.expect(b'|'.join(markers.values()) + rb'|ZT_CUSTODY_RECOVERY_TIMEOUT',
                                       deadline, console.pos)
            found = console._text(console.pos, end)
            console.pos = end
            if found.endswith('ZT_CUSTODY_RECOVERY_TIMEOUT'):
                raise ConsoleError('restart did not close both exact custody leaves')
            for name, pattern in list(markers.items()):
                if re.search(pattern, found.encode()):
                    del markers[name]
        console._record('custody-restart', kill, console._text(start, console.pos), 0)
        no_banner(console, 'custody-no-ssh')
        console.enter_shell()
        # Exact PID/starttime handles reuse; a reparented zombie has already
        # exited and holds neither the mount nor the recovered cgroup alive.
        console.must('custody-after', f'set -e; test ! -d {shlex.quote(leaf)}; '
            f'test ! -d {shlex.quote(empty)}; '
            f'if test -r /proc/{job["pid"]}/stat; then '
            f'awk \'{{if ($22 == {job["starttime"]} && $3 != "Z") exit 1}}\' /proc/{job["pid"]}/stat; fi; '
            'test ! -e /run/zboot-connect/dhcp-lease; '
            'test ! -e /run/zboot-connect/network-interface; '
            'test ! -e /run/zboot-connect/authorized_keys; '
            'awk -F: \'$1 == "root" { print $2; if ($2 != "NP") exit 1 }\' /etc/shadow; '
            f'/bin/ip -o -4 addr show dev {shlex.quote(interface)}; '
            f'test -z "$(/bin/ip -o -4 addr show dev {shlex.quote(interface)})"; '
            'zpool get -H -o value readonly e2ea; test "$(zpool get -H -o value readonly e2ea)" = on; '
            'umount /run/zt-connect-custody-mount; /bin/busybox rmdir /run/zt-connect-custody-mount; '
            'printf "CUSTODY_CLOSED\\n"')
        console.leave_shell()
        console.menu('custody-status', 'status')
    finally:
        if child.poll() is None:
            child.kill()
        try:
            tail, errors = child.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            tail, errors = child.communicate(timeout=10)
        output.extend(tail)
        record(console, 'custody-login', argv, subprocess.CompletedProcess(
            argv, child.returncode, output.decode(errors='replace'), errors.decode(errors='replace')))


def log_records(step):
    return raw_log_records(step.out)


def raw_log_records(output):
    entries = [json.loads(line) for line in output.splitlines() if line.strip()]
    records = []
    for entry in entries:
        if not isinstance(entry.get('listener_pid'), int) or entry.get('process_group') != entry['listener_pid']:
            raise ValueError('native SSH log lacks its owned listener/group binding')
        records.append(bytes(entry['record']).decode('utf-8'))
    return records


def target(ev, check, stage):
    observed = ev.stage(stage)
    transport = {3: 'usb', 5: 'nvme', 7: 'nvme', 11: 'nvme'}[stage]
    check.equal(observed.step('boot-disk-bus').out.split()[1:], ['ZFS-E2E-A', transport],
                f'stage{stage}: real installed root retains the expected {transport} A identity after kexec')
    check.equal(observed.step('esp-partuuid').out.strip(), ev.stage(1).step('setup-esp-partuuid').out.strip(),
                f'stage{stage}: transport changes preserve the original owned A1 PARTUUID')
    check.equal(observed.step('running-root').out.strip(), ROOT, f'stage{stage} is the actual installed ZFS root')
    check.equal(observed.step('root-systemd').out.strip(), 'systemd', f'stage{stage} uses the installed systemd')
    for name in ('installed-version', 'installed-sha256', 'loader-var-mounts', 'loader-variable'):
        check.equal(observed.step(name).rc, 0, f'stage{stage}: {name}')
    check(observed.step('installed-package').rc in (0, 1),
          f'stage{stage}: zboot package query is retained')
    installed = re.fullmatch(r'([0-9a-f]{64})  /usr/bin/zboot\n?', observed.step('installed-sha256').out)
    setup = ev.stage(1).step('setup-sha256')
    check.equal(setup.rc, 0, 'setup independently records this fresh family executable')
    check(installed is not None and installed[1] == setup.out.split()[0],
          f'stage{stage}: installed executable matches the fresh setup family bytes')
    raw = observed.step('loader-variable').out.split()
    check.equal(len(raw), 78, f'stage{stage}: actual handoff preserves the bounded firmware variable; absence requires product fallback')
    preview = observed.step('reboot-preview')
    if transport == 'usb':
        check(preview.rc != 0, f'stage{stage}: reboot --menu refuses the booted ESP on a USB disk')
        check.equal(preview.json.get('mode'), 'refused', f'stage{stage}: the booted USB ESP is a refusal')
        check.contains(preview.out, 'to keep using this one', f'stage{stage}: the refusal says to name it with --esp')
        preview = observed.step('reboot-esp-preview')
    check.equal(preview.rc, 0, f'stage{stage}: installed reboot --menu dryrun')
    envelope = preview.json
    check.equal(envelope.get('mode'), 'preview', f'stage{stage}: normal preview envelope')
    check.equal(envelope.get('result', {}).get('target', {}).get('partition', {}).get('partition_uuid'),
                observed.step('esp-partuuid').out.strip(), f'stage{stage}: reboot resolves this boot ESP')
    return observed


def verdict(ev, check):
    setup = ev.stage(1)
    check.equal(setup.step('deploy').rc, 0, 'fresh factory installed through current deploy')
    check.equal(setup.step('probe-enabled').rc, 0, 'installed real-root probe enabled')
    check.equal(setup.step('request-key').rc, 0, 'first key request persisted on the actual boot ESP')
    first = ev.stage(2)
    check.equal(first.step('firmware-var').rc, 0, 'actual firmware menu exposes LoaderDevicePartUUID before handoff')
    # The menu may print a status line into the shell's output; count the dump's lines only.
    dump = [line for line in first.step('firmware-var').out.splitlines() if re.fullmatch(r'( [0-9a-f]{2})+', line)]
    check.equal(sum(len(line.split()) for line in dump), 78, 'firmware variable has exact native attribute/UTF16 bytes')
    text = first.step('consumed').out + first.step('ready').out
    check(text.index(CONSUMED) < text.index('Menu SSH enabled on '), 'ESP deletion/sync/unmount precedes network listener announcement')
    check(re.search(r'(?m)^/dev/sd[a-z]+\s+ZFS-E2E-A\s+usb\s*$', first.step('key-login').out) is not None,
          'firmware automatic key request is consumed from the actual USB A disk')
    check.contains(first.step('key-login').out, 'REQUEST_ABSENT', 'authenticated native ESP read sees request gone')
    check.contains(first.step('key-login').out, 'PasswordAuthentication no', 'key-started sshd never offers password')
    check.contains(first.step('console-hold').out, 'Menu held by the console.', 'physical console holds after successful authentication')
    key_records = ''.join(log_records(first.step('key-auth-log')))
    check(re.search(r'auth\.c:auth_log\(\).*Accepted publickey for root from ', key_records) is not None,
          'raw owned sshd datagrams prove actual root publickey authentication')
    check(re.search(r'(session_close|process_input|sshpkt_vfatal)\(', key_records) is not None,
          'raw owned sshd datagrams retain session termination evidence')
    installed = target(ev, check, 3)
    preview = installed.step('reboot-key-preview')
    check.equal(preview.rc, 0, 'installed normal CLI reviews a symlinked public-key source')
    partial = installed.step('reboot-partial')
    check.equal(partial.rc, 4, 'real ESP publication followed by service-manager failure is partial')
    check.equal(partial.json.get('mode'), 'partial', 'normal finalizer emits one partial envelope')
    message = partial.json.get('result', {}).get('message', '')
    check.contains(message, 'a one-boot menu request may remain at zboot/authorized_keys',
                   'partial result explains the retained exact request')
    check.contains(message, installed.step('esp-partuuid').out.strip(),
                   'partial guidance identifies the exact native partition UUID')
    check.contains(message, preview.json['result']['target']['partition']['path'],
                   'partial guidance identifies the reviewed native ESP path')
    check.equal(installed.step('reboot-systemctl').out.splitlines(),
                ['reboot', 'SYSTEMCTL_SKIP_AUTO_KEXEC=1', 'SYSTEMCTL_SKIP_AUTO_SOFT_REBOOT=1'],
                'actual CLI dispatch forces a firmware reboot, excluding automatic kexec/soft reboot')
    published = installed.step('reboot-published-key')
    check.equal(published.rc, 0, 'native ESP read matches the exact canonical reviewed public bytes')
    check.equal(published.out.split()[0], preview.json['result']['authorized_keys_sha256'],
                'published key digest equals the actual reviewed canonical payload')
    check.equal(installed.step('reboot-request-cleanup').rc, 0,
                'fixture removes and syncs only its retained request before following ordinary boot')
    ordinary = ev.stage(4)
    check('Remote-access wait lasts' not in ordinary.step('ordinary-autoboot').out, 'following boot has no stale remote request')
    check.contains(ordinary.step('ordinary-autoboot').out, 'Auto-booting ', 'following boot takes the ordinary countdown')
    second = target(ev, check, 5)
    check.equal(second.step('arm-key').rc, 0, 'next native request uses the same public key')
    expiry = ev.stage(6)
    wait = expiry.step('full-wait').json
    check(wait['elapsed_seconds'] >= 599, f'full real600-second noauth window with <=1s serial delivery tolerance: {wait}')
    check(expiry.step('failed-key').rc != 0, 'failed authentication does not hold the menu')
    check.contains(expiry.step('expiry-autoboot').out, WAIT_ENDED, 'unused SSH wait expires')
    check.contains(expiry.step('expiry-autoboot').out, 'Auto-booting ', 'ordinary countdown returns after listener stops')
    third = target(ev, check, 7)
    check.equal(third.step('arm-empty').rc, 0, 'empty request persisted for final boot')
    last = ev.stage(8)
    check('Menu SSH enabled' not in last.step('ready').out, 'empty request starts no SSH')
    check.equal(last.step('password-login').out, 'PASSWORD_LOGIN_OK', 'printed password logs in once')
    check(last.step('password-reuse').rc != 0, 'password cannot be reused')
    check.equal(last.step('password-retired').out.strip(), 'NP', 'first authentication removes root password hash')
    password_records = ''.join(log_records(last.step('password-auth-log')))
    check(re.search(r'auth\.c:auth_log\(\).*Accepted password for root from ', password_records) is not None,
          'raw owned sshd datagrams prove actual root password authentication')
    check(re.search(r'(session_close|process_input|sshpkt_vfatal)\(', password_records) is not None,
          'password session end is retained in raw native records')
    # The repair is a normal CLI writer action under actual root SSH. Its
    # before/after hashes prove the new kernel names preserve the boot ABI.
    repair_boot = ev.stage(10)
    check.equal(last.step('arm-repair-key').rc, 0, 'next request is synced on actual A1')
    request_input = last.step('repair-request-input').json
    check.equal(last.step('arm-repair-key').out.split()[0], request_input['sha256'],
                'armed request contains exactly the host-owned public bytes')
    check.equal(int(last.step('arm-repair-key').out.split()[-1]), request_input['bytes'],
                'armed request retains the exact public byte count')
    check.equal(last.step('arm-repair-cmdline').json.get('mode'), 'applied',
                'normal CLI applies the installed stage11 command line')
    repair = repair_boot.step('ssh-kernel-repair')
    check.equal(repair.rc, 0, 'normal zboot chroot completes the authenticated repair')
    check.contains(repair.out, 'ZT_REPAIR_APPLIED\non\n', 'writer returns the selected pool to readonly')
    check.contains(repair.out, 'ClientAliveInterval 30', 'native server uses the full configured keepalive interval')
    check.contains(repair.out, 'ClientAliveCountMax 3', 'native server uses the full configured keepalive count')
    hashes = re.findall(r'(?m)^([0-9a-f]{64})  (/boot/[^\n]+)$', repair.out)
    check.equal(len(hashes), 4, 'both original and copied kernel pairs are independently hashed')
    check.equal([value for value, _ in hashes[:2]], [value for value, _ in hashes[2:]],
                'path-changing repair preserves exact kernel and initrd bytes')
    check.contains(repair.out, 'ZT_NEW_KERNEL=/boot/vmlinuz-zt-after-ssh', 'repair changes the kernel alias target')
    check.contains(repair.out, 'ZT_NEW_INITRD=/boot/initrd.img-zt-after-ssh', 'repair changes the initrd alias target')
    native_log = repair.out.split('ZT_REPAIR_LOG_BEGIN\n', 1)[1]
    records = raw_log_records(native_log)
    check(sum(re.search(r'auth\.c:auth_log\(\).*Accepted publickey for root from ', row) is not None
              for row in records) >= 2, 'native records bind both real SSH logins before timeout')
    check.contains(repair_boot.step('ready').out, request_input['fingerprint'],
                   'native startup admits the same armed public-key fingerprint')
    wait = repair_boot.step('clientalive-wait').json
    check(wait['elapsed_seconds'] >= 85, 'ClientAlive release waits for real interval/count failure, not immediate EOF')
    transcript = repair_boot.step('clientalive-autoboot').out
    check.contains(transcript, SESSION_ENDED, 'normal native session-end cleanup releases the automatic hold')
    check.contains(transcript, 'Auto-booting ', 'ordinary countdown restarts after the last SSH session')
    check('menu SSH:' not in transcript and 'menu SSH cleanup:' not in transcript,
          'timeout is a normal session end rather than supervisor failure')
    check('Menu held by the console.' not in transcript, 'timeout boot receives no physical-console hold')
    repaired = target(ev, check, 11)
    aliases = repaired.step('repaired-aliases')
    check.equal(aliases.rc, 0, 'the real installed target retains both new selected paths')
    check.equal(aliases.out.splitlines()[:2], ['/boot/vmlinuz-zt-after-ssh', '/boot/initrd.img-zt-after-ssh'],
                'handoff reaches the repaired installed root aliases')
    check.equal(re.findall(r'(?m)^([0-9a-f]{64})  ', aliases.out), [value for value, _ in hashes[2:]],
                'real installed target reads the exact repaired native kernel pair')
    preview = repaired.step('reboot-success-preview')
    applied = repaired.step('reboot-success-apply')
    check.equal((preview.rc, preview.json.get('mode')), (0, 'preview'),
                'installed root reviews the actual CLI reboot and exact public file')
    check.equal((applied.rc, applied.json.get('mode')), (0, 'applied'),
                'normal installed CLI publishes the request and queues the real service-manager reboot')
    check('token' not in preview.json and 'token' not in applied.json, 'reboot --menu loses nothing and prints no token')
    order = repaired.step('reboot-success-order').out
    check.contains(order, 'ActiveState=active', 'runtime shutdown guard is active before the real reboot')
    check(re.search(r'(?m)^After=.*\bzt-connect-probe\.service\b', order) is not None,
          'reverse shutdown ordering keeps the actual probe alive for evidence capture')
    for relation in ('Before', 'Conflicts'):
        check(re.search(r'(?m)^' + relation + r'=.*\bshutdown\.target\b', order) is not None,
              f'runtime guard keeps the normal {relation} shutdown dependency')
    public = (Path(ev.root).parent / 'public/authorized_keys').read_text()
    canonical = (' '.join(public.split()[:2]) + '\n').encode()
    canonical_sha = hashlib.sha256(canonical).hexdigest()
    check.equal(preview.json['result']['authorized_keys_sha256'], canonical_sha,
                'real reboot review binds independently canonicalized exact public bytes')
    published = repaired.step('reboot-success-published-key')
    check.equal(published.rc, 0, 'native ESP read matches the canonical request before hardware reboot')
    check.equal(published.out.split()[0], canonical_sha, 'native published request has the expected public-key digest')
    check.equal(repaired.step('reboot-success-published-unmount').rc, 0, 'native proof releases the ESP before reboot')
    reboot_record = next(boot for boot in ev.boots if boot['stage'] == 10)
    check.equal((reboot_record.get('target_event'), reboot_record.get('exit'), reboot_record.get('killed')),
                (['DONE', 'ok'], 0, 0), 'DONE is captured and QEMU exits naturally before any host power cut')
    reboot_console = (Path(ev.root).parent / 'boot-6/console.log').read_text(errors='replace')
    queued = reboot_console.split('EFI_CONNECT_REAL_REBOOT_QUEUED', 1)
    check.equal(len(queued), 2, 'actual installed probe records the real queued reboot on serial')
    check(len(queued) == 2 and re.search(r'reboot: Restarting system(?:\s|$)', queued[1]) is not None,
          'the queued CLI action reaches the native kernel hardware-reboot path')
    custody = ev.stage(12)
    fingerprints = preview.json['result'].get('fingerprints', [])
    check.equal(len(fingerprints), 1, 'actual reboot review contains exactly the fixture public key')
    check.contains(custody.step('ready').out, fingerprints[0] if len(fingerprints) == 1 else '<missing fingerprint>',
                   'following firmware boot admits the key published by the actual CLI reboot')
    check.contains(custody.step('consumed').out, CONSUMED,
                   'following firmware boot deletes and syncs the actual CLI-published request before SSH')
    identities = custody.step('custody-identities').json
    check.equal(identities['job']['parent'], 1, 'the actual double-fork job has reparented to guest PID1')
    check(identities['job']['session'] != identities['menu']['session'],
          'real setsid job escapes the Menu session while retaining owned cgroup custody')
    check.contains(custody.step('custody-login').out, 'ZT_CUSTODY_HOLD_READY',
                   'actual authenticated detached job exists before the exact Menu kill')
    records = ''.join(log_records(custody.step('custody-auth-log')))
    check(re.search(r'auth\.c:auth_log\(\).*Accepted publickey for root from ', records) is not None,
          'raw native datagrams prove the custody session actually authenticated')
    restart = custody.step('custody-restart').out
    check(restart.index(RECOVERED) < restart.index(READY),
          'native recovery barrier finishes before the restarted Menu becomes ready')
    late = re.findall(r'(?m)ZT_LATE_JOIN_RC=(\d+)\r?$', restart)
    check.equal(len(late), 1, 'the physically held pre-kill cgroup descriptor is attempted exactly once')
    check(late and int(late[0]) != 0, 'removed cgroup refuses a late join through its old open descriptor')
    check('menu SSH:' not in restart and 'menu SSH cleanup:' not in restart,
          'parent death recovers through the normal cgroup cleanup path')
    check.equal(custody.step('custody-after').rc, 0,
                'exact detached job is gone, both leaves removed, password/lease retired and pool readonly')
    check.contains(custody.step('custody-after').out, 'CUSTODY_CLOSED',
                   'native mount unmount succeeds after all owned cgroup members exit')
    check.equal(custody.step('custody-status').rc, 0, 'restarted normal Menu remains usable')
    primary_identities = []
    for index in range(1, 8):
        directory = Path(ev.root).parent / f'boot-{index}'
        launch = json.loads((directory / 'launch.json').read_text())
        argv = launch['argv']
        bus = {2: 'usb', 3: 'nvme', 4: 'nvme', 6: 'nvme'}.get(index, 'virtio')
        if bus == 'virtio':
            check('disk_bus' not in launch, f'boot{index}: default virtio storage remains unchanged')
        else:
            check.equal(launch.get('disk_bus'), {'A': bus, 'B': 'virtio', 'D': 'virtio'},
                        f'boot{index}: only owned A uses the selected {bus} bus')
        check.equal('qemu-xhci,id=zt-usb' in argv, bus == 'usb',
                    f'boot{index}: only the USB leg adds its owned controller')
        driver = {'virtio': 'virtio-blk-pci', 'usb': 'usb-storage,bus=zt-usb.0', 'nvme': 'nvme'}[bus]
        boot_index = '' if index == 1 else ',bootindex=1'
        primary_devices = [argv[n + 1] for n, arg in enumerate(argv[:-1])
                           if arg == '-device' and ',drive=diskA,' in argv[n + 1]]
        check.equal(primary_devices, [f'{driver},drive=diskA,serial=ZFS-E2E-A{boot_index}'],
                    f'boot{index}: exact native A device, serial and firmware priority')
        for label in ('B', 'D'):
            check(f'virtio-blk-pci,drive=disk{label},serial=ZFS-E2E-{label}' in argv,
                  f'boot{index}: owned {label} remains virtio')
        primary_drives = [dict(field.split('=', 1) for field in argv[n + 1].split(',') if '=' in field)
                          for n, arg in enumerate(argv[:-1]) if arg == '-drive']
        primary_drives = [drive for drive in primary_drives if drive.get('id') == 'diskA']
        check.equal(len(primary_drives), 1, f'boot{index}: exactly one backing file for A')
        if len(primary_drives) == 1:
            backing = Path(primary_drives[0]['file'])
            check.equal(backing, directory / 'disk-A.raw', f'boot{index}: only the private case disk backs A')
            current = backing.stat()
            primary_identities.append((current.st_dev, current.st_ino))
        if index == 1:
            check('network' not in launch and '-netdev' not in argv, 'setup retains its no-NIC default')
            continue
        network = launch.get('network', {})
        check.equal((network.get('host'), network.get('guest_port'), network.get('restrict')),
                    ('127.0.0.1', 22, True), f'boot{index}: one restricted loopback SSH forward')
        check.equal(launch['argv'].count('-netdev'), 1, f'boot{index}: exactly one user NIC')
    check.equal(len(set(primary_identities)), 1, 'all transports use the same original A backing inode')
