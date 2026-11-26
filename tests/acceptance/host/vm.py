"""One disposable QEMU guest: private sparse disks, serial sockets, owned process.

The guest normally sees three virtio disks with serials ZFS-E2E-A, -B and -D.
Selected EFI fixtures present A as USB or NVMe; a case asking for `N` also gets
an emulated NVMe disk ZFS-E2E-N. These are never host devices. ttyS0 is the console (kernel log, Menu dialogue); ttyS1 carries
only the test channel (see channel.py). The QEMU process is this Popen's own
child: kill and reap go through that handle, never a PID lookup.
"""
from dataclasses import dataclass
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from host.uki import sha256

DISKS = ('A', 'B', 'D')
QEMU = '/usr/bin/qemu-system-x86_64'
# Direct-kernel guests are development fixtures. Product UKI entry tests opt
# into their actual RAM contract explicitly through Boot.append. EFI guests
# use the command line embedded in the constructed product image.
APPEND = 'console=tty0 console=ttyS0,115200 loglevel=4'
# A network boot's HTTP server: a slirp guest forward that starts http.py
# for each connection. Only the guest reaches it.
PXE_SERVER = '10.0.2.100'


def default_memory_mib(case_id):
    value = os.environ.get('ZBOOT_VM_MEMORY_MIB')
    if value is None:
        return 2048 if case_id == 'SMOKE' else 8192
    try:
        memory = int(value)
    except ValueError as error:
        raise ValueError('ZBOOT_VM_MEMORY_MIB must be an integer from 1 to 1048576 MiB') from error
    if not 1 <= memory <= 1048576:
        raise ValueError('ZBOOT_VM_MEMORY_MIB must be an integer from 1 to 1048576 MiB')
    return memory


def regular(path):
    st = os.stat(path, follow_symlinks=False)
    if not (st.st_mode & 0o170000) == 0o100000:
        raise RuntimeError(f'{path}: not a regular file')
    return Path(path)


@dataclass(frozen=True)
class ImageInput:
    relative: str              # canonical path under this private case directory
    sha256: str
    bytes: int
    serial: str
    boot: bool = False


def copy_image(root, image, destination):
    """Copy a file a previous boot of this case wrote under ROOT, the case's
    own resolved directory, and check the copy's size and full SHA-256."""
    parts = image.relative.split('/')
    if not parts or any(part in ('', '.', '..') for part in parts):
        raise ValueError('case image path must be canonical and relative')
    if not re.fullmatch(r'[0-9a-f]{64}', image.sha256) or not 0 < image.bytes <= 32 << 30:
        raise ValueError('case image lacks a bounded full content identity')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,40}', image.serial) or image.serial in (*DISKS, 'C', 'N'):
        raise ValueError('case image serial is invalid or collides with a stock disk')
    # The guest wrote this tree through 9p and could have left symlinks.
    source = Path(root, *parts)
    if source.resolve() != source.absolute():
        raise RuntimeError('case image path leaves the case directory')
    subprocess.run(['cp', '--sparse=always', '--', regular(source), destination], check=True, timeout=1800)
    if Path(destination).stat().st_size != image.bytes or sha256(destination) != image.sha256:
        raise RuntimeError('case image bytes differ from the guest-recorded size and SHA256')
    return {'source_relative': image.relative, 'sha256': image.sha256,
            'bytes': image.bytes, 'serial': image.serial, 'boot': image.boot,
            'copy': str(destination), 'allocated_bytes': Path(destination).stat().st_blocks * 512}


def disk_device(label, boot_index='', *, primary_bus='virtio'):
    drivers = {'virtio': 'virtio-blk-pci', 'usb': 'usb-storage,bus=zt-usb.0', 'nvme': 'nvme'}
    if primary_bus not in drivers:
        raise ValueError('unsupported primary fixture bus')
    driver = drivers[primary_bus] if label == 'A' else drivers['virtio']
    return f'{driver},drive=disk{label},serial=ZFS-E2E-{label}{boot_index}'


class Vm:
    """Launch with `boot` = {'kernel','initrd','append'} or {'efi':(code,vars),'disk':path},
    or {'efi':(code,vars),'pxe':uki}: the NIC is then the only boot device,
    and the firmware's UEFI HTTP boot gets the UKI's URL from DHCP and starts
    it with no arguments, so it runs its own command line.

    `disks` maps A/B/D to GiB. `previous` reuses that run's disks (hard links),
    so a restart after a cut sees exactly the bytes the killed guest left.
    """

    def __init__(self, run, boot, disks, *, memory_mib=8192, previous=None,
                 shares=(), network=False, images=(), case_root=None, fresh_disks=False, deadline):
        self.run = Path(run)
        self.run.mkdir(mode=0o700)
        self.deadline = deadline
        # Serial sockets live in a short private /tmp directory: run paths
        # exceed the 108-byte AF_UNIX limit.
        self.sockets = Path(tempfile.mkdtemp(prefix='zt-', dir='/tmp'))
        # KVM with the host CPU; there is no software-emulation fallback.
        # Back guest RAM with preallocated memfd pages; anonymous demand faults
        # stalled guest execution on a development host. No host policy is changed.
        ram = (f'memory-backend-memfd,id=zt-ram,size={memory_mib}M,'
               'hugetlb=off,share=on,prealloc=on,prealloc-threads=2')
        argv = [QEMU, '-object', ram, '-machine', 'q35,accel=kvm,memory-backend=zt-ram', '-cpu', 'host',
                '-m', str(memory_mib),
                '-smp', '2', '-display', 'none', '-monitor', 'none', '-nic', 'none',
                '-no-reboot', '-object', 'rng-builtin,id=rng',
                '-device', 'virtio-rng-pci,rng=rng',
                '-chardev', f'socket,id=con,path={self.sockets}/console.sock,server=on,wait=on',
                '-serial', 'chardev:con',
                '-chardev', f'socket,id=test,path={self.sockets}/test.sock,server=on,wait=on',
                '-serial', 'chardev:test',
                '-fw_cfg', 'name=opt/zboot/console,string=ttyS0']
        self.ssh_port = None
        if network:
            # Bind only loopback. Slirp supplies wired DHCP but cannot initiate
            # connections to the host or external network (restrict=on).
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(('127.0.0.1', 0))
                self.ssh_port = reservation.getsockname()[1]
            offset = argv.index('-nic')
            del argv[offset:offset + 2]
        evidence = {'schema': 1, 'inputs': {}, 'memory_mib': memory_mib}
        if 'kernel' in boot:
            for name in ('kernel', 'initrd'):
                shutil.copyfile(regular(boot[name]), self.run / name)
                evidence['inputs'][name] = sha256(self.run / name)
            argv += ['-kernel', str(self.run / 'kernel'), '-initrd', str(self.run / 'initrd'),
                     '-append', f"{APPEND} {boot.get('append', '')}".strip()]
        else:
            code, fresh_vars = boot['efi']
            shutil.copyfile(regular(code), self.run / 'code.fd')
            shutil.copyfile(regular(fresh_vars), self.run / 'vars.fd')
            argv += ['-drive', f'if=pflash,format=raw,readonly=on,file={self.run}/code.fd',
                     '-drive', f'if=pflash,format=raw,file={self.run}/vars.fd']
            evidence['inputs'].update(code=sha256(self.run / 'code.fd'),
                                      vars=sha256(self.run / 'vars.fd'))
        def image(label):
            path = self.run / f'disk-{label}.raw'
            size = disks.get(label, 2) << 30
            if previous and not fresh_disks:
                source = regular(Path(previous) / path.name)
                if source.stat().st_size != size:
                    raise RuntimeError(f'{source}: size changed')
                os.link(source, path)
            else:
                with open(path, 'xb') as f:
                    f.truncate(size)
            return path
        primary_bus = boot.get('a_bus', 'virtio')
        if (primary_bus not in ('virtio', 'usb', 'nvme')
                or primary_bus != 'virtio' and (boot.get('boot_disk') != 'A' or 'efi' not in boot or 'kernel' in boot)):
            raise RuntimeError('alternate fixture bus requires an EFI boot of owned disk A')
        if primary_bus == 'usb':
            argv += ['-device', 'qemu-xhci,id=zt-usb']
        if primary_bus != 'virtio':
            evidence['disk_bus'] = {'A': primary_bus, 'B': 'virtio', 'D': 'virtio'}
        for label in DISKS:
            path = image(label)
            boot_disk = boot.get('boot_disk')
            if boot_disk is not None and boot_disk not in DISKS:
                raise ValueError('boot disk must be a declared stock disk')
            boot_index = ',bootindex=1' if label == boot_disk else ''
            argv += ['-drive', f'if=none,id=disk{label},format=raw,file={path}',
                     '-device', disk_device(label, boot_index, primary_bus=primary_bus)]
        if 'pxe' in boot:
            if (not network or 'efi' not in boot or 'disk' in boot or images
                    or boot.get('boot_disk')
                    # QEMU option and slirp command syntax
                    or any(c in f'{self.run}{Path(__file__)}' for c in ', ')):
                raise ValueError('a network boot is a firmware launch with a NIC and no boot disk')
            http = self.run / 'http'
            http.mkdir(mode=0o700)
            shutil.copyfile(regular(boot['pxe']), http / 'zboot.efi')
            evidence['inputs']['zboot.efi'] = sha256(http / 'zboot.efi')
            evidence['pxe'] = {'server': PXE_SERVER}
        if 'disk' in boot:
            shutil.copyfile(regular(boot['disk']), self.run / 'boot.raw')
            evidence['inputs']['boot.raw'] = sha256(self.run / 'boot.raw')
            argv += ['-drive', f'if=none,id=boot,format=raw,file={self.run}/boot.raw',
                     '-device', 'virtio-blk-pci,drive=boot,serial=ZFS-E2E-C,bootindex=1']
        self.image_paths = {}
        if images:
            if case_root is None or 'kernel' in boot or 'disk' in boot or boot.get('boot_disk'):
                raise ValueError('case images need an explicit private root and firmware-only launch')
            if len(images) > 2 or sum(image.boot for image in images) != 1:
                raise ValueError('attach one boot image and at most one independent copy')
            if len({image.serial for image in images}) != len(images):
                raise ValueError('case image serials must be distinct')
            evidence['case_images'] = []
            for index, supplied in enumerate(images):
                path = self.run / f'case-image-{index}.raw'
                fact = copy_image(case_root, supplied, path)
                evidence['case_images'].append(fact)
                self.image_paths[supplied.serial] = path
                boot_index = ',bootindex=1' if supplied.boot else ''
                argv += ['-drive', f'if=none,id=caseimage{index},format=raw,file={path}',
                         '-device', f'virtio-blk-pci,drive=caseimage{index},serial=ZFS-E2E-{supplied.serial}{boot_index}']
        # 9p shares go after the disks so A/B/D PCI paths never move. Only the
        # run's own `zt-out` directory is writable; fixtures are read-only.
        for tag, path in shares:
            mode = '' if tag == 'zt-out' else ',readonly=on'
            argv += ['-fsdev', f'local,id={tag},path={path},security_model=none{mode}',
                     '-device', f'virtio-9p-pci,fsdev={tag},mount_tag={tag}']
        # QEMU's emulated NVMe has no Sanitize command (SANICAP 0), so wipe
        # clears its metadata. Attached last so no other PCI path moves.
        if 'N' in disks:
            argv += ['-drive', f'if=none,id=diskN,format=raw,file={image("N")}',
                     '-device', 'nvme,serial=ZFS-E2E-N,drive=diskN']
        if network:
            # Last PCI device: all original disks and shares keep their slots.
            netdev = f'user,id=zt-net,restrict=on,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22'
            nic = 'virtio-net-pci,netdev=zt-net'
            if 'pxe' in boot:
                server = Path(__file__).with_name('http.py')
                netdev += (f',ipv6=off,bootfile=http://{PXE_SERVER}/zboot.efi'
                           f',guestfwd=tcp:{PXE_SERVER}:80-cmd:/usr/bin/python3 -I -B {server}'
                           f' {self.run / "http"} {self.run / "http.log"}')
                nic += ',bootindex=1'
            argv += ['-netdev', netdev, '-device', nic]
            evidence['network'] = {'backend': 'user', 'restrict': True,
                                   'host': '127.0.0.1', 'host_port': self.ssh_port,
                                   'guest_port': 22}
        evidence['argv'] = argv
        evidence['sockets'] = str(self.sockets)
        (self.run / 'launch.json').write_text(json.dumps(evidence, indent=2) + '\n')
        self.stderr = open(self.run / 'qemu.log', 'wb')
        self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                        stdout=self.stderr, stderr=subprocess.STDOUT)
        self.console = self.test = None
        # wait=on: QEMU does not run the guest until both sockets are connected.
        try:
            self.console = self._connect('console.sock')
            self.test = self._connect('test.sock')
        except BaseException:
            self.kill()
            raise

    def _connect(self, name):
        path = self.sockets / name
        while True:
            if self.process.poll() is not None:
                raise RuntimeError(f'QEMU exited during startup: see {self.run}/qemu.log')
            if time.monotonic() > self.deadline:
                raise TimeoutError(f'{name} not ready')
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(str(path))
                return s
            except (FileNotFoundError, ConnectionRefusedError):
                s.close()
                time.sleep(0.05)

    def kill(self):
        """Power cut: SIGKILL the owned QEMU and reap it. Idempotent."""
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        for s in (self.console, self.test):
            if s:
                s.close()
        self.stderr.close()
        shutil.rmtree(self.sockets, ignore_errors=True)
        return self.process.returncode

    def wait(self, seconds):
        """Wait for the guest to power off by itself (it runs with -no-reboot)."""
        try:
            return self.process.wait(timeout=max(0, min(seconds, self.deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            self.kill()
            raise TimeoutError(f'guest did not power off: {self.run}')

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.kill()
