"""The zboot UKI and its initramfs, for the acceptance runner and the two native
proofs (tests/native-api, tests/native-readers): PE sections, the payloads a
guest boots, and the newc archives the proofs append."""
import hashlib
from pathlib import Path
import shutil
import subprocess

# Where a UKI's publisher recorded its digest: a dist/dist.sh OUT, or dpkg.
UKI_PATH = 'usr/lib/zboot/zboot.efi'
DPKG_MD5SUMS = Path('/var/lib/dpkg/info/zboot.md5sums')
# What a native proof puts in place of each writer the UKI carries.
DISABLED_WRITER = b'#!/bin/sh\necho cached-writer-disabled >&2\nexit 125\n'


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def uki_section(uki, name):
    """The bytes of PE section NAME (its VirtualSize, the exact payload)."""
    data = Path(uki).read_bytes()
    if data[:2] != b'MZ':
        raise RuntimeError(f'{uki}: not a PE file')
    pe = int.from_bytes(data[0x3c:0x40], 'little')
    if data[pe:pe + 4] != b'PE\0\0':
        raise RuntimeError(f'{uki}: no PE header')
    count = int.from_bytes(data[pe + 6:pe + 8], 'little')
    table = pe + 24 + int.from_bytes(data[pe + 20:pe + 22], 'little')
    found = []
    for i in range(count):
        entry = data[table + 40 * i:table + 40 * (i + 1)]
        if entry[:8].rstrip(b'\0') == name.encode():
            size = int.from_bytes(entry[8:12], 'little')
            raw = int.from_bytes(entry[16:20], 'little')
            start = int.from_bytes(entry[20:24], 'little')
            if size > raw or start + raw > len(data):
                raise RuntimeError(f'{uki}: section {name} is out of range')
            found.append(data[start:start + size])
    if len(found) != 1:
        raise RuntimeError(f'{uki}: needs exactly one {name} section')
    return found[0]


def published_digest(uki, md5sums=DPKG_MD5SUMS):
    """(algorithm, digest, record) its publisher recorded for UKI: the
    SHA256SUMS of the dist/dist.sh OUT it is in, or the installed zboot
    package's dpkg md5sums. Any other UKI is refused."""
    uki = Path(uki).resolve(strict=True)
    depth = len(Path(UKI_PATH).parts)
    out = uki.parents[depth - 1] if len(uki.parents) >= depth else None
    if out is not None and uki == out / UKI_PATH and (out / 'SHA256SUMS').is_file():
        algorithm, record = 'sha256', out / 'SHA256SUMS'
    elif uki == Path('/') / UKI_PATH and md5sums.is_file():
        algorithm, record = 'md5', md5sums
    else:
        raise RuntimeError(f'{uki}: no publisher record; use OUT/{UKI_PATH} of a dist/dist.sh '
                           'output or the installed zboot package\'s UKI')
    found = [fields[0] for fields in map(str.split, record.read_text().splitlines())
             if len(fields) == 2 and fields[1] == UKI_PATH]
    if len(found) != 1:
        raise RuntimeError(f'{record}: needs exactly one {UKI_PATH} entry')
    return algorithm, found[0], str(record)


def boot_payloads(uki, copy, kernel, initramfs):
    """Copy UKI to COPY and write its kernel and initramfs to KERNEL and
    INITRAMFS, so a guest boots exactly the payloads of the recorded digests.
    The copy must match its publisher's record (published_digest)."""
    algorithm, expected, record = published_digest(uki)
    shutil.copyfile(uki, copy)
    digest = hashlib.new(algorithm)
    with open(copy, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise RuntimeError(f'{uki}: {algorithm} differs from its record in {record}')
    os_release = uki_section(copy, '.osrel').decode(errors='replace')
    if 'ID=zboot' not in os_release.splitlines():
        raise RuntimeError(f'{uki}: not a zboot UKI (its .osrel has no ID=zboot)')
    kernel.write_bytes(uki_section(copy, '.linux'))
    initramfs.write_bytes(uki_section(copy, '.initrd'))
    return {'uki': str(uki), 'uki_sha256': sha256(copy), 'uki_record': record, 'os_release': os_release,
            'kernel_sha256': sha256(kernel), 'initrd_sha256': sha256(initramfs)}


def guest_initrd(initramfs, destination, init, stubs):
    """Write DESTINATION for a native proof's guest: the UKI's zstd INITRAMFS
    unpacked, then INIT (bytes) as /init and DISABLED_WRITER at usr/bin/NAME for
    each NAME in STUBS. The kernel unpacks the appended archive last, so it
    replaces those files."""
    with destination.open('wb') as image:
        subprocess.run(['zstd', '-dc', '--', str(initramfs)], stdout=image, check=True)
        image.write(newc('init', init))
        for inode, name in enumerate(stubs, 2):
            image.write(newc(f'usr/bin/{name}', DISABLED_WRITER, inode=inode))
        image.write(newc('TRAILER!!!', b'', mode=0, inode=len(stubs) + 2))
        image.write(b'\0' * (-image.tell() % 512))


def newc(name, data, mode=0o100755, inode=1):
    """One newc cpio member."""
    name = name.encode() + b'\0'
    fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    result = b'070701' + b''.join(f'{field:08x}'.encode() for field in fields) + name
    result += b'\0' * (-len(result) % 4)
    result += data
    return result + b'\0' * (-len(data) % 4)

