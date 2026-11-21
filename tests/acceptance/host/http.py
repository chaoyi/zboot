#!/usr/bin/python3
"""http.py DIRECTORY LOG: one guest HTTP connection on stdin and stdout.

QEMU's slirp starts this for each connection to the network boot server
(vm.py PXE_SERVER). It serves GET and HEAD of the files directly in
DIRECTORY, keeping the connection open between requests, and appends `METHOD PATH STATUS BYTES` to LOG for each request.
"""
import shutil
import sys
from pathlib import Path


def respond(writer, status, reason, length, kind='application/octet-stream'):
    writer.write(f'HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\n'
                 f'Content-Length: {length}\r\n\r\n'.encode())


def main():
    directory, log = Path(sys.argv[1]), Path(sys.argv[2])
    reader, writer = sys.stdin.buffer, sys.stdout.buffer
    while True:
        request = reader.readline(8192)
        if not request:
            return
        while reader.readline(8192) not in (b'\r\n', b'\n', b''):
            pass
        words = request.decode('latin-1').split()
        method = words[0] if len(words) == 3 else '-'
        name = words[1].removeprefix('/') if len(words) == 3 else ''
        path = directory / name
        found = (method in ('GET', 'HEAD') and name and '/' not in name
                 and name not in ('.', '..') and path.is_file())
        if found:
            size = path.stat().st_size
            # UEFI HTTP boot starts an image it is told is EFI.
            respond(writer, 200, 'OK', size,
                    'application/efi' if name.endswith('.efi') else 'application/octet-stream')
            if method == 'GET':
                with path.open('rb') as source:
                    shutil.copyfileobj(source, writer, 1 << 20)
        else:
            size = 0
            respond(writer, 404, 'Not Found', 0)
        writer.flush()
        with log.open('a') as record:
            record.write(f'{method} /{name} {200 if found else 404} {size}\n')
        if not found:
            return


if __name__ == '__main__':
    main()
