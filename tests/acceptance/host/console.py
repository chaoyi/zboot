"""Drive the Menu's own console on ttyS0 for firmware (EFI) boots.

No guest helper runs in an EFI boot: the product's recovery console is the
interface. The host records every exchange in the same files a guest stage
writes (out/STAGE/NN-NAME.{argv,out,rc}), so verdicts read EFI and direct-
kernel stages alike.

A shell body's output is bracketed by the lines `ZT-<nonce>-out` and
`ZT-<nonce>=<rc>`. The nonce reaches printf as an argument, so the echoed
command (which the console may wrap anywhere) never contains either line.
"""
import re
import secrets
import time

MENU_PROMPT = 'zboot> '
SHELL_PROMPT = 'zboot-shell# '
READY = 'ZBOOT_MENU_READY'
EOF = '\x04'
# Any of these before an awaited marker means the boot or the Menu failed.
FAILURES = ('menu returned', 'Kernel panic', 'stty: not found')
COUNTDOWN = rb'Auto-booting [^\r\n]+ in [1-5]s; press any key to pause\.'


def active_countdown(text):
    return re.search(COUNTDOWN, text.encode()) is not None


class ConsoleError(RuntimeError):
    pass


def last_listing(text):
    """The last complete Menu snapshot within a retained console exchange."""
    banners = list(re.finditer(r'(?m)^Zboot menu ', text))
    return text[banners[-1].start():] if banners else text


class Console:
    def __init__(self, drain, out, deadline, *, ssh_port=None, case_dir=None):
        self.drain = drain
        self.out = out
        self.out.mkdir(parents=True, exist_ok=True)
        self.deadline = deadline
        self.ssh_port = ssh_port
        self.case_dir = case_dir
        self.pos = 0
        self.n = 0

    def _text(self, start, end):
        with self.drain.lock:
            return bytes(self.drain.text[start:end]).decode(errors='replace')

    def expect(self, text, seconds=600, failures=FAILURES):
        """Wait for `text` after the last match; fail on a failure marker first."""
        deadline = min(self.deadline, time.monotonic() + seconds)
        alternatives = [re.escape(text.encode())] + [re.escape(f.encode()) for f in failures]
        end = self.drain.expect(b'|'.join(alternatives), deadline, self.pos)
        found = self._text(self.pos, end)
        for failure in failures:
            if found.endswith(failure):
                # Keep the rest of the failure's line (its native detail) before giving up.
                try:
                    found = self._text(self.pos, self.drain.expect(rb'\n', time.monotonic() + 5, end))
                except TimeoutError:
                    found = self._text(self.pos, len(self.drain.text))
                raise ConsoleError(f'console showed {failure!r} while waiting for {text!r}:\n{found[-800:]}')
        start, self.pos = self.pos, end
        return self._text(start, end)

    def send(self, line):
        self.drain.send(line.encode() + b'\n')

    def _record(self, name, argv, out, rc):
        self.n += 1
        base = self.out / f'{self.n:02d}-{name}'
        base.with_suffix('.argv').write_text(argv + '\n')
        base.with_suffix('.out').write_text(out)
        base.with_suffix('.err').write_text('')
        base.with_suffix('.rc').write_text(f'{rc}\n')

    def ready(self, name='ready', seconds=900):
        """Wait for the Menu; record its boot output and listing as `name`."""
        start = self.pos
        self.expect(READY, seconds)
        alternatives = [re.escape(MENU_PROMPT.encode()), COUNTDOWN,
                        *[re.escape(failure.encode()) for failure in FAILURES]]
        end = self.drain.expect(b'|'.join(alternatives),
                                min(self.deadline, time.monotonic() + 120), self.pos)
        found = self._text(self.pos, end)
        self.pos = end
        for failure in FAILURES:
            if found.endswith(failure):
                raise ConsoleError(f'console showed {failure!r} while waiting for the prompt')
        if active_countdown(found):
            # Pause only the real countdown, never READY or its description:
            # sending a key during a remote wait would permanently hold it.
            self.drain.send(b' ')
            self.expect('Auto-boot paused;', 120)
            self.expect(MENU_PROMPT, 120)
        text = self._text(start, self.pos)
        self._record(name, '', text, 0)
        return text

    def menu(self, name, command, until=(MENU_PROMPT,), seconds=600, failures=FAILURES):
        """A Menu command (EOF sends Ctrl-D); its output is everything up to
        the last of the `until` markers, awaited in order."""
        start = self.pos
        if command == EOF:
            self.drain.send(b'\x04')
        else:
            self.send(command)
        for marker in until:
            self.expect(marker, seconds, failures)
        text = self._text(start, self.pos)
        self._record(name, repr(command) if command == EOF else command, text, 0)
        return text

    def shell(self, name, body, seconds=120):
        """Run `body` in the already open maintenance shell; record rc and output."""
        nonce = secrets.token_hex(8)
        line = (f"printf '\\nZT-%s-out\\n' {nonce}; ({body}); r=$?; "
                f"printf '\\nZT-%s=%s\\n' {nonce} \"$r\"")
        if len(line) > 3000:
            raise ConsoleError(f'{name}: shell line too long for the console')
        start = self.pos
        self.send(line)
        deadline = min(self.deadline, time.monotonic() + seconds)
        self.pos = self.drain.expect(rf'(?m)^ZT-{nonce}=\d+\r?$'.encode(), deadline, self.pos)
        text = self._text(start, self.pos)
        rc = int(re.findall(rf'(?m)^ZT-{nonce}=(\d+)', text)[-1])
        begin = re.search(rf'(?m)^ZT-{nonce}-out\r?\n', text)
        output = text[begin.end():] if begin else text
        output = output.rsplit(f'ZT-{nonce}=', 1)[0].replace('\r\n', '\n')
        output = output[:-1] if output.endswith('\n') else output
        self._record(name, body, output, rc)
        return rc

    def must(self, name, body, seconds=120):
        rc = self.shell(name, body, seconds)
        if rc:
            raise ConsoleError(f'{name} exited {rc}')

    def enter_shell(self):
        self.send('shell')
        self.expect(SHELL_PROMPT, 60)

    def leave_shell(self):
        self.send('exit')
        self.expect('Maintenance shell returned', 60)
        self.expect(MENU_PROMPT, 60)
