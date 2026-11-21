"""Drain the guest's serial lines and expose test events.

ttyS0 (console) and ttyS1 (test) are drained continuously into console.log
and test.log, so a guest never stalls on a full UART. ttyS1 carries only
`ZT1 <EVENT> [ARG]` lines from guest/lib.sh: BEGIN, CUT and DONE. Bulk
evidence never crosses the serial line; the guest writes it to the run's
writable 9p `out` share (see case.py and guest/init.sh).
"""
import queue
import re
import threading
import time

EVENT = re.compile(rb'^ZT1 (BEGIN|CUT|DONE)(?: ([A-Za-z0-9_.:-]{1,64}))?\r?$')


class Drain:
    def __init__(self, sock, log_path, events=None):
        self.sock = sock
        self.log = open(log_path, 'ab')
        self.events = events
        self.lock = threading.Condition()
        self.text = bytearray()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        pending = b''
        while True:
            try:
                data = self.sock.recv(65536)
            except OSError:
                data = b''
            if not data:
                break
            self.log.write(data)
            self.log.flush()
            with self.lock:
                self.text += data
                self.lock.notify_all()
            if self.events is not None:
                pending += data
                *lines, pending = pending.split(b'\n')
                for line in lines:
                    m = EVENT.match(line)
                    if m:
                        self.events.put((m[1].decode(), (m[2] or b'').decode()))
        self.log.close()
        if self.events is not None:
            self.events.put(('EOF', ''))

    def expect(self, pattern, deadline, start=0):
        """Wait until `pattern` (bytes regex) appears at or after offset `start`.
        Returns the match end offset, for chaining dialogue steps."""
        rx = re.compile(pattern)
        with self.lock:
            while True:
                m = rx.search(self.text, start)
                if m:
                    return m.end()
                left = deadline - time.monotonic()
                if left <= 0 or not self.thread.is_alive():
                    tail = bytes(self.text[-600:]).decode(errors='replace')
                    raise TimeoutError(f'console never showed {pattern!r}; tail:\n{tail}')
                self.lock.wait(min(left, 1.0))

    def send(self, data):
        self.sock.sendall(data)


class Channel:
    """The test channel of one boot."""

    def __init__(self, vm):
        self.events = queue.Queue()
        self.console = Drain(vm.console, vm.run / 'console.log')
        self.test = Drain(vm.test, vm.run / 'test.log', self.events)

    def next(self, deadline):
        try:
            return self.events.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            raise TimeoutError('no test event before the deadline') from None

    def until(self, wanted, deadline):
        """Next event of a kind in `wanted`; BEGIN is recorded and skipped."""
        while True:
            kind, arg = self.next(deadline)
            if kind in wanted:
                return kind, arg
            if kind == 'EOF':
                raise RuntimeError(f'guest channel closed while waiting for {wanted}')
