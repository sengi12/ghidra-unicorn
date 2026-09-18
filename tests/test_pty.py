"""Line editing under a real pty.

Ghidra's terminal sends 0x08 for Backspace, while a macOS pty erases on 0x7f,
so without readline doing the editing itself Backspace does nothing. This
drives the console through an actual pty and checks that both erase
characters delete, and that Up-arrow recalls the previous line.
"""
import json
import os
import select
import subprocess
import sys
import time

import pytest

pty = pytest.importorskip('pty')
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHILD = r'''
import json, sys
sys.path.insert(0, {repo!r})
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP
from ghidraunicorn.target import UnicornTarget
from ghidraunicorn.console import UnicornConsole

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x1000, 0x1000)
uc.mem_map(0x7000, 0x1000)
uc.mem_write(0x1000, bytes.fromhex('48ffc0' * 4))
uc.reg_write(UC_X86_REG_RIP, 0x1000)
uc.reg_write(UC_X86_REG_RSP, 0x7ff0)
t = UnicornTarget(uc)
UnicornConsole(t, color=False).run(banner='PTY-READY')
open({out!r}, 'w').write(json.dumps({{'rax': t.reg_read('rax'), 'rbx': t.reg_read('rbx')}}))
'''


class Pty:
    def __init__(self, argv, env):
        self.master, slave = pty.openpty()
        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                     env=env, close_fds=True)
        os.close(slave)
        self.buf = bytearray()

    def expect(self, pattern: bytes, timeout: float = 20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pattern in bytes(self.buf):
                return
            r, _, _ = select.select([self.master], [], [], 0.2)
            if r:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    break
                if not data:
                    break
                self.buf.extend(data)
        if pattern in bytes(self.buf):
            return
        raise AssertionError(f'timed out waiting for {pattern!r}; '
                             f'last output: {bytes(self.buf)[-400:]!r}')

    def send(self, data: bytes):
        self.buf.clear()
        os.write(self.master, data)

    def wait(self, timeout: float = 20.0) -> int:
        """Wait for exit while still draining the pty, or the child blocks."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return self.proc.returncode
            r, _, _ = select.select([self.master], [], [], 0.2)
            if r:
                try:
                    if not os.read(self.master, 65536):
                        break
                except OSError:
                    break
        return self.proc.wait(timeout=5)

    def close(self):
        try:
            os.close(self.master)
        except OSError:
            pass
        if self.proc.poll() is None:
            self.proc.kill()


@pytest.mark.skipif(sys.platform == 'win32', reason='no pty on Windows')
def test_backspace_arrows_and_history_under_a_pty(tmp_path):
    out = tmp_path / 'result.json'
    script = CHILD.format(repo=REPO, out=str(out))
    env = dict(os.environ, TERM='xterm-256color', NO_COLOR='1',
               GHIDRA_UNICORN_HISTORY=str(tmp_path / 'history'),
               PYTHONUNBUFFERED='1')
    t = Pty([sys.executable, '-c', script], env)
    try:
        t.expect(b'PTY-READY')
        t.expect(b'>>> ')

        # 0x7f (what a real terminal sends) must erase the stray X.
        t.send(b'r rax 0x41X\x7f\r')
        t.expect(b'rax = 0x41')

        # 0x08 (what Ghidra's terminal sends) must erase too.
        t.send(b'r rbx 0x42Y\x08\r')
        t.expect(b'rbx = 0x42')

        # Up-arrow recalls the previous line, and it is editable.
        t.send(b'\x1b[A')
        t.expect(b'r rbx 0x42')
        t.send(b'\x7f\x7f\x7f\x7f0x99\r')
        t.expect(b'rbx = 0x99')

        t.send(b'q\r')
        assert t.wait() == 0
    finally:
        t.close()

    assert json.loads(out.read_text()) == {'rax': 0x41, 'rbx': 0x99}


@pytest.mark.skipif(sys.platform == 'win32', reason='no pty on Windows')
def test_tab_completion_under_a_pty(tmp_path):
    out = tmp_path / 'result.json'
    script = CHILD.format(repo=REPO, out=str(out))
    env = dict(os.environ, TERM='xterm-256color', NO_COLOR='1',
               GHIDRA_UNICORN_HISTORY=str(tmp_path / 'history'),
               PYTHONUNBUFFERED='1')
    t = Pty([sys.executable, '-c', script], env)
    try:
        t.expect(b'>>> ')
        # "fiel" + Tab completes to `fields`, which then runs.
        t.send(b'fiel\t\r')
        t.expect(b'rflags.IOPL')
        # "r RA" + Tab completes the register name, space included.
        t.send(b'r RA\t0x7\r')
        t.expect(b'RAX = 0x7')
        t.send(b'q\r')
        assert t.wait() == 0
    finally:
        t.close()
