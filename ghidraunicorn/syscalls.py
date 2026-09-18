"""System calls for a program that has no operating system under it.

A Unicorn target is a piece of a process with nothing behind it: the moment
the program traps into the kernel, emulation stops with an unhandled
interrupt. This module puts a small Linux underneath, so a harness can run
code that reads its input, writes its output and allocates memory instead of
having to avoid every call that leaves the binary.

What it is not
--------------
There is no host filesystem here. `open` sees only the files handed to
`Syscalls` up front, and anything else comes back as ENOENT. A debugger that
let an emulated program open the debugging machine's files would be a
surprising thing to point at a crashing input, so the sandbox is the default
and there is no switch to turn it off.

Replay
------
This is the part that is easy to get wrong. Reverse execution works by
restoring a checkpoint and re-emulating forward with the hooks muted, so the
trap instruction runs again - and a system call is not a pure function of
the machine state. Running `read` twice consumes the input twice; running
`write` twice prints twice; running `mmap` twice hands out a different
address.

So a call is executed once and *recorded*: its result, the memory it wrote,
the regions it mapped and unmapped. During a replay the recorded effects are
applied instead of the handler running, which makes the replay reproduce
history exactly and stay silent while doing it. Records older than the
timeline's earliest instruction can never be reached again and are dropped,
so the log costs nothing that the history is not already paying for.
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from unicorn import (UC_HOOK_INSN, UC_HOOK_INTR, UC_PROT_ALL, UC_PROT_EXEC,
                     UC_PROT_READ, UC_PROT_WRITE, UcError)
from unicorn import x86_const as x86

from . import abi as _abi
from .abi import MIPS, PPC, SyscallAbi
from .effects import EffectLog

PAGE = 0x1000

#: The generic `asm-generic/errno.h` numbers, for the handful the layer uses.
ERRNO = {'EPERM': 1, 'ENOENT': 2, 'EBADF': 9, 'ENOMEM': 12, 'EACCES': 13,
         'EFAULT': 14, 'ENODEV': 19, 'EINVAL': 22, 'EMFILE': 24,
         'ESPIPE': 29, 'ENOSYS': 38}

#: Where an anonymous mapping goes when the program does not ask for an
#: address. Far enough from a typical image and stack to stay out of the way.
MMAP_BASE = {32: 0x4000_0000, 64: 0x7f00_0000_0000}
MMAP_SIZE = 64 << 20
#: Where the program break starts when the harness did not set one up.
BRK_BASE = {32: 0x3000_0000, 64: 0x6000_0000_0000}
BRK_SIZE = 16 << 20

# mmap flags, from `asm-generic/mman-common.h`. The PROT_* bits are the same
# numbers as Unicorn's UC_PROT_*, which is why they are not translated.
MAP_FIXED = 0x10
MAP_ANONYMOUS = 0x20

SEEK_SET, SEEK_CUR, SEEK_END = 0, 1, 2

#: No single call moves more than this. A count larger than any plausible
#: mapping is a wild argument - an uninitialised register, or a length that
#: came back from a function nobody stubbed - and a kernel answers those with
#: EFAULT rather than trying to allocate for them.
MAX_TRANSFER = 1 << 30


class SyscallError(Exception):
    """A call that failed, carrying the name of the error to report."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


@dataclass
class OpenFile:
    """A file the emulated program can see. There are no others."""
    name: str
    data: bytes = b''
    offset: int = 0
    #: Where bytes written to this descriptor go. A file with no sink is
    #: read-only and a write to it fails with EBADF, as writing to a
    #: descriptor opened for reading does.
    sink: Optional[Callable[[bytes], None]] = None

    @property
    def writable(self) -> bool:
        return self.sink is not None


@dataclass
class SyscallRecord:
    """What one call was, for reporting. What it *did* lives on the Effect."""
    icount: int
    name: str
    number: int
    args: Tuple[int, ...]
    result: int = 0
    failed: bool = False
    #: Name of the error, when `failed`.
    result_name: str = ''

    def describe(self) -> str:
        args = ', '.join(f'{a:#x}' for a in self.args)
        if self.failed:
            return f'{self.name}({args}) = -{self.result_name}'
        return f'{self.name}({args}) = {self.result:#x}'


class Syscalls:
    """The kernel side of the emulator: traps in, results out.

    Handlers are looked up by name, so a harness can replace `write` or add a
    call the layer does not know without touching the number tables::

        sys = syscalls.install(target)
        sys.handlers['getpid'] = lambda s, args: 4242
    """

    def __init__(self, target, abi: Optional[SyscallAbi] = None, *,
                 stdin: bytes = b'', files: Optional[Dict[str, bytes]] = None,
                 on_output: Optional[Callable[[int, bytes], None]] = None,
                 mmap_base: Optional[int] = None, mmap_size: int = MMAP_SIZE,
                 brk_base: Optional[int] = None, brk_size: int = BRK_SIZE,
                 trace: bool = False) -> None:
        self.target = target
        self.abi = abi or _abi.syscall_abi(target.spec.key)
        self.spec = target.spec
        self.on_output = on_output
        self.trace = trace
        self.log = EffectLog(target, 'syscalls', self._snapshot, self._restore)
        self._hooks: List[int] = []
        self._names = self.abi.by_number

        bits = self.spec.bits
        self.files: Dict[int, OpenFile] = {
            0: OpenFile('<stdin>', stdin),
            1: OpenFile('<stdout>', sink=lambda d: self._output(1, d)),
            2: OpenFile('<stderr>', sink=lambda d: self._output(2, d)),
        }
        self.contents: Dict[str, bytes] = dict(files or {})
        self._next_fd = 3

        self.mmap_base = MMAP_BASE[bits] if mmap_base is None else mmap_base
        self.mmap_size = mmap_size
        self.mmap_next = self.mmap_base
        self.brk_base = BRK_BASE[bits] if brk_base is None else brk_base
        self.brk_size = brk_size
        self.brk_current = self.brk_base
        self.brk_mapped = self.brk_base

        self.handlers: Dict[str, Callable[['Syscalls', List[int]], int]] = dict(HANDLERS)
        #: Calls that arrived with a number the table does not name.
        self.unknown: Dict[int, int] = {}

    # ---- installation ----------------------------------------------------

    def install(self) -> 'Syscalls':
        uc = self.target.uc
        if self.abi.intnos:
            self._hooks.append(uc.hook_add(UC_HOOK_INTR, self._on_intr))
        if self.abi.insn:
            # Only x86 has a trap instruction Unicorn reports this way.
            self._hooks.append(uc.hook_add(UC_HOOK_INSN, self._on_insn,
                                           None, 1, 0, x86.UC_X86_INS_SYSCALL))
        self.target.syscalls = self
        return self

    def remove(self) -> None:
        for h in self._hooks:
            try:
                self.target.uc.hook_del(h)
            except UcError:
                pass
        self._hooks = []
        if self.target.syscalls is self:
            self.target.syscalls = None

    # ---- hooks -----------------------------------------------------------

    def _on_intr(self, uc, intno, user_data=None) -> None:
        if intno not in self.abi.intnos:
            return          # a real trap; leave it to Unicorn to complain
        self._dispatch()

    def _on_insn(self, uc, user_data=None) -> None:
        self._dispatch()

    # ---- dispatch --------------------------------------------------------

    def _dispatch(self) -> None:
        t = self.target
        if self.abi.advance:
            # m68k is left on the `trap`, so without this it traps forever.
            t.reg_write(self.spec.pc, t.pc() + self.abi.advance, external=False)
        icount = t.executing_icount
        if t.replaying:
            self.log.replay(icount)
            return
        number = t.reg_read(self.abi.number)
        name = self._names.get(number)
        args = self._read_args()
        rec = SyscallRecord(icount, name or f'syscall_{number}', number, tuple(args))
        with self.log.recording(icount, rec.name) as effect:
            effect.detail = rec
            try:
                handler = self.handlers.get(name) if name else None
                if handler is None:
                    self.unknown[number] = self.unknown.get(number, 0) + 1
                    raise SyscallError('ENOSYS')
                rec.result = int(handler(self, args))
            except SyscallError as e:
                rec.failed, rec.result_name = True, e.name
                rec.result = self.errno(e.name)
            except UcError as e:
                # A handler that touched memory the program does not own.
                # That is the program's fault, and EFAULT is what a kernel
                # says about it.
                rec.failed, rec.result_name = True, 'EFAULT'
                rec.result = self.errno('EFAULT')
                if self.trace:
                    self._log(f'  ({e})')
            except Exception as e:
                # Anything else means the arguments made no sense - a length
                # from a register nobody set, a pointer from a function
                # nobody stubbed. A kernel answers that; it does not bring
                # the machine down, and neither may we: an exception raised
                # here would propagate out of emu_start and end the session.
                rec.failed, rec.result_name = True, 'EINVAL'
                rec.result = self.errno('EINVAL')
                if self.trace:
                    self._log(f'  ({type(e).__name__}: {e})')
            self._apply_result(rec)
        if self.trace:
            self._log(f'[syscall] {rec.describe()}')
        stop = self.log.entries[-1].stop
        if stop is not None:
            t.request_stop(*stop)

    def _read_args(self) -> List[int]:
        t = self.target
        args = [t.reg_read(r) for r in self.abi.args]
        if self.abi.stack_args is not None:
            # MIPS o32 passes the fifth and sixth on the stack.
            sp = t.sp()
            size = self.spec.ptr_size
            for i in range(2):
                try:
                    args.append(self.read_word(sp + self.abi.stack_args + i * size))
                except UcError:
                    args.append(0)
        while len(args) < 6:
            args.append(0)
        return args

    def _apply_result(self, rec: SyscallRecord) -> None:
        """Put the answer where this architecture's programs look for it.

        These go through the log, so that a replay crossing the call sets
        them again and the machine comes out the same way it did first time.
        """
        a = self.abi
        if a.error == MIPS:
            self.log.set_reg(a.ret, self.mask(rec.result))
            if a.error_reg:
                self.log.set_reg(a.error_reg, 1 if rec.failed else 0)
        elif a.error == PPC:
            self.log.set_reg(a.ret, self.mask(rec.result))
            if a.error_cr and self.spec.has_reg(a.error_cr):
                # CR0 is four bits (LT, GT, EQ, SO); SO is the low one.
                cr = self.target.reg_read(a.error_cr)
                self.log.set_reg(a.error_cr, (cr | 1) if rec.failed else (cr & ~1))
        else:
            self.log.set_reg(
                a.ret, self.mask(-rec.result if rec.failed else rec.result))

    # ---- the kernel's own state ------------------------------------------

    def _snapshot(self) -> tuple:
        return (dict(self.files), {fd: f.offset for fd, f in self.files.items()},
                self._next_fd, self.brk_current, self.brk_mapped, self.mmap_next)

    def _restore(self, snap: tuple) -> None:
        files, offsets, next_fd, brk, brk_mapped, mmap_next = snap
        self.files = dict(files)
        for fd, offset in offsets.items():
            self.files[fd].offset = offset
        self._next_fd = next_fd
        self.brk_current, self.brk_mapped, self.mmap_next = brk, brk_mapped, mmap_next

    # ---- what a handler works with ---------------------------------------

    def errno(self, name: str) -> int:
        overrides = self.abi.errnos or {}
        return overrides.get(name, ERRNO[name])

    def mask(self, value: int) -> int:
        return value & ((1 << self.spec.bits) - 1)

    @property
    def records(self) -> List[SyscallRecord]:
        """What has been called, oldest first, as far back as the history goes."""
        return [e.detail for e in self.log.entries if e.detail is not None]

    def read_mem(self, address: int, size: int) -> bytes:
        if size < 0 or size > MAX_TRANSFER:
            raise SyscallError('EFAULT')
        return self.target.read(address, size)

    def write_mem(self, address: int, data: bytes) -> None:
        """Write on the program's behalf, and remember it for the replay."""
        self.log.write_mem(address, data)

    def read_word(self, address: int) -> int:
        size = self.spec.ptr_size
        return int.from_bytes(self.target.read(address, size), self.spec.endian)

    def read_cstring(self, address: int, limit: int = 4096) -> str:
        out = bytearray()
        while len(out) < limit:
            chunk = self.target.read(address + len(out), min(64, limit - len(out)))
            if b'\0' in chunk:
                out += chunk[:chunk.index(b'\0')]
                break
            out += chunk
        return out.decode('utf-8', 'replace')

    def map(self, start: int, size: int, perms: int = UC_PROT_ALL) -> None:
        self.log.map(start, size, perms)

    def unmap(self, start: int, size: int) -> None:
        self.log.unmap(start, size)

    def exit(self, status: int, description: str) -> None:
        self.log.stop('exit', description)

    def _output(self, fd: int, data: bytes) -> None:
        self.log.output(fd, data)
        if self.on_output is not None:
            self.on_output(fd, data)

    def _log(self, text: str) -> None:
        if self.on_output is not None:
            self.on_output(2, (text + '\n').encode())
        else:
            print(text, flush=True)

    # ---- descriptors and memory ------------------------------------------

    def file(self, fd: int) -> OpenFile:
        f = self.files.get(fd)
        if f is None:
            raise SyscallError('EBADF')
        return f

    def add_file(self, path: str, data: bytes) -> None:
        """Make `path` visible to the program, with these contents."""
        self.contents[path] = bytes(data)

    def open_file(self, path: str) -> int:
        if path not in self.contents:
            raise SyscallError('ENOENT')
        fd = self._next_fd
        self._next_fd += 1
        self.files[fd] = OpenFile(path, self.contents[path])
        return fd

    def free_span(self, size: int) -> int:
        """The next unused address in the mmap arena."""
        size = (size + PAGE - 1) & ~(PAGE - 1)
        start = self.mmap_next
        if start + size > self.mmap_base + self.mmap_size:
            raise SyscallError('ENOMEM')
        self.mmap_next = start + size
        return start

    def mapped(self, start: int, size: int) -> bool:
        end = start + size - 1
        for rs, re_, _ in self.target.regions():
            if rs <= start and end <= re_:
                return True
        return False

    def describe(self) -> str:
        if not self.records:
            calls = 'no system calls yet'
        else:
            names: Dict[str, int] = {}
            for r in self.records:
                names[r.name] = names.get(r.name, 0) + 1
            calls = ', '.join(f'{n}x{c}' for n, c in sorted(names.items()))
        unknown = (', unhandled: '
                   + ', '.join(f'{n} ({c}x)' for n, c in sorted(self.unknown.items()))
                   if self.unknown else '')
        return (f'syscalls: {self.spec.key} Linux, {len(self.records)} recorded '
                f'({calls}){unknown}; brk {self.brk_current:#x}, '
                f'mmap next {self.mmap_next:#x}')


# ---------------------------------------------------------------------------
# The Linux layer

def sys_read(s: Syscalls, args: List[int]) -> int:
    fd, buf, count = args[0], args[1], args[2]
    f = s.file(fd)
    if f.writable:
        raise SyscallError('EBADF')
    data = f.data[f.offset:f.offset + count]
    f.offset += len(data)
    s.write_mem(buf, data)
    return len(data)


def sys_write(s: Syscalls, args: List[int]) -> int:
    fd, buf, count = args[0], args[1], args[2]
    f = s.file(fd)
    if not f.writable:
        raise SyscallError('EBADF')
    data = s.read_mem(buf, count) if count else b''
    f.sink(data)
    return len(data)


def sys_writev(s: Syscalls, args: List[int]) -> int:
    fd, iov, count = args[0], args[1], args[2]
    f = s.file(fd)
    if not f.writable:
        raise SyscallError('EBADF')
    size = s.spec.ptr_size
    total = 0
    for i in range(count):
        base = s.read_word(iov + i * 2 * size)
        length = s.read_word(iov + i * 2 * size + size)
        if length:
            f.sink(s.read_mem(base, length))
        total += length
    return total


def sys_open(s: Syscalls, args: List[int]) -> int:
    return s.open_file(s.read_cstring(args[0]))


def sys_openat(s: Syscalls, args: List[int]) -> int:
    # Only AT_FDCWD with an absolute-or-known name; there are no directories
    # here to resolve a relative path against.
    return s.open_file(s.read_cstring(args[1]))


def sys_close(s: Syscalls, args: List[int]) -> int:
    fd = args[0]
    s.file(fd)
    if fd <= 2:
        return 0          # closing a standard stream is a no-op, not an error
    del s.files[fd]
    return 0


def sys_lseek(s: Syscalls, args: List[int]) -> int:
    fd, offset, whence = args[0], _signed(args[1], s.spec.bits), args[2]
    f = s.file(fd)
    if f.writable:
        raise SyscallError('ESPIPE')
    if whence == SEEK_SET:
        pos = offset
    elif whence == SEEK_CUR:
        pos = f.offset + offset
    elif whence == SEEK_END:
        pos = len(f.data) + offset
    else:
        raise SyscallError('EINVAL')
    if pos < 0:
        raise SyscallError('EINVAL')
    f.offset = pos
    return pos


def sys_mmap(s: Syscalls, args: List[int]) -> int:
    addr, length, prot, flags, fd = args[0], args[1], args[2], args[3], _signed(args[4], 32)
    if length == 0:
        raise SyscallError('EINVAL')
    size = (length + PAGE - 1) & ~(PAGE - 1)
    perms = prot & (UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    if perms == 0:
        perms = UC_PROT_READ       # PROT_NONE still needs a page to exist
    if flags & MAP_FIXED and addr:
        start = addr & ~(PAGE - 1)
        if s.mapped(start, size):
            return start           # already ours; nothing to do
    else:
        start = s.free_span(size)
    try:
        s.map(start, size, perms)      # Unicorn hands out zeroed pages
    except UcError:
        raise SyscallError('ENOMEM')
    if not (flags & MAP_ANONYMOUS) and fd >= 0:
        f = s.file(fd)
        s.write_mem(start, f.data[:size])
    return start


def sys_munmap(s: Syscalls, args: List[int]) -> int:
    addr, length = args[0], args[1]
    start = addr & ~(PAGE - 1)
    size = (length + (addr - start) + PAGE - 1) & ~(PAGE - 1)
    if size == 0:
        raise SyscallError('EINVAL')
    try:
        s.unmap(start, size)
    except UcError:
        raise SyscallError('EINVAL')
    return 0


def sys_brk(s: Syscalls, args: List[int]) -> int:
    want = args[0]
    if want == 0 or want < s.brk_base:
        return s.brk_current
    if want > s.brk_base + s.brk_size:
        return s.brk_current       # Linux returns the old break on failure
    top = (want + PAGE - 1) & ~(PAGE - 1)
    if top > s.brk_mapped:
        size = top - s.brk_mapped
        try:
            s.map(s.brk_mapped, size)
        except UcError:
            return s.brk_current
        s.brk_mapped = top
    s.brk_current = want
    return want


def sys_getpid(s: Syscalls, args: List[int]) -> int:
    return 1


def sys_exit(s: Syscalls, args: List[int]) -> int:
    status = _signed(args[0], 32)
    s.exit(status, f'Program exited with status {status}')
    return 0


HANDLERS: Dict[str, Callable[[Syscalls, List[int]], int]] = {
    'read': sys_read, 'write': sys_write, 'writev': sys_writev,
    'open': sys_open, 'openat': sys_openat, 'close': sys_close,
    'lseek': sys_lseek, 'mmap': sys_mmap, 'mmap2': sys_mmap,
    'munmap': sys_munmap, 'brk': sys_brk, 'getpid': sys_getpid,
    'exit': sys_exit, 'exit_group': sys_exit,
}


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def install(target, **kwargs) -> Syscalls:
    """Put a Linux under `target` and return it."""
    return Syscalls(target, **kwargs).install()


def available(key: str) -> bool:
    return key in _abi.SYSCALLS
