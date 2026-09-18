"""Standing in for library functions the binary calls but does not contain.

A harness usually has the program's own code and nothing else: `malloc` is a
PLT entry pointing at a library that was never loaded, and calling it walks
into unmapped memory. This module puts a Python implementation at the
function's address instead, so the call returns a sensible answer and the
program carries on.

How a stub runs
---------------
A stub is a `UC_HOOK_CODE` hook on the function's entry address alone.
Unicorn filters by address range, so a bound stub costs nothing until it is
reached. When it fires, the stub reads the arguments where this
architecture's calling convention puts them, does the work in Python, puts
the result where the convention says, and writes the return address into the
program counter - which Unicorn honours from inside a code hook on every
architecture here, including across a MIPS delay slot. The function's own
instructions never execute, so it does not matter that they are not there.

That also decides what stepping does: one step over a call to a stubbed
function executes the whole function, because from the emulator's point of
view it is one instruction that happens to change the program counter. A
breakpoint on a stubbed function still stops before it, because the
target's own code hook runs first and says so.

Replay
------
A stub has the same problem as a system call and then some. `malloc` is not
a pure function of the machine state - it hands out a different block every
time - and, worse, a stub that failed to fire during a replay would let the
function's own instructions run, which the first pass skipped entirely, and
the machine would diverge for good. So, exactly as in `syscalls.py`, a stub
runs once and records what it did, and a replay applies the record. The
program counter it returns through is one of the recorded registers, which
is what keeps the replay on the same path.

The heap
--------
`malloc` needs memory to hand out. It comes from an arena this layer maps
on demand, with a free list so that a freed block can come back. It is a
debugger's allocator, not libc's: the aim is that a program under
examination behaves plausibly, and that a use-after-free or an overflow is
visible rather than silently absorbed.
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from unicorn import UC_HOOK_CODE, UC_PROT_ALL, UcError

from . import abi as _abi
from .abi import CallAbi
from .effects import EffectLog

PAGE = 0x1000
#: Blocks are handed out on this boundary, which is what the SysV ABIs ask
#: for and what a program that stores a double in a malloc'd block expects.
ALIGN = 16

#: Where the heap goes when nobody says otherwise. Clear of a typical image,
#: stack and the `mmap` arena in syscalls.py.
HEAP_BASE = {32: 0x5000_0000, 64: 0x5000_0000_0000}
HEAP_SIZE = 32 << 20


class StubError(Exception):
    """A stub that cannot do what it was asked."""


@dataclass
class Block:
    address: int
    size: int          # what the program asked for
    capacity: int      # what it actually got, rounded up


class Heap:
    """A bump allocator with a free list, over one region of memory.

    It is deliberately simple and deliberately *not* a recycler of the most
    recent block: a freed block goes back on the list and is reused only
    when a later request fits it. That keeps a use-after-free reading the
    bytes it had, which is usually what a person looking at a crash wants to
    see.
    """

    def __init__(self, base: int, size: int) -> None:
        self.base = base
        self.size = size
        self.top = base            # first address never handed out
        self.mapped = base         # first address not yet mapped
        self.blocks: Dict[int, Block] = {}
        self.freed: Dict[int, Block] = {}

    # The allocator's whole state, for a rewind to put back. The mapping
    # itself is rewound by the timeline and the effect log.
    def snapshot(self) -> tuple:
        return (self.top, self.mapped,
                {a: Block(b.address, b.size, b.capacity) for a, b in self.blocks.items()},
                {a: Block(b.address, b.size, b.capacity) for a, b in self.freed.items()})

    def restore(self, snap: tuple) -> None:
        self.top, self.mapped, self.blocks, self.freed = snap

    def _fit(self, want: int) -> Optional[Block]:
        best = None
        for block in self.freed.values():
            if block.capacity >= want and (best is None or block.capacity < best.capacity):
                best = block
        return best

    def allocate(self, size: int) -> Tuple[Block, int]:
        """Return the block and how far the arena must now be mapped."""
        want = max((size + ALIGN - 1) & ~(ALIGN - 1), ALIGN)
        reused = self._fit(want)
        if reused is not None:
            del self.freed[reused.address]
            reused.size = size
            self.blocks[reused.address] = reused
            return reused, self.mapped
        if self.top + want > self.base + self.size:
            raise StubError('out of heap')
        block = Block(self.top, size, want)
        self.top += want
        self.blocks[block.address] = block
        need = (self.top + PAGE - 1) & ~(PAGE - 1)
        return block, need

    def release(self, address: int) -> Block:
        block = self.blocks.pop(address, None)
        if block is None:
            raise StubError(f'free of {address:#x}, which is not an allocated block')
        self.freed[address] = block
        return block

    def describe(self) -> str:
        live = sum(b.capacity for b in self.blocks.values())
        return (f'heap {self.base:#x}+{self.size:#x}: {len(self.blocks)} blocks '
                f'({live} bytes) live, {len(self.freed)} freed, '
                f'{self.top - self.base} handed out')


class Stubs:
    """The library side of the emulator: a call in, an answer out.

    Implementations are looked up by name, so a harness can add or replace
    one without touching this file::

        st = stubs.install(target, symbols)
        st.implementations['my_hash'] = lambda s, a: 0
        st.bind('my_hash', 0x401000)
    """

    def __init__(self, target, abi: Optional[CallAbi] = None, *,
                 heap_base: Optional[int] = None, heap_size: int = HEAP_SIZE,
                 on_output: Optional[Callable[[int, bytes], None]] = None,
                 trace: bool = False) -> None:
        self.target = target
        self.spec = target.spec
        self.abi = abi or _abi.call_abi(target.spec.key)
        self.on_output = on_output
        self.trace = trace
        bits = self.spec.bits
        self.heap = Heap(HEAP_BASE[bits] if heap_base is None else heap_base, heap_size)
        self.log = EffectLog(target, 'stubs', self.heap.snapshot, self.heap.restore)
        self.implementations: Dict[str, Callable[['Stubs', List[int]], Optional[int]]] = \
            dict(IMPLEMENTATIONS)
        #: address -> name of what is bound there.
        self.bound: Dict[int, str] = {}
        self._hooks: Dict[int, int] = {}
        #: name -> how many times it has been called, for reporting.
        self.calls: Dict[str, int] = {}

    # ---- binding ---------------------------------------------------------

    def install(self) -> 'Stubs':
        self.target.stubs = self
        return self

    def bind(self, name: str, address: int) -> None:
        """Stand in for `name` at `address`."""
        if name not in self.implementations:
            raise KeyError(f'no implementation of {name}; known: '
                           + ', '.join(sorted(self.implementations)))
        if address in self._hooks:
            self.unbind(address)
        self.bound[address] = name
        self._hooks[address] = self.target.uc.hook_add(
            UC_HOOK_CODE, self._on_code, None, address, address)

    def unbind(self, address: int) -> None:
        handle = self._hooks.pop(address, None)
        if handle is not None:
            try:
                self.target.uc.hook_del(handle)
            except UcError:
                pass
        self.bound.pop(address, None)

    def bind_symbols(self, symbols, names=None) -> List[str]:
        """Bind every implementation the symbol table has an address for.

        Returns the names actually bound. A name the binary does not import
        is simply not there, which is not an error: most programs use a
        handful of these and nothing else.
        """
        done = []
        for name in sorted(names if names is not None else self.implementations):
            if name not in self.implementations:
                continue
            address = symbols.address_of(name) if symbols is not None else None
            if address is None:
                continue
            self.bind(name, address)
            done.append(name)
        return done

    def remove(self) -> None:
        for address in list(self._hooks):
            self.unbind(address)
        if self.target.stubs is self:
            self.target.stubs = None

    # ---- the hook --------------------------------------------------------

    def _on_code(self, uc, address, size, user_data) -> None:
        t = self.target
        icount = t.executing_icount
        if t.replaying:
            # A replay must stand in for the function again, or the
            # instructions the first pass skipped would run this time.
            self.log.replay(icount)
            return
        if t.halting:
            # The target's own code hook runs first and has already decided
            # this instruction is not running - a breakpoint on the function,
            # say. Standing in for it now would return from a call that has
            # not happened yet.
            return
        name = self.bound.get(address)
        if name is None:
            return
        self.calls[name] = self.calls.get(name, 0) + 1
        args = [self.arg(i) for i in range(6)]
        result: Optional[int] = 0
        with self.log.recording(icount, name) as effect:
            effect.detail = name
            try:
                result = self.implementations[name](self, args)
            except (StubError, UcError) as e:
                # The program asked for something impossible - a free of a
                # pointer it never got, a string with no terminator. Say so
                # and return zero, which is what a failing libc call does.
                if self.trace:
                    self._log(f'[stub] {name} failed: {e}')
                result = 0
            self._return(result)
        if self.trace:
            shown = ', '.join(f'{a:#x}' for a in args[:3])
            self._log(f'[stub] {name}({shown}) = '
                      + ('void' if result is None else f'{result:#x}'))
        stop = self.log.entries[-1].stop
        if stop is not None:
            t.request_stop(*stop)

    # ---- the calling convention ------------------------------------------

    def arg(self, index: int) -> int:
        """Argument `index`, wherever this convention puts it."""
        if index < len(self.abi.args):
            return self.target.reg_read(self.abi.args[index])
        slot = self.abi.stack_slot + (index - len(self.abi.args))
        try:
            return self.read_word(self.target.sp() + slot * self.spec.ptr_size)
        except UcError:
            return 0

    def _return(self, value: Optional[int]) -> None:
        """Put the result in place and go back to the caller."""
        t, a = self.target, self.abi
        if a.returns == 'link':
            ret = t.reg_read(a.link) + a.link_offset
        else:
            # The return address is on the stack, where the call pushed it.
            sp = t.sp()
            ret = self.read_word(sp)
            self.log.set_reg(self.spec.sp, sp + self.spec.ptr_size)
        if value is not None:
            self.log.set_reg(a.ret, value & ((1 << self.spec.bits) - 1))
        self.log.set_reg(self.spec.pc, ret)

    # ---- what an implementation works with -------------------------------

    def read(self, address: int, size: int) -> bytes:
        return self.target.read(address, size)

    def write(self, address: int, data: bytes) -> None:
        self.log.write_mem(address, data)

    def read_word(self, address: int) -> int:
        return int.from_bytes(self.target.read(address, self.spec.ptr_size),
                              self.spec.endian)

    def read_cstring(self, address: int, limit: int = 1 << 16) -> bytes:
        """The bytes up to the first NUL, not including it."""
        out = bytearray()
        while len(out) < limit:
            chunk = self.target.read(address + len(out), min(64, limit - len(out)))
            if b'\0' in chunk:
                return bytes(out + chunk[:chunk.index(b'\0')])
            out += chunk
        raise StubError(f'no terminator within {limit} bytes of {address:#x}')

    def malloc(self, size: int) -> int:
        if size == 0:
            size = 1           # a unique address, as libc gives
        block, need = self.heap.allocate(size)
        if need > self.heap.mapped:
            self.log.map(self.heap.mapped, need - self.heap.mapped)
            self.heap.mapped = need
        return block.address

    def output(self, data: bytes) -> None:
        self.log.output(1, data)
        if self.on_output is not None:
            self.on_output(1, data)

    def _log(self, text: str) -> None:
        if self.on_output is not None:
            self.on_output(2, (text + '\n').encode())
        else:
            print(text, flush=True)

    def describe(self) -> str:
        if not self.bound:
            return 'stubs: nothing bound'
        names = ', '.join(f'{n}@{a:#x}' for a, n in sorted(self.bound.items()))
        called = ', '.join(f'{n}x{c}' for n, c in sorted(self.calls.items()))
        return (f'stubs: {len(self.bound)} bound ({names}); '
                f'called {called or "nothing yet"}; ' + self.heap.describe())


# ---------------------------------------------------------------------------
# The implementations
#
# Each takes the layer and the arguments already read out of the convention,
# and returns the value the function returns, or None for a void one.

def _malloc(s: Stubs, a: List[int]) -> int:
    return s.malloc(a[0])


def _calloc(s: Stubs, a: List[int]) -> int:
    size = a[0] * a[1]
    address = s.malloc(size)
    s.write(address, b'\0' * max(size, 1))
    return address


def _realloc(s: Stubs, a: List[int]) -> int:
    old, size = a[0], a[1]
    if old == 0:
        return s.malloc(size)
    if size == 0:
        s.heap.release(old)
        return 0
    block = s.heap.blocks.get(old)
    if block is not None and block.capacity >= size:
        block.size = size
        return old
    new = s.malloc(size)
    if block is not None:
        s.write(new, s.read(old, min(block.size, size)))
        s.heap.release(old)
    return new


def _free(s: Stubs, a: List[int]) -> None:
    if a[0]:
        s.heap.release(a[0])
    return None


def _memcpy(s: Stubs, a: List[int]) -> int:
    dst, src, n = a[0], a[1], a[2]
    if n:
        s.write(dst, s.read(src, n))
    return dst


def _memmove(s: Stubs, a: List[int]) -> int:
    # Reading it all before writing any of it is what makes this the
    # overlapping-safe one.
    dst, src, n = a[0], a[1], a[2]
    if n:
        s.write(dst, s.read(src, n))
    return dst


def _memset(s: Stubs, a: List[int]) -> int:
    dst, value, n = a[0], a[1] & 0xff, a[2]
    if n:
        s.write(dst, bytes([value]) * n)
    return dst


def _memcmp(s: Stubs, a: List[int]) -> int:
    n = a[2]
    return _cmp(s.read(a[0], n), s.read(a[1], n)) if n else 0


def _strlen(s: Stubs, a: List[int]) -> int:
    return len(s.read_cstring(a[0]))


def _strcpy(s: Stubs, a: List[int]) -> int:
    s.write(a[0], s.read_cstring(a[1]) + b'\0')
    return a[0]


def _strncpy(s: Stubs, a: List[int]) -> int:
    dst, n = a[0], a[2]
    src = s.read_cstring(a[1])[:n]
    # strncpy pads to n with NULs and does not terminate if it does not fit.
    s.write(dst, src + b'\0' * (n - len(src)))
    return dst


def _strcat(s: Stubs, a: List[int]) -> int:
    dst = a[0]
    at = dst + len(s.read_cstring(dst))
    s.write(at, s.read_cstring(a[1]) + b'\0')
    return dst


def _strncat(s: Stubs, a: List[int]) -> int:
    dst, n = a[0], a[2]
    at = dst + len(s.read_cstring(dst))
    s.write(at, s.read_cstring(a[1])[:n] + b'\0')
    return dst


def _strcmp(s: Stubs, a: List[int]) -> int:
    return _cmp(s.read_cstring(a[0]), s.read_cstring(a[1]))


def _strncmp(s: Stubs, a: List[int]) -> int:
    n = a[2]
    return _cmp(s.read_cstring(a[0])[:n], s.read_cstring(a[1])[:n])


def _strchr(s: Stubs, a: List[int]) -> int:
    text, ch = s.read_cstring(a[0]), a[1] & 0xff
    if ch == 0:
        return a[0] + len(text)      # the terminator counts, as in libc
    idx = text.find(bytes([ch]))
    return 0 if idx < 0 else a[0] + idx


def _strrchr(s: Stubs, a: List[int]) -> int:
    text, ch = s.read_cstring(a[0]), a[1] & 0xff
    if ch == 0:
        return a[0] + len(text)
    idx = text.rfind(bytes([ch]))
    return 0 if idx < 0 else a[0] + idx


def _strdup(s: Stubs, a: List[int]) -> int:
    text = s.read_cstring(a[0])
    address = s.malloc(len(text) + 1)
    s.write(address, text + b'\0')
    return address


def _strstr(s: Stubs, a: List[int]) -> int:
    hay, needle = s.read_cstring(a[0]), s.read_cstring(a[1])
    if not needle:
        return a[0]
    idx = hay.find(needle)
    return 0 if idx < 0 else a[0] + idx


def _puts(s: Stubs, a: List[int]) -> int:
    s.output(s.read_cstring(a[0]) + b'\n')
    return 0


def _putchar(s: Stubs, a: List[int]) -> int:
    s.output(bytes([a[0] & 0xff]))
    return a[0] & 0xff


def _exit(s: Stubs, a: List[int]) -> None:
    s.log.stop('exit', f'Program called exit({_signed(a[0], 32)})')
    return None


def _abort(s: Stubs, a: List[int]) -> None:
    s.log.stop('exit', 'Program called abort()')
    return None


def _cmp(left: bytes, right: bytes) -> int:
    return 0 if left == right else (1 if left > right else -1)


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


IMPLEMENTATIONS: Dict[str, Callable[[Stubs, List[int]], Optional[int]]] = {
    'malloc': _malloc, 'calloc': _calloc, 'realloc': _realloc, 'free': _free,
    'memcpy': _memcpy, 'memmove': _memmove, 'memset': _memset, 'memcmp': _memcmp,
    'strlen': _strlen, 'strcpy': _strcpy, 'strncpy': _strncpy,
    'strcat': _strcat, 'strncat': _strncat,
    'strcmp': _strcmp, 'strncmp': _strncmp,
    'strchr': _strchr, 'strrchr': _strrchr, 'strstr': _strstr, 'strdup': _strdup,
    'puts': _puts, 'putchar': _putchar, 'exit': _exit, 'abort': _abort,
}


def install(target, symbols=None, names=None, **kwargs) -> Stubs:
    """Put the stub layer under `target`, binding what `symbols` can place."""
    layer = Stubs(target, **kwargs).install()
    if symbols is not None:
        layer.bind_symbols(symbols, names)
    return layer


def available(key: str) -> bool:
    return key in _abi.CALLS
