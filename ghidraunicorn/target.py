"""A debuggable wrapper around a Unicorn engine.

Everything Ghidra needs from an emulator is here and nothing here knows about
Ghidra: run, step, interrupt, breakpoints, watchpoints, memory and register
access. The Trace RMI layers (commands/methods/hooks) call into this.

Execution model
---------------
Unicorn is single-threaded. `run()` blocks the calling thread until the
emulator stops; the connector calls it from a dedicated thread so that Ghidra
can still invoke `interrupt()`, which is the one call allowed to come from
another thread while emulation is in progress (it only flips Unicorn's stop
flag).

Breakpoints are a UC_HOOK_CODE hook over all memory that calls emu_stop when
the address about to execute is a breakpoint. The hook fires *before* the
instruction executes, so a stop leaves PC on the breakpoint address, like a
hardware debugger. The first instruction of any run is exempt, so resuming from
a breakpoint steps past it.
"""
from dataclasses import dataclass, field
import threading
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UC_MEM_WRITE, Uc, UcError)

from .arch import ArchSpec, spec_for_uc

PAGE = 0x1000

READ, WRITE, ACCESS, EXECUTE = 'READ', 'WRITE', 'READ,WRITE', 'SW_EXECUTE'


class TargetError(Exception):
    pass


@dataclass
class Breakpoint:
    num: int
    kind: str            # EXECUTE | READ | WRITE | ACCESS
    address: int
    size: int = 1
    enabled: bool = True
    hit_count: int = 0
    temporary: bool = False
    _hooks: List[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.address + self.size - 1

    def describe(self) -> str:
        if self.kind == EXECUTE:
            return f'*{self.address:#x}'
        return f'{self.kind.lower()} {self.address:#x}+{self.size}'


@dataclass(frozen=True)
class StopEvent:
    reason: str          # 'breakpoint' | 'watchpoint' | 'step' | 'interrupt' | 'exit' | 'error' | 'stopped'
    pc: int
    description: str
    breakpoint: Optional[Breakpoint] = None
    error: Optional[UcError] = None

    @property
    def terminated(self) -> bool:
        return self.reason == 'exit'


class UnicornTarget:

    def __init__(self, uc: Uc, spec: Optional[ArchSpec] = None,
                 end: Optional[int] = None, exits: Iterable[int] = (),
                 name: str = 'unicorn') -> None:
        self.uc = uc
        self.spec = spec or spec_for_uc(uc)
        self.name = name
        self.end = end
        self.exits: Set[int] = set(exits)
        self.breakpoints: Dict[int, Breakpoint] = {}
        self._next_bp = 1
        self._bp_by_addr: Dict[int, Breakpoint] = {}
        self._temp: Set[int] = set()
        self._running = False
        self._first = False
        self._stop: Optional[StopEvent] = None
        self._pending: Optional[StopEvent] = None
        self._lock = threading.Lock()
        self.terminated = False
        self.exit_description = ''
        self.listeners: List[Callable[[StopEvent], None]] = []
        self._code_hook = uc.hook_add(UC_HOOK_CODE, self._on_code)
        self._cs = None

    # ---- registers -------------------------------------------------------

    def reg_read(self, name: str) -> int:
        return self.uc.reg_read(self.spec.reg(name).uc)

    def reg_write(self, name: str, value: int) -> None:
        self.uc.reg_write(self.spec.reg(name).uc, value)

    def pc(self) -> int:
        return self.reg_read(self.spec.pc)

    def sp(self) -> int:
        return self.reg_read(self.spec.sp)

    def regs(self) -> Dict[str, int]:
        out = {}
        for r in self.spec.regs:
            try:
                out[r.name] = self.uc.reg_read(r.uc)
            except UcError:
                pass
        return out

    # ---- memory ----------------------------------------------------------

    def regions(self) -> List[Tuple[int, int, int]]:
        """Mapped regions as (start, end_inclusive, perms)."""
        return sorted(self.uc.mem_regions())

    def read(self, address: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(address, size))

    def write(self, address: int, data: bytes) -> None:
        self.uc.mem_write(address, data)

    def read_mapped(self, start: int, end: int) -> List[Tuple[int, bytes]]:
        """Read [start, end) clipped to mapped regions; returns chunks."""
        chunks = []
        for rstart, rend, _ in self.regions():
            lo = max(start, rstart)
            hi = min(end, rend + 1)
            if lo < hi:
                chunks.append((lo, self.read(lo, hi - lo)))
        return chunks

    # ---- breakpoints -----------------------------------------------------

    def add_breakpoint(self, address: int, temporary: bool = False) -> Breakpoint:
        for b in self.breakpoints.values():
            if b.kind == EXECUTE and b.address == address and not temporary:
                return b
        bp = Breakpoint(self._next_bp, EXECUTE, address, 1, temporary=temporary)
        self._next_bp += 1
        self.breakpoints[bp.num] = bp
        self._bp_by_addr[address] = bp
        return bp

    def add_watchpoint(self, address: int, size: int, kind: str) -> Breakpoint:
        if kind not in (READ, WRITE, ACCESS):
            raise TargetError(f'bad watchpoint kind {kind}')
        bp = Breakpoint(self._next_bp, kind, address, max(size, 1))
        self._next_bp += 1
        self.breakpoints[bp.num] = bp
        self._install_watch(bp)
        return bp

    def _install_watch(self, bp: Breakpoint) -> None:
        types = 0
        if bp.kind in (READ, ACCESS):
            types |= UC_HOOK_MEM_READ
        if bp.kind in (WRITE, ACCESS):
            types |= UC_HOOK_MEM_WRITE
        h = self.uc.hook_add(types, self._on_mem, user_data=bp,
                             begin=bp.address, end=bp.end)
        bp._hooks.append(h)

    def enable_breakpoint(self, num: int, enabled: bool) -> Breakpoint:
        bp = self.breakpoints[num]
        bp.enabled = enabled
        return bp

    def delete_breakpoint(self, num: int) -> None:
        bp = self.breakpoints.pop(num)
        if bp.kind == EXECUTE:
            if self._bp_by_addr.get(bp.address) is bp:
                del self._bp_by_addr[bp.address]
        for h in bp._hooks:
            self.uc.hook_del(h)

    # ---- hooks -----------------------------------------------------------

    def _on_code(self, uc, address, size, user_data) -> None:
        if self._pending is not None:
            # A watchpoint fired during the previous instruction. That
            # instruction has now completed, so stop here, before this one.
            self._stop = self._pending
            self._pending = None
            uc.emu_stop()
            return
        if self._first:
            self._first = False
            return
        if address in self.exits or (self.end is not None and address == self.end):
            self._stop = StopEvent('exit', address, f'Reached exit {address:#x}')
            uc.emu_stop()
            return
        bp = self._bp_by_addr.get(address)
        if bp is not None and bp.enabled:
            bp.hit_count += 1
            self._stop = StopEvent('breakpoint', address,
                                   f'Breakpoint {bp.num} at {address:#x}', bp)
            uc.emu_stop()

    def _on_mem(self, uc, access, address, size, value, bp: Breakpoint) -> bool:
        if not bp.enabled or self._stop is not None or self._pending is not None:
            return True
        what = 'write' if access == UC_MEM_WRITE else 'read'
        bp.hit_count += 1
        # Do not stop here: Unicorn would leave PC on the accessing instruction
        # with its side effects already applied, and a resume would run it
        # again. Let the instruction finish and stop at the next code hook.
        self._pending = StopEvent(
            'watchpoint', 0, f'Watchpoint {bp.num}: {what} {size} bytes at {address:#x}', bp)
        return True

    # ---- execution -------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._running

    def _emulate(self, count: int, until: Optional[int] = None) -> StopEvent:
        if self.terminated:
            raise TargetError('target has terminated')
        with self._lock:
            if self._running:
                raise TargetError('target is already running')
            self._running = True
        self._stop = None
        self._pending = None
        self._first = True
        start = self.pc()
        if self.spec.context.get('TMode'):
            start |= 1   # Unicorn wants the Thumb bit on the start address
        stop_at = until if until is not None else (self.end if self.end is not None else 0)
        error = None
        try:
            self.uc.emu_start(start, stop_at, 0, count)
        except UcError as e:
            error = e
        finally:
            self._running = False
        pc = self.pc()
        if self._stop is None and self._pending is not None:
            # count=1 (or `until`) ended the run before the next code hook
            # could report the watchpoint; report it now, PC is already past.
            self._stop = self._pending
            self._pending = None
        if error is not None:
            ev = StopEvent('error', pc, f'{error} at {pc:#x}', error=error)
        elif self._stop is not None:
            ev = self._stop
            if ev.reason == 'watchpoint':
                ev = StopEvent(ev.reason, pc, ev.description, ev.breakpoint)
        elif until is not None and pc == until:
            ev = StopEvent('step', pc, f'Advanced to {pc:#x}')
        elif self.end is not None and pc == self.end:
            ev = StopEvent('exit', pc, f'Reached end {pc:#x}')
        elif count > 0:
            ev = StopEvent('step', pc, f'Stepped to {pc:#x}')
        elif self._interrupted:
            ev = StopEvent('interrupt', pc, f'Interrupted at {pc:#x}')
        elif until is not None or self.end is not None:
            # emu_start returned on its own: the `until` address was reached.
            # On MIPS/ARM-with-delay-slots Unicorn stops at the branch when the
            # target is its delay slot, so PC can sit one instruction short.
            target_addr = until if until is not None else self.end
            reason = 'step' if until is not None else 'exit'
            ev = StopEvent(reason, pc, f'Reached {target_addr:#x} (stopped at {pc:#x})')
        else:
            ev = StopEvent('stopped', pc, f'Stopped at {pc:#x}')
        self._interrupted = False
        if ev.terminated:
            self.terminated = True
            self.exit_description = ev.description
        if ev.breakpoint is not None and ev.breakpoint.temporary:
            self.delete_breakpoint(ev.breakpoint.num)
        for cb in list(self.listeners):
            cb(ev)
        return ev

    _interrupted = False

    def run(self) -> StopEvent:
        """Run until a breakpoint, watchpoint, exit, error, or interrupt."""
        return self._emulate(0)

    def step(self, n: int = 1) -> StopEvent:
        ev = None
        for _ in range(max(n, 1)):
            ev = self._emulate(1)
            if ev.reason != 'step':
                break
        return ev

    def advance(self, address: int) -> StopEvent:
        """Run until PC reaches `address` (or something else stops us)."""
        self.add_breakpoint(address, temporary=True)
        return self._emulate(0)

    def step_over(self, n: int = 1) -> StopEvent:
        ev = None
        for _ in range(max(n, 1)):
            pc = self.pc()
            insn = self.decode(pc)
            if insn is not None and insn[1] in self.spec.call_mnemonics:
                ev = self.advance(pc + insn[0])
            else:
                ev = self._emulate(1)
            if ev.reason != 'step':
                break
        return ev

    def interrupt(self) -> None:
        if self._running:
            self._interrupted = True
            self.uc.emu_stop()

    # ---- decoding --------------------------------------------------------

    def decode(self, address: int) -> Optional[Tuple[int, str, str]]:
        """(size, mnemonic, operands) of the instruction at address, via
        Capstone when available; None otherwise."""
        if self.spec.cs is None:
            return None
        if self._cs is None:
            import capstone
            self._cs = capstone.Cs(*self.spec.cs)
        try:
            code = self.read(address, 16)
        except UcError:
            try:
                code = self.read(address, 4)
            except UcError:
                return None
        for _, size, mnem, ops in self._cs.disasm_lite(code, address, 1):
            return size, mnem, ops
        return None
