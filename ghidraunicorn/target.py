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

Reverse execution
-----------------
That same code hook counts instructions and hands them to a `Timeline`, which
checkpoints the machine periodically (see timeline.py). Going back to
instruction K restores the newest checkpoint at or before K and re-emulates the
difference with `_replaying` set, which mutes the breakpoint and watchpoint
hooks and suppresses stop events, so a replay is invisible: no hit counts move
and no listener hears about it. Only the reverse operation itself reports, once.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import threading
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_WRITE, UC_MEM_WRITE, Uc, UcError)
from unicorn import unicorn_const as _uc_const

from .arch import ArchSpec, spec_for_uc
from .timeline import DEFAULT_BUDGET, DEFAULT_INTERVAL, Timeline

PAGE = 0x1000

READ, WRITE, ACCESS, EXECUTE = 'READ', 'WRITE', 'READ,WRITE', 'SW_EXECUTE'

#: How far behind a requested stop address Unicorn may leave the program
#: counter and still be considered to have arrived: one instruction, and the
#: longest instruction of any architecture here is 15 bytes.
ARRIVAL_SLACK = 16

_ACCESS_NAMES = {getattr(_uc_const, n): n for n in dir(_uc_const)
                 if n.startswith('UC_MEM_')}


def _arrived_at(pc: int, target: Optional[int]) -> bool:
    return target is not None and 0 <= target - pc <= ARRIVAL_SLACK


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
    #: For a fault, the access Unicorn refused. UcError itself carries only an
    #: error number, so these come from an invalid-memory hook.
    fault_address: Optional[int] = None
    fault_access: Optional[str] = None
    fault_size: Optional[int] = None

    @property
    def terminated(self) -> bool:
        return self.reason == 'exit'


class UnicornTarget:

    def __init__(self, uc: Uc, spec: Optional[ArchSpec] = None,
                 end: Optional[int] = None, exits: Iterable[int] = (),
                 name: str = 'unicorn', record: bool = True,
                 checkpoint_interval: int = DEFAULT_INTERVAL,
                 memory_budget: int = DEFAULT_BUDGET) -> None:
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
        self._fault: Optional[Tuple[str, int, int]] = None
        uc.hook_add(UC_HOOK_MEM_INVALID, self._on_invalid)
        self._cs = None
        self.timeline = Timeline(uc, interval=checkpoint_interval,
                                 budget=memory_budget, enabled=record)
        self._replaying = False
        self._left = -1            # instructions left in this run; -1 is all
        self._trace: Optional[List[int]] = None
        self._write_hook = (uc.hook_add(UC_HOOK_MEM_WRITE, self._on_write)
                            if record else None)

    # ---- registers -------------------------------------------------------

    def _field(self, name: str):
        """'cpsr.M' -> (status register, Field) or None."""
        if '.' not in name:
            return None
        reg, fname = name.split('.', 1)
        if self.spec.status is None or reg.lower() != self.spec.status.lower():
            raise KeyError(f'{reg} has no fields (status register is {self.spec.status})')
        fld = self.spec.field(fname)
        if fld is None:
            raise KeyError(f'{reg} has no field {fname}; fields: '
                           + ', '.join(f.name for f in self.spec.fields))
        return self.spec.reg(reg), fld

    def reg_read(self, name: str) -> int:
        rf = self._field(name)
        if rf is not None:
            return rf[1].get(self.uc.reg_read(rf[0].uc))
        f = self.spec.flag(name)
        if f is not None:
            return f.get(self.uc.reg_read(self.spec.reg(f.source).uc))
        return self.uc.reg_read(self.spec.reg(name).uc)

    def reg_write(self, name: str, value: int) -> None:
        rf = self._field(name)
        if rf is not None:
            cur = self.uc.reg_read(rf[0].uc)
            self.uc.reg_write(rf[0].uc, rf[1].set(cur, value))
            self.timeline.note_external_change()
            return
        f = self.spec.flag(name)
        if f is not None:
            src = self.spec.reg(f.source)
            cur = self.uc.reg_read(src.uc)
            self.uc.reg_write(src.uc, f.set(cur, int(value)))
            self.timeline.note_external_change()
            return
        self.uc.reg_write(self.spec.reg(name).uc, value)
        self.timeline.note_external_change()

    def fields(self) -> List[Tuple[str, str]]:
        """Decoded fields of the status register, MSB first."""
        if self.spec.status is None:
            return []
        return self.spec.decode_fields(self.uc.reg_read(self.spec.reg(self.spec.status).uc))

    def flags(self) -> Dict[str, int]:
        """Ghidra's one-byte flag registers decoded from the status register."""
        if self.spec.status is None:
            return {}
        return self.spec.decode_flags(self.uc.reg_read(self.spec.reg(self.spec.status).uc))

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
        # The memory hook only sees the program's own writes, and this one is
        # not in the instruction stream a replay re-runs, so the timeline has
        # to checkpoint it.
        self.timeline.note_external_write(address, len(data))

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
        if self._replaying:
            # Re-running history: no breakpoints, no exits, no counting, and
            # no stop event. Only the instruction limit applies.
            if self._left == 0:
                uc.emu_stop()
                return
            self._left -= 1
            if self._trace is not None:
                self._trace.append(address)
            return
        if self._pending is not None:
            # A watchpoint fired during the previous instruction. That
            # instruction has now completed, so stop here, before this one.
            self._stop = self._pending
            self._pending = None
            uc.emu_stop()
            return
        if self._first:
            self._first = False
            self.timeline.note_instruction()
            self._left -= 1
            return
        # Arriving at the end is terminal, so it is checked before the
        # instruction budget. A branch and its delay slot are one step, and the
        # delay slot can be the end address: checking the budget first would
        # stop without ever noticing we had arrived.
        if address in self.exits or (self.end is not None and address == self.end):
            self._stop = StopEvent('exit', address, f'Reached exit {address:#x}')
            uc.emu_stop()
            return
        if self._left == 0:
            # Unicorn's own instruction count overruns after a context_restore
            # - it will happily run a whole basic block for a count of one -
            # so the limit is enforced here, where a stop is exact.
            uc.emu_stop()
            return
        bp = self._bp_by_addr.get(address)
        if bp is not None and bp.enabled:
            bp.hit_count += 1
            self._stop = StopEvent('breakpoint', address,
                                   f'Breakpoint {bp.num} at {address:#x}', bp)
            uc.emu_stop()
            return
        # Nothing stopped us, so this instruction is about to run: the state we
        # are in now is the state at `timeline.icount`.
        self.timeline.note_instruction()
        self._left -= 1

    def _on_invalid(self, uc, access, address, size, value, user_data) -> bool:
        """Remember the access Unicorn is about to refuse.

        A UcError carries only an error number, so without this the faulting
        address is lost. Returning False lets the fault propagate unchanged.
        """
        self._fault = (_ACCESS_NAMES.get(access, str(access)), address, size)
        return False

    def _on_write(self, uc, access, address, size, value, user_data) -> bool:
        """Note the pages the program writes, for the next checkpoint's delta."""
        self.timeline.note_write(address, size)
        return True

    def _on_mem(self, uc, access, address, size, value, bp: Breakpoint) -> bool:
        if self._replaying:
            return True
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

    def _start_pc(self) -> int:
        pc = self.pc()
        if self.spec.context.get('TMode'):
            pc |= 1      # Unicorn wants the Thumb bit on the start address
        return pc

    def _notify(self, ev: StopEvent) -> StopEvent:
        for cb in list(self.listeners):
            cb(ev)
        return ev

    def _emulate(self, count: int, until: Optional[int] = None) -> StopEvent:
        if self.terminated:
            raise TargetError('target has terminated')
        with self._lock:
            if self._running:
                raise TargetError('target is already running')
            self._running = True
        self._stop = None
        self._pending = None
        self._fault = None
        self._first = True
        self._left = count if count > 0 else -1     # -1: as long as it takes
        start = self._start_pc()
        # Only a free run hands `end` to Unicorn as its stop address. When
        # stepping, the instruction count bounds the run and the code hook
        # reports the end, because Unicorn leaves the program counter on the
        # *branch* when the stop address is its delay slot: passing `end` here
        # would re-execute that branch on every step, forever, applying its
        # side effects each time.
        stop_at = until if until is not None else (
            self.end if (self.end is not None and count == 0) else 0)
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
            # The faulting instruction was counted when its hook ran but never
            # completed; PC sits on it, which is the state before it.
            self.timeline.uncount()
            access, faddr, fsize = self._fault or (None, None, None)
            where = '' if faddr is None else f' touching {faddr:#x}'
            ev = StopEvent('error', pc, f'{error} at {pc:#x}{where}', error=error,
                           fault_address=faddr, fault_access=access, fault_size=fsize)
        elif self._stop is not None:
            ev = self._stop
            if ev.reason == 'watchpoint':
                ev = StopEvent(ev.reason, pc, ev.description, ev.breakpoint)
        elif until is not None and pc == until:
            ev = StopEvent('step', pc, f'Advanced to {pc:#x}')
        elif pc in self.exits or (self.end is not None and pc == self.end):
            # Unicorn's instruction count stops the run before the hook for the
            # next instruction fires, so a step that lands on an exit is only
            # visible here. Without this, stepping would walk straight past an
            # exit that a free run stops at.
            ev = StopEvent('exit', pc, f'Reached exit {pc:#x}')
        elif count > 0:
            ev = StopEvent('step', pc, f'Stepped to {pc:#x}')
        elif self._interrupted:
            ev = StopEvent('interrupt', pc, f'Interrupted at {pc:#x}')
        elif _arrived_at(pc, until if until is not None else self.end):
            # emu_start returned on its own, just short of where it was told to
            # stop: with delay slots Unicorn stops on the branch when the stop
            # address is its slot, leaving PC one instruction behind. Only a PC
            # that close counts as arriving; anything else is some other hook
            # calling emu_stop, and claiming the program ended would be a lie.
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
        return self._notify(ev)

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

    # ---- reverse execution -----------------------------------------------

    @property
    def icount(self) -> int:
        """Instructions executed to reach the state we are in now."""
        return self.timeline.icount

    @property
    def earliest_icount(self) -> int:
        """The oldest instruction still in the history."""
        return self.timeline.earliest

    @property
    def can_reverse(self) -> bool:
        return self.timeline.recording and self.icount > self.earliest_icount

    def _require_reversible(self, k: int) -> None:
        if self._running:
            raise TargetError('target is running; interrupt it first')
        self._check_bounds(k)

    def _check_bounds(self, k: int) -> None:
        if not self.timeline.enabled:
            raise TargetError('execution history is off for this target')
        if not self.timeline.recording:
            raise TargetError('no execution history yet: nothing has run')
        if k < self.timeline.earliest:
            dropped = self.timeline.dropped
            extra = (f' ({dropped} older checkpoint(s) were dropped to stay '
                     f'inside the {self.timeline.budget} byte history budget)'
                     if dropped else '')
            raise TargetError(
                f'cannot go back to instruction {k}: the history only reaches '
                f'back to instruction {self.timeline.earliest}{extra}')
        if k > self.icount:
            raise TargetError(
                f'cannot go forward to instruction {k}: the target is at '
                f'instruction {self.icount} and the future is not recorded; '
                f'use step or resume')

    def _replay_forward(self, n: int, trace: Optional[List[int]] = None) -> None:
        """Emulate n instructions with the hooks muted: no breakpoint or
        watchpoint may fire and no stop event is produced."""
        if n <= 0:
            return
        self._replaying = True
        self._trace = trace
        self._left = n
        try:
            self.uc.emu_start(self._start_pc(), 0, 0, n)
        except UcError as e:
            raise TargetError(f'replaying history failed at {self.pc():#x}: {e}') from e
        finally:
            self._replaying = False
            self._trace = None

    def _restore_state(self, icount: int):
        """The timeline's restore, plus the flag fix-up below."""
        cp = self.timeline.restore(icount)
        self._resync_status()
        return cp

    def _resync_status(self) -> None:
        """Unicorn keeps x86's flags lazily in cc_op/cc_src, and the first
        emu_start after a context_restore recomputes them from the stale
        eflags word, losing PF and friends. Reading the status register forces
        the computation; writing it back makes the word the truth again."""
        name = self.spec.status
        if name is None:
            return
        try:
            reg = self.spec.reg(name)
            self.uc.reg_write(reg.uc, self.uc.reg_read(reg.uc))
        except (KeyError, UcError):
            pass

    @contextmanager
    def _reversing(self):
        """Hold the emulator for the duration of a reverse operation, so a
        resume from another thread cannot start on top of a replay."""
        with self._lock:
            if self._running:
                raise TargetError('target is already running')
            self._running = True
        try:
            yield
        finally:
            self._running = False

    def _go(self, k: int) -> None:
        """Put the machine in the state it had at instruction k. Silent."""
        was = self.icount
        self._check_bounds(k)
        cp = self._restore_state(k)
        self.timeline.truncate(cp.icount)
        self._replay_forward(k - cp.icount)
        self.timeline.advance_to(k)
        self._stop = None
        self._pending = None
        if k < was and self.terminated:
            self.terminated = False
            self.exit_description = ''

    def _history_pcs(self, lo: int, hi: int) -> Dict[int, int]:
        """The PC at each instruction in [lo, hi], by replaying from the
        checkpoint at or before `lo`. Leaves the machine at the end of the
        replay, so a caller must always finish with `_go`."""
        cp = self._restore_state(lo)
        trace: List[int] = []
        self._replay_forward(hi - cp.icount + 1, trace)
        return {cp.icount + i: pc for i, pc in enumerate(trace)}

    def _depths(self, pcs: List[int]) -> List[int]:
        """Call depth at each of a run of consecutive PCs, relative to the
        first. A call pushes its return address; arriving at that address pops
        it. Needs Capstone; without it everything stays at depth 0, which makes
        a reverse step-over a plain reverse step."""
        depth, out, stack = 0, [], []
        calls = self.spec.call_mnemonics
        sizes: Dict[int, Optional[int]] = {}       # a loop decodes once
        for pc in pcs:
            while stack and pc == stack[-1]:
                stack.pop()
                depth -= 1
            out.append(depth)
            if pc not in sizes:
                insn = self.decode(pc)
                sizes[pc] = (pc + insn[0]) if (insn is not None
                                               and insn[1] in calls) else None
            ret = sizes[pc]
            if ret is not None:
                stack.append(ret)
                depth += 1
        return out

    def goto_icount(self, k: int) -> StopEvent:
        """Restore the state the target had at instruction `k`."""
        self._require_reversible(k)
        with self._reversing():
            self._go(k)
        pc = self.pc()
        return self._notify(StopEvent(
            'step', pc, f'At instruction {k} ({pc:#x})'))

    def step_back(self, n: int = 1) -> StopEvent:
        """Undo the last n instructions."""
        k = self.icount - max(n, 1)
        self._require_reversible(k)
        with self._reversing():
            self._go(k)
        pc = self.pc()
        return self._notify(StopEvent(
            'step', pc, f'Stepped back to {pc:#x} (instruction {k})'))

    def step_back_over(self, n: int = 1) -> StopEvent:
        """Undo the last n instructions, skipping back over whole calls."""
        k = self.icount
        self._require_reversible(k - 1)
        with self._reversing():
            for _ in range(max(n, 1)):
                self._check_bounds(k - 1)
                k = self._prev_over()
                self._go(k)
        pc = self.pc()
        return self._notify(StopEvent(
            'step', pc, f'Stepped back over to {pc:#x} (instruction {k})'))

    def _prev_over(self) -> int:
        """The instruction a reverse step-over lands on: the most recent one
        before now that ran at the current call depth or shallower.

        Call depth is only meaningful against a fixed starting point, so this
        replays the whole retained history once and is O(instructions kept).
        A window starting mid-call would count a `ret` out of a frame it never
        saw entered as depth 0 and land inside the callee.
        """
        cur = self.icount
        cur_pc = self.pc()
        earliest = self.timeline.earliest
        pcs = self._history_pcs(earliest, cur - 1)
        seq = [pcs[i] for i in range(earliest, cur)]
        depths = self._depths(seq + [cur_pc])
        here = depths[-1]
        for idx in range(len(seq) - 1, -1, -1):
            if depths[idx] <= here:
                return earliest + idx
        return earliest

    def resume_back(self) -> StopEvent:
        """Run backwards to the most recent breakpoint hit before now, or to
        the earliest instruction the history still holds."""
        cur = self.icount
        self._require_reversible(cur - 1)
        addrs = {b.address for b in self.breakpoints.values()
                 if b.enabled and b.kind == EXECUTE}
        earliest = self.timeline.earliest
        found: Optional[int] = None
        with self._reversing():
            hi = cur - 1
            while addrs and found is None and hi >= earliest:
                cp = self.timeline.checkpoint_at_or_before(hi)
                pcs = self._history_pcs(cp.icount, hi)
                for j in range(hi, cp.icount - 1, -1):
                    if pcs[j] in addrs:
                        found = j
                        break
                hi = cp.icount - 1
            self._go(earliest if found is None else found)
        if found is None:
            pc = self.pc()
            return self._notify(StopEvent(
                'stopped', pc, f'No earlier breakpoint; at the start of the '
                               f'history, instruction {earliest} ({pc:#x})'))
        pc = self.pc()
        bp = self._bp_by_addr.get(pc)
        num = bp.num if bp is not None else 0
        return self._notify(StopEvent(
            'breakpoint', pc,
            f'Breakpoint {num} at {pc:#x} (backwards, instruction {found})', bp))

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
