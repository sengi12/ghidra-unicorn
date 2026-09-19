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
from .effects import EffectLog
from .timeline import DEFAULT_BUDGET, DEFAULT_INTERVAL, Timeline

PAGE = 0x1000

READ, WRITE, ACCESS, EXECUTE = 'READ', 'WRITE', 'READ,WRITE', 'SW_EXECUTE'
#: A watch on a register rather than on memory. Unicorn has no hook for one,
#: so it is a comparison made once per instruction, and it costs that. It has
#: no Ghidra equivalent either - the trace's breakpoint kinds are all about
#: addresses - so it lives in the console and is not published.
REGISTER = 'REGISTER'

#: How far behind a requested stop address Unicorn may leave the program
#: counter and still be considered to have arrived: one instruction, and the
#: longest instruction of any architecture here is 15 bytes.
ARRIVAL_SLACK = 16

_ACCESS_NAMES = {getattr(_uc_const, n): n for n in dir(_uc_const)
                 if n.startswith('UC_MEM_')}


def _arrived_at(pc: int, target: Optional[int]) -> bool:
    return target is not None and 0 <= target - pc <= ARRIVAL_SLACK


def _condition_note(bp: 'Breakpoint') -> str:
    """A condition that would not evaluate is said out loud on every stop it
    causes, rather than left for someone to notice the breakpoint is firing
    more often than it should."""
    if bp.condition_error:
        return f' (condition {bp.condition!r} failed: {bp.condition_error})'
    return ''


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
    #: A Python expression that has to be true for this to stop. Registers
    #: are in scope by name; see `UnicornTarget.condition_scope`.
    condition: Optional[str] = None
    #: Stop only after this many more qualifying hits. Each one consumes it.
    ignore_count: int = 0
    #: What went wrong the last time the condition was evaluated. A condition
    #: that raises stops anyway, because a breakpoint that silently never
    #: fires is far harder to notice than one that stops and says why.
    condition_error: str = ''
    #: For a REGISTER watch: which register, and what it last held.
    register: Optional[str] = None
    previous: Optional[int] = None
    _hooks: List[int] = field(default_factory=list)
    _code: object = None          # the compiled condition

    @property
    def end(self) -> int:
        return self.address + self.size - 1

    def describe(self) -> str:
        if self.kind == EXECUTE:
            where = f'*{self.address:#x}'
        elif self.kind == REGISTER:
            where = f'${self.register}'
        else:
            where = f'{self.kind.lower()} {self.address:#x}+{self.size}'
        if self.condition:
            where += f' if {self.condition}'
        if self.ignore_count:
            where += f' (ignore {self.ignore_count})'
        return where


@dataclass(frozen=True)
class Hit:
    """One breakpoint firing, at the instruction the stop belongs to.

    A hit count means "how many times has this fired at or before where we
    are now", so going back past a hit has to undo it, and an ignore count
    the hit consumed has to come back with it.
    """
    icount: int
    num: int
    ignored: bool = False


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
        self._reg_watches: List[Breakpoint] = []
        self._temp: Set[int] = set()
        self._running = False
        self._first = False
        self._halting = False
        self._stop: Optional[StopEvent] = None
        self._pending: Optional[StopEvent] = None
        self._lock = threading.Lock()
        self.terminated = False
        self.exit_description = ''
        self.listeners: List[Callable[[StopEvent], None]] = []
        self._code_hook = uc.hook_add(UC_HOOK_CODE, self._on_code)
        self._fault: Optional[Tuple[str, int, int]] = None
        uc.hook_add(UC_HOOK_MEM_INVALID, self._on_invalid)
        self._decoders: Dict[Tuple[int, int], object] = {}
        self.timeline = Timeline(uc, interval=checkpoint_interval,
                                 budget=memory_budget, enabled=record)
        self.timeline.on_forget = self._on_history_forgotten
        self._replaying = False
        self._replay_icount = 0    # instruction index reached by a replay
        self._left = -1            # instructions left in this run; -1 is all
        self._trace: Optional[List[int]] = None
        #: Every layer that stands in for code that is not here keeps a log
        #: of what it did, so a replay can put it back rather than do it
        #: again. They are rewound and pruned with the history; see
        #: effects.py.
        self.effect_logs: List['EffectLog'] = []
        #: Every breakpoint hit so far, newest last, as far back as the
        #: history reaches. Reverse execution undoes them from the end.
        self._hits: List[Hit] = []
        #: While a search replays history, where watchpoints would have
        #: fired. None outside one, which is when they may actually stop.
        self._observed: Optional[List[Tuple[int, Breakpoint, Dict]]] = None
        self._sync_thumb_flag()
        #: Set by `syscalls.install`; None means traps are left to Unicorn.
        self.syscalls = None
        #: Set by `stubs.install`; None means no function is stood in for.
        self.stubs = None
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

    def reg_write(self, name: str, value: int, external: bool = True) -> None:
        """Write a register. `external` says whether a replay reproduces it.

        The same distinction `write` makes: an edit made through the debugger
        has to be checkpointed because re-running the instructions will not
        put it back, while a register a system call handler sets as part of
        executing the trap is replayed with the rest of that call's effects.
        Checkpointing the latter would also mean calling `context_save` from
        inside a hook on every system call, and during a replay it would
        append a checkpoint for an instruction that has already happened.
        """
        keep_thumb = (self.spec.thumb_field is not None
                      and name.lower() == self.spec.pc.lower() and self.thumb)
        rf = self._field(name)
        if rf is not None:
            cur = self.uc.reg_read(rf[0].uc)
            self.uc.reg_write(rf[0].uc, rf[1].set(cur, value))
        else:
            f = self.spec.flag(name)
            if f is not None:
                src = self.spec.reg(f.source)
                cur = self.uc.reg_read(src.uc)
                self.uc.reg_write(src.uc, f.set(cur, int(value)))
            else:
                self.uc.reg_write(self.spec.reg(name).uc, value)
        if keep_thumb and not self.thumb:
            # Writing the program counter on ARM *is* a `bx`: the low bit
            # picks the instruction set and never reaches the register, so an
            # even address silently drops out of Thumb. Someone moving the
            # program counter did not ask to change instruction set; writing
            # the T flag is how that is asked for.
            self.uc.reg_write(self.spec.reg(self.spec.pc).uc, value | 1)
        if external:
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

    def write(self, address: int, data: bytes, external: bool = True) -> None:
        """Write memory. `external` says whether a replay can reproduce it.

        A write made through the debugger happens between instructions and
        re-running the instruction stream will not put it back, so the only
        way to keep it is to checkpoint the state it made. A write made by
        something inside the emulation - a system call handler - *is*
        reproduced, because the syscall layer replays its recorded effects,
        so it only needs its pages marked dirty like any other.
        """
        self.uc.mem_write(address, data)
        if external:
            self.timeline.note_external_write(address, len(data))
        else:
            self.timeline.note_write(address, len(data))

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

    def add_register_watch(self, register: str) -> Breakpoint:
        """Stop when `register` changes value.

        There is no Unicorn hook for this, so it is a comparison made once
        per instruction from the code hook that is already there. That is
        the whole cost, and it is only paid while such a watch exists.
        """
        value = self.reg_read(register)          # KeyError for a bad name
        bp = Breakpoint(self._next_bp, REGISTER, 0, 1, register=register,
                        previous=value)
        self._next_bp += 1
        self.breakpoints[bp.num] = bp
        self._reg_watches.append(bp)
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

    def set_condition(self, num: int, expression: Optional[str]) -> Breakpoint:
        """Stop at this breakpoint only when `expression` is true.

        It is compiled here rather than at the hook, both so that a typo is
        reported when it is made and so that a breakpoint in a hot loop costs
        an eval rather than a compile each time round.
        """
        bp = self.breakpoints[num]
        expression = (expression or '').strip() or None
        if expression is not None:
            try:
                bp._code = compile(expression, f'<breakpoint {num}>', 'eval')
            except SyntaxError as e:
                raise TargetError(f'bad condition for breakpoint {num}: {e}') from e
        else:
            bp._code = None
        bp.condition = expression
        bp.condition_error = ''
        return bp

    def set_ignore_count(self, num: int, count: int) -> Breakpoint:
        """Pass this breakpoint `count` more times before stopping at it."""
        bp = self.breakpoints[num]
        bp.ignore_count = max(int(count), 0)
        return bp

    # ---- conditions ------------------------------------------------------

    def condition_scope(self, bp: Breakpoint, extra: Optional[Dict] = None) -> Dict:
        """The names a breakpoint condition can use.

        Every register by its Ghidra name and in lower case, so that both
        `RAX == 1` and `rax == 1` work; `pc`, `sp`, `icount` and `hits`;
        `reg('cpsr.M')` for the names that are not identifiers; `mem`, and
        `u8`/`u16`/`u32`/`u64` to read through a pointer. A watchpoint also
        gets `address`, `size`, `value` and `access` for the access that
        fired it.
        """
        scope: Dict[str, object] = {
            'target': self, 'uc': self.uc, 'bp': bp,
            'hits': bp.hit_count, 'icount': self.icount,
            'pc': self.pc(), 'sp': self.sp(),
            'reg': self.reg_read, 'mem': self.read,
            'u8': lambda a: self._uint(a, 1), 'u16': lambda a: self._uint(a, 2),
            'u32': lambda a: self._uint(a, 4), 'u64': lambda a: self._uint(a, 8),
        }
        for name, value in self.regs().items():
            scope[name] = value
            scope.setdefault(name.lower(), value)
        if extra:
            scope.update(extra)
        return scope

    def _uint(self, address: int, size: int) -> int:
        return int.from_bytes(self.read(address, size), self.spec.endian)

    def _passes(self, bp: Breakpoint, extra: Optional[Dict] = None) -> bool:
        if bp._code is None:
            return True
        try:
            result = bool(eval(bp._code, self.condition_scope(bp, extra)))
            bp.condition_error = ''
            return result
        except Exception as e:                # any expression, any failure
            bp.condition_error = f'{type(e).__name__}: {e}'
            return True

    def _triggers(self, bp: Breakpoint, extra: Optional[Dict] = None) -> bool:
        """Whether this hit actually stops, and the bookkeeping for it.

        gdb's order, which is what Ghidra's breakpoint model is built around:
        a condition that is false is not a hit at all and does not count,
        while an ignore count consumes a hit that did count.
        """
        if not self._passes(bp, extra):
            return False
        bp.hit_count += 1
        ignored = bp.ignore_count > 0
        if ignored:
            bp.ignore_count -= 1
        # Recorded at the instruction the *stop* belongs to, which is where
        # the machine would be left: for an execute breakpoint the one about
        # to run, and for a watchpoint the one after the access, since the
        # accessing instruction has already been counted by the time its
        # memory hook runs.
        self._hits.append(Hit(self.icount, bp.num, ignored))
        return not ignored

    def delete_breakpoint(self, num: int) -> None:
        bp = self.breakpoints.pop(num)
        if bp.kind == EXECUTE:
            if self._bp_by_addr.get(bp.address) is bp:
                del self._bp_by_addr[bp.address]
        if bp in self._reg_watches:
            self._reg_watches.remove(bp)
        for h in bp._hooks:
            self.uc.hook_del(h)

    # ---- hooks -----------------------------------------------------------

    def _on_code(self, uc, address, size, user_data) -> None:
        if self._replaying:
            # Re-running history: no breakpoints, no exits, no counting, and
            # no stop event. Only the instruction limit applies.
            self._halting = False
            if self._left == 0:
                self._halting = True
                uc.emu_stop()
                return
            self._left -= 1
            # Mirror the instruction counting the normal path does, so that
            # `executing_icount` names the same instruction either way and a
            # system call can find the effects it recorded the first time.
            self._replay_icount += 1
            if self._trace is not None:
                self._trace.append(address)
            return
        self._halting = False
        if self._pending is not None:
            # A watchpoint fired during the previous instruction. That
            # instruction has now completed, so stop here, before this one.
            self._stop = self._pending
            self._pending = None
            self._halting = True
            uc.emu_stop()
            return
        # Before the first-instruction exemption and before the instruction
        # budget, because a register watch reports a change the *previous*
        # instruction made and this hook is the only place it is ever seen.
        # `step` is a run of one instruction each time, so every instruction
        # is a first one and every stop is the budget: checking after either
        # meant a watch that never fired while stepping, and a stale value to
        # compare against when something finally did run.
        if self._reg_watches:
            changed = self._changed_register(address)
            if changed is not None:
                self._stop = changed
                self._halting = True
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
            self._halting = True
            uc.emu_stop()
            return
        if self._left == 0:
            # Unicorn's own instruction count overruns after a context_restore
            # - it will happily run a whole basic block for a count of one -
            # so the limit is enforced here, where a stop is exact.
            self._halting = True
            uc.emu_stop()
            return
        bp = self._bp_by_addr.get(address)
        if bp is not None and bp.enabled and self._triggers(bp):
            self._stop = StopEvent('breakpoint', address,
                                   f'Breakpoint {bp.num} at {address:#x}'
                                   + _condition_note(bp), bp)
            self._halting = True
            uc.emu_stop()
            return
        # Nothing stopped us, so this instruction is about to run: the state we
        # are in now is the state at `timeline.icount`.
        self.timeline.note_instruction()
        self._left -= 1

    def _on_history_forgotten(self, earliest: int) -> None:
        """The history no longer reaches back as far as it did."""
        for log in self.effect_logs:
            log.forget_before(earliest)
        # A hit that can no longer be reached can no longer be undone, so
        # only the record goes; the count it contributed stays, because the
        # count is cumulative and that hit really did happen.
        while self._hits and self._hits[0].icount < earliest:
            self._hits.pop(0)

    def _undo_hits(self, k: int) -> None:
        """Un-fire every hit that happens after instruction `k`.

        A hit recorded *at* k survives: being stopped at a breakpoint is the
        state in which it has fired.
        """
        while self._hits and self._hits[-1].icount > k:
            hit = self._hits.pop()
            bp = self.breakpoints.get(hit.num)
            if bp is None:
                continue
            bp.hit_count = max(bp.hit_count - 1, 0)
            if hit.ignored:
                bp.ignore_count += 1

    def hits_at(self, icount: int, num: int) -> bool:
        """Whether breakpoint `num` is already recorded as firing at `icount`."""
        return any(h.icount == icount and h.num == num for h in self._hits)

    def _changed_register(self, address: int) -> Optional[StopEvent]:
        """The first register watch whose register moved since last time.

        The check runs before each instruction, so a change is noticed once
        the instruction that made it has finished - which is where a memory
        watchpoint stops too, and means resuming never re-runs it.
        """
        for bp in self._reg_watches:
            if not bp.enabled:
                continue
            try:
                value = self.reg_read(bp.register)
            except (KeyError, UcError):
                continue
            if bp.previous is None:
                bp.previous = value
                continue
            if value == bp.previous:
                continue
            old, bp.previous = bp.previous, value
            # `previous` moves whether or not this one stops, so a rejected
            # change is not reported again at the next instruction.
            if not self._triggers(bp, {'old': old, 'new': value, 'value': value,
                                       'register': bp.register}):
                continue
            return StopEvent(
                'watchpoint', address,
                f'Watchpoint {bp.num}: {bp.register} {old:#x} -> {value:#x}'
                + _condition_note(bp), bp)
        return None

    def _resync_register_watches(self) -> None:
        """After a rewind, what a register held before is whatever it holds
        now; otherwise the next instruction reports a change that the machine
        did not make."""
        for bp in self._reg_watches:
            try:
                bp.previous = self.reg_read(bp.register)
            except (KeyError, UcError):
                bp.previous = None

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
            # A replay is silent, but a backward search needs to know where a
            # watchpoint *would* have fired, and this hook is the only thing
            # that sees it. Note it and carry on; nothing stops.
            if self._observed is not None and bp.enabled:
                what = 'write' if access == UC_MEM_WRITE else 'read'
                self._observed.append((self.executing_icount, bp,
                                       {'address': address, 'size': size,
                                        'value': value, 'access': what}))
            return True
        if not bp.enabled or self._stop is not None or self._pending is not None:
            return True
        what = 'write' if access == UC_MEM_WRITE else 'read'
        if not self._triggers(bp, {'address': address, 'size': size,
                                   'value': value, 'access': what}):
            return True
        # Do not stop here: Unicorn would leave PC on the accessing instruction
        # with its side effects already applied, and a resume would run it
        # again. Let the instruction finish and stop at the next code hook.
        self._pending = StopEvent(
            'watchpoint', 0, f'Watchpoint {bp.num}: {what} {size} bytes at '
                             f'{address:#x}' + _condition_note(bp), bp)
        return True

    # ---- execution -------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._running

    @property
    def halting(self) -> bool:
        """True when the code hook has decided this instruction will not run.

        Hooks fire in the order they were added and the target's own code
        hook is always first, so by the time anything else hooked to the same
        address runs, this says whether that address is about to execute or
        is being stopped at. A function stub has to ask: a breakpoint on a
        stubbed function should stop *before* the stub stands in for it,
        not after it has already returned.
        """
        return self._halting

    @property
    def replaying(self) -> bool:
        """True while history is being re-run, when nothing may be reported."""
        return self._replaying

    @property
    def executing_icount(self) -> int:
        """Index of the instruction executing now; only valid inside a hook.

        The code hook counts an instruction *before* it runs, so during the
        instruction the count is one past it. A replay keeps its own count
        because the timeline's does not move while history is re-run.
        """
        counted = self._replay_icount if self._replaying else self.timeline.icount
        return counted - 1

    def request_stop(self, reason: str, description: str) -> None:
        """End the current run with a given verdict, from inside a hook.

        This is how something that is not a breakpoint - an `exit` system
        call, say - reports why the program stopped. A replay is silent, so
        it is ignored there.
        """
        if self._replaying:
            return
        self._stop = StopEvent(reason, self.pc(), description)
        self.uc.emu_stop()

    def _start_pc(self) -> int:
        pc = self.pc()
        if self.thumb:
            # emu_start decides how to decode from this bit and *not* from
            # the T flag, so resuming a Thumb program counter without it
            # reads the instruction as ARM: the wrong width, and usually the
            # wrong instruction.
            pc |= 1
        return pc

    # ---- instruction set -------------------------------------------------

    @property
    def thumb(self) -> bool:
        """Whether the processor is in Thumb state now.

        Not a property of the language the target was launched with: ARM
        code changes instruction set as it runs, with `blx` and with `bx` to
        an odd address, and the T flag in the status register is where that
        shows.
        """
        field = self.spec.thumb_field
        if field is None or self.spec.status is None:
            return False
        try:
            return bool(self.reg_read(f'{self.spec.status}.{field}'))
        except (KeyError, UcError):
            return False

    def _sync_thumb_flag(self) -> None:
        """Make the T flag agree with the language the target was launched as.

        Creating the engine with UC_MODE_THUMB does not set it - both modes
        start with the flag clear - so a Thumb target would otherwise begin
        life claiming to be in ARM state, and everything derived from the
        flag would be wrong until the first `bx`.
        """
        if not self.spec.context.get('TMode') or self.spec.status is None:
            return
        try:
            if not self.thumb:
                self.reg_write(f'{self.spec.status}.{self.spec.thumb_field}', 1,
                               external=False)
        except (KeyError, UcError):
            pass

    def context(self) -> Dict[str, int]:
        """Ghidra's context registers for the state the machine is in now.

        TMode is not settled by the language: a stop in Thumb code has to say
        so, or Ghidra disassembles four-byte ARM instructions over two-byte
        Thumb ones and the Dynamic Listing is nonsense from there on.
        """
        ctx = dict(self.spec.context)
        if self.spec.thumb_field is not None:
            ctx['TMode'] = 1 if self.thumb else 0
        return ctx

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
        # A replay starting here is at the checkpoint's instruction.
        self._replay_icount = cp.icount
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
        # We are at k and the only way forward is to execute again, so
        # anything recorded past here describes a future that no longer
        # exists. Dropping it now keeps a re-run from replaying it, and puts
        # back the state those layers had before it.
        for log in self.effect_logs:
            log.truncate(k)
        self._undo_hits(k)
        self._resync_register_watches()

    def _history_pcs(self, lo: int, hi: int) -> Dict[int, int]:
        """The PC at each instruction in [lo, hi], by replaying from the
        checkpoint at or before `lo`. Leaves the machine at the end of the
        replay, so a caller must always finish with `_go`."""
        cp = self._restore_state(lo)
        trace: List[int] = []
        self._replay_forward(hi - cp.icount + 1, trace)
        return {cp.icount + i: pc for i, pc in enumerate(trace)}

    def _depth_delta(self, pc: int, cache: Dict[int, int]) -> int:
        """How the call depth changes going one instruction *further back*.

        Moving from instruction j+1 back to j: if j is a call then j+1 was
        one frame deeper, so going back to j is one frame shallower (-1);
        if j returns then j+1 was one frame shallower, so going back is one
        deeper (+1); anything else leaves it alone.

        Without Capstone nothing is recognised and everything comes back
        zero, which turns a reverse step-over into a plain reverse step -
        the same thing that happens to the forward step-over.
        """
        if pc in cache:
            return cache[pc]
        delta = 0
        insn = self.decode(pc)
        if insn is not None:
            _, mnemonic, operands = insn
            if self.spec.is_call(mnemonic, operands):
                delta = -1
            elif self.spec.is_return(mnemonic, operands):
                delta = +1
        cache[pc] = delta
        return delta

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

        Depth is kept *relative to where we are now*, which is what makes
        this local: a call met on the way back makes the relative depth one
        shallower and a return makes it one deeper, and nothing else moves
        it, so no absolute depth and no stack of return addresses is needed.
        The search therefore walks back only as far as it actually travels,
        one checkpoint window at a time.

        It used to replay the whole retained history first, to establish an
        absolute depth it could trust, which cost time proportional to how
        much history was being kept rather than to the distance travelled.
        """
        cur = self.icount
        earliest = self.timeline.earliest
        kinds: Dict[int, int] = {}       # pc -> delta, so a loop decodes once
        rel = 0
        hi = cur - 1
        while hi >= earliest:
            cp = self.timeline.checkpoint_at_or_before(hi)
            pcs = self._history_pcs(cp.icount, hi)
            for j in range(hi, cp.icount - 1, -1):
                rel += self._depth_delta(pcs[j], kinds)
                if rel <= 0:
                    return j
            hi = cp.icount - 1
        return earliest

    def resume_back(self) -> StopEvent:
        """Run backwards to the most recent hit before now.

        "Hit" means the same thing it means going forwards: an enabled
        execute breakpoint whose condition holds, or a watchpoint whose
        access the history actually made. Watchpoints need the history
        replayed with the memory hooks watched rather than merely muted,
        because the access is the only evidence they ever happened - which
        is why this used to find execute breakpoints and nothing else.

        The machine is left exactly where a forward run would have stopped:
        *on* an execute breakpoint's instruction, and *after* the
        instruction a watchpoint's access belongs to.
        """
        cur = self.icount
        self._require_reversible(cur - 1)
        live = [b for b in self.breakpoints.values() if b.enabled]
        by_address = {b.address: b for b in live if b.kind == EXECUTE}
        watched = [b for b in live if b.kind != EXECUTE]
        earliest = self.timeline.earliest
        found: Optional[Tuple[int, Breakpoint, Optional[Dict]]] = None
        with self._reversing():
            hi = cur - 1
            while (by_address or watched) and found is None and hi >= earliest:
                cp = self.timeline.checkpoint_at_or_before(hi)
                candidates = self._scan_back(cp.icount, hi, by_address, watched)
                found = self._first_that_holds(candidates, cur)
                hi = cp.icount - 1
            if found is None:
                self._go(earliest)
            else:
                self._go(found[0])
                self._recount(found)
        pc = self.pc()
        if found is None:
            return self._notify(StopEvent(
                'stopped', pc, f'No earlier breakpoint; at the start of the '
                               f'history, instruction {earliest} ({pc:#x})'))
        at, bp, extra = found
        kind = 'Watchpoint' if bp.kind != EXECUTE else 'Breakpoint'
        detail = ''
        if extra is not None:
            detail = (f': {extra["access"]} {extra["size"]} bytes at '
                      f'{extra["address"]:#x}')
        return self._notify(StopEvent(
            'watchpoint' if bp.kind != EXECUTE else 'breakpoint', pc,
            f'{kind} {bp.num} at {pc:#x}{detail} (backwards, instruction {at})',
            bp))

    def _scan_back(self, lo: int, hi: int, by_address: Dict[int, Breakpoint],
                   watched: List[Breakpoint]
                   ) -> List[Tuple[int, Breakpoint, Optional[Dict]]]:
        """Every place in [lo, hi] where a breakpoint would have fired.

        One replay of the window finds both kinds at once: the program
        counter trace gives the execute breakpoints, and the watched memory
        hooks give the accesses. Ordered oldest first.
        """
        cp = self._restore_state(lo)
        trace: List[int] = []
        observed: List[Tuple[int, Breakpoint, Dict]] = []
        self._observed = observed if watched else None
        try:
            self._replay_forward(hi - cp.icount + 1, trace)
        finally:
            self._observed = None
        out: List[Tuple[int, Breakpoint, Optional[Dict]]] = []
        for i, pc in enumerate(trace):
            at = cp.icount + i
            if at > hi:
                break
            bp = by_address.get(pc)
            if bp is not None:
                out.append((at, bp, None))
        for at, bp, extra in observed:
            # Forwards, a watchpoint stops *after* the accessing instruction
            # completes, so that is where going back to it must land too.
            out.append((at + 1, bp, extra))
        out.sort(key=lambda c: c[0])
        return out

    def _first_that_holds(self, candidates, cur: int):
        """The newest candidate before `cur` whose condition is satisfied.

        A condition has to be tested in the state it would have seen, so the
        machine is moved to the candidate before evaluating. Most breakpoints
        have no condition and cost nothing here.
        """
        for at, bp, extra in reversed(candidates):
            if at >= cur or at < self.timeline.earliest:
                continue
            if bp.condition is None:
                return (at, bp, extra)
            self._go(at)
            if self._passes(bp, extra):
                return (at, bp, extra)
        return None

    def _recount(self, found: Tuple[int, Breakpoint, Optional[Dict]]) -> None:
        """Make the hit count agree with having arrived here backwards.

        `_go` has already undone every hit after this point. If the history
        records this one - the forward run really did fire it - there is
        nothing to do. If it does not, the breakpoint was set after this
        point was first passed, and arriving at it now is its first hit.
        """
        at, bp, _ = found
        if not self.hits_at(at, bp.num):
            bp.hit_count += 1
            self._hits.append(Hit(at, bp.num))
            self._hits.sort(key=lambda h: h.icount)

    # ---- decoding --------------------------------------------------------

    def decode(self, address: int) -> Optional[Tuple[int, str, str]]:
        """(size, mnemonic, operands) of the instruction at address, via
        Capstone when available; None otherwise."""
        decoder = self._decoder()
        if decoder is None:
            return None
        try:
            code = self.read(address, 16)
        except UcError:
            try:
                code = self.read(address, 4)
            except UcError:
                return None
        for _, size, mnem, ops in decoder.disasm_lite(code, address, 1):
            return size, mnem, ops
        return None

    def _decoder(self):
        """The Capstone for the instruction set the processor is in now."""
        spec = self.spec
        mode = spec.cs
        if spec.thumb_field is not None:
            alt = spec.cs_thumb if self.thumb else spec.cs_arm
            if alt is not None:
                mode = alt
        if mode is None:
            return None
        decoder = self._decoders.get(mode)
        if decoder is None:
            import capstone
            decoder = capstone.Cs(*mode)
            self._decoders[mode] = decoder
        return decoder
