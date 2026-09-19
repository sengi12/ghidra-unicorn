"""Remote methods Ghidra's Debugger can invoke on this connector.

The `action` names are what the Debugger's toolbar buttons look for:
resume, interrupt, kill, step_into, step_over, step_ext, break_*, toggle,
delete, refresh, activate, read_mem, write_mem, write_reg.

Ghidra invokes these on a single worker thread. `resume` therefore does not
block: it starts the emulator on its own thread and returns, so `interrupt`
can still be delivered while the target runs.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from io import StringIO
import re
import threading
from typing import Annotated, Any, Dict, Optional

from ghidratrace.client import (Address, AddressRange, MethodRegistry,
                                ParamDesc, TraceObject)

from . import commands, hooks
from .target import ACCESS, READ, WRITE, TargetError

REGISTRY = MethodRegistry(ThreadPoolExecutor(
    max_workers=1, thread_name_prefix='MethodRegistry'))


def extre(base: re.Pattern, ext: str) -> re.Pattern:
    return re.compile(base.pattern + ext)


PROCESSES_PATTERN = re.compile('Processes')
PROCESS_PATTERN = extre(PROCESSES_PATTERN, r'\[(?P<procnum>\d*)\]')
ENV_PATTERN = extre(PROCESS_PATTERN, r'\.Environment')
THREADS_PATTERN = extre(PROCESS_PATTERN, r'\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, r'\[(?P<tnum>\d*)\]')
STACK_PATTERN = extre(THREAD_PATTERN, r'\.Stack')
FRAME_PATTERN = extre(STACK_PATTERN, r'\[(?P<level>\d*)\]')
REGS_PATTERN = extre(FRAME_PATTERN, r'\.Registers')
MEMORY_PATTERN = extre(PROCESS_PATTERN, r'\.Memory')
MODULES_PATTERN = extre(PROCESS_PATTERN, r'\.Modules')
BREAKS_PATTERN = re.compile('Breakpoints')
BREAK_PATTERN = extre(BREAKS_PATTERN, r'\[(?P<breaknum>\d*)\]')
BREAK_LOC_PATTERN = extre(BREAK_PATTERN, r'\[(?P<locnum>\d*)\]')


class BreakpointContainer(TraceObject):
    pass


class BreakpointSpec(TraceObject):
    pass


class BreakpointLocation(TraceObject):
    pass


class Environment(TraceObject):
    pass


class Memory(TraceObject):
    pass


class ModuleContainer(TraceObject):
    pass


class Process(TraceObject):
    pass


class ProcessContainer(TraceObject):
    pass


class RegisterValueContainer(TraceObject):
    pass


class Stack(TraceObject):
    pass


class StackFrame(TraceObject):
    pass


class Thread(TraceObject):
    pass


class ThreadContainer(TraceObject):
    pass


def _match(pattern: re.Pattern, obj: TraceObject, what: str) -> re.Match:
    mat = pattern.fullmatch(obj.str_path())
    if mat is None:
        raise TypeError(f'{obj.str_path()} is not {what}')
    return mat


def find_bp_by_obj(obj: TraceObject):
    mat = _match(BREAK_PATTERN, obj, 'a BreakpointSpec')
    num = int(mat['breaknum'])
    target = commands.STATE.target
    if num not in target.breakpoints:
        raise KeyError(f'No breakpoint {num}')
    return target.breakpoints[num]


def find_bp_by_loc_obj(obj: TraceObject):
    mat = _match(BREAK_LOC_PATTERN, obj, 'a BreakpointLocation')
    num = int(mat['breaknum'])
    target = commands.STATE.target
    if num not in target.breakpoints:
        raise KeyError(f'No breakpoint {num}')
    return target.breakpoints[num]


shared_globals: Dict[str, Any] = dict()


def _require_stopped():
    target = commands.STATE.target
    if target.running:
        raise TargetError('Target is running; interrupt it first')
    if target.terminated:
        raise TargetError('Target has terminated')
    return target


def _require_reversible(back: int = 1):
    """A target that can go `back` instructions into its past.

    A terminated target is fine here: going back is how you leave that state.
    """
    target = commands.STATE.target
    if target.running:
        raise TargetError('Target is running; interrupt it first')
    if not target.can_reverse:
        raise TargetError(
            f'No history to go back to: the target is at instruction '
            f'{target.icount}, the earliest recorded is '
            f'{target.earliest_icount}')
    want = target.icount - back
    if want < target.earliest_icount:
        raise TargetError(
            f'Cannot step back {back}: that is instruction {want} and the '
            f'history only reaches back to {target.earliest_icount}')
    return target


# ---------------------------------------------------------------------------
# Generic

@REGISTRY.method()
def execute(cmd: str, to_string: bool = False) -> Optional[str]:
    """Execute Python in the connector. `target` and `uc` are in scope."""
    shared_globals.setdefault('target', commands.STATE.target)
    shared_globals.setdefault('uc', commands.STATE.target.uc)
    shared_globals.setdefault('commands', commands)
    if to_string:
        data = StringIO()
        with redirect_stdout(data):
            exec(cmd, shared_globals)
        return data.getvalue()
    exec(cmd, shared_globals)
    return None


# ---------------------------------------------------------------------------
# Refresh

@REGISTRY.method(action='refresh', display='Refresh Processes')
def refresh_processes(node: ProcessContainer) -> None:
    """Refresh the process list."""
    with commands.batched_tx('Refresh Processes'):
        commands.put_processes()


@REGISTRY.method(action='refresh', display='Refresh Environment')
def refresh_environment(node: Environment) -> None:
    """Refresh the environment descriptors."""
    with commands.batched_tx('Refresh Environment'):
        commands.put_environment()


@REGISTRY.method(action='refresh', display='Refresh Threads')
def refresh_threads(node: ThreadContainer) -> None:
    """Refresh the thread list."""
    with commands.batched_tx('Refresh Threads'):
        commands.put_threads()


@REGISTRY.method(action='refresh', display='Refresh Stack')
def refresh_stack(node: Stack) -> None:
    """Refresh the frame."""
    with commands.batched_tx('Refresh Stack'):
        commands.put_frames()


@REGISTRY.method(action='refresh', display='Refresh Registers')
def refresh_registers(node: RegisterValueContainer) -> None:
    """Refresh the register values."""
    with commands.batched_tx('Refresh Registers'):
        commands.putreg()


@REGISTRY.method(action='refresh', display='Refresh Memory')
def refresh_mappings(node: Memory) -> None:
    """Refresh the memory map."""
    with commands.batched_tx('Refresh Memory'):
        commands.put_regions()


@REGISTRY.method(action='refresh', display='Refresh Modules')
def refresh_modules(node: ModuleContainer) -> None:
    """Refresh the module list."""
    with commands.batched_tx('Refresh Modules'):
        commands.put_modules()


@REGISTRY.method(action='refresh', display='Refresh Breakpoints')
def refresh_breakpoints(node: BreakpointContainer) -> None:
    """Refresh the breakpoint list."""
    with commands.batched_tx('Refresh Breakpoints'):
        commands.put_breakpoints()


# ---------------------------------------------------------------------------
# Activation (single process/thread/frame: nothing to switch)

@REGISTRY.method(action='activate')
def activate_process(process: Process) -> None:
    """Switch to the process."""
    _match(PROCESS_PATTERN, process, 'a Process')


@REGISTRY.method(action='activate')
def activate_thread(thread: Thread) -> None:
    """Switch to the thread."""
    _match(THREAD_PATTERN, thread, 'a Thread')


@REGISTRY.method(action='activate')
def activate_frame(frame: StackFrame) -> None:
    """Select the frame."""
    _match(FRAME_PATTERN, frame, 'a StackFrame')


# ---------------------------------------------------------------------------
# Execution control

@REGISTRY.method()
def resume(process: Process) -> None:
    """Run the emulator until a breakpoint, watchpoint, exit, or fault."""
    _match(PROCESS_PATTERN, process, 'a Process')
    target = _require_stopped()
    hooks.on_cont()

    def run() -> None:
        try:
            target.run()
        except Exception as e:
            print(f'Emulation thread error: {e!r}')

    t = threading.Thread(target=run, name='unicorn-run', daemon=True)
    commands.STATE.run_thread = t
    t.start()


@REGISTRY.method()
def interrupt(process: Process) -> None:
    """Stop the running emulator."""
    _match(PROCESS_PATTERN, process, 'a Process')
    target = commands.STATE.target
    if not target.running:
        return
    target.interrupt()
    t = commands.STATE.run_thread
    if t is not None:
        t.join(5)


@REGISTRY.method()
def kill(process: Process) -> None:
    """Terminate the target (the emulator instance is kept for inspection)."""
    _match(PROCESS_PATTERN, process, 'a Process')
    target = commands.STATE.target
    if target.running:
        target.interrupt()
        t = commands.STATE.run_thread
        if t is not None:
            t.join(5)
    if not target.terminated:
        target.terminated = True
        from .target import StopEvent
        hooks.on_stop(StopEvent('exit', target.pc(), 'Killed'))


@REGISTRY.method()
def step_into(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Execute one instruction."""
    _match(THREAD_PATTERN, thread, 'a Thread')
    _require_stopped().step(n)


@REGISTRY.method()
def step_over(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Execute one instruction, running through calls (needs Capstone)."""
    _match(THREAD_PATTERN, thread, 'a Thread')
    _require_stopped().step_over(n)


@REGISTRY.method(action='step_ext', display='Advance')
def step_advance(thread: Thread, address: Address) -> None:
    """Run until the given address."""
    _match(THREAD_PATTERN, thread, 'a Thread')
    target = _require_stopped()
    offset = thread.trace.extra.map_back(address)
    target.advance(offset)


# ---------------------------------------------------------------------------
# Reverse execution
#
# The action, icon and signature of each of these are the ones Ghidra's gdb
# connector uses, so the Debugger's existing reverse toolbar buttons drive them.

@REGISTRY.method(action='step_ext', icon='icon.debugger.resume.back')
def resume_back(process: Process) -> None:
    """Run the emulator backwards to the previous breakpoint hit."""
    _match(PROCESS_PATTERN, process, 'a Process')
    _require_reversible().resume_back()


@REGISTRY.method(action='step_ext', icon='icon.debugger.step.back.into')
def step_back_into(thread: Thread,
                   n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Undo one instruction."""
    _match(THREAD_PATTERN, thread, 'a Thread')
    n = max(n, 1)
    _require_reversible(n).step_back(n)


@REGISTRY.method(action='step_ext', icon='icon.debugger.step.back.over')
def step_back_over(thread: Thread,
                   n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Undo one instruction, stepping back over whole calls (needs Capstone)."""
    _match(THREAD_PATTERN, thread, 'a Thread')
    n = max(n, 1)
    _require_reversible(n).step_back_over(n)


@REGISTRY.method(action='step_ext', display='Go To Instruction')
def step_goto_icount(thread: Thread,
                     icount: Annotated[int, ParamDesc(display='Instruction')] = 0) -> None:
    """Restore the state the target had at an instruction count."""
    _match(THREAD_PATTERN, thread, 'a Thread')
    target = commands.STATE.target
    _require_reversible(target.icount - icount).goto_icount(icount)


# ---------------------------------------------------------------------------
# Breakpoints

def _after_bp_change() -> None:
    with commands.batched_tx('Breakpoints changed'):
        commands.put_breakpoints()


@REGISTRY.method(action='break_sw_execute')
def break_sw_execute_address(process: Process, address: Address) -> None:
    """Set a breakpoint."""
    _match(PROCESS_PATTERN, process, 'a Process')
    commands.STATE.target.add_breakpoint(process.trace.extra.map_back(address))
    _after_bp_change()


@REGISTRY.method(action='break_hw_execute')
def break_hw_execute_address(process: Process, address: Address) -> None:
    """Set a breakpoint (Unicorn has no distinct hardware breakpoints)."""
    _match(PROCESS_PATTERN, process, 'a Process')
    commands.STATE.target.add_breakpoint(process.trace.extra.map_back(address))
    _after_bp_change()


@REGISTRY.method(action='break_ext', display='Set Breakpoint')
def break_sw_execute_expression(
        expression: Annotated[str, ParamDesc(display='Address')]) -> None:
    """Set a breakpoint at a numeric address (e.g. 0x1000)."""
    commands.STATE.target.add_breakpoint(int(expression, 0))
    _after_bp_change()


def _watch(process: Process, range: AddressRange, kind: str) -> None:
    _match(PROCESS_PATTERN, process, 'a Process')
    start = process.trace.extra.map_back(Address(range.space, range.min))
    commands.STATE.target.add_watchpoint(start, range.length(), kind)
    _after_bp_change()


@REGISTRY.method(action='break_read')
def break_read_range(process: Process, range: AddressRange) -> None:
    """Set a read watchpoint."""
    _watch(process, range, READ)


@REGISTRY.method(action='break_write')
def break_write_range(process: Process, range: AddressRange) -> None:
    """Set a write watchpoint."""
    _watch(process, range, WRITE)


@REGISTRY.method(action='break_access')
def break_access_range(process: Process, range: AddressRange) -> None:
    """Set an access watchpoint."""
    _watch(process, range, ACCESS)


@REGISTRY.method(action='toggle', display='Toggle Breakpoint')
def toggle_breakpoint(breakpoint: BreakpointSpec, enabled: bool) -> None:
    """Enable or disable a breakpoint."""
    bp = find_bp_by_obj(breakpoint)
    commands.STATE.target.enable_breakpoint(bp.num, enabled)
    _after_bp_change()


@REGISTRY.method(action='toggle', display='Toggle Breakpoint Location')
def toggle_breakpoint_location(location: BreakpointLocation, enabled: bool) -> None:
    """Enable or disable a breakpoint (locations and specs are one here)."""
    bp = find_bp_by_loc_obj(location)
    commands.STATE.target.enable_breakpoint(bp.num, enabled)
    _after_bp_change()


@REGISTRY.method(display='Set Condition')
def set_breakpoint_condition(
        breakpoint: BreakpointSpec,
        condition: Annotated[str, ParamDesc(display='Condition')]) -> None:
    """Stop here only when a Python expression is true.

    Registers are in scope by name, in either case, along with pc, sp,
    icount, hits, and u8/u16/u32/u64 to read through a pointer: for
    instance `rdi == 0` or `u32(rsp + 8) > 0x1000`. Empty clears it.
    """
    bp = find_bp_by_obj(breakpoint)
    commands.STATE.target.set_condition(bp.num, condition)
    _after_bp_change()


@REGISTRY.method(display='Set Ignore Count')
def set_breakpoint_ignore_count(
        breakpoint: BreakpointSpec,
        count: Annotated[int, ParamDesc(display='Count')]) -> None:
    """Pass this breakpoint `count` more times before stopping at it."""
    bp = find_bp_by_obj(breakpoint)
    commands.STATE.target.set_ignore_count(bp.num, count)
    _after_bp_change()


@REGISTRY.method(action='delete', display='Delete Breakpoint')
def delete_breakpoint(breakpoint: BreakpointSpec) -> None:
    """Delete a breakpoint."""
    bp = find_bp_by_obj(breakpoint)
    commands.STATE.target.delete_breakpoint(bp.num)
    _after_bp_change()


# ---------------------------------------------------------------------------
# Memory and registers

@REGISTRY.method()
def read_mem(process: Process, range: AddressRange) -> None:
    """Read memory."""
    _match(PROCESS_PATTERN, process, 'a Process')
    start = process.trace.extra.map_back(Address(range.space, range.min))
    with commands.batched_tx('Read Memory'):
        commands.putmem(start, range.length(), pages=True)


@REGISTRY.method()
def write_mem(process: Process, address: Address, data: bytes) -> None:
    """Write memory."""
    _match(PROCESS_PATTERN, process, 'a Process')
    target = commands.STATE.target
    offset = process.trace.extra.map_back(address)
    target.write(offset, bytes(data))
    with commands.batched_tx('Write Memory'):
        commands.putmem(offset, len(data), pages=False)


@REGISTRY.method()
def write_reg(frame: StackFrame, name: str, value: bytes) -> None:
    """Write a register (value is big-endian bytes, as Ghidra sends it)."""
    _match(FRAME_PATTERN, frame, 'a StackFrame')
    target = commands.STATE.target
    target.reg_write(name, int.from_bytes(bytes(value), 'big'))
    with commands.batched_tx('Write Register'):
        commands.putreg()
        commands.put_frames()
