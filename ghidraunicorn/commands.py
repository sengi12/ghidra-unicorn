"""Trace plumbing: everything that writes the target's state into Ghidra.

The object tree mirrors the gdb and drgn connectors so Ghidra's Debugger
windows recognise it (see schema.xml). There is exactly one process (0) and
one thread (0) with one frame (0): Unicorn has no notion of threads or call
stacks, and Ghidra unwinds the stack on its own from the registers and memory
we publish.
"""
from contextlib import contextmanager
import os
import socket
import threading
from typing import Dict, Generator, List, Optional, Tuple

from ghidratrace.client import (Address, Client, RegVal, Trace, TraceObject,
                                Transaction)

from .loaders import Loaded, Module
from .target import EXECUTE, REGISTER, Breakpoint, StopEvent, UnicornTarget

PAGE_SIZE = 4096
# Trace RMI refuses messages over 64 KiB; keep byte payloads well under it.
PUT_CHUNK = 32 * 1024

PROCESSES_PATH = 'Processes'
PROCESS_KEY_PATTERN = '[{procnum}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
ENV_PATTERN = PROCESS_PATTERN + '.Environment'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
STACK_PATTERN = THREAD_PATTERN + '.Stack'
FRAME_KEY_PATTERN = '[{level}]'
FRAME_PATTERN = STACK_PATTERN + FRAME_KEY_PATTERN
REGS_PATTERN = FRAME_PATTERN + '.Registers'
MEMORY_PATTERN = PROCESS_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
BREAKS_PATH = 'Breakpoints'
BREAK_KEY_PATTERN = '[{breaknum}]'
BREAK_PATTERN = BREAKS_PATH + BREAK_KEY_PATTERN
BREAK_LOC_KEY_PATTERN = '[{locnum}]'
BREAK_LOC_PATTERN = BREAK_PATTERN + BREAK_LOC_KEY_PATTERN
PROC_BREAKS_PATTERN = PROCESS_PATTERN + '.Breakpoints'
PROC_BREAK_KEY_PATTERN = '[{breaknum}.{locnum}]'

PROC = 0
THREAD = 0
FRAME = 0

DEFAULT_SPACE = 'ram'


class Extra(object):
    """Attached to the trace; nothing to map for a flat address space."""

    def map(self, offset: int) -> Address:
        return Address(DEFAULT_SPACE, offset)

    def map_back(self, address: Address) -> int:
        if address.space != DEFAULT_SPACE:
            raise ValueError(f'Address {address} is not in {DEFAULT_SPACE}')
        return address.offset


class State(object):

    def __init__(self) -> None:
        self.client: Optional[Client] = None
        self.trace: Optional[Trace] = None
        self.tx: Optional[Transaction] = None
        self.loaded: Optional[Loaded] = None
        self.image: Optional[str] = None
        self.run_thread: Optional[threading.Thread] = None
        self.disconnected = threading.Event()

    @property
    def target(self) -> UnicornTarget:
        if self.loaded is None:
            raise RuntimeError('No target loaded')
        return self.loaded.target

    def require_client(self) -> Client:
        if self.client is None:
            raise RuntimeError('Not connected')
        return self.client

    def require_trace(self) -> Trace:
        if self.trace is None:
            raise RuntimeError('No trace active')
        return self.trace

    def require_tx(self) -> Tuple[Trace, Transaction]:
        trace = self.require_trace()
        if self.tx is None:
            raise RuntimeError('No transaction')
        return trace, self.tx


STATE = State()


# ---------------------------------------------------------------------------
# Connection and trace lifecycle

def connect(address: str) -> Client:
    from . import methods  # late import: methods imports this module
    if STATE.client is not None:
        raise RuntimeError('Already connected')
    host, port = address.rsplit(':', 1)
    s = socket.socket()
    s.connect((host, int(port)))
    STATE.client = Client(s, 'unicorn', methods.REGISTRY)
    print(f'Connected to {STATE.client.description} at {address}', flush=True)
    return STATE.client


def listen(address: str = '127.0.0.1:0') -> Client:
    """Wait for Ghidra to connect to us (its "Connect Outbound" action).

    The opposite of connect(): useful when the connector runs in your own
    terminal rather than one Ghidra spawned.
    """
    from . import methods
    if STATE.client is not None:
        raise RuntimeError('Already connected')
    if ':' in address:
        host, port = address.rsplit(':', 1)
    else:
        host, port = '127.0.0.1', address
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, int(port)))
    host, port = s.getsockname()
    s.listen(1)
    print(f'Listening for Ghidra at {host}:{port}', flush=True)
    print(f'In Ghidra: Window -> Connections -> Connect Outbound -> {host}:{port}',
          flush=True)
    conn, peer = s.accept()
    s.close()
    STATE.client = Client(conn, 'unicorn', methods.REGISTRY)
    print(f'Connected to {STATE.client.description} from {peer[0]}:{peer[1]}', flush=True)
    return STATE.client


def disconnect() -> None:
    if STATE.client is not None:
        STATE.client.close()
    STATE.client = None
    STATE.trace = None
    STATE.tx = None


def start_trace(name: Optional[str] = None) -> Trace:
    target = STATE.target
    if name is None:
        name = f'unicorn/{target.name}'
    trace = STATE.require_client().create_trace(
        name, target.spec.language, target.spec.compiler, extra=Extra())
    STATE.trace = trace
    schema_fn = os.path.join(os.path.dirname(__file__), 'schema.xml')
    with open(schema_fn) as f:
        schema_xml = f.read()
    with trace.open_tx('Create Root Object'):
        root = trace.create_root_object(schema_xml, 'UnicornRoot')
        root.set_value('_display', f'unicorn {_unicorn_version()}: {target.name}')
    return trace


def _unicorn_version() -> str:
    try:
        import unicorn
        return unicorn.__version__
    except Exception:
        return '?'


@contextmanager
def open_tracked_tx(description: str) -> Generator[Transaction, None, None]:
    with STATE.require_trace().open_tx(description) as tx:
        STATE.tx = tx
        yield tx
    STATE.tx = None


@contextmanager
def batched_tx(description: str) -> Generator[None, None, None]:
    trace = STATE.require_trace()
    with trace.client.batch():
        with open_tracked_tx(description):
            yield


def snapshot(description: str) -> int:
    return STATE.require_trace().snapshot(description)


# ---------------------------------------------------------------------------
# Object publishing

def _proc_path() -> str:
    return PROCESS_PATTERN.format(procnum=PROC)


def _thread_path() -> str:
    return THREAD_PATTERN.format(procnum=PROC, tnum=THREAD)


def _frame_path() -> str:
    return FRAME_PATTERN.format(procnum=PROC, tnum=THREAD, level=FRAME)


def _regs_path() -> str:
    return REGS_PATTERN.format(procnum=PROC, tnum=THREAD, level=FRAME)


def put_processes(state: str = 'STOPPED', reason: str = '') -> None:
    trace = STATE.require_trace()
    target = STATE.target
    procobj = trace.create_object(_proc_path())
    procobj.set_value('PID', PROC)
    procobj.set_value('State', state)
    procobj.set_value('Reason', reason)
    procobj.set_value('_display', f'[{PROC}] {target.name}')
    procobj.set_value('_short_display', f'[{PROC}]')
    procobj.insert()
    trace.proxy_object_path(PROCESSES_PATH).retain_values(
        [PROCESS_KEY_PATTERN.format(procnum=PROC)])
    for path in (ENV_PATTERN, THREADS_PATTERN, MEMORY_PATTERN, MODULES_PATTERN,
                 PROC_BREAKS_PATTERN):
        trace.create_object(path.format(procnum=PROC)).insert()
    trace.create_object(BREAKS_PATH).insert()


def put_state(state: str, reason: str = '') -> None:
    trace = STATE.require_trace()
    target = STATE.target
    procobj = trace.proxy_object_path(_proc_path())
    procobj.set_value('State', state)
    procobj.set_value('Reason', reason)
    # Where the target is in its own history, which is what the reverse
    # methods count in.
    procobj.set_value('Instruction', target.icount)
    trace.proxy_object_path(_thread_path()).set_value('State', state)


def put_environment() -> None:
    trace = STATE.require_trace()
    spec = STATE.target.spec
    envobj = trace.create_object(ENV_PATTERN.format(procnum=PROC))
    envobj.set_value('Debugger', 'unicorn')
    envobj.set_value('Arch', spec.key)
    envobj.set_value('OS', 'none')
    envobj.set_value('Endian', spec.endian)
    envobj.insert()


def put_threads(state: str = 'STOPPED') -> None:
    trace = STATE.require_trace()
    tobj = trace.create_object(_thread_path())
    tobj.set_value('TID', THREAD)
    tobj.set_value('State', state)
    tobj.set_value('_display', f'[{PROC}.{THREAD}] cpu0')
    tobj.set_value('_short_display', f'[{PROC}.{THREAD}]')
    tobj.insert()
    trace.create_object(STACK_PATTERN.format(procnum=PROC, tnum=THREAD)).insert()
    trace.proxy_object_path(THREADS_PATTERN.format(procnum=PROC)).retain_values(
        [THREAD_KEY_PATTERN.format(tnum=THREAD)])


def put_frames() -> None:
    trace = STATE.require_trace()
    target = STATE.target
    pc = target.pc()
    sp = target.sp()
    fobj = trace.create_object(_frame_path())
    fobj.set_value('PC', trace.extra.map(pc))
    fobj.set_value('SP', trace.extra.map(sp))
    fobj.set_value('_display', f'#{FRAME} {pc:#x}')
    fobj.insert()
    trace.create_object(_regs_path()).insert()
    trace.proxy_object_path(STACK_PATTERN.format(procnum=PROC, tnum=THREAD)).retain_values(
        [FRAME_KEY_PATTERN.format(level=FRAME)])


def putreg() -> Dict[str, List[str]]:
    trace = STATE.require_trace()
    target = STATE.target
    space = _regs_path()
    trace.create_overlay_space('register', space)
    robj = trace.create_object(space)
    robj.insert()
    values = []
    for r in target.spec.regs:
        try:
            v = target.uc.reg_read(r.uc)
        except Exception:
            continue
        v &= (1 << (8 * r.size)) - 1
        values.append(RegVal(r.name, v.to_bytes(r.size, 'big')))
    # From the live machine, not the launch spec: ARM changes instruction
    # set as it runs, and Ghidra disassembles by TMode.
    for name, v in target.context().items():
        values.append(RegVal(name, v.to_bytes(1, 'big')))
    for name, v in target.flags().items():
        values.append(RegVal(name, bytes([v])))
    missing = trace.put_registers(space, values)
    if isinstance(missing, list) and missing:
        return {'missing': missing}
    return {}


def quantize_pages(start: int, end: int) -> Tuple[int, int]:
    return (start // PAGE_SIZE * PAGE_SIZE,
            (end + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE)


def putmem(start: int, length: int, pages: bool = True) -> int:
    """Copy [start, start+length) into the trace, clipped to mapped memory.

    Returns the number of bytes written. Unmapped parts are marked as errors
    so Ghidra stops asking for them.
    """
    trace = STATE.require_trace()
    target = STATE.target
    end = start + length
    if pages:
        start, end = quantize_pages(start, end)
    total = 0
    cursor = start
    for cstart, data in target.read_mapped(start, end):
        if cstart > cursor:
            trace.set_memory_state(trace.extra.map(cursor).extend(cstart - cursor), 'error')
        for off in range(0, len(data), PUT_CHUNK):
            chunk = data[off:off + PUT_CHUNK]
            trace.put_bytes(trace.extra.map(cstart + off), chunk)
        total += len(data)
        cursor = cstart + len(data)
    if cursor < end:
        trace.set_memory_state(trace.extra.map(cursor).extend(end - cursor), 'error')
    return total


def putmem_state(start: int, length: int, state: str) -> None:
    trace = STATE.require_trace()
    trace.set_memory_state(trace.extra.map(start).extend(length), state)


def preload_memory(cap: int = 32 * 1024 * 1024) -> int:
    """Copy every mapped region into the trace, up to `cap` bytes total."""
    target = STATE.target
    total = 0
    for s, e, _ in target.regions():
        size = e - s + 1
        if total + size > cap:
            break
        total += putmem(s, size, pages=False)
    return total


def put_regions() -> None:
    trace = STATE.require_trace()
    target = STATE.target
    keys = []
    for start, end, perms in target.regions():
        size = end - start + 1
        rpath = REGION_PATTERN.format(procnum=PROC, start=start)
        keys.append(REGION_KEY_PATTERN.format(start=start))
        regobj = trace.create_object(rpath)
        regobj.set_value('Range', trace.extra.map(start).extend(size))
        regobj.set_value('_readable', bool(perms & 1))
        regobj.set_value('_writable', bool(perms & 2))
        regobj.set_value('_executable', bool(perms & 4))
        flags = ('r' if perms & 1 else '-') + ('w' if perms & 2 else '-') + ('x' if perms & 4 else '-')
        regobj.set_value('_display', f'{start:#x}-{end:#x} {flags}')
        regobj.insert()
    trace.proxy_object_path(MEMORY_PATTERN.format(procnum=PROC)).retain_values(keys)


def put_modules() -> None:
    trace = STATE.require_trace()
    if STATE.loaded is None:
        return
    keys = []
    for m in STATE.loaded.modules:
        key = f'{m.base:x}'
        mpath = MODULE_PATTERN.format(procnum=PROC, modpath=key)
        keys.append(MODULE_KEY_PATTERN.format(modpath=key))
        modobj = trace.create_object(mpath)
        modobj.set_value('Range', trace.extra.map(m.base).extend(m.size))
        modobj.set_value('Name', m.name)
        modobj.set_value('_display', f'{m.base:x} {os.path.basename(m.name)}')
        modobj.insert()
        trace.create_object(mpath + '.Sections').insert()
    trace.proxy_object_path(MODULES_PATTERN.format(procnum=PROC)).retain_values(keys)


def put_breakpoints() -> None:
    trace = STATE.require_trace()
    target = STATE.target
    pbobj = trace.create_object(PROC_BREAKS_PATTERN.format(procnum=PROC))
    keys: List[str] = []
    pkeys: List[str] = []
    for bp in target.breakpoints.values():
        if bp.kind == REGISTER:
            # Ghidra's breakpoint kinds are all about addresses, and a
            # register watch has none. It stays a console feature rather
            # than being published at a made-up location.
            continue
        keys.append(BREAK_KEY_PATTERN.format(breaknum=bp.num))
        bpath = BREAK_PATTERN.format(breaknum=bp.num)
        bobj = trace.create_object(bpath)
        bobj.set_value('Enabled', bp.enabled)
        bobj.set_value('Expression', bp.describe())
        bobj.set_value('Kinds', bp.kind)
        bobj.set_value('Hit Count', bp.hit_count)
        bobj.set_value('Ignore Count', bp.ignore_count)
        bobj.set_value('Condition', bp.condition or '')
        bobj.set_value('Temporary', bp.temporary)
        bobj.set_value('_display', f'[{bp.num}] {bp.describe()}')
        lpath = BREAK_LOC_PATTERN.format(breaknum=bp.num, locnum=1)
        lobj = trace.create_object(lpath)
        lobj.set_value('Enabled', bp.enabled)
        lobj.set_value('Range', trace.extra.map(bp.address).extend(bp.size))
        lobj.set_value('_display', f'[{bp.num}.1] {bp.describe()}')
        lobj.insert()
        bobj.retain_values([BREAK_LOC_KEY_PATTERN.format(locnum=1)])
        bobj.insert()
        pkey = PROC_BREAK_KEY_PATTERN.format(breaknum=bp.num, locnum=1)
        pkeys.append(pkey)
        pbobj.set_value(pkey, lobj)
    pbobj.insert()
    trace.proxy_object_path(BREAKS_PATH).retain_values(keys)
    pbobj.retain_values(pkeys)


def put_all(preload: bool = True, preload_cap: int = 32 * 1024 * 1024) -> None:
    put_processes('STOPPED', 'Launched')
    put_environment()
    put_threads()
    put_frames()
    putreg()
    put_regions()
    put_modules()
    put_breakpoints()
    target = STATE.target
    if preload:
        preload_memory(preload_cap)
    else:
        putmem(target.pc(), 1)
        putmem(target.sp(), 1)


def activate() -> None:
    STATE.require_trace().proxy_object_path(_frame_path()).activate()


# ---------------------------------------------------------------------------
# Recording execution events (called from hooks)

def record_stop(ev: StopEvent) -> None:
    """A new snapshot with the state after the target stopped."""
    trace = STATE.require_trace()
    target = STATE.target
    with trace.client.batch():
        with open_tracked_tx('Stopped'):
            snapshot(ev.description)
            state = 'TERMINATED' if ev.terminated else 'STOPPED'
            put_state(state, ev.description)
            if ev.terminated:
                trace.proxy_object_path(_proc_path()).set_value('Exit Code', 0)
            put_frames()
            putreg()
            putmem(ev.pc, 1)
            try:
                putmem(target.sp() - 1, 2)
            except Exception:
                pass
            put_breakpoints()
            activate()


def record_continued() -> None:
    trace = STATE.require_trace()
    with trace.client.batch():
        with open_tracked_tx('Continued'):
            put_state('RUNNING', 'Running')
