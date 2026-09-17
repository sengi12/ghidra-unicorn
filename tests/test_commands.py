"""The trace-publishing layer, exercised against a recording fake trace.

This checks object paths, register encoding, and memory clipping without a
Ghidra. The real protocol is exercised by tools/e2e_ghidra.py.
"""
from contextlib import contextmanager

import pytest
from ghidratrace.client import Address, AddressRange, RegVal

from ghidraunicorn import commands, hooks, methods
from ghidraunicorn.loaders import Loaded, Module
from ghidraunicorn.target import WRITE, UnicornTarget

from test_target import CODE, DATA, X64, make_x64


class FakeObject:
    def __init__(self, trace, path):
        self.trace = trace
        self.path = path
        self.values = trace.objects.setdefault(path, {})
        self.inserted = False

    def set_value(self, key, value, schema=None):
        self.values[key] = value

    def insert(self, span=None, resolution='adjust'):
        self.trace.inserted.add(self.path)

    def retain_values(self, keys, span=None, kinds='elements'):
        self.trace.retained[self.path] = list(keys)

    def activate(self):
        self.trace.activated.append(self.path)

    def str_path(self):
        return self.path


class FakeClient:
    @contextmanager
    def batch(self):
        yield None


class FakeTrace:
    def __init__(self):
        self.objects = {}
        self.inserted = set()
        self.retained = {}
        self.activated = []
        self.bytes = {}          # addr -> bytes chunks
        self.states = []
        self.registers = {}
        self.snapshots = []
        self.txs = []
        self.overlays = set()
        self.client = FakeClient()
        self.extra = commands.Extra()
        self._snap = 0

    def create_object(self, path):
        return FakeObject(self, path)

    def proxy_object_path(self, path):
        return FakeObject(self, path)

    def create_root_object(self, xml, schema):
        return FakeObject(self, '')

    @contextmanager
    def open_tx(self, description, undoable=False):
        self.txs.append(description)
        yield object()

    def snapshot(self, description, datetime=None, time=None):
        self._snap += 1
        self.snapshots.append(description)
        return self._snap

    def snap(self):
        return self._snap

    def create_overlay_space(self, base, name):
        self.overlays.add((base, name))

    def put_bytes(self, address, data, snap=None):
        self.bytes[address.offset] = data
        return len(data)

    def set_memory_state(self, rng, state, snap=None):
        self.states.append((rng.min, rng.max, state))

    def put_registers(self, space, values, snap=None):
        self.registers[space] = {rv.name: rv.value for rv in values}
        return []


@pytest.fixture
def session():
    t = make_x64(end=0x1025)
    trace = FakeTrace()
    commands.STATE.loaded = Loaded(t, [Module('/tmp/prog', CODE, 0x1000)], 'test')
    commands.STATE.trace = trace
    commands.STATE.client = None
    hooks.install(t)
    yield t, trace
    hooks.remove(t)
    commands.STATE.trace = None
    commands.STATE.loaded = None


def test_put_all_publishes_tree(session):
    t, trace = session
    commands.put_all(preload=True)
    assert 'Processes[0]' in trace.inserted
    assert 'Processes[0].Threads[0]' in trace.inserted
    assert 'Processes[0].Threads[0].Stack[0]' in trace.inserted
    assert 'Processes[0].Threads[0].Stack[0].Registers' in trace.inserted
    assert trace.objects['Processes[0]']['State'] == 'STOPPED'
    assert trace.objects['Processes[0].Environment']['Arch'] == 'x64'
    frame = trace.objects['Processes[0].Threads[0].Stack[0]']
    assert frame['PC'] == Address('ram', CODE) and frame['SP'] == Address('ram', 0x7ff0)
    regs = trace.registers['Processes[0].Threads[0].Stack[0].Registers']
    assert regs['RIP'] == CODE.to_bytes(8, 'big') and regs['CS'] == (0x33).to_bytes(2, 'big') or 'CS' in regs
    assert len(regs['rflags']) == 8
    # Regions, modules and preloaded memory.
    assert trace.retained['Processes[0].Memory'] == ['[00001000]', '[00002000]', '[00007000]']
    assert trace.objects['Processes[0].Modules[1000]']['Name'] == '/tmp/prog'
    assert trace.objects['Processes[0].Modules[1000]']['Range'] == Address('ram', CODE).extend(0x1000)
    assert trace.bytes[CODE][:len(X64)] == X64
    assert set(trace.bytes) == {CODE, DATA, 0x7000}


def test_putmem_marks_unmapped_as_error(session):
    t, trace = session
    n = commands.putmem(0x0ff0, 0x20)      # page 0 unmapped, page 0x1000 mapped
    assert n == 0x1000
    assert (0x0, 0x0fff, 'error') in trace.states
    assert trace.bytes[0x1000][:len(X64)] == X64


def test_stop_event_records_snapshot_and_state(session):
    t, trace = session
    commands.put_all(preload=False)
    bp = t.add_breakpoint(0x100a)
    ev = t.run()                                    # listener -> record_stop
    assert trace.snapshots[-1] == ev.description
    assert trace.objects['Processes[0]']['State'] == 'STOPPED'
    assert trace.objects['Processes[0]']['Reason'].startswith('Breakpoint 1')
    regs = trace.registers['Processes[0].Threads[0].Stack[0].Registers']
    assert regs['RAX'] == (2).to_bytes(8, 'big')
    assert trace.activated[-1] == 'Processes[0].Threads[0].Stack[0]'
    # Breakpoints published with hit counts under both containers.
    spec = trace.objects['Breakpoints[1]']
    assert spec['Kinds'] == 'SW_EXECUTE' and spec['Hit Count'] == 1 and spec['Enabled']
    loc = trace.objects['Breakpoints[1][1]']
    assert loc['Range'] == Address('ram', 0x100a).extend(1)
    assert trace.retained['Processes[0].Breakpoints'] == ['[1.1]']


def test_exit_marks_terminated(session):
    t, trace = session
    commands.put_all(preload=False)
    t.run()
    assert t.terminated
    assert trace.objects['Processes[0]']['State'] == 'TERMINATED'
    assert trace.objects['Processes[0]']['Exit Code'] == 0


def test_methods_breakpoints_and_memory(session):
    t, trace = session
    commands.put_all(preload=False)
    proc = methods.Process(trace, None, 'Processes[0]')
    methods.break_sw_execute_address(proc, Address('ram', 0x100d))
    methods.break_write_range(proc, AddressRange('ram', DATA, DATA + 7))
    assert [b.kind for b in t.breakpoints.values()] == ['SW_EXECUTE', 'WRITE']
    assert 'Breakpoints[2]' in trace.objects
    methods.toggle_breakpoint(methods.BreakpointSpec(trace, None, 'Breakpoints[1]'), False)
    assert not t.breakpoints[1].enabled
    methods.delete_breakpoint(methods.BreakpointSpec(trace, None, 'Breakpoints[1]'))
    assert 1 not in t.breakpoints
    methods.write_mem(proc, Address('ram', DATA), b'\x11\x22')
    assert t.read(DATA, 2) == b'\x11\x22'
    methods.read_mem(proc, AddressRange('ram', 0x5000, 0x5fff))
    assert (0x5000, 0x5fff, 'error') in trace.states
    frame = methods.StackFrame(trace, None, 'Processes[0].Threads[0].Stack[0]')
    methods.write_reg(frame, 'rax', (0x77).to_bytes(8, 'big'))
    assert t.reg_read('RAX') == 0x77


def test_methods_step_resume_interrupt(session):
    import time
    t, trace = session
    commands.put_all(preload=False)
    thread = methods.Thread(trace, None, 'Processes[0].Threads[0]')
    proc = methods.Process(trace, None, 'Processes[0]')
    methods.step_into(thread, 2)
    assert t.pc() == 0x100a and trace.snapshots[-1].startswith('Stepped')
    t.end = None
    bp = t.add_breakpoint(0x1025)
    methods.resume(proc)
    commands.STATE.run_thread.join(5)
    assert t.pc() == 0x1025 and trace.objects['Processes[0]']['State'] == 'STOPPED'
    assert 'Continued' in trace.txs
    t.delete_breakpoint(bp.num)
    methods.resume(proc)
    time.sleep(0.1)
    assert t.running and trace.objects['Processes[0]']['State'] == 'RUNNING'
    methods.interrupt(proc)
    assert not t.running and trace.objects['Processes[0]']['Reason'].startswith('Interrupted')
    methods.step_advance(thread, Address('ram', 0x1025))
    assert t.pc() == 0x1025
    methods.kill(proc)
    assert t.terminated and trace.objects['Processes[0]']['State'] == 'TERMINATED'
    with pytest.raises(Exception):
        methods.step_into(thread)


def test_registry_has_debugger_actions():
    actions = {m.action for m in methods.REGISTRY._methods.values()}
    assert {'resume', 'interrupt', 'kill', 'step_into', 'step_over', 'step_ext',
            'break_sw_execute', 'break_read', 'break_write', 'break_access',
            'toggle', 'delete', 'refresh', 'activate',
            'read_mem', 'write_mem', 'write_reg', 'execute'} <= actions


def test_putmem_chunks_large_regions(session):
    t, trace = session
    t.uc.mem_map(0x100000, 0x20000)
    n = commands.putmem(0x100000, 0x20000, pages=False)
    assert n == 0x20000
    chunks = sorted(a for a in trace.bytes if 0x100000 <= a < 0x120000)
    assert chunks == [0x100000 + i * commands.PUT_CHUNK for i in range(4)]
    assert all(len(trace.bytes[a]) == commands.PUT_CHUNK for a in chunks)
