"""Reverse execution: the timeline, and going back through it.

The programme under test is the x86-64 one from test_target:

    0  1000: mov rax, 1
    1  1007: inc rax
    2  100a: inc rax
    3  100d: mov [0x2000], rax      <- the only write to DATA
    4  1015: mov rbx, [0x2000]
    5  101d: call 0x1027
    6  1027: inc rcx
    7  102a: ret
    8  1022: inc rbx
    9  1025: jmp 0x1025             (spins)

The left column is the instruction count at that state, which is what
`goto_icount` takes. Checkpoint intervals here are tiny on purpose, so a few
steps already cross several of them.
"""
import pytest

from ghidraunicorn.target import WRITE, TargetError

from test_target import CODE, DATA, make_x64


def make_tt(interval=3, budget=1 << 20, end=None):
    t = make_x64(end=end)
    t.timeline.interval = interval
    t.timeline.budget = budget
    return t


def state(t):
    """Everything a restore has to reproduce."""
    return (t.icount, t.pc(), t.regs(),
            t.read(CODE, 0x40), t.read(DATA, 0x40), t.read(0x7000, 0x1000))


def test_icount_counts_executed_instructions():
    t = make_tt()
    assert t.icount == 0 and not t.can_reverse
    t.step(3)
    assert t.icount == 3 and t.pc() == 0x100d and t.can_reverse
    t.add_breakpoint(0x1022)
    t.run()
    # A breakpoint stops before its instruction, so it is not counted.
    assert t.icount == 8 and t.pc() == 0x1022


def test_step_back_restores_registers_and_memory():
    t = make_tt()
    before = state(t.step(3) and t)          # after 3 steps, before the store
    assert t.read(DATA, 8) == b'\0' * 8
    t.step()                                 # mov [0x2000], rax
    assert t.read(DATA, 8) == b'\x03' + b'\0' * 7
    ev = t.step_back()
    assert ev.reason == 'step' and ev.pc == 0x100d
    assert t.icount == 3 and t.read(DATA, 8) == b'\0' * 8
    assert state(t) == before


def test_step_back_several_across_checkpoints():
    t = make_tt(interval=2)
    marks = {}
    for _ in range(8):
        marks[t.icount] = state(t)
        t.step()
    assert t.icount == 8
    for k in (7, 5, 4, 1, 0):
        t.step_back(t.icount - k)
        assert t.icount == k and state(t) == marks[k], k


def test_reverse_across_a_checkpoint_boundary():
    t = make_tt(interval=3)
    at2 = None
    for _ in range(7):
        if t.icount == 2:
            at2 = state(t)
        t.step()
    # Instruction 2 is in the checkpoint-0 interval, we are past checkpoint 6.
    assert len(t.timeline.checkpoints) >= 2
    t.goto_icount(2)
    assert state(t) == at2 and t.pc() == 0x100a


def test_goto_zero_reproduces_the_initial_state():
    t = make_tt(interval=2)
    start = state(t)
    t.step(6)
    assert t.reg_read('rax') == 3 and t.read(DATA, 8) != b'\0' * 8
    ev = t.goto_icount(0)
    assert ev.pc == CODE and t.icount == 0
    assert state(t) == start
    assert t.reg_read('rax') == 0 and t.read(DATA, 8) == b'\0' * 8


def test_step_back_then_forward_is_deterministic():
    t = make_tt(interval=2)
    t.step(5)
    after5 = state(t)
    t.step(3)
    after8 = state(t)
    t.step_back(3)
    assert state(t) == after5
    t.step(3)
    assert state(t) == after8
    t.step_back(8)
    t.step(8)
    assert state(t) == after8


def test_resume_back_stops_at_the_previous_breakpoint_hit():
    t = make_tt(interval=2)
    bp = t.add_breakpoint(0x100a)
    t.run()
    assert t.pc() == 0x100a and t.icount == 2 and bp.hit_count == 1
    t.step(5)
    assert t.pc() == 0x102a
    ev = t.resume_back()
    assert ev.reason == 'breakpoint' and ev.pc == 0x100a and ev.breakpoint is bp
    assert t.icount == 2 and t.reg_read('rax') == 2
    # Replaying to get here must not have counted another hit.
    assert bp.hit_count == 1


def test_resume_back_without_a_breakpoint_lands_at_the_start():
    t = make_tt(interval=2)
    t.step(6)
    ev = t.resume_back()
    assert ev.reason == 'stopped' and t.icount == t.earliest_icount == 0
    assert t.pc() == CODE


def test_resume_back_skips_a_disabled_breakpoint():
    t = make_tt(interval=2)
    bp = t.add_breakpoint(0x100a)
    t.step(6)
    t.enable_breakpoint(bp.num, False)
    assert t.resume_back().reason == 'stopped'
    t.step(6)
    t.enable_breakpoint(bp.num, True)
    assert t.resume_back().pc == 0x100a


def test_step_back_over_a_call_lands_on_the_call():
    pytest.importorskip('capstone')
    t = make_tt(interval=3)
    t.step(8)
    assert t.pc() == 0x1022 and t.reg_read('rcx') == 1
    ev = t.step_back_over()
    assert ev.pc == 0x101d and t.icount == 5
    assert t.reg_read('rcx') == 0            # the call was undone whole
    # With no call in the way it is an ordinary reverse step.
    assert t.step_back_over().pc == 0x1015


def test_breakpoints_and_watchpoints_do_not_fire_during_replay():
    t = make_tt(interval=4)
    bp = t.add_breakpoint(0x1007)
    wp = t.add_watchpoint(DATA, 8, WRITE)
    t.run()                                   # breakpoint at 0x1007
    assert (bp.hit_count, wp.hit_count) == (1, 0)
    t.step(3)                                 # runs the store: one watch hit
    assert wp.hit_count == 1
    seen = []
    t.listeners.append(seen.append)
    ev = t.goto_icount(0)                     # back to the start, silently
    assert (bp.hit_count, wp.hit_count) == (1, 1)
    assert seen == [ev]                       # the replay itself says nothing
    t.enable_breakpoint(bp.num, False)
    t.step(4)                                 # forward again: the store hits
    assert (bp.hit_count, wp.hit_count) == (1, 2)
    seen.clear()
    ev = t.step_back(3)                       # replays the store from the base
    assert (bp.hit_count, wp.hit_count) == (1, 2)
    assert seen == [ev]


def test_reverse_operations_notify_listeners_once():
    t = make_tt(interval=2)
    t.step(6)
    seen = []
    t.listeners.append(seen.append)
    evs = [t.step_back(), t.step_back_over(), t.goto_icount(1), t.resume_back()]
    assert seen == evs


def test_going_back_further_than_retained_raises():
    t = make_tt(interval=2)
    t.step(4)
    with pytest.raises(TargetError) as e:
        t.step_back(9)
    assert 'instruction -5' in str(e.value)
    assert 'reaches back to instruction 0' in str(e.value)
    with pytest.raises(TargetError):
        t.goto_icount(-1)
    # And the failed request left the target where it was.
    assert t.icount == 4 and t.pc() == 0x1015


def test_dropping_old_checkpoints_moves_the_earliest_point():
    t = make_tt(interval=2, budget=0)         # keep nothing but the base
    t.step(7)
    assert t.timeline.dropped >= 2 and t.timeline.checkpoints == []
    earliest = t.earliest_icount
    assert 0 < earliest <= 7
    at_earliest = None
    with pytest.raises(TargetError) as e:
        t.goto_icount(earliest - 1)
    assert f'reaches back to instruction {earliest}' in str(e.value)
    # What is still retained restores exactly.
    t.goto_icount(earliest)
    at_earliest = state(t)
    t.step(7 - earliest)
    t.goto_icount(earliest)
    assert state(t) == at_earliest
    assert 'folded away' in t.timeline.describe()


def test_reverse_out_of_a_terminated_target():
    t = make_tt(interval=2, end=0x1025)
    ev = t.run()
    assert ev.reason == 'exit' and t.terminated
    assert t.icount == 9 and t.pc() == 0x1025
    t.step_back(2)
    assert not t.terminated and t.pc() == 0x102a
    assert t.step().pc == 0x1022               # and it runs again


def test_debugger_writes_are_captured_by_the_next_checkpoint():
    t = make_tt(interval=2)
    t.step(1)
    t.write(DATA + 0x20, b'\xaa' * 4)          # a write from the debugger
    marked = state(t)
    t.step(5)
    t.write(DATA + 0x20, b'\xbb' * 4)
    t.goto_icount(1)
    assert t.read(DATA + 0x20, 4) == b'\xaa' * 4
    assert state(t) == marked


def test_reverse_refuses_while_the_target_runs():
    import threading
    import time
    t = make_tt(interval=2)
    bp = t.add_breakpoint(0x1025)
    t.run()                                    # up to the spin loop
    t.delete_breakpoint(bp.num)
    th = threading.Thread(target=t.run, daemon=True)
    th.start()
    time.sleep(0.2)
    assert t.running
    with pytest.raises(TargetError) as e:
        t.step_back()
    assert 'running' in str(e.value)
    t.interrupt()
    th.join(5)
    assert t.step_back().reason == 'step'


def test_recording_can_be_turned_off():
    t = make_x64()
    t.timeline.enabled = False
    t.step(3)
    assert t.icount == 3 and not t.can_reverse      # counted, but not kept
    with pytest.raises(TargetError) as e:
        t.step_back()
    assert 'history is off' in str(e.value)


# ---------------------------------------------------------------------------
# The console and Ghidra's side of it

def make_console(interval=2):
    import io
    from ghidraunicorn.console import UnicornConsole
    t = make_tt(interval=interval)
    out = io.StringIO()
    return t, UnicornConsole(t, out=out, color=False), out


def test_console_reverse_commands():
    t, c, out = make_console()
    c.push('si 6')
    assert t.icount == 6 and t.pc() == 0x1027
    c.push('rsi 2')
    assert t.icount == 4 and t.pc() == 0x1015
    c.push('back')
    assert t.icount == 3 and t.pc() == 0x100d
    c.push('goto 0')
    assert t.icount == 0 and t.pc() == CODE
    c.push('icount')
    assert 'instruction 0, history from 0' in out.getvalue()
    c.push('rsi')                                  # already at the start
    assert 'error: cannot go back' in out.getvalue()


def test_console_reverse_continue_and_step_over():
    pytest.importorskip('capstone')
    t, c, out = make_console()
    c.push('b 0x100a')
    c.push('c')
    assert t.pc() == 0x100a
    c.push('si 6')
    assert t.pc() == 0x1022
    c.push('rni')                                  # back over the call
    assert t.pc() == 0x101d and t.reg_read('rcx') == 0
    c.push('rc')                                   # back to the breakpoint
    assert t.pc() == 0x100a and t.icount == 2


def test_help_lists_the_reverse_commands():
    from ghidraunicorn.console import HELP
    for word in ('rsi', 'rni', 'rc', 'goto N', 'icount'):
        assert word in HELP


def test_ghidra_reverse_methods_are_registered():
    from ghidraunicorn import methods
    entries = {m.name: m for m in methods.REGISTRY._methods.values()}
    for name, icon in (('resume_back', 'icon.debugger.resume.back'),
                       ('step_back_into', 'icon.debugger.step.back.into'),
                       ('step_back_over', 'icon.debugger.step.back.over')):
        assert entries[name].action == 'step_ext'
        assert entries[name].icon == icon


def test_the_trace_carries_the_instruction_count():
    from ghidraunicorn import commands
    from ghidraunicorn.loaders import Loaded

    from test_commands import FakeTrace

    t = make_tt(interval=2)
    commands.STATE.loaded = Loaded(t, [], 'test')
    commands.STATE.trace = trace = FakeTrace()
    try:
        t.step(4)
        commands.put_state('STOPPED', 'Stepped')
        assert trace.objects['Processes[0]']['Instruction'] == 4
        t.step_back(2)
        commands.put_state('STOPPED', 'Stepped back')
        assert trace.objects['Processes[0]']['Instruction'] == 2
    finally:
        commands.STATE.trace = None
        commands.STATE.loaded = None


def test_ghidra_reverse_methods_drive_the_target():
    from ghidraunicorn import commands, methods
    from ghidraunicorn.loaders import Loaded

    t = make_tt(interval=2)
    commands.STATE.loaded = Loaded(t, [], 'test')
    try:
        thread = methods.Thread(None, None, 'Processes[0].Threads[0]')
        process = methods.Process(None, None, 'Processes[0]')
        with pytest.raises(TargetError):          # nothing has run yet
            methods.step_back_into(thread)
        t.add_breakpoint(0x100a)
        t.run()
        t.step(5)
        methods.step_back_into(thread, 2)
        assert t.icount == 5 and t.pc() == 0x101d
        methods.step_back_over(thread)
        assert t.icount == 4
        methods.resume_back(process)
        assert t.pc() == 0x100a and t.icount == 2
        with pytest.raises(TargetError) as e:
            methods.step_back_into(thread, 9)
        assert 'history only reaches back to 0' in str(e.value)
    finally:
        commands.STATE.loaded = None
