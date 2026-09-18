"""Conditional breakpoints, ignore counts and what counts as a hit.

The programme is the x86-64 one from test_target:

    0  1000: mov rax, 1
    1  1007: inc rax
    2  100a: inc rax               <- rax is 2 here, 3 after
    3  100d: mov [0x2000], rax
    4  1015: mov rbx, [0x2000]
    5  101d: call 0x1027
    6  1027: inc rcx
    7  102a: ret
    8  1022: inc rbx
    9  1025: jmp 0x1025            (spins, so a breakpoint here fires forever)

The order the hit count and the ignore count move in is gdb's, because that
is what Ghidra's breakpoint model is built around: a condition that is false
is not a hit at all, while an ignore count consumes a hit that did count.
"""
import pytest

from ghidraunicorn.target import ACCESS, WRITE, TargetError

from test_target import CODE, DATA, make_x64


def test_a_true_condition_stops():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    t.set_condition(bp.num, 'rax == 2')
    ev = t.run()
    assert ev.reason == 'breakpoint' and ev.pc == 0x100a
    assert bp.hit_count == 1


def test_a_false_condition_does_not_stop_and_does_not_count():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    t.set_condition(bp.num, 'rax == 99')
    backstop = t.add_breakpoint(0x1022)
    ev = t.run()
    assert ev.breakpoint is backstop, 'the conditional breakpoint stopped anyway'
    assert bp.hit_count == 0, 'a hit that did not qualify was counted'


def test_a_register_name_works_in_either_case():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    t.set_condition(bp.num, 'RAX == 2')
    assert t.run().breakpoint is bp


def test_a_condition_can_read_memory_through_a_pointer():
    # 0x100d is the store into DATA, so the value put there below is still
    # what is in memory when the breakpoint there is tested.
    t = make_x64()
    t.write(DATA, (0xcafe).to_bytes(8, 'little'))
    bp = t.add_breakpoint(0x100d)
    t.set_condition(bp.num, f'u32({DATA:#x}) == 0xcafe')
    assert t.run().breakpoint is bp


def test_the_same_condition_one_instruction_later_is_false():
    # By 0x1015 the store has run and DATA holds 3, not 0xcafe.
    t = make_x64()
    t.write(DATA, (0xcafe).to_bytes(8, 'little'))
    bp = t.add_breakpoint(0x1015)
    t.set_condition(bp.num, f'u32({DATA:#x}) == 0xcafe')
    backstop = t.add_breakpoint(0x1022)
    assert t.run().breakpoint is backstop
    assert bp.hit_count == 0


def test_a_condition_sees_pc_sp_and_icount():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    t.set_condition(bp.num, 'pc == 0x100a and icount == 2 and sp != 0')
    assert t.run().breakpoint is bp


def test_clearing_a_condition_brings_the_breakpoint_back():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    t.set_condition(bp.num, 'rax == 99')
    t.add_breakpoint(0x1022)
    assert t.run().breakpoint is not bp
    t.goto_icount(0)
    t.set_condition(bp.num, None)
    assert bp.condition is None
    assert t.run().breakpoint is bp


def test_a_condition_that_will_not_compile_is_refused_when_it_is_set():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    with pytest.raises(TargetError, match='bad condition'):
        t.set_condition(bp.num, 'rax ==')
    assert bp.condition is None, 'a condition that does not compile was kept'


def test_a_condition_that_raises_stops_and_says_why():
    """Better a breakpoint that stops and complains than one that silently
    never fires."""
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    t.set_condition(bp.num, 'no_such_name == 1')
    ev = t.run()
    assert ev.breakpoint is bp
    assert 'NameError' in bp.condition_error
    assert 'condition' in ev.description and 'NameError' in ev.description


def test_an_ignore_count_passes_that_many_times_but_counts_them():
    t = make_x64()
    bp = t.add_breakpoint(0x1025)          # the spin: hit every iteration
    t.set_ignore_count(bp.num, 3)
    ev = t.run()
    assert ev.breakpoint is bp
    assert bp.ignore_count == 0, 'the ignore count was not consumed'
    assert bp.hit_count == 4, 'the ignored hits were not counted'


def test_an_ignore_count_of_zero_stops_at_once():
    t = make_x64()
    bp = t.add_breakpoint(0x1025)
    t.set_ignore_count(bp.num, 0)
    t.run()
    assert bp.hit_count == 1


def test_a_negative_ignore_count_is_taken_as_none():
    t = make_x64()
    bp = t.add_breakpoint(0x1025)
    t.set_ignore_count(bp.num, -5)
    assert bp.ignore_count == 0


def test_the_condition_is_applied_before_the_ignore_count():
    """Only qualifying hits are ignored, so the count is not eaten by hits
    the condition rejected."""
    t = make_x64()
    bp = t.add_breakpoint(0x1025)
    t.set_condition(bp.num, 'rbx >= 3')    # rbx is 3 from the first pass on
    t.set_ignore_count(bp.num, 2)
    t.run()
    assert bp.hit_count == 3 and bp.ignore_count == 0


def test_a_disabled_breakpoint_evaluates_nothing():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    t.set_condition(bp.num, 'no_such_name')
    t.enable_breakpoint(bp.num, False)
    t.add_breakpoint(0x1022)
    t.run()
    assert bp.hit_count == 0 and bp.condition_error == ''


# ---- watchpoints ----------------------------------------------------------

def test_a_watchpoint_condition_sees_the_access():
    t = make_x64()
    bp = t.add_watchpoint(DATA, 8, WRITE)
    t.set_condition(bp.num, f'access == "write" and address == {DATA:#x} and size == 8')
    ev = t.run()
    assert ev.reason == 'watchpoint' and ev.breakpoint is bp


def test_a_watchpoint_condition_can_reject_the_access():
    t = make_x64()
    bp = t.add_watchpoint(DATA, 8, ACCESS)
    t.set_condition(bp.num, 'value == 0xdead')
    backstop = t.add_breakpoint(0x1022)
    ev = t.run()
    assert ev.breakpoint is backstop
    assert bp.hit_count == 0


def test_a_watchpoint_condition_can_match_the_value_written():
    t = make_x64()
    bp = t.add_watchpoint(DATA, 8, WRITE)
    t.set_condition(bp.num, 'value == 3')    # `mov [0x2000], rax` with rax = 3
    assert t.run().breakpoint is bp


def test_a_watchpoint_ignore_count_works_too():
    t = make_x64()
    bp = t.add_watchpoint(DATA, 8, ACCESS)   # written at 3, then read at 4
    t.set_ignore_count(bp.num, 1)
    ev = t.run()
    assert ev.reason == 'watchpoint' and bp.hit_count == 2


# ---- how it reads ---------------------------------------------------------

def test_the_description_carries_the_condition_and_the_ignore_count():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    t.set_condition(bp.num, 'rax == 2')
    t.set_ignore_count(bp.num, 4)
    assert bp.describe() == '*0x100a if rax == 2 (ignore 4)'


def test_the_console_sets_and_clears_a_condition():
    import io
    from ghidraunicorn.console import UnicornConsole
    t = make_x64()
    out = io.StringIO()
    c = UnicornConsole(t, out=out, color=False)
    c.push('b 0x100a')
    c.push('cond 1 rax == 2')
    assert t.breakpoints[1].condition == 'rax == 2', 'the expression was mangled'
    assert 'stops only when rax == 2' in out.getvalue()
    c.push('cond 1')
    assert t.breakpoints[1].condition is None
    assert 'has no condition' in out.getvalue()


def test_the_console_sets_an_ignore_count_and_lists_it():
    import io
    from ghidraunicorn.console import UnicornConsole
    t = make_x64()
    out = io.StringIO()
    c = UnicornConsole(t, out=out, color=False)
    c.push('b 0x1025')
    c.push('ignore 1 3')
    assert t.breakpoints[1].ignore_count == 3
    c.push('bl')
    assert 'ignore 3' in out.getvalue()


def test_the_console_reports_a_condition_it_cannot_compile():
    import io
    from ghidraunicorn.console import UnicornConsole
    t = make_x64()
    out = io.StringIO()
    c = UnicornConsole(t, out=out, color=False)
    c.push('b 0x100a')
    c.push('cond 1 rax ==')
    assert 'bad condition' in out.getvalue()
