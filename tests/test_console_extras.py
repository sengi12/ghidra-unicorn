"""Disassembly, hexdump, memory search and register watchpoints.

The programme is the x86-64 one from test_target, so the addresses in these
tests line up with the listing in its docstring.
"""
import io

import pytest

from ghidraunicorn.console import UnicornConsole
from ghidraunicorn.symbols import Symbol, SymbolTable
from ghidraunicorn.target import REGISTER, TargetError

from test_target import CODE, DATA, make_x64


def make_console(symbols=None):
    t = make_x64()
    out = io.StringIO()
    return t, UnicornConsole(t, out=out, color=False, symbols=symbols), out


# ---- disassembly ----------------------------------------------------------

def test_disas_shows_instructions_from_the_program_counter():
    t, c, out = make_console()
    c.push('disas')
    text = out.getvalue()
    assert 'mov' in text and 'inc' in text
    assert '→ 0x1000' in text, 'the program counter is not marked'


def test_disas_takes_an_address_and_a_count():
    t, c, out = make_console()
    c.push('disas 0x1007 2')
    lines = [l for l in out.getvalue().splitlines() if '0x' in l]
    assert len(lines) == 2
    assert '0x1007' in lines[0] and '0x100a' in lines[1]


def test_x_slash_i_disassembles_too():
    t, c, out = make_console()
    c.push('x/3i 0x1000')
    lines = [l for l in out.getvalue().splitlines() if '0x' in l]
    assert len(lines) == 3 and 'mov' in lines[0]


def test_disassembly_marks_breakpoints():
    t, c, out = make_console()
    c.push('b 0x100a')
    c.push('disas 0x1000 3')
    assert '●  0x100a' in out.getvalue()


def test_disassembly_names_addresses_when_symbols_are_loaded():
    table = SymbolTable([Symbol('main', CODE, 0x30)])
    t, c, out = make_console(symbols=table)
    c.push('disas 0x1007 1')
    assert 'main+0x7' in out.getvalue()


def test_disassembling_unmapped_memory_says_so():
    t, c, out = make_console()
    c.push('disas 0xdead0000 2')
    assert 'unmapped or undecodable' in out.getvalue()


# ---- hexdump --------------------------------------------------------------

def test_hexdump_shows_bytes_and_an_ascii_pane():
    t, c, out = make_console()
    t.write(DATA, b'Hello, world!\x00\x01\x02')
    c.push('hd 0x2000 16')
    line = out.getvalue().strip()
    assert '48 65 6c 6c 6f' in line
    assert '|Hello, world!...|' in line


def test_hexdump_defaults_to_sixty_four_bytes_in_four_lines():
    t, c, out = make_console()
    c.push('hd 0x2000')
    assert len([l for l in out.getvalue().splitlines() if l.strip()]) == 4


def test_hexdump_takes_a_register_as_an_address():
    t, c, out = make_console()
    c.push('hd RSP 16')
    assert '0x0000007ff0' in out.getvalue()


def test_hexdump_needs_an_address():
    t, c, out = make_console()
    c.push('hd')
    assert 'usage: hexdump' in out.getvalue()


# ---- searching ------------------------------------------------------------

def test_find_locates_a_string():
    t, c, out = make_console()
    t.write(DATA + 0x40, b'needle')
    c.push('find "needle"')
    assert f'{DATA + 0x40:#012x}' in out.getvalue()
    assert '1 match(es)' in out.getvalue()


def test_find_locates_hex_bytes():
    t, c, out = make_console()
    t.write(DATA + 0x10, bytes.fromhex('deadbeef'))
    c.push('find deadbeef')
    assert f'{DATA + 0x10:#012x}' in out.getvalue()


def test_find_locates_a_value_of_pointer_width():
    t, c, out = make_console()
    t.write(DATA + 0x20, (0x1234).to_bytes(8, 'little'))
    c.push('find 0x1234')
    assert f'{DATA + 0x20:#012x}' in out.getvalue()


def test_find_can_be_limited_to_a_range():
    t, c, out = make_console()
    t.write(DATA, b'needle')
    t.write(DATA + 0x100, b'needle')
    c.push('find "needle"')
    assert '2 match(es)' in out.getvalue()
    out.truncate(0), out.seek(0)
    c.push('find "needle" 0x2000 0x2010')
    assert '1 match(es)' in out.getvalue()


def test_find_reports_when_there_is_nothing():
    t, c, out = make_console()
    c.push('find "definitely not present anywhere"')
    assert '0 match(es)' in out.getvalue()


def test_find_needs_a_pattern():
    t, c, out = make_console()
    c.push('find')
    assert 'usage: find' in out.getvalue()


def test_a_quoted_pattern_that_looks_like_hex_is_still_text():
    t, c, out = make_console()
    t.write(DATA, b'abcd')
    c.push('find "abcd" 0x2000 0x2010')
    assert '1 match(es)' in out.getvalue()
    out.truncate(0), out.seek(0)
    c.push('find abcd 0x2000 0x2010')      # the two bytes ab cd, not there
    assert '0 match(es)' in out.getvalue()


def test_the_three_pattern_forms_are_told_apart_by_how_they_are_written():
    t, c, out = make_console()
    assert c.pattern('"hi"') == b'hi'
    assert c.pattern('4142') == b'AB'
    assert c.pattern('0x41') == (0x41).to_bytes(8, 'little')
    assert c.pattern('hello') == b'hello'     # not hex, not quoted: text


# ---- register watchpoints -------------------------------------------------

def test_a_register_watch_stops_when_the_register_changes():
    t = make_x64()
    bp = t.add_register_watch('RAX')
    assert bp.kind == REGISTER and bp.previous == 0
    ev = t.run()
    assert ev.reason == 'watchpoint' and ev.breakpoint is bp
    # `mov rax, 1` is instruction 0, so the stop is on the one after it.
    assert t.pc() == 0x1007 and t.reg_read('RAX') == 1
    assert '0x0 -> 0x1' in ev.description


def test_a_register_watch_does_not_fire_when_nothing_changes():
    t = make_x64()
    bp = t.add_register_watch('RCX')          # untouched until the call
    t.add_breakpoint(0x1015)
    ev = t.run()
    assert ev.reason == 'breakpoint' and bp.hit_count == 0


def test_a_register_watch_takes_a_condition():
    t = make_x64()
    bp = t.add_register_watch('RAX')
    t.set_condition(bp.num, 'new == 3')
    ev = t.run()
    assert ev.breakpoint is bp and t.reg_read('RAX') == 3
    assert bp.hit_count == 1, 'the changes that did not match were counted'


def test_a_register_watch_condition_sees_the_old_and_new_values():
    t = make_x64()
    bp = t.add_register_watch('RAX')
    t.set_condition(bp.num, 'old == 2 and new == 3 and register == "RAX"')
    assert t.run().breakpoint is bp


def test_a_register_watch_can_be_disabled_and_deleted():
    t = make_x64()
    bp = t.add_register_watch('RAX')
    t.enable_breakpoint(bp.num, False)
    t.add_breakpoint(0x1015)
    assert t.run().reason == 'breakpoint'
    t.delete_breakpoint(bp.num)
    assert bp.num not in t.breakpoints


def test_a_register_watch_resyncs_after_a_rewind():
    """Going back changes the register under the watch, and that is not a
    change the programme made."""
    t = make_x64()
    t.timeline.interval = 1
    t.step(3)
    bp = t.add_register_watch('RAX')
    t.goto_icount(0)
    assert bp.previous == t.reg_read('RAX')
    ev = t.run()
    assert ev.breakpoint is bp and '0x0 -> 0x1' in ev.description


def test_the_console_adds_a_register_watch():
    t, c, out = make_console()
    c.push('rwatch RAX')
    assert 'watchpoint 1: $RAX' in out.getvalue()
    c.push('c')
    assert t.pc() == 0x1007


def test_the_console_refuses_a_register_that_does_not_exist():
    t, c, out = make_console()
    c.push('rwatch nosuchregister')
    assert 'error' in out.getvalue()
    assert not t.breakpoints


def test_a_register_watch_is_listed_with_the_others():
    t, c, out = make_console()
    c.push('rwatch RAX')
    c.push('bl')
    assert '$RAX' in out.getvalue() and 'REGISTER' in out.getvalue()


def test_a_register_watch_is_not_published_to_ghidra():
    """Ghidra's breakpoint kinds are all about addresses; this has none."""
    from ghidraunicorn import commands
    t = make_x64()
    t.add_register_watch('RAX')
    t.add_breakpoint(0x100a)
    assert commands.STATE.trace is None      # nothing to publish to here
    kinds = [b.kind for b in t.breakpoints.values()]
    assert REGISTER in kinds and 'SW_EXECUTE' in kinds


def test_a_register_watch_fires_while_stepping():
    """The check has to happen before the instruction budget ends the run,
    or a step never notices the change and never refreshes what it compares
    against - and the next run then reports it somewhere else entirely."""
    t = make_x64()
    bp = t.add_register_watch('RAX')
    ev = t.step()                             # `mov rax, 1` changes it
    assert ev.reason == 'step', 'the change is only visible at the next hook'
    ev = t.step()
    assert ev.reason == 'watchpoint' and ev.breakpoint is bp
    assert '0x0 -> 0x1' in ev.description


def test_every_change_is_reported_once_and_in_order():
    """`mov rax, 1`, `inc rax`, `inc rax`: three changes, three stops, and
    no stop reported twice.

    A change is noticed at the hook for the instruction *after* the one that
    made it, which is where a memory watchpoint stops too, so the stop
    itself makes no progress and the step after it carries on.
    """
    t = make_x64()
    bp = t.add_register_watch('RAX')
    seen = []
    for _ in range(6):
        ev = t.step()
        if ev.reason == 'watchpoint':
            seen.append(ev.description.split(': ')[1])
    assert seen == ['RAX 0x0 -> 0x1', 'RAX 0x1 -> 0x2', 'RAX 0x2 -> 0x3']
    assert bp.hit_count == 3


def test_a_run_after_a_step_picks_up_where_it_left_off():
    t = make_x64()
    bp = t.add_register_watch('RAX')
    t.step(2)                                 # stops at the first change
    assert bp.hit_count == 1 and t.reg_read('RAX') == 1
    ev = t.run()
    assert ev.reason == 'watchpoint' and '0x1 -> 0x2' in ev.description


def test_asking_for_no_syscalls_shows_none():
    """`records[-0:]` is the whole list, which is the opposite of `sys 0`."""
    from ghidraunicorn import syscalls
    t, c, out = make_console()
    syscalls.install(t)
    c.push('sys 0')
    assert 'nothing called yet' in out.getvalue()
