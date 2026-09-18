"""Scripted runs with no GUI, and no Ghidra either.

`--commands` feeds the same console the prompt uses, so anything that can be
typed can be scripted; and since anything that is not a command is Python, a
bare `assert` is how a scripted run is made to fail, which is what makes it
usable from CI.
"""
import io
import os

import pytest

from ghidraunicorn.__main__ import build_parser, main, script_text
from ghidraunicorn.console import UnicornConsole, split_commands

from test_target import CODE, DATA, make_x64

# A tiny harness: three increments and then a spin, so `c` never returns
# unless something stops it.
HARNESS = '''
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP

START = 0x1000

def create(input_file=None):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_map(0x2000, 0x1000)
    #  mov rax, 1 ; inc rax ; inc rax ; jmp .
    uc.mem_write(0x1000, bytes.fromhex("48c7c001000000" "48ffc0" "48ffc0" "ebfe"))
    uc.reg_write(UC_X86_REG_RIP, 0x1000)
    uc.reg_write(UC_X86_REG_RSP, 0x2f00)
    return uc
'''


def write_harness(tmp_path):
    path = tmp_path / 'h.py'
    path.write_text(HARNESS)
    return str(path)


# ---- splitting ------------------------------------------------------------

def test_commands_split_on_semicolons_and_newlines():
    assert split_commands('b 0x100040; c; x/8xw 0x300000') == \
        ['b 0x100040', 'c', 'x/8xw 0x300000']
    assert split_commands('b main\nc\nr rax') == ['b main', 'c', 'r rax']


def test_a_comment_runs_to_the_end_of_the_line():
    assert split_commands('b main  # stop at main\nc') == ['b main', 'c']
    assert split_commands('# nothing but a comment') == []


def test_a_semicolon_inside_quotes_is_left_alone():
    assert split_commands('m 0x1000 "41;42"; c') == ['m 0x1000 "41;42"', 'c']


def test_a_hash_inside_quotes_is_not_a_comment():
    assert split_commands("""r rax '#1'""") == ["r rax '#1'"]


def test_blank_lines_and_stray_semicolons_disappear():
    assert split_commands('\n\n b main ;; ; c \n') == ['b main', 'c']


# ---- running a script -----------------------------------------------------

def make_console():
    t = make_x64()
    out = io.StringIO()
    return t, UnicornConsole(t, out=out, color=False), out


def test_a_script_drives_the_target():
    t, c, out = make_console()
    failed = c.run_script('b 0x100d; c; r rax')
    assert failed == 0
    assert t.pc() == 0x100d and t.reg_read('RAX') == 3
    assert 'breakpoint 1 at 0x100d' in out.getvalue()


def test_a_failing_command_is_counted():
    t, c, out = make_console()
    assert c.run_script('b nosuchsymbol') == 1
    assert 'error:' in out.getvalue()


def test_a_failing_assertion_is_counted():
    """Python is the assertion language, so this has to register."""
    t, c, out = make_console()
    assert c.run_script('assert target.pc() == 0xdead') == 1
    assert c.run_script('assert target.pc() == 0x1000') == 0


def test_a_syntax_error_is_counted():
    t, c, out = make_console()
    assert c.run_script('1 +* 2') == 1


def test_a_script_that_ends_part_way_through_something_fails():
    """An unclosed bracket makes the interpreter wait for more, which at a
    prompt is right and in a script means the rest was swallowed."""
    t, c, out = make_console()
    assert c.run_script('print(target.pc()') == 1
    assert 'ended part way through' in out.getvalue()


def test_errors_are_counted_but_the_script_carries_on():
    t, c, out = make_console()
    assert c.run_script('b nosuchsymbol; b 0x100d; c') == 1
    assert t.pc() == 0x100d, 'the script stopped at the first error'


def test_quit_ends_the_script_early():
    t, c, out = make_console()
    assert c.run_script('b 0x100d; q; c') == 0
    assert t.pc() == CODE, 'the commands after `q` still ran'


def test_a_script_can_be_silent():
    t, c, out = make_console()
    c.run_script('r rax', echo=False)
    assert '>>> ' not in out.getvalue()


# ---- the command line -----------------------------------------------------

def test_batch_runs_without_ghidra(tmp_path, capsys):
    status = main(['--harness', write_harness(tmp_path), '--batch',
                   '--commands', 'si 3; assert target.reg_read("RAX") == 3'])
    assert status == 0
    assert 'Trace started' not in capsys.readouterr().out


def test_batch_exits_non_zero_when_a_command_fails(tmp_path, capsys):
    status = main(['--harness', write_harness(tmp_path), '--batch',
                   '--commands', 'si 3; assert target.reg_read("RAX") == 99'])
    assert status == 1
    assert 'command(s) failed' in capsys.readouterr().out


def test_commands_can_come_from_a_file(tmp_path, capsys):
    script = tmp_path / 'run.gu'
    script.write_text('# set up\nsi 3\nassert target.reg_read("RAX") == 3\n')
    status = main(['--harness', write_harness(tmp_path), '--batch',
                   '--commands-file', str(script)])
    assert status == 0


def test_a_file_and_an_argument_are_both_used(tmp_path):
    script = tmp_path / 'run.gu'
    script.write_text('si 1\n')
    args = build_parser().parse_args(['--commands-file', str(script),
                                      '--commands', 'si 2'])
    assert split_commands(script_text(args)) == ['si 1', 'si 2']


def test_a_missing_command_file_is_reported(tmp_path):
    args = build_parser().parse_args(['--commands-file', str(tmp_path / 'nope')])
    with pytest.raises(SystemExit, match='could not read'):
        script_text(args)


def test_without_ghidra_or_batch_it_still_asks_for_an_address(tmp_path):
    with pytest.raises(SystemExit, match='No Ghidra address'):
        main(['--harness', write_harness(tmp_path)])


def test_the_syscall_and_stub_layers_are_there_in_batch_mode(tmp_path):
    status = main(['--harness', write_harness(tmp_path), '--batch',
                   '--commands', 'assert target.syscalls is not None\n'
                                 'assert target.stubs is not None'])
    assert status == 0


def test_reverse_execution_works_in_batch_mode(tmp_path):
    status = main(['--harness', write_harness(tmp_path), '--batch',
                   '--commands', 'si 3; rsi 2; assert target.icount == 1\n'
                                 'assert target.reg_read("RAX") == 1'])
    assert status == 0


def test_the_options_come_from_the_environment_too(monkeypatch):
    monkeypatch.setenv('OPT_COMMANDS', 'si 1')
    monkeypatch.setenv('OPT_BATCH', 'true')
    args = build_parser().parse_args([])
    assert args.commands == 'si 1' and args.batch is True
