"""Recording a session to a file that is both a transcript and a script.

The whole design rests on one thing: `#` starts a comment, so a file whose
commands are plain lines and whose everything-else is commented can be read
by a person and fed back to `--commands-file` without editing. The round
trip test at the end is the one that matters.
"""
import io
import os

import pytest

from ghidraunicorn.__main__ import main
from ghidraunicorn.console import UnicornConsole, split_commands
from ghidraunicorn.recording import SessionRecorder

from test_batch import HARNESS, write_harness
from test_target import CODE, DATA, make_x64


def make_console():
    t = make_x64()
    out = io.StringIO()
    return t, UnicornConsole(t, out=out, color=False), out


# ---- the file -------------------------------------------------------------

def test_the_header_says_what_was_being_debugged(tmp_path):
    t = make_x64()
    path = str(tmp_path / 's.gu')
    with SessionRecorder(path, t, argv=['prog', '--harness', 'h.py']):
        pass
    text = open(path).read()
    assert '# architecture: x64 (x86:LE:64:default)' in text
    assert '# start: pc=0x1000' in text
    assert "launched as: prog --harness h.py" in text


def test_commands_are_plain_lines_and_output_is_commented(tmp_path):
    t = make_x64()
    path = str(tmp_path / 's.gu')
    with SessionRecorder(path, t) as r:
        r.command('b 0x100a')
        r.output('breakpoint 1 at 0x100a\n')
    lines = open(path).read().splitlines()
    assert 'b 0x100a' in lines
    assert '#  | breakpoint 1 at 0x100a' in lines


def test_stops_are_recorded_wherever_they_came_from(tmp_path):
    """The recorder listens to the target, so a stop caused from Ghidra is
    logged the same as one caused by a command typed here."""
    t = make_x64()
    path = str(tmp_path / 's.gu')
    with SessionRecorder(path, t) as r:
        t.add_breakpoint(0x100a)
        t.run()                        # nothing typed; the target just stopped
        assert r.stops == 1
    assert '# stop: breakpoint - Breakpoint 1 at 0x100a' in open(path).read()


def test_colour_escapes_are_stripped(tmp_path):
    t = make_x64()
    path = str(tmp_path / 's.gu')
    with SessionRecorder(path, t) as r:
        r.output('\x1b[1;31mRAX\x1b[0m 1\n')
    assert '#  | RAX 1' in open(path).read()
    assert '\x1b' not in open(path).read()


def test_blank_output_is_not_recorded(tmp_path):
    t = make_x64()
    path = str(tmp_path / 's.gu')
    with SessionRecorder(path, t) as r:
        r.output('\n\n   \n')
        r.command('   ')
    assert r.commands == 0
    assert '#  |' not in open(path).read()


def test_the_footer_counts_what_happened(tmp_path):
    t = make_x64()
    path = str(tmp_path / 's.gu')
    r = SessionRecorder(path, t)
    r.command('si')
    t.step()
    r.close()
    assert 'after 1 command(s) and 1 stop(s)' in open(path).read()


def test_closing_twice_is_harmless(tmp_path):
    t = make_x64()
    r = SessionRecorder(str(tmp_path / 's.gu'), t)
    r.close()
    r.close()
    assert r.closed and not t.listeners


# ---- the console ----------------------------------------------------------

def test_the_console_records_what_is_typed(tmp_path):
    t, c, out = make_console()
    path = str(tmp_path / 's.gu')
    c.push(f'record {path}')
    c.push('b 0x100a')
    c.push('c')
    c.stop_recording()
    text = open(path).read()
    assert 'b 0x100a' in text.splitlines()
    assert 'c' in text.splitlines()
    assert '# stop: breakpoint' in text


def test_record_with_no_argument_reports_the_state(tmp_path):
    t, c, out = make_console()
    c.push('record')
    assert 'not recording' in out.getvalue()
    c.push(f'record {tmp_path / "s.gu"}')
    c.push('record')
    assert 'recording to' in out.getvalue()


def test_record_off_stops_it(tmp_path):
    t, c, out = make_console()
    path = str(tmp_path / 's.gu')
    c.push(f'record {path}')
    c.push('record off')
    assert c.recorder is None
    c.push('b 0x100a')
    assert 'b 0x100a' not in open(path).read().splitlines()


def test_recording_again_closes_the_first_file(tmp_path):
    t, c, out = make_console()
    first, second = str(tmp_path / 'a.gu'), str(tmp_path / 'b.gu')
    c.push(f'record {first}')
    c.push(f'record {second}')
    assert 'ended' in open(first).read()
    c.stop_recording()


def test_the_stop_context_is_in_the_recording(tmp_path):
    """What the target looked like when it stopped is the useful part of a
    recording attached to a bug report.

    The context is drawn by the stop listener that `run` and `run_script`
    install, so this drives the console the way a session actually does
    rather than pushing lines at it one by one.
    """
    t, c, out = make_console()
    path = str(tmp_path / 's.gu')
    c.run_script(f'record {path}\nb 0x100a\nc')
    c.stop_recording()
    text = open(path).read()
    assert '[ registers ]' in text and 'RAX' in text
    assert '[ disassembly ]' in text
    assert '# stop: breakpoint' in text


# ---- the round trip -------------------------------------------------------

def test_a_recording_replays(tmp_path):
    """The point of the format: no editing between recording and replaying."""
    harness = write_harness(tmp_path)
    recorded = str(tmp_path / 'session.gu')
    assert main(['--harness', harness, '--batch', '--record', recorded,
                 '--commands', 'si 2; r rax']) == 0

    replayed = str(tmp_path / 'again.gu')
    status = main(['--harness', harness, '--batch', '--record', replayed,
                   '--commands-file', recorded,
                   '--commands', 'assert target.reg_read("RAX") == 2\n'
                                 'assert target.icount == 2'])
    assert status == 0, 'replaying the recording did not reach the same state'


def test_only_the_commands_survive_the_round_trip(tmp_path):
    harness = write_harness(tmp_path)
    recorded = str(tmp_path / 'session.gu')
    main(['--harness', harness, '--batch', '--record', recorded,
          '--commands', 'si 2; r rax'])
    assert split_commands(open(recorded).read()) == ['si 2', 'r rax']


def test_recording_a_failing_session_still_replays(tmp_path):
    harness = write_harness(tmp_path)
    recorded = str(tmp_path / 'session.gu')
    assert main(['--harness', harness, '--batch', '--record', recorded,
                 '--commands', 'b nosuchsymbol; si 1']) == 1
    # The bad command is recorded as typed, so the replay fails the same way,
    # which is exactly what attaching it to a bug report is for.
    assert main(['--harness', harness, '--batch',
                 '--commands-file', recorded]) == 1
