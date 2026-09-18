"""Batch triage over synthetic harnesses, plus the real afl-unicorn sample.

The x86-64 harnesses below are the smallest thing that produces each outcome:
a clean exit, an unmapped read, an invalid instruction, an endless loop, and a
crash site reachable from several inputs (so grouping has something to group).
"""
import json
import os

import pytest

from ghidraunicorn import triage

# ---------------------------------------------------------------------------
# Harnesses written into tmp_path

CLEAN = '''
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RIP, UC_X86_REG_RSP

START = 0x1000
END = 0x1006                      # after two `inc rax`

def create(input_file=None):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_map(0x7000, 0x1000)
    uc.mem_write(0x1000, bytes.fromhex("48ffc0" "48ffc0" "90"))
    uc.reg_write(UC_X86_REG_RSP, 0x7ff0)
    uc.reg_write(UC_X86_REG_RIP, START)
    if input_file:
        uc.reg_write(UC_X86_REG_RAX, len(open(input_file, "rb").read()))
    return uc
'''

# Two crash sites, both `mov rbx, [rax]`: one at 0x1000, one at 0x1010. The
# first input byte picks which one runs, the second picks the address RAX
# points at, so inputs can share a faulting PC but not a faulting target.
CRASH = '''
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RSP

END = 0x1020

def create(input_file=None):
    data = open(input_file, "rb").read() if input_file else b"\\x00\\x00"
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_map(0x7000, 0x1000)
    code = bytes.fromhex("488b18") + b"\\x90" * 13 + bytes.fromhex("488b18") + b"\\x90" * 13
    uc.mem_write(0x1000, code)
    uc.reg_write(UC_X86_REG_RSP, 0x7ff0)
    uc.reg_write(UC_X86_REG_RAX, 0x9000 if data[1:2] == b"\\x00" else 0xa000)
    return uc, (0x1000 if data[0:1] == b"\\x00" else 0x1010), END
'''

LOOP = '''
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RSP

START = 0x1000

def create(input_file=None):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_map(0x7000, 0x1000)
    uc.mem_write(0x1000, bytes.fromhex("48ffc0" "ebfb"))   # inc rax; jmp $-3
    uc.reg_write(UC_X86_REG_RSP, 0x7ff0)
    return uc
'''

BAD_INSN = '''
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RSP

START = 0x1000
END = 0x1010

def create(input_file=None):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_map(0x7000, 0x1000)
    uc.mem_write(0x1000, bytes.fromhex("0f0b"))            # ud2
    uc.reg_write(UC_X86_REG_RSP, 0x7ff0)
    return uc
'''

# One harness, three fates, picked by the input's first byte: exit, crash, loop.
MIXED = '''
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RSP

END = 0x1002

def create(input_file=None):
    data = open(input_file, "rb").read() if input_file else b"\\x00"
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_map(0x7000, 0x1000)
    uc.mem_write(0x1000, bytes.fromhex("9090"))            # nop; nop -> END
    uc.mem_write(0x1010, bytes.fromhex("488b18"))          # mov rbx, [rax]
    uc.mem_write(0x1020, bytes.fromhex("ebfe"))            # jmp $
    uc.reg_write(UC_X86_REG_RSP, 0x7ff0)
    uc.reg_write(UC_X86_REG_RAX, 0x9000)
    return uc, {0: 0x1000, 1: 0x1010, 2: 0x1020}[data[0]], END
'''

BROKEN = '''
def create(input_file=None):
    raise ValueError("no engine for you")
'''


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def write_input(tmp_path, name, data):
    d = tmp_path / 'inputs'
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def crash_inputs(tmp_path):
    """Three inputs: two fault at 0x1000 (different targets), one at 0x1010."""
    return [write_input(tmp_path, 'a.bin', b'\x00\x00'),      # 0x1000 -> 0x9000
            write_input(tmp_path, 'b.bin', b'\x00\x01\xff'),  # 0x1000 -> 0xa000
            write_input(tmp_path, 'c.bin', b'\x01\x00')]      # 0x1010 -> 0x9000


# ---------------------------------------------------------------------------
# One input at a time

def test_clean_exit(tmp_path):
    h = write(tmp_path, 'clean.py', CLEAN)
    inp = write_input(tmp_path, 'in.bin', b'abcd')
    r = triage.triage_input(h, inp)
    assert r.outcome == triage.OK
    assert r.reason == 'exit' and r.pc == 0x1006
    assert not r.crashed
    assert r.fault is None
    assert r.instructions == 2
    assert r.registers['RAX'] == 6          # 4 input bytes + two `inc rax`
    assert r.signature == 'ok@0x1006'
    assert r.stack is not None and r.stack.address == 0x7ff0


def test_unmapped_read_records_fault_and_instruction(tmp_path, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    r = triage.triage_input(h, crash_inputs[0])
    assert r.outcome == triage.CRASH and r.crashed
    assert r.reason == 'error' and r.pc == 0x1000
    assert r.fault is not None
    assert r.fault.kind == 'UC_ERR_READ_UNMAPPED'
    assert r.fault.address == 0x9000        # what the instruction tried to read
    assert r.fault.access == 'UC_MEM_READ_UNMAPPED'
    assert r.kind == 'UC_ERR_READ_UNMAPPED'
    assert r.signature == 'UC_ERR_READ_UNMAPPED@0x1000'
    # Capstone is a test dependency, so the faulting instruction is decoded.
    assert r.instruction is not None
    assert r.instruction.mnemonic == 'mov'
    assert r.instruction.text == 'mov rbx, qword ptr [rax]'
    assert r.instruction.bytes == bytes.fromhex('488b18')
    assert r.registers['RAX'] == 0x9000 and r.registers['RIP'] == 0x1000


def test_second_crash_site_is_a_different_pc(tmp_path, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    r = triage.triage_input(h, crash_inputs[2])
    assert r.outcome == triage.CRASH and r.pc == 0x1010


def test_invalid_instruction_has_no_fault_address(tmp_path):
    h = write(tmp_path, 'ud2.py', BAD_INSN)
    r = triage.triage_input(h, write_input(tmp_path, 'i.bin', b'x'))
    assert r.outcome == triage.CRASH
    assert r.fault.kind == 'UC_ERR_INSN_INVALID'
    assert r.fault.address is None and r.fault.access is None


def test_broken_harness_is_an_error_not_a_crash(tmp_path):
    h = write(tmp_path, 'broken.py', BROKEN)
    r = triage.triage_input(h, write_input(tmp_path, 'i.bin', b'x'))
    assert r.outcome == triage.ERROR and r.reason == 'load'
    assert 'no engine for you' in r.description
    assert not r.crashed and r.pc is None
    assert r.signature == 'error'


def test_instruction_budget_stops_an_endless_loop(tmp_path):
    h = write(tmp_path, 'loop.py', LOOP)
    inp = write_input(tmp_path, 'i.bin', b'x')
    r = triage.triage_input(h, inp, max_instructions=5000, timeout=60)
    assert r.outcome == triage.TIMEOUT
    assert r.reason == 'instructions'
    assert r.instructions == 5001           # the one that tripped the budget
    assert r.pc is not None
    assert r.signature == f'timeout@{r.pc:#x}'


def test_wall_clock_backstop_stops_an_endless_loop(tmp_path):
    h = write(tmp_path, 'loop.py', LOOP)
    inp = write_input(tmp_path, 'i.bin', b'x')
    # No instruction budget at all: only the clock can stop this.
    r = triage.triage_input(h, inp, max_instructions=0, timeout=0.5)
    assert r.outcome == triage.TIMEOUT
    assert r.reason == 'wall'
    assert r.wall_time < 20                 # generously loose; it should be ~0.5
    assert r.instructions > 1000


def test_each_input_gets_a_fresh_engine(tmp_path, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    first = triage.triage_input(h, crash_inputs[0])
    triage.triage_input(h, crash_inputs[2])
    again = triage.triage_input(h, crash_inputs[0])
    assert (again.pc, again.fault.address, again.instructions) == \
           (first.pc, first.fault.address, first.instructions)


# ---------------------------------------------------------------------------
# Batches and grouping

def test_grouping_counts_and_representative(tmp_path, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    report = triage.triage_inputs(h, crash_inputs)
    assert len(report.results) == 3
    assert report.counts() == {triage.CRASH: 3}
    assert len(report.groups) == 2 and len(report.crash_groups) == 2

    big, small = report.groups[0], report.groups[1]
    assert big.signature == 'UC_ERR_READ_UNMAPPED@0x1000'
    assert big.count == 2                       # a.bin and b.bin share the PC
    assert sorted(os.path.basename(p) for p in big.inputs) == ['a.bin', 'b.bin']
    # a.bin is 2 bytes, b.bin is 3: the smallest input represents the group.
    assert os.path.basename(big.representative) == 'a.bin'
    assert big.instruction.text == 'mov rbx, qword ptr [rax]'
    assert small.signature == 'UC_ERR_READ_UNMAPPED@0x1010' and small.count == 1
    assert report.group_for('UC_ERR_READ_UNMAPPED@0x1000') is big


def test_signature_function_is_replaceable(tmp_path, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    coarse = triage.triage_inputs(h, crash_inputs, signature=triage.signature_kind)
    assert [g.signature for g in coarse.groups] == ['UC_ERR_READ_UNMAPPED']
    assert coarse.groups[0].count == 3

    fine = triage.triage_inputs(h, crash_inputs,
                                signature=triage.signature_kind_pc_target)
    assert len(fine.groups) == 3                # the two 0x1000 inputs split
    assert 'UC_ERR_READ_UNMAPPED@0x1000->0xa000' in {g.signature for g in fine.groups}

    custom = triage.triage_inputs(h, crash_inputs, signature=lambda r: 'all-one')
    assert [g.signature for g in custom.groups] == ['all-one']
    assert custom.groups[0].count == 3


def test_mixed_batch_groups_every_outcome_crashes_first(tmp_path):
    h = write(tmp_path, 'mixed.py', MIXED)
    inputs = [write_input(tmp_path, 'exit.bin', b'\x00'),
              write_input(tmp_path, 'loop.bin', b'\x02'),
              write_input(tmp_path, 'crash.bin', b'\x01'),
              write_input(tmp_path, 'crash2.bin', b'\x01\x01')]
    report = triage.triage_inputs(h, inputs, max_instructions=2000, timeout=30)
    assert report.counts() == {triage.OK: 1, triage.TIMEOUT: 1, triage.CRASH: 2}
    # Crashes first, then timeouts, then the clean runs; ties by size.
    assert [g.outcome for g in report.groups] == [triage.CRASH, triage.TIMEOUT, triage.OK]
    assert report.groups[0].count == 2
    assert os.path.basename(report.groups[0].representative) == 'crash.bin'
    assert report.groups[1].signature == 'timeout@0x1020'


def test_collect_inputs_walks_directories_and_skips_fuzzer_files(tmp_path):
    d = tmp_path / 'crashes'
    d.mkdir()
    (d / 'README.txt').write_text('afl bookkeeping')
    (d / '.hidden').write_bytes(b'x')
    for name in ('id:000001', 'id:000000'):
        (d / name).write_bytes(b'x')
    lone = tmp_path / 'lone.bin'
    lone.write_bytes(b'y')

    found = triage.collect_inputs([str(d), str(lone)])
    assert [os.path.basename(p) for p in found] == ['id:000000', 'id:000001', 'lone.bin']
    assert len(triage.collect_inputs([str(d)], limit=1)) == 1
    with pytest.raises(FileNotFoundError):
        triage.collect_inputs([str(tmp_path / 'nope')])


def test_limit_applies_to_the_batch(tmp_path, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    report = triage.triage_inputs(h, [os.path.dirname(crash_inputs[0])], limit=2)
    assert len(report.results) == 2


def test_progress_callback_sees_every_input(tmp_path, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    seen = []
    triage.triage_inputs(h, crash_inputs, progress=seen.append)
    assert [r.name for r in seen] == ['a.bin', 'b.bin', 'c.bin']


# ---------------------------------------------------------------------------
# JSON and the command line

def test_json_shape(tmp_path, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    report = triage.triage_inputs(h, crash_inputs, max_instructions=1234, timeout=5)
    doc = json.loads(report.to_json())

    assert doc['harness'] == os.path.abspath(h)
    assert doc['inputs'] == 3
    assert doc['counts'] == {'crash': 3}
    assert doc['limits'] == {'max_instructions': 1234, 'timeout': 5.0}

    g = doc['groups'][0]
    assert set(g) >= {'signature', 'outcome', 'kind', 'count', 'pc', 'pc_hex',
                      'instruction', 'fault', 'inputs', 'representative'}
    assert g['count'] == 2 and g['pc'] == 0x1000 and g['pc_hex'] == '0x1000'
    assert g['instruction']['text'] == 'mov rbx, qword ptr [rax]'
    assert g['fault']['kind'] == 'UC_ERR_READ_UNMAPPED'
    assert g['fault']['address_hex'] == '0x9000'
    assert os.path.basename(g['representative']) == 'a.bin'

    r = doc['results'][0]
    assert set(r) >= {'path', 'name', 'size', 'outcome', 'reason', 'kind', 'pc',
                      'pc_hex', 'instruction', 'fault', 'registers', 'stack',
                      'instructions', 'wall_time', 'signature'}
    assert r['registers']['RAX'] == 0x9000
    assert r['stack']['address_hex'] == '0x7ff0'
    assert isinstance(r['stack']['data'], str)          # hex, JSON-safe


def test_cli_prints_table_writes_json_and_fails_on_crash(tmp_path, capsys, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    out_json = tmp_path / 'report.json'
    code = triage.main(['--harness', h,
                        '--inputs', os.path.dirname(crash_inputs[0]),
                        '--json', str(out_json)])
    assert code == 1                                    # crashes -> non-zero, for CI
    text = capsys.readouterr().out
    assert '3 inputs through crash.py: 3 crash' in text
    assert 'COUNT  OUTCOME' in text and 'REPRESENTATIVE' in text
    assert 'UC_ERR_READ_UNMAPPED' in text
    assert 'a.bin' in text and 'INPUT' in text          # per-input detail table
    doc = json.loads(out_json.read_text())
    assert len(doc['groups']) == 2

    code = triage.main(['--harness', h, '--inputs', crash_inputs[0], '--quiet',
                        '--signature', 'kind'])
    text = capsys.readouterr().out
    assert code == 1 and 'INPUT ' not in text          # --quiet drops the detail


def test_cli_exit_zero_when_nothing_crashes(tmp_path, capsys):
    h = write(tmp_path, 'clean.py', CLEAN)
    inp = write_input(tmp_path, 'in.bin', b'abcd')
    assert triage.main(['--harness', h, '--inputs', inp]) == 0
    assert 'ok' in capsys.readouterr().out


def test_cli_exit_two_when_the_harness_is_broken(tmp_path, capsys):
    h = write(tmp_path, 'broken.py', BROKEN)
    inp = write_input(tmp_path, 'in.bin', b'abcd')
    assert triage.main(['--harness', h, '--inputs', inp]) == 2
    assert 'error' in capsys.readouterr().out


def test_cli_verbose_shows_registers_and_stack(tmp_path, capsys, crash_inputs):
    h = write(tmp_path, 'crash.py', CRASH)
    triage.main(['--harness', h, '--inputs', crash_inputs[0], '--quiet', '--verbose'])
    text = capsys.readouterr().out
    assert 'fault: UC_ERR_READ_UNMAPPED touching 0x9000' in text
    assert 'RAX=0x9000' in text
    assert '0x00007ff0|+0x000:' in text


def test_triage_module_does_not_need_ghidra():
    """Importing triage must not drag in ghidratrace (commands/console do)."""
    import subprocess
    import sys
    code = ('import sys;'
            'sys.modules["ghidratrace"] = None;'
            'import ghidraunicorn.triage as t;'
            'assert "ghidraunicorn.commands" not in sys.modules;'
            'assert "ghidraunicorn.console" not in sys.modules;'
            'print("ok")')
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = subprocess.run([sys.executable, '-c', code], capture_output=True,
                       text=True, cwd=root)
    assert p.returncode == 0, p.stderr
    assert 'ok' in p.stdout


# ---------------------------------------------------------------------------
# The real thing

def _simple_sample():
    afl = os.getenv('AFL_UNICORN_DIR')
    if not afl:
        pytest.skip('AFL_UNICORN_DIR is not set')
    simple = os.path.join(afl, 'unicorn_mode', 'samples', 'simple')
    inputs = os.path.join(simple, 'sample_inputs')
    if not os.path.isdir(inputs) or not os.path.isfile(os.path.join(simple, 'simple_target.bin')):
        pytest.skip(f'afl-unicorn simple sample not found under {simple}')
    return simple, inputs


def test_real_mips_sample_inputs_all_run_clean():
    simple, inputs = _simple_sample()
    harness = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'examples', 'afl_unicorn_simple.py')
    report = triage.triage_inputs(harness, [inputs], max_instructions=100_000, timeout=30)
    assert len(report.results) == 5
    assert [r.outcome for r in report.results] == [triage.OK] * 5
    assert not report.crashes and not report.crash_groups
    # Every sample input walks main() to the same exit, so they are one group.
    assert len(report.groups) == 1
    assert report.groups[0].count == 5
    for r in report.results:
        assert r.pc == 0x00100000 + 0xf0      # the delay slot of main's return
        assert r.instructions < 100
        assert r.registers['sp'] == 0x00210000   # main restored the frame


# ---------------------------------------------------------------------------
# tools/import_triage.py, the half that needs no Ghidra

def _import_tool():
    import importlib.util
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, 'tools', 'import_triage.py')
    spec = importlib.util.spec_from_file_location('import_triage', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_import_triage_plans_one_annotation_per_crash_address(tmp_path, capsys, crash_inputs):
    tool = _import_tool()
    h = write(tmp_path, 'crash.py', CRASH)
    out_json = tmp_path / 'report.json'
    triage.main(['--harness', h, '--inputs'] + crash_inputs
                + ['--quiet', '--json', str(out_json)])
    capsys.readouterr()

    doc = tool.load_report(str(out_json))
    plan = tool.plan_annotations(doc)
    assert [address for address, _, _, _ in plan] == [0x1000, 0x1010]
    assert plan[0][1] == 2 and plan[0][2] == 'crash'
    text = plan[0][3]
    assert tool.TAG in text
    assert 'UC_ERR_READ_UNMAPPED' in text and '0x9000' in text
    assert 'replay: a.bin' in text

    # An offset shifts emulated addresses onto the program's image base.
    assert [a for a, _, _, _ in tool.plan_annotations(doc, offset=0x400000)] \
        == [0x401000, 0x401010]

    # Re-running replaces the previous run's lines and keeps anyone else's.
    assert tool.strip_tagged('mine\n' + text) == 'mine'

    assert tool.main(['--json', str(out_json), '--dry-run']) == 0
    printed = capsys.readouterr().out
    assert '0x00001000  [2 crash]' in printed and tool.TAG in printed


def test_import_triage_skips_non_crashes_unless_asked(tmp_path, capsys):
    tool = _import_tool()
    h = write(tmp_path, 'clean.py', CLEAN)
    inp = write_input(tmp_path, 'in.bin', b'abcd')
    out_json = tmp_path / 'report.json'
    triage.main(['--harness', h, '--inputs', inp, '--quiet', '--json', str(out_json)])
    capsys.readouterr()

    doc = tool.load_report(str(out_json))
    assert tool.plan_annotations(doc) == []
    assert len(tool.plan_annotations(doc, crashes_only=False)) == 1


def test_import_triage_rejects_a_file_that_is_not_a_report(tmp_path):
    tool = _import_tool()
    p = tmp_path / 'other.json'
    p.write_text('{"hello": 1}')
    with pytest.raises(SystemExit):
        tool.load_report(str(p))


# ---- triage runs harnesses that leave the binary ---------------------------

SYSCALL_HARNESS = '''
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP

START = 0x1000
STDIN = b"triaged"

def create(input_file=None):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_map(0x2000, 0x1000)
    # read(0, 0x2000, 8) ; then exit(0)
    uc.mem_write(0x1000, bytes.fromhex(
        "4831c0" "4831ff" "48c7c600200000" "48c7c208000000" "0f05"
        "48c7c03c000000" "4831ff" "0f05"))
    uc.reg_write(UC_X86_REG_RIP, 0x1000)
    uc.reg_write(UC_X86_REG_RSP, 0x2f00)
    return uc
'''

UNKNOWN_CALL_HARNESS = SYSCALL_HARNESS.replace(
    '"4831c0" "4831ff"', '"48c7c0adde0000" "4831ff"')


def write_harness(tmp_path, text, name='h.py'):
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def test_triage_services_a_harness_that_uses_system_calls(tmp_path):
    """Without the layer the trap faults, and the input is triaged as a
    crash in the program rather than as a harness that left the binary."""
    harness = write_harness(tmp_path, SYSCALL_HARNESS)
    sample = tmp_path / 'in.bin'
    sample.write_bytes(b'abcd')
    result = triage.triage_input(harness, str(sample))
    assert result.outcome == triage.OK, result.description
    assert result.unhandled_calls == ()


def test_triage_can_be_told_not_to(tmp_path):
    harness = write_harness(tmp_path, SYSCALL_HARNESS)
    sample = tmp_path / 'in.bin'
    sample.write_bytes(b'abcd')
    result = triage.triage_input(harness, str(sample),
                                 syscalls=False, stubs=False)
    assert result.outcome != triage.OK, 'the trap was serviced anyway'


def test_an_unserviced_call_is_reported(tmp_path):
    harness = write_harness(tmp_path, UNKNOWN_CALL_HARNESS)
    sample = tmp_path / 'in.bin'
    sample.write_bytes(b'abcd')
    result = triage.triage_input(harness, str(sample))
    assert 0xdead in result.unhandled_calls


def test_the_report_says_when_calls_went_unserviced(tmp_path):
    import io
    harness = write_harness(tmp_path, UNKNOWN_CALL_HARNESS)
    sample = tmp_path / 'in.bin'
    sample.write_bytes(b'abcd')
    report = triage.triage_inputs(harness, [str(sample)])
    out = io.StringIO()
    triage.print_report(report, stream=out)
    assert 'went unserviced' in out.getvalue()
    assert '57005' in out.getvalue()        # 0xdead


def test_nothing_is_said_when_every_call_was_serviced(tmp_path):
    import io
    harness = write_harness(tmp_path, SYSCALL_HARNESS)
    sample = tmp_path / 'in.bin'
    sample.write_bytes(b'abcd')
    report = triage.triage_inputs(harness, [str(sample)])
    out = io.StringIO()
    triage.print_report(report, stream=out)
    assert 'went unserviced' not in out.getvalue()
