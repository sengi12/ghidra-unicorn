import json
import os
import zlib

import pytest

from ghidraunicorn import loaders

HARNESS = '''
from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, Uc
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0

START = 0x400000
END = 0x400008
EXITS = [0x400010]
MODULES = [("libfoo.so", 0x400000, 0x1000)]

def create(input_file=None):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x400000, 0x1000)
    # add x0, x0, #1 ; add x0, x0, #1 ; nop
    uc.mem_write(0x400000, bytes.fromhex("00040091" "00040091" "1f2003d5"))
    uc.mem_map(0x7f0000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    uc.reg_write(UC_ARM64_REG_SP, 0x7f1000)
    uc.reg_write(UC_ARM64_REG_X0, 5)
    if input_file:
        uc.mem_write(0x7f0000, open(input_file, "rb").read())
    return uc
'''


def test_load_harness(tmp_path):
    h = tmp_path / 'h.py'
    h.write_text(HARNESS)
    inp = tmp_path / 'in.bin'
    inp.write_bytes(b'hello')
    loaded = loaders.load_harness(str(h), str(inp))
    t = loaded.target
    assert t.spec.key == 'arm64le'
    assert t.pc() == 0x400000 and t.end == 0x400008 and 0x400010 in t.exits
    assert loaded.modules == [loaders.Module('libfoo.so', 0x400000, 0x1000)]
    assert t.read(0x7f0000, 5) == b'hello'
    ev = t.run()
    assert ev.reason == 'exit' and t.reg_read('x0') == 7


def test_harness_overrides_and_defaults(tmp_path):
    h = tmp_path / 'h.py'
    h.write_text(HARNESS.replace('MODULES = ', 'IGNORED = '))
    loaded = loaders.load_harness(str(h), None, start=0x400004, end=None, image='/bin/foo')
    t = loaded.target
    assert t.pc() == 0x400004 and t.end == 0x400008
    # No MODULES: one module named after the image over the executable regions.
    assert loaded.modules == [loaders.Module('/bin/foo', 0x400000, 0x1000)]


def test_harness_tuple_return(tmp_path):
    h = tmp_path / 'h.py'
    h.write_text(HARNESS.replace('    return uc', '    return uc, 0x400004, 0x400008'))
    t = loaders.load_harness(str(h)).target
    assert t.pc() == 0x400004 and t.end == 0x400008


def test_harness_without_create(tmp_path):
    h = tmp_path / 'h.py'
    h.write_text('x = 1\n')
    with pytest.raises(ValueError):
        loaders.load_harness(str(h))


def _write_context(dirpath, arch='x64'):
    code = bytes.fromhex('48ffc0' '48ffc0' 'ebfe')      # inc rax; inc rax; jmp $
    seg1 = 'seg_code'
    seg2 = 'seg_stack'
    with open(os.path.join(dirpath, seg1), 'wb') as f:
        f.write(zlib.compress(code + b'\x00' * (0x1000 - len(code))))
    index = {
        'arch': {'arch': arch},
        'regs': {'rax': 40, 'rip': 0x401000, 'rsp': 0x7fff0000, 'efl': 0x202, 'bogus': 1},
        'segments': [
            {'name': '/tmp/prog', 'start': 0x401000, 'end': 0x402000,
             'permissions': {'r': True, 'w': False, 'x': True}, 'content_file': seg1},
            {'name': '/tmp/prog', 'start': 0x402000, 'end': 0x403000,
             'permissions': {'r': True, 'w': True, 'x': False}, 'content_file': ''},
            {'name': '[stack]', 'start': 0x7ffe0000, 'end': 0x7fff0000,
             'permissions': {'r': True, 'w': True, 'x': False}, 'content_file': ''},
            # Overlaps the first segment: must not break mapping.
            {'name': '/tmp/prog', 'start': 0x401800, 'end': 0x402800,
             'permissions': {'r': True, 'w': True, 'x': False}, 'content_file': ''},
        ],
    }
    with open(os.path.join(dirpath, '_index.json'), 'w') as f:
        json.dump(index, f)


def test_load_context(tmp_path):
    _write_context(str(tmp_path))
    loaded = loaders.load_context(str(tmp_path), end=0x401006)
    t = loaded.target
    assert t.spec.key == 'x64'
    assert t.pc() == 0x401000 and t.reg_read('rax') == 40 and t.reg_read('rflags') == 0x202
    # Unicorn reports adjacent maps separately; check coverage instead.
    covered = set()
    for s, e, _ in t.regions():
        covered.update(range(s, e + 1, 0x1000))
    assert {0x401000, 0x402000, 0x7ffe0000, 0x7ffef000} <= covered and 0x403000 not in covered
    assert loaded.modules == [loaders.Module('/tmp/prog', 0x401000, 0x2000)]
    ev = t.run()
    assert ev.reason == 'exit' and t.reg_read('rax') == 42


def test_load_context_missing_index(tmp_path):
    with pytest.raises(ValueError):
        loaders.load_context(str(tmp_path))


def test_mips_dump_register_aliases(tmp_path):
    (tmp_path / '_index.json').write_text(json.dumps({
        'arch': {'arch': 'mips'},
        'regs': {'0': 0, 'fp': 0x1234, 'pc': 0x400000, 'sp': 0x7000},
        'segments': [{'name': 'x', 'start': 0x400000, 'end': 0x401000,
                      'permissions': {'r': True, 'w': False, 'x': True}}],
    }))
    t = loaders.load_context(str(tmp_path)).target
    assert t.spec.key == 'mips' and t.reg_read('s8') == 0x1234 and t.pc() == 0x400000


# ---- standing in for the operating system ---------------------------------

def test_install_layers_puts_both_under_a_harness(tmp_path):
    h = tmp_path / 'h.py'
    h.write_text(HARNESS)
    loaded = loaders.load_harness(str(h), None)
    installed = loaders.install_layers(loaded, stdin=b'from the test')
    assert set(installed) == {'syscalls', 'stubs'}
    assert loaded.target.syscalls is installed['syscalls']
    assert loaded.target.stubs is installed['stubs']
    assert installed['syscalls'].files[0].data == b'from the test'


def test_a_harness_can_opt_out(tmp_path):
    h = tmp_path / 'h.py'
    h.write_text(HARNESS + '\nSYSCALLS = False\nSTUBS = False\n')
    loaded = loaders.load_harness(str(h), None)
    assert loaders.install_layers(loaded) == {}
    assert loaded.target.syscalls is None and loaded.target.stubs is None


def test_a_harness_can_supply_its_own_input_and_files(tmp_path):
    h = tmp_path / 'h.py'
    h.write_text(HARNESS + '\nSTDIN = "typed in"\nFILES = {"/conf": b"k=v"}\n')
    loaded = loaders.load_harness(str(h), None)
    layer = loaders.install_layers(loaded)['syscalls']
    assert layer.files[0].data == b'typed in'
    assert layer.contents == {'/conf': b'k=v'}


def test_the_caller_wins_over_the_harness(tmp_path):
    h = tmp_path / 'h.py'
    h.write_text(HARNESS + '\nSTDIN = "from the harness"\n')
    loaded = loaders.load_harness(str(h), None)
    layer = loaders.install_layers(loaded, stdin=b'from the caller')['syscalls']
    assert layer.files[0].data == b'from the caller'


def test_stubs_bind_from_a_symbol_table(tmp_path):
    from ghidraunicorn.symbols import Symbol, SymbolTable
    h = tmp_path / 'h.py'
    h.write_text(HARNESS)
    loaded = loaders.load_harness(str(h), None)
    table = SymbolTable([Symbol('malloc', 0x400004, 4), Symbol('main', 0x400000, 4)])
    layer = loaders.install_layers(loaded, symbols=table)['stubs']
    assert layer.bound == {0x400004: 'malloc'}


def test_the_example_harness_runs_through_both_layers():
    """End to end on the example: no libc, no kernel, and it still works.

    This is the whole point of the two layers, so it is worth one test that
    goes all the way through rather than only the parts.
    """
    import sys
    from ghidraunicorn.symbols import Symbol, SymbolTable

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, 'examples', 'syscalls_and_stubs.py')
    if not os.path.isfile(path):
        pytest.skip('example harness not in this checkout')
    loaded = loaders.load_harness(path, None)
    module = loaded.module
    table = SymbolTable([Symbol(n, a, 1) for n, a in module.stubs_at().items()])
    printed = []
    layers = loaders.install_layers(
        loaded, symbols=table, stdin=b'hello from the test\n',
        on_output=lambda fd, data: printed.append(data))
    t = loaded.target

    ev = t.run()
    assert ev.reason == 'exit' and t.terminated
    assert printed == [b'hello from the test\n']
    names = sorted({r.name for r in layers['syscalls'].records})
    assert names == ['exit', 'read', 'write']
    assert layers['stubs'].calls == {'malloc': 1, 'strlen': 1}

    # And all of it rewinds: go back before the read and run it again.
    read = [r for r in layers['syscalls'].records if r.name == 'read'][0]
    t.goto_icount(read.icount)
    assert not t.terminated
    assert layers['syscalls'].files[0].offset == 0
    printed.clear()
    assert t.run().reason == 'exit'
    assert printed == [b'hello from the test\n'], 'the re-run read different bytes'
