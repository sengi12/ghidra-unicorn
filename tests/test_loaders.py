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
