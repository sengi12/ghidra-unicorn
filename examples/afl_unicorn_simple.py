"""Harness for afl-unicorn's `samples/simple` target, ghidra-unicorn style.

The fuzzing harness (simple_test_harness.py in afl-unicorn) sets up the
engine and immediately runs it. This file does only the set-up and hands the
engine to Ghidra, which then drives it. The layout is identical to the fuzzing
harness so what you see in the Debugger is what AFL fuzzes:

    code   at 0x00100000  simple_target.bin (MIPS32 big-endian, raw .text)
    stack  at 0x00200000
    input  at 0x00300000  the fuzz input

Point OPT_HARNESS at this file, OPT_INPUT at any file in sample_inputs/, and
import simple_target.bin into Ghidra as MIPS:BE:32 at base 0x100000 so the
module mapping lines up.

Set AFL_UNICORN_DIR if afl-unicorn is not checked out next to this repo.
"""
import os

from unicorn import UC_ARCH_MIPS, UC_MODE_BIG_ENDIAN, UC_MODE_MIPS32, Uc
from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_SP

CODE_ADDRESS = 0x00100000
CODE_SIZE_MAX = 0x00010000
STACK_ADDRESS = 0x00200000
STACK_SIZE = 0x00010000
DATA_ADDRESS = 0x00300000
DATA_SIZE_MAX = 0x00010000

START = CODE_ADDRESS
END = CODE_ADDRESS + 0xf4          # last instruction of main()


def _binary_path() -> str:
    env = os.getenv('AFL_UNICORN_DIR')
    candidates = []
    if env:
        candidates.append(os.path.join(env, 'unicorn_mode', 'samples', 'simple', 'simple_target.bin'))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, '..', '..', 'afl-unicorn', 'unicorn_mode',
                                   'samples', 'simple', 'simple_target.bin'))
    candidates.append(os.path.join(here, 'simple_target.bin'))
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    raise FileNotFoundError('simple_target.bin not found; set AFL_UNICORN_DIR')


MODULES = [(_binary_path(), CODE_ADDRESS, CODE_SIZE_MAX)]


def create(input_file=None) -> Uc:
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)

    with open(_binary_path(), 'rb') as f:
        code = f.read()
    if len(code) > CODE_SIZE_MAX:
        raise ValueError('binary is larger than the code region')
    uc.mem_map(CODE_ADDRESS, CODE_SIZE_MAX)
    uc.mem_write(CODE_ADDRESS, code)
    uc.reg_write(UC_MIPS_REG_PC, START)

    uc.mem_map(STACK_ADDRESS, STACK_SIZE)
    uc.reg_write(UC_MIPS_REG_SP, STACK_ADDRESS + STACK_SIZE)

    uc.mem_map(DATA_ADDRESS, DATA_SIZE_MAX)
    if input_file:
        with open(input_file, 'rb') as f:
            data = f.read()
        if len(data) > DATA_SIZE_MAX:
            raise ValueError('input is larger than the data region')
        uc.mem_write(DATA_ADDRESS, data)
    return uc
