"""Architecture tables: Unicorn arch/mode <-> Ghidra language, register names.

Register names are Ghidra's SLEIGH names (case matters only for display; the
trace matches them case-insensitively). Each entry maps the Ghidra register
name to the Unicorn register constant and the register's size in bytes, which
is the width Ghidra expects when the value is pushed into the trace.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from unicorn import (UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_MIPS, UC_ARCH_X86,
                     UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_MODE_BIG_ENDIAN,
                     UC_MODE_LITTLE_ENDIAN, UC_MODE_MIPS32, UC_MODE_MIPS64,
                     UC_MODE_THUMB)
from unicorn import arm64_const as a64
from unicorn import arm_const as arm
from unicorn import mips_const as mips
from unicorn import x86_const as x86


@dataclass(frozen=True)
class Reg:
    name: str
    uc: int
    size: int


@dataclass(frozen=True)
class ArchSpec:
    #: afl-unicorn style key: x64, x86, arm64le, armle, armlethumb, mips, ...
    key: str
    uc_arch: int
    uc_mode: int
    language: str
    compiler: str
    endian: str          # 'little' | 'big'
    bits: int
    regs: Tuple[Reg, ...]
    pc: str
    sp: str
    #: Capstone (arch, mode) for instruction decoding, or None.
    cs: Optional[Tuple[int, int]] = None
    #: Mnemonics that transfer control to a subroutine (for step-over).
    call_mnemonics: Tuple[str, ...] = ()
    #: Extra register values Ghidra needs for correct disassembly context.
    context: Dict[str, int] = field(default_factory=dict)

    @property
    def ptr_size(self) -> int:
        return self.bits // 8

    def reg(self, name: str) -> Reg:
        lname = name.lower()
        for r in self.regs:
            if r.name.lower() == lname:
                return r
        raise KeyError(name)

    def has_reg(self, name: str) -> bool:
        lname = name.lower()
        return any(r.name.lower() == lname for r in self.regs)


def _regs(names: List[str], consts, size: int, prefix: str) -> List[Reg]:
    return [Reg(n, getattr(consts, f'{prefix}{n.upper()}'), size) for n in names]


def _x86_64() -> ArchSpec:
    gp = ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
          'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RIP']
    regs = _regs(gp, x86, 8, 'UC_X86_REG_')
    regs.append(Reg('rflags', x86.UC_X86_REG_EFLAGS, 8))
    regs += _regs(['CS', 'SS', 'DS', 'ES', 'FS', 'GS'], x86, 2, 'UC_X86_REG_')
    regs.append(Reg('FS_OFFSET', x86.UC_X86_REG_FS_BASE, 8))
    regs.append(Reg('GS_OFFSET', x86.UC_X86_REG_GS_BASE, 8))
    return ArchSpec('x64', UC_ARCH_X86, UC_MODE_64, 'x86:LE:64:default', 'gcc',
                    'little', 64, tuple(regs), 'RIP', 'RSP',
                    cs=_cs('CS_ARCH_X86', 'CS_MODE_64'), call_mnemonics=('call',))


def _x86_32() -> ArchSpec:
    gp = ['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP', 'EIP']
    regs = _regs(gp, x86, 4, 'UC_X86_REG_')
    regs.append(Reg('eflags', x86.UC_X86_REG_EFLAGS, 4))
    regs += _regs(['CS', 'SS', 'DS', 'ES', 'FS', 'GS'], x86, 2, 'UC_X86_REG_')
    return ArchSpec('x86', UC_ARCH_X86, UC_MODE_32, 'x86:LE:32:default', 'gcc',
                    'little', 32, tuple(regs), 'EIP', 'ESP',
                    cs=_cs('CS_ARCH_X86', 'CS_MODE_32'), call_mnemonics=('call',))


def _arm64(big: bool) -> ArchSpec:
    names = [f'x{i}' for i in range(31)]
    regs = _regs(names, a64, 8, 'UC_ARM64_REG_')
    regs.append(Reg('sp', a64.UC_ARM64_REG_SP, 8))
    regs.append(Reg('pc', a64.UC_ARM64_REG_PC, 8))
    regs.append(Reg('nzcv', a64.UC_ARM64_REG_NZCV, 4))
    endian = 'big' if big else 'little'
    mode = UC_MODE_ARM | (UC_MODE_BIG_ENDIAN if big else UC_MODE_LITTLE_ENDIAN)
    lang = 'AARCH64:BE:64:v8A' if big else 'AARCH64:LE:64:v8A'
    return ArchSpec('arm64be' if big else 'arm64le', UC_ARCH_ARM64, mode, lang,
                    'default', endian, 64, tuple(regs), 'pc', 'sp',
                    cs=_cs('CS_ARCH_ARM64', 'CS_MODE_ARM'),
                    call_mnemonics=('bl', 'blr'))


def _arm(big: bool, thumb: bool) -> ArchSpec:
    names = [f'r{i}' for i in range(13)]
    regs = _regs(names, arm, 4, 'UC_ARM_REG_')
    regs += [Reg('sp', arm.UC_ARM_REG_SP, 4), Reg('lr', arm.UC_ARM_REG_LR, 4),
             Reg('pc', arm.UC_ARM_REG_PC, 4), Reg('cpsr', arm.UC_ARM_REG_CPSR, 4)]
    endian = 'big' if big else 'little'
    mode = (UC_MODE_THUMB if thumb else UC_MODE_ARM) | \
        (UC_MODE_BIG_ENDIAN if big else UC_MODE_LITTLE_ENDIAN)
    lang = f"ARM:{'BE' if big else 'LE'}:32:{'v8T' if thumb else 'v8'}"
    key = 'arm' + ('be' if big else 'le') + ('thumb' if thumb else '')
    cs_mode = 'CS_MODE_THUMB' if thumb else 'CS_MODE_ARM'
    return ArchSpec(key, UC_ARCH_ARM, mode, lang, 'default', endian, 32,
                    tuple(regs), 'pc', 'sp', cs=_cs('CS_ARCH_ARM', cs_mode),
                    call_mnemonics=('bl', 'blx'),
                    context={'TMode': 1} if thumb else {})


_MIPS_GP = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
            't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
            's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
            't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra']


def _mips(big: bool, bits: int) -> ArchSpec:
    size = bits // 8
    regs = _regs(_MIPS_GP, mips, size, 'UC_MIPS_REG_')
    regs += [Reg('pc', mips.UC_MIPS_REG_PC, size),
             Reg('hi', mips.UC_MIPS_REG_HI, size),
             Reg('lo', mips.UC_MIPS_REG_LO, size)]
    endian = 'big' if big else 'little'
    mode = (UC_MODE_MIPS64 if bits == 64 else UC_MODE_MIPS32) | \
        (UC_MODE_BIG_ENDIAN if big else UC_MODE_LITTLE_ENDIAN)
    lang = f"MIPS:{'BE' if big else 'LE'}:{bits}:default"
    key = 'mips' + ('64' if bits == 64 else '') + ('' if big else 'el')
    cs_mode = ('CS_MODE_MIPS64' if bits == 64 else 'CS_MODE_MIPS32',
               'CS_MODE_BIG_ENDIAN' if big else 'CS_MODE_LITTLE_ENDIAN')
    return ArchSpec(key, UC_ARCH_MIPS, mode, lang, 'default', endian, bits,
                    tuple(regs), 'pc', 'sp', cs=_cs('CS_ARCH_MIPS', *cs_mode),
                    call_mnemonics=('jal', 'jalr', 'bal', 'jalx'))


def _cs(arch_name: str, *mode_names: str) -> Optional[Tuple[int, int]]:
    try:
        import capstone
    except ImportError:
        return None
    mode = 0
    for m in mode_names:
        mode |= getattr(capstone, m)
    return getattr(capstone, arch_name), mode


SPECS: Dict[str, ArchSpec] = {}
for _s in (_x86_64(), _x86_32(),
           _arm64(False), _arm64(True),
           _arm(False, False), _arm(True, False), _arm(False, True), _arm(True, True),
           _mips(True, 32), _mips(False, 32), _mips(True, 64), _mips(False, 64)):
    SPECS[_s.key] = _s

# afl-unicorn dump names that differ from ours.
ALIASES = {'arm64': 'arm64le', 'arm': 'armle', 'x86_64': 'x64', 'amd64': 'x64',
           'i386': 'x86', 'mips32': 'mips', 'mips32el': 'mipsel', 'aarch64': 'arm64le'}


def spec_for_key(key: str) -> ArchSpec:
    k = ALIASES.get(key.lower(), key.lower())
    if k not in SPECS:
        raise KeyError(f"Unknown architecture '{key}'. Known: {', '.join(sorted(SPECS))}")
    return SPECS[k]


def spec_for_uc(uc) -> ArchSpec:
    """Pick the spec matching a live Uc instance's arch and mode."""
    arch = uc.ctl_get_arch() if hasattr(uc, 'ctl_get_arch') else uc._arch
    mode = uc.ctl_get_mode() if hasattr(uc, 'ctl_get_mode') else uc._mode
    big = bool(mode & UC_MODE_BIG_ENDIAN)
    if arch == UC_ARCH_X86:
        return SPECS['x64'] if mode & UC_MODE_64 else SPECS['x86']
    if arch == UC_ARCH_ARM64:
        return SPECS['arm64be' if big else 'arm64le']
    if arch == UC_ARCH_ARM:
        thumb = bool(mode & UC_MODE_THUMB)
        return SPECS['arm' + ('be' if big else 'le') + ('thumb' if thumb else '')]
    if arch == UC_ARCH_MIPS:
        bits = 64 if mode & UC_MODE_MIPS64 else 32
        return SPECS['mips' + ('64' if bits == 64 else '') + ('' if big else 'el')]
    raise KeyError(f"Unsupported Unicorn arch {arch} mode {mode:#x}")
