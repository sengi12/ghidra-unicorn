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
class Flag:
    """A one-byte Ghidra flag register that is a bit of a wider register."""
    name: str
    source: str
    bit: int


@dataclass(frozen=True)
class Field:
    """A named bit field of a status register (not necessarily known to Ghidra)."""
    name: str
    bit: int
    width: int = 1
    #: value -> label, for enumerated fields such as the ARM mode bits
    names: Dict[int, str] = field(default_factory=dict)

    @property
    def mask(self) -> int:
        return ((1 << self.width) - 1) << self.bit

    def get(self, value: int) -> int:
        return (value >> self.bit) & ((1 << self.width) - 1)

    def set(self, value: int, v: int) -> int:
        if v < 0 or v >= (1 << self.width):
            raise ValueError(f'{self.name} is {self.width} bit(s); {v:#x} does not fit')
        return (value & ~self.mask) | (v << self.bit)

    def label(self, value: int) -> str:
        v = self.get(value)
        if self.names:
            return self.names.get(v, f'{v:#x}')
        return str(v) if self.width == 1 else f'{v:#x}'


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
    #: Ghidra's flag registers, derived from a status register.
    flags: Tuple[Flag, ...] = ()
    #: The status register the flags come from (for display).
    status: Optional[str] = None
    #: Every bit field of the status register, for the console and context.
    fields: Tuple[Field, ...] = ()

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

    def flag(self, name: str) -> Optional[Flag]:
        lname = name.lower()
        for f in self.flags:
            if f.name.lower() == lname:
                return f
        return None

    def decode_flags(self, value: int) -> Dict[str, int]:
        return {f.name: (value >> f.bit) & 1 for f in self.flags}

    def set_flag(self, value: int, name: str, on: bool) -> int:
        f = self.flag(name)
        if f is None:
            raise KeyError(name)
        return (value | (1 << f.bit)) if on else (value & ~(1 << f.bit))

    def field(self, name: str) -> Optional[Field]:
        lname = name.lower()
        for f in self.fields:
            if f.name.lower() == lname:
                return f
        return None

    def decode_fields(self, value: int) -> List[Tuple[str, str]]:
        """[(name, label)] for every field of the status register, MSB first."""
        return [(f.name, f.label(value)) for f in self.fields]


def _regs(names: List[str], consts, size: int, prefix: str) -> List[Reg]:
    return [Reg(n, getattr(consts, f'{prefix}{n.upper()}'), size) for n in names]


_X86_FLAG_BITS = {'CF': 0, 'PF': 2, 'AF': 4, 'ZF': 6, 'SF': 7, 'TF': 8, 'IF': 9, 'DF': 10,
                  'OF': 11, 'NT': 14, 'RF': 16, 'VM': 17, 'AC': 18, 'VIF': 19, 'VIP': 20, 'ID': 21}
_ARM_FLAG_BITS = {'NG': 31, 'ZR': 30, 'CY': 29, 'OV': 28, 'Q': 27,
                  'GE4': 19, 'GE3': 18, 'GE2': 17, 'GE1': 16, 'TB': 5}
_A64_FLAG_BITS = {'NG': 31, 'ZR': 30, 'CY': 29, 'OV': 28}


def _flags(bits: Dict[str, int], source: str) -> Tuple[Flag, ...]:
    return tuple(Flag(n, source, b) for n, b in bits.items())


_ARM_MODES = {0x10: 'USR', 0x11: 'FIQ', 0x12: 'IRQ', 0x13: 'SVC', 0x16: 'MON', 0x17: 'ABT',
              0x1a: 'HYP', 0x1b: 'UND', 0x1f: 'SYS'}

# Full bit layouts (MSB first). Names follow the architecture manuals.
_X86_FIELDS = (Field('ID', 21), Field('VIP', 20), Field('VIF', 19), Field('AC', 18),
               Field('VM', 17), Field('RF', 16), Field('NT', 14), Field('IOPL', 12, 2),
               Field('OF', 11), Field('DF', 10), Field('IF', 9), Field('TF', 8),
               Field('SF', 7), Field('ZF', 6), Field('AF', 4), Field('PF', 2), Field('CF', 0))
_ARM_FIELDS = (Field('N', 31), Field('Z', 30), Field('C', 29), Field('V', 28), Field('Q', 27),
               Field('IT_lo', 25, 2), Field('J', 24), Field('GE', 16, 4), Field('IT_hi', 10, 6),
               Field('E', 9), Field('A', 8), Field('I', 7), Field('F', 6), Field('T', 5),
               Field('M', 0, 5, _ARM_MODES))
_A64_FIELDS = (Field('N', 31), Field('Z', 30), Field('C', 29), Field('V', 28))


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
                    cs=_cs('CS_ARCH_X86', 'CS_MODE_64'), call_mnemonics=('call',),
                    flags=_flags(_X86_FLAG_BITS, 'rflags'), status='rflags', fields=_X86_FIELDS)


def _x86_32() -> ArchSpec:
    gp = ['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP', 'EIP']
    regs = _regs(gp, x86, 4, 'UC_X86_REG_')
    regs.append(Reg('eflags', x86.UC_X86_REG_EFLAGS, 4))
    regs += _regs(['CS', 'SS', 'DS', 'ES', 'FS', 'GS'], x86, 2, 'UC_X86_REG_')
    return ArchSpec('x86', UC_ARCH_X86, UC_MODE_32, 'x86:LE:32:default', 'gcc',
                    'little', 32, tuple(regs), 'EIP', 'ESP',
                    cs=_cs('CS_ARCH_X86', 'CS_MODE_32'), call_mnemonics=('call',),
                    flags=_flags(_X86_FLAG_BITS, 'eflags'), status='eflags', fields=_X86_FIELDS)


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
                    call_mnemonics=('bl', 'blr'),
                    flags=_flags(_A64_FLAG_BITS, 'nzcv'), status='nzcv', fields=_A64_FIELDS)


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
                    context={'TMode': 1} if thumb else {},
                    flags=_flags(_ARM_FLAG_BITS, 'cpsr'), status='cpsr', fields=_ARM_FIELDS)


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
