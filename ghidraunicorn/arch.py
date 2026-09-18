"""Architecture tables: Unicorn arch/mode <-> Ghidra language, register names.

Register names are Ghidra's SLEIGH names (case matters only for display; the
trace matches them case-insensitively). Each entry maps the Ghidra register
name to the Unicorn register constant and the register's size in bytes, which
is the width Ghidra expects when the value is pushed into the trace.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from unicorn import (UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_M68K, UC_ARCH_MIPS,
                     UC_ARCH_PPC, UC_ARCH_RISCV, UC_ARCH_SPARC, UC_ARCH_TRICORE,
                     UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_MODE_ARM,
                     UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN, UC_MODE_MIPS32,
                     UC_MODE_MIPS64, UC_MODE_PPC32, UC_MODE_PPC64,
                     UC_MODE_RISCV32, UC_MODE_RISCV64, UC_MODE_SPARC32,
                     UC_MODE_SPARC64, UC_MODE_THUMB)
from unicorn import arm64_const as a64
from unicorn import arm_const as arm
from unicorn import m68k_const as m68k
from unicorn import mips_const as mips
from unicorn import ppc_const as ppc
from unicorn import riscv_const as riscv
from unicorn import sparc_const as sparc
from unicorn import tricore_const as tricore
from unicorn import x86_const as x86


@dataclass(frozen=True)
class Reg:
    name: str
    uc: int
    size: int


@dataclass(frozen=True)
class Flag:
    """A one-byte Ghidra flag register carved out of a wider register.

    Usually one bit, but Ghidra also defines a few several bits wide, such as
    m68k's interrupt level and PowerPC's `xer_count`, and those still fit in
    the byte Ghidra stores them in.
    """
    name: str
    source: str
    bit: int
    width: int = 1

    @property
    def mask(self) -> int:
        return ((1 << self.width) - 1) << self.bit

    def get(self, value: int) -> int:
        return (value >> self.bit) & ((1 << self.width) - 1)

    def set(self, value: int, v: int) -> int:
        if v < 0 or v >= (1 << self.width):
            raise ValueError(f'{self.name} is {self.width} bit(s); {v:#x} does not fit')
        return (value & ~self.mask) | (v << self.bit)


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
    #: Mnemonics that return from one (for reverse step-over). An entry with
    #: a space in it is matched against the operands as well, because
    #: several architectures return through an ordinary instruction rather
    #: than a dedicated one: ARM's `bx lr` is an indirect branch, `pop
    #: {r4, pc}` is a load, and MIPS's `jr $ra` is a jump. Every spelling
    #: here is what Capstone actually emits for that encoding, not what the
    #: manual calls it.
    return_mnemonics: Tuple[str, ...] = ()
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

    def is_call(self, mnemonic: str, operands: str = '') -> bool:
        return mnemonic.lower() in self.call_mnemonics

    def is_return(self, mnemonic: str, operands: str = '') -> bool:
        mnemonic, operands = mnemonic.lower(), operands.lower()
        for entry in self.return_mnemonics:
            if ' ' in entry:
                want_mnem, want_ops = entry.split(None, 1)
                if mnemonic == want_mnem and want_ops in operands:
                    return True
            elif mnemonic == entry:
                return True
        return False

    def flag(self, name: str) -> Optional[Flag]:
        lname = name.lower()
        for f in self.flags:
            if f.name.lower() == lname:
                return f
        return None

    def decode_flags(self, value: int) -> Dict[str, int]:
        return {f.name: f.get(value) for f in self.flags}

    def set_flag(self, value: int, name: str, on) -> int:
        f = self.flag(name)
        if f is None:
            raise KeyError(name)
        return f.set(value, int(on))

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


# What Capstone emits for each architecture's return encodings, checked
# against a real disassembly rather than taken from the manuals.
_X86_RETURNS = ('ret', 'retf', 'iret', 'iretd', 'iretq')
_ARM_RETURNS = ('bx lr', 'pop pc', 'ldm pc', 'ldmia pc', 'mov pc, lr')

_X86_FLAG_BITS = {'CF': 0, 'PF': 2, 'AF': 4, 'ZF': 6, 'SF': 7, 'TF': 8, 'IF': 9, 'DF': 10,
                  'OF': 11, 'NT': 14, 'RF': 16, 'VM': 17, 'AC': 18, 'VIF': 19, 'VIP': 20, 'ID': 21}
_ARM_FLAG_BITS = {'NG': 31, 'ZR': 30, 'CY': 29, 'OV': 28, 'Q': 27,
                  'GE4': 19, 'GE3': 18, 'GE2': 17, 'GE1': 16, 'TB': 5}
_A64_FLAG_BITS = {'NG': 31, 'ZR': 30, 'CY': 29, 'OV': 28}


def _flags(bits: Dict[str, int], source: str) -> Tuple[Flag, ...]:
    """`{name: bit}` or `{name: (bit, width)}`."""
    out = []
    for name, spec in bits.items():
        bit, width = spec if isinstance(spec, tuple) else (spec, 1)
        out.append(Flag(name, source, bit, width))
    return tuple(out)


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
                    cs=_cs('CS_ARCH_X86', 'CS_MODE_64'), call_mnemonics=('call',), return_mnemonics=_X86_RETURNS,
                    flags=_flags(_X86_FLAG_BITS, 'rflags'), status='rflags', fields=_X86_FIELDS)


def _x86_32() -> ArchSpec:
    gp = ['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP', 'EIP']
    regs = _regs(gp, x86, 4, 'UC_X86_REG_')
    regs.append(Reg('eflags', x86.UC_X86_REG_EFLAGS, 4))
    regs += _regs(['CS', 'SS', 'DS', 'ES', 'FS', 'GS'], x86, 2, 'UC_X86_REG_')
    return ArchSpec('x86', UC_ARCH_X86, UC_MODE_32, 'x86:LE:32:default', 'gcc',
                    'little', 32, tuple(regs), 'EIP', 'ESP',
                    cs=_cs('CS_ARCH_X86', 'CS_MODE_32'), call_mnemonics=('call',), return_mnemonics=_X86_RETURNS,
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
                    call_mnemonics=('bl', 'blr'), return_mnemonics=('ret',),
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
                    call_mnemonics=('bl', 'blx'), return_mnemonics=_ARM_RETURNS,
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
                    call_mnemonics=('jal', 'jalr', 'bal', 'jalx'),
                    return_mnemonics=('jr $ra', 'jr ra'))


# ---- RISC-V --------------------------------------------------------------
# Ghidra names the integer registers by their ABI names (riscv.reg.sinc:46);
# x0..x31 appear there only as comments. RISC-V has no condition-code
# register: Ghidra defines no one-byte flag registers for it (fcsr is
# commented out of riscv.reg.sinc), so `flags`, `status` and `fields` are all
# empty here. Unicorn 2.1.4 only builds little-endian RISC-V.
_RISCV_GP = ['zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
             's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
             'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
             's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6']


def _riscv(bits: int) -> ArchSpec:
    size = bits // 8
    regs = _regs(_RISCV_GP, riscv, size, 'UC_RISCV_REG_')
    regs.append(Reg('pc', riscv.UC_RISCV_REG_PC, size))
    mode = UC_MODE_RISCV64 if bits == 64 else UC_MODE_RISCV32
    cs_mode = ('CS_MODE_RISCV64' if bits == 64 else 'CS_MODE_RISCV32', 'CS_MODE_RISCVC')
    # RISCVC so Capstone reports the 2-byte size of compressed instructions;
    # step-over needs the size to place its temporary breakpoint.
    return ArchSpec(f'riscv{bits}', UC_ARCH_RISCV, mode,
                    f'RISCV:LE:{bits}:default', 'gcc', 'little', bits,
                    tuple(regs), 'pc', 'sp', cs=_cs('CS_ARCH_RISCV', *cs_mode),
                    call_mnemonics=('jal', 'jalr', 'c.jal', 'c.jalr'),
                    return_mnemonics=('ret', 'c.jr ra', 'jalr zero'))


# ---- PowerPC -------------------------------------------------------------
# Unicorn 2.1.4 only builds big-endian PowerPC; UC_MODE_LITTLE_ENDIAN is
# rejected with UC_ERR_MODE, so the PowerPC:LE:* languages get no entry.
# Ghidra's one-byte XER flag registers are ppc_common.sinc:41. xer_count (the
# 7-bit string-transfer byte count) is one of them and is carried as a wide
# flag, since it still fits the byte Ghidra keeps it in; cr0..cr7 are 4-bit
# condition fields, which
# Unicorn exposes as their own registers, so they are listed as registers.
# OV32/CA32 are ISA 3.0 (64-bit) additions; the bits are reserved and read as
# zero on 32-bit, but Ghidra defines the flag registers for both languages.
_PPC_FLAG_BITS = {'xer_so': 31, 'xer_ov': 30, 'xer_ov32': 19,
                  'xer_ca': 29, 'xer_ca32': 18, 'xer_count': (0, 7)}
_PPC_FIELDS = (Field('SO', 31), Field('OV', 30), Field('CA', 29),
               Field('OV32', 19), Field('CA32', 18), Field('BC', 0, 7))


def _ppc(bits: int) -> ArchSpec:
    size = bits // 8
    regs = [Reg(f'r{i}', getattr(ppc, f'UC_PPC_REG_{i}'), size) for i in range(32)]
    regs += [Reg('pc', ppc.UC_PPC_REG_PC, size),
             Reg('LR', ppc.UC_PPC_REG_LR, size),
             Reg('CTR', ppc.UC_PPC_REG_CTR, size),
             Reg('XER', ppc.UC_PPC_REG_XER, size),
             Reg('MSR', ppc.UC_PPC_REG_MSR, size)]
    regs += _regs([f'cr{i}' for i in range(8)], ppc, 1, 'UC_PPC_REG_')
    mode = (UC_MODE_PPC64 if bits == 64 else UC_MODE_PPC32) | UC_MODE_BIG_ENDIAN
    cs_mode = ('CS_MODE_64' if bits == 64 else 'CS_MODE_32', 'CS_MODE_BIG_ENDIAN')
    return ArchSpec(f'ppc{bits}', UC_ARCH_PPC, mode,
                    f'PowerPC:BE:{bits}:default', 'default', 'big', bits,
                    tuple(regs), 'pc', 'r1', cs=_cs('CS_ARCH_PPC', *cs_mode),
                    call_mnemonics=('bl', 'bla', 'bctrl', 'blrl'),
                    return_mnemonics=('blr', 'bclr', 'bctr'),
                    flags=_flags(_PPC_FLAG_BITS, 'XER'), status='XER',
                    fields=_PPC_FIELDS)


# ---- m68k ----------------------------------------------------------------
# Ghidra calls A7 "SP" (68000.sinc:12) and defines the SR flag registers at
# 68000.sinc:15; the packflags macro (68000.sinc:812) pins their bit
# positions: SR = (TF<<15)|(SVF<<13)|(IPL<<8)|(XF<<4)|(NF<<3)|(ZF<<2)|(VF<<1)|CF.
# IPL is one of those flag registers and holds 3 bits, carried as a wide flag.
# Unicorn 2.1.4 only builds big-endian m68k.
_M68K_FLAG_BITS = {'TF': 15, 'SVF': 13, 'IPL': (8, 3),
                   'XF': 4, 'NF': 3, 'ZF': 2, 'VF': 1, 'CF': 0}
_M68K_FIELDS = (Field('T', 14, 2), Field('S', 13), Field('M', 12), Field('IPL', 8, 3),
                Field('X', 4), Field('N', 3), Field('Z', 2), Field('V', 1), Field('C', 0))


def _m68k() -> ArchSpec:
    regs = _regs([f'D{i}' for i in range(8)], m68k, 4, 'UC_M68K_REG_')
    regs += _regs([f'A{i}' for i in range(7)], m68k, 4, 'UC_M68K_REG_')
    regs += [Reg('SP', m68k.UC_M68K_REG_A7, 4),
             Reg('PC', m68k.UC_M68K_REG_PC, 4),
             Reg('SR', m68k.UC_M68K_REG_SR, 2)]
    return ArchSpec('m68k', UC_ARCH_M68K, UC_MODE_BIG_ENDIAN,
                    '68000:BE:32:default', 'default', 'big', 32,
                    tuple(regs), 'PC', 'SP',
                    cs=_cs('CS_ARCH_M68K', 'CS_MODE_BIG_ENDIAN', 'CS_MODE_M68K_040'),
                    call_mnemonics=('jsr', 'bsr', 'bsr.b', 'bsr.w', 'bsr.l'),
                    return_mnemonics=('rts', 'rtr', 'rte', 'rtd'),
                    flags=_flags(_M68K_FLAG_BITS, 'SR'), status='SR',
                    fields=_M68K_FIELDS)


# ---- SPARC ---------------------------------------------------------------
# Ghidra names o6 "sp" and i6 "fp" (SparcV9.sinc:10) and Unicorn's SP/FP
# constants are the same ids as O6/I6, so the SLEIGH names map straight
# across. Ghidra also defines the one-byte flag registers i_nf/i_zf/i_vf/i_cf
# (and x_* for the 64-bit condition codes) as bits of CCR, but Unicorn 2.1.4
# exposes no readable condition-code register: reading UC_SPARC_REG_Y is a
# documented no-op, UC_SPARC_REG_ICC/XCC return UC_ERR_ARG on sparc64, and
# UC_SPARC_REG_PSR segfaults the emulator on sparc32. So no flags, no status
# register and no fields here, and Y/nPC are left out of the register table.
# Unicorn 2.1.4 only builds big-endian SPARC.
_SPARC_GP = (['g0', 'g1', 'g2', 'g3', 'g4', 'g5', 'g6', 'g7',
              'o0', 'o1', 'o2', 'o3', 'o4', 'o5', 'sp', 'o7',
              'l0', 'l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7',
              'i0', 'i1', 'i2', 'i3', 'i4', 'i5', 'fp', 'i7'])


def _sparc(bits: int) -> ArchSpec:
    size = bits // 8
    regs = _regs(_SPARC_GP, sparc, size, 'UC_SPARC_REG_')
    regs.append(Reg('PC', sparc.UC_SPARC_REG_PC, size))
    mode = (UC_MODE_SPARC64 if bits == 64 else UC_MODE_SPARC32) | UC_MODE_BIG_ENDIAN
    cs_mode = ('CS_MODE_BIG_ENDIAN', 'CS_MODE_V9') if bits == 64 else ('CS_MODE_BIG_ENDIAN',)
    return ArchSpec(f'sparc{bits}', UC_ARCH_SPARC, mode,
                    f'sparc:BE:{bits}:default', 'default', 'big', bits,
                    tuple(regs), 'PC', 'sp', cs=_cs('CS_ARCH_SPARC', *cs_mode),
                    call_mnemonics=('call', 'jmpl'),
                    return_mnemonics=('ret', 'retl'))


# ---- TriCore -------------------------------------------------------------
# Ghidra defines no one-byte flag registers for TriCore: the PSW bit
# definitions in tricore.sinc are commented out and used only as @define
# bitranges, so `flags` is empty and the whole PSW layout is Fields.
# tricore.cspec names a10 the stack pointer. Unicorn's only valid TriCore
# mode is 0 (little-endian).
_TRICORE_RM = {0: 'RN', 1: 'RZ', 2: 'RP', 3: 'RM'}
_TRICORE_IO = {0: 'User-0', 1: 'User-1', 2: 'Supervisor', 3: 'reserved'}
_TRICORE_FIELDS = (Field('C', 31), Field('V', 30), Field('SV', 29), Field('AV', 28),
                   Field('SAV', 27), Field('FX', 26), Field('RM', 24, 2, _TRICORE_RM),
                   Field('S', 14), Field('PRS', 12, 2), Field('IO', 10, 2, _TRICORE_IO),
                   Field('IS', 9), Field('GW', 8), Field('CDE', 7), Field('CDC', 0, 7))
_TRICORE_SFR = ['PC', 'PSW', 'PCXI', 'ISP', 'SYSCON', 'CPU_ID',
                'FCX', 'LCX', 'BIV', 'BTV', 'ICR']


def _tricore() -> ArchSpec:
    regs = _regs([f'd{i}' for i in range(16)], tricore, 4, 'UC_TRICORE_REG_')
    regs += _regs([f'a{i}' for i in range(16)], tricore, 4, 'UC_TRICORE_REG_')
    regs += _regs(_TRICORE_SFR, tricore, 4, 'UC_TRICORE_REG_')
    return ArchSpec('tricore', UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN,
                    'tricore:LE:32:default', 'default', 'little', 32,
                    tuple(regs), 'PC', 'a10',
                    cs=_cs('CS_ARCH_TRICORE', 'CS_MODE_TRICORE_162'),
                    call_mnemonics=('call', 'calla', 'calli',
                                    'fcall', 'fcalla', 'fcalli'),
                    return_mnemonics=('ret', 'rfe'),
                    status='PSW', fields=_TRICORE_FIELDS)

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
           _mips(True, 32), _mips(False, 32), _mips(True, 64), _mips(False, 64),
           _riscv(32), _riscv(64), _ppc(32), _ppc(64), _m68k(),
           _sparc(32), _sparc(64), _tricore()):
    SPECS[_s.key] = _s

# afl-unicorn dump names that differ from ours, plus the spellings people
# reach for. afl-unicorn's dumpers only ever emit x64/x86/arm*/mips*, so the
# architectures below it does not know contribute only convenience spellings.
ALIASES = {'arm64': 'arm64le', 'arm': 'armle', 'x86_64': 'x64', 'amd64': 'x64',
           'i386': 'x86', 'mips32': 'mips', 'mips32el': 'mipsel', 'aarch64': 'arm64le',
           'rv32': 'riscv32', 'rv64': 'riscv64', 'riscv32i': 'riscv32',
           'riscv64i': 'riscv64', 'riscv32le': 'riscv32', 'riscv64le': 'riscv64',
           'ppc': 'ppc32', 'powerpc': 'ppc32', 'powerpc64': 'ppc64',
           'ppc32be': 'ppc32', 'ppc64be': 'ppc64',
           '68k': 'm68k', '68000': 'm68k', 'm68000': 'm68k', 'm68kbe': 'm68k',
           'sparc': 'sparc32', 'sparcbe': 'sparc32', 'sparc32be': 'sparc32',
           'sparc64be': 'sparc64', 'sparcv9': 'sparc64',
           'tricore32': 'tricore', 'tc': 'tricore'}


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
    if arch == UC_ARCH_RISCV:
        return SPECS['riscv64' if mode & UC_MODE_RISCV64 else 'riscv32']
    if arch == UC_ARCH_PPC:
        return SPECS['ppc64' if mode & UC_MODE_PPC64 else 'ppc32']
    if arch == UC_ARCH_SPARC:
        return SPECS['sparc64' if mode & UC_MODE_SPARC64 else 'sparc32']
    if arch == UC_ARCH_M68K:
        return SPECS['m68k']
    if arch == UC_ARCH_TRICORE:
        return SPECS['tricore']
    raise KeyError(f"Unsupported Unicorn arch {arch} mode {mode:#x}")
