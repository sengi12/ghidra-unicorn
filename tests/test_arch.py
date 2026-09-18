import pytest
from unicorn import (UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_M68K, UC_ARCH_MIPS,
                     UC_ARCH_PPC, UC_ARCH_RISCV, UC_ARCH_SPARC, UC_ARCH_TRICORE,
                     UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_MODE_ARM,
                     UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN, UC_MODE_MIPS32,
                     UC_MODE_MIPS64, UC_MODE_PPC32, UC_MODE_PPC64,
                     UC_MODE_RISCV32, UC_MODE_RISCV64, UC_MODE_SPARC32,
                     UC_MODE_SPARC64, UC_MODE_THUMB, Uc)

from ghidraunicorn import arch


@pytest.mark.parametrize('key,lang,pc,nregs', [
    ('x64', 'x86:LE:64:default', 'RIP', 26),
    ('x86', 'x86:LE:32:default', 'EIP', 16),
    ('arm64le', 'AARCH64:LE:64:v8A', 'pc', 34),
    ('armle', 'ARM:LE:32:v8', 'pc', 17),
    ('armlethumb', 'ARM:LE:32:v8T', 'pc', 17),
    ('mips', 'MIPS:BE:32:default', 'pc', 35),
    ('mipsel', 'MIPS:LE:32:default', 'pc', 35),
    ('mips64', 'MIPS:BE:64:default', 'pc', 35),
    ('riscv32', 'RISCV:LE:32:default', 'pc', 33),
    ('riscv64', 'RISCV:LE:64:default', 'pc', 33),
    ('ppc32', 'PowerPC:BE:32:default', 'pc', 45),
    ('ppc64', 'PowerPC:BE:64:default', 'pc', 45),
    ('m68k', '68000:BE:32:default', 'PC', 18),
    ('sparc32', 'sparc:BE:32:default', 'PC', 33),
    ('sparc64', 'sparc:BE:64:default', 'PC', 33),
    ('tricore', 'tricore:LE:32:default', 'PC', 43),
])
def test_specs(key, lang, pc, nregs):
    s = arch.spec_for_key(key)
    assert s.language == lang and s.pc == pc and len(s.regs) == nregs
    assert s.has_reg(s.sp)
    names = [r.name.lower() for r in s.regs]
    assert len(names) == len(set(names)), 'duplicate register names'


def test_aliases():
    assert arch.spec_for_key('aarch64').key == 'arm64le'
    assert arch.spec_for_key('X86_64').key == 'x64'
    assert arch.spec_for_key('sparc').key == 'sparc32'
    assert arch.spec_for_key('SPARCV9').key == 'sparc64'
    assert arch.spec_for_key('powerpc').key == 'ppc32'
    assert arch.spec_for_key('ppc64be').key == 'ppc64'
    assert arch.spec_for_key('rv64').key == 'riscv64'
    assert arch.spec_for_key('68k').key == 'm68k'
    with pytest.raises(KeyError):
        arch.spec_for_key('s390x')


@pytest.mark.parametrize('uc_arch,mode,key', [
    (UC_ARCH_X86, UC_MODE_64, 'x64'),
    (UC_ARCH_X86, UC_MODE_32, 'x86'),
    (UC_ARCH_ARM64, UC_MODE_ARM, 'arm64le'),
    (UC_ARCH_ARM, UC_MODE_ARM, 'armle'),
    (UC_ARCH_ARM, UC_MODE_THUMB, 'armlethumb'),
    (UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN, 'armbe'),
    (UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN, 'mips'),
    (UC_ARCH_MIPS, UC_MODE_MIPS32, 'mipsel'),
    (UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN, 'mips64'),
    (UC_ARCH_RISCV, UC_MODE_RISCV32, 'riscv32'),
    (UC_ARCH_RISCV, UC_MODE_RISCV64, 'riscv64'),
    (UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN, 'ppc32'),
    (UC_ARCH_PPC, UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN, 'ppc64'),
    (UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, 'm68k'),
    (UC_ARCH_SPARC, UC_MODE_SPARC32 | UC_MODE_BIG_ENDIAN, 'sparc32'),
    (UC_ARCH_SPARC, UC_MODE_SPARC64 | UC_MODE_BIG_ENDIAN, 'sparc64'),
    (UC_ARCH_TRICORE, UC_MODE_LITTLE_ENDIAN, 'tricore'),
])
def test_detect_from_uc(uc_arch, mode, key):
    uc = Uc(uc_arch, mode)
    assert arch.spec_for_uc(uc).key == key


def test_every_register_is_readable():
    for key, spec in arch.SPECS.items():
        uc = Uc(spec.uc_arch, spec.uc_mode)
        for r in spec.regs:
            v = uc.reg_read(r.uc)
            assert isinstance(v, int), (key, r.name)
            assert v < (1 << (8 * r.size)) or r.name in ('FS_OFFSET', 'GS_OFFSET'), (key, r.name, v)


def test_flags_decode_and_set():
    s = arch.spec_for_key('x64')
    names = [f.name for f in s.flags]
    assert names[:5] == ['CF', 'PF', 'AF', 'ZF', 'SF'] and s.status == 'rflags'
    d = s.decode_flags(0x246)
    assert d['ZF'] == 1 and d['PF'] == 1 and d['IF'] == 1 and d['CF'] == 0
    assert s.set_flag(0x246, 'CF', True) == 0x247
    assert s.set_flag(0x247, 'ZF', False) == 0x207
    a = arch.spec_for_key('armle')
    assert a.decode_flags(0xa0000010) == {'NG': 1, 'ZR': 0, 'CY': 1, 'OV': 0, 'Q': 0,
                                          'GE4': 0, 'GE3': 0, 'GE2': 0, 'GE1': 0, 'TB': 0}
    assert arch.spec_for_key('arm64le').decode_flags(0x60000000) == {'NG': 0, 'ZR': 1, 'CY': 1, 'OV': 0}
    assert arch.spec_for_key('mips').flags == ()


def test_status_and_flag_sources_are_real_registers():
    """Every spec's status register and every flag's source must be readable."""
    for key, spec in arch.SPECS.items():
        if spec.status is not None:
            assert spec.has_reg(spec.status), (key, spec.status)
        for f in spec.flags:
            assert spec.has_reg(f.source), (key, f.name, f.source)
        names = [f.name.lower() for f in spec.flags]
        assert len(names) == len(set(names)), key
        assert not (set(names) & {r.name.lower() for r in spec.regs}), key


def test_ppc_xer_flags_and_fields():
    for key in ('ppc32', 'ppc64'):
        s = arch.spec_for_key(key)
        assert s.status == 'XER' and s.sp == 'r1'
        assert s.has_reg('cr0') and s.reg('cr0').size == 1
        assert s.reg('XER').size == s.ptr_size
        # SO|OV|CA (31..29), OV32|CA32 (19,18) and a byte count of 0x7f
        assert s.decode_flags(0xE00C007F) == {'xer_so': 1, 'xer_ov': 1, 'xer_ca': 1,
                                              'xer_ov32': 1, 'xer_ca32': 1}
        assert s.decode_flags(0) == {'xer_so': 0, 'xer_ov': 0, 'xer_ca': 0,
                                     'xer_ov32': 0, 'xer_ca32': 0}
        assert s.set_flag(0, 'xer_ca', True) == 1 << 29
        assert s.set_flag(0xE0000000, 'xer_so', False) == 0x60000000
        assert s.field('BC').get(0xE00C007F) == 0x7f
        assert [n for n, _ in s.decode_fields(0)][:3] == ['SO', 'OV', 'CA']
        assert 'bl' in s.call_mnemonics


def test_m68k_sr_flags_and_fields():
    s = arch.spec_for_key('m68k')
    assert s.status == 'SR' and s.reg('SR').size == 2
    assert s.pc == 'PC' and s.sp == 'SP'
    # SR = (TF<<15)|(SVF<<13)|(IPL<<8)|(XF<<4)|(NF<<3)|(ZF<<2)|(VF<<1)|CF
    assert s.decode_flags(0x2715) == {'TF': 0, 'SVF': 1, 'XF': 1, 'NF': 0,
                                      'ZF': 1, 'VF': 0, 'CF': 1}
    assert s.set_flag(0x2715, 'TF', True) == 0xA715
    assert s.set_flag(0x2715, 'CF', False) == 0x2714
    # IPL is a Ghidra flag register but three bits wide, so it is a Field only
    assert s.flag('IPL') is None
    assert s.field('IPL').get(0x2715) == 7
    assert s.field('IPL').mask == 0x700
    assert s.field('S').get(0x2715) == 1


def test_tricore_psw_fields_without_flags():
    s = arch.spec_for_key('tricore')
    # Ghidra comments out the PSW bit definitions, so there are no flag registers
    assert s.flags == () and s.status == 'PSW'
    assert s.sp == 'a10' and s.has_reg('d15') and s.has_reg('PCXI')
    assert s.field('C').get(0x80000000) == 1
    assert s.field('RM').label(0x02000000) == 'RP'
    assert s.field('IO').label(0x00000800) == 'Supervisor'
    assert s.field('CDC').get(0x7f) == 0x7f
    assert [n for n, _ in s.decode_fields(0)][:5] == ['C', 'V', 'SV', 'AV', 'SAV']


def test_riscv_and_sparc_have_no_flag_registers():
    for key in ('riscv32', 'riscv64', 'sparc32', 'sparc64'):
        s = arch.spec_for_key(key)
        assert s.flags == () and s.fields == () and s.status is None, key
    rv = arch.spec_for_key('riscv64')
    assert rv.has_reg('zero') and rv.has_reg('s11') and rv.sp == 'sp'
    assert rv.call_mnemonics == ('jal', 'jalr', 'c.jal', 'c.jalr')
    sp = arch.spec_for_key('sparc64')
    # Ghidra names o6 "sp" and i6 "fp"; both are in the table under those names
    assert sp.has_reg('sp') and sp.has_reg('fp') and sp.has_reg('o7')
    assert not sp.has_reg('o6') and not sp.has_reg('i6')


@pytest.mark.parametrize('key,code,mnemonic,size', [
    ('riscv64', b'\xef\x00\x80\x00', 'jal', 4),
    ('riscv64', b'\x82\x90', 'c.jalr', 2),
    ('ppc32', b'\x48\x00\x00\x05', 'bl', 4),
    ('m68k', b'\x4e\xb9\x00\x00\x10\x00', 'jsr', 6),
    ('sparc64', b'\x40\x00\x00\x02', 'call', 4),
    ('tricore', b'\x6d\x00\x02\x00', 'call', 4),
])
def test_capstone_pairs_decode_calls(key, code, mnemonic, size):
    """The (arch, mode) pair must decode, since step-over needs the size."""
    capstone = pytest.importorskip('capstone')
    spec = arch.spec_for_key(key)
    assert spec.cs is not None
    insns = list(capstone.Cs(*spec.cs).disasm_lite(code, 0x1000, 1))
    assert insns, (key, code)
    _, isize, mnem, _ = insns[0]
    assert mnem == mnemonic and isize == size
    assert mnem in spec.call_mnemonics
