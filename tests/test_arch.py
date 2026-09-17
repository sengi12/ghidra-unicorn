import pytest
from unicorn import (UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_MIPS, UC_ARCH_X86,
                     UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_MODE_BIG_ENDIAN,
                     UC_MODE_MIPS32, UC_MODE_MIPS64, UC_MODE_THUMB, Uc)

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
    with pytest.raises(KeyError):
        arch.spec_for_key('sparc')


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
