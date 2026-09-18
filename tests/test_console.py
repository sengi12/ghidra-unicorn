import io

from ghidraunicorn import hooks
from ghidraunicorn.__main__ import parse_regs
from ghidraunicorn.console import UnicornConsole
from ghidraunicorn.context import Context

from test_target import CODE, DATA, make_x64


def make_console():
    t = make_x64()
    out = io.StringIO()
    c = UnicornConsole(t, out=out, color=False)
    return t, c, out


def test_context_renders_sections():
    t = make_x64()
    text = Context(t, io.StringIO(), color=False).render()
    assert '[ registers ]' in text and '[ disassembly ]' in text and '[ stack ]' in text
    assert 'RIP     0x0000000000001000' in text
    assert '→ 0x1000' in text and 'mov' in text
    assert 'rflags' in text and '[' in text


def test_context_highlights_changes_with_color():
    t = make_x64()
    ctx = Context(t, io.StringIO(), color=True)
    ctx.render()
    t.step()
    text = ctx.render()
    assert '\x1b[1;31m0x0000000000000001\x1b[0m' in text      # RAX changed to 1


def test_console_commands_drive_target():
    t, c, out = make_console()
    c.push('b 0x100d')
    assert 1 in t.breakpoints and 'breakpoint 1 at 0x100d' in out.getvalue()
    c.push('c')
    assert t.pc() == 0x100d
    c.push('si 2')
    assert t.pc() == 0x101d
    c.push('n')
    assert t.pc() == 0x1022 and t.reg_read('rcx') == 1
    c.push('r rax 0x55')
    assert t.reg_read('rax') == 0x55
    c.push('r ZF 1')
    assert t.reg_read('ZF') == 1
    c.push('m 0x2000 41424344')
    c.push('x/4xb 0x2000')
    assert '0x2000: 41 42 43 44' in out.getvalue()
    c.push('x/s 0x2000')
    assert "'ABCD'" in out.getvalue()
    c.push('x/2xg rsp')
    assert '0x7ff0:' in out.getvalue()
    c.push('w 0x2000 4 w')
    c.push('bl')
    assert 'WRITE' in out.getvalue()
    c.push('d 1')
    assert 1 not in t.breakpoints
    c.push('help')
    assert 'ghidra-unicorn commands' in out.getvalue()
    # Unknown commands are still Python.
    c.push('_pc = target.pc()')
    assert c.locals['_pc'] == 0x1022
    c.push('r rflags.ZF 0')
    assert t.reg_read('ZF') == 0
    c.push('fields')
    assert 'rflags.IOPL' in out.getvalue()


def test_console_value_expressions():
    t, c, out = make_console()
    assert c.value('rsp+0x10') == 0x8000
    assert c.value('$rip') == CODE
    assert c.value('0x2000-8') == 0x1ff8
    assert c.value('16') == 16


def test_console_reports_errors_not_tracebacks():
    t, c, out = make_console()
    c.push('x/4xw 0x9000')
    assert 'error:' in out.getvalue()
    c.push('adv')
    assert 'usage' in out.getvalue()


def test_parse_regs():
    assert parse_regs('cpsr=0x60000030, r0=1;ZF=1') == {'cpsr': 0x60000030, 'r0': 1, 'ZF': 1}
    assert parse_regs('') == {} and parse_regs(None) == {}


def test_status_register_fields_arm():
    from unicorn import UC_ARCH_ARM, UC_MODE_ARM, Uc
    from ghidraunicorn.target import UnicornTarget
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    t = UnicornTarget(uc)
    t.reg_write('cpsr', 0x600001d3)
    assert dict(t.fields())['M'] == 'SVC' and dict(t.fields())['Z'] == '1'
    assert t.reg_read('cpsr.M') == 0x13 and t.reg_read('cpsr.I') == 1
    t.reg_write('cpsr.M', 0x10)
    t.reg_write('cpsr.T', 1)
    assert t.reg_read('cpsr') == 0x600001f0 and t.reg_read('TB') == 1
    import pytest
    with pytest.raises(ValueError):
        t.reg_write('cpsr.M', 0x40)
    with pytest.raises(KeyError):
        t.reg_read('cpsr.bogus')
    text = Context(t, io.StringIO(), color=False).flags()
    assert 'M=USR' in text and ' Z ' in text and 'T' in text


def test_context_disassembly_without_history_at_region_start():
    from unicorn import UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN, Uc
    from unicorn.mips_const import UC_MIPS_REG_PC
    from ghidraunicorn.target import UnicornTarget
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)
    uc.mem_map(0x100000, 0x1000)
    uc.mem_write(0x100000, bytes.fromhex('27bdffe8' '00000000'))   # addiu sp,sp,-24 ; nop
    uc.reg_write(UC_MIPS_REG_PC, 0x100000)
    text = Context(UnicornTarget(uc), io.StringIO(), color=False).render()
    assert '→ 0x100000' in text and 'addiu' in text


def test_symbol_names_work_as_addresses():
    from ghidraunicorn.symbols import Symbol, SymbolTable
    t = make_x64()
    syms = SymbolTable([Symbol('entry', CODE, 0x30, 'function'),
                        Symbol('spin', 0x1025, 2, 'function')])
    out = io.StringIO()
    c = UnicornConsole(t, out=out, color=False, symbols=syms)
    assert c.value('spin') == 0x1025
    assert c.value('entry+0x7') == CODE + 7
    c.push('b spin')
    assert any(b.address == 0x1025 for b in t.breakpoints.values())
    c.push('sym entry')
    assert 'entry = 0x1000' in out.getvalue()
    c.push('sym 0x1007')
    assert 'entry+0x7' in out.getvalue()


def test_coverage_command_records_and_saves(tmp_path):
    from ghidraunicorn.loaders import Module
    t = make_x64(end=0x1025)
    out = io.StringIO()
    c = UnicornConsole(t, loaded=type('L', (), {'modules': [Module('/tmp/p', CODE, 0x1000)]})(),
                       out=out, color=False)
    c.push('cov')
    assert 'not recording' in out.getvalue()
    c.push('cov on')
    c.push('c')
    c.push('cov off')
    target = tmp_path / 'run.drcov'
    c.push(f'cov save {target}')
    assert target.exists() and 'blocks' in out.getvalue()
    assert b'DRCOV VERSION: 2' in target.read_bytes()
    c.push('cov reset')
    assert c.coverage.block_count == 0


def test_provenance_command_reports_reads():
    t = make_x64(end=0x1025)
    out = io.StringIO()
    c = UnicornConsole(t, out=out, color=False)
    c.push('prov')                       # not watching yet
    assert 'error:' in out.getvalue()
    c.push(f'prov on {DATA} 16')
    c.push('c')
    c.push('prov')
    text = out.getvalue()
    assert 'read:   0-7' in text and 'unread: 8-15' in text


# ---- standing in for what is not there ------------------------------------

def test_console_reports_when_there_is_no_layer():
    t, c, out = make_console()
    c.push('sys')
    c.push('stub')
    c.push('heap')
    text = out.getvalue()
    assert 'no system call layer' in text
    assert 'no stub layer' in text and 'no heap' in text


def test_console_shows_the_system_call_layer():
    from ghidraunicorn import syscalls
    t, c, out = make_console()
    layer = syscalls.install(t)
    c.push('sys')
    assert 'x64 Linux' in out.getvalue()
    assert 'nothing called yet' in out.getvalue()


def test_console_binds_and_lists_a_stub():
    from ghidraunicorn import stubs
    t, c, out = make_console()
    stubs.install(t)
    c.push('stub malloc 0x1027')
    assert 'malloc stands in at 0x1027' in out.getvalue()
    c.push('stub')
    assert '0x1027' in out.getvalue() and 'malloc' in out.getvalue()
    c.push('heap')
    assert 'heap 0x' in out.getvalue()


def test_console_refuses_a_half_given_stub():
    from ghidraunicorn import stubs
    t, c, out = make_console()
    stubs.install(t)
    c.push('stub malloc')
    assert 'usage: stub NAME ADDR' in out.getvalue()


# ---- the context renders from anything with the target's surface ----------

class FakeSource:
    """Everything `Context` needs, and nothing that is a UnicornTarget.

    The panel inside Ghidra draws the same view from a trace, so this is the
    check that the renderer really is separable from the emulator rather
    than only looking as though it is.
    """

    def __init__(self, target):
        self.spec = target.spec
        self.breakpoints = {}
        self._regs = dict(target.regs())
        self._memory = {start: target.read(start, end - start + 1)
                        for start, end, _ in target.regions()}
        self._regions = target.regions()
        self._decode = target.decode

    def pc(self):
        return self._regs[self.spec.pc]

    def sp(self):
        return self._regs[self.spec.sp]

    def regs(self):
        return dict(self._regs)

    def reg_read(self, name):
        return self._regs[self.spec.reg(name).name]

    def regions(self):
        return list(self._regions)

    def read(self, address, size):
        for start, data in self._memory.items():
            if start <= address and address + size <= start + len(data):
                return data[address - start:address - start + size]
        raise ValueError(f'{address:#x} is not mapped')

    def decode(self, address):
        return self._decode(address)

    def fields(self):
        if self.spec.status is None:
            return []
        return self.spec.decode_fields(self._regs[self.spec.status])


def test_the_context_renders_from_something_that_is_not_a_target():
    t = make_x64()
    t.step(3)
    text = Context(FakeSource(t), io.StringIO(), color=False).render()
    assert '[ registers ]' in text and '[ disassembly ]' in text
    assert 'RAX' in text and '0x0000000000000003' in text
    assert 'mov' in text


def test_the_two_renderings_agree():
    """Same state, same picture, whichever side it came from."""
    t = make_x64()
    t.step(3)
    direct = Context(t, io.StringIO(), color=False).render()
    indirect = Context(FakeSource(t), io.StringIO(), color=False).render()
    assert direct == indirect
