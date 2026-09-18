import struct

import pytest
from unicorn import UC_ARCH_X86, UC_MODE_64, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN, Uc

from ghidraunicorn import arch
from ghidraunicorn.target import ACCESS, READ, WRITE, UnicornTarget

CODE = 0x1000
DATA = 0x2000

# x86-64:
#   1000: 48 c7 c0 01 00 00 00   mov rax, 1
#   1007: 48 ff c0               inc rax
#   100a: 48 ff c0               inc rax
#   100d: 48 89 04 25 00 20 00 00  mov [0x2000], rax
#   1015: 48 8b 1c 25 00 20 00 00  mov rbx, [0x2000]
#   101d: e8 05 00 00 00         call 0x1027
#   1022: 48 ff c3               inc rbx
#   1025: eb fe                  jmp 0x1025          (spin forever)
#   1027: 48 ff c1               inc rcx
#   102a: c3                     ret
X64 = bytes.fromhex(
    '48c7c001000000' '48ffc0' '48ffc0' '4889042500200000' '488b1c2500200000'
    'e805000000' '48ffc3' 'ebfe' '48ffc1' 'c3')


def make_x64(end=None):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000)
    uc.mem_map(DATA, 0x1000)
    uc.mem_map(0x7000, 0x1000)
    uc.mem_write(CODE, X64)
    uc.reg_write(arch.x86.UC_X86_REG_RIP, CODE)
    uc.reg_write(arch.x86.UC_X86_REG_RSP, 0x7ff0)
    return UnicornTarget(uc, end=end)


def test_spec_detection():
    t = make_x64()
    assert t.spec.key == 'x64'
    assert t.spec.language == 'x86:LE:64:default'
    assert t.pc() == CODE and t.sp() == 0x7ff0
    assert set(t.regs()) >= {'RAX', 'RIP', 'RSP', 'rflags', 'CS'}


def test_step_advances_one_instruction():
    t = make_x64()
    ev = t.step()
    assert ev.reason == 'step' and ev.pc == 0x1007
    assert t.reg_read('rax') == 1
    ev = t.step(2)
    assert ev.pc == 0x100d and t.reg_read('RAX') == 3


def test_breakpoint_stops_before_instruction():
    t = make_x64()
    bp = t.add_breakpoint(0x100a)
    ev = t.run()
    assert ev.reason == 'breakpoint' and ev.pc == 0x100a and ev.breakpoint is bp
    assert t.reg_read('rax') == 2          # 0x100a not executed yet
    assert bp.hit_count == 1
    # Resuming from the breakpoint executes it instead of re-triggering.
    bp2 = t.add_breakpoint(0x101d)
    ev = t.run()
    assert ev.reason == 'breakpoint' and ev.breakpoint is bp2
    assert t.reg_read('rax') == 3 and t.reg_read('rbx') == 3


def test_disabled_and_deleted_breakpoints():
    t = make_x64(end=0x1025)
    bp = t.add_breakpoint(0x100a)
    t.enable_breakpoint(bp.num, False)
    ev = t.run()
    assert ev.reason == 'exit' and t.terminated
    t2 = make_x64(end=0x1025)
    bp = t2.add_breakpoint(0x100a)
    t2.delete_breakpoint(bp.num)
    assert t2.run().reason == 'exit'


def test_write_watchpoint():
    t = make_x64()
    wp = t.add_watchpoint(DATA, 8, WRITE)
    ev = t.run()
    assert ev.reason == 'watchpoint' and ev.breakpoint is wp
    assert struct.unpack('<Q', t.read(DATA, 8))[0] == 3
    # The store completed and execution stopped before the next instruction,
    # so resuming does not re-run the store.
    assert ev.pc == 0x1015 and t.pc() == 0x1015
    assert t.step().pc == 0x101d and t.reg_read('rbx') == 3


def test_watchpoint_reported_when_stepping():
    t = make_x64()
    t.add_watchpoint(DATA, 8, WRITE)
    t.add_breakpoint(0x100d)
    t.run()
    ev = t.step()
    assert ev.reason == 'watchpoint' and ev.pc == 0x1015


def test_read_watchpoint_ignores_writes():
    t = make_x64()
    wp = t.add_watchpoint(DATA, 8, READ)
    ev = t.run()
    assert ev.reason == 'watchpoint' and ev.breakpoint is wp and ev.pc == 0x101d


def test_access_watchpoint_hits_first_access():
    t = make_x64()
    t.add_watchpoint(DATA, 8, ACCESS)
    assert t.run().pc == 0x1015


def test_step_over_call_uses_capstone():
    pytest.importorskip('capstone')
    t = make_x64()
    t.add_breakpoint(0x101d)
    t.run()
    ev = t.step_over()
    assert ev.pc == 0x1022 and t.reg_read('rcx') == 1
    # A temporary breakpoint should not linger.
    assert all(not b.temporary for b in t.breakpoints.values())


def test_step_into_call():
    t = make_x64()
    t.add_breakpoint(0x101d)
    t.run()
    assert t.step().pc == 0x1027


def test_interrupt_from_another_thread():
    import threading
    t = make_x64()
    bp = t.add_breakpoint(0x1025)     # stop right before the spin loop
    t.run()
    t.delete_breakpoint(bp.num)
    ev_holder = {}

    def runner():
        ev_holder['ev'] = t.run()

    th = threading.Thread(target=runner)
    th.start()
    import time
    time.sleep(0.2)
    assert t.running
    t.interrupt()
    th.join(5)
    assert not th.is_alive()
    assert ev_holder['ev'].reason == 'interrupt'
    assert ev_holder['ev'].pc == 0x1025


def test_error_stop_reports_faulting_pc():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000)
    # mov rax, [0x9000]  (unmapped)
    uc.mem_write(CODE, bytes.fromhex('488b042500900000'))
    uc.reg_write(arch.x86.UC_X86_REG_RIP, CODE)
    t = UnicornTarget(uc)
    ev = t.run()
    assert ev.reason == 'error' and ev.error is not None and ev.pc == CODE
    assert 'UC_ERR_READ_UNMAPPED' in ev.description


def test_read_mapped_clips_to_regions():
    t = make_x64()
    chunks = t.read_mapped(0x0fff, 0x1010)
    assert chunks == [(0x1000, X64[:0x10])]
    assert t.read_mapped(0x5000, 0x6000) == []


def test_exits_and_listeners():
    t = make_x64()
    t.exits.add(0x100d)
    seen = []
    t.listeners.append(seen.append)
    ev = t.run()
    assert ev.reason == 'exit' and t.terminated and seen == [ev]
    with pytest.raises(Exception):
        t.run()


def test_mips_big_endian_spec():
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)
    t = UnicornTarget(uc)
    assert t.spec.key == 'mips' and t.spec.language == 'MIPS:BE:32:default'
    assert t.spec.reg('ra').size == 4 and t.spec.has_reg('s8')


def test_flag_registers_read_and_write():
    t = make_x64()
    t.step()                       # mov rax, 1 -> flags untouched, but readable
    assert set(t.flags()) >= {'CF', 'ZF', 'SF', 'OF'}
    t.reg_write('rflags', 0x202)
    assert t.reg_read('ZF') == 0
    t.reg_write('ZF', 1)
    assert t.reg_read('rflags') == 0x242 and t.reg_read('zf') == 1
    t.reg_write('CF', 1)
    t.reg_write('ZF', 0)
    assert t.reg_read('rflags') == 0x203


def make_mips_delay_slot(end=0x1008):
    """MIPS where the end address is a branch delay slot.

        0x1000  addiu sp, sp, -0x18
        0x1004  jr ra
        0x1008  addiu sp, sp, 0x18     <- delay slot, and the end address
    """
    from unicorn import UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN
    from unicorn import mips_const as mips
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_map(0x8000, 0x1000)
    uc.mem_write(0x1000, bytes.fromhex('27bdffe8' '03e00008' '27bd0018'))
    uc.reg_write(mips.UC_MIPS_REG_PC, 0x1000)
    uc.reg_write(mips.UC_MIPS_REG_SP, 0x8800)
    uc.reg_write(mips.UC_MIPS_REG_RA, 0x100c)
    return UnicornTarget(uc, end=end)


def test_stepping_past_a_delay_slot_end_makes_progress():
    """Regression: stepping toward an end address that is a branch delay slot
    used to re-execute the branch forever, applying its stack adjustment every
    time while the program counter stood still.

    Unicorn runs a branch and its delay slot as one step, so the end cannot be
    stopped on exactly here; what matters is that every step advances and the
    epilogue is applied once, not once per step."""
    t = make_mips_delay_slot()
    seen = []
    for _ in range(6):
        before, sp_before = t.pc(), t.sp()
        t.step()
        seen.append((hex(before), hex(t.pc())))
        assert t.pc() != before or t.terminated, (
            f'no progress at {before:#x}: sp {sp_before:#x} -> {t.sp():#x}')
        if t.terminated:
            break
    # The prologue subtracted 0x18 and the delay slot added it back, once each.
    assert t.sp() == 0x8800, (hex(t.sp()), seen)


def test_running_to_a_delay_slot_end_still_terminates():
    t = make_mips_delay_slot()
    ev = t.run()
    assert ev.terminated and t.terminated, ev


def test_stepping_onto_an_exit_address_terminates():
    """Arriving at an exit is terminal even when the step budget runs out on
    the very same instruction; the budget must not mask it."""
    t = make_x64()
    t.exits.add(0x100a)
    assert t.step().reason == 'step' and t.pc() == 0x1007
    ev = t.step()
    assert ev.reason == 'exit' and ev.pc == 0x100a, ev
    assert t.terminated


def test_fault_carries_the_refused_access():
    """A UcError has only an error number; the stop event should still say
    which access Unicorn refused."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000)
    uc.mem_write(CODE, bytes.fromhex('488b042500900000'))     # mov rax,[0x9000]
    uc.reg_write(arch.x86.UC_X86_REG_RIP, CODE)
    ev = UnicornTarget(uc).run()
    assert ev.reason == 'error'
    assert ev.fault_address == 0x9000
    assert ev.fault_access == 'UC_MEM_READ_UNMAPPED'
    assert ev.fault_size == 8
    assert 'touching 0x9000' in ev.description


def test_a_stop_forced_from_outside_is_not_called_termination():
    """Regression: an unrelated hook calling emu_stop, while an end address was
    declared, used to be reported as having reached the end."""
    from unicorn import UC_HOOK_CODE
    t = make_x64(end=0x1025)

    def meddle(uc, address, size, user_data):
        if address == 0x100a:
            uc.emu_stop()
    t.uc.hook_add(UC_HOOK_CODE, meddle)

    ev = t.run()
    assert ev.reason == 'stopped', ev
    assert not ev.terminated and not t.terminated
    assert t.pc() == 0x100a


def test_a_delay_slot_short_stop_still_counts_as_arriving():
    """The other side of that coin: stopping one instruction short of the end
    because it is a delay slot is still arriving."""
    t = make_mips_delay_slot()
    ev = t.run()
    assert ev.terminated and 'Reached 0x1008' in ev.description, ev


def test_wide_flag_registers_read_and_write():
    """m68k's interrupt level is three bits, and Ghidra models it as its own
    register, so it must be readable and writable like any other flag."""
    from unicorn import UC_ARCH_M68K, UC_MODE_BIG_ENDIAN
    from unicorn import m68k_const as m68k
    uc = Uc(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN)
    t = UnicornTarget(uc)
    t.reg_write('SR', 0x2715)
    assert t.reg_read('IPL') == 7 and t.reg_read('ZF') == 1
    t.reg_write('IPL', 2)
    assert t.reg_read('IPL') == 2 and t.reg_read('SR') == 0x2215
    assert t.flags()['IPL'] == 2
    with pytest.raises(ValueError):
        t.reg_write('IPL', 9)
