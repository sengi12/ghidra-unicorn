"""The Linux layer under the emulator, and its behaviour under a replay.

The x86-64 programme most of these use is assembled by `sysprog` below: a
run of no-ops, then one `syscall` with the arguments already in place, then
more no-ops. The no-ops on either side are there so a checkpoint interval of
two or three lands both before and after the trap, which is what makes the
replay cases interesting.
"""
import pytest
from unicorn import (UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_M68K, UC_ARCH_MIPS,
                     UC_ARCH_PPC, UC_ARCH_RISCV, UC_ARCH_X86, UC_MODE_32,
                     UC_MODE_64, Uc)

from ghidraunicorn import abi, arch, syscalls
from ghidraunicorn.syscalls import SyscallError
from ghidraunicorn.target import UnicornTarget

CODE = 0x1000
DATA = 0x2000
STACK = 0x7000

# x86-64 argument registers for a syscall, in order, as `mov r, imm32`.
_SETUP = {'RAX': '48c7c0', 'RDI': '48c7c7', 'RSI': '48c7c6', 'RDX': '48c7c2',
          'R10': '49c7c2', 'R8': '49c7c0', 'R9': '49c7c1'}
_ORDER = ('RAX', 'RDI', 'RSI', 'RDX', 'R10', 'R8', 'R9')


def sysprog(lead=0, tail=4, **regs):
    """`lead` no-ops, the register setup, `syscall`, then `tail` no-ops."""
    code = b'\x90' * lead
    for name in _ORDER:
        if name in regs:
            code += bytes.fromhex(_SETUP[name]) + (regs[name] & 0xffffffff).to_bytes(4, 'little')
    return code + bytes.fromhex('0f05') + b'\x90' * tail


def make(code, interval=1000, budget=1 << 20, **kwargs):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    for base in (CODE, DATA, STACK):
        uc.mem_map(base, 0x1000)
    uc.mem_write(CODE, code)
    uc.reg_write(arch.x86.UC_X86_REG_RIP, CODE)
    uc.reg_write(arch.x86.UC_X86_REG_RSP, STACK + 0xff0)
    t = UnicornTarget(uc, checkpoint_interval=interval, memory_budget=budget)
    out = []
    s = syscalls.install(t, on_output=lambda fd, d: out.append((fd, d)), **kwargs)
    return t, s, out


def run(t, n=64):
    """Step until the programme stops being interesting."""
    for _ in range(n):
        ev = t.step()
        if ev.reason != 'step':
            return ev
    return None


# ---- the calls themselves -------------------------------------------------

def test_write_reaches_the_output_callback():
    t, s, out = make(sysprog(RAX=1, RDI=1, RSI=DATA, RDX=5))
    t.write(DATA, b'hello!')
    run(t)
    assert out == [(1, b'hello')]
    assert t.reg_read('RAX') == 5


def test_read_fills_memory_and_advances_the_offset():
    t, s, out = make(sysprog(RAX=0, RDI=0, RSI=DATA, RDX=4), stdin=b'abcdefgh')
    run(t)
    assert t.read(DATA, 4) == b'abcd'
    assert t.reg_read('RAX') == 4 and s.files[0].offset == 4


def test_read_past_the_end_returns_what_is_left():
    t, s, out = make(sysprog(RAX=0, RDI=0, RSI=DATA, RDX=64), stdin=b'ab')
    run(t)
    assert t.reg_read('RAX') == 2 and t.read(DATA, 2) == b'ab'


def test_exit_terminates_the_target():
    t, s, out = make(sysprog(RAX=60, RDI=3))
    ev = run(t)
    assert ev.reason == 'exit' and t.terminated
    assert 'status 3' in ev.description


def test_exit_group_terminates_too():
    t, s, out = make(sysprog(RAX=231, RDI=0))
    assert run(t).reason == 'exit'


def test_brk_with_no_argument_reports_the_current_break():
    t, s, out = make(sysprog(RAX=12, RDI=0))
    run(t)
    assert t.reg_read('RAX') == s.brk_base


def test_brk_grows_the_heap_and_maps_it():
    # `mov rdi, imm32` cannot carry a 64-bit break address, so the argument
    # is put in place directly and only the trap is executed.
    t, s, out = make(sysprog(RAX=12))
    t.reg_write('RDI', s.brk_base + 0x1000)
    run(t)
    assert t.reg_read('RAX') == s.brk_base + 0x1000
    assert s.mapped(s.brk_base, 0x1000)
    t.write(s.brk_base, b'heap')          # the new break is real memory
    assert t.read(s.brk_base, 4) == b'heap'


def test_brk_below_the_base_is_refused():
    t, s, out = make(sysprog(RAX=12, RDI=0x10))
    run(t)
    assert t.reg_read('RAX') == s.brk_base


def test_mmap_returns_a_mapped_region():
    t, s, out = make(sysprog(RAX=9, RDI=0, RSI=0x2000, RDX=3, R10=0x22, R8=0xffffffff))
    run(t)
    addr = t.reg_read('RAX')
    assert addr == s.mmap_base and s.mapped(addr, 0x2000)
    t.write(addr, b'ok')          # it is real memory, not just a number
    assert t.read(addr, 2) == b'ok'


def test_munmap_takes_a_region_away():
    t, s, out = make(sysprog(RAX=11, RDI=DATA, RSI=0x1000))
    run(t)
    assert t.reg_read('RAX') == 0
    assert DATA not in [start for start, _, _ in t.regions()]


def test_an_unknown_call_comes_back_as_enosys():
    t, s, out = make(sysprog(RAX=0xdead))
    run(t)
    assert _signed(t.reg_read('RAX')) == -syscalls.ERRNO['ENOSYS']
    assert s.unknown == {0xdead: 1}


def test_writing_to_a_read_only_descriptor_fails():
    t, s, out = make(sysprog(RAX=1, RDI=0, RSI=DATA, RDX=1))
    run(t)
    assert _signed(t.reg_read('RAX')) == -syscalls.ERRNO['EBADF']


def test_open_sees_only_the_files_it_was_given():
    t, s, out = make(sysprog(RAX=2, RDI=DATA), files={'/input': b'contents'})
    t.write(DATA, b'/input\0')
    run(t)
    fd = t.reg_read('RAX')
    assert fd == 3 and s.files[fd].data == b'contents'


def test_open_of_anything_else_is_enoent():
    t, s, out = make(sysprog(RAX=2, RDI=DATA))
    t.write(DATA, b'/etc/passwd\0')
    run(t)
    assert _signed(t.reg_read('RAX')) == -syscalls.ERRNO['ENOENT']


def test_a_handler_can_be_replaced():
    t, s, out = make(sysprog(RAX=39))
    s.handlers['getpid'] = lambda sys_, args: 4242
    run(t)
    assert t.reg_read('RAX') == 4242


def test_a_bad_buffer_comes_back_as_efault():
    t, s, out = make(sysprog(RAX=1, RDI=1, RSI=0xdead0000, RDX=4))
    run(t)
    assert _signed(t.reg_read('RAX')) == -syscalls.ERRNO['EFAULT']


# ---- replay ---------------------------------------------------------------

def test_a_replay_across_a_call_does_not_run_it_again():
    t, s, out = make(sysprog(lead=4, tail=6, RAX=1, RDI=1, RSI=DATA, RDX=3),
                     interval=2)
    t.write(DATA, b'abc')
    run(t)
    assert out == [(1, b'abc')]
    trap = s.records[0].icount
    # Land after the call, from a checkpoint before it: the replay crosses it.
    t.goto_icount(trap + 1)
    assert out == [(1, b'abc')], 'the replay printed a second time'
    assert t.reg_read('RAX') == 3, 'the replay lost the result'


def test_going_back_before_a_call_undoes_its_memory_and_its_result():
    t, s, out = make(sysprog(lead=4, tail=6, RAX=0, RDI=0, RSI=DATA, RDX=4),
                     interval=2, stdin=b'wxyz1234')
    run(t)
    trap = s.records[0].icount
    assert t.read(DATA, 4) == b'wxyz'
    t.goto_icount(trap)
    assert t.read(DATA, 4) == b'\0' * 4
    assert s.files[0].offset == 0, 'the file offset did not come back'
    assert not s.records, 'the record of a call that has not happened was kept'


def test_re_running_a_read_returns_the_same_bytes():
    t, s, out = make(sysprog(lead=4, tail=6, RAX=0, RDI=0, RSI=DATA, RDX=4),
                     interval=2, stdin=b'wxyz1234')
    run(t)
    trap = s.records[0].icount
    t.goto_icount(trap)
    run(t)
    assert t.read(DATA, 4) == b'wxyz', 'the re-run consumed the next bytes'


def test_a_mapping_made_by_mmap_is_rewound():
    t, s, out = make(sysprog(lead=4, tail=6, RAX=9, RDI=0, RSI=0x1000,
                             RDX=3, R10=0x22, R8=0xffffffff), interval=3)
    run(t)
    addr = t.reg_read('RAX')
    assert s.mapped(addr, 0x1000)
    trap = s.records[0].icount
    t.goto_icount(trap)
    assert not s.mapped(addr, 0x1000), 'the mapping outlived the state that made it'
    assert s.mmap_next == s.mmap_base, 'the arena pointer did not come back'
    run(t)
    assert t.reg_read('RAX') == addr, 'the re-run handed out a different address'


def test_a_replay_across_mmap_puts_the_mapping_back():
    t, s, out = make(sysprog(lead=4, tail=6, RAX=9, RDI=0, RSI=0x1000,
                             RDX=3, R10=0x22, R8=0xffffffff), interval=3)
    run(t)
    addr = t.reg_read('RAX')
    trap = s.records[0].icount
    t.goto_icount(trap + 1)
    assert s.mapped(addr, 0x1000)
    assert t.reg_read('RAX') == addr


def test_a_terminated_target_comes_back_when_you_step_before_the_exit():
    t, s, out = make(sysprog(lead=4, tail=2, RAX=60, RDI=0), interval=2)
    run(t)
    assert t.terminated
    t.goto_icount(s.records[0].icount)
    assert not t.terminated
    assert run(t).reason == 'exit'


def test_the_log_is_pruned_as_the_history_is_folded_away():
    """A loop of calls, with a history too small to hold them all.

    The log is meant to cost nothing the history is not paying for already,
    so it has to shrink as the history folds - not grow with the run.
    """
    #   1000: mov rax, 39      (getpid)
    #   1007: syscall
    #   1009: jmp 0x1000
    t, s, out = make(bytes.fromhex('48c7c027000000') + bytes.fromhex('0f05')
                     + bytes.fromhex('ebf5'), interval=2, budget=12 * 1024)
    calls = []
    s.handlers['getpid'] = lambda sys_, args: calls.append(1) or 1
    t.step(300)
    assert len(calls) >= 50, f'only {len(calls)} calls in 300 instructions'
    assert t.timeline.dropped, 'the history never folded, so nothing was proved'
    assert all(r.icount >= t.earliest_icount for r in s.records), \
        'a record outlived the history it belongs to'
    assert len(s.records) < len(calls), \
        f'{len(s.records)} records kept for {len(calls)} calls'


# ---- the other architectures ---------------------------------------------

TRAPS = {
    # key: (code for the trap, the instruction after it)
    'x86': ('cd80', '90'),
    'armle': ('000000ef', '00f020e3'),
    'armlethumb': ('00df', '00bf'),
    'arm64le': ('010000d4', '1f2003d5'),
    'mips': ('0000000c', '00000000'),
    'mipsel': ('0c000000', '00000000'),
    'riscv64': ('73000000', '13000000'),
    'ppc32': ('44000002', '60000000'),
    'm68k': ('4e40', '4e71'),
}


@pytest.mark.parametrize('key', sorted(TRAPS))
def test_the_trap_is_recognised_and_answered(key):
    """Every architecture's trap reaches a handler and gets a result back."""
    spec = arch.spec_for_key(key)
    a = abi.syscall_abi(key)
    uc = Uc(spec.uc_arch, spec.uc_mode)
    uc.mem_map(CODE, 0x1000)
    trap, after = TRAPS[key]
    uc.mem_write(CODE, bytes.fromhex(trap) + bytes.fromhex(after) * 4)
    t = UnicornTarget(uc, spec=spec)
    t.reg_write(spec.pc, CODE)
    s = syscalls.install(t)
    t.reg_write(a.number, a.numbers['getpid'])
    t.step(2)
    assert [r.name for r in s.records] == ['getpid']
    assert t.reg_read(a.ret) == 1


@pytest.mark.parametrize('key', sorted(TRAPS))
def test_a_failure_is_reported_the_way_the_architecture_does(key):
    spec = arch.spec_for_key(key)
    a = abi.syscall_abi(key)
    uc = Uc(spec.uc_arch, spec.uc_mode)
    uc.mem_map(CODE, 0x1000)
    trap, after = TRAPS[key]
    uc.mem_write(CODE, bytes.fromhex(trap) + bytes.fromhex(after) * 4)
    t = UnicornTarget(uc, spec=spec)
    t.reg_write(spec.pc, CODE)
    s = syscalls.install(t)
    t.reg_write(a.number, 0xfff)          # nothing is number 0xfff
    t.step(2)
    enosys = s.errno('ENOSYS')
    result = t.reg_read(a.ret)
    if a.error == abi.MIPS:
        assert result == enosys and t.reg_read(a.error_reg) == 1
    elif a.error == abi.PPC:
        assert result == enosys and t.reg_read(a.error_cr) & 1
    else:
        assert _signed(result, spec.bits) == -enosys


def test_m68k_moves_past_the_trap_itself():
    """Unicorn leaves m68k on the `trap`, so without the fix-up it loops."""
    spec = arch.spec_for_key('m68k')
    uc = Uc(spec.uc_arch, spec.uc_mode)
    uc.mem_map(CODE, 0x1000)
    uc.mem_write(CODE, bytes.fromhex('4e40') + bytes.fromhex('4e71') * 4)
    t = UnicornTarget(uc, spec=spec)
    t.reg_write(spec.pc, CODE)
    s = syscalls.install(t)
    t.reg_write('D0', 20)                 # getpid
    t.step(3)
    assert t.pc() > CODE + 2
    assert len(s.records) == 1, 'the trap ran more than once'


def test_architectures_without_a_table_say_so():
    with pytest.raises(KeyError, match='no system call convention'):
        abi.syscall_abi('sparc32')
    assert not syscalls.available('sparc32')
    assert syscalls.available('x64')


def test_the_number_tables_agree_with_the_generic_header():
    """arm64 and riscv share asm-generic/unistd.h; spot-check it stayed so."""
    for key in ('arm64le', 'riscv64', 'riscv32'):
        numbers = abi.syscall_abi(key).numbers
        assert numbers['read'] == 63 and numbers['write'] == 64
        assert numbers['exit'] == 93 and numbers['mmap'] == 222


def test_describe_summarises_what_happened():
    t, s, out = make(sysprog(RAX=39))
    run(t)
    text = s.describe()
    assert 'getpid' in text and 'x64' in text


def _signed(value, bits=64):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


# ---- the argument-block form of mmap --------------------------------------

def test_old_mmap_reads_its_arguments_from_a_block_not_registers():
    """i386 and m68k number 90 takes one pointer to six words. Dispatching
    it like the register form would read the arguments from nowhere."""
    t, s, out = make(sysprog(RAX=0, RDI=DATA))
    # struct mmap_arg_struct { addr, len, prot, flags, fd, offset }
    block = b''.join(v.to_bytes(8, 'little') for v in
                     (0, 0x2000, 3, 0x22, (1 << 64) - 1, 0))
    t.write(DATA, block)
    s.handlers['old_mmap'] = syscalls.HANDLERS['old_mmap']
    result = s.handlers['old_mmap'](s, [DATA, 0, 0, 0, 0, 0])
    assert result == s.mmap_base and s.mapped(result, 0x2000)


def test_old_mmap_with_a_bad_block_is_efault():
    t, s, out = make(sysprog(RAX=39))
    with pytest.raises(syscalls.SyscallError) as e:
        syscalls.HANDLERS['old_mmap'](s, [0xdead0000, 0, 0, 0, 0, 0])
    assert e.value.name == 'EFAULT'


def test_the_tables_that_have_old_mmap_are_the_ones_that_should():
    assert abi.syscall_abi('x86').numbers['old_mmap'] == 90
    assert abi.syscall_abi('m68k').numbers['old_mmap'] == 90
    assert 'mmap' not in abi.syscall_abi('x86').numbers
    # arm leaves 90 out entirely; ppc and the 64-bit tables use the
    # register-argument form at their own numbers.
    assert 'old_mmap' not in abi.syscall_abi('armle').numbers
    assert abi.syscall_abi('ppc32').numbers['mmap'] == 90
    assert abi.syscall_abi('x64').numbers['mmap'] == 9


def test_writev_refuses_a_wild_count():
    t, s, out = make(sysprog(RAX=20, RDI=1, RSI=DATA, RDX=0x7fffffff))
    run(t)
    assert _signed(t.reg_read('RAX')) == -syscalls.ERRNO['EINVAL']


def test_a_wild_write_length_is_efault_not_a_crash():
    t, s, out = make(sysprog(RAX=1, RDI=1, RSI=DATA, RDX=0x7fffffff))
    run(t)
    assert _signed(t.reg_read('RAX')) == -syscalls.ERRNO['EFAULT']
    assert not t.terminated, 'the emulator was brought down by a bad length'
