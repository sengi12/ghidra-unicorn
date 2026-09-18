"""Standing in for library functions, and doing it again on a replay.

Most of these drive x86-64, where `callprog` assembles a real call to a
stubbed address. The calling-convention tests instead put the machine
directly at the stub's entry with the arguments and the return address in
place, which is the same thing the call would have arranged and is a great
deal easier to get right on nine architectures.
"""
import pytest
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc

from ghidraunicorn import abi, arch, stubs
from ghidraunicorn.stubs import StubError
from ghidraunicorn.symbols import Symbol, SymbolTable
from ghidraunicorn.target import UnicornTarget

CODE = 0x1000
DATA = 0x2000
LIB = 0x3000
STACK = 0x7000


def callprog(*calls, arg=None):
    """`mov rdi, arg` then a `call` to each address in turn, then no-ops."""
    code = b'' if arg is None else bytes.fromhex('48c7c7') + arg.to_bytes(4, 'little')
    for target in calls:
        here = CODE + len(code)
        code += bytes.fromhex('e8') + ((target - (here + 5)) & 0xffffffff).to_bytes(4, 'little')
    return code + b'\x90' * 8


def make(code, interval=1000, **kwargs):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    for base in (CODE, DATA, LIB, STACK):
        uc.mem_map(base, 0x1000)
    uc.mem_write(CODE, code)
    uc.mem_write(LIB, b'\xf4' * 0x100)     # hlt: the real bodies, never run
    uc.reg_write(arch.x86.UC_X86_REG_RIP, CODE)
    uc.reg_write(arch.x86.UC_X86_REG_RSP, STACK + 0xff0)
    t = UnicornTarget(uc, checkpoint_interval=interval)
    out = []
    st = stubs.install(t, on_output=lambda fd, d: out.append(d), **kwargs)
    return t, st, out


def run(t, n=40):
    for _ in range(n):
        ev = t.step()
        if ev.reason != 'step':
            return ev
    return None


def call1(name, arg, extra=None, **kwargs):
    """Call `name` with one register argument; return (target, stubs, out)."""
    t, st, out = make(callprog(LIB, arg=arg), **kwargs)
    st.bind(name, LIB)
    if extra:
        extra(t)
    run(t)
    return t, st, out


# ---- the heap -------------------------------------------------------------

def test_malloc_returns_usable_memory():
    t, st, out = call1('malloc', 0x40)
    address = t.reg_read('RAX')
    assert address == st.heap.base
    t.write(address, b'x' * 0x40)          # it is mapped, not just a number
    assert t.read(address, 4) == b'xxxx'


def test_two_allocations_do_not_overlap_and_are_aligned():
    t, st, out = make(callprog(LIB, LIB, arg=0x18))
    st.bind('malloc', LIB)
    run(t)
    first, second = sorted(b.address for b in st.heap.blocks.values())
    assert len(st.heap.blocks) == 2
    assert second >= first + 0x18
    assert first % stubs.ALIGN == 0 and second % stubs.ALIGN == 0


def test_calloc_hands_back_zeroed_memory():
    t, st, out = make(callprog(LIB, arg=8))
    st.bind('calloc', LIB)
    t.reg_write('RSI', 4)                  # calloc(8, 4)
    run(t)
    address = t.reg_read('RAX')
    assert t.read(address, 32) == b'\0' * 32


def test_free_puts_a_block_back_and_it_gets_reused():
    t, st, out = make(callprog(LIB, arg=0x20))
    st.bind('malloc', LIB)
    run(t)
    address = t.reg_read('RAX')
    st.heap.release(address)
    assert st.heap.freed and not st.heap.blocks
    again, _ = st.heap.allocate(0x20)
    assert again.address == address


def test_freeing_something_that_was_never_allocated_is_reported_not_fatal():
    t, st, out = make(callprog(LIB, arg=0xdead))
    st.bind('free', LIB)
    run(t)
    assert t.pc() > CODE                   # it returned rather than blowing up
    with pytest.raises(StubError, match='not an allocated block'):
        st.heap.release(0xdead)


def test_realloc_keeps_the_contents():
    t, st, out = make(callprog(LIB, arg=8))
    st.bind('malloc', LIB)
    run(t)
    old = t.reg_read('RAX')
    t.write(old, b'12345678')
    new = st.implementations['realloc'](st, [old, 0x200, 0, 0, 0, 0])
    assert t.read(new, 8) == b'12345678'


def test_the_heap_grows_its_mapping_as_it_is_used():
    t, st, out = make(callprog(LIB, arg=0x3000))
    st.bind('malloc', LIB)
    run(t)
    address = t.reg_read('RAX')
    t.write(address + 0x2f00, b'far')      # well past the first page
    assert t.read(address + 0x2f00, 3) == b'far'


# ---- strings and memory ---------------------------------------------------

def test_strlen_counts_to_the_terminator():
    t, st, out = call1('strlen', DATA, extra=lambda t: t.write(DATA, b'hello world\0'))
    assert t.reg_read('RAX') == 11


def test_strcpy_copies_the_terminator_too():
    t, st, out = make(callprog(LIB, arg=DATA))
    st.bind('strcpy', LIB)
    t.write(DATA, b'\xff' * 16)
    t.write(DATA + 0x100, b'source\0')
    t.reg_write('RSI', DATA + 0x100)
    run(t)
    assert t.read(DATA, 7) == b'source\0'
    assert t.reg_read('RAX') == DATA


def test_strcmp_orders_the_way_libc_does():
    st = _bare()
    st.target.write(DATA, b'abc\0')
    st.target.write(DATA + 0x10, b'abd\0')
    assert st.implementations['strcmp'](st, [DATA, DATA, 0, 0, 0, 0]) == 0
    assert st.implementations['strcmp'](st, [DATA, DATA + 0x10, 0, 0, 0, 0]) < 0
    assert st.implementations['strcmp'](st, [DATA + 0x10, DATA, 0, 0, 0, 0]) > 0


def test_memset_and_memcpy_and_memcmp():
    st = _bare()
    st.implementations['memset'](st, [DATA, 0x41, 8, 0, 0, 0])
    assert st.target.read(DATA, 8) == b'A' * 8
    st.implementations['memcpy'](st, [DATA + 0x20, DATA, 8, 0, 0, 0])
    assert st.target.read(DATA + 0x20, 8) == b'A' * 8
    assert st.implementations['memcmp'](st, [DATA, DATA + 0x20, 8, 0, 0, 0]) == 0


def test_memmove_handles_an_overlap():
    st = _bare()
    st.target.write(DATA, b'abcdefgh')
    st.implementations['memmove'](st, [DATA + 2, DATA, 6, 0, 0, 0])
    assert st.target.read(DATA, 8) == b'ababcdef'


def test_strchr_finds_and_misses():
    st = _bare()
    st.target.write(DATA, b'hello\0')
    assert st.implementations['strchr'](st, [DATA, ord('l'), 0, 0, 0, 0]) == DATA + 2
    assert st.implementations['strrchr'](st, [DATA, ord('l'), 0, 0, 0, 0]) == DATA + 3
    assert st.implementations['strchr'](st, [DATA, ord('z'), 0, 0, 0, 0]) == 0


def test_strdup_allocates_a_copy():
    st = _bare()
    st.target.write(DATA, b'copy me\0')
    address = st.implementations['strdup'](st, [DATA, 0, 0, 0, 0, 0])
    assert address in st.heap.blocks
    assert st.target.read(address, 8) == b'copy me\0'


def test_strncpy_pads_to_the_length():
    st = _bare()
    st.target.write(DATA + 0x10, b'ab\0')
    st.target.write(DATA, b'\xff' * 8)
    st.implementations['strncpy'](st, [DATA, DATA + 0x10, 6, 0, 0, 0])
    assert st.target.read(DATA, 6) == b'ab\0\0\0\0'


def test_a_string_with_no_terminator_is_refused_rather_than_read_forever():
    st = _bare()
    st.target.write(DATA, b'A' * 0x100)
    with pytest.raises(StubError, match='no terminator'):
        st.read_cstring(DATA, limit=0x40)


def test_puts_reaches_the_output_callback():
    t, st, out = call1('puts', DATA, extra=lambda t: t.write(DATA, b'printed\0'))
    assert out == [b'printed\n']


def test_exit_terminates_the_target():
    t, st, out = call1('exit', 7)
    assert t.terminated
    assert 'exit(7)' in t.exit_description


def test_abort_terminates_the_target():
    t, st, out = call1('abort', 0)
    assert t.terminated and 'abort' in t.exit_description


# ---- how a stub sits in the emulator --------------------------------------

def test_the_real_body_never_runs():
    """The bytes at the stub's address are `hlt`; reaching them would fault."""
    t, st, out = call1('malloc', 0x10)
    assert t.pc() > CODE and not t.terminated


def test_a_breakpoint_on_a_stub_stops_before_it_stands_in():
    t, st, out = make(callprog(LIB, arg=0x10))
    st.bind('malloc', LIB)
    t.add_breakpoint(LIB)
    ev = t.run()
    assert ev.reason == 'breakpoint' and ev.pc == LIB
    assert st.calls == {}, 'the stub ran even though we stopped before it'


def test_binding_an_unknown_name_is_refused():
    t, st, out = make(callprog())
    with pytest.raises(KeyError, match='no implementation'):
        st.bind('frobnicate', LIB)


def test_bind_symbols_binds_what_the_table_can_place():
    t, st, out = make(callprog())
    table = SymbolTable([Symbol('malloc', LIB, 1), Symbol('strlen', LIB + 0x10, 1),
                         Symbol('main', CODE, 1)])
    bound = st.bind_symbols(table)
    assert bound == ['malloc', 'strlen']
    assert st.bound == {LIB: 'malloc', LIB + 0x10: 'strlen'}


def test_unbinding_lets_the_real_code_run_again():
    t, st, out = make(callprog(LIB, arg=0x10))
    st.bind('malloc', LIB)
    run(t)
    assert st.calls == {'malloc': 1}
    t.goto_icount(0)
    st.unbind(LIB)
    run(t)
    assert st.calls == {'malloc': 1}, 'the stub stood in after being unbound'
    assert t.pc() >= LIB, 'execution did not reach the function itself'


def test_an_implementation_can_be_replaced():
    t, st, out = make(callprog(LIB, arg=0x10))
    st.implementations['malloc'] = lambda s, a: 0xcafe
    st.bind('malloc', LIB)
    run(t)
    assert t.reg_read('RAX') == 0xcafe


# ---- replay ---------------------------------------------------------------

def test_a_replay_across_a_stub_keeps_the_same_answer():
    t, st, out = make(callprog(LIB, arg=0x40), interval=2)
    st.bind('malloc', LIB)
    run(t)
    address = t.reg_read('RAX')
    at = st.log.entries[0].icount
    t.goto_icount(at + 1)
    assert t.reg_read('RAX') == address, 'the replay lost the result'
    assert len(st.heap.blocks) == 1, 'the replay allocated a second time'


def test_going_back_before_a_stub_undoes_the_allocation():
    t, st, out = make(callprog(LIB, arg=0x40), interval=2)
    st.bind('malloc', LIB)
    run(t)
    at = st.log.entries[0].icount
    t.goto_icount(at)
    assert st.heap.blocks == {} and st.heap.top == st.heap.base
    run(t)
    assert t.reg_read('RAX') == st.heap.base, 'the re-run moved the block'


def test_a_replay_does_not_print_twice():
    t, st, out = make(callprog(LIB, arg=DATA), interval=2)
    st.bind('puts', LIB)
    t.write(DATA, b'once\0')
    run(t)
    assert out == [b'once\n']
    t.goto_icount(st.log.entries[0].icount + 1)
    assert out == [b'once\n']


def test_a_long_replay_still_stands_in_for_the_function():
    """The crux of the whole thing.

    With one checkpoint, at instruction 0, landing anywhere means replaying
    from the start. If the stub did not fire on the way through, the
    emulator would run the function's own instructions - which the first
    pass never touched - and the machine would diverge from there on.
    """
    t, st, out = make(callprog(LIB, arg=0x40), interval=1000)
    st.bind('malloc', LIB)
    run(t)
    address, end = t.reg_read('RAX'), t.icount
    assert t.timeline.checkpoint_at_or_before(end).icount == 0, 'more than one checkpoint'
    t.goto_icount(end - 1)
    assert st.calls == {'malloc': 1}, 'the replay called the stub for real'
    assert t.reg_read('RAX') == address
    assert len(st.heap.blocks) == 1


# ---- the calling conventions ----------------------------------------------

#: A no-op for each architecture, to fill the code the stub returns into.
#: TriCore is absent: Unicorn 2.1.4 refuses `mem_map` for it at every
#: address tried, so nothing can be emulated on it here. Its calling
#: convention is still in the table and still covered by the test below
#: that every architecture has one.
NOPS = {'x64': '90', 'x86': '90', 'armle': '00f020e3', 'armlethumb': '00bf',
        'arm64le': '1f2003d5', 'mips': '00000000', 'mipsel': '00000000',
        'riscv64': '13000000', 'ppc32': '60000000', 'm68k': '4e71',
        'sparc32': '01000000'}


@pytest.mark.parametrize('key', sorted(NOPS))
def test_the_convention_reads_the_argument_and_returns_to_the_caller(key):
    """Put the machine where a call would have left it, and step once.

    `strlen` is the probe: it takes one argument and returns a number, so a
    wrong argument register gives a fault or a wrong length, and a wrong
    return path leaves the program counter somewhere it should not be.
    """
    spec = arch.spec_for_key(key)
    a = abi.call_abi(key)
    uc = Uc(spec.uc_arch, spec.uc_mode)
    for base in (CODE, DATA, LIB, STACK):
        uc.mem_map(base, 0x1000)
    thumb = 1 if spec.context.get('TMode') else 0
    # Both the caller's code and the function's own address need something
    # legal under them: RISC-V traps on an all-zero word while the
    # instruction is still being translated, before any code hook runs.
    uc.mem_write(CODE, bytes.fromhex(NOPS[key]) * 16)
    uc.mem_write(LIB, bytes.fromhex(NOPS[key]) * 16)
    t = UnicornTarget(uc, spec=spec)
    st = stubs.install(t)
    st.bind('strlen', LIB)
    t.write(DATA, b'measure me\0')
    t.reg_write(spec.pc, LIB)
    sp = STACK + 0x800
    t.reg_write(spec.sp, sp)
    # Where the call would have left the return address, and the argument.
    ret = CODE | thumb
    if a.returns == 'link':
        t.reg_write(a.link, ret - a.link_offset)
    else:
        t.write(sp, ret.to_bytes(spec.ptr_size, spec.endian))
    if a.args:
        t.reg_write(a.args[0], DATA)
    else:
        t.write(sp + a.stack_slot * spec.ptr_size,
                DATA.to_bytes(spec.ptr_size, spec.endian))
    t.step()
    assert t.reg_read(a.ret) == 10, f'{key}: wrong argument or return register'
    assert t.pc() & ~1 == CODE, f'{key}: returned to {t.pc():#x}, not the caller'
    if a.returns == 'stack':
        assert t.sp() == sp + spec.ptr_size, f'{key}: the return address was not popped'


def test_every_architecture_has_a_calling_convention():
    for key in arch.SPECS:
        assert stubs.available(key), f'{key} has no calling convention'


def _bare():
    """A stub layer with memory to work on and nothing bound."""
    t, st, out = make(callprog())
    return st
