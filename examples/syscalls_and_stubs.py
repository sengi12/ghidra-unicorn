"""A harness for code that talks to an operating system that is not there.

This is the thing the connector could not do until the system call and stub
layers landed: the program below reads its input with `read`, allocates with
`malloc`, measures with `strlen`, prints with `write` and leaves through
`exit`. None of that is in the binary - there is no libc and no kernel - and
all of it works, because `syscalls.py` services the traps and `stubs.py`
stands in for the functions.

Run it without Ghidra at all::

    python -m ghidraunicorn --harness examples/syscalls_and_stubs.py \\
        --listen --stdin /etc/hostname

or point the launcher's OPT_HARNESS at it. The console's `sys`, `stub` and
`heap` commands show what the layers did, and reverse execution works
straight through the calls: `rsi` back over the `read` and the input is
un-read, the heap block is un-allocated, and running forward again gives
exactly the same bytes and the same address.

The x86-64 programme, assembled by hand below:

    main:
        mov  rdi, 0x40
        call malloc           ; -> rax, a heap block
        mov  rbx, rax
        xor  eax, eax         ; read(0, rbx, 0x40)
        xor  edi, edi
        mov  rsi, rbx
        mov  rdx, 0x40
        syscall
        mov  rdi, rbx         ; strlen(rbx)
        call strlen
        mov  rdx, rax         ; write(1, rbx, rax)
        mov  rax, 1
        mov  rdi, 1
        mov  rsi, rbx
        syscall
        mov  rax, 60          ; exit(0)
        xor  edi, edi
        syscall
"""
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP

CODE = 0x0040_0000
STACK = 0x0050_0000
SIZE = 0x1_0000

#: The stub layer binds by name, so these are where the "library" lives. The
#: bytes there are never executed: a stub takes over at the entry address.
MALLOC = CODE + 0x800
STRLEN = CODE + 0x810

START = CODE
MODULES = [('example', CODE, SIZE)]
#: What the program reads when nothing is given with --stdin.
STDIN = b'a line of input\n'
#: This file is a raw programme with no symbol table, so it says where its
#: stubs belong rather than leaving it to --symbols.
STUBS_AT = {'malloc': MALLOC, 'strlen': STRLEN}


def _call(here: int, target: int) -> bytes:
    return b'\xe8' + ((target - (here + 5)) & 0xffffffff).to_bytes(4, 'little')


def _program() -> bytes:
    code = bytes.fromhex('48c7c740000000')                 # mov rdi, 0x40
    code += _call(CODE + len(code), MALLOC)
    code += bytes.fromhex('4889c3')                        # mov rbx, rax
    code += bytes.fromhex('4831c0' '4831ff' '4889de'       # read(0, rbx, 0x40)
                          '48c7c240000000' '0f05')
    code += bytes.fromhex('4889df')                        # mov rdi, rbx
    code += _call(CODE + len(code), STRLEN)
    code += bytes.fromhex('4889c2')                        # mov rdx, rax
    code += bytes.fromhex('48c7c001000000' '48c7c701000000'  # write(1, rbx, rdx)
                          '4889de' '0f05')
    code += bytes.fromhex('48c7c03c000000' '4831ff' '0f05')  # exit(0)
    return code


def create(input_file=None):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, SIZE)
    uc.mem_map(STACK, SIZE)
    uc.mem_write(CODE, _program())
    # Where the stubs go. `ret` is a harmless thing to leave under them, so
    # that unbinding one does something sane rather than running off a cliff.
    uc.mem_write(MALLOC, b'\xc3')
    uc.mem_write(STRLEN, b'\xc3')
    uc.reg_write(UC_X86_REG_RIP, CODE)
    uc.reg_write(UC_X86_REG_RSP, STACK + SIZE - 0x100)
    if input_file:
        global STDIN
        with open(input_file, 'rb') as f:
            STDIN = f.read()
    return uc


def stubs_at():
    """Where the stub layer binds. `STUBS_AT` above is what does it."""
    return dict(STUBS_AT)
