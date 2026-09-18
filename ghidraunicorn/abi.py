"""Application binary interfaces: how a program passes arguments.

Two different conventions are needed, and they are not the same one:

* the **syscall** convention, for the trap instruction a kernel would service
  (used by `syscalls.py`), and
* the **C calling** convention, for the library functions that get stubbed
  out (used by `stubs.py`).

Like `arch.py` this is a table, and the same rule applies: every register
name here is one of the Ghidra SLEIGH names `arch.py` defines, so a handler
reads registers through `UnicornTarget.reg_read` and never touches a Unicorn
constant. Adding an architecture is data, not code.

Where the numbers come from
---------------------------
The syscall conventions are Linux's, from each architecture's kernel entry
code. The numbers are from `arch/<arch>/kernel/syscalls/syscall*.tbl`, and
for the architectures that share the generic table (arm64, riscv) from
`include/uapi/asm-generic/unistd.h`. The C conventions are each
architecture's SysV psABI, except TriCore's, which is Infineon's EABI.

Only the calls the Linux layer implements are listed. A number that is not
in the table reaches the catch-all and comes back as -ENOSYS, which is both
honest and debuggable.

SPARC and TriCore get a calling convention but no syscall table: neither is
a Linux target this connector has ever been pointed at, and inventing a
syscall table nobody can check is worse than saying it is not there.
"""
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Syscall numbers

# x86_64: arch/x86/entry/syscalls/syscall_64.tbl
_NR_X86_64 = {'read': 0, 'write': 1, 'open': 2, 'close': 3, 'lseek': 8,
              'mmap': 9, 'munmap': 11, 'brk': 12, 'writev': 20, 'getpid': 39,
              'exit': 60, 'exit_group': 231, 'openat': 257}

# i386: arch/x86/entry/syscalls/syscall_32.tbl. Number 90 is `sys_old_mmap`,
# which takes one pointer to a block of six words rather than six registers,
# so it gets its own handler; 192 is the register-argument `mmap2`. Wiring 90
# to the ordinary mmap would read the arguments out of the wrong place
# entirely - the same trap the arm table avoids by leaving 90 out.
_NR_I386 = {'exit': 1, 'read': 3, 'write': 4, 'open': 5, 'close': 6,
            'lseek': 19, 'getpid': 20, 'brk': 45, 'old_mmap': 90,
            'munmap': 91, 'writev': 146, 'mmap2': 192, 'exit_group': 252,
            'openat': 295}

# arm, EABI: arch/arm/tools/syscall.tbl. There is deliberately no `mmap`
# here: number 90 is OABI's old_mmap, which an EABI binary never issues.
_NR_ARM = {'exit': 1, 'read': 3, 'write': 4, 'open': 5, 'close': 6,
           'lseek': 19, 'getpid': 20, 'brk': 45, 'munmap': 91, 'writev': 146,
           'mmap2': 192, 'exit_group': 248, 'openat': 322}

# arm64 and riscv: include/uapi/asm-generic/unistd.h. `open` is not in the
# generic table at all; everything goes through openat.
_NR_GENERIC = {'openat': 56, 'close': 57, 'lseek': 62, 'read': 63,
               'write': 64, 'writev': 66, 'exit': 93, 'exit_group': 94,
               'getpid': 172, 'brk': 214, 'munmap': 215, 'mmap': 222}

# mips o32: arch/mips/kernel/syscalls/syscall_o32.tbl, offset by 4000.
_NR_MIPS_O32 = {'exit': 4001, 'read': 4003, 'write': 4004, 'open': 4005,
                'close': 4006, 'lseek': 4019, 'getpid': 4020, 'brk': 4045,
                'mmap': 4090, 'munmap': 4091, 'writev': 4146, 'mmap2': 4210,
                'exit_group': 4246, 'openat': 4288}

# mips n64: arch/mips/kernel/syscalls/syscall_n64.tbl, offset by 5000.
_NR_MIPS_N64 = {'read': 5000, 'write': 5001, 'open': 5002, 'close': 5003,
                'lseek': 5008, 'mmap': 5009, 'munmap': 5011, 'brk': 5012,
                'writev': 5019, 'getpid': 5038, 'exit': 5058,
                'exit_group': 5205, 'openat': 5247}

# powerpc, 32 and 64 share one table: arch/powerpc/kernel/syscalls/syscall.tbl
# PowerPC came late enough that its 90 is the register-argument `sys_mmap`,
# not the `old_mmap` that i386 and m68k have at the same number.
_NR_PPC = {'exit': 1, 'read': 3, 'write': 4, 'open': 5, 'close': 6,
           'lseek': 19, 'getpid': 20, 'brk': 45, 'mmap': 90, 'munmap': 91,
           'writev': 146, 'mmap2': 192, 'exit_group': 234, 'openat': 286}

# m68k: arch/m68k/kernel/syscalls/syscall.tbl. 90 is `sys_old_mmap` here
# too, as it is on every port old enough to have had it.
_NR_M68K = {'exit': 1, 'read': 3, 'write': 4, 'open': 5, 'close': 6,
            'lseek': 19, 'getpid': 20, 'brk': 45, 'old_mmap': 90,
            'munmap': 91, 'writev': 146, 'mmap2': 192, 'exit_group': 247,
            'openat': 322}


# ---------------------------------------------------------------------------
# Conventions

#: A result is an error when it comes back as a small negative number. Every
#: architecture here uses this except MIPS and PowerPC.
NEGATIVE = 'negative'
#: MIPS: the result is the positive errno and a separate register is the flag.
MIPS = 'mips'
#: PowerPC: the result is the positive errno and CR0's summary-overflow bit
#: is the flag.
PPC = 'ppc'


@dataclass(frozen=True)
class SyscallAbi:
    """How a program asks for a system call, and how the answer comes back."""
    #: Register holding the call number.
    number: str
    #: Registers holding arguments one to six, in order.
    args: Tuple[str, ...]
    #: Register the result goes in.
    ret: str
    #: Call number -> name, for the calls the Linux layer knows.
    numbers: Dict[str, int]
    #: Interrupt numbers that mean "system call" on this architecture, as
    #: Unicorn reports them to a UC_HOOK_INTR callback.
    intnos: Tuple[int, ...] = ()
    #: True when the trap is an instruction Unicorn reports through
    #: UC_HOOK_INSN instead of an interrupt. x86-64's `syscall` is the only
    #: one. Its `int 0x80` is the 32-bit compatibility entry, which takes the
    #: i386 numbers in the i386 registers, so it is left unwired rather than
    #: dispatched through the 64-bit table and quietly given the wrong call.
    insn: bool = False
    #: How failure is reported: NEGATIVE, MIPS or PPC.
    error: str = NEGATIVE
    #: MIPS puts the error flag in its own register.
    error_reg: Optional[str] = None
    #: PowerPC puts it in a condition field.
    error_cr: Optional[str] = None
    #: Error numbers that differ from the generic `asm-generic/errno.h` ones.
    #: MIPS agrees with everyone up to about 35 and then goes its own way.
    errnos: Optional[Dict[str, int]] = None
    #: Offset from the stack pointer of the arguments that did not fit in
    #: registers. MIPS o32 is the only convention here that needs it: it
    #: passes four in registers and the fifth and sixth at sp+16 and sp+20.
    stack_args: Optional[int] = None
    #: Bytes to move the program counter past the trap. Unicorn does this
    #: itself everywhere except m68k, where the hook is entered with the
    #: program counter still on the `trap` instruction, so returning without
    #: moving it executes the trap again, forever.
    advance: int = 0

    @property
    def by_number(self) -> Dict[int, str]:
        return {v: k for k, v in self.numbers.items()}


@dataclass(frozen=True)
class CallAbi:
    """The C calling convention, for a stubbed function."""
    #: Integer argument registers, in order. Empty where every argument is
    #: passed on the stack (x86 cdecl, m68k).
    args: Tuple[str, ...]
    #: Register the return value goes in.
    ret: str
    #: 'link' returns by jumping to the link register; 'stack' returns by
    #: popping the return address off the stack.
    returns: str
    #: The link register, when `returns` is 'link'.
    link: Optional[str] = None
    #: Bytes to add to the link register to get the return address. SPARC's
    #: `ret` is `jmpl %i7+8`, because the call's delay slot has already run.
    link_offset: int = 0
    #: Pointer-sized slot, counted from the stack pointer, where the first
    #: argument that did not travel in a register lives. A convention that
    #: pushes the return address puts it in slot 0, so arguments start at 1.
    stack_slot: int = 1
    #: Where the high half of a 64-bit value returned by a 32-bit machine
    #: goes, when the architecture defines one.
    ret_hi: Optional[str] = None


_ARM_SYS = dict(number='r7', args=('r0', 'r1', 'r2', 'r3', 'r4', 'r5'),
                ret='r0', numbers=_NR_ARM, intnos=(2,))
_ARM_CALL = dict(args=('r0', 'r1', 'r2', 'r3'), ret='r0', returns='link',
                 link='lr', stack_slot=0, ret_hi='r1')
_A64_SYS = dict(number='x8', args=('x0', 'x1', 'x2', 'x3', 'x4', 'x5'),
                ret='x0', numbers=_NR_GENERIC, intnos=(2,))
_A64_CALL = dict(args=tuple(f'x{i}' for i in range(8)), ret='x0',
                 returns='link', link='x30', stack_slot=0)
# MIPS reports EXCP_SYSCALL as 17.
_MIPS_ERRNOS = {'ENOSYS': 89}
_MIPS_O32_SYS = dict(number='v0', args=('a0', 'a1', 'a2', 'a3'), ret='v0',
                     numbers=_NR_MIPS_O32, intnos=(17,), error=MIPS,
                     error_reg='a3', stack_args=16, errnos=_MIPS_ERRNOS)
_MIPS_O32_CALL = dict(args=('a0', 'a1', 'a2', 'a3'), ret='v0', returns='link',
                      link='ra', stack_slot=4, ret_hi='v1')
# n64 passes eight arguments in a0-a7; Ghidra spells a4-a7 t0-t3.
_MIPS_N64_SYS = dict(number='v0', args=('a0', 'a1', 'a2', 'a3', 't0', 't1'),
                     ret='v0', numbers=_NR_MIPS_N64, intnos=(17,), error=MIPS,
                     error_reg='a3', errnos=_MIPS_ERRNOS)
_MIPS_N64_CALL = dict(args=('a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3'),
                      ret='v0', returns='link', link='ra', stack_slot=0)
# RISC-V reports an environment call from user mode as 8.
_RISCV_SYS = dict(number='a7', args=('a0', 'a1', 'a2', 'a3', 'a4', 'a5'),
                  ret='a0', numbers=_NR_GENERIC, intnos=(8,))
_PPC_SYS = dict(number='r0', args=('r3', 'r4', 'r5', 'r6', 'r7', 'r8'),
                ret='r3', numbers=_NR_PPC, intnos=(8,), error=PPC,
                error_cr='cr0')
_PPC_CALL = dict(args=tuple(f'r{i}' for i in range(3, 11)), ret='r3',
                 returns='link', link='LR')


SYSCALLS: Dict[str, SyscallAbi] = {
    'x64': SyscallAbi(number='RAX',
                      args=('RDI', 'RSI', 'RDX', 'R10', 'R8', 'R9'),
                      ret='RAX', numbers=_NR_X86_64, insn=True),
    'x86': SyscallAbi(number='EAX',
                      args=('EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP'),
                      ret='EAX', numbers=_NR_I386, intnos=(0x80,)),
    'armle': SyscallAbi(**_ARM_SYS),
    'armbe': SyscallAbi(**_ARM_SYS),
    'armlethumb': SyscallAbi(**_ARM_SYS),
    'armbethumb': SyscallAbi(**_ARM_SYS),
    'arm64le': SyscallAbi(**_A64_SYS),
    'arm64be': SyscallAbi(**_A64_SYS),
    'mips': SyscallAbi(**_MIPS_O32_SYS),
    'mipsel': SyscallAbi(**_MIPS_O32_SYS),
    'mips64': SyscallAbi(**_MIPS_N64_SYS),
    'mips64el': SyscallAbi(**_MIPS_N64_SYS),
    'riscv32': SyscallAbi(**_RISCV_SYS),
    'riscv64': SyscallAbi(**_RISCV_SYS),
    'ppc32': SyscallAbi(**_PPC_SYS),
    'ppc64': SyscallAbi(**_PPC_SYS),
    # m68k signals `trap #N` as interrupt 32+N, and Linux uses trap #0. The
    # program counter is left on the trap, so the handler moves it.
    'm68k': SyscallAbi(number='D0', args=('D1', 'D2', 'D3', 'D4', 'D5', 'A0'),
                       ret='D0', numbers=_NR_M68K, intnos=(32,), advance=2),
}


CALLS: Dict[str, CallAbi] = {
    'x64': CallAbi(args=('RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9'), ret='RAX',
                   returns='stack'),
    'x86': CallAbi(args=(), ret='EAX', returns='stack', ret_hi='EDX'),
    'armle': CallAbi(**_ARM_CALL),
    'armbe': CallAbi(**_ARM_CALL),
    'armlethumb': CallAbi(**_ARM_CALL),
    'armbethumb': CallAbi(**_ARM_CALL),
    'arm64le': CallAbi(**_A64_CALL),
    'arm64be': CallAbi(**_A64_CALL),
    'mips': CallAbi(**_MIPS_O32_CALL),
    'mipsel': CallAbi(**_MIPS_O32_CALL),
    'mips64': CallAbi(**_MIPS_N64_CALL),
    'mips64el': CallAbi(**_MIPS_N64_CALL),
    'riscv32': CallAbi(args=tuple(f'a{i}' for i in range(8)), ret='a0',
                       returns='link', link='ra', stack_slot=0, ret_hi='a1'),
    'riscv64': CallAbi(args=tuple(f'a{i}' for i in range(8)), ret='a0',
                       returns='link', link='ra', stack_slot=0),
    # PowerPC's SysV ABI starts the stack parameters at r1+8 on 32-bit; the
    # ELFv1 64-bit stack frame reserves six more doublewords first.
    'ppc32': CallAbi(stack_slot=2, **_PPC_CALL),
    'ppc64': CallAbi(stack_slot=6, **_PPC_CALL),
    'm68k': CallAbi(args=(), ret='D0', returns='stack', ret_hi='D1'),
    # SPARC's `retl` is `jmpl %o7+8`: the call's delay slot has already run.
    'sparc32': CallAbi(args=('o0', 'o1', 'o2', 'o3', 'o4', 'o5'), ret='o0',
                       returns='link', link='o7', link_offset=8, stack_slot=16),
    'sparc64': CallAbi(args=('o0', 'o1', 'o2', 'o3', 'o4', 'o5'), ret='o0',
                       returns='link', link='o7', link_offset=8, stack_slot=16),
    # TriCore passes data arguments in d4-d7 and returns in d2; `ret` jumps
    # to the return address in a11.
    'tricore': CallAbi(args=('d4', 'd5', 'd6', 'd7'), ret='d2',
                       returns='link', link='a11', stack_slot=0),
}


def syscall_abi(key: str) -> SyscallAbi:
    if key not in SYSCALLS:
        raise KeyError(
            f'no system call convention for {key}; known: '
            + ', '.join(sorted(SYSCALLS)))
    return SYSCALLS[key]


def call_abi(key: str) -> CallAbi:
    if key not in CALLS:
        raise KeyError(
            f'no calling convention for {key}; known: ' + ', '.join(sorted(CALLS)))
    return CALLS[key]
