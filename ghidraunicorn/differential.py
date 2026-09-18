"""Running a program under two engines and finding where they disagree.

Unicorn and Ghidra's p-code emulator implement the same instruction sets
from entirely separate descriptions of them: QEMU's translation on one side,
a SLEIGH specification on the other. Where they disagree about what an
instruction did, one of them is wrong - which makes this both a way to find
bugs in a processor specification and a way to check this connector's own
register tables, because a name that maps to the wrong register shows up
immediately as a value that never matches.

How it works
------------
Both engines are put in the same state, stepped in lockstep, and compared
after every instruction. The first disagreement is reported with everything
needed to look at it: the step, the program counter each engine reached, the
registers that differ and the instruction that was executed.

The comparison needs no mapping table between the two, which is the whole
reason it is cheap to do here: `arch.py` already names every register the
way Ghidra's SLEIGH specification names it, because that is what the trace
needs. The two engines therefore speak the same names already.

What is here without Ghidra
---------------------------
`UnicornEngine` and everything that drives a comparison work anywhere, and
are tested by running Unicorn against Unicorn - which sounds circular but
exercises every part of the machinery and catches a comparison that cannot
detect a difference. `PcodeEngine` needs a Ghidra installation and PyGhidra,
and is imported lazily so that nothing here depends on having one.
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple


class EngineError(Exception):
    pass


class Engine:
    """One side of a comparison.

    Deliberately small: a comparison needs to put an engine somewhere, step
    it, and read it back. Anything more would be a second debugger.
    """
    name = 'engine'

    def pc(self) -> int:
        raise NotImplementedError

    def registers(self) -> Dict[str, int]:
        raise NotImplementedError

    def write_register(self, name: str, value: int) -> None:
        raise NotImplementedError

    def read(self, address: int, size: int) -> bytes:
        raise NotImplementedError

    def write(self, address: int, data: bytes) -> None:
        raise NotImplementedError

    def step(self) -> None:
        raise NotImplementedError

    def disassemble(self, address: int) -> str:
        return ''

    def close(self) -> None:
        pass


class UnicornEngine(Engine):
    """A `UnicornTarget` as one side of a comparison."""
    name = 'unicorn'

    def __init__(self, target) -> None:
        self.target = target

    def pc(self) -> int:
        return self.target.pc()

    def registers(self) -> Dict[str, int]:
        return self.target.regs()

    def write_register(self, name: str, value: int) -> None:
        self.target.reg_write(name, value)

    def read(self, address: int, size: int) -> bytes:
        return self.target.read(address, size)

    def write(self, address: int, data: bytes) -> None:
        self.target.write(address, data)

    def step(self) -> None:
        event = self.target.step()
        if event.reason == 'error':
            raise EngineError(event.description)

    def disassemble(self, address: int) -> str:
        insn = self.target.decode(address)
        return f'{insn[1]} {insn[2]}'.strip() if insn else ''


@dataclass
class Divergence:
    """The first place two engines stopped agreeing."""
    step: int
    address: int
    instruction: str
    #: register -> (what the first engine had, what the second had)
    registers: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    #: (address, first engine's bytes, second engine's bytes)
    memory: List[Tuple[int, bytes, bytes]] = field(default_factory=list)
    names: Tuple[str, str] = ('a', 'b')

    @property
    def only_pc(self) -> bool:
        return 'pc' in self.registers and len(self.registers) == 1

    def describe(self) -> str:
        left, right = self.names
        lines = [f'diverged at step {self.step}, {self.address:#x}'
                 + (f': {self.instruction}' if self.instruction else '')]
        width = max((len(n) for n in self.registers), default=3)
        for name, (a, b) in sorted(self.registers.items()):
            lines.append(f'  {name:<{width}}  {left} {a:#x}  {right} {b:#x}'
                         f'  (xor {a ^ b:#x})')
        for address, a, b in self.memory:
            lines.append(f'  {address:#x}  {left} {a.hex()}  {right} {b.hex()}')
        return '\n'.join(lines)


@dataclass
class Comparison:
    """What a run of `compare` found."""
    steps: int = 0
    divergence: Optional[Divergence] = None
    #: Registers left out because only one engine has them.
    unmatched: Tuple[str, ...] = ()
    stopped: str = ''

    @property
    def agreed(self) -> bool:
        return self.divergence is None

    def describe(self) -> str:
        if self.divergence is not None:
            return self.divergence.describe()
        text = f'{self.steps} instruction(s), no disagreement'
        if self.stopped:
            text += f'; stopped: {self.stopped}'
        if self.unmatched:
            text += f'\nnot compared (only one engine has them): ' \
                    + ', '.join(sorted(self.unmatched))
        return text


def align(source: Engine, target: Engine, regions: Sequence[Tuple[int, int]],
          registers: Optional[Iterable[str]] = None) -> None:
    """Copy `source`'s memory and registers into `target`.

    A comparison is only meaningful from the same starting state, and the
    two engines are set up in completely different ways, so one of them is
    made to match the other rather than both being built twice.
    """
    for start, end in regions:
        length = end - start + 1
        for offset in range(0, length, 0x1000):
            chunk = min(0x1000, length - offset)
            try:
                target.write(start + offset, source.read(start + offset, chunk))
            except Exception:
                pass          # the other engine may not have this mapped
    values = source.registers()
    for name in (registers if registers is not None else values):
        if name not in values:
            continue
        try:
            target.write_register(name, values[name])
        except Exception:
            pass              # a register this engine does not have


def compare(a: Engine, b: Engine, steps: int = 1000, *,
            registers: Optional[Iterable[str]] = None,
            ignore: Iterable[str] = (),
            watch: Sequence[Tuple[int, int]] = (),
            on_step: Optional[Callable[[int, int], None]] = None,
            stop_at: Optional[int] = None) -> Comparison:
    """Step both engines together and report the first disagreement.

    `registers` limits what is compared, `ignore` drops individual names
    from it, and `watch` names (address, length) ranges of memory to compare
    as well. Only registers both engines report are compared at all; the
    rest are listed in the result rather than silently dropped, because a
    register quietly missing from one side is exactly the sort of thing that
    makes a differential run look cleaner than it is.
    """
    ignore = {n.lower() for n in ignore}
    left, right = a.registers(), b.registers()
    shared = {n for n in left if n in right}
    if registers is not None:
        wanted = {n.lower() for n in registers}
        shared = {n for n in shared if n.lower() in wanted}
    unmatched = tuple(n for n in set(left) ^ set(right))
    shared = {n for n in shared if n.lower() not in ignore}

    result = Comparison(unmatched=unmatched)
    for step in range(1, max(steps, 0) + 1):
        address = a.pc()
        instruction = a.disassemble(address)
        try:
            a.step()
            b.step()
        except Exception as e:
            # Not just EngineError: an engine stops for all sorts of reasons
            # that are not a disagreement - reaching its end address, running
            # out of mapped memory - and none of them should come out of a
            # comparison as an exception. Where it stopped is the answer.
            result.stopped = f'{type(e).__name__}: {e}' \
                if not isinstance(e, EngineError) else str(e)
            break
        result.steps = step
        differences = _differences(a, b, shared, watch)
        if differences is not None:
            differences.step = step
            differences.address = address
            differences.instruction = instruction
            differences.names = (a.name, b.name)
            result.divergence = differences
            return result
        if on_step is not None:
            on_step(step, a.pc())
        if stop_at is not None and a.pc() == stop_at:
            result.stopped = f'reached {stop_at:#x}'
            break
    return result


def _differences(a: Engine, b: Engine, shared, watch) -> Optional[Divergence]:
    found = Divergence(0, 0, '')
    pc_a, pc_b = a.pc(), b.pc()
    if pc_a != pc_b:
        found.registers['pc'] = (pc_a, pc_b)
    left, right = a.registers(), b.registers()
    for name in sorted(shared):
        if name in left and name in right and left[name] != right[name]:
            found.registers[name] = (left[name], right[name])
    # Memory is only worth reading where the caller said to look; reading all
    # of it every instruction would cost more than the comparison is worth.
    for start, length in watch:
        try:
            one, two = a.read(start, length), b.read(start, length)
        except Exception:
            continue
        if one != two:
            found.memory.append((start, one, two))
    if not found.registers and not found.memory:
        return None
    return found


# ---------------------------------------------------------------------------
# The p-code side
#
# This is the half that needs a Ghidra installation, so it is imported only
# when it is asked for. Everything it does follows tools/e2e_ghidra.py, which
# is the file in this repository that already knows how to drive Ghidra from
# Python without opening dialogs nobody can click.

class PcodeEngine(Engine):
    """Ghidra's own p-code emulator, through `EmulatorHelper`.

    Needs a started PyGhidra and an open `Program`. `ghidra_program` below
    is one way to get one; a Ghidra script already has `currentProgram`.
    """
    name = 'p-code'

    def __init__(self, program) -> None:
        from ghidra.app.emulator import EmulatorHelper
        from ghidra.util.task import TaskMonitor
        self.program = program
        self.helper = EmulatorHelper(program)
        self.monitor = TaskMonitor.DUMMY
        self._space = program.getAddressFactory().getDefaultAddressSpace()
        self._pc_register = self.helper.getPCRegister()

    def _address(self, value: int):
        return self._space.getAddress(value)

    def pc(self) -> int:
        # What the emulator itself calls the next instruction, rather than a
        # register read that depends on naming the program counter.
        address = self.helper.getExecutionAddress()
        if address is not None:
            return int(address.getOffset()) & 0xffff_ffff_ffff_ffff
        return int(self.helper.readRegister(self._pc_register).longValue()) \
            & 0xffff_ffff_ffff_ffff

    def registers(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for register in self.program.getLanguage().getRegisters():
            if register.isProcessorContext() or register.isHidden():
                continue
            if not register.isBaseRegister():
                # Ghidra lists every sub-register too: EAX, AX, AH and AL
                # are all parts of RAX. Comparing them says nothing the
                # parent has not already said, and they would swamp the list
                # of registers only one engine has.
                continue
            name = register.getName()
            try:
                out[name] = int(self.helper.readRegister(name).longValue()) \
                    & ((1 << register.getBitLength()) - 1)
            except Exception:
                continue          # not every register is readable
        return out

    def write_register(self, name: str, value: int) -> None:
        from java.math import BigInteger
        self.helper.writeRegister(name, BigInteger(str(value)))

    def read(self, address: int, size: int) -> bytes:
        """Bytes from the emulator's memory state.

        `EmulatorHelper.readMemory` answers a failure with null rather than
        an exception, and a *partial* read by filling what it got and
        logging the rest - it does not say how much. So a short read comes
        back zero-padded and there is no way to tell from here; compare
        memory only where the program has actually been.
        """
        data = self.helper.readMemory(self._address(address), size)
        if data is None:
            raise EngineError(f'nothing mapped at {address:#x} in the p-code '
                              f'emulator')
        return bytes(data)

    def write(self, address: int, data: bytes) -> None:
        self.helper.writeMemory(self._address(address), bytes(data))

    def step(self) -> None:
        # step() answers an error with false and the reason through
        # getLastError(), and throws CancelledException if the monitor is
        # cancelled. Neither is a disagreement, so both become the reason the
        # comparison stopped.
        try:
            stepped = self.helper.step(self.monitor)
        except Exception as e:
            raise EngineError(f'p-code step failed: {e}')
        if not stepped:
            raise EngineError(self.helper.getLastError() or 'p-code step failed')

    def disassemble(self, address: int) -> str:
        instruction = self.program.getListing().getInstructionAt(
            self._address(address))
        return str(instruction) if instruction is not None else ''

    def close(self) -> None:
        try:
            self.helper.dispose()
        except Exception:
            pass


def ghidra_program(path: str, language: str, base: int = 0, project=None):
    """Open `path` as a Ghidra program, importing it if need be.

    A convenience for running this from a plain script rather than from
    inside Ghidra. PyGhidra must already have been started.
    """
    import pyghidra
    return pyghidra.open_program(path, language=language,
                                 loader='ghidra.app.util.opinion.BinaryLoader',
                                 project_location=project)


def compare_with_pcode(loaded, program, steps: int = 1000, **kwargs) -> Comparison:
    """Run a loaded Unicorn target against the p-code emulator.

    The Unicorn side is the one that was set up by a harness, so it is the
    one holding the state worth comparing, and the p-code side is aligned to
    it rather than the other way round.
    """
    unicorn_side = UnicornEngine(loaded.target)
    pcode_side = PcodeEngine(program)
    regions = [(start, end) for start, end, _ in loaded.target.regions()]
    align(unicorn_side, pcode_side, regions)
    return compare(unicorn_side, pcode_side, steps, **kwargs)
