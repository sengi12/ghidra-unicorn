"""Which bytes of the fuzz input did the program actually read, and where.

When an input crashes a target, the first question is which bytes matter. This
watches reads of the input buffer and records, for each one, the offset into
the input and the instruction that read it. At a crash you can then ask what
the faulting instruction consumed, and which parts of the input were never
looked at at all.

This is provenance, not taint: it records direct reads of the buffer, and does
not follow a value once it is in a register. That is enough to answer "which
input offsets reach this instruction" for the great majority of parsers, and
it costs one hook on one address range rather than an instrumented
interpreter.

    prov = InputProvenance(target, base=0x300000, length=len(data))
    prov.start()
    ev = target.run()
    prov.reads_at(ev.pc)        # offsets the faulting instruction read
    prov.unread_ranges()        # parts of the input nothing touched
"""
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from unicorn import UC_HOOK_MEM_READ


@dataclass(frozen=True)
class Access:
    """One read of the input buffer."""
    offset: int          # offset into the input
    size: int
    pc: int              # instruction that read it
    address: int         # absolute address read

    @property
    def offsets(self) -> range:
        return range(self.offset, self.offset + max(self.size, 1))


def ranges(offsets: Iterable[int]) -> List[Tuple[int, int]]:
    """Collapse offsets into inclusive (start, end) runs."""
    out: List[Tuple[int, int]] = []
    for off in sorted(set(offsets)):
        if out and off == out[-1][1] + 1:
            out[-1] = (out[-1][0], off)
        else:
            out.append((off, off))
    return out


def format_ranges(rs: Sequence[Tuple[int, int]]) -> str:
    """`0-3, 7, 12-15`, the way a person would write it."""
    if not rs:
        return '(none)'
    return ', '.join(str(a) if a == b else f'{a}-{b}' for a, b in rs)


class InputProvenance:
    """Records reads of one buffer, keyed by the instruction that read it."""

    def __init__(self, target, base: int, length: int, label: str = 'input') -> None:
        if length <= 0:
            raise ValueError('length must be positive')
        self.target = target
        self.base = base
        self.length = length
        self.label = label
        self.accesses: List[Access] = []
        self._hook = None
        self._pc_reg = target.spec.reg(target.spec.pc).uc

    # ---- recording -------------------------------------------------------

    def start(self) -> None:
        if self._hook is None:
            self._hook = self.target.uc.hook_add(
                UC_HOOK_MEM_READ, self._on_read,
                begin=self.base, end=self.base + self.length - 1)

    def stop(self) -> None:
        if self._hook is not None:
            self.target.uc.hook_del(self._hook)
            self._hook = None

    @property
    def recording(self) -> bool:
        return self._hook is not None

    def reset(self) -> None:
        self.accesses.clear()

    def _on_read(self, uc, access, address, size, value, user_data) -> bool:
        pc = uc.reg_read(self._pc_reg)
        self.accesses.append(Access(address - self.base, size, pc, address))
        return True

    # ---- queries ---------------------------------------------------------

    @property
    def offsets_read(self) -> Set[int]:
        out: Set[int] = set()
        for a in self.accesses:
            out.update(o for o in a.offsets if 0 <= o < self.length)
        return out

    def by_pc(self) -> Dict[int, Set[int]]:
        out: Dict[int, Set[int]] = {}
        for a in self.accesses:
            out.setdefault(a.pc, set()).update(
                o for o in a.offsets if 0 <= o < self.length)
        return out

    def reads_at(self, pc: int) -> Set[int]:
        """Offsets read by the instruction at `pc`."""
        return self.by_pc().get(pc, set())

    def read_ranges(self) -> List[Tuple[int, int]]:
        return ranges(self.offsets_read)

    def unread_ranges(self) -> List[Tuple[int, int]]:
        return ranges(set(range(self.length)) - self.offsets_read)

    def first_read(self, offset: int) -> Optional[Access]:
        """The first access that touched `offset`, in execution order."""
        for a in self.accesses:
            if a.offset <= offset < a.offset + max(a.size, 1):
                return a
        return None

    def summary(self, pc: Optional[int] = None) -> str:
        lines = [f'{self.label}: {self.length} bytes at {self.base:#x}, '
                 f'{len(self.accesses)} reads']
        lines.append(f'  read:   {format_ranges(self.read_ranges())}')
        lines.append(f'  unread: {format_ranges(self.unread_ranges())}')
        if pc is not None:
            at = self.reads_at(pc)
            lines.append(f'  at {pc:#x}: {format_ranges(ranges(at))}')
        return '\n'.join(lines)
