"""Things the emulator did that re-running the instructions will not redo.

Two layers stand in for code that is not there: `syscalls.py` for the kernel
and `stubs.py` for library functions. Both have the same problem with
reverse execution, and it is the same problem for the same reason.

Reverse execution restores a checkpoint and re-emulates forward with the
hooks muted. That works because emulating an instruction twice from the same
state gives the same answer. Neither of these layers is like that: running
`read` twice consumes the input twice, `malloc` twice hands out two blocks,
and `write` twice prints twice. Worse, a stub never lets the function's own
instructions run at all, so a replay where the stub does not fire does not
merely repeat a side effect - it walks into code the first run skipped and
the machine diverges for good.

So the rule is: do it once, write down everything it did, and on the way
through again apply what was written down instead of doing it again. What
has to be written down is every change a replay would otherwise miss:

* memory written on the program's behalf,
* regions mapped and unmapped,
* registers set, which includes the program counter a stub returns through,
* output, which is recorded so that it is *not* repeated, and
* the verdict, when the call ended the program.

An entry is keyed by the instruction it belongs to, so it can be found again
by an arbitrary replay, and dropped when a rewind makes it a future that no
longer happens or when the history stops reaching back that far.

The `before` snapshot is the layer's own state - file offsets, the break,
where the allocator had got to - taken just before the entry. Going back to
before an entry has to put that back too, or the machine rewinds and the
kernel does not.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from unicorn import UC_PROT_ALL, UcError


@dataclass
class Effect:
    """One thing that happened, and everything it changed."""
    icount: int
    label: str
    writes: List[Tuple[int, bytes]] = field(default_factory=list)
    maps: List[Tuple[int, int, int]] = field(default_factory=list)
    unmaps: List[Tuple[int, int]] = field(default_factory=list)
    #: (register, value) pairs, applied in order. A stub's return address is
    #: one of these, which is why a replay lands where the first run did.
    regs: List[Tuple[str, int]] = field(default_factory=list)
    #: (reason, description) when it ended the program.
    stop: Optional[Tuple[str, str]] = None
    #: (stream, bytes) the program produced. Kept so a replay can stay quiet.
    output: List[Tuple[int, bytes]] = field(default_factory=list)
    #: The owning layer's state just before this, for a rewind to put back.
    before: Optional[object] = None
    #: Whatever the layer wants to remember for its own reporting.
    detail: Optional[object] = None

    @property
    def nbytes(self) -> int:
        return (sum(len(d) for _, d in self.writes)
                + sum(len(d) for _, d in self.output))


class EffectLog:
    """The record of one layer's effects, and how to put them back.

    `snapshot` and `restore` are the layer's own state: called with no
    arguments to capture, and with what was captured to put it back.
    `forget`, if given, is called with the oldest snapshot still reachable
    whenever entries are dropped - or with None when none are left - so that
    a layer keeping an undo journal can throw away the part of it that can
    never be reached again.
    """

    def __init__(self, target, name: str,
                 snapshot: Optional[Callable[[], object]] = None,
                 restore: Optional[Callable[[object], None]] = None,
                 forget: Optional[Callable[[object], None]] = None) -> None:
        self.target = target
        self.name = name
        self._snapshot = snapshot
        self._restore = restore
        self._forget = forget
        self.entries: List[Effect] = []
        self._by_icount: Dict[int, Effect] = {}
        self._current: Optional[Effect] = None
        target.effect_logs.append(self)

    # ---- recording -------------------------------------------------------

    @contextmanager
    def recording(self, icount: int, label: str):
        """Collect everything done inside the block into one entry.

        The entry is kept even when the body raises, because a call that
        failed part way through still changed whatever it changed before it
        failed, and a replay has to reproduce that too.
        """
        effect = Effect(icount, label,
                        before=self._snapshot() if self._snapshot else None)
        self._current = effect
        try:
            yield effect
        finally:
            self._current = None
            self.entries.append(effect)
            self._by_icount[icount] = effect

    @property
    def current(self) -> Optional[Effect]:
        return self._current

    def write_mem(self, address: int, data: bytes) -> None:
        """Write on the program's behalf and remember it."""
        if not data:
            return
        self.target.write(address, data, external=False)
        if self._current is not None:
            self._current.writes.append((address, bytes(data)))

    def set_reg(self, name: str, value: int) -> None:
        self.target.reg_write(name, value, external=False)
        if self._current is not None:
            self._current.regs.append((name, value))

    def map(self, start: int, size: int, perms: int = UC_PROT_ALL) -> None:
        self.target.uc.mem_map(start, size, perms)
        if self._current is not None:
            self._current.maps.append((start, size, perms))

    def unmap(self, start: int, size: int) -> None:
        self.target.uc.mem_unmap(start, size)
        if self._current is not None:
            self._current.unmaps.append((start, size))

    def output(self, stream: int, data: bytes) -> None:
        if self._current is not None:
            self._current.output.append((stream, bytes(data)))

    def stop(self, reason: str, description: str) -> None:
        if self._current is not None:
            self._current.stop = (reason, description)

    # ---- replaying -------------------------------------------------------

    def replay(self, icount: int) -> Optional[Effect]:
        """Re-apply what happened at `icount`, without doing it again."""
        effect = self._by_icount.get(icount)
        if effect is None:
            return None
        uc = self.target.uc
        for start, size, perms in effect.maps:
            try:
                uc.mem_map(start, size, perms)
            except UcError:
                pass        # already there: a replay may cross a checkpoint
        for start, size in effect.unmaps:
            try:
                uc.mem_unmap(start, size)
            except UcError:
                pass
        for address, data in effect.writes:
            try:
                uc.mem_write(address, data)
            except UcError:
                pass
        for name, value in effect.regs:
            try:
                self.target.reg_write(name, value, external=False)
            except (KeyError, UcError):
                pass
        return effect

    # ---- forgetting ------------------------------------------------------

    def truncate(self, icount: int) -> None:
        """Forget everything that has not happened yet at `icount`.

        Being *at* instruction K means K is about to run, so an entry
        recorded at K has not happened and the cut is at `>= icount`. The
        oldest entry dropped carries the state from before it ran, and
        putting that back is what rewinds the layer along with the machine.
        """
        oldest = None
        while self.entries and self.entries[-1].icount >= icount:
            effect = self.entries.pop()
            self._by_icount.pop(effect.icount, None)
            oldest = effect
        if oldest is not None and oldest.before is not None and self._restore:
            self._restore(oldest.before)

    def forget_before(self, earliest: int) -> None:
        """Drop entries for instructions the history no longer reaches.

        They can never be replayed again, so keeping them would make this
        log the one thing in the process that grows with the length of the
        run rather than with the size of the history.
        """
        dropped = False
        while self.entries and self.entries[0].icount < earliest:
            self._by_icount.pop(self.entries.pop(0).icount, None)
            dropped = True
        if dropped and self._forget is not None:
            self._forget(self.entries[0].before if self.entries else None)

    # ---- reporting -------------------------------------------------------

    @property
    def nbytes(self) -> int:
        return sum(e.nbytes for e in self.entries)

    def __len__(self) -> int:
        return len(self.entries)
