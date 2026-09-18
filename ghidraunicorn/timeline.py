"""Execution history: what the machine looked like at instruction N.

This is the storage half of reverse execution. It knows about Unicorn and
nothing about Ghidra; `UnicornTarget` owns one and drives it from its existing
`UC_HOOK_CODE` callback, so there is exactly one code hook in the process.

How it records
--------------
Instruction 0 gets a *base* snapshot: the CPU context plus every byte of every
mapped region. After that a *delta* checkpoint is taken every `interval`
instructions holding the CPU context and only the pages written since the
previous checkpoint - a `UC_HOOK_MEM_WRITE` hook over all memory notes the
page-aligned addresses as they are written, and `note_external_write` does the
same for writes made through the debugger.

How it restores
---------------
To reach instruction K: restore the base image, replay the page deltas of every
checkpoint up to the last one at or before K in order, restore that
checkpoint's CPU context. The caller then emulates the remaining
`K - checkpoint.icount` instructions forward with its hooks muted.

Forgetting
----------
Retained deltas are capped by `budget` bytes. When they exceed it the oldest
delta is *folded into the base*: its pages overwrite the base image and its
context becomes the base context, which turns the base into a full snapshot of
that later instruction. Everything after it is still restorable and everything
before it is gone for good - `earliest` says where the history now begins.
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from unicorn import Uc, UcError

PAGE = 0x1000
PAGE_MASK = ~(PAGE - 1)

DEFAULT_INTERVAL = 10000
DEFAULT_BUDGET = 64 << 20


@dataclass
class Checkpoint:
    """State at an instruction: CPU context plus some memory pages.

    The base checkpoint holds every mapped page; the others hold only the
    pages written since the checkpoint before them.
    """
    icount: int
    context: object
    pages: Dict[int, bytes] = field(default_factory=dict)
    #: Every checkpoint carries the whole region list, not just the base:
    #: what is mapped is part of the state, and a region that appeared after
    #: the base has to disappear again on the way back to before it existed.
    #: It is a handful of tuples, so it is not worth a delta.
    regions: Optional[List[Tuple[int, int, int]]] = None

    @property
    def nbytes(self) -> int:
        return sum(len(p) for p in self.pages.values()) + getattr(self.context, 'size', 0)


class Timeline:

    def __init__(self, uc: Uc, interval: int = DEFAULT_INTERVAL,
                 budget: int = DEFAULT_BUDGET, enabled: bool = True) -> None:
        self.uc = uc
        self.interval = max(int(interval), 1)
        self.budget = max(int(budget), 0)
        self.enabled = enabled
        self.icount = 0
        self.base: Optional[Checkpoint] = None
        self.checkpoints: List[Checkpoint] = []      # deltas, ascending icount
        self.dirty: Set[int] = set()
        self.dropped = 0                             # checkpoints folded away
        self._next: int = 0                          # icount of the next checkpoint
        #: Called with the new `earliest` whenever folding moves the start of
        #: the history forward. Anything else that keeps state per instruction
        #: - the system call log - uses it to drop what can no longer be
        #: reached, instead of waiting until it is next written to.
        self.on_forget: Optional[Callable[[int], None]] = None

    # ---- recording -------------------------------------------------------

    def note_instruction(self) -> None:
        """One instruction is about to execute, in the state we have now."""
        if self.enabled and self.icount >= self._next:
            self.checkpoint()
        self.icount += 1

    def note_write(self, address: int, size: int) -> None:
        """Memory changed under emulation."""
        if not self.enabled:
            return
        dirty = self.dirty
        page = address & PAGE_MASK
        last = (address + max(size, 1) - 1) & PAGE_MASK
        while page <= last:
            dirty.add(page)
            page += PAGE

    def note_external_write(self, address: int, size: int) -> None:
        """A write made through the debugger rather than by the program.

        It happens between instructions and replaying cannot reproduce it, so
        the only way to keep it is to checkpoint the state it made.
        """
        if not self.enabled:
            return
        self.note_write(address, size)
        if self.base is not None:
            self.checkpoint()

    def note_external_change(self) -> None:
        """Registers were edited through the debugger; same story."""
        if self.enabled and self.base is not None:
            self.checkpoint()

    def uncount(self) -> None:
        """The last counted instruction did not complete after all (a fault).

        The state we are left in - PC on the faulting instruction - is the
        state before it, so the count has to come back by one to match.
        """
        if self.icount > 0:
            self.icount -= 1

    # ---- checkpoints -----------------------------------------------------

    def checkpoint(self) -> Checkpoint:
        """Snapshot the state we are in now, at the current instruction."""
        regions = list(sorted(self.uc.mem_regions()))
        if self.base is None:
            cp = Checkpoint(self.icount, self.uc.context_save(),
                            self._read_all(), regions)
            self.base = cp
        else:
            cp = Checkpoint(self.icount, self.uc.context_save(),
                            self._read_pages(self.dirty), regions)
            self.checkpoints.append(cp)
        self.dirty = set()
        self._next = self.icount + self.interval
        self._enforce_budget()
        return cp

    def _read_all(self) -> Dict[int, bytes]:
        pages = {}
        for start, end, _ in sorted(self.uc.mem_regions()):
            for addr in range(start & PAGE_MASK, end + 1, PAGE):
                try:
                    pages[addr] = bytes(self.uc.mem_read(addr, PAGE))
                except UcError:
                    pass
        return pages

    def _read_pages(self, addrs) -> Dict[int, bytes]:
        pages = {}
        for addr in sorted(addrs):
            try:
                pages[addr] = bytes(self.uc.mem_read(addr, PAGE))
            except UcError:
                pass       # unmapped since it was written; nothing to keep
        return pages

    @property
    def nbytes(self) -> int:
        """Bytes held by the delta checkpoints (the base is always kept)."""
        return sum(c.nbytes for c in self.checkpoints)

    def _enforce_budget(self) -> None:
        total = self.nbytes
        folded = False
        while self.checkpoints and total > self.budget:
            cp = self.checkpoints.pop(0)
            total -= cp.nbytes
            base = self.base
            assert base is not None
            base.pages.update(cp.pages)       # the base becomes a snapshot of cp
            base.context = cp.context
            base.icount = cp.icount
            if cp.regions is not None:
                base.regions = cp.regions
            self.dropped += 1
            folded = True
        if folded and self.on_forget is not None:
            self.on_forget(self.earliest)

    # ---- querying --------------------------------------------------------

    @property
    def recording(self) -> bool:
        return self.enabled and self.base is not None

    @property
    def earliest(self) -> int:
        """The oldest instruction we can still restore."""
        return self.base.icount if self.base is not None else self.icount

    def last_checkpoint(self) -> Optional[Checkpoint]:
        """The most recent checkpoint, base included; None if nothing ran."""
        if self.checkpoints:
            return self.checkpoints[-1]
        return self.base

    def checkpoint_at_or_before(self, icount: int) -> Checkpoint:
        """The latest checkpoint we can restore that is not after `icount`."""
        if self.base is None or icount < self.base.icount:
            raise KeyError(icount)
        best = self.base
        for cp in self.checkpoints:
            if cp.icount > icount:
                break
            best = cp
        return best

    def truncate(self, icount: int) -> None:
        """Forget everything recorded after `icount`; we are back there now."""
        self.checkpoints = [c for c in self.checkpoints if c.icount <= icount]
        self.icount = icount
        self.dirty = set()
        last = self.last_checkpoint()
        self._next = (last.icount if last is not None else 0) + self.interval
        if self._next <= icount:
            self._next = icount + self.interval

    def advance_to(self, icount: int) -> None:
        """We replayed forward to `icount` without counting on the way."""
        self.icount = icount
        if self._next < icount:
            self._next = icount      # checkpoint at the next instruction

    # ---- restoring -------------------------------------------------------

    def restore(self, icount: int) -> Checkpoint:
        """Put the machine in the state of the checkpoint at or before
        `icount` and return it. The caller emulates the rest forward."""
        cp = self.checkpoint_at_or_before(icount)
        base = self.base
        assert base is not None
        # What is mapped comes first: the pages below are written into it, and
        # a page whose region no longer existed then has nowhere to land.
        self._sync_regions(cp.regions if cp.regions is not None else base.regions or [])
        for addr, data in base.pages.items():
            try:
                self.uc.mem_write(addr, data)
            except UcError:
                pass
        for c in self.checkpoints:
            if c.icount > cp.icount:
                break
            for addr, data in c.pages.items():
                try:
                    self.uc.mem_write(addr, data)
                except UcError:
                    pass
        self.uc.context_restore(cp.context)
        return cp

    def _sync_regions(self, regions) -> None:
        """Make what is mapped match `regions` exactly.

        Mapping back what a snapshot had is only half of it: a region the
        program mapped *after* the snapshot has to go away again, or going
        back to before it existed leaves it behind and the program finds
        memory it has not allocated yet. With system calls under the
        emulator that is no longer a corner case - every `mmap` and every
        `brk` that grows the heap makes one.

        A region that only partly overlaps one of `regions` is unmapped
        whole and the wanted pieces are mapped back, which is also how a
        region that was split or merged since gets put right.
        """
        if not regions:
            return
        want = {(s, e): p for s, e, p in regions}
        base = self.base
        # Regions the *base* holds have an image in `base.pages` to be
        # restored from. Regions that appeared later have no baseline
        # anywhere, so nothing below would overwrite a byte written into one
        # after the checkpoint being restored - the write would survive the
        # rewind. Taking such a region down and putting it back gives the
        # zeroed pages Unicorn maps, which is what it held when it appeared;
        # the deltas then put back whatever should be in it at this point.
        baseline = {(s, e) for s, e, _ in ((base.regions or []) if base else [])}
        for start, end, _ in list(self.uc.mem_regions()):
            if (start, end) not in want or (start, end) not in baseline:
                try:
                    self.uc.mem_unmap(start, end - start + 1)
                except UcError:
                    pass
        have = {(s, e) for s, e, _ in self.uc.mem_regions()}
        for (start, end), perms in want.items():
            if (start, end) not in have:
                try:
                    self.uc.mem_map(start, end - start + 1, perms)
                except UcError:
                    pass       # overlaps something we could not take down

    # ---- reporting -------------------------------------------------------

    def describe(self) -> str:
        if not self.enabled:
            return 'history: off'
        kept = len(self.checkpoints) + (1 if self.base is not None else 0)
        return (f'instruction {self.icount}, history from {self.earliest}, '
                f'{kept} checkpoints every {self.interval}, '
                f'{self.nbytes / 1024:.0f} KiB of deltas'
                + (f', {self.dropped} folded away' if self.dropped else ''))
