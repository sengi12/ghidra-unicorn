"""Symbol names for the emulated program.

Unicorn knows addresses; Ghidra knows names. Exporting the open program's
symbols once, with `tools/export_symbols.py`, lets the console take
`b main` instead of `b 0x100440` and lets the context print
`0x100448 <main+8>` instead of a bare address.

The file is plain JSON so anything can produce it:

    {
      "image_base": 1048576,
      "symbols": [
        {"name": "main", "address": 1049152, "size": 244, "kind": "function"}
      ]
    }

If the harness maps the code somewhere other than the image base the export
was taken at, `rebase()` shifts every symbol by the difference.
"""
from bisect import bisect_right
from dataclasses import dataclass, field
import json
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int = 0
    kind: str = 'label'

    @property
    def end(self) -> int:
        return self.address + max(self.size, 1)

    def contains(self, address: int) -> bool:
        return self.address <= address < self.end


class SymbolTable:
    """Address to name and name to address, with nearest-preceding lookup."""

    def __init__(self, symbols: Iterable[Symbol] = (), image_base: int = 0) -> None:
        self.image_base = image_base
        self._by_name: Dict[str, Symbol] = {}
        self._sorted: List[Symbol] = []
        self._addrs: List[int] = []
        self._sized: List[Symbol] = []
        self._sized_addrs: List[int] = []
        self.extend(symbols)

    def __len__(self) -> int:
        return len(self._sorted)

    def __bool__(self) -> bool:
        return bool(self._sorted)

    def __iter__(self):
        return iter(self._sorted)

    def extend(self, symbols: Iterable[Symbol]) -> None:
        for s in symbols:
            self._by_name.setdefault(s.name, s)
            self._sorted.append(s)
        # Functions before labels at the same address, so describe() prefers
        # the more meaningful name.
        self._sorted.sort(key=lambda s: (s.address, s.kind != 'function', s.name))
        self._addrs = [s.address for s in self._sorted]
        # Sized symbols are indexed separately so an address inside a function
        # is reported as that function, not as a nearer generated label.
        self._sized = [s for s in self._sorted if s.size]
        self._sized_addrs = [s.address for s in self._sized]

    # ---- lookup ----------------------------------------------------------

    def lookup(self, name: str) -> Optional[Symbol]:
        s = self._by_name.get(name)
        if s is not None:
            return s
        lower = name.lower()
        for sym in self._sorted:
            if sym.name.lower() == lower:
                return sym
        return None

    def address_of(self, name: str) -> Optional[int]:
        s = self.lookup(name)
        return None if s is None else s.address

    def nearest(self, address: int) -> Optional[Tuple[Symbol, int]]:
        """The symbol at or before `address`, with the offset into it."""
        if not self._sorted:
            return None
        i = bisect_right(self._addrs, address) - 1
        if i < 0:
            return None
        # bisect lands on the last symbol sharing that address; back up to the
        # first, which the sort order makes the preferred one.
        addr = self._addrs[i]
        while i > 0 and self._addrs[i - 1] == addr:
            i -= 1
        sym = self._sorted[i]
        return sym, address - sym.address

    def enclosing(self, address: int) -> Optional[Tuple[Symbol, int]]:
        """The sized symbol whose range covers `address`, with the offset."""
        i = bisect_right(self._sized_addrs, address) - 1
        while i >= 0:
            sym = self._sized[i]
            if sym.contains(address):
                return sym, address - sym.address
            # Ranges can nest or overlap, so keep looking back while a symbol
            # could still reach this address.
            if address - sym.address > 0x100000:
                break
            i -= 1
        return None

    def describe(self, address: int, max_offset: int = 0x10000) -> Optional[str]:
        """`main`, `main+0x8`, or None when nothing is close enough.

        A function that contains the address wins, the way gdb and IDA report
        it, so an address in the middle of a function is not attributed to a
        generated label that happens to sit nearer. Failing that, a sizeless
        label describes up to `max_offset` past itself.
        """
        found = self.enclosing(address)
        if found is not None:
            sym, offset = found
            return sym.name if offset == 0 else f'{sym.name}+{offset:#x}'
        # Outside every function. Walk back for a standalone label, skipping
        # labels that live inside some function: that function does not cover
        # this address, so neither should its internal labels.
        i = bisect_right(self._addrs, address) - 1
        while i >= 0:
            sym = self._sorted[i]
            offset = address - sym.address
            if offset > max_offset or sym.size:
                return None
            if self.enclosing(sym.address) is None:
                return sym.name if offset == 0 else f'{sym.name}+{offset:#x}'
            i -= 1
        return None

    # ---- transformation --------------------------------------------------

    def rebase(self, new_base: int) -> 'SymbolTable':
        """A copy shifted so `image_base` lands on `new_base`."""
        delta = new_base - self.image_base
        if delta == 0:
            return self
        return SymbolTable(
            (Symbol(s.name, s.address + delta, s.size, s.kind) for s in self._sorted),
            image_base=new_base)

    # ---- serialisation ---------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict) -> 'SymbolTable':
        syms = []
        for row in data.get('symbols', ()):
            syms.append(Symbol(str(row['name']), int(row['address']),
                               int(row.get('size', 0) or 0),
                               str(row.get('kind', 'label'))))
        return cls(syms, image_base=int(data.get('image_base', 0) or 0))

    @classmethod
    def load(cls, path: str) -> 'SymbolTable':
        with open(path) as f:
            return cls.from_dict(json.load(f))

    def to_dict(self) -> dict:
        return {
            'image_base': self.image_base,
            'symbols': [{'name': s.name, 'address': s.address,
                         'size': s.size, 'kind': s.kind} for s in self._sorted],
        }

    def save(self, path: str) -> int:
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=1)
        return len(self._sorted)
