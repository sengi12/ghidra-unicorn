"""Basic-block coverage from a live session, written as drcov.

drcov is what the coverage tools read: DynamoRIO's own drcov client,
Lighthouse, Dragondance, and the companion
[ghidra-aflcov](https://github.com/sengi12/ghidra-aflcov) plugin. Recording it
here means the blocks you just stepped through can be painted onto the same
listing you are debugging, and a crashing run can be diffed against a clean
one.

Two pieces, mirroring afl-unicorn's `helper_scripts/drcov.py` so the files are
interchangeable:

- `DrcovWriter` is the file format alone, with no Unicorn dependency.
- `SessionCoverage` attaches a `UC_HOOK_BLOCK` to a running target and sorts
  the blocks it sees into modules when it is asked to save.

The hook does as little as possible, since it runs for every basic block: it
adds the absolute address and size to a set. Working out which module a block
belongs to happens once, at save time.
"""
from dataclasses import dataclass
import struct
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from unicorn import UC_HOOK_BLOCK

# One drcov basic-block entry: u32 start offset from the module base, u16 size,
# u16 module id, little-endian.
_BB_STRUCT = struct.Struct('<IHH')


@dataclass(frozen=True)
class Module:
    id: int
    base: int
    end: int          # exclusive
    path: str

    def contains(self, address: int) -> bool:
        return self.base <= address < self.end


class DrcovWriter:
    """Accumulates modules and blocks and serialises them as drcov version 2."""

    def __init__(self) -> None:
        self._modules: List[Module] = []
        self._blocks: Set[Tuple[int, int, int]] = set()

    def add_module(self, path: str, base: int, end: int,
                   module_id: Optional[int] = None) -> int:
        if end <= base:
            raise ValueError(f'module end {end:#x} must be above base {base:#x}')
        if module_id is None:
            module_id = len(self._modules)
        self._modules.append(Module(module_id, base, end, path))
        return module_id

    def add_block(self, module_id: int, start_offset: int, size: int) -> None:
        self._blocks.add((module_id, start_offset & 0xFFFFFFFF, size & 0xFFFF))

    @property
    def modules(self) -> Sequence[Module]:
        return tuple(self._modules)

    def block_count(self) -> int:
        return len(self._blocks)

    def to_bytes(self) -> bytes:
        header = [
            'DRCOV VERSION: 2',
            'DRCOV FLAVOR: drcov',
            f'Module Table: version 2, count {len(self._modules)}',
            'Columns: id, base, end, entry, checksum, timestamp, path',
        ]
        for m in self._modules:
            header.append(f'  {m.id}, {m.base:#018x}, {m.end:#018x}, '
                          f'{m.base:#018x}, 0x0, 0x0, {m.path}')
        header.append(f'BB Table: {len(self._blocks)} bbs')
        text = ('\n'.join(header) + '\n').encode('utf-8')
        body = bytearray()
        # Sorted so the output is deterministic; the format is order-independent.
        for module_id, start, size in sorted(self._blocks):
            body += _BB_STRUCT.pack(start, size, module_id)
        return text + bytes(body)

    def save(self, path: str) -> int:
        with open(path, 'wb') as f:
            f.write(self.to_bytes())
        return self.block_count()


def _normalise(modules: Iterable) -> List[Tuple[str, int, int]]:
    """Accept loaders.Module, (name, base, size) or (name, base, end) triples."""
    out = []
    for m in modules:
        if hasattr(m, 'base') and hasattr(m, 'name'):
            size = getattr(m, 'size', None)
            end = m.end + 1 if size is None else m.base + size
            out.append((str(m.name), int(m.base), int(end)))
        else:
            name, base, third = m
            # A size and an end are told apart by magnitude: an end is above base.
            end = third if third > base else base + third
            out.append((str(name), int(base), int(end)))
    return out


class SessionCoverage:
    """Records executed basic blocks for a target, and writes them as drcov.

    Blocks that fall outside every declared module are attributed to a
    synthetic module covering the mapped region they landed in, so coverage of
    a harness's scratch code is reported rather than silently dropped. Set
    `fallback_regions=False` to drop them instead.
    """

    def __init__(self, target, modules: Iterable = (),
                 fallback_regions: bool = True) -> None:
        self.target = target
        self.modules = _normalise(modules)
        self.fallback_regions = fallback_regions
        self._raw: Set[Tuple[int, int]] = set()
        self._hook = None

    # ---- recording -------------------------------------------------------

    def start(self) -> None:
        if self._hook is None:
            self._hook = self.target.uc.hook_add(UC_HOOK_BLOCK, self._on_block)

    def stop(self) -> None:
        if self._hook is not None:
            self.target.uc.hook_del(self._hook)
            self._hook = None

    @property
    def recording(self) -> bool:
        return self._hook is not None

    def reset(self) -> None:
        self._raw.clear()

    def _on_block(self, uc, address, size, user_data) -> None:
        self._raw.add((address, size))

    @property
    def block_count(self) -> int:
        return len(self._raw)

    @property
    def blocks(self) -> Sequence[Tuple[int, int]]:
        return tuple(sorted(self._raw))

    # ---- output ----------------------------------------------------------

    def to_writer(self) -> DrcovWriter:
        w = DrcovWriter()
        ids: Dict[Tuple[int, int], int] = {}
        for name, base, end in self.modules:
            ids[(base, end)] = w.add_module(name, base, end)
        dropped = 0
        for address, size in sorted(self._raw):
            span = self._module_for(address)
            if span is None:
                dropped += 1
                continue
            if span not in ids:
                base, end = span
                ids[span] = w.add_module(f'region_{base:#x}', base, end)
            base = span[0]
            w.add_block(ids[span], address - base, size)
        self.dropped = dropped
        return w

    def _module_for(self, address: int) -> Optional[Tuple[int, int]]:
        for _, base, end in self.modules:
            if base <= address < end:
                return (base, end)
        if not self.fallback_regions:
            return None
        for start, last, _perms in self.target.regions():
            if start <= address <= last:
                return (start, last + 1)
        return None

    def stats(self) -> Dict[str, int]:
        """Blocks per module path, for a quick summary."""
        w = self.to_writer()
        by_id = {m.id: m.path for m in w.modules}
        counts: Dict[str, int] = {}
        for module_id, _start, _size in w._blocks:
            path = by_id.get(module_id, '?')
            counts[path] = counts.get(path, 0) + 1
        return counts

    def save(self, path: str) -> int:
        return self.to_writer().save(path)
