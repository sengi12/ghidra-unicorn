"""Ways to obtain a Unicorn engine to debug.

Two sources are supported:

* A **harness**: a Python file that builds the engine, the same code an
  afl-unicorn fuzzing harness uses to set up its target. It must define::

      def create(input_file: str | None) -> unicorn.Uc

  and may return ``(uc, start, end)`` instead of a bare engine. Optional
  module-level names ``START``, ``END`` (int addresses), ``EXITS`` (iterable of
  addresses), ``MODULES`` (list of ``(name, base, size)``) and
  ``INPUT_BASE``/``INPUT_SIZE`` (or ``INPUT_REGION``, where the input was
  written) refine what Ghidra and the triage report see. ``create`` runs once; the engine it returns is what gets
  debugged, so map memory, load code and the input, and set PC/SP in there.

* An **afl-unicorn context directory** produced by one of the
  ``unicorn_dumper_*.py`` scripts (``_index.json`` plus zlib'd segment files).
  This is loaded natively so afl-unicorn need not be importable.
"""
from dataclasses import dataclass, field
import importlib.util
import json
import os
import sys
import zlib
from typing import Dict, Iterable, List, Optional, Tuple

from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE, Uc, UcError

from . import arch
from .target import UnicornTarget

PAGE = 0x1000


@dataclass(frozen=True)
class Module:
    name: str
    base: int
    size: int

    @property
    def end(self) -> int:
        return self.base + self.size - 1


@dataclass
class Loaded:
    target: UnicornTarget
    modules: List[Module] = field(default_factory=list)
    description: str = ''
    #: Where the harness put the fuzz input, as (base, maximum size), when it
    #: says so. Triage uses it to report which input bytes a crash read.
    input_region: Optional[Tuple[int, int]] = None
    #: The harness module, when the target came from one. `install_layers`
    #: reads its opt-outs from here; an afl-unicorn dump has no module.
    module: object = None


def _parse_addr(value) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    value = str(value).strip()
    if value == '':
        return None
    return int(value, 0)


def default_modules(target: UnicornTarget, image: Optional[str]) -> List[Module]:
    """One module named after the image spanning the executable regions."""
    exec_regions = [(s, e) for s, e, p in target.regions() if p & UC_PROT_EXEC]
    if not exec_regions:
        exec_regions = [(s, e) for s, e, p in target.regions()]
    if not exec_regions:
        return []
    base = min(s for s, _ in exec_regions)
    end = max(e for _, e in exec_regions)
    name = image or target.name
    return [Module(name, base, end - base + 1)]


# ---------------------------------------------------------------------------
# Harness files

def load_harness(path: str, input_file: Optional[str] = None,
                 start: Optional[int] = None, end: Optional[int] = None,
                 image: Optional[str] = None) -> Loaded:
    path = os.path.abspath(path)
    name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(f'harness_{name}', path)
    if spec is None or spec.loader is None:
        raise ValueError(f'cannot import harness {path}')
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.dirname(path))
    spec.loader.exec_module(mod)
    if not hasattr(mod, 'create'):
        raise ValueError(f'{path} does not define create(input_file)')
    result = mod.create(input_file)
    h_start = h_end = None
    if isinstance(result, tuple):
        uc = result[0]
        if len(result) > 1:
            h_start = result[1]
        if len(result) > 2:
            h_end = result[2]
    else:
        uc = result
    if not isinstance(uc, Uc):
        raise ValueError(f'{path}: create() must return a unicorn.Uc (got {type(uc).__name__})')
    if start is None:
        start = h_start if h_start is not None else _parse_addr(getattr(mod, 'START', None))
    if end is None:
        end = h_end if h_end is not None else _parse_addr(getattr(mod, 'END', None))
    exits = [_parse_addr(x) for x in getattr(mod, 'EXITS', ())]
    target = UnicornTarget(uc, end=end, exits=exits, name=name)
    if start is not None:
        target.reg_write(target.spec.pc, start)
    modules = [Module(n, _parse_addr(b), int(s)) for n, b, s in getattr(mod, 'MODULES', ())]
    if not modules:
        modules = default_modules(target, image)
    return Loaded(target, modules, f'harness {os.path.basename(path)}',
                  input_region=_input_region(mod), module=mod)


def _input_region(mod) -> Optional[Tuple[int, int]]:
    """`INPUT_REGION = (base, size)`, or `INPUT_BASE` with optional `INPUT_SIZE`."""
    region = getattr(mod, 'INPUT_REGION', None)
    if region:
        base, size = region
        return _parse_addr(base), int(size)
    base = _parse_addr(getattr(mod, 'INPUT_BASE', None))
    if base is None:
        return None
    size = getattr(mod, 'INPUT_SIZE', None)
    return base, int(size) if size else 0


# ---------------------------------------------------------------------------
# afl-unicorn context dumps

# Register names used by unicorn_dumper_*.py, per dump arch, mapped to ours.
_DUMP_REG_ALIASES: Dict[str, Dict[str, str]] = {
    'x64': {'efl': 'rflags'},
    'x86': {'efl': 'eflags'},
    'mips': {'0': 'zero', 'fp': 's8'},
    'mipsel': {'0': 'zero', 'fp': 's8'},
    'arm64le': {'fp': 'x29', 'lr': 'x30'},
    'arm64be': {'fp': 'x29', 'lr': 'x30'},
}


def load_context(directory: str, start: Optional[int] = None,
                 end: Optional[int] = None, image: Optional[str] = None) -> Loaded:
    index = os.path.join(directory, '_index.json')
    if not os.path.isfile(index):
        raise ValueError(f'{index} not found; is this an afl-unicorn context directory?')
    with open(index) as f:
        ctx = json.load(f)
    for key in ('arch', 'regs', 'segments'):
        if key not in ctx:
            raise ValueError(f'{index}: missing "{key}"')
    arch_key = ctx['arch']['arch']
    spec = arch.spec_for_key(arch_key)
    uc = Uc(spec.uc_arch, spec.uc_mode)

    modules: Dict[str, Tuple[int, int]] = {}
    for seg in ctx['segments']:
        _map_segment(uc, seg, directory)
        name = seg.get('name') or ''
        if name and not name.startswith('['):
            lo, hi = modules.get(name, (seg['start'], seg['end']))
            modules[name] = (min(lo, seg['start']), max(hi, seg['end']))

    aliases = _DUMP_REG_ALIASES.get(spec.key, {})
    for rname, value in ctx['regs'].items():
        gname = aliases.get(rname, rname)
        if spec.has_reg(gname):
            try:
                uc.reg_write(spec.reg(gname).uc, int(value))
            except UcError:
                pass

    target = UnicornTarget(uc, spec=spec, end=end,
                           name=os.path.basename(os.path.normpath(directory)))
    if start is not None:
        target.reg_write(spec.pc, start)
    mods = [Module(n, lo, hi - lo) for n, (lo, hi) in sorted(modules.items(), key=lambda kv: kv[1])]
    if not mods:
        mods = default_modules(target, image)
    return Loaded(target, mods, f'afl-unicorn context {directory} ({arch_key})')


def _perms(seg) -> int:
    p = seg.get('permissions', {})
    perms = 0
    if p.get('r', True):
        perms |= UC_PROT_READ
    if p.get('w', True):
        perms |= UC_PROT_WRITE
    if p.get('x', False):
        perms |= UC_PROT_EXEC
    return perms


def _map_segment(uc: Uc, seg, directory: str) -> None:
    start = seg['start'] & ~(PAGE - 1)
    end = (seg['end'] + PAGE - 1) & ~(PAGE - 1)
    if end <= start:
        return
    # Map whatever is not mapped yet, in page-aligned pieces.
    mapped = sorted((s, e + 1) for s, e, _ in uc.mem_regions())
    cursor = start
    for ms, me in mapped:
        if me <= cursor:
            continue
        if ms >= end:
            break
        if ms > cursor:
            uc.mem_map(cursor, ms - cursor, _perms(seg))
        cursor = max(cursor, me)
    if cursor < end:
        uc.mem_map(cursor, end - cursor, _perms(seg))
    content = seg.get('content_file')
    if content:
        path = os.path.join(directory, content)
        if not os.path.isfile(path):
            raise ValueError(f'segment content {path} missing')
        with open(path, 'rb') as f:
            data = zlib.decompress(f.read())
        uc.mem_write(seg['start'], data[:seg['end'] - seg['start']])


# ---------------------------------------------------------------------------
# Standing in for the operating system

def install_layers(loaded: Loaded, harness=None, *, syscalls: bool = True,
                   stubs: bool = True, symbols=None, stdin: bytes = b'',
                   files: Optional[Dict[str, bytes]] = None,
                   on_output=None, trace: bool = False) -> Dict[str, object]:
    """Put the system call and function stub layers under a loaded target.

    Both are opt-out rather than opt-in, because a target that traps into a
    kernel that is not there simply stops, and that is never what the person
    running it wanted. Neither can do any harm where it is not used: the
    system call layer only acts on the trap numbers its architecture uses,
    and a stub only exists at an address a symbol put it at.

    A harness can say otherwise for itself with module-level `SYSCALLS` or
    `STUBS` set to False, `STDIN` for the bytes the program reads from its
    standard input, and `FILES` for the only files it will be able to open.
    Arguments given here win over the harness, which wins over the defaults.

    Returns what was installed, for reporting.
    """
    from . import stubs as stubs_mod
    from . import syscalls as syscalls_mod

    target = loaded.target
    harness = harness if harness is not None else loaded.module
    if harness is not None:
        syscalls = syscalls and getattr(harness, 'SYSCALLS', True)
        stubs = stubs and getattr(harness, 'STUBS', True)
        stdin = stdin or _as_bytes(getattr(harness, 'STDIN', b''))
        files = files or {k: _as_bytes(v)
                          for k, v in (getattr(harness, 'FILES', None) or {}).items()}
    installed: Dict[str, object] = {}
    if syscalls and syscalls_mod.available(target.spec.key):
        installed['syscalls'] = syscalls_mod.install(
            target, stdin=stdin, files=files, on_output=on_output, trace=trace)
    if stubs and stubs_mod.available(target.spec.key):
        layer = stubs_mod.install(target, symbols, on_output=on_output, trace=trace)
        # A raw binary has no symbol table, so a harness may name the
        # addresses itself: STUBS_AT = {'malloc': 0x400800}.
        for name, address in (getattr(harness, 'STUBS_AT', None) or {}).items():
            try:
                layer.bind(name, _parse_addr(address))
            except KeyError:
                pass
        # With no symbols nothing is bound, and an empty stub layer is just
        # overhead; keep it anyway so a person can bind by hand from the
        # console, which is the whole point of having it there.
        installed['stubs'] = layer
    return installed


def _as_bytes(value) -> bytes:
    if value is None:
        return b''
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    return bytes(value)
