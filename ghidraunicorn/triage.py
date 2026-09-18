"""Batch crash triage: replay a directory of fuzzing inputs through a harness.

This is the non-interactive half of what the Debugger gives you one input at a
time. Point it at the harness you fuzz with and at ``output/crashes`` and it
tells you, per input, what happened: clean exit, Unicorn fault (with the error
kind, the faulting access address and the faulting instruction), or a run that
never finished. Then it buckets the inputs by crash signature so a thousand
crashes become the handful of distinct bugs behind them.

Every input gets a *fresh* engine from :func:`ghidraunicorn.loaders.load_harness`,
so one input cannot leave state behind for the next.

Two independent brakes stop a run that never ends:

* an instruction budget, counted by a ``UC_HOOK_CODE`` hook this module adds to
  the target's engine (the target itself has no notion of a budget), and
* a wall-clock deadline, checked in the same hook and, as a true backstop,
  by a timer thread that calls ``emu_stop`` from the outside.

Either one is reported as a ``timeout`` outcome.

Nothing here imports Ghidra: ``python -m ghidraunicorn.triage`` works on a
machine with no Ghidra and no ``ghidratrace``. Feed its ``--json`` to
``tools/import_triage.py`` to paint the results onto a Ghidra program.
"""
from dataclasses import dataclass, field, replace
import argparse
import json
import os
import sys
import threading
import time
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import unicorn
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UcError

from . import loaders
from .coverage import SessionCoverage
from .provenance import InputProvenance, format_ranges, ranges

#: Instructions a single input may execute before it is called a timeout.
DEFAULT_MAX_INSTRUCTIONS = 10_000_000
#: Seconds a single input may run before it is called a timeout.
DEFAULT_TIMEOUT = 30.0
#: Bytes of stack captured from SP at the stop.
DEFAULT_STACK_BYTES = 64

#: How often the instruction hook bothers to look at the clock.
_CLOCK_EVERY = 1 << 12

# Outcome kinds.
OK = 'ok'                # reached the harness's end/exit address
CRASH = 'crash'          # Unicorn raised (unmapped access, bad instruction...)
TIMEOUT = 'timeout'      # instruction budget or wall clock ran out
STOPPED = 'stopped'      # stopped for some other reason (breakpoint, interrupt)
ERROR = 'error'          # the harness itself blew up; nothing was executed

#: Files a fuzzer leaves in its output directories that are not inputs.
SKIP_NAMES = {'README.txt', '.state'}


def _const_names(prefix: str) -> Dict[int, str]:
    out = {}
    for name in dir(unicorn):
        if name.startswith(prefix):
            value = getattr(unicorn, name)
            if isinstance(value, int):
                out.setdefault(value, name)
    return out


_ERR_NAMES = _const_names('UC_ERR_')
_MEM_NAMES = _const_names('UC_MEM_')


def error_kind(err: Optional[UcError]) -> str:
    """'UC_ERR_READ_UNMAPPED' for a Unicorn error, best effort."""
    if err is None:
        return ''
    errno = getattr(err, 'errno', None)
    if errno is None:
        return str(err)
    return _ERR_NAMES.get(errno, f'UC_ERR_{errno}')


def _access_kind(access: int) -> str:
    return _MEM_NAMES.get(access, f'UC_MEM_{access}')


# ---------------------------------------------------------------------------
# Results


@dataclass(frozen=True)
class Instruction:
    """The instruction at the stop, when Capstone can decode it."""
    address: int
    size: int
    mnemonic: str
    operands: str
    bytes: bytes = b''

    @property
    def text(self) -> str:
        return f'{self.mnemonic} {self.operands}'.strip()

    def to_dict(self) -> dict:
        return {'address': self.address, 'address_hex': f'{self.address:#x}',
                'size': self.size, 'mnemonic': self.mnemonic,
                'operands': self.operands, 'text': self.text,
                'bytes': self.bytes.hex()}


@dataclass(frozen=True)
class Fault:
    """What Unicorn refused to do."""
    kind: str                       # UC_ERR_READ_UNMAPPED, ...
    errno: Optional[int]
    message: str
    address: Optional[int] = None   # the address the instruction tried to touch
    access: Optional[str] = None    # UC_MEM_READ_UNMAPPED, ...
    size: Optional[int] = None

    def to_dict(self) -> dict:
        d = {'kind': self.kind, 'errno': self.errno, 'message': self.message,
             'address': self.address, 'access': self.access, 'size': self.size}
        d['address_hex'] = None if self.address is None else f'{self.address:#x}'
        return d


@dataclass(frozen=True)
class MemoryWindow:
    address: int
    data: bytes
    words: Tuple[int, ...] = ()

    def to_dict(self) -> dict:
        return {'address': self.address, 'address_hex': f'{self.address:#x}',
                'data': self.data.hex(), 'words': list(self.words)}


@dataclass(frozen=True)
class InputResult:
    """What one input did."""
    path: str
    size: int
    outcome: str                        # OK | CRASH | TIMEOUT | STOPPED | ERROR
    reason: str                         # the StopEvent reason, or why not
    description: str = ''
    pc: Optional[int] = None
    instruction: Optional[Instruction] = None
    fault: Optional[Fault] = None
    registers: Dict[str, int] = field(default_factory=dict)
    stack: Optional[MemoryWindow] = None
    instructions: int = 0
    wall_time: float = 0.0
    signature: str = ''
    #: Inclusive (start, end) runs of input offsets the program read, and the
    #: subset the faulting instruction read. Empty when the harness does not
    #: say where the input lives.
    input_read: Tuple[Tuple[int, int], ...] = ()
    input_at_fault: Tuple[Tuple[int, int], ...] = ()
    #: Basic blocks executed, and where the drcov file was written.
    blocks: int = 0
    coverage_path: str = ''

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def crashed(self) -> bool:
        return self.outcome == CRASH

    @property
    def kind(self) -> str:
        """The coarse label a signature is built from: the fault kind for a
        crash, the outcome otherwise."""
        return self.fault.kind if self.fault is not None else self.outcome

    @property
    def insn_text(self) -> str:
        return self.instruction.text if self.instruction is not None else ''

    def to_dict(self) -> dict:
        return {
            'path': self.path,
            'name': self.name,
            'size': self.size,
            'outcome': self.outcome,
            'reason': self.reason,
            'description': self.description,
            'kind': self.kind,
            'pc': self.pc,
            'pc_hex': None if self.pc is None else f'{self.pc:#x}',
            'instruction': None if self.instruction is None else self.instruction.to_dict(),
            'fault': None if self.fault is None else self.fault.to_dict(),
            'registers': {k: v for k, v in self.registers.items()},
            'stack': None if self.stack is None else self.stack.to_dict(),
            'instructions': self.instructions,
            'wall_time': round(self.wall_time, 6),
            'signature': self.signature,
            'input_read': [list(r) for r in self.input_read],
            'input_at_fault': [list(r) for r in self.input_at_fault],
            'blocks': self.blocks,
            'coverage_path': self.coverage_path,
        }


@dataclass
class CrashGroup:
    """Inputs that share a signature; one bug, however many inputs found it."""
    signature: str
    outcome: str
    kind: str
    pc: Optional[int]
    instruction: Optional[Instruction]
    fault: Optional[Fault]
    inputs: List[str] = field(default_factory=list)
    representative: str = ''

    @property
    def count(self) -> int:
        return len(self.inputs)

    @property
    def crashed(self) -> bool:
        return self.outcome == CRASH

    def to_dict(self) -> dict:
        return {
            'signature': self.signature,
            'outcome': self.outcome,
            'kind': self.kind,
            'count': self.count,
            'pc': self.pc,
            'pc_hex': None if self.pc is None else f'{self.pc:#x}',
            'instruction': None if self.instruction is None else self.instruction.to_dict(),
            'fault': None if self.fault is None else self.fault.to_dict(),
            'inputs': list(self.inputs),
            'representative': self.representative,
        }


@dataclass
class TriageReport:
    harness: str
    results: List[InputResult] = field(default_factory=list)
    groups: List[CrashGroup] = field(default_factory=list)
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS
    timeout: float = DEFAULT_TIMEOUT

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in self.results:
            out[r.outcome] = out.get(r.outcome, 0) + 1
        return out

    @property
    def crashes(self) -> List[InputResult]:
        return [r for r in self.results if r.crashed]

    @property
    def crash_groups(self) -> List[CrashGroup]:
        return [g for g in self.groups if g.crashed]

    def group_for(self, signature: str) -> Optional[CrashGroup]:
        for g in self.groups:
            if g.signature == signature:
                return g
        return None

    def to_dict(self) -> dict:
        return {
            'harness': self.harness,
            'inputs': len(self.results),
            'counts': self.counts(),
            'limits': {'max_instructions': self.max_instructions, 'timeout': self.timeout},
            'groups': [g.to_dict() for g in self.groups],
            'results': [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Signatures
#
# A signature function turns a result into the string that decides which bucket
# it lands in. Swap one in through `signature=` to make grouping coarser or
# finer than the default.

def signature_kind_pc(result: InputResult) -> str:
    """Default: the fault kind (or outcome) and where it happened."""
    if result.pc is None:
        return result.kind
    return f'{result.kind}@{result.pc:#x}'


def signature_kind(result: InputResult) -> str:
    """Coarser: everything that failed the same way is one bucket."""
    return result.kind


def signature_kind_pc_target(result: InputResult) -> str:
    """Finer: also the address the faulting instruction tried to touch."""
    base = signature_kind_pc(result)
    if result.fault is not None and result.fault.address is not None:
        return f'{base}->{result.fault.address:#x}'
    return base


SIGNATURES: Dict[str, Callable[[InputResult], str]] = {
    'kind-pc': signature_kind_pc,
    'kind': signature_kind,
    'kind-pc-target': signature_kind_pc_target,
}

DEFAULT_SIGNATURE = signature_kind_pc


# ---------------------------------------------------------------------------
# Running one input


class _Budget:
    """Instruction counter and clock, as a UC_HOOK_CODE hook on the engine.

    The target class knows nothing about this: the hook is added to its `uc`
    from the outside and removed afterwards.
    """

    def __init__(self, uc, max_instructions: int, deadline: Optional[float]):
        self.uc = uc
        self.max_instructions = max_instructions
        self.deadline = deadline
        self.count = 0
        self.tripped: Optional[str] = None      # 'instructions' | 'wall'
        self._hook = uc.hook_add(UC_HOOK_CODE, self._on_code)

    def _on_code(self, uc, address, size, user_data) -> None:
        self.count += 1
        if self.max_instructions and self.count > self.max_instructions:
            if self.tripped is None:
                self.tripped = 'instructions'
            uc.emu_stop()
            return
        if self.deadline is not None and (self.count & (_CLOCK_EVERY - 1)) == 0:
            if time.monotonic() > self.deadline:
                if self.tripped is None:
                    self.tripped = 'wall'
                uc.emu_stop()

    def expire(self) -> None:
        """Called from the watchdog thread: the only cross-thread call Unicorn
        allows is emu_stop, which is all this does."""
        if self.tripped is None:
            self.tripped = 'wall'
        try:
            self.uc.emu_stop()
        except UcError:
            pass

    def remove(self) -> None:
        try:
            self.uc.hook_del(self._hook)
        except UcError:
            pass


def _decode(target, pc: Optional[int]) -> Optional[Instruction]:
    if pc is None:
        return None
    try:
        decoded = target.decode(pc)
    except Exception:
        return None
    if decoded is None:
        return None
    size, mnem, ops = decoded
    try:
        raw = target.read(pc, size)
    except Exception:
        raw = b''
    return Instruction(pc, size, mnem, ops, raw)


def _stack(target, nbytes: int) -> Optional[MemoryWindow]:
    if nbytes <= 0:
        return None
    try:
        sp = target.sp()
        chunks = target.read_mapped(sp, sp + nbytes)
    except Exception:
        return None
    if not chunks:
        return None
    address, data = chunks[0]
    psize = target.spec.ptr_size
    order = 'big' if target.spec.endian == 'big' else 'little'
    words = tuple(int.from_bytes(data[i:i + psize], order)
                  for i in range(0, len(data) - psize + 1, psize))
    return MemoryWindow(address, data, words)


def _registers(target) -> Dict[str, int]:
    try:
        return dict(target.regs())
    except Exception:
        return {}


def triage_input(harness: str, input_path: str, *,
                 start: Optional[int] = None, end: Optional[int] = None,
                 image: Optional[str] = None,
                 max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
                 timeout: Optional[float] = DEFAULT_TIMEOUT,
                 stack_bytes: int = DEFAULT_STACK_BYTES,
                 signature: Callable[[InputResult], str] = DEFAULT_SIGNATURE,
                 input_at: Optional[int] = None,
                 coverage_dir: Optional[str] = None,
                 ) -> InputResult:
    """Replay one input on a freshly built engine and report what it did."""
    try:
        size = os.path.getsize(input_path)
    except OSError:
        size = 0

    started = time.monotonic()
    try:
        loaded = loaders.load_harness(harness, input_path, start, end, image)
    except Exception as e:                       # a harness that will not build
        return _finish(InputResult(
            path=input_path, size=size, outcome=ERROR, reason='load',
            description=f'{type(e).__name__}: {e}',
            wall_time=time.monotonic() - started), signature)

    target = loaded.target
    prov = _provenance(target, loaded, input_at, size)
    if prov is not None:
        prov.start()
    cov = None
    if coverage_dir:
        cov = SessionCoverage(target, loaded.modules)
        cov.start()
    deadline = None if not timeout else started + timeout
    budget = _Budget(target.uc, max_instructions, deadline)
    watchdog = None
    if timeout:
        watchdog = threading.Timer(max(timeout - (time.monotonic() - started), 0.0),
                                   budget.expire)
        watchdog.daemon = True
        watchdog.start()
    try:
        ev = target.run()
    except Exception as e:                       # target refused to run at all
        return _finish(InputResult(
            path=input_path, size=size, outcome=ERROR, reason='run',
            description=f'{type(e).__name__}: {e}',
            instructions=budget.count,
            wall_time=time.monotonic() - started), signature)
    finally:
        if watchdog is not None:
            watchdog.cancel()
        budget.remove()
        if prov is not None:
            prov.stop()
        if cov is not None:
            cov.stop()
    elapsed = time.monotonic() - started

    pc = ev.pc
    fault = None
    if ev.reason == 'error' and ev.error is not None:
        fault = Fault(
            kind=error_kind(ev.error),
            errno=getattr(ev.error, 'errno', None),
            message=str(ev.error),
            address=ev.fault_address,
            access=ev.fault_access,
            size=ev.fault_size)

    if budget.tripped is not None and ev.reason != 'error':
        outcome, reason = TIMEOUT, budget.tripped
        description = (f'{budget.tripped} limit reached after {budget.count} '
                       f'instructions at {pc:#x}')
    elif ev.reason == 'error':
        outcome, reason, description = CRASH, ev.reason, ev.description
    elif ev.reason == 'exit':
        outcome, reason, description = OK, ev.reason, ev.description
    else:
        outcome, reason, description = STOPPED, ev.reason, ev.description

    return _finish(InputResult(
        path=input_path, size=size, outcome=outcome, reason=reason,
        description=description, pc=pc,
        instruction=_decode(target, pc), fault=fault,
        registers=_registers(target), stack=_stack(target, stack_bytes),
        instructions=budget.count, wall_time=elapsed,
        input_read=() if prov is None else tuple(prov.read_ranges()),
        input_at_fault=() if prov is None or pc is None
        else tuple(ranges(prov.reads_at(pc))),
        blocks=0 if cov is None else cov.block_count,
        coverage_path='' if cov is None else _save_coverage(cov, coverage_dir, input_path)),
        signature)


def _safe_name(name: str) -> str:
    """Fuzzer file names carry commas and colons; keep them off the filesystem."""
    return ''.join(c if c.isalnum() or c in '.-_' else '_' for c in name)[:120]


def _save_coverage(cov: SessionCoverage, directory: str, input_path: str) -> str:
    os.makedirs(directory, exist_ok=True)
    out = os.path.join(directory, _safe_name(os.path.basename(input_path)) + '.drcov')
    try:
        cov.save(out)
    except OSError:
        return ''
    return out


def _provenance(target, loaded, input_at: Optional[int],
                size: int) -> Optional[InputProvenance]:
    """Watch the input buffer, when we know where the harness put it."""
    if size <= 0:
        return None
    declared = getattr(loaded, 'input_region', None)
    base = input_at if input_at is not None else (declared[0] if declared else None)
    if base is None:
        return None
    length = size
    if declared and declared[1]:
        length = min(length, declared[1])
    if length <= 0:
        return None
    try:
        return InputProvenance(target, base, length)
    except Exception:
        return None


def _finish(result: InputResult, signature: Callable[[InputResult], str]) -> InputResult:
    return replace(result, signature=signature(result))


# ---------------------------------------------------------------------------
# Running a batch


def collect_inputs(paths: Iterable[str], limit: Optional[int] = None) -> List[str]:
    """Files named directly, plus every file under any directory named.

    Fuzzer bookkeeping (`README.txt`, `.state`, dotfiles) is skipped.
    """
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs
                                 if not d.startswith('.') and d not in SKIP_NAMES)
                for name in sorted(names):
                    if name.startswith('.') or name in SKIP_NAMES:
                        continue
                    out.append(os.path.join(root, name))
        elif os.path.exists(p):
            out.append(p)
        else:
            raise FileNotFoundError(p)
    if limit is not None and limit >= 0:
        out = out[:limit]
    return out


def group_results(results: Sequence[InputResult]) -> List[CrashGroup]:
    """Bucket results by their signature, biggest bucket first.

    The representative is the smallest input in the bucket (ties broken by
    name), which is the one worth opening in the Debugger.
    """
    groups: Dict[str, CrashGroup] = {}
    members: Dict[str, List[InputResult]] = {}
    for r in results:
        g = groups.get(r.signature)
        if g is None:
            g = CrashGroup(signature=r.signature, outcome=r.outcome, kind=r.kind,
                           pc=r.pc, instruction=r.instruction, fault=r.fault)
            groups[r.signature] = g
            members[r.signature] = []
        g.inputs.append(r.path)
        members[r.signature].append(r)
    for sig, g in groups.items():
        rep = min(members[sig], key=lambda r: (r.size, r.name))
        g.representative = rep.path
        # Describe the group with its representative's decode, so the row shown
        # is the row of the input a human would open.
        g.instruction = rep.instruction
        g.fault = rep.fault
    order = {CRASH: 0, TIMEOUT: 1, ERROR: 2, STOPPED: 3, OK: 4}
    return sorted(groups.values(),
                  key=lambda g: (order.get(g.outcome, 9), -g.count, g.signature))


def triage_inputs(harness: str, inputs: Iterable[str], *,
                  start: Optional[int] = None, end: Optional[int] = None,
                  image: Optional[str] = None,
                  max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
                  timeout: Optional[float] = DEFAULT_TIMEOUT,
                  stack_bytes: int = DEFAULT_STACK_BYTES,
                  signature: Callable[[InputResult], str] = DEFAULT_SIGNATURE,
                  limit: Optional[int] = None,
                  progress: Optional[Callable[[InputResult], None]] = None,
                  input_at: Optional[int] = None,
                  coverage_dir: Optional[str] = None,
                  ) -> TriageReport:
    """Replay every input through `harness` and group the outcomes.

    `inputs` is any mix of files and directories. Each input runs on its own
    engine, so nothing one input does can affect another.
    """
    paths = collect_inputs(inputs, limit)
    report = TriageReport(harness=os.path.abspath(harness),
                          max_instructions=max_instructions,
                          timeout=0.0 if not timeout else float(timeout))
    for path in paths:
        r = triage_input(harness, path, start=start, end=end, image=image,
                         max_instructions=max_instructions, timeout=timeout,
                         stack_bytes=stack_bytes, signature=signature,
                         input_at=input_at, coverage_dir=coverage_dir)
        report.results.append(r)
        if progress is not None:
            progress(r)
    report.groups = group_results(report.results)
    return report


# ---------------------------------------------------------------------------
# Printing


#: Fuzzer file names are long; the JSON keeps the full path.
NAME_WIDTH = 40


def _hex(value: Optional[int]) -> str:
    return '' if value is None else f'{value:#x}'


def _short(name: str, width: int = NAME_WIDTH) -> str:
    return name if len(name) <= width else name[:width - 3] + '...'


def format_table(rows: Sequence[Sequence[str]], headers: Sequence[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = ['  '.join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip(),
             '  '.join('-' * w for w in widths)]
    for row in rows:
        lines.append('  '.join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip())
    return '\n'.join(lines)


def format_groups(report: TriageReport) -> str:
    rows = []
    for g in report.groups:
        rows.append([str(g.count), g.outcome, g.kind, _hex(g.pc),
                     g.instruction.text if g.instruction is not None else '',
                     _hex(g.fault.address) if g.fault is not None else '',
                     _short(os.path.basename(g.representative))])
    return format_table(rows, ['COUNT', 'OUTCOME', 'KIND', 'PC', 'INSTRUCTION',
                               'FAULT ADDR', 'REPRESENTATIVE'])


def format_results(report: TriageReport) -> str:
    rows = []
    for r in report.results:
        rows.append([_short(r.name), str(r.size), r.outcome, _hex(r.pc), r.insn_text,
                     str(r.instructions), f'{r.wall_time:.3f}', r.signature])
    return format_table(rows, ['INPUT', 'BYTES', 'OUTCOME', 'PC', 'INSTRUCTION',
                               'INSNS', 'SECONDS', 'SIGNATURE'])


def format_detail(result: InputResult, spec_status: Optional[str] = None) -> str:
    """The full state of one input's run: fault, registers, stack."""
    out = [f'{result.name}  [{result.outcome}] {result.description}']
    if result.fault is not None:
        f = result.fault
        where = '' if f.address is None else f' touching {f.address:#x}'
        access = '' if f.access is None else f' ({f.access}, {f.size} bytes)'
        out.append(f'  fault: {f.kind}{where}{access}')
    if result.instruction is not None:
        i = result.instruction
        out.append(f'  insn:  {i.address:#x}  {i.bytes.hex():<16} {i.text}')
    out.append(f'  ran {result.instructions} instructions in {result.wall_time:.3f}s')
    if result.coverage_path:
        out.append(f'  coverage: {result.blocks} blocks -> {result.coverage_path}')
    if result.input_read:
        out.append(f'  input read: {format_ranges(result.input_read)}')
        if result.input_at_fault:
            out.append(f'  input read here: {format_ranges(result.input_at_fault)}')
    if result.registers:
        names = list(result.registers)
        cells = [f'{n}={result.registers[n]:#x}' for n in names]
        width = max(len(c) for c in cells) + 2
        per_line = max(1, 100 // width)
        for i in range(0, len(cells), per_line):
            out.append('  ' + ''.join(c.ljust(width) for c in cells[i:i + per_line]).rstrip())
    if result.stack is not None and result.stack.words:
        s = result.stack
        psize = len(s.data) // len(s.words) if s.words else 8
        for i, w in enumerate(s.words[:8]):
            out.append(f'  {s.address + i * psize:#010x}|+{i * psize:#05x}: {w:#0{psize * 2 + 2}x}')
    return '\n'.join(out)


def print_report(report: TriageReport, stream=None, detail: bool = True,
                 verbose: bool = False) -> None:
    out = stream or sys.stdout
    counts = report.counts()
    summary = ', '.join(f'{counts[k]} {k}' for k in (CRASH, TIMEOUT, ERROR, STOPPED, OK)
                        if counts.get(k))
    print(f'{len(report.results)} inputs through {os.path.basename(report.harness)}'
          f': {summary or "nothing ran"}', file=out)
    print(f'{len(report.groups)} distinct signatures '
          f'({len(report.crash_groups)} crashing)', file=out)
    print(file=out)
    print(format_groups(report), file=out)
    if detail and report.results:
        print(file=out)
        print(format_results(report), file=out)
    if verbose:
        by_path = {r.path: r for r in report.results}
        for g in report.groups:
            rep = by_path.get(g.representative)
            if rep is None:
                continue
            print(file=out)
            print(f'=== {g.signature} ({g.count} input'
                  f'{"s" if g.count != 1 else ""}) ===', file=out)
            print(format_detail(rep), file=out)


# ---------------------------------------------------------------------------
# Command line


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='python -m ghidraunicorn.triage',
        description='Replay fuzzing inputs through a harness and group the crashes.')
    p.add_argument('--harness', required=True,
                   help='Python harness defining create(input_file) -> Uc')
    p.add_argument('--inputs', required=True, nargs='+', metavar='PATH',
                   help='input files, or directories of them (output/crashes)')
    p.add_argument('--json', dest='json_out', metavar='FILE',
                   help='write the full report as JSON (tools/import_triage.py reads it)')
    p.add_argument('--limit', type=int, help='only the first N inputs')
    p.add_argument('--max-instructions', type=int, default=DEFAULT_MAX_INSTRUCTIONS,
                   help=f'instruction budget per input (default {DEFAULT_MAX_INSTRUCTIONS}, 0 for none)')
    p.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT,
                   help=f'wall-clock seconds per input (default {DEFAULT_TIMEOUT}, 0 for none)')
    p.add_argument('--image', help='program image path, for module naming')
    p.add_argument('--start', help='start address override')
    p.add_argument('--end', help='end address override')
    p.add_argument('--input-at', metavar='ADDR',
                   help='address the harness writes the input to, if it does '
                        'not declare INPUT_BASE; enables the input-bytes report')
    p.add_argument('--coverage-dir', metavar='DIR',
                   help='write a drcov file per input here, for ghidra-aflcov '
                        'or Lighthouse')
    p.add_argument('--stack-bytes', type=int, default=DEFAULT_STACK_BYTES,
                   help='bytes of stack captured at the stop')
    p.add_argument('--signature', choices=sorted(SIGNATURES), default='kind-pc',
                   help='how inputs are grouped (default kind-pc)')
    p.add_argument('--quiet', action='store_true',
                   help='only the group table, no per-input rows')
    p.add_argument('--verbose', action='store_true',
                   help='also registers, stack and fault detail per group')
    p.add_argument('--progress', action='store_true',
                   help='print each input to stderr as it finishes')
    return p


def _addr(v: Optional[str]) -> Optional[int]:
    if v is None or str(v).strip() == '':
        return None
    return int(str(v), 0)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    progress = None
    if args.progress:
        def progress(r: InputResult) -> None:
            print(f'[{r.outcome:8}] {r.name} {_hex(r.pc)} {r.insn_text}',
                  file=sys.stderr, flush=True)

    try:
        report = triage_inputs(
            args.harness, args.inputs,
            start=_addr(args.start), end=_addr(args.end), image=args.image,
            max_instructions=args.max_instructions, timeout=args.timeout,
            stack_bytes=args.stack_bytes, signature=SIGNATURES[args.signature],
            limit=args.limit, progress=progress, input_at=_addr(args.input_at),
            coverage_dir=args.coverage_dir)
    except FileNotFoundError as e:
        print(f'no such input: {e}', file=sys.stderr)
        return 2

    print_report(report, detail=not args.quiet, verbose=args.verbose)
    if args.json_out:
        with open(args.json_out, 'w') as f:
            f.write(report.to_json())
            f.write('\n')
        print(f'\nwrote {args.json_out}')
    counts = report.counts()
    if counts.get(CRASH):
        return 1
    if counts.get(ERROR):
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
