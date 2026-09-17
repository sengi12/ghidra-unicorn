"""A gef/pwndbg-style context printed in the launcher's terminal on every stop.

Sections: the stop reason, registers (changed ones highlighted, pointers
annotated), decoded flags, disassembly around PC (Capstone), and the stack.
Colour is on when stdout is a terminal and NO_COLOR is unset. Ghidra's
terminal understands ANSI, so this looks the same there as in a shell.
"""
import os
import sys
from typing import Dict, List, Optional, TextIO, Tuple

from unicorn import UcError

from .target import EXECUTE, StopEvent, UnicornTarget


class Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _c(self, code: str, s: str) -> str:
        return f'\x1b[{code}m{s}\x1b[0m' if self.enabled else s

    def title(self, s: str) -> str: return self._c('1;34', s)     # bold blue
    def reg(self, s: str) -> str: return self._c('1;33', s)       # bold yellow
    def changed(self, s: str) -> str: return self._c('1;31', s)   # bold red
    def code(self, s: str) -> str: return self._c('31', s)        # red   (pointer into code)
    def stack(self, s: str) -> str: return self._c('35', s)       # magenta (pointer into stack)
    def data(self, s: str) -> str: return self._c('36', s)        # cyan  (pointer into data)
    def pc(self, s: str) -> str: return self._c('1;32', s)        # bold green
    def dim(self, s: str) -> str: return self._c('2', s)
    def bp(self, s: str) -> str: return self._c('1;31', s)
    def ok(self, s: str) -> str: return self._c('32', s)
    def warn(self, s: str) -> str: return self._c('1;31', s)


def _want_color(out: TextIO) -> bool:
    if os.getenv('NO_COLOR'):
        return False
    if os.getenv('FORCE_COLOR') or os.getenv('GHIDRA_UNICORN_COLOR'):
        return True
    try:
        return out.isatty()
    except Exception:
        return False


class Context:

    def __init__(self, target: UnicornTarget, out: Optional[TextIO] = None,
                 color: Optional[bool] = None, disasm_lines: int = 8,
                 stack_words: int = 8, width: int = 100) -> None:
        self.target = target
        self.out = out or sys.stdout
        self.p = Palette(_want_color(self.out) if color is None else color)
        self.disasm_lines = disasm_lines
        self.stack_words = stack_words
        self.width = width
        self._last: Dict[str, int] = {}

    # ---- helpers ---------------------------------------------------------

    def _region_kind(self, addr: int) -> Optional[str]:
        for s, e, perms in self.target.regions():
            if s <= addr <= e:
                if perms & 4:
                    return 'code'
                sp = self.target.sp()
                if s <= sp <= e:
                    return 'stack'
                return 'data'
        return None

    def _fmt_val(self, v: int) -> str:
        return f'{v:#0{self.target.spec.ptr_size * 2 + 2}x}'

    def _annotate(self, v: int) -> str:
        kind = self._region_kind(v)
        if kind is None:
            return ''
        try:
            raw = self.target.read(v, min(self.target.spec.ptr_size, 8))
        except UcError:
            return ''
        word = int.from_bytes(raw, 'little' if self.target.spec.endian == 'little' else 'big')
        printable = all(32 <= b < 127 for b in raw)
        text = f' -> {self._fmt_val(word)}'
        if printable and len(raw) >= 4:
            text += f' {raw.decode("ascii")!r}'
        colorer = {'code': self.p.code, 'stack': self.p.stack, 'data': self.p.data}[kind]
        return colorer(text)

    def _rule(self, name: str) -> str:
        label = f'[ {name} ]'
        line = '─' * max(0, self.width - len(label) - 1)
        return self.p.title(f'{line}{label}')

    # ---- sections --------------------------------------------------------

    def registers(self) -> List[str]:
        t = self.target
        lines = []
        regs = t.regs()
        for r in t.spec.regs:
            if r.name not in regs:
                continue
            v = regs[r.name]
            name = f'{r.name:<8}'
            val = self._fmt_val(v) if r.size >= t.spec.ptr_size else f'{v:#0{r.size * 2 + 2}x}'
            if self._last and self._last.get(r.name) != v:
                val = self.p.changed(val)
            else:
                val = self.p.reg(val) if r.name in (t.spec.pc, t.spec.sp) else val
            lines.append(f'{self.p.reg(name)}{val}{self._annotate(v) if r.size >= t.spec.ptr_size else ""}')
        self._last = regs
        return lines

    def flags(self) -> Optional[str]:
        t = self.target
        if t.spec.status is None:
            return None
        v = t.reg_read(t.spec.status)
        parts = []
        for name, label in t.fields():
            fld = t.spec.field(name)
            if fld is not None and fld.width == 1:
                parts.append(self.p.ok(name) if label == '1' else self.p.dim(name.lower()))
            else:
                parts.append(f'{name}={label}')
        return f'{self.p.reg(t.spec.status)} {v:#x} [ {" ".join(parts)} ]'

    def disassembly(self) -> List[str]:
        t = self.target
        pc = t.pc()
        lines = []
        if t.spec.cs is None:
            return [self.p.dim('(install capstone for disassembly)')]
        # Fixed-width ISAs can show a little history.
        width = 4 if t.spec.key.startswith(('arm64', 'mips')) or t.spec.key in ('armle', 'armbe') else 0
        start = pc - 3 * width if width else pc
        if width and (start < 0 or t.decode(start) is None):
            start = pc          # nothing mapped before PC: no history
            width = 0
        addr = start
        bps = {b.address for b in t.breakpoints.values() if b.kind == EXECUTE and b.enabled}
        count = 0
        while count < self.disasm_lines + (3 if width else 0):
            insn = t.decode(addr)
            if insn is None:
                lines.append(f'   {addr:#x}  {self.p.dim("(unmapped or undecodable)")}')
                break
            size, mnem, ops = insn
            try:
                raw = t.read(addr, size).hex()
            except UcError:
                raw = ''
            marker = ' → ' if addr == pc else ('●  ' if addr in bps else '   ')
            text = f'{marker}{addr:#x}  {raw:<16} {mnem:<8} {ops}'
            if addr == pc:
                text = self.p.pc(text)
            elif addr in bps:
                text = self.p.bp(text)
            elif addr < pc:
                text = self.p.dim(text)
            lines.append(text)
            addr += size
            count += 1
        return lines

    def stack(self) -> List[str]:
        t = self.target
        sp = t.sp()
        ps = t.spec.ptr_size
        lines = []
        for i in range(self.stack_words):
            a = sp + i * ps
            try:
                raw = t.read(a, ps)
            except UcError:
                lines.append(f'{a:#x}│+{i * ps:#05x}: {self.p.dim("(unmapped)")}')
                break
            v = int.from_bytes(raw, 'little' if t.spec.endian == 'little' else 'big')
            lines.append(f'{self.p.stack(f"{a:#x}")}│+{i * ps:#05x}: {self._fmt_val(v)}{self._annotate(v)}')
        return lines

    def reason(self, ev: Optional[StopEvent]) -> str:
        if ev is None:
            return ''
        if ev.reason in ('error',):
            return self.p.warn(f'✗ {ev.description}')
        if ev.reason == 'exit':
            return self.p.ok(f'■ {ev.description}')
        return self.p.ok(f'● {ev.description}')

    # ---- whole thing -----------------------------------------------------

    def render(self, ev: Optional[StopEvent] = None) -> str:
        parts: List[str] = []
        if ev is not None:
            parts.append(self.reason(ev))
        parts.append(self._rule('registers'))
        parts += self.registers()
        fl = self.flags()
        if fl:
            parts.append(fl)
        parts.append(self._rule('disassembly'))
        parts += self.disassembly()
        parts.append(self._rule('stack'))
        parts += self.stack()
        parts.append(self.p.title('─' * self.width))
        return '\n'.join(parts) + '\n'

    def show(self, ev: Optional[StopEvent] = None) -> None:
        self.out.write(self.render(ev))
        self.out.flush()
