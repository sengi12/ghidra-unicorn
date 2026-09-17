"""The interactive prompt in the launcher's terminal.

It is a Python console with a layer of short debugger commands on top, in
the style of gdb/gef: anything that is not a known command is Python, with
`target`, `uc` and `commands` in scope. Stops caused here are reported to
Ghidra exactly like stops caused by Ghidra's own buttons, because both go
through the target's stop listeners.
"""
import code
import shlex
import struct
import sys
from typing import Callable, Dict, List, Optional, TextIO

from unicorn import UcError

from . import commands, hooks
from .context import Context
from .target import ACCESS, EXECUTE, READ, WRITE, TargetError, UnicornTarget

HELP = """\
ghidra-unicorn commands (anything else is Python; `target`, `uc`, `commands` are in scope)

  c, continue            run until a breakpoint, watchpoint, exit or fault
  s, si, step [N]        step N instructions into calls
  n, ni, next [N]        step N instructions over calls
  adv, advance ADDR      run until ADDR
  b, break ADDR          breakpoint at ADDR
  w, watch ADDR [SIZE] [r|w|rw]   watchpoint (default 4 bytes, rw)
  d, delete NUM          delete breakpoint NUM
  bl, breakpoints        list breakpoints
  en NUM / dis NUM       enable / disable breakpoint NUM
  x/NFU ADDR             examine memory, e.g. x/8xw 0x2000, x/16xb sp, x/s 0x3000
  r, regs [NAME [VALUE]] show registers, one register, or set one
                         flags and fields too: r ZF 1, r cpsr.T 1, r cpsr.M 0x13
  fields                 list the status register's bit fields
  m, set ADDR HEXBYTES   write bytes, e.g. m 0x3000 41424344
  ctx, context           print the context again
  k, kill                terminate the target
  q, quit                leave (Ghidra's target is disconnected)
  help, ?                this text
"""

_UNITS = {'b': 1, 'h': 2, 'w': 4, 'g': 8}


class UnicornConsole(code.InteractiveConsole):

    def __init__(self, target: UnicornTarget, loaded=None,
                 out: Optional[TextIO] = None, color: Optional[bool] = None) -> None:
        self.target = target
        self.out = out or sys.stdout
        self.ctx = Context(target, self.out, color=color)
        local = {'target': target, 'uc': target.uc, 'commands': commands,
                 'loaded': loaded, 'ctx': self.ctx}
        super().__init__(locals=local)
        self.commands: Dict[str, Callable[[List[str]], None]] = {
            'c': self.cmd_continue, 'continue': self.cmd_continue,
            's': self.cmd_step, 'si': self.cmd_step, 'step': self.cmd_step,
            'n': self.cmd_next, 'ni': self.cmd_next, 'next': self.cmd_next,
            'adv': self.cmd_advance, 'advance': self.cmd_advance,
            'b': self.cmd_break, 'break': self.cmd_break,
            'w': self.cmd_watch, 'watch': self.cmd_watch,
            'd': self.cmd_delete, 'delete': self.cmd_delete,
            'bl': self.cmd_breaklist, 'breakpoints': self.cmd_breaklist,
            'en': self.cmd_enable, 'dis': self.cmd_disable,
            'r': self.cmd_regs, 'regs': self.cmd_regs,
            'm': self.cmd_set, 'set': self.cmd_set,
            'ctx': self.cmd_context, 'context': self.cmd_context,
            'k': self.cmd_kill, 'kill': self.cmd_kill,
            'help': self.cmd_help, '?': self.cmd_help,
            'fields': self.cmd_fields,
        }
        self.quit = False

    # ---- dispatch --------------------------------------------------------

    def push(self, line: str, *args, **kwargs) -> bool:  # type: ignore[override]
        stripped = line.strip()
        if not stripped:
            return super().push(line, *args, **kwargs)
        head = stripped.split(None, 1)[0]
        if head in ('q', 'quit', 'exit'):
            self.quit = True
            raise SystemExit
        if head.startswith('x/') or head == 'x':
            self._run(self.cmd_examine, stripped)
            return False
        if head in self.commands:
            self._run(self.commands[head], stripped)
            return False
        return super().push(line, *args, **kwargs)

    def _run(self, fn: Callable[[List[str]], None], line: str) -> None:
        try:
            fn(shlex.split(line))
        except SystemExit:
            raise
        except (TargetError, UcError, ValueError, KeyError, IndexError) as e:
            self.write(f'error: {e}\n')
        except Exception as e:  # pragma: no cover
            self.write(f'error: {e!r}\n')

    def write(self, data: str) -> None:
        self.out.write(data)
        self.out.flush()

    # ---- value parsing ---------------------------------------------------

    def value(self, text: str) -> int:
        """A number, a register name, or a simple `reg+off` expression."""
        text = text.strip().replace('$', '')
        for op in ('+', '-'):
            if op in text[1:]:
                idx = text.rfind(op)
                left, right = text[:idx], text[idx + 1:]
                if left and right:
                    try:
                        return self.value(left) + (self.value(right) if op == '+' else -self.value(right))
                    except (ValueError, KeyError):
                        pass
        t = self.target
        if t.spec.has_reg(text) or t.spec.flag(text) is not None:
            return t.reg_read(text)
        return int(text, 0)

    # ---- execution -------------------------------------------------------

    def _stopped(self) -> UnicornTarget:
        if self.target.running:
            raise TargetError('target is running (interrupt it from Ghidra first)')
        if self.target.terminated:
            raise TargetError('target has terminated')
        return self.target

    def cmd_continue(self, args: List[str]) -> None:
        t = self._stopped()
        hooks.on_cont()
        t.run()

    def cmd_step(self, args: List[str]) -> None:
        n = int(args[1], 0) if len(args) > 1 else 1
        self._stopped().step(n)

    def cmd_next(self, args: List[str]) -> None:
        n = int(args[1], 0) if len(args) > 1 else 1
        self._stopped().step_over(n)

    def cmd_advance(self, args: List[str]) -> None:
        if len(args) < 2:
            raise ValueError('usage: advance ADDR')
        self._stopped().advance(self.value(args[1]))

    def cmd_kill(self, args: List[str]) -> None:
        t = self.target
        if t.running:
            t.interrupt()
        if not t.terminated:
            t.terminated = True
            from .target import StopEvent
            hooks.on_stop(StopEvent('exit', t.pc(), 'Killed'))
            self.write('target killed\n')

    # ---- breakpoints -----------------------------------------------------

    def _publish_bps(self) -> None:
        if commands.STATE.trace is not None:
            try:
                with commands.batched_tx('Breakpoints changed'):
                    commands.put_breakpoints()
            except Exception as e:
                self.write(f'(could not publish breakpoints to Ghidra: {e})\n')

    def cmd_break(self, args: List[str]) -> None:
        if len(args) < 2:
            raise ValueError('usage: break ADDR')
        bp = self.target.add_breakpoint(self.value(args[1]))
        self.write(f'breakpoint {bp.num} at {bp.address:#x}\n')
        self._publish_bps()

    def cmd_watch(self, args: List[str]) -> None:
        if len(args) < 2:
            raise ValueError('usage: watch ADDR [SIZE] [r|w|rw]')
        addr = self.value(args[1])
        size = int(args[2], 0) if len(args) > 2 else 4
        kind = {'r': READ, 'w': WRITE, 'rw': ACCESS}[args[3].lower()] if len(args) > 3 else ACCESS
        bp = self.target.add_watchpoint(addr, size, kind)
        self.write(f'watchpoint {bp.num}: {bp.describe()}\n')
        self._publish_bps()

    def cmd_delete(self, args: List[str]) -> None:
        if len(args) < 2:
            raise ValueError('usage: delete NUM')
        self.target.delete_breakpoint(int(args[1], 0))
        self._publish_bps()

    def cmd_enable(self, args: List[str]) -> None:
        self.target.enable_breakpoint(int(args[1], 0), True)
        self._publish_bps()

    def cmd_disable(self, args: List[str]) -> None:
        self.target.enable_breakpoint(int(args[1], 0), False)
        self._publish_bps()

    def cmd_breaklist(self, args: List[str]) -> None:
        if not self.target.breakpoints:
            self.write('no breakpoints\n')
            return
        for bp in self.target.breakpoints.values():
            state = 'enabled' if bp.enabled else 'disabled'
            self.write(f'{bp.num:>3}  {bp.kind:<11} {bp.describe():<24} {state}  hits={bp.hit_count}\n')

    # ---- memory and registers -------------------------------------------

    def cmd_examine(self, args: List[str]) -> None:
        spec = args[0][2:] if args[0].startswith('x/') else ''
        if len(args) < 2:
            raise ValueError('usage: x/NFU ADDR   (N count, F x|d|s, U b|h|w|g)')
        addr = self.value(args[1])
        count = ''
        fmt = 'x'
        unit = 'w'
        for ch in spec:
            if ch.isdigit():
                count += ch
            elif ch in 'xds':
                fmt = ch
            elif ch in _UNITS:
                unit = ch
        n = int(count) if count else 8
        if fmt == 's':
            data = self.target.read(addr, min(n if count else 256, 4096))
            end = data.find(b'\x00')
            text = data[:end if end >= 0 else len(data)]
            self.write(f'{addr:#x}: {text.decode("utf-8", "replace")!r}\n')
            return
        size = _UNITS[unit]
        data = self.target.read(addr, n * size)
        order = '<' if self.target.spec.endian == 'little' else '>'
        code = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[size]
        vals = struct.unpack(f'{order}{n}{code}', data)
        per_line = max(1, 16 // size)
        for i in range(0, n, per_line):
            chunk = vals[i:i + per_line]
            if fmt == 'x':
                cells = ' '.join(f'{v:0{size * 2}x}' for v in chunk)
            else:
                cells = ' '.join(f'{v}' for v in chunk)
            self.write(f'{addr + i * size:#x}: {cells}\n')

    def cmd_regs(self, args: List[str]) -> None:
        t = self.target
        if len(args) == 1:
            for line in self.ctx.registers():
                self.write(line + '\n')
            fl = self.ctx.flags()
            if fl:
                self.write(fl + '\n')
            return
        name = args[1]
        if len(args) == 2:
            self.write(f'{name} = {t.reg_read(name):#x}\n')
            return
        t.reg_write(name, self.value(args[2]))
        self.write(f'{name} = {t.reg_read(name):#x}\n')
        if commands.STATE.trace is not None:
            with commands.batched_tx('Write Register'):
                commands.putreg()
                commands.put_frames()

    def cmd_set(self, args: List[str]) -> None:
        if len(args) < 3:
            raise ValueError('usage: set ADDR HEXBYTES')
        addr = self.value(args[1])
        data = bytes.fromhex(args[2])
        self.target.write(addr, data)
        self.write(f'wrote {len(data)} bytes at {addr:#x}\n')
        if commands.STATE.trace is not None:
            with commands.batched_tx('Write Memory'):
                commands.putmem(addr, len(data), pages=False)

    def cmd_fields(self, args: List[str]) -> None:
        t = self.target
        if t.spec.status is None:
            self.write('this architecture has no status register in the table\n')
            return
        v = t.reg_read(t.spec.status)
        self.write(f'{t.spec.status} = {v:#x}\n')
        for f in t.spec.fields:
            bits = f'bit {f.bit}' if f.width == 1 else f'bits {f.bit + f.width - 1}:{f.bit}'
            self.write(f'  {t.spec.status}.{f.name:<6} {bits:<11} = {f.label(v)}\n')

    def cmd_context(self, args: List[str]) -> None:
        self.ctx.show()

    def cmd_help(self, args: List[str]) -> None:
        self.write(HELP)

    # ---- entry -----------------------------------------------------------

    def run(self, banner: Optional[str] = None) -> None:
        if banner is None:
            banner = ('ghidra-unicorn console. Type `help` for commands; anything else is Python. '
                      'Ctrl-D or `q` to leave.')
        self.target.listeners.append(self._on_stop)
        try:
            self.ctx.show()
            self.interact(banner=banner, exitmsg='')
        except SystemExit:
            pass
        finally:
            if self._on_stop in self.target.listeners:
                self.target.listeners.remove(self._on_stop)

    def _on_stop(self, ev) -> None:
        self.write('\n')
        self.ctx.show(ev)
