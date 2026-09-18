"""The interactive prompt in the launcher's terminal.

It is a Python console with a layer of short debugger commands on top, in
the style of gdb/gef: anything that is not a known command is Python, with
`target`, `uc` and `commands` in scope. Stops caused here are reported to
Ghidra exactly like stops caused by Ghidra's own buttons, because both go
through the target's stop listeners.
"""
import atexit
import code
import os
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
  rsi, back [N]          step N instructions backwards
  rni [N]                step N instructions backwards, over calls
  rc                     run backwards to the previous breakpoint hit
  goto N                 go to instruction N (0 is where the target started)
  icount                 instruction count and how far back the history goes
  b, break ADDR          breakpoint at ADDR (a symbol name works: `b main`)
  w, watch ADDR [SIZE] [r|w|rw]   watchpoint (default 4 bytes, rw)
  d, delete NUM          delete breakpoint NUM
  bl, breakpoints        list breakpoints
  en NUM / dis NUM       enable / disable breakpoint NUM
  x/NFU ADDR             examine memory, e.g. x/8xw 0x2000, x/16xb sp, x/s 0x3000
  r, regs [NAME [VALUE]] show registers, one register, or set one
                         flags and fields too: r ZF 1, r cpsr.T 1, r cpsr.M 0x13
  fields                 list the status register's bit fields
  cov on|off|save PATH   record basic blocks and write drcov for ghidra-aflcov
  prov on [BASE LEN]     watch the input buffer; `prov` reports what was read
  sym NAME|ADDR          look a symbol up in either direction
  sys [N]                the system call layer, and the last N calls
  stub [NAME ADDR]       list the stubbed functions, or stand in for one
  heap                   blocks the stubbed malloc has handed out
  m, set ADDR HEXBYTES   write bytes, e.g. m 0x3000 41424344
  ctx, context           print the context again
  k, kill                terminate the target
  q, quit                leave (Ghidra's target is disconnected)
  help, ?                this text

Line editing is readline: arrows for history, Tab to complete, Ctrl-A/E/U/K/W,
Ctrl-R to search. History is kept in ~/.ghidra_unicorn_history.
In Ghidra's terminal, copy and paste are Cmd+Shift+C / Cmd+Shift+V on macOS
(Ctrl+Shift elsewhere); plain Ctrl+C sends an interrupt, as in any xterm.
"""

_UNITS = {'b': 1, 'h': 2, 'w': 4, 'g': 8}

HISTORY_FILE = os.path.expanduser(
    os.getenv('GHIDRA_UNICORN_HISTORY') or '~/.ghidra_unicorn_history')

# Characters that end a word for completion. Unlike readline's default this
# keeps '/', '-' and '.' inside a word, so `x/8xw` and `cpsr.M` complete whole.
COMPLETER_DELIMS = ' \t\n`!@#$%^&*()=+[{]}\\|;:\'",<>?'


class _Completer:
    """Tab completion: our commands first, register names after `r`, else Python."""

    def __init__(self, console: 'UnicornConsole') -> None:
        self.console = console
        self.matches: List[str] = []

    def complete(self, text: str, state: int) -> Optional[str]:
        if state == 0:
            try:
                self.matches = self._matches(text)
            except Exception:
                self.matches = []
        return self.matches[state] if state < len(self.matches) else None

    def _matches(self, text: str) -> List[str]:
        import readline
        head = readline.get_line_buffer()[:readline.get_begidx()].split()
        if not head:
            names = sorted(set(self.console.commands) | {'x/8xw', 'q'})
            return [n + ' ' for n in names if n.startswith(text)]
        spec = self.console.target.spec
        if head[0] in ('r', 'regs'):
            names = [r.name for r in spec.regs] + [f.name for f in spec.flags]
            if spec.status:
                names += [f'{spec.status}.{f.name}' for f in spec.fields]
            low = text.lower()
            return [n + ' ' for n in sorted(names) if n.lower().startswith(low)]
        if head[0] in self.console.commands:
            return []
        return self._python(text)

    def _python(self, text: str) -> List[str]:
        import rlcompleter
        completer = rlcompleter.Completer(self.console.locals)
        out, i = [], 0
        while True:
            m = completer.complete(text, i)
            if m is None:
                return out
            out.append(m)
            i += 1


class UnicornConsole(code.InteractiveConsole):

    def __init__(self, target: UnicornTarget, loaded=None,
                 out: Optional[TextIO] = None, color: Optional[bool] = None,
                 symbols=None) -> None:
        self.target = target
        self.loaded = loaded
        self.symbols = symbols
        self.out = out or sys.stdout
        self.ctx = Context(target, self.out, color=color, symbols=symbols)
        self.coverage = None
        self.provenance = None
        local = {'target': target, 'uc': target.uc, 'commands': commands,
                 'loaded': loaded, 'ctx': self.ctx, 'symbols': symbols}
        super().__init__(locals=local)
        self.commands: Dict[str, Callable[[List[str]], None]] = {
            'c': self.cmd_continue, 'continue': self.cmd_continue,
            's': self.cmd_step, 'si': self.cmd_step, 'step': self.cmd_step,
            'n': self.cmd_next, 'ni': self.cmd_next, 'next': self.cmd_next,
            'adv': self.cmd_advance, 'advance': self.cmd_advance,
            'rsi': self.cmd_back, 'back': self.cmd_back,
            'rni': self.cmd_back_over,
            'rc': self.cmd_reverse_continue,
            'goto': self.cmd_goto, 'icount': self.cmd_icount,
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
            'cov': self.cmd_coverage, 'coverage': self.cmd_coverage,
            'prov': self.cmd_provenance, 'provenance': self.cmd_provenance,
            'sym': self.cmd_symbol, 'symbol': self.cmd_symbol,
            'sys': self.cmd_syscalls, 'syscalls': self.cmd_syscalls,
            'stub': self.cmd_stubs, 'stubs': self.cmd_stubs,
            'heap': self.cmd_heap,
        }
        self.quit = False
        self._readline = None

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
        if self.symbols is not None:
            addr = self.symbols.address_of(text)
            if addr is not None:
                return addr
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

    # ---- going backwards -------------------------------------------------

    def _reversible(self) -> UnicornTarget:
        """Unlike the forward commands this one accepts a terminated target:
        stepping back is how you get out of that state."""
        if self.target.running:
            raise TargetError('target is running (interrupt it from Ghidra first)')
        return self.target

    def cmd_back(self, args: List[str]) -> None:
        n = int(args[1], 0) if len(args) > 1 else 1
        self._reversible().step_back(n)

    def cmd_back_over(self, args: List[str]) -> None:
        n = int(args[1], 0) if len(args) > 1 else 1
        self._reversible().step_back_over(n)

    def cmd_reverse_continue(self, args: List[str]) -> None:
        self._reversible().resume_back()

    def cmd_goto(self, args: List[str]) -> None:
        if len(args) < 2:
            raise ValueError('usage: goto N   (instruction number)')
        self._reversible().goto_icount(int(args[1], 0))

    def cmd_icount(self, args: List[str]) -> None:
        self.write(self.target.timeline.describe() + '\n')

    def cmd_kill(self, args: List[str]) -> None:
        t = self.target
        if t.running:
            t.interrupt()
        if not t.terminated:
            t.terminated = True
            from .target import StopEvent
            hooks.on_stop(StopEvent('exit', t.pc(), 'Killed'))
            self.write('target killed\n')

    # ---- standing in for what is not there -------------------------------

    def cmd_syscalls(self, args: List[str]) -> None:
        layer = self.target.syscalls
        if layer is None:
            self.write('no system call layer: the target traps straight to a '
                       'fault (launch with --syscalls, or the architecture '
                       'has no table)\n')
            return
        self.write(layer.describe() + '\n')
        recent = layer.records[-(int(args[1], 0) if len(args) > 1 else 10):]
        for rec in recent:
            self.write(f'  {rec.icount:>10}  {rec.describe()}\n')
        if not recent:
            self.write('  nothing called yet\n')

    def cmd_stubs(self, args: List[str]) -> None:
        layer = self.target.stubs
        if layer is None:
            self.write('no stub layer (launch with --stubs)\n')
            return
        if len(args) >= 3:
            name, address = args[1], self.value(args[2])
            layer.bind(name, address)
            self.write(f'{name} stands in at {address:#x}\n')
            return
        if len(args) == 2:
            raise ValueError('usage: stub NAME ADDR')
        self.write(layer.describe() + '\n')
        for address, name in sorted(layer.bound.items()):
            self.write(f'  {address:#012x}  {name}  '
                       f'(called {layer.calls.get(name, 0)}x)\n')
        if not layer.bound:
            self.write('  nothing bound; `stub malloc 0x401000` binds one, and '
                       '--symbols binds them all at launch\n')

    def cmd_heap(self, args: List[str]) -> None:
        layer = self.target.stubs
        if layer is None:
            self.write('no stub layer, so no heap\n')
            return
        heap = layer.heap
        self.write(heap.describe() + '\n')
        for block in sorted(heap.blocks.values(), key=lambda b: b.address):
            self.write(f'  {block.address:#012x}  {block.size:>8} bytes  live\n')
        for block in sorted(heap.freed.values(), key=lambda b: b.address):
            self.write(f'  {block.address:#012x}  {block.size:>8} bytes  freed\n')

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

    def cmd_coverage(self, args: List[str]) -> None:
        """cov [on|off|save PATH|reset]"""
        from .coverage import SessionCoverage
        what = args[1] if len(args) > 1 else 'status'
        if what in ('on', 'start'):
            if self.coverage is None:
                modules = getattr(self.loaded, 'modules', ()) or ()
                self.coverage = SessionCoverage(self.target, modules)
            self.coverage.start()
            self.write('recording basic-block coverage\n')
        elif what in ('off', 'stop'):
            if self.coverage is not None:
                self.coverage.stop()
            self.write('stopped recording\n')
        elif what == 'reset':
            if self.coverage is not None:
                self.coverage.reset()
            self.write('coverage cleared\n')
        elif what == 'save':
            if self.coverage is None:
                raise ValueError('nothing recorded; `cov on` first')
            if len(args) < 3:
                raise ValueError('usage: cov save PATH')
            n = self.coverage.save(args[2])
            self.write(f'wrote {args[2]}: {n} blocks\n')
            for path, count in sorted(self.coverage.stats().items()):
                self.write(f'  {count:6} {path}\n')
        else:
            if self.coverage is None:
                self.write('not recording; `cov on` to start\n')
            else:
                state = 'recording' if self.coverage.recording else 'stopped'
                self.write(f'{state}, {self.coverage.block_count} blocks\n')

    def cmd_provenance(self, args: List[str]) -> None:
        """prov [on BASE LENGTH|off]: which input bytes the program reads."""
        from .provenance import InputProvenance
        what = args[1] if len(args) > 1 else 'show'
        if what in ('on', 'start'):
            if len(args) >= 4:
                base, length = self.value(args[2]), self.value(args[3])
            else:
                region = getattr(self.loaded, 'input_region', None)
                if not region:
                    raise ValueError('usage: prov on BASE LENGTH '
                                     '(the harness declares no INPUT_BASE)')
                base, length = region[0], region[1] or 0x1000
            self.provenance = InputProvenance(self.target, base, length)
            self.provenance.start()
            self.write(f'watching {length} bytes at {base:#x}\n')
        elif what in ('off', 'stop'):
            if self.provenance is not None:
                self.provenance.stop()
            self.write('stopped watching\n')
        else:
            if self.provenance is None:
                raise ValueError('not watching; `prov on` first')
            self.write(self.provenance.summary(pc=self.target.pc()) + '\n')

    def cmd_symbol(self, args: List[str]) -> None:
        """sym NAME_OR_ADDR: look a symbol up in either direction."""
        if self.symbols is None:
            raise ValueError('no symbols loaded; launch with --symbols FILE')
        if len(args) < 2:
            self.write(f'{len(self.symbols)} symbols loaded\n')
            return
        text = args[1]
        addr = self.symbols.address_of(text)
        if addr is not None:
            self.write(f'{text} = {addr:#x}\n')
            return
        where = self.symbols.describe(self.value(text))
        self.write(f'{self.value(text):#x} = {where or "(no symbol)"}\n')

    def cmd_context(self, args: List[str]) -> None:
        self.ctx.show()

    def cmd_help(self, args: List[str]) -> None:
        self.write(HELP)

    # ---- entry -----------------------------------------------------------

    def setup_readline(self) -> None:
        """Line editing, history and completion.

        Without this the console is whatever the pty's line discipline does,
        and Ghidra's terminal sends 0x08 for Backspace while a macOS pty
        erases on 0x7f - so Backspace would do nothing. readline reads in raw
        mode and does the editing itself, binding both erase characters.
        """
        try:
            import readline
        except ImportError:
            self.write('(no readline module: no line editing, history or completion)\n')
            return
        self._readline = readline
        if 'libedit' in (readline.__doc__ or ''):
            readline.parse_and_bind('bind ^I rl_complete')
            readline.parse_and_bind('bind ^H ed-delete-prev-char')
            readline.parse_and_bind('bind ^? ed-delete-prev-char')
        else:
            readline.parse_and_bind('tab: complete')
            readline.parse_and_bind(r'"\C-h": backward-delete-char')
            readline.parse_and_bind(r'"\C-?": backward-delete-char')
        readline.set_completer(_Completer(self).complete)
        readline.set_completer_delims(COMPLETER_DELIMS)
        readline.set_history_length(2000)
        try:
            readline.read_history_file(HISTORY_FILE)
        except OSError:
            pass
        atexit.register(self.save_history)

    def save_history(self) -> None:
        if self._readline is None:
            return
        try:
            self._readline.write_history_file(HISTORY_FILE)
        except OSError:
            pass

    def run(self, banner: Optional[str] = None) -> None:
        if banner is None:
            banner = ('ghidra-unicorn console. Type `help` for commands; anything else is Python. '
                      'Ctrl-D or `q` to leave.')
        self.setup_readline()
        self.target.listeners.append(self._on_stop)
        try:
            self.ctx.show()
            self.interact(banner=banner, exitmsg='')
        except SystemExit:
            pass
        finally:
            self.save_history()
            if self._on_stop in self.target.listeners:
                self.target.listeners.remove(self._on_stop)

    def _on_stop(self, ev) -> None:
        """A stop happened - possibly from Ghidra while we sit at the prompt."""
        self.write('\n')
        self.ctx.show(ev)
        if self.target.timeline.recording:
            # Where we are in time: the number `goto` and `rsi` count in.
            self.write(f'instruction {self.target.icount}'
                       f' (history from {self.target.earliest_icount})\n')
        if self._readline is not None:
            try:
                self.write(getattr(sys, 'ps1', '>>> ') + self._readline.get_line_buffer())
            except Exception:
                pass
