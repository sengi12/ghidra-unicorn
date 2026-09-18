"""Entry point used by the Ghidra launcher (and usable by hand).

Ghidra sets GHIDRA_TRACE_RMI_ADDR and the OPT_* variables declared in
debugger-launchers/local-unicorn.sh. Every option can also be given on the
command line, which is how the tests drive it.
"""
import argparse
import os
import sys
import threading
from typing import Optional

from . import commands, hooks, loaders


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    if v is None or v == '':
        return default
    return v


def _addr(v: Optional[str]) -> Optional[int]:
    if v is None or str(v).strip() == '':
        return None
    return int(str(v), 0)


def _bool(v: Optional[str], default: bool) -> bool:
    if v is None:
        return default
    return str(v).lower() in ('1', 'true', 'yes', 'on')


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='ghidraunicorn',
                                description='Unicorn back-end for the Ghidra Debugger (Trace RMI)')
    p.add_argument('--address', default=_env('GHIDRA_TRACE_RMI_ADDR'),
                   help='host:port of the Ghidra Trace RMI acceptor (GHIDRA_TRACE_RMI_ADDR)')
    p.add_argument('--listen', nargs='?', const='127.0.0.1:0', default=None,
                   metavar='[HOST:]PORT',
                   help='instead of connecting, wait for Ghidra to connect to us '
                        '(its Connections window -> Connect Outbound)')
    p.add_argument('--harness', default=_env('OPT_HARNESS'),
                   help='Python harness defining create(input_file) -> Uc (OPT_HARNESS)')
    p.add_argument('--context', default=_env('OPT_CONTEXT_DIR'),
                   help='afl-unicorn context directory (OPT_CONTEXT_DIR)')
    p.add_argument('--input', default=_env('OPT_INPUT'),
                   help='input file handed to the harness (OPT_INPUT)')
    p.add_argument('--image', default=_env('OPT_TARGET_IMG'),
                   help='program image path, used to name the module (OPT_TARGET_IMG)')
    p.add_argument('--start', default=_env('OPT_START'), help='start address (OPT_START)')
    p.add_argument('--end', default=_env('OPT_END'), help='stop address (OPT_END)')
    p.add_argument('--symbols', default=_env('OPT_SYMBOLS'),
                   help='JSON symbol table from tools/export_symbols.py, so '
                        'addresses get names and `b main` works (OPT_SYMBOLS)')
    p.add_argument('--symbols-at', default=_env('OPT_SYMBOLS_AT'),
                   help='rebase the symbols so their image base lands here '
                        '(OPT_SYMBOLS_AT)')
    p.add_argument('--regs', default=_env('OPT_REGS'),
                   help='initial register overrides, e.g. "cpsr=0x60000030,r0=1" (OPT_REGS)')
    p.add_argument('--syscalls', default=_env('OPT_SYSCALLS', 'true'),
                   help='service the program\'s system calls with a small '
                        'Linux layer instead of faulting on the trap '
                        '(OPT_SYSCALLS)')
    p.add_argument('--stubs', default=_env('OPT_STUBS', 'true'),
                   help='stand in for malloc, free and the common string and '
                        'memory functions, at the addresses --symbols gives '
                        'them (OPT_STUBS)')
    p.add_argument('--stdin', default=_env('OPT_STDIN'),
                   help='file whose contents the program reads from its '
                        'standard input (OPT_STDIN)')
    p.add_argument('--trace-calls', action='store_true',
                   default=_bool(_env('OPT_TRACE_CALLS'), False),
                   help='print every system call and stub as it happens '
                        '(OPT_TRACE_CALLS)')
    p.add_argument('--preload', default=_env('OPT_PRELOAD', 'true'),
                   help='copy all mapped memory into the trace at launch (OPT_PRELOAD)')
    p.add_argument('--preload-cap', type=int, default=32 * 1024 * 1024,
                   help='byte cap for --preload. The regions that matter go '
                        'first, so a huge dump still arrives with its code '
                        'and stack resident and the rest read on demand')
    p.add_argument('--commands', default=_env('OPT_COMMANDS'),
                   help='console commands to run once the target is loaded, '
                        'separated by ";" or newlines, e.g. '
                        '"b 0x100040; c; x/8xw 0x300000" (OPT_COMMANDS)')
    p.add_argument('--commands-file', default=_env('OPT_COMMANDS_FILE'),
                   help='file of console commands, one per line '
                        '(OPT_COMMANDS_FILE)')
    p.add_argument('--record', default=_env('OPT_RECORD'),
                   help='log this session to a file: the commands as '
                        'themselves and everything else as comments, so the '
                        'file both reads as a transcript and replays with '
                        '--commands-file (OPT_RECORD)')
    p.add_argument('--batch', action='store_true',
                   default=_bool(_env('OPT_BATCH'), False),
                   help='run the commands and exit, with no prompt and no '
                        'Ghidra needed; the exit status is the number of '
                        'commands that failed (OPT_BATCH)')
    p.add_argument('--no-repl', action='store_true',
                   help='do not open the interactive prompt; wait for Ghidra to disconnect')
    return p


def parse_regs(text: Optional[str]) -> dict:
    """'cpsr=0x60000030, r0=1' -> {'cpsr': 0x60000030, 'r0': 1}"""
    out = {}
    if not text:
        return out
    for item in text.replace(';', ',').split(','):
        item = item.strip()
        if not item:
            continue
        if '=' not in item:
            raise SystemExit(f'bad register override {item!r}; expected NAME=VALUE')
        name, value = item.split('=', 1)
        out[name.strip()] = int(value.strip(), 0)
    return out


def load(args) -> loaders.Loaded:
    start, end = _addr(args.start), _addr(args.end)
    if args.harness:
        loaded = loaders.load_harness(args.harness, args.input, start, end, args.image)
    elif args.context:
        loaded = loaders.load_context(args.context, start, end, args.image)
    else:
        raise SystemExit('Nothing to run: give --harness or --context '
                         '(OPT_HARNESS / OPT_CONTEXT_DIR in the Ghidra launcher).')
    for name, value in parse_regs(args.regs).items():
        loaded.target.reg_write(name, value)
    return loaded


class _Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)
            s.flush()

    def flush(self):
        for s in self.streams:
            s.flush()

    def isatty(self):
        return self.streams[0].isatty()

    def fileno(self):
        # input() only uses readline when stdout has a real fd.
        return self.streams[0].fileno()


def script_text(args) -> str:
    """The commands to run, from --commands and --commands-file together."""
    parts = []
    if args.commands_file:
        try:
            with open(args.commands_file) as f:
                parts.append(f.read())
        except OSError as e:
            raise SystemExit(f'could not read {args.commands_file}: {e}')
    if args.commands:
        parts.append(args.commands)
    return '\n'.join(parts)


def main(argv=None) -> int:
    logfile = os.getenv('GHIDRA_UNICORN_LOG')
    if logfile:
        f = open(logfile, 'a', buffering=1)
        sys.stdout = _Tee(sys.stdout, f)
        sys.stderr = _Tee(sys.stderr, f)
    args = build_parser().parse_args(argv)
    script = script_text(args)
    attached = bool(args.address) or args.listen is not None
    # A batch run needs no Ghidra at all: the console, the emulator and
    # everything the commands can reach work perfectly well without a trace,
    # which is what makes this usable from CI.
    if not attached and not (args.batch or script):
        raise SystemExit('No Ghidra address: set GHIDRA_TRACE_RMI_ADDR, pass --address, '
                         'pass --listen to wait for Ghidra to connect, or pass '
                         '--batch with --commands to run without Ghidra')

    loaded = load(args)
    commands.STATE.loaded = loaded
    commands.STATE.image = args.image
    target = loaded.target
    print(f'Loaded {loaded.description}: {target.spec.key} ({target.spec.language}), '
          f'pc={target.pc():#x} sp={target.sp():#x}, '
          f'{len(target.regions())} regions, {len(loaded.modules)} modules', flush=True)

    symbols = _symbols(args)
    _install_layers(args, loaded, symbols)

    if attached:
        if args.listen is not None:
            commands.listen(args.listen)
        else:
            commands.connect(args.address)
        commands.start_trace()
        hooks.install(target)
        with commands.batched_tx('Launch'):
            commands.snapshot('Launched')
            preloaded = commands.put_all(preload=_bool(args.preload, True),
                                         preload_cap=args.preload_cap)
        if preloaded is not None:
            print(preloaded.describe(), flush=True)
        commands.activate()
        print('Trace started. Ghidra is now driving the emulator.', flush=True)

    from .console import UnicornConsole
    console = UnicornConsole(target, loaded, symbols=symbols)
    if args.record:
        console.start_recording(args.record,
                                argv=[sys.argv[0]] + list(argv or sys.argv[1:]))
    failed = 0
    if script:
        failed = console.run_script(script)
        if failed:
            print(f'{failed} command(s) failed', flush=True)

    if args.batch:
        pass                      # the commands were the whole run
    elif args.no_repl or not sys.stdin.isatty():
        if attached:
            _wait_for_disconnect()
    else:
        console.run()
    console.stop_recording()
    if attached:
        commands.disconnect()
    return 1 if failed else 0


def _program_output(stream: int, data: bytes) -> None:
    """What the emulated program printed. Its standard error is marked so it
    is not mistaken for the connector's own."""
    text = data.decode('utf-8', 'replace')
    sys.stdout.write(text if stream == 1 else f'[stderr] {text}')
    sys.stdout.flush()


def _install_layers(args, loaded, symbols):
    """Put a system call layer and function stubs under the target."""
    stdin = b''
    if args.stdin:
        try:
            with open(args.stdin, 'rb') as f:
                stdin = f.read()
        except OSError as e:
            print(f'could not read {args.stdin}: {e}', flush=True)
    installed = loaders.install_layers(
        loaded, syscalls=_bool(args.syscalls, True), stubs=_bool(args.stubs, True),
        symbols=symbols, stdin=stdin, on_output=_program_output,
        trace=args.trace_calls)
    sys_layer = installed.get('syscalls')
    if sys_layer is not None:
        print(f'System calls: a small Linux for {loaded.target.spec.key}'
              + (f', {len(stdin)} bytes on standard input' if stdin else ''), flush=True)
    elif _bool(args.syscalls, True):
        print(f'System calls: none for {loaded.target.spec.key}; a trap will '
              f'stop the target', flush=True)
    stub_layer = installed.get('stubs')
    if stub_layer is not None and stub_layer.bound:
        print(f'Stubs: {", ".join(sorted(set(stub_layer.bound.values())))}', flush=True)
    return installed


def _symbols(args):
    """Load the symbol table, rebased if asked."""
    if not args.symbols:
        return None
    from .symbols import SymbolTable
    try:
        table = SymbolTable.load(args.symbols)
    except (OSError, ValueError) as e:
        print(f'could not read symbols from {args.symbols}: {e}', flush=True)
        return None
    at = _addr(args.symbols_at)
    if at is not None:
        table = table.rebase(at)
    print(f'{len(table)} symbols from {os.path.basename(args.symbols)}'
          + (f', rebased to {at:#x}' if at is not None else ''), flush=True)
    return table


def _wait_for_disconnect() -> None:
    client = commands.STATE.require_client()
    while client.receiver.is_alive():
        client.receiver.join(0.5)
    print('Ghidra disconnected.')


if __name__ == '__main__':
    sys.exit(main())
