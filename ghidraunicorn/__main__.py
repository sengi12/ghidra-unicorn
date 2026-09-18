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
    p.add_argument('--regs', default=_env('OPT_REGS'),
                   help='initial register overrides, e.g. "cpsr=0x60000030,r0=1" (OPT_REGS)')
    p.add_argument('--preload', default=_env('OPT_PRELOAD', 'true'),
                   help='copy all mapped memory into the trace at launch (OPT_PRELOAD)')
    p.add_argument('--preload-cap', type=int, default=32 * 1024 * 1024,
                   help='byte cap for --preload')
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


def main(argv=None) -> int:
    logfile = os.getenv('GHIDRA_UNICORN_LOG')
    if logfile:
        f = open(logfile, 'a', buffering=1)
        sys.stdout = _Tee(sys.stdout, f)
        sys.stderr = _Tee(sys.stderr, f)
    args = build_parser().parse_args(argv)
    if not args.address and args.listen is None:
        raise SystemExit('No Ghidra address: set GHIDRA_TRACE_RMI_ADDR, pass --address, '
                         'or pass --listen to wait for Ghidra to connect')

    loaded = load(args)
    commands.STATE.loaded = loaded
    commands.STATE.image = args.image
    target = loaded.target
    print(f'Loaded {loaded.description}: {target.spec.key} ({target.spec.language}), '
          f'pc={target.pc():#x} sp={target.sp():#x}, '
          f'{len(target.regions())} regions, {len(loaded.modules)} modules', flush=True)

    if args.listen is not None:
        commands.listen(args.listen)
    else:
        commands.connect(args.address)
    commands.start_trace()
    hooks.install(target)
    with commands.batched_tx('Launch'):
        commands.snapshot('Launched')
        commands.put_all(preload=_bool(args.preload, True), preload_cap=args.preload_cap)
    commands.activate()
    print('Trace started. Ghidra is now driving the emulator.', flush=True)

    if args.no_repl or not sys.stdin.isatty():
        _wait_for_disconnect()
    else:
        from .console import UnicornConsole
        UnicornConsole(target, loaded).run()
    commands.disconnect()
    return 0


def _wait_for_disconnect() -> None:
    client = commands.STATE.require_client()
    while client.receiver.is_alive():
        client.receiver.join(0.5)
    print('Ghidra disconnected.')


if __name__ == '__main__':
    sys.exit(main())
