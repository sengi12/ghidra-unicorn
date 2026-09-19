"""Run a harness under Unicorn and under Ghidra's p-code emulator, and
compare them instruction by instruction.

Where the two disagree about what an instruction did, one of them is wrong,
which makes this a way to find bugs in a SLEIGH processor specification or
in Unicorn - and a check on this connector's own register tables, since a
name mapped to the wrong register never matches.

    GHIDRA_INSTALL_DIR=... python tools/differential.py \\
        --harness examples/afl_unicorn_simple.py \\
        --program /path/to/simple_target.bin \\
        --language MIPS:BE:32:default --base 0x100000 --steps 500

The comparison itself lives in `ghidraunicorn/differential.py` and is tested
without Ghidra by running Unicorn against Unicorn. This script is the part
that needs a real installation: headless PyGhidra, an imported program, and
`EmulatorHelper`. Run it on a machine that has one.

Registers that differ for reasons that are not bugs can be dropped with
`--ignore`. The usual candidate is the status register: Unicorn keeps x86's
flags lazily and recomputes them on demand, so a flag nobody has read yet
may legitimately hold something else. Compare the flags Ghidra defines
individually instead, or start with `--ignore rflags,eflags`.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='Compare Unicorn against Ghidra\'s p-code emulator')
    p.add_argument('--harness', required=True,
                   help='Python harness defining create(input_file) -> Uc')
    p.add_argument('--input', help='input file handed to the harness')
    p.add_argument('--program', required=True,
                   help='the same binary, for Ghidra to import')
    p.add_argument('--language', required=True,
                   help='Ghidra language id, e.g. MIPS:BE:32:default')
    p.add_argument('--base', default='0',
                   help='base address the program is loaded at (hex)')
    p.add_argument('--steps', type=int, default=1000,
                   help='how many instructions to compare')
    p.add_argument('--ignore', default='',
                   help='comma-separated registers to leave out of the '
                        'comparison, e.g. rflags')
    p.add_argument('--registers', default='',
                   help='comma-separated registers to compare, instead of '
                        'every one both engines have')
    p.add_argument('--watch', default='',
                   help='memory to compare as well, as ADDR:LEN[,ADDR:LEN]')
    p.add_argument('--stop-at', help='stop when the program counter reaches this')
    p.add_argument('--progress', action='store_true',
                   help='print the program counter as it goes')
    return p


def _addr(text):
    return int(text, 0) if text else None


def _watches(text):
    out = []
    for item in text.split(','):
        item = item.strip()
        if not item:
            continue
        address, _, length = item.partition(':')
        out.append((int(address, 0), int(length or '8', 0)))
    return out


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not os.getenv('GHIDRA_INSTALL_DIR'):
        raise SystemExit('set GHIDRA_INSTALL_DIR to a Ghidra installation')

    import pyghidra
    pyghidra.start()

    from ghidraunicorn import differential, loaders

    loaded = loaders.load_harness(args.harness, args.input)
    print(f'unicorn: {loaded.description}, {loaded.target.spec.key}, '
          f'pc={loaded.target.pc():#x}', flush=True)

    with pyghidra.open_program(args.program, language=args.language,
                               loader='ghidra.app.util.opinion.BinaryLoader',
                               loader_args={'-loader-baseAddr': args.base},
                               analyze=False) as api:
        program = api.getCurrentProgram()
        print(f'p-code: {program.getName()} as '
              f'{program.getLanguage().getLanguageID()}', flush=True)
        result = differential.compare_with_pcode(
            loaded, program, steps=args.steps,
            ignore=[n.strip() for n in args.ignore.split(',') if n.strip()],
            registers=([n.strip() for n in args.registers.split(',') if n.strip()]
                       or None),
            watch=_watches(args.watch),
            stop_at=_addr(args.stop_at),
            on_step=((lambda step, pc: print(f'  {step:>6} {pc:#x}', flush=True))
                     if args.progress else None))

    print(result.describe(), flush=True)
    return 0 if result.agreed else 1


if __name__ == '__main__':
    sys.exit(main())
