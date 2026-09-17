# ghidra-unicorn

[Unicorn Engine](https://www.unicorn-engine.org/) as a back-end for Ghidra's
Debugger. Step, set breakpoints and watchpoints, edit registers and memory,
and read the crash state of an [afl-unicorn](https://github.com/sengi12/afl-unicorn)
fuzzing run, all from the Debugger windows you already use for gdb.

It talks to Ghidra over **Trace RMI**, the same protocol Ghidra's own gdb,
lldb, dbgeng and drgn connectors use, so it needs no Ghidra plugin: one
launcher script and a small Python package.

```
Ghidra Debugger  <-- Trace RMI (TCP) -->  ghidraunicorn  <-->  unicorn.Uc
   Listing, Registers, Memory,             commands/methods     your harness or
   Breakpoints, Threads, Time               hooks/target         afl-unicorn dump
```

## What you get

- **Two ways to load a target**
  - a *harness*: a Python file with `create(input_file) -> unicorn.Uc`, the
    set-up half of an afl-unicorn fuzzing harness;
  - an *afl-unicorn context directory* from `unicorn_dumper_gdb.py`,
    `unicorn_dumper_lldb.py`, `unicorn_dumper_ida.py` or
    `unicorn_dumper_pwndbg.py` (`_index.json` plus segments), loaded natively.
- **Execution control**: resume, interrupt, step into, step over (runs
  through calls when Capstone is installed), advance to address, kill.
- **Breakpoints and watchpoints** from Ghidra's Breakpoints window or the
  Listing: execute, read, write and access. A breakpoint stops *before* its
  instruction; a watchpoint stops *after* the accessing instruction completes,
  with PC on the next one, so resuming never re-runs an instruction.
- **State**: every stop is a new snapshot in the Time window. Registers,
  the memory map (with permissions), a module for the image so Ghidra maps
  the trace onto your static listing, and, by default, all mapped memory
  copied into the trace at launch (capped at 32 MiB) so the Listing is
  populated immediately. Everything else is read on demand.
- **Architectures**: x86-64, x86, AArch64 (LE/BE), ARM (LE/BE, ARM and
  Thumb), MIPS32 and MIPS64 (LE/BE). Adding one is a table in `arch.py`.
- **A Python prompt** in the launcher's terminal with `target` and `uc` in
  scope, and an `execute` remote method, for anything the buttons don't cover.

Tested with Ghidra 12.1.3 (JDK 21) and Unicorn 2.1.

## Install

1. A Python 3.9+ with Unicorn and protobuf (Capstone is optional but gives
   you step-over):

   ```
   pip install unicorn protobuf capstone
   ```

   The Trace RMI client library, `ghidratrace`, ships inside Ghidra; the
   launcher puts it on `PYTHONPATH` for you. Outside Ghidra, `pip install
   ghidratrace` (match your Ghidra's major.minor).

2. Clone this repository anywhere.

3. In Ghidra's Debugger tool: **Edit → Tool Options → Debugger → Paths to
   search for user-created debugger launchers**, add the
   `debugger-launchers` directory of this checkout.

That is all. Open a program, switch to the Debugger tool, and **unicorn**
appears in the Launch dropdown (the menu next to the debug button).

## Use

### From a harness

Write a harness. It is the set-up part of an afl-unicorn harness with the
`emu_start` left out:

```python
# my_harness.py
from unicorn import *
from unicorn.mips_const import *

START = 0x100000
END   = 0x1000f4            # stop here and mark the target terminated
MODULES = [("/path/to/simple_target.bin", 0x100000, 0x10000)]   # optional

def create(input_file=None):
    uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN)
    uc.mem_map(0x100000, 0x10000)
    uc.mem_write(0x100000, open("simple_target.bin", "rb").read())
    uc.mem_map(0x200000, 0x10000)
    uc.reg_write(UC_MIPS_REG_SP, 0x210000)
    uc.mem_map(0x300000, 0x10000)
    if input_file:
        uc.mem_write(0x300000, open(input_file, "rb").read())
    uc.reg_write(UC_MIPS_REG_PC, START)
    return uc
```

`create` may also return `(uc, start, end)`. `EXITS` (a list of addresses)
adds more stopping points that count as the program ending.

Then: Launch → **unicorn**, set *Harness* to the file, *Input* to the input
you want to replay (the crashing one from `output/crashes/`, say), and go.
*Image* is filled in with the program you have open; it names the module so
Ghidra can map it. If your harness loads the code at a different address than
the static program's image base, use the Modules window's *Map Modules* to
line them up, or set the program's image base to match.

`examples/afl_unicorn_simple.py` is this harness for afl-unicorn's
`samples/simple` target and is what the end-to-end test runs.

### From an afl-unicorn context dump

Dump a process with one of afl-unicorn's `unicorn_dumper_*.py` scripts, then
set *afl-unicorn context* to the output directory and leave *Harness* empty.
The registers, memory map and contents come from the dump; the dumped
segments' object-file names become modules, so a program you imported from
the same binary maps automatically.

### While it runs

- The Debugger's Resume, Interrupt, Step Into, Step Over buttons and the
  Breakpoints window work as with gdb. *Advance* (Step Ext → Advance) runs to
  an address.
- Reaching `END`, an `EXITS` address, or the address given as *End* in the
  launcher marks the target **terminated**. A Unicorn fault (unmapped access,
  invalid instruction...) stops with the error text in the process's
  *Reason* attribute and leaves PC on the faulting instruction so you can
  inspect it.
- The launcher's terminal is a Python prompt: `target.regs()`,
  `target.step()`, `uc.mem_read(...)`, `target.add_watchpoint(addr, 4, "WRITE")`.

Pair it with [ghidra-aflcov](https://github.com/sengi12/ghidra-aflcov) to
paint the fuzzer's coverage over the same listing you are stepping through.

## How it is built

```
ghidraunicorn/
  arch.py       Unicorn arch/mode <-> Ghidra language ID, register tables
  target.py     UnicornTarget: run/step/interrupt, breakpoints, watchpoints
  loaders.py    harness files and afl-unicorn context directories
  schema.xml    the object model Ghidra's Debugger windows expect
  commands.py   writes target state into the trace (objects, regs, memory)
  methods.py    the remote methods Ghidra invokes (resume, step, break_*, ...)
  hooks.py      stop/continue events -> snapshots
  __main__.py   entry point: connect, load, publish, then REPL
debugger-launchers/local-unicorn.sh   the launcher Ghidra shows in its menu
examples/      harnesses
tests/         pytest, no Ghidra needed (49 tests)
tools/e2e_ghidra.py   drives a real Ghidra through the whole flow
```

`target.py` knows nothing about Ghidra and `commands.py`/`methods.py` know
nothing about Unicorn beyond the target interface, so either half can be
tested alone. The structure follows Ghidra's own `Debugger-agent-drgn` and
`Debugger-agent-gdb` connectors.

Two Unicorn behaviours shape the design:

- A `UC_HOOK_CODE` callback runs before its instruction. Calling `emu_stop`
  there stops *before* the instruction, which is exactly what a breakpoint
  wants. The first instruction of every run is exempt so resuming from a
  breakpoint moves past it.
- A memory hook runs in the middle of its instruction. Calling `emu_stop`
  there leaves PC on that instruction with its effects already applied, so a
  resume would execute it twice. Watchpoints therefore only *note* the hit and
  the next code hook performs the stop.

`resume` returns immediately and runs the emulator on its own thread, since
Ghidra delivers method calls on a single worker and `interrupt` has to get
through while the target runs.

## Testing

```
pip install -e '.[test]'
pytest                              # unit tests, no Ghidra
GHIDRA_INSTALL_DIR=... JAVA_HOME=... AFL_UNICORN_DIR=... \
    python tools/e2e_ghidra.py      # needs a desktop; launches Ghidra in-process
```

The end-to-end test creates a project, imports `simple_target.bin`, creates a
Debugger tool, launches the *unicorn* offer through the real launcher script
and checks the trace Ghidra built: registers, preloaded bytes, module, then
step, step-over, breakpoint, resume, register write, and run-to-end.

## Limitations and ideas

- One thread, one frame. Ghidra unwinds the stack itself from registers and
  memory when it has a mapped program with function information.
- Step-over needs Capstone to recognise calls; without it, it steps into.
- Thumb harnesses get the `ARM:LE:32:v8T` language. Mixed ARM/Thumb code
  would need context-register tracking.
- Ideas: a `unicorn_dumper_ghidra.py` that dumps a *Ghidra* trace (from gdb)
  into an afl-unicorn context; time-travel by re-running from snapshot 0 with
  an instruction count; syscall stubs as Python hooks editable from Ghidra.

## License

Apache-2.0. Copyright 2026 Michael Sengelmann.
