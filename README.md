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
- **Flags as registers**: cpsr, nzcv and eflags are decomposed into the
  one-byte flag registers Ghidra defines (NG/ZR/CY/OV, CF/ZF/SF/OF, ...), so
  each shows as its own editable row in the Registers window and editing one
  recomposes the status register. Every other bit field (ARM mode, I/F/A
  masks, T, E, IOPL...) is reachable by name from the console.
- **A gef-style console** in the launcher's terminal: on every stop it
  prints the reason, registers with changed values highlighted and pointers
  dereferenced, the decoded status register, disassembly around PC and the
  stack; and it takes short commands (`c`, `si`, `ni`, `b`, `watch`, `x/8xw`,
  `r cpsr.M 0x13`...). Anything else is Python with `target` and `uc` in
  scope.

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

## Try it (five minutes)

This walks the afl-unicorn `samples/simple` target, a raw MIPS32 big-endian
blob, through the Debugger.

1. Get the binary into a project. Either let a script do it:

   ```
   GHIDRA_INSTALL_DIR=... AFL_UNICORN_DIR=... python tools/setup_project.py
   ```

   which creates `~/ghidra_projects/unicorn/unicorn.gpr` with
   `simple_target.bin` imported as MIPS:BE:32 at base `0x100000` and
   analyzed (needs pyghidra: `pip install --no-index -f
   $GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist pyghidra`). Or by
   hand: **File → Import File**, pick
   `afl-unicorn/unicorn_mode/samples/simple/simple_target.bin`, choose
   *Raw Binary* with language **MIPS:BE:32:default**, and under *Options*
   set the base address to `0x100000` (the harness loads the code there).
2. Open the project in Ghidra (**File → Open Project**), then open the
   program in the **Debugger** tool: drag `simple_target.bin` onto the
   Debugger icon in the Tool Chest at the bottom of the project window. One
   time only: in the Debugger, **Edit → Tool Options → Debugger → Script
   Paths**, add this checkout's `debugger-launchers` directory.
3. Launch: click the dropdown next to the debug button and pick **unicorn**.
   In the dialog:
   - *Harness*: `examples/afl_unicorn_simple.py` from this repository
   - *Input*: `samples/simple/sample_inputs/sample1.bin`
   - *python command*: leave `python3`; the launcher picks a `.venv` in this
     checkout or a pyenv virtualenv named `ghidra` if one exists, otherwise
     name a Python that has unicorn and protobuf. Leave *Image* as filled.
   Press Launch. A terminal opens with the context printout, and the
   Dynamic Listing lands on `0x100000`.
4. Look around: the **Registers** window lists every MIPS register; the
   **Memory** window shows three regions (code, stack, input); the
   **Modules** window shows `simple_target.bin` at `0x100000` and the
   listing shows the static analysis mapped onto the trace.
5. Set a breakpoint: in the Dynamic Listing go to `0x100040` (`lbu $v0,
   ($v0)`, the first read of the input), right-click → *Toggle Breakpoint*.
   Press **Resume** (F5). The target stops there; the **Time** window has a
   new snapshot, the terminal prints the new context with `v0` pointing at
   `0x300000 -> 'abcd'`.
6. Step with F8 / F10, edit `v0` in the Registers window, watch the input
   with a write watchpoint on `0x300000` from the Breakpoints window, or
   type in the terminal: `x/4xw 0x300000`, `r a0 0x1234`, `si 3`, `c`.
7. Press **Resume** again with no breakpoints: the target reaches the end of
   `main` and the process shows as *Terminated*. The emulator stays alive for
   inspection until you close the terminal or the target.

Replace the input with one from `output/crashes/` after a fuzzing run and
step 5 is your crash triage.

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

### Presetting registers

The launcher's *Registers* field takes `NAME=VALUE` pairs, so a harness can
stay generic while you pick the CPU state per run:

```
cpsr=0x600001d3          # ARM: N=0 Z=1 C=1 V=0, SVC mode, I/F masked
cpsr.M=0x10, cpsr.T=1    # or by field: user mode, Thumb
ZF=1, rflags.IOPL=3      # x86: Ghidra flag names or fields
```

Flag and field names are the same ones the console's `fields` command lists.

### While it runs

- The Debugger's Resume, Interrupt, Step Into, Step Over buttons and the
  Breakpoints window work as with gdb. *Advance* (Step Ext → Advance) runs to
  an address.
- Reaching `END`, an `EXITS` address, or the address given as *End* in the
  launcher marks the target **terminated**. A Unicorn fault (unmapped access,
  invalid instruction...) stops with the error text in the process's
  *Reason* attribute and leaves PC on the faulting instruction so you can
  inspect it.
- The launcher's terminal is the console. On each stop, whether you pressed a
  Ghidra button or typed a command, it prints:

  ```
  ● Breakpoint 1 at 0x100040
  ───────────────────────────────────────────────────────[ registers ]
  v0      0x00300000 -> 0x61626364 'abcd'
  ...
  sp      0x0020ffe8 -> 0x00000000
  pc      0x00100040 -> 0x90420000
  ─────────────────────────────────────────────────────[ disassembly ]
     0x10003c  8fc20008         lw       $v0, 8($fp)
   → 0x100040  90420000         lbu      $v0, ($v0)
     0x100044  2c420011         sltiu    $v0, $v0, 0x11
  ───────────────────────────────────────────────────────────[ stack ]
  0x20ffe8│+0x000: 0x00000000
  0x20fff0│+0x008: 0x00300000 -> 0x61626364 'abcd'
  ```

  Changed registers are red, pointers into code/stack/data are coloured by
  kind, the status register line shows every field by name
  (`cpsr 0x600001d3 [ n Z C v q ... I F t M=SVC ]`). `help` lists the
  commands: `c`, `si N`, `ni N`, `adv ADDR`, `b ADDR`, `watch ADDR SIZE w`,
  `d N`, `bl`, `x/8xw ADDR`, `x/s ADDR`, `r NAME VALUE`, `r cpsr.M 0x13`,
  `fields`, `m ADDR HEXBYTES`, `ctx`, `k`, `q`. Addresses accept registers and
  `reg+off`. Everything else is Python with `target`, `uc`, `commands`.
  Set `NO_COLOR=1` to turn colour off.

### Working in Ghidra's terminal

Ghidra's terminal is a real VT100 emulator, but two things about it surprise
people:

- **Copy and paste are Cmd+Shift+C / Cmd+Shift+V** on macOS (Ctrl+Shift+C /
  Ctrl+Shift+V elsewhere). That is deliberate on Ghidra's part: plain Ctrl+C
  has to stay free to send an interrupt, as in any xterm. Also useful:
  Cmd+F find, Cmd+A select all, Cmd+= and Cmd+- for font size, and
  right-click for the same actions in a menu.
- **Backspace** used to do nothing here. Ghidra's terminal sends `0x08` for
  the Backspace key, but a macOS pty erases on `0x7f`, so the line
  discipline ignored it. The console now uses readline and does its own
  editing, binding both: Backspace, arrow keys, history across sessions
  (`~/.ghidra_unicorn_history`), Tab completion for commands and register
  names, Ctrl-A/E/U/K/W and Ctrl-R all work. `tests/test_pty.py` drives a
  real pty to keep it that way.

### Running the console in your own terminal

If you would rather have iTerm or Terminal.app, with its own scrollback,
mouse and clipboard, run the connector yourself and connect the two. Either
direction works; both need `ghidratrace` importable (`pip install
ghidratrace`, or put `$GHIDRA_INSTALL_DIR/Ghidra/Debug/Debugger-rmi-trace/pypkg/src`
on `PYTHONPATH`).

**Ghidra listens, you connect.** In Ghidra: **Window → Connections**, then
the *Connect by Accept* button in that window's toolbar. It shows the address
it is waiting on. Then, in your terminal:

```
python -m ghidraunicorn --address 127.0.0.1:12345 \
    --harness examples/afl_unicorn_simple.py \
    --input .../sample_inputs/sample1.bin \
    --image .../simple_target.bin
```

**You listen, Ghidra connects.** In your terminal:

```
python -m ghidraunicorn --listen 127.0.0.1:12345 --harness ... --input ...
```

then in Ghidra's **Connections** window use *Connect Outbound* and give it
`127.0.0.1:12345`. With no argument, `--listen` picks a free port and prints
it.

Either way the trace, breakpoints and stepping behave exactly as when Ghidra
launches the connector; the difference is only which terminal you type in.

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
  context.py    the gef-style context printout
  console.py    the terminal commands on top of a Python console
  __main__.py   entry point: connect, load, publish, then console
debugger-launchers/local-unicorn.sh   the launcher Ghidra shows in its menu
examples/      harnesses
tests/         pytest, no Ghidra needed (61 tests, incl. a real-pty test)
tools/e2e_ghidra.py   drives a real Ghidra through the whole flow
tools/setup_project.py  makes a project with the sample imported
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

## Where the pretty output lives

Ghidra's Debugger already has the windows a gef/pwndbg context is made of,
and this connector feeds all of them: **Registers** (with the flag bits as
rows), **Dynamic Listing** (disassembly that follows PC, with breakpoint
markers), **Memory** and **Bytes** views, **Stack**, **Watches** (typed
expressions like `*:4 sp+8`), **Breakpoints**, **Time** (every stop is a
snapshot you can step back to), and **Model** (the raw object tree). The
terminal context is for when the terminal is what you are looking at.

A single "context" panel inside Ghidra, with pointer chains and stack
annotations like the terminal one, would be a small Ghidra script with a
docking `ComponentProvider` (the pattern ghidra-hexEditor and ghidra-aflcov
use) that reads the current trace's registers and memory through
`DebuggerTraceManagerService` and repaints on snapshot change. It needs no
change on this side: everything it would show is already in the trace.

## What is planned

[TODO.md](TODO.md) is the roadmap and [CHANGELOG.md](CHANGELOG.md) records
what has shipped. The short version of what is coming: reverse execution, so
Ghidra's step-back buttons work; batch crash triage over an afl-unicorn
crashes directory; more processors and a Windows launcher; symbols and
syscall stubs; and a coverage handoff to ghidra-aflcov.

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
