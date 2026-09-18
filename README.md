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
- **Reverse execution.** Ghidra's step-back and reverse-continue buttons
  work, because the connector checkpoints the processor state every few
  thousand instructions along with the pages written since the last
  checkpoint, and steps backwards by restoring the nearest checkpoint and
  replaying forward in silence. With gdb this needs rr; with an emulator it
  falls out of the design. `goto` jumps to any instruction number in the
  recorded history. Reverse-continue finds watchpoint hits as well as
  breakpoints, hit counts rewind along with the machine, and a reverse
  step-over costs the distance it travels rather than the whole history.
- **An operating system underneath**, so a harness no longer has to avoid
  every call that leaves the binary. System calls are serviced by a small
  Linux layer (`read`, `write`, `open`, `mmap`, `brk`, `exit` and friends)
  with the right numbers and argument registers for each architecture, and
  `malloc`, `free` and the common `str*`/`mem*` functions are stood in for at
  the addresses your symbols give them. Both are on by default, both rewind
  correctly when you step backwards, and `open` can see only the files the
  harness handed over - never the debugging machine's own.
- **Breakpoints and watchpoints** from Ghidra's Breakpoints window or the
  Listing: execute, read, write and access. A breakpoint stops *before* its
  instruction; a watchpoint stops *after* the accessing instruction completes,
  with PC on the next one, so resuming never re-runs an instruction.
- **Conditions and ignore counts** on any breakpoint or watchpoint. The
  condition is a Python expression with the registers in scope -
  `cond 3 rdi == 0 and u32(rsp + 8) > 0x1000` - and a watchpoint condition
  also sees the `address`, `size`, `value` and `access` that fired it.
  `ignore 3 100` passes it a hundred more times first. Both show in Ghidra's
  Breakpoints window and can be set from there.
- **State**: every stop is a new snapshot in the Time window. Registers,
  the memory map (with permissions), a module for the image so Ghidra maps
  the trace onto your static listing, and, by default, all mapped memory
  copied into the trace at launch (capped at 32 MiB) so the Listing is
  populated immediately. The cap is spent on the regions that matter first -
  the code you are stopped in, the stack, the input - and a region too big
  for what is left gets a window around the interesting part rather than
  being skipped, so a multi-gigabyte dump still comes up usable. Everything
  else is read on demand.
- **Thumb tracking**: ARM code that switches instruction set with `blx` or
  `bx` is followed as it runs, so each stop tells Ghidra which set it is in
  and mixed code disassembles correctly instead of being pinned to the
  language chosen at launch.
- **Architectures**: x86-64, x86, AArch64, ARM and Thumb, MIPS32 and MIPS64,
  RISC-V 32 and 64, PowerPC 32 and 64, m68k, SPARC 32 and 64, and TriCore,
  in both endiannesses wherever Unicorn supports the pair. Twenty in all, and
  adding one is a table entry in `arch.py`.
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
  scope. `disas` and `x/5i` disassemble, `hd` is a hexdump with an ASCII
  pane, `find` searches memory for text, bytes or a value, and `rwatch RAX`
  stops the moment a register changes.

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
   `debugger-launchers` directory of this checkout. The same directory works
   on Windows, where Ghidra picks up the `.ps1` and `.bat` launchers instead
   of the `.sh`. Those two are written to Ghidra's own conventions but have
   not been run on Windows.

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
  `fields`, `cov`, `prov`, `sym`, `m ADDR HEXBYTES`, `ctx`, `k`, `q`, and
  going backwards with
  `rsi N`, `rni N`, `rc`, `goto N` and `icount`. Addresses accept registers and
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

## Scripted and headless runs

`--commands` runs console commands as soon as the target is loaded, and
`--batch` then exits instead of prompting. With `--batch` there is no Ghidra
in the picture at all:

```
python -m ghidraunicorn --harness examples/syscalls_and_stubs.py --batch \
    --commands 'b 0x400020; c; r rax; assert target.reg_read("RAX") == 16'
```

It is the same console the prompt uses, so anything you can type you can
script. Anything that is not a command is Python, which means `assert` is
the assertion language and needs nothing new: the exit status is non-zero if
any command failed, whether that was a bad command, an exception, a syntax
error, or a script that ended part way through an unclosed bracket. That is
enough to put a harness in CI and have it fail the build when the crash
stops reproducing.

`--commands-file` reads the same thing from a file. Commands split on
newlines and semicolons, quotes are respected, and `#` starts a comment.

## A context panel in Ghidra

`ghidra_scripts/UnicornContextPanel.py` puts the same view the console
prints into a docking window beside the Listing: registers with pointers
dereferenced, the decoded status register, disassembly and the stack. Add
this repository's `ghidra_scripts` directory in the Script Manager and run
it. It draws from the trace, so it follows the Time window: scrub back and
the panel shows that point in history.

Not yet run against a real Ghidra - see [CHANGELOG.md](CHANGELOG.md).

## Checking one emulator against the other

Unicorn and Ghidra's p-code emulator implement the same instruction sets
from entirely separate descriptions of them, so where they disagree about
what an instruction did, one of them is wrong:

```
GHIDRA_INSTALL_DIR=... python tools/differential.py \
    --harness examples/afl_unicorn_simple.py \
    --program simple_target.bin --language MIPS:BE:32:default \
    --base 0x100000 --steps 500
```

Both engines are put in the same state, stepped together, and compared after
every instruction; the first disagreement is reported with the instruction
and the registers that differ. It needs no mapping between the two, because
the register names in `arch.py` are already Ghidra's.

The p-code half has not yet been run against a real Ghidra - see
[CHANGELOG.md](CHANGELOG.md).

## Recording a session

`--record session.gu`, or `record session.gu` in the console, logs
everything to a file:

```
# ghidra-unicorn session, 2026-09-18T21:55:59Z
# architecture: x64 (x86:LE:64:default)
# launched as: python -m ghidraunicorn --harness h.py --record session.gu
b 0x40000c
#  | breakpoint 1 at 0x40000c
c
# stop: breakpoint - Breakpoint 1 at 0x40000c at instruction 3
#  | ... the whole context at the stop ...
```

The commands are plain lines and everything else is a comment, so the same
file reads as a transcript and replays as a script:

```
python -m ghidraunicorn --harness h.py --batch --commands-file session.gu
```

Which makes it worth attaching to a bug report: whoever reads it can see
what you did and run it.

## Triaging a fuzzing run

Stepping one crash is useful; a fuzzer hands you a directory of them. Replay
the whole directory and see what is actually distinct:

```
python -m ghidraunicorn.triage \
    --harness examples/afl_unicorn_simple.py \
    --inputs .../output/default/crashes \
    --json crashes.json
```

```
4 inputs through afl_unicorn_simple.py: 4 crash
3 distinct signatures (3 crashing)

COUNT  OUTCOME  KIND                  PC        INSTRUCTION     FAULT ADDR  REPRESENTATIVE
2      crash    UC_ERR_READ_UNMAPPED  0x1000dc  lbu $v0, ($v0)  0x0         id:000002,sig:06,...
1      crash    UC_ERR_READ_UNMAPPED  0x10002c  lbu $v0, ($v0)  0x0         id:000001,sig:06,...
1      crash    UC_ERR_READ_UNMAPPED  0x10008c  lbu $v0, ($v0)  0x0         id:000000,sig:06,...
```

Those three addresses are the three null reads in the sample's source, so the
four files are three bugs. Each input runs in a fresh target, bounded by an
instruction budget and a wall clock so a looping input is reported as a
timeout rather than hanging. Crashes are grouped by a signature, by default
the fault kind and the faulting address, and each group keeps its smallest
input as the representative. The command exits non-zero when anything
crashed, so it can gate CI, and it needs no Ghidra at all.

With `--verbose`, and a harness that declares `INPUT_BASE` as the example one
does, each result also reports the input offsets that run actually read, which
is the short answer to which bytes matter:

```
  insn:  0x1000dc  90420000         lbu $v0, ($v0)
  input read: 0, 9-10
```

Add `--coverage-dir DIR` and each replayed input leaves a drcov file there,
ready to load in ghidra-aflcov and paint over the same listing.

To put the result back in front of you in Ghidra:

```
python tools/import_triage.py --json crashes.json \
    --project ~/ghidra_projects/unicorn --program simple_target.bin
```

That writes a bookmark and a comment at each crash address, so the listing
shows where crashes land and how many inputs reach each one. It is idempotent,
takes `--dry-run`, and takes `--offset` when the emulated addresses sit at a
different image base than the program.

## Naming addresses

Ghidra knows the function names; Unicorn only knows addresses. Export them
once and the context prints `0x100040 <main+0x40>` instead of a bare number:

```
python tools/export_symbols.py ~/ghidra_projects/unicorn/unicorn.gpr \
    simple_target.bin symbols.json
```

An enclosing function wins over a nearer generated label, which is how gdb and
IDA report an address.

## When the program calls out of the binary

A harness is a piece of a process with nothing behind it, so historically
anything that trapped into a kernel or called into libc stopped the run. Two
layers fix that, and both are on by default.

**System calls.** The trap - `syscall`, `int 0x80`, `svc`, `sc`, `ecall`,
`trap #0`, whichever this architecture uses - is serviced instead of
faulting. `read`, `write`, `writev`, `open`, `openat`, `close`, `lseek`,
`mmap`, `munmap`, `brk`, `getpid`, `exit` and `exit_group` are there, with
the call numbers and argument registers of x86, x86-64, ARM, ARM64, MIPS
(o32 and n64), RISC-V, PowerPC and m68k. Failures come back the way each
architecture reports them, including MIPS's separate flag register and
PowerPC's CR0 bit. Anything not in the table returns ENOSYS and shows up in
`sys`, rather than failing silently.

`--stdin FILE` is what the program reads from descriptor 0. There is no host
filesystem: `open` sees only files the harness declared in a module-level
`FILES` dict, so pointing this at a crashing input cannot reach your own
files.

**Function stubs.** Point `--symbols` at an exported symbol table and every
implementation it can place is bound: `malloc`, `calloc`, `realloc`, `free`,
`memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcpy`, `strncpy`,
`strcat`, `strcmp`, `strncmp`, `strchr`, `strrchr`, `strstr`, `strdup`,
`puts`, `putchar`, `exit`, `abort`. `malloc` allocates from an arena mapped
on demand. A stub replaces the whole call, so stepping over a stubbed
function is one step - but a breakpoint on it still stops before it stands
in.

In the console, `sys` shows the calls made, `stub` what is bound (and
`stub NAME ADDR` binds one by hand), and `heap` the blocks handed out.
A harness opts out with `SYSCALLS = False` or `STUBS = False`, or supplies
its own `STDIN` and `FILES`.

Both layers are correct under reverse execution, which is the interesting
part: a system call is not a pure function of the machine state, and a stub
skips the function's instructions entirely, so simply re-running them during
a replay would consume the input twice, print twice, or walk into code the
first pass never executed. Instead each call runs once and records what it
did, and a replay applies the record. Step back over a `read` and the input
is un-read, the heap block is un-allocated, and running forward again gives
exactly the same bytes at exactly the same address.

`examples/syscalls_and_stubs.py` is a complete worked example: a program
with no libc and no kernel that reads, allocates, measures, prints and
exits.

## Coverage and input provenance

`ghidraunicorn.coverage` records the basic blocks a run executed and writes
drcov, the format [ghidra-aflcov](https://github.com/sengi12/ghidra-aflcov),
Lighthouse and Dragondance read; the files are byte-identical to the ones
afl-unicorn's own writer produces, and a test keeps them that way.
`ghidraunicorn.provenance` watches reads of the input buffer and records which
offsets were read and by which instruction, so a crash points back at the
bytes that reached it and you can see which parts of the input were never
looked at.

Both are console commands:

```
cov on                 # start recording basic blocks
c                      # ... run ...
cov save run.drcov     # write it for ghidra-aflcov
prov on                # watch the input buffer the harness declared
prov                   # which offsets were read, and which never were
```

Point the launcher's *Symbols* field at the exported JSON and the console
takes names where it takes addresses:

```
b main
sym 0x100040           ->  main+0x40
```

If the harness loads the code somewhere other than the image base the symbols
were exported at, *Symbols base* rebases them.

## How it is built

```
ghidraunicorn/
  arch.py       Unicorn arch/mode <-> Ghidra language ID, register tables
  target.py     UnicornTarget: run/step/interrupt, breakpoints, watchpoints
  timeline.py   checkpoints and page deltas, for going backwards
  loaders.py    harness files and afl-unicorn context directories
  schema.xml    the object model Ghidra's Debugger windows expect
  commands.py   writes target state into the trace (objects, regs, memory)
  methods.py    the remote methods Ghidra invokes (resume, step, break_*, ...)
  hooks.py      stop/continue events -> snapshots
  context.py    the gef-style context printout
  console.py    the terminal commands on top of a Python console
  __main__.py   entry point: connect, load, publish, then console
  triage.py     replay a directory of fuzzing inputs and group the crashes
  symbols.py    names for addresses, exported from a Ghidra program
  coverage.py   basic-block recording, written as drcov
  provenance.py which input bytes were read, and by which instruction
debugger-launchers/    the launchers Ghidra shows in its menu:
  local-unicorn.sh       macOS and Linux
  local-unicorn.ps1      Windows, PowerShell
  local-unicorn.bat      Windows, cmd, via local-unicorn-win.py
examples/      harnesses
tests/         pytest, no Ghidra needed (169 tests, incl. a real-pty test)
tools/e2e_ghidra.py     drives a real Ghidra through the whole flow
tools/setup_project.py  makes a project with the sample imported
tools/export_symbols.py exports a program's symbols as JSON
tools/import_triage.py  paints a triage report onto a program
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
what has shipped. Everything on the roadmap is now written, and there are no
known bugs outstanding. Two items - the context panel and the p-code side of
the differential runner - were written without a Ghidra installation to try
them against, and are marked as such until someone runs them once.

## Limitations and ideas

- One thread, one frame. Ghidra unwinds the stack itself from registers and
  memory when it has a mapped program with function information.
- Step-over needs Capstone to recognise calls; without it, it steps into.
- The operating system under the emulator is a small one: the calls a
  harness usually needs, and ENOSYS for the rest, which `sys` shows rather
  than hiding. There is deliberately no host filesystem behind `open`.
- A stubbed function is one step, not a step into: the stub stands in for
  the whole call. A breakpoint on it still stops before it.
- Going backwards is bounded by what is kept: checkpoints are dropped oldest
  first once they exceed the memory budget, and the connector says how far
  back it can still reach rather than guessing.
- A register watchpoint is a comparison made once per instruction, because
  Unicorn has no hook for one, and it is not published to Ghidra: the
  trace's breakpoint kinds are all about addresses.
- SPARC and TriCore have calling conventions but no system call table, and
  Unicorn 2.1.4 cannot map memory for TriCore at all.

## License

Apache-2.0. Copyright 2026 Michael Sengelmann.
