# Working on ghidra-unicorn

Unicorn Engine as a back-end for Ghidra's Debugger, over Trace RMI. Read
[README.md](README.md) for what it does, [TODO.md](TODO.md) for what is
planned and what is known broken, and [CHANGELOG.md](CHANGELOG.md) for what
has shipped. This file is the part that is not obvious from the code.

## Where things are

This is one developer's machine, already set up; none of it needs installing
again. If you are reading this anywhere else, the paths below are not yours -
[README.md](README.md) has the install that is. What is worth reading here is
everything after this table.

| What | Where |
|---|---|
| This checkout (the durable one) | `/Volumes/Linux Share/ghidra-unicorn` |
| Remote | `sengi12/ghidra-unicorn`, branch `main`, tag `v0.1.0` |
| Ghidra 12.1.3 | `~/Applications/ghidra_12.1.3_PUBLIC` |
| JDK 21, which Ghidra needs | `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home` |
| Python with every dependency | `~/.pyenv/versions/ghidra/bin/python` |
| afl-unicorn, the sample target and real crashes | `/Volumes/Linux Share/afl-unicorn` |
| A Ghidra project with the sample imported | `~/ghidra_projects/unicorn/unicorn.gpr` |

The pyenv environment `ghidra` (3.11.9) has unicorn 2.1.4, capstone,
protobuf, ghidratrace 12.1, pyghidra and pytest. `ghidratrace` also ships
inside Ghidra at `Ghidra/Debug/Debugger-rmi-trace/pypkg/src`, which is what
the launcher puts on `PYTHONPATH`.

## Commands

```bash
PY=~/.pyenv/versions/ghidra/bin/python
export AFL_UNICORN_DIR="/Volumes/Linux Share/afl-unicorn"

# Unit tests: no Ghidra, ~2 seconds, 169 of them. Run these constantly.
$PY -m pytest -q tests

# End to end against a real Ghidra, in process via PyGhidra. Needs a desktop
# session, takes about a minute, and is the only thing that proves the
# protocol still works. Run it after touching target.py, commands.py,
# methods.py, schema.xml or the launcher.
GHIDRA_INSTALL_DIR=~/Applications/ghidra_12.1.3_PUBLIC \
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
$PY tools/e2e_ghidra.py

# A scripted run with no Ghidra at all. The exit status is what CI reads.
$PY -m ghidraunicorn --harness examples/syscalls_and_stubs.py --batch \
    --commands 'c; sys; assert target.terminated'

# Triage the sample's real crashes (four files, three distinct bugs)
$PY -m ghidraunicorn.triage --harness examples/afl_unicorn_simple.py \
    --inputs "$AFL_UNICORN_DIR/unicorn_mode/samples/simple/output/default/crashes" \
    --verbose
```

`tools/setup_project.py` rebuilds the Ghidra project, and
`tools/export_symbols.py` writes the symbol JSON the `--symbols` option
takes. `tools/differential.py` runs a harness under both Unicorn and
Ghidra's p-code emulator and reports the first instruction they disagree
about; it needs a Ghidra installation.

`.github/workflows/tests.yml` runs the unit tests on 3.9 and 3.12 and then
drives the connector headlessly on the example harness - run, record,
replay, reverse, and a deliberate failure that must fail the build. Nothing
Ghidra-shaped is in CI; that is what `e2e_ghidra.py` is for, by hand.

## Design rules, worth keeping

- **`target.py` knows nothing about Ghidra**, and `commands.py` / `methods.py`
  know nothing about Unicorn beyond the target's API. That is what lets each
  half be tested without the other, and it is why `triage.py` works with no
  Ghidra installed at all. Do not reach across.
- **`arch.py` and `abi.py` are tables.** Adding a processor is data, not code. Every
  language id, compiler spec and register name must be checked against the
  processor definitions in the installed Ghidra
  (`Ghidra/Processors/*/data/languages/*.ldefs` and the `define register`
  lines in the `.sinc` files). Do not write them from memory; several look
  obvious and are wrong.
- **Call depth going backwards is relative, not absolute.** A reverse
  step-over does not need to know how deep the stack is, only how the depth
  changes as it walks back: a call is one frame shallower, a return is one
  frame deeper. That is what lets it stop at a checkpoint window instead of
  replaying everything retained. Do not reintroduce an absolute depth.
- **Flags are Ghidra's own one-byte registers** carved out of a status
  register, so they appear as editable rows in the Registers window. Every
  other bit of that register is a `Field`, reachable as `cpsr.M`. A `Flag` may
  be wider than one bit.
- **Anything that stands in for code that is not there must be replay-safe.**
  `syscalls.py` and `stubs.py` both change the machine in ways re-running the
  instructions will not reproduce - and a stub skips instructions entirely, so
  a replay where it did not fire diverges for good. Both therefore record what
  they did and a replay applies the record; `effects.py` holds that logic once
  so there are not two subtly different copies of it. A new layer of the same
  kind uses `EffectLog` and does not invent its own.
- **Nothing is done until a test covers it**, and a test that cannot fail is
  not a test. When something passes suspiciously easily, print the real
  sequence of events and look at it. The delay-slot bug below was hiding
  behind a green assertion.

## Unicorn behaviour that cost time to learn

Each of these has a regression test; do not undo them.

- **Never hand `end` to `emu_start` as its stop address when stepping.** With
  a delay slot, Unicorn leaves the program counter on the *branch*, so the
  step re-executes it and re-applies its side effects, forever. A step is
  bounded by its instruction count instead.
- **`emu_start`'s count returns before the next instruction's hook fires**, so
  arriving at an exit address is only visible after the fact, in `_emulate`.
- **An `emu_stop` from someone else's hook is not termination.** Only a
  program counter within `ARRIVAL_SLACK` of the target counts as arriving.
- **A `UcError` carries only an error number.** The faulting address comes
  from a `UC_HOOK_MEM_INVALID` hook, and rides on the `StopEvent`.
- **Stopping inside a memory hook** leaves the program counter on the
  accessing instruction with its effects applied, so a watchpoint records the
  hit and the next code hook performs the stop.
- **`emu_start`'s count overruns after a `context_restore`**, and x86 flags
  are recomputed lazily from a stale word, so the timeline re-syncs the status
  register after every restore.
- **`emu_start` decodes ARM or Thumb from the low bit of the address it is
  given, not from the T flag.** Resuming a Thumb program counter without
  that bit reads the instruction as ARM, at the wrong width. Creating the
  engine with `UC_MODE_THUMB` does not set the T flag either, so the target
  sets it at construction; and writing the program counter on ARM *is* a
  `bx`, where the low bit picks the instruction set and is stripped before
  it reaches the register. The T flag is the single source of truth for
  which instruction set the machine is in; `target.thumb` reads it and the
  decoder, `_start_pc` and `TMode` all follow it. Do not reintroduce
  anything keyed on the launch spec.
- **Writing the program counter inside a `UC_HOOK_CODE` hook redirects
  execution**, on every architecture here, including across a MIPS delay slot
  and for a stack-based return on m68k. That is what makes a function stub a
  hook rather than a patched binary. There is no need to `emu_stop` and
  restart.
- **The trap instruction leaves the program counter past itself everywhere
  except m68k**, where the interrupt hook is entered with it still on the
  `trap` - so returning without moving it traps forever. x86-64's `syscall`
  arrives through `UC_HOOK_INSN`, not the interrupt hook, with the program
  counter still on the instruction; Unicorn moves it afterwards itself.
  `int 0x80` on x86-64 is the 32-bit compatibility entry with its own
  numbering and is deliberately not wired up.
- **Hooks fire in the order they were added**, so the target's own code hook
  always runs first and `target.halting` tells anything else hooked to the
  same address whether that instruction is actually about to run. Without
  it a breakpoint on a stubbed function would stop *after* the stub had
  already returned from it.
- **The extra keyword to `hook_add` is `aux1`, not `arg1`**, which is how the
  instruction is named for `UC_HOOK_INSN`. Getting it wrong raises nothing;
  the hook is simply never called.
- **Unicorn hands out zeroed pages on `mem_map`**, so `mmap` and a growing
  `brk` do not need to write zeros over them, and recording those writes
  would cost real memory for nothing.
- **TriCore cannot map memory at all** in Unicorn 2.1.4: `mem_map` returns
  `UC_ERR_ARG` at every address tried. It is in the tables and covered by the
  static tests, and nothing can be emulated on it.
- **`hlt` is a no-op on x86-64 under Unicorn**; it advances the instruction
  pointer and carries on, so it is no good as a "this must never execute"
  marker in a test.

## Ghidra behaviour that cost time to learn

- **The breakpoint attributes Ghidra understands are `Condition` and
  `Ignore Count`**, spelled exactly like that, alongside `Hit Count`,
  `Commands`, `Pending`, `Silent` and `Temporary`. They are not guessable;
  they came from Ghidra's own gdb connector, whose schema is at
  `Ghidra/Debug/Debugger-agent-gdb/src/main/py/src/ghidragdb/schema.xml`
  inside the installation. Check that file before inventing an attribute
  name.
- **Trace RMI refuses messages over 64 KiB**, so memory goes in 32 KiB chunks.
- **Launcher parameters are keyed `env:OPT_NAME`**, not `OPT_NAME`, and
  `#@image-opt` must name the prefixed form too.
- **The launcher search path option is the string `Script Paths`** under the
  Debugger tool's options. The constant is protected, so it is spelled out.
- **Ghidra's terminal sends `0x08` for Backspace** while a macOS pty erases on
  `0x7f`, which is why the console drives readline itself. Copy and paste are
  Cmd+Shift+C and Cmd+Shift+V there, deliberately, so Ctrl+C stays an
  interrupt.
- **A raw binary gives auto-analysis no entry point**, so the listing comes up
  empty and a symbol export finds nothing. `setup_project.py` disassembles at
  the base and declares `main` first.
- **JPype cannot extend Java classes**, only implement interfaces with
  `@JImplements`; it refuses with "Java classes cannot be extended in
  Python". So no PyGhidra script can subclass `ComponentProvider`,
  `GhidraScript` or any other Ghidra class, and anything that needs to be a
  subclass has to be written in Java. `tests/test_ghidra_scripts.py` refuses
  a script that tries. What *does* work is instantiating Java objects and
  casting a Python callable to a functional interface with `Interface @ fn`.
- **Every accessor on a `TraceMemoryRegion` takes the snapshot**:
  `getRange(snap)`, `isRead(snap)`, `isWrite(snap)`, `isExecute(snap)`. A
  trace holds the whole history at once, so a region's range and permissions
  are things it had at a time, not properties of the object.
- **`EmulatorHelper.readMemory` answers failure with null**, not an
  exception, and a partial read by filling what it got and logging the rest
  without saying how much. **`step` throws `CancelledException`** as well as
  returning false with `getLastError()`.
- **`Language.getRegisters()` lists every sub-register** - EAX, AX, AH and AL
  as well as RAX - so anything iterating it wants `isBaseRegister()` unless
  it means to see all of them.
- **Driving Ghidra from PyGhidra** needs `Runnable @ fn` casts for
  `Swing.runNow`, the Eclipse and VS Code plugins excluded from the Debugger
  tool template, and `Msg.setErrorDisplay(ConsoleErrorDisplay())` so errors do
  not open modal dialogs nobody can click. `tools/e2e_ghidra.py` does all
  three; copy from it rather than rediscovering.

## Conventions

- Keep [TODO.md](TODO.md) and [CHANGELOG.md](CHANGELOG.md) current in the same
  commit as the change. Shipped items leave TODO and appear in the changelog
  under Unreleased.
- Commit messages say what changed and why, in prose. End them with the
  `Co-Authored-By:` line your session is told to use.
- Prefer verifying against the real thing: the installed Ghidra, the real
  afl-unicorn sample, a real pty. Several tests do exactly that and skip
  cleanly when the fixture is missing.

## Where to start

[TODO.md](TODO.md) is ordered and there are no known bugs left.

Two things in it were written without a Ghidra to try them against, because
the session that wrote them had none, and both are marked `[~]` rather than
done: the p-code half of `differential.py` with `tools/differential.py`, and
the context panel. Their untested halves are kept apart from the tested ones
- the comparison machinery in `differential.py` is covered by running
Unicorn against Unicorn, and the panel's renderer by rendering the same
state through both a target and a plain object - so what is left unchecked
is only the Ghidra API calls.

Those calls have since been read against Ghidra's own source and a real
JPype, which found four mistakes including one that made the panel
unrunnable, but read is not run. **Run each once on a machine with Ghidra
12.1.3 and then mark them done.** `tools/e2e_ghidra.py` wants a run too:
this branch changed `schema.xml`, `putreg` and `put_breakpoints`, and that
script is the only thing that proves the protocol still works.

`examples/syscalls_and_stubs.py` is the shortest way to see the system call
and stub layers working: it reads, allocates, measures, prints and exits with
neither a libc nor a kernel underneath it.
