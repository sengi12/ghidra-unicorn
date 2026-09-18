# Working on ghidra-unicorn

Unicorn Engine as a back-end for Ghidra's Debugger, over Trace RMI. Read
[README.md](README.md) for what it does, [TODO.md](TODO.md) for what is
planned and what is known broken, and [CHANGELOG.md](CHANGELOG.md) for what
has shipped. This file is the part that is not obvious from the code.

## Where things are

This machine is set up already; none of it needs installing again.

| What | Where |
|---|---|
| This checkout (the durable one) | `/Volumes/Linux Share/ghidra-unicorn` |
| Remote | `sengi12/ghidra-unicorn`, private, branch `main`, tag `v0.1.0` |
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

# Triage the sample's real crashes (four files, three distinct bugs)
$PY -m ghidraunicorn.triage --harness examples/afl_unicorn_simple.py \
    --inputs "$AFL_UNICORN_DIR/unicorn_mode/samples/simple/output/default/crashes" \
    --verbose
```

`tools/setup_project.py` rebuilds the Ghidra project, and
`tools/export_symbols.py` writes the symbol JSON the `--symbols` option
takes.

## Design rules, worth keeping

- **`target.py` knows nothing about Ghidra**, and `commands.py` / `methods.py`
  know nothing about Unicorn beyond the target's API. That is what lets each
  half be tested without the other, and it is why `triage.py` works with no
  Ghidra installed at all. Do not reach across.
- **`arch.py` is a table.** Adding a processor is data, not code. Every
  language id, compiler spec and register name must be checked against the
  processor definitions in the installed Ghidra
  (`Ghidra/Processors/*/data/languages/*.ldefs` and the `define register`
  lines in the `.sinc` files). Do not write them from memory; several look
  obvious and are wrong.
- **Flags are Ghidra's own one-byte registers** carved out of a status
  register, so they appear as editable rows in the Registers window. Every
  other bit of that register is a `Field`, reachable as `cpsr.M`. A `Flag` may
  be wider than one bit.
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

## Ghidra behaviour that cost time to learn

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

[TODO.md](TODO.md) is ordered. The next item is syscall and function stubs,
which is the biggest practical limit: anything that leaves the binary has to
be stubbed today, which is why harnesses stay artificial. After that, a
context panel inside Ghidra, then the three known reverse-execution bugs.
