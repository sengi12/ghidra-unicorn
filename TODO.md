# Roadmap

What is planned for ghidra-unicorn, roughly in the order it is worth doing.
Shipped work moves to [CHANGELOG.md](CHANGELOG.md).

Status: `[ ]` not started, `[~]` in progress, `[x]` done and in the changelog.

## In flight

- [~] **Reverse execution (time travel).** Checkpoint the CPU context every N
  instructions plus the pages dirtied since the last checkpoint; step back by
  restoring the nearest checkpoint and replaying forward. Wire
  `resume_back`, `step_back_into` and `step_back_over` so Ghidra's existing
  step-back toolbar buttons work, and add `rsi`/`rni`/`rc`/`goto` to the
  console. Only an emulator can offer this without something like rr.
- [~] **More processors, and a Windows launcher.** RISC-V, PowerPC, m68k and
  SPARC are table entries in `arch.py`. Ghidra supports `.bat` and PowerShell
  launchers; we ship only the Unix one.

## Next

- [~] **Symbols from Ghidra.** `symbols.py` and `tools/export_symbols.py`
  are in, and the context annotates disassembly and pointers with
  `<main+0x40>`. Still to wire: a `--symbols` option and resolving a name
  where the console takes an address, so `b main` works.
- [ ] **Syscall and function stubs.** Dispatch `syscall` / `svc` / `sc` to
  Python handlers, with a small Linux layer for read, write, mmap, brk and
  exit. Add symbol-driven stubs for malloc, free and the common string and
  memory functions; afl-unicorn's loader already carries a simple heap to
  lift. This is the biggest practical limit today: anything that leaves the
  binary has to be stubbed.
- [~] **Coverage handoff to ghidra-aflcov.** The recorder and drcov writer
  are in `coverage.py`, proved byte-identical to afl-unicorn's writer, which
  is what aflcov, Lighthouse and Dragondance read. Still to wire: a console
  command and a launcher option to start recording and save on exit.
- [~] **Input provenance.** `provenance.py` records reads of the input
  buffer and answers which offsets a given instruction consumed and which
  bytes were never read, and the triage report shows it per input. Still to
  wire: a console command.
- [ ] **Conditional breakpoints, hit and ignore counts.** Ghidra's breakpoint
  model already carries Condition and Ignore Count; populate them and
  evaluate a Python predicate in the hook.

## Later

- [ ] **A context panel inside Ghidra.** A docking `ComponentProvider` in a
  Ghidra script, in the style of ghidra-hexEditor and ghidra-aflcov, showing
  the gef-style register, pointer-chain and stack view in a window instead of
  the terminal. It needs nothing new on the Python side: everything it would
  draw is already in the trace.
- [ ] **Differential execution against Ghidra's p-code emulator.** Run the
  same program under both engines and compare registers each step. A
  disagreement is a bug in a SLEIGH specification or in Unicorn, which makes
  this a useful test as well as a research tool.
- [ ] **Thumb tracking.** Follow `cpsr.T` per instruction and keep Ghidra's
  `TMode` context register in step, so mixed ARM and Thumb code disassembles
  correctly rather than being pinned to the language chosen at launch.
- [ ] **Batch and headless mode.** `--commands "b 0x100040; c; x/8xw 0x300000"`
  for runs with no GUI, so a session can be scripted and used in CI.
- [ ] **Console extras.** `disas`, memory search, a hexdump with an ASCII
  pane, `x/i`, and register watchpoints.
- [ ] **Session recording.** Log every command and stop to a file so a triage
  session can be replayed or attached to a bug report.
- [ ] **Lazy memory for large dumps.** Preloading is capped at 32 MiB today
  and the rest is read on demand; make the cap region-aware so the regions
  that matter are resident and huge dumps stay usable.

## Known bugs

- [ ] **A stop forced from outside is reported as termination.** When a hook
  that the target does not own calls `emu_stop` and the harness declared an
  end address, `_emulate` takes its "reached the end" branch and returns
  `exit`, even though the end was never reached. Triage works around it by
  tracking its own instruction counter. The honest answer is `stopped`
  whenever the program counter is not actually at the end or the requested
  address.
- [ ] **A fault's address is not on the stop event.** `UcError` carries only
  an error number, so anything wanting the faulting access has to install its
  own invalid-memory hook, as triage does. The target could record it once
  and put it on the event.

## Known limitations

These are consequences of the design rather than missing work, but they are
worth stating.

- One thread and one frame. Unicorn has no threads, and Ghidra unwinds the
  stack itself from the registers and memory the connector publishes.
- Step-over needs Capstone to recognise a call; without it, it steps into.
- No operating system. A harness has to map its own memory and either avoid
  syscalls or stub them, until the stubs item above lands.
