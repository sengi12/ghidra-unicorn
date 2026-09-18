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
- [~] **Batch crash triage.** Replay a directory of afl-unicorn crashes,
  capture the faulting instruction, registers and stack for each, group them
  by crash site, and emit a table plus JSON. A companion tool turns that JSON
  into Ghidra bookmarks and comments so the listing shows where crashes land.
- [~] **More processors, and a Windows launcher.** RISC-V, PowerPC, m68k and
  SPARC are table entries in `arch.py`. Ghidra supports `.bat` and PowerShell
  launchers; we ship only the Unix one.

## Next

- [ ] **Symbols from Ghidra.** Export the open program's symbols so `b main`
  works by name, the context and stack annotate addresses with function
  names, and stubs can be attached by symbol rather than by address.
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
- [ ] **Input provenance.** Tag the input buffer with a read hook and report
  which input offsets reach the faulting instruction, answering "which bytes
  do I have to change".
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

## Known limitations

These are consequences of the design rather than missing work, but they are
worth stating.

- One thread and one frame. Unicorn has no threads, and Ghidra unwinds the
  stack itself from the registers and memory the connector publishes.
- Step-over needs Capstone to recognise a call; without it, it steps into.
- No operating system. A harness has to map its own memory and either avoid
  syscalls or stub them, until the stubs item above lands.
