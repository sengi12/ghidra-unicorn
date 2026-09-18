# Roadmap

What is planned for ghidra-unicorn, roughly in the order it is worth doing.
Shipped work moves to [CHANGELOG.md](CHANGELOG.md).

Status: `[ ]` not started, `[~]` in progress, `[x]` done and in the changelog.

## Next

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

- [ ] **Reverse-continue finds execute breakpoints only**, not watchpoint
  hits, and it does not adjust hit counts as it passes them.
- [ ] **Step-over backwards replays the whole retained history** to work out
  call depth, so it costs time proportional to what is kept rather than to
  the distance travelled.

Fixed, kept here until the next release notes ship:

- [x] A region mapped after a checkpoint survived a rewind to before it
  existed, because restoring mapped missing regions back but never unmapped
  extra ones.
- [x] A flag register had to be exactly one bit, which kept m68k's interrupt
  level and PowerPC's `xer_count` out of the Registers window.
- [x] A stop forced by an unrelated hook was reported as termination when an
  end address had been declared.
- [x] A fault's address was not on the stop event, so every caller installed
  its own invalid-memory hook.
- [x] Stepping toward an end address that is a branch delay slot looped
  forever, re-applying that instruction's side effects each time.

## Known limitations

These are consequences of the design rather than missing work, but they are
worth stating.

- One thread and one frame. Unicorn has no threads, and Ghidra unwinds the
  stack itself from the registers and memory the connector publishes.
- Step-over needs Capstone to recognise a call; without it, it steps into.
- The operating system under the emulator is a small one. `syscalls.py`
  services the calls a harness usually needs and nothing else; anything it
  does not know comes back as ENOSYS, which is visible in `sys` rather than
  silent. There is deliberately no host filesystem behind `open`.
- A stubbed function is one step, not a step into: a stub stands in for the
  whole call, so `s` over a stubbed `malloc` returns from it. A breakpoint on
  it still stops before it.
- SPARC and TriCore have calling conventions but no system call table, and
  Unicorn 2.1.4 cannot map memory for TriCore at all, so nothing can be
  emulated on it here.
