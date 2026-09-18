# Roadmap

What is planned for ghidra-unicorn, roughly in the order it is worth doing.
Shipped work moves to [CHANGELOG.md](CHANGELOG.md).

Status: `[ ]` not started, `[~]` in progress, `[x]` done and in the changelog.

## Next

These two need a running Ghidra to build against, so they are last.

- [ ] **A context panel inside Ghidra.** A docking `ComponentProvider` in a
  Ghidra script, in the style of ghidra-hexEditor and ghidra-aflcov, showing
  the gef-style register, pointer-chain and stack view in a window instead of
  the terminal. It needs nothing new on the Python side: everything it would
  draw is already in the trace.
- [~] **Differential execution against Ghidra's p-code emulator.** The
  comparison is written and tested (`differential.py`, Unicorn against
  Unicorn, with deliberate divergences so the machinery is shown to be able
  to fail). The p-code side and `tools/differential.py` are written but have
  not been run against a real Ghidra yet - there was none on the machine
  they were written on. Run it once on a machine with one, against the
  afl-unicorn sample, before calling this done.

## Known bugs

None known. The three reverse-execution bugs listed here are fixed and are
in the changelog under Unreleased.

Fixed, kept here until the next release notes ship:

- [x] Reverse-continue found execute breakpoints only, never a watchpoint
  hit, and hit counts did not move as it passed them.
- [x] Step-over backwards replayed the whole retained history to work out
  call depth.
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
