# Roadmap

What is planned for ghidra-unicorn, roughly in the order it is worth doing.
Shipped work moves to [CHANGELOG.md](CHANGELOG.md).

Status: `[ ]` not started, `[~]` in progress, `[x]` done and in the changelog.

## Next

These two need a running Ghidra to build against, so they are last.

- [~] **A context panel inside Ghidra.** Written as
  `ghidra_scripts/UnicornContextPanel.py`, drawing the same view the console
  prints, from the trace rather than from the emulator. As the item said, it
  needed nothing new on the Python side - only that `context.py` render from
  a small surface instead of from the target, which it now documents and
  which a test pins down by rendering both ways and comparing.

  It is a **floating window, not a docked `ComponentProvider`**, and that is
  not laziness: `docking.ComponentProvider` is an abstract class with an
  abstract method, Ghidra ships no concrete one, and JPype cannot extend
  Java classes at all. A docked version has to be written in Java, and a
  Java panel cannot call this renderer - it would have to reimplement
  `context.py`, and then two views of the same machine could disagree. If a
  docked panel is wanted enough to pay that price, that is a new item, not
  this one.

  Every Ghidra and JPype call in it has been checked against Ghidra's own
  source and a real JPype, which found three mistakes; it has still not been
  *run*. Do that once on a machine with Ghidra 12.1.3.
- [~] **Differential execution against Ghidra's p-code emulator.** The
  comparison is written and tested (`differential.py`, Unicorn against
  Unicorn, with deliberate divergences so the machinery is shown to be able
  to fail). The p-code side and `tools/differential.py` are written and
  every `EmulatorHelper` call has been checked against Ghidra's source,
  which found three mistakes, but it has not been *run*. Do that once on a
  machine with Ghidra 12.1.3, against the afl-unicorn sample.

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
