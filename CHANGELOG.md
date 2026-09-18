# Changelog

Notable changes to ghidra-unicorn. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html). Planned work is in
[TODO.md](TODO.md).

## [Unreleased]

### Added

- **Basic-block coverage recording** in `coverage.py`: a `UC_HOOK_BLOCK`
  recorder that sorts blocks into modules and writes drcov version 2, the
  format ghidra-aflcov, Lighthouse and Dragondance read. Blocks outside every
  declared module are attributed to the mapped region they landed in rather
  than dropped. A test asserts the bytes are identical to afl-unicorn's own
  writer for the same input, so the files are interchangeable. Not yet wired
  to a console command or launcher option.
- **Symbol names** in `symbols.py`, loaded from JSON that
  `tools/export_symbols.py` writes from an open Ghidra program. The context
  now annotates disassembly and pointer targets as `<main+0x40>`. An
  enclosing function wins over a nearer generated label, the way gdb and IDA
  report an address, and a label inside a function does not describe
  addresses outside it. Not yet wired to a launcher option or to breakpoints
  by name.
- **Batch crash triage** in `triage.py`, with a command line at
  `python -m ghidraunicorn.triage`. It replays a directory of fuzzing inputs
  through a harness, each in a fresh target, and reports the outcome, the
  faulting instruction, the fault address, registers and a stack window for
  each. Runs are bounded by an instruction budget and a wall clock, so an
  input that loops forever is reported as a timeout rather than hanging.
  Results are grouped by a replaceable crash signature, defaulting to the
  fault kind and faulting address, and each group keeps the smallest input as
  its representative. It exits non-zero when anything crashed, so it can gate
  CI, and it imports nothing from the Ghidra side so it runs with no Ghidra
  present. On the afl-unicorn sample it reduces four crash files to the three
  distinct null reads in the target's source.
- **`tools/import_triage.py`** paints a triage report onto a Ghidra program
  as bookmarks and comments at each crash address, so the listing shows where
  crashes land and how many inputs reach each one. Idempotent, with a
  `--dry-run` that needs no Ghidra and an `--offset` for a different image
  base.
- **Input provenance** in `provenance.py`: a read hook over the input buffer
  that records which offsets were read and by which instruction, so a crash
  can be traced back to the bytes that reached it, along with which parts of
  the input were never looked at. It records direct reads rather than
  following values through registers, which is honest about its cost and
  enough for most parsers. Not yet wired to a console command or the triage
  report. Triage uses it: a harness that declares `INPUT_BASE` (or a
  `--input-at` address) gets an "input read" line per result, naming the
  offsets that run consumed. On the sample's crashes that is `0, 9-10` for
  one bug and `20` for another, out of inputs of 11 and 32 bytes.

- **Eight more processors**: RISC-V 32 and 64, PowerPC 32 and 64, m68k,
  SPARC 32 and 64, and TriCore, bringing the total to twenty. Every language
  id, compiler spec and register name was checked against the processor
  definitions in the installed Ghidra rather than written from memory, and
  each one is covered by the tests that read every register from a live
  engine and decode a call for step-over. Where Ghidra models a status
  register's bits as its own registers, those are exposed as flags: PowerPC's
  carry and overflow bits off `XER`, and m68k's condition codes off `SR`.
  TriCore's `PSW` is exposed as fields, since Ghidra leaves its bit
  definitions commented out.
- **Windows launchers**, `local-unicorn.ps1` and `local-unicorn.bat`, with
  the same options as the Unix one, following Ghidra's own launcher
  conventions for each file type. They are unverified on Windows: there was
  no Windows machine to run them on.

### Changed

- **`tools/setup_project.py` seeds the entry point.** A raw binary has no
  entry point for auto-analysis to follow, so the sample imported as
  undefined bytes and the static listing came up empty. It now disassembles
  at the base address and declares `main` there before analysing, which is
  also what makes the symbol export produce anything.

## [0.1.0] - 2026-09-18

The first working connector: Unicorn Engine as a Ghidra Debugger back-end
over Trace RMI, verified end to end against Ghidra 12.1.3.

### Added

- **The connector.** A Python Trace RMI back-end in the shape of Ghidra's own
  drgn and gdb agents: `arch.py` maps Unicorn arch and mode to a Ghidra
  language and register table, `target.py` wraps an engine with run, step,
  interrupt, breakpoints and watchpoints, `commands.py` publishes state into
  the trace, `methods.py` exposes the remote methods Ghidra's toolbar drives,
  and `hooks.py` turns stops into snapshots. One launcher script makes it
  appear in Ghidra's Launch menu; no Ghidra plugin is needed.
- **Two ways to load a target.** A harness file defining
  `create(input_file) -> unicorn.Uc`, which is the set-up half of an
  afl-unicorn fuzzing harness, or an afl-unicorn context dump directory,
  parsed natively so afl-unicorn need not be importable.
- **Execution control.** Resume, interrupt, step into, step over through
  calls when Capstone is present, advance to address, and kill. Resume runs
  the emulator on its own thread so an interrupt can still be delivered.
- **Breakpoints and watchpoints** driven from Ghidra's windows: execute,
  read, write and access, with enable, disable, delete and hit counts.
- **Trace publishing.** Every stop becomes a snapshot; registers, the memory
  map with permissions, and a module for the image so the trace maps onto the
  static listing. All mapped memory is copied in at launch, capped at 32 MiB,
  with everything else read on demand.
- **Architectures**: x86-64, x86, AArch64, ARM and Thumb, MIPS32 and MIPS64,
  in both endiannesses where the processor has them.
- **Flag registers and status-register fields.** `cpsr`, `nzcv` and `eflags`
  are decomposed into the one-byte flag registers Ghidra defines, so each is
  its own editable row in the Registers window, and writing one recomposes
  the status register. Every other bit field, including the ARM mode, the
  interrupt masks and x86 IOPL, is addressable as `reg.field`.
- **Register presets** at launch through the `Registers` option, by value or
  by field: `cpsr=0x600001d3`, `cpsr.M=0x10`, `ZF=1`.
- **A gef-style console** in the launcher's terminal. On every stop it prints
  the reason, registers with changes highlighted and pointers dereferenced
  and coloured by region, the decoded status register, disassembly around the
  program counter, and the stack. It takes short commands: `c`, `si`, `ni`,
  `adv`, `b`, `watch`, `d`, `bl`, `x/8xw`, `x/s`, `r`, `fields`, `m`, `ctx`,
  `k`, `q`. Anything else is Python with `target` and `uc` in scope.
- **Line editing** through readline: backspace, arrow keys, history kept
  across sessions, Tab completion over commands then register, flag and field
  names then Python, and the usual Ctrl-A/E/U/K/W/R.
- **Running outside Ghidra.** `--address` connects to Ghidra's "Connect by
  Accept", and `--listen` waits for its "Connect Outbound", so the console
  can live in a terminal of your choosing.
- **`tools/setup_project.py`**, which builds a Ghidra project with the
  afl-unicorn sample imported at the right base address and analyzed, so the
  first run is a few clicks.
- **`tools/e2e_ghidra.py`**, which drives a real Ghidra in process through
  the whole flow: import, tool, launch through the real launcher script,
  initial state, stepping, breakpoints, resume, register writes, run to
  termination, and the listen-mode connection.
- **Tests**: 61 unit tests that need no Ghidra, including two that drive the
  console through a real pty.

### Fixed

- **Watchpoints no longer re-run an instruction.** Stopping inside a Unicorn
  memory hook leaves the program counter on the accessing instruction with
  its effects already applied, so resuming would execute it twice. A
  watchpoint now records the hit and the following code hook performs the
  stop.
- **Reaching the end address is reported as termination** even when Unicorn
  returns from `emu_start` on its own, which happens when the end address is
  a delay slot and the engine stops on the branch.
- **Memory is pushed in 32 KiB chunks**, since Trace RMI refuses messages
  over 64 KiB and preloading a whole region exceeded it.
- **Backspace works in Ghidra's terminal.** It sends `0x08` while a macOS pty
  erases on `0x7f`, and nothing was doing line editing; readline now binds
  both.
- **Progress lines are flushed**, so they appear when output is not a
  terminal, which had left listen mode looking silent.

[Unreleased]: https://github.com/sengi12/ghidra-unicorn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sengi12/ghidra-unicorn/releases/tag/v0.1.0
