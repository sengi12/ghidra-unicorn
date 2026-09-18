# Changelog

Notable changes to ghidra-unicorn. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html). Planned work is in
[TODO.md](TODO.md).

## [Unreleased]

### Added

- **Differential execution against Ghidra's p-code emulator**, in
  `differential.py`: both engines are put in the same state, stepped in
  lockstep, and compared after every instruction, with the first
  disagreement reported as the step, the instruction, and the registers that
  differ with the xor of each pair. Unicorn and the p-code emulator
  implement the same instruction sets from completely separate descriptions
  of them, so a disagreement is a bug in one of them - and a check on this
  connector's own tables, since a register name mapped to the wrong register
  never matches. No mapping table is needed between the two, because
  `arch.py` already names every register the way Ghidra's SLEIGH
  specification does.

  The comparison is tested by running Unicorn against Unicorn, with engines
  deliberately made to disagree in each of the ways they can, so that a
  comparison unable to report anything cannot pass. **The p-code half and
  `tools/differential.py` have not yet been run against a real Ghidra**;
  they were written on a machine that had none, and want one run against the
  afl-unicorn sample before they are trusted.

- **Preloading is region-aware.** The cap was applied to the regions in
  address order, and the first region that did not fit stopped the loop
  outright, so a dump with a large heap low in the address space filled the
  budget before reaching the code and the stack and the Dynamic Listing came
  up empty - the two regions anybody wants to see first were the ones most
  likely to be missed. Regions are now ranked by what they are: the one
  holding the program counter, then the stack pointer, then the input region
  a harness declared, then a declared module, then anything executable, with
  size as the tie-break so the budget buys as many as it can. A region too
  large for what is left is no longer skipped either - a window of it is
  copied around whatever made it interesting, because part of a huge region
  is far more use than none of it and the rest is read on demand anyway. The
  launch line now says what was preloaded and what was left.

- **Session recording.** `--record PATH`, or `record PATH` in the console,
  logs the session to a file that is both a transcript and a script. The
  trick is that `#` already starts a comment, so the commands go in as
  themselves, one per line, and everything else - the setup, what the target
  printed, the full context at every stop - goes in behind a `#`. The result
  reads as a transcript and replays with `--commands-file` without a word
  being edited out of it, so there is no second format to keep in step with
  the first. Stops are recorded by listening to the target rather than the
  console, so one caused from Ghidra's buttons is logged like one caused by
  a command typed here. Colour escapes are stripped on the way in.

- **Console extras.** `disas [ADDR] [N]` disassembles with symbol names, a
  marker on the program counter and a dot on each breakpoint, and `x/5i`
  does the same through the examine command. `hexdump ADDR [N]` (`hd`) shows
  bytes and an ASCII pane. `find` searches every mapped region, or a given
  range, and tells the three kinds of pattern apart by how they are written:
  `find "text"` is those characters, `find 41424344` is those bytes, and
  `find 0xdeadbeef` is a value stored the way this architecture stores one -
  which matters, because `abcd` is both a word and a pair of bytes and
  guessing would be worse than asking.

  `rwatch REG` stops when a register changes. Unicorn has no hook for that,
  so it is a comparison made once per instruction from the code hook that is
  already there, and it costs that only while such a watch exists. It is an
  ordinary breakpoint otherwise - numbered, listed, conditional (`old`,
  `new` and `register` are in scope), with a hit count that rewinds - except
  that it is not published to Ghidra, whose breakpoint kinds are all about
  addresses. Going back in time resyncs it, so a rewind is not reported as a
  change the programme made.

- **Batch and headless mode.** `--commands "b 0x100040; c; x/8xw 0x300000"`
  runs console commands as soon as the target is loaded, from the command
  line or from a file with `--commands-file`, and `--batch` then exits
  instead of prompting. With `--batch` no Ghidra is needed at all: the
  emulator, the console and everything the commands can reach work without a
  trace, so a run can be scripted from CI. It is the same console the prompt
  uses, so anything that can be typed can be scripted - and since anything
  that is not a command is Python, `assert target.pc() == 0x1234` is how a
  scripted run is made to fail. The exit status is non-zero when any command
  failed, counting failed commands, Python exceptions, syntax errors, and a
  script that ended part way through something (an unclosed bracket, which
  at a prompt means "type more" and in a script means the rest was
  swallowed). Commands split on newlines and semicolons, with quotes
  respected and `#` starting a comment, so a breakpoint condition survives
  being written in one.

  Two things that only showed up once whole runs could be scripted are fixed
  with it: a system call handler or a stub given a wild argument - a length
  out of a register nobody set, a pointer from a function nobody stubbed -
  raised out of `emu_start` and ended the session, where a kernel would
  simply answer EINVAL; and a harness can now name its own stub addresses
  with `STUBS_AT`, so a raw binary with no symbol table gets its stubs bound
  without anyone typing `stub malloc 0x400800` first.

- **Thumb tracking.** ARM code changes instruction set as it runs, and
  everything that used to be settled by the language the target was launched
  with now follows the processor instead: the T flag in the status register
  is the one source of truth, and the decoder, the address emulation is
  resumed from, and the `TMode` context register Ghidra disassembles by are
  all derived from it. A stop in Thumb code is published as Thumb, so mixed
  code comes up right in the Dynamic Listing rather than four-byte ARM
  instructions laid over two-byte Thumb ones. Two Unicorn behaviours made
  this necessary and are now covered by tests: `emu_start` decides how to
  decode from the low bit of the address it is given and *not* from the T
  flag, so resuming a Thumb program counter without that bit reads the wrong
  instruction at the wrong width; and creating the engine with
  `UC_MODE_THUMB` does not set the T flag at all, so a Thumb target used to
  begin life claiming to be in ARM state. Writing the program counter on ARM
  is itself a `bx` - the low bit selects the instruction set and never
  reaches the register - so moving it now keeps the instruction set it was
  in, and the T flag is how a change is asked for.

- **Conditional breakpoints, hit and ignore counts.** A breakpoint or
  watchpoint can carry a Python expression that has to be true before it
  stops, and an ignore count that passes it a given number of times first.
  Registers are in scope by name in either case, along with `pc`, `sp`,
  `icount`, `hits`, `reg()` for the names that are not identifiers, `mem()`
  and `u8`/`u16`/`u32`/`u64` to read through a pointer; a watchpoint also
  sees the `address`, `size`, `value` and `access` that fired it. The order
  is gdb's, which is what Ghidra's breakpoint model is built around: a
  condition that is false is not a hit at all and does not count, while an
  ignore count consumes a hit that did. A condition is compiled when it is
  set, so a typo is reported there rather than at the hook, and one that
  raises at evaluation stops and says why - a breakpoint that silently never
  fires is much harder to notice than one that complains. `Condition` and
  `Ignore Count` are published on the breakpoint spec under the names
  Ghidra's own gdb connector uses, with methods to set them from the
  Breakpoints window, and the console gains `cond` and `ignore`.

- **System calls.** `syscalls.py` puts a small Linux under the emulator, so a
  program that traps into a kernel gets an answer instead of a fault: `read`,
  `write`, `writev`, `open`, `openat`, `close`, `lseek`, `mmap`, `mmap2`,
  `munmap`, `brk`, `getpid`, `exit` and `exit_group`, with the call numbers
  and argument registers of every Linux architecture here - x86, x86-64, ARM,
  ARM64, MIPS o32 and n64, RISC-V, PowerPC and m68k - in `abi.py` beside the
  calling conventions. Errors come back the way each architecture reports
  them: a negative result, MIPS's separate flag register, or PowerPC's CR0
  summary-overflow bit. There is no host filesystem: `open` sees only the
  files the harness handed over, so pointing the debugger at a crashing input
  cannot reach the debugging machine's own files. A handler can be replaced or
  added by name without touching the number tables. `--syscalls`,
  `--stdin` and `--trace-calls` on the command line, the same as
  `OPT_SYSCALLS`, `OPT_STDIN` and `OPT_TRACE_CALLS` in the launcher, and `sys`
  in the console.

- **Function stubs.** `stubs.py` stands in for library functions the binary
  calls but does not contain: `malloc`, `calloc`, `realloc`, `free`, the
  `mem*` and `str*` family, `puts`, `putchar`, `exit` and `abort`. A stub is a
  code hook on the function's entry address that reads the arguments where the
  architecture's C calling convention puts them, does the work in Python and
  writes the return address into the program counter, so the function's own
  instructions never run and it does not matter that they are not there.
  `malloc` allocates from an arena mapped on demand, with a free list that
  does not immediately recycle the most recent block, so a use-after-free
  still reads the bytes it had. `--symbols` binds every implementation the
  symbol table has an address for; `stub NAME ADDR` in the console binds one
  by hand, and `stubs` and `heap` show what is bound and what has been handed
  out. A breakpoint on a stubbed function still stops before the stub stands
  in for it.

  Both layers are on by default, opt out per run or per harness, and both are
  correct under reverse execution - which is the hard part, and is what
  `effects.py` is for. A system call is not a pure function of the machine
  state and a stub skips instructions entirely, so re-running either during a
  replay would consume the input twice, print twice, hand out a second block,
  or walk into code the first pass never executed. Each one therefore runs
  once and records what it did - memory written, regions mapped, registers
  set, output produced, and whether it ended the program - and a replay
  applies the record instead of doing it again. Going back before a call puts
  back the layer's own state as well, so the file offset, the break and the
  allocator rewind with the machine and running forward again reads the same
  bytes and returns the same address. The log is pruned as the history folds,
  so it costs nothing the history is not paying for already.

- **Reverse execution.** The processor context is checkpointed every few
  thousand instructions, along with only the pages written since the previous
  checkpoint, so stepping backwards means restoring the nearest checkpoint and
  replaying forward with breakpoints and events silenced. `resume_back`,
  `step_back_into` and `step_back_over` carry the action names and icons
  Ghidra's toolbar already draws, so its step-back buttons light up, and the
  console gains `rsi`, `rni`, `rc`, `goto` and `icount`. Old checkpoints are
  folded into the base rather than discarded when the memory budget is
  reached, so history stays exact and the connector reports honestly how far
  back it can still reach. Verified against Ghidra 12.1.3: stepping back and
  forward again returns to the same instruction.

- **Basic-block coverage recording** in `coverage.py`: a `UC_HOOK_BLOCK`
  recorder that sorts blocks into modules and writes drcov version 2, the
  format ghidra-aflcov, Lighthouse and Dragondance read. Blocks outside every
  declared module are attributed to the mapped region they landed in rather
  than dropped. A test asserts the bytes are identical to afl-unicorn's own
  writer for the same input, so the files are interchangeable. Triage takes
  `--coverage-dir` and leaves one drcov file per replayed input, so a crash
  can be painted in ghidra-aflcov straight from a triage run. Not yet wired
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

- **Console commands for the three libraries.** `cov on|off|save PATH`
  records basic blocks and writes drcov, `prov on` watches the input buffer
  and `prov` reports which offsets were read, and `sym` looks a symbol up in
  either direction. With a symbol table loaded, anywhere the console takes an
  address now takes a name, so `b main` works. The launcher gained *Symbols*
  and *Symbols base* fields, and the command line `--symbols` and
  `--symbols-at`.

### Fixed

- **Reverse-continue finds watchpoint hits, not just breakpoints.** It looked
  only at the program counter of each instruction it replayed, and a memory
  access leaves no mark there, so a watchpoint could never be reached going
  backwards. The search now replays each window with the memory hooks
  *watched* rather than merely muted, which is the only place the access is
  visible, and considers both kinds of hit together - landing where a forward
  run would have stopped, which for a watchpoint is after the accessing
  instruction. Conditions are honoured too: a candidate with a condition is
  tested in the state it would have seen, and rejected candidates are skipped
  over to the next one back.

- **Hit counts rewind with the machine.** A hit count says how many times a
  breakpoint has fired at or before where the machine is now, so going back
  past a hit undoes it, and an ignore count that hit consumed comes back with
  it. Arriving backwards at a breakpoint the history does not record - one
  set after that point was first passed - counts as its first hit. The record
  is pruned with the history, like everything else that is kept per
  instruction.

- **Reverse step-over costs the distance travelled, not the history kept.**
  It replayed everything retained to establish an absolute call depth before
  it could say which instructions were in the current frame, so a long
  session made every reverse step-over slow. Depth is now kept relative to
  the current position, which makes it local - a call met on the way back is
  one frame shallower, a return is one frame deeper, nothing else moves it -
  so the search walks back only as far as it travels, one checkpoint window
  at a time, and needs neither an absolute depth nor a stack of return
  addresses. `arch.py` gains the return mnemonics this needs, each one
  checked against what Capstone actually emits rather than taken from a
  manual.

- **Reverse execution rewinds a mapping.** Restoring a checkpoint mapped back
  the regions it had and left alone any that had appeared since, so a region
  mapped after the checkpoint survived a rewind to before it existed and the
  program found memory it had not allocated yet. Every checkpoint now carries
  the region list - what is mapped is part of the state - and restoring makes
  the region set match exactly, unmapping what should not be there and
  mapping back what should. A region that only partly overlaps is taken down
  whole and the wanted pieces put back, which also puts right a region that
  was split or merged since. This was a corner case while nothing could map
  memory; with `mmap` and a growing `brk` under the emulator it is not.

- **Stepping toward an end address that is a branch delay slot no longer
  loops forever.** The end was handed to Unicorn as a stop address even when
  stepping, and Unicorn leaves the program counter on the branch when the
  stop address is its delay slot, so every step re-executed that branch and
  applied its stack adjustment again. Only a free run passes the end address
  now; a step is bounded by its instruction count.
- **Arriving at an exit address while stepping ends the run.** Unicorn's
  instruction count returns before the next instruction's hook fires, so a
  step that landed on an exit used to walk straight past what a free run
  stops at.
- **A stop forced by an unrelated hook is no longer reported as
  termination.** With an end address declared, anything else calling
  `emu_stop` was described as having reached it. Only a program counter
  within one instruction of the target counts as arriving, which still covers
  the delay-slot case.
- **The refused access is carried on the stop event.** A `UcError` holds only
  an error number, so the faulting address and access kind now come from an
  invalid-memory hook in the target, and the triage report no longer needs
  its own copy.
- **Flag registers may be more than one bit wide**, which brings m68k's
  three-bit interrupt level and PowerPC's seven-bit `xer_count` into the
  Registers window as editable rows instead of read-only fields.

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
