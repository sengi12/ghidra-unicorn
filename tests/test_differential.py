"""Comparing two engines instruction by instruction.

The p-code side needs a Ghidra installation, so what is exercised here is
the comparison itself: Unicorn against Unicorn. That sounds circular, and
would be if the test only checked that two identical engines agree - a
comparison that can never report anything would pass that. So the engines
are also made to disagree, in each of the ways they can, and the machinery
has to find it.
"""
import pytest

from ghidraunicorn import differential
from ghidraunicorn.differential import (Comparison, Divergence, EngineError,
                                        UnicornEngine, align, compare)

from test_target import CODE, DATA, make_x64


def two_engines():
    return UnicornEngine(make_x64()), UnicornEngine(make_x64())


class Wrong(UnicornEngine):
    """An engine that lies about one register after a given step.

    This stands in for the thing a differential run exists to find: an
    instruction one engine got wrong.
    """
    name = 'wrong'

    def __init__(self, target, register='RAX', after=2, delta=1) -> None:
        super().__init__(target)
        self.register, self.after, self.delta = register, after, delta
        self.steps = 0

    def step(self) -> None:
        super().step()
        self.steps += 1
        if self.steps == self.after:
            self.target.reg_write(
                self.register, self.target.reg_read(self.register) + self.delta)


# ---- agreeing -------------------------------------------------------------

def test_two_engines_running_the_same_program_agree():
    a, b = two_engines()
    result = compare(a, b, steps=6)
    assert result.agreed and result.steps == 6
    assert 'no disagreement' in result.describe()


def test_a_comparison_of_zero_steps_does_nothing():
    a, b = two_engines()
    result = compare(a, b, steps=0)
    assert result.agreed and result.steps == 0


def test_stopping_at_an_address_ends_the_run():
    a, b = two_engines()
    result = compare(a, b, steps=100, stop_at=0x1015)
    assert result.agreed and 'reached 0x1015' in result.stopped
    assert result.steps == 4


def test_the_step_callback_sees_every_step():
    a, b = two_engines()
    seen = []
    compare(a, b, steps=3, on_step=lambda step, pc: seen.append((step, pc)))
    assert [s for s, _ in seen] == [1, 2, 3]
    assert seen[0][1] == 0x1007


# ---- disagreeing ----------------------------------------------------------

def test_a_register_that_differs_is_found():
    a = UnicornEngine(make_x64())
    b = Wrong(make_x64(), register='RAX', after=2)
    result = compare(a, b, steps=6)
    assert not result.agreed
    d = result.divergence
    assert d.step == 2 and 'RAX' in d.registers
    assert d.registers['RAX'] == (2, 3)
    assert d.names == ('unicorn', 'wrong')


def test_the_report_says_where_and_what():
    a = UnicornEngine(make_x64())
    b = Wrong(make_x64(), register='RAX', after=1)
    text = compare(a, b, steps=4).describe()
    assert 'diverged at step 1' in text
    assert '0x1000' in text and 'mov' in text, 'the instruction is not named'
    assert 'unicorn 0x1' in text and 'wrong 0x2' in text
    assert 'xor 0x3' in text, 'the xor of the two values helps spot a bit flip'


def test_a_program_counter_that_differs_is_found():
    a, b = two_engines()
    b.target.reg_write('RIP', 0x1007)         # a step ahead
    result = compare(a, b, steps=2)
    assert not result.agreed and 'pc' in result.divergence.registers


def test_the_comparison_stops_at_the_first_disagreement():
    a = UnicornEngine(make_x64())
    b = Wrong(make_x64(), after=2)
    result = compare(a, b, steps=100)
    assert result.steps == 2, 'it kept going after finding a difference'


def test_watched_memory_is_compared():
    a, b = two_engines()
    b.target.write(DATA, b'different')
    result = compare(a, b, steps=1, watch=[(DATA, 8)])
    assert not result.agreed
    address, one, two = result.divergence.memory[0]
    assert address == DATA and one != two


def test_memory_outside_the_watch_is_not_compared():
    a, b = two_engines()
    b.target.write(DATA + 0x100, b'different')
    assert compare(a, b, steps=1, watch=[(DATA, 8)]).agreed


# ---- what gets compared ---------------------------------------------------

def test_a_register_can_be_ignored():
    # R15, because the programme never touches it: corrupting RAX instead
    # would show up in the flags and then in RBX through memory, which is
    # the difference propagating rather than the filter failing.
    a = UnicornEngine(make_x64())
    b = Wrong(make_x64(), register='R15', after=2)
    assert compare(a, b, steps=6, ignore=['r15']).agreed
    assert not compare(*[UnicornEngine(make_x64()),
                         Wrong(make_x64(), register='R15', after=2)],
                       steps=6).agreed


def test_the_comparison_can_be_limited_to_named_registers():
    a = UnicornEngine(make_x64())
    b = Wrong(make_x64(), register='R15', after=2)
    assert compare(a, b, steps=6, registers=['RBX', 'RCX']).agreed
    a = UnicornEngine(make_x64())
    b = Wrong(make_x64(), register='R15', after=2)
    assert not compare(a, b, steps=6, registers=['R15']).agreed


def test_a_difference_that_propagates_is_still_caught_downstream():
    """Ignoring a register hides that register, not its consequences: a
    wrong RAX shows up in the flags and then in RBX through memory."""
    a = UnicornEngine(make_x64())
    b = Wrong(make_x64(), register='RAX', after=2)
    result = compare(a, b, steps=6, ignore=['rax'])
    assert not result.agreed and 'RAX' not in result.divergence.registers


def test_registers_only_one_engine_has_are_reported_not_hidden():
    """A register quietly missing from one side would make a differential
    run look cleaner than it is."""
    class Fewer(UnicornEngine):
        def registers(self):
            values = dict(super().registers())
            values.pop('RBX', None)
            return values

    a = UnicornEngine(make_x64())
    b = Fewer(make_x64())
    result = compare(a, b, steps=3)
    assert result.agreed
    assert 'RBX' in result.unmatched


def test_an_engine_that_faults_ends_the_comparison():
    class Faulty(UnicornEngine):
        def step(self):
            raise EngineError('bad memory access at 0xdead')

    a = UnicornEngine(make_x64())
    result = compare(a, Faulty(make_x64()), steps=5)
    assert result.agreed and 'bad memory access' in result.stopped


# ---- aligning -------------------------------------------------------------

def test_align_copies_memory_and_registers_across():
    a, b = two_engines()
    a.target.write(DATA, b'copied across')
    a.target.reg_write('RAX', 0x1234)
    align(a, b, [(DATA, DATA + 0xfff)])
    assert b.target.read(DATA, 13) == b'copied across'
    assert b.target.reg_read('RAX') == 0x1234


def test_align_survives_a_register_the_other_engine_lacks():
    class Picky(UnicornEngine):
        def write_register(self, name, value):
            if name == 'RBX':
                raise KeyError(name)
            super().write_register(name, value)

    a = UnicornEngine(make_x64())
    b = Picky(make_x64())
    a.target.reg_write('RAX', 7)
    align(a, b, [])                      # must not raise
    assert b.target.reg_read('RAX') == 7


def test_aligned_engines_then_agree():
    """The two halves together: align, then compare."""
    a, b = two_engines()
    a.target.step(3)
    regions = [(s, e) for s, e, _ in a.target.regions()]
    align(a, b, regions)
    assert compare(a, b, steps=5).agreed


# ---- the p-code side ------------------------------------------------------

def test_the_pcode_engine_needs_ghidra():
    """It is imported lazily, so the rest of this works without Ghidra."""
    with pytest.raises(Exception):
        differential.PcodeEngine(object())


def test_the_engine_interface_is_what_the_pcode_side_implements():
    """Both sides answer the same questions, so neither can drift."""
    wanted = {'pc', 'registers', 'write_register', 'read', 'write', 'step',
              'disassemble', 'close'}
    for engine in (UnicornEngine, differential.PcodeEngine):
        assert wanted <= set(dir(engine)), engine.__name__


def test_a_divergence_of_only_the_program_counter_is_flagged():
    d = Divergence(1, 0x1000, 'jmp', registers={'pc': (1, 2)})
    assert d.only_pc
    d.registers['RAX'] = (3, 4)
    assert not d.only_pc


def test_an_engine_that_simply_stops_ends_the_comparison_cleanly():
    """A target reaching its end address raises TargetError, which is not a
    disagreement and must not come out of `compare` as an exception."""
    from ghidraunicorn.target import TargetError

    class Ends(UnicornEngine):
        def step(self):
            raise TargetError('target has terminated')

    result = compare(UnicornEngine(make_x64()), Ends(make_x64()), steps=5)
    assert result.agreed and 'terminated' in result.stopped


def test_a_target_that_reaches_its_end_stops_the_comparison():
    a = UnicornEngine(make_x64(end=0x100a))
    b = UnicornEngine(make_x64(end=0x100a))
    for engine in (a, b):
        engine.target.run()                  # both sit at the end, terminated
    result = compare(a, b, steps=5)
    assert result.agreed and result.stopped
