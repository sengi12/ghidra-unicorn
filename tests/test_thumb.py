"""Following the instruction set as it changes, rather than as it started.

ARM code moves between ARM and Thumb while it runs, so nothing may be
settled by the language the target was launched with: the decoder, the
address emulation resumes from, and the TMode context register Ghidra
disassembles by all have to follow the processor.

The programme, little-endian ARM:

    0  1000: blx 0x1008        fa000000     ARM, and switches to Thumb
    1  1008: movs r0, #1       2001         Thumb
    2  100a: movs r1, #2       0221         Thumb
    3  100c: bx lr             4770         Thumb, and switches back
    4  1004: nop               00f020e3     ARM again
"""
import pytest
from unicorn import UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_MODE_THUMB, Uc

from ghidraunicorn import arch
from ghidraunicorn.target import UnicornTarget

CODE = 0x1000


def make_mixed(thumb=False):
    spec = arch.spec_for_key('armlethumb' if thumb else 'armle')
    uc = Uc(spec.uc_arch, spec.uc_mode)
    uc.mem_map(CODE, 0x1000)
    uc.mem_write(CODE, bytes.fromhex('000000fa'))          # blx 0x1008
    uc.mem_write(CODE + 4, bytes.fromhex('00f020e3'))      # nop (ARM)
    uc.mem_write(CODE + 8, bytes.fromhex('0120') + bytes.fromhex('0221')
                 + bytes.fromhex('7047'))                  # thumb, then bx lr
    t = UnicornTarget(uc, spec=spec)
    t.reg_write(spec.pc, CODE)
    t.reg_write('lr', CODE + 4)
    return t


def test_an_arm_target_starts_in_arm_state():
    t = make_mixed()
    assert not t.thumb
    assert t.context() == {'TMode': 0}


def test_a_thumb_target_starts_in_thumb_state():
    """Creating the engine with UC_MODE_THUMB does not set the T flag, so
    without the fix-up a Thumb target begins life claiming to be ARM."""
    t = make_mixed(thumb=True)
    assert t.thumb
    assert t.context() == {'TMode': 1}


def test_the_state_follows_the_programme_across_a_blx():
    t = make_mixed()
    assert not t.thumb
    t.step()                                  # blx
    assert t.thumb and t.pc() == CODE + 8
    assert t.context() == {'TMode': 1}
    t.step(2)                                 # two Thumb instructions
    assert t.thumb and t.reg_read('r1') == 2
    t.step()                                  # bx lr, back to ARM
    assert not t.thumb and t.pc() == CODE + 4
    assert t.context() == {'TMode': 0}


def test_stepping_in_thumb_advances_two_bytes_not_four():
    """The proof that emulation resumed with the Thumb bit on the address:
    without it the two-byte instruction is decoded as a four-byte ARM one."""
    t = make_mixed()
    t.step()                                  # into Thumb at 0x1008
    t.step()
    assert t.pc() == CODE + 0x0a, f'stepped to {t.pc():#x}, not one Thumb wide'
    assert t.reg_read('r0') == 1


def test_the_decoder_follows_the_instruction_set():
    t = make_mixed()
    size, mnem, _ = t.decode(CODE)
    assert (size, mnem) == (4, 'blx')
    t.step()
    size, mnem, ops = t.decode(t.pc())
    assert size == 2 and mnem == 'movs', f'decoded {mnem} of {size} bytes as ARM'


def test_moving_the_program_counter_does_not_change_instruction_set():
    """Writing the program counter on ARM is a `bx`, and an even address
    would quietly drop out of Thumb."""
    t = make_mixed()
    t.step()
    assert t.thumb
    t.reg_write('pc', CODE + 0x0a)
    assert t.thumb, 'setting the program counter left Thumb state'
    t.step()
    assert t.reg_read('r1') == 2 and t.pc() == CODE + 0x0c


def test_the_t_flag_is_how_the_instruction_set_is_changed():
    t = make_mixed()
    t.reg_write('cpsr.T', 1)
    assert t.thumb and t.context() == {'TMode': 1}
    t.reg_write('cpsr.T', 0)
    assert not t.thumb and t.context() == {'TMode': 0}


def test_reverse_execution_puts_the_instruction_set_back():
    t = make_mixed()
    t.timeline.interval = 1
    t.step(3)                                 # in Thumb, about to `bx lr`
    assert t.thumb
    t.step()                                  # back in ARM
    assert not t.thumb
    t.step_back()
    assert t.thumb, 'going back did not restore Thumb state'
    assert t.decode(t.pc())[0] == 2
    t.goto_icount(0)
    assert not t.thumb


def test_a_breakpoint_in_thumb_code_stops_there():
    t = make_mixed()
    bp = t.add_breakpoint(CODE + 0x0a)
    ev = t.run()
    assert ev.breakpoint is bp and t.pc() == CODE + 0x0a and t.thumb


def test_an_architecture_without_thumb_has_no_tmode():
    from test_target import make_x64
    t = make_x64()
    assert not t.thumb
    assert t.context() == {}


@pytest.mark.parametrize('key', ['armle', 'armbe', 'armlethumb', 'armbethumb'])
def test_every_arm_spec_carries_both_decoders(key):
    spec = arch.spec_for_key(key)
    assert spec.thumb_field == 'T'
    assert spec.cs_arm is not None and spec.cs_thumb is not None
    assert spec.cs_arm != spec.cs_thumb


def test_the_trace_publishes_the_live_tmode():
    """What Ghidra is told has to be the state of the machine now, not the
    language it was launched with."""
    t = make_mixed()
    assert t.context()['TMode'] == 0
    t.step()
    assert t.context()['TMode'] == 1
