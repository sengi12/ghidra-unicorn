import pytest

from ghidraunicorn.provenance import InputProvenance, format_ranges, ranges

from test_target import DATA, make_x64


def test_ranges_collapse():
    assert ranges([]) == []
    assert ranges([3]) == [(3, 3)]
    assert ranges([0, 1, 2, 5, 6, 9]) == [(0, 2), (5, 6), (9, 9)]
    assert ranges([2, 1, 0, 0]) == [(0, 2)]
    assert format_ranges(ranges([0, 1, 2, 5])) == '0-2, 5'
    assert format_ranges([]) == '(none)'


def test_records_reads_of_the_input_buffer():
    # The sample program stores rax to DATA then loads it back; the load is the
    # read we should see, and it comes from the instruction at 0x1015.
    t = make_x64(end=0x1025)
    prov = InputProvenance(t, base=DATA, length=16)
    prov.start()
    assert prov.recording
    t.run()
    prov.stop()
    assert not prov.recording

    assert prov.offsets_read == set(range(8))
    assert prov.read_ranges() == [(0, 7)]
    assert prov.unread_ranges() == [(8, 15)]
    assert prov.reads_at(0x1015) == set(range(8))
    assert prov.reads_at(0x1000) == set()
    first = prov.first_read(3)
    assert first is not None and first.pc == 0x1015 and first.address == DATA
    assert first.offset == 0 and first.size == 8


def test_summary_mentions_read_and_unread():
    t = make_x64(end=0x1025)
    prov = InputProvenance(t, base=DATA, length=16, label='crash input')
    prov.start()
    ev = t.run()
    prov.stop()
    text = prov.summary(pc=0x1015)
    assert 'crash input: 16 bytes' in text
    assert 'read:   0-7' in text
    assert 'unread: 8-15' in text
    assert 'at 0x1015: 0-7' in text


def test_reset_and_bad_length():
    t = make_x64(end=0x1025)
    prov = InputProvenance(t, base=DATA, length=16)
    prov.start()
    t.run()
    prov.stop()
    assert prov.accesses
    prov.reset()
    assert prov.accesses == [] and prov.offsets_read == set()
    with pytest.raises(ValueError):
        InputProvenance(t, base=DATA, length=0)


def test_reads_outside_the_buffer_are_not_recorded():
    t = make_x64(end=0x1025)
    # Watch a window that the program never reads.
    prov = InputProvenance(t, base=DATA + 0x100, length=16)
    prov.start()
    t.run()
    prov.stop()
    assert prov.accesses == [] and prov.unread_ranges() == [(0, 15)]


def test_loaders_read_the_declared_input_region(tmp_path):
    from ghidraunicorn import loaders
    harness = tmp_path / 'h.py'
    harness.write_text(
        'from unicorn import UC_ARCH_X86, UC_MODE_64, Uc\n'
        'from unicorn.x86_const import UC_X86_REG_RIP\n'
        'INPUT_BASE = 0x300000\n'
        'INPUT_SIZE = 0x1000\n'
        'def create(input_file=None):\n'
        '    uc = Uc(UC_ARCH_X86, UC_MODE_64)\n'
        '    uc.mem_map(0x100000, 0x1000)\n'
        '    uc.mem_map(0x300000, 0x1000)\n'
        '    uc.reg_write(UC_X86_REG_RIP, 0x100000)\n'
        '    return uc\n')
    loaded = loaders.load_harness(str(harness))
    assert loaded.input_region == (0x300000, 0x1000)

    # The tuple form works too, and a harness that says nothing reports None.
    harness2 = tmp_path / 'h2.py'
    harness2.write_text(harness.read_text().replace(
        'INPUT_BASE = 0x300000\nINPUT_SIZE = 0x1000',
        'INPUT_REGION = (0x300000, 0x40)'))
    assert loaders.load_harness(str(harness2)).input_region == (0x300000, 0x40)
    harness3 = tmp_path / 'h3.py'
    harness3.write_text(harness.read_text().replace(
        'INPUT_BASE = 0x300000\nINPUT_SIZE = 0x1000\n', ''))
    assert loaders.load_harness(str(harness3)).input_region is None
