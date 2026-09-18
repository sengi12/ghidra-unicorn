import importlib.util
import os
import struct

import pytest

from ghidraunicorn.coverage import DrcovWriter, SessionCoverage
from ghidraunicorn.loaders import Module

from test_target import CODE, DATA, make_x64


def parse(data: bytes):
    """A minimal drcov reader, deliberately independent of the writer."""
    split = data.index(b'BB Table:')
    end_of_line = data.index(b'\n', split)
    header = data[:end_of_line].decode()
    count = int(header.rsplit('BB Table:', 1)[1].split('bbs')[0].strip())
    body = data[end_of_line + 1:]
    assert len(body) == count * 8, 'BB table length must match the declared count'
    blocks = [struct.unpack_from('<IHH', body, i * 8) for i in range(count)]
    modules = {}
    for line in header.splitlines():
        line = line.strip()
        if line and line[0].isdigit() and ',' in line:
            fields = [f.strip() for f in line.split(',')]
            modules[int(fields[0])] = (int(fields[1], 16), int(fields[2], 16), fields[6])
    return header, modules, blocks


def test_writer_format_and_dedup():
    w = DrcovWriter()
    mid = w.add_module('/tmp/prog', 0x400000, 0x401000)
    w.add_block(mid, 0x10, 0x20)
    w.add_block(mid, 0x10, 0x20)          # a repeat collapses
    w.add_block(mid, 0x40, 0x8)
    assert w.block_count() == 2
    header, modules, blocks = parse(w.to_bytes())
    assert header.startswith('DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n')
    assert 'Columns: id, base, end, entry, checksum, timestamp, path' in header
    assert modules[0] == (0x400000, 0x401000, '/tmp/prog')
    assert sorted(blocks) == [(0x10, 0x20, 0), (0x40, 0x8, 0)]
    # Deterministic output.
    assert w.to_bytes() == w.to_bytes()


def test_writer_rejects_bad_module():
    w = DrcovWriter()
    with pytest.raises(ValueError):
        w.add_module('x', 0x1000, 0x1000)


def test_records_blocks_from_a_real_run(tmp_path):
    t = make_x64(end=0x1025)
    cov = SessionCoverage(t, [Module('/tmp/prog', CODE, 0x1000)])
    cov.start()
    assert cov.recording
    t.run()
    cov.stop()
    assert not cov.recording
    assert cov.block_count >= 1
    out = tmp_path / 'run.drcov'
    n = cov.save(str(out))
    header, modules, blocks = parse(out.read_bytes())
    assert n == len(blocks)
    assert modules[0] == (CODE, CODE + 0x1000, '/tmp/prog')
    # Every block is inside the module and its offset is relative to the base.
    for start, size, module_id in blocks:
        assert module_id == 0 and 0 <= start < 0x1000 and size > 0
    # The first block executed starts at the entry point.
    assert min(b[0] for b in blocks) == 0


def test_blocks_outside_a_module_become_a_region(tmp_path):
    t = make_x64(end=0x1025)
    # Declare a module that covers nothing the program executes.
    cov = SessionCoverage(t, [Module('/tmp/other', 0x2000, 0x1000)])
    cov.start()
    t.run()
    cov.stop()
    header, modules, blocks = parse(cov.to_writer().to_bytes())
    paths = {m[2] for m in modules.values()}
    assert '/tmp/other' in paths
    assert any(p.startswith('region_') for p in paths), paths
    assert cov.dropped == 0


def test_blocks_can_be_dropped_instead(tmp_path):
    t = make_x64(end=0x1025)
    cov = SessionCoverage(t, [Module('/tmp/other', 0x2000, 0x1000)],
                          fallback_regions=False)
    cov.start()
    t.run()
    cov.stop()
    w = cov.to_writer()
    assert w.block_count() == 0 and cov.dropped > 0


def test_reset_and_stats():
    t = make_x64(end=0x1025)
    cov = SessionCoverage(t, [Module('/tmp/prog', CODE, 0x1000)])
    cov.start()
    t.run()
    cov.stop()
    assert cov.stats()['/tmp/prog'] == cov.block_count
    cov.reset()
    assert cov.block_count == 0 and cov.to_writer().block_count() == 0


def test_module_spec_forms_are_accepted():
    t = make_x64()
    from ghidraunicorn.coverage import _normalise
    assert _normalise([Module('a', 0x1000, 0x100)]) == [('a', 0x1000, 0x1100)]
    assert _normalise([('b', 0x1000, 0x100)]) == [('b', 0x1000, 0x1100)]
    assert _normalise([('c', 0x1000, 0x2000)]) == [('c', 0x1000, 0x2000)]


@pytest.mark.skipif(not os.getenv('AFL_UNICORN_DIR'), reason='AFL_UNICORN_DIR unset')
def test_byte_identical_to_afl_unicorns_writer(tmp_path):
    """Our files must be interchangeable with afl-unicorn's, which is what
    ghidra-aflcov, Lighthouse and Dragondance already read."""
    path = os.path.join(os.getenv('AFL_UNICORN_DIR'), 'unicorn_mode',
                        'helper_scripts', 'drcov.py')
    if not os.path.isfile(path):
        pytest.skip('afl-unicorn drcov.py not found')
    spec = importlib.util.spec_from_file_location('afl_drcov', path)
    afl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(afl)

    theirs = afl.DrcovWriter()
    mid = theirs.add_module('target.bin', 0x400000, 0x452000)
    ours = DrcovWriter()
    ours.add_module('target.bin', 0x400000, 0x452000)
    for start, size in [(0x1000, 0x20), (0x1020, 0x10), (0x1234, 0x8)]:
        theirs.add_block(mid, start, size)
        ours.add_block(0, start, size)
    assert ours.to_bytes() == theirs.to_bytes()


@pytest.mark.skipif(not os.getenv('AFL_UNICORN_DIR'), reason='AFL_UNICORN_DIR unset')
def test_triage_writes_one_drcov_per_input(tmp_path):
    """Replaying a crash should leave a coverage file aflcov can paint."""
    from ghidraunicorn.triage import triage_inputs
    root = os.getenv('AFL_UNICORN_DIR')
    sample = os.path.join(root, 'unicorn_mode', 'samples', 'simple')
    inputs = os.path.join(sample, 'sample_inputs')
    harness = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'examples', 'afl_unicorn_simple.py')
    if not os.path.isdir(inputs):
        pytest.skip('sample inputs missing')
    out = tmp_path / 'cov'
    report = triage_inputs(harness, [inputs], coverage_dir=str(out), limit=2)
    assert len(report.results) == 2
    for r in report.results:
        assert r.blocks > 0, r.path
        assert os.path.isfile(r.coverage_path)
        header, modules, blocks = parse(open(r.coverage_path, 'rb').read())
        assert len(blocks) == r.blocks
        # The module is the sample binary, and every block sits inside it.
        assert any('simple_target.bin' in m[2] for m in modules.values()), modules
    # Names with commas and colons are made filesystem-safe.
    assert all(',' not in os.path.basename(r.coverage_path) for r in report.results)
