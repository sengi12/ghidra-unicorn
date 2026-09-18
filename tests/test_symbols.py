import io
import json

import pytest

from ghidraunicorn.context import Context
from ghidraunicorn.symbols import Symbol, SymbolTable

from test_target import CODE, make_x64


def table():
    return SymbolTable([
        Symbol('main', 0x1000, 0x20, 'function'),
        Symbol('helper', 0x1030, 0x10, 'function'),
        Symbol('a_label', 0x2000),
    ], image_base=0x1000)


def test_lookup_by_name_is_case_insensitive_as_a_fallback():
    t = table()
    assert t.address_of('main') == 0x1000
    assert t.address_of('MAIN') == 0x1000
    assert t.address_of('nope') is None
    assert len(t) == 3 and bool(t)


def test_describe_inside_and_outside():
    t = table()
    assert t.describe(0x1000) == 'main'
    assert t.describe(0x1008) == 'main+0x8'
    assert t.describe(0x101f) == 'main+0x1f'
    # Past the end of a sized function, nothing claims it.
    assert t.describe(0x1020) is None
    assert t.describe(0x1030) == 'helper'
    # A sizeless label describes forward up to max_offset.
    assert t.describe(0x2004) == 'a_label+0x4'
    assert t.describe(0x2004, max_offset=2) is None
    # Before every symbol.
    assert t.describe(0x100) is None


def test_functions_win_over_labels_at_one_address():
    t = SymbolTable([Symbol('zz_label', 0x400), Symbol('aa_func', 0x400, 8, 'function')])
    assert t.describe(0x400) == 'aa_func'


def test_an_enclosing_function_beats_a_nearer_label():
    # Ghidra exports generated labels inside functions; an address in the body
    # of main should read as main+off, the way gdb and IDA report it.
    t = SymbolTable([Symbol('main', 0x100000, 252, 'function'),
                     Symbol('LAB_0010003c', 0x10003c)])
    assert t.describe(0x100040) == 'main+0x40'
    assert t.describe(0x10003c) == 'main+0x3c'
    # Past the end of main, the label no longer applies either.
    assert t.describe(0x100000 + 252) is None
    assert t.enclosing(0x100040)[0].name == 'main'
    assert t.enclosing(0x200000) is None


def test_rebase():
    t = table().rebase(0x400000)
    assert t.address_of('main') == 0x400000
    assert t.describe(0x400008) == 'main+0x8'
    assert t.image_base == 0x400000
    assert table().rebase(0x1000) is not None


def test_json_round_trip(tmp_path):
    path = tmp_path / 'syms.json'
    n = table().save(str(path))
    assert n == 3
    data = json.loads(path.read_text())
    assert data['image_base'] == 0x1000
    again = SymbolTable.load(str(path))
    assert again.to_dict() == table().to_dict()
    assert again.describe(0x1008) == 'main+0x8'


def test_from_dict_tolerates_missing_fields():
    t = SymbolTable.from_dict({'symbols': [{'name': 'x', 'address': 16}]})
    assert t.describe(16) == 'x' and t.image_base == 0


def test_context_annotates_with_symbols():
    target = make_x64()
    syms = SymbolTable([Symbol('entry', CODE, 0x30, 'function')])
    plain = Context(target, io.StringIO(), color=False).render()
    assert '<entry>' not in plain
    named = Context(target, io.StringIO(), color=False, symbols=syms).render()
    assert f'{CODE:#x} <entry>' in named
    assert '<entry+0x7>' in named
