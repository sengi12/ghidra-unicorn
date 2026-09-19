"""The object schema, and what the connector publishes into it.

Ghidra validates every value against `schema.xml`. A schema whose catch-all
is `VOID` accepts nothing it has not declared, so an attribute published but
not declared there is rejected at run time - and only a run against a real
Ghidra would show it. These checks are what can be done without one.
"""
import os
import re
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, 'ghidraunicorn', 'schema.xml')
COMMANDS = os.path.join(ROOT, 'ghidraunicorn', 'commands.py')

#: Attributes published on an object whose schema has an `ANY` catch-all,
#: which accepts them without a declaration. Each one is named here so that
#: relying on the catch-all is a decision rather than an oversight.
UNDECLARED = {
    # On Process, which is `ANY`: where the target is in its own history.
    'Instruction',
}


@pytest.fixture(scope='module')
def schema():
    return ET.parse(SCHEMA).getroot()


def declared(schema):
    return {a.get('name') for s in schema.iter('schema')
            for a in s.findall('attribute') if a.get('name')}


def published():
    """Every attribute name commands.py writes into the trace."""
    with open(COMMANDS) as f:
        return set(re.findall(r"set_value\('([^']+)'", f.read()))


def test_the_schema_is_well_formed(schema):
    assert schema.tag == 'context'
    assert {s.get('name') for s in schema.iter('schema')} >= {
        'UnicornRoot', 'Process', 'Thread', 'BreakpointSpec'}


def test_every_published_attribute_is_declared_or_deliberately_not(schema):
    names = published()
    assert names, 'nothing is published at all; the regex must have broken'
    unknown = names - declared(schema) - UNDECLARED
    assert not unknown, (
        f'{sorted(unknown)} published but not declared in schema.xml. '
        f'Declare them, or add them to UNDECLARED if the object they go on '
        f'has an ANY catch-all.')


def test_the_conditional_breakpoint_attributes_are_declared(schema):
    """These two are what a conditional breakpoint shows in Ghidra, and
    BreakpointSpec's catch-all is VOID, so they have to be declared."""
    spec = [s for s in schema.iter('schema')
            if s.get('name') == 'BreakpointSpec'][0]
    names = {a.get('name') for a in spec.findall('attribute')}
    assert {'Condition', 'Ignore Count', 'Hit Count'} <= names
    catch_all = [a.get('schema') for a in spec.findall('attribute')
                 if not a.get('name')]
    assert catch_all == ['VOID'], \
        'BreakpointSpec no longer requires its attributes to be declared'


def test_the_names_are_ghidras_own(schema):
    """Spelled as Ghidra's gdb connector spells them; they are not
    guessable, and a wrong one is silently ignored rather than refused."""
    names = declared(schema)
    for name in ('Hit Count', 'Ignore Count', 'Condition', 'Expression',
                 'Kinds', 'Enabled', 'Temporary', 'Exit Code'):
        assert name in names, f'{name} is missing from schema.xml'


def test_every_schema_referenced_by_an_attribute_exists(schema):
    """A typo in a schema name would leave an object with no type at all."""
    defined = {s.get('name') for s in schema.iter('schema')}
    builtin = {'ANY', 'VOID', 'STRING', 'INT', 'LONG', 'BOOL', 'ADDRESS',
               'RANGE', 'EXECUTION_STATE', 'OBJECT', 'MAP_OBJECT', 'BYTE',
               'SHORT', 'CHAR', 'DOUBLE', 'FLOAT'}
    for element in schema.iter():
        if element.tag not in ('attribute', 'element'):
            continue
        referenced = element.get('schema')
        if referenced and referenced not in builtin:
            assert referenced in defined, \
                f'{element.tag} refers to schema {referenced}, which is not defined'
