"""What can be checked about the Ghidra scripts without a Ghidra.

They cannot be imported here: their first statements are `from java.awt
import ...`. But two things about them can still be pinned down, and both
are things that have already gone wrong once:

* `TraceSource` has to provide everything `Context` renders from. That list
  is written down in `context.py`, and a rename on either side would part
  them silently, because nothing here imports the script.
* Nothing in a PyGhidra script may subclass a Java class. JPype refuses -
  "Java classes cannot be extended in Python" - and the first version of the
  panel subclassed `docking.ComponentProvider`, which would have thrown the
  moment anybody ran it.
"""
import ast
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, 'ghidra_scripts')
PANEL = os.path.join(SCRIPTS, 'UnicornContextPanel.py')

#: The surface `context.py` documents as what it renders from.
SURFACE = {'pc', 'sp', 'regs', 'reg_read', 'read', 'regions', 'decode',
           'fields'}
ATTRIBUTES = {'breakpoints', 'spec'}

#: Java packages a script may import from. Anything from one of these is a
#: Java class, and a class from one of these may not be subclassed.
JAVA_ROOTS = ('java', 'javax', 'ghidra', 'docking', 'generic', 'db', 'utility')


def parsed(path):
    with open(path) as f:
        return ast.parse(f.read(), filename=path)


def classes(tree):
    return {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}


def methods(node):
    return {n.name for n in node.body if isinstance(n, ast.FunctionDef)}


def java_names(tree):
    """Everything imported from a Java package."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split('.')[0] in JAVA_ROOTS:
                out.update(alias.asname or alias.name for alias in node.names)
    return out


def test_the_panel_parses():
    assert classes(parsed(PANEL)), 'no classes in the panel at all'


def test_trace_source_provides_what_the_context_renders_from():
    node = classes(parsed(PANEL))['TraceSource']
    missing = SURFACE - methods(node)
    assert not missing, f'TraceSource is missing {sorted(missing)}'


def test_trace_source_sets_the_attributes_the_context_reads():
    node = classes(parsed(PANEL))['TraceSource']
    assigned = set()
    for statement in ast.walk(node):
        if isinstance(statement, ast.Attribute) and isinstance(statement.ctx, ast.Store):
            assigned.add(statement.attr)
    missing = ATTRIBUTES - assigned
    assert not missing, f'TraceSource never sets {sorted(missing)}'


def test_the_surface_matches_what_context_actually_uses():
    """If `context.py` starts using something new, this says so."""
    import re
    with open(os.path.join(ROOT, 'ghidraunicorn', 'context.py')) as f:
        source = f.read()
    used = set(re.findall(r'\b(?:t|self\.target)\.([a-zA-Z_]+)', source))
    assert used <= SURFACE | ATTRIBUTES, \
        f'context.py now also uses {sorted(used - SURFACE - ATTRIBUTES)}; ' \
        f'the panel has to provide it too'


@pytest.mark.parametrize('name', sorted(
    f for f in os.listdir(SCRIPTS) if f.endswith('.py')))
def test_no_script_subclasses_a_java_class(name):
    """JPype cannot extend Java classes, only implement interfaces."""
    tree = parsed(os.path.join(SCRIPTS, name))
    java = java_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            base_name = base.id if isinstance(base, ast.Name) else \
                getattr(base, 'attr', '')
            assert base_name not in java, (
                f'{name}: class {node.name} extends the Java class '
                f'{base_name}, which JPype refuses at run time')
