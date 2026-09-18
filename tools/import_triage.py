"""Paint a triage report onto a Ghidra program: a bookmark and a comment per
crash address.

    python -m ghidraunicorn.triage --harness H --inputs output/crashes --json t.json
    GHIDRA_INSTALL_DIR=... JAVA_HOME=... \
        python tools/import_triage.py --json t.json \
            --project ~/ghidra_projects/unicorn --program simple_target.bin

Every distinct crash signature in the report becomes, at its faulting address:

* a bookmark (type *Note*, category ``Crash`` by default) so the whole set is
  one click away in Ghidra's Bookmarks window, sorted by category; and
* an EOL comment (``--comment plate`` for a plate comment instead), saying how
  many inputs land there, how they fail, what the instruction tried to touch,
  and which input to replay in the Debugger.

Re-running replaces what a previous run wrote rather than piling up: every line
this tool adds is tagged with ``TAG``.

Addresses come from the emulated run. If the harness loads the code at a
different base than the program's image base, give ``--offset`` the difference
(program address = triage pc + offset).

Needs pyghidra (``pip install --no-index -f
$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist pyghidra``), like
tools/setup_project.py, which this follows for opening and saving a project.
``--dry-run`` prints what would be written and needs no Ghidra at all.
"""
import argparse
import json
import os
import sys

#: Marker on every line this tool writes, so a re-run can replace them.
TAG = 'afl-unicorn triage:'


def load_report(path):
    with open(path) as f:
        doc = json.load(f)
    if 'groups' not in doc:
        raise SystemExit(f'{path} does not look like a triage report (no "groups")')
    return doc


def annotation_text(group, offset=0):
    """The comment written at one crash address."""
    count = group.get('count', 0)
    plural = 'input' if count == 1 else 'inputs'
    kind = group.get('kind') or group.get('outcome', '?')
    head = f'{TAG} {group.get("outcome", "?")}: {count} {plural} ({kind})'
    lines = [head]
    fault = group.get('fault') or {}
    if fault.get('address_hex'):
        access = fault.get('access') or 'access'
        size = fault.get('size')
        size_text = f', {size} bytes' if size else ''
        lines.append(f'{TAG}   {access} of {fault["address_hex"]}{size_text}')
    insn = group.get('instruction') or {}
    if insn.get('text'):
        lines.append(f'{TAG}   {insn["text"]}')
    rep = group.get('representative')
    if rep:
        lines.append(f'{TAG}   replay: {os.path.basename(rep)}')
    lines.append(f'{TAG}   signature: {group.get("signature", "")}')
    return '\n'.join(lines)


def plan_annotations(doc, offset=0, crashes_only=True):
    """[(address, count, outcome, text)] for the groups worth marking.

    Groups with no faulting address (a harness that never built an engine) are
    dropped; several groups at one address are merged into one annotation, in
    report order.
    """
    by_address = {}
    order = []
    for g in doc.get('groups', []):
        if g.get('pc') is None:
            continue
        if crashes_only and g.get('outcome') != 'crash':
            continue
        address = g['pc'] + offset
        if address not in by_address:
            by_address[address] = {'count': 0, 'outcomes': [], 'texts': []}
            order.append(address)
        entry = by_address[address]
        entry['count'] += g.get('count', 0)
        entry['outcomes'].append(g.get('outcome', '?'))
        entry['texts'].append(annotation_text(g, offset))
    plan = []
    for address in order:
        e = by_address[address]
        plan.append((address, e['count'], e['outcomes'][0], '\n'.join(e['texts'])))
    return plan


def strip_tagged(comment):
    """A previous run's lines out of an existing comment."""
    if not comment:
        return ''
    kept = [ln for ln in str(comment).splitlines() if TAG not in ln]
    return '\n'.join(kept).strip()


# ---------------------------------------------------------------------------
# Ghidra


def comment_types():
    """(eol, plate) comment selectors, whichever API this Ghidra has."""
    try:                                    # Ghidra 11.4+/12.x
        from ghidra.program.model.listing import CommentType
        return CommentType.EOL, CommentType.PLATE
    except ImportError:                     # older releases
        from ghidra.program.model.listing import CodeUnit
        return CodeUnit.EOL_COMMENT, CodeUnit.PLATE_COMMENT


def annotate(program, plan, comment='eol', category='Crash'):
    """Write the plan into an open program. Returns (written, skipped)."""
    from ghidra.program.model.listing import BookmarkType

    eol, plate = comment_types()
    kind = plate if comment == 'plate' else eol
    listing = program.getListing()
    bookmarks = program.getBookmarkManager()
    space = program.getAddressFactory().getDefaultAddressSpace()
    memory = program.getMemory()

    written, skipped = [], []
    txid = program.startTransaction('afl-unicorn triage')
    try:
        for address, count, outcome, text in plan:
            addr = space.getAddress(address)
            if not memory.contains(addr):
                skipped.append((address, 'not in program memory'))
                continue
            for existing in bookmarks.getBookmarks(addr, BookmarkType.NOTE):
                if existing.getCategory() == category:
                    bookmarks.removeBookmark(existing)
            label = f'{count} input{"" if count == 1 else "s"} {outcome}'
            bookmarks.setBookmark(addr, BookmarkType.NOTE, category, label)
            if comment != 'none':
                old = strip_tagged(listing.getComment(kind, addr))
                listing.setComment(addr, kind, (text + ('\n' + old if old else '')))
            written.append((address, label))
    finally:
        program.endTransaction(txid, True)
    return written, skipped


def run_ghidra(args, plan):
    import pyghidra
    pyghidra.start()
    from ghidra.base.project import GhidraProject

    projdir = os.path.abspath(os.path.expanduser(args.project))
    name = args.project_name or os.path.basename(projdir.rstrip(os.sep))
    if not os.path.exists(os.path.join(projdir, name + '.gpr')):
        raise SystemExit(f'no Ghidra project {name}.gpr in {projdir}')
    gp = GhidraProject.openProject(projdir, name, True)
    program = None
    try:
        folder, _, progname = args.program.rpartition('/')
        program = gp.openProgram(folder + '/' if folder else '/', progname, False)
        written, skipped = annotate(program, plan, args.comment, args.category)
        for address, label in written:
            print(f'  {address:#010x}  {label}')
        for address, why in skipped:
            print(f'  {address:#010x}  skipped: {why}', file=sys.stderr)
        if written:
            gp.save(program)
        print(f'{len(written)} address(es) annotated in {args.program}'
              + (f', {len(skipped)} skipped' if skipped else ''))
        return 0 if written or not plan else 1
    finally:
        try:
            if program is not None:
                gp.close(program)
        except Exception:
            pass
        try:
            gp.close()
        except Exception as e:      # Ghidra can complain about a spent transaction
            print(f'(close: {e})')


def build_parser():
    p = argparse.ArgumentParser(
        prog='import_triage.py',
        description='Bookmark and comment a Ghidra program from a triage report.')
    p.add_argument('--json', required=True, metavar='FILE',
                   help='report from `python -m ghidraunicorn.triage --json`')
    p.add_argument('--project', help='Ghidra project directory (holds NAME.gpr)')
    p.add_argument('--project-name', help='project name, if not the directory name')
    p.add_argument('--program', help='program in the project, e.g. simple_target.bin')
    p.add_argument('--comment', choices=('eol', 'plate', 'none'), default='eol',
                   help='comment style to write at each crash (default eol)')
    p.add_argument('--category', default='Crash', help='bookmark category (default Crash)')
    p.add_argument('--offset', default='0',
                   help='program address = triage pc + this (default 0)')
    p.add_argument('--all-outcomes', action='store_true',
                   help='also mark timeouts and clean exits, not just crashes')
    p.add_argument('--dry-run', action='store_true',
                   help='print the annotations instead of opening Ghidra')
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    doc = load_report(args.json)
    plan = plan_annotations(doc, int(str(args.offset), 0),
                            crashes_only=not args.all_outcomes)
    print(f'{len(plan)} address(es) from {args.json} '
          f'({doc.get("inputs", "?")} inputs, {len(doc.get("groups", []))} signatures)')
    if args.dry_run:
        for address, count, outcome, text in plan:
            print(f'\n{address:#010x}  [{count} {outcome}]')
            for line in text.splitlines():
                print(f'    {line}')
        return 0
    if not args.project or not args.program:
        raise SystemExit('--project and --program are required (or use --dry-run)')
    return run_ghidra(args, plan)


if __name__ == '__main__':
    sys.exit(main())
