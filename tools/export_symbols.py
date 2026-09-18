"""Export a Ghidra program's symbols for ghidra-unicorn.

Writes the JSON that `ghidraunicorn.symbols.SymbolTable` reads, so the console
can take `b main` and the context can print `0x100448 <main+8>`.

    GHIDRA_INSTALL_DIR=... python tools/export_symbols.py \\
        ~/ghidra_projects/unicorn/unicorn.gpr simple_target.bin symbols.json

The program argument is the name inside the project. Needs pyghidra.
"""
import json
import os
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    gpr = os.path.abspath(sys.argv[1])
    program_name = sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else 'symbols.json'
    if not gpr.endswith('.gpr'):
        raise SystemExit('first argument must be a .gpr project file')
    projdir = os.path.dirname(gpr)
    projname = os.path.basename(gpr)[:-4]

    import pyghidra
    pyghidra.start()
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.symbol import SymbolType

    gp = GhidraProject.openProject(projdir, projname, True)
    try:
        program = gp.openProgram('/', program_name, True)
        try:
            image_base = int(program.getImageBase().getOffset())
            rows = []
            seen = set()
            for f in program.getFunctionManager().getFunctions(True):
                addr = int(f.getEntryPoint().getOffset())
                size = int(f.getBody().getNumAddresses())
                rows.append({'name': str(f.getName()), 'address': addr,
                             'size': size, 'kind': 'function'})
                seen.add(addr)
            table = program.getSymbolTable()
            for s in table.getAllSymbols(True):
                if s.getSymbolType() != SymbolType.LABEL:
                    continue
                addr = int(s.getAddress().getOffset())
                if addr in seen:
                    continue
                rows.append({'name': str(s.getName()), 'address': addr,
                             'size': 0, 'kind': 'label'})
            rows.sort(key=lambda r: (r['address'], r['name']))
            with open(out, 'w') as fh:
                json.dump({'image_base': image_base, 'symbols': rows}, fh, indent=1)
            functions = sum(1 for r in rows if r['kind'] == 'function')
            print(f'wrote {out}: {len(rows)} symbols ({functions} functions), '
                  f'image base {image_base:#x}')
        finally:
            gp.close(program)
    finally:
        try:
            gp.close()
        except Exception as e:
            print(f'(close: {e})')
    print('Use it with:  --symbols ' + out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
