"""Create a Ghidra project with afl-unicorn's simple_target.bin ready to debug.

Imports the raw MIPS32 big-endian blob at base 0x100000 (where the example
harness loads it), analyzes it, and saves the project, so the GUI steps in
the README start at "open the project".

    GHIDRA_INSTALL_DIR=... AFL_UNICORN_DIR=... python tools/setup_project.py [project_dir]

Default project_dir is ~/ghidra_projects/unicorn (project name "unicorn").
Needs pyghidra in the current Python.
"""
import os
import sys

CODE_BASE = 0x00100000


def main():
    afl = os.getenv('AFL_UNICORN_DIR')
    if not afl:
        raise SystemExit('set AFL_UNICORN_DIR to your afl-unicorn checkout')
    binary = os.path.join(afl, 'unicorn_mode', 'samples', 'simple', 'simple_target.bin')
    if not os.path.isfile(binary):
        raise SystemExit(f'{binary} not found')
    projdir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser('~/ghidra_projects/unicorn'))
    name = os.path.basename(projdir)
    os.makedirs(projdir, exist_ok=True)

    import pyghidra
    pyghidra.start()
    from java.io import File
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.lang import LanguageID
    from ghidra.program.util import DefaultLanguageService

    gpr = os.path.join(projdir, name + '.gpr')
    if os.path.exists(gpr):
        gp = GhidraProject.openProject(projdir, name, True)
        print(f'opened existing project {gpr}')
    else:
        gp = GhidraProject.createProject(projdir, name, False)
        print(f'created project {gpr}')
    try:
        existing = gp.getRootFolder().getFile('simple_target.bin')
        if existing is not None:
            print('simple_target.bin already in the project; nothing to do')
            return
        lang = DefaultLanguageService.getLanguageService().getLanguage(LanguageID('MIPS:BE:32:default'))
        program = gp.importProgram(File(binary), lang, lang.getDefaultCompilerSpec())
        txid = program.startTransaction('image base')
        try:
            base = program.getAddressFactory().getDefaultAddressSpace().getAddress(CODE_BASE)
            program.setImageBase(base, True)
        finally:
            program.endTransaction(txid, True)
        gp.analyze(program)
        gp.saveAs(program, '/', 'simple_target.bin', True)
        print(f'imported {os.path.basename(binary)} as MIPS:BE:32:default at {CODE_BASE:#x} and analyzed it')
    finally:
        try:
            gp.close()          # closes open programs and the project
        except Exception as e:  # Ghidra sometimes complains about a spent transaction here
            print(f'(close: {e})')
    print()
    print('Next: in Ghidra, File -> Open Project ->', gpr)


if __name__ == '__main__':
    main()
