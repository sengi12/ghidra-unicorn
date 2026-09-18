"""PYTHONPATH bootstrap for local-unicorn.bat.

A .bat file cannot work out where Ghidra put a module's Python sources: the
module may be installed (``pypkg/src``) or a development build
(``build/pypkg/src``). Ghidra's own Windows launchers solve this by invoking a
small Python script that imports ``gmodutils`` from the Debugger-rmi-trace
module and asks it, and this file does the same before handing control to
``ghidraunicorn.__main__``.

Not a launcher itself: Ghidra only scans a launcher directory for *.sh, *.bat,
*.ps1 and *.jsh, so this file is invisible to the Launch menu. Everything it
needs beyond the module home comes from the OPT_* environment variables that
local-unicorn.bat's header declares. The PowerShell twin, local-unicorn.ps1,
has no use for this file: setuputils.ps1 answers the same question there.
"""
import os
import runpy
import sys


def append_paths() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    # ghidraunicorn is this checkout; it wins over anything installed.
    sys.path.insert(0, repo)
    sys.path.append(f"{os.getenv('MODULE_Debugger_rmi_trace_HOME')}/data/support")
    try:
        from gmodutils import ghidra_module_pypath
        sys.path.append(ghidra_module_pypath('Debugger-rmi-trace'))
    except Exception as e:
        # ghidratrace may still be importable from a pip install.
        print(f'ghidra-unicorn: could not locate ghidratrace via gmodutils: {e}',
              file=sys.stderr)


def main() -> None:
    append_paths()
    runpy.run_module('ghidraunicorn', run_name='__main__', alter_sys=True)


if __name__ == '__main__':
    main()
