#!/usr/bin/env bash
## ###
# ghidra-unicorn: run a Unicorn harness or an afl-unicorn context dump as a
# Ghidra Debugger target.
#
# Ghidra finds this file when the directory containing it is listed in
# Debugger -> Options -> "Paths to search for user-created debugger launchers".
##
#@title unicorn
#@desc <html><body width="300px">
#@desc   <h3>Emulate with <tt>unicorn</tt></h3>
#@desc   <p>
#@desc     Runs a Python harness (a file defining <tt>create(input_file)</tt> that
#@desc     returns a <tt>unicorn.Uc</tt>) or an afl-unicorn context directory
#@desc     inside Unicorn Engine, and connects it to the Debugger. Step, set
#@desc     breakpoints and watchpoints, edit registers and memory, and read the
#@desc     crash state from a fuzzing run.
#@desc   </p>
#@desc </body></html>
#@menu-group unicorn
#@icon icon.debugger
#@depends Debugger-rmi-trace
#@image-opt env:OPT_TARGET_IMG
#@env OPT_TARGET_IMG:file="" "Image" "The program being emulated; names the module so Ghidra can map it to this listing."
#@env OPT_HARNESS:file="" "Harness" "Python file defining create(input_file) -> unicorn.Uc. Leave empty to use a context directory."
#@env OPT_CONTEXT_DIR:dir="" "afl-unicorn context" "Directory written by unicorn_dumper_*.py (_index.json + segments)."
#@env OPT_INPUT:file="" "Input" "Input file passed to the harness's create()."
#@env OPT_START:str="" "Start" "Address to start at (hex). Empty: the PC the harness or dump set."
#@env OPT_END:str="" "End" "Address that ends the run (hex). Empty: the harness's END, if any."
#@env OPT_SYMBOLS:file="" "Symbols" "JSON from tools/export_symbols.py: names for addresses, and `b main` in the console."
#@env OPT_SYMBOLS_AT:str="" "Symbols base" "Rebase those symbols so their image base lands at this address (hex)."
#@env OPT_REGS:str="" "Registers" "Initial register overrides, e.g. cpsr=0x60000030,r0=1 (flags like ZF=1 work too)."
#@env OPT_PRELOAD:bool=true "Preload memory" "Copy all mapped memory into the trace at launch (capped at 32 MiB)."
#@env OPT_PYTHON_EXE:file="python3" "python command" "Python 3 with unicorn (and protobuf) installed. Omit the path to resolve using PATH."

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

# ghidratrace ships with Ghidra; ghidraunicorn is this checkout.
export PYTHONPATH="$repo:$MODULE_Debugger_rmi_trace_HOME/pypkg/src:$PYTHONPATH"

# With the default "python3", prefer an interpreter that has unicorn installed:
# a .venv in this checkout, then a pyenv virtualenv named "ghidra".
python="$OPT_PYTHON_EXE"
if [ "$python" = "python3" ]; then
	for candidate in "$repo/.venv/bin/python" "$HOME/.pyenv/versions/ghidra/bin/python"; do
		if [ -x "$candidate" ] && "$candidate" -c 'import unicorn' 2>/dev/null; then
			python="$candidate"
			break
		fi
	done
fi
echo "ghidra-unicorn: using $python"

exec "$python" -m ghidraunicorn
