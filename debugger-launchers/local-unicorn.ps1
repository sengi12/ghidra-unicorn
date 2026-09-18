## ###
# ghidra-unicorn: run a Unicorn harness or an afl-unicorn context dump as a
# Ghidra Debugger target. This is the Windows (PowerShell) twin of
# local-unicorn.sh; the options and their defaults are identical.
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
#@env OPT_REGS:str="" "Registers" "Initial register overrides, e.g. cpsr=0x60000030,r0=1 (flags like ZF=1 work too)."
#@env OPT_SYSCALLS:bool=true "System calls" "Service the program's system calls with a small Linux layer (read, write, open, mmap, brk, exit) instead of faulting on the trap."
#@env OPT_STDIN:file="" "Standard input" "File whose contents the program reads from file descriptor 0. No other host file is visible to it."
#@env OPT_STUBS:bool=true "Function stubs" "Stand in for malloc, free and the common string and memory functions, at the addresses the symbols give them."
#@env OPT_TRACE_CALLS:bool=false "Trace calls" "Print every system call and stub as it happens."
#@env OPT_PRELOAD:bool=true "Preload memory" "Copy all mapped memory into the trace at launch (capped at 32 MiB)."
#@env OPT_PYTHON_EXE:file="python3" "python command" "Python 3 with unicorn (and protobuf) installed. Omit the path to resolve using PATH."

# Ghidra runs a launcher with its own directory as the working directory.
$here = $PSScriptRoot
$repo = (Resolve-Path "$here\..").Path

# setuputils.ps1 ships with Ghidra and knows both the installed
# (pypkg\src) and development (build\pypkg\src) layouts.
. "$Env:MODULE_Debugger_rmi_trace_HOME\data\support\setuputils.ps1"
$pypathTrace = Ghidra-Module-PyPath "Debugger-rmi-trace"

# ghidratrace ships with Ghidra; ghidraunicorn is this checkout.
$Env:PYTHONPATH = "$repo;$pypathTrace;$Env:PYTHONPATH"

function Test-Unicorn-Python {
	param([string]$Exe)
	if (-not $Exe) {
		return $false
	}
	& $Exe -c "import unicorn" 2>$null
	return $LASTEXITCODE -eq 0
}

# With the default "python3", prefer an interpreter that has unicorn installed:
# a .venv in this checkout, then a pyenv-win virtualenv named "ghidra". If
# neither has it, fall back to whatever "python3" or "python" resolves to on
# PATH -- on Windows "python3" is often only the Microsoft Store stub.
$python = $Env:OPT_PYTHON_EXE
if ($python -eq "python3") {
	$candidates = @(
		"$repo\.venv\Scripts\python.exe",
		"$Env:USERPROFILE\.pyenv\pyenv-win\versions\ghidra\python.exe"
	)
	foreach ($candidate in $candidates) {
		if ((Test-Path -LiteralPath $candidate) -and (Test-Unicorn-Python $candidate)) {
			$python = $candidate
			break
		}
	}
	if ($python -eq "python3" -and -not (Get-Command "python3" -ErrorAction SilentlyContinue)) {
		$python = "python"
	}
}
Write-Host "ghidra-unicorn: using $python"

Start-Process -FilePath $python -ArgumentList @("-m", "ghidraunicorn") -NoNewWindow -Wait
