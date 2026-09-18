"""End-to-end test against a real Ghidra: launch the unicorn offer and drive it.

Runs Ghidra in-process through PyGhidra with a headed configuration (a
Debugger tool needs Swing, but no window is shown), imports afl-unicorn's
simple_target.bin, launches this connector through the same launcher script a
user would pick from the Debugger's Launch menu, and then exercises the
remote methods over the Trace RMI protocol: step, breakpoint, resume,
interrupt, memory read, kill. It checks the trace Ghidra builds, not the
connector's own bookkeeping.

Needs: a display (macOS/Linux desktop), GHIDRA_INSTALL_DIR, JAVA_HOME with
JDK 21, a Python with pyghidra, unicorn, protobuf, capstone installed, and
AFL_UNICORN_DIR pointing at an afl-unicorn checkout.

    GHIDRA_INSTALL_DIR=... AFL_UNICORN_DIR=... python tools/e2e_ghidra.py
"""
import os
import sys
import tempfile
import threading
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(REPO, 'examples', 'afl_unicorn_simple.py')
CODE_BASE = 0x00100000
MAIN_END = CODE_BASE + 0xf4
TIMEOUT = float(os.getenv('E2E_TIMEOUT', '240'))

results = {'ok': None, 'error': None}


def log(msg: str) -> None:
    print(f'[e2e] {msg}', flush=True)


def sample_paths():
    afl = os.getenv('AFL_UNICORN_DIR')
    if not afl:
        raise SystemExit('set AFL_UNICORN_DIR')
    simple = os.path.join(afl, 'unicorn_mode', 'samples', 'simple')
    return os.path.join(simple, 'simple_target.bin'), os.path.join(simple, 'sample_inputs', 'sample1.bin')


def wait_until(pred, what: str, timeout: float = 30.0, interval: float = 0.25):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            v = pred()
            if v:
                return v
        except Exception as e:
            last = e
        time.sleep(interval)
    raise TimeoutError(f'timed out waiting for {what}'
                       + (f' (last error: {last!r})' if last else ''))


def run_checks():
    import jpype
    from java.io import File
    from java.lang import Runnable
    from java.util import HashMap
    from ghidra.base.project import GhidraProject
    from ghidra.program.model.lang import LanguageID
    from ghidra.program.util import DefaultLanguageService
    from ghidra.framework import ToolUtils
    from ghidra.util import Swing
    from ghidra.util.task import TaskMonitor
    from ghidra.app.services import ProgramManager, TraceRmiLauncherService
    from ghidra.app.plugin.core.debug import DebuggerPluginPackage
    from ghidra.trace.model.target.path import KeyPath

    binary, sample_input = sample_paths()
    with open(binary, 'rb') as f:
        code = f.read()

    projdir = tempfile.mkdtemp(prefix='ghidra-unicorn-e2e-')
    log(f'project in {projdir}')
    gp = GhidraProject.createProject(projdir, 'unicorn_e2e', False)
    lang = DefaultLanguageService.getLanguageService().getLanguage(LanguageID('MIPS:BE:32:default'))
    program = gp.importProgram(File(binary), lang, lang.getDefaultCompilerSpec())
    txid = program.startTransaction('image base')
    try:
        base = program.getAddressFactory().getDefaultAddressSpace().getAddress(CODE_BASE)
        program.setImageBase(base, True)
    finally:
        program.endTransaction(txid, True)
    log(f'imported {program.getName()} as {program.getLanguageID()} at {program.getImageBase()}')

    # Errors go to the console instead of modal dialogs nobody can click.
    try:
        from ghidra.util import Msg, ConsoleErrorDisplay
        Msg.setErrorDisplay(ConsoleErrorDisplay())
    except Exception as e:
        log(f'could not install console error display: {e}')

    # The stock Debugger tool includes the Eclipse and VS Code integration
    # plugins, which need a Front End window we do not have; drop them.
    from org.jdom2 import Element
    from ghidra.framework.project.tool import GhidraToolTemplate
    stock = next(t for t in ToolUtils.getDefaultApplicationTools() if str(t.getName()) == 'Debugger')
    tool_elem = stock.getToolElement()
    for pkg in tool_elem.getChildren('PACKAGE'):
        if str(pkg.getAttributeValue('NAME')) == 'Ghidra Core':
            for cls in ('ghidra.app.plugin.core.eclipse.EclipseIntegrationPlugin',
                        'ghidra.app.plugin.core.vscode.VSCodeIntegrationPlugin'):
                ex = Element('EXCLUDE')
                ex.setAttribute('CLASS', cls)
                pkg.addContent(ex)
    template = GhidraToolTemplate(stock.getIconURL(), tool_elem, stock.getSupportedDataTypes())
    holder = {}

    def make_tool():
        holder['tool'] = template.createTool(gp.getProject())
    Swing.runNow(Runnable @ make_tool)
    tool = holder['tool']
    log(f'created tool {tool.getName()}')
    show = os.getenv('E2E_SHOW')
    if show:
        Swing.runNow(Runnable @ (lambda: tool.setVisible(True)))

    opts = tool.getOptions(DebuggerPluginPackage.NAME)
    # TraceRmiLauncherServicePlugin.OPTION_NAME_SCRIPT_PATHS (protected)
    opts.setString('Script Paths', os.path.join(REPO, 'debugger-launchers'))
    pm = tool.getService(ProgramManager)
    Swing.runNow(Runnable @ (lambda: pm.openProgram(program)))

    svc = tool.getService(TraceRmiLauncherService)
    offers = wait_until(
        lambda: [o for o in svc.getOffers(program) if str(o.getTitle()) == 'unicorn'],
        'the unicorn launcher to be discovered', 30)
    offer = offers[0]
    log(f'offer: {offer.getTitle()} ({offer.getConfigName()})')
    params = offer.getParameters()
    log('parameters: ' + ', '.join(str(k) for k in params.keySet()))

    overrides = {
        'OPT_TARGET_IMG': binary,
        'OPT_HARNESS': HARNESS,
        'OPT_INPUT': sample_input,
        'OPT_PYTHON_EXE': sys.executable,
        'OPT_PRELOAD': 'true',
    }

    @jpype.JImplements('ghidra.debug.api.tracermi.TraceRmiLaunchOffer$LaunchConfigurator')
    class Configurator:
        @jpype.JOverride
        def configureLauncher(self, offer, arguments, relPrompt):
            args = HashMap(arguments)
            for name, value in overrides.items():
                key = 'env:' + name
                p = params.get(key)
                if p is None:
                    raise RuntimeError(f'launcher has no parameter {key}')
                args.put(key, p.decode(value))
            return args

    log('launching...')
    result = offer.launchProgram(TaskMonitor.DUMMY, Configurator())
    if result.exception() is not None:
        raise RuntimeError(f'launch failed: {result.exception()}')
    trace = result.trace()
    conn = result.connection()
    if trace is None or conn is None:
        raise RuntimeError('launch produced no trace/connection')
    log(f'trace: {trace.getName()} language {trace.getBaseLanguage().getLanguageID()}')

    om = trace.getObjectManager()

    def obj(path):
        return om.getObjectByCanonicalPath(KeyPath.parse(path))

    def snap():
        m = trace.getTimeManager().getMaxSnap()
        return 0 if m is None else int(m)

    def value(path, key):
        o = obj(path)
        if o is None:
            return None
        v = o.getValue(snap(), key)
        return None if v is None else v.getValue()

    def reg(name):
        thread = trace.getThreadManager().getAllThreads().iterator().next()
        space = trace.getMemoryManager().getMemoryRegisterSpace(thread, 0, False)
        r = trace.getBaseLanguage().getRegister(name)
        return int(space.getValue(snap(), r).getUnsignedValue().longValue())

    def mem(addr, n):
        from java.nio import ByteBuffer
        buf = ByteBuffer.allocate(n)
        a = trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(addr)
        got = trace.getMemoryManager().getBytes(snap(), a, buf)
        return bytes(buf.array())[:int(got)]

    wait_until(lambda: obj('Processes[0].Threads[0].Stack[0]') is not None, 'the frame object', 30)
    assert str(value('Processes[0]', 'State')) == 'STOPPED', value('Processes[0]', 'State')
    assert reg('pc') == CODE_BASE, hex(reg('pc'))
    assert reg('sp') == 0x00210000, hex(reg('sp'))
    # Preloaded memory arrives in a batch; wait for the last region.
    expect_in = open(sample_input, 'rb').read()[:4]
    wait_until(lambda: mem(CODE_BASE, 16) == code[:16] and mem(0x00300000, 4) == expect_in,
               'preloaded code and input bytes', 30)
    regions = obj('Processes[0].Memory')
    assert regions is not None
    modname = value('Processes[0].Modules[100000]', 'Name')
    assert modname is not None and str(modname).endswith('simple_target.bin'), modname
    log('initial state OK: PC, SP, code and input bytes, module')

    methods = conn.getMethods()
    names = {str(k) for k in methods.all().keySet()}
    for needed in ('resume', 'interrupt', 'step_into', 'step_over', 'break_sw_execute_address',
                   'read_mem', 'write_reg', 'kill'):
        assert needed in names, f'method {needed} missing; have {sorted(names)}'
    thread_obj = obj('Processes[0].Threads[0]')
    proc_obj = obj('Processes[0]')
    frame_obj = obj('Processes[0].Threads[0].Stack[0]')

    def invoke(_method, **kwargs):
        m = HashMap()
        for k, v in kwargs.items():
            m.put(k, v)
        return methods.get(_method).invoke(m)

    invoke('step_into', thread=thread_obj, n=jpype.JLong(1))
    wait_until(lambda: reg('pc') == CODE_BASE + 4, 'step_into to land', 20)
    assert str(value('Processes[0]', 'Reason')).startswith('Stepped'), value('Processes[0]', 'Reason')
    log(f'step_into OK: pc={reg("pc"):#x}')

    invoke('step_over', thread=thread_obj, n=jpype.JLong(2))
    wait_until(lambda: reg('pc') == CODE_BASE + 12, 'step_over x2', 20)
    log('step_over OK')

    bp_addr = trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(CODE_BASE + 0x40)
    invoke('break_sw_execute_address', process=proc_obj, address=bp_addr)
    wait_until(lambda: obj('Breakpoints[1]') is not None, 'breakpoint object', 20)
    assert str(value('Breakpoints[1]', 'Kinds')) == 'SW_EXECUTE'
    log('breakpoint published')

    invoke('resume', process=proc_obj)
    wait_until(lambda: reg('pc') == CODE_BASE + 0x40
               and str(value('Processes[0]', 'State')) == 'STOPPED',
               'the breakpoint to be hit', 30)
    assert str(value('Processes[0]', 'Reason')).startswith('Breakpoint 1'), value('Processes[0]', 'Reason')
    assert int(value('Breakpoints[1]', 'Hit Count')) == 1
    log(f'resume to breakpoint OK: {value("Processes[0]", "Reason")}')
    if show:
        import subprocess
        time.sleep(6)
        subprocess.run(['screencapture', '-x', show], check=False)
        log(f'screenshot written to {show}')

    # Reverse execution: these are what Ghidra's step-back buttons invoke.
    for needed in ('step_back_into', 'step_back_over', 'resume_back'):
        assert needed in names, f'{needed} missing; have {sorted(names)}'
    at_break = reg('pc')
    invoke('step_back_into', thread=thread_obj, n=jpype.JLong(1))
    wait_until(lambda: reg('pc') != at_break, 'step_back_into to land', 20)
    back_to = reg('pc')
    assert back_to < at_break, (hex(back_to), hex(at_break))
    log(f'step_back_into OK: {at_break:#x} -> {back_to:#x}')
    # Forward again lands exactly where we were, which is the whole point.
    invoke('step_into', thread=thread_obj, n=jpype.JLong(1))
    wait_until(lambda: reg('pc') == at_break, 'stepping forward again', 20)
    log('reverse then forward returns to the same instruction')

    # Registers are writable from Ghidra.
    invoke('write_reg', frame=frame_obj, name='a0', value=jpype.JArray(jpype.JByte)(bytes([0, 0, 0x12, 0x34])))
    wait_until(lambda: reg('a0') == 0x1234, 'a0 write', 20)
    log('write_reg OK')

    # Resume to the end of main: the harness's END marks the target terminated.
    invoke('delete_breakpoint', breakpoint=obj('Breakpoints[1]'))
    invoke('resume', process=proc_obj)
    wait_until(lambda: str(value('Processes[0]', 'State')) == 'TERMINATED',
               'the target to run to the end', 60)
    state = str(value('Processes[0]', 'State'))
    reason = str(value('Processes[0]', 'Reason'))
    log(f'run to end: state={state} reason={reason} pc={reg("pc"):#x}')
    # MAIN_END is the delay slot of the final jr; Unicorn stops at the branch.
    assert state == 'TERMINATED' and reg('pc') in (MAIN_END, MAIN_END - 4), (state, hex(reg('pc')))

    result.close()

    check_listen_mode(tool, binary, sample_input)

    log('ALL CHECKS PASSED')
    # Do not leave the temp project behind: Ghidra would offer to reopen it.
    import shutil
    gp.close()
    shutil.rmtree(projdir, ignore_errors=True)


def free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def check_listen_mode(tool, binary: str, sample_input: str) -> None:
    """The external-terminal workflow: the connector listens, Ghidra connects.

    This is what you get when you run ghidraunicorn in your own terminal and
    use the Connections window's "Connect Outbound" action.
    """
    import socket
    import subprocess
    import tempfile
    from java.net import InetSocketAddress
    from ghidra.app.services import TraceRmiService

    port = free_port()
    out = tempfile.NamedTemporaryFile('w+', suffix='.log', delete=False)
    out.close()
    argv = [sys.executable, '-m', 'ghidraunicorn',
            '--listen', f'127.0.0.1:{port}',
            '--harness', HARNESS, '--input', sample_input,
            '--image', binary, '--no-repl']
    env = dict(os.environ, PYTHONUNBUFFERED='1')
    env['PYTHONPATH'] = os.pathsep.join([REPO, env.get('PYTHONPATH', '')]).rstrip(os.pathsep)
    log(f'listen mode: starting connector on port {port}')
    with open(out.name, 'w') as fh:
        proc = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT, env=env)
    try:
        def said(text):
            with open(out.name) as fh:
                return text in fh.read()

        wait_until(lambda: said('Listening for Ghidra'), 'the connector to listen', 30)
        svc = tool.getService(TraceRmiService)
        conn = svc.connect(InetSocketAddress('127.0.0.1', port))
        wait_until(lambda: said('Trace started'), 'the connector to publish its trace', 30)
        names = {str(k) for k in conn.getMethods().all().keySet()}
        assert 'resume' in names and 'step_into' in names, sorted(names)
        log(f'listen mode OK: Ghidra connected outbound and sees {len(names)} methods')
        conn.close()
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
        with open(out.name) as fh:
            tail = fh.read()[-300:]
        os.unlink(out.name)
        if proc.returncode not in (0, None, -15):
            log(f'connector exited {proc.returncode}; tail: {tail!r}')


def worker():
    try:
        run_checks()
        results['ok'] = True
    except BaseException as e:  # noqa
        results['ok'] = False
        results['error'] = ''.join(traceback.format_exception(type(e), e, e.__traceback__))
        log('FAILED:\n' + results['error'])
    finally:
        # Let the JVM's terminal/pty threads unwind, then leave hard: Ghidra
        # keeps non-daemon threads alive otherwise.
        time.sleep(1.0)
        os._exit(0 if results['ok'] else 1)


def main():
    import pyghidra
    from pyghidra.launcher import PyGhidraLauncher

    class HeadedLauncher(PyGhidraLauncher):
        def _launch(self):
            from ghidra.framework import Application, GhidraApplicationConfiguration
            config = GhidraApplicationConfiguration()
            config.setShowSplashScreen(False)
            Application.initializeApplication(self._layout, config)

    launcher = HeadedLauncher(verbose=False)
    launcher.start()
    log(f'Ghidra {launcher.app_info.version} started')
    threading.Thread(target=worker, name='e2e-worker', daemon=True).start()
    if sys.platform == 'darwin':
        from pyghidra.launcher import _run_mac_app
        _run_mac_app()
    else:
        while True:
            time.sleep(3600)


if __name__ == '__main__':
    main()
