# A window in Ghidra showing the same context the console prints.
#
# The connector already prints a gef-style context in the launcher's terminal
# on every stop: registers with the changed ones highlighted and pointers
# dereferenced, the decoded status register, disassembly around the program
# counter, and the stack. This puts the same view in a window, so it sits
# beside the Listing instead of in a terminal you have to switch to.
#
# Nothing new is computed for it. Everything it draws is already in the
# trace, and the rendering is `ghidraunicorn.context.Context`, which is
# written against a small surface rather than against the emulator - see the
# list in that file's docstring. `TraceSource` below is the other
# implementation of that surface, over a Ghidra trace.
#
# Why this is a window and not a docked panel
# -------------------------------------------
# The roadmap asked for a docking `ComponentProvider`. That cannot be done
# from Python: `docking.ComponentProvider` is an abstract *class* with an
# abstract `getComponent()`, Ghidra ships no concrete one to instantiate,
# and JPype - which is what runs Python inside Ghidra - cannot extend Java
# classes at all. It refuses with "Java classes cannot be extended in
# Python"; only interfaces can be implemented, with @JImplements.
#
# So a docked version would have to be written in Java, and a Java panel
# could not call this renderer: it would have to reimplement `context.py`,
# which is the one thing worth avoiding, because then two views of the same
# machine could disagree. A floating window that shares the renderer is the
# better trade, and it is the same picture either way.
#
# It refreshes on a timer, so it follows the current trace and snapshot:
# scrub the Time window and the view follows to that point in history.
#
# To use it: Window -> Script Manager, add this directory to the script
# directories, and run UnicornContextPanel.
#
# NOT YET RUN AGAINST A REAL GHIDRA. It was written on a machine that had
# none. The rendering half is covered by the test suite, and every Ghidra
# and JPype call below was checked against Ghidra's own source and against
# a real JPype - but checked is not run. See CHANGELOG.md.
#
# @category Unicorn
# @menupath Window.Unicorn Context
# @runtime PyGhidra

import sys
import os

from java.awt import BorderLayout, Dimension, Font
from java.awt.event import ActionListener
from java.lang import Runnable
from javax.swing import (BorderFactory, BoxLayout, JButton, JFrame, JPanel,
                         JScrollPane, JTextArea, Timer, WindowConstants)

from ghidra.app.services import DebuggerTraceManagerService
from ghidra.util import Swing


def _import_ghidraunicorn():
    """Find the connector package next to this script's checkout."""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    if root not in sys.path:
        sys.path.insert(0, root)
    from ghidraunicorn import arch, context
    return arch, context


arch, context = _import_ghidraunicorn()


class TraceSource(object):
    """The trace, wearing the face `Context` renders from.

    A Ghidra trace already holds every register and every byte of memory the
    connector published, at every snapshot, so drawing the context from it
    needs no cooperation from the Python side at all - which is what makes
    this a script rather than a protocol change.
    """

    def __init__(self, trace, snap, thread, frame=0):
        self.trace = trace
        self.snap = snap
        self.thread = thread
        self.frame = frame
        self.spec = self._spec()
        self.breakpoints = {}
        self._registers = trace.getMemoryManager()
        self._values = self._read_registers()

    # ---- what architecture is this -------------------------------------

    def _spec(self):
        """Our table entry for the trace's language.

        `arch.py` records the Ghidra language id for every processor it
        knows, so this is a lookup in that table rather than a second one.
        """
        return arch.spec_for_language(
            str(self.trace.getBaseLanguage().getLanguageID()))

    # ---- registers -------------------------------------------------------

    def _register_space(self):
        space = self.trace.getMemoryManager().getMemoryRegisterSpace(
            self.thread, self.frame, False)
        if space is None:
            raise ValueError('the trace has no registers for this thread')
        return space

    def _read_registers(self):
        """Every register the trace holds at this snapshot, by name."""
        values = {}
        space = self._register_space()
        language = self.trace.getBaseLanguage()
        for register in language.getRegisters():
            if register.isProcessorContext() or register.isHidden():
                continue
            if not register.isBaseRegister():
                # EAX, AX, AH and AL are all parts of RAX. Reading every one
                # of them on every redraw buys nothing: the context is drawn
                # from the table in arch.py, which names the parents.
                continue
            try:
                value = space.getValue(self.snap, register)
            except Exception:
                continue
            if value is None or not value.hasValue():
                continue
            values[register.getName()] = int(
                value.getUnsignedValue().longValue()) & \
                ((1 << register.getBitLength()) - 1)
        return values

    def regs(self):
        return dict(self._values)

    def reg_read(self, name):
        # The dotted names - `cpsr.M` - are fields of a status register, and
        # the table knows how to pull them out of the word.
        if '.' in name:
            register, field = name.split('.', 1)
            whole = self._value_of(register)
            decoded = self.spec.field(field)
            if decoded is None:
                raise KeyError(name)
            return decoded.get(whole)
        flag = self.spec.flag(name)
        if flag is not None:
            return flag.get(self._value_of(flag.source))
        return self._value_of(name)

    def _value_of(self, name):
        lowered = name.lower()
        for key, value in self._values.items():
            if key.lower() == lowered:
                return value
        raise KeyError(name)

    def pc(self):
        return self._value_of(self.spec.pc)

    def sp(self):
        return self._value_of(self.spec.sp)

    def fields(self):
        if self.spec.status is None:
            return []
        return self.spec.decode_fields(self._value_of(self.spec.status))

    # ---- memory ----------------------------------------------------------

    def _address(self, offset):
        return self.trace.getBaseAddressFactory() \
            .getDefaultAddressSpace().getAddress(offset)

    def read(self, address, size):
        """Bytes from the trace. Raises when they are not there.

        `Context` treats a failure here as "not mapped" and renders it as
        such, which is why this may raise whatever it likes.
        """
        from java.nio import ByteBuffer
        buffer = ByteBuffer.allocate(size)
        read = self.trace.getMemoryManager().getViewBytes(
            self.snap, self._address(address), buffer)
        if read < size:
            raise ValueError('only %d of %d bytes at %#x are in the trace'
                             % (read, size, address))
        return bytes(buffer.array())

    def regions(self):
        """What is mapped at this snapshot.

        Every accessor on a region takes the snapshot: a region's range and
        its permissions are things it had *at a time*, not properties of the
        object, because a trace holds the whole history at once.
        """
        out = []
        for region in self.trace.getMemoryManager().getRegionsAtSnap(self.snap):
            span = region.getRange(self.snap)
            perms = 0
            if region.isRead(self.snap):
                perms |= 1
            if region.isWrite(self.snap):
                perms |= 2
            if region.isExecute(self.snap):
                perms |= 4
            out.append((span.getMinAddress().getOffset(),
                        span.getMaxAddress().getOffset(), perms))
        return sorted(out)

    # ---- code ------------------------------------------------------------

    def decode(self, address):
        """(size, mnemonic, operands), from Capstone as the console does.

        Ghidra could disassemble this itself, and in the Listing it does.
        Using the same decoder as the console means the panel and the
        terminal cannot disagree about what an instruction is, which would
        be a confusing thing for two views of one machine to do.
        """
        if self.spec.cs is None:
            return None
        if not hasattr(self, '_cs'):
            import capstone
            mode = self.spec.cs
            if self.spec.thumb_field is not None:
                thumb = False
                try:
                    thumb = bool(self.reg_read(
                        self.spec.status + '.' + self.spec.thumb_field))
                except Exception:
                    pass
                mode = self.spec.cs_thumb if thumb else self.spec.cs_arm
            self._cs = capstone.Cs(*mode)
        try:
            code = self.read(address, 16)
        except Exception:
            try:
                code = self.read(address, 4)
            except Exception:
                return None
        for _, size, mnemonic, operands in self._cs.disasm_lite(code, address, 1):
            return size, mnemonic, operands
        return None


class ContextWindow(object):
    """A monospaced text area in a frame, redrawn from the current trace.

    Plain composition, no subclassing: every Java object here is one JPype
    can build, and the two callbacks are cast to Java functional interfaces
    with the `Interface @ function` idiom that `tools/e2e_ghidra.py` already
    uses for `Swing.runNow`.
    """

    REFRESH_MS = 1000

    def __init__(self, tool):
        self.tool = tool
        self.frame = None
        self.text = None
        self.timer = None

    def open(self):
        # Swing objects belong to the event dispatch thread, and a Ghidra
        # script does not run on it.
        Swing.runNow(Runnable @ self._build)
        self.refresh()
        return self

    def _build(self):
        self.text = JTextArea()
        self.text.setEditable(False)
        self.text.setFont(Font(Font.MONOSPACED, Font.PLAIN, 12))

        refresh = JButton('Refresh')
        refresh.addActionListener(ActionListener @ (lambda event: self.refresh()))
        buttons = JPanel()
        buttons.setLayout(BoxLayout(buttons, BoxLayout.LINE_AXIS))
        buttons.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
        buttons.add(refresh)

        panel = JPanel(BorderLayout())
        panel.add(JScrollPane(self.text), BorderLayout.CENTER)
        panel.add(buttons, BorderLayout.SOUTH)

        self.frame = JFrame('Unicorn Context')
        self.frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
        self.frame.setContentPane(panel)
        self.frame.setPreferredSize(Dimension(900, 700))
        self.frame.pack()
        self.frame.setVisible(True)

        self.timer = Timer(self.REFRESH_MS,
                           ActionListener @ (lambda event: self._tick()))
        self.timer.start()

    def _tick(self):
        # Nothing stops the timer when the window is closed, so it stops
        # itself rather than redrawing something nobody can see.
        if self.frame is None or not self.frame.isDisplayable():
            if self.timer is not None:
                self.timer.stop()
            return
        self.refresh()

    def refresh(self):
        try:
            text = self.render()
        except Exception as e:
            text = 'no context: %s: %s' % (type(e).__name__, e)
        if self.text is None:
            return
        if str(self.text.getText()) == text:
            return          # do not fight the scrollbar for no reason
        position = self.text.getCaretPosition()
        self.text.setText(text)
        try:
            self.text.setCaretPosition(min(position, len(text)))
        except Exception:
            pass

    def render(self):
        traces = self.tool.getService(DebuggerTraceManagerService)
        if traces is None:
            return 'no trace manager: run this in the Debugger tool'
        coordinates = traces.getCurrent()
        trace = coordinates.getTrace()
        if trace is None:
            return 'no trace: launch a target first'
        source = TraceSource(trace, coordinates.getSnap(),
                             coordinates.getThread(), coordinates.getFrame())
        # No colour: a JTextArea prints escape codes rather than obeying them.
        return context.Context(source, color=False).render()


def run():
    ContextWindow(state.getTool()).open()
    print('Unicorn Context window opened; it follows the current trace.')


run()
