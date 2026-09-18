# A docking window in Ghidra showing the same context the console prints.
#
# The connector already prints a gef-style context in the launcher's terminal
# on every stop: registers with the changed ones highlighted and pointers
# dereferenced, the decoded status register, disassembly around the program
# counter, and the stack. This puts the same view in a Ghidra window, so it
# sits beside the Listing instead of in a terminal you have to switch to.
#
# Nothing new is computed for it. Everything it draws is already in the
# trace, and the rendering is `ghidraunicorn.context.Context`, which is
# written against a small surface rather than against the emulator - see the
# list in that file's docstring. `TraceSource` below is the other
# implementation of that surface, over a Ghidra trace.
#
# To use it: Window -> Script Manager, add this directory to the script
# directories, and run UnicornContextPanel. The window appears in the
# Debugger tool and follows the current trace and snapshot, so scrubbing the
# Time window redraws it at that point in history.
#
# NOT YET RUN AGAINST A REAL GHIDRA. It was written on a machine that had
# none. The rendering half is covered by the test suite; what wants checking
# here is the Ghidra API use - see CHANGELOG.md.
#
# @category Unicorn
# @menupath Window.Unicorn Context
# @runtime PyGhidra

import sys
import os

from java.awt import BorderLayout, Font
from javax.swing import JComponent, JPanel, JScrollPane, JTextArea

from docking import ComponentProvider
from ghidra.app.services import DebuggerTraceManagerService
from ghidra.program.model.lang import RegisterValue
from ghidra.trace.model import Lifespan


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
            if register.isProcessorContext():
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
        out = []
        for region in self.trace.getMemoryManager().getRegionsAtSnap(self.snap):
            span = region.getRange()
            perms = 0
            if region.isRead():
                perms |= 1
            if region.isWrite():
                perms |= 2
            if region.isExecute():
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


class UnicornContextProvider(ComponentProvider):
    """The window itself: a monospaced text area, redrawn on demand."""

    def __init__(self, tool, owner):
        ComponentProvider.__init__(self, tool, 'Unicorn Context', owner)
        self.tool = tool
        self.text = JTextArea()
        self.text.setEditable(False)
        self.text.setFont(Font(Font.MONOSPACED, Font.PLAIN, 12))
        self.panel = JPanel(BorderLayout())
        self.panel.add(JScrollPane(self.text), BorderLayout.CENTER)
        self.setVisible(True)

    def getComponent(self):
        return self.panel

    def refresh(self):
        try:
            self.text.setText(self._render())
        except Exception as e:
            self.text.setText('no context: %s' % (e,))
        self.text.setCaretPosition(0)

    def _render(self):
        traces = self.tool.getService(DebuggerTraceManagerService)
        if traces is None:
            return 'no trace manager; open this in the Debugger tool'
        coordinates = traces.getCurrent()
        trace = coordinates.getTrace()
        if trace is None:
            return 'no trace: launch a target first'
        source = TraceSource(trace, coordinates.getSnap(),
                             coordinates.getThread())
        # No colour: a JTextArea shows escape codes rather than obeying them.
        return context.Context(source, color=False).render()


def run():
    tool = state.getTool()
    provider = UnicornContextProvider(tool, 'ghidra-unicorn')
    tool.addComponentProvider(provider, True)
    provider.refresh()
    print('Unicorn Context panel added. Re-run this script to redraw it.')


run()
