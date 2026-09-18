"""A log of a session, in a form that can be run again.

The point of recording a triage session is that someone else can see what
you did, and that you can do it again. Those two wants pull in opposite
directions - a transcript is readable and a script is runnable - so this
writes a file that is both: the commands appear as themselves, one per line,
and everything else (what the target printed, where it stopped, what the
setup was) appears behind a `#`.

`split_commands` in the console treats `#` as a comment to the end of the
line, so the recording is already a valid command file:

    python -m ghidraunicorn --harness h.py --batch --commands-file session.gu

replays the session, and the same file read by a person is a transcript of
it. Nothing has to be stripped out first, and there is no second format to
keep in step with the first.
"""
from datetime import datetime, timezone
import re
import shlex
import sys
from typing import List, Optional, TextIO

#: Colour escapes, which a recording has no use for.
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class SessionRecorder:
    """Writes one session to one file.

    It listens for stops itself, so a stop caused from Ghidra's buttons is
    recorded the same as one caused by a command typed here - the log is of
    the session, not of the console.
    """

    def __init__(self, path: str, target, argv: Optional[List[str]] = None,
                 description: str = '', append: bool = False) -> None:
        self.path = path
        self.target = target
        self.commands = 0
        self.stops = 0
        self.closed = False
        self.file: TextIO = open(path, 'a' if append else 'w', buffering=1)
        self._header(argv, description)
        target.listeners.append(self._on_stop)

    # ---- writing ---------------------------------------------------------

    def _header(self, argv: Optional[List[str]], description: str) -> None:
        t = self.target
        self.note(f'ghidra-unicorn session, {_now()}')
        if description:
            self.note(f'target: {description}')
        self.note(f'architecture: {t.spec.key} ({t.spec.language})')
        try:
            self.note(f'start: pc={t.pc():#x} sp={t.sp():#x}, '
                      f'{len(t.regions())} regions')
        except Exception:
            pass
        # How it was launched, so the file says how to get back here.
        line = argv if argv is not None else sys.argv
        if line:
            self.note('launched as: ' + ' '.join(shlex.quote(a) for a in line))
        self.note('commands are the plain lines; everything else is a comment,'
                  ' so this file replays with --commands-file')
        self.file.write('\n')

    def note(self, text: str) -> None:
        """A line of commentary."""
        for line in str(text).splitlines() or ['']:
            self.file.write(f'# {line}\n')

    def command(self, line: str) -> None:
        """A command as it was typed, which is what makes this replayable."""
        text = line.strip()
        if not text:
            return
        self.commands += 1
        self.file.write(text + '\n')

    def output(self, text: str) -> None:
        """Whatever was printed, commented out so it does not replay."""
        clean = ANSI.sub('', text)
        if not clean.strip():
            return
        for line in clean.rstrip('\n').split('\n'):
            self.file.write(f'#  | {line}\n')

    def _on_stop(self, event) -> None:
        self.stops += 1
        where = f' at instruction {self.target.icount}' \
            if self.target.timeline.recording else ''
        self.note(f'stop: {event.reason} - {event.description}{where}')

    # ---- ending ----------------------------------------------------------

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._on_stop in self.target.listeners:
            self.target.listeners.remove(self._on_stop)
        self.file.write('\n')
        self.note(f'ended {_now()} after {self.commands} command(s) '
                  f'and {self.stops} stop(s)')
        try:
            self.file.close()
        except OSError:
            pass

    def describe(self) -> str:
        state = 'closed' if self.closed else 'recording'
        return (f'{state} to {self.path}: {self.commands} command(s), '
                f'{self.stops} stop(s)')

    def __enter__(self) -> 'SessionRecorder':
        return self

    def __exit__(self, *exc) -> None:
        self.close()
