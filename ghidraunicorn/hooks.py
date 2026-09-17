"""Bridge between target events and the trace.

The target calls `on_stop` for every stop (run, step, advance). `on_cont` is
called by the resume method before it hands the target to the run thread.
"""
from . import commands
from .target import StopEvent, UnicornTarget


def on_stop(ev: StopEvent) -> None:
    if commands.STATE.trace is None:
        return
    try:
        commands.record_stop(ev)
    except Exception as e:  # never let a recording failure kill the emulator
        print(f'Error recording stop: {e!r}')


def on_cont() -> None:
    if commands.STATE.trace is None:
        return
    commands.record_continued()


def install(target: UnicornTarget) -> None:
    if on_stop not in target.listeners:
        target.listeners.append(on_stop)


def remove(target: UnicornTarget) -> None:
    if on_stop in target.listeners:
        target.listeners.remove(on_stop)
