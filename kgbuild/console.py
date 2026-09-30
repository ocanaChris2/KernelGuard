"""Terminal output and prompts.  Nothing here knows about platforms or about building."""
import os
import sys


# --------------------------------------------------------------------------- output
# Same tags as linux/scripts/kg-deploy.sh; ASCII only so legacy Windows consoles cope.

COLOR = False


def paint(code, text):
    return f'\033[{code}m{text}\033[0m' if COLOR else text


def say(msg):
    print(f'{paint(36, "[....]")} {msg}')


def ok(msg):
    print(f'{paint(32, "[ OK ]")} {msg}')


def warn(msg):
    print(f'{paint(33, "[WARN]")} {msg}')


def fail(msg):
    print(f'{paint(31, "[FAIL]")} {msg}')


def more(*lines):
    """Continuation lines under a [....] / [WARN] / [FAIL] message."""
    for line in lines:
        print(f'       {line}')


def header(title):
    print(f'\n{paint(1, title)}')


def enable_vt():
    """Turn on ANSI escape processing in the Windows console (Windows 10+)."""
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.GetStdHandle.restype = ctypes.c_void_p
        k32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        k32.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        handle = k32.GetStdHandle(-11)                      # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(k32.SetConsoleMode(handle, mode.value | 0x0004))   # ..._VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        return False


def setup_output(no_color):
    global COLOR
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            try:
                # errors: a path must never crash a message.  line_buffering: when piped (tee, CI) our
                # lines must not trail the compiler output that make and MSBuild write directly.
                stream.reconfigure(errors='replace', line_buffering=True)
            except Exception:
                pass
    COLOR = (not no_color and 'NO_COLOR' not in os.environ and sys.stdout.isatty()
             and os.environ.get('TERM') != 'dumb')
    if COLOR and os.name == 'nt':
        COLOR = enable_vt()


class Fatal(Exception):
    """Stop with a message and an exit status."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


class Abort(Exception):
    """The user answered q, or the input was closed."""


# --------------------------------------------------------------------------- prompts
# Plain numbered menus: they behave the same in every terminal, over ssh and in CI logs.

def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        print()
        raise Abort('input closed')


def choose(title, rows, default=0, footer=None):
    """rows: (value, label, note, unavailable-reason-or-None).  Returns the chosen value."""
    header(title)
    width = max(len(r[1]) for r in rows)
    for i, (_, label, note, off) in enumerate(rows, 1):
        tail = f'[unavailable: {off}]' if off else note
        print(f'  {i}) {label.ljust(width)}   {tail}'.rstrip())
    if footer:
        print(f'  {footer}')
    while True:
        answer = ask(f'Select [{default + 1}, q = quit]: ').lower()
        if answer in ('q', 'quit'):
            raise Abort('cancelled')
        if not answer:
            pick = default
        elif answer.isdigit() and 1 <= int(answer) <= len(rows):
            pick = int(answer) - 1
        else:
            print(f'Enter a number from 1 to {len(rows)}.')
            continue
        if rows[pick][3]:
            print(f'Not available: {rows[pick][3]}.')
            continue
        return rows[pick][0]


def confirm(question, default=True):
    while True:
        answer = ask(f'{question} [{"Y/n" if default else "y/N"}]: ').lower()
        if not answer:
            return default
        if answer in ('y', 'yes'):
            return True
        if answer in ('n', 'no'):
            return False
