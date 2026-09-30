"""What every platform shares: the repository root, the build plan, the prerequisite checks and helpers."""
import os
import platform
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

from .console import Fatal, fail, more, ok, warn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))     # <repo>; this file is <repo>/kgbuild/core.py

# Only x86-64 can be built: the driver programs x86-64 MSRs, the PMU, VERW and the PCIe ECAM.
ARCH_ALIASES = {'x64': 'x64', 'x86_64': 'x64', 'amd64': 'x64',
                'arm64': 'arm64', 'aarch64': 'arm64',
                'x86': 'x86', 'i386': 'x86', 'i686': 'x86'}
ARCH_WHY = 'the driver relies on x86-64 MSRs, the PMU and VERW'
ARCH_NOTE = f'x86 (32-bit) and ARM64 are not offered: {ARCH_WHY}.'


# --------------------------------------------------------------------------- helpers

def rel(path):
    """Repository-relative path, for readable messages."""
    return os.path.relpath(path, ROOT) if path.startswith(ROOT + os.sep) else path


def detect_os():
    if sys.platform.startswith(('win', 'cygwin', 'msys')):
        return 'windows'
    if sys.platform.startswith('linux'):
        return 'linux'
    return sys.platform


def normalize_arch(name):
    return ARCH_ALIASES.get(name.lower(), name.lower() or 'unknown')


def first_line(cmd):
    """First line of a command's output, '' if it cannot be run."""
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             encoding='utf-8', errors='replace', timeout=30).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ''
    return out.splitlines()[0] if out else ''


def version_key(text):
    return tuple(int(n) for n in re.findall(r'\d+', text))


def describe_generic_host(host_arch):
    """One-line host description for a platform that has nothing more specific to say."""
    return f'{platform.system()} {host_arch} - {platform.platform()}'


# --------------------------------------------------------------------------- plan and checks

@dataclass
class Plan:
    """What to build.  Each platform adds its own settings in a subclass (linux.LinuxPlan, windows.WindowsPlan)."""
    platform: str
    components: str = 'all'                 # all | kernel | monitor
    clean: bool = False
    jobs: Optional[int] = None
    dry_run: bool = False

    @property
    def kernel(self):
        return self.components in ('all', 'kernel')

    @property
    def monitor(self):
        return self.components in ('all', 'monitor')


class Checks:
    """Prerequisite results.  Only a FAIL stops the build; a WARN is reported and ignored."""

    def __init__(self, quiet=False):
        self.failed = 0
        self.warned = 0
        self.quiet = quiet

    def ok(self, msg):
        if not self.quiet:
            ok(msg)

    def warn(self, msg, *fix):
        self.warned += 1
        if not self.quiet:
            warn(msg)
            more(*fix)

    def fail(self, msg, *fix):
        self.failed += 1
        if not self.quiet:
            fail(msg)
            more(*fix)


def run(cmd, plan):
    shown = subprocess.list2cmdline(cmd) if os.name == 'nt' else shlex.join(cmd)
    more(f'$ {shown}')
    if plan.dry_run:
        return 0
    sys.stdout.flush()
    try:
        return subprocess.call(cmd, cwd=ROOT)           # output streams straight to the terminal
    except OSError as e:
        raise Fatal(f'cannot run {cmd[0]}: {e}')
