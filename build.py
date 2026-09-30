#!/usr/bin/env python3
"""
build.py  -  interactive, cross-platform build for KernelGuard.

  Windows host   KernelGuard.sys (WDM driver) + KernelGuardMonitor.exe   via MSBuild
  Linux host     kernelguard.ko (kernel module) + kgmon                  via make / Kbuild

It asks what to build (platform and architecture, components, and the configuration
or kernel version), checks that the toolchain for that choice is installed, then builds.
It never signs, installs or loads anything: see Deploy-KernelGuard.ps1 (Windows) and
linux/scripts/kg-deploy.sh (Linux) for that.

    python build.py             ask everything
    python build.py --check     only verify the prerequisites
    python build.py -y          take every default, ask nothing
    python build.py --help      all options

Standard library only.  Exit status: 0 ok, 1 build failed, 2 bad usage,
3 prerequisites missing, 130 interrupted.
"""
import argparse
import glob
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import namedtuple
from dataclasses import dataclass, field
from typing import Optional

if sys.version_info < (3, 8):
    sys.exit('[FAIL] Python 3.8 or newer is required (this is %s)' % platform.python_version())

ROOT = os.path.dirname(os.path.abspath(__file__))
LINUX_DIR = os.path.join(ROOT, 'linux')
DRIVER_PROJ = os.path.join(ROOT, 'src', 'KernelGuard.vcxproj')
MONITOR_PROJ = os.path.join(ROOT, 'usermode', 'KernelGuardMonitor.vcxproj')

VS_URL = 'https://visualstudio.microsoft.com/downloads/'
WDK_URL = 'https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk'

# Only x86-64 can be built: the driver programs x86-64 MSRs, the PMU, VERW and the PCIe ECAM.
ARCH_ALIASES = {'x64': 'x64', 'x86_64': 'x64', 'amd64': 'x64',
                'arm64': 'arm64', 'aarch64': 'arm64',
                'x86': 'x86', 'i386': 'x86', 'i686': 'x86'}
ARCH_WHY = 'the driver relies on x86-64 MSRs, the PMU and VERW'
ARCH_NOTE = f'x86 (32-bit) and ARM64 are not offered: {ARCH_WHY}.'

Platform = namedtuple('Platform', 'id title produces')
PLATFORMS = [
    Platform('linux', 'Linux x64 (x86-64)', 'kernelguard.ko + kgmon'),
    Platform('windows', 'Windows x64 (x86-64)', 'KernelGuard.sys + KernelGuardMonitor.exe'),
]

COMPONENTS = {
    'linux': [('all', 'Everything', 'kernel module + monitor'),
              ('kernel', 'Kernel module only', 'kernelguard.ko'),
              ('monitor', 'Monitor only', 'kgmon')],
    'windows': [('all', 'Everything', 'driver + monitor'),
                ('kernel', 'Driver only', 'KernelGuard.sys'),
                ('monitor', 'Monitor only', 'KernelGuardMonitor.exe')],
}


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


def os_release():
    info = {}
    try:
        with open('/etc/os-release') as f:
            for line in f:
                key, sep, value = line.strip().partition('=')
                if sep:
                    info[key] = value.strip('"\'')
    except OSError:
        pass
    return info


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


def unavailable(platform_id, host_os, host_arch):
    """Why this platform cannot be built on this host, or None."""
    if platform_id != host_os:
        need = 'a Windows host with Visual Studio and the WDK' if platform_id == 'windows' \
            else 'a Linux host with kernel headers'
        return f'needs {need}'
    if platform_id == 'linux' and host_arch != 'x64':
        return f'needs an x86-64 host, this one is {host_arch}'
    return None


@dataclass
class Plan:
    platform: str
    components: str = 'all'                 # all | kernel | monitor
    config: str = 'Debug'                   # Windows only
    kver: str = ''                          # Linux only: kernel release ...
    kdir: str = ''                          # ... and its build tree
    clean: bool = False
    jobs: Optional[int] = None
    dry_run: bool = False
    msbuild: dict = field(default_factory=dict)     # Windows: component -> MSBuild.exe, set by the checks
    wdk_root: str = ''                              # Windows: Windows Kits root holding the WDK

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


# --------------------------------------------------------------------------- Linux

def package_manager():
    info = os_release()
    ids = set(f'{info.get("ID", "")} {info.get("ID_LIKE", "")}'.lower().split())
    if ids & {'debian', 'ubuntu', 'linuxmint'}:
        return 'apt'
    if ids & {'fedora', 'rhel', 'centos'}:
        return 'dnf'
    if 'arch' in ids:
        return 'pacman'
    if ids & {'suse', 'opensuse'}:
        return 'zypper'
    for tool, name in (('apt-get', 'apt'), ('dnf', 'dnf'), ('pacman', 'pacman'), ('zypper', 'zypper')):
        if shutil.which(tool):
            return name
    return None


def tools_hint(pm, cc=None):
    pinned = re.fullmatch(r'gcc-(\d+)', cc or '')       # a versioned gcc named by the kernel tree
    if pinned and pm == 'apt':
        return f'sudo apt install {cc}'
    return {'apt': 'sudo apt install build-essential',
            'dnf': 'sudo dnf install gcc make',
            'pacman': 'sudo pacman -S base-devel',
            'zypper': 'sudo zypper install gcc make'}.get(pm, 'install gcc and GNU make with your package manager')


def headers_hint(pm, kver):
    return {'apt': f'sudo apt install linux-headers-{kver}',
            'dnf': f'sudo dnf install kernel-devel-{kver}',
            'pacman': 'sudo pacman -S linux-headers      (linux-lts-headers, linux-zen-headers, ... for other kernels)',
            'zypper': 'sudo zypper install kernel-default-devel'
            }.get(pm, f'install the kernel headers/devel package that matches {kver}')


def installed_kernels():
    """Kernel releases that have a header tree under /lib/modules, newest first."""
    names = {os.path.basename(os.path.dirname(p)) for p in glob.glob('/lib/modules/*/build') if os.path.isdir(p)}
    return sorted(names, key=version_key, reverse=True)


def kernel_release(kdir):
    try:
        with open(os.path.join(kdir, 'include', 'config', 'kernel.release')) as f:
            return f.read().strip() or None
    except OSError:
        return None


def resolve_kernel(args, interactive):
    """(release, build tree) the module is built against.  Precedence: --kver, $KDIR, $KVER, menu."""
    running = platform.release()
    if args.kver:
        return args.kver, f'/lib/modules/{args.kver}/build'
    if os.environ.get('KDIR'):
        kdir = os.path.abspath(os.environ['KDIR'])
        return kernel_release(kdir) or os.environ.get('KVER') or running, kdir
    default = os.environ.get('KVER') or running
    known = installed_kernels()
    names = []
    for name in [default, running] + known:
        if name not in names:
            names.append(name)
    if len(names) == 1 or not interactive:
        say(f'kernel: {default}')
        return default, f'/lib/modules/{default}/build'
    rows = []
    for name in names:
        notes = ['running kernel'] if name == running else []
        if name not in known:
            notes.append('headers not installed')
        rows.append((name, name, ', '.join(notes), None))
    kver = choose('Kernel to build the module against', rows)
    return kver, f'/lib/modules/{kver}/build'


def kernel_compiler(kdir):
    """Compiler the kernel tree was built with, e.g. 'x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0) 13.3.0'."""
    try:
        with open(os.path.join(kdir, 'include', 'generated', 'autoconf.h')) as f:
            for line in f:
                m = re.match(r'#define CONFIG_CC_VERSION_TEXT "(.*)"', line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def kbuild_compiler(kdir):
    """Compiler command Kbuild runs for this tree.  Debian/Ubuntu trees pin a versioned gcc in their
    Makefile (CC = $(CROSS_COMPILE)gcc-13), so the plain 'gcc' is not necessarily the one that counts."""
    try:
        with open(os.path.join(kdir, 'Makefile'), errors='replace') as f:
            m = re.search(r'^CC\s*=\s*\$\(CROSS_COMPILE\)(gcc\S*)\s*$', f.read(), re.M)
    except OSError:
        m = None
    return m.group(1) if m else 'gcc'


def compiler_id(text):
    """('gcc' | 'clang', major version) from a compiler banner, or None."""
    m = re.search(r'\b(\d+)\.\d+', text)
    if not m:
        return None
    return ('clang' if 'clang' in text.lower() else 'gcc', int(m.group(1)))


def cc_command(cc):
    try:
        return shlex.split(cc)[0]
    except (ValueError, IndexError):
        return cc


def sig_enforced():
    try:
        with open('/sys/module/module/parameters/sig_enforce') as f:
            return f.read().strip() == 'Y'
    except OSError:
        return False


def linux_checks(plan, chk):
    pm = package_manager()

    if os.path.isfile(os.path.join(LINUX_DIR, 'Makefile')):
        chk.ok('linux/Makefile present')
    else:
        chk.fail('linux/Makefile not found', 'run build.py from a complete checkout of the repository')

    if plan.kernel and os.environ.get('KG_TESTHOOKS') == '1':
        chk.fail('KG_TESTHOOKS=1 is set in the environment',
                 'that builds the module with the synthetic-alert test hook, which is for the VM test',
                 'suite only (linux/README.md).  Unset it: unset KG_TESTHOOKS')

    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        chk.warn('running as root: the build products will be owned by root',
                 'building needs no privileges, only loading the module does')

    make = shutil.which('make')
    if not make:
        chk.fail('make not found', tools_hint(pm))
    else:
        banner = first_line([make, '--version'])
        if 'GNU Make' in banner:
            chk.ok(f'make: {banner}')
        else:
            chk.warn(f'make is not GNU Make ({banner or "unknown"}); Kbuild needs GNU Make')

    # CC wins for both; otherwise Kbuild uses the compiler its tree names, and the monitor's Makefile uses cc.
    cc_env = os.environ.get('CC')
    needed = {}
    if plan.kernel:
        needed.setdefault(cc_env or kbuild_compiler(plan.kdir), []).append('kernel module')
    if plan.monitor:
        needed.setdefault(cc_env or 'cc', []).append('monitor')
    module_cc = None
    for cc, users in needed.items():
        exe = shutil.which(cc_command(cc))
        if not exe:
            chk.fail(f'{cc} not found (needed for the {" and ".join(users)})', tools_hint(pm, cc))
            continue
        banner = first_line(shlex.split(cc) + ['--version'])
        chk.ok(f'{cc} ({" and ".join(users)}): {banner}')
        if 'kernel module' in users:
            module_cc = banner

    if not plan.kernel:
        return
    kdir = plan.kdir
    missing = [p for p in ('Makefile', 'include/generated/autoconf.h')
               if not os.path.exists(os.path.join(kdir, *p.split('/')))]
    if not os.path.isdir(kdir):
        chk.fail(f'no kernel headers for {plan.kver}: {kdir} is missing', headers_hint(pm, plan.kver))
    elif missing:
        chk.fail(f'kernel header tree {kdir} is incomplete (no {", ".join(missing)})',
                 headers_hint(pm, plan.kver))
    else:
        chk.ok(f'kernel headers for {plan.kver}: {kdir}')
        built_with = kernel_compiler(kdir)
        have, want = compiler_id(module_cc or ''), compiler_id(built_with or '')
        if have and want and have != want:
            fix = 'LLVM=1' if want[0] == 'clang' else f'CC={built_with.split()[0]}'
            chk.warn(f'kernel {plan.kver} was built with {built_with}',
                     f'but the compiler here is {module_cc}; a mismatch can break the module build.',
                     f'If it does, install the matching compiler and run with {fix}')
        elif have and want:
            chk.ok(f'kernel and compiler agree ({want[0]} {want[1]})')


def linux_build(plan):
    # KVER and KDIR go on the command line so make builds exactly the tree the checks verified,
    # whatever is in the environment.  CC too: Kbuild would ignore it as an environment variable.
    tree = [f'KVER={plan.kver}', f'KDIR={plan.kdir}'] if plan.kernel else []
    if os.environ.get('CC'):
        tree.append(f'CC={os.environ["CC"]}')
    make = ['make', '--no-print-directory']
    if plan.clean:
        say('cleaning')
        # Per component: a monitor-only rebuild must not delete a module built for another kernel.
        for enabled, subdir, extra in ((plan.kernel, 'module', tree), (plan.monitor, 'monitor', [])):
            if enabled and run(make + ['-C', os.path.join(LINUX_DIR, subdir)] + extra + ['clean'], plan):
                raise Fatal(f'make clean failed in linux/{subdir}')
    goal = {'all': [], 'kernel': ['module'], 'monitor': ['monitor']}[plan.components]
    cmd = make + ['-C', LINUX_DIR] + tree + ([f'-j{plan.jobs}'] if plan.jobs else [])
    say({'all': 'building the kernel module and the monitor',
         'kernel': 'building the kernel module',
         'monitor': 'building the monitor'}[plan.components])
    if run(cmd + goal, plan):
        raise Fatal('make failed - see the compiler output above')


def linux_outputs(plan):
    files = []
    if plan.kernel:
        files.append(os.path.join(LINUX_DIR, 'module', 'kernelguard.ko'))
    if plan.monitor:
        files.append(os.path.join(LINUX_DIR, 'monitor', 'kgmon'))
    return files


def linux_report(plan):
    """Extra facts about the module that was just built, and what to do with it."""
    module = os.path.join(LINUX_DIR, 'module', 'kernelguard.ko')
    running = platform.release()
    if plan.kernel and shutil.which('modinfo'):
        magic = first_line(['modinfo', '-F', 'vermagic', module])
        if magic:
            more(f'vermagic: {magic}')
            if magic.split()[0] != plan.kver:
                warn(f'the module reports {magic.split()[0]}, not {plan.kver}')
    if plan.kernel and plan.kver != running:
        warn(f'built for {plan.kver}, but this machine runs {running}: it loads only after booting {plan.kver}')

    header('Next steps')
    steps = [('linux/scripts/kg-deploy.sh preflight', 'what would stop the module loading on this machine?')]
    if plan.monitor:
        steps.append(('make -C linux check', 'monitor known-answer tests (no root, nothing is loaded)'))
    if plan.kernel and plan.kver == running and sig_enforced():
        steps.append(('sudo linux/scripts/kg-deploy.sh sign', 'required: this kernel enforces module signatures'))
    if plan.kernel:
        steps.append(('sudo linux/scripts/kg-deploy.sh install', "load it - read 'Safety model' in linux/README.md first"))
    width = max(len(s[0]) for s in steps)
    for command, why in steps:
        print(f'  {command.ljust(width)}   {why}')


# --------------------------------------------------------------------------- Windows

class VsInstance(namedtuple('VsInstance', 'path name version prerelease')):
    @property
    def label(self):
        """'Visual Studio Community 2026 18.0.1234' - the version only when it is a full one (vswhere)."""
        return f'{self.name} {self.version}' if '.' in self.version else self.name


Kit = namedtuple('Kit', 'root version sdk wdk')
YEAR_TO_VERSION = {'2017': '15', '2019': '16', '2022': '17'}    # the 2026 install dir is already "18"


def program_files():
    dirs = []
    for var in ('ProgramFiles(x86)', 'ProgramFiles', 'ProgramW6432'):
        d = os.environ.get(var)
        if d and d not in dirs:
            dirs.append(d)
    return dirs


def msbuild_of(vs):
    return os.path.join(vs.path, 'MSBuild', 'Current', 'Bin', 'MSBuild.exe')


def vswhere_instances():
    """Visual Studio installs known to the installer (vswhere.exe ships with it)."""
    exe = next((p for p in (os.path.join(b, 'Microsoft Visual Studio', 'Installer', 'vswhere.exe')
                            for b in program_files()) if os.path.isfile(p)), None) or shutil.which('vswhere')
    if not exe:
        return []
    try:
        out = subprocess.run([exe, '-products', '*', '-prerelease', '-format', 'json', '-utf8'],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60).stdout
        data = json.loads(out.decode('utf-8-sig', 'replace') or '[]')
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []
    found = []
    for d in data:
        path = d.get('installationPath')
        if not path or d.get('isComplete') is False:
            continue
        vs = VsInstance(path, d.get('displayName') or os.path.basename(path),
                        d.get('installationVersion') or '0', bool(d.get('isPrerelease')))
        if os.path.isfile(msbuild_of(vs)):
            found.append(vs)
    return found


def glob_instances():
    """Fallback when vswhere is missing: look in the default install directories."""
    found, seen = [], set()
    for base in program_files():
        for path in sorted(glob.glob(os.path.join(glob.escape(base), 'Microsoft Visual Studio', '*', '*'))):
            year = os.path.basename(os.path.dirname(path))
            vs = VsInstance(path, f'Visual Studio {year} {os.path.basename(path)}',
                            YEAR_TO_VERSION.get(year, year), False)
            key = os.path.normcase(path)
            if key not in seen and os.path.isfile(msbuild_of(vs)):
                seen.add(key)
                found.append(vs)
    return found


def vc_targets(vs, *parts):
    """Paths below <VS>\\MSBuild\\Microsoft\\VC\\v<nnn>\\ (v170 for VS 2022, v180 for VS 2026)."""
    return glob.glob(os.path.join(glob.escape(vs.path), 'MSBuild', 'Microsoft', 'VC', 'v*', *parts))


def toolsets_of(vs):
    return sorted(os.path.basename(p) for p in vc_targets(vs, 'Platforms', 'x64', 'PlatformToolsets', '*'))


def pick_instance(instances, toolset):
    """Newest stable install that provides the toolset.  Chosen per project on purpose: the driver
    pins v145 and the monitor v143, which side-by-side Visual Studio installs may split between them."""
    usable = [v for v in instances if toolset is None or vc_targets(v, 'Platforms', 'x64', 'PlatformToolsets', toolset)]
    usable.sort(key=lambda v: (not v.prerelease, version_key(v.version)), reverse=True)
    return usable[0] if usable else None


def project_settings(path):
    """Literal values of the build settings we verify, read from the .vcxproj (None if absent or a macro)."""
    keys = ('PlatformToolset', 'WdkVer', 'WindowsTargetPlatformVersion', 'SpectreMitigation')
    found = dict.fromkeys(keys)
    try:
        elements = list(ET.parse(path).iter())
    except (OSError, ET.ParseError):
        return found
    for el in elements:
        tag = el.tag.rsplit('}', 1)[-1]
        text = (el.text or '').strip()
        if tag in found and found[tag] is None and text and '$(' not in text:
            found[tag] = text
    return found


def kits_roots():
    roots = []
    try:
        import winreg
        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows Kits\Installed Roots',
                                    0, winreg.KEY_READ | view) as key:
                    roots.append(winreg.QueryValueEx(key, 'KitsRoot10')[0])
            except OSError:
                pass
    except ImportError:
        pass
    roots += [os.path.join(base, 'Windows Kits', '10') for base in program_files()]
    unique, seen = [], set()
    for root in roots:
        key = os.path.normcase(os.path.normpath(root))
        if key not in seen and os.path.isdir(root):
            seen.add(key)
            unique.append(root)
    return unique


def scan_kits():
    """Every Windows SDK / WDK version installed, with what each one provides."""
    kits = []
    for root in kits_roots():
        try:
            versions = os.listdir(os.path.join(root, 'Include'))
        except OSError:
            continue
        for v in sorted((v for v in versions if re.fullmatch(r'10\.\d+\.\d+\.\d+', v)), reverse=True):
            inc, lib = os.path.join(root, 'Include', v), os.path.join(root, 'Lib', v)
            kits.append(Kit(root, v,
                            os.path.isfile(os.path.join(inc, 'um', 'Windows.h')),
                            os.path.isfile(os.path.join(inc, 'km', 'ntddk.h'))
                            and os.path.isfile(os.path.join(lib, 'km', 'x64', 'ntoskrnl.lib'))))
    return kits


def windows_projects(plan):
    projects = []
    if plan.kernel:
        projects.append(('kernel', 'driver', DRIVER_PROJ))
    if plan.monitor:
        projects.append(('monitor', 'monitor', MONITOR_PROJ))
    return projects


def windows_checks(plan, chk):
    projects = windows_projects(plan)
    instances = vswhere_instances() or glob_instances()
    if not instances:
        chk.fail('no Visual Studio installation found',
                 'Install Visual Studio 2022 or later with the "Desktop development with C++" workload:', VS_URL)

    settings, chosen = {}, {}
    for key, label, path in projects:
        if not os.path.isfile(path):
            chk.fail(f'{rel(path)} not found', 'run build.py from a complete checkout of the repository')
            continue
        settings[key] = cfg = project_settings(path)
        toolset = cfg['PlatformToolset']
        vs = pick_instance(instances, toolset)
        if vs:
            chosen[key] = vs
            plan.msbuild[key] = msbuild_of(vs)
            chk.ok(f'{label}: MSBuild + MSVC toolset {toolset or "(default)"} from {vs.label}')
        elif instances:
            have = '; '.join(f'{", ".join(toolsets_of(v)) or "none"} in {v.label}' for v in instances)
            chk.fail(f'{label}: MSVC toolset {toolset} (set in {rel(path)}) is not installed',
                     f'installed: {have}',
                     f'Visual Studio Installer > Modify > Individual components: add the "MSVC {toolset} ... '
                     'C++ x64/x86 build tools" component,',
                     f'or change PlatformToolset in {rel(path)}')

    if 'kernel' in chosen:
        vs = chosen['kernel']
        with open(DRIVER_PROJ, encoding='utf-8-sig', errors='replace') as f:
            uses_masm = 'masm.props' in f.read()
        if uses_masm:
            if vc_targets(vs, 'BuildCustomizations', 'masm.props'):
                chk.ok('driver: MASM build customization (for src/asm/verw_flush.asm)')
            else:
                chk.fail('driver: MASM build customization (masm.props) not found',
                         f'Install or repair the "Desktop development with C++" workload in {vs.name}')

    if 'monitor' in chosen:
        vs = chosen['monitor']
        if settings['monitor']['SpectreMitigation'] == 'Spectre':
            # Any Spectre lib set is accepted: none at all is a certain MSB8040, a set for the
            # wrong toolset version is reported by MSBuild itself.
            if glob.glob(os.path.join(glob.escape(vs.path), 'VC', 'Tools', 'MSVC', '*', 'lib', 'spectre', 'x64')):
                chk.ok('monitor: Spectre-mitigated libraries')
            else:
                chk.fail('monitor: Spectre-mitigated libraries not installed (the project sets SpectreMitigation=Spectre)',
                         f'Visual Studio Installer > Modify > Individual components in {vs.name}:',
                         'add "MSVC ... x64/x86 Spectre-mitigated libs (Latest)"')

    kits = scan_kits()
    if plan.kernel and 'kernel' in settings:
        want = settings['kernel']['WdkVer']
        hit = next((k for k in kits if k.wdk and (want is None or k.version == want)), None)
        if hit:
            plan.wdk_root = hit.root
            chk.ok(f'driver: Windows Driver Kit {hit.version} (km headers + libs) in {hit.root}')
        else:
            have = ', '.join(sorted({k.version for k in kits if k.wdk}, reverse=True)) or 'none'
            chk.fail(f'driver: Windows Driver Kit {want or "(any version)"} not found '
                     '(needs km\\ntddk.h and km\\x64\\ntoskrnl.lib)',
                     f'WDK versions installed: {have}',
                     f'Install the WDK for the same version as the SDK: {WDK_URL}',
                     f'(the version is pinned as WdkVer in {rel(DRIVER_PROJ)})')
        sdk = next((k for k in kits if k.sdk), None)
        if sdk:
            chk.ok(f'driver: Windows SDK {sdk.version}')
        else:
            chk.fail('driver: no Windows SDK found', 'Visual Studio Installer > Individual components > "Windows 11 SDK"')
    if plan.monitor and 'monitor' in settings:
        want = settings['monitor']['WindowsTargetPlatformVersion']
        hit = next((k for k in kits if k.sdk and (want is None or k.version == want)), None)
        if hit:
            chk.ok(f'monitor: Windows SDK {hit.version} in {hit.root}')
        else:
            have = ', '.join(sorted({k.version for k in kits if k.sdk}, reverse=True)) or 'none'
            chk.fail(f'monitor: Windows SDK {want} not found (WindowsTargetPlatformVersion in {rel(MONITOR_PROJ)})',
                     f'SDK versions installed: {have}',
                     f'Visual Studio Installer > Individual components > "Windows 11 SDK ({want})"')


def msbuild_escape(value):
    """Escape the characters MSBuild treats specially inside a property value."""
    return re.sub(r'[%;$@]', lambda m: f'%{ord(m.group()):02X}', value)


def windows_build(plan):
    for key, label, path in windows_projects(plan):
        msbuild = plan.msbuild.get(key) or shutil.which('msbuild')
        if not msbuild:
            raise Fatal(f'MSBuild not found for the {label} (was --skip-checks used outside a Developer prompt?)', 3)
        cmd = [msbuild, path, f'/p:Configuration={plan.config}', '/p:Platform=x64',
               '/p:SolutionDir=' + msbuild_escape(ROOT + os.sep),    # -> <repo>\x64\<config>\ like the solution
               '/v:minimal', '/nologo', f'/m:{plan.jobs}' if plan.jobs else '/m']
        if key == 'kernel' and plan.wdk_root:
            # Pin the kit the checks verified; the project would otherwise read it from the registry,
            # where a 32-bit and a 64-bit MSBuild can see different values.
            cmd.append('/p:WDKContentRoot=' + msbuild_escape(plan.wdk_root.rstrip('\\/') + os.sep))
        if plan.clean:
            cmd.append('/t:Rebuild')
        say(f'building the {label} ({plan.config}|x64)')
        if run(cmd, plan):
            raise Fatal(f'MSBuild failed for the {label} - see the output above')


def windows_outputs(plan):
    out = os.path.join(ROOT, 'x64', plan.config)
    files = []
    if plan.kernel:
        files.append(os.path.join(out, 'KernelGuard.sys'))
    if plan.monitor:
        files.append(os.path.join(out, 'KernelGuardMonitor.exe'))
    return files


def windows_report(plan):
    header('Next steps')
    print(f'  .\\Deploy-KernelGuard.ps1 -SkipBuild -Configuration {plan.config}')
    print('      sign (test certificate), register and load the driver; needs an elevated prompt,')
    print('      test-signing on and Memory Integrity (HVCI) off - see README.md "Deploy"')


# --------------------------------------------------------------------------- main flow

def describe_host(host_os, host_arch):
    if host_os == 'linux':
        name = os_release().get('PRETTY_NAME') or 'Linux'
        return f'Linux {host_arch} - {name} - kernel {platform.release()}'
    return f'{platform.system()} {host_arch} - {platform.platform()}'


def build_plan(args, host_os, host_arch, interactive):
    """Turn the command line and the answers to the questions into a Plan."""
    rows = [(p.id, p.title, p.produces, unavailable(p.id, host_os, host_arch)) for p in PLATFORMS]
    usable = [i for i, r in enumerate(rows) if not r[3]]
    if not usable:
        raise Fatal('nothing can be built on this host: ' + '; '.join(f'{r[0]} {r[3]}' for r in rows), 3)
    if args.platform:
        row = next(r for r in rows if r[0] == args.platform)
        if row[3]:
            raise Fatal(f'cannot build for {args.platform} here: {row[3]}', 3)
        chosen = args.platform
    elif interactive:
        chosen = choose('Target platform and architecture', rows, usable[0], footer=ARCH_NOTE)
    else:
        chosen = rows[usable[0]][0]

    plan = Plan(platform=chosen, clean=args.clean, jobs=args.jobs, dry_run=args.dry_run)

    if args.components:
        plan.components = args.components
    elif interactive:
        plan.components = choose('Components', [(v, label, note, None) for v, label, note in COMPONENTS[chosen]])

    if chosen == 'linux':
        if args.config:
            warn('--config only applies to Windows builds; ignored')
        plan.kver, plan.kdir = resolve_kernel(args, interactive) if plan.kernel else (platform.release(), '')
    elif args.kver:
        warn('--kver only applies to Linux builds; ignored')

    if chosen == 'windows':
        if args.config:
            plan.config = args.config
        elif interactive and not args.check:
            plan.config = choose('Configuration', [
                ('Debug', 'Debug', 'unoptimised, with symbols (the Deploy-KernelGuard.ps1 default)', None),
                ('Release', 'Release', 'optimised', None)])
    return plan


def describe_plan(plan):
    names = {v: f'{label} - {note}' for v, label, note in COMPONENTS[plan.platform]}
    rows = [('platform', next(p.title for p in PLATFORMS if p.id == plan.platform)),
            ('components', names[plan.components])]
    if plan.platform == 'windows':
        rows.append(('configuration', plan.config))
    elif plan.kernel:
        rows.append(('kernel', plan.kver + (' (running)' if plan.kver == platform.release() else '')))
    if plan.clean:
        rows.append(('clean', 'yes, rebuild from scratch'))
    return rows


def verify_outputs(files):
    """Every expected file must exist after a build that reported success."""
    missing = [f for f in files if not os.path.isfile(f)]
    for f in files:
        if f in missing:
            fail(f'{rel(f)} was not produced')
        else:
            ok(f'{rel(f)}  ({os.path.getsize(f):,} bytes)')
    if missing:
        raise Fatal('the build reported success but its output is missing')


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog='build.py', formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Interactive, cross-platform build for KernelGuard: the Windows driver + monitor '
                    '(MSBuild) or the\nLinux kernel module + monitor (make).  Questions you do not '
                    'answer on the command line are asked.',
        epilog='examples:\n'
               '  python build.py                              ask everything\n'
               '  python build.py --check                      verify the prerequisites, build nothing\n'
               '  python build.py -y --components monitor      user-space monitor only, no questions\n'
               '  python build.py -y --config Release          Windows: Release driver + monitor\n'
               '  python build.py -y --kver 6.14.0-37-generic  Linux: module for another installed kernel\n'
               '\n'
               'Linux environment: KVER / KDIR pick the kernel (--kver wins), CC picks the compiler,\n'
               'and it is handed to make.  Exit status: 0 ok, 1 build failed, 2 bad usage,\n'
               '3 prerequisites missing, 130 interrupted.')
    sel = p.add_argument_group('selection (asked when omitted)')
    sel.add_argument('--platform', choices=[x.id for x in PLATFORMS],
                     help='what to build for; must match this host (default: this host)')
    sel.add_argument('--arch', metavar='ARCH', help='CPU architecture; only x64 (x86-64) is supported')
    sel.add_argument('--components', choices=['all', 'kernel', 'monitor'],
                     help='kernel = driver / kernel module, monitor = user-space monitor (default: all)')
    sel.add_argument('--config', type=str.capitalize, choices=['Debug', 'Release'],
                     help='Windows build configuration (default: Debug)')
    sel.add_argument('--kver', metavar='RELEASE', help='Linux: kernel release to build the module against')
    act = p.add_argument_group('behaviour')
    act.add_argument('--check', action='store_true', help='verify the prerequisites, then stop')
    act.add_argument('--skip-checks', action='store_true', help='build without verifying the prerequisites first')
    act.add_argument('--clean', action='store_true', help='rebuild from scratch')
    act.add_argument('-j', '--jobs', type=int, metavar='N', help='parallel jobs (Linux default: all CPUs)')
    act.add_argument('-y', '--yes', action='store_true', help='take the defaults, ask nothing')
    act.add_argument('-n', '--dry-run', action='store_true', help='show the build commands without running them')
    act.add_argument('--no-color', action='store_true', help='plain output')
    args = p.parse_args(argv)
    if args.jobs is not None and args.jobs < 1:
        p.error('--jobs must be at least 1')
    if args.arch and normalize_arch(args.arch) != 'x64':
        p.error(f'architecture {args.arch} is not supported: {ARCH_WHY}, so only x64 can be built')
    return args


def run_build(args):
    host_os, host_arch = detect_os(), normalize_arch(platform.machine())
    print(paint(1, 'KernelGuard build'))
    say(f'host: {describe_host(host_os, host_arch)}')
    if host_os not in ('windows', 'linux'):
        raise Fatal(f'unsupported host ({platform.system() or sys.platform}). KernelGuard builds on Windows '
                    '(driver + monitor) and on Linux (module + monitor).', 3)

    interactive = sys.stdin.isatty() and not args.yes
    if not sys.stdin.isatty() and not args.yes:
        say('stdin is not a terminal: taking the defaults for whatever is not given on the command line')

    plan = build_plan(args, host_os, host_arch, interactive)
    if plan.platform == 'linux' and plan.jobs is None:
        plan.jobs = os.cpu_count() or 1

    if not args.skip_checks or plan.platform == 'windows':
        quiet = args.skip_checks                    # Windows still needs the toolchain lookup to build
        header('Checking prerequisites')
        chk = Checks(quiet=quiet)
        (linux_checks if plan.platform == 'linux' else windows_checks)(plan, chk)
        if chk.failed and not quiet:
            fail(f'{chk.failed} prerequisite(s) missing' + ('' if args.check else ' - nothing was built'))
            return 3
        if not quiet:
            ok('all prerequisites are met' + (f' ({chk.warned} warning(s))' if chk.warned else ''))
    if args.check:
        return 0

    header('Build plan')
    for label, value in describe_plan(plan):
        print(f'  {label.ljust(14)}{value}')
    if interactive and not confirm('Proceed?'):
        raise Abort('cancelled')

    header('Building')
    started = time.monotonic()
    (linux_build if plan.platform == 'linux' else windows_build)(plan)
    if plan.dry_run:
        say('dry run: nothing was executed')
        return 0

    header('Result')
    verify_outputs((linux_outputs if plan.platform == 'linux' else windows_outputs)(plan))
    ok(f'built in {time.monotonic() - started:.1f} s')
    (linux_report if plan.platform == 'linux' else windows_report)(plan)
    return 0


def main(argv=None):
    args = parse_args(argv)
    setup_output(args.no_color)
    try:
        return run_build(args)
    except Fatal as e:
        fail(str(e))
        return e.code
    except Abort as e:
        print(f'\nAborted ({e}).')
        return 1
    except KeyboardInterrupt:
        print('\nInterrupted.')
        return 130


if __name__ == '__main__':
    sys.exit(main())
