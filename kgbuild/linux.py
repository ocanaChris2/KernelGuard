"""Linux platform: kernelguard.ko (Kbuild) and kgmon (make), built from linux/."""
import glob
import os
import platform
import re
import shlex
import shutil
from dataclasses import dataclass

from .console import Fatal, choose, header, more, say, warn
from .core import ROOT, Plan, first_line, run, version_key

ID = 'linux'
TITLE = 'Linux x64 (x86-64)'
PRODUCES = 'kernelguard.ko + kgmon'
COMPONENTS = [('all', 'Everything', 'kernel module + monitor'),
              ('kernel', 'Kernel module only', 'kernelguard.ko'),
              ('monitor', 'Monitor only', 'kgmon')]
CHECKS_REQUIRED = False

LINUX_DIR = os.path.join(ROOT, 'linux')


@dataclass
class LinuxPlan(Plan):
    kver: str = ''                          # kernel release ...
    kdir: str = ''                          # ... and its build tree


PLAN = LinuxPlan


# --------------------------------------------------------------------------- what build.py asks of a platform

def unavailable(host_os, host_arch):
    """Why this platform cannot be built on this host, or None."""
    if host_os != ID:
        return 'needs a Linux host with kernel headers'
    if host_arch != 'x64':
        return f'needs an x86-64 host, this one is {host_arch}'
    return None


def describe_host(host_arch):
    name = os_release().get('PRETTY_NAME') or 'Linux'
    return f'Linux {host_arch} - {name} - kernel {platform.release()}'


def configure(plan, args, interactive):
    """The kernel to build against, and every CPU by default."""
    if args.config:
        warn('--config only applies to Windows builds; ignored')
    plan.kver, plan.kdir = resolve_kernel(args, interactive) if plan.kernel else (platform.release(), '')
    if plan.jobs is None:
        plan.jobs = os.cpu_count() or 1


def plan_rows(plan):
    if not plan.kernel:
        return []
    return [('kernel', plan.kver + (' (running)' if plan.kver == platform.release() else ''))]


# --------------------------------------------------------------------------- the Linux toolchain

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


def checks(plan, chk):
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


def build(plan):
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


def outputs(plan):
    files = []
    if plan.kernel:
        files.append(os.path.join(LINUX_DIR, 'module', 'kernelguard.ko'))
    if plan.monitor:
        files.append(os.path.join(LINUX_DIR, 'monitor', 'kgmon'))
    return files


def report(plan):
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
