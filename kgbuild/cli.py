"""Options and the platform-neutral flow: ask, check, build, verify.  The platform work is in linux.py / windows.py."""
import argparse
import os
import platform
import sys
import time

from . import linux, windows
from .console import Abort, Fatal, choose, confirm, fail, header, ok, paint, say, setup_output
from .core import ARCH_NOTE, ARCH_WHY, Checks, describe_generic_host, detect_os, normalize_arch, rel

BACKENDS = [linux, windows]                 # the order of the platform menu


def backend_for(platform_id):
    return next(b for b in BACKENDS if b.ID == platform_id)


# --------------------------------------------------------------------------- main flow

def describe_host(host_os, host_arch):
    backend = next((b for b in BACKENDS if b.ID == host_os), None)
    return (backend.describe_host if backend else describe_generic_host)(host_arch)


def build_plan(args, host_os, host_arch, interactive):
    """Turn the command line and the answers to the questions into a Plan."""
    rows = [(b.ID, b.TITLE, b.PRODUCES, b.unavailable(host_os, host_arch)) for b in BACKENDS]
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

    backend = backend_for(chosen)
    plan = backend.PLAN(platform=chosen, clean=args.clean, jobs=args.jobs, dry_run=args.dry_run)

    if args.components:
        plan.components = args.components
    elif interactive:
        plan.components = choose('Components', [(v, label, note, None) for v, label, note in backend.COMPONENTS])

    backend.configure(plan, args, interactive)
    return plan


def describe_plan(plan):
    backend = backend_for(plan.platform)
    names = {v: f'{label} - {note}' for v, label, note in backend.COMPONENTS}
    rows = [('platform', backend.TITLE),
            ('components', names[plan.components])]
    rows += backend.plan_rows(plan)
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
    sel.add_argument('--platform', choices=[b.ID for b in BACKENDS],
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
    if host_os not in [b.ID for b in BACKENDS]:
        raise Fatal(f'unsupported host ({platform.system() or sys.platform}). KernelGuard builds on Windows '
                    '(driver + monitor) and on Linux (module + monitor).', 3)

    interactive = sys.stdin.isatty() and not args.yes
    if not sys.stdin.isatty() and not args.yes:
        say('stdin is not a terminal: taking the defaults for whatever is not given on the command line')

    plan = build_plan(args, host_os, host_arch, interactive)
    backend = backend_for(plan.platform)

    if not args.skip_checks or backend.CHECKS_REQUIRED:
        quiet = args.skip_checks                    # a platform whose build needs the toolchain lookup still runs it
        header('Checking prerequisites')
        chk = Checks(quiet=quiet)
        backend.checks(plan, chk)
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
    backend.build(plan)
    if plan.dry_run:
        say('dry run: nothing was executed')
        return 0

    header('Result')
    verify_outputs(backend.outputs(plan))
    ok(f'built in {time.monotonic() - started:.1f} s')
    backend.report(plan)
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
