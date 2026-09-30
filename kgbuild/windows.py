"""Windows platform: KernelGuard.sys (WDM driver) and KernelGuardMonitor.exe, built from windows/ with MSBuild."""
import glob
import json
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections import namedtuple
from dataclasses import dataclass, field

from .console import Fatal, choose, header, say, warn
from .core import ROOT, Plan, describe_generic_host, rel, run, version_key

ID = 'windows'
TITLE = 'Windows x64 (x86-64)'
PRODUCES = 'KernelGuard.sys + KernelGuardMonitor.exe'
COMPONENTS = [('all', 'Everything', 'driver + monitor'),
              ('kernel', 'Driver only', 'KernelGuard.sys'),
              ('monitor', 'Monitor only', 'KernelGuardMonitor.exe')]
CHECKS_REQUIRED = True                      # the checks also locate MSBuild and the WDK, which the build uses

WINDOWS_DIR = os.path.join(ROOT, 'windows')     # holds KernelGuard.sln: MSBuild's $(SolutionDir) and x64\<config>\
DRIVER_PROJ = os.path.join(WINDOWS_DIR, 'src', 'KernelGuard.vcxproj')
MONITOR_PROJ = os.path.join(WINDOWS_DIR, 'usermode', 'KernelGuardMonitor.vcxproj')

VS_URL = 'https://visualstudio.microsoft.com/downloads/'
WDK_URL = 'https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk'


@dataclass
class WindowsPlan(Plan):
    config: str = 'Debug'
    msbuild: dict = field(default_factory=dict)     # component -> MSBuild.exe, set by the checks
    wdk_root: str = ''                              # Windows Kits root holding the WDK


PLAN = WindowsPlan


# --------------------------------------------------------------------------- what build.py asks of a platform

def unavailable(host_os, host_arch):
    """Why this platform cannot be built on this host, or None."""
    if host_os != ID:
        return 'needs a Windows host with Visual Studio and the WDK'
    return None


def configure(plan, args, interactive):
    """The build configuration."""
    if args.kver:
        warn('--kver only applies to Linux builds; ignored')
    if args.config:
        plan.config = args.config
    elif interactive and not args.check:
        plan.config = choose('Configuration', [
            ('Debug', 'Debug', 'unoptimised, with symbols (the Deploy-KernelGuard.ps1 default)', None),
            ('Release', 'Release', 'optimised', None)])


def describe_host(host_arch):
    return describe_generic_host(host_arch)


def plan_rows(plan):
    return [('configuration', plan.config)]


# --------------------------------------------------------------------------- the Windows toolchain

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


def selected_projects(plan):
    projects = []
    if plan.kernel:
        projects.append(('kernel', 'driver', DRIVER_PROJ))
    if plan.monitor:
        projects.append(('monitor', 'monitor', MONITOR_PROJ))
    return projects


def checks(plan, chk):
    projects = selected_projects(plan)
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
                chk.ok('driver: MASM build customization (for windows/src/asm/verw_flush.asm)')
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


def build(plan):
    for key, label, path in selected_projects(plan):
        msbuild = plan.msbuild.get(key) or shutil.which('msbuild')
        if not msbuild:
            raise Fatal(f'MSBuild not found for the {label} (was --skip-checks used outside a Developer prompt?)', 3)
        cmd = [msbuild, path, f'/p:Configuration={plan.config}', '/p:Platform=x64',
               '/p:SolutionDir=' + msbuild_escape(WINDOWS_DIR + os.sep),    # -> <repo>\windows\x64\<config>\ like the solution
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


def outputs(plan):
    out = os.path.join(WINDOWS_DIR, 'x64', plan.config)
    files = []
    if plan.kernel:
        files.append(os.path.join(out, 'KernelGuard.sys'))
    if plan.monitor:
        files.append(os.path.join(out, 'KernelGuardMonitor.exe'))
    return files


def report(plan):
    header('Next steps')
    print(f'  .\\windows\\scripts\\Deploy-KernelGuard.ps1 -SkipBuild -Configuration {plan.config}')
    print('      sign (test certificate), register and load the driver; needs an elevated prompt,')
    print('      test-signing on and Memory Integrity (HVCI) off - see README.md "Deploy"')
