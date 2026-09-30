#!/usr/bin/env python3
"""
build.py  -  interactive, cross-platform build for KernelGuard.

  Windows host   KernelGuard.sys (WDM driver) + KernelGuardMonitor.exe   via MSBuild      (windows/)
  Linux host     kernelguard.ko (kernel module) + kgmon                  via make / Kbuild (linux/)

It asks what to build (platform and architecture, components, and the configuration
or kernel version), checks that the toolchain for that choice is installed, then builds.
It never signs, installs or loads anything: see windows/scripts/Deploy-KernelGuard.ps1 (Windows)
and linux/scripts/kg-deploy.sh (Linux) for that.

    python build.py             ask everything
    python build.py --check     only verify the prerequisites
    python build.py -y          take every default, ask nothing
    python build.py --help      all options

Standard library only.  Exit status: 0 ok, 1 build failed, 2 bad usage,
3 prerequisites missing, 130 interrupted.

The code is in kgbuild/: one module per platform (linux.py, windows.py) and the platform-neutral
flow they plug into.
"""
import os
import platform
import sys

if sys.version_info < (3, 8):
    sys.exit('[FAIL] Python 3.8 or newer is required (this is %s)' % platform.python_version())

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kgbuild.cli import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())
