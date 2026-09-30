#!/bin/sh
# Launcher for build.py: finds a Python 3 interpreter, then runs it with the same arguments.
#   ./build.sh [options]        see ./build.sh --help
# On Windows use build.cmd.

HERE=$(cd "$(dirname "$0")" && pwd)

for py in python3 python; do
    if command -v "$py" >/dev/null 2>&1 &&
       "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
        exec "$py" "$HERE/build.py" "$@"
    fi
done

echo "[FAIL] Python 3.8 or newer is required to run build.py" >&2
echo "       Debian/Ubuntu/Mint: sudo apt install python3      Fedora: sudo dnf install python3" >&2
echo "       Arch: sudo pacman -S python                       openSUSE: sudo zypper install python3" >&2
exit 3
