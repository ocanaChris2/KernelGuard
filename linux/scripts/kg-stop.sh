#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# kg-stop.sh - emergency stop.  Counterpart of windows/scripts/stop_driver.bat.
#
# Turns active mitigation off first (so nothing more is cleared or detached), then
# stops the monitor and unloads the module.  Needs no keyboard input beyond
# running it, so it works from an SSH session or a script when local input
# misbehaves.  Run as root:   sudo sh kg-stop.sh
set -u

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo sh $0" >&2; exit 1; }

P=/sys/module/kernelguard/parameters/enforce
[ -w "$P" ] && { echo 0 > "$P"; echo "enforce switched off"; }

[ -f /run/kernelguard-monitor.pid ] && kill "$(cat /run/kernelguard-monitor.pid)" 2>/dev/null
systemctl stop kernelguard-monitor.service 2>/dev/null
killall kgmon 2>/dev/null

if grep -q '^kernelguard ' /proc/modules; then
    rmmod kernelguard && echo "kernelguard unloaded" || { echo "rmmod failed - is something holding /dev/kernelguard open?" >&2; exit 1; }
else
    echo "kernelguard is not loaded"
fi
echo "If an input device stopped working while enforce=1 was active, reload the driver that"
echo "provides its input handler (modprobe -r X && modprobe X) or replug the device."
