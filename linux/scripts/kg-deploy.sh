#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# kg-deploy.sh - build / sign / load / persist KernelGuard on Linux.
# Counterpart of windows/scripts/Deploy-KernelGuard.ps1.
#
#   kg-deploy.sh preflight                 what would stop the module loading here?
#   kg-deploy.sh build                     build module + monitor for the running kernel
#   kg-deploy.sh sign [--key K --cert C]   sign the module (Secure Boot / sig_enforce)
#   kg-deploy.sh install [--enforce] [--monitor] [key=value ...]
#                                          load the module now (needs root)
#   kg-deploy.sh status                    module + monitor state
#   kg-deploy.sh uninstall                 stop the monitor, unload the module
#   kg-deploy.sh persist [key=value ...]   load at every boot (module, modprobe options,
#                                          monitor service, udev rule)
#   kg-deploy.sh unpersist                 undo persist
#
# key=value arguments are module parameters (enforce=1, kbd_allow=..., dma_allow=...,
# pmu_warn=..., see README).  Environment: KVER (kernel to build for),
# KG_MODULE / KG_KGMON (override the artefact paths), DESTDIR (stage `persist`
# into a directory instead of the live system - no root needed).
#
# Nothing here is destructive beyond insmod/rmmod of this one module and the files
# `persist` names.  The module defaults to detect-only; --enforce is opt-in.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
LINUX=$(cd "$HERE/.." && pwd)
KVER=${KVER:-$(uname -r)}
MOD=${KG_MODULE:-$LINUX/module/kernelguard.ko}
KGMON=${KG_KGMON:-$LINUX/monitor/kgmon}
DESTDIR=${DESTDIR:-}
PIDFILE=/run/kernelguard-monitor.pid
LOGFILE=/var/log/kernelguard-alerts.csv

say()  { printf '[....] %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

need_root() {
    [ "$(id -u)" -eq 0 ] || die "this action needs root (try: sudo $0 $ACTION ...)"
}

loaded() { grep -q '^kernelguard ' /proc/modules 2>/dev/null; }

sig_enforced() {
    [ "$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null || echo N)" = Y ]
}

module_signed() {
    [ -n "$(modinfo -F sig_id "$MOD" 2>/dev/null)" ]
}

# ---------------------------------------------------------------------------
do_preflight() {
    say "kernel $KVER on $(uname -m)"
    [ "$(uname -m)" = x86_64 ] || die "x86-64 only"

    if [ -d "/lib/modules/$KVER/build" ]; then ok "kernel headers present"
    else warn "no kernel headers at /lib/modules/$KVER/build (install linux-headers-$KVER to build)"; fi
    for t in make gcc; do
        command -v $t >/dev/null 2>&1 && ok "$t found" || warn "$t not found (needed to build)"
    done

    if command -v mokutil >/dev/null 2>&1; then
        say "Secure Boot: $(mokutil --sb-state 2>&1 | head -1)"
    fi
    if sig_enforced; then
        warn "module signature enforcement is ON (sig_enforce=Y): the module must be signed"
    else
        ok "module signature enforcement is off"
    fi
    if [ -r /sys/kernel/security/lockdown ]; then
        say "kernel lockdown: $(cat /sys/kernel/security/lockdown)"
    fi
    [ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 0)" = 0 ] \
        && ok "module loading is enabled" || die "kernel.modules_disabled=1: nothing can be loaded until reboot"

    if [ -f "$MOD" ]; then
        if module_signed; then ok "$MOD is signed"; else warn "$MOD is not signed"; fi
    else
        warn "$MOD not built yet (run: $0 build)"
    fi
    loaded && warn "kernelguard is already loaded" || ok "kernelguard is not loaded"
}

do_build() {
    say "building module + monitor for $KVER"
    make -C "$LINUX" KVER="$KVER" >/dev/null
    ok "built $MOD"
    ok "built $KGMON"
}

do_sign() {
    KEY=/var/lib/shim-signed/mok/MOK.priv
    CERT=/var/lib/shim-signed/mok/MOK.der
    FORCE=0
    while [ $# -gt 0 ]; do
        case $1 in
            --key) KEY=$2; shift 2;;
            --cert) CERT=$2; shift 2;;
            --force) FORCE=1; shift;;
            *) die "unknown option $1";;
        esac
    done
    [ -f "$MOD" ] || die "$MOD not built (run: $0 build)"
    if module_signed && [ $FORCE -eq 0 ]; then ok "module already signed (use --force to re-sign)"; return; fi
    SIGN=""
    for c in "/usr/src/linux-headers-$KVER/scripts/sign-file" "/lib/modules/$KVER/build/scripts/sign-file"; do
        [ -x "$c" ] && { SIGN=$c; break; }
    done
    [ -n "$SIGN" ] || die "scripts/sign-file not found in the kernel headers for $KVER"
    [ -r "$KEY" ] && [ -r "$CERT" ] || die "signing key/cert not readable: $KEY $CERT
       Create and enrol a Machine Owner Key first (Ubuntu/Mint: sudo update-secureboot-policy --new-key,
       then reboot and confirm the enrolment), or pass --key / --cert."
    say "signing with $CERT"
    cp "$MOD" "$MOD.signing"
    "$SIGN" sha256 "$KEY" "$CERT" "$MOD.signing"
    mv "$MOD.signing" "$MOD"
    ok "signed $MOD"
}

start_monitor() {
    [ -x "$KGMON" ] || die "$KGMON not built"
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        ok "monitor already running (pid $(cat "$PIDFILE"))"; return
    fi
    "$KGMON" --syslog --quiet --log "$LOGFILE" >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    ok "monitor started (pid $!, alerts -> syslog and $LOGFILE)"
}

stop_monitor() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null && ok "monitor stopped" || true
        rm -f "$PIDFILE"
    fi
}

do_install() {
    need_root
    PARAMS=""; MONITOR=0
    while [ $# -gt 0 ]; do
        case $1 in
            --enforce) PARAMS="$PARAMS enforce=1"; shift;;
            --monitor) MONITOR=1; shift;;
            *=*) PARAMS="$PARAMS $1"; shift;;
            *) die "unknown option $1";;
        esac
    done
    [ -f "$MOD" ] || die "$MOD not built (run: $0 build)"
    if sig_enforced && ! module_signed; then
        die "the kernel enforces module signatures and $MOD is unsigned.
       Run: $0 sign      (needs an enrolled Machine Owner Key - see README 'Secure Boot')"
    fi
    if loaded; then die "kernelguard is already loaded (use: $0 uninstall)"; fi
    case " $PARAMS " in *" enforce=1 "*)
        warn "enforce=1: unauthorised bus masters lose bus mastering, unauthorised input handlers are detached."
        warn "Emergency off without unloading: echo 0 > /sys/module/kernelguard/parameters/enforce";;
    esac

    say "loading kernelguard${PARAMS:+ ($PARAMS)}"
    # shellcheck disable=SC2086
    insmod "$MOD" $PARAMS || die "insmod failed - see: dmesg | tail -20"
    i=0; while [ $i -lt 20 ] && [ ! -c /dev/kernelguard ]; do sleep 0.1; i=$((i + 1)); done
    [ -c /dev/kernelguard ] || die "/dev/kernelguard did not appear"
    ok "module loaded, /dev/kernelguard ready"
    [ ! -x "$KGMON" ] || "$KGMON" status 2>&1 | sed -n '1,9p'
    [ $MONITOR -eq 0 ] || start_monitor
}

do_status() {
    if loaded; then
        ok "kernelguard is loaded"
        for p in /sys/module/kernelguard/parameters/*; do
            [ -r "$p" ] && printf '        %-24s %s\n' "$(basename "$p")" "$(cat "$p" 2>/dev/null)"
        done
        [ ! -x "$KGMON" ] || [ "$(id -u)" -ne 0 ] || "$KGMON" status
    else
        warn "kernelguard is not loaded"
    fi
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        ok "monitor running (pid $(cat "$PIDFILE"))"
    else
        say "monitor not running from this script (a systemd unit would show in: systemctl status kernelguard-monitor)"
    fi
}

do_uninstall() {
    need_root
    stop_monitor
    if loaded; then
        WAS=$(cat /sys/module/kernelguard/parameters/enforce 2>/dev/null || echo N)
        # Make sure nothing is left acting on the system before the module goes.
        echo 0 > /sys/module/kernelguard/parameters/enforce 2>/dev/null || true
        rmmod kernelguard || die "rmmod failed (is a monitor still holding /dev/kernelguard?)"
        ok "kernelguard unloaded"
        if [ "$WAS" = Y ]; then
            warn "enforce was on: input handlers it detached were NOT re-attached - reload the driver"
            warn "that provides them (or replug the device) if any input stopped working"
        fi
    else
        ok "kernelguard was not loaded"
    fi
}

do_persist() {
    [ -n "$DESTDIR" ] || need_root
    PARAMS=""
    for a in "$@"; do
        case $a in *=*) PARAMS="$PARAMS $a";; *) die "persist takes only key=value module parameters";; esac
    done
    [ -f "$MOD" ] || die "$MOD not built (run: $0 build)"
    if [ -z "$DESTDIR" ] && sig_enforced && ! module_signed; then
        die "signature enforcement is on and the module is unsigned - run: $0 sign"
    fi
    R=$DESTDIR
    say "installing into ${R:-/} for kernel $KVER"

    mkdir -p "$R/lib/modules/$KVER/extra" "$R/etc/modules-load.d" "$R/etc/modprobe.d" \
             "$R/usr/local/sbin" "$R/etc/systemd/system" "$R/etc/udev/rules.d"
    install -m 0644 "$MOD" "$R/lib/modules/$KVER/extra/kernelguard.ko"
    echo kernelguard > "$R/etc/modules-load.d/kernelguard.conf"
    {
        echo "# written by kg-deploy.sh persist"
        echo "options kernelguard$PARAMS"
    } > "$R/etc/modprobe.d/kernelguard.conf"
    [ ! -x "$KGMON" ] || install -m 0755 "$KGMON" "$R/usr/local/sbin/kgmon"
    install -m 0644 "$HERE/kernelguard-monitor.service" "$R/etc/systemd/system/kernelguard-monitor.service"
    install -m 0644 "$HERE/70-kernelguard.rules" "$R/etc/udev/rules.d/70-kernelguard.rules"

    if [ -z "$DESTDIR" ]; then
        depmod -a "$KVER"
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable kernelguard-monitor.service 2>/dev/null || true
        udevadm control --reload 2>/dev/null || true
    fi
    ok "module in /lib/modules/$KVER/extra, options in /etc/modprobe.d/kernelguard.conf"
    ok "loads at boot via /etc/modules-load.d/kernelguard.conf; monitor unit installed"
    warn "this is per kernel: after a kernel update rebuild (or use DKMS) and sign again"
}

do_unpersist() {
    [ -n "$DESTDIR" ] || need_root
    R=$DESTDIR
    [ -n "$DESTDIR" ] || { systemctl disable --now kernelguard-monitor.service 2>/dev/null || true; }
    rm -f "$R/etc/modules-load.d/kernelguard.conf" "$R/etc/modprobe.d/kernelguard.conf" \
          "$R/etc/systemd/system/kernelguard-monitor.service" "$R/etc/udev/rules.d/70-kernelguard.rules" \
          "$R/lib/modules/$KVER/extra/kernelguard.ko" "$R/usr/local/sbin/kgmon"
    [ -n "$DESTDIR" ] || { depmod -a "$KVER"; systemctl daemon-reload 2>/dev/null || true; }
    ok "persistent installation removed"
}

usage() { sed -n '4,25p' "$0" | sed 's/^# \{0,1\}//'; }

ACTION=${1:-}
[ $# -eq 0 ] || shift
case $ACTION in
    preflight) do_preflight;;
    build) do_build;;
    sign) do_sign "$@";;
    install) do_install "$@";;
    status) do_status;;
    uninstall) do_uninstall;;
    persist) do_persist "$@";;
    unpersist) do_unpersist;;
    ""|-h|--help|help) usage;;
    *) usage; exit 2;;
esac
