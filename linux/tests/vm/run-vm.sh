#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# run-vm.sh - load-test kernelguard.ko inside a throw-away QEMU/KVM guest.
#
# The module is NEVER loaded on the host.  The guest boots a real distro kernel
# (same version as the header tree the module is built against) with a busybox
# initramfs, loads a KG_TESTHOOKS build of the module, and runs one guest-side
# test script from tests/vm/guest/.  Success is the line "TEST-RESULT: PASS" on
# the serial console.
#
# Usage:   run-vm.sh TEST [TEST...]      e.g. run-vm.sh basic pmu
#          run-vm.sh --list
#
# A test may ship optional files next to guest/TEST.sh:
#   TEST.qemu     extra QEMU arguments            (hw: PCIe root ports to hot-plug into)
#   TEST.smp      value for -smp                  (smt: 4,sockets=1,cores=2,threads=2)
#   TEST.machine  value for -machine              (hwlegacy: pc, i.e. no MCFG table)
# The guest can drive the QEMU monitor (e.g. PCI hot-plug) by printing "@@QEMU <command>".
#
# Environment:
#   KG_KVER      kernel version to build for / boot   (default: uname -r)
#   KG_KERNEL    bzImage to boot                       (default: /boot/vmlinuz-$KG_KVER)
#                Distro images are often root-only; fetch a readable copy with
#                  apt-get download linux-image-$KG_KVER && dpkg-deb -x linux-image-*.deb dir
#   KG_CPUS KG_MEM KG_MACHINE KG_TIMEOUT KG_QEMU_ARGS KG_KEEP=1 (keep work dir)
set -euo pipefail
shopt -s nullglob

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LINUX=$(cd "$HERE/../.." && pwd)
KVER=${KG_KVER:-$(uname -r)}
KERNEL=${KG_KERNEL:-/boot/vmlinuz-$KVER}
CPUS=${KG_CPUS:-4}
MEM=${KG_MEM:-1024}
MACHINE=${KG_MACHINE:-q35}
TIMEOUT=${KG_TIMEOUT:-180}

if [[ ${1:-} == --list ]]; then
    ls "$HERE/guest" | sed -n 's/\.sh$//p' | grep -v '^lib$'
    exit 0
fi
[[ $# -ge 1 ]] || { sed -n '3,22p' "$0"; exit 2; }

for tool in qemu-system-x86_64 busybox cpio gzip gcc make; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
[[ -r $KERNEL ]] || { echo "cannot read kernel image $KERNEL (see KG_KERNEL in the header)" >&2; exit 2; }
[[ -d /lib/modules/$KVER/build ]] || { echo "no kernel headers for $KVER" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/kgvm.XXXXXX")
[[ ${KG_KEEP:-0} == 1 ]] || trap 'rm -rf "$WORK"' EXIT
echo "== work dir: $WORK   kernel: $KVER ($KERNEL)"

# ---- 1. build everything (out of tree copy, so the working tree stays clean) ----
cp -a "$LINUX/module" "$WORK/module"
cp -a "$LINUX/include" "$WORK/include"
cp -a "$HERE/testmods" "$WORK/testmods"
make -C "$WORK/module" KVER="$KVER" KG_TESTHOOKS=1 >"$WORK/build-module.log" 2>&1 \
    || { tail -30 "$WORK/build-module.log"; echo "module build failed" >&2; exit 1; }
make -C "$WORK/testmods" KVER="$KVER" EXTRA_SYMBOLS="$WORK/module/Module.symvers" >"$WORK/build-testmods.log" 2>&1 \
    || { tail -30 "$WORK/build-testmods.log"; echo "test module build failed" >&2; exit 1; }
make -C "$LINUX/monitor" static >"$WORK/build-monitor.log" 2>&1 \
    || { tail -30 "$WORK/build-monitor.log"; echo "monitor build failed" >&2; exit 1; }
cp "$LINUX/monitor/kgmon" "$WORK/kgmon"
make -C "$LINUX/monitor" clean >/dev/null 2>&1 || true
for h in "$HERE"/helpers/*.c; do
    gcc -O2 -static -Wall -Wextra -I"$LINUX/include" "$h" -o "$WORK/$(basename "${h%.c}")" \
        || { echo "helper build failed: $h" >&2; exit 1; }
done

# ---- 2. initramfs ----
R="$WORK/rootfs"
mkdir -p "$R"/{bin,sbin,proc,sys,dev,tmp,run,etc,modules,tests}
cp "$(command -v busybox)" "$R/bin/busybox"
for a in $(busybox --list); do [[ $a == busybox ]] || ln -sf busybox "$R/bin/$a"; done
cp "$WORK/module/kernelguard.ko" "$R/modules/"
cp "$WORK"/testmods/*.ko "$R/modules/" 2>/dev/null || true
cp "$WORK/kgmon" "$R/bin/kgmon"
for h in "$HERE"/helpers/*.c; do cp "$WORK/$(basename "${h%.c}")" "$R/bin/"; done
cp "$HERE"/guest/*.sh "$R/tests/"
mkdir -p "$R/scripts" "$R/var/log"
cp "$LINUX"/scripts/*.sh "$R/scripts/"
cp "$HERE/guest/init" "$R/init"
chmod +x "$R/init"
( cd "$R" && find . | cpio -o -H newc --quiet | gzip -1 ) > "$WORK/initramfs.gz"

# ---- 3. run the guest ----
run_one() {
    local test=$1 log="$WORK/console-$1.log" accel cpu quiet=1
    [[ -z ${KG_VERBOSE:-} ]] || quiet=0
    [[ -f $HERE/guest/$test.sh ]] || { echo "no such test: $test (try --list)" >&2; return 2; }
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then
        accel="-enable-kvm"; cpu="host,pmu=on"
    else
        echo "!! /dev/kvm not available: falling back to TCG (no PMU, slow)"; accel=""; cpu="max"
    fi
    local extra="" mon="$WORK/mon-$test.sock" watcher smp="$CPUS" machine="$MACHINE"
    [[ -f $HERE/guest/$test.qemu ]] && extra=$(<"$HERE/guest/$test.qemu")
    [[ -f $HERE/guest/$test.smp ]] && smp=$(<"$HERE/guest/$test.smp")      # e.g. 4,cores=2,threads=2
    [[ -f $HERE/guest/$test.machine ]] && machine=$(<"$HERE/guest/$test.machine")   # e.g. pc
    echo "== test: $test"

    # The guest can ask the host to drive the QEMU monitor (e.g. PCI hot-plug) by
    # printing a line "@@QEMU <monitor command>" on its console.
    : > "$log"
    ( tail -n +1 -F "$log" 2>/dev/null | while IFS= read -r line; do
          line=${line%$'\r'}
          [[ $line == "@@QEMU "* ]] || continue
          {
          python3 - "$mon" "${line#@@QEMU }" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
for _ in range(50):
    try:
        s.connect(sys.argv[1]); break
    except OSError:
        time.sleep(0.1)
s.settimeout(1.0)
try: s.recv(4096)
except Exception: pass
s.sendall((sys.argv[2] + "\n").encode())
time.sleep(0.4)
try:
    reply = s.recv(4096).decode(errors="replace").replace("\r", "").strip()
except Exception:
    reply = ""
print("@@QEMU-REPLY " + sys.argv[2] + " => " + " | ".join(l for l in reply.splitlines() if l.strip() and not l.startswith("(qemu)")), flush=True)
PY
          } >> "$WORK/monitor-$test.log" 2>&1
      done ) &
    watcher=$!

    # shellcheck disable=SC2086
    timeout "$TIMEOUT" qemu-system-x86_64 $accel -cpu "$cpu" -machine "$machine" \
        -m "$MEM" -smp "$smp" -nographic -no-reboot -monitor "unix:$mon,server,nowait" \
        -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
        -append "console=ttyS0 panic=-1 oops=panic loglevel=7 printk.time=0 rdinit=/init kgtest=$test kgquiet=$quiet" \
        $extra ${KG_QEMU_ARGS:-} 2>&1 | sed -u 's/\r$//' | tee -a "$log" \
        | sed -u -n '/^== guest begin/,$p'
    pkill -P "$watcher" 2>/dev/null; kill "$watcher" 2>/dev/null || true
    [[ -s $WORK/monitor-$test.log ]] && sed 's/^/   /' "$WORK/monitor-$test.log"
    grep -q '^TEST-RESULT: PASS' "$log"
}

rc=0
for t in "$@"; do run_one "$t" || rc=1; done
[[ $rc -eq 0 ]] && echo "== ALL PASSED" || echo "== FAILURES (logs in $WORK, rerun with KG_KEEP=1)"
exit $rc
