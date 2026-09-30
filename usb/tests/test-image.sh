#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# test-image.sh - boot usb/out/kernelguard-live.img in QEMU (BIOS, then UEFI) and check the scan.
#
# Two fake "host" drives are attached: a Linux root holding a module (as .ko and as .ko.zst) and a
# Windows system drive holding one .sys.  Both are put on the deny lists in the image's KGDATA
# partition, so a passing run shows: the module loads, both host drives are found and listed,
# compressed modules are identified, deny-list matches become FINDINGs, the report lands on
# KGDATA, and the guest powers itself off.
#
# The module is loaded only inside QEMU, never on the host.
#
# Usage:   usb/tests/test-image.sh [IMAGE]       Environment: KG_KVER (as for build-image.sh), KG_TIMEOUT
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMG=${1:-$HERE/../out/kernelguard-live.img}
KVER=${KG_KVER:-$(uname -r)}
TIMEOUT=${KG_TIMEOUT:-240}
OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd

die() { echo "test-image: $*" >&2; exit 1; }
for t in qemu-system-x86_64 sgdisk mcopy mkfs.ext4 mkfs.vfat zstd sha256sum; do
    command -v "$t" >/dev/null || die "missing tool: $t"
done
[[ -f $IMG ]] || die "no image at $IMG (run usb/build-image.sh first)"
DUMMY=/lib/modules/$KVER/kernel/drivers/net/dummy.ko.zst
[[ -f $DUMMY ]] || die "need a sample module: $DUMMY"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/kgusbtest.XXXXXX")
[[ ${KG_KEEP:-0} == 1 ]] || trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

part_start() { sgdisk -i "$1" "$2" | awk '/First sector/ {print $3}'; }

# Wrap a filesystem image in a one-partition GPT disk (real hosts have partition tables).
wrap_disk() {   # fsimg outdisk
    local size_mb=$(( $(stat -c %s "$1") / 1048576 + 2 ))
    truncate -s "${size_mb}M" "$2"
    sgdisk -o -n 1:2048:0 -t 1:8300 "$2" >/dev/null
    dd if="$1" of="$2" bs=512 seek=2048 conv=notrunc status=none
}

# ---- fake host drives ----
mkdir -p "$WORK/lin/lib/modules/$KVER/kernel/drivers/net"
zstd -dcq "$DUMMY" > "$WORK/lin/lib/modules/$KVER/kernel/drivers/net/dummy.ko"
cp "$DUMMY" "$WORK/lin/lib/modules/$KVER/kernel/drivers/net/dummy-zst.ko.zst"
truncate -s 24M "$WORK/lin.fs"
mkfs.ext4 -q -d "$WORK/lin" "$WORK/lin.fs"
wrap_disk "$WORK/lin.fs" "$WORK/host-linux.img"

mkdir -p "$WORK/win"
printf 'MZ this is not a real driver, just bytes with a known hash\n' > "$WORK/evil.sys"
truncate -s 34M "$WORK/win.fs"
mkfs.vfat -F 32 "$WORK/win.fs" >/dev/null
mmd -i "$WORK/win.fs" ::/Windows ::/Windows/System32 ::/Windows/System32/drivers
mcopy -i "$WORK/win.fs" "$WORK/evil.sys" ::/Windows/System32/drivers/evil.sys
wrap_disk "$WORK/win.fs" "$WORK/host-windows.img"
EVIL_HASH=$(sha256sum "$WORK/evil.sys" | cut -d' ' -f1)

run_boot() {   # mode(bios|uefi)
    local mode=$1 disk="$WORK/live-$1.img" log="$WORK/console-$1.log" fw=() accel cpu
    cp "$IMG" "$disk"
    local off=$(( $(part_start 3 "$disk") * 512 ))

    # deny entries: the Windows driver by hash, the compressed module by name (@srcversion-less)
    echo "$EVIL_HASH  test driver" > "$WORK/sha256.deny"
    echo "dummy  test module entry" > "$WORK/modules.deny"
    mcopy -o -i "$disk@@$off" "$WORK/sha256.deny" "$WORK/modules.deny" ::/blocklist/

    [[ $mode == uefi ]] && { cp "$OVMF_VARS" "$WORK/vars-$mode.fd"
        fw=(-drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" -drive if=pflash,format=raw,file="$WORK/vars-$mode.fd"); }
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then accel=-enable-kvm; cpu=host,pmu=on
    else echo "!! no /dev/kvm: TCG (slow)"; accel=""; cpu=max; fi

    echo "== boot: $mode"
    # shellcheck disable=SC2086
    timeout "$TIMEOUT" qemu-system-x86_64 $accel -cpu "$cpu" -machine q35 -m 1024 -smp 2 \
        -nographic -no-reboot "${fw[@]}" \
        -drive file="$disk",format=raw,if=none,id=live -device ide-hd,drive=live,bus=ide.0,bootindex=0 \
        -drive file="$WORK/host-linux.img",format=raw,if=none,id=hl -device virtio-blk-pci,drive=hl \
        -drive file="$WORK/host-windows.img",format=raw,if=none,id=hw -device virtio-blk-pci,drive=hw \
        2>&1 | sed -u 's/\r$//' > "$log" || true

    grep -q '^LIVE-RESULT: PASS' "$log" && ok "$mode: guest finished the scan" || bad "$mode: no LIVE-RESULT: PASS (see $log)"
    grep -q 'report volume:' "$log" && ok "$mode: KGDATA partition found" || bad "$mode: KGDATA not found"

    # pull the report back out of the KGDATA partition
    rm -rf "$WORK/rep-$mode"; mkdir -p "$WORK/rep-$mode"
    mcopy -s -i "$disk@@$off" ::/reports "$WORK/rep-$mode/" 2>/dev/null || true
    local rep; rep=$(ls "$WORK/rep-$mode"/reports/*/report.txt 2>/dev/null | head -1 || true)
    if [[ -z $rep ]]; then bad "$mode: no report written to KGDATA"; return; fi
    ok "$mode: report written to KGDATA"
    local d; d=$(dirname "$rep")
    grep -q 'module loaded' "$rep"                         && ok "$mode: kernelguard.ko loaded"          || bad "$mode: module did not load"
    grep -q 'state integrity : ok' "$rep"                  && ok "$mode: module state integrity ok"       || bad "$mode: no state integrity line"
    grep -q ': Linux root' "$rep"                          && ok "$mode: Linux host drive found"          || bad "$mode: Linux host drive not found"
    grep -q ': Windows system drive' "$rep"                && ok "$mode: Windows host drive found"        || bad "$mode: Windows host drive not found"
    grep -q '^[0-9a-f]\{64\} dummy@[0-9A-F]* ' "$d"/linux-modules-*.txt \
                                                           && ok "$mode: compressed module identified"    || bad "$mode: compressed module not identified"
    grep -q "^FINDING denied Windows driver.*evil.sys" "$rep" && ok "$mode: Windows hash match -> FINDING"  || bad "$mode: Windows hash match missing"
    grep -q "^FINDING denied Linux module.*dummy" "$rep"      && ok "$mode: Linux module match -> FINDING"  || bad "$mode: Linux module match missing"
    grep -q '== summary: 3 finding' "$rep"                 && ok "$mode: summary counts 3 findings"       || bad "$mode: summary count wrong ($(grep summary "$rep"))"
}

run_boot bios
run_boot uefi

echo "== $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && echo "== ALL PASSED" || { echo "== FAILURES (rerun with KG_KEEP=1; work dir $WORK)"; exit 1; }
