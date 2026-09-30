#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build-image.sh - build kernelguard-live.img, a raw disk image to write to a USB stick.
#
# The stick boots a small live Linux (the distro kernel matching KG_KVER, a busybox initramfs,
# kernelguard.ko, a static kgmon, and kg-live-scan).  It scans the machine it was plugged into
# and writes the report back onto the stick.  Nothing needs root: the image is assembled with
# mtools/sgdisk/grub tools on plain files.
#
#   GPT layout:  1 BIOS boot (1 MiB)   2 ESP FAT32 (kernel, initramfs, GRUB)   3 KGDATA FAT32
#   KGDATA:      reports/  blocklist/  linux/ (the .deb, if built)  windows/ (driver package)
#
# Usage:   usb/build-image.sh [-o IMAGE]
# Environment:
#   KG_KVER        kernel version (default: uname -r).  Headers must be installed for it.
#   KG_KERNEL      bzImage to boot (default: /boot/vmlinuz-$KG_KVER).  Distro images are often
#                  root-only; fetch a readable copy with
#                    apt-get download linux-image-$KG_KVER && dpkg-deb -x linux-image-*.deb dir
#   KG_USB_DATA_MB size of the KGDATA partition            (default 512)
#   KG_SIGN_KEY / KG_SIGN_CERT   sign kernelguard.ko with this key (needed on Secure Boot machines
#                  whose MOK list holds the certificate)
#   KG_WINDOWS_DIR directory with a built Windows driver package to copy into KGDATA/windows
#   KG_KEEP=1      keep the work directory
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
LINUX=$ROOT/linux
KVER=${KG_KVER:-$(uname -r)}
KERNEL=${KG_KERNEL:-/boot/vmlinuz-$KVER}
DATA_MB=${KG_USB_DATA_MB:-512}
OUT=$HERE/out/kernelguard-live.img
ESP_MB=200

while getopts 'o:h' opt; do
    case $opt in
        o) OUT=$OPTARG ;;
        *) sed -n '3,26p' "$0"; exit 2 ;;
    esac
done

die() { echo "build-image: $*" >&2; exit 1; }
for tool in busybox cpio gzip gcc make sgdisk mkfs.vfat mcopy mmd mformat grub-mkimage depmod modprobe; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done
[[ -r $KERNEL ]] || die "cannot read kernel image $KERNEL (see KG_KERNEL in the header)"
[[ -d /lib/modules/$KVER/build ]] || die "no kernel headers for $KVER"
GRUB_EFI=/usr/lib/grub/x86_64-efi
[[ -d $GRUB_EFI ]] || die "grub-efi-amd64-bin is not installed"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/kglive.XXXXXX")
[[ ${KG_KEEP:-0} == 1 ]] || trap 'rm -rf "$WORK"' EXIT
echo "== work dir: $WORK   kernel: $KVER"

# ---- 1. module and monitor ----
cp -a "$LINUX/module" "$WORK/module"
cp -a "$LINUX/include" "$WORK/include"
make -C "$WORK/module" KVER="$KVER" >"$WORK/build-module.log" 2>&1 \
    || { tail -30 "$WORK/build-module.log"; die "module build failed"; }
if [[ -n ${KG_SIGN_KEY:-} ]]; then
    SIGN=/usr/src/linux-headers-$KVER/scripts/sign-file
    [[ -x $SIGN ]] || SIGN=/lib/modules/$KVER/build/scripts/sign-file
    [[ -x $SIGN ]] || die "sign-file not found in the header tree for $KVER"
    "$SIGN" sha256 "$KG_SIGN_KEY" "${KG_SIGN_CERT:?KG_SIGN_CERT is required with KG_SIGN_KEY}" "$WORK/module/kernelguard.ko"
    echo "== kernelguard.ko signed"
fi
make -C "$LINUX/monitor" static >"$WORK/build-monitor.log" 2>&1 || { tail -30 "$WORK/build-monitor.log"; die "monitor build failed"; }
cp "$LINUX/monitor/kgmon" "$WORK/kgmon"
make -C "$LINUX/monitor" clean >/dev/null 2>&1 || true

# ---- 2. initramfs ----
R=$WORK/rootfs
mkdir -p "$R"/{bin,sbin,proc,sys,dev,tmp,run,etc,mnt,modules,lib,lib64}
cp "$(command -v busybox)" "$R/bin/busybox"
for a in $(busybox --list); do [[ $a == busybox ]] || ln -sf busybox "$R/bin/$a"; done
cp "$WORK/module/kernelguard.ko" "$R/modules/"
cp "$WORK/kgmon" "$R/bin/kgmon"
cp "$HERE/live/init" "$R/init"
cp "$HERE/live/kg-live-scan" "$R/bin/kg-live-scan"
chmod +x "$R/init" "$R/bin/kg-live-scan"

# Copy a dynamic executable's shared libraries into the initramfs (a static one needs none).
copy_libs() {
    { ldd "$1" 2>/dev/null || true; } | awk '/=>/ {print $3} /^[[:space:]]*\/.*ld-linux/ {print $1}' | while read -r lib; do
        [[ -f $lib ]] || continue
        mkdir -p "$R$(dirname "$lib")"
        cp -L "$lib" "$R$lib"
    done
}
copy_libs "$(command -v busybox)"

# Copy a dynamic executable's shared libraries into the initramfs (a static one needs none).
copy_libs() {
    { ldd "$1" 2>/dev/null || true; } | awk '/=>/ {print $3} /^[[:space:]]*\/.*ld-linux/ {print $1}' | while read -r lib; do
        [[ -f $lib ]] || continue
        mkdir -p "$R$(dirname "$lib")"
        cp -L "$lib" "$R$lib"
    done
}
copy_libs "$(command -v busybox)"

# zstd/xz for compressed module files on the host's drives.
for b in zstd xz; do
    p=$(command -v "$b" || true)
    [[ -n $p ]] || { echo "!! $b not found: compressed .ko files on host drives will not be identified"; continue; }
    rm -f "$R/bin/$b"      # busybox has an xz applet: a symlink here would make cp overwrite busybox itself
    cp "$p" "$R/bin/$b"
    copy_libs "$p"
done

# Boot-time drivers: the wanted modules plus their dependencies, decompressed (busybox modprobe
# cannot read .ko.zst); the appended module signature survives decompression.
MODDIR=$R/lib/modules/$KVER
mkdir -p "$MODDIR/kernel"
: > "$R/etc/live-modules"
while read -r m; do
    [[ -z $m || $m == \#* ]] && continue
    deps=$(modprobe -S "$KVER" --show-depends "$m" 2>/dev/null | awk '$1 == "insmod" {print $2}') || true
    [[ -n $deps ]] || continue
    for f in $deps; do
        dest=$MODDIR/kernel/$(basename "${f%.zst}")
        dest=${dest%.xz}
        [[ -f $dest ]] && continue
        case $f in
            *.zst) zstd -dcq "$f" > "$dest" ;;
            *.xz)  xz -dc "$f" > "$dest" ;;
            *)     cp "$f" "$dest" ;;
        esac
    done
    echo "$m" >> "$R/etc/live-modules"
done < "$HERE/live/modules.list"
cp "/lib/modules/$KVER"/modules.{order,builtin,builtin.modinfo} "$MODDIR/" 2>/dev/null || true
depmod -b "$R" "$KVER"
echo "== initramfs modules: $(ls "$MODDIR/kernel" | wc -l) files, $(wc -l < "$R/etc/live-modules") wanted"
( cd "$R" && find . | cpio -o -H newc --quiet | gzip -6 ) > "$WORK/initramfs.gz"

# ---- 3. partition contents ----
# ESP: EFI/BOOT/BOOTX64.EFI is a standalone GRUB that finds its config by a marker file.
cat > "$WORK/grub.cfg" <<EOF
set timeout=3
set default=0
menuentry "KernelGuard live scan (report, then power off)" {
    linux /vmlinuz console=tty0 console=ttyS0 quiet kglive=auto
    initrd /initramfs.gz
}
menuentry "KernelGuard live scan, then a shell" {
    linux /vmlinuz console=tty0 console=ttyS0 kglive=shell
    initrd /initramfs.gz
}
EOF
cat > "$WORK/embed.cfg" <<'EOF'
search --no-floppy --file --set=root /kg-esp.marker
set prefix=($root)/grub
configfile $prefix/grub.cfg
EOF
grub-mkimage -O x86_64-efi -o "$WORK/BOOTX64.EFI" -p /grub -c "$WORK/embed.cfg" \
    part_gpt part_msdos fat normal linux configfile search search_fs_file echo all_video gzio test
echo kernelguard > "$WORK/kg-esp.marker"

truncate -s "${ESP_MB}M" "$WORK/esp.img"
mkfs.vfat -F 32 -n KGBOOT "$WORK/esp.img" >/dev/null
mmd -i "$WORK/esp.img" ::/EFI ::/EFI/BOOT ::/grub
mcopy -i "$WORK/esp.img" "$WORK/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$WORK/esp.img" "$WORK/grub.cfg" ::/grub/grub.cfg
mcopy -i "$WORK/esp.img" "$WORK/kg-esp.marker" ::/kg-esp.marker
mcopy -i "$WORK/esp.img" "$KERNEL" ::/vmlinuz
mcopy -i "$WORK/esp.img" "$WORK/initramfs.gz" ::/initramfs.gz

# KGDATA: readable and writable from Windows, macOS and Linux.
truncate -s "${DATA_MB}M" "$WORK/data.img"
mkfs.vfat -F 32 -n KGDATA "$WORK/data.img" >/dev/null
mmd -i "$WORK/data.img" ::/reports ::/blocklist ::/linux ::/windows
echo "KernelGuard report volume. Do not delete." > "$WORK/kgdata.marker"
mcopy -i "$WORK/data.img" "$WORK/kgdata.marker" ::/kgdata.marker
mcopy -i "$WORK/data.img" "$HERE"/blocklist/* ::/blocklist/
mcopy -i "$WORK/data.img" "$HERE/README.md" ::/README.md
for deb in "$ROOT"/linux/packaging/*.deb "$ROOT"/*.deb; do
    [[ -f $deb ]] && mcopy -i "$WORK/data.img" "$deb" ::/linux/
done
mcopy -i "$WORK/data.img" "$ROOT/windows/KernelGuard.inf" "$ROOT/windows/scripts/Deploy-KernelGuard.ps1" ::/windows/
if [[ -n ${KG_WINDOWS_DIR:-} ]]; then
    [[ -d $KG_WINDOWS_DIR ]] || die "KG_WINDOWS_DIR is not a directory: $KG_WINDOWS_DIR"
    mcopy -s -i "$WORK/data.img" "$KG_WINDOWS_DIR"/* ::/windows/
fi

# ---- 4. assemble the disk ----
MIB=$((1024 * 1024))
TOTAL_MB=$((1 + 1 + ESP_MB + DATA_MB + 1))     # 1 MiB gap, BIOS boot, ESP, data, backup GPT
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
truncate -s "${TOTAL_MB}M" "$OUT"
sgdisk -o -a 2048 \
    -n 1:2048:+1M -t 1:ef02 -c 1:"BIOS boot" \
    -n 2:0:+${ESP_MB}M -t 2:ef00 -c 2:"KGBOOT" \
    -n 3:0:+${DATA_MB}M -t 3:0700 -c 3:"KGDATA" "$OUT" >/dev/null
part_start() { sgdisk -i "$1" "$OUT" | awk '/First sector/ {print $3}'; }
dd if="$WORK/esp.img"  of="$OUT" bs=512 seek="$(part_start 2)" conv=notrunc status=none
dd if="$WORK/data.img" of="$OUT" bs=512 seek="$(part_start 3)" conv=notrunc status=none

# BIOS boot: GRUB's core image goes into the BIOS boot partition (partition 1) and boot.img into the
# MBR.  grub-bios-setup wants to probe a real device for its root, so the two patches it would make
# are done here: boot.img learns where core.img starts, and core.img's first sector gets its blocklist.
# The embedded config finds the ESP by marker file, so no device name is baked in.
if [[ -f /usr/lib/grub/i386-pc/boot.img ]]; then
    grub-mkimage -O i386-pc -o "$WORK/core.img" -p /grub -c "$WORK/embed.cfg" \
        biosdisk part_gpt part_msdos fat normal linux configfile search search_fs_file echo gzio test
    python3 - "$OUT" /usr/lib/grub/i386-pc/boot.img "$WORK/core.img" "$(part_start 1)" <<'PY'
import struct, sys
img, boot_p, core_p, lba = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
boot = bytearray(open(boot_p, "rb").read())
core = bytearray(open(core_p, "rb").read())
core += b"\0" * (-len(core) % 512)
nsec = len(core) // 512
if nsec > 2047:
    sys.exit("core.img does not fit the BIOS boot partition")
struct.pack_into("<Q", boot, 0x5c, lba)              # first sector of core.img
boot[0x66:0x68] = b"\x90\x90"                        # hard disk: no floppy drive check
struct.pack_into("<QHH", core, 512 - 12, lba + 1, nsec - 1, 0x0820)   # diskboot blocklist
with open(img, "r+b") as f:
    mbr = bytearray(f.read(512))
    mbr[0:440] = boot[0:440]
    mbr[446] = 0x80                                   # protective partition marked active (some BIOSes insist)
    f.seek(0); f.write(mbr)
    f.seek(lba * 512); f.write(core)
PY
    echo "== BIOS boot code installed"
else
    echo "!! grub-pc-bin not installed: the image boots on UEFI machines only"
fi

sha256sum "$OUT" > "$OUT.sha256"
echo "== image: $OUT ($(du -h --apparent-size "$OUT" | cut -f1))"
echo "== write it with:  usb/flash.sh /dev/sdX"
