#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# flash.sh - write kernelguard-live.img to a USB stick, then read it back and compare.
#
#   sudo usb/flash.sh /dev/sdX [IMAGE]
#   usb/flash.sh --dry-run /dev/sdX          run every safety check, write nothing
#
# Safety rules (all enforced before anything is written):
#   * the target must be a whole disk, not a partition
#   * it must be removable or on the USB bus (--force-fixed overrides this, and only this)
#   * it must not hold a mounted filesystem, and must not be the disk the running system is on
#   * you must type the device name to confirm, after the model and size are shown
# A regular file is also accepted as a target (used by the tests; no removable check applies).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DRY=0
FIXED=0
ASSUME=""       # test hook: KG_FLASH_CONFIRM=<answer> answers the prompt

while [[ ${1:-} == --* ]]; do
    case $1 in
        --dry-run) DRY=1 ;;
        --force-fixed) FIXED=1 ;;
        *) sed -n '3,15p' "$0"; exit 2 ;;
    esac
    shift
done
[[ $# -ge 1 && $# -le 2 ]] || { sed -n '3,15p' "$0"; exit 2; }
DEV=$1
IMG=${2:-$HERE/out/kernelguard-live.img}
ASSUME=${KG_FLASH_CONFIRM:-}

die() { echo "flash: refusing: $*" >&2; exit 1; }
[[ -f $IMG ]] || die "no image at $IMG (run usb/build-image.sh first)"
SIZE=$(stat -c %s "$IMG")

if [[ -f $DEV ]]; then
    echo "target is a regular file: $DEV (test mode)"
    MODEL="file"; TSIZE=$(stat -c %s "$DEV")
else
    [[ -b $DEV ]] || die "$DEV is not a block device"
    command -v lsblk >/dev/null || die "lsblk is required"
    [[ $(lsblk -dno TYPE "$DEV") == disk ]] || die "$DEV is not a whole disk (a partition, loop or mapper device?)"
    name=$(basename "$DEV")

    removable=$(cat "/sys/block/$name/removable" 2>/dev/null || echo 0)
    bus=$(lsblk -dno TRAN "$DEV" 2>/dev/null | tr -d ' ')
    if [[ $removable != 1 && $bus != usb ]]; then
        [[ $FIXED == 1 ]] || die "$DEV is neither removable nor on the USB bus (bus: ${bus:-unknown}); this looks like an internal disk"
        echo "!! --force-fixed: $DEV is not removable" >&2
    fi

    # never the disk under the running system
    rootsrc=$(findmnt -no SOURCE / 2>/dev/null || true)
    if [[ -n $rootsrc && -b $rootsrc ]]; then
        rootdisk=$(lsblk -no PKNAME "$rootsrc" 2>/dev/null | head -1 || true)
        [[ -n $rootdisk && $rootdisk == "$name" ]] && die "$DEV holds the running system's root filesystem"
    fi
    if lsblk -no MOUNTPOINTS "$DEV" 2>/dev/null | grep -q .; then
        die "$DEV has mounted filesystems ($(lsblk -no MOUNTPOINTS "$DEV" | grep . | tr '\n' ' ')); unmount them first"
    fi

    MODEL=$(lsblk -dno VENDOR,MODEL "$DEV" | sed 's/  */ /g')
    TSIZE=$(blockdev --getsize64 "$DEV")
fi
[[ $TSIZE -ge $SIZE ]] || die "the target is $TSIZE bytes; the image needs $SIZE"

echo "image  : $IMG ($(numfmt --to=iec "$SIZE"))"
echo "target : $DEV  $MODEL  ($(numfmt --to=iec "$TSIZE"))"
echo "ALL DATA ON THE TARGET WILL BE DESTROYED."
if [[ $DRY == 1 ]]; then echo "dry run: all checks passed, nothing written"; exit 0; fi

if [[ -n $ASSUME ]]; then ans=$ASSUME; else read -r -p "Type the device name to continue ($DEV): " ans; fi
[[ $ans == "$DEV" ]] || die "confirmation did not match; nothing was written"

if [[ -f $DEV ]]; then
    dd if="$IMG" of="$DEV" bs=4M conv=fsync,notrunc status=progress
else
    [[ $EUID -eq 0 ]] || die "run as root (sudo) to write to $DEV"
    dd if="$IMG" of="$DEV" bs=4M conv=fsync status=progress
    sync
    blockdev --rereadpt "$DEV" 2>/dev/null || true
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true       # so the read-back hits the stick, not the page cache
fi

echo "verifying..."
want=$(sha256sum < "$IMG" | cut -d' ' -f1)
got=$(head -c "$SIZE" "$DEV" | sha256sum | cut -d' ' -f1)
if [[ $want == "$got" ]]; then
    echo "verified: the stick matches the image (sha256 ${want:0:16}...)"
else
    echo "flash: VERIFY FAILED: image $want, stick $got" >&2
    exit 1
fi
