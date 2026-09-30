#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Build kernelguard_<version>-1_amd64.deb (DKMS module source, kgmon, systemd unit, udev rule, example policy).
#
#   linux/packaging/build-deb.sh [OUTPUT_DIR]        default OUTPUT_DIR: <repo>/dist
#
# Needs: dpkg-dev, debhelper (>= 13), fakeroot, gcc, make. Nothing is installed or loaded by the build.
# The Maintainer field comes from DEBFULLNAME / DEBEMAIL, else a placeholder (a build must not pick up
# somebody's personal git identity by accident).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
LINUX=$(cd "$HERE/.." && pwd)
ROOT=$(cd "$LINUX/.." && pwd)
VERSION=$(cat "$ROOT/VERSION")
OUT=${1:-$ROOT/dist}

name=${DEBFULLNAME:-KernelGuard contributors}
mail=${DEBEMAIL:-noreply@localhost}
MAINTAINER="$name <$mail>"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
SRC=$W/kernelguard-$VERSION
mkdir -p "$SRC" "$OUT"

# The source tree: linux/ minus build products, plus the licence text.
tar -C "$LINUX" \
    --exclude='*.ko' --exclude='*.o' --exclude='*.mod' --exclude='*.mod.c' --exclude='.*.cmd' \
    --exclude='Module.symvers' --exclude='modules.order' --exclude='monitor/kgmon' \
    --exclude='monitor/fuzz/fuzz_policy' --exclude='monitor/fuzz/fuzz_policy_lf' --exclude='monitor/fuzz/corpus' \
    --exclude='.tmp_versions' \
    -cf - module include monitor scripts man packaging/dkms README.md | tar -C "$SRC" -xf -
cp -a "$HERE/debian" "$SRC/debian"
cp "$ROOT/VERSION" "$SRC/VERSION"

sed -i "s#@MAINTAINER@#$MAINTAINER#" "$SRC/debian/control"
{
    echo "kernelguard ($VERSION-1) unstable; urgency=medium"
    echo
    echo "  * Release $VERSION. See CHANGELOG.md in the upstream repository."
    echo
    echo " -- $MAINTAINER  $(date -R)"
} > "$SRC/debian/changelog"

(cd "$SRC" && dpkg-buildpackage -us -uc -b)
cp "$W"/kernelguard_*.deb "$OUT"/
ls -l "$OUT"/kernelguard_*.deb
