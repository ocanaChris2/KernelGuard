#!/bin/sh
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 KernelGuard contributors
#
# Install (or with --remove, remove) the per-user systemd timer that keeps blocklist/kernelguard-blocklist.db fresh.
# No root needed; it only writes ~/.config/systemd/user/.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
unit=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
if [ "${1:-}" = "--remove" ]; then
    systemctl --user disable --now kernelguard-blocklist.timer 2>/dev/null || true
    rm -f "$unit/kernelguard-blocklist.service" "$unit/kernelguard-blocklist.timer"
    systemctl --user daemon-reload
    echo "removed"; exit 0
fi
mkdir -p "$unit"
sed "s|@REPO@|$repo|" "$here/kernelguard-blocklist.service" > "$unit/kernelguard-blocklist.service"
cp "$here/kernelguard-blocklist.timer" "$unit/"
systemctl --user daemon-reload
systemctl --user enable --now kernelguard-blocklist.timer
systemctl --user list-timers kernelguard-blocklist.timer --no-pager
