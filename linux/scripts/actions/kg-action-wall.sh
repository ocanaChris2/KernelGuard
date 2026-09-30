#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# kgmon escalation action: broadcast the alert to every logged-in terminal with wall(1).
# Needs write access to the terminals: see "Escalation policy" in linux/README.md for the
# systemd sandbox settings.
set -eu

command -v wall >/dev/null 2>&1 || { echo "kg-action-wall: wall(1) not found" >&2; exit 1; }

prefix=
[ "${KG_TIER:-0}" = 1 ] && prefix="ESCALATED (${KG_COUNT:-?} time(s), ${KG_AGE_S:-?} s) "

printf '%s\n' "${prefix}KernelGuard [${KG_LEVEL:-?}] ${KG_TITLE:-alert} on ${KG_HOST:-?}: ${KG_DETAILS:-} (seq ${KG_SEQ:-?}, run: kgmon ack)" |
    wall
