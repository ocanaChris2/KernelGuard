#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# kgmon escalation action: mail the alert with mail(1) or sendmail(8).  Recipients come from a
# root-only file, one address per line:
#
#   echo 'security@example.org' | sudo tee /etc/kernelguard/mail.to
#
# Needs a working local MTA; the default systemd sandbox only allows AF_UNIX sockets, which is
# enough to hand the message to a local sendmail-compatible spool.
set -eu

to_file=${KG_MAIL_TO_FILE:-/etc/kernelguard/mail.to}
[ -r "$to_file" ] || { echo "kg-action-mail: cannot read $to_file" >&2; exit 1; }
to=$(grep -v '^[[:space:]]*\(#\|$\)' "$to_file" | tr '\n' ' ')
[ -n "$to" ] || { echo "kg-action-mail: $to_file lists no recipient" >&2; exit 1; }
case $to in -*) echo "kg-action-mail: refusing an address that starts with '-'" >&2; exit 1;; esac

prefix=
[ "${KG_TIER:-0}" = 1 ] && prefix="ESCALATED: "
subject="${prefix}[KernelGuard ${KG_LEVEL:-?}] ${KG_TITLE:-alert} on ${KG_HOST:-?}"

body() {
    printf 'Host:      %s\n' "${KG_HOST:-?}"
    printf 'Time:      %s\n' "${KG_TIME:-?}"
    printf 'Alert:     %s (%s)\n' "${KG_TITLE:-?}" "${KG_ALERT:-?}"
    printf 'Level:     %s\n' "${KG_LEVEL:-?}"
    printf 'Details:   %s\n' "${KG_DETAILS:-}"
    printf 'Sequence:  %s\n' "${KG_SEQ:-?}"
    printf 'Rule:      %s (tier %s, %s occurrence(s), first seen %s s ago)\n' \
        "${KG_RULE:-?}" "${KG_TIER:-0}" "${KG_COUNT:-?}" "${KG_AGE_S:-?}"
    printf '\nInspect with:   kgmon --once   and   kgmon status   and   kgmon posture\n'
    printf 'Acknowledge:    kgmon ack\n'
}

if command -v mail >/dev/null 2>&1; then
    # shellcheck disable=SC2086  # $to is a space separated address list on purpose
    body | mail -s "$subject" $to
elif command -v sendmail >/dev/null 2>&1; then
    {
        printf 'To: %s\nSubject: %s\n\n' "$(echo "$to" | sed 's/ *$//; s/ /, /g')" "$subject"
        body
    } | sendmail -t
else
    echo "kg-action-mail: neither mail(1) nor sendmail(8) found" >&2
    exit 1
fi
