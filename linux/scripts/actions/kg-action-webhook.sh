#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# kgmon escalation action: POST the alert as {"text": "..."} to a chat webhook (Slack, Mattermost,
# Rocket.Chat and Teams incoming webhooks accept this shape).  The URL is a secret: it is read
# from a root-only file, never from the policy.
#
#   echo 'https://hooks.example.org/services/...' | sudo tee /etc/kernelguard/webhook.url
#   sudo chmod 600 /etc/kernelguard/webhook.url
#
# The default systemd sandbox only allows AF_UNIX sockets: add a drop-in that permits AF_INET and
# AF_INET6 (see "Escalation policy" in linux/README.md).
set -eu

url_file=${KG_WEBHOOK_URL_FILE:-/etc/kernelguard/webhook.url}
[ -r "$url_file" ] || { echo "kg-action-webhook: cannot read $url_file" >&2; exit 1; }
url=$(head -n 1 "$url_file")
[ -n "$url" ] || { echo "kg-action-webhook: $url_file is empty" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "kg-action-webhook: curl not found" >&2; exit 1; }

# Escape for a JSON string: drop control characters, then backslash and double quote.
json_escape() {
    printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

prefix=
[ "${KG_TIER:-0}" = 1 ] && prefix="ESCALATED (${KG_COUNT:-?} time(s), ${KG_AGE_S:-?} s) "

text="${prefix}KernelGuard [${KG_LEVEL:-?}] ${KG_TITLE:-alert} on ${KG_HOST:-?}: ${KG_DETAILS:-} (${KG_ALERT:-?}, seq ${KG_SEQ:-?}, ${KG_TIME:-?})"

printf '{"text":"%s"}' "$(json_escape "$text")" |
    curl --fail --silent --show-error --max-time 10 \
         --header 'Content-Type: application/json' --data-binary @- --url "$url" >/dev/null
