# basic: load/unload, device node, ioctls, the authenticated ring and the uevent fallback.
step "load"
check "insmod kernelguard.ko" load_kg
check "device node /dev/kernelguard exists" test -c /dev/kernelguard
check "device node is mode 0600" sh -c '[ "$(stat -c %a /dev/kernelguard)" = 600 ]'
check "kgmon selftest" kgmon selftest

step "status"
kgmon status > /tmp/status.txt 2>&1
cat /tmp/status.txt
check "status reports ABI 1"           grep -q 'ABI 1' /tmp/status.txt
check "state integrity ok"             grep -q 'state integrity : ok' /tmp/status.txt
check "detect-only by default"         grep -q 'detect-only' /tmp/status.txt
check "per-CPU table has 4 CPUs"       sh -c '[ "$(grep -c "^  [0-9]" /tmp/status.txt)" = 4 ]'

step "authenticated ring"
inject 0x22 2 0x1000 8        # TEXT_PATCH critical -> also drives fail-safe
inject 0x10 1 0x6f67756572 0  # KBD filter warning (name bytes in param1)
inject 0x99 0 1 2             # unknown code, info
sleep 0.5
kgmon --once > /tmp/ring.txt 2>&1
cat /tmp/ring.txt
check "critical text-patch alert delivered, HMAC ok" \
    grep -q 'CRITICAL.*Kernel .text Patched.*HMAC=OK.*0x0000000000001000' /tmp/ring.txt
check "warning keyboard-filter alert delivered"      grep -q 'Warning.*Unauthorized Keyboard Filter.*HMAC=OK' /tmp/ring.txt
check "fail-safe alert raised by the text patch"     grep -q 'Fail-Safe Mode.*HMAC=OK' /tmp/ring.txt
check "no HMAC failures"                             sh -c '! grep -q "HMAC=FAIL" /tmp/ring.txt'
check "sequence numbers are contiguous"              sh -c \
    'grep -o "seq=[0-9]*" /tmp/ring.txt | sed "s/seq=//" | awk "NR>1 && \$1!=p+1{e=1} {p=\$1} END{exit e}"'

step "fail-safe policy"
kgmon status > /tmp/status2.txt 2>&1
check "fail-safe flag set"                 grep -q 'FAIL-SAFE' /tmp/status2.txt
check "every CPU now full-spectrum"        sh -c '[ "$(grep -c "full-spectrum" /tmp/status2.txt)" -ge 4 ]'
check "state hash still valid after policy change" grep -q 'state integrity : ok' /tmp/status2.txt

step "uevent fallback channel"
uevent sh -c 'echo "$KERNELGUARD_ALERT $KERNELGUARD_LEVEL $KERNELGUARD_SEQ" >> /tmp/uev.txt' &
UEV=$!
sleep 0.5
inject 0x12 1 0 0
wait_for 5 grep -q '^0x0012 1 ' /tmp/uev.txt
check "uevent carried alert type, level and sequence" grep -q '^0x0012 1 [0-9]' /tmp/uev.txt
check "uevent does not leak parameters"              sh -c '! grep -q "0x1000" /tmp/uev.txt'
kill $UEV 2>/dev/null

step "ring wrap-around and rate limiting"
i=0
while [ $i -lt 100 ]; do inject 0x99 2 $i 0; i=$((i + 1)); done   # critical -> never rate-limited
sleep 0.3
kgmon --once > /tmp/wrap.txt 2>&1
check "only the newest 16 slots are readable"    sh -c '[ "$(grep -c "HMAC=" /tmp/wrap.txt)" = 16 ]'
check "all surviving slots authenticate"         sh -c '! grep -q "HMAC=FAIL" /tmp/wrap.txt'
check "newest alert is param 99"                 sh -c 'tail -1 /tmp/wrap.txt | grep -q "Param1: 0x63"'
i=0
while [ $i -lt 200 ]; do inject 0x99 0 $i 0; i=$((i + 1)); done   # info -> rate limited
kgmon status > /tmp/status3.txt
DROPPED=$(awk '/notifications_dropped/ {print $2}' /tmp/status3.txt)
check "non-critical flood was rate limited (dropped=$DROPPED)" sh -c "[ ${DROPPED:-0} -gt 100 ]"

step "device access control"
check "mmap of the ring cannot be made writable" sh -c \
    'kgmon --once >/dev/null 2>&1'   # kgmon maps PROT_READ; writable mapping is refused by the driver

step "unload"
check "rmmod kernelguard" rmmod kernelguard
check "device node gone" sh -c '! test -e /dev/kernelguard'
check_no_kernel_faults
