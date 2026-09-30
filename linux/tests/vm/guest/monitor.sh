# monitor: the user-space side - CSV log, syslog, --max/--once, run --sensitive.
step "set up"
check "insmod kernelguard" load_kg
inject 0x22 2 0x4000 12
inject 0x10 1 0x6f67756572 0
inject 0x11 1 0x00000200 0x80861234

step "CSV log (Windows 'Save Log' columns)"
kgmon --once --quiet --log /tmp/kg.csv
cat /tmp/kg.csv
check "header row matches the Windows monitor"  sh -c 'head -1 /tmp/kg.csv | grep -qx "Time,Level,AlertType,HMAC,Seq,Param1,Param2,Details"'
check "one row per alert (load-policy audit, 4 injected incl. fail-safe)" sh -c '[ $(wc -l < /tmp/kg.csv) -eq 6 ]'
check "rows are quoted and hex-formatted"       grep -q '"Kernel .text Patched",OK,[0-9]*,0x0000000000004000,0x0000000c00000000\|"Kernel .text Patched",OK,[0-9]*,0x0000000000004000,0x000000000000000c' /tmp/kg.csv
check "HMAC status column says OK"              sh -c '! grep -q ",FAIL," /tmp/kg.csv'
kgmon --once --quiet --log /tmp/kg.csv
check "appending does not repeat the header"    sh -c '[ $(grep -c "^Time," /tmp/kg.csv) -eq 1 ]'

step "--max stops after N alerts"
check "--max 2 prints exactly two"  sh -c '[ $(kgmon --once --max 2 2>/dev/null | grep -c "HMAC=") -eq 2 ]'

step "syslog sink"
syslogd -n -O /tmp/messages &
SLP=$!
sleep 0.5
kgmon --once --quiet --syslog
sleep 0.5
kill $SLP 2>/dev/null
cat /tmp/messages | head -4
check "alerts reached syslog with severity and HMAC state" grep -q 'Kernel .text Patched.*hmac ok' /tmp/messages

step "a second instance is refused (single-instance lock)"
kgmon --quiet &
K1=$!
sleep 0.7
check "second kgmon exits with an error" sh -c '! kgmon --quiet 2>/tmp/second.err'
check "…saying why" grep -q 'already running' /tmp/second.err
kill -TERM $K1; wait $K1 2>/dev/null

step "status against a dead driver"
check "rmmod" rmmod kernelguard
check "kgmon status reports the module is not loaded" sh -c 'kgmon status 2>&1 | grep -q "not found - is the kernelguard module loaded"'

step "run --sensitive"
kgmon run --sensitive -- specget > /tmp/run.txt 2>&1
cat /tmp/run.txt
check "command was exec'd"                       grep -q '^specget:' /tmp/run.txt
check "each control reports enabled or a reason"  sh -c '[ $(grep -c "^kgmon: .*\(enabled\|unavailable\)" /tmp/run.txt) -eq 4 ]'
# where a control was reported enabled it must really be set in the exec'd task
if grep -q "kgmon: indirect-branch mitigation.*enabled" /tmp/run.txt; then
    check "indirect-branch mitigation is set in the child" grep -q 'indirect_branch state=0x[0-9a-f]* speculation-disabled' /tmp/run.txt
else
    skip "indirect-branch control unavailable on this CPU/kernel policy"
fi
if grep -q "kgmon: L1D flush.*enabled" /tmp/run.txt; then
    check "L1D flush is set in the child"               grep -q 'l1d_flush state=0x[0-9a-f]*' /tmp/run.txt
else
    skip "L1D flush control unavailable in this guest"
fi
if grep -q "kgmon: core scheduling.*enabled" /tmp/run.txt; then
    check "core-scheduling cookie is set in the child"  grep -q 'cookie=set' /tmp/run.txt
else
    skip "core scheduling unavailable in this guest"
fi
kgmon run -- specget > /tmp/run2.txt 2>&1
check "without --sensitive nothing is changed"    sh -c '! grep -q "^kgmon: " /tmp/run2.txt && grep -q "cookie=none\|unsupported" /tmp/run2.txt'
check_no_kernel_faults
