# escalate: kgmon's escalation policy with real fork/exec: level filter, throttle, escalation by
# repetition and by age, acknowledgement, action timeouts, a minimal environment, validation,
# and the systemd notify protocol.
LOG=/tmp/act.log
: > $LOG

cat > /tmp/act-base.sh <<'SH'
#!/bin/sh
echo "base rule=$KG_RULE alert=$KG_ALERT level=$KG_LEVEL tier=$KG_TIER count=$KG_COUNT seq=$KG_SEQ p1=$KG_PARAM1 host=${KG_HOST:+set} secret=${SECRET_TOKEN:-unset} details=$KG_DETAILS" >> /tmp/act.log
SH
cat > /tmp/act-esc.sh <<'SH'
#!/bin/sh
echo "esc rule=$KG_RULE alert=$KG_ALERT tier=$KG_TIER count=$KG_COUNT p1=$KG_PARAM1 age=$KG_AGE_S" >> /tmp/act.log
SH
cat > /tmp/act-slow.sh <<'SH'
#!/bin/sh
echo $$ > /tmp/slow.pid
sleep 30
echo "slow finished (should have been killed)" >> /tmp/act.log
SH
chmod 755 /tmp/act-base.sh /tmp/act-esc.sh /tmp/act-slow.sh

cat > /tmp/policy.conf <<'CONF'
# test policy
action base  /tmp/act-base.sh
action esc   /tmp/act-esc.sh
action slow  timeout=1 /tmp/act-slow.sh
rule kbd    alert=UNAUTHORIZED_KBD_FILTER level=warning throttle=30 do=base repeat=3/60 then=esc
rule pci    alert=PCI_DISCREPANCY do=base unacked=3 then=esc
rule dma    alert=UNAUTHORIZED_DMA do=slow
rule kernel alert=TEXT_PATCH level=critical do=base
rule forged alert=FORGED,TAMPER,OVERRUN level=forged throttle=0 do=base
CONF
chmod 600 /tmp/policy.conf

count() { grep -c "$1" $LOG; }

step "policy files are validated before anything runs"
check "unit tests of the engine (kgmon selftest)" sh -c 'kgmon selftest | grep -q "escalation policy tests: passed"'
check "a valid policy passes 'policy check'"      sh -c 'kgmon policy check /tmp/policy.conf | grep -q "ok, 3 action(s), 5 rule(s)"'
printf 'action base /tmp/act-base.sh\n\nrule r do=nothing\n' > /tmp/bad1.conf; chmod 600 /tmp/bad1.conf
check "an unknown action is rejected, with the line number" sh -c '! kgmon policy check /tmp/bad1.conf 2>/tmp/e1.txt'
cat /tmp/e1.txt
check "…naming file, line and reason"             grep -q 'bad1.conf:3: unknown action .nothing.' /tmp/e1.txt
cp /tmp/policy.conf /tmp/bad2.conf; chmod 666 /tmp/bad2.conf
check "a policy writable by others is refused"    sh -c '! kgmon policy check /tmp/bad2.conf 2>/tmp/e2.txt'
check "…and says why"                             grep -q 'writable by group or others' /tmp/e2.txt
cp /tmp/act-base.sh /tmp/act-bad.sh; chmod 777 /tmp/act-bad.sh
printf 'action a /tmp/act-bad.sh\nrule r do=a\n' > /tmp/bad3.conf; chmod 600 /tmp/bad3.conf
check "an action program writable by others is refused" sh -c '! kgmon policy check /tmp/bad3.conf 2>/tmp/e3.txt'
cat /tmp/e3.txt
check "…and says why"                             grep -q "act-bad.sh' is writable by group or others" /tmp/e3.txt

step "set up: module, monitor with the policy"
check "insmod kernelguard"                        load_kg
export SECRET_TOKEN=must-not-reach-actions
kgmon --policy /tmp/policy.conf --new-only --quiet 2>/tmp/kgmon.err &
KGPID=$!
sleep 1
cat /tmp/kgmon.err
check "monitor loaded the policy"                 grep -q 'policy /tmp/policy.conf: 3 action(s), 5 rule(s)' /tmp/kgmon.err
check "monitor is running"                        kill -0 $KGPID

step "level filter, base action, environment"
inject 0x10 0 0x6575676f72 0                    # INFO: below the rule's minimum level
sleep 0.6
check "an INFO alert runs nothing"                test "$(count '^base')" -eq 0
inject 0x10 1 0x6575676f72 0                    # WARNING unauthorised keyboard filter, handler "rogue" (bytes 0-7, little-endian)
check "a WARNING alert runs the base action"      wait_for 4 grep -q '^base rule=kbd alert=UNAUTHORIZED_KBD_FILTER level=warning tier=0 count=1' $LOG
cat $LOG
check "the environment names the host"            grep -q 'host=set' $LOG
check "the caller's environment does not leak into actions" grep -q 'secret=unset' $LOG
check "details carry the formatted alert"         grep -q 'details=name: "rogue"' $LOG

step "throttle, then escalation by repetition"
inject 0x10 1 0x6575676f72 0
inject 0x10 1 0x6575676f72 0
check "the third arrival within 60 s escalates"   wait_for 4 grep -q '^esc rule=kbd alert=UNAUTHORIZED_KBD_FILTER tier=1 count=3' $LOG
sleep 0.5
check "the repeats inside the throttle window ran no second base action" test "$(count '^base rule=kbd')" -eq 1
check "it escalated exactly once"                 test "$(count '^esc rule=kbd')" -eq 1
inject 0x10 1 0x6575676f72 0
sleep 0.6
check "and not again for the same incident"       test "$(count '^esc rule=kbd')" -eq 1
inject 0x10 1 0x326575676f72 0                  # "rogue2": a different offender is a different incident
check "another offender gets its own base action" wait_for 4 grep -q '^base rule=kbd .*count=1 .*p1=0x0000326575676f72' $LOG

step "escalation by age, and acknowledgement"
inject 0x12 1 0x100 0x100800000001              # PCI discrepancy, incident 1
check "base action ran for the first incident"    wait_for 4 grep -q '^base rule=pci .*p1=0x0000000000000100' $LOG
check "unacknowledged for 3 s => escalated"       wait_for 7 grep -q '^esc rule=pci .*tier=1.*p1=0x0000000000000100' $LOG
inject 0x12 1 0x200 0x100800000001              # incident 2
check "base action ran for the second incident"   wait_for 4 grep -q '^base rule=pci .*p1=0x0000000000000200' $LOG
check "kgmon ack records the acknowledgement"     sh -c 'kgmon ack | grep -q "acknowledged alerts up to sequence"'
check "the running monitor noticed it"            wait_for 3 grep -q 'acknowledged$' /tmp/kgmon.err
sleep 5
check "an acknowledged incident is never escalated" test "$(count '^esc rule=pci .*p1=0x0000000000000200')" -eq 0
check "the first incident still escalated only once" test "$(count '^esc rule=pci .*p1=0x0000000000000100')" -eq 1
inject 0x12 1 0x200 0x100800000001              # it comes back after the ack
check "a repeat after the ack is a new incident (base action again)" wait_for 4 sh -c '[ $(grep -c "^base rule=pci .*p1=0x0000000000000200" /tmp/act.log) -eq 2 ]'

step "an action that overruns its timeout is killed, process group and all"
rm -f /tmp/slow.pid
inject 0x11 1 0x00000200 0x80861234
check "the slow action started"                   wait_for 4 test -s /tmp/slow.pid
SLOWPID=$(cat /tmp/slow.pid)
check "…and is running"                           kill -0 "$SLOWPID"
check "the monitor killed it after its 1 s timeout" wait_for 5 sh -c "! kill -0 $SLOWPID 2>/dev/null"
check "its child (sleep 30) went with it"         sh -c '[ "$(ps | grep -c "[s]leep 30")" -eq 0 ]'
check "the monitor said so"                       grep -q 'slow timed out, killing it' /tmp/kgmon.err
check "it never got to finish"                    sh -c '! grep -q "slow finished" /tmp/act.log'

step "a notification whose HMAC fails is never matched by content"
echo 1 > $KGPARAM/test_bad_hmac
inject 0x22 2 0x4000 12                         # TEXT_PATCH, CRITICAL: rule 'kernel' would match it if it were trusted
echo 0 > $KGPARAM/test_bad_hmac
check "the FORGED rule ran"                       wait_for 4 grep -q '^base rule=forged alert=FORGED level=forged' $LOG
sleep 0.5
grep 'rule=forged' $LOG
check "the rule for TEXT_PATCH did not"           test "$(count '^base rule=kernel')" -eq 0
check "the details are kgmon's own words, not the sender's" grep -q 'rule=forged.*details=notification [0-9]* failed HMAC verification' $LOG
inject 0x22 2 0x4000 12                         # the same alert with a good HMAC is trusted again
check "authentic, it does run its own rule"       wait_for 4 grep -q '^base rule=kernel alert=TEXT_PATCH level=critical' $LOG

step "no zombies, monitor still healthy"
sleep 1
check "no defunct processes left behind"          sh -c '[ "$(for p in /proc/[0-9]*; do grep -q "^State:.*Z" $p/status 2>/dev/null && echo z; done | wc -l)" -eq 0 ]'
check "monitor still running"                     kill -0 $KGPID
kill -TERM $KGPID
wait $KGPID
check "clean exit on SIGTERM"                     test $? -eq 0

step "--once never runs actions"
BEFORE=$(wc -l < $LOG)
kgmon --once --policy /tmp/policy.conf > /tmp/once.txt 2>&1
sleep 1
check "backlog printed"                           grep -q "HMAC=OK" /tmp/once.txt
check "no action ran"                             test "$(wc -l < $LOG)" -eq "$BEFORE"

step "a broken policy stops the service instead of silently not escalating"
check "kgmon refuses to start"                    sh -c '! kgmon --policy /tmp/bad1.conf --quiet 2>/tmp/e4.txt'
check "…and names the problem"                    grep -q 'policy: /tmp/bad1.conf:3' /tmp/e4.txt
check "--no-policy ignores the file"              sh -c 'kgmon --once --no-policy --policy /tmp/bad1.conf --quiet'

step "systemd notify protocol and watchdog"
sdlisten /tmp/notify.sock 5 > /tmp/sd.out &
SDPID=$!
sleep 0.5
NOTIFY_SOCKET=/tmp/notify.sock WATCHDOG_USEC=2000000 kgmon --new-only --quiet &
NPID=$!
sleep 3
kill -TERM $NPID
wait $NPID
wait $SDPID
cat /tmp/sd.out
check "READY=1 announced"                         grep -q 'READY=1' /tmp/sd.out
check "watchdog pinged (interval is half of WatchdogSec)" sh -c '[ "$(grep -c "WATCHDOG=1" /tmp/sd.out)" -ge 2 ]'
check "STOPPING=1 on shutdown"                    grep -q 'STOPPING=1' /tmp/sd.out

check "rmmod kernelguard"                         rmmod kernelguard
check_no_kernel_faults
