# posture: graduated response - automatic raises, decay, the sticky HIGH floor, operator control,
# the max_posture cap, refusing to reset a corrupted state, and auto_enforce.
EV=/sys/module/kg_test_rogue/parameters/events
NCPU=$(grep -c ^processor /proc/cpuinfo)

POS()        { kgmon posture | sed -n 's/^posture  *: \([A-Z-]*\).*/\1/p'; }
pos_is()     { [ "$(POS)" = "$1" ]; }
full_cpus()  { kgmon status | grep -c '^ *[0-9][0-9]* *yes *full-spectrum('; }
# CPUs whose current strategy differs from the one chosen at probe time
off_base()   { kgmon status | sed -n 's/^ *[0-9][0-9]* *yes *\([a-z0-9+-]*\) *(\([a-z0-9+-]*\) *).*/\1 \2/p' \
                 | awk '$1 != $2 {n++} END {print n+0}'; }
posture_alerts() { kgmon --once 2>&1 | grep -c "Response Posture Changed"; }

step "baseline"
check "insmod kernelguard (decay 4 s, slow scans)" load_kg posture_decay_s=4 hw_interval_ms=2000 integrity_interval_ms=4000
kgmon posture
check "starts NORMAL"                      pos_is NORMAL
check "scans at their configured interval" sh -c 'kgmon posture | grep -q "PCI/input 2000 ms, integrity 4000 ms"'
check "detect-only"                        sh -c 'kgmon posture | grep -q "enforcement *: detect-only"'
check "status shows the posture"           sh -c 'kgmon status | grep -q "posture *: NORMAL"'

step "a suspicious event raises the posture and speeds up the scans"
inject 0x10 1 0x6f67756572 0                # unauthorised keyboard filter, WARNING
check "posture ELEVATED"                   pos_is ELEVATED
check "scans 4x as often"                  sh -c 'kgmon posture | grep -q "PCI/input 500 ms, integrity 1000 ms"'
check "last trigger is the keyboard-filter alert" sh -c 'kgmon posture | grep -q "last trigger *: Unauthorized Keyboard Filter"'
check "an automatic raise is not announced by a second alert" test "$(posture_alerts)" -eq 0
check "kernel log says so"                 klog_has "posture ELEVATED"

step "ELEVATED decays after a quiet period; a new trigger restarts the clock"
sleep 2
inject 0x10 1 0x6f67756572 0
sleep 3                                     # 5 s after the first trigger, 3 s after the second
check "still ELEVATED (the second trigger restarted the 4 s clock)" pos_is ELEVATED
check "decays to NORMAL"                   wait_for 6 pos_is NORMAL
check "scans back to the configured interval" sh -c 'kgmon posture | grep -q "PCI/input 2000 ms, integrity 4000 ms"'
kgmon --once > /tmp/p1.txt 2>&1
grep "Posture" /tmp/p1.txt
check "decay announced: authenticated, INFO, both postures named" \
      grep -q '\[Info *\] Response Posture Changed *HMAC=OK.*ELEVATED -> NORMAL  (quiet period elapsed)' /tmp/p1.txt

step "HIGH holds every CPU at full-spectrum, and it stays that way"
kgmon status | grep -E "modules "
inject 0x20 2 0xffffffff81000000 14         # IDT hook, CRITICAL
check "posture HIGH"                       pos_is HIGH
check "every CPU at full-spectrum"         sh -c "[ $(full_cpus) -eq $NCPU ]"
check "kernel log says so"                 klog_has "posture HIGH"
sleep 5                                     # past the decay time and several PMU windows
check "HIGH does not decay"                pos_is HIGH
check "still full-spectrum everywhere: the PMU sampler must not relax the floor" sh -c "[ $(full_cpus) -eq $NCPU ]"

step "an operator steps down after investigating"
check "kgmon posture set normal"           kgmon posture set normal
check "posture NORMAL"                     pos_is NORMAL
check "baseline strategy restored on every CPU" sh -c "[ $(off_base) -eq 0 ]"
check "policy hash was refreshed with the table" sh -c 'kgmon status | grep -q "state integrity : ok"'
kgmon --once > /tmp/p2.txt 2>&1
grep "Posture" /tmp/p2.txt
check "announced: WARNING, authenticated, operator request" \
      grep -q '\[Warning *\] Response Posture Changed *HMAC=OK.*HIGH -> NORMAL  (operator request)' /tmp/p2.txt
N1=$(posture_alerts)
kgmon posture set normal
check "setting the posture it already has is a no-op (no alert)" test "$(posture_alerts)" -eq "$N1"
check "a bad level is rejected"            sh -c '! kgmon posture set bogus 2>/dev/null'

step "an operator can raise it, including to fail-safe, and step down from there"
check "kgmon posture set failsafe"         kgmon posture set failsafe
check "posture FAIL-SAFE"                  pos_is FAIL-SAFE
check "status flags fail-safe"             sh -c 'kgmon status | grep -q "\*\*\* FAIL-SAFE"'
check "the fail-safe alert was sent"       sh -c 'kgmon --once 2>&1 | grep -q "Fail-Safe Mode"'
check "every CPU at full-spectrum"         sh -c "[ $(full_cpus) -eq $NCPU ]"
check "kgmon posture set high"             kgmon posture set high
check "posture HIGH"                       pos_is HIGH
check "fail-safe flag gone from status"    sh -c '! kgmon status | grep -q "\*\*\* FAIL-SAFE"'
check "kgmon posture set normal"           kgmon posture set normal
check "back to the baseline"               sh -c "[ $(off_base) -eq 0 ]"
check "policy hash still valid"            sh -c 'kgmon status | grep -q "state integrity : ok"'

step "a corrupted policy state cannot be reset away"
inject 0x30 2 0 0                           # SHARED_STATE_CORRUPT
check "fail-safe on corruption"            pos_is FAIL-SAFE
check "resetting is refused"               sh -c '! kgmon posture set normal 2>/tmp/refuse.txt'
cat /tmp/refuse.txt
check "...with an explanation"             grep -q "policy state was found corrupted" /tmp/refuse.txt
check "still FAIL-SAFE"                    pos_is FAIL-SAFE
check "kgmon posture warns"                sh -c 'kgmon posture | grep -q "WARNING"'
check "kernel log says why"                klog_has "refusing to lower the posture"
check "rmmod kernelguard"                  rmmod kernelguard

step "max_posture caps what the module does by itself"
dmesg -c > /dev/null
check "insmod kernelguard max_posture=1"   load_kg max_posture=1
inject 0x22 2 0x4000 12                     # kernel text patched, CRITICAL
check "the alert is recorded"              sh -c 'kgmon --once 2>&1 | grep -q "Kernel .text Patched"'
check "posture stops at ELEVATED"          pos_is ELEVATED
check "no fail-safe"                       sh -c '! kgmon status | grep -q "\*\*\* FAIL-SAFE"'
echo 3 > $KGPARAM/max_posture               # 0644: adjustable at run time
inject 0x22 2 0x4000 12
check "after raising the cap the next alert goes all the way" wait_for 3 pos_is FAIL-SAFE
check "rmmod kernelguard"                  rmmod kernelguard
check "insmod kernelguard max_posture=0 (alerts only)" load_kg max_posture=0
inject 0x22 2 0x4000 12
check "the alert is recorded"              sh -c 'kgmon --once 2>&1 | grep -q "Kernel .text Patched"'
check "posture stays NORMAL"               pos_is NORMAL
check "rmmod kernelguard"                  rmmod kernelguard

step "auto_enforce: detect-only until the posture reaches HIGH"
dmesg -c > /dev/null
check "insmod kernelguard auto_enforce=1 (enforce stays 0)" load_kg hw_interval_ms=500 auto_enforce=1 posture_decay_s=0
check "insmod rogue keylogger fixture"     insmod /modules/kg_test_rogue.ko
check "rogue handler reported"             wait_for 6 klog_has 'unauthorised input handler "rogue_logger"'
check "which raises ELEVATED"              wait_for 3 pos_is ELEVATED
check "still detect-only at ELEVATED"      sh -c 'kgmon posture | grep -q "enforcement *: detect-only (auto_enforce"'
vkbd vk1 3 > /tmp/vk1.txt &
wait
E1=$(cat $EV)
echo "   rogue handler saw $E1 events"
check "handler still attached: it receives keystrokes" sh -c "[ ${E1:-0} -gt 0 ]"
check "nothing detached"                   sh -c '! dmesg | grep -q "detached from keyboard"'
inject 0x20 2 0xffffffff81000000 14
check "posture HIGH"                       pos_is HIGH
check "the posture switched enforcement on" sh -c 'kgmon posture | grep -q "enforcement *: ACTIVE"'
vkbd vk2 6 > /tmp/vk2.txt &
check "rogue handler detached from the next keyboard" wait_for 8 klog_has 'input handler "rogue_logger" detached from keyboard "vk2"'
wait
check "operator reset switches enforcement off again" sh -c 'kgmon posture set normal && kgmon posture | grep -q "enforcement *: detect-only"'
check "rmmod rogue fixture"                rmmod kg_test_rogue
check "rmmod kernelguard"                  rmmod kernelguard
check_no_kernel_faults

step "a posture raise with the monitors disabled is harmless (regression: the ladder kicks every monitor)"
dmesg -c > /dev/null
check "insmod kernelguard hw=0 integrity=0 input=0 pmu=0" load_kg hw=0 integrity=0 input=0 pmu=0
inject 0x10 1 0x6f67756572 0
check "ELEVATED without the PCI and input monitors" wait_for 3 pos_is ELEVATED
inject 0x20 2 0xffffffff81000000 14
check "HIGH without the integrity monitor"  wait_for 3 pos_is HIGH
check "rmmod kernelguard"                  rmmod kernelguard
check_no_kernel_faults
