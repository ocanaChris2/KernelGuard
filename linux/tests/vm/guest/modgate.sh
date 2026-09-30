# modgate: Module 3.5, the driver-load gate ("bring your own vulnerable driver").
# kg_test_stub plays the vulnerable module (harmless: it only logs), kg_test_other the innocent bystander.
# Detect-only reporting, the posture each outcome causes, refusal under enforce=1 before init() runs,
# name@srcversion identity, lock mode (baseline, allow list, dry run, run-time switch), auto_enforce,
# hostile parameters, concurrency, and `kgmon modid` against what the kernel reports.
# Counting tests use `modload`, which makes one system call: BusyBox insmod retries a failed
# finit_module with init_module, so a single refused insmod reaches the kernel's loader twice.
POS()       { kgmon posture | sed -n 's/^posture  *: \([A-Z-]*\).*/\1/p'; }
pos_is()    { [ "$(POS)" = "$1" ]; }
loaded()    { grep -q "^$1 " /proc/modules; }
gate_line() { kgmon status | grep -q -- "$1"; }
regions()   { kgmon status | sed -n 's/.*monitored  *: \([0-9]*\) text region.*/\1/p'; }
gate_denied()  { kgmon status | sed -n 's/.*gate counters *: denied \([0-9]*\),.*/\1/p'; }
gate_refused() { kgmon status | sed -n 's/.*gate counters.*refused \([0-9]*\),.*/\1/p'; }
alerts()    { kgmon --once 2>&1; }
PARAMS=/sys/module/kernelguard/parameters

step "baseline: the gate is on, and the OS defences are audited"
check "insmod kernelguard mod_deny=kg_test_stub" load_kg mod_deny=kg_test_stub
check "the gate says what it holds" klog_has "driver-load gate: 1 denied, 0 allowed, lock off (0 module(s) baselined), detect-only"
alerts > /tmp/a0.txt
grep "Load Policy" /tmp/a0.txt
check "LOAD_POLICY: an authenticated WATCH alert with the three findings" \
      grep -q '\[Warning *\] Driver Load Policy *HMAC=OK.*sig_enforce=no lockdown=no secure_boot=no  weak: sig_enforce lockdown secure_boot' /tmp/a0.txt
check "status: detect-only, one deny entry"  gate_line 'module gate     : detect-only, deny 1, allow 0, lock off (baseline 0)'
check "status: the audit result"             gate_line 'load policy     : sig_enforce=no lockdown=no secure_boot=no  weak: sig_enforce lockdown secure_boot'
check "the audit agrees with the kernel's own sig_enforce" test "$(cat /sys/module/module/parameters/sig_enforce)" = N
check "an audit finding is not an incident: posture NORMAL" pos_is NORMAL

step "detect-only: a denied module loads, and the load is the alert"
check "insmod the denied stub (enforce is off, nothing refuses it)" insmod /modules/kg_test_stub.ko
check "it is loaded"                         loaded kg_test_stub
check "and its init ran"                     klog_has "kg_test_stub: init ran"
alerts > /tmp/a1.txt
grep "Vulnerable" /tmp/a1.txt
check "VULN_DRIVER: CRITICAL, authenticated, names the module" \
      grep -q '\[CRITICAL *\] Vulnerable Driver Loaded *HMAC=OK.*name: "kg_test_stub"' /tmp/a1.txt
check "kernel log: detect-only, enforce=1 would refuse" \
      klog_has "denied module kg_test_stub is being loaded (detect-only: enforce=1 would refuse it)"
check "a loaded denied driver is the attack primitive: posture HIGH" wait_for 3 pos_is HIGH
check "counters: one denied, none refused"   gate_line 'gate counters   : denied 1, refused 0, lock hits 0, ignored entries 0'
SV=$(cat /sys/module/kg_test_stub/srcversion)
echo "   srcversion of the stub: $SV"
check "the module carries a srcversion to match" test -n "$SV"
check "an unlisted module is left alone"     insmod /modules/kg_test_other.ko
alerts > /tmp/a2.txt
check "…no gate alert names it" sh -c '! grep -E "(Vulnerable Driver Loaded|Driver Load Blocked).*kg_test_other" /tmp/a2.txt'
check "…and the counters did not move"       gate_line 'denied 1, refused 0, lock hits 0'
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod bystander"                      rmmod kg_test_other
check "rmmod kernelguard"                    rmmod kernelguard

step "identity: name, name@srcversion, exact match only"
check "kgmon modid prints the entry the kernel's srcversion gives" test "$(kgmon modid --entry /modules/kg_test_stub.ko)" = "kg_test_stub@$SV"
check "insmod kernelguard mod_deny=kg_test_stub@SRCVERSION" load_kg "mod_deny=kg_test_stub@$SV"
check "insmod stub"                          insmod /modules/kg_test_stub.ko
check "matched by name and srcversion"       wait_for 3 sh -c 'kgmon --once 2>&1 | grep -q "Vulnerable Driver Loaded.*kg_test_stub"'
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard
check "insmod kernelguard with the srcversion in lower case" load_kg "mod_deny=kg_test_stub@$(echo "$SV" | tr 'A-F' 'a-f')"
check "insmod stub"                          insmod /modules/kg_test_stub.ko
check "case does not matter"                 wait_for 3 sh -c 'kgmon --once 2>&1 | grep -q "Vulnerable Driver Loaded.*kg_test_stub"'
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard
check "insmod kernelguard with another build's srcversion" load_kg mod_deny=kg_test_stub@0123456789ABCDEF0123456
check "insmod stub"                          insmod /modules/kg_test_stub.ko
sleep 1
check "a different srcversion is a different module: no alert" sh -c '! kgmon --once 2>&1 | grep -q "Vulnerable Driver"'
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard
check "insmod kernelguard mod_deny with dashes and prefixes only" load_kg mod_deny=kg_test,kg_tes,kg-test-stub-x
check "insmod stub"                          insmod /modules/kg_test_stub.ko
sleep 1
check "a prefix or a longer name is not a match" sh -c '! kgmon --once 2>&1 | grep -q "Vulnerable Driver"'
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard
check "insmod kernelguard mod_deny=kg-test-stub (dashes)" load_kg mod_deny=kg-test-stub
check "insmod stub"                          insmod /modules/kg_test_stub.ko
check "dashes match the kernel's underscores" wait_for 3 sh -c 'kgmon --once 2>&1 | grep -q "Vulnerable Driver Loaded.*kg_test_stub"'
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard

step "enforce=1: the load is refused before init() runs"
dmesg -c > /dev/null
check "insmod kernelguard enforce=1 mod_deny=kg_test_stub" load_kg enforce=1 mod_deny=kg_test_stub posture_decay_s=0
R0=$(regions)
modload /modules/kg_test_stub.ko 2>/tmp/e1.txt; RC=$?
cat /tmp/e1.txt
check "finit_module fails"                   test "$RC" -ne 0
check "with EPERM"                           grep -q "Operation not permitted" /tmp/e1.txt
check "the module is not in /proc/modules"   sh -c '! grep -q "^kg_test_stub " /proc/modules'
check "nor in sysfs"                         test ! -d /sys/module/kg_test_stub
check "its init never ran"                   sh -c '! dmesg | grep -q "kg_test_stub: init ran"'
alerts > /tmp/a3.txt
grep "Blocked" /tmp/a3.txt
check "DRIVER_BLOCKED: CRITICAL, authenticated, names the module" \
      grep -q '\[CRITICAL *\] Driver Load Blocked *HMAC=OK.*name: "kg_test_stub"' /tmp/a3.txt
check "kernel log gives the reason"          klog_has "refused to load kg_test_stub (on the deny list)"
check "a stopped attempt still means someone with root tried: ELEVATED" wait_for 3 pos_is ELEVATED
check "…but nothing was executed, so not HIGH" sh -c '! kgmon posture | grep -q "posture  *: HIGH"'
check "counters: one denied, one refused"    gate_line 'gate counters   : denied 1, refused 1, lock hits 0'
check "status says the gate is refusing"     gate_line 'module gate     : refusing, deny 1'
modload -i /modules/kg_test_stub.ko 2>/tmp/e1b.txt; RC=$?
check "the older init_module entry point is gated too" test "$RC" -ne 0
check "…also with EPERM"                     grep -q "Operation not permitted" /tmp/e1b.txt
check "…and counted"                         gate_line 'denied 2, refused 2'
check "a second authenticated DRIVER_BLOCKED reached the ring" sh -c '[ "$(kgmon --once 2>&1 | grep -c "Driver Load Blocked *HMAC=OK")" -eq 2 ]'

step "refusals are cheap and leave nothing behind"
i=0
while [ $i -lt 100 ]; do
    modload /modules/kg_test_stub.ko 2>/dev/null
    modload -i /modules/kg_test_stub.ko 2>/dev/null
    i=$((i + 1))
done
check "200 more refusals counted"            gate_line 'denied 202, refused 202'
check "no text region was added for a refused module" test "$(regions)" = "$R0"
check "the stub is still not loaded"         sh -c '! grep -q "^kg_test_stub " /proc/modules'
check_no_kernel_faults

step "concurrent loads, refusals and unloads"
# The kernel answers a load that overlaps another of the same module name with EBUSY before any
# notifier runs, so not every attempt reaches the gate: what must hold is that none gets through.
dmesg -c > /dev/null
for _ in 1 2 3 4; do
    ( j=0
      while [ $j -lt 40 ]; do
          modload /modules/kg_test_stub.ko 2>/dev/null
          insmod /modules/kg_test_other.ko 2>/dev/null && rmmod kg_test_other 2>/dev/null
          j=$((j + 1))
      done ) &
done
wait
kgmon status | grep 'gate counters'
check "the denied module never got through, whatever the interleaving" sh -c '! grep -q "^kg_test_stub " /proc/modules && ! dmesg | grep -q "kg_test_stub: init ran"'
check "the counters agree with each other"   test "$(gate_denied)" = "$(gate_refused)"
check "and grew by at least one refusal per worker" test "$(gate_refused)" -ge 206
check "the bystander ended up unloaded"      sh -c '! grep -q "^kg_test_other " /proc/modules'
check_no_kernel_faults
check "rmmod kernelguard: nothing pins it"   rmmod kernelguard
check "with the guard gone the denied module loads freely" insmod /modules/kg_test_stub.ko
check "rmmod stub"                           rmmod kg_test_stub

step "lock mode: baseline, allow list, refusal at WATCH"
dmesg -c > /dev/null
check "insmod the bystander first: it becomes part of the baseline" insmod /modules/kg_test_other.ko
check "insmod kernelguard mod_lock=1 enforce=1 mod_allow=kg_test_tamper" load_kg mod_lock=1 enforce=1 mod_allow=kg_test_tamper posture_decay_s=0
check "the baseline holds the bystander"     gate_line 'module gate     : refusing, deny 0, allow 1, lock on (baseline 1)'
check "starts NORMAL"                        pos_is NORMAL
modload /modules/kg_test_stub.ko 2>/tmp/e2.txt; RC=$?
check "an unexpected module is refused"      test "$RC" -ne 0
alerts > /tmp/a4.txt
grep "Blocked" /tmp/a4.txt
check "DRIVER_BLOCKED at WATCH: a lock-mode refusal is not an incident" \
      grep -q '\[Warning *\] Driver Load Blocked *HMAC=OK.*name: "kg_test_stub"' /tmp/a4.txt
check "kernel log gives the reason"          klog_has "refused to load kg_test_stub (not in the lock-mode allow list)"
check "…and the posture did not move"        pos_is NORMAL
check "a baseline module can be reloaded"    sh -c 'rmmod kg_test_other && insmod /modules/kg_test_other.ko'
check "a module in mod_allow loads"          insmod /modules/kg_test_tamper.ko
check "…and unloads"                         rmmod kg_test_tamper
check "counters: only the lock counted"      gate_line 'gate counters   : denied 0, refused 1, lock hits 1'
check "rmmod bystander"                      rmmod kg_test_other
check "rmmod kernelguard"                    rmmod kernelguard

step "lock mode without enforce is a dry run"
check "insmod kernelguard mod_lock=1 (detect-only)" load_kg mod_lock=1
check "the stub loads"                       insmod /modules/kg_test_stub.ko
check "kernel log: it would have been refused" \
      wait_for 3 klog_has "module kg_test_stub is not in the lock-mode allow list (dry run: enforce=1 would refuse it)"
check "counted as a lock hit, nothing refused" gate_line 'refused 0, lock hits 1'
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard

step "mod_lock at run time records what is loaded right then"
check "insmod the bystander"                 insmod /modules/kg_test_other.ko
check "insmod kernelguard enforce=1 (lock off)" load_kg enforce=1
check "with the lock off the stub loads"     sh -c 'insmod /modules/kg_test_stub.ko && rmmod kg_test_stub'
check "switch the lock on"                   sh -c "echo 1 > $PARAMS/mod_lock"
check "kernel log records the baseline"      klog_has "lock mode on: 1 module(s) loaded now are the baseline"
check "status shows it"                      gate_line 'lock on (baseline 1)'
check "the stub is refused now"              sh -c '! insmod /modules/kg_test_stub.ko 2>/dev/null'
check "switching the lock off is the emergency exit" sh -c "echo 0 > $PARAMS/mod_lock && insmod /modules/kg_test_stub.ko"
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod bystander"                      rmmod kg_test_other
check "rmmod kernelguard"                    rmmod kernelguard

step "auto_enforce: the gate closes by itself once the posture reaches HIGH"
check "insmod kernelguard auto_enforce=1 mod_deny=kg_test_stub" load_kg auto_enforce=1 mod_deny=kg_test_stub posture_decay_s=0
check "detect-only while the system is quiet" gate_line 'module gate     : detect-only'
inject 0x20 2 0xffffffff81000000 14         # IDT hook, CRITICAL
check "posture HIGH"                         pos_is HIGH
check "the gate is refusing now"             gate_line 'module gate     : refusing'
check "the denied module is refused"         sh -c '! insmod /modules/kg_test_stub.ko 2>/dev/null'
check "an operator reset opens the gate again" sh -c 'kgmon posture set normal && kgmon status | grep -q "module gate     : detect-only"'
check "insmod stub"                          insmod /modules/kg_test_stub.ko
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard

step "max_posture caps what the gate can raise"
check "insmod kernelguard max_posture=1"     load_kg mod_deny=kg_test_stub max_posture=1
check "insmod stub"                          insmod /modules/kg_test_stub.ko
check "a CRITICAL denied load wants HIGH; the cap holds it at ELEVATED" wait_for 3 pos_is ELEVATED
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard

step "modgate=0 switches the whole gate off"
check "insmod kernelguard modgate=0 enforce=1 mod_deny=kg_test_stub" load_kg modgate=0 enforce=1 mod_deny=kg_test_stub
check "status says so"                       gate_line 'module gate     : off (modgate=0)'
check "and there is no audit either"         sh -c '! kgmon status | grep -q "load policy"'
check "the denied module loads"              insmod /modules/kg_test_stub.ko
check "rmmod stub"                           rmmod kg_test_stub
check "rmmod kernelguard"                    rmmod kernelguard

step "hostile parameters never fail the load"
dmesg -c > /dev/null
check "insmod with malformed entries in both lists" \
      load_kg 'mod_deny="bad@,,kg_test_stub, ,x@,@zz,foo@GHI,ok@1F" mod_allow="a@b,good_one"' enforce=1
check "the valid entries are in force"       gate_line 'deny 2, allow 1'
check "five malformed entries were counted"  gate_line 'ignored entries 5'
check "and each was logged"                  test "$(klog_count 'ignoring malformed entry')" -eq 5
check "the valid entry still refuses the stub" sh -c '! insmod /modules/kg_test_stub.ko 2>/dev/null'
check "rmmod kernelguard"                    rmmod kernelguard
dmesg -c > /dev/null
LIST="kg_test_stub,$(i=0; while [ $i -lt 70 ]; do printf 'm%02d,' $i; i=$((i + 1)); done)m70"
check "insmod with 72 deny entries"          load_kg enforce=1 "mod_deny=$LIST"
check "only 64 are kept"                     gate_line 'deny 64, allow 0'
check "the rest is counted and logged"       gate_line 'ignored entries 8'
check "…once, not per entry"                 test "$(klog_count 'only the first 64 entries are used')" -eq 1
check "an entry within the limit still works" sh -c '! insmod /modules/kg_test_stub.ko 2>/dev/null'
check "rmmod kernelguard"                    rmmod kernelguard
LONG=$(i=0; while [ $i -lt 300 ]; do printf 'abcd,'; i=$((i + 1)); done)
check_not "a list that does not fit the parameter is rejected by the kernel, not truncated" load_kg "mod_deny=$LONG"
check "and nothing is left loaded"           sh -c '! grep -q "^kernelguard " /proc/modules'

step "kgmon modid reads what the kernel sees"
check "the entry line names the module and srcversion" sh -c 'kgmon modid /modules/kg_test_stub.ko | grep -q "^mod_deny    : kg_test_stub@[0-9A-F]"'
check "MODULE_VERSION is read"               sh -c 'kgmon modid /modules/kg_test_stub.ko | grep -q "^version     : 1.0$"'
check "a module without MODULE_VERSION still has a srcversion" sh -c 'kgmon modid /modules/kg_test_other.ko | grep -q "^srcversion  : [0-9A-F]"'
check "the SHA-256 agrees with sha256sum"    sh -c 'test "$(kgmon modid /modules/kg_test_stub.ko | sed -n "s/^sha256      : //p")" = "$(sha256sum /modules/kg_test_stub.ko | cut -d" " -f1)"'
check "standard input works"                 sh -c 'kgmon modid --entry - < /modules/kg_test_stub.ko | grep -q "^kg_test_stub@"'
check "the build is unsigned, and it says so" sh -c 'kgmon modid /modules/kg_test_stub.ko | grep -q "^signature   : not appended"'
printf '\050\265\057\375\000\000\000\000' > /tmp/c.ko.zst
check "a compressed module gets a hint"      sh -c '! kgmon modid /tmp/c.ko.zst 2>/tmp/e5.txt && grep -q "decompress it first" /tmp/e5.txt'
check "a file that is not a module is refused" sh -c '! kgmon modid /init 2>/tmp/e6.txt && grep -q "not an ELF file" /tmp/e6.txt'
check "a missing file is an error, not a crash" sh -c '! kgmon modid /nonexistent 2>/dev/null'
check_no_kernel_faults
