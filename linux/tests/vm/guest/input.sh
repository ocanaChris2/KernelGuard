# input: Module 2 keyboard path + Module 3 input-path integrity.
EV=/sys/module/kg_test_rogue/parameters/events

step "baseline on a clean system"
check "insmod kernelguard (fast rescan)" load_kg hw_interval_ms=500
check "keyboards tracked" klog_has "keyboard path: [1-9]"
klog | grep "keyboard path:"
sleep 1.6
check "stock handlers (kbd/evdev/sysrq/leds) raise no alert" sh -c '! dmesg | grep -q "alert 0x001[03]\]\|alert 0x0021\]"'
kgmon status | grep -E "monitored|modules "

step "rogue handler, detect-only (default)"
check "insmod rogue keylogger fixture" insmod /modules/kg_test_rogue.ko
check "unknown handler reported" wait_for 6 klog_has 'unauthorised input handler "rogue_logger"'
check "reported critical (its handle is open => it receives keys)" \
      sh -c 'dmesg | grep "unauthorised input handler \"rogue_logger\"" | head -1 | grep -q "receiving keystrokes"'
kgmon --once > /tmp/r.txt 2>&1
check "alert authenticated and carries the handler name" \
      grep -q 'Unauthorized Keyboard Filter.*HMAC=OK.*name: "rogue_logger"' /tmp/r.txt
vkbd vk1 3 > /tmp/vk1.txt &
wait
cat /tmp/vk1.txt
E1=$(cat $EV)
echo "   rogue handler saw $E1 events"
check "detect-only leaves the handler attached: it really receives the keystrokes" sh -c "[ ${E1:-0} -gt 0 ]"
check "no neutralisation in detect-only mode" sh -c '! dmesg | grep -q "detached from keyboard"'

step "enforce=1: detach the rogue handler, keep the legitimate consumer"
echo 1 > $KGPARAM/enforce
vkbd vk2 6 > /tmp/vk2.txt &
check "handler detached from the virtual keyboard" wait_for 8 klog_has 'input handler "rogue_logger" detached from keyboard "vk2"'
sleep 0.8
E2=$(cat $EV)
sleep 2
E3=$(cat $EV)
echo "   rogue counter after detach: $E2 -> $E3"
check "rogue handler stops receiving keystrokes" sh -c "[ $E2 -eq $E3 ]"
wait
cat /tmp/vk2.txt
INJ=$(sed -n 's/.*injected=\([0-9]*\).*/\1/p' /tmp/vk2.txt)
REC=$(sed -n 's/.*received=\([0-9]*\).*/\1/p' /tmp/vk2.txt)
check "legitimate consumer (evdev) kept receiving keys: received $REC of $INJ" sh -c "[ ${REC:-0} -ge $((INJ - 1)) ]"
check "neutralisation authenticated (0x0013)" sh -c 'kgmon --once 2>&1 | grep -q "Keyboard Filter Neutralized.*HMAC=OK.*rogue_logger"'

step "unloading a detached handler must not crash"
check "rmmod rogue fixture" rmmod kg_test_rogue
check_no_kernel_faults

step "trust on first use: a handler that is already there when we load is not news"
check "rmmod kernelguard" rmmod kernelguard
dmesg -c > /dev/null
check "insmod rogue BEFORE kernelguard" insmod /modules/kg_test_rogue.ko
check "insmod kernelguard" load_kg hw_interval_ms=500
sleep 2
check "pre-existing handler is baselined, not reported" sh -c '! dmesg | grep -q "unauthorised input handler"'
check "rmmod rogue" rmmod kg_test_rogue
check "rmmod kernelguard" rmmod kernelguard

step "kbd_allow= authorises a named handler"
dmesg -c > /dev/null
check "insmod kernelguard kbd_allow=rogue_logger" load_kg hw_interval_ms=500 kbd_allow=rogue_logger
check "insmod rogue" insmod /modules/kg_test_rogue.ko
sleep 2
check "allow-listed handler raises nothing" sh -c '! dmesg | grep -q "unauthorised input handler"'
check "rmmod rogue" rmmod kg_test_rogue

step "callback integrity: hijacked function pointer"
dmesg -c > /dev/null
check "insmod rogue mode=foreign (name 'leds' is allowed, .event points into another module)" \
      insmod /modules/kg_test_rogue.ko mode=foreign
check "identity is fine, integrity check fires" wait_for 8 klog_has "different module than its handler"
check "reported as INPUT hook (0x0021) critical" sh -c 'dmesg | grep "alert 0x0021" | head -1 | grep -q .'
check "name-based check did not fire (handler is called leds)" sh -c '! dmesg | grep -q "unauthorised input handler"'
check "hook triggers fail-safe" klog_has "FAIL-SAFE MODE ENTERED"
check "rmmod rogue" rmmod kg_test_rogue

step "callback integrity: entry-point detour"
dmesg -c > /dev/null
check "insmod rogue mode=detour (JMP at .event entry into another module)" \
      insmod /modules/kg_test_rogue.ko mode=detour
check "detour detected" wait_for 8 klog_has "entry point jumps into a different module"
check "rmmod rogue (restores its bytes)" rmmod kg_test_rogue
sleep 1

step "unload"
check "rmmod kernelguard" rmmod kernelguard
check_no_kernel_faults
