# smt: an anomaly on one hardware thread must escalate and flush the thread that shares its core.
step "topology"
SIB0=$(cat /sys/devices/system/cpu/cpu0/topology/thread_siblings_list)
echo "   cpu0 thread siblings: $SIB0"
check "guest really has SMT siblings" sh -c "[ '$SIB0' != '0' ]"
# the other thread of cpu0's core
OTHER=$(echo "$SIB0" | tr ',-' '  ' | tr ' ' '\n' | grep -vx 0 | head -1)
echo "   sibling of cpu0 is cpu$OTHER"

step "load"
check "insmod kernelguard" load_kg pmu_period_l1d=10000 pmu_period_llc=2000 pmu_window_ms=500 pmu_warn=50 pmu_crit=300
if ! klog_has "PMU detection: "; then
    skip "guest has no usable vPMU"
    rmmod kernelguard; check_no_kernel_faults; return 0 2>/dev/null || exit 0
fi
kgmon status > /tmp/st0.txt
check "driver reports SMT" grep -q 'SMT=yes' /tmp/st0.txt
check "every CPU starts at its baseline strategy" sh -c '! grep -q "full-spectrum" /tmp/st0.txt'

step "load ONE hardware thread"
hog 1 4 0 > /dev/null &
sleep 2.2
kgmon status > /tmp/st1.txt
grep -E "^  [0-9]" /tmp/st1.txt
check "the loaded CPU 0 is escalated"  sh -c "grep -E '^  0 ' /tmp/st1.txt | grep -q full-spectrum"
check "its SMT sibling (cpu$OTHER) is escalated too" sh -c "grep -E '^  $OTHER ' /tmp/st1.txt | grep -q full-spectrum"
check "a CPU on the other core is left alone" sh -c "[ \$(grep -c full-spectrum /tmp/st1.txt) -le 2 ]"
wait
sleep 4
kgmon status > /tmp/st2.txt
check "both threads relax once the load ends"  sh -c '! grep -q "full-spectrum" /tmp/st2.txt'
FL=$(awk '/active_mitigation_flags/ {print $2}' /tmp/st2.txt)
echo "   active_mitigation_flags=$FL"
check "the mitigation bits record what was run" sh -c "[ ${FL:-0} -gt 0 ]"

step "unload"
check "rmmod kernelguard" rmmod kernelguard
check_no_kernel_faults
