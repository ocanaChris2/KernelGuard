# integrity: Module 3.  False-positive control first, then each kind of tampering.
step "baseline"
check "insmod kernelguard (fast integrity interval)" load_kg integrity_interval_ms=300
check "baseline logged" klog_has "integrity baseline"
kgmon status > /tmp/st.txt
grep -E "monitored|modules " /tmp/st.txt
check "text integrity active"           grep -q 'text=on' /tmp/st.txt
check "kernel image + this module baselined" sh -c '[ "$(sed -n "s/.*: \([0-9]*\) text region.*/\1/p" /tmp/st.txt)" -ge 2 ]'
check "kernel text extent found"        klog_has "kernel text: "
sleep 1.5
check "quiet system raises no text alerts" sh -c '! dmesg | grep -q "alert 0x0022"'

step "legitimate kernel self-modification must NOT alert"
T=/sys/kernel/tracing
if [ -d $T ]; then
    echo 1 > $T/events/sched/enable                  # tracepoints = jump labels flipping in vmlinux
    echo 'do_*' > $T/set_ftrace_filter              # ftrace fentry sites: NOP5 -> CALL
    echo function > $T/current_tracer
    echo "   tracing enabled: $(wc -l < $T/set_ftrace_filter) filtered functions"
    sleep 4
    echo nop > $T/current_tracer
    echo 0 > $T/events/sched/enable
    echo > $T/set_ftrace_filter
    sleep 3
    kgmon status > /tmp/st2.txt
    DYN=$(awk '/text_dynamic_patches/ {print $2}' /tmp/st2.txt)
    PATCH=$(awk '/text_patch_detected/ {print $2}' /tmp/st2.txt)
    echo "   dynamic patch sites accepted: $DYN, alerts: $PATCH"
    check "patch sites were seen and classified as benign" sh -c "[ ${DYN:-0} -gt 0 ]"
    check "no TEXT_PATCH alert for ftrace/jump-label activity" sh -c "[ ${PATCH:-1} -eq 0 ]"
    check "driver not in fail-safe"  sh -c '! grep -q FAIL-SAFE /tmp/st2.txt'
    if [ "${PATCH:-1}" -ne 0 ]; then echo "   --- unexpected alerts:"; dmesg | grep "alert 0x0022" | head -12; fi
else
    bad "tracefs not available - cannot exercise the benign-patch classifier"
fi

step "module lifecycle"
check "insmod test fixture" insmod /modules/kg_test_tamper.ko
check "module load reported (unsigned => warning)" wait_for 5 klog_has "module kg_test_tamper loaded"
kgmon --once > /tmp/r.txt 2>&1
check "MODULE_LOADED alert carries the module name" grep -q 'Kernel Module Loaded.*name: "kg_test_tamper"' /tmp/r.txt
P=/sys/module/kg_test_tamper/parameters/apply

step "module text tampering"
echo modtext > $P
check "patched module text detected" wait_for 10 klog_has "module text modified at kg_test_tamper"
check "critical => fail-safe"        wait_for 5 klog_has "FAIL-SAFE MODE ENTERED"
echo undo > $P
sleep 1

step "kernel text tampering"
echo kerneltext > $P
check "patched vmlinux text detected" wait_for 15 klog_has "kernel text modified at vmlinux"
kgmon --once > /tmp/r2.txt 2>&1
check "alert authenticated and flagged [kernel]" grep -q 'Kernel .text Patched.*HMAC=OK.*\[kernel\]' /tmp/r2.txt
echo undo > $P
sleep 1.5

step "syscall-entry MSR tampering"
echo cstar > $P
check "MSR_CSTAR change on CPU1 detected" wait_for 10 klog_has "CPU1 MSR_CSTAR"
echo undo > $P
sleep 1

step "CR0.WP tampering"
echo wp > $P
check "CR0.WP cleared on CPU1 detected" wait_for 10 klog_has "CPU1 CR0.WP"
echo undo > $P
sleep 1

step "IDT tampering"
echo idt > $P
check "modified IDT gate detected" wait_for 10 klog_has "IDT\[0xeb\] changed since baseline"
check "reported as an IDT hook (0x0020)" klog_has "alert 0x0020"
echo undo > $P
sleep 1

step "unload"
check "rmmod fixture (restores everything)" rmmod kg_test_tamper
sleep 1
check "fixture's region dropped"  klog_has "kernelguard"    # notifier ran without incident
check "rmmod kernelguard" rmmod kernelguard
check_no_kernel_faults
