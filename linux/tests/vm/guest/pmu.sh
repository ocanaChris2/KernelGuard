# pmu: Module 1.  Idle control, detection + attribution, mitigation escalation/decay,
# interaction with Module 3, CPU hotplug, clean unload.
step "load (low thresholds so a short burst is enough)"
check "insmod kernelguard" load_kg pmu_period_l1d=10000 pmu_period_llc=2000 \
      pmu_window_ms=500 pmu_warn=50 pmu_crit=300 integrity_interval_ms=400
if klog_has "PMU detection unavailable" || ! klog_has "PMU detection: "; then
    skip "guest has no usable vPMU - the remaining PMU checks need one"
    rmmod kernelguard
    check_no_kernel_faults
    return 0 2>/dev/null || exit 0
fi
klog | grep "PMU detection: "
kgmon status > /tmp/st0.txt
check "status reports the PMU active" grep -q 'pmu=on' /tmp/st0.txt

step "idle system: no cache-attack alert"
sleep 3
check "no PMU alert while idle" sh -c '! dmesg | grep -q "alert 0x000[12]\]"'

step "cache-thrashing load"
hog 2 4 0 > /tmp/hog.txt &
sleep 2.2
kgmon status > /tmp/st1.txt
check "an L1D anomaly alert was raised"        wait_for 5 klog_has "alert 0x0001"
check "mitigation escalated on a loaded CPU"   grep -q 'full-spectrum' /tmp/st1.txt
wait
sleep 0.5
cat /tmp/hog.txt
kgmon --once > /tmp/ring.txt 2>&1
grep -E "Cache Attack" /tmp/ring.txt | head -6
check "alerts authenticated"                   sh -c 'grep -q "Cache Attack Pattern.*HMAC=OK" /tmp/ring.txt && ! grep -q "HMAC=FAIL" /tmp/ring.txt'
HOGPIDS=$(awk '/hog pid/ {print $3}' /tmp/hog.txt | tr '\n' ' ')
dmesg | grep "cache-miss rate on CPU[01]:" | head -4
OFFENDERS=$(dmesg | sed -n 's/.*cache-miss rate on CPU[01]:.*top user task hog\[\([0-9]*\)\].*/\1/p' | sort -u | tr '\n' ' ')
echo "   hog pids: $HOGPIDS  offenders named for the loaded CPUs: ${OFFENDERS:-none}"
check "loaded CPUs' alerts name a hog process" sh -c "for o in $OFFENDERS; do case ' $HOGPIDS ' in *' '\$o' '*) exit 0;; esac; done; exit 1"
check "no alert blamed on an unloaded CPU (self-noise suppressed)" sh -c '! dmesg | grep -q "cache-miss rate on CPU[23]:.*top user task"'

step "decay after the load stops"
sleep 4
kgmon status > /tmp/st2.txt
check "strategy relaxed back to the CPU baseline" sh -c '! grep -q "full-spectrum" /tmp/st2.txt'
FL=$(awk '/total_flush_count/ {print $2}' /tmp/st2.txt)
OV=$(awk '/pmu_l1d_overflows/ {print $2}' /tmp/st2.txt)
echo "   flushes=$FL l1d overflows=$OV"
check "boundary flushes were executed"         sh -c "[ ${FL:-0} -gt 0 ]"
check "overflow counter advanced"              sh -c "[ ${OV:-0} -gt 0 ]"
check "driver state hash still valid"          grep -q 'state integrity : ok' /tmp/st2.txt

step "module 3 must not mistake PMU setup for tampering"
check "no TEXT_PATCH alert (perf static keys flipped by our own counters)" \
      sh -c '! dmesg | grep -q "alert 0x0022"'
check "not in fail-safe"                        sh -c '! grep -q FAIL-SAFE /tmp/st2.txt'

step "CPU hotplug"
if [ -w /sys/devices/system/cpu/cpu3/online ]; then
    echo 0 > /sys/devices/system/cpu/cpu3/online
    sleep 1
    echo 1 > /sys/devices/system/cpu/cpu3/online
    sleep 1
    N=$(dmesg | grep -c "alert 0x0001")
    hog 1 3 3 > /tmp/hog3.txt
    check "counters recreated on the re-onlined CPU" wait_for 3 sh -c "[ \$(dmesg | grep -c 'alert 0x0001') -gt $N ]"
    check "alert names CPU 3" sh -c 'kgmon --once 2>&1 | grep -q "L1D Cache Attack Pattern.*cpu: 3"'
else
    skip "CPU hotplug not available"
fi

step "unload"
check "rmmod kernelguard" rmmod kernelguard
hog 1 1 0 > /dev/null 2>&1
check "load after unload is harmless (no dangling NMI handlers)" true
check_no_kernel_faults
