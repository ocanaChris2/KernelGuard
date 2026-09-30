# lifecycle: init/exit symmetry, leaks, unload under load, hostile parameters.
memfree() { awk '/^MemFree:/ {print $2}' /proc/meminfo; }
hpstates() { cat /sys/devices/system/cpu/hotplug/states 2>/dev/null | grep -c kernelguard; }

step "repeated load/unload"
cycle() {   # cycle N: N full load / exercise / unload cycles; prints number of failures
    n=$1; f=0
    while [ $n -gt 0 ]; do
        load_kg integrity_interval_ms=400 hw_interval_ms=400 pmu_window_ms=300 || f=$((f + 1))
        sleep 0.6
        inject 0x99 1 $n 0
        kgmon status >/dev/null 2>&1 || f=$((f + 1))
        rmmod kernelguard || f=$((f + 1))
        n=$((n - 1))
    done
    echo $f
}
F1=$(cycle 4)                       # warm-up: first-use caches (module file, kgmon binary, ...)
sync; sleep 1; M_A=$(memfree)
F2=$(cycle 12)
sync; sleep 1; M_B=$(memfree)
LOST=$(( (M_A - M_B) / 1024 ))
echo "   4 warm-up cycles, then 12 more: free memory changed by ${LOST} MiB"
echo "   (a leaked 22 MiB text baseline would cost ~264 MiB; even a 0.5 MiB/cycle leak would show as 6)"
check "16 load/unload cycles all succeeded"         sh -c "[ $F1 -eq 0 ] && [ $F2 -eq 0 ]"
check "steady state: 12 further cycles lose < 5 MiB"  sh -c "[ $LOST -lt 5 ]"
check "module gone from /proc/modules and sysfs"    sh -c '! grep -q kernelguard /proc/modules && ! test -d /sys/module/kernelguard'
check "device node gone"                            sh -c '! test -e /dev/kernelguard'
check "cpuhp states unregistered"                   sh -c "[ $(hpstates) -eq 0 ]"
check_no_kernel_faults

step "hostile parameters do not hang or spam"
dmesg -c > /dev/null
check "insmod with nonsense tunables" load_kg pmu_period_l1d=1 pmu_period_llc=1 pmu_window_ms=0 \
      pmu_warn=0 pmu_crit=0 hw_interval_ms=0 integrity_interval_ms=1
sleep 3
kgmon status > /tmp/st.txt 2>&1
check "still responsive"                            grep -q 'ABI 1' /tmp/st.txt
check "tiny sample periods refused"                 klog_has "raised to the minimum"
check "no NMI storm: overflow rate stays sane"      sh -c "[ \$(awk '/pmu_l1d_overflows/ {print \$2}' /tmp/st.txt) -lt 200000 ]"
check "log stays bounded even with absurd thresholds" sh -c "[ \$(dmesg | grep -c 'alert 0x000[12]\]') -lt 45 ]"
check "rmmod" rmmod kernelguard

step "unload while everything is busy"
load_kg integrity_interval_ms=300 hw_interval_ms=300 pmu_window_ms=300 pmu_warn=20 pmu_crit=100 pmu_period_l1d=5000
hog 3 6 0 > /tmp/hog.txt &
vkbd busy 5 > /tmp/vk.txt &
( while [ -w $KGPARAM/test_inject ]; do inject 0x99 1 1 2; done ) 2>/dev/null &
INJ=$!
T=/sys/kernel/tracing
if [ -d $T ]; then
    echo 'do_*' > $T/set_ftrace_filter; echo function > $T/current_tracer
    echo 1 > $T/events/sched/enable
fi
sleep 3
check "rmmod succeeds under load (PMU NMIs, tracing, keyboard events, alert flood)" rmmod kernelguard
kill $INJ 2>/dev/null
if [ -d $T ]; then echo nop > $T/current_tracer; echo 0 > $T/events/sched/enable; echo > $T/set_ftrace_filter; fi
wait
check_no_kernel_faults
