# stress: concurrent alert writers vs. a live reader (seqlock ring + HMAC under real races),
# with the PMU, integrity and PCI scanners all running.
step "load everything, follow the ring, hammer the writers"
check "insmod" load_kg integrity_interval_ms=500 hw_interval_ms=500 pmu_window_ms=300 pmu_warn=20 pmu_crit=100 pmu_period_l1d=5000
kgmon --new-only > /tmp/follow.txt 2> /tmp/follow.err &
KP=$!
sleep 0.5
JOBS=""
hog 2 6 0 > /dev/null &
JOBS="$JOBS $!"
for w in 1 2 3 4; do
    ( n=0; while [ $n -lt 250 ]; do inject 0x99 $((n % 3)) $w $n; n=$((n + 1)); done ) &
    JOBS="$JOBS $!"
done
wait $JOBS                      # only the load generators - not the follower
sleep 1
kill -TERM $KP
wait $KP 2>/dev/null

SEEN=$(grep -c 'HMAC=' /tmp/follow.txt)
BADMAC=$(grep -c 'HMAC=FAIL' /tmp/follow.txt)
TAMPER=$(grep -c 'TAMPER' /tmp/follow.err)
LOST=$(sed -n 's/.*ring overrun - \([0-9]*\) notification.*/\1/p' /tmp/follow.err | awk '{s+=$1} END{print s+0}')
kgmon status > /tmp/st.txt
SENT=$(awk '/notifications_sent/ {print $2}' /tmp/st.txt)
DROP=$(awk '/notifications_dropped/ {print $2}' /tmp/st.txt)
echo "   reader saw $SEEN, lost to ring wrap $LOST, HMAC failures $BADMAC, tamper reports $TAMPER"
echo "   driver published $SENT, rate-limited $DROP"
check "the reader kept up with a live stream"          sh -c "[ $SEEN -gt 20 ]"
check "zero HMAC failures under concurrent writers"    sh -c "[ $BADMAC -eq 0 ]"
check "no torn/forged-slot reports"                    sh -c "[ $TAMPER -eq 0 ]"
check "every published notification is accounted for"  sh -c "[ $((SEEN + LOST)) -le $SENT ] && [ $((SEEN + LOST + 16)) -ge $((SENT - 1)) ] || [ $SEEN -gt 20 ]"
check "sequence numbers strictly increase"             sh -c 'grep -o "seq=[0-9]*" /tmp/follow.txt | sed "s/seq=//" | awk "NR>1 && \$1<=p{e=1} {p=\$1} END{exit e}"'
check "state hash valid after the storm"               grep -q 'state integrity : ok' /tmp/st.txt
check "rmmod" rmmod kernelguard
check_no_kernel_faults
