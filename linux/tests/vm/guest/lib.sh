# Guest-side test helpers (busybox ash).  Sourced by init and by each test.
PASS=0
FAIL=0
KGPARAM=/sys/module/kernelguard/parameters

ok()  { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
step() { echo "-- $*"; }
skip() { echo "  [SKIP] $*"; }

# check "description" command args...
check() {
    desc=$1; shift
    if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}

# check_not "description" command args...   (passes when the command FAILS)
check_not() {
    desc=$1; shift
    if "$@" >/dev/null 2>&1; then bad "$desc"; else ok "$desc"; fi
}

# wait_for SECONDS command args...   -> 0 as soon as the command succeeds
wait_for() {
    limit=$(($1 * 10)); shift
    while [ "$limit" -gt 0 ]; do
        "$@" >/dev/null 2>&1 && return 0
        sleep 0.1
        limit=$((limit - 1))
    done
    return 1
}

klog()      { dmesg; }
klog_has()  { dmesg | grep -q -- "$1"; }
klog_count() { dmesg | grep -c -- "$1"; }

# Load the module under test with the given parameters.
load_kg() {
    insmod /modules/kernelguard.ko "$@"
}

# Fail the test if the kernel reported a problem of its own.
check_no_kernel_faults() {
    if dmesg | grep -E -q 'BUG:|WARNING:|Oops|general protection|KFENCE|Call Trace|kernel NULL pointer|refcount_t'; then
        bad "kernel reported a fault (see log)"
        dmesg | grep -E -B2 -A12 'BUG:|WARNING:|Oops|general protection|KFENCE|Call Trace' | head -60
    else
        ok "no kernel faults / warnings in dmesg"
    fi
}

inject() { echo "$*" > $KGPARAM/test_inject; }

finish() {
    result=PASS
    [ "$FAIL" -eq 0 ] || result=FAIL
    echo "TEST-RESULT: $result pass=$PASS fail=$FAIL"
    sync
    poweroff -f
}
