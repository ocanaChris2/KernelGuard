# hwlegacy: a platform with NO MCFG table (QEMU's i440fx 'pc' machine).  Module 2 must
# degrade to auditing the OS view instead of failing, and still block bus mastering.
find_dev() { for d in /sys/bus/pci/devices/*; do case "$(cat $d/class)" in $1*) basename $d; return 0;; esac; done; return 1; }
bmebit()  { echo $(( (0x$(dd if=/sys/bus/pci/devices/$1/config bs=1 skip=4 count=1 2>/dev/null | xxd -p) >> 2) & 1 )); }
bme_clear() { [ "$(bmebit $NIC)" = 0 ]; }
set_bme() { printf '\007\000' | dd of=/sys/bus/pci/devices/$1/config bs=1 seek=4 count=2 conv=notrunc 2>/dev/null; }

NIC=$(find_dev 0x0200)
check "guest has no MCFG (legacy machine)" sh -c '! dmesg | grep -q "ECAM \[mem"'

step "no ECAM: fall back to the OS view"
echo 1 > /sys/bus/pci/devices/$NIC/remove
check "insmod kernelguard" load_kg hw_interval_ms=500
check "missing ECAM is reported, not fatal" klog_has "ECAM unavailable"
check "baseline is built from the OS view"  klog_has "answering in the OS view"
klog | grep -E "kernelguard: (ECAM|PCI baseline)"
kgmon status > /tmp/st.txt
check "status: ECAM inactive, PCI still audited" sh -c 'grep -q "pci-ecam=off" /tmp/st.txt && grep -q "PCI device" /tmp/st.txt'
sleep 1.5
check "no alert on the baseline" sh -c '! dmesg | grep -q "alert 0x001[12]\]"'

step "a device the OS learns about later"
echo 1 > /sys/bus/pci/rescan
sleep 0.5
set_bme $NIC
check "reported as an unauthorised bus master" wait_for 8 klog_has "unauthorised bus master $NIC"
echo 1 > $KGPARAM/enforce
check "enforce clears it through the PCI core" wait_for 8 bme_clear
check "DEVICE_BME_DISABLED reported"          klog_has "bus mastering cleared on $NIC"

step "unload"
check "rmmod kernelguard" rmmod kernelguard
check_no_kernel_faults
