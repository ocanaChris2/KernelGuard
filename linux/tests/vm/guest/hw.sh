# hw: Module 2 PCI half.  ECAM discovery through bridges, OS<->hardware cross-check,
# DMA audit on a real hot-plugged device, enforcement, allow-list.
devs()    { ls /sys/bus/pci/devices | sort; }
ndevs()   { ls /sys/bus/pci/devices | wc -l; }
find_dev() { for d in /sys/bus/pci/devices/*; do case "$(cat $d/class)" in $1*) basename $d; return 0;; esac; done; return 1; }
cmdbyte() { dd if=/sys/bus/pci/devices/$1/config bs=1 skip=4 count=1 2>/dev/null | xxd -p; }
bme()     { echo $(( (0x$(cmdbyte $1) >> 2) & 1 )); }
set_bme() { printf '\007\000' | dd of=/sys/bus/pci/devices/$1/config bs=1 seek=4 count=2 conv=notrunc 2>/dev/null; }
vendev()  { echo "$(sed 's/0x//' /sys/bus/pci/devices/$1/vendor):$(sed 's/0x//' /sys/bus/pci/devices/$1/device)"; }
# qemu_cmd ...: ask the host harness to run a QEMU monitor command.  Goes to stderr (the console)
# so it still works inside $(...) command substitution.
qemu_cmd() { echo "@@QEMU $*" >&2; }
# hotplug ID BUS: ask the host harness to hot-add a virtio-rng behind root port BUS; print its BDF
hotplug() {
    BEFORE=$(devs); N0=$(ndevs)
    qemu_cmd device_add virtio-rng-pci,id=$1,bus=$2
    wait_for 15 sh -c "[ \$(ls /sys/bus/pci/devices | wc -l) -gt $N0 ]" || { echo 1 > /sys/bus/pci/rescan; sleep 1; }
    for d in $(devs); do echo "$BEFORE" | grep -qx "$d" || echo "$d"; done | tail -1
}

SATA=$(find_dev 0x0106)
echo "   SATA=$SATA  root ports: $(for d in /sys/bus/pci/devices/*; do [ "$(cat $d/class)" = 0x060400 ] && basename $d; done | tr '\n' ' ')"

step "baseline"
check "insmod kernelguard" load_kg hw_interval_ms=500
check "MCFG/ECAM located" klog_has "ECAM: "
check "PCI baseline built from ECAM plus the OS view" klog_has "PCI baseline: [0-9]* device(s)"
klog | grep -E "kernelguard: (ECAM|PCI baseline)"
kgmon status > /tmp/st0.txt
grep -E "monitored|modules " /tmp/st0.txt
NBASE=$(sed -n 's/.*, \([0-9]*\) PCI device.*/\1/p' /tmp/st0.txt)
check "ECAM walk saw the same devices the OS enumerated ($NBASE vs $(ndevs))" sh -c "[ $NBASE -eq $(ndevs) ]"
sleep 1.6
check "clean system raises neither a DMA nor a discrepancy alert" sh -c '! dmesg | grep -q "alert 0x001[12]\]"'

step "hidden device: the hardware answers, the OS does not"
echo 1 > /sys/bus/pci/devices/$SATA/remove
check "discrepancy reported once it persisted over two scans" wait_for 8 klog_has "$SATA.*hidden from the OS"
kgmon --once > /tmp/r.txt 2>&1
grep "Discrepancy" /tmp/r.txt
check "PCI_DISCREPANCY authenticated, kind 'hidden from OS'" grep -q "PCIe Device Discrepancy.*HMAC=OK.*$SATA.*hidden from OS" /tmp/r.txt
echo 1 > /sys/bus/pci/rescan
sleep 1
N1=$(klog_count "alert 0x0012")
sleep 2.5
check "no further alert once the OS sees the device again" sh -c "[ $(klog_count 'alert 0x0012') -eq $N1 ]"

step "hot-plug behind a bridge, then bus mastering"
NEW=$(hotplug hp1 rp1)
echo "   hot-plugged device: ${NEW:-none} [$(vendev $NEW 2>/dev/null)]"
check "device appeared" test -n "$NEW"
kgmon status > /tmp/st1.txt
NNOW=$(sed -n 's/.*, \([0-9]*\) PCI device.*/\1/p' /tmp/st1.txt)
check "ECAM walk followed the bridge to the new device (now $NNOW)" wait_for 6 sh -c "[ \$(kgmon status | sed -n 's/.*, \([0-9]*\) PCI device.*/\1/p') -gt $NBASE ]"
set_bme $NEW
check "BME is set in hardware" sh -c "[ $(bme $NEW) = 1 ]"
check "unauthorised bus master reported" wait_for 8 klog_has "unauthorised bus master $NEW"
dmesg | grep "unauthorised bus master $NEW" | head -2
kgmon --once > /tmp/r2.txt 2>&1
grep "Unauthorized DMA" /tmp/r2.txt
check "authenticated and names the BDF"  grep -q "Unauthorized DMA Access.*HMAC=OK.*$NEW" /tmp/r2.txt
check "detect-only leaves bus mastering alone" sh -c "[ $(bme $NEW) = 1 ]"

step "enforce=1 clears bus mastering - and keeps clearing it"
echo 1 > $KGPARAM/enforce
check "bus mastering cleared in hardware" wait_for 8 sh -c "[ \$(( (0x\$(dd if=/sys/bus/pci/devices/$NEW/config bs=1 skip=4 count=1 2>/dev/null | xxd -p) >> 2) & 1 )) = 0 ]"
check "DEVICE_BME_DISABLED reported" klog_has "bus mastering cleared on $NEW"
set_bme $NEW
check "a driver switching it back on is undone again" wait_for 8 sh -c "[ \$(( (0x\$(dd if=/sys/bus/pci/devices/$NEW/config bs=1 skip=4 count=1 2>/dev/null | xxd -p) >> 2) & 1 )) = 0 ]"
echo 0 > $KGPARAM/enforce
VD=$(vendev $NEW)

step "dma_allow= authorises a device model"
qemu_cmd device_del hp1
wait_for 10 sh -c "[ \$(ls /sys/bus/pci/devices | wc -l) -le $NBASE ]"
check "rmmod kernelguard" rmmod kernelguard
dmesg -c > /dev/null
check "insmod kernelguard dma_allow=$VD" load_kg hw_interval_ms=500 dma_allow=$VD
NEW2=$(hotplug hp2 rp2)
set_bme $NEW2
sleep 3
check "allow-listed device ($NEW2) is not reported" sh -c "! dmesg | grep -q 'unauthorised bus master'"
check "…but the same event without the allow-list would have been (bme=$(bme $NEW2))" sh -c "[ $(bme $NEW2) = 1 ]"

step "unload"
check "rmmod kernelguard" rmmod kernelguard
check_no_kernel_faults
