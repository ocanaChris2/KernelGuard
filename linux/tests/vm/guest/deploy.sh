# deploy: scripts/kg-deploy.sh and kg-stop.sh under busybox ash, with a real insmod.
export KG_MODULE=/modules/kernelguard.ko KG_KGMON=/bin/kgmon
S=/scripts/kg-deploy.sh

step "preflight"
sh $S preflight > /tmp/pre.txt 2>&1
cat /tmp/pre.txt
check "preflight sees a loadable, unsigned-but-unenforced setup" grep -q 'signature enforcement is off' /tmp/pre.txt
check "module reported not loaded"                             grep -q 'kernelguard is not loaded' /tmp/pre.txt

step "install with monitor"
sh $S install --monitor > /tmp/inst.txt 2>&1
cat /tmp/inst.txt
check "module loaded"                    grep -q '^kernelguard ' /proc/modules
check "device node present"              test -c /dev/kernelguard
check "monitor pid file written"         test -s /run/kernelguard-monitor.pid
check "monitor is really running"        sh -c 'kill -0 $(cat /run/kernelguard-monitor.pid)'
inject 0x10 1 0x6f67756572 0
sleep 1
check "monitor logged the alert to its CSV" grep -q 'Unauthorized Keyboard Filter' /var/log/kernelguard-alerts.csv
check "status shows parameters and monitor" sh -c 'sh /scripts/kg-deploy.sh status | grep -q "monitor running"'
check "a second install is refused"         sh -c '! sh /scripts/kg-deploy.sh install >/dev/null 2>&1'

step "uninstall"
sh $S uninstall > /tmp/un.txt 2>&1
cat /tmp/un.txt
check "module unloaded"                  sh -c '! grep -q "^kernelguard " /proc/modules'
check "monitor stopped"                  sh -c '! kill -0 $(cat /run/kernelguard-monitor.pid 2>/dev/null) 2>/dev/null'
check "pid file removed"                 sh -c '! test -e /run/kernelguard-monitor.pid'

step "install --enforce, then the emergency stop"
sh $S install --enforce > /tmp/enf.txt 2>&1
check "enforce warning printed"          grep -q 'enforce=1' /tmp/enf.txt
check "module loaded with enforce=Y"     sh -c '[ "$(cat /sys/module/kernelguard/parameters/enforce)" = Y ]'
sh /scripts/kg-stop.sh > /tmp/stop.txt 2>&1
cat /tmp/stop.txt
check "kg-stop switched enforce off first" grep -q 'enforce switched off' /tmp/stop.txt
check "kg-stop unloaded the module"      sh -c '! grep -q "^kernelguard " /proc/modules'
check "kg-stop is safe to run again"     sh -c 'sh /scripts/kg-stop.sh 2>&1 | grep -q "not loaded"'
check_no_kernel_faults
