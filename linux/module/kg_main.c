// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_main.c - module entry/exit and the /dev/kernelguard character device.
 * Counterpart of windows/src/driver_main.c.
 *
 * Boot sequence (order matters, as in DriverEntry):
 *   1. state + secure channel first, so anything raised while the other
 *      modules initialise already has somewhere to go
 *   2. Module 4 mitigation engine (per-CPU strategy table)
 *   3. Module 3 integrity baseline - captured BEFORE the monitors start, so it
 *      records the clean pre-attack state
 *   4. Module 2 hardware / keyboard-path detection
 *   5. Module 1 PMU detection
 *   6. the device node, last
 *
 * Core failures (state, channel, mitigation, device) abort the load.  The four
 * monitors degrade instead: a VM without a PMU or a board without an MCFG
 * table still gets everything else.
 *
 * Unlike the Windows driver, the monitors that can take *active* action
 * (disable bus mastering, detach an input handle) do so only when the module is
 * loaded with enforce=1.  The Windows README documents keyboard loss on VMs and
 * on non-standard hardware as the price of acting unconditionally; on a
 * developer's Linux box that default would be hostile.
 */
#include "kg.h"

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/*----------------------------------------------------------------------------
 * Module parameters
 *--------------------------------------------------------------------------*/
bool kg_enforce;
module_param_named(enforce, kg_enforce, bool, 0644);
MODULE_PARM_DESC(enforce,
	"Take active mitigation (clear PCI bus mastering of unauthorised DMA devices, "
	"detach unauthorised input handlers). Default 0: detect and report only.");

char kg_kbd_allow[256];
module_param_string(kbd_allow, kg_kbd_allow, sizeof(kg_kbd_allow), 0444);
MODULE_PARM_DESC(kbd_allow,
	"Extra input handler names to treat as authorised (comma separated). "
	"Handlers present at load time and the stock kernel ones are always authorised.");

char kg_dma_allow[256];
module_param_string(dma_allow, kg_dma_allow, sizeof(kg_dma_allow), 0444);
MODULE_PARM_DESC(dma_allow,
	"Extra PCI devices authorised for bus mastering: comma separated "
	"SSSS:BB:DD.F or VVVV:DDDD entries. Devices present at load time are always authorised.");

unsigned int kg_hw_interval_ms = KG_HW_DEF_INTERVAL_MS;
module_param_named(hw_interval_ms, kg_hw_interval_ms, uint, 0644);
MODULE_PARM_DESC(hw_interval_ms, "Module 2 re-scan interval (default 5000)");

unsigned int kg_integ_interval_ms = KG_INTEG_DEF_INTERVAL_MS;
module_param_named(integrity_interval_ms, kg_integ_interval_ms, uint, 0644);
MODULE_PARM_DESC(integrity_interval_ms, "Module 3 verification interval (default 30000)");

static bool p_pmu = true;
static bool p_hw = true;
static bool p_input = true;
static bool p_integrity = true;
module_param_named(pmu, p_pmu, bool, 0444);
module_param_named(hw, p_hw, bool, 0444);
module_param_named(input, p_input, bool, 0444);
module_param_named(integrity, p_integrity, bool, 0444);
MODULE_PARM_DESC(pmu, "Enable Module 1 (PMU cache-miss detection), default 1");
MODULE_PARM_DESC(hw, "Enable Module 2 PCI/DMA audit, default 1");
MODULE_PARM_DESC(input, "Enable Module 2 keyboard-path audit, default 1");
MODULE_PARM_DESC(integrity, "Enable Module 3 kernel integrity, default 1");

struct workqueue_struct *kg_wq;

/*----------------------------------------------------------------------------
 * Test hook - compiled ONLY with `make KG_TESTHOOKS=1`; never in a normal build.
 * Lets the VM test suite push a synthetic alert through the real report /
 * dispatch / HMAC / ring path:  echo "0x22 2 0x1000 8" > .../parameters/test_inject
 *--------------------------------------------------------------------------*/
#ifdef KG_TESTHOOKS
static int kg_inject_set(const char *val, const struct kernel_param *kp)
{
	unsigned int type, level;
	unsigned long long p1 = 0, p2 = 0;

	if (sscanf(val, "%i %u %lli %lli", &type, &level, &p1, &p2) < 2)
		return -EINVAL;
	kg_report(type, level, p1, p2, "injected test alert (KG_TESTHOOKS build)");
	return 0;
}

static const struct kernel_param_ops kg_inject_ops = { .set = kg_inject_set };
module_param_cb(test_inject, &kg_inject_ops, NULL, 0200);
#endif

/*----------------------------------------------------------------------------
 * Character device (Windows: ScpdDispatchCreate/Close/IoControl)
 *--------------------------------------------------------------------------*/
static int kg_open(struct inode *inode, struct file *file)
{
	u32 *seen = kzalloc(sizeof(*seen), GFP_KERNEL);

	if (!seen)
		return -ENOMEM;
	kg_comms_open(seen);
	file->private_data = seen;
	return nonseekable_open(inode, file);
}

static int kg_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static void kg_fill_info(struct kg_info *info)
{
	const struct kg_cpu_mit *m0 = &kg_guard.cpu[cpumask_first(cpu_online_mask)];
	u64 flags = 0;
	int cpu;

	memset(info, 0, sizeof(*info));
	info->abi_version = KG_ABI_VERSION;
	info->struct_size = sizeof(*info);
	info->ring_slots = KG_NOTIFY_SLOTS;
	info->nr_cpus = kg_guard.hdr.ncpu;

	if (kg_enforce)
		flags |= KG_INFO_ENFORCE;
	if (kg_in_failsafe())
		flags |= KG_INFO_FAIL_SAFE;
	if (kg_guard_verify())
		flags |= KG_INFO_INTEGRITY_OK;
	if (kg_pmu_active())
		flags |= KG_INFO_PMU_ACTIVE;
	if (kg_hw_ecam_active())
		flags |= KG_INFO_ECAM_ACTIVE;
	if (kg_text_active())
		flags |= KG_INFO_TEXT_ACTIVE;
	if (kg_input_active())
		flags |= KG_INFO_INPUT_ACTIVE;
	if (m0->features & KG_FEAT_CAT_L3)
		flags |= KG_INFO_CAT_L3;
	for_each_online_cpu(cpu) {
		if (kg_guard.cpu[cpu].features & KG_FEAT_SMT) {
			flags |= KG_INFO_SMT;
			break;
		}
	}
	info->flags = flags;

	kg_text_stats(&info->text_regions, &info->text_kib);
	info->pci_devices = kg_hw_device_count();
	info->kbd_devices = kg_input_device_count();

	info->stats.pmu_alert_level         = kg_stat_read(pmu_alert_level);
	info->stats.pmu_l1d_overflows       = kg_stat_read(pmu_l1d_overflows);
	info->stats.pmu_llc_overflows       = kg_stat_read(pmu_llc_overflows);
	info->stats.hw_discrepancy_count    = kg_stat_read(hw_discrepancy_count);
	info->stats.hw_dma_violation_count  = kg_stat_read(hw_dma_violation_count);
	info->stats.idt_hook_detected       = kg_stat_read(idt_hook_detected);
	info->stats.dispatch_hook_detected  = kg_stat_read(dispatch_hook_detected);
	info->stats.text_patch_detected     = kg_stat_read(text_patch_detected);
	info->stats.failed_module_hash_count = kg_stat_read(failed_module_hash_count);
	info->stats.text_dynamic_patches    = kg_stat_read(text_dynamic_patches);
	info->stats.sens_page_count         = kg_stat_read(sens_page_count);
	info->stats.active_mitigation_flags = kg_stat_read(active_mitigation_flags);
	info->stats.total_flush_count       = kg_stat_read(total_flush_count);
	info->stats.notifications_sent      = kg_stat_read(notifications_sent);
	info->stats.fallback_signals_sent   = kg_stat_read(fallback_signals_sent);
	info->stats.notifications_dropped   = kg_stat_read(notifications_dropped);

	strscpy(info->version, KG_VERSION, sizeof(info->version));
}

static long kg_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	long ret;

	switch (cmd) {
	case KG_IOC_GET_HMAC_KEY: {
		struct kg_hmac_key k;

		ret = kg_comms_get_key(k.key);
		if (!ret && copy_to_user(uarg, &k, sizeof(k)))
			ret = -EFAULT;
		memzero_explicit(&k, sizeof(k));
		return ret;
	}
	case KG_IOC_GET_INFO: {
		struct kg_info *info = kzalloc(sizeof(*info), GFP_KERNEL);

		if (!info)
			return -ENOMEM;
		kg_fill_info(info);
		ret = copy_to_user(uarg, info, sizeof(*info)) ? -EFAULT : 0;
		kfree(info);
		return ret;
	}
	case KG_IOC_GET_CPU_INFO: {
		struct kg_cpu_info ci;

		if (copy_from_user(&ci, uarg, sizeof(ci)))
			return -EFAULT;
		ret = kg_mit_cpu_info(&ci);
		if (!ret && copy_to_user(uarg, &ci, sizeof(ci)))
			ret = -EFAULT;
		return ret;
	}
	default:
		return -ENOTTY;
	}
}

static int kg_mmap(struct file *file, struct vm_area_struct *vma)
{
	return kg_comms_mmap(vma);
}

static __poll_t kg_poll(struct file *file, struct poll_table_struct *wait)
{
	return kg_comms_poll(file, wait);
}

static const struct file_operations kg_fops = {
	.owner          = THIS_MODULE,
	.open           = kg_open,
	.release        = kg_release,
	.unlocked_ioctl = kg_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.mmap           = kg_mmap,
	.poll           = kg_poll,
};

static struct miscdevice kg_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = KG_DEV_NAME,
	.fops  = &kg_fops,
	.mode  = 0600,          /* root only; the key ioctl also requires CAP_SYS_ADMIN */
};

/*----------------------------------------------------------------------------
 * Module entry / exit (Windows: DriverEntry / ScpdDriverUnload)
 *--------------------------------------------------------------------------*/
static int __init kg_init(void)
{
	int ret;

	pr_info("KernelGuard %s loading (enforce=%d)\n", KG_VERSION, kg_enforce);

	/*
	 * Independent periodic jobs (PMU sampler, integrity, PCI, keyboard, uevents) must
	 * not queue behind one another: a text-verification pass can take seconds while
	 * the kernel is being traced.  Each job is its own work item, so it never runs
	 * concurrently with itself.
	 */
	kg_wq = alloc_workqueue("kernelguard", WQ_UNBOUND | WQ_FREEZABLE, 4);
	if (!kg_wq)
		return -ENOMEM;

	ret = kg_state_init();
	if (ret)
		goto err_wq;

	ret = kg_comms_init();
	if (ret) {
		pr_err("secure channel init failed: %d\n", ret);
		goto err_state;
	}

	ret = kg_mit_init();
	if (ret) {
		pr_err("mitigation engine init failed: %d\n", ret);
		goto err_comms;
	}

	if (p_integrity) {
		ret = kg_integrity_init();
		if (ret)
			pr_warn("integrity monitor unavailable: %d (non-fatal)\n", ret);
	}
	if (p_hw) {
		ret = kg_hw_init();
		if (ret)
			pr_warn("PCI/DMA audit unavailable: %d (non-fatal)\n", ret);
	}
	if (p_input) {
		ret = kg_input_init();
		if (ret)
			pr_warn("keyboard-path audit unavailable: %d (non-fatal)\n", ret);
	}
	if (p_pmu) {
		ret = kg_pmu_init();
		if (ret)
			pr_warn("PMU detection unavailable: %d (non-fatal)\n", ret);
	}

	ret = misc_register(&kg_misc);
	if (ret) {
		pr_err("cannot register /dev/%s: %d\n", KG_DEV_NAME, ret);
		goto err_monitors;
	}
	kg_comms_set_device(kg_misc.this_device);

	kg_guard_update();
	pr_info("loaded - /dev/%s ready\n", KG_DEV_NAME);
	return 0;

err_monitors:
	kg_pmu_exit();
	kg_input_exit();
	kg_hw_exit();
	kg_integrity_exit();
	kg_mit_exit();
err_comms:
	kg_comms_exit();
err_state:
	kg_state_exit();
err_wq:
	destroy_workqueue(kg_wq);
	return ret;
}

static void __exit kg_exit(void)
{
	pr_info("unloading\n");

	/* Stop new opens and uevents first, then tear down in reverse order. */
	kg_comms_set_device(NULL);
	misc_deregister(&kg_misc);

	kg_pmu_exit();
	kg_input_exit();
	kg_hw_exit();
	kg_integrity_exit();
	kg_mit_exit();
	kg_comms_exit();
	kg_state_exit();

	destroy_workqueue(kg_wq);
	pr_info("unloaded\n");
}

module_init(kg_init);
module_exit(kg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelGuard Security Research");
MODULE_DESCRIPTION("Side-channel attack detection and mitigation, kernel integrity and hardware keylogger detection");
MODULE_VERSION(KG_VERSION);
