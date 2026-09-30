// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_test_other.c - TEST FIXTURE, loaded only inside the throw-away VM guest.
 *
 * The innocent bystander of the driver-load gate suite: a module that is on no deny list, so the
 * suite can check the gate leaves it alone, and that lock mode treats it according to whether it
 * was loaded before the lock (baseline) or after.  It does nothing.  Unlike kg_test_stub it sets no
 * MODULE_VERSION, so it also covers a module that carries only the srcversion the build adds.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

static int __init other_init(void)
{
	pr_info("kg_test_other: init ran\n");
	return 0;
}

static void __exit other_exit(void)
{
	pr_info("kg_test_other: exit ran\n");
}

module_init(other_init);
module_exit(other_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KernelGuard test fixture: a module the driver-load gate must not touch");
