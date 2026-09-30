// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_test_stub.c - TEST FIXTURE, loaded only inside the throw-away VM guest.
 *
 * Stands in for "the vulnerable driver" of a bring-your-own-vulnerable-driver attack, so the
 * driver-load gate has a module with a known name and srcversion to recognise and refuse.  It has
 * NO vulnerability and no interface at all: it only logs when init and exit run, which is how the
 * suite proves that a refused load never got as far as init().
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

static int __init stub_init(void)
{
	pr_info("kg_test_stub: init ran\n");
	return 0;
}

static void __exit stub_exit(void)
{
	pr_info("kg_test_stub: exit ran\n");
}

module_init(stub_init);
module_exit(stub_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KernelGuard test fixture: a harmless stand-in for a vulnerable driver");
MODULE_VERSION("1.0");
