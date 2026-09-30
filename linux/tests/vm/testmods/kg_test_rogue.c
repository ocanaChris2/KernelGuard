// SPDX-License-Identifier: GPL-2.0
/*
 * kg_test_rogue.c - TEST FIXTURE, loaded only inside the throw-away VM guest.
 *
 * Plays the part of a kernel keylogger's input handler so the suite can check
 * that kernelguard notices it, reports it, and (enforce=1) detaches it without
 * breaking the legitimate consumers of the keyboard or crashing when the fixture
 * later unloads.  It only COUNTS events - it never stores or forwards a key.
 *
 *   mode=rogue     (default)  an ordinary handler with an unknown name, handle
 *                              opened => receives every key of every keyboard
 *   mode=foreign               handler named "leds" (an allowed name) whose .event
 *                              points into another module - a hijacked pointer.
 *                              The handle is NOT opened, so the pointer is never called.
 *   mode=detour                handler named "leds" whose .event function starts
 *                              with a JMP into another module.  Not opened either.
 */
#include <linux/init.h>
#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

static char *mode = "rogue";
module_param(mode, charp, 0444);

static atomic_t events = ATOMIC_INIT(0);
static int events_get(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%d\n", atomic_read(&events));
}
static const struct kernel_param_ops events_ops = { .get = events_get };
module_param_cb(events, &events_ops, NULL, 0444);

/*
 * Another module's function (exported by kernelguard); never actually called.
 * Resolved with symbol_get() only in the modes that need it, so mode=rogue can be
 * loaded before kernelguard (the trust-on-first-use test).
 */
extern void kg_sens_free(void *ptr);
static void (*foreign_fn)(void *);

static noinline void my_event(struct input_handle *h, unsigned int type, unsigned int code, int value)
{
	atomic_inc(&events);
}

static bool open_handles;

static int rogue_connect(struct input_handler *handler, struct input_dev *dev,
			 const struct input_device_id *id)
{
	struct input_handle *h = kzalloc(sizeof(*h), GFP_KERNEL);
	int ret;

	if (!h)
		return -ENOMEM;
	h->dev = dev;
	h->handler = handler;
	h->name = "rogue";
	ret = input_register_handle(h);
	if (ret)
		goto err;
	if (open_handles) {
		ret = input_open_device(h);
		if (ret)
			goto err_unreg;
	}
	return 0;
err_unreg:
	input_unregister_handle(h);
err:
	kfree(h);
	return ret;
}

static void rogue_disconnect(struct input_handle *h)
{
	if (h->open)
		input_close_device(h);
	input_unregister_handle(h);
	kfree(h);
}

static const struct input_device_id rogue_ids[] = {
	{ .flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
	  .evbit = { BIT_MASK(EV_KEY) },
	  .keybit = { [BIT_WORD(KEY_A)] = BIT_MASK(KEY_A) | BIT_MASK(KEY_ENTER) } },
	{ }
};

static struct input_handler rogue = {
	.event      = my_event,
	.connect    = rogue_connect,
	.disconnect = rogue_disconnect,
	.name       = "rogue_logger",
	.id_table   = rogue_ids,
};

/* write through a temporary writable alias, as text_poke() does */
static int poke(void *dst, const void *src, size_t n)
{
	struct page *pg = pfn_to_page(slow_virt_to_phys(dst) >> PAGE_SHIFT);
	void *alias = vmap(&pg, 1, VM_MAP, PAGE_KERNEL);

	if (!alias)
		return -ENOMEM;
	memcpy(alias + offset_in_page(dst), src, n);
	vunmap(alias);
	return 0;
}

static u8 saved[5];
static bool detoured;

static int __init rogue_init(void)
{
	int ret;

	if (!strcmp(mode, "rogue")) {
		open_handles = true;
	} else if (!strcmp(mode, "foreign")) {
		foreign_fn = symbol_get(kg_sens_free);
		if (!foreign_fn)
			return -ENOENT;
		rogue.name = "leds";
		rogue.event = (void *)foreign_fn;
	} else if (!strcmp(mode, "detour")) {
		u8 jmp[5] = { 0xe9 };
		s32 rel;

		foreign_fn = symbol_get(kg_sens_free);
		if (!foreign_fn)
			return -ENOENT;
		rel = (s32)((unsigned long)foreign_fn - ((unsigned long)my_event + 5));
		rogue.name = "leds";
		memcpy(saved, my_event, sizeof(saved));
		memcpy(jmp + 1, &rel, sizeof(rel));
		if (poke(my_event, jmp, sizeof(jmp))) {
			symbol_put(kg_sens_free);
			return -ENOMEM;
		}
		detoured = true;
	} else {
		return -EINVAL;
	}

	ret = input_register_handler(&rogue);
	if (ret) {
		if (detoured)
			poke(my_event, saved, sizeof(saved));
		if (foreign_fn)
			symbol_put(kg_sens_free);
	}
	return ret;
}

static void __exit rogue_exit(void)
{
	input_unregister_handler(&rogue);
	if (detoured)
		poke(my_event, saved, sizeof(saved));
	if (foreign_fn)
		symbol_put(kg_sens_free);
}

module_init(rogue_init);
module_exit(rogue_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernelguard VM test fixture - counts key events like a keylogger would (test guest only)");
