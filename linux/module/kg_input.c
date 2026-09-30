// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_input.c - Module 2 (keyboard-path half) and the input-path part of
 * Module 3.  Counterpart of PciDetectDiscrepancies / NeutralizeKbdFilterDriver
 * in windows/src/hw_keylogger_detect.c and ScanKeyboardDrivers in kernel_integrity.c.
 *
 * The Windows keyboard stack is  hardware -> kbdhid/i8042prt -> [filter drivers]
 * -> kbdclass.  Anything between the port driver and the class driver sees every
 * keystroke; unknown filters are the keylogger.  The Linux analogue is the set
 * of input HANDLERS attached to a keyboard's input_dev: kbd (the console),
 * evdev (X11/Wayland/libinput), sysrq, leds ... - and a kernel keylogger is,
 * almost always, one more input_handler with an event callback.  The list is
 * dev->h_list, one input_handle per attached handler.
 *
 * To reach every keyboard we register our own handler whose connect() runs for
 * each existing and future matching device.  Its handle is registered but never
 * OPENED, so this module never receives a keystroke and does not keep the
 * hardware powered.
 *
 *  Identity     a handler that is not stock (kbd, evdev, sysrq, ...), not present
 *               when the module loaded (trust on first use) and not in kbd_allow=
 *               is UNAUTHORIZED_KBD_FILTER: critical if its handle is open (it is
 *               receiving keys), a warning otherwise.
 *  Integrity    (Windows: dispatch-hook detection) every callback of every
 *               handler must resolve to a kernel/module symbol, must belong to
 *               the same module as its handler, and its entry must not begin with
 *               a JMP/PUSH-RET/MOV-JMP detour into a *different* module.
 *  Neutralise   (enforce=1 only) unlink the offender's handle from dev->h_list -
 *               the analogue of IoDetachDevice.  The handle is left self-linked
 *               so the owner's own input_unregister_handle() later is harmless;
 *               it is NOT re-attached on unload (the owner may be gone).  The
 *               Windows "patch the foreign driver's MajorFunction[]" tier has no
 *               safe equivalent: a handler's function pointers cannot be replaced
 *               without racing the event path.
 *
 * Limits: a hook that does not go through an input_handler (kprobes/ftrace on
 * input_event or atkbd_interrupt, a keyboard-notifier on the VT layer, a
 * scancode-level hook in a port driver) is invisible here.  See README.
 */
#include "kg.h"

#include <linux/input.h>
#include <linux/kallsyms.h>
#include <linux/moduleparam.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define KG_BUILTIN_HANDLERS "kbd,evdev,sysrq,leds,rfkill,mousedev,joydev,kernelguard"
#define KG_MAX_HANDLES      24
#define KG_MAX_BASE         48
#define KG_MAX_REPORTED     96

enum kg_hook_kind {
	KG_HK_NONE = 0,
	KG_HK_UNKNOWN_MEM = 1,          /* callback resolves to no symbol             */
	KG_HK_FOREIGN_MODULE = 2,       /* callback lives in another module than its handler */
	KG_HK_DETOUR_FOREIGN = 3,       /* entry jumps into a different module         */
	KG_HK_DETOUR_UNKNOWN = 4,       /* entry jumps to unresolvable code (watch)    */
	KG_HK_INT3 = 5,                 /* int3 at entry (kprobe) (watch)              */
};

struct kg_kbd {
	struct list_head node;
	struct input_handle handle;
};

static LIST_HEAD(kg_kbds);
static DEFINE_MUTEX(kg_kbd_lock);
static unsigned int kg_nkbd;

static char kg_base_names[KG_MAX_BASE][32];
static unsigned int kg_nbase;

static struct { void *handle; unsigned long cb; u8 kind; } kg_reported[KG_MAX_REPORTED];
static unsigned int kg_nreported;

static struct delayed_work kg_input_work;
static bool kg_input_stop;
static bool kg_input_running;
static bool kg_input_baselining;

bool kg_input_active(void)
{
	return kg_input_running;
}

unsigned int kg_input_device_count(void)
{
	return READ_ONCE(kg_nkbd);
}

void kg_input_kick(void)
{
	if (kg_input_running && !READ_ONCE(kg_input_stop))
		mod_delayed_work(kg_wq, &kg_input_work, 0);
}

/*----------------------------------------------------------------------------
 * Tracking keyboards through our own (never-opened) handle
 *--------------------------------------------------------------------------*/
static int kg_input_connect(struct input_handler *handler, struct input_dev *dev,
			    const struct input_device_id *id)
{
	struct kg_kbd *k = kzalloc(sizeof(*k), GFP_KERNEL);
	int ret;

	if (!k)
		return -ENOMEM;
	k->handle.dev = input_get_device(dev);
	k->handle.handler = handler;
	k->handle.name = "kernelguard";

	ret = input_register_handle(&k->handle);
	if (ret) {
		input_put_device(dev);
		kfree(k);
		return ret;
	}
	mutex_lock(&kg_kbd_lock);
	list_add_tail(&k->node, &kg_kbds);
	kg_nkbd++;
	mutex_unlock(&kg_kbd_lock);

	/* Other handlers attach around now; look once they have. */
	if (kg_input_running)
		kg_input_kick();
	return 0;
}

static void kg_input_disconnect(struct input_handle *handle)
{
	struct kg_kbd *k = container_of(handle, struct kg_kbd, handle);

	mutex_lock(&kg_kbd_lock);
	list_del(&k->node);
	kg_nkbd--;
	mutex_unlock(&kg_kbd_lock);

	input_unregister_handle(handle);
	input_put_device(handle->dev);
	kfree(k);
}

/* Devices that can type: EV_KEY with A and Enter.  (Power buttons, lids etc. do not match.) */
static const struct input_device_id kg_kbd_ids[] = {
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
		.evbit = { BIT_MASK(EV_KEY) },
		.keybit = { [BIT_WORD(KEY_A)] = BIT_MASK(KEY_A) | BIT_MASK(KEY_ENTER) },
	},
	{ }
};

static struct input_handler kg_input_handler = {
	.name       = "kernelguard",
	.connect    = kg_input_connect,
	.disconnect = kg_input_disconnect,
	.id_table   = kg_kbd_ids,
};

/*----------------------------------------------------------------------------
 * Bookkeeping helpers
 *--------------------------------------------------------------------------*/
static bool kg_handler_authorised(const char *name)
{
	unsigned int i;

	if (kg_list_contains(KG_BUILTIN_HANDLERS, name) || kg_list_contains(kg_kbd_allow, name))
		return true;
	for (i = 0; i < kg_nbase; i++)
		if (!strcmp(kg_base_names[i], name))
			return true;
	return false;
}

static void kg_base_add(const char *name)
{
	unsigned int i;

	for (i = 0; i < kg_nbase; i++)
		if (!strcmp(kg_base_names[i], name))
			return;
	if (kg_nbase < KG_MAX_BASE)
		strscpy(kg_base_names[kg_nbase++], name, sizeof(kg_base_names[0]));
}

static bool kg_was_reported(void *handle, unsigned long cb, u8 kind)
{
	unsigned int i;

	for (i = 0; i < kg_nreported; i++)
		if (kg_reported[i].handle == handle && kg_reported[i].cb == cb && kg_reported[i].kind == kind)
			return true;
	return false;
}

static void kg_mark_reported(void *handle, unsigned long cb, u8 kind)
{
	if (kg_nreported < KG_MAX_REPORTED) {
		kg_reported[kg_nreported].handle = handle;
		kg_reported[kg_nreported].cb = cb;
		kg_reported[kg_nreported].kind = kind;
		kg_nreported++;
	}
}

/*----------------------------------------------------------------------------
 * Callback integrity (Windows: CheckDispatchHook)
 *--------------------------------------------------------------------------*/
static bool kg_read_kernel(void *dst, unsigned long src, size_t n)
{
	return !copy_from_kernel_nofault(dst, (const void *)src, n);
}

/* Where does an entry-point detour go?  Returns the hook kind (or KG_HK_NONE). */
static enum kg_hook_kind kg_check_entry(unsigned long fn, const char *fn_mod)
{
	u8 b[24];
	int off, pass;

	if (!kg_read_kernel(b, fn, sizeof(b)))
		return KG_HK_NONE;

	/* pass 0: instruction at the entry; pass 1: after an endbr64 (F3 0F 1E FA) */
	for (off = 0, pass = 0; pass < 2; pass++) {
		const u8 *p = b + off;
		unsigned long tgt = 0;
		char mod[MODULE_NAME_LEN];
		bool found;
		s32 rel;

		if (p[0] == 0xcc)
			return KG_HK_INT3;
		if (p[0] == 0xe9) {                                     /* JMP rel32 */
			memcpy(&rel, p + 1, sizeof(rel));
			tgt = fn + off + 5 + (long)rel;
		} else if (p[0] == 0xff && p[1] == 0x25) {              /* JMP [RIP+disp32] */
			unsigned long slot;

			memcpy(&rel, p + 2, sizeof(rel));
			slot = fn + off + 6 + (long)rel;
			if (!kg_read_kernel(&tgt, slot, sizeof(tgt)))
				tgt = 0;
		} else if (p[0] == 0x48 && p[1] == 0xb8 && p[10] == 0xff && p[11] == 0xe0) {
			memcpy(&tgt, p + 2, sizeof(tgt));                   /* MOV RAX,imm64; JMP RAX */
		} else if (p[0] == 0x68 && p[5] == 0xc3) {              /* PUSH imm32; RET */
			memcpy(&rel, p + 1, sizeof(rel));
			tgt = (unsigned long)(long)rel;
		}

		if (tgt) {
			kg_sym_module(tgt, mod, sizeof(mod), &found);
			if (!found)
				return KG_HK_DETOUR_UNKNOWN;
			/* built-in targets are fine (thin wrappers); another *module* is not */
			if (mod[0] && strcmp(mod, fn_mod))
				return KG_HK_DETOUR_FOREIGN;
			return KG_HK_NONE;
		}

		if (pass == 0 && b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && b[3] == 0xfa)
			off = 4;
		else
			break;
	}
	return KG_HK_NONE;
}

struct kg_hinfo {
	void *handle;
	bool open;
	char name[32];
	unsigned long handler_addr;
	unsigned long cb[7];
};

static const char *const kg_cb_names[7] = {
	"event", "events", "filter", "match", "connect", "disconnect", "start"
};

static void kg_check_callbacks(const struct kg_hinfo *hi)
{
	char hmod[MODULE_NAME_LEN];
	bool hfound;
	int i;

	kg_sym_module(hi->handler_addr, hmod, sizeof(hmod), &hfound);

	for (i = 0; i < 7; i++) {
		char cmod[MODULE_NAME_LEN];
		enum kg_hook_kind kind = KG_HK_NONE;
		bool cfound;
		u32 level = KG_LEVEL_CRITICAL;
		const char *why = "";

		if (!hi->cb[i])
			continue;
		kg_sym_module(hi->cb[i], cmod, sizeof(cmod), &cfound);

		if (!cfound) {
			kind = KG_HK_UNKNOWN_MEM;
			why = "callback is not in any kernel or module symbol";
		} else if (hfound && strcmp(hmod, cmod)) {
			kind = KG_HK_FOREIGN_MODULE;
			why = "callback belongs to a different module than its handler";
		} else {
			kind = kg_check_entry(hi->cb[i], cfound ? cmod : "");
			if (kind == KG_HK_DETOUR_FOREIGN)
				why = "entry point jumps into a different module";
			else if (kind == KG_HK_DETOUR_UNKNOWN) {
				why = "entry point jumps to unresolved code (kprobe detour or hook)";
				level = KG_LEVEL_WATCH;
			} else if (kind == KG_HK_INT3) {
				why = "int3 at entry (kprobe)";
				level = KG_LEVEL_WATCH;
			}
		}
		if (kind == KG_HK_NONE || kg_was_reported(hi->handle, hi->cb[i], kind))
			continue;
		kg_mark_reported(hi->handle, hi->cb[i], kind);

		kg_stat_inc(dispatch_hook_detected);
		kg_report(KG_ALERT_DISPATCH_HOOK, level, hi->cb[i], (u64)kind << 32,
			  "input handler \"%s\" %s(): %s [%pS]", hi->name, kg_cb_names[i], why,
			  (void *)hi->cb[i]);
	}
}

/*----------------------------------------------------------------------------
 * Neutralisation (Windows: NeutralizeKbdFilterDriver - Tier 2, IoDetachDevice)
 *--------------------------------------------------------------------------*/
static bool kg_detach_handle(struct input_dev *dev, void *handle_ptr)
{
	struct input_handle *h, *victim = NULL;

	if (mutex_lock_interruptible(&dev->mutex))
		return false;
	/* Only touch it if it is still on the list: the pointer was gathered earlier. */
	list_for_each_entry(h, &dev->h_list, d_node) {
		if ((void *)h == handle_ptr) {
			victim = h;
			break;
		}
	}
	if (victim) {
		/* An exclusive grab bypasses h_list entirely, so release it too. */
		if (rcu_access_pointer(dev->grab) == victim)
			rcu_assign_pointer(dev->grab, NULL);
		list_del_rcu(&victim->d_node);
	}
	mutex_unlock(&dev->mutex);

	if (victim) {
		synchronize_rcu();
		/* Nobody can hold it now.  Self-link so the owner's later
		 * input_unregister_handle() -> list_del_rcu() is a harmless no-op. */
		INIT_LIST_HEAD(&victim->d_node);
	}
	return victim != NULL;
}

/*----------------------------------------------------------------------------
 * One keyboard
 *--------------------------------------------------------------------------*/
static void kg_scan_kbd(struct kg_kbd *k)
{
	struct input_dev *dev = k->handle.dev;
	struct kg_hinfo *hi;
	struct input_handle *h;
	int n = 0, i;

	hi = kcalloc(KG_MAX_HANDLES, sizeof(*hi), GFP_KERNEL);
	if (!hi)
		return;

	/* Gather under RCU (the handler structs cannot vanish while we are in the section). */
	rcu_read_lock();
	list_for_each_entry_rcu(h, &dev->h_list, d_node) {
		struct input_handler *hd = READ_ONCE(h->handler);

		if (h == &k->handle || !hd || n >= KG_MAX_HANDLES)
			continue;
		hi[n].handle = h;
		hi[n].open = READ_ONCE(h->open) > 0;
		strscpy(hi[n].name, hd->name ? hd->name : "?", sizeof(hi[n].name));
		hi[n].handler_addr = (unsigned long)hd;
		hi[n].cb[0] = (unsigned long)hd->event;
		hi[n].cb[1] = (unsigned long)hd->events;
		hi[n].cb[2] = (unsigned long)hd->filter;
		hi[n].cb[3] = (unsigned long)hd->match;
		hi[n].cb[4] = (unsigned long)hd->connect;
		hi[n].cb[5] = (unsigned long)hd->disconnect;
		hi[n].cb[6] = (unsigned long)hd->start;
		n++;
	}
	rcu_read_unlock();

	for (i = 0; i < n; i++) {
		if (kg_input_baselining) {
			kg_base_add(hi[i].name);
		} else if (!kg_handler_authorised(hi[i].name) &&
			   !kg_was_reported(hi[i].handle, 0, 0)) {
			u64 np[2];

			kg_mark_reported(hi[i].handle, 0, 0);
			kg_pack_name(hi[i].name, np);
			kg_stat_inc(hw_discrepancy_count);
			kg_report(KG_ALERT_UNAUTHORIZED_KBD_FILTER,
				  hi[i].open ? KG_LEVEL_CRITICAL : KG_LEVEL_WATCH, np[0], np[1],
				  "unauthorised input handler \"%s\" on keyboard \"%s\" (%s)",
				  hi[i].name, dev->name ? dev->name : "?",
				  hi[i].open ? "receiving keystrokes" : "attached, not open");
		}
		kg_check_callbacks(&hi[i]);
	}

	/* Enforcement is re-evaluated every scan, so a handler that re-attaches is dealt with again. */
	if (kg_enforcing() && !kg_input_baselining) {
		for (i = 0; i < n; i++) {
			u64 np[2];

			if (kg_handler_authorised(hi[i].name))
				continue;
			if (kg_detach_handle(dev, hi[i].handle)) {
				kg_pack_name(hi[i].name, np);
				kg_report(KG_ALERT_KBD_FILTER_NEUTRALIZED, KG_LEVEL_CRITICAL, np[0], np[1],
					  "input handler \"%s\" detached from keyboard \"%s\"",
					  hi[i].name, dev->name ? dev->name : "?");
			}
		}
	}
	kfree(hi);
}

/* Forget "already reported" entries whose handle has gone, so a reused pointer is judged afresh. */
static void kg_prune_reported(void)
{
	unsigned int i, j = 0;
	struct kg_kbd *k;

	for (i = 0; i < kg_nreported; i++) {
		bool alive = false;

		list_for_each_entry(k, &kg_kbds, node) {
			struct input_handle *h;

			rcu_read_lock();
			list_for_each_entry_rcu(h, &k->handle.dev->h_list, d_node)
				if ((void *)h == kg_reported[i].handle)
					alive = true;
			rcu_read_unlock();
			if (alive)
				break;
		}
		if (alive)
			kg_reported[j++] = kg_reported[i];
	}
	kg_nreported = j;
}

static void kg_input_scan_all(void)
{
	struct kg_kbd *k;

	mutex_lock(&kg_kbd_lock);
	list_for_each_entry(k, &kg_kbds, node)
		kg_scan_kbd(k);
	kg_prune_reported();
	mutex_unlock(&kg_kbd_lock);
}

static void kg_input_workfn(struct work_struct *w)
{
	kg_input_scan_all();
	if (!READ_ONCE(kg_input_stop))
		queue_delayed_work(kg_wq, &kg_input_work,
				   msecs_to_jiffies(kg_scan_ms(kg_hw_interval_ms)));
}

/*----------------------------------------------------------------------------
 * init / exit
 *--------------------------------------------------------------------------*/
int kg_input_init(void)
{
	int ret;

	kg_input_stop = false;
	INIT_DELAYED_WORK(&kg_input_work, kg_input_workfn);

	/* connect() runs for every keyboard that already exists. */
	ret = input_register_handler(&kg_input_handler);
	if (ret)
		return ret;

	/* Trust on first use: whatever is attached now is the baseline. */
	kg_input_baselining = true;
	kg_input_scan_all();
	kg_input_baselining = false;
	pr_info("keyboard path: %u keyboard(s), %u handler name(s) in baseline\n", kg_nkbd, kg_nbase);

	kg_input_running = true;
	queue_delayed_work(kg_wq, &kg_input_work, msecs_to_jiffies(kg_scan_ms(kg_hw_interval_ms)));
	return 0;
}

void kg_input_exit(void)
{
	if (!kg_input_running)
		return;

	WRITE_ONCE(kg_input_stop, true);
	cancel_delayed_work_sync(&kg_input_work);
	kg_input_running = false;
	/* Runs kg_input_disconnect() for every tracked keyboard. */
	input_unregister_handler(&kg_input_handler);
}
