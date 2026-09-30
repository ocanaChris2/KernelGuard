// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_modgate.c - Module 3.5: driver-load gate, the answer to "bring your own vulnerable driver".
 * Counterpart of windows/src/driver_load_guard.c.
 *
 * The attack: someone who already has root loads a module that is legitimately signed but
 * vulnerable, to get a kernel read/write primitive that the rest of the kernel's defences
 * (lockdown, module signing) were meant to deny them.  The other modules of this driver only
 * see what the primitive is used for afterwards (a patched IDT, a cleared CR0.WP); this one
 * sees the load itself.
 *
 * How it works
 * ------------
 * A module notifier registered at the highest priority sees every module at
 * MODULE_STATE_COMING: fully laid out, signature checked, taints and srcversion known, and
 * init() not yet run.  A notifier that returns an error there aborts the load
 * (prepare_coming_module() hands the errno back to the caller of finit_module()), which is what
 * makes this a gate and not just a log entry.  Three things are decided per module:
 *
 *   deny list   mod_deny=NAME or NAME@SRCVERSION.  The name and the srcversion (the value
 *               `modinfo -F srcversion` prints; `kgmon modid FILE.ko` prints the whole entry)
 *               are inside the signed ELF, so with signature enforcement on a signed
 *               vulnerable module cannot be renamed around the list.  The Windows driver has
 *               to match a hash instead, because a Windows driver's file name is not signed.
 *   lock mode   mod_lock=1: every module that was not loaded when the lock was switched on,
 *               and is not in mod_allow, is unexpected.  Meant for kiosks and shared machines
 *               where nothing should load after boot; it breaks on-demand hardware drivers.
 *   audit       once, at load: whether the OS's own defences against this attack are on
 *               (module.sig_enforce, lockdown, Secure Boot).  Those are what really prevent it.
 *
 * Detect-only is the default, as everywhere in this driver.  With kg_enforcing() (enforce=1, or
 * auto_enforce=1 once the posture reached HIGH) a denied or locked-out module is refused with
 * -EPERM; without it the load is reported (VULN_DRIVER at CRITICAL for the deny list,
 * MODULE_LOADED at WATCH for a lock-mode dry run).  Because the gate asks kg_enforcing(), a
 * system running auto_enforce closes itself to further loads after the first incident.
 *
 * What it does NOT do
 * -------------------
 *  - It cannot refuse a module that was already loaded when this driver started; it reports a
 *    denied one (WATCH) and moves on.
 *  - It only sees the module loader.  Built-in code, kexec, /dev/mem and BPF are not modules.
 *  - The identity is only as good as the signature.  With signatures not enforced an attacker
 *    does not need a vulnerable module: the audit says so (LOAD_POLICY).
 *  - root can undo it: enforce=0, mod_lock=0 and rmmod are all root-only writes, exactly like
 *    the switches of the other modules.  The deny and allow lists are load-time only (0444).
 *
 * One kernel behaviour to know when reading the counters: a load that overlaps another load of the
 * same module name is answered with -EBUSY or -EEXIST by add_unformed_module() before any notifier
 * runs.  The attempt that does run is judged, so nothing gets through, but the counters count
 * judged loads, not system calls.  (BusyBox insmod, which retries a failed finit_module with
 * init_module, therefore counts twice per refusal; kmod's tools call the loader once.)
 *
 * Locking: the lists are written once in init and read-only afterwards.  The lock-mode baseline
 * is replaced wholesale (built aside, swapped under kg_gate_lock), so a concurrent load never
 * sees a half-built one.  kg_gate_cfg_lock serialises init/exit against a run-time write of
 * mod_lock.  The notifier runs in the context of the process that is loading the module, holds
 * no lock while it reports, and keeps no pointer to the module.
 */
#include "kg.h"

#include <linux/ctype.h>
#include <linux/efi.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/security.h>
#include <linux/slab.h>

#define KG_GATE_LIST_MAX        64      /* entries kept from each parameter */
#define KG_GATE_SRCVER_MAX      32      /* srcversion strings are 23-24 characters */
#define KG_GATE_BASE_MAX        1024    /* same bound as kg_for_each_live_module() */

typedef char kg_gate_name[MODULE_NAME_LEN];

struct kg_gate_deny {
	kg_gate_name name;
	char srcver[KG_GATE_SRCVER_MAX];        /* empty: every version of the module */
};

/*----------------------------------------------------------------------------
 * Parameters
 *--------------------------------------------------------------------------*/
static bool p_gate = true;
module_param_named(modgate, p_gate, bool, 0444);
MODULE_PARM_DESC(modgate,
	"Enable the driver-load gate and the load-policy audit (default 1)");

static char p_deny[1024];
module_param_string(mod_deny, p_deny, sizeof(p_deny), 0444);
MODULE_PARM_DESC(mod_deny,
	"Known-vulnerable modules, comma separated: NAME (any version) or NAME@SRCVERSION "
	"(as `modinfo -F srcversion` prints it). Reported; refused while enforcing. At most 64 entries.");

static char p_allow[1024];
module_param_string(mod_allow, p_allow, sizeof(p_allow), 0444);
MODULE_PARM_DESC(mod_allow,
	"Module names that mod_lock lets through besides the ones loaded when the lock was switched on "
	"(comma separated, at most 64)");

static bool p_lock;
static int kg_gate_cfg_set_lock(const char *val, const struct kernel_param *kp);
static const struct kernel_param_ops kg_lock_ops = {
	.set = kg_gate_cfg_set_lock,
	.get = param_get_bool,
};
module_param_cb(mod_lock, &kg_lock_ops, &p_lock, 0644);
MODULE_PARM_DESC(mod_lock,
	"Lock mode: treat every module that is neither loaded now nor in mod_allow as unexpected. "
	"Reported (dry run), or refused while enforcing. Default 0.");

/*----------------------------------------------------------------------------
 * State
 *--------------------------------------------------------------------------*/
static struct kg_gate_deny kg_deny[KG_GATE_LIST_MAX];
static unsigned int kg_ndeny;
static kg_gate_name kg_allow[KG_GATE_LIST_MAX];
static unsigned int kg_nallow;
static unsigned int kg_ignored;

static DEFINE_MUTEX(kg_gate_lock);              /* kg_base, kg_nbase */
static kg_gate_name *kg_base;                   /* modules present when the lock was switched on */
static unsigned int kg_nbase;

static DEFINE_MUTEX(kg_gate_cfg_lock);          /* kg_gate_ready and (re)building the baseline */
static bool kg_gate_ready;

static bool kg_gate_registered;
static bool kg_audited;
static u32 kg_lp_mask, kg_lp_raw;
static atomic64_t kg_deny_hits, kg_blocked, kg_lock_hits;

/*----------------------------------------------------------------------------
 * Parsing (root-supplied, but never trusted to be well formed)
 *--------------------------------------------------------------------------*/
static bool kg_gate_sep(char c)
{
	return c == ',' || c == ' ' || c == '\t' || c == '\n';
}

/* Next entry of @*pp: its length (0 at the end); *start is where it begins, *pp moves past it. */
static size_t kg_gate_next(const char **pp, const char **start)
{
	const char *p = *pp;
	size_t n = 0;

	while (kg_gate_sep(*p))
		p++;
	while (p[n] && !kg_gate_sep(p[n]))
		n++;
	*start = p;
	*pp = p + n;
	return n;
}

static bool kg_gate_name_ok(const char *s, size_t n)
{
	size_t i;

	if (!n || n >= MODULE_NAME_LEN)
		return false;
	for (i = 0; i < n; i++)
		if (!isalnum(s[i]) && s[i] != '_' && s[i] != '-' && s[i] != '.')
			return false;
	return true;
}

static bool kg_gate_hex_ok(const char *s, size_t n)
{
	size_t i;

	if (!n || n >= KG_GATE_SRCVER_MAX)
		return false;
	for (i = 0; i < n; i++)
		if (!isxdigit(s[i]))
			return false;
	return true;
}

static void kg_gate_parse(const char *csv, bool is_deny)
{
	const char *label = is_deny ? "mod_deny" : "mod_allow";
	unsigned int *count = is_deny ? &kg_ndeny : &kg_nallow;
	const char *p = csv, *s;
	bool warned_full = false;
	size_t len;

	while ((len = kg_gate_next(&p, &s)) != 0) {
		const char *at = memchr(s, '@', len);
		size_t nlen = at ? (size_t)(at - s) : len;
		size_t vlen = at ? len - nlen - 1 : 0;
		char *name;
		size_t i;

		/* mod_allow is names only; a NAME@SRCVERSION entry there is a mistake, not a name. */
		if (!kg_gate_name_ok(s, nlen) ||
		    (at && (!is_deny || !kg_gate_hex_ok(at + 1, vlen)))) {
			pr_warn("%s: ignoring malformed entry \"%.*s\"\n", label, (int)min(len, (size_t)40), s);
			kg_ignored++;
			continue;
		}
		if (*count >= KG_GATE_LIST_MAX) {
			if (!warned_full)
				pr_warn("%s: only the first %d entries are used\n", label, KG_GATE_LIST_MAX);
			warned_full = true;
			kg_ignored++;
			continue;
		}

		name = is_deny ? kg_deny[*count].name : kg_allow[*count];
		for (i = 0; i < nlen; i++)              /* module names use '_', whatever the file is called */
			name[i] = s[i] == '-' ? '_' : s[i];
		name[nlen] = '\0';
		if (is_deny) {
			for (i = 0; i < vlen; i++)
				kg_deny[*count].srcver[i] = toupper(at[1 + i]);
			kg_deny[*count].srcver[vlen] = '\0';
		}
		(*count)++;
	}
}

/*----------------------------------------------------------------------------
 * Verdicts
 *--------------------------------------------------------------------------*/
static bool kg_gate_denied(const struct module *mod)
{
	unsigned int i;

	for (i = 0; i < kg_ndeny; i++) {
		if (strcmp(kg_deny[i].name, mod->name))
			continue;
		if (!kg_deny[i].srcver[0])
			return true;
		if (mod->srcversion && !strcasecmp(kg_deny[i].srcver, mod->srcversion))
			return true;
	}
	return false;
}

static bool kg_gate_trusted(const char *name)
{
	bool hit = false;
	unsigned int i;

	for (i = 0; i < kg_nallow; i++)
		if (!strcmp(kg_allow[i], name))
			return true;

	mutex_lock(&kg_gate_lock);
	for (i = 0; i < kg_nbase; i++) {
		if (!strcmp(kg_base[i], name)) {
			hit = true;
			break;
		}
	}
	mutex_unlock(&kg_gate_lock);
	return hit;
}

/*----------------------------------------------------------------------------
 * Lock-mode baseline: the modules that are loaded when the lock is switched on
 *--------------------------------------------------------------------------*/
struct kg_gate_snap {
	kg_gate_name *tab;
	unsigned int n;
};

static void kg_gate_snap_cb(struct module *mod, void *arg)
{
	struct kg_gate_snap *s = arg;

	if (s->n < KG_GATE_BASE_MAX)
		strscpy(s->tab[s->n++], mod->name, MODULE_NAME_LEN);
}

/* Built aside and swapped in, so a load that races with it never meets a half-built table. */
static int kg_gate_snapshot(void)
{
	struct kg_gate_snap s = { .n = 0 };
	kg_gate_name *old;
	int ret;

	s.tab = kvcalloc(KG_GATE_BASE_MAX, sizeof(kg_gate_name), GFP_KERNEL);
	if (!s.tab)
		return -ENOMEM;
	ret = kg_for_each_live_module(kg_gate_snap_cb, &s);
	if (ret) {
		kvfree(s.tab);
		return ret;
	}

	mutex_lock(&kg_gate_lock);
	old = kg_base;
	kg_base = s.tab;
	kg_nbase = s.n;
	mutex_unlock(&kg_gate_lock);
	kvfree(old);
	return 0;
}

/*
 * mod_lock is writable at run time.  Switching it on records the modules that are loaded right
 * then; if that cannot be done the switch is refused, because a lock with an empty baseline
 * would refuse everything.  While the module is still initialising (or exiting) only the flag
 * is stored: init takes the baseline itself.
 */
static int kg_gate_cfg_set_lock(const char *val, const struct kernel_param *kp)
{
	bool was = READ_ONCE(p_lock);
	int ret = param_set_bool(val, kp);

	if (ret)
		return ret;

	mutex_lock(&kg_gate_cfg_lock);
	if (kg_gate_ready && READ_ONCE(p_lock) && !was) {
		ret = kg_gate_snapshot();
		if (ret) {
			WRITE_ONCE(p_lock, was);
			pr_warn("mod_lock not switched on: cannot record the baseline (%d)\n", ret);
		} else {
			pr_notice("lock mode on: %u module(s) loaded now are the baseline\n", kg_nbase);
		}
	} else if (kg_gate_ready && was != READ_ONCE(p_lock)) {
		pr_notice("lock mode %s\n", READ_ONCE(p_lock) ? "on" : "off");
	}
	mutex_unlock(&kg_gate_cfg_lock);
	return ret;
}

/*----------------------------------------------------------------------------
 * The gate
 *--------------------------------------------------------------------------*/
static int kg_gate_notify(struct notifier_block *nb, unsigned long action, void *data)
{
	struct module *mod = data;
	bool denied, locked = false;
	u64 np[2];

	if (action != MODULE_STATE_COMING || mod == THIS_MODULE)
		return NOTIFY_DONE;

	denied = kg_gate_denied(mod);
	if (!denied && READ_ONCE(p_lock))
		locked = !kg_gate_trusted(mod->name);
	if (!denied && !locked)
		return NOTIFY_DONE;

	atomic64_inc(denied ? &kg_deny_hits : &kg_lock_hits);
	kg_pack_name(mod->name, np);

	if (kg_enforcing()) {
		atomic64_inc(&kg_blocked);
		kg_report(KG_ALERT_DRIVER_BLOCKED, denied ? KG_LEVEL_CRITICAL : KG_LEVEL_WATCH, np[0], np[1],
			  "refused to load %s (%s)", mod->name,
			  denied ? "on the deny list" : "not in the lock-mode allow list");
		return notifier_from_errno(-EPERM);
	}

	if (denied)
		kg_report(KG_ALERT_VULN_DRIVER, KG_LEVEL_CRITICAL, np[0], np[1],
			  "denied module %s is being loaded (detect-only: enforce=1 would refuse it)", mod->name);
	else
		kg_report(KG_ALERT_MODULE_LOADED, KG_LEVEL_WATCH, np[0], np[1],
			  "module %s is not in the lock-mode allow list (dry run: enforce=1 would refuse it)",
			  mod->name);
	return NOTIFY_DONE;
}

/* Highest priority: a refused module then never reaches the tracing, BPF or integrity notifiers. */
static struct notifier_block kg_gate_nb = {
	.notifier_call = kg_gate_notify,
	.priority = INT_MAX,
};

/* A denied module that was loaded before we started cannot be refused; it can be reported. */
static void kg_gate_walk_cb(struct module *mod, void *unused)
{
	u64 np[2];

	if (!kg_gate_denied(mod))
		return;
	atomic64_inc(&kg_deny_hits);
	kg_pack_name(mod->name, np);
	kg_report(KG_ALERT_VULN_DRIVER, KG_LEVEL_WATCH, np[0], np[1],
		  "denied module %s was already loaded when KernelGuard started (too late to refuse it)",
		  mod->name);
}

/*----------------------------------------------------------------------------
 * Load-policy audit: are the OS's own defences against this attack on?
 * Signature enforcement and lockdown can only be strengthened at run time, never weakened, so
 * one look at load time is enough.
 *--------------------------------------------------------------------------*/
static void kg_gate_audit(void)
{
	u32 weak = 0, raw = 0;
	bool sb = false;

	if (IS_ENABLED(CONFIG_MODULE_SIG))
		raw |= KG_LP_RAW_SIG_BUILT;
	if (is_module_sig_enforced())
		raw |= KG_LP_RAW_SIG_ENFORCE;
	else
		weak |= KG_LP_NO_SIG_ENFORCE;

	/* The lockdown LSM may log a "Lockdown: ..." notice for this probe; that is expected. */
	if (security_locked_down(LOCKDOWN_MODULE_SIGNATURE))
		raw |= KG_LP_RAW_LOCKDOWN;
	else
		weak |= KG_LP_NO_LOCKDOWN;

#ifdef CONFIG_EFI
	sb = efi_enabled(EFI_SECURE_BOOT);
#endif
	if (sb)
		raw |= KG_LP_RAW_SECUREBOOT;
	else
		weak |= KG_LP_NO_SECUREBOOT;

	kg_lp_mask = weak;
	kg_lp_raw = raw;
	kg_audited = true;

	kg_report(KG_ALERT_LOAD_POLICY, weak ? KG_LEVEL_WATCH : KG_LEVEL_INFO, weak, raw,
		  "load policy: sig_enforce=%s lockdown=%s secure_boot=%s%s",
		  raw & KG_LP_RAW_SIG_ENFORCE ? "yes" : "no",
		  raw & KG_LP_RAW_LOCKDOWN ? "yes" : "no",
		  raw & KG_LP_RAW_SECUREBOOT ? "yes" : "no",
		  weak ? " - a signed vulnerable module, or an unsigned one, can be loaded" : "");
}

/*----------------------------------------------------------------------------
 * Information for KG_IOC_GET_MODGATE
 *--------------------------------------------------------------------------*/
void kg_modgate_info(struct kg_modgate_info *mi)
{
	memset(mi, 0, sizeof(*mi));

	if (READ_ONCE(kg_gate_registered)) {
		mi->flags |= KG_MODGATE_F_ACTIVE;
		if (kg_enforcing())
			mi->flags |= KG_MODGATE_F_ENFORCING;
	}
	if (READ_ONCE(p_lock))
		mi->flags |= KG_MODGATE_F_LOCK;
	if (READ_ONCE(kg_audited))
		mi->flags |= KG_MODGATE_F_AUDITED;

	mi->n_deny = kg_ndeny;
	mi->n_allow = kg_nallow;
	mutex_lock(&kg_gate_lock);
	mi->n_baseline = kg_nbase;
	mutex_unlock(&kg_gate_lock);
	mi->deny_hits = atomic64_read(&kg_deny_hits);
	mi->blocked = atomic64_read(&kg_blocked);
	mi->lock_hits = atomic64_read(&kg_lock_hits);
	mi->lp_mask = kg_lp_mask;
	mi->lp_raw = kg_lp_raw;
	mi->ignored = kg_ignored;
}

/*----------------------------------------------------------------------------
 * init / exit
 *--------------------------------------------------------------------------*/
int kg_modgate_init(void)
{
	int ret;

	if (!p_gate) {
		pr_info("driver-load gate disabled (modgate=0)\n");
		return 0;
	}

	kg_gate_parse(p_deny, true);
	kg_gate_parse(p_allow, false);

	mutex_lock(&kg_gate_cfg_lock);
	if (READ_ONCE(p_lock)) {
		ret = kg_gate_snapshot();
		if (ret) {
			pr_warn("cannot record the lock-mode baseline (%d): lock mode is off\n", ret);
			WRITE_ONCE(p_lock, false);
		}
	}
	kg_gate_ready = true;
	mutex_unlock(&kg_gate_cfg_lock);

	ret = register_module_notifier(&kg_gate_nb);
	if (ret) {
		pr_err("cannot register the module notifier: %d\n", ret);
		kg_modgate_exit();
		return ret;
	}
	WRITE_ONCE(kg_gate_registered, true);

	if (kg_ndeny)
		kg_for_each_live_module(kg_gate_walk_cb, NULL);
	kg_gate_audit();

	pr_info("driver-load gate: %u denied, %u allowed, lock %s (%u module(s) baselined), %s\n",
		kg_ndeny, kg_nallow, READ_ONCE(p_lock) ? "on" : "off", kg_nbase,
		kg_enforcing() ? "enforcing" : "detect-only");
	return 0;
}

void kg_modgate_exit(void)
{
	if (READ_ONCE(kg_gate_registered)) {
		/* Waits for a notifier that is running right now. */
		unregister_module_notifier(&kg_gate_nb);
		WRITE_ONCE(kg_gate_registered, false);
	}

	mutex_lock(&kg_gate_cfg_lock);
	kg_gate_ready = false;
	mutex_lock(&kg_gate_lock);
	kvfree(kg_base);
	kg_base = NULL;
	kg_nbase = 0;
	mutex_unlock(&kg_gate_lock);
	mutex_unlock(&kg_gate_cfg_lock);
}
