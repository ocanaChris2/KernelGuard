// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_state.c - global state, alert reporting and cross-module event dispatch.
 * Counterpart of windows/src/shared_state.c.
 *
 * Differences from the Windows driver worth knowing about:
 *
 *  - The Windows StateHash covers counters that change on every flush and
 *    every notification, so VerifySharedStateIntegrity() fails the first time
 *    anything happens after DriverEntry.  Here the hash covers only the
 *    mitigation policy (per-CPU strategy table + fail-safe flag); statistics
 *    live in kg_stats and are deliberately not hashed.  The hash is refreshed
 *    under kg_guard_lock on every legitimate policy change.
 *
 *  - Driver "whitelists" are replaced by allow lists supplied as module
 *    parameters plus a trust-on-first-use baseline (see kg_input.c/kg_hw.c).
 */
#include "kg.h"

#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ratelimit.h>
#include <linux/stdarg.h>

struct kg_kstats kg_stats;
struct kg_guard kg_guard;
DEFINE_PER_CPU(bool, kg_self_busy);

static DEFINE_MUTEX(kg_guard_lock);
static struct crypto_shash *kg_sha_tfm;

#define KG_GUARD_MAGIC  0x4B474744u     /* 'KGGD' */

/*----------------------------------------------------------------------------
 * SHA-256 helper
 *--------------------------------------------------------------------------*/
int kg_sha256(const void *data, size_t len, u8 out[32])
{
	if (!kg_sha_tfm)
		return -ENODEV;
	return crypto_shash_tfm_digest(kg_sha_tfm, data, len, out);
}

/*----------------------------------------------------------------------------
 * Guard hash (Windows: UpdateSharedStateHash / VerifySharedStateIntegrity)
 *--------------------------------------------------------------------------*/
static int kg_guard_compute(u8 out[32])
{
	SHASH_DESC_ON_STACK(desc, kg_sha_tfm);
	int ret;

	if (!kg_guard.cpu)
		return -ENODEV;

	desc->tfm = kg_sha_tfm;
	ret = crypto_shash_init(desc);
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)&kg_guard.hdr,
					  sizeof(kg_guard.hdr));
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)kg_guard.cpu,
					  kg_guard.hdr.ncpu * sizeof(*kg_guard.cpu));
	if (!ret)
		ret = crypto_shash_final(desc, out);
	return ret;
}

/* Caller holds kg_guard_lock. */
static void kg_guard_update_locked(void)
{
	if (!kg_guard_compute(kg_guard.digest))
		kg_guard.valid = true;
}

void kg_guard_update(void)
{
	mutex_lock(&kg_guard_lock);
	kg_guard_update_locked();
	mutex_unlock(&kg_guard_lock);
}

bool kg_guard_verify(void)
{
	u8 now[32];
	bool ok;

	mutex_lock(&kg_guard_lock);
	if (!kg_guard.valid || kg_guard_compute(now)) {
		mutex_unlock(&kg_guard_lock);
		return false;
	}
	ok = kg_ct_eq(now, kg_guard.digest, sizeof(now));
	mutex_unlock(&kg_guard_lock);
	return ok;
}

/* Exposed to kg_mitigate.c so policy mutation and re-hash are one critical section. */
void kg_guard_lock_acquire(void) { mutex_lock(&kg_guard_lock); }
void kg_guard_unlock_release(void)
{
	kg_guard_update_locked();
	mutex_unlock(&kg_guard_lock);
}

/*----------------------------------------------------------------------------
 * Allow-list helper: does the comma/space separated @csv contain @name?
 *--------------------------------------------------------------------------*/
bool kg_list_contains(const char *csv, const char *name)
{
	size_t nlen = strlen(name);
	const char *p = csv;

	if (!nlen)
		return false;

	while (*p) {
		size_t n;

		while (*p == ',' || *p == ' ')
			p++;
		n = strcspn(p, ", ");
		if (n == nlen && !strncmp(p, name, n))
			return true;
		p += n;
	}
	return false;
}

/*----------------------------------------------------------------------------
 * Sensitive allocation registry (Windows: SensAllocatePool / SensFreePool,
 * which tag pages in g_SensPages[]).  Tagging is bookkeeping only - the
 * kernel's own PTI / memfd_secret machinery does the actual isolation - but
 * the buffers are zeroised on free (kfree_sensitive), which the Windows
 * ExFreePoolWithTag path does not do.
 *--------------------------------------------------------------------------*/
struct kg_sens_rec {
	struct list_head node;
	void *ptr;
	size_t size;
	u8 flags;
	pid_t tgid;
};

static LIST_HEAD(kg_sens_list);
static DEFINE_MUTEX(kg_sens_lock);

static unsigned long kg_sens_pages(size_t size)
{
	return DIV_ROUND_UP(size, PAGE_SIZE);
}

void *kg_sens_alloc(size_t size, u8 flags)
{
	struct kg_sens_rec *rec;
	void *ptr;

	rec = kzalloc(sizeof(*rec), GFP_KERNEL);
	ptr = kzalloc(size, GFP_KERNEL);
	if (!rec || !ptr) {
		kfree(rec);
		kfree(ptr);
		return NULL;
	}
	rec->ptr = ptr;
	rec->size = size;
	rec->flags = flags;
	rec->tgid = task_tgid_nr(current);

	mutex_lock(&kg_sens_lock);
	list_add_tail(&rec->node, &kg_sens_list);
	mutex_unlock(&kg_sens_lock);
	kg_stat_add(sens_page_count, kg_sens_pages(size));
	return ptr;
}
EXPORT_SYMBOL_GPL(kg_sens_alloc);

void kg_sens_free(void *ptr)
{
	struct kg_sens_rec *rec, *found = NULL;

	if (!ptr)
		return;

	mutex_lock(&kg_sens_lock);
	list_for_each_entry(rec, &kg_sens_list, node) {
		if (rec->ptr == ptr) {
			found = rec;
			list_del(&rec->node);
			break;
		}
	}
	mutex_unlock(&kg_sens_lock);

	if (found) {
		kg_stat_add(sens_page_count, -(s64)kg_sens_pages(found->size));
		kfree(found);
	}
	kfree_sensitive(ptr);
}
EXPORT_SYMBOL_GPL(kg_sens_free);

bool kg_sens_pfn_tagged(unsigned long pfn)
{
	struct kg_sens_rec *rec;
	bool hit = false;

	mutex_lock(&kg_sens_lock);
	list_for_each_entry(rec, &kg_sens_list, node) {
		unsigned long first = __pa(rec->ptr) >> PAGE_SHIFT;
		unsigned long last = (__pa(rec->ptr) + rec->size - 1) >> PAGE_SHIFT;

		if (pfn >= first && pfn <= last) {
			hit = true;
			break;
		}
	}
	mutex_unlock(&kg_sens_lock);
	return hit;
}
EXPORT_SYMBOL_GPL(kg_sens_pfn_tagged);

/*----------------------------------------------------------------------------
 * Fail-safe mode (Windows: EnterFailSafeMode) is the top rung of the posture
 * ladder in kg_posture.c.
 *--------------------------------------------------------------------------*/
bool kg_in_failsafe(void)
{
	return READ_ONCE(kg_guard.hdr.failsafe) != 0;
}

/*----------------------------------------------------------------------------
 * Cross-module event router (Windows: DispatchCrossModuleEvent, spec 7.2).
 *
 *   M1 cache-miss anomaly  -> M4 escalate + flush the CPU and its SMT siblings;
 *                             posture ELEVATED
 *   M2 DMA violation       -> M4 flush; posture ELEVATED
 *   M2 PCI discrepancy     -> M3 immediate keyboard-path scan; posture ELEVATED
 *   M2 keyboard-path / BME -> posture ELEVATED
 *   M3 IDT/CR/MSR tamper   -> posture HIGH (M4 full-spectrum on all CPUs, held)
 *   M3 denied driver ran   -> posture HIGH (the attack primitive exists); one that was
 *                             already loaded when we started -> ELEVATED
 *   M3 load refused        -> posture ELEVATED when it was a deny-list hit (someone with
 *                             root tried); a lock-mode refusal changes nothing
 *   M3 text/dispatch hook  -> posture FAILSAFE (M5 notification is sent by kg_report)
 *   M4 state corruption    -> posture FAILSAFE
 *
 * Every raise is bounded by the max_posture parameter (kg_posture.c).
 * Process context only.
 *--------------------------------------------------------------------------*/
static void kg_dispatch(u32 type, u32 level, u64 p1, u64 p2)
{
	switch (type) {
	case KG_ALERT_PMU_L1D_ANOMALY:
	case KG_ALERT_PMU_L2_ANOMALY:
		if (level >= KG_LEVEL_CRITICAL) {
			int cpu = (int)(p2 >> 32);

			if (cpu >= 0 && cpu < nr_cpu_ids && cpu_online(cpu)) {
				kg_mit_escalate_cpu(cpu);
				kg_mit_flush_cpu(cpu);
				kg_mit_flush_siblings(cpu);
			}
			kg_posture_raise(KG_POSTURE_ELEVATED, type);
		}
		break;

	case KG_ALERT_UNAUTHORIZED_DMA:
		kg_mit_flush_cpu(raw_smp_processor_id());
		kg_posture_raise(KG_POSTURE_ELEVATED, type);
		break;

	case KG_ALERT_PCI_DISCREPANCY:
		kg_input_kick();
		kg_posture_raise(KG_POSTURE_ELEVATED, type);
		break;

	case KG_ALERT_UNAUTHORIZED_KBD_FILTER:
	case KG_ALERT_KBD_FILTER_NEUTRALIZED:
	case KG_ALERT_DEVICE_BME_DISABLED:
		kg_posture_raise(KG_POSTURE_ELEVATED, type);
		break;

	case KG_ALERT_MODULE_LOADED:
		if (level >= KG_LEVEL_WATCH)            /* only a suspicious load, not every load */
			kg_posture_raise(KG_POSTURE_ELEVATED, type);
		break;

	case KG_ALERT_VULN_DRIVER:
		kg_posture_raise(level >= KG_LEVEL_CRITICAL ? KG_POSTURE_HIGH : KG_POSTURE_ELEVATED, type);
		break;

	case KG_ALERT_DRIVER_BLOCKED:
		if (level >= KG_LEVEL_CRITICAL)
			kg_posture_raise(KG_POSTURE_ELEVATED, type);
		break;

	case KG_ALERT_IDT_HOOK:
	case KG_ALERT_CTRL_REG_TAMPER:
		if (level >= KG_LEVEL_CRITICAL)
			kg_posture_raise(KG_POSTURE_HIGH, type);
		break;

	case KG_ALERT_TEXT_PATCH:
	case KG_ALERT_DISPATCH_HOOK:
		if (level >= KG_LEVEL_CRITICAL)
			kg_posture_raise(KG_POSTURE_FAILSAFE, type);
		break;

	case KG_ALERT_SHARED_STATE_CORRUPT:
		kg_posture_raise(KG_POSTURE_FAILSAFE, type);
		break;

	default:
		break;
	}
}

static DEFINE_RATELIMIT_STATE(kg_log_rs, 5 * HZ, 20);

/*----------------------------------------------------------------------------
 * kg_report (Windows: LogAlert + the notify half of DispatchCrossModuleEvent)
 *--------------------------------------------------------------------------*/
void kg_report(u32 type, u32 level, u64 p1, u64 p2, const char *fmt, ...)
{
	char msg[192];
	va_list ap;

	va_start(ap, fmt);
	vscnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	/*
	 * The kernel log is rate-limited for anything below critical, so a
	 * misconfigured threshold cannot flood dmesg.  Critical alerts always print,
	 * and every alert (limited or not) is still counted and sent to the ring.
	 */
	switch (level) {
	case KG_LEVEL_INFO:
		if (__ratelimit(&kg_log_rs))
			pr_info("[alert %#06x] %s\n", type, msg);
		break;
	case KG_LEVEL_WATCH:
		if (__ratelimit(&kg_log_rs))
			pr_warn("[alert %#06x] %s\n", type, msg);
		break;
	default:
		pr_crit("[alert %#06x] %s\n", type, msg);
		break;
	}

	/* Deliver first so a slow mitigation cannot delay the notification. */
	kg_comms_notify(type, level, p1, p2);
	kg_dispatch(type, level, p1, p2);
}

/*----------------------------------------------------------------------------
 * init / exit
 *--------------------------------------------------------------------------*/
int kg_state_init(void)
{
	memset(&kg_stats, 0, sizeof(kg_stats));
	memset(&kg_guard, 0, sizeof(kg_guard));

	kg_sha_tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(kg_sha_tfm)) {
		int err = PTR_ERR(kg_sha_tfm);

		kg_sha_tfm = NULL;
		pr_err("cannot allocate sha256: %d\n", err);
		return err;
	}
	return 0;
}

void kg_state_exit(void)
{
	if (kg_sha_tfm) {
		crypto_free_shash(kg_sha_tfm);
		kg_sha_tfm = NULL;
	}
}
