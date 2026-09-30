// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_posture.c - graduated response: the module's overall posture.
 *
 * The Windows driver reacts to each alert the same way every time and has one
 * "fail-safe mode" that lasts until the driver is unloaded.  Here the reaction
 * is a ladder, so a single suspicious event does not cost as much as a proven
 * kernel patch, and so an operator can step back down after an investigation
 * without unloading the module:
 *
 *   NORMAL     baseline strategies; scans at their configured interval
 *   ELEVATED   scans run KG_POSTURE_SCAN_DIV times as often
 *   HIGH       every CPU held at full-spectrum mitigation, a floor the PMU
 *              sampler's relax step cannot undo; with auto_enforce=1 also the
 *              active enforcement that enforce=1 gives (bus-master clearing,
 *              input-handler detach)
 *   FAILSAFE   HIGH plus the fail-safe state of the Windows driver
 *
 * Raising is automatic (kg_dispatch in kg_state.c) and bounded by max_posture.
 * Lowering is never automatic above ELEVATED: ELEVATED decays to NORMAL after
 * posture_decay_s seconds without a further trigger; HIGH and FAILSAFE stay
 * until an operator resets them (KG_IOC_SET_POSTURE, CAP_SYS_ADMIN), which is
 * announced with KG_ALERT_POSTURE_CHANGED so the change is in the
 * authenticated log.  Automatic raises are not announced separately: the alert
 * that caused one already is.
 *
 * If the policy state itself was found corrupted, stepping down from HIGH or
 * FAILSAFE is refused: the baseline strategies it would restore cannot be
 * trusted.  Unload and reload the module.
 *
 * Locking: kg_pos_lock serialises transitions and the bookkeeping below.  The
 * state that the posture governs lives in kg_guard and is only mutated through
 * kg_mit_set_posture(), which holds kg_guard_lock.  Follow-up work (flushes,
 * kicks, alerts) runs after kg_pos_lock is dropped, so nothing here re-enters
 * it through kg_report().  Process context only.
 */
#include "kg.h"

#include <linux/timekeeping.h>
#include <linux/workqueue.h>

#define KG_POSTURE_SCAN_DIV     4U
#define KG_POSTURE_MIN_SCAN_MS  100U
#define KG_POSTURE_MAX_DECAY_S  1000000U        /* clamp: keeps the jiffies conversion in range */

static const char *const kg_pos_name[KG_POSTURE_COUNT] = {
	"NORMAL", "ELEVATED", "HIGH", "FAIL-SAFE",
};

static DEFINE_MUTEX(kg_pos_lock);
static struct delayed_work kg_pos_decay_work;
static bool kg_pos_ready;
static bool kg_pos_untrusted;           /* policy state found corrupt: never step down */
static u64 kg_pos_since_ns;             /* realtime, for reporting */
static u64 kg_pos_trigger_ns;           /* realtime, for reporting */
static u64 kg_pos_trigger_mono;         /* monotonic, drives the decay */
static u32 kg_pos_trigger;
static u64 kg_pos_entered[KG_POSTURE_COUNT];

static const char *kg_pos_str(u32 p)
{
	return p < KG_POSTURE_COUNT ? kg_pos_name[p] : "?";
}

u32 kg_posture(void)
{
	return READ_ONCE(kg_guard.hdr.posture);
}

bool kg_enforcing(void)
{
	return kg_enforce || (kg_auto_enforce && kg_posture() >= KG_POSTURE_HIGH);
}

unsigned int kg_scan_ms(unsigned int base_ms)
{
	unsigned int ms = max(base_ms, KG_POSTURE_MIN_SCAN_MS);

	if (kg_posture() >= KG_POSTURE_ELEVATED)
		ms = max(ms / KG_POSTURE_SCAN_DIV, KG_POSTURE_MIN_SCAN_MS);
	return ms;
}

/*----------------------------------------------------------------------------
 * Decay (ELEVATED -> NORMAL)
 *--------------------------------------------------------------------------*/
static unsigned int kg_pos_decay_s(void)
{
	return min(READ_ONCE(kg_posture_decay_s), KG_POSTURE_MAX_DECAY_S);
}

/* Lock held.  (Re)start the quiet-period timer from the last trigger. */
static void kg_pos_arm_decay_locked(void)
{
	unsigned int secs = kg_pos_decay_s();

	if (kg_pos_ready && secs && kg_posture() == KG_POSTURE_ELEVATED)
		mod_delayed_work(kg_wq, &kg_pos_decay_work,
				 msecs_to_jiffies(secs * MSEC_PER_SEC));
}

/* Lock held.  Record that the posture changed to @target and apply it. */
static void kg_pos_apply_locked(u32 target)
{
	kg_mit_set_posture(target);
	kg_pos_since_ns = ktime_get_real_ns();
	kg_pos_entered[target]++;
	if (target != KG_POSTURE_FAILSAFE)
		atomic64_andnot(KG_MIT_FAIL_SAFE, &kg_stats.active_mitigation_flags);
}

/* Audit trail for a change nobody was told about by another alert. */
static void kg_pos_announce(u32 old, u32 new, u32 why, u32 trigger)
{
	const char *by = why == KG_POSTURE_WHY_DECAY ? "quiet period elapsed" : "operator request";

	pr_notice("posture %s -> %s (%s)\n", kg_pos_str(old), kg_pos_str(new), by);
	kg_report(KG_ALERT_POSTURE_CHANGED,
		  why == KG_POSTURE_WHY_DECAY ? KG_LEVEL_INFO : KG_LEVEL_WATCH,
		  ((u64)old << 32) | new, ((u64)why << 32) | trigger,
		  "posture %s -> %s (%s)", kg_pos_str(old), kg_pos_str(new), by);
}

static void kg_pos_decay_fn(struct work_struct *work)
{
	unsigned int secs = kg_pos_decay_s();
	bool lowered = false;
	u32 trigger = 0;

	mutex_lock(&kg_pos_lock);
	if (kg_pos_ready && secs && kg_posture() == KG_POSTURE_ELEVATED) {
		u64 due = kg_pos_trigger_mono + (u64)secs * NSEC_PER_SEC;
		u64 now = ktime_get_ns();

		if (now >= due) {
			trigger = kg_pos_trigger;
			kg_pos_apply_locked(KG_POSTURE_NORMAL);
			lowered = true;
		} else {
			mod_delayed_work(kg_wq, &kg_pos_decay_work,
					 nsecs_to_jiffies(due - now) + 1);
		}
	}
	mutex_unlock(&kg_pos_lock);

	if (lowered)
		kg_pos_announce(KG_POSTURE_ELEVATED, KG_POSTURE_NORMAL, KG_POSTURE_WHY_DECAY, trigger);
}

/*----------------------------------------------------------------------------
 * Raising
 *--------------------------------------------------------------------------*/

/* Everything that has to happen after the posture went up (no lock held). */
static void kg_pos_after_up(u32 target)
{
	switch (target) {
	case KG_POSTURE_FAILSAFE:
		atomic64_or(KG_MIT_FAIL_SAFE, &kg_stats.active_mitigation_flags);
		kg_mit_flush_all();
		pr_crit("*** FAIL-SAFE MODE ENTERED - full-spectrum mitigation on every CPU ***\n");
		kg_report(KG_ALERT_FAIL_SAFE_ENTERED, KG_LEVEL_CRITICAL, 0, 0,
			  "fail-safe mode entered");
		break;
	case KG_POSTURE_HIGH:
		kg_mit_flush_all();
		pr_crit("posture HIGH: every CPU held at full-spectrum mitigation%s\n",
			kg_auto_enforce ? ", active enforcement on" : "");
		break;
	case KG_POSTURE_ELEVATED:
		pr_warn("posture ELEVATED: scans run %ux as often until it decays or is reset\n",
			KG_POSTURE_SCAN_DIV);
		break;
	}

	/* Look now, at the new cadence, instead of after the old interval runs out. */
	kg_input_kick();
	kg_hw_kick();
	if (target >= KG_POSTURE_HIGH)
		kg_integrity_kick();
}

void kg_posture_raise(u32 target, u32 trigger)
{
	u32 old, cap = min_t(u32, kg_max_posture, KG_POSTURE_FAILSAFE);
	bool up = false;

	target = min(target, cap);

	mutex_lock(&kg_pos_lock);
	if (!kg_pos_ready) {
		mutex_unlock(&kg_pos_lock);
		return;
	}
	if (trigger == KG_ALERT_SHARED_STATE_CORRUPT)
		kg_pos_untrusted = true;

	old = kg_posture();
	if (target >= KG_POSTURE_ELEVATED) {
		/* A trigger that does not raise anything still counts as "not quiet yet". */
		kg_pos_trigger_ns = ktime_get_real_ns();
		kg_pos_trigger_mono = ktime_get_ns();
		kg_pos_trigger = trigger;
	}
	if (target > old) {
		kg_pos_apply_locked(target);
		up = true;
	}
	kg_pos_arm_decay_locked();
	mutex_unlock(&kg_pos_lock);

	if (up)
		kg_pos_after_up(target);
}

/*----------------------------------------------------------------------------
 * Operator control (KG_IOC_SET_POSTURE)
 *--------------------------------------------------------------------------*/
int kg_posture_set(u32 target)
{
	u32 old, trigger;

	if (target >= KG_POSTURE_COUNT)
		return -EINVAL;

	mutex_lock(&kg_pos_lock);
	if (!kg_pos_ready) {
		mutex_unlock(&kg_pos_lock);
		return -ENODEV;
	}
	old = kg_posture();
	if (target == old) {
		mutex_unlock(&kg_pos_lock);
		return 0;
	}
	if (target < old && old >= KG_POSTURE_HIGH && kg_pos_untrusted) {
		mutex_unlock(&kg_pos_lock);
		pr_err("refusing to lower the posture: the policy state was corrupted; reload the module\n");
		return -EUCLEAN;
	}

	trigger = kg_pos_trigger;
	kg_pos_apply_locked(target);
	kg_pos_trigger_mono = ktime_get_ns();   /* an operator step restarts the quiet period */
	kg_pos_arm_decay_locked();
	mutex_unlock(&kg_pos_lock);

	if (target > old)
		kg_pos_after_up(target);
	kg_pos_announce(old, target, KG_POSTURE_WHY_OPERATOR, trigger);
	return 0;
}

void kg_posture_info(struct kg_posture_info *pi)
{
	memset(pi, 0, sizeof(*pi));

	mutex_lock(&kg_pos_lock);
	pi->posture = kg_posture();
	pi->max_posture = min_t(u32, kg_max_posture, KG_POSTURE_FAILSAFE);
	pi->decay_s = kg_pos_decay_s();
	if (kg_auto_enforce)
		pi->flags |= KG_POSTURE_F_AUTO_ENFORCE;
	if (kg_enforcing())
		pi->flags |= KG_POSTURE_F_ENFORCING;
	if (kg_pos_untrusted)
		pi->flags |= KG_POSTURE_F_UNTRUSTED;
	pi->since_ns = kg_pos_since_ns;
	pi->last_trigger_ns = kg_pos_trigger_ns;
	pi->last_trigger_alert = kg_pos_trigger;
	memcpy(pi->entered, kg_pos_entered, sizeof(pi->entered));
	mutex_unlock(&kg_pos_lock);

	pi->hw_interval_ms = kg_scan_ms(kg_hw_interval_ms);
	pi->integ_interval_ms = kg_scan_ms(kg_integ_interval_ms);
}

/*----------------------------------------------------------------------------
 * init / exit
 *--------------------------------------------------------------------------*/
void kg_posture_init(void)
{
	INIT_DELAYED_WORK(&kg_pos_decay_work, kg_pos_decay_fn);

	mutex_lock(&kg_pos_lock);
	kg_pos_untrusted = false;
	kg_pos_since_ns = ktime_get_real_ns();
	kg_pos_trigger_ns = 0;
	kg_pos_trigger_mono = 0;
	kg_pos_trigger = 0;
	memset(kg_pos_entered, 0, sizeof(kg_pos_entered));
	kg_pos_entered[KG_POSTURE_NORMAL] = 1;
	kg_pos_ready = true;
	mutex_unlock(&kg_pos_lock);

	pr_info("response posture %s (max %s, decay %us, auto_enforce=%d)\n",
		kg_pos_str(kg_posture()),
		kg_pos_str(min_t(u32, kg_max_posture, KG_POSTURE_FAILSAFE)),
		kg_pos_decay_s(), kg_auto_enforce);
}

void kg_posture_exit(void)
{
	mutex_lock(&kg_pos_lock);
	kg_pos_ready = false;
	mutex_unlock(&kg_pos_lock);
	cancel_delayed_work_sync(&kg_pos_decay_work);
}
