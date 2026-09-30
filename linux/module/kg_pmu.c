// SPDX-License-Identifier: GPL-2.0
/*
 * kg_pmu.c - Module 1: side-channel attack detection through the PMU.
 * Counterpart of src/pmu_detection.c.
 *
 * How this differs from the Windows driver, and why
 * -------------------------------------------------
 * The Windows module programs IA32_PERFEVTSELx / IA32_PMCx / IA32_PERF_GLOBAL_*
 * directly, maps the local APIC, and connects an interrupt at vector 0xE4.  On
 * Linux the PMU belongs to the perf subsystem: it owns the counters, the LVT
 * performance-counter entry, the NMI handler, and the NMI watchdog uses one of
 * the counters.  Doing the same from a module would clobber all of that.  The
 * supported way to get "an overflow callback in NMI context" is a kernel
 * perf counter with a sample period and an overflow handler - exactly what the
 * hard-lockup detector does - so that is what is used here.  It also makes the
 * module portable: generic cache events map to the right raw event on every
 * Intel and AMD microarchitecture, including hybrid parts, instead of the
 * hard-coded Skylake encodings (MEM_LOAD_RETIRED.L1_MISS / L2_RQSTS.MISS).
 *
 * Events per CPU
 *   L1D  PERF_TYPE_HW_CACHE  L1D / READ / MISS          (Flush+Reload, Prime+Probe L1)
 *   LLC  PERF_TYPE_HARDWARE  CACHE_MISSES (last level)  (Prime+Probe LLC, Flush+Flush)
 * The LLC event replaces the Windows L2 counter: perf has no generic L2 event
 * and the LLC is what cross-core attacks work on.  The alert code is unchanged
 * (ALERT_PMU_L2_ANOMALY).
 *
 * NMI discipline (the HIGH_LEVEL rules of PmiIsr): the overflow handler touches
 * only per-CPU atomics, decides nothing that needs a lock, may run a forced
 * VERW/L1D flush, and defers everything else with irq_work.
 *
 * Detection is rate based.  The Windows driver escalates permanently after 3
 * overflows *ever*; here a 1-second sampler turns overflow counts into a rate,
 * raises the level on the way up and decays it after quiet windows.  This is a
 * heuristic - memory-bound workloads also miss a lot - so the alert names the
 * offending process and the thresholds are tunable (README "PMU tuning").
 */
#include "kg.h"

#include <linux/cpuhotplug.h>
#include <linux/irq_work.h>
#include <linux/moduleparam.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/topology.h>

static unsigned long p_period_l1d = KG_PMU_DEF_PERIOD_L1D;
static unsigned long p_period_llc = KG_PMU_DEF_PERIOD_LLC;
static unsigned int p_window_ms = KG_PMU_DEF_WINDOW_MS;
static unsigned int p_warn = KG_PMU_DEF_WARN_OVF;
static unsigned int p_crit = KG_PMU_DEF_CRIT_OVF;
module_param_named(pmu_period_l1d, p_period_l1d, ulong, 0444);
module_param_named(pmu_period_llc, p_period_llc, ulong, 0444);
module_param_named(pmu_window_ms, p_window_ms, uint, 0644);
module_param_named(pmu_warn, p_warn, uint, 0644);
module_param_named(pmu_crit, p_crit, uint, 0644);
MODULE_PARM_DESC(pmu_period_l1d, "L1D read misses per counter overflow (default 100000)");
MODULE_PARM_DESC(pmu_period_llc, "LLC misses per counter overflow (default 20000)");
MODULE_PARM_DESC(pmu_window_ms, "Sampling window in ms (default 1000)");
MODULE_PARM_DESC(pmu_warn, "Overflows/second per CPU that raise a 'watch' alert (default 500)");
MODULE_PARM_DESC(pmu_crit, "Overflows/second per CPU that raise a critical alert (default 2000)");

enum { KG_EV_L1D, KG_EV_LLC, KG_EV_NR };

/*
 * The thresholds are writable at run time (/sys/module/kernelguard/parameters),
 * so every consumer goes through this: warn >= 1 and crit > warn, whatever was
 * typed.  (warn=0 would alert on every silent window.)
 */
static inline void kg_pmu_thresholds(unsigned int *warn, unsigned int *crit)
{
	unsigned int w = max(READ_ONCE(p_warn), 1U);

	*warn = w;
	*crit = max(READ_ONCE(p_crit), w + 1);
}

struct kg_pmu_cpu {
	struct perf_event *ev[KG_EV_NR];
	atomic_long_t ovf[KG_EV_NR];    /* incremented in NMI, drained by the sampler */
	atomic_t cand_tgid;             /* Boyer-Moore majority candidate: user task at overflows */
	atomic_t cand_cnt;
	struct irq_work iw;
	/* sampler-private (only the sampler work touches these) */
	u8  level[KG_EV_NR];
	u8  calm[KG_EV_NR];
	u64 last_alert_ns[KG_EV_NR];
	bool crit;                      /* some event on this CPU is at critical level */
};

static DEFINE_PER_CPU(struct kg_pmu_cpu, kg_pmu_cpu);

static enum cpuhp_state kg_pmu_hp_state;
static bool kg_pmu_running;
static bool kg_pmu_stop;
static atomic_t kg_pmu_events = ATOMIC_INIT(0);
static struct delayed_work kg_pmu_dwork;
static u64 kg_pmu_last_ns;

bool kg_pmu_active(void)
{
	return kg_pmu_running;
}

/*----------------------------------------------------------------------------
 * NMI context (Windows: PmiIsr).  Nothing here may block, allocate, or take a
 * lock.  current is valid in NMI; only its tgid is read.
 *--------------------------------------------------------------------------*/
static void kg_pmu_overflow(struct perf_event *event, struct perf_sample_data *data,
			    struct pt_regs *regs)
{
	struct kg_pmu_cpu *pc = this_cpu_ptr(&kg_pmu_cpu);
	unsigned int kind = (unsigned long)event->overflow_handler_context;
	unsigned int warn, crit;
	long n;

	if (kind >= KG_EV_NR || READ_ONCE(kg_pmu_stop) || this_cpu_read(kg_self_busy))
		return;         /* stopping, or the driver's own integrity scan is running */

	n = atomic_long_inc_return(&pc->ovf[kind]);
	if (kind == KG_EV_L1D)
		kg_stat_inc(pmu_l1d_overflows);
	else
		kg_stat_inc(pmu_llc_overflows);

	/*
	 * Who is causing this?  Keep the majority vote of the user-mode task that was
	 * running at each overflow (Boyer-Moore, one candidate + one counter).  Only
	 * this CPU's NMI writes it; the sampler reads and resets it.
	 */
	if (regs && user_mode(regs)) {
		int tgid = task_tgid_nr(current);

		if (atomic_read(&pc->cand_tgid) == tgid)
			atomic_inc(&pc->cand_cnt);
		else if (atomic_read(&pc->cand_cnt) <= 0) {
			atomic_set(&pc->cand_tgid, tgid);
			atomic_set(&pc->cand_cnt, 1);
		} else {
			atomic_dec(&pc->cand_cnt);
		}
	}

	/*
	 * Sustained miss rate: mitigate right here, before user space can react
	 * (the Windows ISR does the same), and wake the sampler to escalate.
	 */
	kg_pmu_thresholds(&warn, &crit);
	if (n >= (long)crit) {
		kg_boundary_flush_forced();
		if (n == (long)crit)
			irq_work_queue(&pc->iw);
	}
}

/* hardirq context after the NMI returns */
static void kg_pmu_irq_work(struct irq_work *iw)
{
	if (!READ_ONCE(kg_pmu_stop))
		mod_delayed_work(kg_wq, &kg_pmu_dwork, 0);
}

/*----------------------------------------------------------------------------
 * Sampler (process context): counts -> rates -> levels -> alerts
 *--------------------------------------------------------------------------*/
static void kg_pmu_comm(int tgid, char *comm, size_t len)
{
	struct pid *pid;
	struct task_struct *task;

	strscpy(comm, "?", len);
	if (tgid <= 0)
		return;
	pid = find_get_pid(tgid);
	if (!pid)
		return;
	task = get_pid_task(pid, PIDTYPE_TGID);
	if (task) {
		task_lock(task);
		strscpy(comm, task->comm, len);
		task_unlock(task);
		put_task_struct(task);
	}
	put_pid(pid);
}

static void kg_pmu_sample(struct work_struct *work)
{
	u64 now = ktime_get_ns();
	u64 elapsed_ms = max_t(u64, (now - kg_pmu_last_ns) / NSEC_PER_MSEC, 1);
	u64 denom_ms = max_t(u64, elapsed_ms, max(READ_ONCE(p_window_ms), 100U));
	unsigned int warn, crit;
	int cpu, maxlvl = 0;

	kg_pmu_thresholds(&warn, &crit);
	kg_pmu_last_ns = now;

	for_each_online_cpu(cpu) {
		struct kg_pmu_cpu *pc = per_cpu_ptr(&kg_pmu_cpu, cpu);
		bool any_crit = false;
		int kind;

		for (kind = 0; kind < KG_EV_NR; kind++) {
			unsigned long n, rate;
			u8 lvl;

			if (!pc->ev[kind])
				continue;
			n = atomic_long_xchg(&pc->ovf[kind], 0);
			rate = n * 1000 / denom_ms;
			lvl = rate >= crit ? KG_LEVEL_CRITICAL : rate >= warn ? KG_LEVEL_WATCH : 0;

			/*
			 * Alerts for one CPU/event are spaced by at least a second (and repeat every
			 * 10 s while the condition lasts).  If the spacing has not elapsed the level
			 * is left as it was, so the escalation is retried on the next window - never
			 * lost, only deferred.  This bounds the alert rate whatever the thresholds are.
			 */
			if ((lvl > pc->level[kind] && now - pc->last_alert_ns[kind] >= NSEC_PER_SEC) ||
			    (lvl && lvl == pc->level[kind] &&
			     now - pc->last_alert_ns[kind] >= 10ULL * NSEC_PER_SEC)) {
				int tgid = atomic_xchg(&pc->cand_tgid, 0);
				char comm[TASK_COMM_LEN];

				kg_pmu_comm(tgid, comm, sizeof(comm));
				atomic_set(&pc->cand_cnt, 0);
				pc->last_alert_ns[kind] = now;
				pc->level[kind] = lvl;
				pc->calm[kind] = 0;
				kg_report(kind == KG_EV_L1D ? KG_ALERT_PMU_L1D_ANOMALY :
							      KG_ALERT_PMU_L2_ANOMALY,
					  lvl, tgid > 0 ? tgid : 0, ((u64)cpu << 32) | (u32)rate,
					  "%s cache-miss rate on CPU%d: %lu overflows/s (top user task %s[%d])",
					  kind == KG_EV_L1D ? "L1D" : "LLC", cpu, rate, comm, tgid);
			} else if (lvl < pc->level[kind]) {
				if (++pc->calm[kind] >= KG_PMU_CALM_WINDOWS) {
					pc->level[kind] = lvl;
					pc->calm[kind] = 0;
				}
			} else {
				pc->calm[kind] = 0;
			}

			any_crit |= pc->level[kind] >= KG_LEVEL_CRITICAL;
			maxlvl = max_t(int, maxlvl, pc->level[kind]);
		}
		pc->crit = any_crit;
	}
	kg_stat_set(pmu_alert_level, maxlvl);

	/*
	 * Back to a CPU's normal strategy once neither it NOR ITS SMT SIBLINGS are critical:
	 * a sibling was escalated because of its core partner and must stay escalated as
	 * long as that partner is under attack (they share the L1D and the fill buffers).
	 */
	for_each_online_cpu(cpu) {
		bool hot = false;
		int sib;

		for_each_cpu(sib, topology_sibling_cpumask(cpu))
			hot |= per_cpu(kg_pmu_cpu, sib).crit;
		if (!hot && kg_guard.cpu[cpu].strategy != kg_guard.cpu[cpu].base_strategy)
			kg_mit_relax_cpu(cpu);
	}

	if (!READ_ONCE(kg_pmu_stop))
		queue_delayed_work(kg_wq, &kg_pmu_dwork, msecs_to_jiffies(max(READ_ONCE(p_window_ms), 100U)));
}

/*----------------------------------------------------------------------------
 * Per-CPU counters (hotplug aware - Windows: the KeIpiGenericCall broadcast)
 *--------------------------------------------------------------------------*/
static int kg_pmu_cpu_online(unsigned int cpu)
{
	struct kg_pmu_cpu *pc = per_cpu_ptr(&kg_pmu_cpu, cpu);
	int kind;

	memset(pc->level, 0, sizeof(pc->level));
	memset(pc->calm, 0, sizeof(pc->calm));
	atomic_set(&pc->cand_tgid, 0);
	atomic_set(&pc->cand_cnt, 0);
	init_irq_work(&pc->iw, kg_pmu_irq_work);

	for (kind = 0; kind < KG_EV_NR; kind++) {
		struct perf_event_attr attr = {
			.size          = sizeof(attr),
			.exclude_hv    = 1,
			.exclude_idle  = 1,
			.exclude_guest = 1,
		};
		struct perf_event *ev;

		atomic_long_set(&pc->ovf[kind], 0);
		if (kind == KG_EV_L1D) {
			attr.type = PERF_TYPE_HW_CACHE;
			attr.config = PERF_COUNT_HW_CACHE_L1D |
				      (PERF_COUNT_HW_CACHE_OP_READ << 8) |
				      (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
			attr.sample_period = p_period_l1d;
		} else {
			attr.type = PERF_TYPE_HARDWARE;
			attr.config = PERF_COUNT_HW_CACHE_MISSES;
			attr.sample_period = p_period_llc;
		}

		ev = perf_event_create_kernel_counter(&attr, cpu, NULL, kg_pmu_overflow,
						      (void *)(unsigned long)kind);
		if (IS_ERR(ev)) {
			pr_debug("cpu%u: %s counter unavailable: %ld\n", cpu,
				 kind == KG_EV_L1D ? "L1D" : "LLC", PTR_ERR(ev));
			pc->ev[kind] = NULL;
			continue;
		}
		pc->ev[kind] = ev;
		atomic_inc(&kg_pmu_events);
	}
	return 0;               /* never veto a CPU coming online */
}

static int kg_pmu_cpu_offline(unsigned int cpu)
{
	struct kg_pmu_cpu *pc = per_cpu_ptr(&kg_pmu_cpu, cpu);
	int kind;

	for (kind = 0; kind < KG_EV_NR; kind++) {
		if (pc->ev[kind]) {
			perf_event_release_kernel(pc->ev[kind]);
			pc->ev[kind] = NULL;
			atomic_dec(&kg_pmu_events);
		}
	}
	irq_work_sync(&pc->iw);
	pc->crit = false;
	return 0;
}

/*----------------------------------------------------------------------------
 * init / exit (Windows: PmuInitialize / PmuUninitialize)
 *--------------------------------------------------------------------------*/
int kg_pmu_init(void)
{
	int ret;

	if (!boot_cpu_has(X86_FEATURE_ARCH_PERFMON) && !boot_cpu_has(X86_FEATURE_PERFCTR_CORE))
		return -ENODEV;

	/* A tiny period means one NMI per few events - refuse it rather than storm. */
	if (p_period_l1d < 1000 || p_period_llc < 1000) {
		pr_warn("pmu_period_* raised to the minimum of 1000 events per overflow\n");
		p_period_l1d = max(p_period_l1d, 1000UL);
		p_period_llc = max(p_period_llc, 1000UL);
	}
	p_period_l1d = min(p_period_l1d, 1UL << 30);
	p_period_llc = min(p_period_llc, 1UL << 30);

	kg_pmu_stop = false;
	INIT_DELAYED_WORK(&kg_pmu_dwork, kg_pmu_sample);
	kg_pmu_last_ns = ktime_get_ns();

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "kernelguard/pmu:online",
				kg_pmu_cpu_online, kg_pmu_cpu_offline);
	if (ret < 0)
		return ret;
	kg_pmu_hp_state = ret;

	if (!atomic_read(&kg_pmu_events)) {
		cpuhp_remove_state(kg_pmu_hp_state);
		pr_info("no usable PMU counters (virtual machine without a vPMU?)\n");
		return -ENODEV;
	}

	kg_pmu_running = true;
	queue_delayed_work(kg_wq, &kg_pmu_dwork, msecs_to_jiffies(max(READ_ONCE(p_window_ms), 100U)));
	pr_info("PMU detection: %d counters on %u CPUs (L1D period %lu, LLC period %lu, warn %u / crit %u overflows/s)\n",
		atomic_read(&kg_pmu_events), num_online_cpus(), p_period_l1d, p_period_llc, p_warn, p_crit);
	return 0;
}

void kg_pmu_exit(void)
{
	if (!kg_pmu_running)
		return;

	WRITE_ONCE(kg_pmu_stop, true);
	cpuhp_remove_state(kg_pmu_hp_state);    /* releases every counter, syncs irq_work */
	cancel_delayed_work_sync(&kg_pmu_dwork);
	kg_pmu_running = false;
}
