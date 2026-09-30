// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_mitigate.c - Module 4: cache / microarchitectural mitigation engine.
 * Counterpart of windows/src/cache_mitigation.c and windows/src/asm/verw_flush.asm.
 *
 * Subsystems
 *   4a  sensitive-allocation registry              kg_state.c (kg_sens_*)
 *   4b  security-boundary flush (VERW / L1D)       kg.h (kg_boundary_flush) + here
 *   4c  speculation controls (IBPB, LFENCE,       here; SPEC_CTRL is only READ
 *       array_index_nospec)
 *   4d  L3 cache partitioning (Intel CAT)          capability + plan only
 *   4e  SMT sibling handling                       topology-driven sibling flush
 *
 * What is intentionally NOT ported, and why:
 *
 *  - Writing IA32_SPEC_CTRL (Windows EnableSpeculationControls /
 *    DisableSpeculationControls).  On Linux that MSR belongs to the kernel's
 *    spectre_v2 machinery: x86_spec_ctrl_current is cached per CPU, rewritten
 *    on kernel entry/exit in IBRS mode and per task for SSBD/STIBP.  Writing
 *    it from a module races with that and, on an eIBRS system, clearing bit 0
 *    would silently weaken the whole machine.  The escalation path uses the
 *    one-shot, stateless IBPB barrier instead.
 *
 *  - Programming IA32_PQR_ASSOC / IA32_L3_MASKn (CAT).  resctrl owns them and
 *    rewrites PQR_ASSOC on every context switch of a resctrl-managed task.
 *    The module reports whether CAT exists and computes the same partition
 *    the Windows driver would use (top quarter of the ways for sensitive
 *    workloads); README shows the resctrl commands that apply it.
 *
 *  - Per-context-switch hooks (SensContextSwitchHook / HardenedKeyboardIsr are
 *    dead code in the Windows driver: nothing ever registers them).  For
 *    "sensitive process" protection Linux already has per-task controls -
 *    PR_SPEC_L1D_FLUSH, PR_SPEC_INDIRECT_BRANCH and PR_SCHED_CORE - which
 *    `kgmon run --sensitive` applies.
 *
 * The reactive engine that IS ported: strategy selection, boundary flushing on
 * PMU / integrity / DMA events, sibling flush, and fail-safe.
 */
#include "kg.h"

#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/nospec.h>
#include <linux/slab.h>
#include <linux/topology.h>

#ifndef ARCH_CAP_SSB_NO
#define ARCH_CAP_SSB_NO         BIT(4)
#endif

static enum cpuhp_state kg_mit_hp_state;

/*----------------------------------------------------------------------------
 * Capability probe (Windows: ProbeCpuCapabilities).  Runs ON the target CPU.
 *--------------------------------------------------------------------------*/
struct kg_probe {
	u32 features;
	u8  strategy;
	u16 cost_ns;
	u16 cat_ways;
	u32 cat_sens_cbm;
	u32 cat_def_cbm;
};

static bool kg_cpu_needs_buffer_clear(void)
{
	return boot_cpu_has_bug(X86_BUG_MDS) ||
	       boot_cpu_has_bug(X86_BUG_TAA) ||
	       boot_cpu_has_bug(X86_BUG_MMIO_STALE_DATA)
#ifdef X86_BUG_RFDS
	       || boot_cpu_has_bug(X86_BUG_RFDS)
#endif
	       ;
}

static void kg_probe_this_cpu(struct kg_probe *p)
{
	int cpu = raw_smp_processor_id();
	bool mds_vuln, l1tf_vuln;
	u64 cap = 0;
	u32 f = 0;

	memset(p, 0, sizeof(*p));

	/*
	 * IA32_ARCH_CAPABILITIES.  The Windows header aliases L1TF_NO and SSB_NO
	 * to the same bit (4); only RDCL_NO (bit 0) says anything about L1TF, and
	 * SSB_NO really is bit 4.
	 */
	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES) &&
	    !kg_rdmsr_safe(MSR_IA32_ARCH_CAPABILITIES, &cap))
		f |= KG_FEAT_ARCH_CAP_MSR;
	if (cap & ARCH_CAP_RDCL_NO)
		f |= KG_FEAT_RDCL_NO | KG_FEAT_L1TF_NO;
	if (cap & ARCH_CAP_MDS_NO)
		f |= KG_FEAT_MDS_NO;
	if (cap & ARCH_CAP_IBRS_ALL)
		f |= KG_FEAT_IBRS_ALL;
	if (cap & ARCH_CAP_SSB_NO)
		f |= KG_FEAT_SSB_NO;

	if (boot_cpu_has(X86_FEATURE_MD_CLEAR)
#ifdef X86_FEATURE_VERW_CLEAR
	    || boot_cpu_has(X86_FEATURE_VERW_CLEAR)
#endif
	    )
		f |= KG_FEAT_VERW_FLUSH;
	if (boot_cpu_has(X86_FEATURE_FLUSH_L1D))
		f |= KG_FEAT_L1D_FLUSH;
	if (boot_cpu_has(X86_FEATURE_IBPB))
		f |= KG_FEAT_IBPB;
	if (cpumask_weight(topology_sibling_cpumask(cpu)) > 1)
		f |= KG_FEAT_SMT;

	/* CPUID.(EAX=10H,ECX=1): L3 CAT.  EAX[4:0] = CBM length - 1. */
	if (boot_cpu_has(X86_FEATURE_CAT_L3)) {
		u32 eax, ebx, ecx, edx;

		cpuid_count(0x10, 1, &eax, &ebx, &ecx, &edx);
		if ((edx & 0xffff) >= 1) {
			u32 ways = (eax & 0x1f) + 1;
			u32 sens = ways >= 4 ? ways / 4 : 1;
			u64 sens_cbm = ((1ULL << sens) - 1) << (ways - sens);
			u64 all = (1ULL << ways) - 1;

			f |= KG_FEAT_CAT_L3;
			p->cat_ways = ways;
			p->cat_sens_cbm = (u32)sens_cbm;
			p->cat_def_cbm = (u32)(all & ~sens_cbm);
		}
	}

	/*
	 * Cheapest safe strategy (same decision table as the Windows driver, but
	 * driven by the kernel's X86_BUG_* determination, which also covers CPUs
	 * that predate IA32_ARCH_CAPABILITIES and are identified by model).
	 */
	mds_vuln  = kg_cpu_needs_buffer_clear();
	l1tf_vuln = boot_cpu_has_bug(X86_BUG_L1TF);

	if (!mds_vuln && !l1tf_vuln) {
		p->strategy = KG_STRAT_NONE;
		p->cost_ns = 0;
	} else if (mds_vuln && !l1tf_vuln) {
		p->strategy = KG_STRAT_VERW;
		p->cost_ns = 50;
	} else if (!mds_vuln && l1tf_vuln) {
		p->strategy = KG_STRAT_L1D;
		p->cost_ns = 200;
	} else if (f & KG_FEAT_VERW_FLUSH) {
		p->strategy = KG_STRAT_VERW_L1D;
		p->cost_ns = 250;
	} else {
		p->strategy = KG_STRAT_FULL;
		p->cost_ns = 500;
	}
	p->features = f;
}

/* Publish a probe result into the guarded table (process context). */
static void kg_mit_store(int cpu, const struct kg_probe *p)
{
	struct kg_cpu_mit *m;

	kg_guard_lock_acquire();
	m = &kg_guard.cpu[cpu];
	m->features = p->features;
	m->base_strategy = p->strategy;
	m->strategy = kg_guard.hdr.failsafe ? KG_STRAT_FULL : p->strategy;
	m->flush_cost_ns = p->cost_ns;
	m->cat_ways = p->cat_ways;
	m->cat_sens_cbm = p->cat_sens_cbm;
	m->cat_def_cbm = p->cat_def_cbm;
	kg_guard_unlock_release();

	pr_debug("cpu%d: features=%#06x strategy=%u cost=%uns\n",
		 cpu, p->features, p->strategy, p->cost_ns);
}

static int kg_mit_cpu_online(unsigned int cpu)
{
	struct kg_probe p;

	/* The hotplug thread is bound to @cpu, so the probe sees this CPU. */
	kg_probe_this_cpu(&p);
	kg_mit_store(cpu, &p);
	return 0;              /* never veto a CPU coming online */
}

/*----------------------------------------------------------------------------
 * Policy mutation.  Every change goes through the guard lock so the state
 * hash always matches the table it protects.
 *--------------------------------------------------------------------------*/
void kg_mit_set_all(u8 strategy)
{
	int cpu;

	kg_guard_lock_acquire();
	for (cpu = 0; cpu < (int)kg_guard.hdr.ncpu; cpu++)
		kg_guard.cpu[cpu].strategy = strategy;
	kg_guard_unlock_release();
}

bool kg_mit_enter_failsafe(void)
{
	int cpu;

	kg_guard_lock_acquire();
	if (kg_guard.hdr.failsafe) {
		kg_guard_unlock_release();
		return false;
	}
	kg_guard.hdr.failsafe = 1;
	for (cpu = 0; cpu < (int)kg_guard.hdr.ncpu; cpu++)
		kg_guard.cpu[cpu].strategy = KG_STRAT_FULL;
	kg_guard_unlock_release();
	return true;
}

void kg_mit_escalate_cpu(int cpu)
{
	if (cpu < 0 || cpu >= (int)kg_guard.hdr.ncpu)
		return;
	kg_guard_lock_acquire();
	kg_guard.cpu[cpu].strategy = KG_STRAT_FULL;
	kg_guard_unlock_release();
}

void kg_mit_relax_cpu(int cpu)
{
	if (cpu < 0 || cpu >= (int)kg_guard.hdr.ncpu)
		return;
	kg_guard_lock_acquire();
	if (!kg_guard.hdr.failsafe)
		kg_guard.cpu[cpu].strategy = kg_guard.cpu[cpu].base_strategy;
	kg_guard_unlock_release();
}

/*----------------------------------------------------------------------------
 * Flush requests that must run on a specific CPU.
 *
 * The flush follows that CPU's strategy (Windows: ExecuteSecurityBoundaryFlush):
 * a CPU that is not affected by MDS/L1TF is not flushed for a routine event.
 * Confirmed anomalies escalate the CPU to KG_STRAT_FULL first, and FULL adds an
 * IBPB - a one-shot barrier command, issued only from here (process context,
 * never the NMI path: it costs tens of microseconds on some parts).
 *--------------------------------------------------------------------------*/
static void kg_flush_ipi(void *unused)
{
	const struct kg_cpu_mit *m = &kg_guard.cpu[raw_smp_processor_id()];
	u8 strat = READ_ONCE(m->strategy);
	u64 flags = 0;

	kg_boundary_flush();
	if (strat == KG_STRAT_VERW || strat == KG_STRAT_VERW_L1D || strat == KG_STRAT_FULL)
		flags |= KG_MIT_VERW;
	if ((strat == KG_STRAT_L1D || strat == KG_STRAT_VERW_L1D || strat == KG_STRAT_FULL) &&
	    (m->features & KG_FEAT_L1D_FLUSH))
		flags |= KG_MIT_L1D_FLUSH;
	if (strat == KG_STRAT_FULL && (m->features & KG_FEAT_IBPB)) {
		kg_wrmsr_safe(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);
		flags |= KG_MIT_IBPB;
	}
	if (flags)
		atomic64_or(flags, &kg_stats.active_mitigation_flags);
}

void kg_mit_flush_cpu(int cpu)
{
	if (cpu >= 0 && cpu < nr_cpu_ids && cpu_online(cpu))
		smp_call_function_single(cpu, kg_flush_ipi, NULL, 1);
}

/*
 * SMT siblings share the L1D and the fill buffers with @cpu, so an anomaly on one
 * thread escalates and flushes the others too (Windows: SmtSiblingFlushDpc).
 */
void kg_mit_flush_siblings(int cpu)
{
	int sib;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return;
	for_each_cpu(sib, topology_sibling_cpumask(cpu)) {
		if (sib == cpu || !cpu_online(sib))
			continue;
		kg_mit_escalate_cpu(sib);       /* the PMU sampler relaxes it once it is quiet */
		smp_call_function_single(sib, kg_flush_ipi, NULL, 0);
	}
}

void kg_mit_flush_all(void)
{
	on_each_cpu(kg_flush_ipi, NULL, 1);
}

/*----------------------------------------------------------------------------
 * KG_IOC_GET_CPU_INFO backend.  @ci->cpu comes from user space, so it is
 * clamped with array_index_nospec() before indexing (Windows: SafeArrayIndex).
 *--------------------------------------------------------------------------*/
int kg_mit_cpu_info(struct kg_cpu_info *ci)
{
	const struct kg_cpu_mit *m;
	u32 idx;

	if (ci->cpu >= kg_guard.hdr.ncpu)
		return -EINVAL;
	idx = array_index_nospec(ci->cpu, kg_guard.hdr.ncpu);
	m = &kg_guard.cpu[idx];

	ci->online = cpu_online(idx);
	ci->features = m->features;
	ci->strategy = m->strategy;
	ci->base_strategy = m->base_strategy;
	ci->flush_cost_ns = m->flush_cost_ns;
	ci->cat_ways = m->cat_ways;
	ci->cat_sensitive_cbm = m->cat_sens_cbm;
	ci->cat_default_cbm = m->cat_def_cbm;
	return 0;
}

/*----------------------------------------------------------------------------
 * init / exit (Windows: CacheMitigationInitialize / Uninitialize)
 *--------------------------------------------------------------------------*/
int kg_mit_init(void)
{
	unsigned int counts[KG_STRAT_FULL + 1] = { };
	int ret, cpu, n = 0;

	kg_guard.hdr.magic = 0x4B474744;
	kg_guard.hdr.abi = KG_ABI_VERSION;
	kg_guard.hdr.ncpu = nr_cpu_ids;
	kg_guard.hdr.failsafe = 0;
	kg_guard.cpu = kcalloc(nr_cpu_ids, sizeof(*kg_guard.cpu), GFP_KERNEL);
	if (!kg_guard.cpu)
		return -ENOMEM;

	/* Invokes kg_mit_cpu_online() on every CPU that is already up. */
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "kernelguard/mit:online",
				kg_mit_cpu_online, NULL);
	if (ret < 0) {
		kfree(kg_guard.cpu);
		kg_guard.cpu = NULL;
		return ret;
	}
	kg_mit_hp_state = ret;

	for_each_online_cpu(cpu) {
		counts[kg_guard.cpu[cpu].strategy]++;
		n++;
	}
	pr_info("mitigation engine: %d CPUs, strategy none=%u verw=%u l1d=%u verw+l1d=%u full=%u "
		"(mds/taa/mmio=%d l1tf=%d)\n", n,
		counts[KG_STRAT_NONE], counts[KG_STRAT_VERW], counts[KG_STRAT_L1D],
		counts[KG_STRAT_VERW_L1D], counts[KG_STRAT_FULL],
		kg_cpu_needs_buffer_clear(), boot_cpu_has_bug(X86_BUG_L1TF));

	if (kg_guard.cpu[cpumask_first(cpu_online_mask)].cat_ways)
		pr_info("L3 CAT present (%u ways): apply sensitive mask %#x / default %#x via resctrl\n",
			kg_guard.cpu[cpumask_first(cpu_online_mask)].cat_ways,
			kg_guard.cpu[cpumask_first(cpu_online_mask)].cat_sens_cbm,
			kg_guard.cpu[cpumask_first(cpu_online_mask)].cat_def_cbm);

	kg_guard_update();
	return 0;
}

void kg_mit_exit(void)
{
	if (!kg_guard.cpu)
		return;
	cpuhp_remove_state(kg_mit_hp_state);
	kg_guard.valid = false;
	kfree(kg_guard.cpu);
	kg_guard.cpu = NULL;
}
