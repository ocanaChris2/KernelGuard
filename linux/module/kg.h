/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kg.h - internal master header of the KernelGuard Linux module.
 * Counterpart of windows/src/KernelGuard.h.
 *
 * Module map (Windows source -> Linux source):
 *   pmu_detection.c         -> kg_pmu.c        Module 1
 *   hw_keylogger_detect.c   -> kg_hw.c         Module 2 (PCI / DMA)
 *                              kg_input.c      Module 2 (keyboard path)
 *   kernel_integrity.c      -> kg_integrity.c  Module 3
 *   driver_load_guard.c     -> kg_modgate.c    Module 3.5 (driver-load gate)
 *   cache_mitigation.c      -> kg_mitigate.c   Module 4
 *   secure_comms.c          -> kg_comms.c      Module 5
 *   shared_state.c          -> kg_state.c
 *   driver_main.c           -> kg_main.c
 *
 * Context rules (the Linux analogue of the IRQL discipline):
 *   NMI              kg_pmu overflow handler ONLY.  Atomics, per-CPU data,
 *                    kg_boundary_flush() and irq_work_queue().  No locks,
 *                    no allocation, no kg_report().
 *   process context  everything else, including kg_report().
 */
#ifndef _KG_H
#define _KG_H

#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <asm/cpufeature.h>
#include <asm/cpufeatures.h>
#include <asm/msr-index.h>
#include <asm/processor.h>
#include <asm/segment.h>

#include "kernelguard_uapi.h"

#ifndef CONFIG_X86_64
#error "KernelGuard targets x86-64 (Intel and AMD) only"
#endif

#define KG_VERSION              "1.0.0-linux"

/*----------------------------------------------------------------------------
 * MSR accessors.  The rdmsrl/wrmsrl family was renamed rdmsrq/wrmsrq in 6.15.
 * The _safe variants return non-zero instead of oopsing on a #GP, which is
 * the Linux counterpart of the Windows driver's __try/__except around
 * WRMSR - and unlike the Windows code we use them for every access whose
 * presence is not architecturally guaranteed.
 *--------------------------------------------------------------------------*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
#define kg_rdmsr_safe(msr, valp)    rdmsrq_safe((msr), (valp))
#define kg_wrmsr_safe(msr, val)     wrmsrq_safe((msr), (val))
#else
#define kg_rdmsr_safe(msr, valp)    rdmsrl_safe((msr), (valp))
#define kg_wrmsr_safe(msr, val)     wrmsrl_safe((msr), (val))
#endif

/*----------------------------------------------------------------------------
 * Detection thresholds (defaults; most are module parameters)
 *--------------------------------------------------------------------------*/
#define KG_PMU_DEF_PERIOD_L1D   100000UL    /* events per overflow (Windows: 50000) */
#define KG_PMU_DEF_PERIOD_LLC   20000UL
#define KG_PMU_DEF_WINDOW_MS    1000
#define KG_PMU_DEF_WARN_OVF     500         /* overflows per second, per CPU */
#define KG_PMU_DEF_CRIT_OVF     2000
#define KG_PMU_CALM_WINDOWS     3           /* quiet windows before de-escalating */
#define KG_HW_DEF_INTERVAL_MS   5000        /* Windows MONITOR_INTERVAL_MS */
#define KG_INTEG_DEF_INTERVAL_MS 30000      /* Windows integrity worker: 30 s */

/*----------------------------------------------------------------------------
 * Module parameters shared between files (defined in kg_main.c)
 *--------------------------------------------------------------------------*/
extern bool kg_enforce;                 /* allow active mitigations            */
extern bool kg_auto_enforce;            /* ...also once the posture reaches HIGH */
extern unsigned int kg_max_posture;     /* automatic raises stop at this posture */
extern unsigned int kg_posture_decay_s; /* ELEVATED -> NORMAL after this many quiet seconds */
extern char kg_kbd_allow[];             /* extra allowed input handler names   */
extern char kg_dma_allow[];             /* extra allowed PCI devices           */
#ifdef KG_TESTHOOKS
extern bool kg_test_bad_hmac;           /* test builds only: publish notifications with a wrong HMAC */
#endif
extern unsigned int kg_hw_interval_ms;
extern unsigned int kg_integ_interval_ms;
extern struct workqueue_struct *kg_wq;

/*----------------------------------------------------------------------------
 * Per-CPU mitigation descriptor (Windows: CPU_MITIGATIONS)
 *--------------------------------------------------------------------------*/
struct kg_cpu_mit {
	u32 features;                   /* KG_FEAT_* */
	u8  strategy;                   /* current KG_STRAT_* */
	u8  base_strategy;              /* chosen by the capability probe */
	u16 flush_cost_ns;
	u16 cat_ways;
	u16 pad;
	u32 cat_sens_cbm;
	u32 cat_def_cbm;
} __packed;

struct kg_guard_hdr {
	u32 magic;
	u32 abi;
	u32 ncpu;
	u32 failsafe;
	u32 posture;                    /* KG_POSTURE_*; FAILSAFE <=> failsafe != 0 */
} __packed;

/*
 * The integrity-protected part of the driver state (Windows: the region of
 * DRIVER_SHARED_STATE covered by StateHash).  Unlike the Windows layout, pure
 * statistics are kept OUT of the hashed region: they change constantly and
 * would make the hash mismatch on the first alert.
 */
struct kg_guard {
	struct kg_guard_hdr hdr;
	struct kg_cpu_mit  *cpu;        /* [hdr.ncpu], hashed */
	u8                  digest[32];
	bool                valid;
};
extern struct kg_guard kg_guard;

/*
 * Set (with preemption disabled) around the module's own cache-heavy loops -
 * the text-integrity memcmp streams tens of MiB through the caches, which is
 * precisely what Module 1 hunts for.  The PMU overflow handler ignores
 * overflows on a CPU while its flag is set, so the driver never alarms on itself.
 */
DECLARE_PER_CPU(bool, kg_self_busy);

/* Live statistics (atomic; NOT covered by the guard hash). */
struct kg_kstats {
	atomic64_t pmu_alert_level;
	atomic64_t pmu_l1d_overflows;
	atomic64_t pmu_llc_overflows;
	atomic64_t hw_discrepancy_count;
	atomic64_t hw_dma_violation_count;
	atomic64_t idt_hook_detected;
	atomic64_t dispatch_hook_detected;
	atomic64_t text_patch_detected;
	atomic64_t failed_module_hash_count;
	atomic64_t text_dynamic_patches;
	atomic64_t sens_page_count;
	atomic64_t active_mitigation_flags;
	atomic64_t total_flush_count;
	atomic64_t notifications_sent;
	atomic64_t fallback_signals_sent;
	atomic64_t notifications_dropped;
};
extern struct kg_kstats kg_stats;

#define kg_stat_inc(f)      atomic64_inc(&kg_stats.f)
#define kg_stat_add(f, n)   atomic64_add((n), &kg_stats.f)
#define kg_stat_set(f, v)   atomic64_set(&kg_stats.f, (v))
#define kg_stat_read(f)     ((u64)atomic64_read(&kg_stats.f))

/*----------------------------------------------------------------------------
 * Security-boundary flush (Windows: ExecuteSecurityBoundaryFlush + the MASM
 * PerformVerwFlush).  Safe in any context including NMI; touches only the
 * executing CPU.
 *
 * VERW must use the *memory-operand* form: only that form is documented to
 * trigger the MD_CLEAR buffer overwrite.  The kernel's own
 * x86_clear_cpu_buffers() does the same with __KERNEL_DS; any valid writable
 * data selector works.  (The Windows driver used the Ring-3 selector 0x2B.)
 *--------------------------------------------------------------------------*/
static __always_inline void kg_verw(void)
{
	static const u16 sel = __KERNEL_DS;

	asm volatile("mfence\n\t"
		     "verw %[sel]"
		     : : [sel] "m" (sel) : "cc", "memory");
}

static __always_inline void kg_l1d_flush(const struct kg_cpu_mit *m)
{
	if (m->features & KG_FEAT_L1D_FLUSH)
		kg_wrmsr_safe(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
}

static __always_inline void kg_boundary_flush(void)
{
	const struct kg_cpu_mit *m = &kg_guard.cpu[raw_smp_processor_id()];

	atomic64_inc(&kg_stats.total_flush_count);

	switch (READ_ONCE(m->strategy)) {
	case KG_STRAT_NONE:
		break;
	case KG_STRAT_VERW:
		kg_verw();
		break;
	case KG_STRAT_L1D:
		kg_l1d_flush(m);
		break;
	case KG_STRAT_VERW_L1D:
		kg_verw();
		kg_l1d_flush(m);
		break;
	case KG_STRAT_FULL:
		kg_verw();
		kg_l1d_flush(m);
		asm volatile("lfence" : : : "memory");   /* SPECULATION_BARRIER() */
		break;
	}
}

/*
 * Unconditional full flush for the PMU overflow handler (Windows PmiIsr flushes
 * VERW + L1D directly when the anomaly level is critical, independent of the
 * CPU's normal strategy).  NMI-safe.
 */
static __always_inline void kg_boundary_flush_forced(void)
{
	const struct kg_cpu_mit *m = &kg_guard.cpu[raw_smp_processor_id()];

	atomic64_inc(&kg_stats.total_flush_count);
	kg_verw();
	kg_l1d_flush(m);
	asm volatile("lfence" : : : "memory");
}

/* Constant-time comparison for every security-relevant secret/digest. */
#include <crypto/utils.h>
#define kg_ct_eq(a, b, len)     (!crypto_memneq((a), (b), (len)))

/*----------------------------------------------------------------------------
 * Alert plumbing (kg_state.c)
 *--------------------------------------------------------------------------*/
int  kg_state_init(void);
void kg_state_exit(void);

__printf(5, 6)
void kg_report(u32 type, u32 level, u64 p1, u64 p2, const char *fmt, ...);

bool kg_in_failsafe(void);
bool kg_guard_verify(void);
void kg_guard_update(void);
void kg_guard_lock_acquire(void);        /* policy mutation = lock, mutate, unlock_release */
void kg_guard_unlock_release(void);      /* re-hashes, then unlocks */
bool kg_list_contains(const char *csv, const char *name);

/*----------------------------------------------------------------------------
 * Graduated response (kg_posture.c)
 *--------------------------------------------------------------------------*/
void kg_posture_init(void);
void kg_posture_exit(void);
u32  kg_posture(void);
/* Automatic raise to at most @target (bounded by max_posture); @trigger is the KG_ALERT_* that asked. */
void kg_posture_raise(u32 target, u32 trigger);
/* Operator request (KG_IOC_SET_POSTURE): any posture, up or down.  Process context, CAP_SYS_ADMIN checked by the caller. */
int  kg_posture_set(u32 target);
void kg_posture_info(struct kg_posture_info *pi);
/* Scan interval to use right now for a configured @base_ms (shorter while ELEVATED or above). */
unsigned int kg_scan_ms(unsigned int base_ms);
/* Active enforcement: enforce=1, or auto_enforce=1 and the posture is HIGH or FAILSAFE. */
bool kg_enforcing(void);

/* Sensitive-allocation registry (Windows: SensAllocatePool / SensFreePool) */
void *kg_sens_alloc(size_t size, u8 flags);
void  kg_sens_free(void *ptr);
bool  kg_sens_pfn_tagged(unsigned long pfn);
#define KG_SENS_KEYSTROKE       0x01
#define KG_SENS_KEY_MATERIAL    0x02
#define KG_SENS_CRYPTO_IO       0x04

static inline void kg_pack_name(const char *s, u64 out[2])
{
	char b[16];

	strscpy_pad(b, s ? s : "", sizeof(b));
	memcpy(&out[0], b, 8);
	memcpy(&out[1], b + 8, 8);
}

/* SHA-256 helper backed by the crypto API (kg_state.c). */
int kg_sha256(const void *data, size_t len, u8 out[32]);

/*----------------------------------------------------------------------------
 * Module 4 - mitigation engine (kg_mitigate.c)
 *--------------------------------------------------------------------------*/
int  kg_mit_init(void);
void kg_mit_exit(void);
void kg_mit_escalate_cpu(int cpu);
void kg_mit_relax_cpu(int cpu);          /* back to the baseline, but never below the posture's floor */
void kg_mit_set_posture(u32 posture);    /* posture + fail-safe flag + every CPU's strategy, one critical section */
bool kg_mit_enter_failsafe(void);        /* true only for the caller that made the transition */
void kg_mit_flush_cpu(int cpu);          /* process context: flush @cpu per its strategy (FULL adds IBPB) */
void kg_mit_flush_siblings(int cpu);     /* escalate + flush the SMT siblings of @cpu                       */
void kg_mit_flush_all(void);
int  kg_mit_cpu_info(struct kg_cpu_info *ci);

/*----------------------------------------------------------------------------
 * Module 1 - PMU detection (kg_pmu.c)
 *--------------------------------------------------------------------------*/
int  kg_pmu_init(void);
void kg_pmu_exit(void);
bool kg_pmu_active(void);

/*----------------------------------------------------------------------------
 * Module 2 - hardware / keyboard-path detection (kg_hw.c, kg_input.c)
 *--------------------------------------------------------------------------*/
int  kg_hw_init(void);
void kg_hw_exit(void);
bool kg_hw_ecam_active(void);
unsigned int kg_hw_device_count(void);
void kg_hw_kick(void);                   /* schedule an immediate PCI/DMA audit */

int  kg_input_init(void);
void kg_input_exit(void);
void kg_input_kick(void);                /* schedule an immediate keyboard-path scan */
unsigned int kg_input_device_count(void);
bool kg_input_active(void);

/*----------------------------------------------------------------------------
 * Module 3 - kernel integrity (kg_integrity.c)
 *--------------------------------------------------------------------------*/
int  kg_integrity_init(void);
void kg_integrity_exit(void);
bool kg_addr_in_kernel_text(unsigned long addr);
bool kg_text_active(void);
void kg_integrity_kick(void);            /* schedule an immediate verification pass */
void kg_text_stats(unsigned int *regions, unsigned int *kib);
/*
 * Call @fn for every module that is LIVE now (except this one), outside the RCU read side and with the
 * module pinned, so @fn may sleep.  Modules beyond the first 1024 are skipped.  Returns -ENOMEM (and
 * calls @fn for nothing) when the scratch table cannot be allocated.  Process context.
 */
int  kg_for_each_live_module(void (*fn)(struct module *mod, void *arg), void *arg);

/*----------------------------------------------------------------------------
 * Module 3.5 - driver-load gate (kg_modgate.c)
 *--------------------------------------------------------------------------*/
int  kg_modgate_init(void);
void kg_modgate_exit(void);
void kg_modgate_info(struct kg_modgate_info *mi);

/*----------------------------------------------------------------------------
 * Module 5 - secure communication (kg_comms.c)
 *--------------------------------------------------------------------------*/
struct file;
struct poll_table_struct;
struct vm_area_struct;

int  kg_comms_init(void);
void kg_comms_exit(void);
int  kg_comms_notify(u32 type, u32 level, u64 p1, u64 p2);
int  kg_comms_get_key(u8 out[KG_HMAC_KEY_SIZE]);
int  kg_comms_mmap(struct vm_area_struct *vma);
__poll_t kg_comms_poll(struct file *file, struct poll_table_struct *wait);
void kg_comms_open(u32 *seen);
void kg_comms_set_device(struct device *dev);

/* kallsyms helper (kg_integrity.c): owning module of @addr, if any; *found = symbol resolved */
bool kg_sym_module(unsigned long addr, char *modname, size_t len, bool *found);

#endif /* _KG_H */
