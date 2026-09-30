/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * kernelguard_uapi.h - ABI shared by the KernelGuard kernel module and the
 * user-space monitor (kgmon).  Linux counterpart of windows/usermode/kg_shared.h.
 *
 * The notification wire format is byte-identical to the Windows driver's
 * SECURE_NOTIFICATION / SHARED_MEM_REGION so that one protocol description
 * covers both ports, and the alert codes keep their Windows numeric values.
 */
#ifndef _UAPI_KERNELGUARD_H
#define _UAPI_KERNELGUARD_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define KG_ABI_VERSION          1
#define KG_DEV_NAME             "kernelguard"       /* /dev/kernelguard */

#define KG_NOTIFY_SLOTS         16
#define KG_HMAC_KEY_SIZE        32
#define KG_HMAC_SIZE            32
#define KG_NOTIFY_MAGIC         0xDEADC0DEu

/* Alert levels */
#define KG_LEVEL_INFO           0
#define KG_LEVEL_WATCH          1
#define KG_LEVEL_CRITICAL       2

/*
 * Alert codes.  Values 0x0001..0x0031 are identical to the Windows driver.
 * 0x0023..0x0025 are Linux additions in the Module 3 range.
 *
 * Parameter conventions (Param1 / Param2):
 *   PMU_L1D/L2_ANOMALY   offender tgid (0 = unknown) / (cpu << 32) | overflows-per-second
 *   PMU_RDTSC_RATE       reserved - never emitted on Linux (see README)
 *   UNAUTHORIZED_KBD_FILTER, KBD_FILTER_NEUTRALIZED
 *                        handler name, first 16 bytes NUL-padded (Param1 = bytes 0-7)
 *   UNAUTHORIZED_DMA, DEVICE_BME_DISABLED
 *                        (segment << 24) | (bus << 16) | (dev << 8) | fn  /  (vendor << 16) | device
 *   PCI_DISCREPANCY      same BDF packing / (kind << 32) | (vendor << 16) | device
 *   IDT_HOOK             handler address / vector
 *   DISPATCH_HOOK        callback address / (kind << 32) - see kg_input.c
 *   TEXT_PATCH           address of first mismatch / (flags << 32) | run length
 *   CTRL_REG_TAMPER      (cpu << 32) | register id  /  new value
 *   MODULE_LOADED        module name bytes 0-7 / bytes 8-15
 *   SHARED_STATE_CORRUPT, FAIL_SAFE_ENTERED  0 / 0
 */
#define KG_ALERT_PMU_L1D_ANOMALY            0x0001u
#define KG_ALERT_PMU_L2_ANOMALY             0x0002u
#define KG_ALERT_PMU_RDTSC_RATE             0x0003u
#define KG_ALERT_UNAUTHORIZED_KBD_FILTER    0x0010u
#define KG_ALERT_UNAUTHORIZED_DMA           0x0011u
#define KG_ALERT_PCI_DISCREPANCY            0x0012u
#define KG_ALERT_KBD_FILTER_NEUTRALIZED     0x0013u
#define KG_ALERT_DMA_BLOCKED_IOMMU          0x0014u  /* not emitted on Linux */
#define KG_ALERT_DEVICE_BME_DISABLED        0x0015u
#define KG_ALERT_IDT_HOOK                   0x0020u
#define KG_ALERT_DISPATCH_HOOK              0x0021u
#define KG_ALERT_TEXT_PATCH                 0x0022u
#define KG_ALERT_CTRL_REG_TAMPER            0x0023u  /* Linux addition */
#define KG_ALERT_MODULE_LOADED              0x0024u  /* Linux addition */
#define KG_ALERT_SHARED_STATE_CORRUPT       0x0030u
#define KG_ALERT_FAIL_SAFE_ENTERED          0x0031u

/* Flags packed into the high half of TEXT_PATCH Param2 */
#define KG_TEXTF_KERNEL         0x1u    /* region is the core kernel image */
#define KG_TEXTF_UNKNOWN_TARGET 0x2u    /* new branch target is outside known code */
#define KG_TEXTF_BREAKPOINT     0x4u    /* looks like an int3 (kprobe-style) patch */

/* Kinds for PCI_DISCREPANCY Param2 high half */
#define KG_PCI_HIDDEN_FROM_OS   1u      /* answers in ECAM, unknown to the PCI core */
#define KG_PCI_MISSING_IN_HW    2u      /* known to the PCI core, silent in ECAM    */
#define KG_PCI_IDENTITY_MISMATCH 3u     /* vendor/device/class differ between views */

/*
 * One authenticated notification.  HMAC-SHA256 covers bytes [0, 40) using the
 * per-boot key returned by KG_IOC_GET_HMAC_KEY.  Every field is naturally
 * aligned, so the layout (72 bytes, hmac at offset 40) is identical to the
 * Windows #pragma pack(1) definition; both sides static-assert this.
 */
struct kg_notification {
	__u32 magic;            /* KG_NOTIFY_MAGIC while valid, 0 while being written */
	__u32 sequence;         /* monotonically increasing, never reused             */
	__u32 alert_type;       /* KG_ALERT_*                                         */
	__u32 alert_level;      /* KG_LEVEL_*                                         */
	__u64 timestamp;        /* CLOCK_REALTIME nanoseconds                         */
	__u64 param1;
	__u64 param2;
	__u8  hmac[KG_HMAC_SIZE];
};

/*
 * Ring shared read-only with user space through mmap() of /dev/kernelguard.
 * Notification N lives in slot (N % KG_NOTIFY_SLOTS).  A reader that finds
 * write_index - cursor > KG_NOTIFY_SLOTS has been lapped and lost entries.
 * Slot validity is seqlock-style: 'magic' is 0 while the kernel rewrites it.
 */
struct kg_shared_region {
	__u32 write_index;      /* number of notifications published so far */
	__u32 read_index;       /* unused (kept for Windows layout parity)  */
	__u32 driver_nonce;     /* next sequence number to hand out         */
	__u32 reserved;
	struct kg_notification notifications[KG_NOTIFY_SLOTS];
};

#define KG_HMAC_AUTH_LEN        40      /* offsetof(struct kg_notification, hmac) */

/* Statistics block: Linux counterpart of DRIVER_SHARED_STATE's counters. */
struct kg_stats {
	__u64 pmu_alert_level;          /* highest current level over all CPUs  */
	__u64 pmu_l1d_overflows;
	__u64 pmu_llc_overflows;
	__u64 hw_discrepancy_count;
	__u64 hw_dma_violation_count;
	__u64 idt_hook_detected;
	__u64 dispatch_hook_detected;
	__u64 text_patch_detected;
	__u64 failed_module_hash_count;
	__u64 text_dynamic_patches;     /* benign NOP<->CALL/JMP patch sites accepted */
	__u64 sens_page_count;
	__u64 active_mitigation_flags;  /* KG_MIT_* */
	__u64 total_flush_count;
	__u64 notifications_sent;
	__u64 fallback_signals_sent;
	__u64 notifications_dropped;    /* rate limited (never critical ones) */
};

/* active_mitigation_flags */
#define KG_MIT_VERW             0x01u
#define KG_MIT_L1D_FLUSH        0x02u
#define KG_MIT_IBPB             0x04u
#define KG_MIT_FAIL_SAFE        0x08u

/* kg_info.flags */
#define KG_INFO_ENFORCE         (1ull << 0)
#define KG_INFO_FAIL_SAFE       (1ull << 1)
#define KG_INFO_INTEGRITY_OK    (1ull << 2)
#define KG_INFO_PMU_ACTIVE      (1ull << 3)
#define KG_INFO_ECAM_ACTIVE     (1ull << 4)
#define KG_INFO_TEXT_ACTIVE     (1ull << 5)
#define KG_INFO_INPUT_ACTIVE    (1ull << 6)
#define KG_INFO_CAT_L3          (1ull << 7)     /* L3 CAT present (managed via resctrl) */
#define KG_INFO_SMT             (1ull << 8)

/* Mitigation strategies (per logical CPU) */
#define KG_STRAT_NONE           0
#define KG_STRAT_VERW           1
#define KG_STRAT_L1D            2
#define KG_STRAT_VERW_L1D       3
#define KG_STRAT_FULL           4

struct kg_info {
	__u32 abi_version;
	__u32 struct_size;
	__u32 ring_slots;
	__u32 nr_cpus;                  /* possible CPUs covered by KG_IOC_GET_CPU_INFO */
	__u64 flags;                    /* KG_INFO_* */
	__u32 text_regions;             /* regions under text-integrity monitoring */
	__u32 text_kib;                 /* KiB of baseline text held */
	__u32 pci_devices;              /* devices seen in the ECAM walk */
	__u32 kbd_devices;              /* keyboards being audited */
	struct kg_stats stats;
	char  version[32];
};

struct kg_cpu_info {
	__u32 cpu;                      /* in: logical CPU index               */
	__u32 online;                   /* out                                  */
	__u32 features;                 /* out: KG_FEAT_*                       */
	__u32 strategy;                 /* out: current KG_STRAT_*              */
	__u32 base_strategy;            /* out: strategy chosen at probe time   */
	__u32 flush_cost_ns;            /* out: estimated boundary-flush cost   */
	__u32 cat_ways;                 /* out: L3 CAT ways (0 = none)          */
	__u32 cat_sensitive_cbm;        /* out: suggested resctrl mask          */
	__u32 cat_default_cbm;
	__u32 pad;
};

/* kg_cpu_info.features */
#define KG_FEAT_MDS_NO          0x0001u
#define KG_FEAT_L1TF_NO         0x0002u
#define KG_FEAT_RDCL_NO         0x0004u
#define KG_FEAT_IBRS_ALL        0x0008u
#define KG_FEAT_VERW_FLUSH      0x0010u /* MD_CLEAR: VERW clears buffers */
#define KG_FEAT_L1D_FLUSH       0x0020u /* IA32_FLUSH_CMD present        */
#define KG_FEAT_SSB_NO          0x0040u
#define KG_FEAT_IBPB            0x0080u
#define KG_FEAT_CAT_L3          0x0100u
#define KG_FEAT_SMT             0x0200u
#define KG_FEAT_ARCH_CAP_MSR    0x0400u

struct kg_hmac_key {
	__u8 key[KG_HMAC_KEY_SIZE];
};

#define KG_IOC_MAGIC            'K'
#define KG_IOC_GET_HMAC_KEY     _IOR(KG_IOC_MAGIC, 0x01, struct kg_hmac_key)
#define KG_IOC_GET_INFO         _IOR(KG_IOC_MAGIC, 0x02, struct kg_info)
#define KG_IOC_GET_CPU_INFO     _IOWR(KG_IOC_MAGIC, 0x03, struct kg_cpu_info)

#endif /* _UAPI_KERNELGUARD_H */
