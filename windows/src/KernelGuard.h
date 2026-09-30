// KernelGuard.h
// Master header for the KernelGuard driver.
// Windows 11 x64 WDK/KMDF, Ring 0, boot-start driver.
// Requires: ntddk.h, intrin.h, bcrypt.h, aux_klib.h

#pragma once

// Suppress PREfast C28xxx warnings emitted by the WDK headers themselves.
// C28301: Missing annotation on a re-declaration (wdm.h POOL_FLAGS typedef).
#pragma warning(push)
#pragma warning(disable: 28301)

#include <ntddk.h>
#include <intrin.h>
#include <stdarg.h>
#include <bcrypt.h>
#include <aux_klib.h>
#include <wdm.h>
#include <ntstrsafe.h>

#pragma warning(pop)

// IoDriverObjectType — exported from ntoskrnl but needs explicit extern in some WDK versions.
extern POBJECT_TYPE *IoDriverObjectType;

// IoThreadToProcess is declared in ntifs.h (FS filter header) but not ntddk.h.
// Declare it explicitly so drivers that include only ntddk.h can use it.
extern PEPROCESS IoThreadToProcess(_In_ PETHREAD Thread);

// PsGetThreadProcess — alternative documented API (ntddk.h may not expose it on all WDK builds).
extern PEPROCESS PsGetThreadProcess(_In_ PETHREAD Thread);

// ObReferenceObjectByName is undocumented; declare it for use in Module 3.
NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG           Attributes,
    PACCESS_STATE   AccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext,
    PVOID          *Object
);

//==============================================================================
// MSR Addresses (Intel SDM Vol.4 / AMD APM)
//==============================================================================

// Module 1 — PMU
#define MSR_IA32_PERFEVTSEL0        0x186UL
#define MSR_IA32_PERFEVTSEL1        0x187UL
#define MSR_IA32_PERFEVTSEL2        0x188UL
#define MSR_IA32_PERFEVTSEL3        0x189UL
#define MSR_IA32_PMC0               0x0C1UL
#define MSR_IA32_PMC1               0x0C2UL
#define MSR_IA32_PMC2               0x0C3UL
#define MSR_IA32_PMC3               0x0C4UL
#define MSR_IA32_PERF_GLOBAL_CTRL   0x38FUL
#define MSR_IA32_PERF_GLOBAL_STATUS 0x38EUL
#define MSR_IA32_PERF_GLOBAL_OVF    0x390UL
#define MSR_IA32_FIXED_CTR0         0x309UL
#define MSR_IA32_FIXED_CTR_CTRL     0x38DUL
#define MSR_IA32_APIC_BASE          0x1BUL

// Module 4 — Mitigation / Speculation Control
#define MSR_IA32_ARCH_CAPABILITIES  0x10AUL
#define MSR_IA32_SPEC_CTRL          0x48UL
#define MSR_IA32_PRED_CMD           0x49UL
#define MSR_IA32_FLUSH_CMD          0x10BUL
#define MSR_AMD_VIRT_SPEC_CTRL      0xC0011F00UL  // AMD VM speculation ctrl

// Module 4 — Intel CAT (Cache Allocation Technology)
#define MSR_IA32_PQR_ASSOC          0xC8FUL
#define MSR_IA32_L3_QOS_CFG         0xC81UL
#define MSR_IA32_L3_CBMBASE         0xC90UL       // + CLOS_id for each entry

// Module 5 — Covert signal MSR (read by user-mode helper driver)
#define MSR_COVERT_SIGNAL           0x150UL       // IA32_MCG_CAP — low-risk alias

//==============================================================================
// CPUID leaf / sub-leaf constants
//==============================================================================

#define CPUID_LEAF_STRUCTURED_EXT   0x07UL        // Structured Extended Features
#define CPUID_LEAF_ARCH_PERF_MON    0x0AUL        // Architectural PMU
#define CPUID_LEAF_RDT_ALLOC        0x10UL        // RDT Allocation (CAT)
#define CPUID_SUBLEAF_L3_CAT        0x01UL
#define CPUID_LEAF_EXT_TOPOLOGY     0x0BUL        // SMT / core topology

// CPUID.07.00 EDX bits
#define CPUID_EDX_IBRS_IBPB         (1 << 26)
#define CPUID_EDX_STIBP             (1 << 27)
#define CPUID_EDX_L1D_FLUSH         (1 << 28)
#define CPUID_EDX_ARCH_CAP          (1 << 29)
#define CPUID_EDX_SSBD              (1 << 31)
#define CPUID_EDX_MD_CLEAR          (1 << 10)

// IA32_ARCH_CAPABILITIES bits
#define ARCH_CAP_RDCL_NO            (1ULL << 0)
#define ARCH_CAP_IBRS_ALL           (1ULL << 1)
#define ARCH_CAP_RSBA               (1ULL << 2)
#define ARCH_CAP_SKIP_L1DFL_VMENTRY (1ULL << 3)
#define ARCH_CAP_MDS_NO             (1ULL << 5)
#define ARCH_CAP_L1TF_NO            (1ULL << 4)   // Not directly in this MSR; derived
#define ARCH_CAP_SSB_NO             (1ULL << 4)

//==============================================================================
// PMU Event Codes — Intel Skylake / Ice Lake
//==============================================================================

// MEM_LOAD_RETIRED.L1_MISS  (event=0xD1, umask=0x08)
#define PMU_EVT_L1D_MISS            ((ULONG64)0x08D1)
// L2_RQSTS.MISS             (event=0x24, umask=0x3F)
#define PMU_EVT_L2_MISS             ((ULONG64)0x3F24)
// PMU event select register bits
#define PERFEVT_USR                 (1ULL << 16)  // Count in Ring 3
#define PERFEVT_OS                  (1ULL << 17)  // Count in Ring 0
#define PERFEVT_PMI                 (1ULL << 20)  // PMI on overflow
#define PERFEVT_ENABLE              (1ULL << 22)  // Counter enable

// PMC is 48-bit on modern Intel CPUs
#define PMC_WIDTH_BITS              48ULL
#define PMC_MAX_VALUE               ((1ULL << PMC_WIDTH_BITS) - 1ULL)

//==============================================================================
// Detection thresholds (tunable)
//==============================================================================

#define L1D_MISS_THRESHOLD          50000UL       // PMC overflows per sample window
#define L2_MISS_THRESHOLD           20000UL
#define RDTSC_RATE_THRESHOLD        100000UL      // RDTSC traps/second from Ring 3
#define PMU_ALERT_OVERFLOW_COUNT    3UL           // Overflows before escalating

//==============================================================================
// APIC MMIO offsets (relative to APIC base, xAPIC mode)
//==============================================================================

#define APIC_EOI_OFFSET             0x0B0UL       // EOI register
#define APIC_LVT_PERF_OFFSET        0x340UL       // LVT Performance Counter
#define APIC_LVT_DELIVERY_FIXED     0x00000000UL
#define APIC_LVT_MASKED             0x00010000UL
#define PMI_IDT_VECTOR              0xE4UL        // Local APIC LVT Perf vector

//==============================================================================
// VT-d MMIO register offsets
//==============================================================================

#define VTD_VER_REG                 0x000UL
#define VTD_VER_REG                 0x000UL
#define VTD_CAP_REG                 0x008UL
#define VTD_ECAP_REG                0x010UL   // Extended Capability; bits[17:8]=IRO (IOTLB offset)
#define VTD_GCMD_REG                0x018UL
#define VTD_GSTS_REG                0x01CUL
#define VTD_RTADDR_REG              0x020UL
#define VTD_CCMD_REG                0x028UL   // Context Command: flush context cache
#define VTD_IOTLB_REG               0x108UL   // Default IOTLB invalidate register offset

// CCMD_REG command values (bits 63:62 = CIRG, bit 63 = IVT)
#define VTD_CCMD_GLOBAL_INVAL       (3ULL << 61)   // CIRG=11: global invalidation + IVT

// IOTLB invalidate register values (at ECAP.IRO*16+8)
#define VTD_IOTLB_GLOBAL_INVAL      (3ULL << 60)   // IIRG=11: global + IVT

//==============================================================================
// CPU feature bitmap (populated by ProbeCpuCapabilities)
//==============================================================================

#define CPU_FEAT_MDS_NO             0x0001UL
#define CPU_FEAT_L1TF_NO            0x0002UL
#define CPU_FEAT_RDCL_NO            0x0004UL
#define CPU_FEAT_IBRS_ALL           0x0008UL
#define CPU_FEAT_VERW_FLUSH         0x0010UL      // MD_CLEAR: VERW clears buffers
#define CPU_FEAT_L1D_FLUSH          0x0020UL      // IA32_FLUSH_CMD supported
#define CPU_FEAT_SSB_NO             0x0040UL
#define CPU_FEAT_IBPB               0x0080UL      // IA32_PRED_CMD IBPB
#define CPU_FEAT_CAT_L3             0x0100UL      // L3 Cache Allocation Technology
#define CPU_FEAT_SMT                0x0200UL      // SMT / Hyper-Threading present
#define CPU_FEAT_ARCH_CAP_MSR       0x0400UL      // IA32_ARCH_CAPABILITIES readable

//==============================================================================
// Alert type codes
//==============================================================================

#define ALERT_PMU_L1D_ANOMALY       0x0001UL
#define ALERT_PMU_L2_ANOMALY        0x0002UL
#define ALERT_PMU_RDTSC_RATE        0x0003UL
#define ALERT_UNAUTHORIZED_KBD_FILTER 0x0010UL
#define ALERT_UNAUTHORIZED_DMA      0x0011UL
#define ALERT_PCI_DISCREPANCY       0x0012UL
#define ALERT_KBD_FILTER_NEUTRALIZED  0x0013UL  // Dispatch table patched
#define ALERT_DMA_BLOCKED_IOMMU       0x0014UL  // VT-d context entry cleared
#define ALERT_DEVICE_BME_DISABLED     0x0015UL  // PCIe Bus Master Enable cleared
#define ALERT_IDT_HOOK              0x0020UL
#define ALERT_DISPATCH_HOOK         0x0021UL
#define ALERT_TEXT_PATCH            0x0022UL
#define ALERT_SHARED_STATE_CORRUPT  0x0030UL
#define ALERT_FAIL_SAFE_ENTERED     0x0031UL

//==============================================================================
// x64 IDT entry (16 bytes, Intel SDM Vol.3A §6.14)
//==============================================================================

#pragma pack(push, 1)
typedef struct _IDT_ENTRY_64 {
    USHORT  OffsetLow;      // Bits [15:0] of handler VA
    USHORT  Selector;       // Code segment selector
    UCHAR   IstIndex : 3;   // Interrupt Stack Table index (0 = none)
    UCHAR   Reserved1 : 5;
    UCHAR   GateType : 4;   // 0xE = 64-bit interrupt gate
    UCHAR   Reserved2 : 1;
    UCHAR   Dpl : 2;        // Descriptor Privilege Level
    UCHAR   Present : 1;    // Segment present flag
    USHORT  OffsetMid;      // Bits [31:16] of handler VA
    ULONG   OffsetHigh;     // Bits [63:32] of handler VA
    ULONG   Reserved3;
} IDT_ENTRY_64, *PIDT_ENTRY_64;

typedef struct _IDTR {
    USHORT  Limit;
    ULONG64 Base;
} IDTR, *PIDTR;
#pragma pack(pop)

//==============================================================================
// PCI / PCIe configuration space header (Type 0)
//==============================================================================

#pragma pack(push, 1)
typedef struct _PCI_CONFIG_HEADER {
    USHORT VendorId;
    USHORT DeviceId;
    USHORT Command;
    USHORT Status;
    UCHAR  RevisionId;
    UCHAR  ClassCode[3];    // [0]=ProgIF, [1]=SubClass, [2]=BaseClass
    UCHAR  CacheLineSize;
    UCHAR  LatencyTimer;
    UCHAR  HeaderType;
    UCHAR  Bist;
    ULONG  Bar[6];
    ULONG  CardbusCis;
    USHORT SubsystemVendorId;
    USHORT SubsystemDeviceId;
    ULONG  ExpansionRom;
    UCHAR  CapabilitiesPtr;
    UCHAR  Reserved[7];
    UCHAR  InterruptLine;
    UCHAR  InterruptPin;
    UCHAR  MinGnt;
    UCHAR  MaxLat;
} PCI_CONFIG_HEADER, *PPCI_CONFIG_HEADER;
#pragma pack(pop)

//==============================================================================
// VT-d page table structures
//==============================================================================

#pragma pack(push, 1)
typedef struct _VTD_ROOT_ENTRY {
    ULONG64 Present        : 1;
    ULONG64 Reserved0      : 11;
    ULONG64 ContextTablePtr: 52;  // PFN of context table
    ULONG64 Reserved1;
} VTD_ROOT_ENTRY, *PVTD_ROOT_ENTRY;

typedef struct _VTD_CONTEXT_ENTRY {
    ULONG64 Present            : 1;
    ULONG64 FaultProcessing    : 1;
    ULONG64 Reserved0          : 6;
    ULONG64 SlptPtr            : 52; // Second-level page table ptr
    ULONG64 DomainId           : 16;
    ULONG64 Reserved1          : 48;
} VTD_CONTEXT_ENTRY, *PVTD_CONTEXT_ENTRY;
#pragma pack(pop)

//==============================================================================
// PMU context (one per logical processor, non-paged)
//==============================================================================

typedef struct _PMU_CONTEXT {
    volatile LONG   L1DMissOverflows;   // PMC0 overflow count
    volatile LONG   L2MissOverflows;    // PMC1 overflow count
    volatile LONG   AlertLevel;         // 0=normal, 1=watch, 2=critical
    ULONG           CpuIndex;
    ULONG           PmiVector;
    PVOID           ApicVaBase;         // Pre-mapped APIC MMIO VA (non-paged)
    PKINTERRUPT     PmiInterruptObject;
} PMU_CONTEXT, *PPMU_CONTEXT;

//==============================================================================
// RDTSC profiling (per Ring-3 process)
//==============================================================================

#define MAX_PROFILED_PROCS 256

typedef struct _RDTSC_PROFILE {
    HANDLE  ProcessId;
    LONG    RdtscCount;
    ULONG   WindowStartTick;
    BOOLEAN IsFlagged;
} RDTSC_PROFILE, *PRDTSC_PROFILE;

//==============================================================================
// PCIe discovered device entry
//==============================================================================

#define MAX_PCI_DEVICES 512

typedef struct _PCI_DISCOVERY_ENTRY {
    UCHAR   Bus, Device, Function;
    USHORT  VendorId, DeviceId;
    UCHAR   BaseClass, SubClass;
    BOOLEAN IsKeyboardRelated;
    BOOLEAN DmaCapable;
} PCI_DISCOVERY_ENTRY, *PPCI_DISCOVERY_ENTRY;

//==============================================================================
// Kernel integrity baseline entry
//==============================================================================

#define MAX_BASELINE_ENTRIES 128
#define HASH_CHUNK_SIZE      (64 * 1024)  // 64 KB per BCrypt hash call

typedef struct _BASELINE_ENTRY {
    WCHAR   ModuleName[64];
    ULONG64 TextSectionBase;
    ULONG   TextSectionSize;
    UCHAR   Sha256Hash[32];
    BOOLEAN Verified;
    BOOLEAN HashComputed;
} BASELINE_ENTRY, *PBASELINE_ENTRY;

//==============================================================================
// Hook detection signatures
//==============================================================================

#define MAX_HOOK_PATTERNS 6

typedef struct _HOOK_SIGNATURE {
    UCHAR Pattern[8];
    UCHAR Mask[8];          // 1 = byte must match, 0 = wildcard
    CHAR  Description[48];
} HOOK_SIGNATURE;

//==============================================================================
// Sensitive page registry
//==============================================================================

#define MAX_SENSITIVE_PAGES 65536

#define SENS_FLAG_KEYSTROKE     0x01
#define SENS_FLAG_KEY_MATERIAL  0x02
#define SENS_FLAG_CRYPTO_IO     0x04
#define SENS_FLAG_CROSS_BOUND   0x08
#define SENS_FLAG_MULTI_MAP     0x10

typedef struct _SENS_PAGE_ENTRY {
    ULONG64 PageFrameNumber;
    UCHAR   SensitivityFlags;
    ULONG   OwningProcessId;
} SENS_PAGE_ENTRY, *PSENS_PAGE_ENTRY;

//==============================================================================
// Mitigation strategy
//==============================================================================

typedef enum _MITIGATION_STRATEGY {
    MitigateNone = 0,
    MitigateVerwOnly,       // VERW sufficient (MDS only, no L1TF)
    MitigateL1dFlushOnly,   // L1D flush only (L1TF only, no MDS)
    MitigateVerwPlusL1d,    // VERW + L1D flush (both MDS & L1TF)
    MitigateFullSpectrum    // All mitigations
} MITIGATION_STRATEGY;

typedef struct _CPU_MITIGATIONS {
    ULONG               Features;       // CPU_FEAT_* bitmap
    MITIGATION_STRATEGY Strategy;
    USHORT              VerwSelector;   // Selector for VERW (0x2B = Ring3 DS)
    ULONG               FlushCostNs;    // Estimated cost in nanoseconds
} CPU_MITIGATIONS, *PCPU_MITIGATIONS;

//==============================================================================
// CAT (Cache Allocation Technology) configuration
//==============================================================================

typedef struct _CAT_CONFIG {
    BOOLEAN Enabled;
    ULONG   TotalCacheWays;
    ULONG   SensitiveWays;
    ULONG   SensitiveClos;  // CLOS for sensitive code/data
    ULONG   DefaultClos;    // CLOS for everything else
    ULONG64 SensitiveCbm;
    ULONG64 DefaultCbm;
} CAT_CONFIG, *PCAT_CONFIG;

//==============================================================================
// SMT topology map
//==============================================================================

typedef struct _SMT_SIBLING {
    ULONG   LogicalProcessor;
    ULONG   SiblingProcessor;   // MAXULONG if no SMT sibling
    BOOLEAN IsSensitiveRunning;
} SMT_SIBLING, *PSMT_SIBLING;

//==============================================================================
// Secure communication — shared memory layout
//==============================================================================

#define NOTIFICATION_SLOTS  16
#define HMAC_KEY_SIZE       32
#define NOTIFY_MAGIC        0xDEADC0DEUL
#define SIGNAL_MAGIC        0xCAFEBABEUL

typedef struct _SECURE_NOTIFICATION {
    ULONG   Magic;
    ULONG   SequenceNumber;
    ULONG   AlertType;
    ULONG   AlertLevel;
    ULONG64 Timestamp;
    ULONG64 Param1;
    ULONG64 Param2;
    UCHAR   Hmac[32];
} SECURE_NOTIFICATION, *PSECURE_NOTIFICATION;

typedef struct _SHARED_MEM_REGION {
    volatile ULONG      WriteIndex;
    volatile ULONG      ReadIndex;
    volatile ULONG      DriverNonce;
    ULONG               Reserved;
    SECURE_NOTIFICATION Notifications[NOTIFICATION_SLOTS];
} SHARED_MEM_REGION, *PSHARED_MEM_REGION;

//==============================================================================
// Shared driver state (cross-module, integrity-verified)
//==============================================================================

typedef struct _DRIVER_SHARED_STATE {
    // Module 1
    volatile LONG   PmuAlertLevel;
    volatile LONG   PmuL1DOverflows;
    volatile LONG   PmuL2Overflows;
    volatile LONG   PmuRdtscFlaggedPid;

    // Module 2
    volatile LONG   HwDiscrepancyCount;
    volatile LONG   HwDmaViolationCount;

    // Module 3
    volatile LONG   IdtHookDetected;
    volatile LONG   DispatchHookDetected;
    volatile LONG   TextPatchDetected;
    ULONG           FailedModuleHashCount;

    // Module 4
    volatile LONG   SensPageCount;
    volatile LONG   ActiveMitigationFlags;
    volatile LONG   TotalFlushCount;
    ULONG           CurrentClos;

    // Module 5
    volatile LONG   NotificationsSent;
    volatile LONG   MsrSignalsSent;

    // Integrity
    KSPIN_LOCK      StateLock;
    BOOLEAN         FailSafeMode;
    BOOLEAN         IntegrityValid;
    UCHAR           StateHash[32];  // SHA-256 of everything above
} DRIVER_SHARED_STATE, *PDRIVER_SHARED_STATE;

//==============================================================================
// Global state declarations (defined in shared_state.c)
//==============================================================================

extern DRIVER_SHARED_STATE g_SharedState;
extern PMU_CONTEXT         g_PmuCtx[MAXIMUM_PROCESSORS];
extern RDTSC_PROFILE       g_RdtscProfiles[MAX_PROFILED_PROCS];
extern KSPIN_LOCK          g_RdtscLock;
extern PCI_DISCOVERY_ENTRY g_PciDevices[MAX_PCI_DEVICES];
extern ULONG               g_PciDeviceCount;
extern PHYSICAL_ADDRESS    g_EcamBase;
extern BASELINE_ENTRY      g_Baseline[MAX_BASELINE_ENTRIES];
extern ULONG               g_BaselineCount;
extern SENS_PAGE_ENTRY     g_SensPages[MAX_SENSITIVE_PAGES];
extern ULONG               g_SensPageCount;
extern KSPIN_LOCK          g_SensLock;
extern CPU_MITIGATIONS     g_CpuMit[MAXIMUM_PROCESSORS];
extern CAT_CONFIG          g_CatConfig;
extern SMT_SIBLING         g_SmtMap[MAXIMUM_PROCESSORS];
extern PSHARED_MEM_REGION  g_SharedMemKernel;
extern UCHAR               g_HmacKey[HMAC_KEY_SIZE];
extern PUCHAR              g_KbdRingBuffer;
extern volatile ULONG      g_KbdWriteIdx;

#define KBD_RING_SIZE 256

//==============================================================================
// Function prototypes — Module 1 (PMU detection)
//==============================================================================

NTSTATUS PmuInitialize(VOID);
VOID     PmuUninitialize(VOID);
NTSTATUS PmuConfigureOnCpu(ULONG CpuIndex);
BOOLEAN  PmiIsr(PKINTERRUPT Interrupt, PVOID Context);
VOID     EnableTSD(VOID);
VOID     DisableTSD(VOID);

//==============================================================================
// Function prototypes — Module 2 (hardware keylogger)
//==============================================================================

NTSTATUS HwKeyloggerInitialize(VOID);
VOID     HwKeyloggerUninitialize(VOID);
NTSTATUS PciWalkBusTree(VOID);
NTSTATUS PciDetectDiscrepancies(VOID);
NTSTATUS VtdVerifyDmaProtection(VOID);

//==============================================================================
// Function prototypes — Module 3 (kernel integrity)
//==============================================================================

NTSTATUS KernelIntegrityInitialize(VOID);
VOID     KernelIntegrityUninitialize(VOID);
NTSTATUS IdtVerifyKeyboardHandler(ULONG CpuIndex);
NTSTATUS ScanKeyboardDrivers(VOID);
NTSTATUS BuildIntegrityBaseline(VOID);
NTSTATUS VerifyModuleIntegrity(PBASELINE_ENTRY Entry);
NTSTATUS ComputeSha256(PVOID Address, ULONG Size, UCHAR HashOut[32]);

//==============================================================================
// Function prototypes — Module 4 (cache mitigation)
//==============================================================================

NTSTATUS CacheMitigationInitialize(VOID);
VOID     CacheMitigationUninitialize(VOID);
NTSTATUS ProbeCpuCapabilities(ULONG CpuIndex);
PVOID    SensAllocatePool(POOL_TYPE PoolType, SIZE_T Size, ULONG Tag, UCHAR Flags);
VOID     SensFreePool(PVOID Ptr, ULONG Tag);
BOOLEAN  IsProcessSensitive(HANDLE ProcessId);

VOID     EnableSpeculationControls(ULONG CpuIndex);
VOID     DisableSpeculationControls(ULONG CpuIndex);
NTSTATUS CatInitialize(ULONG CpuIndex);
FORCEINLINE VOID CatAssignClos(ULONG ClosId);
NTSTATUS SmtBuildTopology(VOID);
VOID     SmtSiblingFlushDpc(PKDPC Dpc, PVOID Ctx, PVOID Arg1, PVOID Arg2);

FORCEINLINE ULONG SafeArrayIndex(ULONG Index, ULONG ArraySize);
FORCEINLINE NTSTATUS SafeAccessUserPointer(PVOID UserPtr, PVOID KernelBuf,
                                           ULONG Size, BOOLEAN IsSensitive);

//==============================================================================
// Function prototypes — Module 5 (secure comms)
//==============================================================================

NTSTATUS SecureCommInitialize(VOID);
VOID     SecureCommUninitialize(VOID);
NTSTATUS SecureCommMapToUserMode(PVOID *UserMapping);
NTSTATUS SecureCommNotify(ULONG AlertType, ULONG AlertLevel,
                          ULONG64 Param1, ULONG64 Param2);
VOID     SecureCommMsrSignal(ULONG AlertType);
VOID     SecureCommMsrClear(VOID);

//==============================================================================
// Function prototypes — Shared state / event dispatch
//==============================================================================

VOID     LogAlert(ULONG AlertType, PCSTR Format, ...);
VOID     DispatchCrossModuleEvent(ULONG AlertType, ULONG AlertLevel,
                                  ULONG64 Param1, ULONG64 Param2);
BOOLEAN  VerifySharedStateIntegrity(VOID);
VOID     UpdateSharedStateHash(VOID);
VOID     EnterFailSafeMode(VOID);
BOOLEAN  IsWhitelistedDriver(PUNICODE_STRING DriverName);
BOOLEAN  IsAuthorizedDmaDevice(UCHAR Bus, UCHAR Device, UCHAR Function);

//==============================================================================
// External MASM function (verw_flush.asm)
//==============================================================================

VOID PerformVerwFlush(VOID);   // Executes MFENCE + VERW with Ring3 DS selector

//==============================================================================
// Helper macros
//==============================================================================

#define SPECULATION_BARRIER()   _mm_lfence()
#define MEMORY_BARRIER()        _mm_mfence()

// Constant-time comparison — avoids timing-based info leak
#define CONSTANT_TIME_EQ(a, b, len)  ConstantTimeMemEq((a), (b), (len))

FORCEINLINE BOOLEAN ConstantTimeMemEq(const UCHAR *a, const UCHAR *b, ULONG len)
{
    ULONG diff = 0;
    for (ULONG i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return (BOOLEAN)(diff == 0);
}

// Defined here (after PerformVerwFlush + SPECULATION_BARRIER) so the body is
// visible in every TU that includes this header — required for FORCEINLINE.
FORCEINLINE VOID ExecuteSecurityBoundaryFlush(ULONG CpuIndex)
{
    PCPU_MITIGATIONS mit = &g_CpuMit[CpuIndex];
    InterlockedIncrement(&g_SharedState.TotalFlushCount);

    switch (mit->Strategy) {
    case MitigateNone:
        break;
    case MitigateVerwOnly:
        PerformVerwFlush();
        break;
    case MitigateL1dFlushOnly:
        if (mit->Features & CPU_FEAT_L1D_FLUSH)
            __writemsr(MSR_IA32_FLUSH_CMD, 1ULL);
        break;
    case MitigateVerwPlusL1d:
        PerformVerwFlush();
        if (mit->Features & CPU_FEAT_L1D_FLUSH)
            __writemsr(MSR_IA32_FLUSH_CMD, 1ULL);
        break;
    case MitigateFullSpectrum:
        PerformVerwFlush();
        if (mit->Features & CPU_FEAT_L1D_FLUSH)
            __writemsr(MSR_IA32_FLUSH_CMD, 1ULL);
        SPECULATION_BARRIER();
        break;
    }
}

// Kernel base / size helpers
ULONG64 GetNtoskrnlBase(VOID);
ULONG   GetNtoskrnlSize(VOID);
