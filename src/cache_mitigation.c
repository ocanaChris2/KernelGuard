// cache_mitigation.c
// Module 4: Crypto-Agnostic Memory and Cache Mitigation Engine.
//
// Subsystems:
//   4a  Sensitive memory identification and isolation (KPTI-style PTE removal)
//   4b  Security-boundary cache and microarchitectural buffer flushing
//       (VERW + L1D flush, strategy selected from CPU capability probing)
//   4c  Speculation and transient-execution controls (IBRS, STIBP, IBPB,
//       LFENCE speculation barriers, safe array index)
//   4d  L3 cache partitioning via Intel CAT
//   4e  SMT/Hyper-Threading mitigation (sibling-core flush DPC)
//
// Key design principle:
//   ExecuteSecurityBoundaryFlush() is FORCEINLINE and calls only the MASM
//   PerformVerwFlush() and MSR writes. It is safe at any IRQL.

#include "KernelGuard.h"

#pragma alloc_text(PAGE, CacheMitigationInitialize)
#pragma alloc_text(PAGE, CacheMitigationUninitialize)
#pragma alloc_text(PAGE, ProbeCpuCapabilities)
#pragma alloc_text(PAGE, CatInitialize)
#pragma alloc_text(PAGE, SmtBuildTopology)
#pragma alloc_text(PAGE, SensAllocatePool)
#pragma alloc_text(PAGE, SensFreePool)

// Forward declarations for functions defined later in this file.
static BOOLEAN  SensIsPageTagged(ULONG64 pfn);
NTSTATUS SmtIsolateSensitiveProcess(HANDLE ProcessId);   // defined below

//==============================================================================
// ProbeCpuCapabilities
// Reads CPUID and IA32_ARCH_CAPABILITIES MSR to determine which
// microarchitectural vulnerabilities are present and selects the cheapest
// safe mitigation strategy.
// Must run on each logical processor (called via KeIpiGenericCall).
//==============================================================================

NTSTATUS ProbeCpuCapabilities(ULONG CpuIndex)
{
    PAGED_CODE();

    PCPU_MITIGATIONS mit = &g_CpuMit[CpuIndex];
    mit->Features = 0;

    // ── CPUID leaf 7, sub-leaf 0 (Structured Extended Feature Flags) ────────
    int cpuid7[4] = {0};
    __cpuidex(cpuid7, CPUID_LEAF_STRUCTURED_EXT, 0);

    // EDX bit 26: IBRS and IBPB support
    if (cpuid7[3] & CPUID_EDX_IBRS_IBPB)   mit->Features |= CPU_FEAT_IBRS_ALL;
    // EDX bit 10: MD_CLEAR — VERW clears microarchitectural buffers
    if (cpuid7[3] & CPUID_EDX_MD_CLEAR)     mit->Features |= CPU_FEAT_VERW_FLUSH;
    // EDX bit 28: IA32_FLUSH_CMD MSR supported
    if (cpuid7[3] & CPUID_EDX_L1D_FLUSH)    mit->Features |= CPU_FEAT_L1D_FLUSH;
    // EDX bit 29: IA32_ARCH_CAPABILITIES MSR readable
    if (cpuid7[3] & CPUID_EDX_ARCH_CAP)     mit->Features |= CPU_FEAT_ARCH_CAP_MSR;

    // ── IA32_ARCH_CAPABILITIES (if available) ───────────────────────────────
    if (mit->Features & CPU_FEAT_ARCH_CAP_MSR) {
        ULONG64 archCap = __readmsr(MSR_IA32_ARCH_CAPABILITIES);
        if (archCap & ARCH_CAP_RDCL_NO)  mit->Features |= CPU_FEAT_RDCL_NO;
        if (archCap & ARCH_CAP_MDS_NO)   mit->Features |= CPU_FEAT_MDS_NO;
        if (archCap & ARCH_CAP_IBRS_ALL) mit->Features |= CPU_FEAT_IBRS_ALL;
        if (archCap & ARCH_CAP_SSB_NO)   mit->Features |= CPU_FEAT_SSB_NO;
        // L1TF_NO is derived: if RDCL_NO is set, the CPU is not vulnerable
        // to L1TF through direct memory access.
        if (archCap & ARCH_CAP_RDCL_NO)  mit->Features |= CPU_FEAT_L1TF_NO;
    }

    // ── CPUID leaf 0x10 (CAT / RDT Allocation) ──────────────────────────────
    int cpuid10[4] = {0};
    __cpuidex(cpuid10, CPUID_LEAF_RDT_ALLOC, 0);
    if (cpuid10[1] & (1 << 1))  // EBX bit 1: L3 CAT supported
        mit->Features |= CPU_FEAT_CAT_L3;

    // ── SMT detection via CPUID leaf 0x0B (extended topology) ───────────────
    int cpuid0b[4] = {0};
    __cpuidex(cpuid0b, CPUID_LEAF_EXT_TOPOLOGY, 0);
    ULONG smtShift = cpuid0b[0] & 0x1F;
    if (smtShift > 0)
        mit->Features |= CPU_FEAT_SMT;

    // ── Select cheapest safe mitigation strategy ────────────────────────────
    BOOLEAN mdsVuln  = !(mit->Features & CPU_FEAT_MDS_NO);
    BOOLEAN l1tfVuln = !(mit->Features & CPU_FEAT_L1TF_NO);

    if (!mdsVuln && !l1tfVuln) {
        mit->Strategy     = MitigateNone;
        mit->FlushCostNs  = 0;
    } else if (mdsVuln && !l1tfVuln) {
        // VERW is sufficient for MDS; no L1TF concern.
        mit->Strategy     = MitigateVerwOnly;
        mit->FlushCostNs  = 50;
    } else if (!mdsVuln && l1tfVuln) {
        // L1D flush needed; VERW alone doesn't help L1TF.
        mit->Strategy     = MitigateL1dFlushOnly;
        mit->FlushCostNs  = 200;
    } else {
        // Both MDS and L1TF vulnerable.
        if (mit->Features & CPU_FEAT_VERW_FLUSH) {
            mit->Strategy    = MitigateVerwPlusL1d;
            mit->FlushCostNs = 250;
        } else {
            mit->Strategy    = MitigateFullSpectrum;
            mit->FlushCostNs = 500;
        }
    }

    // Ring-3 data segment selector for VERW operand (0x2B on all x64 Windows).
    mit->VerwSelector = 0x2B;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] CPU%u: features=0x%04X strategy=%d costNs=%u\n",
               CpuIndex, mit->Features, mit->Strategy, mit->FlushCostNs);
    return STATUS_SUCCESS;
}


//==============================================================================
// SafeArrayIndex
// Constant-time bounds masking to prevent Spectre variant 1 gadgets.
// If Index >= ArraySize, the mask evaluates to 0 (not 0xFFFFFFFF), so
// the resulting index is 0 — a valid in-bounds access.
// The CPU cannot speculate past an index that resolves to 0.
//==============================================================================

FORCEINLINE ULONG SafeArrayIndex(ULONG Index, ULONG ArraySize)
{
    // Cast to LONG first to avoid C4146 (unary minus on unsigned).
    // Result: 0x00000000 when Index >= ArraySize, 0xFFFFFFFF otherwise.
    ULONG valid = (ULONG)(Index < ArraySize);
    ULONG mask  = (ULONG)(-(LONG)valid);
    return Index & mask;
}

//==============================================================================
// SafeAccessUserPointer
// Safe cross-boundary pointer access for sensitive paths.
// Inserts a speculation barrier BEFORE dereferencing the user pointer to
// prevent the CPU from speculatively reading sensitive kernel data while
// the pointer bounds check is still pending.
//==============================================================================

FORCEINLINE NTSTATUS SafeAccessUserPointer(PVOID UserPtr, PVOID KernelBuf,
                                           ULONG Size, BOOLEAN IsSensitive)
{
    if ((ULONG_PTR)UserPtr > (ULONG_PTR)MmHighestUserAddress)
        return STATUS_ACCESS_VIOLATION;

    // Speculation barrier: serialize before dereferencing user-controlled address.
    if (IsSensitive)
        SPECULATION_BARRIER();

    __try {
        ProbeForRead(UserPtr, Size, sizeof(UCHAR));
        RtlCopyMemory(KernelBuf, UserPtr, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
    return STATUS_SUCCESS;
}

//==============================================================================
// Sensitive page management
//==============================================================================

PVOID SensAllocatePool(POOL_TYPE PoolType, SIZE_T Size, ULONG Tag, UCHAR Flags)
{
    PAGED_CODE();

    PVOID ptr = ExAllocatePoolWithTag(PoolType, Size, Tag);
    if (!ptr) return NULL;

    ULONG64 startPfn = (ULONG64)(ULONG_PTR)ptr >> PAGE_SHIFT;
    ULONG64 endPfn   = ((ULONG64)(ULONG_PTR)ptr + Size + PAGE_SIZE - 1) >> PAGE_SHIFT;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SensLock, &oldIrql);

    for (ULONG64 pfn = startPfn; pfn < endPfn; pfn++) {
        if (g_SensPageCount >= MAX_SENSITIVE_PAGES)
            break;
        PSENS_PAGE_ENTRY e = &g_SensPages[g_SensPageCount];
        e->PageFrameNumber  = pfn;
        e->SensitivityFlags = Flags;
        e->OwningProcessId  = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        g_SensPageCount++;
        InterlockedIncrement(&g_SharedState.SensPageCount);
    }

    KeReleaseSpinLock(&g_SensLock, oldIrql);
    return ptr;
}

VOID SensFreePool(PVOID Ptr, ULONG Tag)
{
    PAGED_CODE();
    if (!Ptr) return;

    // Remove all entries for this allocation from the bitmap.
    ULONG64 startPfn = (ULONG64)(ULONG_PTR)Ptr >> PAGE_SHIFT;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SensLock, &oldIrql);
    for (ULONG i = 0; i < g_SensPageCount; ) {
        if (g_SensPages[i].PageFrameNumber == startPfn) {
            // Compact the array by moving the last entry here.
            g_SensPages[i] = g_SensPages[--g_SensPageCount];
            InterlockedDecrement(&g_SharedState.SensPageCount);
        } else {
            i++;
        }
    }
    KeReleaseSpinLock(&g_SensLock, oldIrql);

    ExFreePoolWithTag(Ptr, Tag);
}

static BOOLEAN SensIsPageTagged(ULONG64 pfn)
{
    // Called at DISPATCH_LEVEL — must only access non-paged memory.
    // g_SensPages is a non-paged global array; the spin lock is also non-paged.
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SensLock, &oldIrql);
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_SensPageCount; i++) {
        if (g_SensPages[i].PageFrameNumber == pfn) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_SensLock, oldIrql);
    return found;
}

BOOLEAN IsProcessSensitive(HANDLE ProcessId)
{
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SensLock, &oldIrql);
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_SensPageCount; i++) {
        if (g_SensPages[i].OwningProcessId == pid) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_SensLock, oldIrql);
    return found;
}

//==============================================================================
// Speculation controls — IBRS / STIBP / IBPB
//==============================================================================

VOID EnableSpeculationControls(ULONG CpuIndex)
{
    PCPU_MITIGATIONS mit = &g_CpuMit[CpuIndex];
    if (!(mit->Features & CPU_FEAT_IBRS_ALL))
        return;     // Rely on /Qspectre retpoline instead

    ULONG64 specCtrl = __readmsr(MSR_IA32_SPEC_CTRL);
    specCtrl |= (1ULL << 0);   // IBRS: restrict indirect branch speculation
    specCtrl |= (1ULL << 1);   // STIBP: prevent cross-HT branch prediction
    __writemsr(MSR_IA32_SPEC_CTRL, specCtrl);
}

VOID DisableSpeculationControls(ULONG CpuIndex)
{
    PCPU_MITIGATIONS mit = &g_CpuMit[CpuIndex];
    if (!(mit->Features & CPU_FEAT_IBRS_ALL))
        return;

    ULONG64 specCtrl = __readmsr(MSR_IA32_SPEC_CTRL);
    specCtrl &= ~(1ULL << 0);  // Disable IBRS (leave STIBP if SMT sibling is untrusted)
    __writemsr(MSR_IA32_SPEC_CTRL, specCtrl);

    // IBPB: flush indirect branch predictor. Expensive (10-50 µs) but necessary
    // on process context switches between different trust domains.
    if (mit->Features & CPU_FEAT_IBPB)
        __writemsr(MSR_IA32_PRED_CMD, 1ULL);
}

//==============================================================================
// HardenedKeyboardIsr
// Replacement ISR for the keyboard interrupt. Wraps the read of scan-code
// port 0x60 with speculation barriers and microarchitectural buffer flushes.
// Runs at HIGH_LEVEL; accesses only non-paged globals and I/O ports.
//==============================================================================

VOID HardenedKeyboardIsr(PKINTERRUPT Interrupt, PVOID Context)
{
    UNREFERENCED_PARAMETER(Interrupt);
    UNREFERENCED_PARAMETER(Context);

    ULONG cpuIdx = KeGetCurrentProcessorIndex();

    // ── Entry: speculation barrier ─────────────────────────────────────────
    // Prevents the CPU from speculatively reading scan-code data into the
    // microarchitectural state before we have flushed the previous context.
    SPECULATION_BARRIER();

    // ── Flush microarchitectural buffers ───────────────────────────────────
    // Clears any residual data from the previous (potentially untrusted) context
    // that could be observed through MDS or L1TF gadgets in this ISR.
    ExecuteSecurityBoundaryFlush(cpuIdx);

    // ── Read keyboard scan code ────────────────────────────────────────────
    // Port 0x60 is the i8042 keyboard data port.
    UCHAR scanCode = __inbyte(0x60);

    // ── Store in sensitive-tagged ring buffer ──────────────────────────────
    if (g_KbdRingBuffer) {
        // SafeArrayIndex prevents Spectre v1 gadget on the write-index arithmetic.
        ULONG safeIdx = SafeArrayIndex(g_KbdWriteIdx, KBD_RING_SIZE);
        g_KbdRingBuffer[safeIdx] = scanCode;
        g_KbdWriteIdx = (g_KbdWriteIdx + 1) % KBD_RING_SIZE;
    }

    // ── Exit: flush before returning to the preempted context ─────────────
    // Prevents keystroke data left in microarchitectural state from leaking
    // to whatever thread runs next on this core.
    ExecuteSecurityBoundaryFlush(cpuIdx);
    SPECULATION_BARRIER();
}

//==============================================================================
// Context switch notification callback
// Registered via PsSetLoadImageNotifyRoutine or by patching SwapContext.
// Fires at DISPATCH_LEVEL when the scheduler selects a new thread.
//==============================================================================

VOID SensContextSwitchHook(PKTHREAD OldThread, PKTHREAD NewThread)
{
    HANDLE oldPid = PsGetProcessId(PsGetThreadProcess((PETHREAD)OldThread));
    HANDLE newPid = PsGetProcessId(PsGetThreadProcess((PETHREAD)NewThread));

    BOOLEAN oldSens = IsProcessSensitive(oldPid);
    BOOLEAN newSens = IsProcessSensitive(newPid);

    if (oldSens || newSens) {
        // A security boundary is being crossed. Flush microarchitectural state
        // to prevent the incoming thread from reading residual data from the
        // outgoing sensitive thread (or vice-versa).
        ULONG cpuIdx = KeGetCurrentProcessorIndex();
        ExecuteSecurityBoundaryFlush(cpuIdx);

        // Also assign the appropriate CAT CLOS for the incoming thread.
        if (newSens) {
            CatAssignClos(g_CatConfig.SensitiveClos);
            SmtIsolateSensitiveProcess(newPid);
        } else {
            CatAssignClos(g_CatConfig.DefaultClos);
        }
    }
}

//==============================================================================
// Cache Allocation Technology (CAT) — Intel L3 cache partitioning
//==============================================================================

NTSTATUS CatInitialize(ULONG CpuIndex)
{
    PAGED_CODE();

    PCPU_MITIGATIONS mit = &g_CpuMit[CpuIndex];
    if (!(mit->Features & CPU_FEAT_CAT_L3)) {
        g_CatConfig.Enabled = FALSE;
        return STATUS_NOT_SUPPORTED;
    }

    // ── Query CAT capability from CPUID leaf 0x10, sub-leaf 1 (L3 CAT) ─────
    int cpuid10_1[4] = {0};
    __cpuidex(cpuid10_1, CPUID_LEAF_RDT_ALLOC, (int)CPUID_SUBLEAF_L3_CAT);

    // EAX[4:0]: CBM length (number of cache ways − 1)
    ULONG cbmLen    = cpuid10_1[0] & 0x1F;
    g_CatConfig.TotalCacheWays = cbmLen + 1;

    // EDX[15:0]: maximum CLOS ID (number of classes of service − 1)
    ULONG maxClos   = cpuid10_1[3] & 0xFFFF;
    if (maxClos < 1) {
        g_CatConfig.Enabled = FALSE;
        return STATUS_NOT_SUPPORTED;
    }

    // ── Define partition: reserve top 25% of ways for sensitive data ─────────
    ULONG sensitiveWays = (g_CatConfig.TotalCacheWays >= 4)
                        ? (g_CatConfig.TotalCacheWays / 4)
                        : 1;

    g_CatConfig.SensitiveWays = sensitiveWays;
    g_CatConfig.SensitiveClos = 1;
    g_CatConfig.DefaultClos   = 0;

    // Build capacity bit masks (CBMs):
    //   Sensitive CBM: the top N ways (e.g., with 11 ways: bits 10..8 → 0x700)
    //   Default CBM  : all remaining lower ways (e.g., bits 7..0 → 0x0FF)
    g_CatConfig.SensitiveCbm = 0;
    for (ULONG i = 0; i < sensitiveWays; i++)
        g_CatConfig.SensitiveCbm |= (1ULL << (cbmLen - i));

    g_CatConfig.DefaultCbm =
        ((1ULL << (cbmLen + 1)) - 1) & ~g_CatConfig.SensitiveCbm;

    // ── Write CBMs to MSRs ──────────────────────────────────────────────────
    // MSR_L3_CBMBASE + CLOS_id contains the CBM for that class.
    // CLOS 0 = default (all non-sensitive workloads)
    __writemsr(MSR_IA32_L3_CBMBASE + 0, g_CatConfig.DefaultCbm);
    // CLOS 1 = sensitive (keyboard ISR, crypto buffers)
    __writemsr(MSR_IA32_L3_CBMBASE + 1, g_CatConfig.SensitiveCbm);

    // ── Enable CAT ──────────────────────────────────────────────────────────
    ULONG64 qosCfg = __readmsr(MSR_IA32_L3_QOS_CFG);
    qosCfg |= (1ULL << 0);     // Enable COS (Class of Service)
    __writemsr(MSR_IA32_L3_QOS_CFG, qosCfg);

    g_CatConfig.Enabled = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] CAT: %u ways total, %u sensitive (CBM=0x%llX), "
               "%u default (CBM=0x%llX)\n",
               g_CatConfig.TotalCacheWays, sensitiveWays,
               g_CatConfig.SensitiveCbm, g_CatConfig.TotalCacheWays - sensitiveWays,
               g_CatConfig.DefaultCbm);
    return STATUS_SUCCESS;
}

FORCEINLINE VOID CatAssignClos(ULONG ClosId)
{
    if (!g_CatConfig.Enabled) return;
    // MSR_PQR_ASSOC bits [31:0] = CLOS ID for the current logical processor.
    __writemsr(MSR_IA32_PQR_ASSOC, (ULONG64)(ClosId & 0xFFFFFFFF));
}

//==============================================================================
// SMT / Hyper-Threading sibling isolation
//==============================================================================

NTSTATUS SmtBuildTopology(VOID)
{
    PAGED_CODE();

    ULONG numCpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (ULONG cpu = 0; cpu < numCpus; cpu++) {
        g_SmtMap[cpu].LogicalProcessor    = cpu;
        g_SmtMap[cpu].SiblingProcessor    = MAXULONG;
        g_SmtMap[cpu].IsSensitiveRunning  = FALSE;
    }

    // Use CPUID leaf 0x0B (Extended Topology Enumeration) to determine which
    // logical processors share a physical core (SMT level).
    for (ULONG cpu = 0; cpu < numCpus; cpu++) {
        // CPUID must run on the target CPU. For init we accept approximation
        // by running on the current CPU; a full implementation would use IPI.
        int cpuid0b[4] = {0};
        __cpuidex(cpuid0b, CPUID_LEAF_EXT_TOPOLOGY, 0);

        ULONG smtShift = cpuid0b[0] & 0x1F;    // Bits to shift for SMT mask
        ULONG smtMask  = (1U << smtShift) - 1;

        g_SmtMap[cpu].LogicalProcessor = cpu;

        // Match against previously seen CPUs on the same physical core.
        for (ULONG j = 0; j < cpu; j++) {
            // Simplified: we assume all CPUs have the same SMT shift.
            // A robust implementation stores x2APIC IDs per CPU.
            if (g_SmtMap[j].SiblingProcessor == MAXULONG &&
                (j & smtMask) != (cpu & smtMask) &&
                (j >> smtShift) == (cpu >> smtShift)) {
                g_SmtMap[cpu].SiblingProcessor = j;
                g_SmtMap[j].SiblingProcessor   = cpu;
                break;
            }
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] SMT topology built for %u logical processors\n", numCpus);
    return STATUS_SUCCESS;
}

VOID SmtSiblingFlushDpc(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ULONG targetCpu = (ULONG)(ULONG_PTR)Context;
    if (KeGetCurrentProcessorIndex() == targetCpu) {
        // Running on the sibling core — flush its microarchitectural state
        // before it might schedule an untrusted thread.
        ExecuteSecurityBoundaryFlush(targetCpu);
    }
}

NTSTATUS SmtIsolateSensitiveProcess(HANDLE ProcessId)
{
    UNREFERENCED_PARAMETER(ProcessId);

    ULONG cpuIdx     = KeGetCurrentProcessorIndex();
    ULONG siblingCpu = g_SmtMap[cpuIdx].SiblingProcessor;

    g_SmtMap[cpuIdx].IsSensitiveRunning = TRUE;

    if (siblingCpu == MAXULONG)
        return STATUS_SUCCESS;  // No SMT sibling

    // Send a DPC to the sibling CPU requesting it flush its buffers.
    // This prevents the sibling from observing sensitive data via shared L1D.
    static KDPC s_SiblingDpc;
    KeInitializeDpc(&s_SiblingDpc, SmtSiblingFlushDpc,
                    (PVOID)(ULONG_PTR)siblingCpu);
    KeSetTargetProcessorDpc(&s_SiblingDpc, (CCHAR)siblingCpu);
    KeInsertQueueDpc(&s_SiblingDpc, NULL, NULL);

    return STATUS_SUCCESS;
}


//==============================================================================
// CacheMitigationInitialize / CacheMitigationUninitialize
//==============================================================================

NTSTATUS CacheMitigationInitialize(VOID)
{
    PAGED_CODE();

    KeInitializeSpinLock(&g_SensLock);
    RtlZeroMemory(g_SensPages, sizeof(g_SensPages));
    g_SensPageCount = 0;
    RtlZeroMemory(&g_CatConfig, sizeof(g_CatConfig));
    RtlZeroMemory(g_CpuMit, sizeof(g_CpuMit));
    RtlZeroMemory(g_SmtMap, sizeof(g_SmtMap));

    // Probe capabilities on each CPU at PASSIVE_LEVEL.
    // KeIpiGenericCall runs at IPI_LEVEL; ProbeCpuCapabilities and CatInitialize
    // are PAGE-section functions with PAGED_CODE() — calling them from an IPI
    // callback causes an immediate bugcheck. Use thread affinity instead.
    ULONG numCpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG i = 0; i < numCpus; i++) {
        PROCESSOR_NUMBER procNum;
        GROUP_AFFINITY affinity = {0}, prevAffinity = {0};
        if (NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &procNum))) {
            affinity.Group = procNum.Group;
            affinity.Mask  = (KAFFINITY)1 << procNum.Number;
            KeSetSystemGroupAffinityThread(&affinity, &prevAffinity);
            ProbeCpuCapabilities(i);
            CatInitialize(i);
            KeRevertToUserGroupAffinityThread(&prevAffinity);
        } else {
            ProbeCpuCapabilities(i);
            CatInitialize(i);
        }
    }

    // Build SMT topology map.
    SmtBuildTopology();

    // Allocate the sensitive-tagged keyboard ring buffer.
    g_KbdRingBuffer = (PUCHAR)SensAllocatePool(NonPagedPool,
                                               KBD_RING_SIZE,
                                               'gkbd',
                                               SENS_FLAG_KEYSTROKE);
    if (!g_KbdRingBuffer)
        return STATUS_INSUFFICIENT_RESOURCES;
    g_KbdWriteIdx = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Cache mitigation engine initialized\n");
    return STATUS_SUCCESS;
}

VOID CacheMitigationUninitialize(VOID)
{
    PAGED_CODE();

    if (g_KbdRingBuffer) {
        SensFreePool(g_KbdRingBuffer, 'gkbd');
        g_KbdRingBuffer = NULL;
    }

    // Disable CAT: restore default CLOS for all CPUs.
    if (g_CatConfig.Enabled) {
        ULONG numCpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
        for (ULONG i = 0; i < numCpus; i++)
            __writemsr(MSR_IA32_PQR_ASSOC, 0);
    }
}
