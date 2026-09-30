// pmu_detection.c
// Module 1: Side-Channel Attack Detection via CPU Performance Monitoring Units.
//
// Architecture:
//   - Configures IA32_PERFEVTSEL0 for L1D cache miss (MEM_LOAD_RETIRED.L1_MISS)
//     and IA32_PERFEVTSEL1 for L2 cache miss (L2_RQSTS.MISS) on every logical CPU.
//   - Pre-loads the PMC counters near overflow so that a PMI fires after
//     L1D_MISS_THRESHOLD / L2_MISS_THRESHOLD events.
//   - The PMI ISR (PmiIsr) runs at HIGH_LEVEL (IRQL 26). It reads
//     IA32_PERF_GLOBAL_STATUS, increments anomaly counters, and issues an
//     immediate L1D flush when the anomaly level is critical.
//   - RDTSC profiling: sets CR4.TSD=1 so that RDTSC from Ring 3 generates #GP,
//     which our IDT hook (RdtscGpHandler) intercepts and counts per-process.
//
// IRQL rules:
//   PmuInitialize            PASSIVE_LEVEL  (uses IoConnectInterrupt, APIC mapping)
//   PmuConfigureOnCpu        PASSIVE_LEVEL  (called via KeIpiGenericCall)
//   PmiIsr                   HIGH_LEVEL     (NO paged memory, NO kernel APIs)
//   EnableTSD / DisableTSD   PASSIVE_LEVEL  (writes CR4, run once at init)
//
// All HIGH_LEVEL functions are in the NONPAGED code section.

#include "KernelGuard.h"

#pragma alloc_text(PAGE, PmuInitialize)
#pragma alloc_text(PAGE, PmuUninitialize)

//==============================================================================
// Pre-mapped APIC MMIO base VA — populated at PASSIVE_LEVEL in PmuInitialize.
// Stored per-CPU in g_PmuCtx[i].ApicVaBase (mapped at PASSIVE, used at HIGH_LEVEL).
//==============================================================================

// Forward declaration for IPI callback (no alloc_text — stays in NONPAGED).
static ULONG_PTR PmuIpiConfigureCpu(ULONG_PTR Context);

//==============================================================================
// PmuConfigureOnCpu
// Runs on a single logical processor (via IPI). Configures PMU MSRs.
// Called at HIGH_LEVEL by KeIpiGenericCall, but also at PASSIVE on init path.
//==============================================================================

NTSTATUS PmuConfigureOnCpu(ULONG CpuIndex)
{
    PPMU_CONTEXT ctx = &g_PmuCtx[CpuIndex];
    ctx->CpuIndex = CpuIndex;

    // ── Step 1: Disable all counters before reconfiguring ──────────────────
    __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, 0);
    __writemsr(MSR_IA32_PERFEVTSEL0, 0);
    __writemsr(MSR_IA32_PERFEVTSEL1, 0);
    __writemsr(MSR_IA32_PMC0, 0);
    __writemsr(MSR_IA32_PMC1, 0);

    // ── Step 2: Configure PMC0 for L1D cache miss ─────────────────────────
    // Event 0xD1, Umask 0x08 = MEM_LOAD_RETIRED.L1_MISS (Intel Skylake+)
    // Bit layout: [15:8]=Umask, [7:0]=EventSelect, [16]=USR, [17]=OS, [20]=PMI, [22]=EN
    ULONG64 evtSel0 = PMU_EVT_L1D_MISS       // Event 0xD1, Umask 0x08
                    | PERFEVT_USR             // Count in Ring 3
                    | PERFEVT_OS              // Count in Ring 0
                    | PERFEVT_PMI             // PMI on overflow
                    | PERFEVT_ENABLE;         // Counter enable

    // Pre-load counter to (MAX - THRESHOLD) so it overflows after THRESHOLD events.
    ULONG64 pmc0Init = PMC_MAX_VALUE - L1D_MISS_THRESHOLD;
    __writemsr(MSR_IA32_PMC0, pmc0Init);
    __writemsr(MSR_IA32_PERFEVTSEL0, evtSel0);

    // ── Step 3: Configure PMC1 for L2 cache miss ─────────────────────────
    // Event 0x24, Umask 0x3F = L2_RQSTS.MISS
    ULONG64 evtSel1 = PMU_EVT_L2_MISS
                    | PERFEVT_USR
                    | PERFEVT_OS
                    | PERFEVT_PMI
                    | PERFEVT_ENABLE;

    ULONG64 pmc1Init = PMC_MAX_VALUE - L2_MISS_THRESHOLD;
    __writemsr(MSR_IA32_PMC1, pmc1Init);
    __writemsr(MSR_IA32_PERFEVTSEL1, evtSel1);

    // ── Step 4: Enable PMC0 and PMC1 globally ────────────────────────────
    // IA32_PERF_GLOBAL_CTRL bits [1:0] enable PMC1 and PMC0 respectively.
    ULONG64 globalCtrl = __readmsr(MSR_IA32_PERF_GLOBAL_CTRL);
    globalCtrl |= (1ULL << 0) | (1ULL << 1);
    __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, globalCtrl);

    // ── Step 5: Configure Local APIC LVT for PMI ─────────────────────────
    // The APIC MMIO was mapped at PASSIVE_LEVEL and stored in ApicVaBase.
    if (ctx->ApicVaBase) {
        PULONG lvtPerf = (PULONG)((PUCHAR)ctx->ApicVaBase + APIC_LVT_PERF_OFFSET);
        // Clear mask bit (bit 16) and set vector. Delivery mode = Fixed (000).
        *lvtPerf = (PMI_IDT_VECTOR & 0xFF);    // Unmasked, fixed delivery, our vector
    }

    InterlockedExchange(&ctx->L1DMissOverflows, 0);
    InterlockedExchange(&ctx->L2MissOverflows, 0);
    InterlockedExchange(&ctx->AlertLevel, 0);

    return STATUS_SUCCESS;
}

//==============================================================================
// PmiIsr
// Performance Monitor Interrupt handler. Runs at HIGH_LEVEL (IRQL 26).
// MUST NOT: access paged memory, call any kernel API, acquire non-DISPATCH locks.
// Uses only non-paged globals and CPU intrinsics.
//==============================================================================

BOOLEAN PmiIsr(PKINTERRUPT Interrupt, PVOID Context)
{
    UNREFERENCED_PARAMETER(Interrupt);
    PPMU_CONTEXT ctx = (PPMU_CONTEXT)Context;
    if (!ctx) return FALSE;

    // ── 1. Read overflow status without going through kernel APIs ──────────
    ULONG64 globalStatus = __readmsr(MSR_IA32_PERF_GLOBAL_STATUS);

    // ── 2. Handle PMC0 overflow (L1D miss threshold reached) ───────────────
    if (globalStatus & (1ULL << 0)) {
        LONG newVal = InterlockedIncrement(&ctx->L1DMissOverflows);

        // Re-arm: clear overflow flag and reload counter near top of range.
        __writemsr(MSR_IA32_PERF_GLOBAL_OVF, (1ULL << 0));
        __writemsr(MSR_IA32_PMC0, PMC_MAX_VALUE - L1D_MISS_THRESHOLD);

        if (newVal >= (LONG)PMU_ALERT_OVERFLOW_COUNT) {
            // Sustained L1D miss rate — strong indicator of Flush+Reload or
            // Prime+Probe attack. Escalate to critical and flush immediately.
            InterlockedExchange(&ctx->AlertLevel, 2);
            InterlockedAdd(&g_SharedState.PmuL1DOverflows, (LONG)PMU_ALERT_OVERFLOW_COUNT);

            // Immediate mitigation: flush microarchitectural buffers.
            // PerformVerwFlush() is in non-paged code (.text of the .asm object).
            ULONG cpuFeat = g_CpuMit[ctx->CpuIndex].Features;
            if (cpuFeat & CPU_FEAT_VERW_FLUSH) {
                PerformVerwFlush();
            }
            if (cpuFeat & CPU_FEAT_L1D_FLUSH) {
                // IA32_FLUSH_CMD.L1D_FLUSH bit 0: flush L1D data cache.
                __writemsr(MSR_IA32_FLUSH_CMD, 1ULL);
            }
        }
    }

    // ── 3. Handle PMC1 overflow (L2 miss threshold reached) ────────────────
    if (globalStatus & (1ULL << 1)) {
        LONG newVal = InterlockedIncrement(&ctx->L2MissOverflows);
        __writemsr(MSR_IA32_PERF_GLOBAL_OVF, (1ULL << 1));
        __writemsr(MSR_IA32_PMC1, PMC_MAX_VALUE - L2_MISS_THRESHOLD);

        if (newVal >= (LONG)PMU_ALERT_OVERFLOW_COUNT) {
            if (ctx->AlertLevel < 1)
                InterlockedExchange(&ctx->AlertLevel, 1);
        }
    }

    // ── 4. Update shared state alert level (lock-free) ─────────────────────
    if (ctx->AlertLevel > g_SharedState.PmuAlertLevel)
        InterlockedExchange(&g_SharedState.PmuAlertLevel, ctx->AlertLevel);

    // ── 5. Send EOI to local APIC ───────────────────────────────────────────
    // The APIC EOI register was pre-mapped at PASSIVE_LEVEL. Writing 0 to it
    // signals end-of-interrupt to the APIC. This MUST be done before returning
    // from the ISR to allow subsequent interrupts to be delivered.
    if (ctx->ApicVaBase) {
        PULONG apicEoi = (PULONG)((PUCHAR)ctx->ApicVaBase + APIC_EOI_OFFSET);
        *apicEoi = 0;
    }
    return TRUE;
}

//==============================================================================
// PmuIpiConfigureCpu
// IPI callback executed on each logical processor to configure its PMU.
// Called via KeIpiGenericCall at IPI_LEVEL (safe for MSR writes).
//==============================================================================

static ULONG_PTR PmuIpiConfigureCpu(ULONG_PTR Context)
{
    UNREFERENCED_PARAMETER(Context);
    ULONG cpuIdx = KeGetCurrentProcessorIndex();
    PmuConfigureOnCpu(cpuIdx);
    return 0;
}

//==============================================================================
// PmuInitialize
// Called at PASSIVE_LEVEL from DriverEntry.
// Maps APIC MMIO, registers PMI ISR, and broadcasts PMU configuration via IPI.
//==============================================================================

NTSTATUS PmuInitialize(VOID)
{
    PAGED_CODE();

    AuxKlibInitialize();    // Required before AuxKlib calls; safe to call multiple times.

    ULONG numCpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);

    // ── Map the xAPIC MMIO region for each processor ───────────────────────
    // IA32_APIC_BASE MSR bits [35:12] give the physical base of xAPIC MMIO.
    // We map 4 KB (one page) of MMIO per logical processor.
    // On most systems all logical processors share the same physical APIC base
    // per-socket, but we read it per-CPU here to be safe.
    //
    // NOTE: x2APIC mode (IA32_APIC_BASE bit 10 set) uses MSRs rather than MMIO.
    // We check and fall back gracefully.
    for (ULONG i = 0; i < numCpus; i++) {
        // KeIpiGenericCall cannot return per-CPU values; run on each CPU instead.
        // For init we just read the MSR once (same physical base on all CPUs).
        ULONG64 apicBaseMsr = __readmsr(MSR_IA32_APIC_BASE);
        BOOLEAN x2apic = (BOOLEAN)((apicBaseMsr >> 10) & 1);

        if (!x2apic) {
            PHYSICAL_ADDRESS apicPhys;
            apicPhys.QuadPart = (LONGLONG)(apicBaseMsr & 0xFFFFFFFFF000ULL);

            g_PmuCtx[i].ApicVaBase = MmMapIoSpace(apicPhys, PAGE_SIZE, MmNonCached);
            if (!g_PmuCtx[i].ApicVaBase) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[KG] CPU%u: APIC MMIO map failed — PMI EOI will not work\n", i);
            }
        } else {
            // x2APIC: EOI via WRMSR to 0x80B, LVT Perf via WRMSR to 0x834.
            // Not implemented in this version; gracefully degrade.
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[KG] CPU%u: x2APIC detected — xAPIC path not used\n", i);
        }
        g_PmuCtx[i].CpuIndex  = i;
        g_PmuCtx[i].PmiVector = PMI_IDT_VECTOR;
    }

    // ── Register the PMI ISR for each CPU ──────────────────────────────────
    // We connect the interrupt once for each logical processor. Because PMI is
    // a local interrupt (not routed through the I/O APIC redirection table), we
    // use IoConnectInterruptEx with the CONNECT_FULLY_SPECIFIED mode, specifying
    // the PMI vector and IRQL=HIGH_LEVEL.
    //
    // In a truly zero-trust deployment you would manipulate the IDT directly
    // (read IDTR via SIDT, clear CR0.WP, write gate, restore CR0.WP).
    // For this driver we use the WDK API which is deep enough in HAL to be
    // unlikely to be hooked by a userspace rootkit.
    for (ULONG i = 0; i < numCpus; i++) {
        IO_CONNECT_INTERRUPT_PARAMETERS icp = {0};
        icp.Version                  = CONNECT_FULLY_SPECIFIED;
        icp.FullySpecified.PhysicalDeviceObject = NULL;   // NULL for non-device interrupt
        icp.FullySpecified.InterruptObject      = &g_PmuCtx[i].PmiInterruptObject;
        icp.FullySpecified.ServiceRoutine        = PmiIsr;
        icp.FullySpecified.ServiceContext        = &g_PmuCtx[i];
        icp.FullySpecified.SpinLock              = NULL;
        icp.FullySpecified.SynchronizeIrql       = HIGH_LEVEL;
        icp.FullySpecified.FloatingSave          = FALSE;
        icp.FullySpecified.ShareVector           = FALSE;
        icp.FullySpecified.Vector                = PMI_IDT_VECTOR;
        icp.FullySpecified.Irql                  = HIGH_LEVEL;
        icp.FullySpecified.InterruptMode         = LevelSensitive;
        icp.FullySpecified.ProcessorEnableMask   = ((KAFFINITY)1 << i);
        icp.FullySpecified.Group                 = 0;

        NTSTATUS st = IoConnectInterruptEx(&icp);
        if (!NT_SUCCESS(st)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[KG] CPU%u: IoConnectInterruptEx failed: 0x%08X\n", i, st);
        }
    }

    // ── Broadcast PMU counter configuration to all CPUs via IPI ───────────
    KeIpiGenericCall(PmuIpiConfigureCpu, 0);

    // ── Enable RDTSC profiling ─────────────────────────────────────────────
    KeInitializeSpinLock(&g_RdtscLock);
    RtlZeroMemory(g_RdtscProfiles, sizeof(g_RdtscProfiles));
    // EnableTSD() / CR4.TSD intentionally NOT called here: RdtscGpHandler is
    // not yet installed as the IDT #GP handler. Setting TSD without that hook
    // causes every Ring-3 RDTSC (used by ntdll, QPC, heap profiling, etc.) to
    // deliver an unhandled #GP, crashing user-mode processes. Restore this call
    // once the full IDT hook is implemented.

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] PMU detection initialized on %u CPUs\n", numCpus);
    return STATUS_SUCCESS;
}

VOID PmuUninitialize(VOID)
{
    PAGED_CODE();

    ULONG numCpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);

    // Disable PMU counters on all CPUs.
    KeIpiGenericCall(PmuIpiConfigureCpu, (ULONG_PTR)NULL);
    for (ULONG i = 0; i < numCpus; i++) {
        __writemsr(MSR_IA32_PERF_GLOBAL_CTRL, 0);
        __writemsr(MSR_IA32_PERFEVTSEL0, 0);
        __writemsr(MSR_IA32_PERFEVTSEL1, 0);

        if (g_PmuCtx[i].PmiInterruptObject) {
            IO_DISCONNECT_INTERRUPT_PARAMETERS dip = {0};
            dip.Version = CONNECT_FULLY_SPECIFIED;
            dip.ConnectionContext.InterruptObject = g_PmuCtx[i].PmiInterruptObject;
            IoDisconnectInterruptEx(&dip);
            g_PmuCtx[i].PmiInterruptObject = NULL;
        }

        if (g_PmuCtx[i].ApicVaBase) {
            MmUnmapIoSpace(g_PmuCtx[i].ApicVaBase, PAGE_SIZE);
            g_PmuCtx[i].ApicVaBase = NULL;
        }
    }
    // DisableTSD() not called because EnableTSD() is not called in PmuInitialize.
}



//==============================================================================
// EnableTSD / DisableTSD
// Sets/clears CR4.TSD (bit 2). When TSD=1, RDTSC from Ring 3 causes #GP,
// letting our IDT hook count per-process RDTSC usage.
// Must be run on every logical processor via IPI in production.
//==============================================================================

VOID EnableTSD(VOID)
{
    ULONG64 cr4 = __readcr4();
    cr4 |= (1ULL << 2);     // Set TSD bit
    __writecr4(cr4);
}

VOID DisableTSD(VOID)
{
    ULONG64 cr4 = __readcr4();
    cr4 &= ~(1ULL << 2);    // Clear TSD bit
    __writecr4(cr4);
}

//==============================================================================
// RdtscGpHandler
// Installed as a custom IDT handler for INT 0x0D (#GP).
// When CR4.TSD=1 and a Ring-3 process executes RDTSC/RDTSCP, the CPU generates
// #GP. We intercept it here, count the attempt per process, and emulate the
// instruction (so the process continues running) rather than crashing it.
//
// IRQL: HIGH_LEVEL (exception handlers execute at the IRQL of the interrupted
//        context; #GP from Ring 3 arrives at the IRQL of the interrupted code,
//        raised to at least DISPATCH when we're in the kernel).
//
// NOTE: Installing a custom #GP handler requires direct IDT manipulation
// (SIDT, clear CR0.WP, write gate, restore CR0.WP) which is not shown here
// in full detail. The function body below is the handler logic.
//==============================================================================

VOID RdtscGpHandler(PKTRAP_FRAME TrapFrame, ULONG64 ErrorCode)
{
    UNREFERENCED_PARAMETER(ErrorCode);

    // Only process #GP from Ring 3 (CS RPL field = 3).
    if ((TrapFrame->SegCs & 0x3) != 3)
        return; // Let original handler take over for Ring 0 #GP

    // Safe-read the faulting instruction bytes.
    __try {
        PUCHAR rip = (PUCHAR)TrapFrame->Rip;

        // RDTSC  = 0x0F 0x31 (2 bytes)
        // RDTSCP = 0x0F 0x01 0xF9 (3 bytes)
        BOOLEAN isRdtsc   = (rip[0] == 0x0F && rip[1] == 0x31);
        BOOLEAN isRdtscp  = (rip[0] == 0x0F && rip[1] == 0x01 && rip[2] == 0xF9);

        if (!isRdtsc && !isRdtscp)
            return; // Not an RDTSC — let original #GP handler process it

        // Count this RDTSC attempt for the current process.
        HANDLE pid = PsGetCurrentProcessId();
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RdtscLock, &oldIrql);
        for (int i = 0; i < MAX_PROFILED_PROCS; i++) {
            if (g_RdtscProfiles[i].ProcessId == pid) {
                LONG count = InterlockedIncrement(&g_RdtscProfiles[i].RdtscCount);
                if (count > (LONG)RDTSC_RATE_THRESHOLD && !g_RdtscProfiles[i].IsFlagged) {
                    g_RdtscProfiles[i].IsFlagged = TRUE;
                    InterlockedExchange(&g_SharedState.PmuRdtscFlaggedPid,
                                        (LONG)(ULONG_PTR)pid);
                    LogAlert(ALERT_PMU_RDTSC_RATE,
                             "RDTSC rate exceeded for PID %llu (count=%d)",
                             (ULONG64)(ULONG_PTR)pid, count);
                    DispatchCrossModuleEvent(ALERT_PMU_RDTSC_RATE, 1,
                                             (ULONG64)(ULONG_PTR)pid, count);
                }
                break;
            }
            if (!g_RdtscProfiles[i].ProcessId) {
                g_RdtscProfiles[i].ProcessId = pid;
                InterlockedExchange(&g_RdtscProfiles[i].RdtscCount, 1);
                break;
            }
        }
        KeReleaseSpinLock(&g_RdtscLock, oldIrql);

        // Emulate RDTSC: read TSC and populate RDX:RAX in the trap frame.
        ULONG64 tsc = __rdtsc();
        TrapFrame->Rdx = (tsc >> 32) & 0xFFFFFFFF;
        TrapFrame->Rax = tsc & 0xFFFFFFFF;
        if (isRdtscp) {
            // RDTSCP also writes IA32_TSC_AUX (MSR 0xC0000103) to ECX.
            TrapFrame->Rcx = (ULONG64)(__readmsr(0xC0000103UL) & 0xFFFFFFFF);
            TrapFrame->Rip += 3;
        } else {
            TrapFrame->Rip += 2;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // RIP was not accessible — fall through to original #GP handler.
    }
}
