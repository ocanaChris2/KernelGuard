// shared_state.c
// Global state storage and cross-module event dispatch.
// All globals are in non-paged memory (driver image is non-paged by default).

#include "KernelGuard.h"

//==============================================================================
// Global state definitions
//==============================================================================

DRIVER_SHARED_STATE g_SharedState;

PMU_CONTEXT         g_PmuCtx[MAXIMUM_PROCESSORS];
RDTSC_PROFILE       g_RdtscProfiles[MAX_PROFILED_PROCS];
KSPIN_LOCK          g_RdtscLock;

PCI_DISCOVERY_ENTRY g_PciDevices[MAX_PCI_DEVICES];
ULONG               g_PciDeviceCount;
PHYSICAL_ADDRESS    g_EcamBase;     // Populated from MCFG ACPI table at init

BASELINE_ENTRY      g_Baseline[MAX_BASELINE_ENTRIES];
ULONG               g_BaselineCount;

SENS_PAGE_ENTRY     g_SensPages[MAX_SENSITIVE_PAGES];
ULONG               g_SensPageCount;
KSPIN_LOCK          g_SensLock;

CPU_MITIGATIONS     g_CpuMit[MAXIMUM_PROCESSORS];
CAT_CONFIG          g_CatConfig;
SMT_SIBLING         g_SmtMap[MAXIMUM_PROCESSORS];

PSHARED_MEM_REGION  g_SharedMemKernel;
UCHAR               g_HmacKey[HMAC_KEY_SIZE];

PUCHAR              g_KbdRingBuffer;
volatile ULONG      g_KbdWriteIdx;

// Driver whitelist — populated at DriverEntry from a signed policy blob.
// For simplicity, these two are always whitelisted.
static const WCHAR *g_WhitelistedDrivers[] = {
    L"\\Driver\\Kbclass",
    L"\\Driver\\Kbdhid",
    L"\\Driver\\i8042prt",
    L"\\Driver\\KernelGuard",
    NULL
};

// DMA-authorized devices list (Bus/Dev/Func tuples, populated from policy).
// Empty by default; HwKeyloggerInitialize adds known-good devices.
typedef struct { UCHAR Bus, Device, Function; } DMA_AUTH_ENTRY;
#define MAX_DMA_AUTH 64
static DMA_AUTH_ENTRY g_AuthorizedDma[MAX_DMA_AUTH];
static ULONG          g_AuthorizedDmaCount;

//==============================================================================
// IsWhitelistedDriver
// Returns TRUE if the driver name is in the known-good list.
// Called at PASSIVE_LEVEL from dispatch hook scan.
//==============================================================================

BOOLEAN IsWhitelistedDriver(PUNICODE_STRING DriverName)
{
    if (!DriverName || !DriverName->Buffer)
        return FALSE;

    for (ULONG i = 0; g_WhitelistedDrivers[i] != NULL; i++) {
        UNICODE_STRING wl;
        RtlInitUnicodeString(&wl, g_WhitelistedDrivers[i]);
        if (RtlEqualUnicodeString(DriverName, &wl, TRUE))
            return TRUE;
    }
    return FALSE;
}

//==============================================================================
// IsAuthorizedDmaDevice
// Returns TRUE if (Bus, Device, Function) is in the authorized DMA list.
//==============================================================================

BOOLEAN IsAuthorizedDmaDevice(UCHAR Bus, UCHAR Device, UCHAR Function)
{
    for (ULONG i = 0; i < g_AuthorizedDmaCount; i++) {
        if (g_AuthorizedDma[i].Bus      == Bus   &&
            g_AuthorizedDma[i].Device   == Device &&
            g_AuthorizedDma[i].Function == Function)
            return TRUE;
    }
    return FALSE;
}

//==============================================================================
// GetNtoskrnlBase / GetNtoskrnlSize
// Returns the load VA and mapped size of ntoskrnl.exe.
// Uses AuxKlib to avoid calling routines that might be hooked.
//==============================================================================

ULONG64 GetNtoskrnlBase(VOID)
{
    // Cache the result after first call.
    static ULONG64 s_NtBase = 0;
    if (s_NtBase) return s_NtBase;

    ULONG bytes = 0;
    NTSTATUS st = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (st != STATUS_BUFFER_TOO_SMALL || bytes == 0)
        return 0;

    AUX_MODULE_EXTENDED_INFO *mods = (AUX_MODULE_EXTENDED_INFO *)
        ExAllocatePoolWithTag(NonPagedPool, bytes, 'bmod');
    if (!mods) return 0;

    st = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), mods);
    if (NT_SUCCESS(st)) {
        // Module 0 is always ntoskrnl.exe in the kernel module list.
        s_NtBase = (ULONG64)mods[0].BasicInfo.ImageBase;
    }
    ExFreePoolWithTag(mods, 'bmod');
    return s_NtBase;
}

ULONG GetNtoskrnlSize(VOID)
{
    static ULONG s_NtSize = 0;
    if (s_NtSize) return s_NtSize;

    ULONG bytes = 0;
    AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!bytes) return 0;

    AUX_MODULE_EXTENDED_INFO *mods = (AUX_MODULE_EXTENDED_INFO *)
        ExAllocatePoolWithTag(NonPagedPool, bytes, 'bmod');
    if (!mods) return 0;

    NTSTATUS st = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), mods);
    if (NT_SUCCESS(st))
        s_NtSize = mods[0].ImageSize;

    ExFreePoolWithTag(mods, 'bmod');
    return s_NtSize;
}

//==============================================================================
// VerifySharedStateIntegrity
// SHA-256 the state fields (excluding StateHash itself) and compare.
// Uses constant-time comparison to avoid timing leaks.
// Safe to call at PASSIVE_LEVEL only (BCrypt call).
//==============================================================================

BOOLEAN VerifySharedStateIntegrity(VOID)
{
    UCHAR computed[32] = {0};
    // Hash all fields up to (but not including) the StateLock and StateHash.
    ULONG hashable = FIELD_OFFSET(DRIVER_SHARED_STATE, StateLock);
    NTSTATUS st = ComputeSha256((PUCHAR)&g_SharedState, hashable, computed);
    if (!NT_SUCCESS(st)) {
        g_SharedState.IntegrityValid = FALSE;
        return FALSE;
    }
    BOOLEAN ok = CONSTANT_TIME_EQ(computed, g_SharedState.StateHash, 32);
    g_SharedState.IntegrityValid = ok;
    return ok;
}

VOID UpdateSharedStateHash(VOID)
{
    ULONG hashable = FIELD_OFFSET(DRIVER_SHARED_STATE, StateLock);
    ComputeSha256((PUCHAR)&g_SharedState, hashable, g_SharedState.StateHash);
}

//==============================================================================
// EnterFailSafeMode
// Called when shared state integrity check fails or a critical hook is found.
// Switches all CPUs to MitigateFullSpectrum and sends a critical alert.
//==============================================================================

VOID EnterFailSafeMode(VOID)
{
    if (g_SharedState.FailSafeMode)
        return;

    g_SharedState.FailSafeMode = TRUE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[KG] *** FAIL-SAFE MODE ENTERED ***\n");

    // Escalate every CPU to full-spectrum mitigation.
    ULONG numCpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG i = 0; i < numCpus; i++) {
        g_CpuMit[i].Strategy = MitigateFullSpectrum;
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        SecureCommNotify(ALERT_FAIL_SAFE_ENTERED, 2, 0, 0);
    SecureCommMsrSignal(ALERT_FAIL_SAFE_ENTERED);
}

//==============================================================================
// LogAlert
// Writes a human-readable alert to the kernel debug output.
// Also sends a structured notification via the secure comms channel.
// Safe to call at DISPATCH_LEVEL (no paged access in this path).
//==============================================================================

VOID LogAlert(ULONG AlertType, PCSTR Format, ...)
{
    // DbgPrintEx is documented as safe at IRQL <= DISPATCH_LEVEL.
    va_list args;
    va_start(args, Format);
    vDbgPrintExWithPrefix("[SCPD ALERT] ", DPFLTR_IHVDRIVER_ID,
                          DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");

    // Attempt to signal user-mode via MSR channel (IRQL-agnostic).
    SecureCommMsrSignal(AlertType);
}

//==============================================================================
// DispatchCrossModuleEvent
// Central event router. Called after any detection event.
// Cross-module trigger table per specification §7.2.
// Called at DISPATCH_LEVEL or lower.
//==============================================================================

VOID DispatchCrossModuleEvent(ULONG AlertType, ULONG AlertLevel,
                              ULONG64 Param1, ULONG64 Param2)
{
    ULONG cpuIdx = KeGetCurrentProcessorIndex();

    switch (AlertType) {

    case ALERT_PMU_L1D_ANOMALY:
    case ALERT_PMU_L2_ANOMALY:
        // M1 → M4: Escalate flush frequency by temporarily upgrading strategy.
        if (AlertLevel >= 2) {
            g_CpuMit[cpuIdx].Strategy = MitigateFullSpectrum;
            ExecuteSecurityBoundaryFlush(cpuIdx);
        }
        break;

    case ALERT_PMU_RDTSC_RATE:
        // M1 → M4: Enable IBRS/STIBP on the affected core.
        EnableSpeculationControls(cpuIdx);
        break;

    case ALERT_UNAUTHORIZED_DMA:
        // M2 → M4: Flush all buffers + full L1D flush.
        ExecuteSecurityBoundaryFlush(cpuIdx);
        break;

    case ALERT_PCI_DISCREPANCY:
        // M2 → M3: Trigger immediate dispatch-routine scan.
        // ScanKeyboardDrivers is a PAGE-section function; only safe at PASSIVE_LEVEL.
        if (KeGetCurrentIrql() == PASSIVE_LEVEL)
            ScanKeyboardDrivers();
        break;

    case ALERT_IDT_HOOK:
        // M3 → M4: Full-spectrum flush + escalate strategy.
        g_CpuMit[cpuIdx].Strategy = MitigateFullSpectrum;
        ExecuteSecurityBoundaryFlush(cpuIdx);
        break;

    case ALERT_TEXT_PATCH:
    case ALERT_DISPATCH_HOOK:
        // M3 → M5: Critical alert + enter fail-safe.
        SecureCommNotify(AlertType, 2, Param1, Param2);
        EnterFailSafeMode();
        break;

    case ALERT_SHARED_STATE_CORRUPT:
        EnterFailSafeMode();
        break;

    default:
        break;
    }

    // Deliver notification to user-mode. SecureCommNotify calls BCrypt and has
    // PAGED_CODE(), so it is only safe at PASSIVE_LEVEL. Fall back to the MSR
    // covert channel when called above PASSIVE_LEVEL (e.g., from a DPC).
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        SecureCommNotify(AlertType, AlertLevel, Param1, Param2);
    else
        SecureCommMsrSignal(AlertType);
}
