// hw_keylogger_detect.c
// Module 2: Hardware Keylogger and Compromised Peripheral Detection + Mitigation.
//
// Detection strategy:
//   1. Walk the PCIe bus directly via ECAM (bypassing OS device stack).
//   2. Compare hardware-discovered devices against OS-reported keyboard/filter
//      drivers to detect unauthorized filter drivers.
//   3. Walk the VT-d root/context tables to verify no unauthorized device has
//      DMA access to memory pages containing keystroke buffers.
//
// Mitigation strategy (tiered, applied immediately on detection):
//
//   Software keyboard filter drivers (ALERT_UNAUTHORIZED_KBD_FILTER):
//     Tier 1 — Overwrite the driver's MajorFunction[IRP_MJ_READ] and
//               MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] with
//               NeutralizePassThroughDispatch: a NONPAGED stub that skips the
//               filter and routes every IRP directly to the lower device.
//               The keyboard continues to function; the filter is blind.
//     Tier 2 — IoDetachDevice: attempted when the unauthorized device sits at
//               the very top of the stack (nothing attached above it). Removes
//               it from the IRP delivery path entirely.
//     Self-healing — A 5-second system thread re-inspects every keyboard stack
//               and re-applies both tiers if the rootkit restores its handler.
//
//   DMA hardware keyloggers (ALERT_UNAUTHORIZED_DMA):
//     Tier 1 — VT-d: clear the IOMMU context entry's Present bit, then flush
//               context cache (CCMD_REG global invalidation) and the IOTLB
//               (IOTLB invalidation register). The device loses all DMA access.
//     Tier 2 — PCIe Command.BME: when VT-d is unavailable, write back the
//               Command register with Bus Master Enable (bit 2) cleared via
//               ECAM. The device can no longer initiate DMA transactions.
//
// IRQL notes:
//   NeutralizePassThroughDispatch  NONPAGED — runs at any IRQL (keyboard IRPs
//                                  arrive at DISPATCH_LEVEL in some paths).
//   All other functions            PASSIVE_LEVEL (PAGE section).

#include "KernelGuard.h"

// Forward declarations for static functions (required before #pragma alloc_text).
static NTSTATUS PciEcamRead(UCHAR, UCHAR, UCHAR, ULONG, PVOID, ULONG);
static NTSTATUS PciEcamWrite(UCHAR, UCHAR, UCHAR, ULONG, PVOID, ULONG);
static NTSTATUS PciGetEcamBaseFromAcpi(VOID);
static NTSTATUS PciDisableBusMaster(UCHAR, UCHAR, UCHAR);
static VOID     VtdFlushIommu(PVOID);
static NTSTATUS VtdInvalidateContextEntry(PVOID, UCHAR, UCHAR, UCHAR);
static NTSTATUS NeutralizeKbdFilterDriver(PDRIVER_OBJECT, PDEVICE_OBJECT,
                                           PDEVICE_OBJECT, BOOLEAN);
static VOID     EnsureNeutralizedStillPatched(VOID);
static VOID     HwMonitorThreadFunc(PVOID);

#pragma alloc_text(PAGE, HwKeyloggerInitialize)
#pragma alloc_text(PAGE, HwKeyloggerUninitialize)
#pragma alloc_text(PAGE, PciWalkBusTree)
#pragma alloc_text(PAGE, PciDetectDiscrepancies)
#pragma alloc_text(PAGE, VtdVerifyDmaProtection)
#pragma alloc_text(PAGE, VtdFlushIommu)
#pragma alloc_text(PAGE, VtdInvalidateContextEntry)
#pragma alloc_text(PAGE, PciEcamWrite)
#pragma alloc_text(PAGE, PciDisableBusMaster)
#pragma alloc_text(PAGE, NeutralizeKbdFilterDriver)
#pragma alloc_text(PAGE, EnsureNeutralizedStillPatched)
#pragma alloc_text(PAGE, HwMonitorThreadFunc)

//==============================================================================
// Neutralized filter table
// Accessed at any IRQL by NeutralizePassThroughDispatch — must stay NONPAGED.
// Written only at PASSIVE_LEVEL (under g_NeutralizedLock).
//==============================================================================

#define MAX_NEUTRALIZED_FILTERS 16

typedef struct _NEUTRALIZED_FILTER {
    PDEVICE_OBJECT   UnauthorizedDev;  // The filter's device object
    PDEVICE_OBJECT   LowerDev;         // Device below it (receives bypassed IRPs)
    PDRIVER_DISPATCH OriginalRead;     // Saved handler for restore-on-unload
    PDRIVER_DISPATCH OriginalIntDc;    // Saved IRP_MJ_INTERNAL_DEVICE_CONTROL
    CHAR             DriverName[128];  // ASCII copy, for logging only
} NEUTRALIZED_FILTER;

// Non-paged globals — NeutralizePassThroughDispatch reads these at high IRQL.
static NEUTRALIZED_FILTER g_NeutralizedFilters[MAX_NEUTRALIZED_FILTERS];
static volatile ULONG     g_NeutralizedCount;
static KSPIN_LOCK         g_NeutralizedLock;

// Monitoring thread
#define MONITOR_INTERVAL_MS 5000ULL
static PKTHREAD g_HwMonitorThread;
static KEVENT   g_HwMonitorStop;

//==============================================================================
// NeutralizePassThroughDispatch  [NONPAGED]
// Replacement dispatch routine installed over an unauthorized filter's
// MajorFunction[IRP_MJ_READ] and MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL].
//
// Behaviour: looks up the lower device object for the current device, skips
// the current IRP stack location (so the original filter code is bypassed),
// and forwards the IRP to the lower driver. The keyboard works normally;
// the filter never sees the keystroke data.
//
// Falls through to STATUS_DEVICE_NOT_CONNECTED if the device is not in the
// table (should not happen, but safe default).
//==============================================================================

static NTSTATUS NeutralizePassThroughDispatch(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    PDEVICE_OBJECT lowerDev = NULL;

    KIRQL irql;
    KeAcquireSpinLock(&g_NeutralizedLock, &irql);
    ULONG count = g_NeutralizedCount;
    for (ULONG i = 0; i < count; i++) {
        if (g_NeutralizedFilters[i].UnauthorizedDev == DevObj) {
            lowerDev = g_NeutralizedFilters[i].LowerDev;
            break;
        }
    }
    KeReleaseSpinLock(&g_NeutralizedLock, irql);

    if (!lowerDev) {
        Irp->IoStatus.Status      = STATUS_DEVICE_NOT_CONNECTED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(lowerDev, Irp);
}

//==============================================================================
// ECAM helpers
//==============================================================================

static NTSTATUS PciEcamRead(UCHAR Bus, UCHAR Device, UCHAR Function,
                             ULONG Offset, PVOID Buffer, ULONG Length)
{
    PAGED_CODE();
    if (!g_EcamBase.QuadPart)
        return STATUS_DEVICE_NOT_READY;

    ULONG64 off = ((ULONG64)Bus << 20) | ((ULONG64)Device << 15)
                | ((ULONG64)Function << 12) | (Offset & 0xFFF);
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = g_EcamBase.QuadPart + (LONGLONG)off;

    PVOID va = MmMapIoSpace(pa, Length, MmNonCached);
    if (!va)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(Buffer, va, Length);
    MmUnmapIoSpace(va, Length);
    return STATUS_SUCCESS;
}

static NTSTATUS PciEcamWrite(UCHAR Bus, UCHAR Device, UCHAR Function,
                              ULONG Offset, PVOID Buffer, ULONG Length)
{
    PAGED_CODE();
    if (!g_EcamBase.QuadPart)
        return STATUS_DEVICE_NOT_READY;

    ULONG64 off = ((ULONG64)Bus << 20) | ((ULONG64)Device << 15)
                | ((ULONG64)Function << 12) | (Offset & 0xFFF);
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = g_EcamBase.QuadPart + (LONGLONG)off;

    PVOID va = MmMapIoSpace(pa, Length, MmNonCached);
    if (!va)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(va, Buffer, Length);
    MmUnmapIoSpace(va, Length);
    return STATUS_SUCCESS;
}

//==============================================================================
// PciGetEcamBaseFromAcpi — stub; caller must populate g_EcamBase from MCFG.
//==============================================================================

#pragma pack(push, 1)
typedef struct _ACPI_TABLE_HEADER {
    ULONG Signature; ULONG Length; UCHAR Revision; UCHAR Checksum;
    UCHAR OemId[6];  UCHAR OemTableId[8]; ULONG OemRevision;
    ULONG CreatorId; ULONG CreatorRevision;
} ACPI_TABLE_HEADER;

typedef struct _MCFG_ALLOC_ENTRY {
    ULONG64 BaseAddress;
    USHORT  PciSegment;
    UCHAR   StartBusNumber;
    UCHAR   EndBusNumber;
    ULONG   Reserved;
} MCFG_ALLOC_ENTRY;
#pragma pack(pop)

static NTSTATUS PciGetEcamBaseFromAcpi(VOID)
{
    PAGED_CODE();
    // Stub: integrate with ACPI MCFG table access for a production system.
    return STATUS_NOT_IMPLEMENTED;
}

//==============================================================================
// PciWalkBusTree
// Iterates all buses, devices, functions via ECAM. Populates g_PciDevices[].
//==============================================================================

NTSTATUS PciWalkBusTree(VOID)
{
    PAGED_CODE();

    if (!g_EcamBase.QuadPart) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG/M2] PciWalkBusTree: ECAM base not set — skipping\n");
        return STATUS_DEVICE_NOT_READY;
    }

    g_PciDeviceCount = 0;

    for (UCHAR bus = 0; bus < 255; bus++) {
        for (UCHAR dev = 0; dev < 32; dev++) {
            for (UCHAR func = 0; func < 8; func++) {

                PCI_CONFIG_HEADER hdr;
                RtlZeroMemory(&hdr, sizeof(hdr));
                if (!NT_SUCCESS(PciEcamRead(bus, dev, func, 0, &hdr, sizeof(hdr))))
                    continue;
                if (hdr.VendorId == 0xFFFF)
                    goto next_func;
                if (g_PciDeviceCount >= MAX_PCI_DEVICES)
                    return STATUS_SUCCESS;

                PPCI_DISCOVERY_ENTRY e = &g_PciDevices[g_PciDeviceCount];
                e->Bus       = bus;
                e->Device    = dev;
                e->Function  = func;
                e->VendorId  = hdr.VendorId;
                e->DeviceId  = hdr.DeviceId;
                e->BaseClass = hdr.ClassCode[2];
                e->SubClass  = hdr.ClassCode[1];
                e->IsKeyboardRelated =
                    (hdr.ClassCode[2] == 0x09) ||
                    (hdr.ClassCode[2] == 0x0C && hdr.ClassCode[1] == 0x03);
                e->DmaCapable = FALSE;
                for (int b = 0; b < 6; b++) {
                    if (hdr.Bar[b]) { e->DmaCapable = TRUE; break; }
                }
                g_PciDeviceCount++;

                if (func == 0 && !(hdr.HeaderType & 0x80))
                    goto next_device;
                continue;
next_func:;
            }
next_device:;
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG/M2] PCIe scan: %u devices\n", g_PciDeviceCount);
    return STATUS_SUCCESS;
}

//==============================================================================
// PciDisableBusMaster
// Clears Command.BME (bit 2) in PCI config space to prevent the device from
// initiating DMA transactions. Used when VT-d is not available.
//==============================================================================

static NTSTATUS PciDisableBusMaster(UCHAR Bus, UCHAR Dev, UCHAR Func)
{
    PAGED_CODE();
    if (!g_EcamBase.QuadPart)
        return STATUS_DEVICE_NOT_READY;

    USHORT cmd = 0;
    NTSTATUS st = PciEcamRead(Bus, Dev, Func, 0x04 /* Command */, &cmd, sizeof(cmd));
    if (!NT_SUCCESS(st))
        return st;

    if (!(cmd & 0x0004))
        return STATUS_SUCCESS;   // BME already cleared

    cmd &= ~(USHORT)0x0004;  // Clear Bus Master Enable
    st = PciEcamWrite(Bus, Dev, Func, 0x04, &cmd, sizeof(cmd));
    if (!NT_SUCCESS(st))
        return st;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[KG/M2] PCIe %02X:%02X.%X — Bus Master Enable cleared\n",
               Bus, Dev, Func);
    return STATUS_SUCCESS;
}

//==============================================================================
// VtdFlushIommu
// Issues a global context-cache invalidation followed by a global IOTLB flush.
// Must be called after modifying any VT-d context entry to ensure the hardware
// is not serving stale translations.
//==============================================================================

static VOID VtdFlushIommu(PVOID VtdRegs)
{
    PAGED_CODE();

    // Read ECAP to find the actual IOTLB register offset.
    // ECAP.IRO (bits 17:8) × 16 = IOTLB invalidate register address.
    ULONG64 ecap = *(volatile ULONG64 *)((PUCHAR)VtdRegs + VTD_ECAP_REG);
    ULONG   iroOffset = (ULONG)(((ecap >> 8) & 0x3FF) * 16);
    if (!iroOffset)
        iroOffset = VTD_IOTLB_REG;  // Fall back to spec default if ECAP unreadable

    // ── Step 1: flush context cache (global) ──────────────────────────────────
    // Write CCMD_REG with CIRG=11b (global) | IVT=1 (bit 63).
    volatile ULONG64 *ccmd = (volatile ULONG64 *)((PUCHAR)VtdRegs + VTD_CCMD_REG);
    *ccmd = VTD_CCMD_GLOBAL_INVAL;
    _mm_mfence();

    // Poll until bit 63 (IVT) clears — hardware clears it when done.
    ULONG spin = 0;
    while ((*ccmd >> 63) & 1) {
        _mm_pause();
        if (++spin > 100000) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[KG/M2] VTD context-cache flush timed out\n");
            break;
        }
    }

    // ── Step 2: flush IOTLB (global) ─────────────────────────────────────────
    // The IOTLB register is a 64-bit register at IRO*16+8.
    volatile ULONG64 *iotlb =
        (volatile ULONG64 *)((PUCHAR)VtdRegs + iroOffset + 8);
    *iotlb = VTD_IOTLB_GLOBAL_INVAL;
    _mm_mfence();

    spin = 0;
    while ((*iotlb >> 63) & 1) {
        _mm_pause();
        if (++spin > 100000) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[KG/M2] VTD IOTLB flush timed out\n");
            break;
        }
    }
}

//==============================================================================
// VtdInvalidateContextEntry
// Clears the Present bit of the VT-d context entry for a specific BDF, then
// flushes the IOMMU. After this the device has no valid DMA mappings.
//==============================================================================

static NTSTATUS VtdInvalidateContextEntry(PVOID VtdRegs, UCHAR Bus,
                                           UCHAR Dev, UCHAR Func)
{
    PAGED_CODE();

    // Locate and map the root table.
    ULONG64 rtAddr = *(volatile ULONG64 *)((PUCHAR)VtdRegs + VTD_RTADDR_REG);
    rtAddr &= ~0xFFFULL;
    if (!rtAddr)
        return STATUS_NOT_FOUND;

    PHYSICAL_ADDRESS rtPhys;
    rtPhys.QuadPart = (LONGLONG)rtAddr;
    PVTD_ROOT_ENTRY rootTable =
        MmMapIoSpace(rtPhys, 256 * sizeof(VTD_ROOT_ENTRY), MmNonCached);
    if (!rootTable)
        return STATUS_INSUFFICIENT_RESOURCES;

    PVTD_ROOT_ENTRY rootEntry = &rootTable[Bus];
    if (!rootEntry->Present) {
        MmUnmapIoSpace(rootTable, 256 * sizeof(VTD_ROOT_ENTRY));
        return STATUS_NOT_FOUND;
    }

    PHYSICAL_ADDRESS ctxPhys;
    ctxPhys.QuadPart = (LONGLONG)(rootEntry->ContextTablePtr << 12);
    MmUnmapIoSpace(rootTable, 256 * sizeof(VTD_ROOT_ENTRY));

    // Map context table and clear the entry for this Dev:Func.
    PVTD_CONTEXT_ENTRY ctxTable =
        MmMapIoSpace(ctxPhys, 256 * sizeof(VTD_CONTEXT_ENTRY), MmNonCached);
    if (!ctxTable)
        return STATUS_INSUFFICIENT_RESOURCES;

    ULONG devFunc = (ULONG)(Dev << 3) | (Func & 0x7);
    PVTD_CONTEXT_ENTRY entry = &ctxTable[devFunc];

    if (entry->Present) {
        entry->Present = 0;      // Block all DMA translations for this device
        _mm_mfence();            // Ensure the store reaches memory before IOTLB flush
        MmUnmapIoSpace(ctxTable, 256 * sizeof(VTD_CONTEXT_ENTRY));

        VtdFlushIommu(VtdRegs); // Invalidate cached translations

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG/M2] VT-d: context entry cleared for %02X:%02X.%X — "
                   "DMA blocked\n", Bus, Dev, Func);
    } else {
        MmUnmapIoSpace(ctxTable, 256 * sizeof(VTD_CONTEXT_ENTRY));
    }

    return STATUS_SUCCESS;
}

//==============================================================================
// NeutralizeKbdFilterDriver
// Installs NeutralizePassThroughDispatch over the unauthorized driver's
// IRP_MJ_READ and IRP_MJ_INTERNAL_DEVICE_CONTROL handlers. Records the
// (UnauthorizedDev, LowerDev) pair so the stub can route correctly.
//
// If the unauthorized device is the topmost in the stack, also calls
// IoDetachDevice to remove it from the IRP delivery path entirely.
//==============================================================================

static NTSTATUS NeutralizeKbdFilterDriver(PDRIVER_OBJECT UnauthorizedDrv,
                                           PDEVICE_OBJECT UnauthorizedDev,
                                           PDEVICE_OBJECT LowerDev,
                                           BOOLEAN IsTopmost)
{
    PAGED_CODE();

    // Copy driver name before acquiring the spinlock (name buffer may be paged).
    CHAR nameBuf[128] = "<unknown>";
    if (UnauthorizedDrv->DriverName.Buffer) {
        ULONG len = min(UnauthorizedDrv->DriverName.Length / sizeof(WCHAR),
                        (ULONG)(sizeof(nameBuf) - 1));
        for (ULONG i = 0; i < len; i++)
            nameBuf[i] = (CHAR)UnauthorizedDrv->DriverName.Buffer[i];
        nameBuf[len] = '\0';
    }

    KIRQL irql;
    KeAcquireSpinLock(&g_NeutralizedLock, &irql);

    // Idempotent: if this device object is already in the table, just update
    // its lower-device pointer in case the stack was reordered.
    for (ULONG i = 0; i < g_NeutralizedCount; i++) {
        if (g_NeutralizedFilters[i].UnauthorizedDev == UnauthorizedDev) {
            g_NeutralizedFilters[i].LowerDev = LowerDev;
            KeReleaseSpinLock(&g_NeutralizedLock, irql);
            return STATUS_SUCCESS;
        }
    }

    if (g_NeutralizedCount >= MAX_NEUTRALIZED_FILTERS) {
        KeReleaseSpinLock(&g_NeutralizedLock, irql);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG/M2] Neutralized filter table full — cannot neutralize %s\n",
                   nameBuf);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Check whether the dispatch table was already patched by a previous call
    // for a different device object of the same driver.
    BOOLEAN dispatchAlreadyPatched =
        (UnauthorizedDrv->MajorFunction[IRP_MJ_READ] == NeutralizePassThroughDispatch);

    NEUTRALIZED_FILTER *nf = &g_NeutralizedFilters[g_NeutralizedCount];
    nf->UnauthorizedDev = UnauthorizedDev;
    nf->LowerDev        = LowerDev;
    // Only save originals the first time (before our stub overwrites them).
    nf->OriginalRead  = dispatchAlreadyPatched
                            ? NULL
                            : UnauthorizedDrv->MajorFunction[IRP_MJ_READ];
    nf->OriginalIntDc = dispatchAlreadyPatched
                            ? NULL
                            : UnauthorizedDrv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
    RtlCopyMemory(nf->DriverName, nameBuf, sizeof(nf->DriverName));

    // ── Tier 1: overwrite dispatch table ─────────────────────────────────────
    if (!dispatchAlreadyPatched) {
        UnauthorizedDrv->MajorFunction[IRP_MJ_READ]                   =
            NeutralizePassThroughDispatch;
        UnauthorizedDrv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
            NeutralizePassThroughDispatch;
        KeMemoryBarrier();
    }

    // Bump count atomically before releasing the lock so the stub sees
    // the new entry as soon as it starts looking.
    InterlockedIncrement((volatile LONG *)&g_NeutralizedCount);

    KeReleaseSpinLock(&g_NeutralizedLock, irql);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[KG/M2] Filter neutralized (dispatch patch): %s\n", nameBuf);

    // ── Tier 2: detach from stack if topmost ─────────────────────────────────
    // IoDetachDevice removes the attachment and drains pending IRPs before
    // returning. Only safe when UnauthorizedDev is the topmost device
    // (nothing is stacked above it), because calling it on a middle device
    // would orphan the upper portion of the stack.
    if (IsTopmost && LowerDev) {
        IoDetachDevice(LowerDev);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG/M2] Filter detached from keyboard stack: %s\n", nameBuf);
    }

    LogAlert(ALERT_KBD_FILTER_NEUTRALIZED,
             "Keyboard filter neutralized: %s (patch+%s)",
             nameBuf, IsTopmost ? "detach" : "patch-only");

    DispatchCrossModuleEvent(ALERT_KBD_FILTER_NEUTRALIZED, 2,
                             (ULONG64)(ULONG_PTR)UnauthorizedDev, 0);
    return STATUS_SUCCESS;
}

//==============================================================================
// EnsureNeutralizedStillPatched
// Called by the monitoring thread. Re-applies dispatch patches for any
// neutralized driver that restored its original handler (rootkit self-healing).
//==============================================================================

static VOID EnsureNeutralizedStillPatched(VOID)
{
    PAGED_CODE();

    // Collect re-patching work under the spinlock (no logging/sleeping inside).
    BOOLEAN repatchedAny    = FALSE;
    CHAR    repatchName[128] = {0};

    KIRQL irql;
    KeAcquireSpinLock(&g_NeutralizedLock, &irql);

    for (ULONG i = 0; i < g_NeutralizedCount; i++) {
        NEUTRALIZED_FILTER *nf = &g_NeutralizedFilters[i];
        if (!nf->UnauthorizedDev)
            continue;
        PDRIVER_OBJECT drv = nf->UnauthorizedDev->DriverObject;
        if (!drv)
            continue;

        BOOLEAN tampered = FALSE;
        if (drv->MajorFunction[IRP_MJ_READ] != NeutralizePassThroughDispatch) {
            nf->OriginalRead = drv->MajorFunction[IRP_MJ_READ];
            drv->MajorFunction[IRP_MJ_READ] = NeutralizePassThroughDispatch;
            tampered = TRUE;
        }
        if (drv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL]
                != NeutralizePassThroughDispatch) {
            nf->OriginalIntDc =
                drv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];
            drv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
                NeutralizePassThroughDispatch;
            tampered = TRUE;
        }
        if (tampered) {
            KeMemoryBarrier();
            repatchedAny = TRUE;
            RtlCopyMemory(repatchName, nf->DriverName, sizeof(repatchName));
        }
    }

    KeReleaseSpinLock(&g_NeutralizedLock, irql);

    if (repatchedAny) {
        LogAlert(ALERT_KBD_FILTER_NEUTRALIZED,
                 "Filter %s restored handler — re-patched", repatchName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG/M2] Re-patched self-restoring filter: %s\n",
                   repatchName);
    }
}

//==============================================================================
// PciDetectDiscrepancies
// Walks the device stack of \\Device\\KeyboardClass0..9. Flags drivers that are
// not in the whitelist, then immediately neutralizes them (Tier 1 + Tier 2).
//==============================================================================

NTSTATUS PciDetectDiscrepancies(VOID)
{
    PAGED_CODE();

    for (ULONG idx = 0; idx < 10; idx++) {
        WCHAR nameBuf[64];
        if (!NT_SUCCESS(RtlStringCchPrintfW(nameBuf, ARRAYSIZE(nameBuf),
                                             L"\\Device\\KeyboardClass%u", idx)))
            break;

        UNICODE_STRING kbdName;
        RtlInitUnicodeString(&kbdName, nameBuf);

        PFILE_OBJECT   fileObj = NULL;
        PDEVICE_OBJECT devObj  = NULL;
        if (!NT_SUCCESS(IoGetDeviceObjectPointer(&kbdName, FILE_READ_DATA,
                                                  &fileObj, &devObj)))
            continue;

        // Walk bottom-to-top via AttachedDevice. Track the previous (lower)
        // device so we can provide it to NeutralizeKbdFilterDriver.
        PDEVICE_OBJECT prev    = NULL;
        PDEVICE_OBJECT current = devObj;

        while (current) {
            PDRIVER_OBJECT drv = current->DriverObject;
            if (drv && drv->DriverName.Buffer) {
                if (!IsWhitelistedDriver(&drv->DriverName)) {

                    // IsTopmost: nothing is attached above this device.
                    BOOLEAN isTopmost = (current->AttachedDevice == NULL);

                    // Log the raw detection only if not already in our table.
                    BOOLEAN alreadyNeutralized = FALSE;
                    KIRQL irql;
                    KeAcquireSpinLock(&g_NeutralizedLock, &irql);
                    for (ULONG i = 0; i < g_NeutralizedCount; i++) {
                        if (g_NeutralizedFilters[i].UnauthorizedDev == current) {
                            alreadyNeutralized = TRUE;
                            break;
                        }
                    }
                    KeReleaseSpinLock(&g_NeutralizedLock, irql);

                    if (!alreadyNeutralized) {
                        LogAlert(ALERT_UNAUTHORIZED_KBD_FILTER,
                                 "Unauthorized keyboard filter detected: %wZ",
                                 &drv->DriverName);
                        InterlockedIncrement(&g_SharedState.HwDiscrepancyCount);
                    }

                    // Neutralize regardless (idempotent; re-applies if needed).
                    NeutralizeKbdFilterDriver(drv, current, prev, isTopmost);
                }
            }
            prev    = current;
            current = current->AttachedDevice;
        }

        ObDereferenceObject(fileObj);
    }

    return STATUS_SUCCESS;
}

//==============================================================================
// VtdVerifyDmaProtection
// Walks VT-d root/context tables. For each BDF that is not in the authorized
// DMA whitelist, immediately invalidates the context entry (Tier 1) and falls
// back to BME disable via ECAM (Tier 2) if VT-d is unavailable.
//==============================================================================

NTSTATUS VtdVerifyDmaProtection(VOID)
{
    PAGED_CODE();

    extern PHYSICAL_ADDRESS g_VtdMmioBase;
    if (!g_VtdMmioBase.QuadPart) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG/M2] VTD MMIO base not available — "
                   "using PCIe BME fallback for DMA mitigation\n");
        goto vtd_unavailable;
    }

    {
        PVOID vtdRegs = MmMapIoSpace(g_VtdMmioBase, 0x1000, MmNonCached);
        if (!vtdRegs)
            goto vtd_unavailable;

        ULONG64 rtAddr = *(volatile ULONG64 *)((PUCHAR)vtdRegs + VTD_RTADDR_REG);
        rtAddr &= ~0xFFFULL;

        if (!rtAddr) {
            MmUnmapIoSpace(vtdRegs, 0x1000);
            goto vtd_unavailable;
        }

        PHYSICAL_ADDRESS rtPhys;
        rtPhys.QuadPart = (LONGLONG)rtAddr;
        PVTD_ROOT_ENTRY rootTable =
            MmMapIoSpace(rtPhys, 256 * sizeof(VTD_ROOT_ENTRY), MmNonCached);
        if (!rootTable) {
            MmUnmapIoSpace(vtdRegs, 0x1000);
            goto vtd_unavailable;
        }

        for (ULONG bus = 0; bus < 256; bus++) {
            if (!rootTable[bus].Present)
                continue;

            PHYSICAL_ADDRESS ctxPhys;
            ctxPhys.QuadPart = (LONGLONG)(rootTable[bus].ContextTablePtr << 12);
            PVTD_CONTEXT_ENTRY ctxTable =
                MmMapIoSpace(ctxPhys, 256 * sizeof(VTD_CONTEXT_ENTRY), MmNonCached);
            if (!ctxTable)
                continue;

            for (ULONG devFunc = 0; devFunc < 256; devFunc++) {
                if (!ctxTable[devFunc].Present)
                    continue;

                UCHAR hwDev  = (UCHAR)(devFunc >> 3);
                UCHAR hwFunc = (UCHAR)(devFunc & 0x7);

                if (!IsAuthorizedDmaDevice((UCHAR)bus, hwDev, hwFunc)) {
                    LogAlert(ALERT_UNAUTHORIZED_DMA,
                             "Unauthorized DMA: %02X:%02X.%X — "
                             "invalidating VT-d context entry",
                             bus, hwDev, hwFunc);
                    InterlockedIncrement(&g_SharedState.HwDmaViolationCount);

                    // ── Tier 1: VT-d context entry invalidation ───────────────
                    NTSTATUS st =
                        VtdInvalidateContextEntry(vtdRegs, (UCHAR)bus,
                                                   hwDev, hwFunc);
                    if (NT_SUCCESS(st)) {
                        LogAlert(ALERT_DMA_BLOCKED_IOMMU,
                                 "DMA blocked via IOMMU: %02X:%02X.%X",
                                 bus, hwDev, hwFunc);
                        DispatchCrossModuleEvent(ALERT_DMA_BLOCKED_IOMMU, 2,
                            ((ULONG64)bus << 16) | ((ULONG64)hwDev << 8) | hwFunc,
                            0);
                    } else {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                   "[KG/M2] VT-d invalidation failed "
                                   "%02X:%02X.%X: 0x%08X — "
                                   "falling back to BME disable\n",
                                   bus, hwDev, hwFunc, st);
                        goto disable_bme_vtd;
                    }
                    continue;

disable_bme_vtd:
                    // ── Tier 2 fallback (within VT-d path) ───────────────────
                    if (NT_SUCCESS(PciDisableBusMaster((UCHAR)bus, hwDev, hwFunc))) {
                        LogAlert(ALERT_DEVICE_BME_DISABLED,
                                 "Bus Master Enable cleared (BME fallback): "
                                 "%02X:%02X.%X", bus, hwDev, hwFunc);
                    }
                }
            }

            MmUnmapIoSpace(ctxTable, 256 * sizeof(VTD_CONTEXT_ENTRY));
        }

        MmUnmapIoSpace(rootTable, 256 * sizeof(VTD_ROOT_ENTRY));
        MmUnmapIoSpace(vtdRegs, 0x1000);
        return STATUS_SUCCESS;
    }

vtd_unavailable:
    // ── Tier 2: PCIe BME disable for all unauthorized DMA-capable devices ─────
    // Walk the hardware-discovered device list. For any keyboard-related device
    // that is not in the DMA whitelist, clear its Bus Master Enable bit.
    for (ULONG i = 0; i < g_PciDeviceCount; i++) {
        PPCI_DISCOVERY_ENTRY e = &g_PciDevices[i];
        if (!e->DmaCapable || !e->IsKeyboardRelated)
            continue;
        if (!IsAuthorizedDmaDevice(e->Bus, e->Device, e->Function)) {
            LogAlert(ALERT_UNAUTHORIZED_DMA,
                     "Unauthorized keyboard-class DMA device: %02X:%02X.%X "
                     "(no VT-d — disabling bus master)",
                     e->Bus, e->Device, e->Function);
            if (NT_SUCCESS(PciDisableBusMaster(e->Bus, e->Device, e->Function))) {
                LogAlert(ALERT_DEVICE_BME_DISABLED,
                         "Bus Master Enable cleared: %02X:%02X.%X",
                         e->Bus, e->Device, e->Function);
                DispatchCrossModuleEvent(ALERT_DEVICE_BME_DISABLED, 2,
                    ((ULONG64)e->Bus << 16) | ((ULONG64)e->Device << 8) | e->Function,
                    0);
            }
            InterlockedIncrement(&g_SharedState.HwDmaViolationCount);
        }
    }
    return STATUS_SUCCESS;
}

//==============================================================================
// HwMonitorThreadFunc
// System thread body. Runs at PASSIVE_LEVEL every MONITOR_INTERVAL_MS.
// Re-checks keyboard stacks and re-applies mitigations.
//==============================================================================

static VOID HwMonitorThreadFunc(PVOID Context)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Context);

    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)(MONITOR_INTERVAL_MS * 10000ULL);

    while (KeWaitForSingleObject(&g_HwMonitorStop, Executive,
                                  KernelMode, FALSE, &interval) == STATUS_TIMEOUT) {
        PciDetectDiscrepancies();
        VtdVerifyDmaProtection();
        EnsureNeutralizedStillPatched();
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

//==============================================================================
// HwKeyloggerInitialize
// Entry point for Module 2. Detects threats and starts the monitoring thread.
//==============================================================================

NTSTATUS HwKeyloggerInitialize(VOID)
{
    PAGED_CODE();

    KeInitializeSpinLock(&g_NeutralizedLock);
    g_NeutralizedCount = 0;
    RtlZeroMemory(g_NeutralizedFilters, sizeof(g_NeutralizedFilters));
    KeInitializeEvent(&g_HwMonitorStop, NotificationEvent, FALSE);

    // Initial hardware scan (may fail gracefully if ECAM unavailable).
    NTSTATUS st = PciGetEcamBaseFromAcpi();
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG/M2] ECAM unavailable (0x%08X) — PCIe scan skipped\n",
                   st);
    } else {
        PciWalkBusTree();
    }

    // Scan and neutralize unauthorized keyboard filter drivers.
    PciDetectDiscrepancies();

    // Block unauthorized DMA (VT-d invalidation or BME fallback).
    VtdVerifyDmaProtection();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG/M2] Initialized — neutralized=%u DMA_violations=%d "
               "filter_discrepancies=%d\n",
               g_NeutralizedCount,
               g_SharedState.HwDmaViolationCount,
               g_SharedState.HwDiscrepancyCount);

    // Start the monitoring thread (5-second periodic re-check).
    HANDLE threadHandle;
    st = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL,
                               NULL, NULL, HwMonitorThreadFunc, NULL);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG/M2] Failed to start monitor thread: 0x%08X\n", st);
        return st;
    }

    ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL,
                               KernelMode, (PVOID *)&g_HwMonitorThread, NULL);
    ZwClose(threadHandle);
    return STATUS_SUCCESS;
}

//==============================================================================
// HwKeyloggerUninitialize
// Signals the monitor thread to stop, waits for it, then restores all patched
// dispatch table entries so the driver stack is clean on unload.
//==============================================================================

VOID HwKeyloggerUninitialize(VOID)
{
    PAGED_CODE();

    // Signal and wait for the monitor thread.
    if (g_HwMonitorThread) {
        KeSetEvent(&g_HwMonitorStop, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(g_HwMonitorThread, Executive,
                               KernelMode, FALSE, NULL);
        ObDereferenceObject(g_HwMonitorThread);
        g_HwMonitorThread = NULL;
    }

    // Restore all patched dispatch tables.
    // Acquiring the spinlock is unnecessary here (thread is stopped, single-threaded
    // cleanup), but kept for correctness in case of concurrent IOCTL paths.
    KIRQL irql;
    KeAcquireSpinLock(&g_NeutralizedLock, &irql);

    for (ULONG i = 0; i < g_NeutralizedCount; i++) {
        NEUTRALIZED_FILTER *nf = &g_NeutralizedFilters[i];
        if (!nf->UnauthorizedDev)
            continue;
        PDRIVER_OBJECT drv = nf->UnauthorizedDev->DriverObject;
        if (!drv)
            continue;

        // Only restore if we saved the original and our stub is still in place.
        if (nf->OriginalRead &&
            drv->MajorFunction[IRP_MJ_READ] == NeutralizePassThroughDispatch) {
            drv->MajorFunction[IRP_MJ_READ] = nf->OriginalRead;
        }
        if (nf->OriginalIntDc &&
            drv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL]
                == NeutralizePassThroughDispatch) {
            drv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = nf->OriginalIntDc;
        }
        KeMemoryBarrier();
    }

    KeReleaseSpinLock(&g_NeutralizedLock, irql);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG/M2] Uninitialized — dispatch tables restored\n");
}
