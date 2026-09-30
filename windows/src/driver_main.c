// driver_main.c
// DriverEntry and DriverUnload for KernelGuard.
//
// Boot sequence (strict ordering matters for security guarantees):
//   1. Zero/initialize shared state
//   2. Probe CPU capabilities & build mitigation strategy (Module 4 init)
//   3. Build kernel integrity baseline *before* any monitoring starts,
//      so the baseline captures the clean pre-attack state (Module 3 init)
//   4. Start hardware keylogger detection (Module 2 init)
//   5. Start PMU detection & RDTSC monitoring (Module 1 init)
//   6. Initialize secure Ring 0→Ring 3 comms channel (Module 5 init)
//   7. Create device object for user-mode shared-memory mapping requests
//
// The driver is designed as a boot-start service (SERVICE_BOOT_START in the
// INF file) so it loads before any user-mode process can interact with the
// kernel, minimizing the attack window.

#include "KernelGuard.h"

// Pool tag for this driver's allocations.
#define SCPD_POOL_TAG   'DPCS'

// Device name and symbolic link for user-mode communication setup.
#define DEVICE_NAME     L"\\Device\\KernelGuard"
#define SYMLINK_NAME    L"\\DosDevices\\KernelGuard"

// VT-d MMIO base (populated from ACPI DMAR table; zero if not available).
PHYSICAL_ADDRESS g_VtdMmioBase;

static PDEVICE_OBJECT g_DeviceObject = NULL;

//==============================================================================
// Device dispatch routines
// IRP_MJ_CREATE / IRP_MJ_CLOSE: allow user-mode to open the device.
// IRP_MJ_DEVICE_CONTROL: maps the shared memory into the caller's process.
//==============================================================================

static NTSTATUS ScpdDispatchCreate(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS ScpdDispatchClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// IOCTL code: user-mode agent calls this to get the shared memory mapping.
#define IOCTL_KG_MAP_SHARED_MEM   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, \
                                              METHOD_BUFFERED, FILE_READ_ACCESS)

// IOCTL code: returns the 32-byte HMAC key so the user-mode agent can validate
// notification signatures. Requires FILE_READ_ACCESS only.
#define IOCTL_KG_GET_HMAC_KEY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, \
                                              METHOD_BUFFERED, FILE_READ_ACCESS)

static NTSTATUS ScpdDispatchIoControl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);

    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS st  = STATUS_INVALID_DEVICE_REQUEST;

    if (ioCode == IOCTL_KG_MAP_SHARED_MEM) {
        if (ioStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PVOID)) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            PVOID userMapping = NULL;
            st = SecureCommMapToUserMode(&userMapping);
            if (NT_SUCCESS(st)) {
                *(PVOID *)Irp->AssociatedIrp.SystemBuffer = userMapping;
                Irp->IoStatus.Information = sizeof(PVOID);
            }
        }
    } else if (ioCode == IOCTL_KG_GET_HMAC_KEY) {
        // Return the 32-byte HMAC key to the user-mode monitoring agent.
        // The caller must have FILE_READ_ACCESS; the key is only valid for
        // the current boot session (re-derived fresh at every DriverEntry).
        if (ioStack->Parameters.DeviceIoControl.OutputBufferLength < HMAC_KEY_SIZE) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_HmacKey, HMAC_KEY_SIZE);
            Irp->IoStatus.Information = HMAC_KEY_SIZE;
            st = STATUS_SUCCESS;
        }
    }

    Irp->IoStatus.Status = st;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

//==============================================================================
// DriverUnload
// Tears down all modules in reverse initialization order and removes the
// device object and symbolic link.
//==============================================================================

static VOID ScpdDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Unloading...\n");

    // Reverse initialization order: M5 → M1 → M2 → M3 → M4
    SecureCommUninitialize();
    PmuUninitialize();
    HwKeyloggerUninitialize();
    KernelIntegrityUninitialize();
    CacheMitigationUninitialize();

    // Remove symbolic link and device object.
    UNICODE_STRING symlinkName;
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (g_DeviceObject)
        IoDeleteDevice(g_DeviceObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Unload complete.\n");
}

//==============================================================================
// DriverEntry
// Called by the kernel loader at driver initialization time.
//==============================================================================

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] DriverEntry — KernelGuard v1.0\n");

    // ── Zero shared state ────────────────────────────────────────────────────
    RtlZeroMemory(&g_SharedState, sizeof(g_SharedState));
    KeInitializeSpinLock(&g_SharedState.StateLock);
    g_SharedState.IntegrityValid = TRUE;
    g_VtdMmioBase.QuadPart = 0;

    // ── Step 1: Probe CPU and initialize mitigation engine ───────────────────
    // Must be first — all subsequent modules depend on g_CpuMit[] being filled.
    NTSTATUS st = CacheMitigationInitialize();
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] CacheMitigationInitialize failed: 0x%08X\n", st);
        return st;
    }

    // ── Step 2: Build integrity baseline (must run before any rootkit scan) ──
    st = KernelIntegrityInitialize();
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] KernelIntegrityInitialize failed: 0x%08X\n", st);
        CacheMitigationUninitialize();
        return st;
    }

    // ── Step 3: Hardware keylogger detection ─────────────────────────────────
    st = HwKeyloggerInitialize();
    if (!NT_SUCCESS(st)) {
        // Non-fatal: log and continue. PCIe scan may fail on systems without
        // ECAM or VT-d. Core mitigation still applies.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG] HwKeyloggerInitialize: 0x%08X (non-fatal)\n", st);
    }

    // ── Step 4: PMU detection and RDTSC profiling ────────────────────────────
    st = PmuInitialize();
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG] PmuInitialize: 0x%08X (non-fatal)\n", st);
    }

    // ── Step 5: Secure comms channel ─────────────────────────────────────────
    st = SecureCommInitialize();
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] SecureCommInitialize failed: 0x%08X\n", st);
        PmuUninitialize();
        KernelIntegrityUninitialize();
        CacheMitigationUninitialize();
        return st;
    }

    // ── Step 6: Create device object ─────────────────────────────────────────
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, DEVICE_NAME);

    st = IoCreateDevice(DriverObject,
                        0,              // No device extension needed
                        &devName,
                        FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN,
                        FALSE,          // Not exclusive
                        &g_DeviceObject);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] IoCreateDevice failed: 0x%08X\n", st);
        SecureCommUninitialize();
        PmuUninitialize();
        KernelIntegrityUninitialize();
        CacheMitigationUninitialize();
        return st;
    }

    // ── Step 7: Create symbolic link for user-mode access ────────────────────
    UNICODE_STRING symlinkName;
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    st = IoCreateSymbolicLink(&symlinkName, &devName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(g_DeviceObject);
        SecureCommUninitialize();
        PmuUninitialize();
        KernelIntegrityUninitialize();
        CacheMitigationUninitialize();
        return st;
    }

    // ── Wire up dispatch table ───────────────────────────────────────────────
    DriverObject->DriverUnload                          = ScpdDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]          = ScpdDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = ScpdDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = ScpdDispatchIoControl;

    // ── Compute initial shared state integrity hash ───────────────────────────
    UpdateSharedStateHash();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] DriverEntry complete — all modules active.\n");
    return STATUS_SUCCESS;
}
