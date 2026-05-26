// secure_comms.c
// Module 5: Secure Ring 0 to Ring 3 Communication.
//
// Since standard DeviceIoControl can be intercepted by a rootkit that has
// hooked the driver dispatch table, this module implements two alternative
// channels:
//
// Primary:   A non-paged shared memory region mapped into both kernel and
//            user address spaces. Each notification payload is authenticated
//            with HMAC-SHA256 using a key derived at boot time. The user-mode
//            monitoring agent validates the HMAC before trusting the payload.
//            A sequence number prevents replay attacks.
//
// Secondary: A covert MSR channel. The driver writes an alert code into an
//            unused MSR. The user-mode helper (a minimal signed kernel driver
//            that exposes a NtQuerySystemInformation interface) reads the MSR
//            and reports it. Because the helper runs Ring-0 code that reads
//            the MSR directly, it bypasses any device-stack hook.
//
// Key derivation: at boot, the HMAC key is seeded from RDTSC XOR'd with the
// current system time. A production implementation would use TPM2_Unseal to
// unseal a key blob that was sealed to the current PCR state, ensuring that
// the key is only accessible when the system is in a trusted boot state.

#include "KernelGuard.h"

#pragma alloc_text(PAGE, SecureCommInitialize)
#pragma alloc_text(PAGE, SecureCommUninitialize)
#pragma alloc_text(PAGE, SecureCommNotify)

static PMDL g_SharedMemMdl = NULL;

//==============================================================================
// SecureCommInitialize
// Allocates the non-paged shared memory and derives the HMAC key.
// Must be called at PASSIVE_LEVEL.
//==============================================================================

NTSTATUS SecureCommInitialize(VOID)
{
    PAGED_CODE();

    // ── Allocate contiguous non-paged memory for the shared region ──────────
    PHYSICAL_ADDRESS highestAcceptable;
    highestAcceptable.QuadPart = (LONGLONG)-1;

    g_SharedMemKernel = (PSHARED_MEM_REGION)
        MmAllocateContiguousMemory(sizeof(SHARED_MEM_REGION), highestAcceptable);
    if (!g_SharedMemKernel)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_SharedMemKernel, sizeof(SHARED_MEM_REGION));

    // ── Create an MDL to allow user-mode mapping ─────────────────────────────
    g_SharedMemMdl = IoAllocateMdl(g_SharedMemKernel,
                                   (ULONG)sizeof(SHARED_MEM_REGION),
                                   FALSE, FALSE, NULL);
    if (!g_SharedMemMdl) {
        MmFreeContiguousMemory(g_SharedMemKernel);
        g_SharedMemKernel = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Lock the pages so they stay resident and can be mapped user-mode.
    MmBuildMdlForNonPagedPool(g_SharedMemMdl);

    // ── Derive HMAC key ──────────────────────────────────────────────────────
    // Seed from the processor's TSC (high-entropy at boot) XOR'd with the
    // interrupt time (provides additional entropy from system activity).
    // A production system uses TPM-sealed key material here.
    LARGE_INTEGER sysTime;
    KeQuerySystemTimePrecise(&sysTime);
    ULONG64 seed = __rdtsc() ^ (ULONG64)sysTime.QuadPart;

    for (ULONG i = 0; i < HMAC_KEY_SIZE; i++) {
        // Rotate and XOR to spread entropy across all 32 key bytes.
        seed = (seed >> 7) | (seed << 57);
        seed ^= __rdtsc();
        g_HmacKey[i] = (UCHAR)(seed & 0xFF);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Secure comms channel initialized (shared mem @ 0x%p)\n",
               g_SharedMemKernel);
    return STATUS_SUCCESS;
}

//==============================================================================
// SecureCommMapToUserMode
// Maps the shared memory region into the current process's address space.
// Called from the driver's IRP_MJ_DEVICE_CONTROL handler when the user-mode
// monitoring agent requests the channel mapping.
// Returns the user-mode VA in *UserMapping.
//==============================================================================

NTSTATUS SecureCommMapToUserMode(PVOID *UserMapping)
{
    PAGED_CODE();

    if (!g_SharedMemMdl || !UserMapping)
        return STATUS_INVALID_PARAMETER;

    __try {
        *UserMapping = MmMapLockedPagesSpecifyCache(
            g_SharedMemMdl,
            UserMode,
            MmNonCached,
            NULL,
            FALSE,
            NormalPagePriority | MdlMappingNoExecute);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return (*UserMapping) ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

//==============================================================================
// SecureCommNotify
// Writes a HMAC-authenticated notification to the circular ring buffer in the
// shared memory region. Thread-safe via InterlockedIncrement on WriteIndex.
// Called at PASSIVE_LEVEL (BCrypt HMAC computation).
//==============================================================================

NTSTATUS SecureCommNotify(ULONG AlertType, ULONG AlertLevel,
                          ULONG64 Param1, ULONG64 Param2)
{
    PAGED_CODE();

    if (!g_SharedMemKernel)
        return STATUS_DEVICE_NOT_READY;

    // Atomically claim a slot in the ring buffer.
    ULONG slotIdx = InterlockedIncrement((PLONG)&g_SharedMemKernel->DriverNonce) - 1;
    ULONG idx     = slotIdx % NOTIFICATION_SLOTS;
    PSECURE_NOTIFICATION notif = &g_SharedMemKernel->Notifications[idx];

    // ── Fill notification fields ─────────────────────────────────────────────
    notif->Magic          = NOTIFY_MAGIC;
    notif->SequenceNumber = slotIdx;
    notif->AlertType      = AlertType;
    notif->AlertLevel     = AlertLevel;
    notif->Timestamp      = KeQueryPerformanceCounter(NULL).QuadPart;
    notif->Param1         = Param1;
    notif->Param2         = Param2;
    RtlZeroMemory(notif->Hmac, sizeof(notif->Hmac));

    // ── Compute HMAC-SHA256 over all fields except the Hmac tail ─────────────
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                     NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st)) goto out;

    st = BCryptCreateHash(hAlg, &hHash, NULL, 0,
                          g_HmacKey, HMAC_KEY_SIZE, 0);
    if (!NT_SUCCESS(st)) goto out_alg;

    // Hash all fields up to (but not including) the Hmac field itself.
    ULONG authDataLen = FIELD_OFFSET(SECURE_NOTIFICATION, Hmac);
    st = BCryptHashData(hHash, (PUCHAR)notif, authDataLen, 0);
    if (!NT_SUCCESS(st)) goto out_hash;

    st = BCryptFinishHash(hHash, notif->Hmac, 32, 0);

out_hash:
    BCryptDestroyHash(hHash);
out_alg:
    BCryptCloseAlgorithmProvider(hAlg, 0);
out:
    if (!NT_SUCCESS(st))
        return st;

    // ── Publish to the ring buffer (release store) ───────────────────────────
    // MFENCE ensures the notification is fully written before WriteIndex advances.
    MEMORY_BARRIER();
    InterlockedIncrement((PLONG)&g_SharedMemKernel->WriteIndex);
    InterlockedIncrement(&g_SharedState.NotificationsSent);

    return STATUS_SUCCESS;
}

//==============================================================================
// SecureCommMsrSignal / SecureCommMsrClear
// Covert MSR-based signal channel. Writes the alert type into bits [63:32] of
// a chosen MSR and a magic value in bits [31:0].
// The user-mode helper reads this MSR via a lightweight kernel driver helper.
// Safe at any IRQL (__writemsr is IRQL-agnostic).
//
// MSR 0x150 (IA32_SMRR_PHYSBASE) is chosen as it is not typically used on
// non-SGX systems. A production implementation would choose a vendor-specific
// MSR that is readable but not architecturally significant.
//==============================================================================

VOID SecureCommMsrSignal(ULONG AlertType)
{
    // MSR_COVERT_SIGNAL (0x150) is unimplemented or SMM-only on many CPUs;
    // a write attempt causes #GP. Catch it so the driver does not crash.
    __try {
        ULONG64 value = ((ULONG64)AlertType << 32) | SIGNAL_MAGIC;
        __writemsr(MSR_COVERT_SIGNAL, value);
        InterlockedIncrement(&g_SharedState.MsrSignalsSent);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

VOID SecureCommMsrClear(VOID)
{
    __try {
        __writemsr(MSR_COVERT_SIGNAL, 0ULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

//==============================================================================
// SecureCommUninitialize
//==============================================================================

VOID SecureCommUninitialize(VOID)
{
    PAGED_CODE();

    SecureCommMsrClear();

    if (g_SharedMemMdl) {
        MmUnlockPages(g_SharedMemMdl);
        IoFreeMdl(g_SharedMemMdl);
        g_SharedMemMdl = NULL;
    }

    if (g_SharedMemKernel) {
        RtlSecureZeroMemory(g_SharedMemKernel, sizeof(SHARED_MEM_REGION));
        MmFreeContiguousMemory(g_SharedMemKernel);
        g_SharedMemKernel = NULL;
    }

    // Zero the HMAC key so it cannot be recovered after unload.
    RtlSecureZeroMemory(g_HmacKey, HMAC_KEY_SIZE);
}
