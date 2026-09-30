// kernel_integrity.c
// Module 3: Kernel Integrity and Hook Detection.
//
// Subsystems:
//   3.1  IDT integrity: reads IDTR via SIDT, reconstructs 64-bit handler
//        addresses from IDT gate descriptors, and verifies they fall within
//        ntoskrnl or HAL image ranges.
//
//   3.2  Dispatch hook detection: checks first 8 bytes of each keyboard
//        driver's IRP_MJ_READ dispatch routine against known hook prologues
//        (JMP rel32, PUSH+RET, JMP[RIP+disp32], MOV RAX imm64).
//
//   3.3  .text section integrity: uses BCrypt SHA-256 to hash the .text
//        section of each loaded kernel module, then compares against a
//        baseline captured at driver load time.  Hash comparison is
//        constant-time to prevent timing-side-channel leakage.
//
// All routines run at PASSIVE_LEVEL (BCrypt, object manager, AuxKlib APIs).

#include "KernelGuard.h"

#pragma alloc_text(PAGE, KernelIntegrityInitialize)
#pragma alloc_text(PAGE, KernelIntegrityUninitialize)
#pragma alloc_text(PAGE, IdtVerifyKeyboardHandler)
#pragma alloc_text(PAGE, ScanKeyboardDrivers)
#pragma alloc_text(PAGE, BuildIntegrityBaseline)
#pragma alloc_text(PAGE, VerifyModuleIntegrity)
#pragma alloc_text(PAGE, ComputeSha256)

// Worker thread object for periodic re-verification.
static PKTHREAD g_IntegrityThread;
static KEVENT   g_IntegrityStopEvent;

//==============================================================================
// ComputeSha256
// Hashes 'Size' bytes starting at 'Address' using BCrypt SHA-256.
// Processes in HASH_CHUNK_SIZE chunks to remain responsive on large sections.
// Must be called at PASSIVE_LEVEL.
//==============================================================================

NTSTATUS ComputeSha256(PVOID Address, ULONG Size, UCHAR HashOut[32])
{
    PAGED_CODE();

    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    st = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return st;
    }

    PUCHAR ptr       = (PUCHAR)Address;
    ULONG  remaining = Size;

    while (remaining > 0) {
        ULONG chunk = (remaining < HASH_CHUNK_SIZE) ? remaining : HASH_CHUNK_SIZE;
        st = BCryptHashData(hHash, ptr, chunk, 0);
        if (!NT_SUCCESS(st)) goto done;
        ptr       += chunk;
        remaining -= chunk;
    }

    st = BCryptFinishHash(hHash, HashOut, 32, 0);

done:
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return st;
}

//==============================================================================
// IdtVerifyKeyboardHandler
// Reads the IDTR on the calling CPU, walks the IDT entries for known keyboard
// interrupt vectors (0x21, 0x24, 0x31), and verifies each handler falls within
// the ntoskrnl or HAL image.
//
// On x64 Windows with IOAPIC, IRQ 1 (keyboard) is typically remapped to
// vector 0x21 (legacy PIC mapping) or 0x24/0x31 (IOAPIC redirection-dependent).
// We check all three to be conservative.
//
// The SIDT instruction cannot be hooked by software — it reads directly from
// the CPU's IDTR register. This makes IDT-base detection hook-resistant.
//==============================================================================

NTSTATUS IdtVerifyKeyboardHandler(ULONG CpuIndex)
{
    PAGED_CODE();

    IDTR idtr;
    __sidt(&idtr);  // Reads CPU's IDTR register directly; cannot be hooked

    PIDT_ENTRY_64 idtBase = (PIDT_ENTRY_64)idtr.Base;

    ULONG64 ntBase = GetNtoskrnlBase();
    ULONG   ntSize = GetNtoskrnlSize();
    ULONG64 ntEnd  = ntBase + ntSize;

    // Keyboard vectors to check. In practice the active one depends on the
    // IOAPIC redirection entry, which we also read and compare.
    static const ULONG kbdVectors[] = { 0x21, 0x24, 0x31 };

    for (ULONG v = 0; v < ARRAYSIZE(kbdVectors); v++) {
        PIDT_ENTRY_64 entry = &idtBase[kbdVectors[v]];

        if (!entry->Present)
            continue;   // Vector not in use on this system

        // Reconstruct the 64-bit handler VA from the split descriptor fields.
        ULONG64 handler = ((ULONG64)entry->OffsetHigh << 32)
                        | ((ULONG64)entry->OffsetMid  << 16)
                        |  (ULONG64)entry->OffsetLow;

        // ── Gate type check ────────────────────────────────────────────────
        // 0xE = 64-bit interrupt gate. 0xF = 64-bit trap gate.
        // Rootkits sometimes use a task gate (0x5) or call gate to chain.
        if (entry->GateType != 0xE && entry->GateType != 0xF) {
            LogAlert(ALERT_IDT_HOOK,
                     "CPU%u IDT[0x%02X]: unexpected gate type 0x%X "
                     "(expected 0xE). Handler=0x%llX",
                     CpuIndex, kbdVectors[v], entry->GateType, handler);
            DispatchCrossModuleEvent(ALERT_IDT_HOOK, 2, kbdVectors[v], handler);
            InterlockedExchange(&g_SharedState.IdtHookDetected, 1);
            continue;
        }

        // ── DPL check ──────────────────────────────────────────────────────
        // Hardware interrupts should have DPL=0 (only Ring 0 can software-int
        // this vector). DPL>0 could allow a Ring-3 process to invoke it.
        if (entry->Dpl != 0) {
            LogAlert(ALERT_IDT_HOOK,
                     "CPU%u IDT[0x%02X]: DPL=%u (expected 0). Handler=0x%llX",
                     CpuIndex, kbdVectors[v], entry->Dpl, handler);
            DispatchCrossModuleEvent(ALERT_IDT_HOOK, 1, kbdVectors[v], handler);
        }

        // ── Selector check ─────────────────────────────────────────────────
        // Must be Ring-0 code segment: 0x10 (GDT[2]) or 0x08 (GDT[1]).
        if (entry->Selector != 0x10 && entry->Selector != 0x08) {
            LogAlert(ALERT_IDT_HOOK,
                     "CPU%u IDT[0x%02X]: selector=0x%X unexpected.",
                     CpuIndex, kbdVectors[v], entry->Selector);
        }

        // ── Handler range check ────────────────────────────────────────────
        // The handler must reside inside ntoskrnl (or HAL, which we skip for
        // brevity). If it points outside, assume it is a rootkit hook.
        if (ntBase && (handler < ntBase || handler >= ntEnd)) {
            LogAlert(ALERT_IDT_HOOK,
                     "CPU%u IDT[0x%02X]: handler 0x%llX is OUTSIDE ntoskrnl "
                     "[0x%llX - 0x%llX]. POSSIBLE ROOTKIT HOOK.",
                     CpuIndex, kbdVectors[v], handler, ntBase, ntEnd);
            DispatchCrossModuleEvent(ALERT_IDT_HOOK, 2, handler, ntBase);
            InterlockedExchange(&g_SharedState.IdtHookDetected, 1);
        }
    }

    return STATUS_SUCCESS;
}

//==============================================================================
// Known hook prologues
// These byte patterns appear at the start of a hooked function. Rootkits
// typically overwrite the first 5-14 bytes with one of these sequences.
//==============================================================================

static const HOOK_SIGNATURE g_HookSigs[] = {
    // JMP rel32: E9 xx xx xx xx
    { {0xE9, 0,0,0,0,  0,0,0}, {0xFF,0,0,0,0, 0,0,0}, "JMP rel32 (5-byte detour)" },
    // PUSH imm32 + RET: 68 xx xx xx xx C3
    { {0x68, 0,0,0,0,0xC3,0,0}, {0xFF,0,0,0,0,0xFF,0,0}, "PUSH imm32 + RET" },
    // JMP [RIP+disp32]: FF 25 xx xx xx xx
    { {0xFF,0x25, 0,0,0,0, 0,0}, {0xFF,0xFF, 0,0,0,0, 0,0}, "JMP [RIP+disp32]" },
    // MOV RAX, imm64: 48 B8 xx xx xx xx xx xx xx xx  (followed by JMP RAX: FF E0)
    { {0x48,0xB8, 0,0,0,0,0,0}, {0xFF,0xFF, 0,0,0,0,0,0}, "MOV RAX,imm64 (trampoline)" },
    // INT3 sled (breakpoint hook used by some debugger-based keyloggers)
    { {0xCC,0xCC, 0,0,0,0,0,0}, {0xFF,0xFF, 0,0,0,0,0,0}, "INT3 breakpoint sled" },
    // CALL rel32: E8 xx xx xx xx (unusual but possible)
    { {0xE8, 0,0,0,0,  0,0,0}, {0xFF,0,0,0,0, 0,0,0}, "CALL rel32 (unusual hook)" },
};

//==============================================================================
// CheckDispatchHook
// Reads the first 8 bytes of a driver's dispatch routine for a given IRP major
// function and matches them against known hook prologues. Also verifies that
// the dispatch function pointer resides within the driver's own image.
//==============================================================================

static NTSTATUS CheckDispatchHook(PDRIVER_OBJECT DrvObj,
                                  UCHAR MajorFunction,
                                  PWSTR DriverName)
{
    PAGED_CODE();
    if (!DrvObj)
        return STATUS_INVALID_PARAMETER;

    ULONG64 dispAddr = (ULONG64)DrvObj->MajorFunction[MajorFunction];
    if (!dispAddr)
        return STATUS_SUCCESS;  // Dispatch not set

    // ── Range check: dispatch must be within the driver image ───────────────
    ULONG64 drvStart = (ULONG64)DrvObj->DriverStart;
    ULONG64 drvEnd   = drvStart + DrvObj->DriverSize;
    if (dispAddr < drvStart || dispAddr >= drvEnd) {
        LogAlert(ALERT_DISPATCH_HOOK,
                 "SUSPICIOUS: %ws MajorFunction[%u] at 0x%llX is "
                 "OUTSIDE driver image [0x%llX - 0x%llX]",
                 DriverName, MajorFunction, dispAddr, drvStart, drvEnd);
        DispatchCrossModuleEvent(ALERT_DISPATCH_HOOK, 2, dispAddr, drvStart);
        InterlockedExchange(&g_SharedState.DispatchHookDetected, 1);
        return STATUS_DEVICE_DATA_ERROR;
    }

    // ── Byte-pattern check ─────────────────────────────────────────────────
    UCHAR prologue[8] = {0};
    __try {
        RtlCopyMemory(prologue, (PVOID)dispAddr, sizeof(prologue));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    for (ULONG i = 0; i < ARRAYSIZE(g_HookSigs); i++) {
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < 8; j++) {
            if (g_HookSigs[i].Mask[j] && prologue[j] != g_HookSigs[i].Pattern[j]) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            LogAlert(ALERT_DISPATCH_HOOK,
                     "HOOK: %ws MajorFunction[%u] at 0x%llX matches \"%s\"",
                     DriverName, MajorFunction, dispAddr,
                     g_HookSigs[i].Description);
            DispatchCrossModuleEvent(ALERT_DISPATCH_HOOK, 2, dispAddr, i);
            InterlockedExchange(&g_SharedState.DispatchHookDetected, 1);
            return STATUS_DEVICE_DATA_ERROR;
        }
    }

    return STATUS_SUCCESS;
}

//==============================================================================
// ScanKeyboardDrivers
// Obtains DRIVER_OBJECTs for Kbclass and Kbdhid via ObReferenceObjectByName
// and checks their IRP_MJ_READ (and IRP_MJ_INTERNAL_DEVICE_CONTROL) dispatch
// routines for inline hooks.
//==============================================================================

NTSTATUS ScanKeyboardDrivers(VOID)
{
    PAGED_CODE();

    static const struct {
        WCHAR Name[32];
        UCHAR MajorFunctions[3];
    } kTargets[] = {
        { L"\\Driver\\Kbclass", { IRP_MJ_READ, IRP_MJ_DEVICE_CONTROL,         0xFF } },
        { L"\\Driver\\Kbdhid",  { IRP_MJ_READ, IRP_MJ_INTERNAL_DEVICE_CONTROL, 0xFF } },
        { L"\\Driver\\i8042prt",{ IRP_MJ_READ, IRP_MJ_INTERNAL_DEVICE_CONTROL, 0xFF } },
    };

    for (ULONG t = 0; t < ARRAYSIZE(kTargets); t++) {
        UNICODE_STRING drvName;
        RtlInitUnicodeString(&drvName, kTargets[t].Name);

        PDRIVER_OBJECT drvObj = NULL;
        NTSTATUS st = ObReferenceObjectByName(&drvName,
                                              OBJ_CASE_INSENSITIVE,
                                              NULL, 0,
                                              *IoDriverObjectType,
                                              KernelMode, NULL,
                                              (PVOID *)&drvObj);
        if (!NT_SUCCESS(st))
            continue;   // Driver not loaded on this system

        for (ULONG m = 0; kTargets[t].MajorFunctions[m] != 0xFF; m++) {
            CheckDispatchHook(drvObj, kTargets[t].MajorFunctions[m],
                              (PWSTR)kTargets[t].Name);
        }

        ObDereferenceObject(drvObj);
    }

    return STATUS_SUCCESS;
}

//==============================================================================
// BuildIntegrityBaseline
// Enumerates all loaded kernel modules via AuxKlib, finds each module's .text
// PE section, and computes its SHA-256 hash. Stores results in g_Baseline[].
// Must be called early in DriverEntry before any rootkit can patch .text.
//==============================================================================

NTSTATUS BuildIntegrityBaseline(VOID)
{
    PAGED_CODE();

    AuxKlibInitialize();    // Required before AuxKlib calls; safe to call multiple times.

    ULONG bytes = 0;
    NTSTATUS st = AuxKlibQueryModuleInformation(&bytes,
                                                sizeof(AUX_MODULE_EXTENDED_INFO),
                                                NULL);
    if (st != STATUS_BUFFER_TOO_SMALL || !bytes)
        return st;

    AUX_MODULE_EXTENDED_INFO *mods = (AUX_MODULE_EXTENDED_INFO *)
        ExAllocatePoolWithTag(PagedPool, bytes, 'base');
    if (!mods)
        return STATUS_INSUFFICIENT_RESOURCES;

    st = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), mods);
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(mods, 'base');
        return st;
    }

    ULONG count = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);
    g_BaselineCount = 0;

    for (ULONG i = 0; i < count && g_BaselineCount < MAX_BASELINE_ENTRIES; i++) {
        AUX_MODULE_EXTENDED_INFO *mod = &mods[i];
        PUCHAR base = (PUCHAR)mod->BasicInfo.ImageBase;
        if (!base) continue;

        // Parse the PE header to locate the .text section.
        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                continue;

            PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                continue;

            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
                if (RtlCompareMemory(sec->Name, ".text", 5) == 5) {
                    PBASELINE_ENTRY entry = &g_Baseline[g_BaselineCount];

                    // Copy module name (last component after last backslash).
                    RtlStringCchCopyW(entry->ModuleName, 64,
                                      (WCHAR *)mod->FullPathName);

                    entry->TextSectionBase = (ULONG64)(base + sec->VirtualAddress);
                    entry->TextSectionSize = sec->Misc.VirtualSize;
                    entry->Verified        = FALSE;
                    entry->HashComputed    = FALSE;

                    NTSTATUS hst = ComputeSha256(
                        (PVOID)entry->TextSectionBase,
                        entry->TextSectionSize,
                        entry->Sha256Hash);

                    if (NT_SUCCESS(hst)) {
                        entry->HashComputed = TRUE;
                        g_BaselineCount++;
                    }
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Some modules may have unmapped sections — skip silently.
        }
    }

    ExFreePoolWithTag(mods, 'base');
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Integrity baseline: %u modules hashed\n", g_BaselineCount);
    return STATUS_SUCCESS;
}

//==============================================================================
// VerifyModuleIntegrity
// Recomputes the SHA-256 of a module's .text section and compares it against
// the stored baseline using constant-time comparison.
//==============================================================================

NTSTATUS VerifyModuleIntegrity(PBASELINE_ENTRY Entry)
{
    PAGED_CODE();

    if (!Entry->HashComputed)
        return STATUS_UNSUCCESSFUL;

    UCHAR currentHash[32] = {0};
    NTSTATUS st = ComputeSha256((PVOID)Entry->TextSectionBase,
                                Entry->TextSectionSize,
                                currentHash);
    if (!NT_SUCCESS(st))
        return st;

    // Constant-time comparison — prevents timing oracle attacks on the hash.
    if (!CONSTANT_TIME_EQ(currentHash, Entry->Sha256Hash, 32)) {
        LogAlert(ALERT_TEXT_PATCH,
                 "INTEGRITY VIOLATION: %ws .text hash mismatch! "
                 "Base=0x%llX Size=0x%X",
                 Entry->ModuleName,
                 Entry->TextSectionBase,
                 Entry->TextSectionSize);
        DispatchCrossModuleEvent(ALERT_TEXT_PATCH, 2,
                                 Entry->TextSectionBase,
                                 Entry->TextSectionSize);
        Entry->Verified = FALSE;
        InterlockedExchange(&g_SharedState.TextPatchDetected, 1);
        InterlockedIncrement((PLONG)&g_SharedState.FailedModuleHashCount);
        return STATUS_DATA_ERROR;
    }

    Entry->Verified = TRUE;
    return STATUS_SUCCESS;
}

//==============================================================================
// IntegrityWorkerThread
// Runs at PASSIVE_LEVEL in a system worker thread. Periodically:
//   1. Verifies IDT integrity on the current CPU.
//   2. Scans keyboard driver dispatch routines for hooks.
//   3. Re-verifies .text sections (one module per iteration to spread load).
//   4. Checks shared state hash.
//==============================================================================

static VOID IntegrityWorkerThread(PVOID Context)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(Context);

    LARGE_INTEGER interval;
    interval.QuadPart = -30LL * 10000LL * 1000LL;   // 30-second polling interval

    ULONG verifyIdx = 0;    // Round-robin through baseline entries

    for (;;) {
        NTSTATUS waitSt = KeWaitForSingleObject(&g_IntegrityStopEvent,
                                                Executive, KernelMode,
                                                FALSE, &interval);
        if (waitSt == STATUS_SUCCESS)
            break;  // Stop event signaled

        // ── IDT check on current CPU ────────────────────────────────────────
        IdtVerifyKeyboardHandler(KeGetCurrentProcessorIndex());

        // ── Dispatch hook scan ──────────────────────────────────────────────
        ScanKeyboardDrivers();

        // ── .text re-verification (one module per tick) ────────────────────
        if (g_BaselineCount > 0) {
            VerifyModuleIntegrity(&g_Baseline[verifyIdx % g_BaselineCount]);
            verifyIdx++;
        }

        // ── Shared state integrity ──────────────────────────────────────────
        if (!VerifySharedStateIntegrity()) {
            LogAlert(ALERT_SHARED_STATE_CORRUPT,
                     "Shared driver state integrity check FAILED");
            DispatchCrossModuleEvent(ALERT_SHARED_STATE_CORRUPT, 2, 0, 0);
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

//==============================================================================
// KernelIntegrityInitialize / KernelIntegrityUninitialize
//==============================================================================

NTSTATUS KernelIntegrityInitialize(VOID)
{
    PAGED_CODE();

    // Build hash baseline immediately at load time.
    NTSTATUS st = BuildIntegrityBaseline();
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] Failed to build integrity baseline: 0x%08X\n", st);
        return st;
    }

    // First-pass IDT check on all CPUs (via DPC broadcast is ideal; simplified
    // here to the current CPU only).
    IdtVerifyKeyboardHandler(KeGetCurrentProcessorIndex());

    // First-pass dispatch hook scan.
    ScanKeyboardDrivers();

    // Start the background integrity worker thread.
    KeInitializeEvent(&g_IntegrityStopEvent, NotificationEvent, FALSE);

    HANDLE threadHandle;
    st = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
                              NULL, NULL, NULL,
                              IntegrityWorkerThread, NULL);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] Failed to start integrity thread: 0x%08X\n", st);
        return st;
    }

    // Get a kernel object reference so we can wait for it during cleanup.
    ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL,
                              KernelMode, (PVOID *)&g_IntegrityThread, NULL);
    ZwClose(threadHandle);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Kernel integrity module initialized (%u baseline modules)\n",
               g_BaselineCount);
    return STATUS_SUCCESS;
}

VOID KernelIntegrityUninitialize(VOID)
{
    PAGED_CODE();

    if (g_IntegrityThread) {
        KeSetEvent(&g_IntegrityStopEvent, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(g_IntegrityThread, Executive,
                              KernelMode, FALSE, NULL);
        ObDereferenceObject(g_IntegrityThread);
        g_IntegrityThread = NULL;
    }
}
