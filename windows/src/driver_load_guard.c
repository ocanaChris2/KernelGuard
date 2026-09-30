// driver_load_guard.c
// Module 3.4: driver-load guard, the Windows answer to "bring your own vulnerable driver" (BYOVD).
// Counterpart of linux/module/kg_modgate.c.
//
// The attack: somebody with administrator rights installs a driver that is legitimately signed and
// vulnerable (a vendor's hardware utility, typically) to get a kernel read/write primitive that Driver
// Signature Enforcement was meant to deny them, and uses it to switch off security software or patch the
// kernel.  Modules 2 and 3 see what the primitive is used for; this module sees the load itself.
//
// What it does
// ------------
//   - PsSetLoadImageNotifyRoutine reports every image the kernel maps.  The callback keeps only kernel-mode
//     images (ProcessId == 0) and copies the path into a small queue: no file I/O, no hashing, no locks
//     beyond a spin lock, because it runs inside the loader.
//   - A system thread takes paths off the queue, reads the file, and computes its Authenticode SHA-256
//     (pe_authenticode.c).  That is the identity a deny list can rely on: the file name is not signed and
//     an ordinary file hash changes when a signature is re-encoded, but the Authenticode digest is what
//     Code Integrity itself verifies, and it is the "Authentihash" the LOLDrivers project publishes.
//   - The digest is looked up in the built-in table (vuln_driver_hashes.h, generated from LOLDrivers by
//     tools/import_loldrivers.py) and in the operator's lists.  The operator's allow list wins, so a
//     legitimate install of a listed driver (a vendor tool that ships one) can be vouched for by exact build.
//   - Every driver that was already loaded when KernelGuard started is checked too, in one pass a minute
//     after start (the volume may not be mounted yet at boot-start time), and reported as "present at
//     start".
//
// How a hit is reported
// ---------------------
//   ALERT_VULN_DRIVER at level 2 (critical, and KernelGuard enters fail-safe) when the driver was loaded
//   after start or belongs to the "malicious" class; at level 1 (watch) when a "vulnerable driver" was
//   already there at start, because legitimate software installs such drivers at boot all the time and
//   BYOVD loads them on demand.  With Parameters\LockMode = 1 every driver that appears after start is also
//   reported (ALERT_MODULE_LOADED, level 1), unless its digest is on the allow list.
//
// What it does NOT do
// -------------------
//   It never refuses a load.  A load-image callback cannot veto one, patching the entry point of a driver
//   that is already mapped is racy and fails under HVCI, and blocking belongs to Code Integrity: the
//   Microsoft vulnerable-driver blocklist, which is on by default on current Windows 11 and enforced with
//   HVCI.  So the driver AUDITS that instead (ALERT_LOAD_POLICY: HVCI, test signing, the blocklist's
//   registry switch) and tells the operator when it is weak.  The consequence to state plainly: by the time
//   a hit is reported the driver's DriverEntry may already have run.  What KernelGuard adds is that the
//   load is no longer silent, and that a critical hit puts the rest of the driver into fail-safe.
//   Also not covered: drivers loaded before KernelGuard's own boot-start slot (they are found by the start
//   pass), a driver whose file is deleted before it is read (reported as unreadable), and any hit that
//   overflows the queue (counted, never silent in the debugger).
//
// Registry, under HKLM\SYSTEM\CurrentControlSet\Services\KernelGuard\Parameters:
//   DriverDenyHashes   REG_MULTI_SZ  64-hex-digit SHA-256 (Authenticode) digests to treat as vulnerable
//   DriverAllowHashes  REG_MULTI_SZ  digests never reported (an exact build the operator vouches for)
//   LockMode           REG_DWORD     read by KgLoadPolicy, part of the hashed policy block
//
// Unload safety: the callback counts itself in and out; unload removes the callback, waits for the count to
// reach zero, stops the worker, and only then frees what the callback and worker touch.
//
// STATUS: compile-checked against the Windows 11 WDK headers (tools/wdk_syntax_check.py) and the digest code
// is tested on Linux against signed Microsoft binaries; this module has never run on Windows.

#include "KernelGuard.h"
#include "pe_authenticode.h"
#include "digest_table.h"
#include "vuln_driver_hashes.h"

#pragma alloc_text(PAGE, DriverLoadGuardInitialize)
#pragma alloc_text(PAGE, DriverLoadGuardUninitialize)

#define LG_POOL_TAG         'gLgK'
#define LG_PATH_CHARS       260
#define LG_QUEUE_SIZE       64
#define LG_MAX_IMAGE_BYTES  (32UL * 1024UL * 1024UL)    // a driver bigger than this is not read
#define LG_READ_CHUNK       (1UL * 1024UL * 1024UL)
#define LG_MAX_USER_HASHES  256
#define LG_MAX_BASELINE     512
#define LG_BASELINE_DELAY_S 60

// ZwQuerySystemInformation is exported by ntoskrnl but declared only in ntifs.h, which this driver does not
// include.  Only the one information class used below is described here.
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
                                                 ULONG SystemInformationLength, PULONG ReturnLength);

#define KG_SystemCodeIntegrityInformation       103UL
#define KG_CODEINTEGRITY_OPTION_ENABLED         0x01UL
#define KG_CODEINTEGRITY_OPTION_TESTSIGN        0x02UL
#define KG_CODEINTEGRITY_OPTION_HVCI_KMCI       0x400UL

typedef struct _KG_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} KG_CODEINTEGRITY_INFORMATION;

typedef DT_DIGEST LG_HASH;

typedef struct _LG_LIST {
    LG_HASH *Items;
    ULONG    Count;
} LG_LIST;

typedef struct _LG_ITEM {
    ULONG Chars;
    WCHAR Path[LG_PATH_CHARS];
} LG_ITEM;

//------------------------------------------------------------------------------
// State.  Everything below is written during initialisation, before the callback is registered, and only
// read afterwards, except the queue (spin lock) and the counters (interlocked).
//------------------------------------------------------------------------------
static LG_HASH   *g_LgTable;                // built-in digests, ascending
static PUCHAR     g_LgClass;                // '1' = "malicious" class, '0' = "vulnerable driver"
static ULONG      g_LgTableCount;
static BOOLEAN    g_LgTableSorted;
static LG_LIST    g_LgDeny;
static LG_LIST    g_LgAllow;

static LG_ITEM   *g_LgQueue;
static ULONG      g_LgHead, g_LgTail, g_LgCount;
static KSPIN_LOCK g_LgQueueLock;
static KSEMAPHORE g_LgItems;                // counts queued paths
static KEVENT     g_LgStop;
static KTIMER     g_LgBaselineTimer;
static PKTHREAD   g_LgThread;
static WCHAR    (*g_LgBaselinePaths)[LG_PATH_CHARS];
static ULONG      g_LgBaselineCount;

static volatile LONG g_LgInFlight;          // callbacks executing right now
static volatile LONG g_LgDropped;           // paths that did not fit the queue
static volatile BOOLEAN g_LgRunning;
static BOOLEAN    g_LgRegistered;
static BOOLEAN    g_LgInitialised;

//------------------------------------------------------------------------------
// Small helpers
//------------------------------------------------------------------------------
static VOID LgHexString(const UCHAR Hash[32], CHAR Out[65])
{
    static const CHAR digits[] = "0123456789abcdef";

    for (ULONG i = 0; i < 32; i++) {
        Out[2 * i]     = digits[Hash[i] >> 4];
        Out[2 * i + 1] = digits[Hash[i] & 0x0F];
    }
    Out[64] = '\0';
}

static PCWSTR LgBaseName(PCWSTR Path)
{
    PCWSTR base = Path;

    for (PCWSTR p = Path; *p; p++)
        if (*p == L'\\')
            base = p + 1;
    return base;
}

// A name travels in Param1|Param2 as 16 ASCII bytes, like the Linux module names.
static VOID LgPackName(PCWSTR Name, ULONG64 *P1, ULONG64 *P2)
{
    CHAR b[16];

    RtlZeroMemory(b, sizeof(b));
    for (ULONG i = 0; i < sizeof(b) && Name[i]; i++)
        b[i] = (Name[i] >= 0x20 && Name[i] < 0x7F) ? (CHAR)Name[i] : '?';
    RtlCopyMemory(P1, b, 8);
    RtlCopyMemory(P2, b + 8, 8);
}

static BOOLEAN LgListContains(const LG_LIST *List, const UCHAR Hash[32])
{
    if (!List->Items)
        return FALSE;
    for (ULONG i = 0; i < List->Count; i++)
        if (!DtCompare(List->Items[i].B, Hash))
            return TRUE;
    return FALSE;
}

// Index into the built-in table, or -1 (digest_table.c: a binary search when the table is in order, which
// LgLoadBuiltin checks, and a plain scan otherwise, so a bad table can only be slow, never blind).
static LONG LgBuiltinFind(const UCHAR Hash[32])
{
    return (LONG)DtFind(g_LgTable, g_LgTableCount, g_LgTableSorted, Hash);
}

//------------------------------------------------------------------------------
// Tables
//------------------------------------------------------------------------------
static VOID LgLoadBuiltin(VOID)
{
    ULONG n = 0;

    g_LgTable = (LG_HASH *)ExAllocatePoolWithTag(PagedPool, KG_VULN_HASH_COUNT * sizeof(LG_HASH), LG_POOL_TAG);
    g_LgClass = (PUCHAR)ExAllocatePoolWithTag(PagedPool, KG_VULN_HASH_COUNT, LG_POOL_TAG);
    if (!g_LgTable || !g_LgClass) {
        if (g_LgTable) ExFreePoolWithTag(g_LgTable, LG_POOL_TAG);
        if (g_LgClass) ExFreePoolWithTag(g_LgClass, LG_POOL_TAG);
        g_LgTable = NULL;
        g_LgClass = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] Load guard: no memory for the built-in table; only the registry lists apply\n");
        return;
    }

    for (ULONG i = 0; i < KG_VULN_HASH_COUNT; i++) {
        if (DtParseHex64(g_KgVulnHashHex[i], 0, 64, g_LgTable[n].B)) {
            g_LgClass[n] = (UCHAR)g_KgVulnClass[i];
            n++;
        }
    }
    g_LgTableCount  = n;
    g_LgTableSorted = DtIsAscending(g_LgTable, n) ? TRUE : FALSE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Load guard: %u built-in digests (%u parsed, %s)\n", KG_VULN_HASH_COUNT, n,
               g_LgTableSorted ? "sorted" : "NOT sorted, scanning");
}

// Called once per string of a REG_MULTI_SZ.
static NTSTATUS NTAPI LgHashListRoutine(PWSTR ValueName, ULONG ValueType, PVOID ValueData,
                                        ULONG ValueLength, PVOID Context, PVOID EntryContext)
{
    LG_LIST *list = (LG_LIST *)EntryContext;
    ULONG    chars;

    UNREFERENCED_PARAMETER(Context);

    if (!list || !list->Items || ValueType != REG_SZ)
        return STATUS_SUCCESS;
    chars = ValueLength / sizeof(WCHAR);
    while (chars && ((PWCHAR)ValueData)[chars - 1] == L'\0')
        chars--;
    if (list->Count >= LG_MAX_USER_HASHES || !DtParseHex64(ValueData, 1, chars, list->Items[list->Count].B)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG] Load guard: ignoring a %ws entry that is not a SHA-256 digest (or over the limit)\n",
                   ValueName);
        return STATUS_SUCCESS;
    }
    list->Count++;
    return STATUS_SUCCESS;
}

static VOID LgLoadList(PUNICODE_STRING RegistryPath, PCWSTR ValueName, LG_LIST *List)
{
    WCHAR keyPath[320];
    RTL_QUERY_REGISTRY_TABLE table[2];

    List->Count = 0;
    List->Items = (LG_HASH *)ExAllocatePoolWithTag(PagedPool, LG_MAX_USER_HASHES * sizeof(LG_HASH), LG_POOL_TAG);
    if (!List->Items || !RegistryPath || !RegistryPath->Buffer)
        return;
    if (!NT_SUCCESS(RtlStringCchPrintfW(keyPath, ARRAYSIZE(keyPath), L"%wZ\\Parameters", RegistryPath)))
        return;

    RtlZeroMemory(table, sizeof(table));
    table[0].QueryRoutine = LgHashListRoutine;
    table[0].Name         = (PWSTR)ValueName;
    table[0].EntryContext = List;
    table[0].DefaultType  = REG_NONE;
    // An absent value is not an error: the list is just empty.
    (VOID)RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, keyPath, table, NULL, NULL);
}

//------------------------------------------------------------------------------
// Hashing a driver file
//------------------------------------------------------------------------------
typedef struct _LG_HASH_CTX {
    BCRYPT_HASH_HANDLE Hash;
} LG_HASH_CTX;

static int LgHashUpdate(void *Ctx, const PEA_U8 *Data, PEA_U32 Length)
{
    return NT_SUCCESS(BCryptHashData(((LG_HASH_CTX *)Ctx)->Hash, (PUCHAR)Data, Length, 0)) ? 0 : 1;
}

static NTSTATUS LgAuthenticodeSha256(const UCHAR *Image, ULONG64 Length, UCHAR Digest[32])
{
    BCRYPT_ALG_HANDLE  alg  = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    LG_HASH_CTX        ctx;
    NTSTATUS           st;
    int                rc;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st))
        return st;
    st = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return st;
    }

    ctx.Hash = hash;
    rc = PeaAuthenticodeHash(Image, Length, LgHashUpdate, &ctx);
    if (rc == PEA_OK)
        st = BCryptFinishHash(hash, Digest, 32, 0);
    else
        st = (rc == PEA_E_FORMAT) ? STATUS_INVALID_IMAGE_FORMAT : STATUS_UNSUCCESSFUL;

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st;
}

static NTSTATUS LgHashFile(PCWSTR Path, UCHAR Digest[32])
{
    UNICODE_STRING           name;
    OBJECT_ATTRIBUTES        oa;
    IO_STATUS_BLOCK          iosb;
    FILE_STANDARD_INFORMATION std;
    HANDLE                   file = NULL;
    PUCHAR                   image = NULL;
    ULONG64                  size, got = 0;
    NTSTATUS                 st;

    RtlInitUnicodeString(&name, Path);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&file, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(st))
        return st;

    st = ZwQueryInformationFile(file, &iosb, &std, sizeof(std), FileStandardInformation);
    if (!NT_SUCCESS(st))
        goto out;
    if (std.EndOfFile.QuadPart <= 0 || (ULONG64)std.EndOfFile.QuadPart > LG_MAX_IMAGE_BYTES) {
        st = STATUS_FILE_TOO_LARGE;
        goto out;
    }
    size  = (ULONG64)std.EndOfFile.QuadPart;
    image = (PUCHAR)ExAllocatePoolWithTag(PagedPool, (SIZE_T)size, LG_POOL_TAG);
    if (!image) {
        st = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    while (got < size) {
        LARGE_INTEGER offset;
        ULONG         want = (ULONG)min((ULONG64)LG_READ_CHUNK, size - got);

        offset.QuadPart = (LONGLONG)got;
        st = ZwReadFile(file, NULL, NULL, NULL, &iosb, image + got, want, &offset, NULL);
        if (!NT_SUCCESS(st))
            goto out;
        if (iosb.Information == 0)
            break;
        got += (ULONG64)iosb.Information;
    }
    if (got != size) {
        st = STATUS_END_OF_FILE;            // the file shrank while we read it
        goto out;
    }
    st = LgAuthenticodeSha256(image, size, Digest);

out:
    if (image)
        ExFreePoolWithTag(image, LG_POOL_TAG);
    ZwClose(file);
    return st;
}

//------------------------------------------------------------------------------
// Reporting
//------------------------------------------------------------------------------
static VOID LgReportDenied(PCWSTR Path, const UCHAR Digest[32], BOOLEAN Malicious, BOOLEAN Baseline,
                           BOOLEAN OperatorListed)
{
    CHAR    hex[65];
    ULONG64 p1, p2;
    ULONG   level = (Malicious || !Baseline) ? 2 : 1;

    LgHexString(Digest, hex);
    LgPackName(LgBaseName(Path), &p1, &p2);
    LogAlert(ALERT_VULN_DRIVER, "%s DRIVER: %ws sha256=%s (%s%s)",
             Malicious ? "MALICIOUS" : "VULNERABLE", Path, hex,
             Baseline ? "already loaded when KernelGuard started" : "loaded after KernelGuard started",
             OperatorListed ? ", on the operator's deny list" : "");
    InterlockedIncrement(&g_SharedState.VulnDriverDetected);
    DispatchCrossModuleEvent(ALERT_VULN_DRIVER, level, p1, p2);
}

static VOID LgReportLocked(PCWSTR Path, const UCHAR Digest[32])
{
    CHAR    hex[65];
    ULONG64 p1, p2;

    LgHexString(Digest, hex);
    LgPackName(LgBaseName(Path), &p1, &p2);
    LogAlert(ALERT_MODULE_LOADED, "LOCK MODE: driver %ws (sha256=%s) appeared after KernelGuard started",
             Path, hex);
    InterlockedIncrement(&g_SharedState.DriverLockViolations);
    DispatchCrossModuleEvent(ALERT_MODULE_LOADED, 1, p1, p2);
}

static VOID LgReportUnreadable(PCWSTR Path, NTSTATUS Status)
{
    ULONG64 p1, p2;

    LgPackName(LgBaseName(Path), &p1, &p2);
    LogAlert(ALERT_MODULE_LOADED,
             "driver %ws was loaded but its file could not be read and hashed (0x%08X): "
             "deleted, replaced, or not a file", Path, (ULONG)Status);
    DispatchCrossModuleEvent(ALERT_MODULE_LOADED, 1, p1, p2);
}

//------------------------------------------------------------------------------
// One image: hash it, then decide
//------------------------------------------------------------------------------
static VOID LgProcessPath(PCWSTR Path, BOOLEAN Baseline)
{
    UCHAR    digest[32];
    LONG     idx;
    BOOLEAN  operatorListed, malicious = FALSE;
    NTSTATUS st = LgHashFile(Path, digest);

    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[KG] Load guard: cannot hash %ws: 0x%08X%s\n", Path, (ULONG)st,
                   Baseline ? " (present at start, not reported)" : "");
        if (!Baseline)
            LgReportUnreadable(Path, st);
        return;
    }
    InterlockedIncrement(&g_SharedState.DriversHashed);

    if (LgListContains(&g_LgAllow, digest))
        return;                             // the operator vouched for this exact build

    idx = LgBuiltinFind(digest);
    operatorListed = LgListContains(&g_LgDeny, digest);
    if (idx >= 0)
        malicious = (g_LgClass[idx] == '1');
    if (idx >= 0 || operatorListed) {
        LgReportDenied(Path, digest, malicious, Baseline, operatorListed);
        return;
    }
    if (KgLockMode() && !Baseline)
        LgReportLocked(Path, digest);
}

//------------------------------------------------------------------------------
// The load-image callback and the queue behind it
//------------------------------------------------------------------------------
static VOID NTAPI LgImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    KIRQL   irql;
    BOOLEAN queued = FALSE;

    // Kernel-mode images only: a driver has no process.
    if (ProcessId != NULL || ImageInfo == NULL || !ImageInfo->SystemModeImage)
        return;
    if (FullImageName == NULL || FullImageName->Buffer == NULL || FullImageName->Length == 0)
        return;

    InterlockedIncrement(&g_LgInFlight);
    if (g_LgRunning && g_LgQueue) {
        ULONG chars = FullImageName->Length / sizeof(WCHAR);

        if (chars > LG_PATH_CHARS - 1)
            chars = LG_PATH_CHARS - 1;

        KeAcquireSpinLock(&g_LgQueueLock, &irql);
        if (g_LgCount < LG_QUEUE_SIZE) {
            LG_ITEM *it = &g_LgQueue[g_LgTail];

            RtlCopyMemory(it->Path, FullImageName->Buffer, chars * sizeof(WCHAR));
            it->Path[chars] = L'\0';
            it->Chars = chars;
            g_LgTail = (g_LgTail + 1) % LG_QUEUE_SIZE;
            g_LgCount++;
            queued = TRUE;
        }
        KeReleaseSpinLock(&g_LgQueueLock, irql);

        if (queued)
            KeReleaseSemaphore(&g_LgItems, IO_NO_INCREMENT, 1, FALSE);
        else
            InterlockedIncrement(&g_LgDropped);
    }
    InterlockedDecrement(&g_LgInFlight);
}

static BOOLEAN LgDequeue(LG_ITEM *Out)
{
    KIRQL   irql;
    BOOLEAN have = FALSE;

    KeAcquireSpinLock(&g_LgQueueLock, &irql);
    if (g_LgCount) {
        *Out = g_LgQueue[g_LgHead];
        g_LgHead = (g_LgHead + 1) % LG_QUEUE_SIZE;
        g_LgCount--;
        have = TRUE;
    }
    KeReleaseSpinLock(&g_LgQueueLock, irql);
    return have;
}

static VOID LgBaselinePass(VOID)
{
    ULONG done = 0;

    for (ULONG i = 0; i < g_LgBaselineCount; i++) {
        if (KeReadStateEvent(&g_LgStop))
            break;
        LgProcessPath(g_LgBaselinePaths[i], TRUE);
        done++;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Load guard: start pass checked %u of %u loaded drivers\n", done, g_LgBaselineCount);
    ExFreePoolWithTag(g_LgBaselinePaths, LG_POOL_TAG);
    g_LgBaselinePaths = NULL;
    g_LgBaselineCount = 0;
}

static VOID NTAPI LgWorker(PVOID Context)
{
    PVOID objs[3];
    LG_ITEM *item;

    UNREFERENCED_PARAMETER(Context);
    objs[0] = &g_LgStop;
    objs[1] = &g_LgItems;
    objs[2] = &g_LgBaselineTimer;

    // One item is 520 bytes: kept off the thread's stack, and in NON-paged memory because LgDequeue copies
    // into it while holding a spin lock (DISPATCH_LEVEL), where touching paged memory is fatal.
    item = (LG_ITEM *)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*item), LG_POOL_TAG);

    for (;;) {
        NTSTATUS w = KeWaitForMultipleObjects(3, objs, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

        if (w == STATUS_WAIT_0)
            break;
        if (w == STATUS_WAIT_0 + 1) {
            if (item && LgDequeue(item))
                LgProcessPath(item->Path, FALSE);
        } else if (w == STATUS_WAIT_0 + 2) {
            LgBaselinePass();
        }
    }
    if (item)
        ExFreePoolWithTag(item, LG_POOL_TAG);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

//------------------------------------------------------------------------------
// Drivers already loaded when we start (AuxKlib, as BuildIntegrityBaseline does).  FullPathName is
// an ANSI path such as \SystemRoot\System32\drivers\x.sys, which ZwCreateFile opens as it is.
//------------------------------------------------------------------------------
static VOID LgCollectBaseline(VOID)
{
    ULONG bytes = 0;
    AUX_MODULE_EXTENDED_INFO *mods;
    NTSTATUS st;

    AuxKlibInitialize();
    st = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (st != STATUS_BUFFER_TOO_SMALL || !bytes)
        return;
    mods = (AUX_MODULE_EXTENDED_INFO *)ExAllocatePoolWithTag(PagedPool, bytes, LG_POOL_TAG);
    if (!mods)
        return;
    g_LgBaselinePaths = (WCHAR (*)[LG_PATH_CHARS])ExAllocatePoolWithTag(
        PagedPool, (SIZE_T)LG_MAX_BASELINE * LG_PATH_CHARS * sizeof(WCHAR), LG_POOL_TAG);
    if (!g_LgBaselinePaths) {
        ExFreePoolWithTag(mods, LG_POOL_TAG);
        return;
    }

    st = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), mods);
    if (NT_SUCCESS(st)) {
        ULONG count = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);

        for (ULONG i = 0; i < count && g_LgBaselineCount < LG_MAX_BASELINE; i++) {
            const UCHAR *ansi = mods[i].FullPathName;
            ULONG n = 0;

            if (!ansi[0])
                continue;
            for (; n < LG_PATH_CHARS - 1 && ansi[n]; n++)
                g_LgBaselinePaths[g_LgBaselineCount][n] = (ansi[n] < 0x80) ? (WCHAR)ansi[n] : L'?';
            g_LgBaselinePaths[g_LgBaselineCount][n] = L'\0';
            g_LgBaselineCount++;
        }
    }
    ExFreePoolWithTag(mods, LG_POOL_TAG);
    if (!g_LgBaselineCount) {
        ExFreePoolWithTag(g_LgBaselinePaths, LG_POOL_TAG);
        g_LgBaselinePaths = NULL;
    }
}

//------------------------------------------------------------------------------
// Audit of the OS's own defences (ALERT_LOAD_POLICY).  Those, and not this driver, are what prevent the
// attack on Windows; the audit says whether they are on.
//------------------------------------------------------------------------------
static ULONG LgReadBlocklistSwitch(VOID)
{
    ULONG value = 0xFFFFFFFFUL, unset = 0xFFFFFFFFUL;
    RTL_QUERY_REGISTRY_TABLE table[2];

    RtlZeroMemory(table, sizeof(table));
    table[0].Flags         = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK;
    table[0].Name          = L"VulnerableDriverBlocklistEnable";
    table[0].EntryContext  = &value;
    table[0].DefaultType   = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_DWORD;
    table[0].DefaultData   = &unset;
    table[0].DefaultLength = sizeof(unset);
    if (!NT_SUCCESS(RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                           L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                                           table, NULL, NULL)))
        value = 0xFFFFFFFFUL;
    return value;
}

static VOID LgAuditLoadPolicy(VOID)
{
    KG_CODEINTEGRITY_INFORMATION ci;
    ULONG    returned = 0, weak = 0, raw = 0, blocklist;
    NTSTATUS st;

    RtlZeroMemory(&ci, sizeof(ci));
    ci.Length = sizeof(ci);
    st = ZwQuerySystemInformation(KG_SystemCodeIntegrityInformation, &ci, sizeof(ci), &returned);
    if (NT_SUCCESS(st)) {
        raw = ci.CodeIntegrityOptions;
        if (!(raw & KG_CODEINTEGRITY_OPTION_ENABLED) || (raw & KG_CODEINTEGRITY_OPTION_TESTSIGN))
            weak |= KG_LP_TESTSIGNING;
        if (!(raw & KG_CODEINTEGRITY_OPTION_HVCI_KMCI))
            weak |= KG_LP_NO_HVCI;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG] Load guard: code-integrity state unavailable (0x%08X); not audited\n", (ULONG)st);
    }
    blocklist = LgReadBlocklistSwitch();
    if (blocklist == 0)
        weak |= KG_LP_NO_BLOCKLIST;

    LogAlert(ALERT_LOAD_POLICY, "load policy: HVCI %s, test signing/CI off %s, vulnerable-driver blocklist %s%s",
             (weak & KG_LP_NO_HVCI) ? "OFF" : "on", (weak & KG_LP_TESTSIGNING) ? "YES" : "no",
             blocklist == 0 ? "DISABLED" : (blocklist == 1 ? "enabled" : "default (not set)"),
             weak ? " - a signed vulnerable driver can be loaded" : "");
    DispatchCrossModuleEvent(ALERT_LOAD_POLICY, weak ? 1 : 0, weak, raw);
}

//------------------------------------------------------------------------------
// Init / uninit
//------------------------------------------------------------------------------
static VOID LgFreeState(VOID)
{
    if (g_LgTable)          { ExFreePoolWithTag(g_LgTable, LG_POOL_TAG);          g_LgTable = NULL; }
    if (g_LgClass)          { ExFreePoolWithTag(g_LgClass, LG_POOL_TAG);          g_LgClass = NULL; }
    if (g_LgDeny.Items)     { ExFreePoolWithTag(g_LgDeny.Items, LG_POOL_TAG);     g_LgDeny.Items = NULL; }
    if (g_LgAllow.Items)    { ExFreePoolWithTag(g_LgAllow.Items, LG_POOL_TAG);    g_LgAllow.Items = NULL; }
    if (g_LgBaselinePaths)  { ExFreePoolWithTag(g_LgBaselinePaths, LG_POOL_TAG);  g_LgBaselinePaths = NULL; }
    if (g_LgQueue)          { ExFreePoolWithTag(g_LgQueue, LG_POOL_TAG);          g_LgQueue = NULL; }
    g_LgTableCount = g_LgDeny.Count = g_LgAllow.Count = g_LgBaselineCount = 0;
}

NTSTATUS DriverLoadGuardInitialize(PUNICODE_STRING RegistryPath)
{
    PAGED_CODE();

    HANDLE   thread = NULL;
    NTSTATUS st;

    LgLoadBuiltin();
    LgLoadList(RegistryPath, L"DriverDenyHashes", &g_LgDeny);
    LgLoadList(RegistryPath, L"DriverAllowHashes", &g_LgAllow);

    g_LgQueue = (LG_ITEM *)ExAllocatePoolWithTag(NonPagedPoolNx, LG_QUEUE_SIZE * sizeof(LG_ITEM), LG_POOL_TAG);
    if (!g_LgQueue) {
        LgFreeState();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_LgHead = g_LgTail = g_LgCount = 0;
    g_LgInFlight = 0;
    g_LgDropped = 0;
    KeInitializeSpinLock(&g_LgQueueLock);
    KeInitializeSemaphore(&g_LgItems, 0, LG_QUEUE_SIZE);
    KeInitializeEvent(&g_LgStop, NotificationEvent, FALSE);
    KeInitializeTimerEx(&g_LgBaselineTimer, SynchronizationTimer);
    g_LgRunning = TRUE;

    st = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, LgWorker, NULL);
    if (!NT_SUCCESS(st)) {
        g_LgRunning = FALSE;
        LgFreeState();
        return st;
    }
    ObReferenceObjectByHandle(thread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID *)&g_LgThread, NULL);
    ZwClose(thread);
    g_LgInitialised = TRUE;

    // Register first, then look at what is already loaded: a driver that loads in between is seen twice
    // (once as new, once as present), which is a duplicate report and never a missed one.
    st = PsSetLoadImageNotifyRoutine(LgImageNotify);
    if (NT_SUCCESS(st)) {
        g_LgRegistered = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] Load guard: PsSetLoadImageNotifyRoutine failed: 0x%08X (start pass only)\n", (ULONG)st);
    }

    LgCollectBaseline();
    if (g_LgBaselineCount) {
        LARGE_INTEGER due;

        due.QuadPart = -(LONGLONG)LG_BASELINE_DELAY_S * 10000000LL;
        KeSetTimer(&g_LgBaselineTimer, due, NULL);
    }

    LgAuditLoadPolicy();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[KG] Driver-load guard active: %u built-in, %u deny, %u allow, lock mode %s\n",
               g_LgTableCount, g_LgDeny.Count, g_LgAllow.Count, KgLockMode() ? "on" : "off");
    return STATUS_SUCCESS;
}

VOID DriverLoadGuardUninitialize(VOID)
{
    PAGED_CODE();

    LARGE_INTEGER pause;

    if (!g_LgInitialised)
        return;

    g_LgRunning = FALSE;
    if (g_LgRegistered) {
        PsRemoveLoadImageNotifyRoutine(LgImageNotify);
        g_LgRegistered = FALSE;
    }

    // A callback that started before the removal may still be running: it has our code and queue.
    pause.QuadPart = -10LL * 1000LL * 10LL;     // 10 ms
    for (ULONG i = 0; i < 500 && g_LgInFlight; i++)
        KeDelayExecutionThread(KernelMode, FALSE, &pause);
    if (g_LgInFlight) {
        // Better to leak the queue than to free it under a callback.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[KG] Load guard: a load-image callback is still running; not freeing its queue\n");
        g_LgQueue = NULL;
    }

    KeSetEvent(&g_LgStop, IO_NO_INCREMENT, FALSE);
    if (g_LgThread) {
        KeWaitForSingleObject(g_LgThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_LgThread);
        g_LgThread = NULL;
    }
    KeCancelTimer(&g_LgBaselineTimer);

    if (g_LgDropped)
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[KG] Load guard: %d image path(s) did not fit the queue and were not checked\n", g_LgDropped);
    LgFreeState();
    g_LgInitialised = FALSE;
}
