// driver_comm.c
// Manages the connection to the kernel driver:
//   - Opens \\.\KernelGuard
//   - Retrieves the HMAC key (IOCTL_KG_GET_HMAC_KEY)
//   - Maps the shared notification ring into this process (IOCTL_KG_MAP_SHARED_MEM)
//   - Polls WriteIndex on a background thread and validates each HMAC
//     before decoding the alert and invoking the callback
//
// Link against: bcrypt.lib

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <wchar.h>
#include "driver_comm.h"

#pragma comment(lib, "bcrypt.lib")

#define DEVICE_PATH     L"\\\\.\\KernelGuard"
#define POLL_INTERVAL_MS 150    // Check for new notifications every 150 ms

static HANDLE           s_Device        = INVALID_HANDLE_VALUE;
static SHARED_MEM_REGION *s_SharedMem   = NULL;
static BYTE             s_HmacKey[HMAC_KEY_SIZE];
static BOOL             s_HmacKeyValid  = FALSE;

static HANDLE           s_PollThread    = NULL;
static HANDLE           s_StopEvent     = NULL;
static ALERT_CALLBACK   s_Callback      = NULL;
static LPVOID           s_CallbackData  = NULL;

//==============================================================================
// HmacSha256Verify
// Computes HMAC-SHA256 over the first 'dataLen' bytes of 'data' using
// s_HmacKey and compares the result against 'expected'.
// Returns TRUE if the signatures match (constant-time comparison).
//==============================================================================

static BOOL HmacSha256Verify(const BYTE *data, ULONG dataLen, const BYTE expected[32])
{
    if (!s_HmacKeyValid)
        return FALSE;   // Key not available — treat as unverified

    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE               computed[32];
    BOOL               match = FALSE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg,
            BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto done;

    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash,
            NULL, 0, s_HmacKey, HMAC_KEY_SIZE, 0)))
        goto done_alg;

    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, dataLen, 0)))
        goto done_hash;

    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, computed, 32, 0)))
        goto done_hash;

    // Constant-time comparison: accumulate XOR differences.
    ULONG diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= computed[i] ^ expected[i];
    match = (diff == 0);

done_hash:
    BCryptDestroyHash(hHash);
done_alg:
    BCryptCloseAlgorithmProvider(hAlg, 0);
done:
    return match;
}

//==============================================================================
// AlertTypeText / FormatAlertDetails
// Converts numeric alert type codes to human-readable strings.
//==============================================================================

static LPCWSTR AlertTypeText(ULONG alertType)
{
    switch (alertType) {
    case ALERT_PMU_L1D_ANOMALY:         return L"L1D Cache Attack Pattern";
    case ALERT_PMU_L2_ANOMALY:          return L"L2 Cache Attack Pattern";
    case ALERT_PMU_RDTSC_RATE:          return L"Timing Reconnaissance (RDTSC)";
    case ALERT_UNAUTHORIZED_KBD_FILTER: return L"Unauthorized Keyboard Filter";
    case ALERT_UNAUTHORIZED_DMA:        return L"Unauthorized DMA Access";
    case ALERT_PCI_DISCREPANCY:         return L"PCIe Device Discrepancy";
    case ALERT_IDT_HOOK:                return L"IDT Hook Detected";
    case ALERT_DISPATCH_HOOK:           return L"Driver Dispatch Hook";
    case ALERT_TEXT_PATCH:              return L"Kernel .text Patched";
    case ALERT_SHARED_STATE_CORRUPT:    return L"Driver State Corrupted";
    case ALERT_FAIL_SAFE_ENTERED:       return L"CRITICAL: Fail-Safe Mode";
    default:                            return L"Unknown Alert";
    }
}

static LPCWSTR AlertLevelText(ULONG level)
{
    switch (level) {
    case 0:  return L"Info";
    case 1:  return L"Warning";
    default: return L"CRITICAL";
    }
}

VOID DriverComm_FormatAlert(const SECURE_NOTIFICATION *n, ALERT_RECORD *out)
{
    ZeroMemory(out, sizeof(*out));
    out->AlertType      = n->AlertType;
    out->AlertLevel     = n->AlertLevel;
    out->Param1         = n->Param1;
    out->Param2         = n->Param2;
    out->SequenceNumber = n->SequenceNumber;

    // Convert driver performance-counter timestamp to local SYSTEMTIME.
    // Use GetLocalTime as a fallback (close enough for display).
    GetLocalTime(&out->LocalTime);

    wcsncpy_s(out->TypeText, 64, AlertTypeText(n->AlertType), _TRUNCATE);

    // Build a detail string based on the alert type.
    switch (n->AlertType) {
    case ALERT_PMU_RDTSC_RATE:
        _snwprintf_s(out->Details, 128, _TRUNCATE,
                     L"PID: %llu  count: %llu",
                     n->Param1, n->Param2);
        break;
    case ALERT_UNAUTHORIZED_DMA:
        _snwprintf_s(out->Details, 128, _TRUNCATE,
                     L"Bus:%02X Dev:%02X Func:%X  Domain=%llu",
                     (ULONG)(n->Param1 >> 16) & 0xFF,
                     (ULONG)(n->Param1 >> 8)  & 0xFF,
                     (ULONG)(n->Param1)        & 0xFF,
                     n->Param2);
        break;
    case ALERT_IDT_HOOK:
    case ALERT_DISPATCH_HOOK:
        _snwprintf_s(out->Details, 128, _TRUNCATE,
                     L"Handler: 0x%016llX  vector/func: %llu",
                     n->Param1, n->Param2);
        break;
    case ALERT_TEXT_PATCH:
        _snwprintf_s(out->Details, 128, _TRUNCATE,
                     L"Base: 0x%016llX  Size: 0x%llX",
                     n->Param1, n->Param2);
        break;
    default:
        _snwprintf_s(out->Details, 128, _TRUNCATE,
                     L"Param1: 0x%llX  Param2: 0x%llX",
                     n->Param1, n->Param2);
        break;
    }

    // HMAC validation: check over all fields except the Hmac tail.
    ULONG authLen = (ULONG)((ULONG_PTR)n->Hmac - (ULONG_PTR)n);
    out->HmacValid = HmacSha256Verify((const BYTE *)n, authLen, n->Hmac);
}

//==============================================================================
// Polling thread
// Runs at normal priority. Every POLL_INTERVAL_MS milliseconds it checks
// whether WriteIndex has advanced past our local read cursor, decodes any
// new notifications, validates their HMACs, and invokes the callback.
//==============================================================================

static DWORD WINAPI PollThreadProc(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);

    ULONG localRead = 0;    // Our local read cursor

    for (;;) {
        DWORD waitResult = WaitForSingleObject(s_StopEvent, POLL_INTERVAL_MS);
        if (waitResult == WAIT_OBJECT_0)
            break;  // Stop event signaled

        if (!s_SharedMem)
            continue;

        // Read volatile WriteIndex with an acquire barrier.
        ULONG writeIdx = InterlockedCompareExchange(
            (volatile LONG *)&s_SharedMem->WriteIndex,
            0, 0);   // Read-only CAS trick for volatile load

        while (localRead != writeIdx) {
            ULONG slot = localRead % NOTIFICATION_SLOTS;
            const SECURE_NOTIFICATION *n = &s_SharedMem->Notifications[slot];

            // Basic sanity check before processing.
            if (n->Magic == NOTIFY_MAGIC && n->SequenceNumber == localRead) {
                ALERT_RECORD alert;
                DriverComm_FormatAlert(n, &alert);

                if (s_Callback)
                    s_Callback(&alert, s_CallbackData);
            }

            localRead++;
        }
    }
    return 0;
}

//==============================================================================
// Public API
//==============================================================================

BOOL DriverComm_Open(void)
{
    s_Device = CreateFileW(DEVICE_PATH,
                           GENERIC_READ,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (s_Device == INVALID_HANDLE_VALUE)
        return FALSE;

    // ── Get HMAC key ─────────────────────────────────────────────────────────
    DWORD returned = 0;
    s_HmacKeyValid = DeviceIoControl(s_Device,
                                     IOCTL_KG_GET_HMAC_KEY,
                                     NULL, 0,
                                     s_HmacKey, HMAC_KEY_SIZE,
                                     &returned, NULL)
                   && (returned == HMAC_KEY_SIZE);

    // ── Get shared memory mapping ─────────────────────────────────────────────
    LPVOID mapping = NULL;
    DWORD  mapReturned = 0;
    BOOL   ok = DeviceIoControl(s_Device,
                                IOCTL_KG_MAP_SHARED_MEM,
                                NULL, 0,
                                &mapping, sizeof(mapping),
                                &mapReturned, NULL);
    if (!ok || !mapping) {
        CloseHandle(s_Device);
        s_Device = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    s_SharedMem = (SHARED_MEM_REGION *)mapping;
    return TRUE;
}

VOID DriverComm_Close(void)
{
    DriverComm_StopPolling();

    // Zero the HMAC key from process memory.
    SecureZeroMemory(s_HmacKey, HMAC_KEY_SIZE);
    s_HmacKeyValid = FALSE;
    s_SharedMem    = NULL;   // Mapping is owned by the kernel MDL; do not UnmapViewOfFile

    if (s_Device != INVALID_HANDLE_VALUE) {
        CloseHandle(s_Device);
        s_Device = INVALID_HANDLE_VALUE;
    }
}

BOOL DriverComm_StartPolling(ALERT_CALLBACK alertCb, LPVOID userData)
{
    if (s_PollThread)
        return TRUE;    // Already running

    s_Callback     = alertCb;
    s_CallbackData = userData;

    s_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!s_StopEvent)
        return FALSE;

    s_PollThread = CreateThread(NULL, 0, PollThreadProc, NULL, 0, NULL);
    if (!s_PollThread) {
        CloseHandle(s_StopEvent);
        s_StopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

VOID DriverComm_StopPolling(void)
{
    if (s_StopEvent)
        SetEvent(s_StopEvent);

    if (s_PollThread) {
        WaitForSingleObject(s_PollThread, 3000);
        CloseHandle(s_PollThread);
        s_PollThread = NULL;
    }

    if (s_StopEvent) {
        CloseHandle(s_StopEvent);
        s_StopEvent = NULL;
    }
}

BOOL DriverComm_IsConnected(void)
{
    return s_Device != INVALID_HANDLE_VALUE;
}
