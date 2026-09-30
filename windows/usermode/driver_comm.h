// driver_comm.h
// API for communicating with the KernelGuard kernel driver.

#pragma once
#include "kg_shared.h"

// Maximum alerts kept in the in-process ring before wrapping.
#define MAX_LOCAL_ALERTS    512

// Decoded, display-ready alert record.
typedef struct _ALERT_RECORD {
    SYSTEMTIME  LocalTime;          // Converted from driver timestamp
    ULONG       AlertType;
    ULONG       AlertLevel;         // 0=info 1=watch 2=critical
    ULONG64     Param1;
    ULONG64     Param2;
    ULONG       SequenceNumber;
    BOOL        HmacValid;          // TRUE if HMAC verified successfully
    WCHAR       TypeText[64];       // Human-readable alert type
    WCHAR       Details[128];       // Human-readable detail string
} ALERT_RECORD;

// Callback invoked on the polling thread when a new alert arrives.
// The callback must be thread-safe (posted to UI thread via PostMessage).
typedef VOID (*ALERT_CALLBACK)(const ALERT_RECORD *Alert, LPVOID UserData);

// Open the driver device and set up the shared memory channel.
// Returns TRUE on success, FALSE if the driver is not loaded.
BOOL  DriverComm_Open(void);

// Close the device handle and unmap shared memory.
VOID  DriverComm_Close(void);

// Start the background polling thread.
// alertCb is called on the polling thread — callers must post to UI thread.
BOOL  DriverComm_StartPolling(ALERT_CALLBACK alertCb, LPVOID userData);

// Signal the polling thread to stop and wait for it to exit.
VOID  DriverComm_StopPolling(void);

// Returns TRUE if the driver device is currently open.
BOOL  DriverComm_IsConnected(void);

// Formats the alert type code as a human-readable string.
VOID  DriverComm_FormatAlert(const SECURE_NOTIFICATION *n, ALERT_RECORD *out);
