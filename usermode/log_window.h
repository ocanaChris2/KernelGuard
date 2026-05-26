// log_window.h
// Alert log dialog API.

#pragma once
#include <windows.h>
#include "driver_comm.h"

// Create (but do not show) the log window. Must be called from the main thread.
BOOL LogWindow_Create(HINSTANCE hInst, HWND hParent);

// Show or bring to foreground.
VOID LogWindow_Show(void);

// Hide without destroying.
VOID LogWindow_Hide(void);

// Append a new alert record to the list view (thread-safe via WM_NEW_ALERT).
VOID LogWindow_AddAlert(const ALERT_RECORD *alert);

// Remove all entries.
VOID LogWindow_Clear(void);

// Returns the underlying dialog HWND (may be NULL before creation).
HWND LogWindow_GetHwnd(void);
