// log_window.c
// Modeless alert log dialog with a ListView showing all received alerts.
// The list displays: Time | Level | Type | HMAC | Details
// Columns are auto-sized; the dialog is resizable via WS_SIZEBOX.

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdio.h>
#include <wchar.h>
#include "log_window.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

// Column indices
#define COL_TIME    0
#define COL_LEVEL   1
#define COL_TYPE    2
#define COL_HMAC    3
#define COL_DETAILS 4

static HWND  s_hDlg     = NULL;
static HWND  s_hList    = NULL;
static HWND  s_hStatus  = NULL;
static ULONG s_AlertCount = 0;

// Alert records stored for save-to-file (bounded ring).
#define STORED_MAX 512
static ALERT_RECORD s_Stored[STORED_MAX];
static ULONG        s_StoredCount = 0;
static CRITICAL_SECTION s_StoreLock;

//==============================================================================
// ListView helpers
//==============================================================================

static VOID InitListView(HWND hList)
{
    ListView_SetExtendedListViewStyle(hList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNW col = {0};
    col.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    col.fmt  = LVCFMT_LEFT;

    static const struct { LPCWSTR name; int width; } cols[] = {
        { L"Time",      100 },
        { L"Level",      60 },
        { L"Alert Type", 180 },
        { L"HMAC",        50 },
        { L"Details",    300 },
    };

    for (int i = 0; i < 5; i++) {
        col.cx       = cols[i].width;
        col.pszText  = (LPWSTR)cols[i].name;
        col.iSubItem = i;
        ListView_InsertColumn(hList, i, &col);
    }
}

static VOID AddAlertToList(HWND hList, const ALERT_RECORD *a)
{
    WCHAR timeBuf[32];
    _snwprintf_s(timeBuf, 32, _TRUNCATE, L"%02d:%02d:%02d.%03d",
                 a->LocalTime.wHour, a->LocalTime.wMinute,
                 a->LocalTime.wSecond, a->LocalTime.wMilliseconds);

    static const LPCWSTR levelColors[] = { L"Info", L"Warning", L"CRITICAL" };
    LPCWSTR levelText = (a->AlertLevel < 3) ? levelColors[a->AlertLevel] : L"???";

    int iItem = ListView_GetItemCount(hList);

    LVITEMW lvi = {0};
    lvi.mask    = LVIF_TEXT;
    lvi.iItem   = iItem;
    lvi.pszText = timeBuf;
    ListView_InsertItem(hList, &lvi);

    ListView_SetItemText(hList, iItem, COL_LEVEL,   (LPWSTR)levelText);
    ListView_SetItemText(hList, iItem, COL_TYPE,    (LPWSTR)a->TypeText);
    ListView_SetItemText(hList, iItem, COL_HMAC,    a->HmacValid ? L"OK" : L"FAIL");
    ListView_SetItemText(hList, iItem, COL_DETAILS, (LPWSTR)a->Details);

    // Auto-scroll to the newest entry.
    ListView_EnsureVisible(hList, iItem, FALSE);
}

//==============================================================================
// Save log to a text file
//==============================================================================

static VOID SaveLog(HWND hParent)
{
    WCHAR filePath[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = hParent;
    ofn.lpstrFilter  = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile    = filePath;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrDefExt  = L"txt";
    ofn.Flags        = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle   = L"Save Alert Log";

    if (!GetSaveFileNameW(&ofn))
        return;

    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        MessageBoxW(hParent, L"Could not create file.", L"Error", MB_ICONERROR);
        return;
    }

    // UTF-8 BOM
    DWORD written;
    WriteFile(hFile, "\xEF\xBB\xBF", 3, &written, NULL);

    // Header line
    static const char *header =
        "Time,Level,AlertType,HMAC,Seq,Param1,Param2,Details\r\n";
    WriteFile(hFile, header, (DWORD)strlen(header), &written, NULL);

    EnterCriticalSection(&s_StoreLock);
    for (ULONG i = 0; i < s_StoredCount; i++) {
        const ALERT_RECORD *a = &s_Stored[i % STORED_MAX];
        static const char *levels[] = { "Info", "Warning", "CRITICAL" };
        char line[512];
        int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
            "%02d:%02d:%02d,%s,%S,%s,%u,0x%016llX,0x%016llX,%S\r\n",
            a->LocalTime.wHour, a->LocalTime.wMinute, a->LocalTime.wSecond,
            (a->AlertLevel < 3) ? levels[a->AlertLevel] : "???",
            a->TypeText,
            a->HmacValid ? "OK" : "FAIL",
            a->SequenceNumber,
            a->Param1, a->Param2,
            a->Details);
        if (len > 0)
            WriteFile(hFile, line, (DWORD)len, &written, NULL);
    }
    LeaveCriticalSection(&s_StoreLock);

    CloseHandle(hFile);

    WCHAR msg[256];
    _snwprintf_s(msg, 256, _TRUNCATE, L"Saved %u alert(s) to:\n%s",
                 s_StoredCount, filePath);
    MessageBoxW(hParent, msg, L"Log Saved", MB_ICONINFORMATION);
}

//==============================================================================
// Dialog procedure
//==============================================================================

static INT_PTR CALLBACK LogDlgProc(HWND hDlg, UINT msg,
                                   WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
        s_hList   = GetDlgItem(hDlg, IDC_LOG_LIST);
        s_hStatus = GetDlgItem(hDlg, IDC_STATUS_BAR);
        InitListView(s_hList);
        return TRUE;

    case WM_NEW_ALERT: {
        // lParam = heap-allocated ALERT_RECORD*, we own it.
        ALERT_RECORD *a = (ALERT_RECORD *)lParam;
        AddAlertToList(s_hList, a);

        // Update status bar.
        WCHAR status[64];
        _snwprintf_s(status, 64, _TRUNCATE, L"Total alerts: %u",
                     ListView_GetItemCount(s_hList));
        SetWindowTextW(s_hStatus, status);

        // Store for save-to-file.
        EnterCriticalSection(&s_StoreLock);
        s_Stored[s_StoredCount % STORED_MAX] = *a;
        s_StoredCount++;
        LeaveCriticalSection(&s_StoreLock);

        HeapFree(GetProcessHeap(), 0, a);
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_CLEAR_BTN:
            ListView_DeleteAllItems(s_hList);
            EnterCriticalSection(&s_StoreLock);
            s_StoredCount = 0;
            LeaveCriticalSection(&s_StoreLock);
            SetWindowTextW(s_hStatus, L"Log cleared.");
            return TRUE;
        case IDC_SAVE_BTN:
            SaveLog(hDlg);
            return TRUE;
        case IDCANCEL:
            ShowWindow(hDlg, SW_HIDE);
            return TRUE;
        }
        break;

    case WM_SIZE: {
        // Resize the list view to fill the client area (minus button row).
        RECT rc;
        GetClientRect(hDlg, &rc);
        int btnRowH = 28;
        SetWindowPos(s_hList, NULL,
                     7, 7,
                     rc.right - 14,
                     rc.bottom - btnRowH - 7,
                     SWP_NOZORDER);
        // Reposition buttons and status bar at bottom.
        SetWindowPos(GetDlgItem(hDlg, IDC_CLEAR_BTN), NULL,
                     7, rc.bottom - btnRowH + 4, 60, 14, SWP_NOZORDER);
        SetWindowPos(GetDlgItem(hDlg, IDC_SAVE_BTN), NULL,
                     72, rc.bottom - btnRowH + 4, 70, 14, SWP_NOZORDER);
        SetWindowPos(s_hStatus, NULL,
                     150, rc.bottom - btnRowH + 6,
                     rc.right - 160, 12, SWP_NOZORDER);
        InvalidateRect(hDlg, NULL, TRUE);
        return TRUE;
    }

    case WM_CLOSE:
        ShowWindow(hDlg, SW_HIDE);
        return TRUE;
    }
    return FALSE;
}

//==============================================================================
// Public API
//==============================================================================

BOOL LogWindow_Create(HINSTANCE hInst, HWND hParent)
{
    InitializeCriticalSection(&s_StoreLock);

    s_hDlg = CreateDialogParamW(hInst,
                                MAKEINTRESOURCEW(IDD_LOG_DIALOG),
                                hParent, LogDlgProc, 0);
    return s_hDlg != NULL;
}

VOID LogWindow_Show(void)
{
    if (!s_hDlg) return;
    ShowWindow(s_hDlg, SW_SHOWNORMAL);
    SetForegroundWindow(s_hDlg);
}

VOID LogWindow_Hide(void)
{
    if (s_hDlg) ShowWindow(s_hDlg, SW_HIDE);
}

VOID LogWindow_AddAlert(const ALERT_RECORD *alert)
{
    if (!s_hDlg) return;

    // Allocate a copy and post to the dialog thread via WM_NEW_ALERT.
    ALERT_RECORD *copy = (ALERT_RECORD *)
        HeapAlloc(GetProcessHeap(), 0, sizeof(ALERT_RECORD));
    if (!copy) return;

    *copy = *alert;
    PostMessageW(s_hDlg, WM_NEW_ALERT, 0, (LPARAM)copy);
    InterlockedIncrement((LONG *)&s_AlertCount);
}

VOID LogWindow_Clear(void)
{
    if (s_hDlg)
        PostMessageW(s_hDlg, WM_COMMAND, IDC_CLEAR_BTN, 0);
}

HWND LogWindow_GetHwnd(void) { return s_hDlg; }
