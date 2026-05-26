// main.c
// KernelGuard Monitor — user-mode tray application.
//
// Architecture:
//   - A hidden message-pump window (HWND) anchors the tray icon and receives
//     WM_TRAY_ICON messages from the shell.
//   - DriverComm_StartPolling() runs a background thread that polls the
//     shared memory ring buffer; when a new alert arrives it calls
//     OnNewAlert() which posts WM_NEW_ALERT to the message window.
//   - WM_NEW_ALERT handler shows a balloon notification and forwards to
//     LogWindow_AddAlert().
//   - The tray icon turns red (IDI_TRAY_ALERT) on the first critical alert
//     and returns to green (IDI_TRAY_NORMAL) when the log is cleared.
//
// Compile: cl /W4 /O2 main.c driver_comm.c log_window.c app.rc
//          /link shell32.lib user32.lib gdi32.lib bcrypt.lib comctl32.lib comdlg32.lib

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <wchar.h>
#include "resource.h"
#include "driver_comm.h"
#include "log_window.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

//==============================================================================
// Globals
//==============================================================================

static HINSTANCE    g_hInst         = NULL;
static HWND         g_hMsgWnd       = NULL;
static NOTIFYICONDATAW g_Nid        = {0};
static BOOL         g_AlertActive   = FALSE;
static ULONG        g_TotalAlerts   = 0;

// Registered message sent by Windows when the taskbar is recreated (e.g.
// after Explorer crashes). We must re-add our tray icon.
static UINT         g_WmTaskbarCreated = 0;

// Class name for the hidden message window.
#define WNDCLASS_NAME   L"ScpdMonitorMsgWnd"
#define APP_MUTEX_NAME  L"ScpdMonitor_SingleInstance"

//==============================================================================
// Tray icon management
//==============================================================================

static VOID TrayIcon_Add(HWND hWnd, HINSTANCE hInst)
{
    g_Nid.cbSize           = sizeof(g_Nid);
    g_Nid.hWnd             = hWnd;
    g_Nid.uID              = 1;
    g_Nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    g_Nid.uCallbackMessage = WM_TRAY_ICON;
    g_Nid.hIcon            = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_TRAY_NORMAL));
    if (!g_Nid.hIcon)
        g_Nid.hIcon = LoadIconW(NULL, IDI_SHIELD);
    wcsncpy_s(g_Nid.szTip, ARRAYSIZE(g_Nid.szTip),
               L"KernelGuard Monitor — Monitoring", _TRUNCATE);
    Shell_NotifyIconW(NIM_ADD, &g_Nid);

    // Request version 4 behaviour (better balloon support).
    g_Nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_Nid);
}

static VOID TrayIcon_Remove(void)
{
    Shell_NotifyIconW(NIM_DELETE, &g_Nid);
}

static VOID TrayIcon_SetAlert(BOOL alert)
{
    HICON hIcon;
    if (alert) {
        hIcon = LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_TRAY_ALERT));
        if (!hIcon) hIcon = LoadIconW(NULL, IDI_ERROR);
    } else {
        hIcon = LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_TRAY_NORMAL));
        if (!hIcon) hIcon = LoadIconW(NULL, IDI_SHIELD);
    }
    g_Nid.uFlags = NIF_ICON;
    g_Nid.hIcon  = hIcon;
    Shell_NotifyIconW(NIM_MODIFY, &g_Nid);
    g_AlertActive = alert;
}

static VOID TrayIcon_ShowBalloon(LPCWSTR title, LPCWSTR text, DWORD infoFlags)
{
    g_Nid.uFlags        = NIF_INFO;
    g_Nid.dwInfoFlags   = infoFlags | NIIF_NOSOUND;
    g_Nid.uTimeout      = 6000;
    wcsncpy_s(g_Nid.szInfoTitle, ARRAYSIZE(g_Nid.szInfoTitle), title, _TRUNCATE);
    wcsncpy_s(g_Nid.szInfo,      ARRAYSIZE(g_Nid.szInfo),      text,  _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g_Nid);
}

static VOID TrayIcon_UpdateTip(void)
{
    WCHAR tip[128];
    if (g_TotalAlerts == 0) {
        wcsncpy_s(g_Nid.szTip, ARRAYSIZE(g_Nid.szTip),
                  L"KernelGuard Monitor — No alerts", _TRUNCATE);
    } else {
        _snwprintf_s(tip, 128, _TRUNCATE,
                     L"KernelGuard Monitor — %u alert(s)", g_TotalAlerts);
        wcsncpy_s(g_Nid.szTip, ARRAYSIZE(g_Nid.szTip), tip, _TRUNCATE);
    }
    g_Nid.uFlags = NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &g_Nid);
}

//==============================================================================
// Tray context menu
//==============================================================================

static VOID ShowContextMenu(HWND hWnd)
{
    HMENU hMenu = LoadMenuW(g_hInst, MAKEINTRESOURCEW(IDR_TRAY_MENU));
    if (!hMenu) return;

    HMENU hPopup = GetSubMenu(hMenu, 0);

    // Make "Open Alert Log" the bold default item.
    SetMenuDefaultItem(hPopup, ID_TRAY_OPEN_LOG, FALSE);

    // Gray out "Clear Log" if nothing to clear.
    if (g_TotalAlerts == 0)
        EnableMenuItem(hPopup, ID_TRAY_CLEAR_LOG, MF_BYCOMMAND | MF_GRAYED);

    // Required: set the foreground window so the menu dismisses correctly.
    SetForegroundWindow(hWnd);

    POINT pt;
    GetCursorPos(&pt);
    TrackPopupMenu(hPopup, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                   pt.x, pt.y, 0, hWnd, NULL);
    PostMessageW(hWnd, WM_NULL, 0, 0);
    DestroyMenu(hMenu);
}

//==============================================================================
// Alert callback — called from the polling thread
//==============================================================================

static VOID OnNewAlert(const ALERT_RECORD *alert, LPVOID userData)
{
    UNREFERENCED_PARAMETER(userData);

    // Marshal to the UI thread via a posted message; avoid calling shell APIs
    // from the background thread.
    ALERT_RECORD *copy = (ALERT_RECORD *)
        HeapAlloc(GetProcessHeap(), 0, sizeof(ALERT_RECORD));
    if (!copy) return;
    *copy = *alert;
    PostMessageW(g_hMsgWnd, WM_NEW_ALERT, 0, (LPARAM)copy);
}

//==============================================================================
// Hidden message window procedure
//==============================================================================

static LRESULT CALLBACK MsgWndProc(HWND hWnd, UINT msg,
                                   WPARAM wParam, LPARAM lParam)
{
    if (msg == g_WmTaskbarCreated) {
        // Taskbar was recreated — re-add the tray icon.
        TrayIcon_Add(hWnd, g_hInst);
        return 0;
    }

    switch (msg) {
    case WM_CREATE:
        TrayIcon_Add(hWnd, g_hInst);
        return 0;

    case WM_DESTROY:
        TrayIcon_Remove();
        PostQuitMessage(0);
        return 0;

    // ── Tray icon mouse events ──────────────────────────────────────────────
    case WM_TRAY_ICON:
        switch (LOWORD(lParam)) {
        case WM_LBUTTONDBLCLK:
        case NIN_BALLOONUSERCLICK:
            LogWindow_Show();
            break;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowContextMenu(hWnd);
            break;
        }
        return 0;

    // ── New alert received from polling thread ──────────────────────────────
    case WM_NEW_ALERT: {
        ALERT_RECORD *a = (ALERT_RECORD *)lParam;
        InterlockedIncrement((LONG *)&g_TotalAlerts);

        // Show tray balloon for level >= 1 (warnings and critical).
        if (a->AlertLevel >= 1) {
            DWORD flags = (a->AlertLevel >= 2) ? NIIF_ERROR : NIIF_WARNING;
            WCHAR balloonText[256];
            _snwprintf_s(balloonText, 256, _TRUNCATE,
                         L"%s\n%s", a->TypeText, a->Details);
            TrayIcon_ShowBalloon(
                (a->AlertLevel >= 2) ? L"⚠ Critical Security Alert"
                                     : L"Security Warning",
                balloonText, flags);
            TrayIcon_SetAlert(TRUE);
        }

        // Warn about failed HMAC validation (possible notification tampering).
        if (!a->HmacValid) {
            TrayIcon_ShowBalloon(
                L"Notification Integrity Warning",
                L"Alert HMAC validation failed — notification may be forged.",
                NIIF_ERROR);
        }

        TrayIcon_UpdateTip();
        LogWindow_AddAlert(a);
        HeapFree(GetProcessHeap(), 0, a);
        return 0;
    }

    // ── Menu commands ───────────────────────────────────────────────────────
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_TRAY_OPEN_LOG:
            LogWindow_Show();
            break;
        case ID_TRAY_CLEAR_LOG:
            LogWindow_Clear();
            g_TotalAlerts = 0;
            TrayIcon_SetAlert(FALSE);
            TrayIcon_UpdateTip();
            break;
        case ID_TRAY_ABOUT:
            MessageBoxW(hWnd,
                L"KernelGuard Monitor\n"
                L"Version 1.0\n\n"
                L"Monitors the kernel driver for side-channel attack\n"
                L"detection events and kernel integrity violations.\n\n"
                L"Double-click the tray icon to view the alert log.",
                L"About", MB_ICONINFORMATION);
            break;
        case ID_TRAY_EXIT:
            DestroyWindow(hWnd);
            break;
        }
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

//==============================================================================
// WinMain
//==============================================================================

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst,
                   LPSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInst);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    g_hInst = hInst;

    // ── Single-instance guard ─────────────────────────────────────────────────
    HANDLE hMutex = CreateMutexW(NULL, TRUE, APP_MUTEX_NAME);
    if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        // Another instance is running — bring its log window to front.
        HWND hExisting = FindWindowW(WNDCLASS_NAME, NULL);
        if (hExisting)
            PostMessageW(hExisting, WM_COMMAND, ID_TRAY_OPEN_LOG, 0);
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    // ── Initialize common controls (ListView, etc.) ───────────────────────────
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&icc);

    // ── Register the hidden message window class ──────────────────────────────
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = MsgWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = WNDCLASS_NAME;
    RegisterClassExW(&wc);

    g_hMsgWnd = CreateWindowExW(0, WNDCLASS_NAME, L"ScpdMonitor",
                                0, 0, 0, 0, 0,
                                HWND_MESSAGE, NULL, hInst, NULL);
    if (!g_hMsgWnd) {
        CloseHandle(hMutex);
        return 1;
    }

    // Register the TaskbarCreated message (sent when Explorer restarts).
    g_WmTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    // ── Create the log window (hidden initially) ───────────────────────────────
    LogWindow_Create(hInst, g_hMsgWnd);

    // ── Connect to driver ─────────────────────────────────────────────────────
    if (!DriverComm_Open()) {
        // Driver not loaded — show a warning balloon then continue monitoring.
        TrayIcon_ShowBalloon(
            L"Driver Not Found",
            L"The KernelGuard kernel driver is not running.\n"
            L"Install the driver and restart the monitor.",
            NIIF_WARNING);
    } else {
        // Start background polling; alerts arrive via OnNewAlert → WM_NEW_ALERT.
        DriverComm_StartPolling(OnNewAlert, NULL);

        TrayIcon_ShowBalloon(
            L"KernelGuard Monitor Active",
            L"Monitoring kernel for side-channel attacks and integrity violations.",
            NIIF_INFO);
    }

    // ── Message pump ──────────────────────────────────────────────────────────
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        // Dispatch to the log dialog if it exists and the message is for it.
        HWND hLog = LogWindow_GetHwnd();
        if (hLog && IsDialogMessageW(hLog, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────
    DriverComm_StopPolling();
    DriverComm_Close();
    CloseHandle(hMutex);
    return (int)msg.wParam;
}
