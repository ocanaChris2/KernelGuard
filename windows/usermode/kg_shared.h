// kg_shared.h
// Definitions shared between the kernel driver and the user-mode monitor.
// This header is plain C89 / Win32-compatible — no kernel-only types.

#pragma once

#include <windows.h>

//==============================================================================
// IOCTL codes (mirror of driver_main.c)
//==============================================================================

#define KG_DEVICE_TYPE    FILE_DEVICE_UNKNOWN

#define IOCTL_KG_MAP_SHARED_MEM \
    CTL_CODE(KG_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_KG_GET_HMAC_KEY \
    CTL_CODE(KG_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)

//==============================================================================
// Shared memory structures (byte-identical to kernel-side definitions)
//==============================================================================

#define NOTIFICATION_SLOTS  16
#define HMAC_KEY_SIZE       32
#define NOTIFY_MAGIC        0xDEADC0DEUL
#define SIGNAL_MAGIC        0xCAFEBABEUL

#pragma pack(push, 1)
typedef struct _SECURE_NOTIFICATION {
    ULONG   Magic;
    ULONG   SequenceNumber;
    ULONG   AlertType;
    ULONG   AlertLevel;         // 0=info, 1=watch, 2=critical
    ULONG64 Timestamp;          // KeQueryPerformanceCounter value
    ULONG64 Param1;             // Alert-specific
    ULONG64 Param2;             // Alert-specific
    BYTE    Hmac[32];           // HMAC-SHA256 over all fields above
} SECURE_NOTIFICATION;

typedef struct _SHARED_MEM_REGION {
    volatile ULONG      WriteIndex;
    volatile ULONG      ReadIndex;
    volatile ULONG      DriverNonce;
    ULONG               Reserved;
    SECURE_NOTIFICATION Notifications[NOTIFICATION_SLOTS];
} SHARED_MEM_REGION;
#pragma pack(pop)

//==============================================================================
// Alert type codes (mirror of KernelGuard.h)
//==============================================================================

#define ALERT_PMU_L1D_ANOMALY           0x0001UL
#define ALERT_PMU_L2_ANOMALY            0x0002UL
#define ALERT_PMU_RDTSC_RATE            0x0003UL
#define ALERT_UNAUTHORIZED_KBD_FILTER   0x0010UL
#define ALERT_UNAUTHORIZED_DMA          0x0011UL
#define ALERT_PCI_DISCREPANCY           0x0012UL
#define ALERT_KBD_FILTER_NEUTRALIZED    0x0013UL
#define ALERT_DMA_BLOCKED_IOMMU         0x0014UL
#define ALERT_DEVICE_BME_DISABLED       0x0015UL
#define ALERT_IDT_HOOK                  0x0020UL
#define ALERT_DISPATCH_HOOK             0x0021UL
#define ALERT_TEXT_PATCH                0x0022UL
#define ALERT_SHARED_STATE_CORRUPT      0x0030UL
#define ALERT_FAIL_SAFE_ENTERED         0x0031UL
