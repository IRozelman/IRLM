#pragma once

#include <ntddk.h>

//
// Memory allocation tag (used for tagging driver allocations)
// 'SLEU' (in reverse because of endianness)
//
#define SLEUTH_POOL_TAG 'UELS'

//
// Max length for strings
//
#define MAX_FUNCTION_NAME_LEN 64
#define MAX_CATEGORY_LEN 32

//
// Logging levels
//
#define LOG_INFO    1
#define LOG_WARN    2
#define LOG_ERROR   3

//
// Debug mode (can toggle off in release builds)
//
#define DEBUG_MODE 1

//
// Utility macro for logging (basic)
//
#if DEBUG_MODE
    #define LOG(level, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[SLEUTH] " fmt "\n", ##__VA_ARGS__)
#else
    #define LOG(level, fmt, ...)
#endif

NTSTATUS InitCommsDevice(PDRIVER_OBJECT DriverObject);
VOID CleanupCommsDevice();
NTSTATUS InstallSyscallHooks();
VOID RemoveSyscallHooks();
NTSTATUS InstallRegistryHooks();
NTSTATUS CommsDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
