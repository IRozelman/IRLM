#include <ntifs.h>
#include <ntddk.h>
#include "../include/comms_shared.h"
#include "../include/sleuth_defs.h"

//
// Driver Unload Routine
//
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    LOG(LOG_INFO, "Sleuth Driver Unloading...");
    CleanupCommsDevice();
    RemoveSyscallHooks();
    LOG(LOG_INFO, "All hooks removed. Goodbye.");
}

//
// Driver Entry Point
//
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    LOG(LOG_INFO, "Sleuth Driver Loaded.");

    // Register cleanup callback
    DriverObject->DriverUnload = DriverUnload;

    // Initialize communication device first
    NTSTATUS status = InitCommsDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        LOG(LOG_ERROR, "Failed to initialize communication device.");
        return status;
    }

    // Register IRP dispatch for IOCTLs
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CommsDispatch;

    // Hook syscalls
    status = InstallSyscallHooks();
    if (!NT_SUCCESS(status)) {
        LOG(LOG_ERROR, "Failed to install syscall hooks!");
        CleanupCommsDevice(); 
        return status;
    }

    status = InstallRegistryHooks();
    if (!NT_SUCCESS(status)) {
        LOG(LOG_ERROR, "Failed to install registry hooks.");
        return status;
    }


    LOG(LOG_INFO, "Syscall hooks installed successfully.");
    return STATUS_SUCCESS;
}
