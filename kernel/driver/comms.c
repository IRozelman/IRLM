#include <ntifs.h>
#include <ntddk.h>
#include "../include/comms_shared.h"
#include "../include/sleuth_defs.h"

//
// External event buffer & count from syscall_hooks.c
//
extern SYSCALL_EVENT g_EventBuffer[MAX_SYSCALLS_PER_MESSAGE];
extern ULONG g_EventCount;

//
// IOCTL code used to fetch syscall logs
//
#define IOCTL_GET_SYSCALLS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

//
// Global device object + symbolic link (needed for cleanup)
//
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\SleuthComms");
UNICODE_STRING g_SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\SleuthComms");

//
// Dispatcher prototype (used by IRP table)
//
NTSTATUS CommsDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS HandleIoctl(IN PIRP Irp, IN PIO_STACK_LOCATION stack);

//
// Initialize the comms device — called in DriverEntry
//
NTSTATUS InitCommsDevice(PDRIVER_OBJECT DriverObject) {
    NTSTATUS status;

    status = IoCreateDevice(
        DriverObject,            // Pass the driver object from DriverEntry
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        LOG(LOG_ERROR, "Failed to create SleuthComms device.");
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymbolicLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        LOG(LOG_ERROR, "Failed to create symbolic link.");
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Configure device behavior
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    LOG(LOG_INFO, "SleuthComms device initialized.");
    return STATUS_SUCCESS;
}

//
// Cleanup the device on unload
//
VOID CleanupCommsDevice() {
    IoDeleteSymbolicLink(&g_SymbolicLink);
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }
}

//
// Main IRP dispatcher (handles IOCTL requests)
//
NTSTATUS CommsDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = HandleIoctl(Irp, stack);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//
// Handle a specific IOCTL code
//
NTSTATUS HandleIoctl(IN PIRP Irp, IN PIO_STACK_LOCATION stack) {
    ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    if (ioctlCode == IOCTL_GET_SYSCALLS) {
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (outLen < sizeof(KERNEL_TO_USER_MSG)) {
            LOG(LOG_WARN, "User buffer too small for syscall dump.");
            return STATUS_BUFFER_TOO_SMALL;
        }

        PKERNEL_TO_USER_MSG outMsg = (PKERNEL_TO_USER_MSG)Irp->AssociatedIrp.SystemBuffer;
        RtlZeroMemory(outMsg, sizeof(KERNEL_TO_USER_MSG));

        // Copy syscall events into output
        outMsg->Count = g_EventCount;
        RtlCopyMemory(outMsg->Events, g_EventBuffer, sizeof(SYSCALL_EVENT) * g_EventCount);

        g_EventCount = 0;
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_DEVICE_REQUEST;
}
