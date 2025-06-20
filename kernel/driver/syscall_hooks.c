#include <ntifs.h>
#include <ntstrsafe.h>
#include "../include/syscall_hooks.h"
#include "../include/sleuth_defs.h"
#include "../include/comms_shared.h"

//
// Global array to store our syscall hooks
//
SYSCALL_HOOK g_Hooks[MAX_HOOKS];  // Only use index 0 for ZwCreateFile
int g_HookCount = 0;

// These buffers will eventually be shared with user-mode via IOCTL/SharedMemory
SYSCALL_EVENT g_EventBuffer[MAX_SYSCALLS_PER_MESSAGE];
ULONG g_EventCount = 0;

//
// Interceptor for ZwCreateFile
//
NTSTATUS Hook_ZwCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    LOG(LOG_INFO, "Intercepted ZwCreateFile from process!");

    // Log behavior into event buffer if not full
    if (g_EventCount < MAX_SYSCALLS_PER_MESSAGE) {
        SYSCALL_EVENT* event = &g_EventBuffer[g_EventCount];
        event->ProcessId = (DWORD)(ULONG_PTR)PsGetCurrentProcessId();
        RtlStringCchCopyA(event->FunctionName, 64, "ZwCreateFile");
        RtlStringCchCopyA(event->Category, 32, "file_io");
        event->Timestamp = KeQueryInterruptTime();
        g_EventCount++;
    } else {
        LOG(LOG_WARN, "Syscall event buffer is full.");
    }

    // Forward the original syscall as-is
    return ((NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                         PIO_STATUS_BLOCK, PLARGE_INTEGER,
                         ULONG, ULONG, ULONG, ULONG, PVOID, ULONG))
            g_Hooks[0].OriginalFunction)(FileHandle, DesiredAccess,
                                         ObjectAttributes, IoStatusBlock,
                                         AllocationSize, FileAttributes,
                                         ShareAccess, CreateDisposition,
                                         CreateOptions, EaBuffer, EaLength);
}

//
// Hook initialization function
//
NTSTATUS InstallSyscallHooks(void) {
    RtlZeroMemory(&g_Hooks, sizeof(g_Hooks));

    UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZwCreateFile");
    g_Hooks[0].OriginalFunction = MmGetSystemRoutineAddress(&name);

    if (!g_Hooks[0].OriginalFunction) {
        LOG(LOG_ERROR, "Could not resolve ZwCreateFile.");
        return STATUS_UNSUCCESSFUL;
    }

    g_Hooks[0].HookFunction = Hook_ZwCreateFile;
    RtlStringCchCopyA(g_Hooks[0].FunctionName, 64, "ZwCreateFile");

    g_HookCount = 1;

    LOG(LOG_INFO, "ZwCreateFile hook installed (placeholder mode).");

    return STATUS_SUCCESS;
}

//
// Cleanup hook teardown
//
VOID RemoveSyscallHooks(void) {
    LOG(LOG_INFO, "Syscall hooks removed (hook unpatching not yet implemented).");
}
