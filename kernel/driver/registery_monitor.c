#include <ntifs.h>
#include <ntstrsafe.h>
#include "../include/sleuth_defs.h"
#include "../include/comms_shared.h"
#include "../include/syscall_hooks.h"

//
// Hook slot index
//
#define REG_HOOK_INDEX 1  // Avoid index 0 (used by file_monitor)

//
// External shared syscall event buffer
//
extern SYSCALL_EVENT g_EventBuffer[MAX_SYSCALLS_PER_MESSAGE];
extern ULONG g_EventCount;
extern SYSCALL_HOOK g_Hooks[MAX_HOOKS];

//
// Interceptor for ZwSetValueKey
//
NTSTATUS Hook_ZwSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
) {
    LOG(LOG_INFO, "Intercepted ZwSetValueKey!");

    if (g_EventCount < MAX_SYSCALLS_PER_MESSAGE) {
        SYSCALL_EVENT* event = &g_EventBuffer[g_EventCount];

        event->ProcessId = (DWORD)(ULONG_PTR)PsGetCurrentProcessId();
        RtlStringCchCopyA(event->FunctionName, 64, "ZwSetValueKey");
        RtlStringCchCopyA(event->Category, 32, "registry");
        event->Timestamp = KeQueryInterruptTime();

        g_EventCount++;
    } else {
        LOG(LOG_WARN, "Registry hook: Event buffer full.");
    }

    // Forward original syscall
    return ((NTSTATUS(*)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG))
            g_Hooks[REG_HOOK_INDEX].OriginalFunction)(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

//
// Hook initialization for registry-related syscalls
//
NTSTATUS InstallRegistryHooks(void) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZwSetValueKey");
    g_Hooks[REG_HOOK_INDEX].OriginalFunction = MmGetSystemRoutineAddress(&name);

    if (!g_Hooks[REG_HOOK_INDEX].OriginalFunction) {
        LOG(LOG_ERROR, "Failed to locate ZwSetValueKey.");
        return STATUS_UNSUCCESSFUL;
    }

    g_Hooks[REG_HOOK_INDEX].HookFunction = Hook_ZwSetValueKey;
    RtlStringCchCopyA(g_Hooks[REG_HOOK_INDEX].FunctionName, 64, "ZwSetValueKey");

    LOG(LOG_INFO, "Registry hook for ZwSetValueKey installed (placeholder mode).");

    return STATUS_SUCCESS;
}
