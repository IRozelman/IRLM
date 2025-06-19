#ifndef SYSCALL_HOOKS_H
#define SYSCALL_HOOKS_H

#include <ntddk.h>

// Represents a single system call hook entry
typedef struct _SYSCALL_HOOK {
    PVOID OriginalFunction;
    PVOID HookFunction;
    CHAR FunctionName[64];
} SYSCALL_HOOK, *PSYSCALL_HOOK;

// Maximum number of system calls we'll hook
#define MAX_HOOKS 32

// Hook manager interface
NTSTATUS InstallSyscallHooks(void);
VOID RemoveSyscallHooks(void);

#endif // SYSCALL_HOOKS_H
