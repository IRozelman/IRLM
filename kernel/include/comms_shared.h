#ifndef COMMS_SHARED_H
#define COMMS_SHARED_H

// Detect user-mode vs kernel-mode
#if defined(_KERNEL_MODE) || defined(__KERNEL__) || defined(_NTDDK_)
    #include <ntddk.h>
    typedef ULONG32 DWORD;
    typedef ULONG64 ULONGLONG;
#else
    #include <Windows.h>
#endif

#define MAX_SYSCALLS_PER_MESSAGE 32

typedef enum _COMMAND_TYPE {
    CMD_CLEAR_LOG
} COMMAND_TYPE;

typedef struct _SYSCALL_EVENT {
    DWORD ProcessId;
    CHAR FunctionName[64];
    CHAR Category[32];
    ULONGLONG Timestamp;
} SYSCALL_EVENT, *PSYSCALL_EVENT;

typedef struct _KERNEL_TO_USER_MSG {
    DWORD Count;
    SYSCALL_EVENT Events[MAX_SYSCALLS_PER_MESSAGE];
} KERNEL_TO_USER_MSG, *PKERNEL_TO_USER_MSG;

typedef struct _USER_TO_KERNEL_MSG {
    COMMAND_TYPE Command;
} USER_TO_KERNEL_MSG, *PUSER_TO_KERNEL_MSG;

#endif // COMMS_SHARED_H
