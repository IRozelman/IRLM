#ifndef COMMS_SHARED_H
#define COMMS_SHARED_H

#include <Windows.h>
#include <ntifs.h>

NTSTATUS InitCommsDevice(void);
VOID CleanupCommsDevice(void);
NTSTATUS CommsDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

// Define the max number of intercepted syscalls we can send in one message
#define MAX_SYSCALLS_PER_MESSAGE 32

// Operation codes used to define what user-mode is requesting
typedef enum _COMMAND_TYPE {
    CMD_NONE = 0,
    CMD_GET_SYSCALLS,
    CMD_CLEAR_LOG
} COMMAND_TYPE;

// Structure used to describe a single syscall event
typedef struct _SYSCALL_EVENT {
    DWORD ProcessId;
    CHAR FunctionName[64];
    CHAR Category[32]; 
    ULONGLONG Timestamp;
} SYSCALL_EVENT, *PSYSCALL_EVENT;

// This is the structure the kernel sends to user mode
typedef struct _KERNEL_TO_USER_MSG {
    DWORD Count;
    SYSCALL_EVENT Events[MAX_SYSCALLS_PER_MESSAGE];
} KERNEL_TO_USER_MSG, *PKERNEL_TO_USER_MSG;

// This is the structure user mode sends to the kernel
typedef struct _USER_TO_KERNEL_MSG {
    COMMAND_TYPE Command;
} USER_TO_KERNEL_MSG, *PUSER_TO_KERNEL_MSG;

#endif
