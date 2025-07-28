#ifndef SYSCALL_EVENTS_USER_H
#define SYSCALL_EVENTS_USER_H


#include <stdint.h>

struct syscall_event_t {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t syscall_id;
    char  filename[256];
};

#endif
