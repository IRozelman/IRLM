#ifndef SYSCALL_EVENTS_USER_H
#define SYSCALL_EVENTS_USER_H


#include <stdint.h>

struct syscall_event_t {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t syscall_id;
    uint32_t category;
    char comm[16];  
    char  filename[256];
};

#endif
