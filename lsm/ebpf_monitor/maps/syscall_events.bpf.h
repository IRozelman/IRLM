#ifndef __SYSCALL_EVENTS_BPF_H__
#define __SYSCALL_EVENTS_BPF_H__

#include <linux/types.h>
#include <linux/limits.h>
#include <bpf/bpf_helpers.h> // For BPF helpers

#define MAX_SYSCALL_EVENTS 4096
#define TASK_COMM_LEN 16

// Enum for syscall categories
enum syscall_category {
    CATEGORY_FILE = 1,
    CATEGORY_NETWORK,
    CATEGORY_PROCESS,
    CATEGORY_REGISTRY,
    CATEGORY_MEMFD
};

// Structure to log syscall events
struct syscall_event_t {
    __u64 timestamp_ns;               // High-resolution timestamp in nanoseconds
    __u32 pid;                        // Process ID
    __u32 ppid;                       // Parent Process ID
    __u32 uid;                        // User ID
    __u32 syscall_id;                 // Raw syscall number
    __u32 category;                   // From syscall_category
    char comm[TASK_COMM_LEN];         // Process name (like "bash" or "python3")
    char filename[PATH_MAX];          // Affected filename (if applicable)
};

#ifdef __BPF_TRACING__
// eBPF ring buffer map for sending syscall events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_SYSCALL_EVENTS * sizeof(struct syscall_event_t));
} syscall_events_map SEC(".maps");
#endif

#endif // __SYSCALL_EVENTS_BPF_H__
