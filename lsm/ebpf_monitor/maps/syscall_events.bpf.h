#ifndef __SYSCALL_EVENTS_BPF_H__
#define __SYSCALL_EVENTS_BPF_H__

#include <linux/limits.h>
#include <bpf/bpf_helpers.h> // For BPF helpers

#define MAX_SYSCALL_EVENTS 4096
#define TASK_COMM_LEN 16

// Enum for syscall categories
enum syscall_category {
    CATEGORY_FILE = 0,
    CATEGORY_NETWORK = 1,
    CATEGORY_PROCESS = 2,
    CATEGORY_CONFIG = 3,
    CATEGORY_MEMFD = 4
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

// eBPF ring buffer map for sending syscall events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_SYSCALL_EVENTS * sizeof(struct syscall_event_t));
} syscall_events_map SEC(".maps");

// Helper function to get parent process ID
__always_inline u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    struct task_struct *real_parent;
    bpf_core_read(&real_parent, sizeof(real_parent), &task->real_parent);
    u32 ppid = 0;
    bpf_core_read(&ppid, sizeof(ppid), &real_parent->tgid);
    return ppid;
}


#endif // __SYSCALL_EVENTS_BPF_H__
