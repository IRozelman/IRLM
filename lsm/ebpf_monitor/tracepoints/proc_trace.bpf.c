#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../maps/syscall_events.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Helper: Fill in a syscall_event_t struct
static __always_inline int submit_process_event(struct pt_regs *ctx, u32 syscall_id) {
    struct syscall_event_t *event;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid & 0xffffffff;

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;

    event = bpf_ringbuf_reserve(&syscall_events_map, sizeof(*event), 0);
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = tgid;
    event->ppid = bpf_get_current_ppid();
    event->uid = uid;
    event->syscall_id = syscall_id;
    event->category = CATEGORY_PROCESS;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memset(&event->filename, 0, sizeof(event->filename));

    bpf_ringbuf_submit(event, 0);
    return 0;
}


// Hooks for process-related syscalls

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    return submit_process_event((struct pt_regs *)ctx, __NR_execve);
}

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_fork(struct trace_event_raw_sys_enter *ctx) {
    return submit_process_event((struct pt_regs *)ctx, __NR_fork);
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int trace_vfork(struct trace_event_raw_sys_enter *ctx) {
    return submit_process_event((struct pt_regs *)ctx, __NR_vfork);
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx) {
    return submit_process_event((struct pt_regs *)ctx, __NR_clone);
}

SEC("tracepoint/syscalls/sys_exit_exit")
int trace_exit(struct trace_event_raw_sys_exit *ctx) {
    return submit_process_event((struct pt_regs *)ctx, __NR_exit);
}

SEC("tracepoint/syscalls/sys_exit_exit_group")
int trace_exit_group(struct trace_event_raw_sys_exit *ctx) {
    return submit_process_event((struct pt_regs *)ctx, __NR_exit_group);
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx) {
    return submit_process_event((struct pt_regs *)ctx, __NR_setns);
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl(struct trace_event_raw_sys_enter *ctx) {
    // prctl doesn't have a specific syscall ID, but we can log it
    return submit_process_event((struct pt_regs *)ctx, __NR_prctl);
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx) {
    // setuid doesn't have a specific syscall ID, but we can log it
    return submit_process_event((struct pt_regs *)ctx, __NR_setuid);
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx) {
    // setgid doesn't have a specific syscall ID, but we can log it
    return submit_process_event((struct pt_regs *)ctx, __NR_setgid);
}

SEC("tracepoint/syscalls/sys_enter_setpgid")
int trace_setpgid(struct trace_event_raw_sys_enter *ctx) {
    // setpgid doesn't have a specific syscall ID, but we can log it
    return submit_process_event((struct pt_regs *)ctx, __NR_setpgid);
}

SEC("tracepoint/syscalls/sys_enter_setsid")
int trace_setsid(struct trace_event_raw_sys_enter *ctx) {
    // setsid doesn't have a specific syscall ID, but we can log it
    return submit_process_event((struct pt_regs *)ctx, __NR_setsid);
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_setreuid(struct trace_event_raw_sys_enter *ctx) {
    // setreuid doesn't have a specific syscall ID, but we can log it
    return submit_process_event((struct pt_regs *)ctx, __NR_setreuid);
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int trace_setregid(struct trace_event_raw_sys_enter *ctx) {
    // setregid doesn't have a specific syscall ID, but we can log it
    return submit_process_event((struct pt_regs *)ctx, __NR_setregid);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid(struct trace_event_raw_sys_enter *ctx) {
    // setresuid doesn't have a specific syscall ID, but we can log it
    return submit_process_event((struct pt_regs *)ctx, __NR_setresuid);
}
