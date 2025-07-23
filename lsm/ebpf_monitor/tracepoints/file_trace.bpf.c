#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../maps/syscall_events.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Helper: submit event to ring buffer
static __always_inline int submit_event(struct pt_regs *ctx, const char *filename, __u32 syscall_id) {
    struct syscall_event_t *event = bpf_ringbuf_reserve(&syscall_events_map, sizeof(*event), 0);
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = bpf_get_current_ppid();
    event->uid = bpf_get_current_uid_gid();
    event->syscall_id = syscall_id;
    event->category = CATEGORY_FILE;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    if (filename)
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    else
        event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}


// Hooks

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, __NR_open);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[1];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, __NR_openat);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[1];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, __NR_write);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, __NR_unlink);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[1];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, __NR_unlinkat);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx) {
    const char *old = (const char *)ctx->args[0];
    const char *new = (const char *)ctx->args[1];
    if (!old || !new) return 0;
    submit_event((struct pt_regs *)ctx, old, __NR_rename);
    submit_event((struct pt_regs *)ctx, new, __NR_rename);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx) {
    const char *old = (const char *)ctx->args[1];
    const char *new = (const char *)ctx->args[2];
    if (!old || !new) return 0;
    submit_event((struct pt_regs *)ctx, old, __NR_renameat);
    submit_event((struct pt_regs *)ctx, new, __NR_renameat);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_creat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, __NR_creat);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int trace_fsync(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, __NR_fsync);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int trace_fdatasync(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, __NR_fdatasync);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    if (fd < 0) return 0; // Invalid fd
    submit_event((struct pt_regs *)ctx, NULL, __NR_ftruncate);
    return 0;
}