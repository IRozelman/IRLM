#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_events.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Helper: submit event to ring buffer
static __always_inline int submit_event(struct pt_regs *ctx, const char *filename, __u32 syscall_id) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    // Adjust the name if your binary is different
    if (!__builtin_memcmp(comm, "ringbuf_reader", sizeof("ringbuf_reader") - 1))
        return 0;

    struct syscall_event_t *event = bpf_ringbuf_reserve(&syscall_events_map, sizeof(*event), 0);
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = get_ppid();
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->category = CATEGORY_FILE;
    event->syscall_id = syscall_id;
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
    submit_event((struct pt_regs *)ctx, fname, 2); // 2 = open
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[1];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, 257); // 257 = openat
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_write")
// int trace_write(struct trace_event_raw_sys_enter *ctx) {
   // int fd = (__u32)ctx->args[0];
    // Skip stdout/stderr to avoid feedback loop
    // if (fd == 1 || fd == 2)
       // return 0;

    // No filename in write(); submit without one, if you really need it
    // return submit_event((struct pt_regs *)ctx, NULL, 1);
// }


SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, 87); // 87 = unlink
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[1];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, 263); // 263 = unlinkat
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx) {
    const char *old = (const char *)ctx->args[0];
    const char *new = (const char *)ctx->args[1];
    if (!old || !new) return 0;
    submit_event((struct pt_regs *)ctx, old, 82); // 82 = rename
    submit_event((struct pt_regs *)ctx, new, 82);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx) {
    const char *old = (const char *)ctx->args[1];
    const char *new = (const char *)ctx->args[2];
    if (!old || !new) return 0;
    submit_event((struct pt_regs *)ctx, old, 316); // 316 = renameat
    submit_event((struct pt_regs *)ctx, new, 316);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_creat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, 85); // 85 = creat
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int trace_fsync(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, 74); // 74 = fsync
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int trace_fdatasync(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!fname) return 0;
    submit_event((struct pt_regs *)ctx, fname, 75); // 75 = fdatasync
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    if (fd < 0) return 0; // Invalid fd
    submit_event((struct pt_regs *)ctx, NULL, 77); // 77 = ftruncate
    return 0;
}