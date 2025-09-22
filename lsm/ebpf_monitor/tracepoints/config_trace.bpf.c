#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_events.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Utility: check if path refers to a config directory or file
static __always_inline int is_config_path(const char *filename) {
    char fname[256];
    if (bpf_probe_read_user_str(fname, sizeof(fname), filename) > 0) {
        if (!fname) return 0;
        if (__builtin_memcmp(fname, "/etc/", 5) == 0) return 1;
        if (__builtin_memcmp(fname, "/usr/lib/systemd/", 17) == 0) return 1;
        if (__builtin_memcmp(fname, "/var/lib/", 9) == 0) return 1;
        if (__builtin_memcmp(fname, "/run/systemd/", 13) == 0) return 1;
    }
    return 0;
}

// General event submission
static __always_inline void submit_event(struct pt_regs *ctx, const char *filename) {
    struct syscall_event_t *event = bpf_ringbuf_reserve(&syscall_events_map, sizeof(*event), 0);
    if (!event) return;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = get_ppid();
    event->uid = bpf_get_current_uid_gid();
    event->category = CATEGORY_CONFIG;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    if (filename)
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename);
    else
        event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
}


// ----------- Tracepoints for config-related syscalls -----------

// openat: opening config files (/etc, systemd, var/lib)
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[1];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}

// open: legacy open
SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}

// creat: create new file
SEC("tracepoint/syscalls/sys_enter_creat")
int trace_creat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}

// unlinkat: delete config files
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[1];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}

// renameat: rename config files
SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx) {
    const char *old = (const char *)ctx->args[1];
    const char *new = (const char *)ctx->args[2];
    if (!is_config_path(old) && !is_config_path(new)) return 0;
    submit_event((struct pt_regs *)ctx, old);
    return 0;
}

// renameat2: extended rename
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx) {
    const char *old = (const char *)ctx->args[1];
    const char *new = (const char *)ctx->args[2];
    if (!is_config_path(old) && !is_config_path(new)) return 0;
    submit_event((struct pt_regs *)ctx, old);
    return 0;
}

// chmod: change permissions
SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}

// fchmod: change permissions via fd
SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_fchmod(struct trace_event_raw_sys_enter *ctx) {
    // We cannot get filename from fd easily here
    submit_event((struct pt_regs *)ctx, NULL);
    return 0;
}

// chown: change ownership
SEC("tracepoint/syscalls/sys_enter_chown")
int trace_chown(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}

// linkat: hard link
SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_linkat(struct trace_event_raw_sys_enter *ctx) {
    const char *old = (const char *)ctx->args[1];
    const char *new = (const char *)ctx->args[2];
    if (!is_config_path(old) && !is_config_path(new)) return 0;
    submit_event((struct pt_regs *)ctx, old);
    return 0;
}

// symlinkat: symbolic link
SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    const char *target = (const char *)ctx->args[0];
    const char *linkpath = (const char *)ctx->args[1];
    if (!is_config_path(target) && !is_config_path(linkpath)) return 0;
    submit_event((struct pt_regs *)ctx, linkpath);
    return 0;
}

// truncate: shorten or clear file content
SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_truncate(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}

// ftruncate: via file descriptor
SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    submit_event((struct pt_regs *)ctx, NULL);
    return 0;
}

// setxattr: extended attribute
SEC("tracepoint/syscalls/sys_enter_setxattr")
int trace_setxattr(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}

// removexattr: remove extended attribute
SEC("tracepoint/syscalls/sys_enter_removexattr")
int trace_removexattr(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[0];
    if (!is_config_path(fname)) return 0;
    submit_event((struct pt_regs *)ctx, fname);
    return 0;
}