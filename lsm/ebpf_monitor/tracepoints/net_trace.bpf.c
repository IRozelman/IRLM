#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_events.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Helper: fill in a syscall_event_t struct
static __always_inline int submit_event(struct pt_regs *ctx, __u32 syscall_id) {
    struct syscall_event_t *event = bpf_ringbuf_reserve(&syscall_events_map, sizeof(*event), 0);
    if (!event) return 0;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = get_ppid();
    event->uid = bpf_get_current_uid_gid();
    event->category = CATEGORY_FILE; // Adjust category as needed
    event->syscall_id = syscall_id;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}


// Hooks for net-related syscalls

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 41); // 41 = socket
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 42); // 42 = connect
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 44); // 44 = sendto
}


SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 46); // 46 = sendmsg
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 47); // 47 = recvmsg
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_accept(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 43); // 43 = accept
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 288); // 288 = accept4
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 49); // 49 = bind
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 50); // 50 = listen
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int trace_shutdown(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 48); // 48 = shutdown
}


// TODO: Check if this lack of tracepoint can cause security breach
// SEC("tracepoint/syscalls/sys_enter_sendfile")
// int trace_sendfile(struct trace_event_raw_sys_enter *ctx) {
//     return submit_event((struct pt_regs *)ctx, 40); // 40 = sendfile
// }

SEC("tracepoint/syscalls/sys_enter_socketpair")
int trace_socketpair(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 53); // 53 = socketpair
}



SEC("tracepoint/syscalls/sys_enter_sendfile64")
int trace_sendfile64(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 239); // 239 = sendfile64
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int trace_recvmmsg(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 299); // 299 = recvmmsg
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int trace_sendmmsg(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 307); // 307 = sendmmsg
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int trace_getsockopt(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 55); // 55 = getsockopt
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int trace_setsockopt(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 54); // 54 = setsockopt
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int trace_getsockname(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 51); // 51 = getsockname
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int trace_getpeername(struct trace_event_raw_sys_enter *ctx) {
    return submit_event((struct pt_regs *)ctx, 52); // 52 = getpeername
}
