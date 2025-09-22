#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../../lsm/ebpf_monitor/maps/syscall_events_user.h"

static struct ring_buffer *rb = nullptr;
static volatile bool stop = false;

static const char* syscall_name(__u32 id) {
    switch (id) {
        case 41:  return "socket";
        case 42:  return "connect";
        case 43:  return "accept";
        case 44:  return "sendto";
        case 45:  return "recvfrom";
        case 46:  return "sendmsg";
        case 47:  return "recvmsg";
        case 48:  return "shutdown";
        case 49:  return "bind";
        case 50:  return "listen";
        case 51:  return "getsockname";
        case 52:  return "getpeername";
        case 53:  return "socketpair";
        case 54:  return "setsockopt";
        case 55:  return "getsockopt";
        case 40:  return "sendfile";
        case 288: return "accept4";
        case 299: return "recvmmsg";
        case 307: return "sendmmsg";
        default:  return "unknown";
    }
}

static void handle_signal(int) { stop = true; }

static int handle_event(void *, void *data, size_t) {
    const syscall_event_t *event = static_cast<const syscall_event_t *>(data);
    if (event->uid == 0) {
        std::cout << "[NET] PID=" << event->pid
                  << " PPID=" << event->ppid
                  << " UID="  << event->uid
                  << " SYSCALL=" << syscall_name(event->syscall_id)
                  << " (" << event->syscall_id << ")"
                  << " COMM=\"" << event->comm << "\""
                  << std::endl;
    }
    return 0;
}

int main() {
    signal(SIGINT, handle_signal);

    // (Optional) raise memlock
    rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    // Load and attach net_trace.bpf.o
    const char *bpf_obj_path = "../../lsm/ebpf_monitor/build/net_trace.o";
    struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, nullptr);
    if (!obj) {
        std::cerr << "Failed to open BPF object file: " << bpf_obj_path << std::endl;
        return 1;
    }
    if (bpf_object__load(obj)) {
        std::cerr << "Failed to load BPF object" << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    // Attach all programs in the object to their tracepoints
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            std::cerr << "Failed to attach program: " << bpf_program__name(prog) << std::endl;
            bpf_object__close(obj);
            return 1;
        }
        // Optionally keep track of links for cleanup
    }

    // Find the syscall_events_map
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "syscall_events_map");
    if (!map) {
        std::cerr << "Failed to find syscall_events_map in BPF object" << std::endl;
        bpf_object__close(obj);
        return 1;
    }
    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        std::cerr << "Failed to get fd from syscall_events_map" << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer\n";
        bpf_object__close(obj);
        return 1;
    }

    std::cout << "[*] Listening for NET syscalls... (Ctrl+C to stop)\n";
    while (!stop) {
        int n = ring_buffer__poll(rb, 250);
        if (n < 0 && n != -EINTR) {
            std::cerr << "ring_buffer__poll() failed: " << n << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
