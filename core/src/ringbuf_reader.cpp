#include <iostream>
#include <csignal>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include "../../lsm/ebpf_monitor/maps/syscall_events_user.h"

// Global ring buffer pointer for cleanup on exit
static struct ring_buffer *rb = nullptr;
static volatile bool stop = false;

// Signal handler for clean exit (Ctrl+C)
void handle_signal(int) {
    stop = true;
}

// Callback function for incoming syscall events
static int handle_event(void *ctx, void *data, size_t len) {
    const syscall_event_t *event = static_cast<syscall_event_t *>(data);

    std::cout << "[EVENT] PID=" << event->pid
              << " PPID=" << event->ppid
              << " UID=" << event->uid
              << " SYSCALL=" << event->syscall_id
              << " FILE=\"" << event->filename << "\""
              << std::endl;

    return 0;
}

int main() {
    int map_fd;

    // Attach SIGINT handler (Ctrl+C)
    signal(SIGINT, handle_signal);

    // Try to open the pinned BPF ring buffer map
    map_fd = bpf_obj_get("/sys/fs/bpf/syscall_events_map");
    if (map_fd < 0) {
        perror("Failed to open ringbuf map (/sys/fs/bpf/syscall_events_map)");
        return 1;
    }

    // Create a new ring buffer instance
    rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer" << std::endl;
        close(map_fd);
        return 1;
    }

    std::cout << "[*] Listening for syscall events... (Ctrl+C to stop)" << std::endl;

    // Event loop
    while (!stop) {
        int err = ring_buffer__poll(rb, 100 /* ms timeout */);
        if (err < 0) {
            std::cerr << "ring_buffer__poll() failed: " << err << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    close(map_fd);
    std::cout << "[*] Exiting ring buffer reader." << std::endl;
    return 0;
}
