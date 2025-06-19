#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct event {
    __u64 latency_ns;
    __u8 direction;
};

static volatile int exiting = 0;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("%s latency: %llu ns\n",
        e->direction == 0 ? "Ingress" : "Egress",
        e->latency_ns);
    return 0;
}

static void handle_signal(int sig) {
    exiting = 1;
}

int main() {
    struct ring_buffer *rb = NULL;
    int map_fd;

    map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/events");
    if (map_fd < 0) {
        perror("bpf_obj_get failed");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    signal(SIGINT, handle_signal);

    while (!exiting) {
        int err = ring_buffer__poll(rb, 100 /* ms timeout */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    return 0;
}
