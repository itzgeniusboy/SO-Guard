#include "anti_debug.h"
#include "string_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern volatile int g_state_corrupted;

/* Parse /proc/self/status looking for TracerPid != 0 */
bool check_tracerpid(void) {
    FILE *fp = fopen(ENC_STR("/proc/self/status"), "r");
    if (!fp) return false;

    char line[256];
    bool traced = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, ENC_STR("TracerPid:"), 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) {
                traced = true;
            }
            break;
        }
    }
    fclose(fp);
    return traced;
}

/* Attempt ptrace(PTRACE_TRACEME) - if it fails, a debugger is already attached */
bool check_ptrace_self(void) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return true; // Already traced
    }
    return false;
}

/* Monitor execution latency via CLOCK_MONOTONIC to detect step-debugging */
bool check_timing(void) {
    struct timespec ts1, ts2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);

    volatile int count = 0;
    for (int i = 0; i < 10000; i++) {
        count += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts2);
    long diff_ns = (ts2.tv_sec - ts1.tv_sec) * 1000000000L + (ts2.tv_nsec - ts1.tv_nsec);

    if (diff_ns > 100000000L) {
        return true;
    }
    return false;
}

/* Scan for open JDWP debugger ports (8700, 8000, 23946, etc.) */
bool check_debugger_port(void) {
    int ports[] = {8700, 8000, 23946, 5037};
    int num_ports = sizeof(ports) / sizeof(ports[0]);

    for (int i = 0; i < num_ports; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        inet_pton(AF_INET, ENC_STR("127.0.0.1"), &addr.sin_addr);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000; // 50ms timeout
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            close(sock);
            return true; // Debugger listener active
        }
        close(sock);
    }
    return false;
}

static void* anti_debug_worker(void* arg) {
    (void)arg;
    while (1) {
        unsigned int delay = 1 + (rand() % 4);
        sleep(delay);

        if (check_tracerpid() || check_ptrace_self() || check_timing() || check_debugger_port()) {
            g_state_corrupted ^= 0xBADF00D;
        }
    }
    return NULL;
}

void start_anti_debug_thread(void) {
    pthread_t t;
    pthread_create(&t, NULL, anti_debug_worker, NULL);
    pthread_detach(t);
}
