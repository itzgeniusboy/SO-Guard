#include "anti_hook.h"
#include "string_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern volatile int g_state_corrupted;

/* Scan /proc/self/maps for Frida artifacts */
bool check_frida_files(void) {
    FILE *fp = fopen(ENC_STR("/proc/self/maps"), "r");
    if (!fp) return false;

    char line[512];
    bool detected = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, ENC_STR("frida-agent")) ||
            strstr(line, ENC_STR("frida-gadget")) ||
            strstr(line, ENC_STR("linjector"))) {
            detected = true;
            break;
        }
    }
    fclose(fp);
    return detected;
}

/* Connect to default Frida server (27042) and D-Bus (27043) ports */
bool check_frida_ports(void) {
    int ports[] = {27042, 27043};
    for (int i = 0; i < 2; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        inet_pton(AF_INET, ENC_STR("127.0.0.1"), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            close(sock);
            return true;
        }
        close(sock);
    }
    return false;
}

/* Detect anonymous executable mapping regions typical of dynamic hook trampolines */
bool check_maps_anomalies(void) {
    FILE *fp = fopen(ENC_STR("/proc/self/maps"), "r");
    if (!fp) return false;

    char line[512];
    bool anomaly = false;
    while (fgets(line, sizeof(line), fp)) {
        // Look for r-xp or rwxp regions not associated with a named file path
        if (strstr(line, "rwxp") || (strstr(line, "r-xp") && !strstr(line, "/"))) {
            // Suspicious anonymous executable memory segment
            anomaly = true;
            break;
        }
    }
    fclose(fp);
    return anomaly;
}

/* Scan /proc/self/task/*/comm for Frida stealth thread names (gum-js-loop, gmain, gdbus) */
bool check_frida_threads(void) {
    DIR *dir = opendir(ENC_STR("/proc/self/task"));
    if (!dir) return false;

    struct dirent *entry;
    bool found_frida_thread = false;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char comm_path[256];
        snprintf(comm_path, sizeof(comm_path), ENC_STR("/proc/self/task/%s/comm"), entry->d_name);

        FILE *fp = fopen(comm_path, "r");
        if (fp) {
            char comm[64] = {0};
            if (fgets(comm, sizeof(comm), fp)) {
                if (strstr(comm, ENC_STR("gum-js-loop")) ||
                    strstr(comm, ENC_STR("gmain")) ||
                    strstr(comm, ENC_STR("gdbus"))) {
                    found_frida_thread = true;
                    fclose(fp);
                    break;
                }
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return found_frida_thread;
}

/* Use inotify to monitor late modifications/injections in /proc/self/maps & status */
bool check_inotify_maps_status(void) {
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) return false;

    int wd1 = inotify_add_watch(fd, ENC_STR("/proc/self/maps"), IN_MODIFY | IN_ACCESS);
    int wd2 = inotify_add_watch(fd, ENC_STR("/proc/self/status"), IN_MODIFY | IN_ACCESS);

    char buffer[1024];
    ssize_t len = read(fd, buffer, sizeof(buffer));

    if (wd1 >= 0) inotify_rm_watch(fd, wd1);
    if (wd2 >= 0) inotify_rm_watch(fd, wd2);
    close(fd);

    return (len > 0);
}

/* Stub marker for Xposed/LSPosed Java bridge checks */
bool check_xposed(void) {
    return false;
}

static void* anti_hook_worker(void* arg) {
    (void)arg;
    while (1) {
        unsigned int delay = 2 + (rand() % 4);
        sleep(delay);

        if (check_frida_files() || check_frida_ports() || check_maps_anomalies() || check_frida_threads() || check_inotify_maps_status()) {
            g_state_corrupted ^= 0xCAFEBABE;
        }
    }
    return NULL;
}

void start_anti_hook_thread(void) {
    pthread_t t;
    pthread_create(&t, NULL, anti_hook_worker, NULL);
    pthread_detach(t);
}
