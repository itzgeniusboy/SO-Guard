#include "anti_hook.h"
#include "string_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

/* Stub marker for Xposed/LSPosed Java bridge checks */
bool check_xposed(void) {
    // If running inside JVM context via JNI, would call FindClass("de.robv.android.xposed.XposedBridge")
    return false;
}

static void* anti_hook_worker(void* arg) {
    (void)arg;
    while (1) {
        sleep(3);
        if (check_frida_files() || check_frida_ports() || check_maps_anomalies()) {
            exit(0);
        }
    }
    return NULL;
}

void start_anti_hook_thread(void) {
    pthread_t t;
    pthread_create(&t, NULL, anti_hook_worker, NULL);
    pthread_detach(t);
}
