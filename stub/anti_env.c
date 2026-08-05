#include "anti_env.h"
#include "string_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/system_properties.h>

// Global internal state flag. When set to non-zero, loader silently corrupts key/decryption.
volatile int g_state_corrupted = 0;

/* Root Detection: su binaries in standard system paths */
bool check_root_binaries(void) {
    const char *su_paths[] = {
        ENC_STR("/system/bin/su"),
        ENC_STR("/system/xbin/su"),
        ENC_STR("/sbin/su"),
        ENC_STR("/system/sd/xbin/su")
    };
    for (size_t i = 0; i < sizeof(su_paths)/sizeof(su_paths[0]); i++) {
        if (access(su_paths[i], F_OK) == 0) {
            return true;
        }
    }
    return false;
}

/* Root Detection: Magisk framework directories */
bool check_magisk_artifacts(void) {
    const char *magisk_paths[] = {
        ENC_STR("/sbin/.magisk"),
        ENC_STR("/data/adb/magisk"),
        ENC_STR("/data/adb/modules")
    };
    for (size_t i = 0; i < sizeof(magisk_paths)/sizeof(magisk_paths[0]); i++) {
        if (access(magisk_paths[i], F_OK) == 0) {
            return true;
        }
    }
    return false;
}

/* Root Detection: test-keys in ro.build.tags */
bool check_system_build_tags(void) {
    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get(ENC_STR("ro.build.tags"), value) > 0) {
        if (strstr(value, ENC_STR("test-keys"))) {
            return true;
        }
    }
    return false;
}

/* Root Detection: Writable /system partition check via /proc/mounts */
bool check_system_mounts(void) {
    FILE *fp = fopen(ENC_STR("/proc/mounts"), "r");
    if (!fp) return false;

    char line[512];
    bool rw_system = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, ENC_STR(" /system ")) && strstr(line, ENC_STR(" rw,"))) {
            rw_system = true;
            break;
        }
    }
    fclose(fp);
    return rw_system;
}

/* Emulator Detection: QEMU pipe device nodes */
bool check_emulator_qemu(void) {
    const char *qemu_devices[] = {
        ENC_STR("/dev/qemu_pipe"),
        ENC_STR("/dev/socket/qemud")
    };
    for (size_t i = 0; i < sizeof(qemu_devices)/sizeof(qemu_devices[0]); i++) {
        if (access(qemu_devices[i], F_OK) == 0) {
            return true;
        }
    }
    return false;
}

/* Emulator Detection: Product/hardware build properties */
bool check_emulator_props(void) {
    char model[PROP_VALUE_MAX] = {0};
    char hardware[PROP_VALUE_MAX] = {0};

    __system_property_get(ENC_STR("ro.product.model"), model);
    __system_property_get(ENC_STR("ro.hardware"), hardware);

    if (strstr(model, ENC_STR("sdk_gphone")) ||
        strstr(model, ENC_STR("generic")) ||
        strstr(hardware, ENC_STR("goldfish")) ||
        strstr(hardware, ENC_STR("ranchu"))) {
        return true;
    }
    return false;
}

/* Emulator Detection: CPU core count and hypervisor flags in /proc/cpuinfo */
bool check_cpu_hypervisor(void) {
    FILE *fp = fopen(ENC_STR("/proc/cpuinfo"), "r");
    if (!fp) return false;

    char line[256];
    bool found_hypervisor = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, ENC_STR("hypervisor")) || strstr(line, ENC_STR("QEMU"))) {
            found_hypervisor = true;
            break;
        }
    }
    fclose(fp);
    return found_hypervisor;
}

bool is_hostile_environment(void) {
    return check_root_binaries() ||
           check_magisk_artifacts() ||
           check_system_build_tags() ||
           check_system_mounts() ||
           check_emulator_qemu() ||
           check_emulator_props() ||
           check_cpu_hypervisor();
}

static void* anti_env_worker(void* arg) {
    (void)arg;
    while (1) {
        // Randomized interval between 2 and 6 seconds to resist sleep patching
        unsigned int delay = 2 + (rand() % 5);
        sleep(delay);

        if (is_hostile_environment()) {
            // Silently corrupt state flag rather than calling exit() or logging
            g_state_corrupted ^= 0xDEADBEEF;
        }
    }
    return NULL;
}

void start_anti_env_thread(void) {
    pthread_t t;
    pthread_create(&t, NULL, anti_env_worker, NULL);
    pthread_detach(t);
}
