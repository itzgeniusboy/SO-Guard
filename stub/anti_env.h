#ifndef ANTI_ENV_H
#define ANTI_ENV_H

#include <stdbool.h>

bool check_root_binaries(void);
bool check_magisk_artifacts(void);
bool check_system_build_tags(void);
bool check_system_mounts(void);

bool check_emulator_qemu(void);
bool check_emulator_props(void);
bool check_cpu_hypervisor(void);

bool is_hostile_environment(void);
void start_anti_env_thread(void);

#endif // ANTI_ENV_H
