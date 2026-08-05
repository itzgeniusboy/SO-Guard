#ifndef ANTI_HOOK_H
#define ANTI_HOOK_H

#include <stdbool.h>

bool check_frida_files(void);
bool check_frida_ports(void);
bool check_maps_anomalies(void);
bool check_xposed(void);
bool check_frida_threads(void);
bool check_inotify_maps_status(void);

void start_anti_hook_thread(void);

#endif // ANTI_HOOK_H
