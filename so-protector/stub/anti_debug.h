#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <stdbool.h>

bool check_tracerpid(void);
bool check_ptrace_self(void);
bool check_timing(void);
bool check_debugger_port(void);

void start_anti_debug_thread(void);

#endif // ANTI_DEBUG_H
