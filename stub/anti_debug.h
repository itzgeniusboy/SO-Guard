#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <stdbool.h>

/**
 * Parse /proc/self/status looking for TracerPid != 0.
 */
bool check_tracerpid(void);

/**
 * Attempt ptrace(PTRACE_TRACEME) - if it fails, a debugger is attached.
 */
bool check_ptrace_self(void);

/**
 * Monitor execution latency via CLOCK_MONOTONIC to detect step-debugging.
 */
bool check_timing(void);

/**
 * Scan for open JDWP/debugger ports.
 */
bool check_debugger_port(void);

/**
 * Spawn anti-debugging thread.
 */
void start_anti_debug_thread(void);

#endif // ANTI_DEBUG_H
