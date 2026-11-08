/* dagr/owner.h — owner identity and liveness for the multi-producer SharedBuffer strategies
 * (spec/40 §3.2, §4.3; spec/44 §8.2): a lock word or a ring slot records WHICH process holds
 * it, and a waiter takes it over only once that process is gone — never on a timeout, which
 * would let a merely paused holder resume and write beside the new one.
 *
 * The owner word is BIT-IDENTICAL across languages (processes of different languages share
 * one lock): pid in the low 32 bits, the process's start token in the high 32 — a port of
 * the C++ target's dagr/owner.hpp. Linux and macOS (POSIX); the start token comes from
 * /proc/<pid>/stat where it exists (Linux) and is 0 elsewhere, as in every target.
 *
 * OS tier: it talks to the operating system (getpid, kill, /proc).
 */
#ifndef DAGR_OWNER_H
#define DAGR_OWNER_H

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "sb_core.h"

#if defined(__GLIBC__) && !defined(_POSIX_C_SOURCE)
#error "dagr/owner.h needs POSIX (kill, getpid): compile with -std=gnu11, or define _POSIX_C_SOURCE=200809L before any include"
#endif

/** The low 32 bits of a process's start time (Linux: /proc/<pid>/stat field 22, clock ticks
 * since boot), or-ed with 1 so that it is never 0; 0 where it is not available — liveness
 * then goes by pid alone, and a reused pid can delay a recovery but never cause a wrong one. */
static inline uint32_t dagr_owner_start_token(long pid) {
  char path[64];
  snprintf(path, sizeof path, "/proc/%ld/stat", pid);
  FILE *f = fopen(path, "r");
  if (f == NULL) return 0;
  char buf[1024];
  const size_t n = fread(buf, 1, sizeof buf - 1, f);
  fclose(f);
  buf[n] = '\0';
  const char *close = strrchr(buf, ')'); /* the command name may contain spaces */
  if (close == NULL) return 0;
  /* fields 3.. follow ") "; field 22 (starttime) is the 20th of them */
  const char *q = close + 1;
  for (int field = 0; field < 19; field++) {
    while (*q == ' ') q++;
    while (*q != ' ' && *q != '\0') q++;
    if (*q == '\0') return 0;
  }
  while (*q == ' ') q++;
  uint64_t v = 0;
  bool any = false;
  for (; *q >= '0' && *q <= '9'; q++) {
    v = v * 10 + (uint64_t)(*q - '0');
    any = true;
  }
  if (!any) return 0;
  return (uint32_t)v | 1u;
}

/** This process's identity: pid in the low 32 bits, its start token in the high 32. Never
 * zero (zero is "unowned"). Computed once per translation unit and cached; the cache is read
 * and written with relaxed atomics, so two threads computing it at once is a benign repeat,
 * not a data race. A fork()ed child must not inherit it: the cache is keyed on the pid. */
static inline uint64_t dagr_owner_self(void) {
  static uint64_t cached = 0;
  const long pid = (long)getpid();
  uint64_t self = __atomic_load_n(&cached, __ATOMIC_RELAXED);
  if (self == 0 || (uint32_t)self != (uint32_t)pid) {
    self = (uint64_t)(uint32_t)pid | ((uint64_t)dagr_owner_start_token(pid) << 32);
    __atomic_store_n(&cached, self, __ATOMIC_RELAXED);
  }
  return self;
}

/** Whether the process an owner word names still exists. A process always counts itself
 * alive (its threads cannot die without it), and any doubt answers "alive": a false "dead"
 * would let two writers run at once, a false "alive" only delays recovery. */
static inline bool dagr_owner_alive(uint64_t owner) {
  const long pid = (long)(uint32_t)owner;
  if (owner == 0 || pid == (long)getpid()) return true;
  if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) return false;
  /* the pid exists — the same process, or a later one that reused the pid? */
  const uint32_t token = (uint32_t)(owner >> 32);
  if (token != 0) {
    const uint32_t current = dagr_owner_start_token(pid);
    if (current != 0 && current != token) return false;
  }
  return true;
}

/** Gives the processor to another thread — what a spinning waiter does now and then. */
static inline void dagr_owner_yield(void) { sched_yield(); }

#endif /* DAGR_OWNER_H */
