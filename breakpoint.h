#ifndef _BREAKPOINT_H
#define _BREAKPOINT_H

#include <stdint.h>

typedef struct bp {
    pid_t pid;
    uint64_t addr;
    long orig;
    struct bp *next;
} bp_t;

int insert_breakpoint(bp_t **out, pid_t pid, uint64_t addr);
int remove_breakpoint(bp_t **out, pid_t pid, uint64_t addr);

#endif
