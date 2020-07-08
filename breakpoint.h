#ifndef __BREAKPOINT_H__
#define __BREAKPOINT_H__

#include <stdint.h>
#include <unistd.h>

struct breakpoint {
	long address;
	long bkp;
};

int enable_breakpoint(struct breakpoint *bp, pid_t pid, uint64_t addr);
int disable_breakpoint(struct breakpoint *bp, pid_t pid);
int breakpoint_hit(struct breakpoint *bp, pid_t pid);

#endif
