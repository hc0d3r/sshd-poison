#include "breakpoint.h"
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <ignotum.h>

int enable_breakpoint(struct breakpoint *bp, pid_t pid, uint64_t addr)
{
	bp->address = addr;
	return (ignotum_mem_read(pid, &bp->bkp, 1, addr) != 1 ||
		ignotum_mem_write(pid, "\xcc", 1, addr) != 1);
}

int disable_breakpoint(struct breakpoint *bp, pid_t pid)
{
	return (ignotum_mem_write(pid, &bp->bkp, 1, bp->address) != 1 ||
		ptrace(PTRACE_POKEUSER, pid, RIP * 8, bp->address) == -1);
}

int breakpoint_hit(struct breakpoint *bp, pid_t pid)
{
	return (bp->address == ptrace(PTRACE_PEEKUSER, pid, RIP * 8, NULL) - 1);
}
