#include "ptrace-loop.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>

int ptrace_start(struct ptrace_info *info, pid_t pid, int opts)
{
	if ((waitpid(pid, &info->status, 0) == -1) ||
		ptrace(PTRACE_SETOPTIONS, pid, 0, opts) ||
		ptrace(PTRACE_CONT, pid, 0, 0))
		return 1;

	info->wait = 1;
	info->op = PTRACE_CONT;
	info->pid = pid;
	info->signal = 0;

	return 0;
}

int ptrace_loop(struct ptrace_info *info, ptrace_cb cb)
{
	while (1) {
		if (info->wait) {
			if (waitpid(info->pid, &info->status, 0) == -1)
				return 1;

			info->wait = 0;

			if (cb(info))
				break;
		}

		else {
			if (ptrace(info->op, info->pid, 0, info->signal))
				return 1;

			info->wait = 1;
		}
	}

	return 0;
}
