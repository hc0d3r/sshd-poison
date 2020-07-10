#ifndef __PTRACE_CB_LOOP_H__
#define __PTRACE_CB_LOOP_H__

#include <unistd.h>

struct ptrace_info {
	pid_t pid;
	int status;
	int wait;
	void *aux;
	long op;
	long signal;
};

typedef int (*ptrace_cb)(struct ptrace_info *info);

int ptrace_start(struct ptrace_info *info, pid_t pid, int opts);
int ptrace_loop(struct ptrace_info *info, ptrace_cb cb);


#endif
