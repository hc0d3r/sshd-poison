#ifndef _PTRACE_UTILS_H
#define _PTRACE_UTILS_H

#include <sys/ptrace.h>
#include <unistd.h>

#define TRACE_OPTS  PTRACE_O_TRACEEXEC|PTRACE_O_TRACEFORK

int ptrace_seize(pid_t pid, unsigned long opts);
const char *ptrace_stropt(int opt);
unsigned long getip(pid_t pid);

int status_info(int *opt, int *sig, int *event, int status);


#endif
