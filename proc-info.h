#ifndef _PROC_INFO_H
#define _PROC_INFO_H

#include <stdint.h>
#include <unistd.h>

uint64_t get_elf_baseaddr(pid_t pid);
char *get_elf_name(pid_t pid);
int re_exec(const char *name, pid_t pid);

#endif
