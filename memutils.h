#ifndef __MEMORY_UTILS_H__
#define __MEMORY_UTILS_H__

#include <unistd.h>
#include <stdint.h>

#include "elf-parser.h"

uint64_t get_base_address(pid_t pid, const char *name, int wildcard);
uint64_t get_pid_entry_point(elf_t *elf, pid_t pid);
void *memory_dump(pid_t pid, uint64_t start, uint64_t end);

#endif
