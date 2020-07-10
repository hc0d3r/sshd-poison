#ifndef __AUTHPASSWORD_SCAN_H__
#define __AUTHPASSWORD_SCAN_H__

#include <unistd.h>
#include <stdint.h>
#include <ignotum.h>

uint64_t memsearch_montable(const char *mem, uint64_t start, uint64_t end, size_t len);
uint64_t memmem_mon_table(pid_t pid, ignotum_maplist_t *maplist, uint64_t start, uint64_t end);
uint64_t get_mm_answer_authpassword(const char *sshd, pid_t pid);

#endif
