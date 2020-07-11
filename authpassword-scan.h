#ifndef __AUTHPASSWORD_SCAN_H__
#define __AUTHPASSWORD_SCAN_H__

#include <unistd.h>
#include <stdint.h>
#include <ignotum.h>

uint64_t get_mm_answer_authpassword(pid_t pid, const char *sshd);

#endif
