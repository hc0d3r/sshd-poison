#ifndef __SSH_SERVER_H__
#define __SSH_SERVER_H__

#include <unistd.h>

char *create_hostkey(void);
pid_t exec_ssh_server(const char *output, const char *file, char * const argv[]);

#endif
