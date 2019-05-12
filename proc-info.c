#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "proc-info.h"

static char *xreadlink(const char *link);

int re_exec(const char *name, pid_t pid){
    char *buf, exe[32];
    size_t len;
    int ret;

    len = strlen(name);
    buf = malloc(len+1);
    if(buf == NULL){
        perror("re_exec() malloc()");
        exit(1);
    }

    sprintf(exe, "/proc/%d/exe", pid);

    if((size_t)readlink(exe, buf, len) != len){
        ret = 0;
        goto end;
    }

    ret = (memcmp(buf, name, len) == 0);

    end:
    free(buf);
    return ret;
}

uint64_t get_elf_baseaddr(pid_t pid){
    char buf[64];
    int fd;

    sprintf(buf, "/proc/%d/maps", pid);

    fd = open(buf, O_RDONLY);
    if(fd == -1){
        perror("get_elf_baseaddr(), open()");
        exit(1);
    }

    if(read(fd, buf, 16) != 16){
        perror("get_elf_baseaddr(), read()");
        exit(1);
    }

    close(fd);

    return (uint64_t)strtol(buf, NULL, 16);
}

char *get_elf_name(pid_t pid){
    char buf[32];
    sprintf(buf, "/proc/%d/exe", pid);

    return xreadlink(buf);
}

static char *xreadlink(const char *link){
    char *ret = NULL, *aux;

    ssize_t nread;
    size_t len = 16;

    while(1){
        aux = realloc(ret, len);
        if(aux == NULL){
            free(ret);
            ret = NULL;
            break;
        }

        ret = aux;

        if((nread = readlink(link, ret, len)) == -1){
            free(ret);
            ret = NULL;
            break;
        }

        if((size_t)nread < len){
            /* try dealloc unused space */
            aux = realloc(ret, nread+1);
            if(aux != NULL){
                ret = aux;
            }

            ret[nread] = 0x0;
            break;
        }

        len *= 2;
    }

    return ret;
}
