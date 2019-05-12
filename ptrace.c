#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <stdio.h>

#include "ptrace.h"

int ptrace_seize(pid_t pid, unsigned long opts){
    if(ptrace(PTRACE_SEIZE, pid, NULL, opts) == 0 &&
        ptrace(PTRACE_INTERRUPT) == 0){
        return 0;
    }

    else {
        return 1;
    }
}

unsigned long getip(pid_t pid){
    return ptrace(PTRACE_PEEKUSER, pid, RIP*sizeof(long), 0);
}

const char *ptrace_stropt(int opt){
    const char *ret;
    static char buf[64];

    switch(opt){
        case PTRACE_CONT:
            ret = "PTRACE_CONT";
            break;
        case PTRACE_DETACH:
            ret = "PTRACE_DETACH";
            break;
        case PTRACE_LISTEN:
            ret = "PTRACE_LISTEN";
            break;
        default:
            sprintf(buf, "/*PTRACE_%d*/", opt);
            ret = buf;
    }

    return ret;
}

int status_info(int *opt, int *sig, int *event, int status){
    int ret = 1;

    if(WIFSTOPPED(status)){
        *sig = WSTOPSIG(status);
    }

    else if(WIFSIGNALED(status)){
        goto end;
    }

    else if(WIFEXITED(status)){
        goto end;
    }

    else {
        *sig = 0;
    }

    *event = status >> 16;
    *opt = PTRACE_CONT;

    switch(*event){
        case PTRACE_EVENT_FORK:
            if(*sig == SIGTRAP)
                *sig = 0;
        break;

        case PTRACE_EVENT_EXEC:
            if(*sig == SIGTRAP)
                *sig = 0;
        break;

        case PTRACE_EVENT_STOP:
            switch(*sig){
                case SIGSTOP:
                case SIGTSTP:
                case SIGTTIN:
                case SIGTTOU:
                    *opt = PTRACE_LISTEN;
                break;

                /* signal suppression */
                default:
                    *sig = 0;
            }
        break;
    }

    ret = 0;

    end:
    return ret;
}
