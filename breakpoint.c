#include <sys/ptrace.h>
#include <sys/reg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "breakpoint.h"

int insert_breakpoint(bp_t **out, pid_t pid, uint64_t addr){
    long orig;
    int ret;

    orig = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if(errno){
        ret = 1;
        goto end;
    }

    if(ptrace(PTRACE_POKETEXT, pid, addr, (orig << 8)|0xcc) == -1){
        ret = 1;
        goto end;
    }

    while(*out){
        out = &((*out)->next);
    }

    *out = malloc(sizeof(bp_t));
    if(*out != NULL){
        (*out)->pid = pid;
        (*out)->addr = addr;
        (*out)->orig = orig;
        (*out)->next = NULL;
        ret = 0;
    }

    end:
    return ret;
}

int remove_breakpoint(bp_t **out, pid_t pid, uint64_t addr){
    bp_t *aux, *prev;
    int ret = 0;

    for(prev=NULL, aux=*out; aux; prev=aux, aux=aux->next){
        if(aux->pid == pid && aux->addr == addr){
            /* set instruction point to default address */
            ptrace(PTRACE_POKEUSER, pid, RIP*sizeof(long), addr);

            if(ptrace(PTRACE_POKETEXT, pid, addr, aux->orig) == -1){
                perror("ptrace_poketext");
            }

            if(!prev){
                *out = aux->next;
            } else {
                prev->next = aux->next;
            }

            free(aux);
            ret = 1;
            break;
        }
    }

    return ret;
}
