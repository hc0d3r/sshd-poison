#include "caves.h"

uint64_t xcave(elf_t *elf, unsigned int len){
     uint64_t ret = 0, aux;

     Elf64_Phdr *phdr;
     size_t i;

     for(i=0; i<elf->nsegments; i++){
         phdr = elf->segments[i].header;
         if(!(phdr->p_flags & PF_X))
             continue;

        aux = (phdr->p_filesz+phdr->p_align) & 0xfffffffffffff000L;
        if((aux - phdr->p_filesz) >= len){
            ret = phdr->p_filesz+phdr->p_offset;
            break;
        }
    }

    return ret;
}
