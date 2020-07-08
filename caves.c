#include "caves.h"

/* find the biggest code cave with execution permission */
uint64_t xcave(uint64_t *len, elf_t *elf)
{
	uint64_t ret, aligned_addr;

	Elf64_Phdr *phdr;
	size_t i;

	*len = ret = 0;

	for (i = 0; i < elf->nsegments; i++) {
		phdr = elf->segments[i].header;

		if (!(phdr->p_flags & PF_X))
			continue;

		aligned_addr = (phdr->p_filesz + phdr->p_align) & -phdr->p_align;
		aligned_addr -= phdr->p_filesz;

		if (aligned_addr > *len) {
			*len = aligned_addr;
			ret = phdr->p_filesz + phdr->p_offset;
		}
	}

	return ret;
}
