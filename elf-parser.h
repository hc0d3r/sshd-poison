#ifndef _ELF_PARSER_H_
#define _ELF_PARSER_H_

#include <stddef.h>
#include <elf.h>

typedef struct {
	Elf64_Shdr *header;
	void *data;
	size_t len;
} section_t;

typedef struct {
	Elf64_Phdr *header;
	void *data;
	size_t len;
} segment_t;

typedef struct {
	Elf64_Ehdr *header;
	segment_t *segments;
	size_t nsegments;
	section_t *sections;
	size_t nsections;
	size_t nbytes;
} elf_t;

typedef struct {
	Elf64_Rela *rel;
	Elf64_Sym *sym;
} rela_t;

section_t *getsectionbyname(elf_t * elf, const char *name);
int getrelabyname(elf_t * elf, rela_t * rel, char *section_name,
		  const char *name);
Elf64_Sym *dynsym_name_lookup(elf_t * elf, const char *name);
void elf_parser(elf_t * elf, const char *filename);
void free_elf(elf_t * elf);

#endif
