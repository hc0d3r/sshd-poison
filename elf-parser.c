#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <elf.h>

#include "elf-parser.h"

#define sanitize(x, y) do { \
	if (x < y) { \
		fprintf(stderr, "error: %zu avaliable %zu required\n", x, y); \
		exit(1); \
	} \
} while(0)

void *mapfile(const char *filename, size_t *len)
{
	void *ret = MAP_FAILED;
	struct stat st;
	int fd;

	if ((fd = open(filename, O_RDONLY)) == -1)
		goto end;

	if (fstat(fd, &st) == -1)
		goto end;

	ret = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	*len = (size_t)st.st_size;

 end:
	if (fd != -1)
		close(fd);

	return ret;
}

section_t *getsectionbyname(elf_t * elf, const char *name)
{
	section_t *ret = NULL;
	char *strings;
	size_t len;

	uint32_t sh_name;
	uint16_t shstrndx;
	size_t i, slen;

	/* get section string index */
	shstrndx = elf->header->e_shstrndx;
	if (shstrndx == SHN_UNDEF || shstrndx >= elf->nsections) {
		goto end;
	}

	strings = elf->sections[shstrndx].data;
	len = elf->sections[shstrndx].len;

	slen = strlen(name) + 1;

	for (i = 0; i < elf->nsections; i++) {
		sh_name = elf->sections[i].header->sh_name;
		if (sh_name == 0)
			continue;

		if (sh_name >= len || len - sh_name < slen)
			continue;

		if (memcmp(strings + sh_name, name, slen) == 0x0) {
			ret = elf->sections + i;
			break;
		}
	}

 end:
	return ret;
}

int getrelabyname(elf_t * elf, rela_t * rel, char *section_name,
		  const char *name)
{
	section_t *dynstr, *dynsym, *sec;
	Elf64_Sym *symbols;
	Elf64_Rela *rela;
	size_t i, j;

	int ret = 1;

	rel->rel = NULL;
	rel->sym = NULL;

	if ((sec = getsectionbyname(elf, section_name)) == NULL)
		goto end;

	dynstr = getsectionbyname(elf, ".dynstr");
	if (dynstr == NULL)
		goto end;

	dynsym = getsectionbyname(elf, ".dynsym");
	if (dynsym == NULL)
		goto end;

	rela = sec->data;
	symbols = dynsym->data;

	size_t nsym = dynsym->len / sizeof(Elf64_Sym);
	size_t nplt = sec->len / sizeof(Elf64_Rela);

	size_t slen = strlen(name) + 1;

	for (i = 0; i < nplt; i++) {
		j = ELF64_R_SYM(rela[i].r_info);

		/* check overflow */
		if (j >= nsym)
			continue;

		if (symbols[j].st_name == 0)
			continue;

		if (symbols[j].st_name >= dynstr->len ||
		    dynstr->len - symbols[j].st_name < slen) {
			continue;
		}

		if (memcmp(dynstr->data + symbols[j].st_name, name, slen) ==
		    0x0) {
			rel->rel = rela + i;
			rel->sym = symbols + j;
			ret = 0;
			break;
		}
	}

 end:
	return ret;
}

Elf64_Sym *dynsym_name_lookup(elf_t * elf, const char *name)
{
	section_t *strtab, *symtab;
	Elf64_Sym *ret = NULL, *symbols;

	size_t slen, i;

	strtab = getsectionbyname(elf, ".dynstr");
	symtab = getsectionbyname(elf, ".dynsym");

	if (!strtab || !symtab) {
		goto end;
	}

	slen = strlen(name) + 1;

	symbols = symtab->data;
	for (i = 0; i < symtab->len / sizeof(Elf64_Sym); i++) {
		if (symbols[i].st_name == 0)
			continue;

		if (symbols[i].st_name >= strtab->len ||
		    strtab->len - symbols[i].st_name < slen) {
			continue;
		}

		if (memcmp(strtab->data + symbols[i].st_name, name, slen) ==
		    0x0) {
			ret = symbols + i;
			break;
		}
	}

 end:
	return ret;
}

void elf_parser(elf_t * elf, const char *filename)
{
	Elf64_Ehdr *header;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	void *ptr;
	size_t i, len;

	memset(elf, 0x0, sizeof(elf_t));

	ptr = mapfile(filename, &len);
	if (ptr == MAP_FAILED) {
		perror("map_file() failed");
		exit(1);
	}

	/* sanity check */
	sanitize(len, sizeof(Elf64_Ehdr));

	elf->nbytes = len;
	elf->header = header = ptr;

	elf->nsegments = header->e_phnum;
	if (elf->nsegments) {
		elf->segments = malloc(elf->nsegments * sizeof(segment_t));
		if (elf->segments == NULL) {
			perror("malloc()");
			exit(1);
		}
	}

	for (i = 0; i < header->e_phnum; i++) {
		/* +1 for ensure that contains the size for the element */
		sanitize(len, header->e_phoff + sizeof(Elf64_Phdr) * (i + 1));

		phdr = ptr + header->e_phoff + sizeof(Elf64_Phdr) * i;

		sanitize(len, phdr->p_offset + phdr->p_filesz);

		elf->segments[i].header = phdr;
		elf->segments[i].len = phdr->p_filesz;
		elf->segments[i].data =
		    (phdr->p_filesz) ? ptr + phdr->p_offset : NULL;
	}

	elf->nsections = header->e_shnum;
	if (elf->nsections) {
		elf->sections = malloc(elf->nsections * sizeof(section_t));
		if (elf->sections == NULL) {
			perror("malloc()");
			exit(1);
		}
	}

	for (i = 0; i < header->e_shnum; i++) {
		sanitize(len, header->e_shoff + sizeof(Elf64_Shdr) * (i + 1));

		shdr = ptr + header->e_shoff + sizeof(Elf64_Shdr) * i;

		if (shdr->sh_type == SHT_NOBITS) {
			elf->sections[i].data = NULL;
			elf->sections[i].len = 0;
		} else {
			sanitize(len, shdr->sh_offset + shdr->sh_size);
			elf->sections[i].data = ptr + shdr->sh_offset;
			elf->sections[i].len = shdr->sh_size;
		}

		elf->sections[i].header = shdr;
	}
}

void free_elf(elf_t * elf)
{
	free(elf->segments);
	free(elf->sections);
	munmap(elf->header, elf->nbytes);
}
