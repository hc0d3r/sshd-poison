#include "memutils.h"
#include <ignotum.h>
#include <stdlib.h>
#include <string.h>

uint64_t get_base_address(pid_t pid, const char *name, int wildcard)
{
	uint64_t base_addr;
	ignotum_mapinfo_t map;

	if (ignotum_getbasemap(&map, pid, name, wildcard)) {
		base_addr = 0;
	} else {
		base_addr = map.start_addr;

		if (map.pathname)
			free(map.pathname);
	}


	return base_addr;
}

uint64_t get_pid_entry_point(elf_t *elf, pid_t pid)
{
	uint64_t entry_point;

	entry_point = elf->header->e_entry;

	if (elf->header->e_type == ET_DYN)
		entry_point += get_base_address(pid, "*", 1);


	return entry_point;
}

void *memory_dump(pid_t pid, uint64_t start, uint64_t end)
{
	void *dump;
	size_t len;
	ssize_t n;

	len = end - start;

	dump = malloc(len);
	if (dump == NULL) {
		return NULL;
	}

	n = ignotum_mem_read(pid, dump, len, start);
	if ((size_t)n != len) {
		free(dump);
		dump = NULL;
	}

	return dump;
}
