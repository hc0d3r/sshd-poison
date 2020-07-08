#ifndef __CAVES_H__
#define __CAVES_H__

#include "elf-parser.h"
#include <stdint.h>

uint64_t xcave(uint64_t *len, elf_t *elf);

#endif
