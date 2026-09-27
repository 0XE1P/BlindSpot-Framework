// src/common/memory.h
#ifndef BLINDSPOT_MEMORY_H
#define BLINDSPOT_MEMORY_H

#include "types.h"

void*  bs_memcpy(void* dst, const void* src, size_t_ n);
void*  bs_memset(void* dst, int c, size_t_ n);
int    bs_memcmp(const void* a, const void* b, size_t_ n);

#endif