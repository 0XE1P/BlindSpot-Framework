// src/common/memory.c
// Свои memcpy/memset, чтобы не тащить CRT.
// С флагом -fno-builtin компилятор не превратит циклы в вызовы CRT.

#include "memory.h"

void* bs_memcpy(void* dst, const void* src, size_t_ n) {
    u8* d = (u8*)dst;
    const u8* s = (const u8*)src;
    while (n--) *d++ = *s++;
    return dst;
}

void* bs_memset(void* dst, int c, size_t_ n) {
    u8* d = (u8*)dst;
    while (n--) *d++ = (u8)c;
    return dst;
}

int bs_memcmp(const void* a, const void* b, size_t_ n) {
    const u8* pa = (const u8*)a;
    const u8* pb = (const u8*)b;
    while (n--) {
        if (*pa != *pb) return (int)(*pa - *pb);
        pa++; pb++;
    }
    return 0;
}