// src/loader/pe_parser.c
#include "pe_parser.h"
#include "../common/memory.h"

// ------------------------------------------------------------
// Валидация PE
// ------------------------------------------------------------
BOOL_ pe_is_valid(void* raw_pe) {
    if (!raw_pe) return FALSE_;

    IMAGE_DOS_HEADER_* dos = (IMAGE_DOS_HEADER_*)raw_pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE_;

    // e_lfanew должно быть разумным (не 0, не за пределами)
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) return FALSE_;

    IMAGE_NT_HEADERS64_* nt = (IMAGE_NT_HEADERS64_*)((u8*)raw_pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE_;

    // Только x64
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return FALSE_;

    // Только PE32+
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return FALSE_;

    return TRUE_;
}

// ------------------------------------------------------------
// Парсинг PE
// ------------------------------------------------------------
BOOL_ pe_parse(void* raw_pe, pe_info_t* out) {
    if (!raw_pe || !out) return FALSE_;
    if (!pe_is_valid(raw_pe)) return FALSE_;

    bs_memset(out, 0, sizeof(pe_info_t));

    out->base = raw_pe;
    out->dos  = (IMAGE_DOS_HEADER_*)raw_pe;
    out->nt   = (IMAGE_NT_HEADERS64_*)((u8*)raw_pe + out->dos->e_lfanew);

    // Секции идут сразу после NT headers
    u8* after_nt = (u8*)out->nt
                 + sizeof(u32)                      // Signature
                 + sizeof(IMAGE_FILE_HEADER_)
                 + out->nt->FileHeader.SizeOfOptionalHeader;

    out->sections = (IMAGE_SECTION_HEADER_*)after_nt;

    out->num_sections    = out->nt->FileHeader.NumberOfSections;
    out->preferred_base  = out->nt->OptionalHeader.ImageBase;
    out->size_of_image   = out->nt->OptionalHeader.SizeOfImage;
    out->size_of_headers = out->nt->OptionalHeader.SizeOfHeaders;
    out->entry_point_rva = out->nt->OptionalHeader.AddressOfEntryPoint;

    return TRUE_;
}

// ------------------------------------------------------------
// RVA → указатель (когда PE уже развёрнут в памяти)
// ------------------------------------------------------------
void* pe_rva_to_ptr(pe_info_t* pe, u32 rva) {
    if (!pe || !pe->base) return NULL_;
    return (void*)((u8*)pe->base + rva);
}

// ------------------------------------------------------------
// DataDirectory
// ------------------------------------------------------------
IMAGE_DATA_DIRECTORY_* pe_get_directory(pe_info_t* pe, u32 index) {
    if (!pe || !pe->nt) return NULL_;
    if (index >= pe->nt->OptionalHeader.NumberOfRvaAndSizes) return NULL_;
    return &pe->nt->OptionalHeader.DataDirectory[index];
}

// ------------------------------------------------------------
// Секции
// ------------------------------------------------------------
IMAGE_SECTION_HEADER_* pe_first_section(pe_info_t* pe) {
    if (!pe) return NULL_;
    return pe->sections;
}

IMAGE_SECTION_HEADER_* pe_section_at(pe_info_t* pe, u32 index) {
    if (!pe || index >= pe->num_sections) return NULL_;
    return &pe->sections[index];
}

