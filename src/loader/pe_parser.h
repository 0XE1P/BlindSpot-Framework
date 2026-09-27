// src/loader/pe_parser.h
// Парсер PE — без CRT, без Windows SDK.
#ifndef BLINDSPOT_PE_PARSER_H
#define BLINDSPOT_PE_PARSER_H

#include "../common/types.h"

// Распарсенные указатели на части PE, лежащего в памяти.
typedef struct {
    void*                   base;               // указатель на сырой PE
    IMAGE_DOS_HEADER_*      dos;                // DOS заголовок
    IMAGE_NT_HEADERS64_*    nt;                 // NT заголовки
    IMAGE_SECTION_HEADER_*  sections;           // массив секций
    u16                     num_sections;
    u64                     preferred_base;     // ImageBase из OptionalHeader
    u32                     size_of_image;
    u32                     size_of_headers;
    u32                     entry_point_rva;
} pe_info_t;

// Проверка валидности PE.
BOOL_ pe_is_valid(void* raw_pe);

// Парсинг PE. Заполняет pe_info_t. Возвращает TRUE_ при успехе.
BOOL_ pe_parse(void* raw_pe, pe_info_t* out);

// RVA → указатель (для случая, когда PE уже смаплен по своим адресам)
void* pe_rva_to_ptr(pe_info_t* pe, u32 rva);

// Получить DataDirectory по индексу
IMAGE_DATA_DIRECTORY_* pe_get_directory(pe_info_t* pe, u32 index);

// Получить указатель на первую секцию
IMAGE_SECTION_HEADER_* pe_first_section(pe_info_t* pe);

// Получить указатель на секцию по индексу
IMAGE_SECTION_HEADER_* pe_section_at(pe_info_t* pe, u32 index);

#endif