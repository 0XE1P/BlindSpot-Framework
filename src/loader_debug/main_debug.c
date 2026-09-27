// src/loader_debug/main_debug.c
// Тест reflective loader'а с правильной диагностикой raw по PointerToRawData.

#include <windows.h>
#include <stdio.h>
#include "../loader/reflective.h"
#include "../common/types.h"

static BYTE* read_file(const char* path, DWORD* out_size) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }

    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) { CloseHandle(h); return NULL; }

    DWORD read = 0;
    if (!ReadFile(h, buf, size, &read, NULL) || read != size) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(h);
        return NULL;
    }

    CloseHandle(h);
    *out_size = size;
    return buf;
}

// RVA → file offset (правильно, через PointerToRawData)
static DWORD rva_to_file_offset(IMAGE_NT_HEADERS64_* nt, DWORD rva) {
    IMAGE_SECTION_HEADER_* sec = (IMAGE_SECTION_HEADER_*)
        ((BYTE*)nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER_)
         + nt->FileHeader.SizeOfOptionalHeader);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD va    = sec[i].VirtualAddress;
        DWORD vsize = sec[i].Misc.VirtualSize;
        if (rva >= va && rva < va + vsize) {
            return sec[i].PointerToRawData + (rva - va);
        }
    }
    return 0;
}

int main(void) {
    printf("=== BlindSpot Reflective Loader Test ===\n\n");
    fflush(stdout);

    // 1. Читаем payload с диска
    const char* payload_path = "build\\payload_test.exe";
    DWORD payload_size = 0;
    BYTE* payload_data = read_file(payload_path, &payload_size);

    if (!payload_data) {
        printf("[!] Failed to read payload: %s\n", payload_path);
        printf("\nPress Enter to exit...\n");
        getchar();
        return 1;
    }

    printf("[+] Payload loaded: %s\n", payload_path);
    printf("    Size: %lu bytes\n\n", payload_size);
    fflush(stdout);

    // === Разбор raw ===
    BYTE* raw = payload_data;
    IMAGE_DOS_HEADER_* dos = (IMAGE_DOS_HEADER_*)raw;
    IMAGE_NT_HEADERS64_* nt = (IMAGE_NT_HEADERS64_*)(raw + dos->e_lfanew);

    printf("[*] Raw DOS magic: 0x%04X\n", dos->e_magic);
    printf("[*] Raw NT signature: 0x%08X\n", nt->Signature);
    printf("[*] Raw entry point RVA: 0x%08X\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("[*] Raw preferred base: 0x%llX\n", (unsigned long long)nt->OptionalHeader.ImageBase);
    printf("[*] Raw size of image: 0x%X\n", nt->OptionalHeader.SizeOfImage);
    printf("[*] Raw size of headers: 0x%X\n\n", nt->OptionalHeader.SizeOfHeaders);

    // === Вывод всех секций ===
    printf("[*] Sections in RAW:\n");
    IMAGE_SECTION_HEADER_* secs = (IMAGE_SECTION_HEADER_*)
        ((BYTE*)nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER_)
         + nt->FileHeader.SizeOfOptionalHeader);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        for (int j = 0; j < 8 && secs[i].Name[j]; j++) name[j] = secs[i].Name[j];

        printf("    [%d] %-8s VA=0x%05X RawOff=0x%05X RawSize=0x%05X VirtSize=0x%05X\n",
               i, name,
               secs[i].VirtualAddress,
               secs[i].PointerToRawData,
               secs[i].SizeOfRawData,
               secs[i].Misc.VirtualSize);
    }
    printf("\n");
    fflush(stdout);

    // 2. Reflective load
    void* image_base = NULL;
    void* entry = reflective_load(payload_data, payload_size, 0, &image_base);

    if (!entry) {
        printf("[!] Reflective load FAILED\n");
        printf("\nPress Enter to exit...\n");
        getchar();
        return 2;
    }

    printf("[+] Reflective load OK\n");
    printf("    Image base: 0x%p\n", image_base);
    printf("    Entry point: 0x%p\n\n", entry);
    fflush(stdout);

    // === Сравнение байтов mapped vs raw (правильно!) ===
    unsigned char* e = (unsigned char*)entry;
    unsigned long long entry_rva = (unsigned long long)entry - (unsigned long long)image_base;
    DWORD entry_off = rva_to_file_offset(nt, (DWORD)entry_rva);

    printf("[*] Entry point RVA: 0x%llX\n", entry_rva);
    printf("[*] Entry point file offset: 0x%X\n", entry_off);

    printf("[*] First 16 bytes at entry in MAPPED memory:\n    ");
    for (int i = 0; i < 16; i++) printf("%02X ", e[i]);
    printf("\n");

    printf("[*] First 16 bytes at entry in RAW file (correct offset):\n    ");
    for (int i = 0; i < 16; i++) printf("%02X ", raw[entry_off + i]);
    printf("\n");

    int same = 1;
    for (int i = 0; i < 16; i++) {
        if (e[i] != raw[entry_off + i]) { same = 0; break; }
    }
    printf("[*] Match: %s\n\n", same ? "YES — MAPPING IS CORRECT" : "NO — MAPPING IS WRONG");
    fflush(stdout);

    printf("[*] Calling entry point...\n");
    fflush(stdout);

    // 3. Вызов entry point payload'а
    typedef void (__stdcall *pEntry)(void);
    pEntry payload_main = (pEntry)entry;
    payload_main();

    printf("\n[+] Payload returned normally.\n");
    printf("\nPress Enter to exit...\n");
    getchar();

    return 0;
}