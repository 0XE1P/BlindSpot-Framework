// src/common/types.h
// BlindSpot — базовые типы, PE-структуры, PEB.
// Компилируется без CRT, без Windows SDK.

#ifndef BLINDSPOT_TYPES_H
#define BLINDSPOT_TYPES_H

// ============================================================
// БАЗОВЫЕ ТИПЫ
// ============================================================

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;

typedef signed char         i8;
typedef signed short        i16;
typedef signed int          i32;
typedef signed long long    i64;

typedef u64                 size_t_;
typedef u64                 uintptr_t_;

// Windows-специфичные
typedef void*               HANDLE_;
typedef void*               HMODULE_;
typedef unsigned long       DWORD_;
typedef int                 BOOL_;
typedef unsigned short      WORD_;
typedef const char*         LPCSTR_;
typedef char*               LPSTR_;
typedef void*               LPVOID_;
typedef u64                 SIZE_T_;

#define TRUE_   1
#define FALSE_  0
#define NULL_   ((void*)0)

// ============================================================
// PE-КОНСТАНТЫ
// ============================================================

#define IMAGE_DOS_SIGNATURE             0x5A4D      // "MZ"
#define IMAGE_NT_SIGNATURE              0x00004550  // "PE\0\0"
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC   0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x20b

#define IMAGE_FILE_MACHINE_I386         0x014c
#define IMAGE_FILE_MACHINE_AMD64        0x8664

#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_TLS       9

#define IMAGE_REL_BASED_ABSOLUTE        0
#define IMAGE_REL_BASED_HIGHLOW         3
#define IMAGE_REL_BASED_DIR64           10

// ============================================================
// ВИРТУАЛЬНАЯ ПАМЯТЬ (константы)
// ============================================================

#define MEM_COMMIT_             0x1000
#define MEM_RESERVE_            0x2000
#define MEM_RELEASE_            0x8000

#define PAGE_NOACCESS_          0x01
#define PAGE_READONLY_          0x02
#define PAGE_READWRITE_         0x04
#define PAGE_EXECUTE_          0x10
#define PAGE_EXECUTE_READ_      0x20
#define PAGE_EXECUTE_READWRITE_ 0x40

// ============================================================
// PE-СТРУКТУРЫ
// ============================================================

// --- DOS Header ---
typedef struct {
    u16 e_magic;        // "MZ"
    u16 e_cblp;
    u16 e_cp;
    u16 e_crlc;
    u16 e_cparhdr;
    u16 e_minalloc;
    u16 e_maxalloc;
    u16 e_ss;
    u16 e_sp;
    u16 e_csum;
    u16 e_ip;
    u16 e_cs;
    u16 e_lfarlc;
    u16 e_ovno;
    u16 e_res[4];
    u16 e_oemid;
    u16 e_oeminfo;
    u16 e_res2[10];
    i32 e_lfanew;       // смещение до NT Headers
} IMAGE_DOS_HEADER_;

// --- File Header ---
typedef struct {
    u16 Machine;
    u16 NumberOfSections;
    u32 TimeDateStamp;
    u32 PointerToSymbolTable;
    u32 NumberOfSymbols;
    u16 SizeOfOptionalHeader;
    u16 Characteristics;
} IMAGE_FILE_HEADER_;

// --- Data Directory ---
typedef struct {
    u32 VirtualAddress;
    u32 Size;
} IMAGE_DATA_DIRECTORY_;

// --- Optional Header (только x64) ---
typedef struct {
    u16 Magic;
    u8  MajorLinkerVersion;
    u8  MinorLinkerVersion;
    u32 SizeOfCode;
    u32 SizeOfInitializedData;
    u32 SizeOfUninitializedData;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u64 ImageBase;
    u32 SectionAlignment;
    u32 FileAlignment;
    u16 MajorOperatingSystemVersion;
    u16 MinorOperatingSystemVersion;
    u16 MajorImageVersion;
    u16 MinorImageVersion;
    u16 MajorSubsystemVersion;
    u16 MinorSubsystemVersion;
    u32 Win32VersionValue;
    u32 SizeOfImage;
    u32 SizeOfHeaders;
    u32 CheckSum;
    u16 Subsystem;
    u16 DllCharacteristics;
    u64 SizeOfStackReserve;
    u64 SizeOfStackCommit;
    u64 SizeOfHeapReserve;
    u64 SizeOfHeapCommit;
    u32 LoaderFlags;
    u32 NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_ DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64_;

// --- NT Headers ---
typedef struct {
    u32 Signature;
    IMAGE_FILE_HEADER_ FileHeader;
    IMAGE_OPTIONAL_HEADER64_ OptionalHeader;
} IMAGE_NT_HEADERS64_;

// --- Section Header ---
typedef struct {
    u8  Name[8];
    union {
        u32 PhysicalAddress;
        u32 VirtualSize;
    } Misc;
    u32 VirtualAddress;
    u32 SizeOfRawData;
    u32 PointerToRawData;
    u32 PointerToRelocations;
    u32 PointerToLinenumbers;
    u16 NumberOfRelocations;
    u16 NumberOfLinenumbers;
    u32 Characteristics;
} IMAGE_SECTION_HEADER_;

// --- Import Descriptor ---
typedef struct {
    union {
        u32 Characteristics;
        u32 OriginalFirstThunk;
    };
    u32 TimeDateStamp;
    u32 ForwarderChain;
    u32 Name;
    u32 FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR_;

// --- Thunk Data (x64) ---
typedef struct {
    u64 AddressOfData;
} IMAGE_THUNK_DATA64_;

// --- Export Directory ---
typedef struct {
    u32 Characteristics;
    u32 TimeDateStamp;
    u16 MajorVersion;
    u16 MinorVersion;
    u32 Name;
    u32 Base;
    u32 NumberOfFunctions;
    u32 NumberOfNames;
    u32 AddressOfFunctions;
    u32 AddressOfNames;
    u32 AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY_;

// --- Base Relocation ---
typedef struct {
    u32 VirtualAddress;
    u32 SizeOfBlock;
} IMAGE_BASE_RELOCATION_;

// ============================================================
// PEB-СТРУКТУРЫ (для PEB walking)
// ============================================================

typedef struct _UNICODE_STRING_ {
    u16 Length;         // в байтах, не в символах
    u16 MaximumLength;
    u16* Buffer;
} UNICODE_STRING_;

typedef struct _LIST_ENTRY_ {
    void* Flink;
    void* Blink;
} LIST_ENTRY_;

typedef struct _PEB_LDR_DATA_ {
    u32 Length;
    u8  Initialized;
    void* SsHandle;
    LIST_ENTRY_ InLoadOrderModuleList;              // +0x10 (16 байт)
    LIST_ENTRY_ InMemoryOrderModuleList;            // +0x20
    LIST_ENTRY_ InInitializationOrderModuleList;    // +0x30
} PEB_LDR_DATA_;

typedef struct _LDR_DATA_TABLE_ENTRY_ {
    LIST_ENTRY_ InLoadOrderLinks;                   // +0x00
    LIST_ENTRY_ InMemoryOrderLinks;                 // +0x10
    LIST_ENTRY_ InInitializationOrderLinks;         // +0x20
    void* DllBase;                                  // +0x30
    void* EntryPoint;                               // +0x38
    u32 SizeOfImage;                                // +0x40
    u32 Padding;                                    // +0x44
    UNICODE_STRING_ FullDllName;                    // +0x48
    UNICODE_STRING_ BaseDllName;                    // +0x58
} LDR_DATA_TABLE_ENTRY_;

typedef struct _PEB_ {
    u8  InheritedAddressSpace;
    u8  ReadImageFileExecOptions;
    u8  BeingDebugged;          // anti-debug флаг
    u8  BitField;
    void* Mutant;
    void* ImageBaseAddress;
    PEB_LDR_DATA_* Ldr;
    void* ProcessParameters;
    void* SubSystemData;
    void* ProcessHeap;
    void* FastPebLock;
} PEB_;

#endif // BLINDSPOT_TYPES_H