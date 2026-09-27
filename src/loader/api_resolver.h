// src/loader/api_resolver.h
#ifndef BLINDSPOT_API_RESOLVER_H
#define BLINDSPOT_API_RESOLVER_H

#include "../common/types.h"

// === PEB walking ===
void* get_peb(void);
void* get_module_base_by_name(const char* name);

// === Export parsing ===
void* resolve_api_by_hash(void* module_base, u32 func_hash);

// === Высокоуровневые обёртки ===
void* resolve_kernel32(u32 func_hash);
void* resolve_ntdll(u32 func_hash);
void* resolve_user32(u32 func_hash);
void* resolve_ws2_32(u32 func_hash);

// === Хеш-функция ===
u32 api_hash(const char* name);

#endif