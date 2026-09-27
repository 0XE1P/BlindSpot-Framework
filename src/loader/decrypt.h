// src/loader/decrypt.h
#ifndef BLINDSPOT_DECRYPT_H
#define BLINDSPOT_DECRYPT_H

#include "../common/types.h"

// Расшифровка payload.
BOOL_ decrypt_payload(u8* dst, u32 dst_size,
                      const u8* src, u32 src_size,
                      const u8* key, u32 key_size,
                      const u8* iv, u32 iv_size,
                      const char* algorithm);

void xor_decrypt(u8* dst, const u8* src, u32 size, const u8* key, u32 key_size);
void rc4_decrypt(u8* dst, const u8* src, u32 size, const u8* key, u32 key_size);

#endif