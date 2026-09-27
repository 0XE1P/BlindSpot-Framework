// src/loader/decrypt.c
// Расшифровка payload внутри loader'а.

#include "decrypt.h"
#include "../common/memory.h"

// ------------------------------------------------------------
// XOR-расшифровка с многобайтным ключом.
// ------------------------------------------------------------
void xor_decrypt(u8* dst, const u8* src, u32 size, const u8* key, u32 key_size) {
    if (key_size == 0) return;
    for (u32 i = 0; i < size; i++) {
        dst[i] = src[i] ^ key[i % key_size];
    }
}

// ------------------------------------------------------------
// RC4-расшифровка.
// ------------------------------------------------------------
void rc4_decrypt(u8* dst, const u8* src, u32 size, const u8* key, u32 key_size) {
    u8 S[256];
    u8 K[256];

    // Инициализация
    for (int i = 0; i < 256; i++) {
        S[i] = (u8)i;
        K[i] = key[i % key_size];
    }

    // KSA
    u8 j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + S[i] + K[i];
        u8 tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }

    // PRGA
    u8 i = 0;
    j = 0;
    for (u32 n = 0; n < size; n++) {
        i = i + 1;
        j = j + S[i];
        u8 tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        u8 k = S[(u8)(S[i] + S[j])];
        dst[n] = src[n] ^ k;
    }
}

// ------------------------------------------------------------
// Сравнение строк.
// ------------------------------------------------------------
static int str_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

// ------------------------------------------------------------
// Расшифровать payload.
// ------------------------------------------------------------
BOOL_ decrypt_payload(u8* dst, u32 dst_size,
                      const u8* src, u32 src_size,
                      const u8* key, u32 key_size,
                      const u8* iv, u32 iv_size,
                      const char* algorithm) {
    (void)iv; (void)iv_size;   // пока не используется

    if (!dst || !src || !key || !algorithm) return FALSE_;
    if (src_size > dst_size) return FALSE_;

    if (str_eq(algorithm, "xor")) {
        xor_decrypt(dst, src, src_size, key, key_size);
        return TRUE_;
    }
    if (str_eq(algorithm, "rc4")) {
        rc4_decrypt(dst, src, src_size, key, key_size);
        return TRUE_;
    }
    return FALSE_;
}