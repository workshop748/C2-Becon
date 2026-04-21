// linux-agent/include/crypto_linux.h
#pragma once
#include <stddef.h>

// AES-256-CBC encrypt
int aes_encrypt_linux(const unsigned char* plain, size_t plain_len,
                      const unsigned char* key, const unsigned char* iv,
                      unsigned char** cipher_out, size_t* cipher_len);

// AES-256-CBC decrypt
int aes_decrypt_linux(const unsigned char* cipher, size_t cipher_len,
                      const unsigned char* key, const unsigned char* iv,
                      unsigned char** plain_out, size_t* plain_len);

// Sleep obfuscation (XOR .text + usleep)
void obf_sleep_linux(unsigned int ms);
