#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

void aes128_enc(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

void aes128_dec(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

void aes192_enc(const uint8_t key[24], const uint8_t in[16], uint8_t out[16]);

void aes192_dec(const uint8_t key[24], const uint8_t in[16], uint8_t out[16]);

void aes256_enc(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);

void aes256_dec(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);

#endif // _AES_H_
