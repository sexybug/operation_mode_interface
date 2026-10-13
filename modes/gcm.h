/**
 * @file gcm.h
 * @author your name (you@domain.com)
 * @brief an implementation of NIST Special Publication 800-38D November, 2007 (Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC)
 * @version 0.1
 * @date 2024-03-13
 *
 * @copyright Copyright (c) 2024
 *
 */
#ifndef _GCM_H_
#define _GCM_H_

#include "../align.h"
#include <stdint.h>
#include <stdbool.h>

typedef void (*cipher_f)(const uint8_t *key, const uint8_t *in, uint8_t *out);

typedef struct
{
    uint64_t hi, lo;
} u128;

typedef struct
{
    // uint8_t H[16];      // hash subkey. removed
    u128 Htable[16];
    uint64_t buf[2];    // partial block buffer, 16 bytes（声明为 uint64_t 以获得 8 字节对齐）
    uint64_t Y[2];      // middle value, Yi, 16 bytes（8 字节对齐）
    uint64_t total_len; // total length of input (in bytes)
} __align8 GHASH_CTX; /* 不能用 __align4：那会把本类型对齐降到 4，而 buf/Y 需要 8 字节对齐 */

typedef struct
{
    uint8_t K[48];   // key. 16 bytes for SM4, 16/24/32 bytes for AES, 16/32/48 bytes for SM1
    uint64_t CB[2];  // counter block, 16 bytes（8 字节对齐）
    uint64_t buf[2]; // partial block buffer, 16 bytes（8 字节对齐）
    uint64_t total_len; // total length of input (in bytes)
    cipher_f cipher; // cipher function, e.g., sm4_enc, aes_enc, sm1_enc
    int K_len;       // key length. 16 bytes for SM4, 16/24/32 bytes for AES, 16/32/48 bytes for SM1
} __align8 GCTR_CTX;

typedef enum
{
    GCM_ENCRYPT = 0,
    GCM_DECRYPT = 1
} GCM_ENC_DEC_MODE;
typedef struct
{
    uint64_t J0[2];           // GCM J0, 16 bytes（8 字节对齐）
    GHASH_CTX ghash;          // GCM GHASH context
    GCTR_CTX gctr;            // GCM GCTR context
    GCM_ENC_DEC_MODE enc_dec; // GCM mode, encrypt or decrypt
    int tag_len;              // The byte length of the tag, must in [4,16]
    uint64_t AAD_len;         // The total byte length of the AAD, must in [0,2^64-1]
} __align8 GCM_CTX;

/**
 * @brief
 *
 * @param ctx
 * @param cipher
 * @param enc_dec
 * @param K
 * @param K_len
 * @param IV
 * @param IV_len
 * @param TAG_len The byte length of the tag, must in [4,16]
 */
void gcm_init(GCM_CTX *ctx, cipher_f cipher, GCM_ENC_DEC_MODE enc_dec,
              const uint8_t *K, int K_len, const uint8_t *IV, int IV_len, int TAG_len);
void gcm_updateAAD(GCM_CTX *ctx, const uint8_t *AAD, int AAD_len, bool is_last);

void gcm_update(GCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);

void gcm_final(GCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *Tag);

#endif //_GCM_H_
