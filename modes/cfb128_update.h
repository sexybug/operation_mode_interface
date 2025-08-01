
#ifndef _CFB128_UPDATE_H_
#define _CFB128_UPDATE_H_

#include "../align.h"
#include <stdint.h>

typedef void (*cipher_f)(const uint8_t *key, const uint8_t *in, uint8_t *out);

typedef enum
{
    ENCRYPT = 0,
    DECRYPT = 1
} ENC_DEC_MODE;

typedef struct
{
    ENC_DEC_MODE mode;
    uint8_t key[48];    // key buffer
    uint8_t iv[16];     // IV buffer
    uint8_t in_buf[16]; // input buffer
    int block_len;      // 算法分组长度
    int total_len;      // 输入总长度
    cipher_f cipher;    // 加密算法函数
} __align4 CFB128_CTX;

void cfb128_init(CFB128_CTX *ctx, cipher_f cipher, ENC_DEC_MODE mode, const uint8_t *key, int key_len, const uint8_t *iv, int block_len);

/**
 * @brief CFB128加密/解密
 * 支持持续输入，支持任何输入长度。
 * 注意: 输入总长度达到整分组后才会有输出。示例：分组16, update(15)->out_len=0, update(17)->out_len=32.
 *
 * @param ctx
 * @param in
 * @param in_len
 * @param out
 * @param out_len
 */
void cfb128_update(CFB128_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);
/**
 * @brief 输出非整分组CFB128加解密结果，*out_len < 16
 *
 * @param ctx
 * @param out
 * @param out_len
 */
void cfb128_final(CFB128_CTX *ctx, uint8_t *out, int *out_len);

#endif //_CFB128_UPDATE_H_