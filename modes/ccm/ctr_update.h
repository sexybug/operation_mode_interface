
#ifndef _CTR_UPDATE_H_
#define _CTR_UPDATE_H_

#include <stdint.h>
#include "../../align.h"

typedef void (*cipher_f)(const uint8_t *key, const uint8_t *in, uint8_t *out);

typedef struct
{
    uint8_t key[32];
    uint8_t ctr[16];
    uint8_t in_buf[16];
    int key_len;     // 密钥长度
    int block_len;   // 算法分组长度
    cipher_f cipher; // 加密算法函数
    int total_len;   // 输入总长度
} __align4 CTR_CTX;

void ctr_init(CTR_CTX *ctx, cipher_f cipher, const uint8_t *key, int key_len, const uint8_t *ctr, int block_len);

/**
 * @brief CTR加密/解密
 * 支持持续输入，支持任何输入长度。
 * 注意: 输入总长度达到整分组后才会有输出。示例：分组16, update(15)->out_len=0, update(17)->out_len=32.
 *
 * @param ctx
 * @param in
 * @param in_len
 * @param out
 * @param out_len
 */
void ctr_update(CTR_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);
/**
 * @brief 输出非整分组CTR加解密结果，*out_len < 16
 *
 * @param ctx
 * @param out
 * @param out_len
 */
void ctr_final(CTR_CTX *ctx, uint8_t *out, int *out_len);

#endif // _CTR_UPDATE_H_