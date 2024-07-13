
#ifndef _CTR_H_
#define _CTR_H_

#include <stdint.h>
#include "../common.h"

/**
 * @brief CTR 加密
 *
 * @param enc 分组密码算法加密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param IV
 * @param P 明文
 * @param len 明文长度（in bytes），可以是任意正整数
 * @param C 密文输出
 */
void ctr_enc(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int len, uint8_t *C);

/**
 * @brief CTR 解密
 *
 * @param enc 分组密码算法加密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param IV
 * @param C 密文
 * @param len 密文长度（in bytes），可以是任意正整数
 * @param P 明文输出
 */
void ctr_dec(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int len, uint8_t *P);

#endif // _CTR_H_