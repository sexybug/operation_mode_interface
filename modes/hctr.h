
#ifndef _HCTR_H_
#define _HCTR_H_

#include <stdint.h>
#include "../common.h"

/**
 * @brief HCTR 加密
 *
 * @param enc 分组密码算法加密函数
 * @param n 算法分组长度（in bytes）
 * @param K1 加密密钥1，长度由分组密码算法决定,当前仅支持128bit
 * @param K2 加密密钥2，长度为n
 * @param TW 调柄，长度为n
 * @param P 明文
 * @param len 明文长度（in bytes），大于等于n的整数
 * @param C 密文输出
 */
void hctr_enc(block_f_ptr enc, int n, const uint8_t *K1, const uint8_t *K2, const uint8_t *TW, const uint8_t *P, int len, uint8_t *C);

/**
 * @brief HCTR 解密
 *
 * @param enc 分组密码算法加密函数
 * @param dec 分组密码算法解密函数
 * @param n 算法分组长度（in bytes）
 * @param K1 加密密钥1，长度由分组密码算法决定
 * @param K2 加密密钥2，长度为n
 * @param TW 调柄，长度为n
 * @param len 密文长度（in bytes），大于等于n的整数
 * @param P 明文输出
 */
void hctr_dec(block_f_ptr enc, block_f_ptr dec, int n, const uint8_t *K1, const uint8_t *K2, const uint8_t *TW, const uint8_t *C, int len, uint8_t *P);

#endif // _HCTR_H_