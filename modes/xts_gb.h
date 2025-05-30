
#ifndef _XTS_GB_H_
#define _XTS_GB_H_

#include <stdint.h>
#include "../common.h"

//XTS GB/T 17964-2021

/**
 * @brief XTS 加密
 *
 * @param enc 分组密码算法加密函数
 * @param K1 加密密钥1
 * @param K2 加密密钥2
 * @param TW 调柄，长度为n
 * @param P 明文
 * @param len 明文长度（in bytes），大于等于n的整数
 * @param C 密文输出
 */
void xts_gb_enc(block_f_ptr enc, const uint8_t *K1, const uint8_t *K2, const uint8_t *TW, const uint8_t *P, int len, uint8_t *C);

/**
 * @brief XTS 解密
 *
 * @param enc 分组密码算法加密函数
 * @param dec 分组密码算法解密函数
 * @param K1 解密密钥1
 * @param K2 解密密钥2
 * @param TW 调柄，长度为n
 * @param C 密文
 * @param len 密文长度（in bytes），大于等于n的整数
 * @param P 明文输出
 */
void xts_gb_dec(block_f_ptr enc, block_f_ptr dec, const uint8_t *K1, const uint8_t *K2, const uint8_t *TW, const uint8_t *C, int len, uint8_t *P);

#endif // _XTS_GB_H_