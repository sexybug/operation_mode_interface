
#ifndef _OFB_H_
#define _OFB_H_

#include <stdint.h>
#include "../common.h"

/**
 * @brief OFB 加密
 *
 * @param enc 分组密码算法加密函数
 * @param n 算法分组长度（in bytes）
 * @param k 反馈长度（in bits），可以是1或[1,n*8]之间8的倍数
 * @param K 密钥
 * @param IV
 * @param P 明文
 * @param bit_len 明文长度（in bits）
 * @param C 密文输出
 */
void ofb_enc(block_f_ptr enc, int n, int k, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int bit_len, uint8_t *C);

/**
 * @brief OFB 解密
 *
 * @param enc 分组密码算法加密函数
 * @param n 算法分组长度（in bytes）
 * @param k 反馈长度（in bits），可以是1或[1,n*8]之间8的倍数
 * @param K 密钥
 * @param IV
 * @param C 密文
 * @param bit_len 密文长度（in bits）
 * @param P 明文输出
 */
void ofb_dec(block_f_ptr enc, int n, int k, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int bit_len, uint8_t *P);

#endif //_OFB_H_