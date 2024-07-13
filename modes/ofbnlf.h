
#ifndef _OFBNLF_H_
#define _OFBNLF_H_

#include <stdint.h>
#include "../common.h"

/**
 * @brief OFBNLF 加密
 *
 * @param enc 分组密码算法加密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param IV 
 * @param P 明文
 * @param len 明文长度（in bytes）
 * @param C 密文输出
 */
void ofbnlf_enc(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int len, uint8_t *C);

/**
 * @brief OFBNLF 解密
 *
 * @param enc 分组密码算法加密函数
 * @param dec 分组密码算法解密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param IV 
 * @param C 密文
 * @param len 密文长度（in bytes）
 * @param P 明文输出
 */
void ofbnlf_dec(block_f_ptr enc, block_f_ptr dec, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int len, uint8_t *P);

#endif // _OFBNLF_H_