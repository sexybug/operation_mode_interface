
#ifndef _ECB_H_
#define _ECB_H_

#include <stdint.h>
#include "../common.h"

/**
 * @brief ECB 加密
 *
 * @param enc 分组密码算法加密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param P 明文
 * @param len 明文长度（in bytes），必须是n的整数倍
 * @param C 密文输出
 */
void ecb_enc(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *P, int len, uint8_t *C);

/**
 * @brief ECB 解密
 *
 * @param dec 分组密码算法解密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param C 密文
 * @param len 密文长度（in bytes），必须是n的整数倍
 * @param P 明文输出
 */
void ecb_dec(block_f_ptr dec, int n, const uint8_t *K, const uint8_t *C, int len, uint8_t *P);

#endif // _ECB_H_