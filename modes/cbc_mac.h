/**
 * @file cbc_mac.h
 * @author your name (you@domain.com)
 * @brief A implenentation of FIPS 113 CBC-MAC. Attentation: The FIPS 113 was withdrawn on September 1, 2008.
 * @version 0.1
 * @date 2024-07-14
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef _CBC_MAC_H_
#define _CBC_MAC_H_

#include <stdint.h>
#include "../common.h"

/**
 * @brief CBC-MAC
 *
 * @param enc 分组密码算法加密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param D Data
 * @param len Data Length（in bytes）, can be any integer > 0
 * @param C  Message Authentication Code
 */
void cbc_mac(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *D, int len, uint8_t *C);

#endif // _CBC_MAC_H_