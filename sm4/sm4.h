/**
 * @file sm4.h
 * @author sexybug (hello.bug@outlook.com)
 * @brief GB_T 32907-2016信息安全技术 SM4分组密码算法 c语言实现
 * @version 0.1
 * @date 2023-02-18
 *
 * @copyright Copyright (c) 2023
 *
 */
#ifndef _SM4_H_
#define _SM4_H_

#include <stdint.h>

/**
 * @brief SM4加密函数，输入必须是整分组
 *
 * @param key 128bit密钥
 * @param in 明文输入
 * @param inlen 明文长度(in Byte)
 * @param out 密文输出
 */
void SM4_Encrypt(const uint8_t *key, const uint8_t *in, int inlen, uint8_t *out);

/**
 * @brief SM4解密函数，输入必须是整分组
 *
 * @param key 128bit密钥
 * @param in 密文输入
 * @param inlen 密文长度(in Byte)
 * @param out 明文输出
 */
void SM4_Decrypt(const uint8_t *key, const uint8_t *in, int inlen, uint8_t *out);

/**
 * Encrypts a single block of data using the SM4 encryption algorithm.
 *
 * @param key The 128-bit encryption key.
 * @param in The input data to be encrypted (16 bytes).
 * @param out The output buffer where the encrypted data will be stored (16 bytes).
 */
void sm4_enc(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/**
 * Decrypts a single block of data using the SM4 decryption algorithm.
 *
 * @param key The 128-bit decryption key.
 * @param in The input data to be decrypted (16 bytes).
 * @param out The output buffer where the decrypted data will be stored (16 bytes).
 */
void sm4_dec(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* _SM4_H_ */