/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef GMSSL_AES_H
#define GMSSL_AES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

	void aes128_enc(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
	void aes128_dec(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
	void aes192_enc(const uint8_t key[24], const uint8_t in[16], uint8_t out[16]);
	void aes192_dec(const uint8_t key[24], const uint8_t in[16], uint8_t out[16]);
	void aes256_enc(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);
	void aes256_dec(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);

#ifdef __cplusplus
}
#endif
#endif
