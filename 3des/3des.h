#ifndef _3DES_H_
#define _3DES_H_

#include <stdint.h>

// des (1key) encrypt
void des_enc(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);

// des (1key) decrypt
void des_dec(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);

// 3des 2key encrypt
void des3_2key_enc(const uint8_t key[16], const uint8_t in[8], uint8_t out[8]);
// 3des 2key decrypt
void des3_2key_dec(const uint8_t key[16], const uint8_t in[8], uint8_t out[8]);

// 3des enc = enc -> dec -> enc
//  3des 3key encrypt
void des3_3key_enc(const uint8_t key[24], const uint8_t in[8], uint8_t out[8]);

// 3des dec = dec -> enc -> dec
//  3des 3key decrypt
void des3_3key_dec(const uint8_t key[24], const uint8_t in[8], uint8_t out[8]);

#endif /* _3DES_H_ */
