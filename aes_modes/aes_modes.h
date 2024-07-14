
#ifndef _AES_MODES_H_
#define _AES_MODES_H_

#include <stdint.h>
#include "../common.h"

/**
 * Encrypts data using the AES algorithm in ECB mode.
 *
 * @param key
 * @param key_len the length of the key in bytes, can be {16, 24, 32}
 * @param in the input data to be encrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the encrypted data will be stored
 *
 * @return CC_SUCCESS if the encryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t aes_ecb_enc(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t *out);

/**
 * @brief Decrypts data using the AES algorithm in ECB mode.
 *
 * @param key
 * @param key_len the length of the key in bytes, can be {16, 24, 32}
 * @param in the input data to be decrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the decrypted data will be stored
 *
 * @return CC_SUCCESS if the decryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t aes_ecb_dec(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t *out);

/**
 * Encrypts data using the AES algorithm in CBC mode.
 *
 * @param key
 * @param key_len the length of the key in bytes, can be {16, 24, 32}
 * @param in the input data to be encrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the encrypted data will be stored
 *
 * @return CC_SUCCESS if the encryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t aes_cbc_enc(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

/**
 * Decrypts data using the AES algorithm in CBC mode.
 *
 * @param key
 * @param key_len the length of the key in bytes, can be {16, 24, 32}
 * @param in the input data to be decrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the decrypted data will be stored
 *
 * @return CC_SUCCESS if the decryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t aes_cbc_dec(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

cc_status_t aes_cfb_enc(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out);
cc_status_t aes_cfb_dec(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out);

cc_status_t aes_ofb_enc(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out);
cc_status_t aes_ofb_dec(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out);

cc_status_t aes_ctr_enc(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);
cc_status_t aes_ctr_dec(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

/**
 * Encrypts data using the AES algorithm in XTS mode.
 *
 * @param K1 the first key
 * @param K2 the second key
 * @param key_len the length of the key(K1 and K2) in bytes, can be {16, 24, 32}
 * @param TW the 16-byte tweak value
 * @param P the input data to be encrypted
 * @param len the length of the input data in bytes
 * @param C the output buffer where the encrypted data will be stored
 *
 * @return CC_SUCCESS if the encryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t aes_xts_enc(const uint8_t *K1, const uint8_t *K2, int key_len, const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C);
cc_status_t aes_xts_dec(const uint8_t *K1, const uint8_t *K2, int key_len, const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P);

/**
 * Encrypts data using the AES algorithm in HCTR mode.
 *
 * @param K1 the first key
 * @param key_len the length of K1 in bytes, can be {16, 24, 32}
 * @param K2 the second key
 * @param TW the 16-byte tweak value
 * @param P the input data to be encrypted
 * @param len the length of the input data in bytes
 * @param C the output buffer where the encrypted data will be stored
 *
 * @return CC_SUCCESS if the encryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t aes_hctr_enc(const uint8_t *K1, int key_len, const uint8_t K2[16], const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C);
cc_status_t aes_hctr_dec(const uint8_t *K1, int key_len, const uint8_t K2[16], const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P);

cc_status_t aes_bc_enc(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);
cc_status_t aes_bc_dec(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

cc_status_t aes_cbc_mac(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t mac[16]);

#endif // _AES_MODES_H_