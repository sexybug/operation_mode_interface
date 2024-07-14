
#ifndef _DES_MODES_H_
#define _DES_MODES_H_

#include <stdint.h>
#include "../common.h"

/**
 * Encrypts data using the DES algorithm in ECB mode.
 *
 * @param key 
 * @param key_len the length of the key in bytes, can be {8, 16, 24}
 * @param in the input data to be encrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the encrypted data will be stored
 *
 * @return CC_SUCCESS if the encryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t des_ecb_enc(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t *out);

/**
 * @brief Decrypts data using the DES algorithm in ECB mode.
 *
 * @param key 
 * @param key_len the length of the key in bytes, can be {8, 16, 24}
 * @param in the input data to be decrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the decrypted data will be stored
 *
 * @return CC_SUCCESS if the decryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t des_ecb_dec(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t *out);

/**
 * Encrypts data using the DES algorithm in CBC mode.
 *
 * @param key 
 * @param key_len the length of the key in bytes, can be {8, 16, 24}
 * @param in the input data to be encrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the encrypted data will be stored
 *
 * @return CC_SUCCESS if the encryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t des_cbc_enc(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out);

/**
 * Decrypts data using the DES algorithm in CBC mode.
 *
 * @param key 
 * @param key_len the length of the key in bytes, can be {8, 16, 24}
 * @param in the input data to be decrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the decrypted data will be stored
 *
 * @return CC_SUCCESS if the decryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t des_cbc_dec(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out);

cc_status_t des_cfb_enc(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_bit_len, uint8_t *out);
cc_status_t des_cfb_dec(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_bit_len, uint8_t *out);

cc_status_t des_ofb_enc(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_bit_len, uint8_t *out);
cc_status_t des_ofb_dec(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_bit_len, uint8_t *out);

cc_status_t des_ctr_enc(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out);
cc_status_t des_ctr_dec(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out);

cc_status_t des_bc_enc(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out);
cc_status_t des_bc_dec(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out);


cc_status_t des_cbc_mac(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t mac[8]);
cc_status_t des_cmac(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t mac[8]);

#endif // _DES_MODES_H_