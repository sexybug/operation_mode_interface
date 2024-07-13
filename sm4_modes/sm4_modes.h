
#ifndef _SM4_MODES_H_
#define _SM4_MODES_H_

#include <stdint.h>
#include "../common.h"

/**
 * Encrypts data using the SM4 algorithm in ECB mode.
 *
 * @param key the 16-byte key used for encryption
 * @param in the input data to be encrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the encrypted data will be stored
 *
 * @return CC_SUCCESS if the encryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t sm4_ecb_enc(const uint8_t key[16], const uint8_t *in, int in_len, uint8_t *out);

/**
 * @brief Decrypts data using the SM4 algorithm in ECB mode.
 *
 * @param key the 16-byte key used for decryption
 * @param in the input data to be decrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the decrypted data will be stored
 *
 * @return CC_SUCCESS if the decryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t sm4_ecb_dec(const uint8_t key[16], const uint8_t *in, int in_len, uint8_t *out);

/**
 * Encrypts data using the SM4 algorithm in CBC mode.
 *
 * @param key the 16-byte key used for encryption
 * @param in the input data to be encrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the encrypted data will be stored
 *
 * @return CC_SUCCESS if the encryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t sm4_cbc_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

/**
 * Decrypts data using the SM4 algorithm in CBC mode.
 *
 * @param key the 16-byte key used for decryption
 * @param in the input data to be decrypted
 * @param in_len the length of the input data in bytes
 * @param out the output buffer where the decrypted data will be stored
 *
 * @return CC_SUCCESS if the decryption is successful, CC_LENGTH_ERROR if the input length is not a multiple of 16 or equal to 0
 */
cc_status_t sm4_cbc_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

cc_status_t sm4_cfb_enc(int feedback_bit_num, const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out);
cc_status_t sm4_cfb_dec(int feedback_bit_num, const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out);

cc_status_t sm4_ofb_enc(int feedback_bit_num, const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out);
cc_status_t sm4_ofb_dec(int feedback_bit_num, const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out);

cc_status_t sm4_ctr_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);
cc_status_t sm4_ctr_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

cc_status_t sm4_xts_enc(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C);
cc_status_t sm4_xts_dec(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P);

cc_status_t sm4_hctr_enc(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C);
cc_status_t sm4_hctr_dec(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P);

cc_status_t sm4_bc_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);
cc_status_t sm4_bc_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

cc_status_t sm4_ofbnlf_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);
cc_status_t sm4_ofbnlf_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out);

cc_status_t sm4_cbc_mac(const uint8_t key[16], const uint8_t *in, int in_len, uint8_t mac[16]);

#endif // _SM4_MODES_H_