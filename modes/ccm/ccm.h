
#ifndef _CCM_H_
#define _CCM_H_

#include <stdint.h>
#include <stdbool.h>
#include "../../align.h"
#include "cbc_mac_update.h"
#include "ctr_update.h"

typedef void (*cipher_f)(const uint8_t *key, const uint8_t *in, uint8_t *out);

typedef enum
{
    CCM_ENCRYPT = 0,
    CCM_DECRYPT = 1
} CCM_ENC_DEC_MODE;

typedef struct
{
    uint8_t S0[16];
    uint8_t tag_len;
    CCM_ENC_DEC_MODE enc_dec;
    CBC_MAC_CTX cbc_mac;
    CTR_CTX ctr;
} __align4 CCM_CTX;

int ccm_init(CCM_CTX *ctx, cipher_f cipher, CCM_ENC_DEC_MODE enc_dec, const uint8_t *key, uint8_t key_len, const uint8_t *nonce, uint8_t nonce_len, uint64_t AData_len, uint64_t message_len, uint8_t tag_len);
void ccm_updateAData(CCM_CTX *ctx, const uint8_t *AData, int len, bool is_last);
void ccm_update(CCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);
void ccm_final(CCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *tag);

#endif // _CCM_H_