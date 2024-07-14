
#ifndef _AES_GCM_H_
#define _AES_GCM_H_

#include "../modes/gcm.h"

typedef struct
{
    GCM_CTX gcm;
} __align4 AES_GCM_CTX;

void aes_gcm_init(AES_GCM_CTX *ctx, GCM_ENC_DEC_MODE enc_dec, const uint8_t *key, int key_len, const uint8_t *IV, int IV_len, int TAG_len);
void aes_gcm_updateAAD(AES_GCM_CTX *ctx, const uint8_t *AAD, int AAD_len, bool is_last);
void aes_gcm_update(AES_GCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);
void aes_gcm_final(AES_GCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *Tag);

#endif //_AES_GCM_H_