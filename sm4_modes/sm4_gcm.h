
#ifndef _SM4_GCM_H_
#define _SM4_GCM_H_

#include "../modes/gcm.h"

typedef struct
{
    GCM_CTX gcm;
} __align4 SM4_GCM_CTX;

void sm4_gcm_init(SM4_GCM_CTX *ctx, GCM_ENC_DEC_MODE enc_dec, const uint8_t *key, const uint8_t *IV, int IV_len, int TAG_len);
void sm4_gcm_updateAAD(SM4_GCM_CTX *ctx, const uint8_t *AAD, int AAD_len, bool is_last);
void sm4_gcm_update(SM4_GCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);
void sm4_gcm_final(SM4_GCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *Tag);

#endif //_SM4_GCM_H_