
#include "sm4_gcm.h"
#include "../sm4/sm4.h"

void sm4_gcm_init(SM4_GCM_CTX *ctx, GCM_ENC_DEC_MODE enc_dec, const uint8_t *key, int key_len, const uint8_t *IV, int IV_len, int TAG_len)
{
    gcm_init(&(ctx->gcm), sm4_enc, enc_dec, key, key_len, IV, IV_len, TAG_len);
}

void sm4_gcm_updateAAD(SM4_GCM_CTX *ctx, const uint8_t *AAD, int AAD_len, bool is_last)
{
    gcm_updateAAD(&(ctx->gcm), AAD, AAD_len, is_last);
}

void sm4_gcm_update(SM4_GCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    gcm_update(&(ctx->gcm), in, in_len, out, out_len);
}

void sm4_gcm_final(SM4_GCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *Tag)
{
    gcm_final(&(ctx->gcm), out, out_len, Tag);
}
