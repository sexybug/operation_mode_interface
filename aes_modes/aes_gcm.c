
#include "aes_gcm.h"
#include "../aes/aes.h"

void aes_gcm_init(AES_GCM_CTX *ctx, GCM_ENC_DEC_MODE enc_dec, const uint8_t *key, int key_len, const uint8_t *IV, int IV_len, int TAG_len)
{
    cipher_f cipher;
    if (key_len == 16)
    {
        cipher = aes128_enc;
    }
    else if (key_len == 24)
    {
        cipher = aes192_enc;
    }
    else if (key_len == 32)
    {
        cipher = aes256_enc;
    }

    gcm_init(&(ctx->gcm), cipher, enc_dec, key, key_len, IV, IV_len, TAG_len);
}

void aes_gcm_updateAAD(AES_GCM_CTX *ctx, const uint8_t *AAD, int AAD_len, bool is_last)
{
    gcm_updateAAD(&(ctx->gcm), AAD, AAD_len, is_last);
}

void aes_gcm_update(AES_GCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    gcm_update(&(ctx->gcm), in, in_len, out, out_len);
}

void aes_gcm_final(AES_GCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *Tag)
{
    gcm_final(&(ctx->gcm), out, out_len, Tag);
}
