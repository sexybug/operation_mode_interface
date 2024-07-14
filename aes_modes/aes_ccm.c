
#include "aes_ccm.h"
#include "../aes/aes.h"

int aes_ccm_init(AES_CCM_CTX *ctx, CCM_ENC_DEC_MODE enc_dec, const uint8_t *key, int key_len, const uint8_t *nonce, uint8_t nonce_len, uint64_t AData_len, uint64_t message_len, uint8_t tag_len)
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

    return ccm_init(&(ctx->ccm), cipher, enc_dec, key, key_len, nonce, nonce_len, AData_len, message_len, tag_len);
}

void aes_ccm_updateAData(AES_CCM_CTX *ctx, const uint8_t *AData, int len, bool is_last)
{
    ccm_updateAData(&(ctx->ccm), AData, len, is_last);
}

void aes_ccm_update(AES_CCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    ccm_update(&(ctx->ccm), in, in_len, out, out_len);
}

void aes_ccm_final(AES_CCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *tag)
{
    ccm_final(&(ctx->ccm), out, out_len, tag);
}