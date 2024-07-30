
#include "sm4_ccm.h"
#include "../sm4/sm4.h"

int sm4_ccm_init(SM4_CCM_CTX *ctx, CCM_ENC_DEC_MODE enc_dec, const uint8_t *key, const uint8_t *nonce, uint8_t nonce_len, uint64_t AData_len, uint64_t message_len, uint8_t tag_len)
{
    return ccm_init(&(ctx->ccm), sm4_enc, enc_dec, key, 16, nonce, nonce_len, AData_len, message_len, tag_len);
}

void sm4_ccm_updateAData(SM4_CCM_CTX *ctx, const uint8_t *AData, int len, bool is_last)
{
    ccm_updateAData(&(ctx->ccm), AData, len, is_last);
}

void sm4_ccm_update(SM4_CCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    ccm_update(&(ctx->ccm), in, in_len, out, out_len);
}

void sm4_ccm_final(SM4_CCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *tag)
{
    ccm_final(&(ctx->ccm), out, out_len, tag);
}