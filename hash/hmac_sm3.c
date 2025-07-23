
#include "hmac_sm3.h"

static void _sm3_init(void *ctx)
{
    sm3_init(ctx);
}

static void _sm3_update(void *ctx, const uint8_t *data, size_t data_len)
{
    sm3_update(ctx, data, data_len);
}

static void _sm3_final(void *ctx, uint8_t *mac)
{
    sm3_final(ctx, mac);
}

void hmac_sm3_init(HMAC_SM3_CTX *ctx, const uint8_t *key, size_t key_len)
{
    hmac_init(&ctx->hmac_ctx, &ctx->hash_ctx, key, key_len,
              _sm3_init, _sm3_update, _sm3_final, 64, 32);
}

void hmac_sm3_update(HMAC_SM3_CTX *ctx, const uint8_t *data, size_t data_len)
{
    hmac_update(&ctx->hmac_ctx, &ctx->hash_ctx, data, data_len);
}

void hmac_sm3_final(HMAC_SM3_CTX *ctx, uint8_t *mac)
{
    hmac_final(&ctx->hmac_ctx, &ctx->hash_ctx, mac);
}