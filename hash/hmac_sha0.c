
#include "hmac_sha0.h"

static void _sha0_init(void *ctx)
{
    sha0_init(ctx);
}

static void _sha0_update(void *ctx, const uint8_t *data, size_t data_len)
{
    sha0_update(ctx, data, data_len);
}

static void _sha0_final(void *ctx, uint8_t *mac)
{
    sha0_final(ctx, mac);
}

void hmac_sha0_init(HMAC_SHA0_CTX *ctx, const uint8_t *key, size_t key_len)
{
    hmac_init(&ctx->hmac_ctx, &ctx->hash_ctx, key, key_len,
              _sha0_init, _sha0_update, _sha0_final, 64, 20);
}

void hmac_sha0_update(HMAC_SHA0_CTX *ctx, const uint8_t *data, size_t data_len)
{
    hmac_update(&ctx->hmac_ctx, &ctx->hash_ctx, data, data_len);
}

void hmac_sha0_final(HMAC_SHA0_CTX *ctx, uint8_t *mac)
{
    hmac_final(&ctx->hmac_ctx, &ctx->hash_ctx, mac);
}