
#include "hmac.h"
#include <string.h>

#define IPAD 0x36
#define OPAD 0x5C

void hmac_init(HMAC_CTX *ctx, void *hash_ctx, const uint8_t *key, size_t key_len,
               hash_init_f hash_init, hash_update_f hash_update, hash_final_f hash_final, size_t hash_block_len, size_t hash_digest_len)
{
    if (hash_block_len > 128)
        return;

    size_t i;
    __align4 uint8_t key_ipad[128];

    ctx->hash_init = hash_init;
    ctx->hash_update = hash_update;
    ctx->hash_final = hash_final;

    ctx->hash_block_size = hash_block_len;
    ctx->hash_digest_size = hash_digest_len;

    if (key_len <= hash_block_len)
    {
        memcpy(ctx->key, key, key_len);
        memset(ctx->key + key_len, 0, hash_block_len - key_len);
    }
    else
    {
        hash_init(hash_ctx);
        hash_update(hash_ctx, key, key_len);
        hash_final(hash_ctx, ctx->key);
        memset(ctx->key + hash_digest_len, 0, hash_block_len - hash_digest_len);
    }

    for (i = 0; i < hash_block_len; i++)
    {
        key_ipad[i] = ctx->key[i] ^ IPAD;
    }

    hash_init(hash_ctx);
    hash_update(hash_ctx, key_ipad, hash_block_len);
}

void hmac_update(HMAC_CTX *ctx, void *hash_ctx, const uint8_t *data, size_t data_len)
{
    ctx->hash_update(hash_ctx, data, data_len);
}

void hmac_final(HMAC_CTX *ctx, void *hash_ctx, uint8_t *mac)
{
    __align4 uint8_t buf[192];
    size_t i;

    for (i = 0; i < ctx->hash_block_size; i++)
    {
        buf[i] = ctx->key[i] ^ OPAD;
    }
    ctx->hash_final(hash_ctx, buf + ctx->hash_block_size);

    ctx->hash_init(hash_ctx);
    ctx->hash_update(hash_ctx, buf, ctx->hash_block_size + ctx->hash_digest_size);
    ctx->hash_final(hash_ctx, mac);
}