
#include "kdf.h"
#include <string.h>

static inline uint32_t cc_swap_u32(uint32_t x)
{
    return (x >> 24) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | (x << 24);
}
static inline void u32_to_u8(uint32_t x, uint8_t buf[4])
{
    buf[0] = (x >> 24) & 0xFF;
    buf[1] = (x >> 16) & 0xFF;
    buf[2] = (x >> 8) & 0xFF;
    buf[3] = x & 0xFF;
}

void kdf_init(KDF_CTX *kdf_ctx,
              hash_init_f hash_init, hash_update_f hash_update, hash_final_f hash_final,
              size_t hash_digest_size)
{
    kdf_ctx->hash_init = hash_init;
    kdf_ctx->hash_update = hash_update;
    kdf_ctx->hash_final = hash_final;
    kdf_ctx->hash_digest_size = hash_digest_size;

    kdf_ctx->counter = 1;
}

void kdf_derive_block(KDF_CTX *kdf_ctx, void *hash_ctx, const uint8_t *Z, size_t Z_len, const uint8_t *shared_info, size_t shared_info_len, uint8_t *Ki)
{
    uint8_t counter_buf[4];
    u32_to_u8(kdf_ctx->counter, counter_buf);
    kdf_ctx->counter++;

    kdf_ctx->hash_init(hash_ctx);
    kdf_ctx->hash_update(hash_ctx, Z, Z_len);
    kdf_ctx->hash_update(hash_ctx, counter_buf, 4);
    if (shared_info != NULL && shared_info_len != 0)
    {
        kdf_ctx->hash_update(hash_ctx, shared_info, shared_info_len);
    }
    kdf_ctx->hash_final(hash_ctx, Ki);
}

void kdf_derive(KDF_CTX *kdf_ctx, void *hash_ctx, const uint8_t *Z, size_t Z_len, const uint8_t *shared_info, size_t shared_info_len, uint8_t *key, size_t key_len)
{
    size_t block = key_len / kdf_ctx->hash_digest_size;
    size_t rest = key_len % kdf_ctx->hash_digest_size;

    size_t i;
    for (i = 0; i < block; i++)
    {
        kdf_derive_block(kdf_ctx, hash_ctx, Z, Z_len, shared_info, shared_info_len, key + i * kdf_ctx->hash_digest_size);
    }
    if (rest != 0)
    {
        __align4 uint8_t T[64];
        kdf_derive_block(kdf_ctx, hash_ctx, Z, Z_len, shared_info, shared_info_len, T);
        memcpy(key + block * kdf_ctx->hash_digest_size, T, rest);
    }
}