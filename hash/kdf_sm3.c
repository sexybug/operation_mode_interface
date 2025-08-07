
#include "kdf_sm3.h"
#include "sm3.h"

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

void kdf_sm3_init(KDF_CTX *kdf_ctx)
{
    kdf_init(kdf_ctx, _sm3_init, _sm3_update, _sm3_final, 32);
}

void kdf_sm3_derive(KDF_CTX *kdf_ctx, const uint8_t *Z, size_t Z_len, const uint8_t *shared_info, size_t shared_info_len, uint8_t *key, size_t key_len)
{
    sm3_ctx_t sm3_ctx;
    kdf_derive(kdf_ctx, &sm3_ctx, Z, Z_len, shared_info, shared_info_len, key, key_len);
}