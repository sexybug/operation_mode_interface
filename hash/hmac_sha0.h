
#ifndef _HMAC_SHA0_H_
#define _HMAC_SHA0_H_

#include "hmac.h"
#include "sha0.h"

typedef struct
{
    SHA0_CTX hash_ctx;
    CC_HMAC_CTX hmac_ctx;
} __align4 HMAC_SHA0_CTX;

void hmac_sha0_init(HMAC_SHA0_CTX *ctx, const uint8_t *key, size_t key_len);

void hmac_sha0_update(HMAC_SHA0_CTX *ctx, const uint8_t *data, size_t data_len);

void hmac_sha0_final(HMAC_SHA0_CTX *ctx, uint8_t *mac);

void hmac_sha0(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac);

#endif /* _HMAC_SHA0_H_ */