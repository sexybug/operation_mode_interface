
#ifndef _HMAC_SM3_H_
#define _HMAC_SM3_H_

#include "hmac.h"
#include "sm3.h"

typedef struct
{
    sm3_ctx_t hash_ctx;
    HMAC_CTX hmac_ctx;
} __align4 HMAC_SM3_CTX;

void hmac_sm3_init(HMAC_SM3_CTX *ctx, const uint8_t *key, size_t key_len);

void hmac_sm3_update(HMAC_SM3_CTX *ctx, const uint8_t *data, size_t data_len);

void hmac_sm3_final(HMAC_SM3_CTX *ctx, uint8_t *mac);

#endif /* _HMAC_SM3_H_ */