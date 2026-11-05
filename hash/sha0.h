#ifndef _SHA0_H
#define _SHA0_H

#include <stdint.h>

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA0_CTX;

void sha0_init(SHA0_CTX *ctx);
void sha0_update(SHA0_CTX *ctx, const uint8_t *data, size_t len);
void sha0_final(SHA0_CTX *ctx, uint8_t hash[20]);

#endif // _SHA0_H