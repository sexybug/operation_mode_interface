#include "xts_ieee.h"
#include <string.h>
#include "../sm4/sm4.h"

// XTS IEEE Std 1619-2018

typedef uint64_t gf128_t[2];

#define GETU64(p)             \
    ((uint64_t)(p)[0] << 56 | \
     (uint64_t)(p)[1] << 48 | \
     (uint64_t)(p)[2] << 40 | \
     (uint64_t)(p)[3] << 32 | \
     (uint64_t)(p)[4] << 24 | \
     (uint64_t)(p)[5] << 16 | \
     (uint64_t)(p)[6] << 8 |  \
     (uint64_t)(p)[7])

#define PUTU64(p, V)                \
    ((p)[0] = (uint8_t)((V) >> 56), \
     (p)[1] = (uint8_t)((V) >> 48), \
     (p)[2] = (uint8_t)((V) >> 40), \
     (p)[3] = (uint8_t)((V) >> 32), \
     (p)[4] = (uint8_t)((V) >> 24), \
     (p)[5] = (uint8_t)((V) >> 16), \
     (p)[6] = (uint8_t)((V) >> 8),  \
     (p)[7] = (uint8_t)(V))

static void gmssl_memxor(void *r, const void *a, const void *b, size_t len)
{
    uint8_t *pr = r;
    const uint8_t *pa = a;
    const uint8_t *pb = b;
    size_t i;
    for (i = 0; i < len; i++)
    {
        pr[i] = pa[i] ^ pb[i];
    }
}

void gf128_mul_by_2(gf128_t r, const gf128_t a)
{
    const uint64_t mask = (uint64_t)1 << 63;

    if (a[1] & mask)
    {
        r[1] = a[1] << 1 | a[0] >> 63;
        r[0] = a[0] << 1;
        r[0] ^= 0x87;
    }
    else
    {
        r[1] = a[1] << 1 | a[0] >> 63;
        r[0] = a[0] << 1;
    }
}

int xts_ieee_enc(block_f_ptr enc, int n, const uint8_t *key1, const uint8_t *key2, const uint8_t tweak[16],
                 const uint8_t *in, size_t inlen, uint8_t *out)
{
    uint8_t T[16];
    uint8_t block[16];
    size_t nblocks, i;
    gf128_t a;

    if (inlen < 16)
    {
        return -1;
    }
    nblocks = inlen / 16 + 1;

    memcpy(T, tweak, 16);
    enc(key2, T, T);

    for (i = 0; i < nblocks - 2; i++)
    {
        gmssl_memxor(block, in, T, 16);
        enc(key1, block, block);
        gmssl_memxor(out, block, T, 16);

        memcpy(a, T, 16);
        gf128_mul_by_2(a, a);
        memcpy(T, a, 16);

        in += 16;
        inlen -= 16;
        out += 16;
    }

    if (inlen % 16 == 0)
    {
        gmssl_memxor(block, in, T, 16);
        enc(key1, block, block);
        gmssl_memxor(out, block, T, 16);
    }
    else
    {
        gmssl_memxor(block, in, T, 16);
        enc(key1, block, block);
        gmssl_memxor(block, block, T, 16);

        memcpy(a, T, 16);
        gf128_mul_by_2(a, a);
        memcpy(T, a, 16);

        in += 16;
        inlen -= 16;

        memcpy(out + 16, block, inlen);
        memcpy(block, in, inlen);

        gmssl_memxor(block, block, T, 16);
        enc(key1, block, block);
        gmssl_memxor(out, block, T, 16);
    }

    return 1;
}

int xts_ieee_dec(block_f_ptr enc, block_f_ptr dec, int n, const uint8_t *key1, const uint8_t *key2, const uint8_t tweak[16],
                 const uint8_t *in, size_t inlen, uint8_t *out)
{
    uint8_t T[16];
    uint8_t block[16];
    size_t nblocks, i;
    gf128_t a;

    if (inlen < 16)
    {
        return -1;
    }
    nblocks = inlen / 16 + 1;

    memcpy(T, tweak, 16);
    enc(key2, T, T);

    for (i = 0; i < nblocks - 2; i++)
    {
        gmssl_memxor(block, in, T, 16);
        dec(key1, block, block);
        gmssl_memxor(out, block, T, 16);

        memcpy(a, T, 16);
        gf128_mul_by_2(a, a);
        memcpy(T, a, 16);

        in += 16;
        inlen -= 16;
        out += 16;
    }

    if (inlen % 16 == 0)
    {
        gmssl_memxor(block, in, T, 16);
        dec(key1, block, block);
        gmssl_memxor(out, block, T, 16);
    }
    else
    {
        uint8_t T1[16];

        memcpy(a, T, 16);
        gf128_mul_by_2(a, a);
        memcpy(T1, a, 16);

        gmssl_memxor(block, in, T1, 16);
        dec(key1, block, block);
        gmssl_memxor(block, block, T1, 16);

        in += 16;
        inlen -= 16;

        memcpy(out + 16, block, inlen);
        memcpy(block, in, inlen);

        gmssl_memxor(block, block, T, 16);
        dec(key1, block, block);
        gmssl_memxor(out, block, T, 16);
    }

    return 1;
}
