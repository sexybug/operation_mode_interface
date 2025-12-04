
#include "gcm128.h"
#include <string.h>
#include <stdlib.h>

#define BSWAP8(x) _byteswap_uint64((uint64_t)(x))

#define PACK(s) ((size_t)(s) << (sizeof(size_t) * 8 - 16))
#define REDUCE1BIT(V)                                           \
    do                                                          \
    {                                                           \
        if (sizeof(size_t) == 8)                                \
        {                                                       \
            uint64_t T = (uint64_t)(0xe100000000000000) & (0 - (V.lo & 1)); \
            V.lo = (V.hi << 63) | (V.lo >> 1);                  \
            V.hi = (V.hi >> 1) ^ T;                             \
        }                                                       \
        else                                                    \
        {                                                       \
            uint32_t T = 0xe1000000U & (0 - (uint32_t)(V.lo & 1));        \
            V.lo = (V.hi << 63) | (V.lo >> 1);                  \
            V.hi = (V.hi >> 1) ^ ((uint64_t)T << 32);                \
        }                                                       \
    } while (0)

void gcm_init_4bit(u128 Htable[16], const uint64_t H[2])
{
    u128 V;

    Htable[0].hi = 0;
    Htable[0].lo = 0;
    V.hi = H[0];
    V.lo = H[1];

    Htable[8] = V;
    REDUCE1BIT(V);
    Htable[4] = V;
    REDUCE1BIT(V);
    Htable[2] = V;
    REDUCE1BIT(V);
    Htable[1] = V;
    Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
    V = Htable[4];
    Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
    Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
    Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
    V = Htable[8];
    Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
    Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
    Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
    Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
    Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
    Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
    Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;
}

static const size_t rem_4bit[16] = {
    PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460),
    PACK(0x7080), PACK(0x6CA0), PACK(0x48C0), PACK(0x54E0),
    PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
    PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0)};

void gcm_gmult_4bit(uint64_t Xi[2], const u128 Htable[16])
{
    u128 Z;
    int cnt = 15;
    size_t rem, nlo, nhi;

    nlo = ((const uint8_t *)Xi)[15];
    nhi = nlo >> 4;
    nlo &= 0xf;

    Z.hi = Htable[nlo].hi;
    Z.lo = Htable[nlo].lo;

    while (1)
    {
        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (uint64_t)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nhi].hi;
        Z.lo ^= Htable[nhi].lo;

        if (--cnt < 0)
            break;

        nlo = ((const uint8_t *)Xi)[cnt];
        nhi = nlo >> 4;
        nlo &= 0xf;

        rem = (size_t)Z.lo & 0xf;
        Z.lo = (Z.hi << 60) | (Z.lo >> 4);
        Z.hi = (Z.hi >> 4);
        if (sizeof(size_t) == 8)
            Z.hi ^= rem_4bit[rem];
        else
            Z.hi ^= (uint64_t)rem_4bit[rem] << 32;

        Z.hi ^= Htable[nlo].hi;
        Z.lo ^= Htable[nlo].lo;
    }

    Xi[0] = BSWAP8(Z.hi);
    Xi[1] = BSWAP8(Z.lo);
}

int main2()
{
    u128 Htable[16];

    uint8_t H[16] = {0};
    uint8_t X[16] = {0};
    for (int i = 0; i < 16; i++)
    {
        H[i] = i;
        X[i] = i;
    }

    u128 h;
    int i;
    h.hi = (uint64_t)H[0] << 56 | (uint64_t)H[1] << 48 | (uint64_t)H[2] << 40 | (uint64_t)H[3] << 32 | (uint64_t)H[4] << 24 | (uint64_t)H[5] << 16 | (uint64_t)H[6] << 8 | (uint64_t)H[7];
    h.lo = (uint64_t)H[8] << 56 | (uint64_t)H[9] << 48 | (uint64_t)H[10] << 40 | (uint64_t)H[11] << 32 | (uint64_t)H[12] << 24 | (uint64_t)H[13] << 16 | (uint64_t)H[14] << 8 | (uint64_t)H[15];

    gcm_init_4bit(Htable, &h);

    gcm_gmult_4bit(X, Htable);

    for (int i = 0; i < 16; i++)
    {
        printf("%02x", X[i]);
    }
    return 0;
}