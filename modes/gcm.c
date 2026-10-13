
#include "gcm.h"
#include <string.h>
#include <stdlib.h>

static inline uint64_t cc_swap_u64(uint64_t x)
{
    return (x & 0x00000000000000FFULL) << 56 |
           (x & 0x000000000000FF00ULL) << 40 |
           (x & 0x0000000000FF0000ULL) << 24 |
           (x & 0x00000000FF000000ULL) << 8 |
           (x & 0x000000FF00000000ULL) >> 8 |
           (x & 0x0000FF0000000000ULL) >> 24 |
           (x & 0x00FF000000000000ULL) >> 40 |
           (x & 0xFF00000000000000ULL) >> 56;
}

#define PACK(s) ((size_t)(s) << (sizeof(size_t) * 8 - 16))
#define REDUCE1BIT(V)                                                       \
    do                                                                      \
    {                                                                       \
        if (sizeof(size_t) == 8)                                            \
        {                                                                   \
            uint64_t T = (uint64_t)(0xe100000000000000) & (0 - (V.lo & 1)); \
            V.lo = (V.hi << 63) | (V.lo >> 1);                              \
            V.hi = (V.hi >> 1) ^ T;                                         \
        }                                                                   \
        else                                                                \
        {                                                                   \
            uint32_t T = 0xe1000000U & (0 - (uint32_t)(V.lo & 1));          \
            V.lo = (V.hi << 63) | (V.lo >> 1);                              \
            V.hi = (V.hi >> 1) ^ ((uint64_t)T << 32);                       \
        }                                                                   \
    } while (0)

static void gcm_init_4bit(u128 Htable[16], const uint64_t H[2])
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

static void gcm_gmult_4bit(uint64_t Xi[2], const u128 Htable[16])
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
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    Xi[0] = cc_swap_u64(Z.hi);
    Xi[1] = cc_swap_u64(Z.lo);
#else
    Xi[0] = Z.hi;
    Xi[1] = Z.lo;
#endif
}

/**
 * @brief 异或 Z = X ^ Y
 *
 * @param Z
 * @param X
 * @param Y
 * @param len (in bytes)
 */
static inline void XOR(uint8_t *Z, const uint8_t *X, const uint8_t *Y, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        Z[i] = X[i] ^ Y[i];
    }
}

/**
 * @brief 128bit 异或 Z = X ^ Y
 *
 * 只用于本模块自己声明的 16 字节缓冲区（已声明为 uint64_t[2]，8 字节对齐），
 * 因此可以安全地按 64bit 访问。调用方传入的 in/out 缓冲区对齐不可知，
 * 不能用这个函数，统一用字节方式的 XOR()。
 */
static inline void XOR128(uint64_t Z[2], const uint64_t X[2], const uint64_t Y[2])
{
    Z[0] = X[0] ^ Y[0];
    Z[1] = X[1] ^ Y[1];
}

static void ghash_init(GHASH_CTX *ctx, const uint64_t H[2])
{
    uint64_t H_u64[2];

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    H_u64[0] = cc_swap_u64(H[0]);
    H_u64[1] = cc_swap_u64(H[1]);
#else
    H_u64[0] = H[0];
    H_u64[1] = H[1];
#endif
    gcm_init_4bit(ctx->Htable, H_u64);
    memset(ctx->Y, 0, 16);
    ctx->total_len = 0;
}
static void ghash_update(GHASH_CTX *ctx, const uint8_t *X, int Xlen)
{
    if (Xlen <= 0)
    {
        return;
    }
    int buf_len = (int)(ctx->total_len % 16);
    ctx->total_len += (uint64_t)Xlen;

    if (buf_len > 0)
    {
        if ((buf_len + Xlen) < 16)
        {
            memcpy((uint8_t *)ctx->buf + buf_len, X, Xlen);
            return;
        }
        else
        {
            int copy_len = 16 - buf_len;
            memcpy((uint8_t *)ctx->buf + buf_len, X, copy_len);
            XOR128(ctx->Y, ctx->Y, ctx->buf);
            gcm_gmult_4bit(ctx->Y, ctx->Htable);
            X += copy_len;
            Xlen -= copy_len;
        }
    }

    while (Xlen >= 16)
    {
        /* X 是调用方缓冲区，对齐不可知，按字节异或 */
        XOR((uint8_t *)ctx->Y, (const uint8_t *)ctx->Y, X, 16);
        gcm_gmult_4bit(ctx->Y, ctx->Htable);
        X += 16;
        Xlen -= 16;
    }
    if (Xlen > 0)
    {
        memcpy(ctx->buf, X, Xlen);
    }
}
static int ghash_final(const GHASH_CTX *ctx, uint8_t *Y)
{
    if (ctx->total_len % 16 != 0)
    {
        return -1;
    }
    memcpy(Y, ctx->Y, 16);
    return 0;
}

/**
 * @brief 计数器低32bit自增1
 *
 * @param CTR 计数器值
 * @param len CTR长度(in bytes)
 */
static void inc32(uint8_t CTR[16])
{
    int i = 15;
    CTR[i]++;
    while (CTR[i] == 0 && i > 12)
    {
        i--;
        CTR[i]++;
    }
}
static void gctr_init(GCTR_CTX *ctx, const uint8_t *K, int K_len, const void *ICB, cipher_f cipher)
{
    ctx->K_len = K_len;
    memcpy(ctx->K, K, K_len);
    memcpy(ctx->CB, ICB, 16);
    ctx->total_len = 0;
    ctx->cipher = cipher;
}

static void gctr_update(GCTR_CTX *ctx, const uint8_t *X, int Xlen, uint8_t *Y, int *Ylen)
{
    __align4 uint8_t T[16];

    *Ylen = 0;
    if (Xlen <= 0)
    {
        return;
    }

    int buf_len = (int)(ctx->total_len % 16);
    ctx->total_len += (uint64_t)Xlen;
    cipher_f cipher = ctx->cipher;

    if (buf_len > 0)
    {
        if ((buf_len + Xlen) < 16)
        {
            memcpy((uint8_t *)ctx->buf + buf_len, X, Xlen);
            return;
        }
        else
        {
            int copy_len = 16 - buf_len;
            memcpy((uint8_t *)ctx->buf + buf_len, X, copy_len);

            cipher(ctx->K, (uint8_t *)ctx->CB, T);
            /* Y 是调用方缓冲区，对齐不可知，按字节异或 */
            XOR(Y, (const uint8_t *)ctx->buf, T, 16);
            X += copy_len;
            Xlen -= copy_len;
            Y += 16;
            *Ylen += 16;
            inc32((uint8_t *)ctx->CB);
        }
    }

    while (Xlen >= 16)
    {
        cipher(ctx->K, (uint8_t *)ctx->CB, T);
        /* X、Y 都是调用方缓冲区，按字节异或 */
        XOR(Y, X, T, 16);
        X += 16;
        Xlen -= 16;
        Y += 16;
        *Ylen += 16;
        inc32((uint8_t *)ctx->CB);
    }
    if (Xlen > 0)
    {
        memcpy(ctx->buf, X, Xlen);
    }
}

static void gctr_final(GCTR_CTX *ctx, uint8_t *Y, int *Ylen)
{
    __align4 uint8_t T[16];

    *Ylen = 0;
    int buf_len = (int)(ctx->total_len % 16);
    if (buf_len > 0)
    {
        ctx->cipher(ctx->K, (uint8_t *)ctx->CB, T);
        XOR(Y, (const uint8_t *)ctx->buf, T, buf_len);
        *Ylen += buf_len;
    }
}

/**
 * @brief uint64转uint8数组
 *
 * @param X uint64数据
 * @param Y uint8数组
 */
static inline void u64_2_u8(uint64_t X, uint8_t *Y)
{
    Y[0] = (uint8_t)(X >> 56);
    Y[1] = (uint8_t)(X >> 48);
    Y[2] = (uint8_t)(X >> 40);
    Y[3] = (uint8_t)(X >> 32);
    Y[4] = (uint8_t)(X >> 24);
    Y[5] = (uint8_t)(X >> 16);
    Y[6] = (uint8_t)(X >> 8);
    Y[7] = (uint8_t)(X >> 0);
}
void gcm_init(GCM_CTX *ctx, cipher_f cipher, GCM_ENC_DEC_MODE enc_dec,
              const uint8_t *K, int K_len, const uint8_t *IV, int IV_len, int TAG_len)
{
    if ((TAG_len < 4) || (TAG_len > 16))
    {
        return;
    }

    ctx->enc_dec = enc_dec;
    ctx->tag_len = TAG_len;
    ctx->AAD_len = 0;

    /* 16 字节缓冲区都用对齐的基本类型声明，配合字节视图访问，
       既不会出现未对齐访问，也不会有严格别名问题 */
    uint64_t H[2] = {0};
    cipher(K, (uint8_t *)H, (uint8_t *)H);

    uint64_t J0[2] = {0};
    uint8_t *J0_u8 = (uint8_t *)J0; /* 字符类型的字节视图是合法的 */
    if (IV_len == 12)
    {
        memcpy(J0_u8, IV, 12);
        J0_u8[12] = 0;
        J0_u8[13] = 0;
        J0_u8[14] = 0;
        J0_u8[15] = 1;
    }
    else
    {
        GHASH_CTX ghash_ctx;
        __align4 uint8_t pad[16] = {0};
        int s = IV_len % 16;

        ghash_init(&ghash_ctx, H);
        ghash_update(&ghash_ctx, IV, IV_len);
        if (s != 0)
        {
            ghash_update(&ghash_ctx, pad, 16 - s);
        }
        uint64_t bit_len = (uint64_t)IV_len * 8;
        u64_2_u8(bit_len, pad + 8);
        ghash_update(&ghash_ctx, pad, 16);
        ghash_final(&ghash_ctx, J0_u8);
    }
    memcpy(ctx->J0, J0, 16);
    inc32(J0_u8);
    gctr_init(&(ctx->gctr), K, K_len, J0, cipher);
    ghash_init(&(ctx->ghash), H);
}

void gcm_updateAAD(GCM_CTX *ctx, const uint8_t *AAD, int AAD_len, bool is_last)
{
    if (AAD_len > 0)
    {
        ctx->AAD_len += (uint64_t)AAD_len;
        ghash_update(&(ctx->ghash), AAD, AAD_len);
    }

    if (is_last)
    {
        int rest_len = (int)(ctx->ghash.total_len % 16);
        if (rest_len > 0)
        {
            __align4 uint8_t pad[16] = {0};
            ghash_update(&(ctx->ghash), pad, 16 - rest_len);
        }
    }
}

void gcm_update(GCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    if (ctx->enc_dec == GCM_ENCRYPT)
    {
        gctr_update(&(ctx->gctr), in, in_len, out, out_len);
        ghash_update(&(ctx->ghash), out, *out_len);
    }
    else if (ctx->enc_dec == GCM_DECRYPT)
    {
        ghash_update(&(ctx->ghash), in, in_len);
        gctr_update(&(ctx->gctr), in, in_len, out, out_len);
    }
}

static void gcm_retrieve_tag(GCM_CTX *ctx, uint8_t *tag, int tag_len)
{
    uint64_t AAD_len = ctx->AAD_len;
    uint64_t in_len = ctx->gctr.total_len;
    uint64_t rest_len = in_len % 16;
    uint8_t pad[16] = {0};
    if (rest_len > 0)
    {
        ghash_update(&(ctx->ghash), pad, (int)(16 - rest_len));
    }
    uint64_t A_bit_len = AAD_len * 8;
    uint64_t in_bit_len = in_len * 8;
    u64_2_u8(A_bit_len, pad);
    u64_2_u8(in_bit_len, pad + 8);
    ghash_update(&(ctx->ghash), pad, 16);

    __align4 uint8_t S[16], T1[16];
    ghash_final(&(ctx->ghash), S);

    int tmp_len = 0;
    GCTR_CTX gctr;
    gctr_init(&gctr, ctx->gctr.K, ctx->gctr.K_len, ctx->J0, ctx->gctr.cipher);
    gctr_update(&gctr, S, 16, T1, &tmp_len);
    gctr_final(&gctr, T1 + tmp_len, &tmp_len);
    memcpy(tag, T1, tag_len);
}

void gcm_final(GCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *Tag)
{
    gctr_final(&(ctx->gctr), out, out_len);

    if (ctx->enc_dec == GCM_ENCRYPT)
    {
        ghash_update(&(ctx->ghash), out, *out_len);
    }
    gcm_retrieve_tag(ctx, Tag, ctx->tag_len);
}
