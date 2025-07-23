
#include "gcm.h"
#include <string.h>

/**
 * @brief GF(2^128)上的本原多项式
 *
 */
static const uint8_t R[16] = {0xE1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/**
 * @brief 异或 Z = X ^ Y
 *
 * @param Z
 * @param X
 * @param Y
 * @param len (in bytes)
 */
static void XOR(uint8_t *Z, const uint8_t *X, const uint8_t *Y, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        Z[i] = X[i] ^ Y[i];
    }
}

/**
 * @brief 获取比特串S左边起第i个比特，以0为起始位置
 * example: bit(0101010101010101,9)=1
 *
 * @param S
 * @param i
 * @return uint8_t 0x00 or 0x01
 */
static inline uint8_t bit(const uint8_t *S, int i)
{
    return (S[i / 8] & (0x80 >> (i % 8))) >> ((8 - (i + 1) % 8) % 8);
}

/**
 * @brief 字节串X整体右移1比特，左侧补0
 *
 * @param X
 * @param len X length (in bytes)
 */
static void right_move1(uint8_t *X, int len)
{
    int i;
    for (i = len - 1; i >= 1; i--)
    {
        X[i] = (X[i - 1] << 7) | (X[i] >> 1);
    }
    X[0] = X[0] >> 1;
}
/**
 * @brief GF(2^128)有限域乘法，Z = X (*) Y, 以G为本原多项式
 * X和Z不能为同一数组，gf128_mul(Z,Z,Y) will cause error.
 *
 * @param Z
 * @param X
 * @param Y
 */
static void gf128_mul(uint8_t *Z, const uint8_t *X, const uint8_t *Y)
{
    int i;
    uint8_t V[16];

    memset(Z, 0, 16);
    memcpy(V, Y, 16);

    for (i = 0; i <= 127; i++)
    {
        if (bit(X, i) == 0x01)
        {
            XOR(Z, Z, V, 16);
        }
        if (bit(V, 127) == 0x00)
        {
            right_move1(V, 16);
        }
        else
        {
            right_move1(V, 16);
            XOR(V, V, R, 16);
        }
    }
}

static void ghash_init(GHASH_CTX *ctx, const uint8_t *H)
{
    memcpy(ctx->H, H, 16);
    memset(ctx->Y, 0, 16);
    ctx->total_len = 0;
}
static void ghash_update(GHASH_CTX *ctx, const uint8_t *X, int Xlen)
{
    if (Xlen <= 0)
    {
        return;
    }
    uint8_t T[16];
    int buf_len = ctx->total_len % 16;
    ctx->total_len += Xlen;

    if (buf_len > 0)
    {
        if ((buf_len + Xlen) < 16)
        {
            memcpy(ctx->buf + buf_len, X, Xlen);
            return;
        }
        else
        {
            int copy_len = 16 - buf_len;
            memcpy(ctx->buf + buf_len, X, copy_len);
            XOR(T, ctx->Y, ctx->buf, 16);
            gf128_mul(ctx->Y, T, ctx->H);
            X += copy_len;
            Xlen -= copy_len;
        }
    }

    while (Xlen >= 16)
    {
        XOR(T, ctx->Y, X, 16);
        gf128_mul(ctx->Y, T, ctx->H);
        X += 16;
        Xlen -= 16;
    }
    if (Xlen > 0)
    {
        memcpy(ctx->buf, X, Xlen);
    }
}
static int ghash_final(GHASH_CTX *ctx, uint8_t *Y)
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
static void inc32(uint8_t *CTR)
{
    int i = 15;
    CTR[i]++;
    while (CTR[i] == 0 && i > 12)
    {
        i--;
        CTR[i]++;
    }
}
static void gctr_init(GCTR_CTX *ctx, const uint8_t *K, int K_len, const uint8_t *ICB, cipher_f cipher)
{
    ctx->K_len = K_len;
    memcpy(ctx->K, K, K_len);
    memcpy(ctx->CB, ICB, 16);
    ctx->total_len = 0;
    ctx->cipher = cipher;
}

static void gctr_update(GCTR_CTX *ctx, const uint8_t *X, int Xlen, uint8_t *Y, int *Ylen)
{
    *Ylen = 0;
    if (Xlen <= 0)
    {
        return;
    }

    int buf_len = ctx->total_len % 16;
    ctx->total_len += Xlen;
    cipher_f cipher = ctx->cipher;

    if (buf_len > 0)
    {
        if ((buf_len + Xlen) < 16)
        {
            memcpy(ctx->buf + buf_len, X, Xlen);
            return;
        }
        else
        {
            int copy_len = 16 - buf_len;
            memcpy(ctx->buf + buf_len, X, copy_len);

            cipher(ctx->K, ctx->CB, Y);
            XOR(Y, ctx->buf, Y, 16);
            X += copy_len;
            Xlen -= copy_len;
            Y += 16;
            *Ylen += 16;
            inc32(ctx->CB);
        }
    }

    while (Xlen >= 16)
    {
        cipher(ctx->K, ctx->CB, Y);
        XOR(Y, X, Y, 16);
        X += 16;
        Xlen -= 16;
        Y += 16;
        *Ylen += 16;
        inc32(ctx->CB);
    }
    if (Xlen > 0)
    {
        memcpy(ctx->buf, X, Xlen);
    }
}

static void gctr_final(GCTR_CTX *ctx, uint8_t *Y, int *Ylen)
{
    *Ylen = 0;
    int buf_len = ctx->total_len % 16;
    if (buf_len > 0)
    {
        __align4 uint8_t T[16];
        ctx->cipher(ctx->K, ctx->CB, T);
        XOR(Y, ctx->buf, T, buf_len);
        *Ylen += buf_len;
    }
}

/**
 * @brief uint64转uint8数组
 *
 * @param X uint64数据
 * @param Y uint8数组
 */
static void u64_2_u8(uint64_t X, uint8_t *Y)
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

    __align4 uint8_t H[16];
    memset(H, 0, 16);
    cipher(K, H, H);

    uint8_t J0[16];
    if (IV_len == 12)
    {
        memcpy(J0, IV, 12);
        J0[12] = 0;
        J0[13] = 0;
        J0[14] = 0;
        J0[15] = 1;
    }
    else
    {
        GHASH_CTX ghash_ctx;
        uint8_t pad[16];
        int s = IV_len % 16;

        ghash_init(&ghash_ctx, H);
        ghash_update(&ghash_ctx, IV, IV_len);
        if (s != 0)
        {
            memset(pad, 0, 16 - s);
            ghash_update(&ghash_ctx, pad, 16 - s);
        }
        memset(pad, 0, 8);
        uint64_t bit_len = IV_len * 8;
        u64_2_u8(bit_len, pad + 8);
        ghash_update(&ghash_ctx, pad, 16);
        ghash_final(&ghash_ctx, J0);
    }
    memcpy(ctx->J0, J0, 16);
    inc32(J0);
    gctr_init(&(ctx->gctr), K, K_len, J0, cipher);
    ghash_init(&(ctx->ghash), H);
}

void gcm_updateAAD(GCM_CTX *ctx, const uint8_t *AAD, int AAD_len, bool is_last)
{
    if (AAD_len > 0)
    {
        ctx->AAD_len += AAD_len;
        ghash_update(&(ctx->ghash), AAD, AAD_len);
    }

    if (is_last)
    {
        int A_len = ctx->ghash.total_len;
        int rest_len = A_len % 16;
        if (rest_len > 0)
        {
            uint8_t pad[16];
            memset(pad, 0, 16 - rest_len);
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
    int AAD_len = ctx->AAD_len;
    int in_len = ctx->gctr.total_len;
    int rest_len = in_len % 16;
    uint8_t pad[16];
    if (rest_len > 0)
    {
        memset(pad, 0, 16 - rest_len);
        ghash_update(&(ctx->ghash), pad, 16 - rest_len);
    }
    uint64_t A_bit_len = (uint64_t)AAD_len * 8;
    uint64_t in_bit_len = (uint64_t)in_len * 8;
    u64_2_u8(A_bit_len, pad);
    u64_2_u8(in_bit_len, pad + 8);
    ghash_update(&(ctx->ghash), pad, 16);

    __align4 uint8_t S[16], T1[16];
    ghash_final(&(ctx->ghash), S);

    int T1_len = 0, tmp_len = 0;
    GCTR_CTX gctr;
    gctr_init(&gctr, ctx->gctr.K, ctx->gctr.K_len, ctx->J0, ctx->gctr.cipher);
    gctr_update(&gctr, S, 16, T1, &tmp_len);
    T1_len += tmp_len;
    gctr_final(&gctr, T1 + tmp_len, &tmp_len);
    T1_len += tmp_len;
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
