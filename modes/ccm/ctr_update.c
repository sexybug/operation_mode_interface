
#include "ctr_update.h"
#include <string.h>

/**
 * @brief Z = X XOR Y
 *
 * @param Z
 * @param X
 * @param Y
 * @param len
 */
static void XOR(uint8_t *Z, const uint8_t *X, const uint8_t *Y, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        Z[i] = X[i] ^ Y[i];
    }
}
static void ctr_increase(uint8_t *ctr, int ctr_len)
{
    int i;
    for (i = ctr_len - 1; i >= 0; i--)
    {
        ctr[i]++;
        if (ctr[i] != 0)
        {
            break;
        }
    }
}

void ctr_init(CTR_CTX *ctx, cipher_f cipher, const uint8_t *key, int key_len, const uint8_t *ctr, int block_len)
{
    ctx->cipher = cipher;
    memcpy(ctx->key, key, key_len);
    ctx->key_len = key_len;
    memcpy(ctx->ctr, ctr, block_len);
    ctx->block_len = block_len;
    ctx->total_len = 0;
}

void ctr_update(CTR_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    *out_len = 0;
    if (in_len <= 0)
    {
        return;
    }
    int block_len = ctx->block_len;
    int buf_len = ctx->total_len % block_len;
    ctx->total_len += in_len;
    if (buf_len > 0)
    {
        if ((buf_len + in_len) < block_len)
        {
            memcpy(ctx->in_buf, in, in_len);
            return;
        }
        else
        {
            int copy_len = block_len - buf_len;
            memcpy(ctx->in_buf + buf_len, in, copy_len);

            ctx->cipher(ctx->key, ctx->ctr, out);
            XOR(out, out, ctx->in_buf, block_len);
            ctr_increase(ctx->ctr, block_len);

            in += copy_len;
            in_len -= copy_len;
            out += block_len;
            *out_len += block_len;
        }
    }
    while (in_len >= block_len)
    {
        ctx->cipher(ctx->key, ctx->ctr, out);
        XOR(out, out, in, block_len);
        ctr_increase(ctx->ctr, block_len);

        in += block_len;
        in_len -= block_len;
        out += block_len;
        *out_len += block_len;
    }
    if (in_len > 0)
    {
        memcpy(ctx->in_buf, in, in_len);
    }
}

void ctr_final(CTR_CTX *ctx, uint8_t *out, int *out_len)
{
    *out_len = 0;
    int block_len = ctx->block_len;
    int rest_len = ctx->total_len % block_len;
    if (rest_len > 0)
    {
        __align4 uint8_t T[16];
        ctx->cipher(ctx->key, ctx->ctr, T);
        XOR(out, T, ctx->in_buf, rest_len);
        ctr_increase(ctx->ctr, block_len);
        *out_len += rest_len;
    }
}
