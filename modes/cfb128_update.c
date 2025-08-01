
#include "cfb128_update.h"
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

void cfb128_init(CFB128_CTX *ctx, cipher_f cipher, ENC_DEC_MODE mode, const uint8_t *key, int key_len, const uint8_t *iv, int block_len)
{
    ctx->mode = mode;
    ctx->cipher = cipher;
    memcpy(ctx->key, key, key_len);
    memcpy(ctx->iv, iv, block_len);
    ctx->block_len = block_len;
    ctx->total_len = 0;
}

void cfb128_update(CFB128_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    __align4 uint8_t T[16];
    
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

            ctx->cipher(ctx->key, ctx->iv, T);
            XOR(out, T, ctx->in_buf, block_len);
            if (ctx->mode == ENCRYPT)
            {
                memcpy(ctx->iv, out, block_len);
            }
            else
            {
                memcpy(ctx->iv, in, block_len);
            }

            in += copy_len;
            in_len -= copy_len;
            out += block_len;
            *out_len += block_len;
        }
    }
    while (in_len >= block_len)
    {
        ctx->cipher(ctx->key, ctx->iv, T);
        XOR(out, T, in, block_len);
        if (ctx->mode == ENCRYPT)
        {
            memcpy(ctx->iv, out, block_len);
        }
        else
        {
            memcpy(ctx->iv, in, block_len);
        }

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

void cfb128_final(CFB128_CTX *ctx, uint8_t *out, int *out_len)
{
    __align4 uint8_t T[16];
    
    *out_len = 0;
    int block_len = ctx->block_len;
    int rest_len = ctx->total_len % block_len;
    if (rest_len > 0)
    {
        ctx->cipher(ctx->key, ctx->iv, T);
        XOR(out, T, ctx->in_buf, rest_len);
        *out_len += rest_len;
    }
}
