
#include "cbc_mac_update.h"
#include <string.h>

static void XOR(uint8_t *Z, const uint8_t *X, const uint8_t *Y, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        Z[i] = X[i] ^ Y[i];
    }
}

void cbc_mac_init(CBC_MAC_CTX *ctx, cipher_f cipher, const uint8_t *key, int key_len, int block_len)
{
    memcpy(ctx->key, key, key_len);
    ctx->block_len = block_len;
    ctx->total_len = 0;
    ctx->cipher = cipher;
    memset(ctx->mac_buf, 0, block_len);
}

void cbc_mac_update(CBC_MAC_CTX *ctx, const uint8_t *in, int in_len)
{
    if (in_len <= 0)
    {
        return;
    }

    int block_len = ctx->block_len;
    int buf_len = ctx->total_len % block_len;
    ctx->total_len += in_len;
    uint8_t *T = ctx->mac_buf;
    if (buf_len > 0)
    {
        if ((buf_len + in_len) < block_len)
        {
            memcpy(ctx->in_buf + buf_len, in, in_len);
            return;
        }
        else
        {
            int copy_len = block_len - buf_len;
            memcpy(ctx->in_buf + buf_len, in, copy_len);

            XOR(T, T, ctx->in_buf, block_len);
            ctx->cipher(ctx->key, T, T);

            in += copy_len;
            in_len -= copy_len;
        }
    }
    while (in_len >= block_len)
    {
        XOR(T, T, in, block_len);
        ctx->cipher(ctx->key, T, T);

        in += block_len;
        in_len -= block_len;
    }
    if (in_len > 0)
    {
        memcpy(ctx->in_buf, in, in_len);
    }
}

void cbc_mac_final(CBC_MAC_CTX *ctx, uint8_t *mac)
{
    int block_len = ctx->block_len;
    int buf_len = ctx->total_len % block_len;
    uint8_t *T = ctx->mac_buf;
    if (buf_len > 0)
    {
        memset(ctx->in_buf + buf_len, 0, block_len - buf_len);
        XOR(T, T, ctx->in_buf, block_len);
        ctx->cipher(ctx->key, T, T);

        ctx->total_len += (block_len - buf_len);
    }
    memcpy(mac, T, block_len);
}