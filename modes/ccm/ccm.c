
#include "ccm.h"
#include <string.h>

static void XOR(uint8_t *Z, const uint8_t *X, const uint8_t *Y, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        Z[i] = X[i] ^ Y[i];
    }
}

static void integer_to_bytes(uint64_t integer, int len, uint8_t *bytes)
{
    while (len > 0)
    {
        bytes[len - 1] = integer & 0xFF;
        integer >>= 8;
        len -= 1;
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

int ccm_init(CCM_CTX *ctx, cipher_f cipher, CCM_ENC_DEC_MODE enc_dec, const uint8_t *key, uint8_t key_len, const uint8_t *nonce, uint8_t nonce_len, uint64_t AData_len, uint64_t message_len, uint8_t tag_len)
{
    if (nonce_len < 7 || nonce_len > 13)
    {
        return -1;
    }
    if (tag_len < 4 || tag_len > 16 || tag_len & 1)
    {
        return -1;
    }
    uint64_t q = 15 - nonce_len;
    if ((q < 8) && (message_len >= ((uint64_t)1 << (q * 8))))
    {
        return -1;
    }

    ctx->enc_dec = enc_dec;
    ctx->tag_len = tag_len;
    cbc_mac_init(&(ctx->cbc_mac), cipher, key, key_len, 16);

    // B0
    __align4 uint8_t B0[16];
    B0[0] = (((AData_len > 0) & 0x01) << 6) | (((tag_len - 2) / 2) << 3) | (q - 1);
    memcpy(B0 + 1, nonce, nonce_len);
    integer_to_bytes(message_len, q, B0 + 1 + nonce_len);
    cbc_mac_update(&(ctx->cbc_mac), B0, 16);

    // a
    if (AData_len > 0)
    {
        uint8_t A[10];
        uint64_t a = AData_len;
        int a_len;
        if (a < ((1 << 16) - (1 << 8)))
        {
            integer_to_bytes(a, 2, A);
            a_len = 2;
        }
        else if (a < ((uint64_t)1 << 32))
        {
            A[0] = 0xff;
            A[1] = 0xfe;
            integer_to_bytes(a, 4, A + 2);
            a_len = 6;
        }
        else
        {
            A[0] = 0xff;
            A[1] = 0xff;
            integer_to_bytes(a, 8, A + 2);
            a_len = 10;
        }
        cbc_mac_update(&(ctx->cbc_mac), A, a_len);
    }

    // CTR0
    __align4 uint8_t Ctr[16];
    Ctr[0] = (q - 1);
    memcpy(Ctr + 1, nonce, nonce_len);
    integer_to_bytes(0, q, Ctr + 1 + nonce_len);
    // S0
    cipher(key, Ctr, ctx->S0);

    ctr_increase(Ctr, 16);
    ctr_init(&(ctx->ctr), cipher, key, key_len, Ctr, 16);

    return 1;
}

void ccm_updateAData(CCM_CTX *ctx, const uint8_t *AData, int len, bool is_last)
{
    if (len > 0)
    {
        cbc_mac_update(&(ctx->cbc_mac), AData, len);
    }
    
    if (is_last)
    {
        uint8_t T[16];
        cbc_mac_final(&(ctx->cbc_mac), T);
    }
}

void ccm_update(CCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len)
{
    if (in_len <= 0)
    {
        *out_len = 0;
        return;
    }
    if (ctx->enc_dec == CCM_ENCRYPT)
    {
        cbc_mac_update(&(ctx->cbc_mac), in, in_len);
        ctr_update(&(ctx->ctr), in, in_len, out, out_len);
    }
    else
    {
        ctr_update(&(ctx->ctr), in, in_len, out, out_len);
        cbc_mac_update(&(ctx->cbc_mac), out, *out_len);
    }
}

void ccm_final(CCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *tag)
{
    ctr_final(&(ctx->ctr), out, out_len);

    if ((ctx->enc_dec == CCM_DECRYPT) && (*out_len > 0))
    {
        cbc_mac_update(&(ctx->cbc_mac), out, *out_len);
    }

    uint8_t T[16];
    cbc_mac_final(&(ctx->cbc_mac), T);
    XOR(tag, T, ctx->S0, ctx->tag_len);
}