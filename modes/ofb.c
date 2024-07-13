
#include "ofb.h"
#include <string.h>

/**
 * @brief 字节数组异或 Z = X ^ Y
 *
 * @param X
 * @param Y
 * @param len (in bytes)
 * @param Z
 */
static void XOR(const uint8_t *X, const uint8_t *Y, int len, uint8_t *Z)
{
    for (int i = 0; i < len; i++)
    {
        Z[i] = X[i] ^ Y[i];
    }
}

// OFB反馈1bit加密
void ofb_enc_fb1(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int bit_len, uint8_t *C)
{
    uint8_t X[16], Y[16];

    int i = 0, q = bit_len / 8;
    int rest_bit = bit_len % 8;
    memcpy(X, IV, n);
    while (i < q)
    {
        uint8_t stream = 0; // 8bit密钥流
        for (int j = 0; j < 8; j++)
        {
            enc(K, X, Y);
            stream = (stream << 1) | ((Y[0] & 0x80) >> 7);
            memcpy(X, Y, n);
        }
        C[i] = P[i] ^ stream;
        i++;
    }
    if (rest_bit != 0)
    {
        uint8_t stream = 0; // 8bit密钥流
        for (int j = 0; j < rest_bit; j++)
        {
            enc(K, X, Y);
            stream = (stream << 1) | ((Y[0] & 0x80) >> 7);
            memcpy(X, Y, n);
        }
        C[i] = ((P[i]>>8-rest_bit) ^ stream) << (8 - rest_bit);
    }
}

void ofb_enc(block_f_ptr enc, int n, int k, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int bit_len, uint8_t *C)
{
    if (k == 1)
    {
        ofb_enc_fb1(enc, n, K, IV, P, bit_len, C);
        return;
    }

    uint8_t X[16], Y[16];

    int i = 1, q = bit_len / k;
    int fb_byte_num = k / 8;

    memcpy(X, IV, n);
    while (i <= q)
    {
        enc(K, X, Y);
        XOR(P, Y, fb_byte_num, C);
        memcpy(X, Y, n);

        P += fb_byte_num;
        C += fb_byte_num;
        i++;
    }
}

void ofb_dec(block_f_ptr enc, int n, int k, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int bit_len, uint8_t *P)
{
    ofb_enc(enc, n, k, K, IV, C, bit_len, P);
}