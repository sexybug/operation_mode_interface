
#include "cfb.h"
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

/**
 * @brief 将字节数组左移n位，低位补0
 *
 * @param src 字节数组
 * @param src_bit_len 字节数组长度
 * @param n 移位位数
 * @param dst 输出
 */
static void left_move_n_bit(const uint8_t *src, int src_bit_len, int n, uint8_t *dst)
{
    int i;
    int stat_index = n / 8;
    int left_move_bit = n % 8;
    int right_move_bit = 8 - left_move_bit;

    for (i = 0; i < (src_bit_len - n) / 8; i++)
    {
        dst[i] = (src[stat_index + i] << left_move_bit) | (src[stat_index + i + 1] >> right_move_bit);
    }
    if ((src_bit_len - n) % 8 != 0)
    {
        dst[i] = src[stat_index + i] << left_move_bit;
        i++;
    }
    for (; i < src_bit_len / 8; i++)
    {
        dst[i] = 0;
    }
}

/**
 * @brief update feedback buffer with F
 *
 * @param FB feedback buffer
 * @param FB_len feedback buffer length (in bytes)
 * @param F
 * @param F_len
 */
static void update_FB(uint8_t *FB, int FB_len, const uint8_t *F, int F_len)
{
    int i, j;
    for (i = 0; i < FB_len - F_len; i++)
    {
        FB[i] = FB[i + F_len];
    }
    j = 0;
    while (i < FB_len)
    {
        FB[i] = F[j];
        i++;
        j++;
    }
}

// CFB反馈1bit加密
static void cfb_enc_fb1(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int bit_len, uint8_t *C)
{
    uint8_t Y[16], FB[16];

    int i = 0, q = bit_len / 8;
    int rest_bit = bit_len % 8;
    memcpy(FB, IV, n);
    while (i < q)
    {
        uint16_t temp = P[i];
        for (int j = 0; j < 8; j++)
        {
            enc(K, FB, Y);
            temp = (temp ^ (Y[0] & 0x80)) << 1;
            left_move_n_bit(FB, n * 8, 1, FB);
            FB[n - 1] = FB[n - 1] | ((temp & 0x0100) >> 8);
        }
        C[i] = temp >> 8;
        i++;
    }
    if (rest_bit != 0)
    {
        uint16_t temp = P[i];
        for (int j = 0; j < rest_bit; j++)
        {
            enc(K, FB, Y);
            temp = (temp ^ (Y[0] & 0x80)) << 1;
            left_move_n_bit(FB, n * 8, 1, FB);
            FB[n - 1] = FB[n - 1] | ((temp & 0x0100) >> 8);
        }
        C[i] = (temp >> 8) << (8 - rest_bit);
    }
}
// CFB反馈1bit解密
static void cfb_dec_fb1(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int bit_len, uint8_t *P)
{
    uint8_t Y[16], FB[16];

    int i = 0, q = bit_len / 8;
    int rest_bit = bit_len % 8;
    memcpy(FB, IV, n);
    while (i < q)
    {
        uint16_t temp = C[i];
        for (int j = 0; j < 8; j++)
        {
            enc(K, FB, Y);
            temp = (temp ^ (Y[0] & 0x80)) << 1;
            left_move_n_bit(FB, n * 8, 1, FB);
            FB[n - 1] = FB[n - 1] | ((C[i] >> (7 - j)) & 0x01);
        }
        P[i] = temp >> 8;
        i++;
    }
    if (rest_bit != 0)
    {
        uint16_t temp = C[i];
        for (int j = 0; j < rest_bit; j++)
        {
            enc(K, FB, Y);
            temp = (temp ^ (Y[0] & 0x80)) << 1;
            left_move_n_bit(FB, n * 8, 1, FB);
            FB[n - 1] = FB[n - 1] | ((C[i] >> (7 - j)) & 0x01);
        }
        P[i] = (temp >> 8) << (8 - rest_bit);
    }
}

void cfb_enc(block_f_ptr enc, int n, int k, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int bit_len, uint8_t *C)
{
    if (k == 1)
    {
        cfb_enc_fb1(enc, n, K, IV, P, bit_len, C);
        return;
    }
    uint8_t Y[16], FB[16];
    int fb_byte_num = k / 8;
    int i = 1, q = bit_len / k, rest_byte_len = (bit_len % k) / 8;
    memcpy(FB, IV, n);
    while (i <= q)
    {
        enc(K, FB, Y);
        XOR(P, Y, fb_byte_num, C);
        update_FB(FB, n, C, fb_byte_num);

        P += fb_byte_num;
        C += fb_byte_num;
        i++;
    }
    if (rest_byte_len != 0)
    {
        enc(K, FB, Y);
        XOR(P, Y, rest_byte_len, C);
    }
}

void cfb_dec(block_f_ptr enc, int n, int k, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int bit_len, uint8_t *P)
{
    if (k == 1)
    {
        cfb_dec_fb1(enc, n, K, IV, C, bit_len, P);
        return;
    }
    uint8_t Y[16], FB[16];
    int fb_byte_num = k / 8;
    int i = 1, q = bit_len / k, rest_byte_len = (bit_len % k) / 8;
    memcpy(FB, IV, n);
    while (i <= q)
    {
        enc(K, FB, Y);
        XOR(C, Y, fb_byte_num, P);
        update_FB(FB, n, C, fb_byte_num);

        C += fb_byte_num;
        P += fb_byte_num;
        i++;
    }
    if (rest_byte_len != 0)
    {
        enc(K, FB, Y);
        XOR(C, Y, rest_byte_len, P);
    }
}