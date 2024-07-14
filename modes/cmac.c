#include "cmac.h"
#include <string.h>

static const uint8_t zero[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t R128[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};
static const uint8_t R64[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B};

/**
 * @brief 异或 Z = X ^ Y
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
 * @brief CMAC派生 K1 and K2
 *
 * @param enc 分组算法加密函数
 * @param b 分组长度（in bytes）
 * @param K 输入密钥
 * @param K1
 * @param K2
 */
static void SUBK(block_f_ptr enc, int b, const uint8_t *K, uint8_t *K1, uint8_t *K2)
{
    uint8_t L[16];
    const uint8_t *Rb;
    if (b == 8)
    {
        Rb = R64;
    }
    else
    {
        Rb = R128;
    }

    // 1. L = CIPHK(0)
    enc(K, zero, L);

    // 2. K1
    left_move_n_bit(L, b * 8, 1, K1);
    if (L[0] & 0x80)
    {
        XOR(K1, Rb, b, K1);
    }

    // 3. K2
    left_move_n_bit(K1, b * 8, 1, K2);
    if (K1[0] & 0x80)
    {
        XOR(K2, Rb, b, K2);
    }
}

/**
 * @brief CMAC算法
 *
 * @param enc 分组算法加密函数
 * @param b 分组长度（in bytes）
 * @param K
 * @param M
 * @param Mlen 消息长度（in bytes）
 * @param T MAC
 */
void cmac(block_f_ptr enc, int b, const uint8_t *K, const uint8_t *M, int Mlen, uint8_t *T)
{
    uint8_t K1[16], K2[16], C[16], Mn[16];
    int n;
    // 1.
    SUBK(enc, b, K, K1, K2);

    // 2.
    if (Mlen == 0)
    {
        n = 1;
    }
    else
    {
        n = (Mlen + b - 1) / b;
    }

    memset(C, 0, b);

    int i = 1;
    while (i < n)
    {
        XOR(C, M, b, C);
        enc(K, C, C);

        M += b;
        i += 1;
    }

    int rest = Mlen % b;
    if ((Mlen > 0) && (rest == 0))
    {
        XOR(K1, M, b, Mn);
    }
    else
    {
        memcpy(Mn, M, rest);
        Mn[rest] = 0x80;
        memset(Mn + rest + 1, 0, b - rest - 1);
        XOR(K2, Mn, b, Mn);
    }

    XOR(C, Mn, b, C);
    enc(K, C, T);
}