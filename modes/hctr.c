#include "hctr.h"
#include <string.h>
#include "ctr.h"

/**
 * @brief GF(2^128)上的本原多项式
 *
 */
static const uint8_t G[16] = {0xE1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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
 * @brief 比特串S左边起第i个比特，以1为起始位置
 *
 * @param S
 * @param i
 * @return uint8_t 0x00 or 0x01
 */
static inline uint8_t bit(const uint8_t *S, int i)
{
    return (S[(i - 1) / 8] & (0x80 >> ((i - 1) % 8))) >> ((8 - i % 8) % 8);
}

/**
 * @brief 字节串X整体右移1比特，左侧补0
 *
 * @param X
 * @param len X length (in bytes)
 */
static void move_right(uint8_t *X, int len)
{
    for (int i = len - 1; i >= 1; i--)
    {
        X[i] = (X[i - 1] << 7) | (X[i] >> 1);
    }
    X[0] = X[0] >> 1;
}
/**
 * @brief GF(2^128)有限域乘法，W = U (X) V, 以G为本原多项式
 *
 * @param U
 * @param V
 * @param W
 */
static void GF2_128_Multiply(const uint8_t *U, const uint8_t *V, uint8_t *W)
{
    uint8_t Z[16], WT[16];

    memset(WT, 0, 16);
    memcpy(Z, U, 16);

    for (int i = 1; i <= 128; i++)
    {
        if (bit(V, i) == 0x01)
        {
            XOR(WT, Z, 16, WT);
        }
        if (bit(Z, 128) == 0x00)
        {
            move_right(Z, 16);
        }
        else
        {
            move_right(Z, 16);
            XOR(Z, G, 16, Z);
        }
    }
    memcpy(W, WT, 16);
}

/**
 * @brief 整数转字节数组，大端存储
 *
 * @param X 整数
 * @param n 数组长度 (in bytes)
 * @param Y 字节数组
 */
static void int_to_uint8(int X, int n, uint8_t *Y)
{
    for (int i = n - 1; i >= 0; i--)
    {
        Y[i] = X & 0xFF;
        X = X >> 8;
    }
}

/**
 * @brief 泛杂凑函数
 *
 * @param K
 * @param M
 * @param len M length (in bytes)
 * @param h 输出
 */
static void HASH(const uint8_t *K, const uint8_t *M, int len, uint8_t *h)
{
    int n = 16;
    uint8_t Ki[16], Mi[16], HT[16], H[16];

    int bitlen = len * 8;
    int_to_uint8(bitlen, n, Mi);
    GF2_128_Multiply(Mi, K, H);

    int m = (len + n - 1) / n;
    int d = len % n;
    if (d == 0)
    {
        memcpy(Mi, M + n * (m - 1), n);
    }
    else
    {
        memcpy(Mi, M + n * (m - 1), d);
        memset(Mi + d, 0, n - d);
    }
    // Ki=K^2
    GF2_128_Multiply(K, K, Ki);
    GF2_128_Multiply(Mi, Ki, HT);
    XOR(H, HT, n, H);

    for (int i = m - 2; i >= 0; i--)
    {
        GF2_128_Multiply(Ki, K, Ki);
        GF2_128_Multiply(M + n * i, Ki, HT);
        XOR(H, HT, n, H);
    }
    memcpy(h, H, 16);
}

void hctr_enc(block_f_ptr enc, int n, const uint8_t *K1, const uint8_t *K2, const uint8_t *TW, const uint8_t *P, int len, uint8_t *C)
{
    uint8_t M[1024], H[16], Z1[16], Z2[16], T[16];

    memcpy(M, P + n, len - n);
    memcpy(M + len - n, TW, n);
    HASH(K2, M, len, H);

    XOR(P, H, n, Z1);
    enc(K1, Z1, Z2);

    int whole_block = len / n;
    for (int i = 1; i <= whole_block - 1; i++)
    {
        int_to_uint8(i, n, T);
        XOR(T, Z1, n, T);
        XOR(T, Z2, n, T);
        ctr_enc(enc, n, K1, T, P + i * n, n, C + i * n);
    }
	int rest = len % n;
    if (rest != 0)
    {
        int_to_uint8(whole_block, n, T);
        XOR(T, Z1, n, T);
        XOR(T, Z2, n, T);
        ctr_enc(enc, n, K1, T, P + whole_block * n, rest, C + whole_block * n);
    }
    memcpy(M, C + n, len - n);
    memcpy(M + len - n, TW, n);
    HASH(K2, M, len, H);
    XOR(Z2, H, n, C);
}

void hctr_dec(block_f_ptr enc, block_f_ptr dec, int n, const uint8_t *K1, const uint8_t *K2, const uint8_t *TW, const uint8_t *C, int len, uint8_t *P)
{
    uint8_t M[1024], H[16], Z1[16], Z2[16], T[16];

    memcpy(M, C + n, len - n);
    memcpy(M + len - n, TW, n);
    HASH(K2, M, len, H);

    XOR(C, H, n, Z2);
    dec(K1, Z2, Z1);

    int whole_block = len / n;
    for (int i = 1; i <= whole_block - 1; i++)
    {
        int_to_uint8(i, n, T);
        XOR(T, Z1, n, T);
        XOR(T, Z2, n, T);
        ctr_dec(enc, n, K1, T, C + i * n, n, P + i * n);
    }
    int rest = len % n;
    if (rest != 0)
    {
        int_to_uint8(whole_block, n, T);
        XOR(T, Z1, n, T);
        XOR(T, Z2, n, T);
        ctr_dec(enc, n, K1, T, C + whole_block * n, rest, P + whole_block * n);
    }
    memcpy(M, P + n, len - n);
    memcpy(M + len - n, TW, n);
    HASH(K2, M, len, H);
    XOR(Z1, H, n, P);
}