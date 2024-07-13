#include "xts.h"
#include <string.h>
#include "../sm4/sm4.h"

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
 * @brief GF(2^128)有限域乘法，W=U (X) V, 以G为本原多项式
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

void xts_enc(block_f_ptr enc, int n, const uint8_t *K1, const uint8_t *K2, const uint8_t *TW, const uint8_t *P, int len, uint8_t *C)
{
    uint8_t ETW[16], alpha[16], T[16], X[16], Y[16], Z[16];

    enc(K2, TW, ETW);
    int i = 1;
    while (i <= len / n)
    {
        // alpha^(i-1)
        memset(alpha, 0, n);
        alpha[(i - 1) / 8] = 0x80 >> ((i - 1) % 8);
        GF2_128_Multiply(ETW, alpha, T);

        XOR(P, T, n, X);
        enc(K1, X, Y);
        XOR(Y, T, n, C);

        P += n;
        C += n;
        i++;
    }
    int d = len % n;
    if (d != 0)
    {
        memcpy(Z, P, d);
        memcpy(Z + d, C - n + d, n - d);

        memset(alpha, 0, n);
        alpha[(i - 1) / 8] = 0x80 >> ((i - 1) % 8);
        GF2_128_Multiply(ETW, alpha, T);
        XOR(Z, T, n, X);
        enc(K1, X, Y);
        XOR(Y, T, n, C);

        memcpy(Z, C - n, n);
        memcpy(C - n, C, n);
        memcpy(C, Z, d);
    }
}

void xts_dec(block_f_ptr enc, block_f_ptr dec, int n, const uint8_t *K1, const uint8_t *K2, const uint8_t *TW, const uint8_t *C, int len, uint8_t *P)
{
    uint8_t ETW[16], alpha[16], T[16], X[16], Y[16], Z[16];

    int i = 1;
    int q = (len + n - 1) / n;
    int d = len % n;

    enc(K2, TW, ETW);
    if (d == 0)
    {
        while (i <= q)
        {
            memset(alpha, 0, n);
            alpha[(i - 1) / 8] = 0x80 >> ((i - 1) % 8);
            GF2_128_Multiply(ETW, alpha, T);

            XOR(C, T, n, X);
            dec(K1, X, Y);
            XOR(Y, T, n, P);

            C += n;
            P += n;
            i++;
        }
    }
    else
    {
        while (i <= q - 2)
        {
            memset(alpha, 0, n);
            alpha[(i - 1) / 8] = 0x80 >> ((i - 1) % 8);
            GF2_128_Multiply(ETW, alpha, T);

            XOR(C, T, n, X);
            dec(K1, X, Y);
            XOR(Y, T, n, P);

            C += n;
            P += n;
            i++;
        }

        memset(alpha, 0, n);
        alpha[(q - 1) / 8] = 0x80 >> ((q - 1) % 8);
        GF2_128_Multiply(ETW, alpha, T);
        XOR(C, T, n, X);
        dec(K1, X, Y);
        XOR(Y, T, n, Z);
        memcpy(P + n, Z, d);

        memset(alpha, 0, n);
        alpha[(q - 2) / 8] = 0x80 >> ((q - 2) % 8);
        GF2_128_Multiply(ETW, alpha, T);
        memcpy(X, C + n, d);
        memcpy(X + d, Z + d, n - d);
        XOR(X, T, n, X);
        dec(K1, X, Y);
        XOR(Y, T, n, P);
    }
}