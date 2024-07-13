
#include "cbc.h"
#include <string.h>

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
 * @brief 计数器自增1
 *
 * @param T 计数器值
 * @param len ctr长度(in bytes)
 */
static void increase(uint8_t *T, int len)
{
    int i = len - 1;
    T[i]++;
    while (T[i] == 0 && i > 0)
    {
        i--;
        T[i]++;
    }
}


void ctr_enc(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int len, uint8_t *C)
{
    uint8_t T[16],Y[16];

    memcpy(T, IV, 16);
    int i = 1;
    while (i <= len / n)
    {
        enc(K, T, Y);
        XOR(P, Y, n, C);
        P += n;
        C += n;
        increase(T, n);
        i++;
    }
    int d = len % n;
    if (d != 0)
    {
        enc(K, T, Y);
        XOR(P, Y, d, C);
    }
}

void ctr_dec(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int len, uint8_t *P)
{
    ctr_enc(enc, n, K, IV, C, len, P);
}