#include "bc.h"
#include <string.h>
#include "../sm4/sm4.h"

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

void bc_enc(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int len, uint8_t *C)
{
    uint8_t buf[16], F[16];

    memcpy(F, IV, n);
    int i = 1, q = len / n;
    while (i <= q - 1)
    {
        XOR(P, F, n, buf);
        enc(K, buf, C);
        XOR(C, F, n, F);
        P += n;
        C += n;
        i++;
    }
    XOR(P, F, n, buf);
    enc(K, buf, C);
}

void bc_dec(block_f_ptr dec, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int len, uint8_t *P)
{
    uint8_t buf[16], F[16];

    memcpy(F, IV, n);
    dec(K, C, buf);
    XOR(F, buf, n, P);
    C += n;
    P += n;
    int i = 2, q = len / n;
    while (i <= q)
    {
        XOR(F, C - n, n, F);
        dec(K, C, buf);
        XOR(buf, F, n, P);
        C += n;
        P += n;
        i++;
    }
}