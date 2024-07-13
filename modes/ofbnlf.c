#include "ofbnlf.h"

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

void ofbnlf_enc(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int len, uint8_t *C)
{
    uint8_t Ki[16];

    enc(K, IV, Ki);
    enc(Ki, P, C);
    P += n;
    C += n;
    int i = 2, q = len / n;
    while (i <= q)
    {
        enc(K, Ki, Ki);
        enc(Ki, P, C);
        P += n;
        C += n;
        i++;
    }
}

void ofbnlf_dec(block_f_ptr enc, block_f_ptr dec, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int len, uint8_t *P)
{
    uint8_t Ki[16];

    enc(K, IV, Ki);
    dec(Ki, C, P);
    C += n;
    P += n;
    int i = 2, q = len / n;
    while (i <= q)
    {
        enc(K, Ki, Ki);
        dec(Ki, C, P);
        C += n;
        P += n;
        i++;
    }
}