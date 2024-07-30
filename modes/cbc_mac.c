#include "cbc_mac.h"
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

void cbc_mac(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *D, int len, uint8_t *C)
{
    uint8_t Opre[16], Ebuf[16];
    
    memset(Opre, 0, n);

    int i = 1;
    while (i <= len / n)
    {
        XOR(D, Opre, n, Ebuf);
        enc(K, Ebuf, Opre);
        D += n;
        i++;
    }
    
    int d = len % n;
    if (d != 0)
    {
        memcpy(Ebuf, D, d);
        memset(Ebuf + d, 0, n - d);
        XOR(Ebuf, Opre, n, Ebuf);
        enc(K, Ebuf, Opre);
    }
    memcpy(C, Opre, n);
}