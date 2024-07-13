
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
 * @brief CBC 加密
 *
 * @param block_f 加密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param IV
 * @param P 明文
 * @param len 明文长度（in bytes）
 * @param C 密文输出
 */
void cbc_enc(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *P, int len, uint8_t *C)
{
    uint8_t iv_buf[16];

    memcpy(iv_buf, IV, n);

    int i = 1, q = len / n;
    while (i <= q)
    {
        XOR(P, iv_buf, n, iv_buf);
        enc(K, iv_buf, C);
        memcpy(iv_buf, C, n);
        P += n;
        C += n;
        i++;
    }
}

/**
 * @brief CBC 解密
 *
 * @param dec 解密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param IV
 * @param C 密文
 * @param len 密文长度（in bytes）
 * @param P 明文输出
 */
void cbc_dec(block_f_ptr dec, int n, const uint8_t *K, const uint8_t *IV, const uint8_t *C, int len, uint8_t *P)
{
    uint8_t iv_buf[16];

    memcpy(iv_buf, IV, n);

    int i = 1, q = len / n;
    while (i <= q)
    {
        dec(K, C, P);
        XOR(P, iv_buf, n, P);
        memcpy(iv_buf, C, n);
        P += n;
        C += n;
        i++;
    }
}