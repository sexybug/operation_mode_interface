
#include "ecb.h"

/**
 * @brief ECB 加密
 *
 * @param block_f 加密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param P 明文
 * @param len 明文长度（in bytes）
 * @param C 密文输出
 */
void ecb_enc(block_f_ptr enc, int n, const uint8_t *K, const uint8_t *P, int len, uint8_t *C)
{
    int i = 1, q = len / n;
    while (i <= q)
    {
        enc(K, P, C);
        P += n;
        C += n;
        i++;
    }
}

/**
 * @brief ECB 解密
 *
 * @param dec 解密函数
 * @param n 算法分组长度（in bytes）
 * @param K 密钥
 * @param C 密文
 * @param len 密文长度（in bytes）
 * @param P 明文输出
 */
void ecb_dec(block_f_ptr dec, int n, const uint8_t *K, const uint8_t *C, int len, uint8_t *P)
{
    int i = 1, q = len / n;
    while (i <= q)
    {
        dec(K, C, P);
        C += n;
        P += n;
        i++;
    }
}
