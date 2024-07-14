
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../des_modes/des_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "0123456789abcdef0123456789abcdef0123456789abcdef";

    uint8_t IV_str[] = "0123456789abcdef";

    uint8_t P_str[] = "0123456789abcdef0123456789abcdef";

    uint8_t C_str[] = "57EF4C80467781009E6610CE2BD2AD98";

    int key_len = 24;
    int in_len = 16;

    uint8_t K[24], IV[8], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(IV_str, 8, IV);
    HexString2Hex(P_str, in_len, P);
    HexString2Hex(C_str, in_len, C);

    // 加密测试
    des_ctr_enc(K, key_len, IV, P, in_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, in_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, in_len));

    // 解密测试
    des_ctr_enc(K, key_len, IV, C, in_len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, in_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, in_len));
    return 0;
}