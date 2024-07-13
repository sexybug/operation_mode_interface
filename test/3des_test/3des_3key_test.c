
#include <stdio.h>
#include <string.h>
#include "../test.h"
#include "../../3des/3des.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                      "AE2D8A571E03AC9C9EB76FAC45AF8E51";

    uint8_t C_str[] = "714772F339841D34267FCC4BD2949CC3"
                      "EE11C22A576A303876183F99C0B6DE87";

    int key_len = 24;
    int plain_len = 8;

    uint8_t K[24], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(P_str, plain_len, P);
    HexString2Hex(C_str, plain_len, C);

    // 加密测试
    des3_3key_enc(K, P, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, plain_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, plain_len));

    // 解密测试
    des3_3key_dec(K, C, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, plain_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, plain_len));
    return 0;
}