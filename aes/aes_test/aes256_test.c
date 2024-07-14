
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes/aes.h"

int main(int argc, char **argv)
{
    char K_str[] = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

    uint8_t P_str[] = "6bc1bee22e409f96e93d7e117393172a";

    uint8_t C_str[] = "f3eed1bdb5d2a03c064b5a7e3db181f8";

    int key_len = 32;
    int plain_len = 16;

    uint8_t K[32], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(P_str, plain_len, P);
    HexString2Hex(C_str, plain_len, C);

    // 加密测试
    aes256_enc(K, P, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, plain_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, plain_len));

    // 解密测试
    aes256_dec(K, C, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, plain_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, plain_len));
    return 0;
}