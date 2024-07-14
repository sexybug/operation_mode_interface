
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes/aes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A";

    uint8_t C_str[] = "3AD77BB40D7A3660A89ECAF32466EF97";

    int key_len = 16;
    int plain_len = 16;

    uint8_t K[32], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(P_str, plain_len, P);
    HexString2Hex(C_str, plain_len, C);

    // 加密测试
    aes128_enc(K, P, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, plain_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, plain_len));

    // 解密测试
    aes128_dec(K, C, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, plain_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, plain_len));
    return 0;
}