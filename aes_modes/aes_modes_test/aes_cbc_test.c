
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes_modes/aes_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t IV_str[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                      "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                      "30C81C46A35CE411E5FBC1191A0A52EF"
                      "F69F2445DF4F9B17AD2B417BE66C3710";

    uint8_t C_str[] = "7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B273BED6B8E3C1743B7116E69E222295163FF1CAA1681FAC09120ECA307586E1A7";

    int key_len = 16;
    int in_len = 64;

    uint8_t K[32], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, in_len, P);
    HexString2Hex(C_str, in_len, C);

    // 加密测试
    aes_cbc_enc(K, key_len, IV, P, in_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, in_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, in_len));

    // 解密测试
    aes_cbc_dec(K, key_len, IV, C, in_len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, in_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, in_len));
    return 0;
}