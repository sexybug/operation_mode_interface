
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes_modes/aes_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t IV_str[] = "00000000000000000000000000000000";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                      "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                      "30C81C46A35CE411E5FBC1191A0A52EF"
                      "F69F2445DF4F9B17AD2B417BE66C3710";

    uint8_t C_str[] = "51F0BEBF7E3B9D92FC49741779363CFE";

    int key_len = 16;
    int in_len = 64;

    uint8_t K[32], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, in_len, P);
    HexString2Hex(C_str, 16, C);

    // 加密测试
    aes_cmac(K, key_len, P, in_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, 16);
    printf("memcmp result: %d\n", memcmp(enc_out, C, 16));
    return 0;
}