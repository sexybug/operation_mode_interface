
#include <stdio.h>
#include <string.h>
#include "../test.h"
#include "../../sm4_modes/sm4_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t IV_str[] = "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                         "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                         "30C81C46A35CE411E5FBC1191A0A52EF"
                         "F69F2445DF4F9B17AD2B417BE66C3710";

    uint8_t C_str[] = "14AE4A72B97A93CE1216CCD998E371C1"
                         "60F7EF8B6344BD6DA1992505E5FC219B"
                         "0BF057F86C5D75103C0F46519C7FB2E7"
                         "292805035ADB9A90ECEF145359D7CF0E";

    uint8_t K[16], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, 16, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, 64, P);
    HexString2Hex(C_str, 64, C);

    // 加密测试
    sm4_ctr_enc(K,IV, P, 64, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, 64);
    printf("memcmp result: %d\n", memcmp(enc_out, C, 64));

    // 解密测试
    sm4_ctr_enc(K,IV, C, 64, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, 64);
    printf("memcmp result: %d\n", memcmp(dec_out, P, 64));
    return 0;
}