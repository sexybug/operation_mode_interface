
#include <stdio.h>
#include <string.h>
#include "../../test.h"
#include "../sm4_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[32] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t P_str[128] = "6BC1BEE22E409F96E93D7E117393172A"
                         "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                         "30C81C46A35CE411E5FBC1191A0A52EF"
                         "F69F2445DF4F9B17AD2B417BE66C3710";

    uint8_t C_str[128] = "D9D6E7E4CE6A50A4E1743577FFD22F20";

    uint8_t K[16], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, 16, K);
    HexString2Hex(P_str, 64, P);
    HexString2Hex(C_str, 64, C);

    // 测试
    sm4_cbc_mac(K, P, 64, enc_out);

    printf("cbc_mac:\n");
    dump_mem(enc_out, 16);
    printf("memcmp result: %d\n", memcmp(enc_out, C, 16));

    return 0;
}