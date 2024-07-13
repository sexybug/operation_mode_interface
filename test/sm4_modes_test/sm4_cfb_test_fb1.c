
#include <stdio.h>
#include <string.h>
#include "../test.h"
#include "../../sm4_modes/sm4_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t IV_str[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                      "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                      "30C81C46A35CE411E5FBC1191A0A52EF"
                      "F69F2445DF4F9B17AD2B417BE66C3710";

    uint8_t C_str[] = "BC98B69C0B3AC87B";

    int bit_len = 63*8-1;

    uint8_t K[16], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, 16, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, 64, P);
    HexString2Hex(C_str, 64, C);

    // 加密测试
    sm4_cfb_enc(1, K, IV, P, bit_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, (bit_len+7)/8);

    // 解密测试
    sm4_cfb_dec(1, K, IV, enc_out, bit_len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, (bit_len+7)/8);
    printf("memcmp result: %d\n", memcmp(dec_out, P, bit_len/8));
    return 0;
}