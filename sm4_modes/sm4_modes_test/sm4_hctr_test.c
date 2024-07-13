
#include <stdio.h>
#include <string.h>
#include "../../test.h"
#include "../sm4_modes.h"

int main(int argc, char **argv)
{
    uint8_t K1_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";
    uint8_t K2_str[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t TW_str[] = "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                         "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                         "30C81C46A35CE411E5FBC1191A0A52EF"
                         "F69F2445DF4F9B17AD2B417BE66C3710";

    uint8_t C_str[] = "9CD7481D3B7CA904B14B4084D9D4C83E"
                         "D39EAC8E16747895FC2AE1EECD220276"
                         "AF3D0D2F21CB3807561347C81AD13811"
                         "7DD85C652AFE16A47DC68EB884068AE3";

    uint8_t K1[16], K2[16],TW[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K1_str, 16, K1);
    HexString2Hex(K2_str, 16, K2);
    HexString2Hex(TW_str, 16, TW);
    HexString2Hex(P_str, 64, P);
    HexString2Hex(C_str, 64, C);

    // 加密测试
    sm4_hctr_enc(K1, K2,TW, P, 64, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, 64);
    printf("memcmp result: %d\n", memcmp(enc_out, C, 64));

    // 解密测试
    sm4_hctr_dec(K1, K2,TW, C, 64, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, 64);
    printf("memcmp result: %d\n", memcmp(dec_out, P, 64));
    return 0;
}