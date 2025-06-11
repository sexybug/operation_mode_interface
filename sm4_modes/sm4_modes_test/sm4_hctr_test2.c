
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../sm4_modes/sm4_modes.h"

int main(int argc, char **argv)
{
    int P_len = 26;

    uint8_t K1_str[] = "c168b0d07d7dd67390891c9c6365cef6";
    uint8_t K2_str[] = "472a6c8f5b8caed4af6ac6bca9a2e543";

    uint8_t TW_str[] = "a82a001ae85dd49da692280584f352df";

    uint8_t P_str[] = "2e8dfcbd3ea3282b5d4872e4ab2d954662b73104b654cc1bff10";

    uint8_t C_str[] = "d18e516a9e431fa7e58d98f94796b58c25cb93abb6cb982bf35a";

    uint8_t K1[16], K2[16],TW[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K1_str, 16, K1);
    HexString2Hex(K2_str, 16, K2);
    HexString2Hex(TW_str, 16, TW);
    HexString2Hex(P_str, P_len*2, P);
    HexString2Hex(C_str, P_len*2, C);


    // 加密测试
    sm4_hctr_enc(K1, K2,TW, P, P_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, P_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, P_len));

    // 解密测试
    sm4_hctr_dec(K1, K2,TW, C, P_len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, P_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, P_len));
    return 0;
}