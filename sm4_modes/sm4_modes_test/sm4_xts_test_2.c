

#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../sm4_modes/sm4_modes.h"


int main(int argc, char **argv)
{
    uint8_t K1_str[] = "00000000000000000000000000000000";
    uint8_t K2_str[] = "00000000000000000000000000000000";

    uint8_t TW_str[] = "00000000000000000000000000000000";

    uint8_t P_str[] = "00000000000000000000000000000000"
                         "00000000000000000000000000000000"
                         "00000000000000000000000000000000"
                         "00000000000000000000000000000000";

    uint8_t C_str[] = "00000000000000000000000000000000"
                         "00000000000000000000000000000000"
                         "00000000000000000000000000000000"
                         "00000000000000000000000000000000";

    uint8_t K1[16], K2[16],TW[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K1_str, 16, K1);
    HexString2Hex(K2_str, 16, K2);
    HexString2Hex(TW_str, 16, TW);
    HexString2Hex(P_str, 64, P);
    HexString2Hex(C_str, 64, C);

    int len=64;

    // 加密测试
    sm4_xts_enc(K1, K2,TW, P, len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, len);
    

    // 解密测试
    sm4_xts_dec(K1, K2,TW, enc_out, len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, len);
    
    return 0;
}