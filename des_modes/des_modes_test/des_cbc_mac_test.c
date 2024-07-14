
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../des_modes/des_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "0123456789abcdef";

    uint8_t P_str[] = "37363534333231204e6f77206873207468652074696d6520666f7220";

    uint8_t C_str[] = "EFBB99CA9F812086";

    uint8_t K[24], IV[8], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, 8, K);
    HexString2Hex(P_str, 28, P);
    HexString2Hex(C_str, 8, C);

    // 测试
    des_cbc_mac(K, 8, P, 28, enc_out);

    printf("cbc_mac:\n");
    dump_mem(enc_out, 8);
    printf("memcmp result: %d\n", memcmp(enc_out, C, 8));

    return 0;
}