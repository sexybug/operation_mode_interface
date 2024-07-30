
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes_modes/aes_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t IV_str[] = "00000000000000000000000000000000";

    uint8_t P_str[] = "000102030405060708090A0B0C0D0E0F"
                      "000102030405060708090A0B0C0D0E0F"
                      "000102030405060708090A0B0C0D0E0F"
                      "000102030405060708090A0B0C0D0E0F";

    //uint8_t C_str[] = "BB1D6929E95937287FA37D129B756746";

    int key_len = 16;
    int in_len = 0;

    uint8_t K[32], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, in_len, P);
    //HexString2Hex(C_str, 16, C);

    // 加密测试
    aes_cmac(K, key_len, P, in_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, 16);
    printf("memcmp result: %d\n", memcmp(enc_out, C, 16));
    return 0;
}