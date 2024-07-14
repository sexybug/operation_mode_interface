
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes_modes/aes_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";

    uint8_t IV_str[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t P_str[] = "000102030405060708090A0B0C0D0E0F"
                      "000102030405060708090A0B0C0D0E0F"
                      "000102030405060708090A0B0C0D0E0F"
                      "000102030405060708090A0B0C0D0E0F";

    uint8_t C_str[] = "0A9509B6456BF642F9CA9E53CA5EE4550262EE97621D749192D3F70447A901D31A2C96B01519A3FFB5CBC246C024E2484D0AA9D19D5A99006A2A2E634BB8DD01";

    int key_len = 16;
    int in_len = 64;

    uint8_t K[32], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, in_len, P);
    HexString2Hex(C_str, in_len, C);

    // 加密测试
    aes_ctr_enc(K, key_len, IV, P, in_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, in_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, in_len));

    // 解密测试
    aes_ctr_dec(K, key_len, IV, C, in_len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, in_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, in_len));
    return 0;
}