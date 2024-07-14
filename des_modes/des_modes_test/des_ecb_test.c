
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../des_modes/des_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "0123456789abcdef";

    uint8_t P_str[] = "37363534333231206f946e16fad24c5c";

    uint8_t C_str[] = "21fb193693a16c286c463f0cb7167a6f";

    int key_len = 8; 
    int plain_len = 16;

    uint8_t K[24], IV[8], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(P_str, plain_len, P);
    HexString2Hex(C_str, plain_len, C);

    // 加密测试
    des_ecb_enc(K, key_len, P, plain_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, plain_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, plain_len));

    // 解密测试
    des_ecb_dec(K, key_len, C, plain_len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, plain_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, plain_len));
    return 0;
}