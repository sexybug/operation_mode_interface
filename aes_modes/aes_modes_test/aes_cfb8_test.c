
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes_modes/aes_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2b7e151628aed2a6abf7158809cf4f3c";

    uint8_t IV_str[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172AAE2D";

    uint8_t C_str[] = "3B79424C9C0DD436BACE9E0ED4586A4F32B9";

    int key_len = 16;
    int in_bit_len = 18*8;
    int in_byte_len = (in_bit_len+7)/8;
    int feedback_bit_num = 8;

    uint8_t K[32], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, in_byte_len, P);
    HexString2Hex(C_str, in_byte_len, C);

    // 加密测试
    aes_cfb_enc(feedback_bit_num, K, key_len, IV, P, in_bit_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, in_byte_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, in_byte_len));

    // 解密测试
    aes_cfb_dec(feedback_bit_num, K, key_len, IV, C, in_bit_len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, in_byte_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, in_byte_len));
    return 0;
}