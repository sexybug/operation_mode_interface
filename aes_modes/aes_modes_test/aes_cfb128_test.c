
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

    uint8_t C_str[] = "0A9509B6456BF642F9CA9E53CA5EE455D15D6B1B0920B646C7738627B586953082DC8C042512C935708EE0FA483835F3225B9C84E6CBA4971238C261D3B46BFB";

    int key_len = 16;
    int in_bit_len = 64*8;
    int in_byte_len = (in_bit_len+7)/8;
    int feedback_bit_num = 128;

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