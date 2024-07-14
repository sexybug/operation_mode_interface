
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../sm4_modes/sm4_modes.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t IV_str[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                      "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                      "30C81C46A35CE411E5FBC1191A0A52EF"
                      "F69F2445DF4F9B17AD2B417BE66C3710";

    uint8_t C_str[] = "BC710D762D070B26361DA82B54565E46A4CD42786A3A5293A3C6CBC123F0B354407055B1C1A5D9982C187D5C3EE0CED84B82C40F2F0A4E0341797F1F307B8047";

    int key_len = 16;
    int in_bit_len = 64*8;
    int in_byte_len = (in_bit_len + 7) / 8;
    int feedback_bit_num = 128;

    uint8_t K[16], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, in_byte_len, P);
    HexString2Hex(C_str, in_byte_len, C);

    // 加密测试
    sm4_cfb_enc(feedback_bit_num, K, IV, P, in_bit_len, enc_out);

    printf("enc:\n");
    dump_mem(enc_out, in_byte_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, in_byte_len));

    // 解密测试
    sm4_cfb_dec(feedback_bit_num, K, IV, C, in_bit_len, dec_out);

    printf("dec:\n");
    dump_mem(dec_out, in_byte_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, in_byte_len));
    return 0;
}