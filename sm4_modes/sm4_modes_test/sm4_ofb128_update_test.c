
#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../sm4/sm4.h"
#include "../../modes/ofb128_update.h"

int main(int argc, char **argv)
{
    uint8_t K_str[] = "2B7E151628AED2A6ABF7158809CF4F3C";

    uint8_t IV_str[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                      "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                      "30C81C46A35CE411E5FBC1191A0A52EF"
                      "F69F2445DF4F9B17AD2B417BE66C3710";

    uint8_t C_str[] =
        "BC710D762D070B26361DA82B54565E46"
        "07A0C62834740AD3240D239125E11621"
        "D476B21CC9F04951F0741D2EF9E09498"
        "1584FC142BF13AA626B82F9D7D076CCE";

    int key_len = 16;
    int in_byte_len = 63;
    int out_len = 0, out_len2 = 0;

    uint8_t K[16], IV[16], P[64], C[64], enc_out[64], dec_out[64];
    HexString2Hex(K_str, key_len, K);
    HexString2Hex(IV_str, 16, IV);
    HexString2Hex(P_str, in_byte_len, P);
    HexString2Hex(C_str, in_byte_len, C);

    OFB128_CTX ctx;

    // 加密测试
    out_len = 0;

    ofb128_init(&ctx, sm4_enc, K, 16, IV, 16);
    ofb128_update(&ctx, P, 16, enc_out, &out_len2);
    out_len += out_len2;
    ofb128_update(&ctx, P + out_len, in_byte_len - out_len2, enc_out + out_len2, &out_len2);
    out_len += out_len2;
    ofb128_final(&ctx, enc_out + out_len, &out_len2);
    out_len += out_len2;

    printf("enc:\n");
    dump_mem(enc_out, in_byte_len);
    printf("memcmp result: %d\n", memcmp(enc_out, C, in_byte_len));

    // 解密测试
    out_len = 0;
    ofb128_init(&ctx, sm4_enc, K, 16, IV, 16);
    ofb128_update(&ctx, C, 16, dec_out, &out_len2);
    out_len += out_len2;
    ofb128_update(&ctx, C + out_len, in_byte_len - out_len2, dec_out + out_len2, &out_len2);
    out_len += out_len2;
    ofb128_final(&ctx, dec_out + out_len, &out_len2);
    out_len += out_len2;

    printf("dec:\n");
    dump_mem(dec_out, in_byte_len);
    printf("memcmp result: %d\n", memcmp(dec_out, P, in_byte_len));
    return 0;
}