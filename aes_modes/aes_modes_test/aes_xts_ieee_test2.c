

#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes_modes/aes_modes.h"

int main(int argc, char **argv)
{
    // 定义密钥K1的十六进制字符串表示
    uint8_t K1_str[] = "6b24212a9e224fa2d60fa69a5010b126";
    // 定义密钥K2的十六进制字符串表示
    uint8_t K2_str[] = "db9e1f035c630f234e64656c549db53e";

    // 定义Tweak值TW的十六进制字符串表示
    uint8_t TW_str[] = "d5f8305bd1074d8d884be21fbb4575fa";

    // 定义明文P的十六进制字符串表示
    uint8_t P_str[] = "24e51027f9c8ec525c5e30f0b63c4d2cb510d093cc3c332c3106677551a7f46f";

    // 定义密文C的十六进制字符串表示，初始化为全零
    uint8_t C_str[] = "813d2d3420eeaf965be28638d94cd7976ead39ccd5b615877d4fab4fe5f9e09f";

    // 定义密钥K1、K2、Tweak值TW、明文P、密文C、加密输出enc_out和解密输出dec_out的缓冲区
    uint8_t K1[16], K2[16], TW[16], P[64], C[64], enc_out[64], dec_out[64];
    // 将十六进制字符串转换为字节序列
    HexString2Hex(K1_str, 16, K1);
    HexString2Hex(K2_str, 16, K2);
    HexString2Hex(TW_str, 16, TW);
    HexString2Hex(P_str, 32, P);
    HexString2Hex(C_str, 32, C);

    // 定义数据长度为32字节
    int plain_len = 32;
    // 定义密钥长度为16字节
    int key_len = 16;

    // 加密测试，使用AES-XTS模式加密明文P
    aes_xts_ieee_enc(K1, K2, key_len, TW, P, plain_len, enc_out);

    // 打印加密输出
    printf("enc:\n");
    dump_mem(enc_out, plain_len);

    // 解密测试，使用AES-XTS模式解密密文enc_out
    aes_xts_ieee_dec(K1, K2, key_len, TW, enc_out, plain_len, dec_out);

    // 打印解密输出
    printf("dec:\n");
    dump_mem(dec_out, plain_len);

    int cmpENC = memcmp(enc_out, C, plain_len);
    int cmpDEC = memcmp(dec_out, P, plain_len);
    if (cmpENC == 0 && cmpDEC == 0)
    {
        printf("AES XTS test success!\n");
    }

    return 0;
}
