

#include <stdio.h>
#include <string.h>
#include "../../test/test.h"
#include "../../aes_modes/aes_modes.h"


int main(int argc, char **argv)
{
    // 定义密钥K1的十六进制字符串表示
    uint8_t K1_str[] = "000102030405060708090A0B0C0D0E0F";
    // 定义密钥K2的十六进制字符串表示
    uint8_t K2_str[] = "101112131415161718191A1B1C1D1E1F";

    // 定义Tweak值TW的十六进制字符串表示
    uint8_t TW_str[] = "000102030405060708090A0B0C0D0E0F";

    // 定义明文P的十六进制字符串表示
    uint8_t P_str[] = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F0001020304050607";

    // 定义密文C的十六进制字符串表示，初始化为全零
    uint8_t C_str[] = "B62412371F8D7CF1E27C05AF1A83D9B924F42A9C90D57BF0A0625CCFC77A158066CBDBD131535F7A";

    int plain_len=40;
    int key_len=16;

    // 定义密钥K1、K2、Tweak值TW、明文P、密文C、加密输出enc_out和解密输出dec_out的缓冲区
    uint8_t K1[16], K2[16],TW[16], P[64], C[64], enc_out[64], dec_out[64];
    // 将十六进制字符串转换为字节序列
    HexString2Hex(K1_str, key_len, K1);
    HexString2Hex(K2_str, key_len, K2);
    HexString2Hex(TW_str, 16, TW);
    HexString2Hex(P_str, plain_len, P);
    HexString2Hex(C_str, plain_len, C);

    

    // 加密测试，使用AES-XTS模式加密明文P
    aes_xts_ieee_enc(K1, K2,key_len, TW, P, plain_len, enc_out);

    // 打印加密输出
    printf("enc:\n");
    dump_mem(enc_out, plain_len);
    

    // 解密测试，使用AES-XTS模式解密密文enc_out
    aes_xts_ieee_dec(K1, K2,key_len,TW, enc_out, plain_len, dec_out);

    // 打印解密输出
    printf("dec:\n");
    dump_mem(dec_out, plain_len);
    
    return 0;
}
