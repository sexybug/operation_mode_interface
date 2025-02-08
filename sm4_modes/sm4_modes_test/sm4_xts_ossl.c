#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

// 定义缓冲区大小
#define BUFFER_SIZE 32


int main(int argc, char **argv) {

    uint8_t K1_str[] = "2B7E151628AED2A6ABF7158809CF4F3C000102030405060708090A0B0C0D0E0F";
    uint8_t K2_str[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t TW_str[] = "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

    uint8_t P_str[] = "6BC1BEE22E409F96E93D7E117393172A"
                         "AE2D8A571E03AC9C9EB76FAC45AF8E51"
                         "30C81C46A35CE411E5FBC1191A0A52EF"
                         "F69F2445DF4F9B17";

    uint8_t C_str[] = "E9538251C71D7B80BBE4483FEF497BD1"
                         "2C5C581BD6242FC51E08964FB4F60FDB"
                         "0BA42F63499279213D318D2C11F6886E"
                         "903BE7F93A1B3479";
 
     // 定义密钥K1、K2、Tweak值TW、明文P、密文C、加密输出enc_out和解密输出dec_out的缓冲区
     uint8_t K1[32], K2[16],TW[16], P[64], C[64], enc_out[64], dec_out[64];
     // 将十六进制字符串转换为字节序列
     HexString2Hex(K1_str, 32, K1);
     HexString2Hex(K2_str, 16, K2);
     HexString2Hex(TW_str, 16, TW);
     HexString2Hex(P_str, 32, P);
     HexString2Hex(C_str, 64, C);

    // 定义数据长度为32字节
    int len = 56;
    // 定义密钥长度为16字节
    int key_len = 16;

    // 创建并初始化加密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_sm4_xts(), NULL, K1, TW);

    // 加密明文P
    int ciphertext_len = 0, ciphertext_len_tmp;
    EVP_EncryptUpdate(ctx, enc_out, &ciphertext_len_tmp, P, len);
    ciphertext_len += ciphertext_len_tmp;

    // 结束加密
    EVP_EncryptFinal_ex(ctx, enc_out + ciphertext_len, &ciphertext_len_tmp);
    ciphertext_len += ciphertext_len_tmp;

    // 打印加密输出
    printf("enc:\n");
    dump_mem(enc_out, ciphertext_len);

    // 初始化解密上下文
    EVP_DecryptInit_ex(ctx, EVP_sm4_xts(), NULL, K1, TW);

    // 解密密文
    int plaintext_len = 0, plaintext_len_tmp;
    EVP_DecryptUpdate(ctx, dec_out, &plaintext_len_tmp, enc_out, ciphertext_len);
    plaintext_len += plaintext_len_tmp;

    // 结束解密
    EVP_DecryptFinal_ex(ctx, dec_out + plaintext_len, &plaintext_len_tmp);
    plaintext_len += plaintext_len_tmp;

    // 打印解密输出
    printf("dec:\n");
    dump_mem(dec_out, plaintext_len);

    // 清理加密上下文
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
