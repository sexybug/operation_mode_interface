
#include "../../test/test.h"
#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

// 定义缓冲区大小
#define BUFFER_SIZE 32


int main(int argc, char **argv) {

     uint8_t K1K2_str[] = "6b24212a9e224fa2d60fa69a5010b126db9e1f035c630f234e64656c549db53e";
 
     // 定义Tweak值TW的十六进制字符串表示
     uint8_t TW_str[] = "d5f8305bd1074d8d884be21fbb4575fa";
 
     // 定义明文P的十六进制字符串表示
     uint8_t P_str[] = "24e51027f9c8ec525c5e30f0b63c4d2cb510d093cc3c332c3106677551a7f46f";
 
     // 定义密文C的十六进制字符串表示，初始化为全零
     uint8_t C_str[] = "813d2d3420eeaf965be28638d94cd7976ead39ccd5b615877d4fab4fe5f9e09f";
 
     // 定义密钥K1、Tweak值TW、明文P、密文C、加密输出enc_out和解密输出dec_out的缓冲区
     uint8_t K1K2[32],TW[16], P[64], C[64], enc_out[64], dec_out[64];
     // 将十六进制字符串转换为字节序列
     HexString2Hex(K1K2_str, 32, K1K2);
     HexString2Hex(TW_str, 16, TW);
     HexString2Hex(P_str, 32, P);
     HexString2Hex(C_str, 32, C);

    // 定义数据长度为32字节
    int len = 32;

    // 创建并初始化加密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, K1K2, TW);

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
    EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, K1K2, TW);

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
