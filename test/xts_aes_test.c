#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

void hex_to_bin(const char *hex, size_t len, unsigned char *bin) {
    for (size_t i = 0; i < len / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
}

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_XTS_IV_SIZE 16

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv)) handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main(void) {
    char plain[]= "9d0ecc25831752449e68fadf8768164c67a0";
    char key_str[] = "471b3c12966db5a1d7774bc3cd8bfca6a96e2e3937398d078b17ad707dddb7f2bf016e343b42bc43301cbce52507abfbaf069afafaa4ec49f2b30a3841453c6c";
    char iv_str[] = "cab10c38afe0907088db6a509a6088eb";
    unsigned char cipher[512]="f3316a799246f3fa3da0226f727f3d6f6de360a2fc4ad6937eea9c25c8ab8680";

    int plain_len = strlen(plain)/2;

    unsigned char key[AES_KEY_SIZE * 2];
    unsigned char iv[AES_XTS_IV_SIZE];
    unsigned char plaintext[512];
    unsigned char ciphertext[512];

    hex_to_bin(plain, strlen(plain), plaintext);
    hex_to_bin(key_str, strlen(key_str), key);
    hex_to_bin(iv_str, strlen(iv_str), iv);

    print_u8("plaintext", plaintext, plain_len);
    print_u8("key", key, AES_KEY_SIZE*2);
    print_u8("iv", iv, AES_XTS_IV_SIZE);


    int ciphertext_len = encrypt(plaintext, plain_len, key, iv, ciphertext);

    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}