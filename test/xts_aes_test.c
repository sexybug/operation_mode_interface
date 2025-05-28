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

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key, iv)) handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main(void) {
    
    char key_str[] = "7BB5A73A2783C7CB8972A8FA70C7E31E5440503DBFC92C9996A8697F6110FBFC";
    char iv_str[] = "FA19059AE6F1B4DDA39F59402F9F6BFF";
    char plain[]= "4AFE3729C6A7B56B28C419E964281D38EC31D7CBF7E2476810251EA17995286F";
    unsigned char cipher[512]="1c69ed3cf4f06b6212c3dc65516da8019ebd15c30ede38294af14feaa8ee27f8";

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