#include "test.h"
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

int encrypt(const char *alg, const unsigned char *key, const unsigned char *iv,
            const unsigned char *msg, size_t msg_len, unsigned char *out)
{
    /*
     * This assumes that key size is 32 bytes and the iv is 16 bytes.
     * For ciphertext stealing mode the length of the ciphertext "out" will be
     * the same size as the plaintext size "msg_len".
     * The "msg_len" can be any size >= 16.
     */
    int ret = 0, encrypt = 1, outlen, len;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_CIPHER_fetch(NULL, alg, NULL);
    if (ctx == NULL || cipher == NULL)
        goto err;

    if (!EVP_CipherInit_ex2(ctx, cipher, key, iv, encrypt, NULL))
        goto err;

    /* NOTE: CTS mode does not support multiple calls to EVP_CipherUpdate() */
    if (!EVP_CipherUpdate(ctx, out, &outlen, msg, msg_len))
        goto err;
    if (!EVP_CipherFinal_ex(ctx, out + outlen, &len))
        goto err;
    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_test1()
{
    uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t in[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t out_ref[32] = {};
    uint8_t out[32] = {};
    int len = 32;

    encrypt("AES-128-CFB", key, iv, in, len, out);
    print_u8("out", out, len);
    return 0;
}
int aes_test2()
{
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    uint8_t in[32] = {0};
    uint8_t out_ref[32] = {};
    uint8_t out[32] = {};
    int len = 32;

    memset(key, 0xff, sizeof(key));
    memset(iv, 0xff, sizeof(iv));
    memset(in, 0xff, sizeof(in));

    encrypt("AES-128-CFB", key, iv, in, len, out);
    print_u8("out", out, len);
    return 0;
}

int main()
{
    aes_test1();
    // aes_test2();
    return 0;
}