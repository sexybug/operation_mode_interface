#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <string.h>
#include "../../test/test.h"

void hmac(const char *alg, const uint8_t *key, int key_len, const uint8_t *input, int input_len, uint8_t *mac, size_t *out_len)
{
    EVP_MAC *mac_alg = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM params[4], *p = params;

    /* Fetch the HMAC implementation */
    mac_alg = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac_alg == NULL)
    {
        fprintf(stdout, "EVP_MAC_fetch() returned NULL\n");
        return;
    }

    /* Create a context for the HMAC operation */
    mctx = EVP_MAC_CTX_new(mac_alg);
    if (mctx == NULL)
    {
        fprintf(stdout, "EVP_MAC_CTX_new() returned NULL\n");
        return;
    }

    /* The underlying digest to be used */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)alg, strlen(alg));
    *p = OSSL_PARAM_construct_end();

    /* Initialise the HMAC operation */
    if (!EVP_MAC_init(mctx, key, key_len, params))
    {
        fprintf(stdout, "EVP_MAC_init() failed\n");
        return;
    }

    /* Make one or more calls to process the data to be authenticated */
    if (!EVP_MAC_update(mctx, input, input_len))
    {
        fprintf(stdout, "EVP_MAC_update() failed\n");
        return;
    }

    /* Make a call to the final with a NULL buffer to get the length of the MAC */
    if (!EVP_MAC_final(mctx, NULL, out_len, 0))
    {
        fprintf(stdout, "EVP_MAC_final() failed\n");
        return;
    }

    /* Make one call to the final to get the MAC */
    if (!EVP_MAC_final(mctx, mac, out_len, *out_len))
    {
        fprintf(stdout, "EVP_MAC_final() failed\n");
        return;
    }

    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac_alg);
}

int main(void)
{
    const char *alg = "SHA-256";
    const uint8_t key[64] = {0};
    const uint8_t input[64*1024] = {0};
    uint8_t mac[EVP_MAX_MD_SIZE];
    size_t out_len = sizeof(mac);

    hmac(alg, key, sizeof(key), input, sizeof(input), mac, &out_len);

    printf("HMAC (%s):\n", alg);
    print_u8("mac", mac, out_len);

    return 0;
}