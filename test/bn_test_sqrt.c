#include "test.h"
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

void print_bn(const char *name, const BIGNUM *bn)
{
    uint8_t buf[1024];
    BN_bn2bin(bn, buf);
    print_u8(name, buf, BN_num_bytes(bn));
}

int main()
{

    int len = 8;

    uint8_t a[256]={0x08,0x08,0xFF,0xFF,0xFF,0xFF,0xFF,0xF8};
    uint8_t d[256];

    uint8_t c[256]={0xCD,0xD1,0xAD,0xCB,0x7C,0x16,0xBA,0xD7};

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_a = BN_bin2bn(a, len, NULL);
    BIGNUM *bn_c = BN_bin2bn(c, len, NULL);

    BIGNUM *bn_d = BN_new();

    BIGNUM *ret = BN_mod_sqrt(bn_d, bn_a, bn_c, ctx);

    if( ret == NULL)
    {
        printf("BN_mod_sqrt error\n");
        return -1;
    }

    print_bn("bn_d", bn_d);

    return 0;
}