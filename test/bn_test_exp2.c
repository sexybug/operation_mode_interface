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

    uint8_t a[256]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t b[256]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint8_t d[256];
    // for (int i = 0; i < len; i++)
    // {
    //     a[i] = 0x77;
    //     b[i] = 0x55;
    // }

    uint8_t c[256]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xF1,0xFF,0xFF,0xFF,0xFF};

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_a = BN_bin2bn(a, len, NULL);
    BIGNUM *bn_b = BN_bin2bn(b, len, NULL);
    BIGNUM *bn_c = BN_bin2bn(c, 12, NULL);

    BIGNUM *bn_d = BN_new();

    // bn_d = bn_a ^ bn_b mod bn_c
    BN_mod_exp(bn_d, bn_a, bn_b, bn_c, ctx);

    print_bn("bn_d", bn_d);

    return 0;
}