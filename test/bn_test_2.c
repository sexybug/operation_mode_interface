#include "test.h"
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

void print_bn(const char *name, const BIGNUM *bn) {
    uint8_t buf[1024];
    BN_bn2bin(bn, buf);
    print_u8(name, buf, BN_num_bytes(bn));
}

int main() {

    int i;
    int len = 32;

    uint8_t a[256]={0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,};
    uint8_t b[256]={0x3};
    uint8_t c[256]={0x87,0x65,0x43,0x21};
    uint8_t d[256];

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_a = BN_bin2bn(a, 8, NULL);
    BIGNUM *bn_b = BN_bin2bn(b, 1, NULL);
    BIGNUM *bn_c = BN_bin2bn(c, 4, NULL);

    BIGNUM *bn_d = BN_new();
    BIGNUM *bn_t1 = BN_new();
    BIGNUM *bn_t2 = BN_new();
    BIGNUM *bn_t3 = BN_new();

    BN_mod_exp(bn_d, bn_a, bn_b, bn_c, ctx);
    print_bn("a^b", bn_d);

    //
    BN_mod(bn_t1, bn_a, bn_c, ctx);
    print_bn("a%n", bn_t1);

    BN_mul(bn_t1, bn_t1, bn_t1, ctx);    
    print_bn("t^2", bn_t1);

    BN_mod(bn_t1, bn_t1, bn_c, ctx);
    print_bn("t^2%n", bn_t1);

    BN_mul(bn_t1, bn_t1, bn_a, ctx);    
    print_bn("t*a", bn_t1);

    BN_mod(bn_t1, bn_t1, bn_c, ctx);
    print_bn("t*a%n", bn_t1);

    BN_CTX_free(ctx);
    return 0;


    return 0;
}