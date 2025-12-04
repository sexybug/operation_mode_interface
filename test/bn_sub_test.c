#include "test.h"
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

void print_bn(const char *name, const BIGNUM *bn) {
    uint8_t buf[1024];
    BN_bn2bin(bn, buf);
    printf("flag: %d\n", BN_is_negative(bn));
    print_u8(name, buf, BN_num_bytes(bn));
}

int main() {

    int i;
    int len = 32;

    uint8_t a[256]={0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,};
    uint8_t b[256]={0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x78,};
    uint8_t c[256]={0x87,0x65,0x43,0x21};
    uint8_t d[256];

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_a = BN_bin2bn(a, 8, NULL);
    BIGNUM *bn_b = BN_bin2bn(b, 8, NULL);
    BIGNUM *bn_c = BN_bin2bn(c, 4, NULL);

    BIGNUM *bn_d = BN_new();
    BIGNUM *bn_t1 = BN_new();
    BIGNUM *bn_t2 = BN_new();
    BIGNUM *bn_t3 = BN_new();

    BN_sub(bn_d, bn_a, bn_b);
    print_bn("a-b", bn_d);
    
    BN_CTX_free(ctx);
    return 0;
}