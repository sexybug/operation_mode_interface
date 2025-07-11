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

    int len = 32;

    uint8_t a[256], b[256], c[256], d[256];
    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    memset(c, 0, sizeof(c));
    memset(d, 0, sizeof(d));
    
    a[0] = 3;
    b[0] = 5;

    memset(c, 0xff, len);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_a = BN_bin2bn(a, len, NULL);
    BIGNUM *bn_b = BN_bin2bn(b, len, NULL);
    BIGNUM *bn_c = BN_bin2bn(c, len, NULL);

    BIGNUM *bn_d = BN_new();

    // int borrow = BN_sub_word(bn_a, 5);
    
    // print_bn("bn_a", bn_a);
    // printf("borrow: %d\n", borrow);

    int borrow = BN_sub(bn_d, bn_a, bn_b);
    print_bn("bn_d", bn_d);
    printf("borrow: %d\n", borrow);

    return 0;
}