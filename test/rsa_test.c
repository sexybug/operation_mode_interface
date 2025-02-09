#include "test.h"
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

//获取RSA私钥中的 n e d p q dp dq invq 并以16进制打印 
void print_rsa_key(RSA *rsa) 
{
    const BIGNUM *n = RSA_get0_n(rsa);
    const BIGNUM *e = RSA_get0_e(rsa);
    const BIGNUM *d = RSA_get0_d(rsa);
    const BIGNUM *p = RSA_get0_p(rsa);
    const BIGNUM *q = RSA_get0_q(rsa);
    const BIGNUM *dp = RSA_get0_dmp1(rsa);
    const BIGNUM *dq = RSA_get0_dmq1(rsa);
    const BIGNUM *invq = RSA_get0_iqmp(rsa);

    uint8_t n_buf[512];
    BN_bn2bin(n, n_buf);
    print_u8("n", n_buf, BN_num_bytes(n));

    uint8_t e_buf[512];
    BN_bn2bin(e, e_buf);
    print_u8("e", e_buf, BN_num_bytes(e));

    uint8_t d_buf[512];
    BN_bn2bin(d, d_buf);
    print_u8("d", d_buf, BN_num_bytes(d));

    uint8_t p_buf[512];
    BN_bn2bin(p, p_buf);
    print_u8("p", p_buf, BN_num_bytes(p));

    uint8_t q_buf[512];
    BN_bn2bin(q, q_buf);
    print_u8("q", q_buf, BN_num_bytes(q));

    uint8_t dp_buf[512];
    BN_bn2bin(dp, dp_buf);
    print_u8("dp", dp_buf, BN_num_bytes(dp));

    uint8_t dq_buf[512];
    BN_bn2bin(dq, dq_buf);
    print_u8("dq", dq_buf, BN_num_bytes(dq));

    uint8_t invq_buf[512];
    BN_bn2bin(invq, invq_buf);
    print_u8("invq", invq_buf, BN_num_bytes(invq));
}

int main() {
    uint32_t bit_len = 4096;
    
    // 生成RSA密钥对
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4); // 公钥指数为65537
    
    RSA_generate_key_ex(rsa, bit_len, e, NULL);

    print_rsa_key(rsa);

    // 加密数据
    uint8_t plaintext[512];
    memset(plaintext, 0, bit_len/8);
    plaintext[0] = 0x01;
    plaintext[bit_len/8-1] = 0x01;
    print_u8("plaintext", plaintext, bit_len/8);

    uint8_t ciphertext[512];
    int ciphertext_len = RSA_public_encrypt(bit_len/8, plaintext, ciphertext, rsa, RSA_NO_PADDING);
    if (ciphertext_len == -1) {
        handleErrors();
    }
    print_u8("ciphertext", ciphertext, ciphertext_len);

    // 解密数据
    uint8_t decrypted[512];
    int decrypted_len = RSA_private_decrypt(ciphertext_len, ciphertext, decrypted, rsa, RSA_NO_PADDING);
    if (decrypted_len == -1) {
        handleErrors();
    }
    print_u8("decrypted", decrypted, decrypted_len);

    RSA_free(rsa);
    BN_free(e);

    return 0;
}