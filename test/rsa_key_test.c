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
    
    BN_CTX *bn_ctx = BN_CTX_new();
    // 生成RSA密钥对
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BN_set_word(e, RSA_F4); // 公钥指数为65537
    
    BN_hex2bn(&p, "E2C7B7CFB473BA8D17E51F9CA436B985E1D094431219E108DBEEB42B427AC70679795F69105BAFB103090051BFA0A5EC3C44EC2B76DBA43F765FB870B93BB95100E271B14BEB5EBA00FA0AFAB0640D2334F9EA26918E0F0E81C1BD9AB93A4CCA06B44698A29ADAFE73926266573E757EDB77D36C161DF706CA275B16D10A12E3B23D7D01DCB718BBFC037FAFD9562AC792E5223B29580D10A3A23571BD00AE26CA12444A33CD7D58DEACFA35CFFC5D563FE3B66BE767D62688C0A3642E98F7478E40C673E1FA01FA39CE263265E4648D30F29BD292E73492643AB497E8A39ED7E1A1936961EE94CC9F7630E89DA223C7078DB26341F82CC15A278FA60A9F5D89");
    BN_hex2bn(&q, "D22708FDF7D2139F602783CB204F21A846AD6956F88507CD194A93D15A80BF7EDC7C03634EE7815B59B651D28CA9BAD959B1C20B42373ECA3A5880BAA006DFD06425B048939E90AC77F56963954DFC7A5ABA0720E6119E8FA146C0B0D7310B576468CCBB154C44C205B51B74DBF0040DB72DC0CF3F0FC008A4A5F008826EA266DC24178181AB9E286EC2A1774E6847A2511AF689F92ACD31E1F9F9619EC264AB27A03B22CD697A94A68DEBCA2FAE88954360666AC6EBE67FBF27C25F675EFB742CF9F1EF5E7A6B33FCD97E2AD753D400021C0ED84E84B10EA10EC4B1EC6043D3D6E1005E786D2106BE3A618BBF2E4C1D3B3F08F9276E572CD0EB99F44197C9A1");

    RSA_set0_factors(rsa, p, q);
    RSA_generate_multi_prime_key(rsa, bit_len, 2, e, NULL);

    print_rsa_key(rsa);

    BN_CTX_free(bn_ctx);
    RSA_free(rsa);
    BN_free(e);
    BN_free(p);
    BN_free(q);

    return 0;
}