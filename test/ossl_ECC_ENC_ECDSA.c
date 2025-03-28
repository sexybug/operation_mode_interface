#include "test.h"
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

/**
 * @brief 打印大数（BIGNUM）的值。
 *
 * 该函数将大数（BIGNUM）转换为二进制格式，并通过调用print_u8函数打印出来。
 *
 * @param name  要打印的大数的名称。
 * @param bn    要打印的大数（BIGNUM）。
 */
void print_bn(const char *name, const BIGNUM *bn)
{
    uint8_t buf[1024];  // 定义一个缓冲区用于存储大数的二进制表示，大小为1024字节。
    BN_bn2bin(bn, buf); // 将大数（BIGNUM）转换为二进制格式并存储在缓冲区buf中。
    print_u8(name, buf, BN_num_bytes(bn)); // 调用print_u8函数打印大数的二进制表示。
}

/**
 * @brief 打印椭圆曲线点 (EC Point) 的坐标。
 *
 * 该函数接收一个椭圆曲线点及其所属的椭圆曲线群，并打印出该点的坐标 (x, y)。
 *
 * @param name 椭圆曲线点的名称，用于打印时的标识。
 * @param point 指向椭圆曲线点的指针。
 * @param group 指向椭圆曲线群的指针。
 * @param bn_ctx 指向大数上下文 (BN_CTX) 的指针，用于大数运算。
 */
void print_ec_point(const char *name, const EC_POINT *point, const EC_GROUP *group, BN_CTX *bn_ctx)
{
    // 打印椭圆曲线点的名称
    printf("%s:\n", name);

    // 创建两个大数对象用于存储椭圆曲线点的 x 和 y 坐标
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    // 获取椭圆曲线点的 x 和 y 坐标
    EC_POINT_get_affine_coordinates(group, point, x, y, bn_ctx);

    // 打印 x 坐标
    print_bn("x", x);
    // 打印 y 坐标
    print_bn("y", y);

    // 释放大数对象
    BN_free(x);
    BN_free(y);
}

void print_ec_group(const char *name, const EC_GROUP *group, BN_CTX *bn_ctx)
{
    printf("%s:\n", name);
    // 打印EC_GROUP所有参数
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    EC_GROUP_get_curve(group, p, a, b, NULL);

    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const BIGNUM *cofactor = EC_GROUP_get0_cofactor(group);

    print_bn("p", p);
    print_bn("a", a);
    print_bn("b", b);
    print_ec_point("G", generator, group, bn_ctx);
    print_bn("order", order);
    print_bn("cofactor", cofactor);

    BN_free(p);
    BN_free(a);
    BN_free(b);
}

// 函数EC_GROUP_setup用于设置椭圆曲线群（EC_GROUP）的参数
void EC_GROUP_setup(EC_GROUP *group,
                    const uint8_t *p, size_t p_len, const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                    const uint8_t *x, size_t x_len, const uint8_t *y, size_t y_len, const uint8_t *n, size_t n_len, const uint8_t *h, size_t h_len, BN_CTX *bn_ctx)
{
    BIGNUM *p_bn = BN_bin2bn(p, p_len, NULL);
    BIGNUM *a_bn = BN_bin2bn(a, a_len, NULL);
    BIGNUM *b_bn = BN_bin2bn(b, b_len, NULL);
    BIGNUM *x_bn = BN_bin2bn(x, x_len, NULL);
    BIGNUM *y_bn = BN_bin2bn(y, y_len, NULL);
    BIGNUM *n_bn = BN_bin2bn(n, n_len, NULL);
    BIGNUM *h_bn = BN_bin2bn(h, h_len, NULL);

    EC_GROUP_set_curve(group, p_bn, a_bn, b_bn, bn_ctx);
    EC_POINT *generator = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, generator, x_bn, y_bn, bn_ctx);
    EC_GROUP_set_generator(group, generator, n_bn, h_bn);

    BN_free(p_bn);
    BN_free(a_bn);
    BN_free(b_bn);
    BN_free(x_bn);
    BN_free(y_bn);
    BN_free(n_bn);
    BN_free(h_bn);
}

int ECC_ENC(const EC_GROUP *group, const EC_POINT *pub_key, const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len, BN_CTX *bn_ctx)
{
    BIGNUM *k_bn = BN_new();

    // generate k in [1, n-1]
    do
    {
        if (!BN_rand_range(k_bn, EC_GROUP_get0_order(group)))
        {
            break;
        }
    } while (BN_is_zero(k_bn));
    BN_set_word(k_bn, 0x07);

    // R = kG
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, k_bn, NULL, NULL, bn_ctx);

    // Q = kP
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_mul(group, Q, NULL, pub_key, k_bn, bn_ctx);

    BIGNUM *m_bn = BN_bin2bn(plain, plain_len, NULL);

    if (BN_is_zero(m_bn) || BN_cmp(m_bn, EC_GROUP_get0_order(group)) >= 0)
    {
        return -1;
    }

    // c = m * Qx mod n
    BIGNUM *c_bn = BN_new();
    const BIGNUM *n = EC_GROUP_get0_order(group);

    BIGNUM *Qx = BN_new();
    BIGNUM *Qy = BN_new();
    
    EC_POINT_get_affine_coordinates(group, Q, Qx, Qy, bn_ctx);

    BN_mod_mul(c_bn, m_bn, Qx, n, bn_ctx);

    // cipher = R || c
    int byte_len = (EC_GROUP_get_degree(group) + 7) / 8;
    byte_len = ((byte_len + 3) / 4) * 4;

    BIGNUM *Rx = BN_new();
    BIGNUM *Ry = BN_new();
    
    EC_POINT_get_affine_coordinates(group, R, Rx, Ry, bn_ctx);
    BN_bn2binpad(Rx, cipher, byte_len);
    BN_bn2binpad(Ry, cipher + byte_len, byte_len);
    BN_bn2binpad(c_bn, cipher + 2 * byte_len, byte_len);

    *cipher_len = 3 * byte_len;

    BN_free(k_bn);
    EC_POINT_free(R);
    EC_POINT_free(Q);
    BN_free(m_bn);
    BN_free(c_bn);
    BN_free(Qx);
    BN_free(Qy);
    BN_free(Rx);
    BN_free(Ry);

    return 0;
}

int ECC_DEC(const EC_GROUP *group, const BIGNUM *priv_key, const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len, BN_CTX *bn_ctx)
{
    int byte_len = (EC_GROUP_get_degree(group) + 7) / 8;
    byte_len = ((byte_len + 3) / 4) * 4;

    BIGNUM *Rx = BN_bin2bn(cipher, byte_len, NULL);
    BIGNUM *Ry = BN_bin2bn(cipher + byte_len, byte_len, NULL);
    BIGNUM *c = BN_bin2bn(cipher + 2 * byte_len, byte_len, NULL);

    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, R, Rx, Ry, bn_ctx);

    // check R
    if (EC_POINT_is_at_infinity(group, R) || (EC_POINT_is_on_curve(group, R, bn_ctx) != 1))
    {
        return -1;
    }

    // Q = priv_key * R
    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_mul(group, Q, NULL, R, priv_key, bn_ctx);

    BIGNUM *Qx = BN_new();
    BIGNUM *Qy = BN_new();
    EC_POINT_get_affine_coordinates(group, Q, Qx, Qy, bn_ctx);

    // m = c * Qx^(-1) mod n
    BIGNUM *m = BN_new();
    const BIGNUM *n = EC_GROUP_get0_order(group);

    BN_mod_inverse(m, Qx, n, bn_ctx);
    BN_mod_mul(m, m, c, n, bn_ctx);

    BN_bn2binpad(m, plain, byte_len);
    *plain_len = byte_len;

    BN_free(Rx);
    BN_free(Ry);
    BN_free(c);
    EC_POINT_free(R);
    EC_POINT_free(Q);
    BN_free(Qx);
    BN_free(Qy);
    BN_free(m);

    return 0;
}

// ECC521 加解密测试
void test_ECC_ENC()
{
    BN_CTX *bn_ctx = BN_CTX_new();

    // 设置椭圆曲线参数
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);

    // 打印EC_GROUP
    print_ec_group("group", group, bn_ctx);

    uint8_t priv_key[68] = {
        0x00, 0x00, 0x01, 0x80, 0x5B, 0x4D, 0xDA, 0xED, 0x83, 0xB6, 0x4C, 0xF5, 0xB3, 0x09, 0x1C, 0xB5, 0x28, 0x99, 0x8E, 0x3E, 0x1E, 0x3A, 0x8A, 0x08, 0x5D, 0x95, 0x98, 0x48, 0xC0, 0xA0, 0xB6, 0xCF, 0xCA, 0x46, 0xF6, 0xFD, 0x15, 0x41, 0x6C, 0x4D, 0xFD, 0x53, 0x3E, 0x1B, 0x5F, 0xD1, 0xE9, 0xCB, 0x33, 0x34, 0x8D, 0x63, 0xFD, 0xD9, 0x0A, 0x87, 0xC7, 0x58, 0xD9, 0xDA, 0x6C, 0x68, 0x06, 0x27, 0x6F, 0x85, 0x2B, 0xAB};

    uint8_t pub_key_x[68] = {
        0x00, 0x00, 0x00, 0x2C, 0x8A, 0x7C, 0x68, 0xD4, 0x5C, 0x44, 0x1B, 0xD0, 0xA4, 0x8E, 0x06, 0xC9, 0xE2, 0x27, 0xCF, 0x96, 0x9F, 0xE7, 0x63, 0x31, 0xBB, 0x37, 0x62, 0xD3, 0xCF, 0xF1, 0x21, 0x90, 0x6D, 0xE6, 0x05, 0x4E, 0xD8, 0x9C, 0x8C, 0x85, 0xDA, 0x10, 0x2A, 0x88, 0xA4, 0x74, 0x02, 0xB1, 0x75, 0xFE, 0xAB, 0x28, 0xEB, 0xE4, 0x30, 0xEA, 0x6E, 0x29, 0xD1, 0x3F, 0xAB, 0x5E, 0x90, 0xA7, 0x6A, 0xC9, 0x2A, 0x60};

    uint8_t pub_key_y[68] = {
        0x00, 0x00, 0x01, 0x91, 0x42, 0xE6, 0xA3, 0x0C, 0x60, 0x87, 0x74, 0xA9, 0x7D, 0x0D, 0xB0, 0x36, 0xCE, 0x0D, 0x7B, 0x9B, 0xE4, 0xAE, 0x15, 0x42, 0x41, 0xE6, 0xCE, 0x6C, 0xFC, 0xF0, 0xA8, 0x1E, 0xEC, 0x48, 0x35, 0xF8, 0xC7, 0xCA, 0x31, 0xCB, 0xFE, 0xA3, 0x18, 0x30, 0x48, 0xD9, 0xA4, 0x7A, 0x29, 0x82, 0x6F, 0xE2, 0xC4, 0x8D, 0xAC, 0x56, 0x32, 0xC7, 0xA4, 0x2F, 0x31, 0x5C, 0x7E, 0xE6, 0x3A, 0x8D, 0xF4, 0x8F};

    // 生成密钥对
    // BIGNUM *priv_key = BN_new();
    // BN_bin2bn(d, sizeof(d), priv_key);
    // BN_set_word(priv_key, 0x07);
    // EC_POINT *pub_key = EC_POINT_new(group);
    // EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, bn_ctx);
    // print_ec_point("pub_key", pub_key, group, bn_ctx);

    // 设置公私钥
    BIGNUM *priv_key_bn = BN_bin2bn(priv_key, sizeof(priv_key), NULL);

    BIGNUM *pub_key_x_bn = BN_bin2bn(pub_key_x, sizeof(pub_key_x), NULL);
    BIGNUM *pub_key_y_bn = BN_bin2bn(pub_key_y, sizeof(pub_key_y), NULL);
    EC_POINT *pub_key = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, pub_key, pub_key_x_bn, pub_key_y_bn, bn_ctx);

    uint8_t plain[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t cipher[68 * 3] = {0};
    size_t cipher_len = 0;

    uint8_t M[68] = {0};
    memcpy(M + 68 - sizeof(plain), plain, sizeof(plain));
    ECC_ENC(group, pub_key, M, 68, cipher, &cipher_len, bn_ctx);

    print_u8("cipher", cipher, cipher_len);

    uint8_t M1[68] = {0};
    size_t M1_len = 0;
    ECC_DEC(group, priv_key_bn, cipher, cipher_len, M1, &M1_len, bn_ctx);
    print_u8("M1", M1, M1_len);

    BN_free(priv_key_bn);
    EC_POINT_free(pub_key);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
}

// ECDSA 521签名验签测试
void test_ECDSA()
{
    BN_CTX *bn_ctx = BN_CTX_new();

    uint8_t priv_key[68] = {
        0x00, 0x00, 0x01, 0x80, 0x5B, 0x4D, 0xDA, 0xED, 0x83, 0xB6, 0x4C, 0xF5, 0xB3, 0x09, 0x1C, 0xB5, 0x28, 0x99, 0x8E, 0x3E, 0x1E, 0x3A, 0x8A, 0x08, 0x5D, 0x95, 0x98, 0x48, 0xC0, 0xA0, 0xB6, 0xCF, 0xCA, 0x46, 0xF6, 0xFD, 0x15, 0x41, 0x6C, 0x4D, 0xFD, 0x53, 0x3E, 0x1B, 0x5F, 0xD1, 0xE9, 0xCB, 0x33, 0x34, 0x8D, 0x63, 0xFD, 0xD9, 0x0A, 0x87, 0xC7, 0x58, 0xD9, 0xDA, 0x6C, 0x68, 0x06, 0x27, 0x6F, 0x85, 0x2B, 0xAB};

    uint8_t pub_key_x[68] = {
        0x00, 0x00, 0x00, 0x2C, 0x8A, 0x7C, 0x68, 0xD4, 0x5C, 0x44, 0x1B, 0xD0, 0xA4, 0x8E, 0x06, 0xC9, 0xE2, 0x27, 0xCF, 0x96, 0x9F, 0xE7, 0x63, 0x31, 0xBB, 0x37, 0x62, 0xD3, 0xCF, 0xF1, 0x21, 0x90, 0x6D, 0xE6, 0x05, 0x4E, 0xD8, 0x9C, 0x8C, 0x85, 0xDA, 0x10, 0x2A, 0x88, 0xA4, 0x74, 0x02, 0xB1, 0x75, 0xFE, 0xAB, 0x28, 0xEB, 0xE4, 0x30, 0xEA, 0x6E, 0x29, 0xD1, 0x3F, 0xAB, 0x5E, 0x90, 0xA7, 0x6A, 0xC9, 0x2A, 0x60};

    uint8_t pub_key_y[68] = {
        0x00, 0x00, 0x01, 0x91, 0x42, 0xE6, 0xA3, 0x0C, 0x60, 0x87, 0x74, 0xA9, 0x7D, 0x0D, 0xB0, 0x36, 0xCE, 0x0D, 0x7B, 0x9B, 0xE4, 0xAE, 0x15, 0x42, 0x41, 0xE6, 0xCE, 0x6C, 0xFC, 0xF0, 0xA8, 0x1E, 0xEC, 0x48, 0x35, 0xF8, 0xC7, 0xCA, 0x31, 0xCB, 0xFE, 0xA3, 0x18, 0x30, 0x48, 0xD9, 0xA4, 0x7A, 0x29, 0x82, 0x6F, 0xE2, 0xC4, 0x8D, 0xAC, 0x56, 0x32, 0xC7, 0xA4, 0x2F, 0x31, 0x5C, 0x7E, 0xE6, 0x3A, 0x8D, 0xF4, 0x8F};
    // sha256(0x00,0x01...0x7F)
    uint8_t Z[32] = {0x47, 0x1F, 0xB9, 0x43, 0xAA, 0x23, 0xC5, 0x11, 0xF6, 0xF7, 0x2F, 0x8D, 0x16, 0x52, 0xD9, 0xC8, 0x80, 0xCF, 0xA3, 0x92, 0xAD, 0x80, 0x50, 0x31, 0x20, 0x54, 0x77, 0x03, 0xE5, 0x6A, 0x2B, 0xE5};

    uint8_t std_r[68] = {
        0x00, 0x00, 0x01, 0xE3, 0xA4, 0x9F, 0x69, 0x7C, 0x6B, 0x4C, 0xC1, 0xC1, 0x14, 0xA8, 0x1A, 0xCC, 0x33, 0xF2, 0xF4, 0xDD, 0x1C, 0x7D, 0x5F, 0x8F, 0x19, 0x7A, 0x27, 0x4E, 0xAF, 0xC9, 0x7D, 0x68, 0x5C, 0x7F, 0x38, 0x4B, 0xE1, 0xC7, 0xEF, 0xF8, 0xE1, 0xF4, 0x59, 0x51, 0x87, 0x76, 0xB3, 0x7A, 0xAB, 0xA8, 0xB9, 0xB9, 0x05, 0x59, 0xA2, 0x1C, 0x0C, 0xCB, 0x23, 0xC4, 0x29, 0x91, 0xE5, 0x7D, 0x7D, 0x53, 0x9B, 0xCA};

    uint8_t std_s[68] = {
        0x00, 0x00, 0x01, 0x1E, 0x07, 0x21, 0x75, 0x3A, 0x9E, 0xFA, 0xC6, 0x76, 0x80, 0x88, 0xC1, 0x2F, 0x04, 0x95, 0x85, 0x87, 0x8D, 0x39, 0x74, 0x9D, 0x77, 0x1A, 0x83, 0x2A, 0xAF, 0xE4, 0x64, 0xFC, 0xC6, 0x6C, 0xAC, 0x5C, 0x03, 0x7E, 0x79, 0xC7, 0xC4, 0x87, 0x85, 0xB8, 0x2E, 0x2C, 0x16, 0xBF, 0xF7, 0xF3, 0x00, 0x9F, 0x2F, 0x2E, 0x1C, 0xD1, 0x53, 0x7C, 0xC5, 0x00, 0xFC, 0x4E, 0x0F, 0x74, 0x46, 0xF0, 0xD4, 0x2B};

    // 设置公私钥
    BIGNUM *priv_key_bn = BN_bin2bn(priv_key, sizeof(priv_key), NULL);
    BIGNUM *pub_key_x_bn = BN_bin2bn(pub_key_x, sizeof(pub_key_x), NULL);
    BIGNUM *pub_key_y_bn = BN_bin2bn(pub_key_y, sizeof(pub_key_y), NULL);

    
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp521r1);
    EC_KEY_set_private_key(eckey, priv_key_bn);
    EC_KEY_set_public_key_affine_coordinates(eckey, pub_key_x_bn, pub_key_y_bn);

    // 签名
    ECDSA_SIG *ecdsa_sig = ECDSA_do_sign(Z, 32, eckey);
    const BIGNUM *r = ECDSA_SIG_get0_r(ecdsa_sig);
    const BIGNUM *s = ECDSA_SIG_get0_s(ecdsa_sig);
    print_bn("r", r);
    print_bn("s", s);
    // 验签
    int verify1 = ECDSA_do_verify(Z, 32, ecdsa_sig, eckey);
    printf("verify1: %d\n", verify1);

    BIGNUM *std_r_bn = BN_bin2bn(std_r, sizeof(std_r), NULL);
    BIGNUM *std_s_bn = BN_bin2bn(std_s, sizeof(std_s), NULL);
    ECDSA_SIG_set0(ecdsa_sig, std_r_bn, std_s_bn);
    // 验签
    int verify2 = ECDSA_do_verify(Z, 32, ecdsa_sig, eckey);
    printf("verify2: %d\n", verify2);

    BN_free(priv_key_bn);
    BN_free(pub_key_x_bn);
    BN_free(pub_key_y_bn);
    BN_free(std_r_bn);
    BN_free(std_s_bn);
    EC_KEY_free(eckey);
    ECDSA_SIG_free(ecdsa_sig);
    BN_CTX_free(bn_ctx);
}

int main()
{
    printf("ECC_ENC\n");
    test_ECC_ENC();

    printf("ECDSA\n");
    test_ECDSA();
    return 0;
}