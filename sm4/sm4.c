/**
 * @file sm4.c
 * @author sexybug (hello.bug@outlook.com)
 * @brief GB_T 32907-2016信息安全技术 SM4分组密码算法 c语言实现
 * @version 0.1
 * @date 2023-02-18
 *
 * @copyright Copyright (c) 2023
 *
 */
#include "sm4.h"

static const uint8_t Sbox[256] =
    {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
     0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
     0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
     0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
     0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
     0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
     0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
     0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
     0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
     0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
     0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
     0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
     0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
     0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
     0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
     0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48};

static const uint32_t FK[4] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};

static const uint32_t CK[32] = {0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
                                0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
                                0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
                                0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
                                0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
                                0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
                                0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
                                0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279};

/**
 * @brief 将X循环左移n位
 *
 * @param
 * @param n
 * @return uint32_t
 */
static inline uint32_t rotl32(uint32_t X, int n)
{
    return (X << n) | (X >> (32 - n));
}
#define LEFTROTATE32(X, n) (((X) << (n)) | ((X) >> (32 - (n))))

/**
 * @brief 获取32位数据第i个字节的值，X=(x0 x1 x2 x3)
 *
 * @param X
 * @param i
 * @return uint8_t
 */
static inline uint8_t byte_at(uint32_t X, int i)
{
    return (X >> (24 - i * 8)) & 0xff;
}

/**
 * @brief uint8数组转uint32数组
 *
 * @param X uint8数组，长度128bit
 * @param Y uint32数组
 */
static void u8_2_u32_128(const uint8_t *X, uint32_t *Y)
{
    for (int i = 0; i < 4; i++)
    {
        Y[i] = ((uint32_t)X[i * 4] << 24) | ((uint32_t)X[i * 4 + 1] << 16) | ((uint32_t)X[i * 4 + 2] << 8) | ((uint32_t)X[i * 4 + 3] << 0);
    }
}

/**
 * @brief uint32数组转uint8数组
 *
 * @param X uint32数组，长度128bit
 * @param Y uint8数组
 */
static void u32_2_u8_128(const uint32_t *X, uint8_t *Y)
{
    for (int i = 0; i < 4; i++)
    {
        Y[i * 4] = (X[i] >> 24) & 0xFF;
        Y[i * 4 + 1] = (X[i] >> 16) & 0xFF;
        Y[i * 4 + 2] = (X[i] >> 8) & 0xFF;
        Y[i * 4 + 3] = (X[i] >> 0) & 0xFF;
    }
}

/**
 * @brief 非线性变换 tau
 *
 * @param A
 * @return uint32_t
 */
static inline uint32_t tau(uint32_t A)
{
    return ((uint32_t)Sbox[(A >> 24) & 0xff] << 24) | ((uint32_t)Sbox[(A >> 16) & 0xff] << 16)
     | ((uint32_t)Sbox[(A >> 8) & 0xff] << 8) | (uint32_t)Sbox[A & 0xff];
}

#define TAU(A) (((uint32_t)Sbox[((A) >> 24) & 0xff] << 24) | ((uint32_t)Sbox[((A) >> 16) & 0xff] << 16) | ((uint32_t)Sbox[((A) >> 8) & 0xff] << 8) | (uint32_t)Sbox[(A) & 0xff])

/**
 * @brief 线性变换 L
 *
 * @param B
 * @return uint32_t
 */
static inline uint32_t L(uint32_t B)
{
    return B ^ LEFTROTATE32(B, 2) ^ LEFTROTATE32(B, 10) ^ LEFTROTATE32(B, 18) ^ LEFTROTATE32(B, 24);
}

/**
 * @brief 合成置换 T
 *
 * @param A
 * @return uint32_t
 */
static inline uint32_t T(uint32_t A)
{
    return L(tau(A));
}

/**
 * @brief 线性变换 L'
 *
 * @param B
 * @return uint32_t
 */
static inline uint32_t LT(uint32_t B)
{
    return B ^ LEFTROTATE32(B, 13) ^ LEFTROTATE32(B, 23);
}

/**
 * @brief 合成置换 T'
 *
 * @param A
 * @return uint32_t
 */
static inline uint32_t TT(uint32_t A)
{
    return LT(tau(A));
}

/**
 * @brief 轮函数 F
 *
 * @param X0
 * @param X1
 * @param X2
 * @param X3
 * @param rk
 * @return uint32_t
 */
static inline uint32_t F(uint32_t X0, uint32_t X1, uint32_t X2, uint32_t X3, uint32_t rk)
{
    return X0 ^ T(X1 ^ X2 ^ X3 ^ rk);
}

/**
 * @brief 加密算法
 *
 * @param X 明文输入(X0,X1,X2,X3)
 * @param rk 轮密钥
 * @param Y 密文输出(Y0,Y1,Y2,Y3)
 */
static void encrypt(const uint32_t *X, const uint32_t *rk, uint32_t *Y)
{
    uint32_t XT[36];
    XT[0] = X[0];
    XT[1] = X[1];
    XT[2] = X[2];
    XT[3] = X[3];

    // 32次迭代运算
    for (int i = 0; i < 32; i++)
    {
        XT[i + 4] = F(XT[i], XT[i + 1], XT[i + 2], XT[i + 3], rk[i]);
    }
    // 反序变换
    Y[0] = XT[35];
    Y[1] = XT[34];
    Y[2] = XT[33];
    Y[3] = XT[32];
}

/**
 * @brief 解密算法
 *
 * @param X 密文输入(X0,X1,X2,X3)
 * @param rk 轮密钥
 * @param Y 明文输出(Y0,Y1,Y2,Y3)
 */
static void decrypt(const uint32_t *X, const uint32_t *rk, uint32_t *Y)
{
    uint32_t XT[36];
    XT[0] = X[0];
    XT[1] = X[1];
    XT[2] = X[2];
    XT[3] = X[3];

    // 32次迭代运算
    for (int i = 0; i < 32; i++)
    {
        XT[i + 4] = F(XT[i], XT[i + 1], XT[i + 2], XT[i + 3], rk[31 - i]);
    }
    // 反序变换
    Y[0] = XT[35];
    Y[1] = XT[34];
    Y[2] = XT[33];
    Y[3] = XT[32];
}

/**
 * @brief 密钥扩展算法
 *
 * @param MK 输入，加密密钥
 * @param rk 输出，轮密钥
 */
static void key_extension(const uint32_t *MK, uint32_t *rk)
{
    uint32_t K[36];
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];
    for (int i = 0; i < 32; i++)
    {
        K[i + 4] = K[i] ^ TT(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

/**
 * @brief 密钥扩展函数
 *
 * @param key
 * @param rk
 */
static void SM4_KeySchedule(const uint8_t *key, uint32_t *rk)
{
    uint32_t MK[4];
    u8_2_u32_128(key, MK);
    key_extension(MK, rk);
}

/**
 * @brief SM4加密函数，输入必须是整分组
 *
 * @param key 128bit密钥
 * @param in 明文输入
 * @param inlen 明文长度(in Byte)
 * @param out 密文输出
 */
void SM4_Encrypt(const uint8_t *key, const uint8_t *in, int inlen, uint8_t *out)
{
    uint32_t rk[32];
    uint32_t P[4], C[4];
    SM4_KeySchedule(key, rk);

    for (int i = 0; i < inlen / 16; i++)
    {
        u8_2_u32_128(in + i * 16, P);
        encrypt(P, rk, C);
        u32_2_u8_128(C, out + i * 16);
    }
}

/**
 * @brief SM4解密函数，输入必须是整分组
 *
 * @param key 128bit密钥
 * @param in 密文输入
 * @param inlen 密文长度(in Byte)
 * @param out 明文输出
 */
void SM4_Decrypt(const uint8_t *key, const uint8_t *in, int inlen, uint8_t *out)
{
    uint32_t rk[32];
    uint32_t C[4], P[4];
    SM4_KeySchedule(key, rk);

    for (int i = 0; i < inlen / 16; i++)
    {
        u8_2_u32_128(in + i * 16, C);
        decrypt(C, rk, P);
        u32_2_u8_128(P, out + i * 16);
    }
}

/**
 * Encrypts a single block of data using the SM4 encryption algorithm.
 *
 * @param key The 128-bit encryption key.
 * @param in The input data to be encrypted (16 bytes).
 * @param out The output buffer where the encrypted data will be stored (16 bytes).
 */
void sm4_enc(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint32_t rk[32];
    uint32_t P[4], C[4];
    SM4_KeySchedule(key, rk);

    u8_2_u32_128(in, P);
    encrypt(P, rk, C);
    u32_2_u8_128(C, out);
}

/**
 * Decrypts a single block of data using the SM4 decryption algorithm.
 *
 * @param key The 128-bit decryption key.
 * @param in The input data to be decrypted (16 bytes).
 * @param out The output buffer where the decrypted data will be stored (16 bytes).
 */
void sm4_dec(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    uint32_t rk[32];
    uint32_t C[4], P[4];
    SM4_KeySchedule(key, rk);

    u8_2_u32_128(in, C);
    decrypt(C, rk, P);
    u32_2_u8_128(P, out);
}