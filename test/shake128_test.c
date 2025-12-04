#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int shake(int alg, const uint8_t *in, size_t inlen,
          uint8_t *out, size_t outlen)
{
    EVP_MD_CTX *mdctx;
    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        return -1;
    }

    if (alg == 0)
    {
        if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            return -1;
        }
    }
    else if (alg == 1)
    {
        if (EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            return -1;
        }
    }
    else
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    if (EVP_DigestUpdate(mdctx, in, inlen) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestFinalXOF(mdctx, out, outlen) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

int main()
{
    EVP_MD_CTX *mdctx;
    unsigned char *digest;
    size_t digest_len = 32; // 你可以根据需要调整输出长度
    const char message[] = {0x00, 0x01, 0x02, 0x03};
    int message_len = 4;

    // 创建并初始化摘要上下文
    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        printf("Failed to create EVP_MD_CTX\n");
        return 1;
    }

    // 初始化SHAKE128摘要操作
    if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1)
    {
        printf("Failed to initialize SHAKE128\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // 处理消息
    if (EVP_DigestUpdate(mdctx, message, message_len) != 1)
    {
        printf("Failed to update digest\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // 分配内存用于存储摘要
    digest = (unsigned char *)malloc(digest_len);
    if (digest == NULL)
    {
        printf("Failed to allocate memory for digest\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // 获取摘要
    if (EVP_DigestFinalXOF(mdctx, digest, digest_len) != 1)
    {
        printf("Failed to finalize digest\n");
        free(digest);
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // 打印摘要
    printf("Digest: ");
    for (size_t i = 0; i < digest_len; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");

    // 清理
    free(digest);
    EVP_MD_CTX_free(mdctx);

    return 0;
}
