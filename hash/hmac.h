
#ifndef _HMAC_H_
#define _HMAC_H_

#include <stdint.h>
#include <stddef.h>
#include "../align.h"

/**
 * @brief 定义初始化hash结构体函数指针
 */
typedef void (*hash_init_f)(void *hash_ctx);

/**
 * @brief 定义hash_update函数指针，功能：输入消息，可多次输入
 */
typedef void (*hash_update_f)(void *hash_ctx, const uint8_t *msg, size_t msg_len);

/**
 * @brief 定义hash_final函数指针，功能：输出摘要
 */
typedef void (*hash_final_f)(void *hash_ctx, uint8_t *digest);

typedef struct
{
    hash_init_f hash_init;
    hash_update_f hash_update;
    hash_final_f hash_final;

    size_t hash_block_size;  // hash块大小：SM3->64字节, SHA256->64字节，SHA512->128字节
    size_t hash_digest_size; // hash摘要大小：SM3->32字节, SHA256->32字节，SHA512->64字节

    uint8_t key[128];
} __align4 HMAC_CTX;

void hmac_init(HMAC_CTX *ctx, void *hash_ctx, const uint8_t *key, size_t key_len,
               hash_init_f hash_init, hash_update_f hash_update, hash_final_f hash_final, size_t hash_block_len, size_t hash_digest_len);

void hmac_update(HMAC_CTX *ctx, void *hash_ctx, const uint8_t *data, size_t data_len);

void hmac_final(HMAC_CTX *ctx, void *hash_ctx, uint8_t *mac);

#endif /* _HMAC_H_ */