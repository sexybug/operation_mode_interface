
#ifndef KDF_H
#define KDF_H

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

    size_t hash_digest_size; // hash摘要大小：SM3->32字节, SHA256->32字节，SHA512->64字节

    uint32_t counter;
} __align4 KDF_CTX;

void kdf_init(KDF_CTX *kdf_ctx,
              hash_init_f hash_init, hash_update_f hash_update, hash_final_f hash_final,
              size_t hash_digest_size);

void kdf_derive_block(KDF_CTX *kdf_ctx, void *hash_ctx, const uint8_t *Z, size_t Z_len, const uint8_t *shared_info, size_t shared_info_len, uint8_t *Ki);

// derive key
// if it's not the last block, key_len must be multiple of hash_digest_size
void kdf_derive(KDF_CTX *kdf_ctx, void *hash_ctx, const uint8_t *Z, size_t Z_len, const uint8_t *shared_info, size_t shared_info_len, uint8_t *key, size_t key_len);

#endif  // KDF_H