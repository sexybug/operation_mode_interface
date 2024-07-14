/**
 * @file sm3.h
 * @author sexybug (hello.bug@outlook.com)
 * @brief GB_T 32905-2016 信息安全技术 SM3密码杂凑算法 c语言实现 可多次update输入消息
 * @version 0.1
 * @date 2023-03-05
 *
 * @copyright Copyright (c) 2023
 *
 */

#ifndef _SM3_H_
#define _SM3_H_

#include <stdint.h>
#include <stdlib.h>

typedef struct
{
    uint32_t digest[8];
    int msg_total_len;
    uint8_t buf[64];
} sm3_ctx_t;

/**
 * @brief 初始化上下文
 *
 * @param ctx
 * @return int 0：失败，1：成功
 */
int sm3_init(sm3_ctx_t *ctx);

/**
 * @brief 输入消息，可多次输入
 *
 * @param ctx
 * @param msg 消息
 * @param msg_len 消息长度（in Byte)
 * @return int 0：失败，1：成功
 */
int sm3_update(sm3_ctx_t *ctx, const uint8_t *msg, size_t msg_len);

/**
 * @brief 输出摘要
 *
 * @param ctx
 * @param digest 摘要
 * @return int 0：失败，1：成功
 */
int sm3_final(sm3_ctx_t *ctx, uint8_t *digest);

/**
 * @brief sm3摘要函数
 *
 * @param msg 输入
 * @param msg_len 输入消息长度（in Byte）
 * @param digest 输出：256bit摘要
 */
void sm3(const uint8_t *msg, int msg_len, uint8_t *digest);

#endif /* _SM3_H_ */