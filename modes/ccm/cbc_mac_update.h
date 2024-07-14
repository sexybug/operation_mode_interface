
#ifndef _CBC_MAC_UPDATE_H_
#define _CBC_MAC_UPDATE_H_

#include <stdint.h>
#include "../../align.h"

typedef void (*cipher_f)(const uint8_t *key, const uint8_t *in, uint8_t *out);

typedef struct
{
    uint8_t key[32]; // key buffer
    uint8_t in_buf[16];
    uint8_t mac_buf[16]; // MAC buffer
    int block_len;       // 算法分组长度
    int total_len;   // 输入总长度
    cipher_f cipher; // 加密算法函数
} __align4 CBC_MAC_CTX;

void cbc_mac_init(CBC_MAC_CTX *ctx, cipher_f cipher, const uint8_t *key, int key_len, int block_len);
void cbc_mac_update(CBC_MAC_CTX *ctx, const uint8_t *in, int in_len);
/**
 * @brief 输出MAC值
 * 不满整分组的，用0填充后计算MAC值；MAC值被保存在CTX中，final后可继续update。
 *
 * @param ctx
 * @param mac
 */
void cbc_mac_final(CBC_MAC_CTX *ctx, uint8_t *mac);

#endif // _CBC_MAC_UPDATE_H_