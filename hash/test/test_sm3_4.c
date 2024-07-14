/**
 * @file sm3.h
 * @author sexybug (hello.bug@outlook.com)
 * @brief 多次输入消息测试
 * @version 0.1
 * @date 2023-03-05
 *
 * @copyright Copyright (c) 2023
 *
 */
#include "../sm3.h"
#include "../../test.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    uint8_t m_str[128] = "6162636461626364616263646162636461626364616263646162636461626364"
                         "6162636461626364616263646162636461626364616263646162636461626364";
    uint8_t hash_str[] = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
    uint8_t m[64];
    int mlen = 64;
    HexString2Hex(m_str, mlen * 2, m);

    uint8_t out[32];

    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, m, 1);
    sm3_update(&ctx, m + 1, 63);
    sm3_final(&ctx, out);

    printf("hash:\n");
    dump_mem(out, 32);
    return 0;
}