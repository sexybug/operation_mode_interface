/**
 * @file sm3.h
 * @author sexybug (hello.bug@outlook.com)
 * @brief GB_T 32905-2016 信息安全技术 SM3密码杂凑算法 示例1数据测试
 * @version 0.1
 * @date 2023-02-18
 *
 * @copyright Copyright (c) 2023
 *
 */
#include "../sm3.h"
#include "../../test.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    uint8_t m_str[6] = "616263";
    uint8_t hash_str[] = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    uint8_t m[3];
    int mlen = 3;
    HexString2Hex(m_str, mlen * 2, m);
    uint8_t out[32];

    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, m, 1);
    sm3_update(&ctx, m + 1, 2);
    sm3_final(&ctx, out);

    printf("hash:\n");
    dump_mem(out, 32);
    return 0;
}