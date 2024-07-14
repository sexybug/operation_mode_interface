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
#include "../../test/test.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    uint8_t m_str[] = "6162636461626364616263646162636461626364616263646162636461626364"
                         "6162636461626364616263646162636461626364616263646162636461626364"
                         "6162636461626364616263646162636461626364616263646162636461626364"
                         "61626364616263646162636461626364616263646162636461626364616263";
    uint8_t hash_str[] = "e9a39509f0654c8a7b65200d22f75fd83e56a41f39126c9200b95ff1b0821eb4";

    uint8_t m[127];
    int mlen = 127;
    HexString2Hex(m_str, mlen, m);
    uint8_t out[32];

    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, m, 1);
    sm3_update(&ctx, m + 1, 64);
    sm3_update(&ctx, m + 1 + 64, mlen - 65);
    sm3_final(&ctx, out);

    printf("hash:\n");
    dump_mem(out, 32);
    return 0;
}