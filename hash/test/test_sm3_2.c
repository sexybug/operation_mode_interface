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
#include "../../test/test.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    uint8_t m_str[] = "6162636461626364616263646162636461626364616263646162636461626364"
                         "6162636461626364616263646162636461626364616263646162636461626364";
    uint8_t hash_str[] = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";

    uint8_t m[64];
    int mlen = 64;
    HexString2Hex(m_str, mlen, m);
    uint8_t out[32];

    sm3(m, mlen, out);
    printf("hash:\n");
    dump_mem(out, 32);
    return 0;
}