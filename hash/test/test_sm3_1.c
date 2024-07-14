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
#include <string.h>

int main(int argc, char **argv)
{
    uint8_t m_str[] = "616263";
    uint8_t hash_str[] = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    
    uint8_t m[3], hash[32], out[32];
    int mlen = 3;
    HexString2Hex(m_str, mlen, m);
    HexString2Hex(hash_str, 32, hash);

    sm3(m, mlen, out);
    printf("hash:\n");
    dump_mem(out, 32);
    printf("memcmp result: %d\n", memcmp(out, hash, 32));
    return 0;
}