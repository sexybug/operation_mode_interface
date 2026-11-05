
#include "../sha0.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    const uint8_t msg[] = {
        0x61, 0x62, 0x63};
    uint32_t msg_len = 3;
    const uint8_t hash_expected[20] = {0x01, 0x64, 0xb8, 0xa9, 0x14, 0xcd, 0x2a, 0x5e, 0x74, 0xc4, 0xf7, 0xff, 0x08, 0x2c, 0x4d, 0x97, 0xf1, 0xed, 0xf8, 0x80};
    uint8_t hash_out[20] = {0};

    SHA0_CTX ctx;
    sha0_init(&ctx);
    sha0_update(&ctx, msg, msg_len);
    sha0_final(&ctx, hash_out);

    int cmp_result = memcmp(hash_out, hash_expected, 20);
    if (cmp_result == 0)
    {
        printf("Test passed!\n");
    }
    else
    {
        printf("Test failed!\n");
    }
}