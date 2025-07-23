
#include "../hmac_sm3.h"
#include "../../test/test.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    uint8_t key_str[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    uint8_t m_str[] = "6162636461626364616263646162636461626364616263646162636461626364"
                      "6162636461626364616263646162636461626364616263646162636461626364"
                      "6162636461626364616263646162636461626364616263646162636461626364"
                      "61626364616263646162636461626364616263646162636461626364616263";
    uint8_t hash_str[] = "E97A8670285457572DCDCB3330B4F3ED13B2A31686178C5718BCC61D7B42DC8B";

    uint8_t key[32];
    uint8_t m[127];
    int klen = 32;
    int mlen = 127;
    HexString2Hex(key_str, klen, key);
    HexString2Hex(m_str, mlen, m);
    uint8_t out[32];

    HMAC_SM3_CTX ctx;
    hmac_sm3_init(&ctx, key, klen);
    hmac_sm3_update(&ctx, m, 1);
    hmac_sm3_update(&ctx, m + 1, 64);
    hmac_sm3_update(&ctx, m + 1 + 64, mlen - 65);
    hmac_sm3_final(&ctx, out);

    printf("hash:\n");
    dump_mem(out, 32);
    return 0;
}