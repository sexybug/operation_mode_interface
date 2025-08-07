
#include "../sm3.h"
#include "../kdf_sm3.h"
#include "../../test/test.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    char Z_str[] = "6162636461626364616263646162636461626364616263646162636461626364";
    char shared_info_str[] = "6162636461626364616263646162636461626364616263646162636461626364";
    char hash_str[] = "B90CB75DDC3D5F2573CBD0B93AD6363F2142892272D00A743F98ABD69E7BD546"
                      "90CBD1704DF8531BED36DA098968A45CE1E3AC29B45496ABC9BE09166BECCCD9";

    uint8_t Z[64], shared_info[64], key[64];
    int Zlen = 32, key_len = 64;
    HexString2Hex(Z_str, Zlen, Z);
    HexString2Hex(shared_info_str, 32, shared_info);
    uint8_t key_out[64];

    KDF_CTX kdf_ctx;
    kdf_sm3_init(&kdf_ctx);
    kdf_sm3_derive(&kdf_ctx, Z, Zlen, shared_info, 32, key_out, key_len);

    printf("key:\n");
    dump_mem(key_out, key_len);
    return 0;
}