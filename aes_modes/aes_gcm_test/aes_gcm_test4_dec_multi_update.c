
#include "../../test/test.h"
#include "../../aes/aes.h"
#include "../aes_gcm.h"
#include <string.h>
#include <stdio.h>

int main()
{
    uint8_t K_str[] = "feffe9928665731c6d6a8f9467308308";
    uint8_t IV_str[] = "cafebabefacedbaddecaf888";
    uint8_t AAD_str[] = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    uint8_t P_str[] = "d9313225f88406e5a55909c5aff5269a"
                      "86a7a9531534f7da2e4c303d8a318a72"
                      "1c3c0c95956809532fcf0e2449a6b525"
                      "b16aedf5aa0de657ba637b39";
    uint8_t C_str[] = "42831ec2217774244b7221b784d0d49c"
                      "e3aa212f2c02a4e035c17e2329aca12e"
                      "21d514b25466931c7d8f6a5aac84aa05"
                      "1ba30b396a0aac973d58e091";
    uint8_t T_str[] = "5bc94fbc3221a5db94fae95ae7121a47";

    int K_len = 16;
    int IV_len = 12;
    int AAD_len = 20;
    int P_len = 60;

    __align4 uint8_t std_K[32], std_IV[64], std_AAD[20], std_P[64], std_C[64], std_T[16], out[64], Tag[16];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(IV_str, IV_len, std_IV);
    HexString2Hex(AAD_str, AAD_len, std_AAD);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);
    HexString2Hex(T_str, 16, std_T);

    AES_GCM_CTX ctx;
    aes_gcm_init(&ctx, GCM_DECRYPT, std_K, K_len, std_IV, IV_len, 16);

    int out_len1, out_len2, out_len3;
    aes_gcm_updateAAD(&ctx, std_AAD, 7, 0);
    aes_gcm_updateAAD(&ctx, std_AAD + 7, AAD_len - 7, 1);
    aes_gcm_update(&ctx, std_C, 17, out, &out_len1);
    aes_gcm_update(&ctx, std_C + 17, P_len - 17, out + out_len1, &out_len2);

    aes_gcm_final(&ctx, out + out_len1 + out_len2, &out_len3, Tag);
    dump_mem(out, P_len);
    dump_mem(Tag, 16);

    int cmpOUT = memcmp(out, std_P, P_len);
    int cmpTag = memcmp(Tag, std_T, 16);

    printf("cmpOUT:%d cmpTag:%d\n", cmpOUT, cmpTag);

    return (cmpOUT == 0) && (cmpTag == 0);
}
