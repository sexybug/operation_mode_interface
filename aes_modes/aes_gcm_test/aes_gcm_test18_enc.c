
#include "../../test/test.h"
#include "../../aes/aes.h"
#include "../aes_gcm.h"
#include <string.h>
#include <stdio.h>

int main()
{
    uint8_t K_str[] = "feffe9928665731c6d6a8f9467308308\
feffe9928665731c6d6a8f9467308308";
    uint8_t IV_str[] = "9313225df88406e555909c5aff5269aa\
6a7a9538534f7da1e4c303d2a318a728\
c3c0c95156809539fcf0e2429a6b5254\
16aedbf5a0de6a57a637b39b";
    uint8_t AAD_str[] = "feedfacedeadbeeffeedfacedeadbeef\
abaddad2";
    uint8_t P_str[] = "d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b39";
    uint8_t C_str[] = "5a8def2f0c9e53f1f75d7853659e2a20\
eeb2b22aafde6419a058ab4f6f746bf4\
0fc0c3b780f244452da3ebf1c5d82cde\
a2418997200ef82e44ae7e3f";
    uint8_t T_str[] = "a44a8266ee1c8eb0c8b5d4cf5ae9f19a";

    int K_len = 32;
    int IV_len = 60;
    int AAD_len = 20;
    int P_len = 60;

    __align4 uint8_t std_K[32], std_IV[64], std_AAD[20], std_P[64], std_C[64], std_T[16], out[64], dec_out[64], Tag[16];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(IV_str, IV_len, std_IV);
    HexString2Hex(AAD_str, AAD_len, std_AAD);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);
    HexString2Hex(T_str, 16, std_T);

    AES_GCM_CTX ctx;
    aes_gcm_init(&ctx, GCM_ENCRYPT, std_K, K_len, std_IV, IV_len, 16);

    int out_len1, out_len2;
    aes_gcm_updateAAD(&ctx, std_AAD, AAD_len, 1);
    aes_gcm_update(&ctx, std_P, P_len, out, &out_len1);

    aes_gcm_final(&ctx, out + out_len1, &out_len2, Tag);
    dump_mem(out, P_len);
    dump_mem(Tag, 16);

    int cmpOUT = memcmp(out, std_C, P_len);
    int cmpTag = memcmp(Tag, std_T, 16);

    printf("cmpOUT:%d cmpTag:%d\n", cmpOUT, cmpTag);

    return (cmpOUT == 0) && (cmpTag == 0);
}
