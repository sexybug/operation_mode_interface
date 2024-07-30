
#include "../../test/test.h"
#include "../../sm4/sm4.h"
#include "../sm4_gcm.h"
#include <string.h>
#include <stdio.h>

int main()
{
    uint8_t K_str[] = "0123456789ABCDEFFEDCBA9876543210";
    uint8_t IV_str[] = "00001234567800000000ABCD";
    uint8_t AAD_str[] = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2";
    uint8_t P_str[] = "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\
CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD\
EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF\
EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA";
    uint8_t C_str[] = "17F399F08C67D5EE19D0DC9969C4BB7D\
5FD46FD3756489069157B282BB200735\
D82710CA5C22F0CCFA7CBF93D496AC15\
A56834CBCF98C397B4024A2691233B8D";
    uint8_t T_str[] = "83DE3541E4C2B58177E065A9BF7B62EC";

    int K_len = 16;
    int IV_len = 12;
    int AAD_len = 20;
    int P_len = 64;

    __align4 uint8_t std_K[32], std_IV[16], std_AAD[20], std_P[64], std_C[64], std_T[16], out[64], dec_out[64], Tag[16];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(IV_str, IV_len, std_IV);
    HexString2Hex(AAD_str, AAD_len, std_AAD);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);
    HexString2Hex(T_str, 16, std_T);

    SM4_GCM_CTX ctx;
    sm4_gcm_init(&ctx, GCM_DECRYPT, std_K, std_IV, IV_len, 16);

    int out_len1, out_len2;
    sm4_gcm_updateAAD(&ctx, std_AAD, AAD_len, 1);
    sm4_gcm_update(&ctx, std_C, P_len, out, &out_len1);
    sm4_gcm_final(&ctx, out + out_len1, &out_len2, Tag);
    dump_mem(out, P_len);
    dump_mem(Tag, 16);

    int cmpOUT = memcmp(out, std_P, P_len);

    int cmpTag = memcmp(Tag, std_T, 16);

    printf("cmpOUT:%d cmpTag:%d\n", cmpOUT, cmpTag);

    return (cmpOUT == 0) && (cmpTag == 0);
}
