
#include "../../test/test.h"
#include "../../sm4/sm4.h"
#include "../sm4_ccm.h"
#include <string.h>
#include <stdio.h>

int main()
{
    uint8_t K_str[] = "0123456789ABCDEFFEDCBA9876543210";
    uint8_t N_str[] = "00001234567800000000ABCD";
    uint8_t A_str[] = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2";
    uint8_t P_str[] = "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB\
CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD\
EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF\
EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA";
    uint8_t C_str[] = "48AF93501FA62ADBCD414CCE6034D895\
DDA1BF8F132F042098661572E7483094\
FD12E518CE062C98ACEE28D95DF4416B\
ED31A2F04476C18BB40C84A74B97DC5B";
    uint8_t T_str[] = "16842D4FA186F56AB33256971FA110F4";

    int K_len = 16;
    int N_len = 12;
    int A_len = 20;
    int P_len = 64;
    int T_len = 16;

    __align4 uint8_t std_K[32], std_N[16], std_A[20], std_P[64], std_C[64], std_T[16], enc_out[64], tag[16];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(N_str, N_len, std_N);
    HexString2Hex(A_str, A_len, std_A);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);
    HexString2Hex(T_str, T_len, std_T);

    SM4_CCM_CTX ctx;
    int ret = sm4_ccm_init(&ctx, CCM_ENCRYPT, std_K, K_len, std_N, N_len, A_len, P_len, T_len);
    if (ret != 1)
    {
        return -1;
    }
    int out_len;
    sm4_ccm_updateAData(&ctx, std_A, A_len, 1);
    sm4_ccm_update(&ctx, std_P, P_len, enc_out, &out_len);
    sm4_ccm_final(&ctx, enc_out + out_len, &out_len, tag);
    dump_mem(enc_out, P_len);
    dump_mem(tag, T_len);

    int cmpOUT = memcmp(enc_out, std_C, P_len);
    int cmpTag = memcmp(tag, std_T, T_len);

    printf("cmpOUT=%d cmpTag=%d\n", cmpOUT, cmpTag);

    return (cmpOUT == 0) && (cmpTag == 0);
}
