
#include "../../test/test.h"
#include "../../aes/aes.h"
#include "../aes_ccm.h"
#include <string.h>
#include <stdio.h>

int main()
{
    uint8_t K_str[] = "404142434445464748494a4b4c4d4e4f";
    uint8_t N_str[] = "10111213141516";
    uint8_t A_str[] = "0001020304050607";
    uint8_t P_str[] = "20212223";
    uint8_t C_str[] = "7162015b";
    uint8_t T_str[] = "4dac255d";

    int K_len = 16;
    int N_len = 7;
    int A_len = 8;
    int P_len = 4;
    int T_len = 4;

    __align4 uint8_t std_K[32], std_N[16], std_A[20], std_P[64], std_C[64], std_T[16], enc_out[64], dec_out[64], enc_Tag[16], dec_Tag[16];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(N_str, N_len, std_N);
    HexString2Hex(A_str, A_len, std_A);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);
    HexString2Hex(T_str, T_len, std_T);

    AES_CCM_CTX ctx;
    int ret = aes_ccm_init(&ctx, CCM_ENCRYPT, std_K, K_len, std_N, N_len, A_len, P_len, T_len);
    if (ret != 1)
    {
        return -1;
    }
    int out_len;
    aes_ccm_updateAData(&ctx, std_A, A_len, 1);
    aes_ccm_update(&ctx, std_P, P_len, enc_out, &out_len);
    aes_ccm_final(&ctx, enc_out + out_len, &out_len, enc_Tag);
    dump_mem(enc_out, P_len);
    dump_mem(enc_Tag, T_len);

    int cmpOUT = memcmp(enc_out, std_C, P_len);
    int cmpTag = memcmp(enc_Tag, std_T, T_len);

    printf("cmpOUT = %d, cmpTag = %d\n", cmpOUT, cmpTag);

    return (cmpOUT == 0) && (cmpTag == 0);
}
