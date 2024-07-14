
#include "../../test/test.h"
#include "../../aes/aes.h"
#include "../aes_ccm.h"
#include <string.h>
#include <stdio.h>

int main()
{
    uint8_t K_str[] = "404142434445464748494a4b4c4d4e4f";
    uint8_t N_str[] = "101112131415161718191a1b";
    uint8_t A_str[] = "000102030405060708090a0b0c0d0e0f10111213";
    uint8_t P_str[] = "202122232425262728292a2b2c2d2e2f3031323334353637";
    uint8_t C_str[] = "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5";
    uint8_t T_str[] = "484392fbc1b09951";

    int K_len = 16;
    int N_len = 12;
    int A_len = 20;
    int P_len = 24;
    int T_len = 8;

    __align4 uint8_t std_K[32], std_N[16], std_A[20], std_P[64], std_C[64], std_T[16], dec_out[64], tag[16];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(N_str, N_len, std_N);
    HexString2Hex(A_str, A_len, std_A);
    HexString2Hex(P_str, P_len, std_P);
    HexString2Hex(C_str, P_len, std_C);
    HexString2Hex(T_str, T_len, std_T);

    AES_CCM_CTX ctx;
    int ret = aes_ccm_init(&ctx, CCM_DECRYPT, std_K, K_len, std_N, N_len, A_len, P_len, T_len);
    if (ret != 1)
    {
        return -1;
    }
    int out_len;
    aes_ccm_updateAData(&ctx, std_A, A_len, 1);
    aes_ccm_update(&ctx, std_C, P_len, dec_out, &out_len);
    aes_ccm_final(&ctx, dec_out + out_len, &out_len, tag);
    dump_mem(dec_out, P_len);
    dump_mem(tag, T_len);

    int cmpOUT = memcmp(dec_out, std_P, P_len);
    int cmpTag = memcmp(tag, std_T, T_len);

    printf("cmpOUT=%d cmpTag=%d\n", cmpOUT, cmpTag);

    return (cmpOUT == 0) && (cmpTag == 0);
}
