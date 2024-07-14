
#include "../../test/test.h"
#include "../../aes/aes.h"
#include "../aes_ccm.h"
#include <string.h>
#include <stdio.h>

int main()
{
    uint8_t K_str[] = "404142434445464748494a4b4c4d4e4f";
    uint8_t N_str[] = "101112131415161718191a1b1c";
    uint8_t A_str[] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    uint8_t P_str[] = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    uint8_t C_str[] = "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72";
    uint8_t T_str[] = "b4ac6bec93e8598e7f0dadbcea5b";

    int K_len = 16;
    int N_len = 13;
    int A_len = 65536;
    int P_len = 32;
    int T_len = 14;

    __align4 uint8_t std_K[32], std_N[16], std_A[256], std_P[64], std_C[64], std_T[16], enc_out[64], dec_out[64], enc_Tag[16], dec_Tag[16];

    HexString2Hex(K_str, K_len, std_K);
    HexString2Hex(N_str, N_len, std_N);
    HexString2Hex(A_str, 256, std_A);
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
    int i;
    for (i = 0; i < A_len - 256; i += 256)
    {
        aes_ccm_updateAData(&ctx, std_A, 256, 0);
    }
    aes_ccm_updateAData(&ctx, std_A, 256, 1);

    aes_ccm_update(&ctx, std_P, P_len, enc_out, &out_len);
    aes_ccm_final(&ctx, enc_out + out_len, &out_len, enc_Tag);
    dump_mem(enc_out, P_len);
    dump_mem(enc_Tag, T_len);

    int cmpOUT = memcmp(enc_out, std_C, P_len);
    int cmpTag = memcmp(enc_Tag, std_T, T_len);

    printf("cmpOUT = %d, cmpTag = %d\n", cmpOUT, cmpTag);

    return (cmpOUT == 0) && (cmpTag == 0);
}
