
#include "sm4_modes.h"
#include "../sm4/sm4.h"
#include "../modes/ecb.h"
#include "../modes/cbc.h"
#include "../modes/cfb.h"
#include "../modes/ofb.h"
#include "../modes/ctr.h"
#include "../modes/xts.h"
#include "../modes/hctr.h"
#include "../modes/bc.h"
#include "../modes/ofbnlf.h"
#include "../modes/cbc_mac.h"
#include "../modes/cmac.h"
#include "../modes/xts_ieee.h"
#include "../modes/xts_gb.h"


/* block size in bytes */
#define BLOCK_SIZE 16

cc_status_t sm4_ecb_enc(const uint8_t key[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    ecb_enc(sm4_enc, BLOCK_SIZE, key, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_ecb_dec(const uint8_t key[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    ecb_dec(sm4_dec, BLOCK_SIZE, key, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_cbc_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    cbc_enc(sm4_enc, BLOCK_SIZE, key, iv, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_cbc_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    cbc_dec(sm4_dec, BLOCK_SIZE, key, iv, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_cfb_enc(int feedback_bit_num, const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    cfb_enc(sm4_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_cfb_dec(int feedback_bit_num, const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    cfb_dec(sm4_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_ofb_enc(int feedback_bit_num, const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    ofb_enc(sm4_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_ofb_dec(int feedback_bit_num, const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    ofb_dec(sm4_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_ctr_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if (in_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    ctr_enc(sm4_enc, BLOCK_SIZE, key, iv, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_ctr_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if (in_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    ctr_dec(sm4_enc, BLOCK_SIZE, key, iv, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_xts_enc(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C)
{
    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    xts_enc(sm4_enc, BLOCK_SIZE, K1, K2, TW, P, len, C);

    return CC_SUCCESS;
}
cc_status_t sm4_xts_dec(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P)
{
    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    xts_dec(sm4_enc, sm4_dec, BLOCK_SIZE, K1, K2, TW, C, len, P);

    return CC_SUCCESS;
}

cc_status_t sm4_hctr_enc(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C)
{
    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    hctr_enc(sm4_enc, BLOCK_SIZE, K1, K2, TW, P, len, C);

    return CC_SUCCESS;
}
cc_status_t sm4_hctr_dec(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P)
{
    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    hctr_dec(sm4_enc, sm4_dec, BLOCK_SIZE, K1, K2, TW, C, len, P);

    return CC_SUCCESS;
}

cc_status_t sm4_bc_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    bc_enc(sm4_enc, BLOCK_SIZE, key, iv, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_bc_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    bc_dec(sm4_dec, BLOCK_SIZE, key, iv, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_ofbnlf_enc(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    ofbnlf_enc(sm4_enc, BLOCK_SIZE, key, iv, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_ofbnlf_dec(const uint8_t key[16], const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    ofbnlf_dec(sm4_enc, sm4_dec, BLOCK_SIZE, key, iv, in, in_len, out);

    return CC_SUCCESS;
}

cc_status_t sm4_cbc_mac(const uint8_t key[16], const uint8_t *in, int in_len, uint8_t mac[16])
{
    if (in_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    cbc_mac(sm4_enc, BLOCK_SIZE, key, in, in_len, mac);

    return CC_SUCCESS;
}

cc_status_t sm4_cmac(const uint8_t key[16], const uint8_t *in, int in_len, uint8_t mac[16])
{
    cmac(sm4_enc, BLOCK_SIZE, key, in, in_len, mac);

    return CC_SUCCESS;
}

cc_status_t sm4_xts_ieee_enc(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C)
{
    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    xts_ieee_enc(sm4_enc, K1, K2, TW, P, len, C);

    return CC_SUCCESS;
}
cc_status_t sm4_xts_ieee_dec(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P)
{
    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    xts_ieee_dec(sm4_enc, sm4_dec, K1, K2, TW, C, len, P);

    return CC_SUCCESS;
}

cc_status_t sm4_xts_gb_enc(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C)
{
    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    xts_gb_enc(sm4_enc, K1, K2, TW, P, len, C);

    return CC_SUCCESS;
}
cc_status_t sm4_xts_gb_dec(const uint8_t K1[16], const uint8_t K2[16], const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P)
{
    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    xts_gb_dec(sm4_enc, sm4_dec, K1, K2, TW, C, len, P);

    return CC_SUCCESS;
}