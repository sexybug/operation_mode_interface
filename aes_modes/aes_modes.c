
#include "aes_modes.h"
#include "../aes/aes.h"
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

/* block size in bytes */
#define BLOCK_SIZE 16

static int check_key_length(int key_len)
{
    if ((key_len == 16) || (key_len == 24) || (key_len == 32))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

cc_status_t aes_ecb_enc(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        ecb_enc(aes128_enc, BLOCK_SIZE, key, in, in_len, out);
    }
    else if (key_len == 24)
    {
        ecb_enc(aes192_enc, BLOCK_SIZE, key, in, in_len, out);
    }
    else
    {
        ecb_enc(aes256_enc, BLOCK_SIZE, key, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_ecb_dec(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        ecb_dec(aes128_dec, BLOCK_SIZE, key, in, in_len, out);
    }
    else if (key_len == 24)
    {
        ecb_dec(aes192_dec, BLOCK_SIZE, key, in, in_len, out);
    }
    else
    {
        ecb_dec(aes256_dec, BLOCK_SIZE, key, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_cbc_enc(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        cbc_enc(aes128_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if (key_len == 24)
    {
        cbc_enc(aes192_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        cbc_enc(aes256_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_cbc_dec(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        cbc_dec(aes128_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if (key_len == 24)
    {
        cbc_dec(aes192_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        cbc_dec(aes256_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_cfb_enc(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        cfb_enc(aes128_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else if (key_len == 24)
    {
        cfb_enc(aes192_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else
    {
        cfb_enc(aes256_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_cfb_dec(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        cfb_dec(aes128_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else if (key_len == 24)
    {
        cfb_dec(aes192_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else
    {
        cfb_dec(aes256_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_ofb_enc(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        ofb_enc(aes128_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else if (key_len == 24)
    {
        ofb_enc(aes192_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else
    {
        ofb_enc(aes256_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_ofb_dec(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        ofb_dec(aes128_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else if (key_len == 24)
    {
        ofb_dec(aes192_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else
    {
        ofb_dec(aes256_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_ctr_enc(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (in_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        ctr_enc(aes128_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if (key_len == 24)
    {
        ctr_enc(aes192_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        ctr_enc(aes256_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_ctr_dec(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (in_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        ctr_dec(aes128_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if (key_len == 24)
    {
        ctr_dec(aes192_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        ctr_dec(aes256_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_xts_enc(const uint8_t *K1, const uint8_t *K2, int key_len, const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        xts_enc(aes128_enc, BLOCK_SIZE, K1, K2, TW, P, len, C);
    }
    else if (key_len == 24)
    {
        xts_enc(aes192_enc, BLOCK_SIZE, K1, K2, TW, P, len, C);
    }
    else
    {
        xts_enc(aes256_enc, BLOCK_SIZE, K1, K2, TW, P, len, C);
    }

    return CC_SUCCESS;
}
cc_status_t aes_xts_dec(const uint8_t *K1, const uint8_t *K2, int key_len, const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        xts_dec(aes128_enc, aes128_dec, BLOCK_SIZE, K1, K2, TW, C, len, P);
    }
    else if (key_len == 24)
    {
        xts_dec(aes192_enc, aes192_dec, BLOCK_SIZE, K1, K2, TW, C, len, P);
    }
    else
    {
        xts_dec(aes256_enc, aes256_dec, BLOCK_SIZE, K1, K2, TW, C, len, P);
    }

    return CC_SUCCESS;
}

cc_status_t aes_hctr_enc(const uint8_t *K1, int key_len, const uint8_t K2[16], const uint8_t TW[16], const uint8_t *P, int len, uint8_t *C)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        hctr_enc(aes128_enc, BLOCK_SIZE, K1, K2, TW, P, len, C);
    }
    else if (key_len == 24)
    {
        hctr_enc(aes192_enc, BLOCK_SIZE, K1, K2, TW, P, len, C);
    }
    else
    {
        hctr_enc(aes256_enc, BLOCK_SIZE, K1, K2, TW, P, len, C);
    }

    return CC_SUCCESS;
}
cc_status_t aes_hctr_dec(const uint8_t *K1, int key_len, const uint8_t K2[16], const uint8_t TW[16], const uint8_t *C, int len, uint8_t *P)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if (len < BLOCK_SIZE)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        hctr_dec(aes128_enc, aes128_dec, BLOCK_SIZE, K1, K2, TW, C, len, P);
    }
    else if (key_len == 24)
    {
        hctr_dec(aes192_enc, aes192_dec, BLOCK_SIZE, K1, K2, TW, C, len, P);
    }
    else
    {
        hctr_dec(aes256_enc, aes256_dec, BLOCK_SIZE, K1, K2, TW, C, len, P);
    }

    return CC_SUCCESS;
}

cc_status_t aes_bc_enc(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        bc_enc(aes128_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if (key_len == 24)
    {
        bc_enc(aes192_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        bc_enc(aes256_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_bc_dec(const uint8_t *key, int key_len, const uint8_t iv[16], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        bc_dec(aes128_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if (key_len == 24)
    {
        bc_dec(aes192_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        bc_dec(aes256_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t aes_cbc_mac(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t mac[16])
{
    if (in_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if (key_len == 16)
    {
        cbc_mac(aes128_enc, BLOCK_SIZE, key, in, in_len, mac);
    }
    else if (key_len == 24)
    {
        cbc_mac(aes192_enc, BLOCK_SIZE, key, in, in_len, mac);
    }
    else
    {
        cbc_mac(aes256_enc, BLOCK_SIZE, key, in, in_len, mac);
    }

    return CC_SUCCESS;
}

cc_status_t aes_cmac(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t mac[16])
{
    if (key_len == 16)
    {
        cmac(aes128_enc, BLOCK_SIZE, key, in, in_len, mac);
    }
    else if (key_len == 24)
    {
        cmac(aes192_enc, BLOCK_SIZE, key, in, in_len, mac);
    }
    else
    {
        cmac(aes256_enc, BLOCK_SIZE, key, in, in_len, mac);
    }

    return CC_SUCCESS;
}