
#include "des_modes.h"
#include "../3des/3des.h"
#include "../modes/ecb.h"
#include "../modes/cbc.h"
#include "../modes/cfb.h"
#include "../modes/ofb.h"
#include "../modes/ctr.h"
#include "../modes/bc.h"
#include "../modes/cbc_mac.h"
#include "../modes/cmac.h"

/* block size in bytes */
#define BLOCK_SIZE 8

static int check_key_length(int key_len)
{
    if ((key_len == 8) || (key_len == 16) || (key_len == 24))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

cc_status_t des_ecb_enc(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        ecb_enc(des_enc, BLOCK_SIZE, key, in, in_len, out);
    }
    else if(key_len == 16)
    {
        ecb_enc(des3_2key_enc, BLOCK_SIZE, key, in, in_len, out);
    }
    else
    {
        ecb_enc(des3_3key_enc, BLOCK_SIZE, key, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_ecb_dec(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        ecb_dec(des_dec, BLOCK_SIZE, key, in, in_len, out);
    }
    else if(key_len == 16)
    {
        ecb_dec(des3_2key_dec, BLOCK_SIZE, key, in, in_len, out);
    }
    else
    {
        ecb_dec(des3_3key_dec, BLOCK_SIZE, key, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_cbc_enc(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        cbc_enc(des_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if(key_len == 16)
    {
        cbc_enc(des3_2key_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        cbc_enc(des3_3key_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_cbc_dec(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        cbc_dec(des_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if(key_len == 16)
    {
        cbc_dec(des3_2key_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        cbc_dec(des3_3key_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_cfb_enc(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        cfb_enc(des_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else if(key_len == 16)
    {
        cfb_enc(des3_2key_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else
    {
        cfb_enc(des3_3key_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_cfb_dec(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        cfb_dec(des_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else if(key_len == 16)
    {
        cfb_dec(des3_2key_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else
    {
        cfb_dec(des3_3key_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_ofb_enc(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        ofb_enc(des_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else if(key_len == 16)
    {
        ofb_enc(des3_2key_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else
    {
        ofb_enc(des3_3key_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_ofb_dec(int feedback_bit_num, const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_bit_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if (in_bit_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        ofb_dec(des_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else if(key_len == 16)
    {
        ofb_dec(des3_2key_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }
    else
    {
        ofb_dec(des3_3key_enc, BLOCK_SIZE, feedback_bit_num, key, iv, in, in_bit_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_ctr_enc(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if (in_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        ctr_enc(des_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if(key_len == 16)
    {
        ctr_enc(des3_2key_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        ctr_enc(des3_3key_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_ctr_dec(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if (in_len == 0)
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        ctr_dec(des_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if(key_len == 16)
    {
        ctr_dec(des3_2key_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        ctr_dec(des3_3key_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_bc_enc(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        bc_enc(des_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if(key_len == 16)
    {
        bc_enc(des3_2key_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        bc_enc(des3_3key_enc, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_bc_dec(const uint8_t *key, int key_len, const uint8_t iv[8], const uint8_t *in, int in_len, uint8_t *out)
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }
    if ((in_len == 0) || (in_len % BLOCK_SIZE != 0))
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        bc_dec(des_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else if(key_len == 16)
    {
        bc_dec(des3_2key_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }
    else
    {
        bc_dec(des3_3key_dec, BLOCK_SIZE, key, iv, in, in_len, out);
    }

    return CC_SUCCESS;
}

cc_status_t des_cbc_mac(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t mac[8])
{
    if (!check_key_length(key_len))
    {
        return CC_LENGTH_ERROR;
    }

    if(key_len == 8)
    {
        cbc_mac(des_enc, BLOCK_SIZE, key, in, in_len, mac);
    }
    else if(key_len == 16)
    {
        cbc_mac(des3_2key_enc, BLOCK_SIZE, key, in, in_len, mac);
    }
    else
    {
        cbc_mac(des3_3key_enc, BLOCK_SIZE, key, in, in_len, mac);
    }

    return CC_SUCCESS;
}

cc_status_t des_cmac(const uint8_t *key, int key_len, const uint8_t *in, int in_len, uint8_t mac[8])
{
    if(key_len == 8)
    {
        cmac(des_enc, BLOCK_SIZE, key, in, in_len, mac);
    }
    else if(key_len == 16)
    {
        cmac(des3_2key_enc, BLOCK_SIZE, key, in, in_len, mac);
    }
    else
    {
        cmac(des3_3key_enc, BLOCK_SIZE, key, in, in_len, mac);
    }

    return CC_SUCCESS;
}