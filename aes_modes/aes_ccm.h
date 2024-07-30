
#ifndef _AES_CCM_H_
#define _AES_CCM_H_

#include "../modes/ccm/ccm.h"

typedef struct
{
    CCM_CTX ccm;
} __align4 AES_CCM_CTX;

/**
 * @brief 初始化CTX结构体
 *
 * @param ctx
 * @param enc_dec
 * @param key
 * @param key_len
 * @param nonce
 * @param nonce_len 范围：[7,13]
 * @param AData_len 范围：[0,2^64)
 * @param message_len   范围：[ 0,2^((15-nonce_len)*8) )
 * @param tag_len   范围：{4,6,8,10,12,14,16}
 * @return int 失败值: -1, 成功值: 1
 */
int aes_ccm_init(AES_CCM_CTX *ctx, CCM_ENC_DEC_MODE enc_dec, const uint8_t *key, int key_len, const uint8_t *nonce, uint8_t nonce_len, uint64_t AData_len, uint64_t message_len, uint8_t tag_len);

/**
 * @brief 持续更新AData
 *
 * @param ctx
 * @param AData
 * @param len
 * @param is_last 最后一次更新必须为true
 */
void aes_ccm_updateAData(AES_CCM_CTX *ctx, const uint8_t *AData, int len, bool is_last);

/**
 * @brief 对输入数据进行加密/解密
 * 支持持续输入，支持任何输入长度。
 * 注意: 输入总长度达到整分组后才会有输出。示例：32字节数据进行两次update：update(15)->out_len=0, update(17)->out_len=32.
 *
 * @param ctx
 * @param in
 * @param in_len
 * @param out 
 * @param out_len
 */
void aes_ccm_update(AES_CCM_CTX *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);

/**
 * @brief 输出tag和非整分组加密/解密结果out。如果总输入数据长度%16=0，则无out。
 *
 * @param ctx
 * @param out 
 * @param out_len
 * @param tag
 */
void aes_ccm_final(AES_CCM_CTX *ctx, uint8_t *out, int *out_len, uint8_t *tag);

#endif // _AES_CCM_H_