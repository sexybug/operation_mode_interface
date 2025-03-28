#include <stdint.h>
#include "test.h"

/**
 * @brief 将字节数组转换为无符号32位整数数组（大数表示）
 *
 * 该函数将输入的字节数组（长度为byte_len）转换为无符号32位整数数组（长度为bn_word_len）。
 * 转换过程中，会在字节数组前添加适当数量的零字节，以确保总长度为bn_word_len*4字节。
 * u8数组左边为最高字节。大数数组右边的u32为最大值，左边的u32为最小值。
 * example: 0x01, 0x02, 0x03 -> 0x00010203, 0x00000000
 *
 * @param src 输入的字节数组
 * @param byte_len 输入字节数组的长度
 * @param bn_word_len 输出无符号32位整数数组的长度
 * @param bn 输出的无符号32位整数数组
 */
void u8_to_bn_ex(const uint8_t *src, int byte_len, int bn_word_len, uint32_t *bn)
{
    int i;
    // 计算需要填充的零字节长度
    int zero_pad_len = bn_word_len * 4 - byte_len;
    // 将bn数组的前zero_pad_len/4个32位整数初始化为零
    for (i = 0; i < zero_pad_len / 4; i++)
    {
        bn[bn_word_len - 1 - i] = 0;
    }

    uint32_t src_index = 0;
    // 如果零填充长度不是4的倍数，则处理剩余的字节
    if (zero_pad_len % 4 != 0)
    {
        src_index = 4 - zero_pad_len % 4;

        uint32_t tmp = 0;
        // 将剩余的字节组合成一个32位整数
        for (i = 0; i < src_index; i++)
        {
            tmp = tmp << 8;
            tmp |= src[i];
        }
        // 将组合后的32位整数存储在bn数组的相应位置
        bn[bn_word_len - 1 - zero_pad_len / 4] = tmp;
    }

    // 处理剩余的字节，每4个字节转换为一个32位整数
    for (i = (zero_pad_len + 3) / 4; i < bn_word_len; i++)
    {
        bn[bn_word_len - 1 - i] = (uint32_t)src[src_index] << 24 | 
                                  (uint32_t)src[src_index + 1] << 16 | 
                                  (uint32_t)src[src_index + 2] << 8 | 
                                  (uint32_t)src[src_index + 3];
        src_index += 4;
    }
}

/**
 * @brief 将大数（以32位无符号整数数组表示）转换为字节数组。
 *
 * 该函数将一个由32位无符号整数组成的大数转换为字节数组。
 * example: 0x00010203, 0x00000000 -> 0x00, 0x00, 0x00,0x00, 0x00, 0x01, 0x02, 0x03
 *
 * @param bn 指向大数（32位无符号整数数组）的指针。
 * @param bn_word_len 大数的长度，即32位无符号整数的数量。
 * @param dest 指向存储结果的字节数组的指针。
 */
void bn_to_u8_ex(const uint32_t *bn, int bn_word_len, uint8_t *dest)
{
    int i;
    for (i = 0; i < bn_word_len; i++)
    {
        // 将32位整数的最高8位存储到目标字节数组中
        dest[i * 4] = (uint8_t)(bn[bn_word_len-1-i] >> 24);
        // 将32位整数的次高8位存储到目标字节数组中
        dest[i * 4 + 1] = (uint8_t)(bn[bn_word_len-1-i] >> 16);
        // 将32位整数的次低8位存储到目标字节数组中
        dest[i * 4 + 2] = (uint8_t)(bn[bn_word_len-1-i] >> 8);
        // 将32位整数的最低8位存储到目标字节数组中
        dest[i * 4 + 3] = (uint8_t)(bn[bn_word_len-1-i]);
    }
}

