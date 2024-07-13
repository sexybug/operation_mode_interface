#ifndef _TEST_H_
#define _TEST_H_

#include <stdint.h>

/**
 * @brief 打印内存数据
 *
 * @param ptr
 * @param len
 */
void dump_mem(const void *ptr, int len);
/**
 * @brief 16进制字符串转数组
 *
 * @param str 16进制字符串
 * @param strLen 字节串长度(in Byte)
 * @param out 输出
 */
void HexString2Hex(const char *str, int len, uint8_t *out);

/**
 * Prints the binary representation of the given byte array.
 *
 * @param ptr pointer to the byte array to be printed
 * @param len length of the byte array
 *
 * @return void
 *
 * @throws None
 */
void print_binary(const uint8_t *ptr, int len);

#endif // _TEST_H_