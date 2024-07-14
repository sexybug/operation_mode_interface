
#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>

typedef enum {
    CC_LENGTH_ERROR = -2,
    CC_ERROR = -1,
    CC_SUCCESS = 0,
} cc_status_t;

/**
 * @brief 定义分组算法函数指针, 用于加解密一个分组
 * 
 */
typedef void (*block_f_ptr)(const uint8_t *key, const uint8_t *in, uint8_t *out);



#endif // _COMMON_H_