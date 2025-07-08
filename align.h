
#ifndef _ALIGN_H_
#define _ALIGN_H_

#include <stdint.h>

#ifndef __align4
#define __align4 __attribute__((aligned(4)))
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline uint32_t GET32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}
static inline void PUT32(uint8_t *p, uint32_t V)
{
    p[0] = (uint8_t)(V);
    p[1] = (uint8_t)(V >> 8);
    p[2] = (uint8_t)(V >> 16);
    p[3] = (uint8_t)(V >> 24);
}
#else
static inline uint32_t GET32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 |
           (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 |
           (uint32_t)p[3];
}
static inline void PUT32(uint8_t *p, uint32_t V)
{
    p[0] = (uint8_t)(V >> 24);
    p[1] = (uint8_t)(V >> 16);
    p[2] = (uint8_t)(V >> 8);
    p[3] = (uint8_t)(V);
}
#endif

#endif //_ALIGN_H_