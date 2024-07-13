#include "test.h"
#include <stdio.h>
#include <stdint.h>

void dump_mem(const void *ptr, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (i % 8 == 0 && i != 0)
        {
            // printf(" ");
        }
        if (i % 16 == 0 && i != 0)
            printf("\n");
        printf("%02X", *((uint8_t *)ptr + i));
        // printf("%02x ", *((uint8_t *)ptr + i));
    }
    printf("\n");
}

uint8_t HexChar2Int(char c)
{
    if (c >= '0' && c <= '9')
    {
        return (c - '0');
    }
    else if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    else if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    else
    {
        return -1;
    }
}

void HexString2Hex(const char *str, int len, uint8_t *out)
{
    for (int i = 0; i < len; i++)
    {
        out[i] = (HexChar2Int(str[i * 2]) << 4) | HexChar2Int(str[i * 2 + 1]);
    }
}

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
void print_binary(const uint8_t *ptr, int len)
{
    for (int i = 0; i < len; i++)
    {
        for (int j = 7; j >= 0; j--)
        {
            printf("%d", (ptr[i] >> j) & 0x01);
        }
        printf(" ");
    }
    printf("\n");
}