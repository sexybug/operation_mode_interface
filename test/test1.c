
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "test.h"

int main()
{
    uint8_t data256[256];
    for (size_t i = 0; i < 256; i++) {
        data256[i] = i;
    }
    print_u8("data256", data256, 256);

    return 0;
}
