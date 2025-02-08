
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

int main()
{
    static const uint64_t arr[10] = {
        0x0000000000000001, 0x0000000000000002, 0x0000000000000004, 0x0000000000000008, 0x0000000000000010, 0x0000000000000020, 0x0000000000000040, 0x0000000000000080,
        0x0000000000000100, 0x0000000000000200
    };

    assert(arr != NULL);
    assert(sizeof(arr) / sizeof(arr[0]) == 10);

    print_u64("arr", arr, sizeof(arr) / sizeof(arr[0]));

    return 0;
}
