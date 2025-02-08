
#include "../sm3.h"
#include "../../test/test.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    uint8_t m[256], out[32];
    uint8_t hash[32]={0x59,0xD1,0x71,0xDB,0xFD,0x25,0x1D,0x5A,0x4C,0xD7,0x7D,0x6B,0xA2,0xB7,0x10,0x9B,0x7D,0x64,0xA4,0xCD,0x7F,0xA8,0x18,0x2B,0xEB,0x10,0x0A,0x01,0x6F,0xA3,0xAC,0x44};
    int mlen = 255;

    int i;
    for(i=0;i<mlen;i++)
    {
        m[i]=i;
    }

    sm3(m, mlen, out);
    print_u8("hash", out, 32);




    sm3_ctx_t ctx;

    int split_len=192;

    sm3_init(&ctx);
    sm3_update(&ctx, m, 65);
    print_u8("ctx.digest", ctx.digest, 32);


    sm3_update(&ctx, m+65, 66);
    print_u8("ctx.digest", ctx.digest, 32);

    sm3_update(&ctx, m+65+66, mlen-65-66);
    print_u8("ctx.digest", ctx.digest, 32);

    sm3_final(&ctx, out);
    print_u8("hash", out, 32);

    int a=0xffff;
    print_u8("a", &a, 4);
    uint32_t a1=0, b1=1;
    printf("%08x\n", a1-b1);
    
    return 0;
}