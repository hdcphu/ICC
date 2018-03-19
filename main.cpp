
#include <stdio.h>
#include <cstdint>
#include <cinttypes>

#define DEBUG_OUT printf

void printListUI64(uint64_t *s, int len)
{
    printf("List_ui64 (%i):\n", len);
    for (int i = 0; i < len; i++)
    {
        printf("0x%" PRIx64 "\n", s[i]);
    }
}

uint64_t siphash_2_4(uint64_t *k, uint8_t *m, unsigned int mlen)
{
    //1
    uint32_t v[4];
    v[0] = k[0] ^ 0x736f6d6570736575;
    v[1] = k[1] ^ 0x646f72616e646f6d;
    v[2] = k[0] ^ 0x6c7967656e657261;
    v[3] = k[1] ^ 0x7465646279746573;

    //2
    int b = mlen;
    int w = ((b + 8 + 1) / 8);

    uint64_t mc[w];
    uint64_t t;

    DEBUG_OUT("1\n");
    int j;
    int i = 0;
    
    mc[0] = 0;
    for (j = 0; j < b; j++)
    {
        int bit = 0;
        uint64_t t = ((uint64_t)m[j] << (bit * 8));
        mc[i] |= t;
        bit++;
        if (bit == 8)
        {
            bit = 0;
            i++;
            mc[i] = 0;
        }
        DEBUG_OUT("1:%d %d %d 0x%" PRIX64 "\n", bit, j, m[j], t);
    }
    DEBUG_OUT("2\n");

    mc[i] |= (uint64_t)(b % 256) << 56;
    DEBUG_OUT("3: %d 0x%" PRIX64 "\n", w, t);

    printListUI64(mc, w);
    DEBUG_OUT("4-end\n");

    //compress
    const int c = 2;
    const int d = 4;
    j = 0;
    for (i = 0; i < c; i++)
    {
        v[0]^=mc[j];

    }
}

int main()
{
    uint64_t k[2] = {0, 0};
    uint8_t m1[8] = {0xab};//, 0xb};
    uint8_t m2[8] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
    uint64_t r;

    r = siphash_2_4(k, m2, 8);
    return 0;
}