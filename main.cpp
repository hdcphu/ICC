
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

uint64_t siphash_2_4(uint64_t *k, uint8_t *m_origin, unsigned int mlen)
{
    //1
    uint64_t v0 = k[0] ^ 0x736f6d6570736575;
    uint64_t v1 = k[1] ^ 0x646f72616e646f6d;
    uint64_t v2 = k[0] ^ 0x6c7967656e657261;
    uint64_t v3 = k[1] ^ 0x7465646279746573;

    //2
    int b = mlen;
    int w = ((b + 1) / 8);
    if (b > 0 && b % 8 == 0)
        w += 1;

    uint64_t m[w];
    uint64_t t;
    
    //compress
    
    int j;
    int i = 0;
    int bit = 0;
    
    m[0] = 0;
    for (j = 0; j < b; j++)
    {
        
        uint64_t t = ((uint64_t)m_origin[j] << (bit * 8));
        m[i] |= t;
        bit++;
        if (bit == 8)
        {
            bit = 0;
            i++;
            m[i] = 0;
        }
        DEBUG_OUT("1:%d %d 0x%" PRIX64 " 0x%" PRIX64 "\n", bit, j, m[i], t);
    }
    

    m[w-1] |= ((uint64_t)(b % 256) << 56);
    
    DEBUG_OUT("Compressed message:\n");
    printListUI64(m, w);
    DEBUG_OUT("= %d words\n", w);

    const int c = 2;
    const int d = 4;

    //For each m[i]
    for (i = 0; i < w; i++)
    {
        //The m[i] ’s are iteratively processed by doing v3 ⊕= m[i]
        v3 = v3 ^ m[i];

        //c iterations of SipRound
        for (j = 0; j < c; j++)
        {
            v0 = v0 + v1;
            v1 = v1 << 13;
            v1 = v1 ^ v0;
            v0 = v0 << 32;
            v2 = v2 + v1;
            v1 = v1 << 17;
            v1 = v1 ^ v2;
            v2 = v2 << 32;
            v2 = v2 + v3;
            v3 = v3 << 16;
            v3 = v3 ^ v2;
            v0 = v0 + v3;
            v3 = v3 << 21;
            v3 = v3 ^ v0;
        }

        //followed by v0 ⊕= m[i]

        v0 = v0 ^ m[i];
    }

    //Finalization: After all the message words have been processed,
    //  SipHash-c-d xors the constant ff to the state:
    v2 = v2 ^ 0xFF;

    //d iterations of SipRound
    for (j = 0; j < d; j++)
    {
        v0 = v0 + v1;
        v1 = v1 << 13;
        v1 = v1 ^ v0;
        v0 = v0 << 32;
        v2 = v2 + v1;
        v1 = v1 << 17;
        v1 = v1 ^ v2;
        v2 = v2 << 32;
        v2 = v2 + v3;
        v3 = v3 << 16;
        v3 = v3 ^ v2;
        v0 = v0 + v3;
        v3 = v3 << 21;
        v3 = v3 ^ v0;
    }

    return (uint64_t)v0 ^ v1 ^ v2 ^ v3;
}

int main()
{
    uint64_t k[2] = {0, 0};
    uint8_t m1[8] = {0xab, 0x12};
    uint8_t m2[8] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
    uint64_t r;

    //r = siphash_2_4(k, m1, 2);
    r = siphash_2_4(k, m2, 8);
    DEBUG_OUT("SipHash 2 4 = 0x%" PRIX64 "\n", r);
    return 0;
}