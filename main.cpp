
#include <stdio.h>
#include <cstdint>
#include <cinttypes>
#include <omp.h>
#include <math.h>
#include <random>

#define DEBUG_OUT printf
const uint64_t _WORD_MASK_ = 0xFFFFFFFFFFFFFFFF;

void printListUI64(uint64_t *s, int len)
{
    printf("List_ui64 (%i):\n", len);
    for (int i = 0; i < len; i++)
    {
        printf("0x%" PRIx64 "\n", s[i]);
    }
}

uint64_t myRotL(const uint64_t value, int shift)
{
    if ((shift & _WORD_MASK_) == 0)
        return value;
    return ((value << shift) & _WORD_MASK_) | (value >> 64 - shift);
}

uint64_t siphash_2_4(uint64_t *k, uint8_t *m_origin, unsigned int mlen)
{
    // DEBUG_OUT("The keys:\n");
    // DEBUG_OUT("k0 %" PRIX64 "\n", k[0]);
    // DEBUG_OUT("k1 %" PRIX64 "\n", k[1]);

    //1
    uint64_t v0 = k[0] ^ 0x736f6d6570736575;
    uint64_t v1 = k[1] ^ 0x646f72616e646f6d;
    uint64_t v2 = k[0] ^ 0x6c7967656e657261;
    uint64_t v3 = k[1] ^ 0x7465646279746573;

    // DEBUG_OUT("Xor to the 4 constants:\n");
    // DEBUG_OUT("%" PRIX64 "\n", v0);
    // DEBUG_OUT("%" PRIX64 "\n", v1);
    // DEBUG_OUT("%" PRIX64 "\n", v2);
    // DEBUG_OUT("%" PRIX64 "\n---\n", v3);

    //2
    int b = mlen;
    int w = ((b + 1) / 8);
    if (w == 0 || (b > 0 && b % 8 == 0))
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
        // DEBUG_OUT("1:%d %d 0x%" PRIX64 " 0x%" PRIX64 "\n", bit, j, m[i], t);
    }

    m[w - 1] |= ((uint64_t)(b % 256) << 56);

    // DEBUG_OUT("Compressed message:\n");
    // printListUI64(m, w);
    // DEBUG_OUT("= %d words\n", w);

    const int c = 2;
    const int d = 4;

    //For each m[i]
    for (i = 0; i < w; i++)
    {
        //The m[i] ’s are iteratively processed by doing v3 ⊕= m[i]
        v3 ^= m[i];
        // DEBUG_OUT("Xor mi to v3:\n");
        // DEBUG_OUT("%" PRIX64 "\n", v0);
        // DEBUG_OUT("%" PRIX64 "\n", v1);
        // DEBUG_OUT("%" PRIX64 "\n", v2);
        // DEBUG_OUT("%" PRIX64 "\n---\n", v3);

        //c iterations of SipRound
        for (j = 0; j < c; j++)
        {
            v0 += v1;
            v0 &= _WORD_MASK_;
            v2 += v3;
            v2 &= _WORD_MASK_;

            v1 = myRotL(v1, 13);
            v3 = myRotL(v3, 16);

            v1 ^= v0;
            v3 ^= v2;

            v0 = myRotL(v0, 32);

            v2 += v1;
            v2 &= _WORD_MASK_;
            v0 += v3;
            v0 &= _WORD_MASK_;

            v1 = myRotL(v1, 17);
            v3 = myRotL(v3, 21);

            v1 ^= v2;
            v3 ^= v0;

            v2 = myRotL(v2, 32);
        }

        // DEBUG_OUT("After 2 Sips:\n");
        // DEBUG_OUT("%" PRIX64 "\n", v0);
        // DEBUG_OUT("%" PRIX64 "\n", v1);
        // DEBUG_OUT("%" PRIX64 "\n", v2);
        // DEBUG_OUT("%" PRIX64 "\n---\n", v3);

        //followed by v0 ⊕= m[i]

        v0 ^= m[i];

        // DEBUG_OUT("Xor mi to v0:\n");
        // DEBUG_OUT("%" PRIX64 "\n", v0);
        // DEBUG_OUT("%" PRIX64 "\n", v1);
        // DEBUG_OUT("%" PRIX64 "\n", v2);
        // DEBUG_OUT("%" PRIX64 "\n---\n", v3);
    }

    //Finalization: After all the message words have been processed,
    //  SipHash-c-d xors the constant ff to the state:
    v2 = v2 ^ 0xFF;
    // DEBUG_OUT("Xor v2 to 0xff:\n");
    // DEBUG_OUT("%" PRIX64 "\n", v0);
    // DEBUG_OUT("%" PRIX64 "\n", v1);
    // DEBUG_OUT("%" PRIX64 "\n", v2);
    // DEBUG_OUT("%" PRIX64 "\n---\n", v3);

    //d iterations of SipRound
    for (j = 0; j < d; j++)
    {
        v0 += v1;
        v0 &= _WORD_MASK_;
        v2 += v3;
        v2 &= _WORD_MASK_;

        v1 = myRotL(v1, 13);
        v3 = myRotL(v3, 16);

        v1 ^= v0;
        v3 ^= v2;

        v0 = myRotL(v0, 32);

        v2 += v1;
        v2 &= _WORD_MASK_;
        v0 += v3;
        v0 &= _WORD_MASK_;

        v1 = myRotL(v1, 17);
        v3 = myRotL(v3, 21);

        v1 ^= v2;
        v3 ^= v0;

        v2 = myRotL(v2, 32);
    }

    // DEBUG_OUT("After 4 Sips:\n");
    // DEBUG_OUT("%" PRIX64 "\n", v0);
    // DEBUG_OUT("%" PRIX64 "\n", v1);
    // DEBUG_OUT("%" PRIX64 "\n", v2);
    // DEBUG_OUT("%" PRIX64 "\n---\n", v3);

    uint64_t r = v0 ^ v1 ^ v2 ^ v3;
    return r;
}

uint32_t siphash_fix32(uint32_t k32b, uint32_t m32b)
{
    uint64_t k[2] = { (uint64_t)k32b << 32, 
                      (uint64_t)k32b
                    };

    // uint8_t m[4] = {(uint8_t)(m32b & 0x000000FF), 
    //                 (uint8_t)((m32b & 0xFF000000) >> 24), 
    //                 (uint8_t)((m32b & 0x0000FF00) >> 8),
    //                 (uint8_t)((m32b & 0x00FF0000) >> 16)
    //                 };
    int B = 0;
    int b = 0;
    uint8_t m[8] = {0, 0, 0, 0};
    uint32_t t = m32b;
    uint8_t mask = 1;

    for (int i = 0; i <32; i++)
    {        
        m[B] |= (t & mask) << b;
        t >>= 1;
        b += 2;
        if (b > 7)
        {
            // DEBUG_OUT("m[%d] %" PRIX32 "\n", B, m[B]);
            b = 0;
            B++;            
        }
    }
    // DEBUG_OUT("The keys:\n");
    // DEBUG_OUT("k0 %" PRIX64 "\n", k[0]);
    // DEBUG_OUT("k1 %" PRIX64 "\n", k[1]);


    uint64_t r2_4 = siphash_2_4(k, m, 8);
    uint32_t v0 = (uint32_t)(r2_4 >> 32);
    uint32_t v1 = (uint32_t)(r2_4 & 0x00000000FFFFFFFF);
    if (m32b > 0x0000FFFF) co gi do sai sai
        v0 = myRotL(v0, 7);
    uint32_t r = v0 ^ v1;

    // DEBUG_OUT("%i \t %" PRIX64 " \t %" PRIX32 "\n", m32b, r2_4, r);

    return r;
}   

int main()
{

    std::random_device rd;     //Get a random seed from the OS entropy device, or whatever
    std::mt19937_64 eng(rd()); //Use the 64-bit Mersenne Twister 19937 generator
                                //and seed it with entropy.

    //Define the distribution, by default it goes from 0 to MAX(unsigned long long)
    //or what have you.
    std::uniform_int_distribution<unsigned long long> distr;

    uint64_t k[2] = {0, 0};
    uint64_t k3[2] = {0x0706050403020100, 0x0f0e0d0c0b0a0908};
    uint8_t m1[8] = {0xab, 0x12};
    uint8_t m2[8] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
    uint8_t m3[15] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe};
    uint64_t r;

    // r = siphash_2_4(k, m1, 2);
    // r = siphash_2_4(k, m2, 8);
    // r = siphash_2_4(k3, m3, 15);
    // siphash_fix32(0x12345678, );
    // DEBUG_OUT("SipHash 2 4 = 0x%" PRIX64 "\n", r);
    
    
    #if 1
    uint32_t i;
    uint32_t r32;
    uint32_t num;
    // #pragma omp parallel for schedule(dynamic) private(num, r32)
    
    for (int j = 0; j < 2; j++)
    {
        num = distr(eng);//108108620;//
        r32 = siphash_fix32(0x0, num);
        DEBUG_OUT("Test on: %u\n", num);
        #pragma omp parallel for schedule(dynamic) private(i)
        for (i = 0; i < 0xFFFFFFFF; i++)
        {
            // if (0xC9DEC8C9 == siphash_fix32(0x0, i))
            if (r32 == siphash_fix32(0x0, i))
            {
                DEBUG_OUT("%u ~ %u\n", num, i);
            }
            // if (i % 100000000 == 0)
            //     DEBUG_OUT("-%u\n", i);
        }
    }
    #else
        siphash_fix32(0x0, 0xF2);
        // siphash_fix32(0x0, 149154147ma7);
    #endif
    return 0;
}