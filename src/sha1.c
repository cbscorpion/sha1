/*
 * This file is part of <https://github.com/cbscorpion/sha1>.
 * Copyright (c) 2018 Christoph Buttler.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include "sha1.h"

// constants for hash state initialisation
#define SHA1_IV_0   UINT32_C(0x67452301)
#define SHA1_IV_1   UINT32_C(0xEFCDAB89)
#define SHA1_IV_2   UINT32_C(0x98BADCFE)
#define SHA1_IV_3   UINT32_C(0x10325476)
#define SHA1_IV_4   UINT32_C(0xC3D2E1F0)
// constants for k-values
#define K_00_19     UINT32_C(0x5A827999)
#define K_20_39     UINT32_C(0x6ED9EBA1)
#define K_40_59     UINT32_C(0x8F1BBCDC)
#define K_60_79     UINT32_C(0xCA62C1D6)
// constants to replace mod with and
#define MOD_NUM_4   UINT32_C(0x00000003)
#define MOD_NUM_16  UINT32_C(0x0000000F)
#define MOD_NUM_64  UINT64_C(0x0000003F)
#define MOD_BIT_32  UINT64_C(0xFFFFFFFF)

// macros for f-functions
#define F_00_19(mB, mC, mD) (mD ^ (mB & (mC ^ mD)))
#define F_40_59(mB, mC, mD) ((mB & mC) ^ (mD & (mB ^ mC)))
#define F_REST(mB, mC, mD)  (mB ^ mC ^ mD)
// macro for circular bitwise left-shift of a 32-bit word (taken from RFC 3174)
#define LEFT_ROTATE(word, bits) (((word) << (bits)) | ((word) >> (32 - (bits))))
// macro for word block expansion
#define GEN_BLOCK(i)                                                                                                          \
    temp = (p_currChunk[(i - 3) & 15] ^ p_currChunk[(i - 8) & 15] ^ p_currChunk[(i - 14) & 15] ^ p_currChunk[(i - 16) & 15]); \
    p_currChunk[i & 15] = LEFT_ROTATE(temp, 1);
// macro for setting state variables in each round
#define ROUND_PROCESSING(mA, mB, mC, mD, mE, f, k, i)             \
    mE = k + mE + LEFT_ROTATE(mA, 5) + f + (p_currChunk[i & 15]); \
    mB = LEFT_ROTATE(mB, 30);
// macros for the round functions
#define ROUND_00_15(mA, mB, mC, mD, mE, i) \
    ROUND_PROCESSING(mA, mB, mC, mD, mE, F_00_19(mB, mC, mD), K_00_19, i)
#define ROUND_16_19(mA, mB, mC, mD, mE, i) \
    GEN_BLOCK(i)                           \
    ROUND_PROCESSING(mA, mB, mC, mD, mE, F_00_19(mB, mC, mD), K_00_19, i)
#define ROUND_20_39(mA, mB, mC, mD, mE, i) \
    GEN_BLOCK(i)                           \
    ROUND_PROCESSING(mA, mB, mC, mD, mE, F_REST(mB, mC, mD),  K_20_39, i)
#define ROUND_40_59(mA, mB, mC, mD, mE, i) \
    GEN_BLOCK(i)                           \
    ROUND_PROCESSING(mA, mB, mC, mD, mE, F_40_59(mB, mC, mD), K_40_59, i)
#define ROUND_60_79(mA, mB, mC, mD, mE, i) \
    GEN_BLOCK(i)                           \
    ROUND_PROCESSING(mA, mB, mC, mD, mE, F_REST(mB, mC, mD),  K_60_79, i)

// function prototype
static void sha1Update(uint32_t    *p_currChunk,
                       struct hash *p_hashState);

/**
 * Function: sha1Digest
 */
int sha1Digest
(
    struct buff *p_input, 
    struct hash *p_result
)
{
    uint32_t    iterationsNeeded,
                i;
    uint64_t    temp,
                inputLengthBit;
    uint32_t    *p_preprocessedBlocks;
    /*********************** PADDING ***********************/
    inputLengthBit = p_input->l_data << 3;
    // we need space for a '1' bit at the end of data
    temp = UINT64_C(1) + p_input->l_data;
    iterationsNeeded = temp / 64;
    // check if there is enough space left to append the input length in bit
    if((temp & MOD_NUM_64) <= 56)
        iterationsNeeded++;
    else
        iterationsNeeded += 2;
    // allocate memory block with (iterationsNeeded * 16 * sizeof(uint32_t)) bytes
    p_preprocessedBlocks = malloc(iterationsNeeded << 6);
    if(p_preprocessedBlocks == NULL)
        return E_DIGEST_MEMALLOC;
    // do not use memcpy to set preprocessed blocks, because big endian is required
    for(i = 0; i < (p_input->l_data / 4); i++)
    {
        p_preprocessedBlocks[i] = (p_input->p_data[    (i << 2)] << 24)
                                | (p_input->p_data[1 | (i << 2)] << 16)
                                | (p_input->p_data[2 | (i << 2)] <<  8)
                                | (p_input->p_data[3 | (i << 2)]);
    }
    // set '1' bit at the end of data
    switch(p_input->l_data & MOD_NUM_4)
    {
        case 0: p_preprocessedBlocks[i] = 0x80000000;
                break;
        case 1: p_preprocessedBlocks[i] = (p_input->p_data[    (i << 2)] << 24)
                                        | 0x00800000;
                break;
        case 2: p_preprocessedBlocks[i] = (p_input->p_data[    (i << 2)] << 24)
                                        | (p_input->p_data[1 | (i << 2)] << 16)
                                        | 0x00008000;
                break;
        case 3: p_preprocessedBlocks[i] = (p_input->p_data[    (i << 2)] << 24)
                                        | (p_input->p_data[1 | (i << 2)] << 16)
                                        | (p_input->p_data[2 | (i << 2)] <<  8)
                                        | 0x00000080;
    }
    i++;
    // do zero padding if needed
    while((i & MOD_NUM_16) != 14)
    {
        p_preprocessedBlocks[i] = 0;
        i++;
    }
    // append original message length
    p_preprocessedBlocks[i    ] = inputLengthBit >> 32;
    p_preprocessedBlocks[i + 1] = inputLengthBit & MOD_BIT_32;
    /*******************************************************/
    // initialize hash state with constants
    p_result->a = SHA1_IV_0;
    p_result->b = SHA1_IV_1;
    p_result->c = SHA1_IV_2;
    p_result->d = SHA1_IV_3;
    p_result->e = SHA1_IV_4;
    // loop through iterations
    for(i = 0; i < iterationsNeeded; i++)
    {
        sha1Update((p_preprocessedBlocks + (i << 4)),
                   p_result);
    }
    // pointer can not be NULL here
    free(p_preprocessedBlocks);

    return 0;
}
/**
 * Function: sha1Update
 */
static void sha1Update
(
    uint32_t    *p_currChunk,
    struct hash *p_hashState
)
{
    static uint32_t a, b, c, d, e, temp;
    // set state variables to current hash state
    a = p_hashState->a;
    b = p_hashState->b;
    c = p_hashState->c;
    d = p_hashState->d;
    e = p_hashState->e;
    /************ UNROLLED ROUND FUNCTION LOOPS ************/
    // rounds 00 - 15
    ROUND_00_15(a, b, c, d, e,  0)
    ROUND_00_15(e, a, b, c, d,  1)
    ROUND_00_15(d, e, a, b, c,  2)
    ROUND_00_15(c, d, e, a, b,  3)
    ROUND_00_15(b, c, d, e, a,  4)
    ROUND_00_15(a, b, c, d, e,  5)
    ROUND_00_15(e, a, b, c, d,  6)
    ROUND_00_15(d, e, a, b, c,  7)
    ROUND_00_15(c, d, e, a, b,  8)
    ROUND_00_15(b, c, d, e, a,  9)
    ROUND_00_15(a, b, c, d, e, 10)
    ROUND_00_15(e, a, b, c, d, 11)
    ROUND_00_15(d, e, a, b, c, 12)
    ROUND_00_15(c, d, e, a, b, 13)
    ROUND_00_15(b, c, d, e, a, 14)
    ROUND_00_15(a, b, c, d, e, 15)
    // rounds 16 - 19
    ROUND_16_19(e, a, b, c, d, 16)
    ROUND_16_19(d, e, a, b, c, 17)
    ROUND_16_19(c, d, e, a, b, 18)
    ROUND_16_19(b, c, d, e, a, 19)
    // rounds 20 - 39
    ROUND_20_39(a, b, c, d, e, 20)
    ROUND_20_39(e, a, b, c, d, 21)
    ROUND_20_39(d, e, a, b, c, 22)
    ROUND_20_39(c, d, e, a, b, 23)
    ROUND_20_39(b, c, d, e, a, 24)
    ROUND_20_39(a, b, c, d, e, 25)
    ROUND_20_39(e, a, b, c, d, 26)
    ROUND_20_39(d, e, a, b, c, 27)
    ROUND_20_39(c, d, e, a, b, 28)
    ROUND_20_39(b, c, d, e, a, 29)
    ROUND_20_39(a, b, c, d, e, 30)
    ROUND_20_39(e, a, b, c, d, 31)
    ROUND_20_39(d, e, a, b, c, 32)
    ROUND_20_39(c, d, e, a, b, 33)
    ROUND_20_39(b, c, d, e, a, 34)
    ROUND_20_39(a, b, c, d, e, 35)
    ROUND_20_39(e, a, b, c, d, 36)
    ROUND_20_39(d, e, a, b, c, 37)
    ROUND_20_39(c, d, e, a, b, 38)
    ROUND_20_39(b, c, d, e, a, 39)
    // rounds 40 - 59
    ROUND_40_59(a, b, c, d, e, 40)
    ROUND_40_59(e, a, b, c, d, 41)
    ROUND_40_59(d, e, a, b, c, 42)
    ROUND_40_59(c, d, e, a, b, 43)
    ROUND_40_59(b, c, d, e, a, 44)
    ROUND_40_59(a, b, c, d, e, 45)
    ROUND_40_59(e, a, b, c, d, 46)
    ROUND_40_59(d, e, a, b, c, 47)
    ROUND_40_59(c, d, e, a, b, 48)
    ROUND_40_59(b, c, d, e, a, 49)
    ROUND_40_59(a, b, c, d, e, 50)
    ROUND_40_59(e, a, b, c, d, 51)
    ROUND_40_59(d, e, a, b, c, 52)
    ROUND_40_59(c, d, e, a, b, 53)
    ROUND_40_59(b, c, d, e, a, 54)
    ROUND_40_59(a, b, c, d, e, 55)
    ROUND_40_59(e, a, b, c, d, 56)
    ROUND_40_59(d, e, a, b, c, 57)
    ROUND_40_59(c, d, e, a, b, 58)
    ROUND_40_59(b, c, d, e, a, 59)
    // rounds 60 - 79
    ROUND_60_79(a, b, c, d, e, 60)
    ROUND_60_79(e, a, b, c, d, 61)
    ROUND_60_79(d, e, a, b, c, 62)
    ROUND_60_79(c, d, e, a, b, 63)
    ROUND_60_79(b, c, d, e, a, 64)
    ROUND_60_79(a, b, c, d, e, 65)
    ROUND_60_79(e, a, b, c, d, 66)
    ROUND_60_79(d, e, a, b, c, 67)
    ROUND_60_79(c, d, e, a, b, 68)
    ROUND_60_79(b, c, d, e, a, 69)
    ROUND_60_79(a, b, c, d, e, 70)
    ROUND_60_79(e, a, b, c, d, 71)
    ROUND_60_79(d, e, a, b, c, 72)
    ROUND_60_79(c, d, e, a, b, 73)
    ROUND_60_79(b, c, d, e, a, 74)
    ROUND_60_79(a, b, c, d, e, 75)
    ROUND_60_79(e, a, b, c, d, 76)
    ROUND_60_79(d, e, a, b, c, 77)
    ROUND_60_79(c, d, e, a, b, 78)
    ROUND_60_79(b, c, d, e, a, 79)
    /*******************************************************/
    // add this chunks hash to hash state
    p_hashState->a += a;
    p_hashState->b += b;
    p_hashState->c += c;
    p_hashState->d += d;
    p_hashState->e += e;
}
