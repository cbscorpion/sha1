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
#define SHA1_IV_0           UINT32_C(0x67452301)
#define SHA1_IV_1           UINT32_C(0xEFCDAB89)
#define SHA1_IV_2           UINT32_C(0x98BADCFE)
#define SHA1_IV_3           UINT32_C(0x10325476)
#define SHA1_IV_4           UINT32_C(0xC3D2E1F0)
// constants for k-values
#define K_00_19             UINT32_C(0x5A827999)
#define K_20_39             UINT32_C(0x6ED9EBA1)
#define K_40_59             UINT32_C(0x8F1BBCDC)
#define K_60_79             UINT32_C(0xCA62C1D6)
// constants for initial step optimization
#define ROUND_CONSTANT_00   UINT32_C(0x9FB498B3)
#define ROUND_CONSTANT_01   UINT32_C(0x66B0CD0D)
#define ROUND_CONSTANT_02   UINT32_C(0xF33D5697)
#define ROUND_CONSTANT_03   UINT32_C(0xD675E47B)
#define ROUND_CONSTANT_04   UINT32_C(0xB453C259)

// macros for f-functions
#define F_00_19(mB, mC, mD) (mD ^ (mB & (mC ^ mD)))
#define F_40_59(mB, mC, mD) ((mB & mC) ^ (mD & (mB ^ mC)))
#define F_REST(mB, mC, mD)  (mB ^ mC ^ mD)
// macro for circular bitwise left-shift of a 32-bit word (taken from RFC 3174)
#define LEFT_ROTATE(word, bits) (((word) << (bits)) | ((word) >> (32 - (bits))))
// macro for word block expansion
#define GEN_BLOCK(i)                                                                                              \
    temp = (p_blocks[(i - 3) & 15] ^ p_blocks[(i - 8) & 15] ^ p_blocks[(i - 14) & 15] ^ p_blocks[(i - 16) & 15]); \
    p_blocks[i & 15] = LEFT_ROTATE(temp, 1);
// macros for the round additions in first 5 rounds (adding all constant parts at once)
#define ROUND_ADDITION_00                 (ROUND_CONSTANT_00 + p_blocks[0])
#define ROUND_ADDITION_01(mA)             (ROUND_CONSTANT_01 + LEFT_ROTATE(mA, 5) + p_blocks[1])
#define ROUND_ADDITION_02(mA, mB, mC, mD) (ROUND_CONSTANT_02 + LEFT_ROTATE(mA, 5) + F_00_19(mB, mC, mD) + p_blocks[2])
#define ROUND_ADDITION_03(mA, mB, mC, mD) (ROUND_CONSTANT_03 + LEFT_ROTATE(mA, 5) + F_00_19(mB, mC, mD) + p_blocks[3])
#define ROUND_ADDITION_04(mA, mB, mC, mD) (ROUND_CONSTANT_04 + LEFT_ROTATE(mA, 5) + F_00_19(mB, mC, mD) + p_blocks[4])
// macros for setting state variables in each round
#define ROUND_PROCESSING_START(mA, mB, mE, mRoundAddition) \
    mE = mRoundAddition;                                   \
    mB = LEFT_ROTATE(mB, 30);
#define ROUND_PROCESSING_REST(mA, mB, mC, mD, mE, f, k, i)     \
    mE = k + mE + LEFT_ROTATE(mA, 5) + f + (p_blocks[i & 15]); \
    mB = LEFT_ROTATE(mB, 30);
// macros for the round functions
#define ROUND_00_04(mA, mB, mC, mD, mE, mRoundAddition) \
    ROUND_PROCESSING_START(mA, mB, mE, mRoundAddition)
#define ROUND_05_19(mA, mB, mC, mD, mE, i) \
    GEN_BLOCK(i)                           \
    ROUND_PROCESSING_REST(mA, mB, mC, mD, mE, F_00_19(mB, mC, mD), K_00_19, i)
#define ROUND_20_39(mA, mB, mC, mD, mE, i) \
    GEN_BLOCK(i)                           \
    ROUND_PROCESSING_REST(mA, mB, mC, mD, mE, F_REST(mB, mC, mD), K_20_39, i)
#define ROUND_40_59(mA, mB, mC, mD, mE, i) \
    GEN_BLOCK(i)                           \
    ROUND_PROCESSING_REST(mA, mB, mC, mD, mE, F_40_59(mB, mC, mD), K_40_59, i)
#define ROUND_60_79(mA, mB, mC, mD, mE, i) \
    GEN_BLOCK(i)                           \
    ROUND_PROCESSING_REST(mA, mB, mC, mD, mE, F_REST(mB, mC, mD), K_60_79, i)

/**
 * Function: sha1Digest
 * 
 * TODO: add doc here
 */
int sha1Digest
(
    char        *p_input, 
    struct hash *p_result
)
{
    uint32_t a, b, c, d, e, temp;
    uint32_t p_blocks[16];
    // TODO: split input into blocks and calculate word like below
    p_blocks[0] = (p_input[0] << 24)
                | (p_input[1] << 16)
                | (p_input[2] << 8)
                | (p_input[3]);
    // initialize state variables with constants
    a = SHA1_IV_0;
    b = SHA1_IV_1;
    c = SHA1_IV_2;
    d = SHA1_IV_3;
    e = SHA1_IV_4;
    /************ UNROLLED ROUND FUNCTION LOOPS ************/
    // round  00
    ROUND_00_04(a, b, c, d, e, ROUND_ADDITION_00)
    // round  01
    ROUND_00_04(e, a, b, c, d, ROUND_ADDITION_01(e))
    // round  02
    ROUND_00_04(d, e, a, b, c, ROUND_ADDITION_02(d, e, a, b))
    // round  03
    ROUND_00_04(c, d, e, a, b, ROUND_ADDITION_03(c, d, e, a))
    // round  04
    ROUND_00_04(b, c, d, e, a, ROUND_ADDITION_04(b, c, d, e))
    // rounds 05 - 19
    ROUND_05_19(a, b, c, d, e,  5)
    ROUND_05_19(e, a, b, c, d,  6)
    ROUND_05_19(d, e, a, b, c,  7)
    ROUND_05_19(c, d, e, a, b,  8)
    ROUND_05_19(b, c, d, e, a,  9)
    ROUND_05_19(a, b, c, d, e, 10)
    ROUND_05_19(e, a, b, c, d, 11)
    ROUND_05_19(d, e, a, b, c, 12)
    ROUND_05_19(c, d, e, a, b, 13)
    ROUND_05_19(b, c, d, e, a, 14)
    ROUND_05_19(a, b, c, d, e, 15)
    ROUND_05_19(e, a, b, c, d, 16)
    ROUND_05_19(d, e, a, b, c, 17)
    ROUND_05_19(c, d, e, a, b, 18)
    ROUND_05_19(b, c, d, e, a, 19)
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
    p_result->a = SHA1_IV_0 + a;
    p_result->b = SHA1_IV_1 + b;
    p_result->c = SHA1_IV_2 + c;
    p_result->d = SHA1_IV_3 + d;
    p_result->e = SHA1_IV_4 + e;
}
