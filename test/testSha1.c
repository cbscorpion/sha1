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
#include "testSha1.h"

// function prototype
void printHashDiff(const struct hash *p_hashExpected, struct hash *p_hashReceived);

// test vectors
const struct sha1TestVec testVectors[] = { { "ananas",
                                           { 0x755BD810, 0xD2BE0EBC, 0xBB6CE6F5, 0x32B3D9CF, 0xCF9D9695 }},
                                           { "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
                                           { 0x6d5025dd, 0x783aab6a, 0x0fd279bd, 0xb5fb7e0a, 0xea6cd1d5 }},
                                           { "passwd",
                                           { 0x30274C47, 0x903BD1BA, 0xC7633BBF, 0x09743149, 0xEBAB805F }},
                                           { "1234567890123456789012345678901234567890123456789012345",
                                           { 0x827a683f, 0xdfdbef22, 0x5a242107, 0x8b7789b1, 0x34c7eafa }},
                                           { "12345678901234567890123456789012345678901234567890123456",
                                           { 0x0a84666b, 0x66e843a4, 0x146088fb, 0x46aabaa9, 0x98b4c2b1 }},
                                           { "123456789012345678901234567890123456789012345678901234567",
                                           { 0x2bf216f1, 0xb6c7e40e, 0x56d36657, 0x7949b62b, 0x40639391 }},
                                           { "1234567890123456789012345678901234567890123456789012345678",
                                           { 0x54ac6df4, 0xe11fe9b1, 0x1e475406, 0xe23a171d, 0xac88988e }},
                                           { "123456789012345678901234567890123456789012345678901234567890",
                                           { 0x245be300, 0x91fd392f, 0xe191f4bf, 0xcec22dcb, 0x30a03ae6 }},
                                           { "12345678901234567890123456789012345678901234567890123456789012",
                                           { 0xd8d073b3, 0x83156617, 0xc5cadf17, 0xf61596a3, 0x840afd8b }},
                                           { "",
                                           { 0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709 }} };

/**
 * Function: main
 */
int main() 
{
    int numberOfTests = sizeof(testVectors) / sizeof(struct sha1TestVec),
        testsPassed   = 0;
    struct buff tempBuffer;
    struct hash result;
    printf("Testing SHA1...\n");
    for(int i = 0; i < numberOfTests; i++)
    {
        tempBuffer.p_data = testVectors[i].p_input;
        tempBuffer.l_data = strlen(tempBuffer.p_data);
        sha1Digest(&tempBuffer,
                   &result);
        if(memcmp(&(testVectors[i].expectedResult),
                  &result,
                  sizeof(struct hash)) == 0)
            testsPassed++;
        else
            printHashDiff(&(testVectors[i].expectedResult),
                          &result);
    }
    printf("Passed %d/%d!\n", testsPassed, numberOfTests);

	return 0;
}
/**
 * Function: printHashDiff
 */
void printHashDiff
(
    const struct hash *p_hashExpected,
          struct hash *p_hashReceived
)
{
    printf("\nExpected: %08X %08X %08X %08X %08X\n", p_hashExpected->a, p_hashExpected->b, p_hashExpected->c, p_hashExpected->d, p_hashExpected->e);
    printf("Received: %08X %08X %08X %08X %08X\n\n", p_hashReceived->a, p_hashReceived->b, p_hashReceived->c, p_hashReceived->d, p_hashReceived->e);
}
