#!/usr/bin/env python
#
# Calculate round constants for SHA1
import numpy

def leftRotate(word, bits):
    word_digits = list(bin(word))
    word_digits = ((34 - len(word_digits)) * [0]) + word_digits[2:]
    word_digits = numpy.roll(word_digits, -(bits))
    word_digits = ''.join(word_digits)

    return int(word_digits, base = 2)

K_00_19       = 0x5A827999
a = SHA1_IV_0 = 0x67452301
b = SHA1_IV_1 = 0xEFCDAB89
c = SHA1_IV_2 = 0x98BADCFE
d = SHA1_IV_3 = 0x10325476
e = SHA1_IV_4 = 0xC3D2E1F0

roundConstant0 = leftRotate(a, 5) + (d ^ (b & (c ^ d))) + e + K_00_19
e = d; d = c; c = leftRotate(b, 30); b = a
roundConstant1 = (d ^ (b & (c ^ d))) + e + K_00_19
e = d; d = c; c = leftRotate(b, 30)
roundConstant2 = e + K_00_19
e = d; d = c
roundConstant3 = e + K_00_19
e = d
roundConstant4 = e + K_00_19

print("Round Constant 0: " + str(hex(roundConstant0))) # Round Constant 0: 0x29fb498b3
print("Round Constant 1: " + str(hex(roundConstant1))) # Round Constant 1: 0x166b0cd0d
print("Round Constant 2: " + str(hex(roundConstant2))) # Round Constant 2: 0xf33d5697
print("Round Constant 3: " + str(hex(roundConstant3))) # Round Constant 3: 0xd675e47b
print("Round Constant 4: " + str(hex(roundConstant4))) # Round Constant 4: 0xb453c259
