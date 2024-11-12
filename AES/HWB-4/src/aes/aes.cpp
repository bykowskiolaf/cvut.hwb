#include "aes.h"
#include <cstdint>
#include "aes_consts.h"
#include "../helper/helper.h"

/* AES state type */
typedef uint32_t t_state[4];

// **************** AES  functions ****************
uint32_t subWord(uint32_t w) {
    // Substitute each byte of the word using the SBOX
    return word(SBOX[wbyte(w, 0)], SBOX[wbyte(w, 1)], SBOX[wbyte(w, 2)], SBOX[wbyte(w, 3)]);
}

// Function to calculate SBOX values based on the AES algorithm
uint8_t calculateSBox(uint8_t byte) {
    // Step 1: Calculate the multiplicative inverse in GF(2^8)
    uint8_t inverse = 1;
    if (byte != 0) {
        uint8_t b = byte;
        for (int i = 1; i < 255; i++) {
            b = xtime(b);
            if (b == 1) {
                inverse = i;
                break;
            }
        }
    }

    // Step 2: Apply the affine transformation
    uint8_t s = inverse;
    s = s ^ (inverse << 1) ^ (inverse << 2) ^ (inverse << 3) ^ (inverse << 4);
    s = s ^ 0x63; // XOR with constant 0x63

    return s;
}

// 5.1.1 SubBytes() Transformation
void subBytes(t_state s) {
    // Apply SBOX substitution for each byte in the state
    for (int i = 0; i < 4; i++) {
        s[i] = word(SBOX[wbyte(s[i], 0)], SBOX[wbyte(s[i], 1)], SBOX[wbyte(s[i], 2)], SBOX[wbyte(s[i], 3)]);
    }
}

// 5.1.2 ShiftRows() Transformation
void shiftRows(t_state s) {
    uint8_t temp[16];

    // Extract bytes from state into temp array
    for (int i = 0; i < 4; i++) {
        temp[i] = wbyte(s[0], i);
        temp[i + 4] = wbyte(s[1], i);
        temp[i + 8] = wbyte(s[2], i);
        temp[i + 12] = wbyte(s[3], i);
    }

    // Perform row shifts directly in the temp array
    // Row 0 remains unchanged
    // Row 1 shifts left by 1
    uint8_t t = temp[1];
    temp[1] = temp[5];
    temp[5] = temp[9];
    temp[9] = temp[13];
    temp[13] = t;

    // Row 2 shifts left by 2
    t = temp[2];
    uint8_t t2 = temp[6];
    temp[2] = temp[10];
    temp[6] = temp[14];
    temp[10] = t;
    temp[14] = t2;

    // Row 3 shifts left by 3
    t = temp[3];
    temp[3] = temp[15];
    temp[15] = temp[11];
    temp[11] = temp[7];
    temp[7] = t;

    // Write temp array back into state
    s[0] = word(temp[0], temp[1], temp[2], temp[3]);
    s[1] = word(temp[4], temp[5], temp[6], temp[7]);
    s[2] = word(temp[8], temp[9], temp[10], temp[11]);
    s[3] = word(temp[12], temp[13], temp[14], temp[15]);
}

// 4.2.1 Multiplication by x in GF(2^8)
uint8_t xtime(uint8_t a) {
    // Multiply by x (i.e., left shift and conditional reduction)
    return (a << 1) ^ ((a >> 7) * 0x1b);
}

// 5.1.3 MixColumns() Transformation
uint32_t mixColumn(uint32_t c) {
    uint8_t a[4], b[4];

    // Extract bytes from the input column and calculate products
    for (int i = 0; i < 4; i++) {
        a[i] = wbyte(c, i);
        b[i] = xtime(a[i]);
    }

    // Compute result bytes for the new column
    uint8_t result[4];
    result[0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    result[1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    result[2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    result[3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];

    return word(result[0], result[1], result[2], result[3]);
}

void mixColumns(t_state s) {
    // Apply mixColumn transformation to each column of the state
    for (int i = 0; i < 4; i++) {
        s[i] = mixColumn(s[i]);
    }
}

/*
 * 5.2 Key Expansion
 *
 * Key expansion from 128bits (4*32b)
 * to 11 round keys (11*4*32b)
 * each round key is 4*32b
*/
void expandKey(uint8_t k[16], uint32_t ek[44]) {
    // Initialize first 4 words of the expanded key with the original key
    for (int i = 0; i < 4; i++) {
        ek[i] = word(k[4 * i], k[4 * i + 1], k[4 * i + 2], k[4 * i + 3]);
    }
    // Generate the remaining words of the expanded key
    for (int i = 4; i < 44; i++) {
        uint32_t temp = ek[i - 1];
        if (i % 4 == 0) {
            // Apply RotWord, SubWord, and Rcon for every 4th word
            uint32_t rotated = word(wbyte(temp, 1), wbyte(temp, 2), wbyte(temp, 3), wbyte(temp, 0));
            temp = subWord(rotated) ^ rCon[i / 4];
        }
        ek[i] = ek[i - 4] ^ temp;
    }
}

// 5.1.4 AddRoundKey() Transformation
void addRoundKey(t_state s, uint32_t ek[], short round) {
    // XOR the state with the corresponding round key
    for (int i = 0; i < 4; i++) {
        s[i] ^= ek[round * 4 + i];
    }
}

void aes(uint8_t *in, uint8_t *out, uint8_t *skey) {
    unsigned short round = 0;
    t_state state;

    // Initialize state from input
    for (int i = 0; i < 4; i++) {
        state[i] = word(in[i * 4], in[i * 4 + 1], in[i * 4 + 2], in[i * 4 + 3]);
    }

    uint32_t expKey[44];
    expandKey(skey, expKey);

    // Initial AddRoundKey
    addRoundKey(state, expKey, 0);

    // Rounds 1-9
    for (round = 1; round < 10; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expKey, round);
    }

    // Round 10 (without MixColumns)
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expKey, 10);

    // Write the final state to output
    for (int i = 0; i < 16; i++) {
        if (i < 4) out[i] = wbyte(state[0], i % 4);
        else if (i < 8) out[i] = wbyte(state[1], i % 4);
        else if (i < 12) out[i] = wbyte(state[2], i % 4);
        else out[i] = wbyte(state[3], i % 4);
    }
}
