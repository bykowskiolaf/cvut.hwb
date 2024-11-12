#include "aes.h"
#include <cstdint>
#include "aes_consts.h"

/* AES state type */
typedef uint32_t t_state[4];

/* Macros for word and wbyte */
#define WORD(a0, a1, a2, a3) ((a0) | ((uint32_t)(a1) << 8) | ((uint32_t)(a2) << 16) | ((uint32_t)(a3) << 24))
#define WBYTE(w, pos) (((w) >> ((pos) * 8)) & 0xff)

uint32_t T0[256], T1[256], T2[256], T3[256];

// Multiply in GF(2^8) and reduce by AES polynomial if necessary
uint8_t GFMult(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int counter = 0; counter < 8; counter++) {
        if (b & 1)
            p ^= a;
        uint8_t hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}


// Concatenate four bytes to form a 32-bit word
uint32_t ConCat(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

// Function to generate T-boxes
void generateTBoxes() {
    for (int i = 0; i < 256; i++) {
        uint8_t s = SBOX[i];
        uint8_t s2 = GFMult(s, 0x02);
        uint8_t s3 = GFMult(s, 0x03);
        T0[i] = WORD(s2, s, s, s3);
        T1[i] = WORD(s3, s2, s, s);
        T2[i] = WORD(s, s3, s2, s);
        T3[i] = WORD(s, s, s3, s2);
    }
}

// **************** AES Functions ****************
uint32_t subWord(uint32_t w) {
    return WORD(SBOX[WBYTE(w, 0)], SBOX[WBYTE(w, 1)], SBOX[WBYTE(w, 2)], SBOX[WBYTE(w, 3)]);
}

void subBytes(t_state s) {
    for (int i = 0; i < 4; i++) {
        s[i] = WORD(SBOX[WBYTE(s[i], 0)], SBOX[WBYTE(s[i], 1)], SBOX[WBYTE(s[i], 2)], SBOX[WBYTE(s[i], 3)]);
    }
}

void shiftRows(t_state s) {
    uint8_t temp[16];

    for (int i = 0; i < 4; i++) {
        temp[i] = WBYTE(s[0], i);
        temp[i + 4] = WBYTE(s[1], i);
        temp[i + 8] = WBYTE(s[2], i);
        temp[i + 12] = WBYTE(s[3], i);
    }

    uint8_t t;

    // Row 1 shifts left by 1
    t = temp[1];
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

    s[0] = WORD(temp[0], temp[1], temp[2], temp[3]);
    s[1] = WORD(temp[4], temp[5], temp[6], temp[7]);
    s[2] = WORD(temp[8], temp[9], temp[10], temp[11]);
    s[3] = WORD(temp[12], temp[13], temp[14], temp[15]);
}

void tboxLookup(t_state s) {
    uint8_t s_bytes[16];
    // Extract bytes from state
    for (int col = 0; col < 4; col++) {
        uint32_t col_word = s[col];
        for (int row = 0; row < 4; row++) {
            s_bytes[col * 4 + row] = WBYTE(col_word, row);
        }
    }
    // T-box lookup
    uint32_t e[4];
    e[0] = T0[s_bytes[0]] ^ T1[s_bytes[5]] ^ T2[s_bytes[10]] ^ T3[s_bytes[15]];
    e[1] = T0[s_bytes[4]] ^ T1[s_bytes[9]] ^ T2[s_bytes[14]] ^ T3[s_bytes[3]];
    e[2] = T0[s_bytes[8]] ^ T1[s_bytes[13]] ^ T2[s_bytes[2]] ^ T3[s_bytes[7]];
    e[3] = T0[s_bytes[12]] ^ T1[s_bytes[1]] ^ T2[s_bytes[6]] ^ T3[s_bytes[11]];
    // Update state
    for (int col = 0; col < 4; col++) {
        s[col] = e[col];
    }
}

void expandKey(uint8_t k[16], uint32_t ek[44]) {
    for (int i = 0; i < 4; i++) {
        ek[i] = WORD(k[4 * i], k[4 * i + 1], k[4 * i + 2], k[4 * i + 3]);
    }
    for (int i = 4; i < 44; i++) {
        uint32_t temp = ek[i - 1];
        if (i % 4 == 0) {
            uint32_t rotated = WORD(WBYTE(temp, 1), WBYTE(temp, 2), WBYTE(temp, 3), WBYTE(temp, 0));
            temp = subWord(rotated) ^ rCon[i / 4];
        }
        ek[i] = ek[i - 4] ^ temp;
    }
}

void addRoundKey(t_state s, uint32_t ek[], short round) {
    for (int i = 0; i < 4; i++) {
        s[i] ^= ek[round * 4 + i];
    }
}

void aes(uint8_t *in, uint8_t *out, uint8_t *skey) {
    t_state state;

    for (int i = 0; i < 4; i++) {
        state[i] = WORD(in[i * 4], in[i * 4 + 1], in[i * 4 + 2], in[i * 4 + 3]);
    }

    uint32_t expKey[44];
    expandKey(skey, expKey);

    addRoundKey(state, expKey, 0);

    for (unsigned short round = 1; round < 10; round++) {
        tboxLookup(state);
        addRoundKey(state, expKey, round);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expKey, 10);

    // Store the output
    for (int i = 0; i < 4; i++) {
        uint32_t col = state[i];
        for (int row = 0; row < 4; row++) {
            out[i * 4 + row] = WBYTE(col, row);
        }
    }
}
