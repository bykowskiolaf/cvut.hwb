#include "aes.h"
#include <cstdint>
#include "aes_consts.h"

/* AES state type */
typedef uint32_t t_state[4];

/* Macros for word and wbyte */
#define WORD(a0, a1, a2, a3) ((a0) | ((uint32_t)(a1) << 8) | ((uint32_t)(a2) << 16) | ((uint32_t)(a3) << 24))
#define WBYTE(w, pos) (((w) >> ((pos) * 8)) & 0xff)

// **************** AES  functions ****************
uint32_t subWord(uint32_t w) {
    return WORD(SBOX[WBYTE(w, 0)], SBOX[WBYTE(w, 1)], SBOX[WBYTE(w, 2)], SBOX[WBYTE(w, 3)]);
}

// 5.1.1 SubBytes() Transformation
void subBytes(t_state s) {
    for (int i = 0; i < 4; i++) {
        s[i] = WORD(SBOX[WBYTE(s[i], 0)], SBOX[WBYTE(s[i], 1)], SBOX[WBYTE(s[i], 2)], SBOX[WBYTE(s[i], 3)]);
    }
}

// 5.1.2 ShiftRows() Transformation
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

// 4.2.1 Multiplication by x in GF(2^8)
uint8_t xtime(uint8_t a) {
    return (a << 1) ^ ((a >> 7) * 0x1b);
}

// 5.1.3 MixColumns() Transformation
uint32_t mixColumn(uint32_t c) {
    uint8_t a[4], b[4];

    for (int i = 0; i < 4; i++) {
        a[i] = WBYTE(c, i);
        b[i] = xtime(a[i]);
    }

    uint8_t result[4];
    result[0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    result[1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    result[2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    result[3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];

    return WORD(result[0], result[1], result[2], result[3]);
}

void mixColumns(t_state s) {
    for (int i = 0; i < 4; i++) {
        s[i] = mixColumn(s[i]);
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
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expKey, round);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expKey, 10);

    for (int i = 0; i < 16; i++) {
        if (i < 4) out[i] = WBYTE(state[0], i % 4);
        else if (i < 8) out[i] = WBYTE(state[1], i % 4);
        else if (i < 12) out[i] = WBYTE(state[2], i % 4);
        else out[i] = WBYTE(state[3], i % 4);
    }
}