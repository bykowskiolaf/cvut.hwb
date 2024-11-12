#include "aes.h"
#include <cstdint>
#include "aes_consts.h"

/* AES state type */
typedef uint32_t t_state[4];

/* Macros for word and wbyte */
#define WORD(a0, a1, a2, a3) ((a0) | ((uint32_t)(a1) << 8) | ((uint32_t)(a2) << 16) | ((uint32_t)(a3) << 24))
#define WBYTE(w, pos) (((w) >> ((pos) * 8)) & 0xff)

uint32_t T0[256], T1[256], T2[256], T3[256];

// Helper function for multiplication in GF(2^8)
uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool high_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (high_bit_set) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// Function to generate T-boxes
void generateTBoxes() {
    for (int i = 0; i < 256; ++i) {
        uint8_t s = SBOX[i];
        T0[i] = (mul(0x02, s) << 24) | (s << 16) | (s << 8) | mul(0x03, s);
        T1[i] = (mul(0x03, s) << 24) | (mul(0x02, s) << 16) | (s << 8) | s;
        T2[i] = (s << 24) | (mul(0x03, s) << 16) | (mul(0x02, s) << 8) | s;
        T3[i] = (s << 24) | (s << 16) | (mul(0x03, s) << 8) | mul(0x02, s);
    }
}

// **************** AES  functions ****************
uint32_t subWord(uint32_t w) {
    return WORD(SBOX[WBYTE(w, 0)], SBOX[WBYTE(w, 1)], SBOX[WBYTE(w, 2)], SBOX[WBYTE(w, 3)]);
}

// 4.2.1 Multiplication by x in GF(2^8)
uint8_t xtime(uint8_t a) {
    return (a << 1) ^ ((a >> 7) * 0x1b);
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

    // Initialize state from input
    for (int i = 0; i < 4; ++i) {
        state[i] = WORD(in[i * 4], in[i * 4 + 1], in[i * 4 + 2], in[i * 4 + 3]);
    }

    uint32_t expKey[44];
    expandKey(skey, expKey);

    addRoundKey(state, expKey, 0);

    for (unsigned short round = 1; round < 10; ++round) {
        uint32_t t0 = T0[WBYTE(state[0], 0)] ^ T1[WBYTE(state[1], 1)] ^ T2[WBYTE(state[2], 2)] ^ T3[WBYTE(state[3], 3)];
        uint32_t t1 = T0[WBYTE(state[1], 0)] ^ T1[WBYTE(state[2], 1)] ^ T2[WBYTE(state[3], 2)] ^ T3[WBYTE(state[0], 3)];
        uint32_t t2 = T0[WBYTE(state[2], 0)] ^ T1[WBYTE(state[3], 1)] ^ T2[WBYTE(state[0], 2)] ^ T3[WBYTE(state[1], 3)];
        uint32_t t3 = T0[WBYTE(state[3], 0)] ^ T1[WBYTE(state[0], 1)] ^ T2[WBYTE(state[1], 2)] ^ T3[WBYTE(state[2], 3)];

        state[0] = t0;
        state[1] = t1;
        state[2] = t2;
        state[3] = t3;
        addRoundKey(state, expKey, round);
    }

    // Final round without MixColumns
    uint32_t t0 = (SBOX[WBYTE(state[0], 0)] << 24) | (SBOX[WBYTE(state[1], 1)] << 16) | (SBOX[WBYTE(state[2], 2)] << 8) | SBOX[WBYTE(state[3], 3)];
    uint32_t t1 = (SBOX[WBYTE(state[1], 0)] << 24) | (SBOX[WBYTE(state[2], 1)] << 16) | (SBOX[WBYTE(state[3], 2)] << 8) | SBOX[WBYTE(state[0], 3)];
    uint32_t t2 = (SBOX[WBYTE(state[2], 0)] << 24) | (SBOX[WBYTE(state[3], 1)] << 16) | (SBOX[WBYTE(state[0], 2)] << 8) | SBOX[WBYTE(state[1], 3)];
    uint32_t t3 = (SBOX[WBYTE(state[3], 0)] << 24) | (SBOX[WBYTE(state[0], 1)] << 16) | (SBOX[WBYTE(state[1], 2)] << 8) | SBOX[WBYTE(state[2], 3)];

    state[0] = t0;
    state[1] = t1;
    state[2] = t2;
    state[3] = t3;
    addRoundKey(state, expKey, 10);

    // Output state to out array
    for (int i = 0; i < 16; ++i) {
        if (i < 4) out[i] = WBYTE(state[0], i % 4);
        else if (i < 8) out[i] = WBYTE(state[1], i % 4);
        else if (i < 12) out[i] = WBYTE(state[2], i % 4);
        else out[i] = WBYTE(state[3], i % 4);
    }
}

