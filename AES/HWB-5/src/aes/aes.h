//
// Created by Olaf Bykowski on 29/10/2024.
//

#ifndef AES_H
#define AES_H

#include <cstdint>

/* AES state type */
typedef uint32_t t_state[4];

// Function prototypes
uint32_t subWord(uint32_t w);

void subBytes(t_state s);

void shiftRows(t_state s);

uint8_t xtime(uint8_t a);

uint32_t mixColumn(uint32_t c);

void mixColumns(t_state s);

void expandKey(uint8_t k[16], uint32_t ek[44]);

void addRoundKey(t_state s, uint32_t ek[], short round);

void aes(uint8_t *in, uint8_t *out, uint8_t *skey);

#endif //AES_H
