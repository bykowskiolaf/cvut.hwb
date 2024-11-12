//
// Created by Olaf Bykowski on 29/10/2024.
//

#ifndef AES_H
#define AES_H

#include <cstdint>

/* AES state type */
typedef uint32_t t_state[4];

void generateTBoxes();

uint32_t subWord(uint32_t w);

uint8_t xtime(uint8_t a);

void expandKey(uint8_t k[16], uint32_t ek[44]);

void addRoundKey(t_state s, uint32_t ek[], short round);

void aes(uint8_t *in, uint8_t *out, uint8_t *skey);

#endif //AES_H
